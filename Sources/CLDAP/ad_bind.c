#include "ad_bind.h"
#include "CLDAP.h"

#include <GSS/GSS.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ad_session {
    LDAP *ld;
    gss_cred_id_t gss_cred;
};

static char *ad_strdup_or_null(const char *s) {
    if (s == NULL) return NULL;
    return strdup(s);
}

static char *ad_format_error(const char *prefix, const char *detail) {
    if (prefix == NULL) prefix = "error";
    if (detail == NULL) detail = "unknown";
    size_t needed = strlen(prefix) + strlen(detail) + 4;
    char *buf = (char *)malloc(needed);
    if (buf == NULL) return NULL;
    snprintf(buf, needed, "%s: %s", prefix, detail);
    return buf;
}

static char *ad_format_gss_error(const char *prefix, OM_uint32 major, OM_uint32 minor) {
    /* Surface the human-readable major and minor messages from GSS. */
    OM_uint32 ctx = 0;
    OM_uint32 ms = 0;
    gss_buffer_desc major_buf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc minor_buf = GSS_C_EMPTY_BUFFER;

    (void)gss_display_status(&ms, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &major_buf);
    (void)gss_display_status(&ms, minor, GSS_C_MECH_CODE, GSS_C_NO_OID, &ctx, &minor_buf);

    const char *maj = major_buf.value ? (const char *)major_buf.value : "gss error";
    const char *min = minor_buf.value ? (const char *)minor_buf.value : "";
    size_t needed = strlen(prefix) + strlen(maj) + strlen(min) + 8;
    char *buf = (char *)malloc(needed);
    if (buf != NULL) snprintf(buf, needed, "%s: %s (%s)", prefix, maj, min);

    (void)gss_release_buffer(&ms, &major_buf);
    (void)gss_release_buffer(&ms, &minor_buf);
    return buf;
}

/*
 * Cyrus SASL interactive callback. With LDAP_OPT_X_SASL_GSS_CREDS supplying
 * the credential, no further user input is required — every SASL_CB_* request
 * is answered with an empty string to keep the SASL state machine moving.
 */
static int ad_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in) {
    (void)ld;
    (void)flags;
    (void)defaults;
    sasl_interact_t *interact = (sasl_interact_t *)in;
    while (interact && interact->id != SASL_CB_LIST_END) {
        interact->result = "";
        interact->len = 0;
        interact++;
    }
    return LDAP_SUCCESS;
}

ad_session_t *ad_session_open(const char *uri, char **err_out) {
    if (err_out) *err_out = NULL;
    if (uri == NULL) {
        if (err_out) *err_out = ad_format_error("ad_session_open", "uri is NULL");
        return NULL;
    }

    LDAP *ld = NULL;
    int rc = ldap_initialize(&ld, uri);
    if (rc != LDAP_SUCCESS || ld == NULL) {
        if (err_out) *err_out = ad_format_error("ldap_initialize", ldap_err2string(rc));
        return NULL;
    }

    int version = LDAP_VERSION3;
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (rc != LDAP_OPT_SUCCESS) {
        if (err_out) *err_out = ad_format_error("LDAP_OPT_PROTOCOL_VERSION", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }

    /* AD returns referrals for forest-wide queries; we want to handle them in
       Swift via explicit GC re-binds, so disable automatic chasing. */
    rc = ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (rc != LDAP_OPT_SUCCESS) {
        if (err_out) *err_out = ad_format_error("LDAP_OPT_REFERRALS", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }

    ad_session_t *s = (ad_session_t *)calloc(1, sizeof(ad_session_t));
    if (s == NULL) {
        if (err_out) *err_out = ad_format_error("calloc", "out of memory");
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }
    s->ld = ld;
    s->gss_cred = GSS_C_NO_CREDENTIAL;
    return s;
}

int ad_session_bind_kerberos(
    ad_session_t *session,
    const char *user,
    const char *realm,
    const char *password,
    char **err_out
) {
    if (err_out) *err_out = NULL;
    if (session == NULL || user == NULL || realm == NULL || password == NULL) {
        if (err_out) *err_out = ad_format_error("ad_session_bind_kerberos", "invalid argument");
        return -1;
    }

    /* Build "user@REALM" principal name. */
    size_t princ_len = strlen(user) + strlen(realm) + 2;
    char *princ = (char *)malloc(princ_len);
    if (princ == NULL) {
        if (err_out) *err_out = ad_format_error("malloc", "out of memory");
        return -1;
    }
    snprintf(princ, princ_len, "%s@%s", user, realm);

    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    gss_buffer_desc name_buf;
    name_buf.value = princ;
    name_buf.length = strlen(princ);

    gss_name_t gss_name = GSS_C_NO_NAME;
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_USER_NAME, &gss_name);
    free(princ);
    if (GSS_ERROR(major)) {
        if (err_out) *err_out = ad_format_gss_error("gss_import_name", major, minor);
        return -1;
    }

    gss_buffer_desc pw_buf;
    pw_buf.value = (void *)password;
    pw_buf.length = strlen(password);

    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    major = gss_acquire_cred_with_password(
        &minor,
        gss_name,
        &pw_buf,
        GSS_C_INDEFINITE,
        GSS_C_NO_OID_SET,    /* default mech (Kerberos 5) */
        GSS_C_INITIATE,
        &cred,
        NULL,
        NULL
    );

    OM_uint32 ms = 0;
    (void)gss_release_name(&ms, &gss_name);

    if (GSS_ERROR(major)) {
        if (err_out) *err_out = ad_format_gss_error("gss_acquire_cred_with_password", major, minor);
        return -1;
    }

    /* Hand the credential to libldap's SASL/GSSAPI plugin. */
    int rc = ldap_set_option(session->ld, LDAP_OPT_X_SASL_GSS_CREDS, (void *)cred);
    if (rc != LDAP_OPT_SUCCESS) {
        if (err_out) *err_out = ad_format_error("LDAP_OPT_X_SASL_GSS_CREDS", ldap_err2string(rc));
        (void)gss_release_cred(&ms, &cred);
        return -1;
    }
    session->gss_cred = cred;

    rc = ldap_sasl_interactive_bind_s(
        session->ld,
        NULL,           /* let SASL/GSSAPI derive the bind DN from the credential */
        "GSSAPI",
        NULL,
        NULL,
        LDAP_SASL_QUIET,
        ad_sasl_interact,
        NULL
    );
    if (rc != LDAP_SUCCESS) {
        if (err_out) *err_out = ad_format_error("ldap_sasl_interactive_bind_s GSSAPI", ldap_err2string(rc));
        return rc;
    }
    return 0;
}

int ad_session_bind_simple(
    ad_session_t *session,
    const char *bind_dn,
    const char *password,
    char **err_out
) {
    if (err_out) *err_out = NULL;
    if (session == NULL || bind_dn == NULL || password == NULL) {
        if (err_out) *err_out = ad_format_error("ad_session_bind_simple", "invalid argument");
        return -1;
    }

    struct berval cred;
    cred.bv_val = (char *)password;
    cred.bv_len = strlen(password);

    int rc = ldap_sasl_bind_s(
        session->ld,
        bind_dn,
        LDAP_SASL_SIMPLE,
        &cred,
        NULL,
        NULL,
        NULL
    );
    if (rc != LDAP_SUCCESS) {
        if (err_out) *err_out = ad_format_error("ldap_sasl_bind_s", ldap_err2string(rc));
        return rc;
    }
    return 0;
}

void ad_session_close(ad_session_t *session) {
    if (session == NULL) return;
    OM_uint32 ms = 0;
    if (session->gss_cred != GSS_C_NO_CREDENTIAL) {
        (void)gss_release_cred(&ms, &session->gss_cred);
    }
    if (session->ld != NULL) {
        (void)ldap_unbind_ext_s(session->ld, NULL, NULL);
    }
    free(session);
}

void ad_string_free(char *str) {
    free(str);
}

/* Avoid an "unused" warning until ad_strdup_or_null is consumed by the
   search implementation in step 4. */
__attribute__((unused)) static void *ad_internal_keepalive[] = {
    (void *)ad_strdup_or_null
};
