#include "ad_bind.h"
#include "CLDAP.h"

#include <GSS/GSS.h>
#include <Kerberos/krb5.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ad_session {
    LDAP *ld;
    /* Process-unique Kerberos memory ccache name (e.g. "MEMORY:adbrowser-12345-1").
       Owned by the session; destroyed in ad_session_close so credentials never
       outlive the picker window. */
    char *ccache_name;
};

static char *ad_format_error(const char *prefix, const char *detail) {
    if (prefix == NULL) prefix = "error";
    if (detail == NULL) detail = "unknown";
    size_t needed = strlen(prefix) + strlen(detail) + 4;
    char *buf = (char *)malloc(needed);
    if (buf == NULL) return NULL;
    snprintf(buf, needed, "%s: %s", prefix, detail);
    return buf;
}

static char *ad_format_krb5_error(krb5_context ctx, const char *prefix, krb5_error_code code) {
    const char *detail = NULL;
    if (ctx != NULL) {
        detail = krb5_get_error_message(ctx, code);
    }
    char *out = ad_format_error(prefix, detail ? detail : "unknown Kerberos error");
    if (ctx != NULL && detail != NULL) {
        krb5_free_error_message(ctx, detail);
    }
    return out;
}

/*
 * Cyrus SASL interactive callback. With the user's TGT already in the
 * per-session memory ccache (and KRB5CCNAME pointed at it), the GSSAPI
 * plugin has everything it needs and the callback is invoked only for
 * cosmetic prompts like the SASL realm. Returning empty strings keeps the
 * SASL state machine progressing.
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
    s->ccache_name = NULL;
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

    /*
     * The cyrus-sasl GSSAPI plugin used by libldap calls into the default GSS
     * credential (gss_acquire_cred(NULL, ...)), which on macOS resolves via
     * the default Kerberos ccache. So we obtain a TGT *into* a fresh in-memory
     * ccache, point KRB5CCNAME at it, and the SASL bind picks up the tickets
     * through the standard channel. This is the same approach `kinit` would
     * take, without polluting the user's default ccache or Keychain.
     *
     * We deliberately do NOT use LDAP_OPT_X_SASL_GSS_CREDS — that option is
     * defined in macOS's libldap headers but not honored by the vendored
     * implementation, so ldap_set_option returns -1 and the bind fails with
     * a misleading "Can't contact LDAP server" error.
     */

    krb5_context ctx = NULL;
    krb5_error_code kerr = krb5_init_context(&ctx);
    if (kerr != 0) {
        if (err_out) *err_out = ad_format_krb5_error(NULL, "krb5_init_context", kerr);
        return -1;
    }

    /* Construct user@REALM principal. */
    size_t princ_len = strlen(user) + strlen(realm) + 2;
    char *princ_str = (char *)malloc(princ_len);
    if (princ_str == NULL) {
        krb5_free_context(ctx);
        if (err_out) *err_out = ad_format_error("malloc", "out of memory");
        return -1;
    }
    snprintf(princ_str, princ_len, "%s@%s", user, realm);

    krb5_principal client_princ = NULL;
    kerr = krb5_parse_name(ctx, princ_str, &client_princ);
    free(princ_str);
    if (kerr != 0) {
        if (err_out) *err_out = ad_format_krb5_error(ctx, "krb5_parse_name", kerr);
        krb5_free_context(ctx);
        return -1;
    }

    /* Obtain a TGT by password. This contacts the KDC (discovered via DNS
       SRV records for the realm) and returns the AS-REP credentials. */
    krb5_creds creds;
    memset(&creds, 0, sizeof(creds));
    kerr = krb5_get_init_creds_password(
        ctx,
        &creds,
        client_princ,
        (char *)password,
        NULL,   /* no prompter — non-interactive */
        NULL,
        0,      /* default lifetime */
        NULL,   /* no target service — we want a TGT */
        NULL    /* default options */
    );
    if (kerr != 0) {
        if (err_out) *err_out = ad_format_krb5_error(ctx, "krb5_get_init_creds_password", kerr);
        krb5_free_principal(ctx, client_princ);
        krb5_free_context(ctx);
        return -1;
    }

    /* Build a process- and session-unique ccache name so concurrent picker
       sessions don't collide and so credentials are isolated from the user's
       default ccache. */
    char ccname[128];
    snprintf(ccname, sizeof(ccname), "MEMORY:adbrowser-%d-%p", (int)getpid(), (void *)session);

    krb5_ccache cc = NULL;
    kerr = krb5_cc_resolve(ctx, ccname, &cc);
    if (kerr != 0) {
        if (err_out) *err_out = ad_format_krb5_error(ctx, "krb5_cc_resolve", kerr);
        krb5_free_cred_contents(ctx, &creds);
        krb5_free_principal(ctx, client_princ);
        krb5_free_context(ctx);
        return -1;
    }

    kerr = krb5_cc_initialize(ctx, cc, client_princ);
    if (kerr != 0) {
        if (err_out) *err_out = ad_format_krb5_error(ctx, "krb5_cc_initialize", kerr);
        krb5_cc_close(ctx, cc);
        krb5_free_cred_contents(ctx, &creds);
        krb5_free_principal(ctx, client_princ);
        krb5_free_context(ctx);
        return -1;
    }

    kerr = krb5_cc_store_cred(ctx, cc, &creds);
    if (kerr != 0) {
        if (err_out) *err_out = ad_format_krb5_error(ctx, "krb5_cc_store_cred", kerr);
        krb5_cc_close(ctx, cc);
        krb5_free_cred_contents(ctx, &creds);
        krb5_free_principal(ctx, client_princ);
        krb5_free_context(ctx);
        return -1;
    }

    /* The tickets are now in the memory ccache; close the handle (the named
       ccache persists in-process) and tell GSSAPI where to find them. */
    krb5_cc_close(ctx, cc);
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, client_princ);
    krb5_free_context(ctx);

    setenv("KRB5CCNAME", ccname, 1);
    session->ccache_name = strdup(ccname);

    int rc = ldap_sasl_interactive_bind_s(
        session->ld,
        NULL,
        "GSSAPI",
        NULL,
        NULL,
        LDAP_SASL_QUIET,
        ad_sasl_interact,
        NULL
    );
    if (rc != LDAP_SUCCESS) {
        /* "Local error" is libldap's generic SASL/GSS wrapper. The real
           reason — cross-realm referral failure, KDC unreachable, time
           skew, missing SPN — lives in the diagnostic message slot the
           SASL plugin populates. Fetch it so the picker can surface the
           actual diagnostic instead of just "Local error". */
        char *diag = NULL;
        (void)ldap_get_option(session->ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &diag);
        const char *short_msg = ldap_err2string(rc);
        char buf[1024];
        if (diag != NULL && diag[0] != '\0') {
            snprintf(buf, sizeof(buf), "%s — %s", short_msg, diag);
        } else {
            snprintf(buf, sizeof(buf), "%s", short_msg);
        }
        if (diag != NULL) ldap_memfree(diag);
        if (err_out) *err_out = ad_format_error("ldap_sasl_interactive_bind_s GSSAPI", buf);
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
    if (session->ccache_name != NULL) {
        /* Destroy the memory ccache so credentials don't outlive the session. */
        krb5_context ctx = NULL;
        if (krb5_init_context(&ctx) == 0) {
            krb5_ccache cc = NULL;
            if (krb5_cc_resolve(ctx, session->ccache_name, &cc) == 0) {
                (void)krb5_cc_destroy(ctx, cc);
            }
            krb5_free_context(ctx);
        }
        free(session->ccache_name);
        session->ccache_name = NULL;
    }
    if (session->ld != NULL) {
        (void)ldap_unbind_ext_s(session->ld, NULL, NULL);
    }
    free(session);
}

void ad_string_free(char *str) {
    free(str);
}
