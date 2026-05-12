#include "ad_search.h"
#include "ad_bind.h"
#include "CLDAP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Internal: libldap LDAP* lives inside ad_session, exposed via the bind module. */
struct ad_session {
    LDAP *ld;
    void *gss_cred;
};

static char *ad_search_format_error(const char *prefix, int rc) {
    const char *detail = ldap_err2string(rc);
    if (detail == NULL) detail = "unknown LDAP error";
    size_t needed = strlen(prefix) + strlen(detail) + 16;
    char *buf = (char *)malloc(needed);
    if (buf == NULL) return NULL;
    snprintf(buf, needed, "%s: %s (%d)", prefix, detail, rc);
    return buf;
}

static char *ad_search_strdup_first_string(LDAP *ld, LDAPMessage *entry, const char *attr) {
    struct berval **vals = ldap_get_values_len(ld, entry, attr);
    if (vals == NULL) return NULL;
    char *result = NULL;
    if (vals[0] != NULL && vals[0]->bv_len > 0) {
        result = (char *)malloc(vals[0]->bv_len + 1);
        if (result != NULL) {
            memcpy(result, vals[0]->bv_val, vals[0]->bv_len);
            result[vals[0]->bv_len] = '\0';
        }
    }
    ldap_value_free_len(vals);
    return result;
}

int ad_session_read_root_dse(
    ad_session_t *session,
    char **root_domain_nc_out,
    char **config_nc_out,
    char **default_nc_out,
    char **err_out
) {
    if (err_out) *err_out = NULL;
    if (root_domain_nc_out) *root_domain_nc_out = NULL;
    if (config_nc_out) *config_nc_out = NULL;
    if (default_nc_out) *default_nc_out = NULL;
    if (session == NULL || session->ld == NULL) return -1;

    const char *attrs[] = {
        "rootDomainNamingContext",
        "configurationNamingContext",
        "defaultNamingContext",
        NULL
    };

    LDAPMessage *result = NULL;
    int rc = ldap_search_ext_s(
        session->ld,
        "",                            /* RootDSE has empty base DN */
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        (char **)(uintptr_t)attrs,
        0,                             /* attrsonly = 0 → want values */
        NULL, NULL,
        NULL,                          /* no timeout */
        0,
        &result
    );
    if (rc != LDAP_SUCCESS) {
        if (err_out) *err_out = ad_search_format_error("RootDSE search", rc);
        if (result) ldap_msgfree(result);
        return rc;
    }

    LDAPMessage *entry = ldap_first_entry(session->ld, result);
    if (entry != NULL) {
        if (root_domain_nc_out) *root_domain_nc_out = ad_search_strdup_first_string(session->ld, entry, "rootDomainNamingContext");
        if (config_nc_out) *config_nc_out = ad_search_strdup_first_string(session->ld, entry, "configurationNamingContext");
        if (default_nc_out) *default_nc_out = ad_search_strdup_first_string(session->ld, entry, "defaultNamingContext");
    }

    ldap_msgfree(result);
    return 0;
}

int ad_session_search(
    ad_session_t *session,
    const char *base_dn,
    const char *filter,
    const char **attributes,
    int size_limit,
    int time_limit_seconds,
    ad_search_result_t *out,
    char **err_out
) {
    if (err_out) *err_out = NULL;
    if (out == NULL) return -1;
    out->entries = NULL;
    out->entry_count = 0;
    out->size_limit_exceeded = 0;

    if (session == NULL || session->ld == NULL) return -1;

    struct timeval tv;
    struct timeval *tvp = NULL;
    if (time_limit_seconds > 0) {
        tv.tv_sec = time_limit_seconds;
        tv.tv_usec = 0;
        tvp = &tv;
    }

    LDAPMessage *result = NULL;
    int rc = ldap_search_ext_s(
        session->ld,
        base_dn,
        LDAP_SCOPE_SUBTREE,
        filter,
        (char **)(uintptr_t)attributes,
        0,
        NULL, NULL,
        tvp,
        size_limit,
        &result
    );

    int partial_ok = (rc == LDAP_SIZELIMIT_EXCEEDED || rc == LDAP_ADMINLIMIT_EXCEEDED || rc == LDAP_TIMELIMIT_EXCEEDED);
    if (rc != LDAP_SUCCESS && !partial_ok) {
        if (err_out) *err_out = ad_search_format_error("ldap_search_ext_s", rc);
        if (result) ldap_msgfree(result);
        return rc;
    }
    if (partial_ok) out->size_limit_exceeded = 1;

    /* Count entries first to size the array exactly. */
    size_t entry_count = 0;
    for (LDAPMessage *e = ldap_first_entry(session->ld, result); e != NULL; e = ldap_next_entry(session->ld, e)) {
        entry_count++;
    }

    if (entry_count == 0) {
        ldap_msgfree(result);
        return 0;
    }

    ad_entry_t *entries = (ad_entry_t *)calloc(entry_count, sizeof(ad_entry_t));
    if (entries == NULL) {
        ldap_msgfree(result);
        if (err_out) *err_out = ad_search_format_error("calloc entries", 0);
        return -1;
    }

    size_t entry_index = 0;
    for (LDAPMessage *e = ldap_first_entry(session->ld, result);
         e != NULL && entry_index < entry_count;
         e = ldap_next_entry(session->ld, e), entry_index++) {

        char *dn = ldap_get_dn(session->ld, e);
        if (dn != NULL) {
            entries[entry_index].dn = strdup(dn);
            ldap_memfree(dn);
        }

        /* Count attributes, then walk again to fill. */
        size_t attr_count = 0;
        BerElement *ber = NULL;
        for (char *attr = ldap_first_attribute(session->ld, e, &ber);
             attr != NULL;
             attr = ldap_next_attribute(session->ld, e, ber)) {
            attr_count++;
            ldap_memfree(attr);
        }
        if (ber) ber_free(ber, 0);

        if (attr_count == 0) continue;

        ad_attribute_t *attrs_arr = (ad_attribute_t *)calloc(attr_count, sizeof(ad_attribute_t));
        if (attrs_arr == NULL) continue;

        size_t attr_index = 0;
        ber = NULL;
        for (char *attr = ldap_first_attribute(session->ld, e, &ber);
             attr != NULL && attr_index < attr_count;
             attr = ldap_next_attribute(session->ld, e, ber), attr_index++) {

            attrs_arr[attr_index].name = strdup(attr);
            ldap_memfree(attr);

            struct berval **vals = ldap_get_values_len(session->ld, e, attrs_arr[attr_index].name);
            if (vals != NULL) {
                size_t vcount = 0;
                while (vals[vcount] != NULL) vcount++;
                if (vcount > 0) {
                    ad_value_t *value_arr = (ad_value_t *)calloc(vcount, sizeof(ad_value_t));
                    if (value_arr != NULL) {
                        for (size_t vi = 0; vi < vcount; vi++) {
                            value_arr[vi].length = vals[vi]->bv_len;
                            value_arr[vi].data = malloc(vals[vi]->bv_len);
                            if (value_arr[vi].data != NULL) {
                                memcpy(value_arr[vi].data, vals[vi]->bv_val, vals[vi]->bv_len);
                            } else {
                                value_arr[vi].length = 0;
                            }
                        }
                        attrs_arr[attr_index].values = value_arr;
                        attrs_arr[attr_index].value_count = vcount;
                    }
                }
                ldap_value_free_len(vals);
            }
        }
        if (ber) ber_free(ber, 0);

        entries[entry_index].attributes = attrs_arr;
        entries[entry_index].attribute_count = attr_count;
    }

    ldap_msgfree(result);
    out->entries = entries;
    out->entry_count = entry_count;
    return 0;
}

void ad_search_result_free(ad_search_result_t *result) {
    if (result == NULL || result->entries == NULL) return;
    for (size_t ei = 0; ei < result->entry_count; ei++) {
        ad_entry_t *e = &result->entries[ei];
        free(e->dn);
        for (size_t ai = 0; ai < e->attribute_count; ai++) {
            ad_attribute_t *a = &e->attributes[ai];
            free(a->name);
            for (size_t vi = 0; vi < a->value_count; vi++) {
                free(a->values[vi].data);
            }
            free(a->values);
        }
        free(e->attributes);
    }
    free(result->entries);
    result->entries = NULL;
    result->entry_count = 0;
}
