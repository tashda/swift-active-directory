#ifndef AD_SEARCH_H
#define AD_SEARCH_H

#include "ad_bind.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *_Nullable data;
    size_t length;
} ad_value_t;

typedef struct {
    char *_Nullable name;
    ad_value_t *_Nullable values;
    size_t value_count;
} ad_attribute_t;

typedef struct {
    char *_Nullable dn;
    ad_attribute_t *_Nullable attributes;
    size_t attribute_count;
} ad_entry_t;

typedef struct {
    ad_entry_t *_Nullable entries;
    size_t entry_count;
    int size_limit_exceeded;
} ad_search_result_t;

/*
 * ad_session_read_root_dse
 *   Reads the special RootDSE entry (base "", scope base, filter
 *   "(objectClass=*)") and extracts the forest-wide naming contexts.
 *
 *   On success the three out-params receive heap-allocated strings
 *   (`rootDomainNamingContext`, `configurationNamingContext`,
 *   `defaultNamingContext`). Any of them may be NULL if the directory does
 *   not publish that attribute. Caller frees each with ad_string_free.
 */
int ad_session_read_root_dse(
    ad_session_t *_Nonnull session,
    char *_Nullable *_Nullable root_domain_nc_out,
    char *_Nullable *_Nullable config_nc_out,
    char *_Nullable *_Nullable default_nc_out,
    char *_Nullable *_Nullable err_out
);

typedef enum {
    AD_SCOPE_BASE = 0,       /* the entry at base_dn only */
    AD_SCOPE_ONE_LEVEL = 1,  /* direct children of base_dn */
    AD_SCOPE_SUBTREE = 2     /* base_dn and every descendant */
} ad_search_scope_t;

/*
 * ad_session_search
 *   Performs an LDAP search at the requested scope. Returns up to size_limit
 *   entries; if AD reports LDAP_SIZELIMIT_EXCEEDED, the result's
 *   size_limit_exceeded flag is set to 1 and the partial entry list is
 *   returned anyway.
 *
 *   `attributes` is a NULL-terminated array of attribute names to request.
 *   Pass NULL to request all attributes (rare — usually expensive on AD).
 *
 *   Caller must free the result with ad_search_result_free.
 */
int ad_session_search(
    ad_session_t *_Nonnull session,
    const char *_Nonnull base_dn,
    ad_search_scope_t scope,
    const char *_Nonnull filter,
    const char *_Nullable *_Nullable attributes,
    int size_limit,
    int time_limit_seconds,
    ad_search_result_t *_Nonnull out,
    char *_Nullable *_Nullable err_out
);

void ad_search_result_free(ad_search_result_t *_Nonnull result);

#ifdef __cplusplus
}
#endif

#endif /* AD_SEARCH_H */
