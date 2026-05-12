#ifndef AD_DNS_H
#define AD_DNS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *_Nullable *_Nullable domains;  /* NULL-terminated array; free with ad_dns_search_list_free */
    size_t count;
} ad_dns_search_list_t;

/*
 * ad_dns_search_list_copy
 *   Reads the resolver's configured DNS search list (the `search` lines from
 *   resolv.conf, or — on macOS — whatever the configd resolver bundle supplies,
 *   including domains pushed by an active VPN).
 *
 *   Returns 0 on success. The result is empty (count=0) when no search list is
 *   configured.
 */
int ad_dns_search_list_copy(ad_dns_search_list_t *_Nonnull out);

void ad_dns_search_list_free(ad_dns_search_list_t *_Nonnull list);

#ifdef __cplusplus
}
#endif

#endif /* AD_DNS_H */
