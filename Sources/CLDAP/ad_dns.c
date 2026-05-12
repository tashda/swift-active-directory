#include "ad_dns.h"

#include <resolv.h>
#include <stdlib.h>
#include <string.h>

int ad_dns_search_list_copy(ad_dns_search_list_t *out) {
    if (out == NULL) return -1;
    out->domains = NULL;
    out->count = 0;

    /* res_ninit initializes a per-call state and fills _u._ext.nsaddrs and dnsrch.
       On macOS the search list pulled here reflects whatever the resolver has
       picked up from /etc/resolv.conf, scutil bundles, and active VPN
       configurations — i.e. the same list `scutil --dns` would print. */
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) {
        return -1;
    }

    size_t count = 0;
    for (int i = 0; i < MAXDNSRCH && state.dnsrch[i] != NULL; i++) {
        if (state.dnsrch[i][0] == '\0') continue;
        count++;
    }

    if (count == 0) {
        res_ndestroy(&state);
        return 0;
    }

    char **domains = (char **)calloc(count + 1, sizeof(char *));
    if (domains == NULL) {
        res_ndestroy(&state);
        return -1;
    }

    size_t filled = 0;
    for (int i = 0; i < MAXDNSRCH && state.dnsrch[i] != NULL && filled < count; i++) {
        if (state.dnsrch[i][0] == '\0') continue;
        domains[filled] = strdup(state.dnsrch[i]);
        if (domains[filled] != NULL) filled++;
    }
    domains[filled] = NULL;

    out->domains = domains;
    out->count = filled;
    res_ndestroy(&state);
    return 0;
}

void ad_dns_search_list_free(ad_dns_search_list_t *list) {
    if (list == NULL || list->domains == NULL) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->domains[i]);
    }
    free(list->domains);
    list->domains = NULL;
    list->count = 0;
}
