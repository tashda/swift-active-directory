#ifndef AD_SRV_H
#define AD_SRV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *_Nullable target;   /* heap-allocated hostname; free with ad_string_free */
    uint16_t port;
    uint16_t priority;
    uint16_t weight;
} ad_srv_record_t;

typedef struct {
    ad_srv_record_t *_Nullable records;
    size_t count;
} ad_srv_result_t;

/*
 * ad_srv_query
 *   Performs a synchronous DNS SRV query for `service` (e.g.
 *   "_ldap._tcp.dc._msdcs.corp.example.com").
 *
 *   Returns 0 on success and populates *out with a heap-allocated array of
 *   records sorted by priority then weight (lowest priority first). The
 *   caller frees the result with ad_srv_result_free.
 *
 *   On failure returns a non-zero error code (matches the h_errno value
 *   from res_query) and writes a diagnostic string into *err_out.
 */
int ad_srv_query(
    const char *_Nonnull service,
    ad_srv_result_t *_Nonnull out,
    char *_Nullable *_Nullable err_out
);

void ad_srv_result_free(ad_srv_result_t *_Nonnull result);

#ifdef __cplusplus
}
#endif

#endif /* AD_SRV_H */
