#include "ad_srv.h"
#include "ad_bind.h"

#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/in.h>
#include <netdb.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NS_PACKETSZ
#define NS_PACKETSZ PACKETSZ
#endif

#define AD_SRV_ANSWER_BUF 8192

static int srv_compare(const void *a, const void *b) {
    const ad_srv_record_t *ra = (const ad_srv_record_t *)a;
    const ad_srv_record_t *rb = (const ad_srv_record_t *)b;
    if (ra->priority != rb->priority) {
        return (ra->priority < rb->priority) ? -1 : 1;
    }
    /* Higher weight first within a priority bucket. */
    if (ra->weight != rb->weight) {
        return (ra->weight > rb->weight) ? -1 : 1;
    }
    return 0;
}

static char *ad_srv_format_error(const char *prefix, int code) {
    const char *detail;
    switch (code) {
        case HOST_NOT_FOUND: detail = "host not found (NXDOMAIN)"; break;
        case TRY_AGAIN:      detail = "DNS server temporary failure"; break;
        case NO_RECOVERY:    detail = "DNS server non-recoverable error"; break;
        case NO_DATA:        detail = "no SRV records published"; break;
        default:             detail = "unknown DNS error"; break;
    }
    size_t needed = strlen(prefix) + strlen(detail) + 16;
    char *buf = (char *)malloc(needed);
    if (buf == NULL) return NULL;
    snprintf(buf, needed, "%s: %s (h_errno=%d)", prefix, detail, code);
    return buf;
}

int ad_srv_query(const char *service, ad_srv_result_t *out, char **err_out) {
    if (err_out) *err_out = NULL;
    if (service == NULL || out == NULL) return -1;
    out->records = NULL;
    out->count = 0;

    unsigned char answer[AD_SRV_ANSWER_BUF];
    int len = res_query(service, ns_c_in, ns_t_srv, answer, sizeof(answer));
    if (len < 0) {
        if (err_out) *err_out = ad_srv_format_error("res_query", h_errno);
        return h_errno != 0 ? h_errno : -1;
    }

    ns_msg msg;
    if (ns_initparse(answer, len, &msg) < 0) {
        if (err_out) *err_out = ad_srv_format_error("ns_initparse", h_errno);
        return -1;
    }

    int count = ns_msg_count(msg, ns_s_an);
    if (count <= 0) {
        return 0; /* zero records is success with empty result */
    }

    ad_srv_record_t *records = (ad_srv_record_t *)calloc((size_t)count, sizeof(ad_srv_record_t));
    if (records == NULL) {
        if (err_out) *err_out = ad_srv_format_error("calloc", 0);
        return -1;
    }

    size_t filled = 0;
    for (int i = 0; i < count; i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_srv) continue;

        const unsigned char *rd = ns_rr_rdata(rr);
        if (ns_rr_rdlen(rr) < 6) continue;

        uint16_t priority = (uint16_t)((rd[0] << 8) | rd[1]);
        uint16_t weight   = (uint16_t)((rd[2] << 8) | rd[3]);
        uint16_t port     = (uint16_t)((rd[4] << 8) | rd[5]);

        char target[NS_MAXDNAME];
        int n = dn_expand(ns_msg_base(msg), ns_msg_end(msg), rd + 6, target, sizeof(target));
        if (n < 0) continue;

        size_t tlen = strlen(target);
        /* Strip the trailing dot that dn_expand leaves on some systems. */
        if (tlen > 0 && target[tlen - 1] == '.') target[tlen - 1] = '\0';

        records[filled].target = strdup(target);
        records[filled].priority = priority;
        records[filled].weight = weight;
        records[filled].port = port;
        filled++;
    }

    if (filled == 0) {
        free(records);
        return 0;
    }

    qsort(records, filled, sizeof(ad_srv_record_t), srv_compare);
    out->records = records;
    out->count = filled;
    return 0;
}

void ad_srv_result_free(ad_srv_result_t *result) {
    if (result == NULL) return;
    for (size_t i = 0; i < result->count; i++) {
        free(result->records[i].target);
    }
    free(result->records);
    result->records = NULL;
    result->count = 0;
}
