#ifndef AD_BIND_H
#define AD_BIND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ad_session ad_session_t;

/*
 * ad_session_open
 *   Allocates an LDAP session handle bound to a URI like "ldap://host:port".
 *   Sets LDAP protocol version 3, disables referrals (we follow them manually
 *   via the global catalog), and pre-binds the SASL options needed for
 *   GSSAPI. The session is *not* yet bound — call ad_session_bind_kerberos
 *   or ad_session_bind_simple next.
 *
 *   On failure returns NULL and writes a heap-allocated error message into
 *   *err_out (caller must free with ad_string_free).
 */
ad_session_t *_Nullable ad_session_open(
    const char *_Nonnull uri,
    char *_Nullable *_Nullable err_out
);

/*
 * ad_session_bind_kerberos
 *   Acquires a Kerberos TGT for `user@REALM` via GSS.framework using the
 *   supplied password (no krb5.conf required — Heimdal resolves the KDC via
 *   DNS SRV records `_kerberos._tcp.<realm>`), then performs an LDAP
 *   SASL/GSSAPI bind on the session.
 *
 *   `realm` must be the uppercase AD domain name, e.g. "CORP.EXAMPLE.COM".
 *   `user` is the sAMAccountName without domain prefix, e.g. "jdoe".
 *
 *   Returns 0 on success, non-zero on failure with *err_out populated.
 */
int ad_session_bind_kerberos(
    ad_session_t *_Nonnull session,
    const char *_Nonnull user,
    const char *_Nonnull realm,
    const char *_Nonnull password,
    char *_Nullable *_Nullable err_out
);

/*
 * ad_session_bind_simple
 *   Plain LDAP simple bind. Sends the password in cleartext on plain
 *   transports — caller is responsible for restricting this to LDAPS or
 *   explicitly opted-in plain transport.
 */
int ad_session_bind_simple(
    ad_session_t *_Nonnull session,
    const char *_Nonnull bind_dn,
    const char *_Nonnull password,
    char *_Nullable *_Nullable err_out
);

/*
 * ad_session_close
 *   Unbinds and frees the session.
 */
void ad_session_close(ad_session_t *_Nonnull session);

/*
 * ad_string_free
 *   Frees a heap string returned by an ad_* function (error messages,
 *   future result attribute values).
 */
void ad_string_free(char *_Nullable str);

#ifdef __cplusplus
}
#endif

#endif /* AD_BIND_H */
