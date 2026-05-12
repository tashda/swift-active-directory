# swift-active-directory

Active Directory browser client for macOS. Provides forest-wide search of users
and groups via the Global Catalog, using Kerberos (SASL/GSSAPI) authentication
without requiring the Mac to be domain-joined.

Used by [Echo](https://github.com/tashda/echo) to back the "Browse…" picker on
Windows-authenticated SQL Server logins and users.

## Requirements

- macOS 13+
- Network reachability to the target forest's DCs and Global Catalogs (typically
  TCP 389, 636, 3268, 3269, and 88 for Kerberos).

## Authentication modes

1. **Kerberos / GSSAPI** (default) — explicit `domain\\user` + password is used
   to acquire a TGT in-process via `GSS.framework`; the TGT then performs a
   SASL/GSSAPI LDAP bind. Works on non-domain-joined Macs.
2. **LDAPS simple bind** — fallback when Kerberos is unreachable. Requires a
   trust decision for self-signed / internal-CA certificates.
3. **Plain simple bind** — opt-in only. Sends the password in cleartext and is
   rejected by most modern AD installs (LDAP signing enforcement).

## Status

In development. The public API surface in `ADClient` is the stable
contract; underlying implementation is being built out incrementally.
