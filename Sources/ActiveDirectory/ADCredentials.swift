import Foundation

public struct ADCredentials: Sendable, Hashable {

    public enum Method: Sendable, Hashable {
        /// Kerberos bind using explicit credentials. The package calls into GSS.framework to
        /// acquire a TGT for `user@DOMAIN` with the supplied password, then performs a
        /// SASL/GSSAPI LDAP bind. No domain-join or external `krb5.conf` required — the
        /// realm is configured from the domain string and KDCs are discovered via DNS SRV.
        case kerberos(domain: String, user: String, password: String)
        /// Reuse a TGT already present in the current login session's credential cache.
        /// Useful only on domain-bound Macs.
        case kerberosTicket
        /// LDAP simple bind. Sends the password in cleartext on plain transports; gated
        /// behind an explicit opt-in in the UI. Most modern AD installs reject this.
        case simple(distinguishedName: String, password: String)
    }

    public let method: Method

    public init(method: Method) {
        self.method = method
    }
}
