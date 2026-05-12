import Foundation

/// Browses Active Directory users and groups, forest-wide or scoped to one domain.
///
/// `ADClient` wraps the system LDAP client with SASL/GSSAPI (Kerberos)
/// authentication. It is designed to run from non-domain-joined macOS clients
/// reaching a domain over VPN, and does not require TLS on the wire — Kerberos
/// negotiates LDAP signing for integrity protection on plain port 389/3268.
public actor ADClient {

    public enum Transport: Sendable, Hashable {
        /// Plain LDAP on the supplied port (389 for a DC, 3268 for a Global Catalog).
        /// SASL/GSSAPI is required on this transport; LDAP signing is negotiated automatically.
        case plain(port: Int)
        /// LDAPS — TLS wraps the LDAP traffic. 636 for a DC, 3269 for a Global Catalog.
        case ldaps(port: Int, trust: TrustPolicy)
        /// StartTLS on the plain port. Reserved for a future revision.
        case startTLS(port: Int, trust: TrustPolicy)
    }

    public enum TrustPolicy: Sendable, Hashable {
        case system
        case acceptAny
        case pinned(certificateSHA256: Data)
    }

    public enum Scope: Sendable, Hashable {
        /// Search a single domain via one of its DCs.
        case domain(String)
        /// Search the entire forest via a Global Catalog. Pass any domain in the forest;
        /// the forest root is discovered from the GC's RootDSE.
        case forest(anyDomainInForest: String)
    }

    public init() {
        // Implementation lands in step 2 (Kerberos bind).
    }
}
