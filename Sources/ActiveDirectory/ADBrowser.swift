import Foundation

/// High-level convenience for the common AD-browsing flows.
///
/// The picker UI in Echo uses these helpers to open a Global Catalog session
/// for forest-wide search, or a Domain Controller session for a single-domain
/// search, without needing to orchestrate DNS discovery + RootDSE + GC bind
/// itself.
public enum ADBrowser {

    public struct ForestSession: Sendable {
        public let client: ADClient
        public let forestRoot: String
        public let rootDomainNamingContext: String
    }

    /// Opens a Global Catalog connection suitable for forest-wide searches.
    ///
    /// Discovers a DC for `anyDomainInForest` (NetBIOS or DNS form), binds with
    /// `credentials`, reads the forest root from RootDSE, discovers a Global
    /// Catalog for that root, and binds the GC. Returns a ready-to-search
    /// ADClient plus the resolved forest metadata.
    ///
    /// If the supplied `domain` is a NetBIOS short name (no dots), the
    /// effective Kerberos realm is derived from the discovered DC's hostname
    /// suffix — necessary because Kerberos KDC discovery is by DNS, and a
    /// NetBIOS realm name does not resolve.
    public static func openForestCatalog(
        anyDomainInForest domain: String,
        credentials: ADCredentials,
        transport: ADClient.Transport = .plain
    ) async throws -> ForestSession {
        let dcs = try await ADDiscovery.domainControllers(domain: domain)
        guard let dc = dcs.first else {
            throw ADError.discoveryFailed(reason: "No domain controllers found for \(domain)")
        }

        let realm = effectiveRealm(userInput: domain, discoveredDCHost: dc.host)
        let effectiveCredentials = rewrite(credentials: credentials, withDomain: realm)

        let dcClient = try ADClient(server: dc, transport: transport)
        try await dcClient.bind(effectiveCredentials)
        let dse = try await dcClient.readRootDSE()
        await dcClient.close()

        guard let rootNC = dse.rootDomainNamingContext,
              let forestRoot = dse.forestRoot else {
            throw ADError.discoveryFailed(reason: "RootDSE missing rootDomainNamingContext on \(dc.host)")
        }

        let gcs = try await ADDiscovery.globalCatalogs(forestRoot: forestRoot)
        guard let gc = gcs.first else {
            throw ADError.discoveryFailed(reason: "No global catalogs found for forest \(forestRoot)")
        }

        let gcClient = try ADClient(server: gc, transport: transport)
        try await gcClient.bind(effectiveCredentials)

        return ForestSession(
            client: gcClient,
            forestRoot: forestRoot,
            rootDomainNamingContext: rootNC
        )
    }

    /// Opens a DC connection for a single-domain search. Skips the GC hop.
    ///
    /// **Cross-realm friendly:** the `credentials` passed here MUST have a
    /// `domain` set to the user's *home* Kerberos realm — the realm where
    /// their password is actually valid. If `domain` here points at a
    /// trusted external domain, Heimdal uses cross-realm referrals through
    /// the trust to acquire a service ticket for that domain's DC. The
    /// caller is responsible for not "rewriting" credentials to the target
    /// domain (that would try to authenticate to the wrong KDC and fail
    /// with `Client unknown`).
    public static func openDomainController(
        domain: String,
        credentials: ADCredentials,
        transport: ADClient.Transport = .plain
    ) async throws -> ADClient {
        let dcs = try await ADDiscovery.domainControllers(domain: domain)
        guard let dc = dcs.first else {
            throw ADError.discoveryFailed(reason: "No domain controllers found for \(domain)")
        }
        let client = try ADClient(server: dc, transport: transport)
        try await client.bind(credentials)
        return client
    }

    // MARK: - Realm resolution

    /// If the user typed a DNS-form domain we keep it. If they typed a NetBIOS
    /// short name, we use the discovered DC's parent zone — that's the actual
    /// Kerberos realm.
    static func effectiveRealm(userInput: String, discoveredDCHost: String) -> String {
        if userInput.contains(".") { return userInput }
        let parts = discoveredDCHost.split(separator: ".")
        guard parts.count >= 2 else { return userInput }
        return parts.dropFirst().joined(separator: ".")
    }

    private static func rewrite(credentials: ADCredentials, withDomain newDomain: String) -> ADCredentials {
        switch credentials.method {
        case let .kerberos(_, user, password):
            return ADCredentials(method: .kerberos(domain: newDomain, user: user, password: password))
        case .kerberosTicket, .simple:
            return credentials
        }
    }
}
