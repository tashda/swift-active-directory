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
    /// Discovers a DC for `anyDomainInForest`, binds with `credentials`, reads
    /// the forest root from RootDSE, discovers a Global Catalog for that root,
    /// and binds the GC. Returns a ready-to-search ADClient plus the resolved
    /// forest metadata.
    public static func openForestCatalog(
        anyDomainInForest domain: String,
        credentials: ADCredentials,
        transport: ADClient.Transport = .plain
    ) async throws -> ForestSession {
        // 1. Find a DC for the user's domain.
        let dcs = try await ADDiscovery.domainControllers(domain: domain)
        guard let dc = dcs.first else {
            throw ADError.discoveryFailed(reason: "No domain controllers found for \(domain)")
        }

        // 2. Bind it just long enough to read RootDSE.
        let dcClient = try ADClient(server: dc, transport: transport)
        try await dcClient.bind(credentials)
        let dse = try await dcClient.readRootDSE()
        await dcClient.close()

        guard let rootNC = dse.rootDomainNamingContext,
              let forestRoot = dse.forestRoot else {
            throw ADError.discoveryFailed(reason: "RootDSE missing rootDomainNamingContext on \(dc.host)")
        }

        // 3. Find a Global Catalog for the forest root.
        let gcs = try await ADDiscovery.globalCatalogs(forestRoot: forestRoot)
        guard let gc = gcs.first else {
            throw ADError.discoveryFailed(reason: "No global catalogs found for forest \(forestRoot)")
        }
        // GCs listen on port 3268 (plain) / 3269 (LDAPS) regardless of what the SRV record
        // claims, but trust the SRV record — AD always publishes the right port.

        // 4. Bind the GC.
        let gcClient = try ADClient(server: gc, transport: transport)
        try await gcClient.bind(credentials)

        return ForestSession(
            client: gcClient,
            forestRoot: forestRoot,
            rootDomainNamingContext: rootNC
        )
    }

    /// Opens a DC connection for a single-domain search. Skips the GC hop.
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
}
