import Foundation
import CLDAP

/// DNS-based discovery of Active Directory infrastructure.
///
/// Resolves the SRV records that Windows clients use to locate domain
/// controllers and Global Catalog servers in a forest. Works against any DNS
/// server that resolves the AD-published SRV records — typically the corporate
/// DNS provided over VPN.
public enum ADDiscovery {

    /// Locate domain controllers for a specific AD domain.
    ///
    /// Queries `_ldap._tcp.dc._msdcs.<domain>`, which AD publishes for every
    /// domain in a forest. Returns servers sorted by SRV priority (lowest first)
    /// and weight (highest first within a priority bucket).
    public static func domainControllers(domain: String) async throws -> [ADServer] {
        try await query(service: "_ldap._tcp.dc._msdcs.\(domain)", role: .domainController)
    }

    /// Locate Global Catalog servers for a forest.
    ///
    /// Queries `_gc._tcp.<forestRoot>`. The forest root is the top-level domain
    /// of the AD forest (the same name returned by `rootDomainNamingContext`
    /// in a DC's RootDSE). Pass any domain in the forest only if you do not
    /// know the root; callers that have already read the RootDSE should pass
    /// the discovered root directly.
    public static func globalCatalogs(forestRoot: String) async throws -> [ADServer] {
        try await query(service: "_gc._tcp.\(forestRoot)", role: .globalCatalog)
    }

    @concurrent
    private static func query(service: String, role: ADServer.Role) async throws -> [ADServer] {
        try service.withCString { serviceCStr -> [ADServer] in
            var result = ad_srv_result_t(records: nil, count: 0)
            var errPtr: UnsafeMutablePointer<CChar>?
            let rc = ad_srv_query(serviceCStr, &result, &errPtr)
            if rc != 0 {
                let message: String
                if let errPtr {
                    message = String(cString: errPtr)
                    ad_string_free(errPtr)
                } else {
                    message = "SRV query failed (\(rc))"
                }
                throw ADError.discoveryFailed(reason: message)
            }
            defer { ad_srv_result_free(&result) }

            var servers: [ADServer] = []
            servers.reserveCapacity(result.count)
            for i in 0..<result.count {
                let record = result.records![i]
                guard let targetPtr = record.target else { continue }
                let host = String(cString: targetPtr)
                servers.append(ADServer(host: host, port: Int(record.port), role: role))
            }
            return servers
        }
    }
}
