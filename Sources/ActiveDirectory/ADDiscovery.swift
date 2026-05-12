import Foundation
import CLDAP

/// DNS-based discovery of Active Directory infrastructure.
///
/// Resolves the SRV records that Windows clients use to locate domain
/// controllers and Global Catalog servers in a forest. Works against any DNS
/// server that resolves the AD-published SRV records — typically the corporate
/// DNS provided over VPN.
public enum ADDiscovery {

    /// Locate domain controllers for an AD domain.
    ///
    /// If `domain` is a DNS-form name (contains a dot), the SRV record is
    /// queried directly. If it is a NetBIOS short name, the resolver's
    /// configured search domains are tried in turn — this matches what
    /// Windows's DC locator does on a non-domain-joined client.
    public static func domainControllers(domain: String) async throws -> [ADServer] {
        if domain.contains(".") {
            return try await query(service: "_ldap._tcp.dc._msdcs.\(domain)", role: .domainController)
        }

        let searchDomains = systemSearchDomains()
        var attempts: [(String, Error)] = []
        for candidate in searchDomains {
            do {
                let dcs = try await query(service: "_ldap._tcp.dc._msdcs.\(candidate)", role: .domainController)
                if !dcs.isEmpty { return dcs }
            } catch {
                attempts.append((candidate, error))
            }
        }

        let detail: String
        if searchDomains.isEmpty {
            detail = "DNS lookup for '\(domain)' returned no SRV records and this Mac has no DNS search domains configured. Either set the connection's domain to the AD DNS root (e.g. corp.example.com) or ensure the VPN is publishing search domains."
        } else {
            let triedList = searchDomains.joined(separator: ", ")
            detail = "Neither '\(domain)' nor any DNS search domain on this Mac (tried: \(triedList)) published SRV records for an AD domain controller. Set the connection's domain to the AD DNS root (e.g. corp.example.com)."
        }
        throw ADError.discoveryFailed(reason: detail)
    }

    /// Locate Global Catalog servers for a forest. `forestRoot` must be the
    /// DNS-form name of the forest root (read from a DC's RootDSE).
    public static func globalCatalogs(forestRoot: String) async throws -> [ADServer] {
        try await query(service: "_gc._tcp.\(forestRoot)", role: .globalCatalog)
    }

    /// Returns the DNS search domains currently configured on this host —
    /// matches the `search` line output of `scutil --dns`, including any
    /// domains pushed by an active VPN.
    public static func systemSearchDomains() -> [String] {
        var list = ad_dns_search_list_t(domains: nil, count: 0)
        guard ad_dns_search_list_copy(&list) == 0 else { return [] }
        defer { ad_dns_search_list_free(&list) }
        guard let ptr = list.domains else { return [] }
        var out: [String] = []
        out.reserveCapacity(list.count)
        for i in 0..<list.count {
            guard let cstr = ptr[i] else { continue }
            out.append(String(cstr: cstr))
        }
        return out
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

private extension String {
    init(cstr: UnsafePointer<CChar>) {
        self.init(cString: cstr)
    }
}
