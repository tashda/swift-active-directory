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
    /// Tries every form Windows's DC locator would attempt before giving up,
    /// in roughly decreasing order of specificity:
    ///   1. literal `<domain>` if FQDN
    ///   2. each DNS search domain (covers NetBIOS short names whose DNS
    ///      suffix the VPN publishes via configd)
    ///   3. `<NetBIOS>.<search>` combinations (covers shops whose AD DNS root
    ///      is a subdomain *of* a search domain)
    ///   4. the plain `_ldap._tcp.<x>` form (some smaller AD installs don't
    ///      publish under `dc._msdcs`)
    public static func domainControllers(domain: String) async throws -> [ADServer] {
        var triedNames: [String] = []
        let candidates = candidateDomainNames(forUserInput: domain)

        for candidate in candidates {
            // Preferred: _ldap._tcp.dc._msdcs.<candidate>
            let preferred = "_ldap._tcp.dc._msdcs.\(candidate)"
            triedNames.append(preferred)
            if let dcs = try? await query(service: preferred, role: .domainController), !dcs.isEmpty {
                return dcs
            }
            // Fallback: _ldap._tcp.<candidate> (no dc._msdcs prefix)
            let fallback = "_ldap._tcp.\(candidate)"
            triedNames.append(fallback)
            if let dcs = try? await query(service: fallback, role: .domainController), !dcs.isEmpty {
                return dcs
            }
        }

        let triedList = triedNames.prefix(8).joined(separator: ", ")
        let more = triedNames.count > 8 ? " (+\(triedNames.count - 8) more)" : ""
        throw ADError.discoveryFailed(reason: "No SRV records found for any candidate name derived from '\(domain)' on this Mac's DNS resolvers. Tried: \(triedList)\(more). Either set the connection's domain to the AD DNS root (e.g. corp.example.com), or check that the VPN is delivering corporate DNS.")
    }

    /// Builds the list of domain names to attempt SRV discovery against. Public
    /// for unit testing — the production caller is `domainControllers(domain:)`.
    static func candidateDomainNames(forUserInput input: String) -> [String] {
        var candidates: [String] = []
        var seen: Set<String> = []

        func push(_ value: String) {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return }
            let lower = trimmed.lowercased()
            guard !seen.contains(lower) else { return }
            seen.insert(lower)
            candidates.append(trimmed)
        }

        let searchDomains = systemSearchDomains()

        if input.contains(".") {
            // User gave an FQDN — try it first, then any search domain it lives under.
            push(input)
            for search in searchDomains where input.lowercased().hasSuffix("." + search.lowercased()) {
                push(search)
            }
            for search in searchDomains { push(search) }
        } else {
            // NetBIOS short name. Prefer search domains whose leftmost label matches.
            let lowerInput = input.lowercased()
            for search in searchDomains where leftmostLabel(of: search).lowercased() == lowerInput {
                push(search)
            }
            // Then any other search domain.
            for search in searchDomains { push(search) }
            // Then nested forms: <netbios>.<search>
            for search in searchDomains {
                push("\(input).\(search)")
            }
            // Finally the literal input — last because we already know it's likely to fail.
            push(input)
        }

        return candidates
    }

    private static func leftmostLabel(of domain: String) -> String {
        domain.split(separator: ".").first.map(String.init) ?? domain
    }

    /// Locate Global Catalog servers for a forest. `forestRoot` must be the
    /// DNS-form name of the forest root (read from a DC's RootDSE).
    public static func globalCatalogs(forestRoot: String) async throws -> [ADServer] {
        try await query(service: "_gc._tcp.\(forestRoot)", role: .globalCatalog)
    }

    /// Returns the DNS search domains currently configured on this host —
    /// matches the `search domain[N]` output of `scutil --dns`, including
    /// any domains pushed by an active VPN.
    ///
    /// We read configd's resolver state via `scutil --dns` rather than the
    /// legacy `res_init`/`/etc/resolv.conf` path because on macOS the VPN-
    /// pushed search domains live per-interface in configd and never
    /// propagate to `/etc/resolv.conf`. Falls back to the libresolv list
    /// only if scutil fails for some reason.
    public static func systemSearchDomains() -> [String] {
        if let domains = scutilSearchDomains(), !domains.isEmpty {
            return domains
        }
        // Legacy fallback — pure resolv.conf, mostly empty on modern macOS.
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

    private static func scutilSearchDomains() -> [String]? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        process.arguments = ["--dns"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return nil
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else { return nil }

        var domains: [String] = []
        var seen: Set<String> = []
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Lines look like:  "search domain[0] : global.cashmgmt.net"
            guard trimmed.hasPrefix("search domain") else { continue }
            guard let colon = trimmed.firstIndex(of: ":") else { continue }
            let value = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty, !seen.contains(value) else { continue }
            seen.insert(value)
            domains.append(value)
        }
        return domains
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
