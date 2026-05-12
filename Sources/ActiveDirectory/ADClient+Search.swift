import Foundation
import CLDAP

extension ADClient {

    public struct RootDSE: Sendable, Hashable {
        public let rootDomainNamingContext: String?
        public let configurationNamingContext: String?
        public let defaultNamingContext: String?

        /// Forest root in DNS form (`corp.example.com`), derived from the
        /// `rootDomainNamingContext` DN. Returns nil if the DN was missing
        /// or malformed.
        public var forestRoot: String? {
            guard let dn = rootDomainNamingContext else { return nil }
            return ADClient.domainFromDN(dn)
        }
    }

    public func readRootDSE() throws -> RootDSE {
        guard let ptr = sessionPointer() else { throw ADError.notBound }
        var rootNC: UnsafeMutablePointer<CChar>?
        var configNC: UnsafeMutablePointer<CChar>?
        var defaultNC: UnsafeMutablePointer<CChar>?
        var errPtr: UnsafeMutablePointer<CChar>?

        let rc = ad_session_read_root_dse(ptr, &rootNC, &configNC, &defaultNC, &errPtr)
        if rc != 0 {
            let message = errPtr.map { String(cString: $0) } ?? "RootDSE read failed (\(rc))"
            if let e = errPtr { ad_string_free(e) }
            throw ADError.searchFailed(code: rc, reason: message)
        }

        let result = RootDSE(
            rootDomainNamingContext: rootNC.map { String(cString: $0) },
            configurationNamingContext: configNC.map { String(cString: $0) },
            defaultNamingContext: defaultNC.map { String(cString: $0) }
        )
        rootNC.map { ad_string_free($0) }
        configNC.map { ad_string_free($0) }
        defaultNC.map { ad_string_free($0) }
        return result
    }

    public func search(_ query: ADSearchQuery) throws -> ADClient.SearchOutcome {
        guard let ptr = sessionPointer() else { throw ADError.notBound }

        let baseDN = try resolveBaseDN(for: query.scope)
        let filter = ADClient.buildFilter(query.filter)
        let attributes: [String] = [
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "objectClass",
            "objectSid",
        ]

        return try attributes.withCStringArray { attrPtrs in
            try filter.withCString { filterCStr in
                try baseDN.withCString { baseCStr in
                    var result = ad_search_result_t(entries: nil, entry_count: 0, size_limit_exceeded: 0)
                    var errPtr: UnsafeMutablePointer<CChar>?

                    let rc = ad_session_search(
                        ptr,
                        baseCStr,
                        filterCStr,
                        attrPtrs,
                        Int32(query.maxResults),
                        30,
                        &result,
                        &errPtr
                    )
                    if rc != 0 {
                        let message = errPtr.map { String(cString: $0) } ?? "search failed (\(rc))"
                        if let e = errPtr { ad_string_free(e) }
                        throw ADError.searchFailed(code: rc, reason: message)
                    }
                    defer { ad_search_result_free(&result) }

                    let principals = ADClient.decodePrincipals(from: &result)
                    return SearchOutcome(
                        principals: principals,
                        truncated: result.size_limit_exceeded != 0
                    )
                }
            }
        }
    }

    public struct SearchOutcome: Sendable, Hashable {
        public let principals: [ADPrincipal]
        public let truncated: Bool
    }

    // MARK: - Internals


    private func resolveBaseDN(for scope: ADClient.Scope) throws -> String {
        switch scope {
        case let .domain(domain):
            return ADClient.dnFromDomain(domain)
        case .forest:
            // The picker resolves forestRoot via RootDSE before issuing forest-scope queries,
            // but pass through here too in case the caller already supplied a full DN.
            // For .forest scope we expect the server to be a Global Catalog and the base DN
            // to be the forest root DN. Caller must have set this up via openForestCatalog().
            let dse = try readRootDSE()
            guard let nc = dse.rootDomainNamingContext else {
                throw ADError.discoveryFailed(reason: "RootDSE missing rootDomainNamingContext")
            }
            return nc
        }
    }

    // Test hooks — exposed for ActiveDirectoryTests; do not call from production code.
    public static func _escapeFilterText_forTesting(_ raw: String) -> String { escapeFilterText(raw) }
    public static func _buildFilter_forTesting(_ filter: ADSearchQuery.Filter) -> String { buildFilter(filter) }
    public static func _dnFromDomain_forTesting(_ domain: String) -> String { dnFromDomain(domain) }
    public static func _domainFromDN_forTesting(_ dn: String) -> String { domainFromDN(dn) }

    fileprivate static func buildFilter(_ filter: ADSearchQuery.Filter) -> String {
        var classClauses: [String] = []
        if filter.includeUsers {
            classClauses.append("(&(objectCategory=person)(objectClass=user))")
        }
        if filter.includeGroups {
            classClauses.append("(objectCategory=group)")
        }
        if filter.includeComputers {
            classClauses.append("(objectCategory=computer)")
        }
        if filter.includeOrganizationalUnits {
            classClauses.append("(objectCategory=organizationalUnit)")
        }
        let classFilter: String
        if classClauses.isEmpty {
            classFilter = "(objectClass=*)"
        } else if classClauses.count == 1 {
            classFilter = classClauses[0]
        } else {
            classFilter = "(|\(classClauses.joined()))"
        }

        let trimmed = filter.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return classFilter }

        let escaped = escapeFilterText(trimmed)
        let textFilter = "(|(sAMAccountName=*\(escaped)*)(displayName=*\(escaped)*)(userPrincipalName=*\(escaped)*))"
        return "(&\(classFilter)\(textFilter))"
    }

    /// RFC 4515 filter escaping.
    fileprivate static func escapeFilterText(_ raw: String) -> String {
        var out = ""
        out.reserveCapacity(raw.count)
        for scalar in raw.unicodeScalars {
            switch scalar {
            case "\\": out += "\\5c"
            case "*":  out += "\\2a"
            case "(":  out += "\\28"
            case ")":  out += "\\29"
            case "\0": out += "\\00"
            default:
                if scalar.isASCII {
                    out.append(Character(scalar))
                } else {
                    for byte in String(scalar).utf8 {
                        out += String(format: "\\%02x", byte)
                    }
                }
            }
        }
        return out
    }

    /// Converts a DNS-style AD domain ("corp.example.com") to a DN ("DC=corp,DC=example,DC=com").
    fileprivate static func dnFromDomain(_ domain: String) -> String {
        domain.split(separator: ".")
            .map { "DC=\($0)" }
            .joined(separator: ",")
    }

    /// Extracts the DNS-style domain from a DN. "DC=corp,DC=example,DC=com" → "corp.example.com".
    fileprivate static func domainFromDN(_ dn: String) -> String {
        let parts = dn
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.lowercased().hasPrefix("dc=") }
            .map { String($0.dropFirst(3)) }
        return parts.joined(separator: ".")
    }

    fileprivate static func decodePrincipals(from result: inout ad_search_result_t) -> [ADPrincipal] {
        guard let entries = result.entries else { return [] }
        var out: [ADPrincipal] = []
        out.reserveCapacity(result.entry_count)

        for i in 0..<result.entry_count {
            let entry = entries[i]
            guard let dnPtr = entry.dn else { continue }
            let dn = String(cString: dnPtr)

            var attrs: [String: [Data]] = [:]
            if let ap = entry.attributes {
                for j in 0..<entry.attribute_count {
                    let attr = ap[j]
                    guard let namePtr = attr.name else { continue }
                    let name = String(cString: namePtr)
                    var values: [Data] = []
                    if let vp = attr.values {
                        for k in 0..<attr.value_count {
                            let value = vp[k]
                            if let data = value.data, value.length > 0 {
                                values.append(Data(bytes: data, count: value.length))
                            } else {
                                values.append(Data())
                            }
                        }
                    }
                    attrs[name] = values
                }
            }

            func string(_ key: String) -> String? {
                attrs[key]?.first.flatMap { String(data: $0, encoding: .utf8) }
            }

            let sam = string("sAMAccountName") ?? dn
            let principal = ADPrincipal(
                sAMAccountName: sam,
                userPrincipalName: string("userPrincipalName"),
                displayName: string("displayName"),
                distinguishedName: dn,
                objectClass: ADPrincipal.ObjectClass.fromValues(attrs["objectClass"] ?? []),
                objectSID: attrs["objectSid"]?.first,
                domain: domainFromDN(dn)
            )
            out.append(principal)
        }
        return out
    }
}

extension ADPrincipal.ObjectClass {
    fileprivate static func fromValues(_ values: [Data]) -> ADPrincipal.ObjectClass {
        let strings = values.compactMap { String(data: $0, encoding: .utf8) }
        // AD entries have a chain like ["top", "person", "organizationalPerson", "user"].
        // The most specific class is the last one.
        if strings.contains("computer") { return .computer }
        if strings.contains("group") { return .group }
        if strings.contains("organizationalUnit") { return .organizationalUnit }
        if strings.contains("user") { return .user }
        return .other(strings.last ?? "unknown")
    }
}

private extension Array where Element == String {
    /// Bridges `[String]` to a NULL-terminated `UnsafePointer<UnsafePointer<CChar>?>?` for C APIs.
    func withCStringArray<R>(_ body: (UnsafeMutablePointer<UnsafePointer<CChar>?>) throws -> R) rethrows -> R {
        var cStrings: [UnsafePointer<CChar>?] = self.map { ($0 as NSString).utf8String }
        cStrings.append(nil)
        return try cStrings.withUnsafeMutableBufferPointer { buffer in
            try body(buffer.baseAddress!)
        }
    }
}
