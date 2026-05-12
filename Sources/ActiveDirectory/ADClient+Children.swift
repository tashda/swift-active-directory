import Foundation
import CLDAP

extension ADClient {

    /// Lists the immediate children of an LDAP container — domains, OUs, and
    /// the built-in CN= containers (Users, Computers, Builtin, Domain
    /// Controllers, …). Used to populate the picker's tree-browser sidebar
    /// one level at a time.
    public func listChildren(of baseDN: String) throws -> [ADContainer] {
        guard let ptr = sessionPointer() else { throw ADError.notBound }

        let filter = "(|(objectCategory=organizationalUnit)(objectCategory=container)(objectCategory=builtinDomain)(objectClass=domain)(objectClass=domainDNS))"
        let attributes: [String] = [
            "objectClass",
            "objectCategory",
            "name",
            "ou",
            "cn",
            "dc",
            "distinguishedName",
        ]

        return try attributes.withCStringArray { attrPtrs in
            try filter.withCString { filterCStr in
                try baseDN.withCString { baseCStr in
                    var result = ad_search_result_t(entries: nil, entry_count: 0, size_limit_exceeded: 0)
                    var errPtr: UnsafeMutablePointer<CChar>?

                    let rc = ad_session_search(
                        ptr,
                        baseCStr,
                        AD_SCOPE_ONE_LEVEL,
                        filterCStr,
                        attrPtrs,
                        500,
                        15,
                        &result,
                        &errPtr
                    )
                    if rc != 0 {
                        let message = errPtr.map { String(cString: $0) } ?? "listChildren failed (\(rc))"
                        if let e = errPtr { ad_string_free(e) }
                        throw ADError.searchFailed(code: rc, reason: message)
                    }
                    defer { ad_search_result_free(&result) }

                    return ADClient.decodeContainers(from: &result)
                }
            }
        }
    }

    /// Lists the child domains in this forest (read from the partitions
    /// container in the configuration NC). Returns the DNS-form domain
    /// names of every NC of objectClass `crossRef` whose `nETBIOSName` is set
    /// — these are the real Windows-AD domains. Synthetic NCs (schema,
    /// configuration, ForestDnsZones, DomainDnsZones) are filtered out.
    public func listForestDomains() throws -> [String] {
        guard let ptr = sessionPointer() else { throw ADError.notBound }
        let dse = try readRootDSE()
        guard let configNC = dse.configurationNamingContext else { return [] }

        let partitionsDN = "CN=Partitions,\(configNC)"
        let filter = "(&(objectClass=crossRef)(nETBIOSName=*))"
        let attributes: [String] = ["nCName", "nETBIOSName", "dnsRoot"]

        return try attributes.withCStringArray { attrPtrs in
            try filter.withCString { filterCStr in
                try partitionsDN.withCString { baseCStr in
                    var result = ad_search_result_t(entries: nil, entry_count: 0, size_limit_exceeded: 0)
                    var errPtr: UnsafeMutablePointer<CChar>?
                    let rc = ad_session_search(
                        ptr,
                        baseCStr,
                        AD_SCOPE_ONE_LEVEL,
                        filterCStr,
                        attrPtrs,
                        50,
                        10,
                        &result,
                        &errPtr
                    )
                    if rc != 0 {
                        let message = errPtr.map { String(cString: $0) } ?? "listForestDomains failed (\(rc))"
                        if let e = errPtr { ad_string_free(e) }
                        throw ADError.searchFailed(code: rc, reason: message)
                    }
                    defer { ad_search_result_free(&result) }

                    return ADClient.decodeDNSRoots(from: &result)
                }
            }
        }
    }

    // MARK: - Decoders

    fileprivate static func decodeContainers(from result: inout ad_search_result_t) -> [ADContainer] {
        guard let entries = result.entries else { return [] }
        var out: [ADContainer] = []
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
                    let name = String(cString: namePtr).lowercased()
                    var values: [Data] = []
                    if let vp = attr.values {
                        for k in 0..<attr.value_count {
                            let value = vp[k]
                            if let data = value.data, value.length > 0 {
                                values.append(Data(bytes: data, count: value.length))
                            }
                        }
                    }
                    attrs[name] = values
                }
            }

            let classStrings = (attrs["objectclass"] ?? []).compactMap { String(data: $0, encoding: .utf8) }
            let kind: ADContainer.Kind
            if classStrings.contains("organizationalUnit") {
                kind = .organizationalUnit
            } else if classStrings.contains("domainDNS") || classStrings.contains("domain") {
                kind = .domain
            } else if classStrings.contains("container") || classStrings.contains("builtinDomain") {
                kind = .container
            } else {
                kind = .other(classStrings.last ?? "unknown")
            }

            let displayName: String
            if let ouData = attrs["ou"]?.first, let s = String(data: ouData, encoding: .utf8), !s.isEmpty {
                displayName = s
            } else if let cnData = attrs["cn"]?.first, let s = String(data: cnData, encoding: .utf8), !s.isEmpty {
                displayName = s
            } else if let dcData = attrs["dc"]?.first, let s = String(data: dcData, encoding: .utf8), !s.isEmpty {
                displayName = s
            } else if let nameData = attrs["name"]?.first, let s = String(data: nameData, encoding: .utf8), !s.isEmpty {
                displayName = s
            } else {
                displayName = dn
            }

            out.append(ADContainer(distinguishedName: dn, displayName: displayName, kind: kind))
        }

        return out.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    fileprivate static func decodeDNSRoots(from result: inout ad_search_result_t) -> [String] {
        guard let entries = result.entries else { return [] }
        var out: [String] = []
        for i in 0..<result.entry_count {
            let entry = entries[i]
            guard let ap = entry.attributes else { continue }
            for j in 0..<entry.attribute_count {
                let attr = ap[j]
                guard let namePtr = attr.name else { continue }
                let name = String(cString: namePtr).lowercased()
                guard name == "dnsroot" else { continue }
                if let vp = attr.values, attr.value_count > 0,
                   let data = vp[0].data, vp[0].length > 0 {
                    if let s = String(data: Data(bytes: data, count: vp[0].length), encoding: .utf8) {
                        out.append(s)
                    }
                }
            }
        }
        return out.sorted()
    }
}
