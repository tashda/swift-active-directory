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

    /// Lists every domain in this forest. Walks the partitions container in
    /// the configuration NC and keeps only crossRef entries whose
    /// `systemFlags` has `FLAG_CR_NTDS_DOMAIN` (0x00000002) set — that bit is
    /// the canonical "this NC is a real AD domain" marker, so schema /
    /// configuration / DNS zone partitions get filtered out automatically.
    /// We deliberately do NOT filter on `nETBIOSName=*` because the Global
    /// Catalog's partial attribute set occasionally drops it.
    ///
    /// Returns the full triple (DNS root, NetBIOS short name, naming context
    /// DN) for each domain so callers can pick the right form for whatever
    /// they're feeding — SQL Server `CREATE LOGIN` wants the NetBIOS form,
    /// Kerberos wants the DNS root, LDAP wants the DN.
    public func listForestDomains() throws -> [ADDomain] {
        guard let ptr = sessionPointer() else { throw ADError.notBound }
        let dse = try readRootDSE()
        guard let configNC = dse.configurationNamingContext else { return [] }

        let partitionsDN = "CN=Partitions,\(configNC)"
        let filter = "(objectClass=crossRef)"
        let attributes: [String] = ["nCName", "nETBIOSName", "dnsRoot", "systemFlags"]

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

                    return ADClient.decodeDomains(from: &result)
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

    fileprivate static func decodeDomains(from result: inout ad_search_result_t) -> [ADDomain] {
        guard let entries = result.entries else { return [] }
        var out: [ADDomain] = []
        for i in 0..<result.entry_count {
            let entry = entries[i]
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

            // FLAG_CR_NTDS_DOMAIN = 0x00000002 marks an AD domain partition.
            // Non-domain partitions (schema, configuration, ForestDnsZones,
            // DomainDnsZones) lack this bit.
            let flagsString = attrs["systemflags"]?.first.flatMap { String(data: $0, encoding: .utf8) } ?? "0"
            let flags = Int(flagsString) ?? 0
            guard (flags & 0x00000002) != 0 else { continue }

            let dnsRoot = attrs["dnsroot"]?.first.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let netBIOSName = attrs["netbiosname"]?.first.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let ncName = attrs["ncname"]?.first.flatMap { String(data: $0, encoding: .utf8) } ?? ""

            guard !ncName.isEmpty else { continue }
            out.append(ADDomain(
                dnsRoot: dnsRoot,
                netBIOSName: netBIOSName,
                namingContext: ncName
            ))
        }
        return out.sorted { $0.dnsRoot.localizedCaseInsensitiveCompare($1.dnsRoot) == .orderedAscending }
    }
}
