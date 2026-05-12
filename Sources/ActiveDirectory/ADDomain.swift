import Foundation

/// A single Windows domain in a forest. Captures all three name forms AD
/// publishes for a domain so callers can pick the right one for the API
/// they're feeding (SQL Server `CREATE LOGIN` wants NetBIOS, Kerberos wants
/// the DNS root, LDAP queries want the DN).
public struct ADDomain: Sendable, Hashable, Identifiable {
    /// DNS-form name, e.g. `corp.example.com`. Same value as the `dnsRoot`
    /// crossRef attribute.
    public let dnsRoot: String
    /// NetBIOS short name, e.g. `CORP`. Same value as the `nETBIOSName`
    /// crossRef attribute. May be empty when AD hasn't published one (rare
    /// for real domains; never empty for an AD-DS domain).
    public let netBIOSName: String
    /// Distinguished name of the domain naming context, e.g.
    /// `DC=corp,DC=example,DC=com`. Same value as the `nCName` crossRef
    /// attribute.
    public let namingContext: String

    public var id: String { namingContext }

    public init(dnsRoot: String, netBIOSName: String, namingContext: String) {
        self.dnsRoot = dnsRoot
        self.netBIOSName = netBIOSName
        self.namingContext = namingContext
    }
}
