import Foundation

/// A node in an AD container hierarchy — used to populate the tree-browser
/// sidebar of the picker. Domains, OUs, and well-known containers like
/// `CN=Users,DC=…` and `CN=Computers,DC=…` all surface as `ADContainer`s.
public struct ADContainer: Sendable, Hashable, Identifiable {

    public enum Kind: Sendable, Hashable {
        case domain
        case organizationalUnit
        case container
        case other(String)
    }

    public let distinguishedName: String
    public let displayName: String
    public let kind: Kind

    public var id: String { distinguishedName }

    public init(distinguishedName: String, displayName: String, kind: Kind) {
        self.distinguishedName = distinguishedName
        self.displayName = displayName
        self.kind = kind
    }
}
