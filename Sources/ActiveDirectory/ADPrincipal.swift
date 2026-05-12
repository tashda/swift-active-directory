import Foundation

public struct ADPrincipal: Sendable, Hashable, Identifiable {

    public enum ObjectClass: Sendable, Hashable {
        case user
        case group
        case computer
        case organizationalUnit
        case other(String)
    }

    public let sAMAccountName: String
    public let userPrincipalName: String?
    public let displayName: String?
    public let distinguishedName: String
    public let objectClass: ObjectClass
    public let objectSID: Data?
    public let domain: String

    public var id: String { distinguishedName }

    /// `DOMAIN\sAMAccountName` form expected by SQL Server `CREATE LOGIN ... FROM WINDOWS`.
    public var ntAccountName: String {
        "\(domain.uppercased())\\\(sAMAccountName)"
    }

    public init(
        sAMAccountName: String,
        userPrincipalName: String?,
        displayName: String?,
        distinguishedName: String,
        objectClass: ObjectClass,
        objectSID: Data?,
        domain: String
    ) {
        self.sAMAccountName = sAMAccountName
        self.userPrincipalName = userPrincipalName
        self.displayName = displayName
        self.distinguishedName = distinguishedName
        self.objectClass = objectClass
        self.objectSID = objectSID
        self.domain = domain
    }
}
