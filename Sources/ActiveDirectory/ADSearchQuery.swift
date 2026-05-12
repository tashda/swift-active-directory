import Foundation

public struct ADSearchQuery: Sendable, Hashable {

    public struct Filter: Sendable, Hashable {
        /// Substring matched against `sAMAccountName`, `displayName`, and `userPrincipalName`.
        public let text: String
        public let includeUsers: Bool
        public let includeGroups: Bool
        public let includeComputers: Bool
        public let includeOrganizationalUnits: Bool

        public init(
            text: String,
            includeUsers: Bool = true,
            includeGroups: Bool = true,
            includeComputers: Bool = false,
            includeOrganizationalUnits: Bool = false
        ) {
            self.text = text
            self.includeUsers = includeUsers
            self.includeGroups = includeGroups
            self.includeComputers = includeComputers
            self.includeOrganizationalUnits = includeOrganizationalUnits
        }
    }

    public let filter: Filter
    public let scope: ADClient.Scope
    /// Overrides the base DN derived from `scope`. Used by the tree browser
    /// to narrow a search to a selected OU or container.
    public let baseDNOverride: String?
    public let pageSize: Int
    public let maxResults: Int

    public init(
        filter: Filter,
        scope: ADClient.Scope,
        baseDNOverride: String? = nil,
        pageSize: Int = 100,
        maxResults: Int = 500
    ) {
        self.filter = filter
        self.scope = scope
        self.baseDNOverride = baseDNOverride
        self.pageSize = pageSize
        self.maxResults = maxResults
    }
}
