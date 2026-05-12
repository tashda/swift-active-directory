import Testing
@testable import ActiveDirectory

@Suite("ADClient filter helpers")
struct ADClientFilterTests {

    @Test func escapesAllReservedFilterCharacters() {
        let escaped = ADClient._escapeFilterText_forTesting("a*b(c)d\\e\0f")
        #expect(escaped == "a\\2ab\\28c\\29d\\5ce\\00f")
    }

    @Test func filterCombinesClassesAndText() {
        let filter = ADClient._buildFilter_forTesting(.init(
            text: "jdoe",
            includeUsers: true,
            includeGroups: true,
            includeComputers: false,
            includeOrganizationalUnits: false
        ))
        #expect(filter.contains("(&"))
        #expect(filter.contains("(objectCategory=person)"))
        #expect(filter.contains("(objectCategory=group)"))
        #expect(filter.contains("(sAMAccountName=*jdoe*)"))
        #expect(filter.contains("(displayName=*jdoe*)"))
        #expect(filter.contains("(userPrincipalName=*jdoe*)"))
    }

    @Test func emptyTextOmitsTextClause() {
        let filter = ADClient._buildFilter_forTesting(.init(
            text: "",
            includeUsers: true,
            includeGroups: false,
            includeComputers: false,
            includeOrganizationalUnits: false
        ))
        #expect(filter == "(&(objectCategory=person)(objectClass=user))")
    }

    @Test func dnFromDomainBuildsHierarchicalDN() {
        #expect(ADClient._dnFromDomain_forTesting("corp.example.com") == "DC=corp,DC=example,DC=com")
    }

    @Test func domainFromDNRoundTrips() {
        let domain = ADClient._domainFromDN_forTesting("CN=Jane,OU=Users,DC=corp,DC=example,DC=com")
        #expect(domain == "corp.example.com")
    }
}
