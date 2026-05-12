import Testing
@testable import ADDirectory

@Test
func principalProducesNTAccountName() {
    let principal = ADPrincipal(
        sAMAccountName: "jdoe",
        userPrincipalName: "jdoe@corp.example.com",
        displayName: "Jane Doe",
        distinguishedName: "CN=Jane Doe,OU=Users,DC=corp,DC=example,DC=com",
        objectClass: .user,
        objectSID: nil,
        domain: "corp"
    )

    #expect(principal.ntAccountName == "CORP\\jdoe")
}
