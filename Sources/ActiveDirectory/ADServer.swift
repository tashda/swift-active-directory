import Foundation

public struct ADServer: Sendable, Hashable {

    public enum Role: Sendable, Hashable {
        case domainController
        case globalCatalog
    }

    public let host: String
    public let port: Int
    public let role: Role

    public init(host: String, port: Int, role: Role) {
        self.host = host
        self.port = port
        self.role = role
    }

    public static func domainController(_ host: String, port: Int = 389) -> ADServer {
        ADServer(host: host, port: port, role: .domainController)
    }

    public static func globalCatalog(_ host: String, port: Int = 3268) -> ADServer {
        ADServer(host: host, port: port, role: .globalCatalog)
    }
}
