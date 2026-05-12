import Foundation
import Dispatch
import CLDAP

/// Browses Active Directory users and groups, forest-wide or scoped to one domain.
///
/// `ADClient` wraps the system LDAP client with SASL/GSSAPI (Kerberos)
/// authentication. It is designed to run from non-domain-joined macOS clients
/// reaching a domain over VPN, and does not require TLS on the wire — Kerberos
/// negotiates LDAP signing for integrity protection on plain port 389/3268.
///
/// Runs on a dedicated default-QoS serial queue rather than the cooperative
/// thread pool. The bind, RootDSE read, search, and listChildren calls all
/// invoke synchronous C functions (Heimdal's krb5, cyrus-sasl, libldap) that
/// block on socket I/O and internally dispatch to default-QoS system queues.
/// Inheriting the caller's user-initiated QoS would create a priority
/// inversion (`Hang risk` warnings at ad_bind.c:161 / :225) — by pinning the
/// actor to a default-QoS executor the C work runs at its natural priority
/// and the inversion goes away.
public actor ADClient {

    /// Shared serial executor for every ADClient instance. Multiple picker
    /// sessions serialize through this queue, which is acceptable: each
    /// bind/search takes O(100ms) and pickers are interactive, not bulk.
    private static let sharedExecutor: DispatchSerialQueue = DispatchSerialQueue(
        label: "dev.echodb.swift-active-directory",
        qos: .default
    )

    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        Self.sharedExecutor.asUnownedSerialExecutor()
    }


    public enum Transport: Sendable, Hashable {
        /// Plain LDAP on the supplied port (389 for a DC, 3268 for a Global Catalog).
        /// SASL/GSSAPI is required on this transport; LDAP signing is negotiated automatically.
        case plain
        /// LDAPS — TLS wraps the LDAP traffic. 636 for a DC, 3269 for a Global Catalog.
        case ldaps(trust: TrustPolicy)
    }

    public enum TrustPolicy: Sendable, Hashable {
        case system
        case acceptAny
        case pinned(certificateSHA256: Data)
    }

    public enum Scope: Sendable, Hashable {
        /// Search a single domain via one of its DCs.
        case domain(String)
        /// Search the entire forest via a Global Catalog. Pass any domain in the forest;
        /// the forest root is discovered from the GC's RootDSE.
        case forest(anyDomainInForest: String)
    }

    /// Owns the libldap session pointer. Wrapped in a Sendable reference type so
    /// the enclosing actor can release it from a nonisolated deinit, and so the
    /// pointer never crosses an actor boundary while in use.
    private final class SessionHandle: @unchecked Sendable {
        var ptr: OpaquePointer?

        init(_ ptr: OpaquePointer) { self.ptr = ptr }

        func close() {
            if let p = ptr {
                ad_session_close(p)
                ptr = nil
            }
        }

        deinit { close() }
    }

    private var session: SessionHandle?
    private let server: ADServer
    private let transport: Transport

    public init(server: ADServer, transport: Transport = .plain) throws {
        self.server = server
        self.transport = transport

        let uri = ADClient.makeURI(server: server, transport: transport)
        var errPtr: UnsafeMutablePointer<CChar>?
        let opened: OpaquePointer? = uri.withCString { ad_session_open($0, &errPtr) }
        guard let opened else {
            let message = ADClient.consumeError(&errPtr) ?? "ad_session_open failed"
            throw ADError.bindFailed(code: -1, reason: message)
        }
        self.session = SessionHandle(opened)
    }

    public func bind(_ credentials: ADCredentials) throws {
        guard let ptr = session?.ptr else { throw ADError.notBound }
        var errPtr: UnsafeMutablePointer<CChar>?
        let rc: Int32

        switch credentials.method {
        case let .kerberos(domain, user, password):
            let realm = domain.uppercased()
            rc = user.withCString { userCStr in
                realm.withCString { realmCStr in
                    password.withCString { pwCStr in
                        ad_session_bind_kerberos(ptr, userCStr, realmCStr, pwCStr, &errPtr)
                    }
                }
            }
        case .kerberosTicket:
            throw ADError.invalidArgument("kerberosTicket bind not yet implemented")
        case let .simple(dn, password):
            rc = dn.withCString { dnCStr in
                password.withCString { pwCStr in
                    ad_session_bind_simple(ptr, dnCStr, pwCStr, &errPtr)
                }
            }
        }

        if rc != 0 {
            let message = ADClient.consumeError(&errPtr) ?? "bind failed (\(rc))"
            // The kerberos bind path surfaces both GSS and LDAP errors; we tag
            // GSS-flavoured ones distinctly so the picker can offer
            // re-enter-credentials vs. retry-with-different-server.
            if message.contains("gss_") || message.lowercased().contains("kerberos") {
                throw ADError.kerberosFailed(reason: message)
            }
            throw ADError.bindFailed(code: rc, reason: message)
        }
    }

    public func close() {
        session?.close()
        session = nil
    }

    /// Hand the raw C pointer to same-actor extension methods (search, RootDSE).
    /// Internal-only — never let this escape the actor.
    internal func sessionPointer() -> OpaquePointer? {
        session?.ptr
    }

    private static func makeURI(server: ADServer, transport: Transport) -> String {
        let scheme: String
        switch transport {
        case .plain: scheme = "ldap"
        case .ldaps: scheme = "ldaps"
        }
        return "\(scheme)://\(server.host):\(server.port)"
    }

    private static func consumeError(_ errPtr: inout UnsafeMutablePointer<CChar>?) -> String? {
        guard let raw = errPtr else { return nil }
        let message = String(cString: raw)
        ad_string_free(raw)
        errPtr = nil
        return message
    }
}
