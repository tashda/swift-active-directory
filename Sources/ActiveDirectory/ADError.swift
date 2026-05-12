import Foundation

public enum ADError: Error, Sendable, Hashable {
    case discoveryFailed(reason: String)
    case bindFailed(code: Int32, reason: String)
    case kerberosFailed(reason: String)
    case searchFailed(code: Int32, reason: String)
    case tlsTrustRejected
    case unsupportedTransport
    case invalidArgument(String)
    case notBound
}
