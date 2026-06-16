import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Failures from the relay envelope-fetch seam. Every case is fail-closed: a fetch or decode error
/// surfaces here and the push wakeup is treated as "no new envelopes" rather than rendering a
/// partial or fabricated request. The relay is zero-knowledge, so the body it returns is opaque
/// ciphertext (`context_ciphertext`); decryption/verification always happens later in the core.
public enum RelayInboxFetchError: Error, Equatable, CustomStringConvertible, Sendable {
    /// The relay was unreachable, timed out, or returned a transport error. Fail-closed: no inbox.
    case transport(String)
    /// The relay returned a non-2xx HTTP status. Fail-closed: no inbox.
    case status(Int)
    /// The relay response body was not the expected `{ "envelopes": [...] }` shape. Fail-closed.
    case malformedResponse(String)

    public var description: String {
        switch self {
        case .transport(let message):
            return "relay inbox fetch transport error: \(message)"
        case .status(let code):
            return "relay inbox fetch returned HTTP \(code)"
        case .malformedResponse(let message):
            return "relay inbox response was malformed: \(message)"
        }
    }
}

/// The narrow seam over the relay's `GET /{account}/devices/{device}/inbox` endpoint.
///
/// Thin-shell discipline: this seam only fetches the relay-visible **ApprovalRequest envelopes**
/// (routing/lifecycle + opaque `context_ciphertext`). It never decrypts, hashes, or interprets
/// crypto — that all stays in `allw-core` via `prepare()`. Production wires
/// `UrlSessionRelayInboxClient`; tests inject a fake so the wakeup→fetch→refresh flow stays
/// deterministic without a live relay.
public protocol RelayInboxFetching: Sendable {
    /// Fetch every pending, non-expired envelope addressed to this device. Throws
    /// `RelayInboxFetchError` (fail-closed) on any transport, status, or decode failure.
    func fetchPendingEnvelopes() async throws -> [ApprovalEnvelope]
}

/// Decoder for the relay's inbox response. Mirrors the wire JSON exactly: a top-level
/// `{ "envelopes": [ ... ] }` whose elements are the snake_case ApprovalRequest envelope keys
/// (`v`, `id`, `created_at`, `expires_at`, `approver`, `context_ciphertext` — `docs/contract.md`
/// §ApprovalRequest). Kept separate from the network client so the pure decode path is unit-testable
/// without any URL loading.
public enum RelayInboxDecoder {
    /// Decode the relay inbox response body into render-layer `ApprovalEnvelope` values.
    ///
    /// Fail-closed: a body that is not the expected shape throws `malformedResponse` rather than
    /// silently dropping or fabricating envelopes. One malformed element fails the whole batch so a
    /// tampered response cannot smuggle a half-formed request past the inbox.
    public static func decodeEnvelopes(from data: Data) throws -> [ApprovalEnvelope] {
        let wire: WireInboxResponse
        do {
            wire = try JSONDecoder().decode(WireInboxResponse.self, from: data)
        } catch {
            throw RelayInboxFetchError.malformedResponse(String(describing: error))
        }
        return wire.envelopes.map { $0.toEnvelope() }
    }
}

/// Decodable mirror of the relay inbox response. Private wire concern; the public surface is
/// `ApprovalEnvelope`.
private struct WireInboxResponse: Decodable {
    let envelopes: [WireEnvelope]
}

/// Decodable mirror of the relay-visible ApprovalRequest envelope (snake_case keys).
private struct WireEnvelope: Decodable {
    let v: Int
    let id: String
    let createdAt: Int64
    let expiresAt: Int64
    let approver: String
    let contextCiphertext: String

    enum CodingKeys: String, CodingKey {
        case v
        case id
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case approver
        case contextCiphertext = "context_ciphertext"
    }

    func toEnvelope() -> ApprovalEnvelope {
        ApprovalEnvelope(
            v: v,
            id: id,
            createdAt: createdAt,
            expiresAt: expiresAt,
            approver: approver,
            contextCiphertext: contextCiphertext
        )
    }
}

#if canImport(FoundationNetworking) || canImport(Darwin)
/// Production relay inbox client backed by `URLSession`.
///
/// Reaches `GET /{account}/devices/{device}/inbox` with the device bearer token, the same token the
/// presence WebSocket uses. The relay returns the opaque envelopes; this client only marshals the
/// HTTP exchange and hands the body to `RelayInboxDecoder`. It never sees plaintext (zero-knowledge
/// invariant) and fails closed on every error path. Validated end-to-end only in CI's macOS
/// `native-bindings` job, where a real `URLSession` exists.
public final class UrlSessionRelayInboxClient: RelayInboxFetching {
    private let relayBaseUrl: URL
    private let accountId: String
    private let deviceId: String
    private let deviceAuthToken: String
    private let session: URLSession
    private let timeout: TimeInterval

    public init(
        relayBaseUrl: URL,
        accountId: String,
        deviceId: String,
        deviceAuthToken: String,
        session: URLSession = .shared,
        timeout: TimeInterval = 10
    ) {
        self.relayBaseUrl = relayBaseUrl
        self.accountId = accountId
        self.deviceId = deviceId
        self.deviceAuthToken = deviceAuthToken
        self.session = session
        self.timeout = timeout
    }

    public func fetchPendingEnvelopes() async throws -> [ApprovalEnvelope] {
        let url = inboxUrl()
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "GET"
        request.setValue("Bearer \(deviceAuthToken)", forHTTPHeaderField: "Authorization")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw RelayInboxFetchError.transport(String(describing: error))
        }

        guard let http = response as? HTTPURLResponse else {
            throw RelayInboxFetchError.transport("response was not HTTP")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw RelayInboxFetchError.status(http.statusCode)
        }
        return try RelayInboxDecoder.decodeEnvelopes(from: data)
    }

    private func inboxUrl() -> URL {
        // Mirror the relay route: /{account_id}/devices/{device_id}/inbox.
        relayBaseUrl
            .appendingPathComponent(accountId)
            .appendingPathComponent("devices")
            .appendingPathComponent(deviceId)
            .appendingPathComponent("inbox")
    }
}
#endif
