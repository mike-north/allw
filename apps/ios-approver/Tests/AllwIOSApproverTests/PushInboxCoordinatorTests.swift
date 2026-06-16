import AllwIOSApprover
import Foundation

/// Tests for the APNs-wakeup → fetch-envelope → inbox-refresh path (issue #142).
///
/// Coverage:
/// - happy path: a wakeup fetches the relay envelope, prepares it through the core, refreshes the
///   inbox, and presents a notification for the now-pending request;
/// - notification reconciliation: a request that resolves/expires/disappears clears its
///   notification; a local decision clears immediately;
/// - fail-closed: a relay fetch error never mutates the inbox, never clears notifications, and never
///   renders an approved-looking row; a tampered/malformed relay response decodes fail-closed;
/// - push-token registration: the raw APNs token is hex-encoded before it reaches the relay.
///
/// Wire shape under test mirrors `docs/contract.md` §ApprovalRequest (relay-visible envelope keys)
/// and §Push (push carries a request id only; tokens registered via pairing).
enum PushInboxCoordinatorTests {
    static func run() async throws {
        try await testWakeupFetchesPreparesAndPresentsPending()
        try await testWakeupClearsNotificationForResolvedRequest()
        try await testWakeupClearsNotificationForExpiredRequest()
        try await testUnverifiedRequestIsNeverPresentedAsActionable()
        try await testFetchFailureFailsClosedAndLeavesInboxUntouched()
        try await testFetchFailureDoesNotClearExistingNotifications()
        try await testDidResolveClearsNotificationImmediately()
        try await testRelayDecoderParsesContractEnvelopeShape()
        try await testRelayDecoderRejectsMalformedEnvelopeFailClosed()
        try await testRelayDecoderRejectsNonObjectBody()
        try await testApnsTokenIsHexEncodedBeforeRegistration()
        try await testHexEncodeApnsTokenMatchesContractFormat()
    }

    // MARK: Happy path — wakeup → fetch → prepare → refresh → present

    @MainActor
    static func testWakeupFetchesPreparesAndPresentsPending() async throws {
        let runtime = FakeRuntime()
        runtime.prepared["req-1"] = .pending(requestHash: "hash-1", expiresAt: 50_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        let relay = FakeRelayInbox(envelopes: [.fixture(id: "req-1", expiresAt: 50_000)])
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        let inbox = try await coordinator.handleWakeup(requestId: "req-1")

        try expectEqual(relay.fetchCount, 1)
        try expectEqual(inbox.map(\.id), ["req-1"])
        try expectEqual(inbox.first?.status, .pending)
        // The newly-pending request is surfaced as a notification; nothing is cleared yet.
        try expectEqual(surface.presented, ["req-1"])
        try expect(surface.cleared.isEmpty)
    }

    // MARK: Notification reconciliation

    /// A request present-and-pending in one wakeup, then absent from the relay (resolved on another
    /// surface), must have its notification cleared on the next refresh.
    @MainActor
    static func testWakeupClearsNotificationForResolvedRequest() async throws {
        let runtime = FakeRuntime()
        runtime.prepared["req-1"] = .pending(requestHash: "hash-1", expiresAt: 50_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        let relay = FakeRelayInbox(envelopes: [.fixture(id: "req-1", expiresAt: 50_000)])
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        _ = try await coordinator.handleWakeup(requestId: "req-1")
        try expectEqual(surface.presented, ["req-1"])

        // The relay no longer lists req-1 (resolved elsewhere); the next wakeup clears it.
        relay.envelopes = []
        _ = try await coordinator.handleWakeup(requestId: nil)

        try expectEqual(surface.cleared, ["req-1"])
    }

    /// A pending request whose core-verified deadline has passed becomes `.expired`; expiry is not an
    /// actionable approval, so its notification is cleared.
    @MainActor
    static func testWakeupClearsNotificationForExpiredRequest() async throws {
        var now: Int64 = 1_000
        let runtime = FakeRuntime()
        runtime.prepared["req-1"] = .pending(requestHash: "hash-1", expiresAt: 5_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { now })
        let relay = FakeRelayInbox(envelopes: [.fixture(id: "req-1", expiresAt: 50_000)])
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        _ = try await coordinator.handleWakeup(requestId: "req-1")
        try expectEqual(surface.presented, ["req-1"])

        // Clock advances past the core-verified expiry; the relay still lists the envelope (it only
        // expires it lazily), but the store renders it `.expired` → not actionable → cleared.
        now = 5_001
        _ = try await coordinator.handleWakeup(requestId: nil)

        try expectEqual(surface.cleared, ["req-1"])
    }

    /// An unverifiable origin decrypts to a deny-only `.unverified` row. It must never be presented
    /// as a fresh actionable approval (`docs/contract.md` fail-closed).
    @MainActor
    static func testUnverifiedRequestIsNeverPresentedAsActionable() async throws {
        let runtime = FakeRuntime()
        runtime.prepareErrors["req-bad"] = ApprovalInboxError.unverified("bad JWE")
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        let relay = FakeRelayInbox(envelopes: [.fixture(id: "req-bad", expiresAt: 50_000)])
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        let inbox = try await coordinator.handleWakeup(requestId: "req-bad")

        // The row is visible (so the human sees something failed) but unverified, never presented.
        try expectEqual(inbox.first?.status, .unverified)
        try expect(surface.presented.isEmpty)
        try expect(surface.cleared.isEmpty)
    }

    // MARK: Fail-closed fetch

    @MainActor
    static func testFetchFailureFailsClosedAndLeavesInboxUntouched() async throws {
        let runtime = FakeRuntime()
        runtime.prepared["req-1"] = .pending(requestHash: "hash-1", expiresAt: 50_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        // Seed a known-good inbox first.
        await store.sync([.fixture(id: "req-1", expiresAt: 50_000)])

        let relay = FakeRelayInbox(error: RelayInboxFetchError.transport("relay unreachable"))
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        try await expectThrows(try await coordinator.handleWakeup(requestId: "req-1"))

        // Fail-closed: the existing inbox is untouched (not wiped) by a transient fetch failure.
        try expectEqual(store.inbox.map(\.id), ["req-1"])
        try expect(surface.presented.isEmpty)
        try expect(surface.cleared.isEmpty)
    }

    /// A fetch failure must not clear notifications for requests the relay simply couldn't be reached
    /// to confirm — clearing on error would let a network blip silently drop a real pending approval.
    @MainActor
    static func testFetchFailureDoesNotClearExistingNotifications() async throws {
        let runtime = FakeRuntime()
        runtime.prepared["req-1"] = .pending(requestHash: "hash-1", expiresAt: 50_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        let relay = FakeRelayInbox(envelopes: [.fixture(id: "req-1", expiresAt: 50_000)])
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        _ = try await coordinator.handleWakeup(requestId: "req-1")
        try expectEqual(surface.presented, ["req-1"])

        relay.error = RelayInboxFetchError.status(503)
        try await expectThrows(try await coordinator.handleWakeup(requestId: nil))

        // The earlier notification stays put; nothing cleared on a fetch error.
        try expect(surface.cleared.isEmpty)
    }

    @MainActor
    static func testDidResolveClearsNotificationImmediately() async throws {
        let runtime = FakeRuntime()
        runtime.prepared["req-1"] = .pending(requestHash: "hash-1", expiresAt: 50_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        let relay = FakeRelayInbox(envelopes: [.fixture(id: "req-1", expiresAt: 50_000)])
        let surface = RecordingNotificationSurface()
        let coordinator = PushInboxCoordinator(store: store, relay: relay, notifications: surface)

        _ = try await coordinator.handleWakeup(requestId: "req-1")
        await coordinator.didResolve(requestId: "req-1")

        try expectEqual(surface.cleared, ["req-1"])

        // A subsequent refresh with the request gone does not double-clear it.
        relay.envelopes = []
        _ = try await coordinator.refresh()
        try expectEqual(surface.cleared, ["req-1"])
    }

    // MARK: Relay envelope decoding (wire shape + tampered/malformed fail-closed)

    static func testRelayDecoderParsesContractEnvelopeShape() async throws {
        // Snake_case keys exactly as the relay's GET /devices/{id}/inbox returns (contract §Request).
        let body = Data(
            """
            {"envelopes":[
              {"v":1,"id":"req-1","created_at":100,"expires_at":50000,"approver":"acct-1","context_ciphertext":"opaque-jwe"}
            ]}
            """.utf8
        )

        let envelopes = try RelayInboxDecoder.decodeEnvelopes(from: body)

        try expectEqual(envelopes.count, 1)
        let envelope = try unwrap(envelopes.first)
        try expectEqual(envelope.v, 1)
        try expectEqual(envelope.id, "req-1")
        try expectEqual(envelope.createdAt, 100)
        try expectEqual(envelope.expiresAt, 50_000)
        try expectEqual(envelope.approver, "acct-1")
        try expectEqual(envelope.contextCiphertext, "opaque-jwe")
    }

    /// A tampered/malformed element (missing the opaque ciphertext) fails the whole batch closed —
    /// a half-formed envelope is never smuggled into the inbox.
    static func testRelayDecoderRejectsMalformedEnvelopeFailClosed() async throws {
        let body = Data(
            """
            {"envelopes":[
              {"v":1,"id":"req-1","created_at":100,"expires_at":50000,"approver":"acct-1"}
            ]}
            """.utf8
        )

        try await expectRelayFetchError(.malformedResponse) {
            _ = try RelayInboxDecoder.decodeEnvelopes(from: body)
        }
    }

    static func testRelayDecoderRejectsNonObjectBody() async throws {
        let body = Data("not json at all".utf8)

        try await expectRelayFetchError(.malformedResponse) {
            _ = try RelayInboxDecoder.decodeEnvelopes(from: body)
        }
    }

    // MARK: APNs token registration

    static func testApnsTokenIsHexEncodedBeforeRegistration() async throws {
        let sent = SentTokenBox()
        let registrar = HexApnsTokenRegistrar { token in
            await sent.set(token)
        }

        // 0xDE 0xAD 0xBE 0xEF → "deadbeef" (lowercase, two hex digits per byte).
        try await registrar.registerApnsToken([0xDE, 0xAD, 0xBE, 0xEF])

        let forwarded = await sent.value()
        try expectEqual(forwarded, "deadbeef")
    }

    static func testHexEncodeApnsTokenMatchesContractFormat() async throws {
        // A 32-byte token (the APNs token length) hex-encodes to the 64-char form the relay accepts.
        let raw = [UInt8](repeating: 0x0A, count: 32)
        let encoded = PushInboxCoordinator.hexEncodeApnsToken(raw)
        try expectEqual(encoded.count, 64)
        try expectEqual(encoded, String(repeating: "0a", count: 32))
    }
}

// MARK: - Fakes

private actor SentTokenBox {
    private var token: String?
    func set(_ value: String) { token = value }
    func value() -> String? { token }
}

private final class FakeRelayInbox: RelayInboxFetching, @unchecked Sendable {
    var envelopes: [ApprovalEnvelope]
    var error: Error?
    private(set) var fetchCount = 0

    init(envelopes: [ApprovalEnvelope] = [], error: Error? = nil) {
        self.envelopes = envelopes
        self.error = error
    }

    func fetchPendingEnvelopes() async throws -> [ApprovalEnvelope] {
        fetchCount += 1
        if let error {
            throw error
        }
        return envelopes
    }
}

private final class RecordingNotificationSurface: InboxNotificationSurface, @unchecked Sendable {
    private(set) var presented: [String] = []
    private(set) var cleared: [String] = []

    func presentPending(requestId: String) async {
        presented.append(requestId)
    }

    func clear(requestId: String) async {
        cleared.append(requestId)
    }
}

private final class FakeRuntime: ApproverCoreRuntime, @unchecked Sendable {
    var prepared: [String: PreparedApproval] = [:]
    var prepareErrors: [String: Error] = [:]

    func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval {
        if let error = prepareErrors[envelope.id] {
            throw error
        }
        guard let prepared = prepared[envelope.id] else {
            throw ApprovalInboxError.unverified("missing prepared fixture for \(envelope.id)")
        }
        return prepared
    }

    func signDecision(_ input: SignDecisionInput) async throws -> SignedVerdict {
        SignedVerdict(
            requestId: input.envelope.id,
            decision: input.decision,
            signedVerdictJson: #"{"v":1}"#
        )
    }
}

// MARK: - Local fixtures + assertions (kept private so they don't collide with other test files)

private extension PreparedApproval {
    static func pending(requestHash: String, expiresAt: Int64) -> PreparedApproval {
        PreparedApproval(
            requestHash: requestHash,
            expiresAt: expiresAt,
            context: ApprovalContext(
                action: .command(CommandAction(cwd: "/repo", argv: ["git", "push", "--force"], raw: nil)),
                actor: ApprovalActor(id: "agent-1", display: "Codex", attestation: .verified),
                risk: ApprovalRisk(level: .critical, reversible: false, summary: "force push to main"),
                allowedDecisions: [.approved, .denied],
                challenge: nil
            )
        )
    }
}

private extension ApprovalEnvelope {
    static func fixture(id: String, expiresAt: Int64) -> ApprovalEnvelope {
        ApprovalEnvelope(
            v: 1,
            id: id,
            createdAt: 100,
            expiresAt: expiresAt,
            approver: "acct-1",
            contextCiphertext: "opaque-jwe"
        )
    }
}

private enum RelayInboxFetchErrorKind: CustomStringConvertible {
    case transport
    case status
    case malformedResponse

    var description: String {
        switch self {
        case .transport: return "transport"
        case .status: return "status"
        case .malformedResponse: return "malformedResponse"
        }
    }

    func matches(_ error: RelayInboxFetchError) -> Bool {
        switch (self, error) {
        case (.transport, .transport), (.status, .status), (.malformedResponse, .malformedResponse):
            return true
        default:
            return false
        }
    }
}

private struct PushTestFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String = "expectation failed") throws {
    if !condition() {
        throw PushTestFailure(message)
    }
}

private func expectEqual<T: Equatable>(_ actual: T, _ expected: T) throws {
    if actual != expected {
        throw PushTestFailure("expected \(String(describing: expected)), got \(String(describing: actual))")
    }
}

private func unwrap<T>(_ value: T?) throws -> T {
    guard let value else {
        throw PushTestFailure("expected non-nil value")
    }
    return value
}

private func expectThrows(_ expression: @autoclosure () async throws -> some Sendable) async throws {
    do {
        _ = try await expression()
        throw PushTestFailure("expected expression to throw")
    } catch is PushTestFailure {
        throw PushTestFailure("expected expression to throw")
    } catch {
        // Expected.
    }
}

private func expectRelayFetchError(
    _ expected: RelayInboxFetchErrorKind,
    _ expression: () throws -> Void
) async throws {
    do {
        try expression()
        throw PushTestFailure("expected expression to throw \(expected)")
    } catch let error as RelayInboxFetchError {
        try expect(expected.matches(error), "expected \(expected), got \(error)")
    } catch {
        throw PushTestFailure("expected \(expected), got \(error)")
    }
}
