import AllwIOSApprover
import Foundation

// Tests for the ambient Live Activity / Dynamic Island surface (issue #143, slice of #23).
//
// These cover the *testable* layer: the platform-agnostic state derivation
// (`PendingApprovalsActivityState`) and the start/update/clear-on-resolve lifecycle
// (`LiveActivityCoordinator`) against a fake presenter. The ActivityKit-backed presenter and the
// WidgetKit Dynamic Island UI are iOS-only (ActivityKit is unavailable on macOS) and validate only
// in the Xcode/iOS build, NOT in the macOS `swiftc` CI job that runs this suite.
//
// Registered into the existing `@main` runner in `ApprovalInboxStoreTests.runLiveActivityTests()`.

extension ApprovalInboxStoreTests {
    static func runLiveActivityTests() async throws {
        // State value semantics (no store / no ActivityKit needed)
        try testAmbientStateIsClearedWhenNothingPending()
        try testAmbientStateCountdownFloorsAtZero()
        // Store integration (drives derivation through the real inbox path)
        try await testStoreAmbientStateReflectsPendingThenClearsOnResolve()
        try await testStoreAmbientStateCountsOnlyPendingAndUsesSoonestExpiry()
        try await testStoreAmbientStateClearsWhenAllExpire()
        // Coordinator lifecycle
        try await testCoordinatorStartsOnFirstPending()
        try await testCoordinatorUpdatesOnPendingChange()
        try await testCoordinatorSkipsRedundantUpdate()
        try await testCoordinatorEndsWhenClearedAfterPresenting()
        try await testCoordinatorDoesNotEndWhenNeverPresented()
        try await testCoordinatorReStartsAfterClear()
    }

    // MARK: - PendingApprovalsActivityState value semantics

    /// `derive(from: [])` and `.cleared` agree: an empty inbox shows nothing.
    static func testAmbientStateIsClearedWhenNothingPending() throws {
        let state = PendingApprovalsActivityState.derive(from: [])
        try expectEqual(state, .cleared)
        try expect(!state.hasPending)
        try expectEqual(state.pendingCount, 0)
        try expectEqual(state.nextExpiryAt, nil)
    }

    /// `countdownMs` floors at zero (never negative) and is `nil` when nothing is pending.
    static func testAmbientStateCountdownFloorsAtZero() throws {
        let pending = PendingApprovalsActivityState(pendingCount: 1, nextExpiryAt: 5_000)
        try expectEqual(pending.countdownMs(nowMs: 1_000), 4_000)
        // Past the deadline → floored at zero, not negative.
        try expectEqual(pending.countdownMs(nowMs: 9_000), 0)
        // Cleared → no countdown.
        try expectEqual(PendingApprovalsActivityState.cleared.countdownMs(nowMs: 1_000), nil)
    }

    // MARK: - ApprovalInboxStore.ambientState

    /// The store's ambient state reflects a pending request, then clears to `.cleared` once it is
    /// resolved (clear-on-resolve, the core acceptance criterion of #143).
    static func testStoreAmbientStateReflectsPendingThenClearsOnResolve() async throws {
        let runtime = LiveActivityRecordingRuntime()
        runtime.prepared["req-1"] = .pendingCommand(requestHash: "h1", expiresAt: 50_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-1", expiresAt: 50_000)])

        let pending = store.ambientState
        try expectEqual(pending.pendingCount, 1)
        try expectEqual(pending.nextExpiryAt, 50_000)
        try expect(pending.hasPending)

        _ = try await store.decide("req-1", decision: .approved)

        // Resolved → ambient surface clears.
        try expectEqual(store.ambientState, .cleared)
    }

    /// Only `.pending` rows feed the ambient summary and the countdown uses the soonest of their
    /// expiries. An expired row's (earlier) deadline must NOT drive the countdown, and a resolved row
    /// must not be counted. Driven through the real store/inbox path so the derivation is exercised as
    /// production uses it.
    static func testStoreAmbientStateCountsOnlyPendingAndUsesSoonestExpiry() async throws {
        var now: Int64 = 1_000
        let runtime = LiveActivityRecordingRuntime()
        // Three pending; "soon" has the earliest live expiry. "stale" has already expired so the
        // expiry sweep demotes it to `.expired` (earlier deadline 500 must be ignored).
        runtime.prepared["late"] = .pendingCommand(requestHash: "hl", expiresAt: 90_000)
        runtime.prepared["soon"] = .pendingCommand(requestHash: "hs", expiresAt: 12_000)
        runtime.prepared["mid"] = .pendingCommand(requestHash: "hm", expiresAt: 40_000)
        runtime.prepared["stale"] = .pendingCommand(requestHash: "hx", expiresAt: 500)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { now })
        await store.sync([
            .fixture(id: "late", expiresAt: 90_000),
            .fixture(id: "soon", expiresAt: 12_000),
            .fixture(id: "mid", expiresAt: 40_000),
            .fixture(id: "stale", expiresAt: 500),
        ])

        // "stale" expired immediately (expiresAt 500 <= now 1_000) → 3 pending remain.
        let state = store.ambientState
        try expectEqual(state.pendingCount, 3)
        try expectEqual(state.nextExpiryAt, 12_000)

        // Resolve the soonest → countdown moves to the next-soonest pending (mid, 40_000).
        _ = try await store.decide("soon", decision: .denied)
        now = 2_000
        let afterResolve = store.ambientState
        try expectEqual(afterResolve.pendingCount, 2)
        try expectEqual(afterResolve.nextExpiryAt, 40_000)
    }

    /// When every pending request expires, the ambient state clears (the expiry sweep moves rows to
    /// `.expired`, which are not counted).
    static func testStoreAmbientStateClearsWhenAllExpire() async throws {
        var now: Int64 = 1_000
        let runtime = LiveActivityRecordingRuntime()
        runtime.prepared["req-exp"] = .pendingCommand(requestHash: "h", expiresAt: 5_000)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { now })
        await store.sync([.fixture(id: "req-exp", expiresAt: 5_000)])

        try expectEqual(store.ambientState.pendingCount, 1)

        now = 5_001
        try expectEqual(store.ambientState, .cleared)
    }

    // MARK: - LiveActivityCoordinator lifecycle

    /// First pending state → presenter.start once; nothing else.
    static func testCoordinatorStartsOnFirstPending() async throws {
        let presenter = FakeActivityPresenter()
        let coordinator = LiveActivityCoordinator(presenter: presenter)

        try await coordinator.apply(PendingApprovalsActivityState(pendingCount: 1, nextExpiryAt: 5_000))

        try await expectEqual(presenter.calls, [.start(pendingCount: 1, nextExpiryAt: 5_000)])
        try await expectEqual(coordinator.isPresenting, true)
    }

    /// A changed pending state while presenting → presenter.update (not a second start).
    static func testCoordinatorUpdatesOnPendingChange() async throws {
        let presenter = FakeActivityPresenter()
        let coordinator = LiveActivityCoordinator(presenter: presenter)

        try await coordinator.apply(PendingApprovalsActivityState(pendingCount: 1, nextExpiryAt: 5_000))
        try await coordinator.apply(PendingApprovalsActivityState(pendingCount: 2, nextExpiryAt: 4_000))

        try await expectEqual(
            presenter.calls,
            [
                .start(pendingCount: 1, nextExpiryAt: 5_000),
                .update(pendingCount: 2, nextExpiryAt: 4_000),
            ]
        )
    }

    /// Applying an identical pending state twice issues no redundant presenter call (avoids
    /// ActivityKit churn).
    static func testCoordinatorSkipsRedundantUpdate() async throws {
        let presenter = FakeActivityPresenter()
        let coordinator = LiveActivityCoordinator(presenter: presenter)

        let state = PendingApprovalsActivityState(pendingCount: 1, nextExpiryAt: 5_000)
        try await coordinator.apply(state)
        try await coordinator.apply(state)

        try await expectEqual(presenter.calls, [.start(pendingCount: 1, nextExpiryAt: 5_000)])
    }

    /// Going from presenting → cleared ends the activity exactly once (clear-on-resolve).
    static func testCoordinatorEndsWhenClearedAfterPresenting() async throws {
        let presenter = FakeActivityPresenter()
        let coordinator = LiveActivityCoordinator(presenter: presenter)

        try await coordinator.apply(PendingApprovalsActivityState(pendingCount: 1, nextExpiryAt: 5_000))
        try await coordinator.apply(.cleared)

        try await expectEqual(
            presenter.calls,
            [.start(pendingCount: 1, nextExpiryAt: 5_000), .end]
        )
        try await expectEqual(coordinator.isPresenting, false)
    }

    /// A cleared state with nothing ever presented must NOT call end (no activity to clear).
    static func testCoordinatorDoesNotEndWhenNeverPresented() async throws {
        let presenter = FakeActivityPresenter()
        let coordinator = LiveActivityCoordinator(presenter: presenter)

        try await coordinator.apply(.cleared)
        // Applying cleared again is still a no-op.
        try await coordinator.apply(.cleared)

        let calls = await presenter.calls
        try expect(calls.isEmpty, "expected no presenter calls, got \(calls)")
        try await expectEqual(coordinator.isPresenting, false)
    }

    /// After a clear, a new pending state starts a fresh activity (not an update on a dead one).
    static func testCoordinatorReStartsAfterClear() async throws {
        let presenter = FakeActivityPresenter()
        let coordinator = LiveActivityCoordinator(presenter: presenter)

        try await coordinator.apply(PendingApprovalsActivityState(pendingCount: 1, nextExpiryAt: 5_000))
        try await coordinator.apply(.cleared)
        try await coordinator.apply(PendingApprovalsActivityState(pendingCount: 3, nextExpiryAt: 8_000))

        try await expectEqual(
            presenter.calls,
            [
                .start(pendingCount: 1, nextExpiryAt: 5_000),
                .end,
                .start(pendingCount: 3, nextExpiryAt: 8_000),
            ]
        )
        try await expectEqual(coordinator.isPresenting, true)
    }
}

/// Records the lifecycle calls the coordinator makes, in order, for deterministic assertions.
private actor FakeActivityPresenter: PendingApprovalsActivityPresenter {
    enum Call: Equatable {
        case start(pendingCount: Int, nextExpiryAt: Int64?)
        case update(pendingCount: Int, nextExpiryAt: Int64?)
        case end
    }

    private(set) var calls: [Call] = []

    func start(_ state: PendingApprovalsActivityState) async throws {
        calls.append(.start(pendingCount: state.pendingCount, nextExpiryAt: state.nextExpiryAt))
    }

    func update(_ state: PendingApprovalsActivityState) async throws {
        calls.append(.update(pendingCount: state.pendingCount, nextExpiryAt: state.nextExpiryAt))
    }

    func end() async throws {
        calls.append(.end)
    }
}

/// Minimal runtime returning canned prepared contexts for the store-integration ambient tests.
private final class LiveActivityRecordingRuntime: ApproverCoreRuntime, @unchecked Sendable {
    var prepared: [String: PreparedApproval] = [:]

    func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval {
        guard let prepared = prepared[envelope.id] else {
            throw LiveActivityTestError("missing prepared fixture for \(envelope.id)")
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

private struct LiveActivityTestError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// MARK: - Assertion helpers (file-private; mirror those in ApprovalInboxStoreTests.swift)

private func expect(
    _ condition: @autoclosure () -> Bool,
    _ message: String = "expectation failed"
) throws {
    if !condition() {
        throw LiveActivityTestError(message)
    }
}

private func expectEqual<T: Equatable>(_ actual: T, _ expected: T) throws {
    if actual != expected {
        throw LiveActivityTestError("expected \(String(describing: expected)), got \(String(describing: actual))")
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

private extension PreparedApproval {
    static func pendingCommand(requestHash: String, expiresAt: Int64) -> PreparedApproval {
        PreparedApproval(
            requestHash: requestHash,
            expiresAt: expiresAt,
            context: ApprovalContext(
                action: .command(CommandAction(cwd: "/repo", argv: ["git", "status"], raw: nil)),
                actor: ApprovalActor(id: "agent-1", display: "Codex", attestation: .verified),
                risk: ApprovalRisk(level: .high, reversible: true, summary: "git status"),
                allowedDecisions: [.approved, .denied],
                challenge: nil
            )
        )
    }
}
