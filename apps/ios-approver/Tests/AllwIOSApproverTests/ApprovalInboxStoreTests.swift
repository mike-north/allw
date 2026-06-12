import AllwIOSApprover
import Foundation

@main
struct ApprovalInboxStoreTests {
    static func main() async throws {
        try await testSyncUsesPreparedExpiryInsteadOfRelayEnvelopeExpiry()
        try await testUndecryptableRequestIsUnverifiedAndCannotSign()
        try await testNumberMatchMustBeCorrectBeforeApprovalSigns()
        try await testDenyCanSignWithoutSatisfyingNumberMatch()
        try await testSigningFailureRestoresPendingState()
    }

    static func testSyncUsesPreparedExpiryInsteadOfRelayEnvelopeExpiry() async throws {
        let runtime = RecordingRuntime()
        runtime.prepared["req-expired"] = .command(
            requestHash: "hash-expired",
            expiresAt: 900,
            summary: "remove production database",
            challenge: nil
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })

        await store.sync([
            .fixture(id: "req-expired", expiresAt: 50_000)
        ])

        let item = try unwrap(store.inbox.first)
        try expectEqual(item.status, .expired)
        try expect(item.denyOnly)
        try expect(!store.canApprove("req-expired"))
    }

    static func testUndecryptableRequestIsUnverifiedAndCannotSign() async throws {
        let runtime = RecordingRuntime()
        runtime.prepareErrors["req-bad"] = ApprovalInboxError.unverified("bad JWE")
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })

        await store.sync([
            .fixture(id: "req-bad", expiresAt: 50_000)
        ])

        let detail = try unwrap(store.detail("req-bad"))
        try expectEqual(detail.status, .unverified)
        try expectEqual(detail.verificationError, "bad JWE")
        try expect(!store.canApprove("req-bad"))
        try await expectThrows(
            try await store.decide("req-bad", decision: .approved)
        )
        try expect(runtime.signInputs.isEmpty)
    }

    static func testNumberMatchMustBeCorrectBeforeApprovalSigns() async throws {
        let runtime = RecordingRuntime()
        runtime.prepared["req-challenge"] = .command(
            requestHash: "hash-challenge",
            expiresAt: 50_000,
            summary: "force push main",
            challenge: NumberMatchChallenge(code: "482", prompt: "Enter 482")
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([
            .fixture(id: "req-challenge", expiresAt: 50_000)
        ])

        try expect(!store.canApprove("req-challenge"))
        try expect(!store.canApprove("req-challenge", challengeResponse: "481"))
        try expect(store.canApprove("req-challenge", challengeResponse: "482"))

        let verdict = try await store.decide(
            "req-challenge",
            decision: .approved,
            challengeResponse: "482"
        )

        try expectEqual(verdict.requestId, "req-challenge")
        try expectEqual(verdict.decision, .approved)
        try expectEqual(store.detail("req-challenge")?.status, .approved)
        try expectEqual(runtime.signInputs.single?.challengeResponse, "482")
    }

    static func testDenyCanSignWithoutSatisfyingNumberMatch() async throws {
        let runtime = RecordingRuntime()
        runtime.prepared["req-deny"] = .command(
            requestHash: "hash-deny",
            expiresAt: 50_000,
            summary: "delete build artifacts",
            challenge: NumberMatchChallenge(code: "482", prompt: "Enter 482")
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([
            .fixture(id: "req-deny", expiresAt: 50_000)
        ])

        let verdict = try await store.decide("req-deny", decision: .denied)

        try expectEqual(verdict.decision, .denied)
        try expectEqual(store.detail("req-deny")?.status, .denied)
        try expectEqual(runtime.signInputs.single?.challengeResponse, nil)
    }

    static func testSigningFailureRestoresPendingState() async throws {
        let runtime = RecordingRuntime()
        runtime.prepared["req-sign-fail"] = .command(
            requestHash: "hash-sign-fail",
            expiresAt: 50_000,
            summary: "edit launch config",
            challenge: nil
        )
        runtime.signError = ApprovalInboxError.signingFailed("key unavailable")
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([
            .fixture(id: "req-sign-fail", expiresAt: 50_000)
        ])

        try await expectThrows(
            try await store.decide("req-sign-fail", decision: .approved)
        )

        try expectEqual(store.detail("req-sign-fail")?.status, .pending)
    }
}

private final class RecordingRuntime: ApproverCoreRuntime {
    var prepared: [String: PreparedApproval] = [:]
    var prepareErrors: [String: Error] = [:]
    var signInputs: [SignDecisionInput] = []
    var signError: Error?

    func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval {
        if let error = prepareErrors[envelope.id] {
            throw error
        }
        guard let prepared = prepared[envelope.id] else {
            throw TestFailure("missing prepared fixture for \(envelope.id)")
        }
        return prepared
    }

    func signDecision(_ input: SignDecisionInput) async throws -> SignedVerdict {
        signInputs.append(input)
        if let signError {
            throw signError
        }
        return SignedVerdict(
            requestId: input.envelope.id,
            decision: input.decision,
            signedVerdictJson: #"{"v":1}"#
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

private extension PreparedApproval {
    static func command(
        requestHash: String,
        expiresAt: Int64,
        summary: String,
        challenge: NumberMatchChallenge?
    ) -> PreparedApproval {
        PreparedApproval(
            requestHash: requestHash,
            expiresAt: expiresAt,
            context: ApprovalContext(
                action: .command(CommandAction(cwd: "/repo", argv: ["git", "push", "--force"], raw: nil)),
                actor: ApprovalActor(id: "agent-1", display: "Codex", attestation: .verified),
                risk: ApprovalRisk(level: .critical, reversible: false, summary: summary),
                allowedDecisions: [.approved, .denied],
                challenge: challenge
            )
        )
    }
}

private extension Array {
    var single: Element? {
        count == 1 ? self[0] : nil
    }
}

private struct TestFailure: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String = "expectation failed") throws {
    if !condition() {
        throw TestFailure(message)
    }
}

private func expectEqual<T: Equatable>(_ actual: T, _ expected: T) throws {
    if actual != expected {
        throw TestFailure("expected \(String(describing: expected)), got \(String(describing: actual))")
    }
}

private func unwrap<T>(_ value: T?) throws -> T {
    guard let value else {
        throw TestFailure("expected non-nil value")
    }
    return value
}

private func expectThrows(_ expression: @autoclosure () async throws -> some Sendable) async throws {
    do {
        _ = try await expression()
        throw TestFailure("expected expression to throw")
    } catch is TestFailure {
        throw TestFailure("expected expression to throw")
    } catch {
        // Expected.
    }
}
