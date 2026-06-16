import AllwIOSApprover
import Foundation

#if canImport(Security)
import Security
#endif

@main
struct ApprovalInboxStoreTests {
    static func main() async throws {
        try await testSyncUsesPreparedExpiryInsteadOfRelayEnvelopeExpiry()
        try await testUndecryptableRequestIsUnverifiedAndCannotSign()
        try await testNumberMatchMustBeCorrectBeforeApprovalSigns()
        try await testDenyCanSignWithoutSatisfyingNumberMatch()
        try await testSigningFailureRestoresPendingState()
        try await testDecisionRechecksCoreVerifiedExpiryBeforeSigning()
        try await testDoubleSubmitProducesOnlyOneSignature()
        try await testDeniedOnlyRequestRejectsApproval()
        try await testTerminalDecisionSurvivesLaterEmptySync()
        try await testUniFfiRuntimePreparesVerifiedContextFromCoreJson()
        try await testUniFfiRuntimePreparesUnverifiedOriginAsDenyOnly()
        try await testUniFfiRuntimeMapsCoreDecryptFailureToUnverified()
        try await testSignDecisionGatesOnBiometricsThenSignsOverPreparedHash()
        try await testSignDecisionBiometricCancelFailsClosedWithoutTouchingSeed()
        try await testSignDecisionBiometricFailureFailsClosedWithoutTouchingSeed()
        try await testSignDecisionSeedReleaseFailureFailsClosed()
        try await testSignDecisionCoreSignFailureFailsClosed()
        try await testSignDecisionDenialOmitsChallengeResponse()
        try await testSignDecisionBindsToCoreComputedHashNotEnvelope()
        try await testSignDecisionUnsignedVerdictOmitsNilNoteAndCarriesDeviceCert()
        try await testCredentialStorePersistsPairedDeviceCredentials()
        try await testAccountStateFloorRejectsRollbackBelowStoredSequence()
        try await testAccountStateFloorRequiresRelayMaxSequenceToBeVerified()
        try await testAccountStateFloorRejectsNegativeSequenceInputs()
        #if canImport(Security)
        try await testKeychainAccountStateFloorRejectsMalformedPersistedData()
        try await testKeychainAccountStateFloorRejectsNegativePersistedSequence()
        try await testKeychainPairedDeviceCredentialsAreThisDeviceOnly()
        #endif

        // APNs wakeup → fetch envelope → inbox refresh (issue #142).
        try await PushInboxCoordinatorTests.run()

        // Ambient Live Activity / Dynamic Island surface (#143).
        try await runLiveActivityTests()
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

    // MARK: UniFfiApproverRuntime.prepare() — core-JSON decode + verified/asserted mapping

    /// A core prepare result with a verified attestation maps to a `.pending`, approvable row whose
    /// render model carries the decrypted command, the core-computed hash/expiry, and the verified
    /// origin. Proves the thin-shell runtime decodes the canonical core context JSON correctly.
    static func testUniFfiRuntimePreparesVerifiedContextFromCoreJson() async throws {
        let core = FakeCoreBinding()
        core.result = CorePreparedApproval(
            contextJson: Self.coreContextJson(
                summary: "force push to main",
                challengeRequired: true
            ),
            requestHashB64: "hash-verified",
            expiresAt: 50_000,
            attestationVerified: true,
            challengeCode: "482"
        )
        let runtime = Self.runtime(core: core)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })

        await store.sync([.fixture(id: "req-verified", expiresAt: 9_999)])

        let detail = try unwrap(store.detail("req-verified"))
        try expectEqual(detail.status, .pending)
        try expectEqual(detail.attestation, .verified)
        try expectEqual(detail.requestHash, "hash-verified")
        // Core-verified expiry overrides the relay envelope's value.
        try expectEqual(detail.expiresAt, 50_000)
        try expect(detail.exactPlaintext.contains("git push --force"))
        // Challenge derived by the core gates approval.
        try expect(!store.canApprove("req-verified"))
        try expect(store.canApprove("req-verified", challengeResponse: "482"))
    }

    /// An unverified origin (core reports `attestationVerified == false`) is NOT an error: the
    /// context still renders, but the row is `.unverified` and cannot be approved (deny-only).
    static func testUniFfiRuntimePreparesUnverifiedOriginAsDenyOnly() async throws {
        let core = FakeCoreBinding()
        core.result = CorePreparedApproval(
            contextJson: Self.coreContextJson(summary: "delete prod db", challengeRequired: false),
            requestHashB64: "hash-unverified",
            expiresAt: 50_000,
            attestationVerified: false,
            challengeCode: nil
        )
        let runtime = Self.runtime(core: core)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })

        await store.sync([.fixture(id: "req-unverified", expiresAt: 9_999)])

        let detail = try unwrap(store.detail("req-unverified"))
        try expectEqual(detail.status, .unverified)
        try expectEqual(detail.attestation, .unverified)
        try expect(detail.denyOnly)
        try expect(!store.canApprove("req-unverified"))
        try await expectThrows(
            try await store.decide("req-unverified", decision: .approved)
        )
    }

    /// A core decrypt/hash failure surfaces as a thrown error → the store renders `.unverified`
    /// (fail-closed). No prepared context, no plaintext, never approvable.
    static func testUniFfiRuntimeMapsCoreDecryptFailureToUnverified() async throws {
        let core = FakeCoreBinding()
        core.error = FakeCoreError.decryptFailed
        let runtime = Self.runtime(core: core)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })

        await store.sync([.fixture(id: "req-bad-jwe", expiresAt: 9_999)])

        let detail = try unwrap(store.detail("req-bad-jwe"))
        try expectEqual(detail.status, .unverified)
        try expect(!store.canApprove("req-bad-jwe"))
        try await expectThrows(
            try await store.decide("req-bad-jwe", decision: .approved)
        )
    }

    // MARK: UniFfiApproverRuntime.signDecision() — Secure-Enclave custody + biometric gate (#141)

    /// Happy path: biometric auth succeeds → the seed is released → the core signs over the
    /// *core-computed* prepared hash. Proves the verdict binds to `prepared.requestHash` and the
    /// runtime returns the core's signed verdict JSON verbatim. (End-to-end key custody + a real
    /// `LAContext` validate only in CI's macOS `native-bindings` job.)
    static func testSignDecisionGatesOnBiometricsThenSignsOverPreparedHash() async throws {
        let gate = FakeBiometricGate()
        let seed = FakeSeedProvider(seedB64: "device-seed-b64")
        let signer = FakeSignBinding(verdictJson: #"{"v":1,"sig":"abc"}"#)
        let runtime = Self.runtime(
            core: Self.preparedCore(challengeRequired: true, challengeCode: "482"),
            signer: signer,
            biometricGate: gate,
            seedProvider: seed
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-sign", expiresAt: 9_999)])

        let verdict = try await store.decide("req-sign", decision: .approved, challengeResponse: "482")

        // Biometric gate ran exactly once, before the seed was released.
        try expectEqual(gate.authorizeCount, 1)
        try expectEqual(seed.releaseCount, 1)
        try expectEqual(signer.calls.count, 1)
        let call = try unwrap(signer.calls.first)
        try expectEqual(call.seed, "device-seed-b64")
        // Nonce is the fixed test nonce, base64url-encoded (16 bytes of 0x09).
        try expectEqual(call.nonce, "CQkJCQkJCQkJCQkJCQkJCQ")
        // The unsigned verdict binds to the core-computed hash, not anything UI-recomputed.
        try expect(call.unsigned.contains("\"request_hash\":\"hash-verified\""))
        try expect(call.unsigned.contains("\"decision\":\"approved\""))
        try expect(call.unsigned.contains("\"challenge_response\":\"482\""))
        try expect(call.unsigned.contains("\"device_id\":\"dev-1\""))
        // The runtime returns the core's signed verdict verbatim.
        try expectEqual(verdict.signedVerdictJson, #"{"v":1,"sig":"abc"}"#)
        try expectEqual(store.detail("req-sign")?.status, .approved)
    }

    /// Fail-closed: a cancelled biometric prompt throws and NO seed is ever released and NO core
    /// signature is produced. The store restores `pending` (covered by the store-level test); here
    /// we prove the custody boundary is never crossed.
    static func testSignDecisionBiometricCancelFailsClosedWithoutTouchingSeed() async throws {
        let gate = FakeBiometricGate(error: .biometricCancelled("user cancelled"))
        let seed = FakeSeedProvider()
        let signer = FakeSignBinding()
        let runtime = Self.runtime(
            core: Self.preparedCore(),
            signer: signer,
            biometricGate: gate,
            seedProvider: seed
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-cancel", expiresAt: 9_999)])

        try await expectThrows(
            try await store.decide("req-cancel", decision: .approved)
        )

        try expectEqual(gate.authorizeCount, 1)
        try expectEqual(seed.releaseCount, 0)
        try expect(signer.calls.isEmpty)
        // Fail-closed: the request is approvable again, never stuck or silently approved.
        try expectEqual(store.detail("req-cancel")?.status, .pending)
    }

    /// Fail-closed: a hard biometric failure (no enrolled biometrics / lockout) behaves like cancel
    /// — no seed release, no signature.
    static func testSignDecisionBiometricFailureFailsClosedWithoutTouchingSeed() async throws {
        let gate = FakeBiometricGate(error: .biometricFailed("no biometrics enrolled"))
        let seed = FakeSeedProvider()
        let signer = FakeSignBinding()
        let runtime = Self.runtime(
            core: Self.preparedCore(),
            signer: signer,
            biometricGate: gate,
            seedProvider: seed
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-biofail", expiresAt: 9_999)])

        try await expectThrows(
            try await store.decide("req-biofail", decision: .approved)
        )

        try expectEqual(seed.releaseCount, 0)
        try expect(signer.calls.isEmpty)
        try expectEqual(store.detail("req-biofail")?.status, .pending)
    }

    /// Fail-closed: biometric passes but the Keychain refuses to release the seed → no signature.
    static func testSignDecisionSeedReleaseFailureFailsClosed() async throws {
        let gate = FakeBiometricGate()
        let seed = FakeSeedProvider(error: .seedUnavailable("keychain denied"))
        let signer = FakeSignBinding()
        let runtime = Self.runtime(
            core: Self.preparedCore(),
            signer: signer,
            biometricGate: gate,
            seedProvider: seed
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-noseed", expiresAt: 9_999)])

        try await expectThrows(
            try await store.decide("req-noseed", decision: .approved)
        )

        try expectEqual(gate.authorizeCount, 1)
        try expectEqual(seed.releaseCount, 1)
        try expect(signer.calls.isEmpty)
        try expectEqual(store.detail("req-noseed")?.status, .pending)
    }

    /// Fail-closed: the core signer rejecting the verdict surfaces as a signing failure → pending.
    static func testSignDecisionCoreSignFailureFailsClosed() async throws {
        let gate = FakeBiometricGate()
        let seed = FakeSeedProvider()
        let signer = FakeSignBinding(error: FakeSignError.coreRejected)
        let runtime = Self.runtime(
            core: Self.preparedCore(),
            signer: signer,
            biometricGate: gate,
            seedProvider: seed
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-corefail", expiresAt: 9_999)])

        try await expectThrows(
            try await store.decide("req-corefail", decision: .approved)
        )

        try expectEqual(signer.calls.count, 1)
        try expectEqual(store.detail("req-corefail")?.status, .pending)
    }

    /// A denial never carries a `challenge_response` even if one was supplied, per `docs/contract.md`
    /// (authenticated denials need no challenge). Denials still require biometric auth.
    static func testSignDecisionDenialOmitsChallengeResponse() async throws {
        let gate = FakeBiometricGate()
        let signer = FakeSignBinding()
        let runtime = Self.runtime(
            core: Self.preparedCore(challengeRequired: true, challengeCode: "482"),
            signer: signer,
            biometricGate: gate
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-deny-sign", expiresAt: 9_999)])

        _ = try await store.decide("req-deny-sign", decision: .denied, challengeResponse: "482")

        try expectEqual(gate.authorizeCount, 1)
        let call = try unwrap(signer.calls.first)
        try expect(call.unsigned.contains("\"decision\":\"denied\""))
        try expect(!call.unsigned.contains("challenge_response"))
    }

    /// The signed verdict binds to the *core-computed* `prepared.requestHash`, never the relay
    /// envelope. WYSIWYS: the device signs what the human saw, computed by the core in `prepare()`.
    static func testSignDecisionBindsToCoreComputedHashNotEnvelope() async throws {
        let signer = FakeSignBinding()
        let runtime = Self.runtime(
            core: Self.preparedCore(),
            signer: signer
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-bind", expiresAt: 9_999)])

        _ = try await store.decide("req-bind", decision: .approved)

        let call = try unwrap(signer.calls.first)
        try expect(call.unsigned.contains("\"request_id\":\"req-bind\""))
        try expect(call.unsigned.contains("\"request_hash\":\"hash-verified\""))
        // The fixed verdict clock is used for decided_at, not Date.now().
        try expect(call.unsigned.contains("\"decided_at\":1700000001000"))
    }

    /// The unsigned verdict omits a nil `note` and includes the device cert (which chains the
    /// device key to the account root so the verdict verifies against the root). A missing optional
    /// is what the core deserializer treats as `None`; emitting `"note":null` is avoided. (Checks
    /// the `"note":` key precisely — the bare word "note" appears in unrelated ids.)
    static func testSignDecisionUnsignedVerdictOmitsNilNoteAndCarriesDeviceCert() async throws {
        let signer = FakeSignBinding()
        let runtime = Self.runtime(core: Self.preparedCore(), signer: signer)
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([.fixture(id: "req-misc", expiresAt: 9_999)])

        _ = try await store.decide("req-misc", decision: .approved)

        let call = try unwrap(signer.calls.first)
        try expect(!call.unsigned.contains("\"note\":"))
        try expect(!call.unsigned.contains("\"challenge_response\":"))
        try expect(call.unsigned.contains("\"device_cert\":\"device-cert\""))
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

    static func testDecisionRechecksCoreVerifiedExpiryBeforeSigning() async throws {
        var now: Int64 = 1_000
        let runtime = RecordingRuntime()
        runtime.prepared["req-toctou"] = .command(
            requestHash: "hash-toctou",
            expiresAt: 5_000,
            summary: "rotate production signing key",
            challenge: nil
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { now })
        await store.sync([
            .fixture(id: "req-toctou", expiresAt: 50_000)
        ])

        now = 5_001

        try await expectThrows(
            try await store.decide("req-toctou", decision: .approved)
        )
        try expect(runtime.signInputs.isEmpty)
        try expectEqual(store.detail("req-toctou")?.status, .expired)
    }

    static func testDoubleSubmitProducesOnlyOneSignature() async throws {
        let runtime = SuspendingRuntime()
        runtime.prepared["req-double-submit"] = .command(
            requestHash: "hash-double-submit",
            expiresAt: 50_000,
            summary: "deploy payment worker",
            challenge: nil
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([
            .fixture(id: "req-double-submit", expiresAt: 50_000)
        ])

        let firstDecision = Task {
            try await store.decide("req-double-submit", decision: .approved)
        }
        await runtime.waitUntilSignStarted()

        try await expectInboxError(.alreadyDeciding) {
            try await store.decide("req-double-submit", decision: .approved)
        }
        try expectEqual(runtime.signInputs.count, 1)

        runtime.completeSigning(
            SignedVerdict(
                requestId: "req-double-submit",
                decision: .approved,
                signedVerdictJson: #"{"v":1}"#
            )
        )
        let verdict = try await firstDecision.value

        try expectEqual(verdict.decision, .approved)
        try expectEqual(runtime.signInputs.count, 1)
        try expectEqual(store.detail("req-double-submit")?.status, .approved)
    }

    static func testDeniedOnlyRequestRejectsApproval() async throws {
        let runtime = RecordingRuntime()
        runtime.prepared["req-deny-only"] = .command(
            requestHash: "hash-deny-only",
            expiresAt: 50_000,
            summary: "drop staging database",
            allowedDecisions: [.denied],
            challenge: nil
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([
            .fixture(id: "req-deny-only", expiresAt: 50_000)
        ])

        let listItem = try unwrap(store.inbox.first)
        try expect(listItem.denyOnly)

        try await expectInboxError(.decisionNotAllowed) {
            try await store.decide("req-deny-only", decision: .approved)
        }
        try expect(runtime.signInputs.isEmpty)
    }

    static func testTerminalDecisionSurvivesLaterEmptySync() async throws {
        let runtime = RecordingRuntime()
        runtime.prepared["req-history"] = .command(
            requestHash: "hash-history",
            expiresAt: 50_000,
            summary: "restart production relay",
            challenge: nil
        )
        let store = ApprovalInboxStore(runtime: runtime, nowMs: { 1_000 })
        await store.sync([
            .fixture(id: "req-history", expiresAt: 50_000)
        ])

        _ = try await store.decide("req-history", decision: .approved)
        try expectEqual(store.history.map(\.id), ["req-history"])

        await store.sync([])

        try expect(store.inbox.isEmpty)
        try expectEqual(store.history.map(\.id), ["req-history"])
    }

    static func testCredentialStorePersistsPairedDeviceCredentials() async throws {
        let storage = MemoryNativeCredentialStorage()
        let store = NativeCredentialStore(storage: storage)
        let credentials = NativeDeviceCredentials.fixture()

        try await store.savePairedDevice(credentials)

        try await expectEqual(store.loadPairedDevice(), credentials)
    }

    static func testAccountStateFloorRejectsRollbackBelowStoredSequence() async throws {
        let storage = MemoryNativeCredentialStorage()
        let store = NativeCredentialStore(storage: storage)

        try await expectEqual(
            store.acceptVerifiedAccountState(accountId: "acct-1", relayMaxSequence: 7, verifiedSequence: 7),
            7
        )

        try await expectCredentialStoreError(.staleAccountStateSequence) {
            try await store.acceptVerifiedAccountState(
                accountId: "acct-1",
                relayMaxSequence: 6,
                verifiedSequence: 6
            )
        }
        try expectEqual(storage.accountStateFloors["acct-1"], 7)
    }

    static func testAccountStateFloorRequiresRelayMaxSequenceToBeVerified() async throws {
        let storage = MemoryNativeCredentialStorage()
        let store = NativeCredentialStore(storage: storage)

        try await expectCredentialStoreError(.unverifiedRelayAccountState) {
            try await store.acceptVerifiedAccountState(
                accountId: "acct-1",
                relayMaxSequence: 9,
                verifiedSequence: 8
            )
        }
        try expectEqual(storage.accountStateFloors["acct-1"], nil)
    }

    static func testAccountStateFloorRejectsNegativeSequenceInputs() async throws {
        let storage = MemoryNativeCredentialStorage()
        let store = NativeCredentialStore(storage: storage)

        try await expectCredentialStoreError(.invalidAccountStateSequence) {
            try await store.acceptVerifiedAccountState(
                accountId: "acct-1",
                relayMaxSequence: nil,
                verifiedSequence: -1
            )
        }

        try await expectCredentialStoreError(.invalidAccountStateSequence) {
            try await store.acceptVerifiedAccountState(
                accountId: "acct-1",
                relayMaxSequence: -1,
                verifiedSequence: 0
            )
        }
    }

    #if canImport(Security)
    static func testKeychainAccountStateFloorRejectsMalformedPersistedData() async throws {
        let service = "dev.allw.ios-approver.tests.\(UUID().uuidString)"
        let accountId = "acct-1"
        let store = NativeCredentialStore(storage: KeychainNativeCredentialStorage(service: service))
        try saveRawKeychainAccountStateFloor(service: service, accountId: accountId, data: Data("not-an-int".utf8))

        defer {
            deleteKeychainAccount(service: service, account: "account-state-floor:\(accountId)")
        }

        try await expectCredentialStoreError(.keychainFailure) {
            try await store.acceptVerifiedAccountState(
                accountId: accountId,
                relayMaxSequence: nil,
                verifiedSequence: 1
            )
        }
    }

    static func testKeychainAccountStateFloorRejectsNegativePersistedSequence() async throws {
        let service = "dev.allw.ios-approver.tests.\(UUID().uuidString)"
        let accountId = "acct-1"
        let store = NativeCredentialStore(storage: KeychainNativeCredentialStorage(service: service))
        try saveRawKeychainAccountStateFloor(service: service, accountId: accountId, data: Data("-1".utf8))

        defer {
            deleteKeychainAccount(service: service, account: "account-state-floor:\(accountId)")
        }

        try await expectCredentialStoreError(.invalidAccountStateSequence) {
            try await store.acceptVerifiedAccountState(
                accountId: accountId,
                relayMaxSequence: nil,
                verifiedSequence: 1
            )
        }
    }

    static func testKeychainPairedDeviceCredentialsAreThisDeviceOnly() async throws {
        let service = "dev.allw.ios-approver.tests.\(UUID().uuidString)"
        let store = NativeCredentialStore(storage: KeychainNativeCredentialStorage(service: service))

        defer {
            deleteKeychainAccount(service: service, account: "paired-device")
        }

        try await store.savePairedDevice(.fixture())

        try expectKeychainItemMatchesLocalOnlyQuery(service: service, account: "paired-device")
    }
    #endif
}

// MARK: - UniFfiApproverRuntime test helpers

private extension ApprovalInboxStoreTests {
    static func runtime(
        core: FakeCoreBinding,
        signer: FakeSignBinding = FakeSignBinding(),
        biometricGate: FakeBiometricGate = FakeBiometricGate(),
        seedProvider: FakeSeedProvider = FakeSeedProvider(),
        nonceSource: FixedNonceSource = FixedNonceSource(),
        nowMs: @escaping @Sendable () -> Int64 = { Self.fixedDecidedAt }
    ) -> UniFfiApproverRuntime {
        UniFfiApproverRuntime(
            credentials: .fixture(),
            trust: AccountTrustMaterial(
                accountStateJws: ["state-jws"],
                accountRootPubkeyB64: "root-pubkey"
            ),
            core: core,
            signer: signer,
            biometricGate: biometricGate,
            seedProvider: seedProvider,
            nonceSource: nonceSource,
            nowMs: nowMs
        )
    }

    /// Fixed verdict-decision clock — never `Date.now()` in test data (repo testing rules).
    static let fixedDecidedAt: Int64 = 1_700_000_001_000

    /// A `FakeCoreBinding` returning a verified, approvable prepared context (request hash
    /// `hash-verified`), used by the signDecision tests so the store reaches a `pending` row.
    static func preparedCore(
        challengeRequired: Bool = false,
        challengeCode: String? = nil
    ) -> FakeCoreBinding {
        let core = FakeCoreBinding()
        core.result = CorePreparedApproval(
            contextJson: Self.coreContextJson(summary: "force push to main", challengeRequired: challengeRequired),
            requestHashB64: "hash-verified",
            expiresAt: 50_000,
            attestationVerified: true,
            challengeCode: challengeCode
        )
        return core
    }

    /// Canonical core `ApprovalContext` wire JSON (snake_case) for a command surface — the exact
    /// shape `prepare_approval_json`'s `context_json` produces.
    static func coreContextJson(summary: String, challengeRequired: Bool) -> String {
        """
        {"action":{"record_schema_version":1,"surface":"command","syntactic":{"bin":"git","argv":["git","push","--force"],"cwd":"/repo","raw":"git push --force origin main"},"risk":"critical"},"summary":"\(summary)","actor":{"id":"machine:macbook-pro","kind":"claude-code"},"risk":"critical","reversible":false,"constraints":{"allowed_decisions":["approved","denied"],"challenge_required":\(challengeRequired ? "true" : "false")}}
        """
    }
}

private enum FakeCoreError: Error {
    case decryptFailed
}

private final class FakeCoreBinding: UniFfiCoreBinding, @unchecked Sendable {
    var result: CorePreparedApproval?
    var error: Error?
    private(set) var lastDeviceEncryptionSeedB64: String?
    private(set) var lastRequestId: String?

    func prepare(
        contextCiphertext: String,
        deviceId: String,
        deviceEncryptionSeedB64: String,
        requestId: String,
        accountId: String,
        expiresAt: Int64,
        accountStateJws: [String],
        accountRootPubkeyB64: String
    ) throws -> CorePreparedApproval {
        lastDeviceEncryptionSeedB64 = deviceEncryptionSeedB64
        lastRequestId = requestId
        if let error {
            throw error
        }
        guard let result else {
            throw FakeCoreError.decryptFailed
        }
        return result
    }
}

/// Records the biometric authorize call and, when armed, fails closed (cancel/failure).
private final class FakeBiometricGate: BiometricGate, @unchecked Sendable {
    var error: SecureEnclaveSigningError?
    private(set) var authorizeCount = 0
    private(set) var lastReason: String?

    init(error: SecureEnclaveSigningError? = nil) {
        self.error = error
    }

    func authorize(reason: String) async throws {
        authorizeCount += 1
        lastReason = reason
        if let error {
            throw error
        }
    }
}

/// In-memory signing-seed custody. Throws before releasing the seed when armed, and records whether
/// release happened so tests can prove no seed is touched after a biometric failure.
private final class FakeSeedProvider: SigningSeedProvider, @unchecked Sendable {
    var seedB64: String
    var error: SecureEnclaveSigningError?
    private(set) var releaseCount = 0

    init(seedB64: String = "ZGV2aWNlLXNpZ25pbmctc2VlZA", error: SecureEnclaveSigningError? = nil) {
        self.seedB64 = seedB64
        self.error = error
    }

    func releaseSigningSeedB64() async throws -> String {
        releaseCount += 1
        if let error {
            throw error
        }
        return seedB64
    }
}

/// Records the FFI sign call. Returns a deterministic verdict JSON or throws a core error.
private final class FakeSignBinding: UniFfiSignBinding, @unchecked Sendable {
    var error: Error?
    var verdictJson: String
    private(set) var calls: [(unsigned: String, seed: String, nonce: String)] = []

    init(verdictJson: String = #"{"v":1,"signed":true}"#, error: Error? = nil) {
        self.verdictJson = verdictJson
        self.error = error
    }

    func signVerdict(
        unsignedVerdictJson: String,
        deviceSeedB64: String,
        nonceB64: String
    ) throws -> String {
        calls.append((unsignedVerdictJson, deviceSeedB64, nonceB64))
        if let error {
            throw error
        }
        return verdictJson
    }
}

/// Deterministic nonce so signed-verdict assertions stay stable (no CSPRNG in tests).
private struct FixedNonceSource: VerdictNonceSource {
    var bytes: [UInt8] = Array(repeating: 9, count: 16)

    func freshNonce() -> [UInt8] {
        bytes
    }
}

private enum FakeSignError: Error {
    case coreRejected
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

private final class SuspendingRuntime: ApproverCoreRuntime {
    var prepared: [String: PreparedApproval] = [:]
    var signInputs: [SignDecisionInput] = []
    private var signStartedContinuation: CheckedContinuation<Void, Never>?
    private var signContinuation: CheckedContinuation<SignedVerdict, Error>?

    func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval {
        guard let prepared = prepared[envelope.id] else {
            throw TestFailure("missing prepared fixture for \(envelope.id)")
        }
        return prepared
    }

    func signDecision(_ input: SignDecisionInput) async throws -> SignedVerdict {
        signInputs.append(input)
        signStartedContinuation?.resume()
        signStartedContinuation = nil
        return try await withCheckedThrowingContinuation { continuation in
            signContinuation = continuation
        }
    }

    func waitUntilSignStarted() async {
        if !signInputs.isEmpty {
            return
        }
        await withCheckedContinuation { continuation in
            signStartedContinuation = continuation
        }
    }

    func completeSigning(_ verdict: SignedVerdict) {
        signContinuation?.resume(returning: verdict)
        signContinuation = nil
    }
}

private final class MemoryNativeCredentialStorage: NativeCredentialStorage {
    var credentials: NativeDeviceCredentials?
    var accountStateFloors: [String: Int64] = [:]

    func loadCredentials() async throws -> NativeDeviceCredentials? {
        credentials
    }

    func saveCredentials(_ credentials: NativeDeviceCredentials) async throws {
        self.credentials = credentials
    }

    func loadHighestAccountStateSequence(accountId: String) async throws -> Int64? {
        accountStateFloors[accountId]
    }

    func saveHighestAccountStateSequence(accountId: String, sequence: Int64) async throws {
        accountStateFloors[accountId] = sequence
    }
}

private extension NativeDeviceCredentials {
    static func fixture() -> NativeDeviceCredentials {
        NativeDeviceCredentials(
            accountId: "acct-1",
            deviceId: "dev-1",
            deviceAuthToken: "device-token",
            deviceSigningSeedB64: "signing-seed",
            deviceEncryptionSeedB64: "encryption-seed",
            deviceCert: "device-cert"
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
        allowedDecisions: [ApprovalDecision] = [.approved, .denied],
        challenge: NumberMatchChallenge?
    ) -> PreparedApproval {
        PreparedApproval(
            requestHash: requestHash,
            expiresAt: expiresAt,
            context: ApprovalContext(
                action: .command(CommandAction(cwd: "/repo", argv: ["git", "push", "--force"], raw: nil)),
                actor: ApprovalActor(id: "agent-1", display: "Codex", attestation: .verified),
                risk: ApprovalRisk(level: .critical, reversible: false, summary: summary),
                allowedDecisions: allowedDecisions,
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

private func expectInboxError(
    _ expected: ApprovalInboxErrorKind,
    _ expression: () async throws -> some Sendable
) async throws {
    do {
        _ = try await expression()
        throw TestFailure("expected expression to throw \(expected)")
    } catch let error as ApprovalInboxError {
        try expect(expected.matches(error), "expected \(expected), got \(error)")
    } catch {
        throw TestFailure("expected \(expected), got \(error)")
    }
}

private func expectCredentialStoreError(
    _ expected: NativeCredentialStoreErrorKind,
    _ expression: () async throws -> some Sendable
) async throws {
    do {
        _ = try await expression()
        throw TestFailure("expected expression to throw \(expected)")
    } catch let error as NativeCredentialStoreError {
        try expect(expected.matches(error), "expected \(expected), got \(error)")
    } catch {
        throw TestFailure("expected \(expected), got \(error)")
    }
}

#if canImport(Security)
private func saveRawKeychainAccountStateFloor(service: String, accountId: String, data: Data) throws {
    let account = "account-state-floor:\(accountId)"
    deleteKeychainAccount(service: service, account: account)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String: data,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw TestFailure("Keychain test fixture add failed with status \(status)")
    }
}

private func expectKeychainItemMatchesLocalOnlyQuery(service: String, account: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecAttrSynchronizable as String: false,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
        throw TestFailure("expected Keychain item to match local-only attributes; status \(status)")
    }
}

private func deleteKeychainAccount(service: String, account: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)
}
#endif

private enum ApprovalInboxErrorKind: CustomStringConvertible {
    case alreadyDeciding
    case decisionNotAllowed

    var description: String {
        switch self {
        case .alreadyDeciding:
            return "alreadyDeciding"
        case .decisionNotAllowed:
            return "decisionNotAllowed"
        }
    }

    func matches(_ error: ApprovalInboxError) -> Bool {
        switch (self, error) {
        case (.alreadyDeciding, .alreadyDeciding),
            (.decisionNotAllowed, .decisionNotAllowed):
            return true
        default:
            return false
        }
    }
}

private enum NativeCredentialStoreErrorKind: CustomStringConvertible {
    case invalidAccountStateSequence
    case keychainFailure
    case staleAccountStateSequence
    case unverifiedRelayAccountState

    var description: String {
        switch self {
        case .invalidAccountStateSequence:
            return "invalidAccountStateSequence"
        case .keychainFailure:
            return "keychainFailure"
        case .staleAccountStateSequence:
            return "staleAccountStateSequence"
        case .unverifiedRelayAccountState:
            return "unverifiedRelayAccountState"
        }
    }

    func matches(_ error: NativeCredentialStoreError) -> Bool {
        switch (self, error) {
        case (.invalidAccountStateSequence, .invalidAccountStateSequence),
            (.keychainFailure, .keychainFailure),
            (.staleAccountStateSequence, .staleAccountStateSequence),
            (.unverifiedRelayAccountState, .unverifiedRelayAccountState):
            return true
        default:
            return false
        }
    }
}
