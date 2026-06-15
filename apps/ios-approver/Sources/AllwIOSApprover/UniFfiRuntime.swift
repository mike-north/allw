import Foundation

/// Configuration the eventual Xcode target will load from Keychain after pairing.
///
/// The device holds **two distinct seeds**: an Ed25519 `deviceSigningSeedB64` for signing verdicts
/// and an X25519 `deviceEncryptionSeedB64` the relay envelope's JWE is encrypted to. They key
/// separate cryptosystems and MUST be independently random (see the UniFFI `derive_device_keys_json`
/// docs and `docs/enrollment.md`); collapsing them into one seed is an enrollment defect.
public struct NativeDeviceCredentials: Codable, Equatable, Sendable {
    public let accountId: String
    public let deviceId: String
    public let deviceAuthToken: String
    public let deviceSigningSeedB64: String
    public let deviceEncryptionSeedB64: String
    public let deviceCert: String

    public init(
        accountId: String,
        deviceId: String,
        deviceAuthToken: String,
        deviceSigningSeedB64: String,
        deviceEncryptionSeedB64: String,
        deviceCert: String
    ) {
        self.accountId = accountId
        self.deviceId = deviceId
        self.deviceAuthToken = deviceAuthToken
        self.deviceSigningSeedB64 = deviceSigningSeedB64
        self.deviceEncryptionSeedB64 = deviceEncryptionSeedB64
        self.deviceCert = deviceCert
    }
}

/// Root-anchored account trust material the runtime needs to verify an actor attestation.
///
/// `accountStateJws` are the root-signed `allw-account-state+jws` documents the app fetched, and
/// `accountRootPubkeyB64` is the configured account root (base64url Ed25519 public key). A relay can
/// distribute the documents but cannot author them, so verification can only ever be driven by the
/// configured root — never by un-anchored relay metadata.
public struct AccountTrustMaterial: Equatable, Sendable {
    public let accountStateJws: [String]
    public let accountRootPubkeyB64: String

    public init(accountStateJws: [String], accountRootPubkeyB64: String) {
        self.accountStateJws = accountStateJws
        self.accountRootPubkeyB64 = accountRootPubkeyB64
    }
}

/// The raw JSON payload the UniFFI `prepare_approval_json` core call returns.
///
/// This mirrors the Rust `PreparedApprovalJson` shape exactly. `contextJson` is the decrypted
/// `ApprovalContext` re-serialized as canonical core wire JSON; `requestHashB64` and `expiresAt` are
/// the **device-computed** WYSIWYS binding; `attestationVerified` is the verified-vs-asserted bit.
public struct CorePreparedApproval: Equatable, Sendable {
    public let contextJson: String
    public let requestHashB64: String
    public let expiresAt: Int64
    public let attestationVerified: Bool
    public let challengeCode: String?

    public init(
        contextJson: String,
        requestHashB64: String,
        expiresAt: Int64,
        attestationVerified: Bool,
        challengeCode: String?
    ) {
        self.contextJson = contextJson
        self.requestHashB64 = requestHashB64
        self.expiresAt = expiresAt
        self.attestationVerified = attestationVerified
        self.challengeCode = challengeCode
    }
}

/// The narrow seam over the generated UniFFI binding.
///
/// The `apps/ios-approver` package compiles standalone (its local `swiftc` validation does not link
/// the generated bindings), so the runtime never references generated symbols directly. The Xcode
/// target wires `corePrepare` to the generated `prepareApprovalJson`; tests inject a fake. All
/// crypto stays in Rust — this seam only carries the JSON string boundary.
public protocol UniFfiCoreBinding: Sendable {
    /// Decrypt + recompute WYSIWYS hash + verify attestation, returning the parsed core payload.
    /// Throws on any decrypt/hash failure (fail-closed); an unverified origin is reported via
    /// `attestationVerified`, not thrown.
    func prepare(
        contextCiphertext: String,
        deviceId: String,
        deviceEncryptionSeedB64: String,
        requestId: String,
        accountId: String,
        expiresAt: Int64,
        accountStateJws: [String],
        accountRootPubkeyB64: String
    ) throws -> CorePreparedApproval
}

/// Native runtime entry point for the iOS shell.
///
/// Thin shell: every security-critical operation (JWE decrypt, WYSIWYS hashing, attestation
/// verification) runs in `allw-core` via the `UniFfiCoreBinding` seam. This type only marshals
/// inputs, decodes the canonical core `ApprovalContext` JSON into the render model, and maps the
/// core-reported attestation result onto the inbox's verified/unverified display state. It never
/// hashes, decrypts, or interprets crypto itself.
public final class UniFfiApproverRuntime: ApproverCoreRuntime {
    private let credentials: NativeDeviceCredentials
    private let trust: AccountTrustMaterial
    private let core: UniFfiCoreBinding

    public init(
        credentials: NativeDeviceCredentials,
        trust: AccountTrustMaterial,
        core: UniFfiCoreBinding
    ) {
        self.credentials = credentials
        self.trust = trust
        self.core = core
    }

    public func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval {
        // Decrypt + recompute hash + verify attestation in the core. Any decrypt/hash failure throws
        // here and the store renders the request `.unverified` — never a partial looks-approved state.
        let prepared: CorePreparedApproval
        do {
            prepared = try core.prepare(
                contextCiphertext: envelope.contextCiphertext,
                deviceId: credentials.deviceId,
                deviceEncryptionSeedB64: credentials.deviceEncryptionSeedB64,
                requestId: envelope.id,
                accountId: credentials.accountId,
                expiresAt: envelope.expiresAt,
                accountStateJws: trust.accountStateJws,
                accountRootPubkeyB64: trust.accountRootPubkeyB64
            )
        } catch let error as ApprovalInboxError {
            throw error
        } catch {
            throw ApprovalInboxError.unverified(
                "core prepare failed for request '\(envelope.id)': \(error)"
            )
        }

        let context = try Self.renderContext(
            from: prepared,
            requestId: envelope.id
        )
        return PreparedApproval(
            requestHash: prepared.requestHashB64,
            expiresAt: prepared.expiresAt,
            context: context
        )
    }

    public func signDecision(_ input: SignDecisionInput) async throws -> SignedVerdict {
        // The production implementation will call UniFFI `sign_verdict_json` with
        // `credentials.deviceSigningSeedB64` and a random nonce after `prepare` is backed by real
        // decrypted context. Leaving this fail-closed prevents a dev-mode app from signing a
        // verdict that did not pass core preparation first. (Signing is issue #141.)
        throw ApprovalInboxError.signingFailed(
            "UniFFI verdict signing is gated until native Secure-Enclave signing lands (#141)"
        )
    }

    /// Decode the canonical core `ApprovalContext` JSON into the render model, mapping the
    /// core-reported `attestationVerified` onto the inbox's display state. Throws fail-closed on any
    /// structural mismatch — a context the device cannot model is treated as unverifiable.
    static func renderContext(
        from prepared: CorePreparedApproval,
        requestId: String
    ) throws -> ApprovalContext {
        guard let data = prepared.contextJson.data(using: .utf8) else {
            throw ApprovalInboxError.unverified(
                "core context for request '\(requestId)' was not valid UTF-8"
            )
        }
        let wire: WireApprovalContext
        do {
            wire = try JSONDecoder().decode(WireApprovalContext.self, from: data)
        } catch {
            throw ApprovalInboxError.unverified(
                "core context for request '\(requestId)' could not be decoded: \(error)"
            )
        }

        let action = try wire.action.toRenderAction(requestId: requestId)
        let attestationState: ActorAttestationState = prepared.attestationVerified ? .verified : .unverified
        let actor = ApprovalActor(
            id: wire.actor.id,
            display: prepared.attestationVerified
                ? "\(wire.actor.kind) · \(wire.actor.id)"
                : wire.actor.id,
            attestation: attestationState
        )
        let risk = ApprovalRisk(
            level: wire.risk.toRenderLevel(),
            reversible: wire.reversible,
            summary: wire.summary
        )
        let allowed = wire.constraints.allowedDecisions.compactMap { $0.toRenderDecision() }
        let challenge: NumberMatchChallenge?
        if wire.constraints.challengeRequired, let code = prepared.challengeCode {
            challenge = NumberMatchChallenge(code: code, prompt: "Enter \(code) to approve")
        } else {
            challenge = nil
        }
        return ApprovalContext(
            action: action,
            actor: actor,
            risk: risk,
            allowedDecisions: allowed,
            challenge: challenge
        )
    }
}

// MARK: - Wire decoding (mirrors the canonical core ApprovalContext JSON)

/// Decodable mirror of the core `ApprovalContext` wire JSON (snake_case keys). Kept private to the
/// runtime so the public render model stays free of wire concerns.
private struct WireApprovalContext: Decodable {
    let action: WireActionRecord
    let summary: String
    let actor: WireActor
    let risk: WireRisk
    let reversible: Bool
    let constraints: WireConstraints
}

private struct WireActor: Decodable {
    let id: String
    let kind: String
}

private struct WireConstraints: Decodable {
    let allowedDecisions: [WireDecision]
    let challengeRequired: Bool

    enum CodingKeys: String, CodingKey {
        case allowedDecisions = "allowed_decisions"
        case challengeRequired = "challenge_required"
    }
}

private enum WireRisk: String, Decodable {
    case low, medium, high, critical

    func toRenderLevel() -> ApprovalRiskLevel {
        switch self {
        case .low: return .low
        case .medium: return .medium
        case .high: return .high
        case .critical: return .critical
        }
    }
}

private enum WireDecision: String, Decodable {
    case approved, denied, expired, aborted

    /// Only human-selectable decisions map into the render model; lifecycle-only decisions
    /// (`expired`/`aborted`) are not approver choices and are dropped.
    func toRenderDecision() -> ApprovalDecision? {
        switch self {
        case .approved: return .approved
        case .denied: return .denied
        case .expired, .aborted: return nil
        }
    }
}

private enum WireSurface: String, Decodable {
    case command
    case mcpToolCall = "mcp_tool_call"
    case fileEdit = "file_edit"
}

private struct WireActionRecord: Decodable {
    let surface: WireSurface
    let syntactic: WireSyntacticSubstrate

    func toRenderAction(requestId: String) throws -> ApprovalAction {
        switch surface {
        case .command, .fileEdit:
            return .command(
                CommandAction(
                    cwd: syntactic.cwd,
                    argv: syntactic.argv ?? [],
                    raw: syntactic.raw
                )
            )
        case .mcpToolCall:
            guard let server = syntactic.server, let tool = syntactic.tool else {
                throw ApprovalInboxError.unverified(
                    "core MCP action for request '\(requestId)' is missing server/tool"
                )
            }
            return .mcp(
                McpCallAction(
                    server: server,
                    tool: tool,
                    paramsSummary: syntactic.raw ?? ""
                )
            )
        }
    }
}

private struct WireSyntacticSubstrate: Decodable {
    let argv: [String]?
    let cwd: String?
    let server: String?
    let tool: String?
    let raw: String?
}
