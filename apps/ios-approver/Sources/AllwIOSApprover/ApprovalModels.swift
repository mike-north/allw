import Foundation

/// Human decisions supported by the v1 verdict contract.
public enum ApprovalDecision: String, Equatable, Sendable {
    case approved
    case denied
}

/// Render/sign lifecycle state for a request in the native inbox.
public enum ApprovalStatus: String, Equatable, Sendable {
    case pending
    case deciding
    case expired
    case unverified
    case approved
    case denied
}

/// Actor-origin display state. A native app may render unverified requests, but must never
/// present them as trusted or let them become approvable.
public enum ActorAttestationState: String, Equatable, Sendable {
    case verified
    case unverified
    case pending
}

/// Contract risk levels shown in the WYSIWYS detail.
public enum ApprovalRiskLevel: String, Equatable, Sendable {
    case low
    case medium
    case high
    case critical
}

/// Errors the native inbox turns into fail-closed render states.
public enum ApprovalInboxError: Error, Equatable, CustomStringConvertible, Sendable {
    case unknownRequest(String)
    case unverified(String)
    case expired(String)
    case notApprovable(String)
    case decisionNotAllowed(String)
    case alreadyDeciding(String)
    case signingFailed(String)

    public var description: String {
        switch self {
        case .unknownRequest(let message),
            .unverified(let message),
            .expired(let message),
            .notApprovable(let message),
            .decisionNotAllowed(let message),
            .alreadyDeciding(let message),
            .signingFailed(let message):
            return message
        }
    }
}

/// Relay-visible lifecycle envelope. The app never trusts this as the WYSIWYS expiry by itself;
/// `PreparedApproval.expiresAt` is the core-verified deadline used for state transitions.
public struct ApprovalEnvelope: Equatable, Sendable {
    public let v: Int
    public let id: String
    public let createdAt: Int64
    public let expiresAt: Int64
    public let approver: String
    public let contextCiphertext: String

    public init(
        v: Int,
        id: String,
        createdAt: Int64,
        expiresAt: Int64,
        approver: String,
        contextCiphertext: String
    ) {
        self.v = v
        self.id = id
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.approver = approver
        self.contextCiphertext = contextCiphertext
    }
}

public struct ApprovalActor: Equatable, Sendable {
    public let id: String
    public let display: String
    public let attestation: ActorAttestationState

    public init(id: String, display: String, attestation: ActorAttestationState) {
        self.id = id
        self.display = display
        self.attestation = attestation
    }
}

public struct ApprovalRisk: Equatable, Sendable {
    public let level: ApprovalRiskLevel
    public let reversible: Bool
    public let summary: String

    public init(level: ApprovalRiskLevel, reversible: Bool, summary: String) {
        self.level = level
        self.reversible = reversible
        self.summary = summary
    }
}

public struct CommandAction: Equatable, Sendable {
    public let cwd: String?
    public let argv: [String]
    public let raw: String?

    public init(cwd: String?, argv: [String], raw: String?) {
        self.cwd = cwd
        self.argv = argv
        self.raw = raw
    }
}

public struct McpCallAction: Equatable, Sendable {
    public let server: String
    public let tool: String
    public let paramsSummary: String

    public init(server: String, tool: String, paramsSummary: String) {
        self.server = server
        self.tool = tool
        self.paramsSummary = paramsSummary
    }
}

public enum ApprovalAction: Equatable, Sendable {
    case command(CommandAction)
    case mcp(McpCallAction)
}

public struct NumberMatchChallenge: Equatable, Sendable {
    public let code: String
    public let prompt: String

    public init(code: String, prompt: String) {
        self.code = code
        self.prompt = prompt
    }
}

/// Decrypted and core-prepared WYSIWYS payload. The request hash and expiry must come from the
/// shared core boundary, not from UI-side recomputation.
public struct PreparedApproval: Equatable, Sendable {
    public let requestHash: String
    public let expiresAt: Int64
    public let context: ApprovalContext
    public let resolvedDecision: ApprovalDecision?

    public init(
        requestHash: String,
        expiresAt: Int64,
        context: ApprovalContext,
        resolvedDecision: ApprovalDecision? = nil
    ) {
        self.requestHash = requestHash
        self.expiresAt = expiresAt
        self.context = context
        self.resolvedDecision = resolvedDecision
    }
}

public struct ApprovalContext: Equatable, Sendable {
    public let action: ApprovalAction
    public let actor: ApprovalActor
    public let risk: ApprovalRisk
    public let allowedDecisions: [ApprovalDecision]
    public let challenge: NumberMatchChallenge?

    public init(
        action: ApprovalAction,
        actor: ApprovalActor,
        risk: ApprovalRisk,
        allowedDecisions: [ApprovalDecision],
        challenge: NumberMatchChallenge?
    ) {
        self.action = action
        self.actor = actor
        self.risk = risk
        self.allowedDecisions = allowedDecisions
        self.challenge = challenge
    }
}

public struct SignDecisionInput: Equatable, Sendable {
    public let envelope: ApprovalEnvelope
    public let prepared: PreparedApproval
    public let decision: ApprovalDecision
    public let challengeResponse: String?

    public init(
        envelope: ApprovalEnvelope,
        prepared: PreparedApproval,
        decision: ApprovalDecision,
        challengeResponse: String?
    ) {
        self.envelope = envelope
        self.prepared = prepared
        self.decision = decision
        self.challengeResponse = challengeResponse
    }
}

public struct SignedVerdict: Equatable, Sendable {
    public let requestId: String
    public let decision: ApprovalDecision
    public let signedVerdictJson: String

    public init(requestId: String, decision: ApprovalDecision, signedVerdictJson: String) {
        self.requestId = requestId
        self.decision = decision
        self.signedVerdictJson = signedVerdictJson
    }
}

public struct ApprovalListItem: Equatable, Sendable {
    public let id: String
    public let status: ApprovalStatus
    public let actor: String
    public let riskLevel: ApprovalRiskLevel?
    public let summary: String
    public let expiresAt: Int64
    public let countdownMs: Int64
    public let denyOnly: Bool
}

public struct ApprovalDetail: Equatable, Sendable {
    public let id: String
    public let status: ApprovalStatus
    public let actor: String
    public let actorId: String?
    public let attestation: ActorAttestationState?
    public let riskLevel: ApprovalRiskLevel?
    public let summary: String
    public let exactPlaintext: String
    public let requestHash: String?
    public let expiresAt: Int64
    public let countdownMs: Int64
    public let denyOnly: Bool
    public let challenge: NumberMatchChallenge?
    public let verificationError: String?
}

/// Thin shell boundary over the shared core. Production implementations call UniFFI-generated
/// functions; tests use a fake runtime so UI lifecycle rules stay deterministic.
public protocol ApproverCoreRuntime: AnyObject {
    func prepare(envelope: ApprovalEnvelope) async throws -> PreparedApproval
    func signDecision(_ input: SignDecisionInput) async throws -> SignedVerdict
}
