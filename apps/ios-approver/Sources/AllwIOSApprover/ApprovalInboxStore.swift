import Foundation

private struct ApprovalRecord {
    let envelope: ApprovalEnvelope
    let prepared: PreparedApproval?
    let verificationError: String?
    var status: ApprovalStatus
    var decidedAt: Int64?

    var expiresAt: Int64 {
        prepared?.expiresAt ?? envelope.expiresAt
    }
}

/// Native inbox state machine for the iOS dev-mode approver.
///
/// This type deliberately contains no crypto, hashing, or JSON canonicalization. It only enforces
/// UI lifecycle rules around values produced by `ApproverCoreRuntime`, preserving the repo's
/// thin-shell discipline: the shared Rust core prepares WYSIWYS data and signs verdicts; Swift
/// decides whether the UI can ask the core to sign.
public final class ApprovalInboxStore {
    private let runtime: ApproverCoreRuntime
    private let nowMs: () -> Int64
    private var records: [String: ApprovalRecord] = [:]

    public init(runtime: ApproverCoreRuntime, nowMs: @escaping () -> Int64) {
        self.runtime = runtime
        self.nowMs = nowMs
    }

    /// Current actionable inbox, including fail-closed states that need to be visible to the
    /// human. Expiry is refreshed from the prepared/core-verified deadline on every read.
    public var inbox: [ApprovalListItem] {
        expirePendingRecords()
        return records.values
            .filter { [.pending, .deciding, .expired, .unverified].contains($0.status) }
            .sorted { $0.envelope.createdAt < $1.envelope.createdAt }
            .map(toListItem)
    }

    /// Terminal decisions retained for the eventual audit/history surface.
    public var history: [ApprovalListItem] {
        records.values
            .filter { [.approved, .denied].contains($0.status) }
            .sorted { ($0.decidedAt ?? 0) < ($1.decidedAt ?? 0) }
            .map(toListItem)
    }

    /// Replace the local inbox with relay envelopes. Each envelope prepares independently so one
    /// malformed or undecryptable request becomes an unverified row instead of hiding the rest.
    public func sync(_ envelopes: [ApprovalEnvelope]) async {
        var next: [String: ApprovalRecord] = [:]
        for envelope in envelopes {
            next[envelope.id] = await prepareRecord(envelope)
        }
        // Relay sync returns the active inbox, not the local audit/history surface. Retain
        // terminal rows that disappeared from the active feed so resolved decisions remain
        // visible until a dedicated history store replaces this in-memory model.
        for (id, record) in records where [.approved, .denied].contains(record.status) && next[id] == nil {
            next[id] = record
        }
        records = next
        expirePendingRecords()
    }

    public func detail(_ id: String) -> ApprovalDetail? {
        expirePendingRecords()
        guard let record = records[id] else {
            return nil
        }
        return toDetail(record)
    }

    /// Approval requires a prepared request, a live core-verified deadline, an allowed approved
    /// decision, and a satisfied number-match challenge when one is present.
    public func canApprove(_ id: String, challengeResponse: String? = nil) -> Bool {
        expirePendingRecords()
        guard
            let record = records[id],
            record.status == .pending,
            let prepared = record.prepared,
            prepared.context.allowedDecisions.contains(.approved)
        else {
            return false
        }
        return challengeSatisfied(prepared.context.challenge, response: challengeResponse)
    }

    /// Ask the core runtime to sign a human decision. The store claims the row as `deciding`
    /// before awaiting the runtime so duplicate taps cannot produce two verdicts. On a signing
    /// error, it restores `pending` so the human can retry without losing the request.
    @discardableResult
    public func decide(
        _ id: String,
        decision: ApprovalDecision,
        challengeResponse: String? = nil
    ) async throws -> SignedVerdict {
        expirePendingRecords()
        guard var record = records[id] else {
            throw ApprovalInboxError.unknownRequest("unknown request '\(id)'")
        }
        guard record.status != .deciding else {
            throw ApprovalInboxError.alreadyDeciding("request '\(id)' is already being decided")
        }
        guard record.status != .expired else {
            throw ApprovalInboxError.expired("request '\(id)' is expired")
        }
        guard let prepared = record.prepared, record.status != .unverified else {
            throw ApprovalInboxError.notApprovable("request '\(id)' is not approvable")
        }
        guard prepared.context.allowedDecisions.contains(decision) else {
            throw ApprovalInboxError.decisionNotAllowed(
                "decision '\(decision.rawValue)' is not allowed for request '\(id)'"
            )
        }
        if decision == .approved && !canApprove(id, challengeResponse: challengeResponse) {
            throw ApprovalInboxError.notApprovable("request '\(id)' is not approvable")
        }

        record.status = .deciding
        records[id] = record

        let input = SignDecisionInput(
            envelope: record.envelope,
            prepared: prepared,
            decision: decision,
            challengeResponse: challengeResponse
        )
        do {
            let verdict = try await runtime.signDecision(input)
            record.status = decision == .approved ? .approved : .denied
            record.decidedAt = nowMs()
            records[id] = record
            return verdict
        } catch {
            record.status = .pending
            records[id] = record
            throw error
        }
    }

    private func prepareRecord(_ envelope: ApprovalEnvelope) async -> ApprovalRecord {
        do {
            let prepared = try await runtime.prepare(envelope: envelope)
            let status = status(for: prepared)
            return ApprovalRecord(
                envelope: envelope,
                prepared: prepared,
                verificationError: nil,
                status: status,
                decidedAt: nil
            )
        } catch let error as ApprovalInboxError {
            return unverifiedRecord(envelope, message: error.description)
        } catch {
            return unverifiedRecord(envelope, message: String(describing: error))
        }
    }

    private func status(for prepared: PreparedApproval) -> ApprovalStatus {
        if let resolved = prepared.resolvedDecision {
            return resolved == .approved ? .approved : .denied
        }
        if prepared.expiresAt <= nowMs() {
            return .expired
        }
        if prepared.context.actor.attestation != .verified {
            return .unverified
        }
        return .pending
    }

    private func unverifiedRecord(_ envelope: ApprovalEnvelope, message: String) -> ApprovalRecord {
        ApprovalRecord(
            envelope: envelope,
            prepared: nil,
            verificationError: message,
            status: .unverified,
            decidedAt: nil
        )
    }

    private func expirePendingRecords() {
        for (id, record) in records where record.status == .pending && record.expiresAt <= nowMs() {
            var expired = record
            expired.status = .expired
            records[id] = expired
        }
    }

    private func challengeSatisfied(_ challenge: NumberMatchChallenge?, response: String?) -> Bool {
        guard let challenge else {
            return true
        }
        return response == challenge.code
    }

    private func toListItem(_ record: ApprovalRecord) -> ApprovalListItem {
        let context = record.prepared?.context
        return ApprovalListItem(
            id: record.envelope.id,
            status: record.status,
            actor: context?.actor.display ?? "Unverified request",
            riskLevel: context?.risk.level,
            summary: context?.risk.summary ?? "Unable to decrypt or verify this request",
            expiresAt: record.expiresAt,
            countdownMs: max(0, record.expiresAt - nowMs()),
            denyOnly: denyOnly(record)
        )
    }

    private func toDetail(_ record: ApprovalRecord) -> ApprovalDetail {
        let context = record.prepared?.context
        return ApprovalDetail(
            id: record.envelope.id,
            status: record.status,
            actor: context?.actor.display ?? "Unverified request",
            actorId: context?.actor.id,
            attestation: context?.actor.attestation,
            riskLevel: context?.risk.level,
            summary: context?.risk.summary ?? "Unable to decrypt or verify this request",
            exactPlaintext: context.map(renderExactPlaintext) ?? "",
            requestHash: record.prepared?.requestHash,
            expiresAt: record.expiresAt,
            countdownMs: max(0, record.expiresAt - nowMs()),
            denyOnly: denyOnly(record),
            challenge: context?.challenge,
            verificationError: record.verificationError
        )
    }

    private func denyOnly(_ record: ApprovalRecord) -> Bool {
        guard record.status == .pending, let prepared = record.prepared else {
            return true
        }
        return !prepared.context.allowedDecisions.contains(.approved)
    }

    private func renderExactPlaintext(_ context: ApprovalContext) -> String {
        switch context.action {
        case .command(let command):
            if let raw = command.raw, !raw.isEmpty {
                return raw
            }
            let cwdPrefix = command.cwd.map { "cd \($0)\n" } ?? ""
            return cwdPrefix + command.argv.joined(separator: " ")
        case .mcp(let call):
            return "\(call.server).\(call.tool)\n\(call.paramsSummary)"
        }
    }
}
