import Foundation

/// Ambient, glanceable pending state for the iOS Live Activity / Dynamic Island
/// (`docs/architecture.md` → "Ambient, glanceable pending state": "N approvals pending" + an
/// expiry countdown).
///
/// This type is deliberately platform-agnostic and crypto-free: it carries only the read-only
/// summary the ambient surface renders. All security-relevant lifecycle (decrypt, verify, sign,
/// expire) stays in `ApprovalInboxStore` / the core. The Live Activity never makes a decision and
/// never renders request plaintext — it shows a count and a deadline, and deep-links into the app
/// for the WYSIWYS surface.
public struct PendingApprovalsActivityState: Equatable, Sendable {
    /// Number of requests awaiting a human decision (`.pending` rows only). Deciding/expired/
    /// unverified rows are intentionally excluded: the ambient count answers "how many decisions do
    /// I still owe?", and an unverified row is not actionable from the ambient surface.
    public let pendingCount: Int

    /// Absolute epoch-millis deadline of the soonest-expiring pending request, or `nil` when nothing
    /// is pending. The widget renders a live countdown to this instant; using the absolute deadline
    /// (not a precomputed remaining-ms) lets ActivityKit tick the timer without a push update.
    public let nextExpiryAt: Int64?

    public init(pendingCount: Int, nextExpiryAt: Int64?) {
        self.pendingCount = pendingCount
        self.nextExpiryAt = nextExpiryAt
    }

    /// The cleared/empty ambient state — nothing pending. The coordinator ends the Live Activity
    /// when the inbox reaches this state so a resolved (or expired) queue clears the surface.
    public static let cleared = PendingApprovalsActivityState(pendingCount: 0, nextExpiryAt: nil)

    /// Whether anything is pending. When `false`, the ambient surface should be cleared, not shown.
    public var hasPending: Bool {
        pendingCount > 0
    }

    /// Remaining milliseconds until the next expiry relative to `nowMs`, floored at zero. `nil` when
    /// nothing is pending. Provided for non-ActivityKit consumers (and tests); the live widget binds
    /// to `nextExpiryAt` directly so the OS can animate the countdown.
    public func countdownMs(nowMs: Int64) -> Int64? {
        guard let nextExpiryAt else {
            return nil
        }
        return max(0, nextExpiryAt - nowMs)
    }

    /// Derive the ambient state from the current actionable inbox. Only `.pending` rows count toward
    /// the ambient summary; the soonest `expiresAt` among them drives the countdown. An inbox with
    /// no pending rows yields `.cleared`, which clears the Live Activity.
    public static func derive(from inbox: [ApprovalListItem]) -> PendingApprovalsActivityState {
        let pending = inbox.filter { $0.status == .pending }
        guard !pending.isEmpty else {
            return .cleared
        }
        let nextExpiry = pending.map(\.expiresAt).min()
        return PendingApprovalsActivityState(pendingCount: pending.count, nextExpiryAt: nextExpiry)
    }
}
