// ActivityKit's `ActivityAttributes` protocol is `iOS`-only — it is explicitly `unavailable` on
// macOS, so this file is gated on `os(iOS)` rather than `canImport(ActivityKit)` (which is true on
// macOS too). Consequence: this surface compiles and validates only in the Xcode/iOS build, NOT in
// the repo's macOS `swiftc` CI job. The testable lifecycle lives in `LiveActivityController.swift`
// and the state model in `LiveActivityState.swift`, both of which DO compile on the CI host.
#if os(iOS)
import ActivityKit
import Foundation

/// ActivityKit attributes for the ambient pending-approvals Live Activity.
///
/// Static `attributes` are fixed for the lifetime of the activity; the dynamic `ContentState` is the
/// part ActivityKit updates as the inbox changes. We mirror `PendingApprovalsActivityState` into the
/// content state so the widget renders the same count + deadline the store derived.
@available(iOS 16.1, *)
public struct PendingApprovalsActivityAttributes: ActivityAttributes {
    public struct ContentState: Codable, Hashable, Sendable {
        /// Number of requests awaiting a human decision.
        public let pendingCount: Int
        /// Absolute deadline (epoch millis) of the soonest-expiring pending request. The widget
        /// binds a `Text(timerInterval:)` to this instant so the OS animates the countdown without a
        /// push for every tick.
        public let nextExpiryAt: Int64?

        public init(pendingCount: Int, nextExpiryAt: Int64?) {
            self.pendingCount = pendingCount
            self.nextExpiryAt = nextExpiryAt
        }

        /// Bridge the platform-agnostic state into the ActivityKit content state.
        public init(_ state: PendingApprovalsActivityState) {
            self.pendingCount = state.pendingCount
            self.nextExpiryAt = state.nextExpiryAt
        }

        /// The soonest expiry as a `Date`, for `Text(timerInterval:)`. `nil` when nothing is pending.
        public var nextExpiryDate: Date? {
            nextExpiryAt.map { Date(timeIntervalSince1970: Double($0) / 1000) }
        }
    }

    /// Account label shown on the ambient surface so a multi-account user can tell whose queue this
    /// is. Carries no request content — the ambient surface never renders plaintext.
    public let accountLabel: String

    public init(accountLabel: String) {
        self.accountLabel = accountLabel
    }
}
#endif
