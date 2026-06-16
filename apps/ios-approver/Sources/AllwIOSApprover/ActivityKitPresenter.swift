// Real ActivityKit-backed presenter for the ambient Live Activity. iOS-only (ActivityKit
// `Activity`/`ActivityAttributes` are unavailable on macOS), so this validates only in the Xcode/iOS
// build, not the macOS `swiftc` CI job. The platform-agnostic lifecycle decisions it serves live in
// `LiveActivityCoordinator` and are exercised against a fake presenter on the CI host.
#if os(iOS)
import ActivityKit
import Foundation

/// Errors raised while presenting the ambient Live Activity. Surfaced to the coordinator's caller;
/// they never affect approval lifecycle (the ambient surface is read-only and best-effort).
public enum ActivityKitPresenterError: Error, Equatable, Sendable {
    /// `ActivityAuthorizationInfo().areActivitiesEnabled` is false (user disabled Live Activities).
    case activitiesDisabled
    /// An update/end was requested but no activity is currently running.
    case noActiveActivity
}

/// Drives a single ActivityKit `Activity` for the pending-approvals attributes. Holds a reference to
/// the live activity so updates and the clear-on-resolve `end` target the same instance.
///
/// This is a thin adapter: it owns no decision logic — `LiveActivityCoordinator` decides
/// start/update/end. It only translates those into ActivityKit calls.
@available(iOS 16.2, *)
public actor ActivityKitPresenter: PendingApprovalsActivityPresenter {
    private let attributes: PendingApprovalsActivityAttributes
    private var activity: Activity<PendingApprovalsActivityAttributes>?

    public init(accountLabel: String) {
        self.attributes = PendingApprovalsActivityAttributes(accountLabel: accountLabel)
    }

    public func start(_ state: PendingApprovalsActivityState) async throws {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            throw ActivityKitPresenterError.activitiesDisabled
        }
        // If one is somehow already live, reuse it as an update rather than spawning a duplicate.
        if activity != nil {
            try await update(state)
            return
        }
        let content = ActivityContent(
            state: PendingApprovalsActivityAttributes.ContentState(state),
            staleDate: state.nextExpiryDate
        )
        activity = try Activity.request(
            attributes: attributes,
            content: content,
            pushType: nil
        )
    }

    public func update(_ state: PendingApprovalsActivityState) async throws {
        guard let activity else {
            throw ActivityKitPresenterError.noActiveActivity
        }
        let content = ActivityContent(
            state: PendingApprovalsActivityAttributes.ContentState(state),
            staleDate: state.nextExpiryDate
        )
        await activity.update(content)
    }

    public func end() async throws {
        guard let activity else {
            return
        }
        // Clear-on-resolve: dismiss immediately so a resolved/expired queue does not linger.
        await activity.end(nil, dismissalPolicy: .immediate)
        self.activity = nil
    }
}
#endif
