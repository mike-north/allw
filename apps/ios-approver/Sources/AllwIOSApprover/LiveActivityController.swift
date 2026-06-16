import Foundation

/// Platform seam for presenting the ambient pending-approvals surface. The real implementation is an
/// ActivityKit-backed presenter compiled only on iOS (see `PendingApprovalsLiveActivity.swift`);
/// tests inject a fake so the start/update/clear lifecycle is deterministic on the macOS CI host
/// (where ActivityKit's `ActivityAttributes` is unavailable).
///
/// The presenter is intentionally a dumb sink: it receives a desired state and reflects it. All the
/// "should we start vs update vs end" decisions live in `LiveActivityCoordinator` so that logic is
/// testable without ActivityKit.
public protocol PendingApprovalsActivityPresenter: AnyObject, Sendable {
    /// Begin presenting a fresh Live Activity for the given non-empty pending state.
    func start(_ state: PendingApprovalsActivityState) async throws

    /// Update the already-presented Live Activity to a new non-empty pending state.
    func update(_ state: PendingApprovalsActivityState) async throws

    /// End and remove the Live Activity (the inbox reached the cleared state — resolved or expired).
    func end() async throws
}

/// Drives the ambient Live Activity from `ApprovalInboxStore` ambient state, deciding whether to
/// start, update, or clear the surface as the inbox changes.
///
/// Lifecycle rules (`docs/architecture.md` → ambient presence; ties to the cross-device retract in
/// "Cross-device notification coordination"):
/// - First pending → `start`.
/// - Still pending, state changed → `update`.
/// - No longer pending (all resolved/expired) → `end` (clear-on-resolve).
/// - No change → no presenter call (avoids redundant ActivityKit churn).
///
/// The coordinator holds no crypto and never decides an approval. It is read-only ambient display of
/// state the store already computed.
public actor LiveActivityCoordinator {
    private let presenter: PendingApprovalsActivityPresenter
    private var presentedState: PendingApprovalsActivityState?

    public init(presenter: PendingApprovalsActivityPresenter) {
        self.presenter = presenter
    }

    /// Whether a Live Activity is currently being presented (i.e. last applied state had pending
    /// requests). Exposed for the app target and tests.
    public var isPresenting: Bool {
        presentedState?.hasPending ?? false
    }

    /// Reconcile the ambient surface to `state`. Idempotent: applying the same state twice issues no
    /// second presenter call. Safe to call on every `ApprovalInboxStore.sync()` /
    /// `ApprovalInboxStore.decide()`.
    public func apply(_ state: PendingApprovalsActivityState) async throws {
        if !state.hasPending {
            // Clear-on-resolve: only end if something was actually being presented.
            if isPresenting {
                try await presenter.end()
            }
            presentedState = .cleared
            return
        }

        if isPresenting {
            // Avoid redundant churn when nothing the human would see changed.
            if presentedState != state {
                try await presenter.update(state)
            }
        } else {
            try await presenter.start(state)
        }
        presentedState = state
    }
}
