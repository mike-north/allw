import Foundation

/// Snapshot of a request id and its lifecycle state, used to reconcile delivered notifications
/// after a fetch+refresh. The coordinator clears notifications for ids that are no longer pending.
public struct InboxNotificationState: Equatable, Sendable {
    public let id: String
    public let status: ApprovalStatus

    public init(id: String, status: ApprovalStatus) {
        self.id = id
        self.status = status
    }
}

/// The native notification surface seam (production wraps `UNUserNotificationCenter`).
///
/// Thin shell: the coordinator decides *which* request ids should have a live notification and which
/// must be cleared; this seam only performs the platform delivery/removal. Push payloads carry a
/// **request id only** — never human-shown context (`docs/contract.md` §Push) — so `present` receives
/// just an id; the actual WYSIWYS context is fetched and decrypted on-device via the core. Tests
/// inject a recording fake; the real `UNUserNotificationCenter` wiring validates only in CI's macOS
/// `native-bindings` job.
public protocol InboxNotificationSurface: Sendable {
    /// Ensure a pending-approval notification is present for `requestId`. Idempotent: presenting an
    /// id that already has a live notification must not duplicate it.
    func presentPending(requestId: String) async
    /// Remove any delivered/pending notification for `requestId` (request resolved, expired, or
    /// became unverifiable). Idempotent.
    func clear(requestId: String) async
}

/// The seam that registers the device's APNs token with the relay during pairing.
///
/// Push tokens are registered by including `push_tokens` on authenticated `POST /pairing/complete`
/// (`docs/contract.md` §Push). The app delegate receives the raw APNs token from
/// `didRegisterForRemoteNotificationsWithDeviceToken`; this seam hex-encodes it (the relay accepts
/// 64-char hex APNs tokens) and forwards it through the relay client. Tests inject a fake.
public protocol PushTokenRegistering: Sendable {
    /// Register a raw APNs device token (the bytes delivered by the OS) with the relay. Throws on a
    /// relay/transport failure so the app can retry; a missing push token degrades to polling, never
    /// to a false "registered" state.
    func registerApnsToken(_ rawToken: [UInt8]) async throws
}

/// Errors from the push/inbox coordinator. All are fail-closed: a wakeup that cannot complete a
/// fetch leaves the inbox unchanged rather than rendering a fabricated or partial request.
public enum PushInboxError: Error, Equatable, CustomStringConvertible, Sendable {
    case fetchFailed(String)

    public var description: String {
        switch self {
        case .fetchFailed(let message):
            return "push wakeup fetch failed: \(message)"
        }
    }
}

/// Coordinates the iOS approver's push-driven inbox lifecycle (issue #142):
///
/// 1. **APNs wakeup** → `handleWakeup(requestId:)`. The payload carries a request id only (never
///    context), so the coordinator does not trust it for rendering — it is purely a signal to refresh.
/// 2. **Fetch** the full relay-visible envelopes via `RelayInboxFetching`
///    (`GET /devices/{id}/inbox`).
/// 3. **Prepare + refresh** by handing the envelopes to `ApprovalInboxStore.sync`, which runs each
///    through the core `prepare()` (decrypt + WYSIWYS hash + attestation verification in `allw-core`).
/// 4. **Reconcile notifications**: present a notification for every still-pending request and clear
///    notifications for request ids that resolved, expired, or became unverifiable.
///
/// Fail-closed throughout: a fetch error never crashes and never renders an approved-looking row; an
/// unverifiable request decrypts to an `.unverified`, deny-only row (handled by the store/core), and
/// its notification is cleared rather than presented as actionable.
///
/// `@MainActor`: the coordinator owns UI-bound state (`ApprovalInboxStore`) and notification
/// presentation, so it runs on the main actor like the rest of the inbox surface.
@MainActor
public final class PushInboxCoordinator {
    private let store: ApprovalInboxStore
    private let relay: RelayInboxFetching
    private let notifications: InboxNotificationSurface
    private let pushRegistrar: PushTokenRegistering?

    /// Request ids the coordinator currently believes have a live, actionable notification. Used to
    /// reconcile against the post-fetch inbox so resolved/expired ids get their notification cleared.
    private var notifiedRequestIds: Set<String> = []

    public init(
        store: ApprovalInboxStore,
        relay: RelayInboxFetching,
        notifications: InboxNotificationSurface,
        pushRegistrar: PushTokenRegistering? = nil
    ) {
        self.store = store
        self.relay = relay
        self.notifications = notifications
        self.pushRegistrar = pushRegistrar
    }

    /// Register the device's raw APNs token with the relay (called from the app delegate's
    /// `didRegisterForRemoteNotificationsWithDeviceToken`). No-op when no registrar is configured.
    public func registerApnsToken(_ rawToken: [UInt8]) async throws {
        try await pushRegistrar?.registerApnsToken(rawToken)
    }

    /// Handle an APNs wakeup. `requestId` is the only context the push carries; it is used solely as
    /// a refresh signal — the coordinator always fetches the authoritative inbox from the relay and
    /// never trusts the push payload as request data.
    ///
    /// Returns the current actionable inbox after the refresh so the UI/Live-Activity layer can
    /// update. Throws `PushInboxError.fetchFailed` (fail-closed) if the relay fetch fails — the
    /// existing inbox and notifications are left untouched rather than cleared on a transient error.
    @discardableResult
    public func handleWakeup(requestId: String?) async throws -> [ApprovalListItem] {
        let envelopes: [ApprovalEnvelope]
        do {
            envelopes = try await relay.fetchPendingEnvelopes()
        } catch {
            throw PushInboxError.fetchFailed(String(describing: error))
        }

        await store.sync(envelopes)
        return await reconcileNotifications()
    }

    /// Refresh from the relay without an APNs wakeup (e.g. foreground poll or pull-to-refresh).
    /// Shares the fetch→sync→reconcile path so notification state stays consistent.
    @discardableResult
    public func refresh() async throws -> [ApprovalListItem] {
        try await handleWakeup(requestId: nil)
    }

    /// After a local decision resolves a request, clear its notification immediately rather than
    /// waiting for the next fetch. The store already moved the row to a terminal status.
    public func didResolve(requestId: String) async {
        notifiedRequestIds.remove(requestId)
        await notifications.clear(requestId: requestId)
    }

    /// Read the post-sync inbox, present notifications for still-pending (actionable) requests, and
    /// clear notifications for ids that are no longer pending. Only `.pending` rows are actionable;
    /// `.unverified`, `.expired`, and `.deciding` rows are never presented as fresh approvals (an
    /// unverifiable request must not look approvable — `docs/contract.md` fail-closed).
    private func reconcileNotifications() async -> [ApprovalListItem] {
        let items = store.inbox
        let actionable = Set(items.filter { $0.status == .pending }.map(\.id))

        let toClear = notifiedRequestIds.subtracting(actionable)
        for id in toClear {
            await notifications.clear(requestId: id)
        }
        let toPresent = actionable.subtracting(notifiedRequestIds)
        for id in toPresent {
            await notifications.presentPending(requestId: id)
        }

        notifiedRequestIds = actionable
        return items
    }

    /// Hex-encode a raw APNs device token to the 64-char lowercase form the relay accepts
    /// (`docs/contract.md` §Push). `nonisolated` because it is a pure byte transform with no actor
    /// state — callable off the main actor (e.g. from the registrar). Exposed for tests.
    public nonisolated static func hexEncodeApnsToken(_ rawToken: [UInt8]) -> String {
        rawToken.map { String(format: "%02x", $0) }.joined()
    }
}

/// A `PushTokenRegistering` that hex-encodes the raw APNs token and forwards the encoded string to
/// an injected relay sender.
///
/// The relay registers push tokens via authenticated `POST /pairing/complete` (`docs/contract.md`
/// §Push); the concrete HTTP call lives in the app's pairing flow (out of this slice's scope), so
/// this registrar is parameterized over an async sender closure rather than reimplementing the relay
/// client. Keeping the registrar this thin means the standalone `swiftc` validation does not need to
/// link any networking, and tests can assert on the exact hex-encoded token forwarded.
public struct HexApnsTokenRegistrar: PushTokenRegistering {
    private let send: @Sendable (String) async throws -> Void

    public init(send: @escaping @Sendable (String) async throws -> Void) {
        self.send = send
    }

    public func registerApnsToken(_ rawToken: [UInt8]) async throws {
        try await send(PushInboxCoordinator.hexEncodeApnsToken(rawToken))
    }
}
