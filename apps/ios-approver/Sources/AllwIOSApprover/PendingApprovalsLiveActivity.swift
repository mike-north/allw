// WidgetKit + ActivityKit Live Activity / Dynamic Island UI for the ambient pending state.
// iOS-only (ActivityKit `ActivityAttributes` is unavailable on macOS), so this validates only in the
// Xcode/iOS build, not the macOS `swiftc` CI job. See `PendingApprovalsActivityAttributes.swift`.
//
// WYSIWYS discipline: this surface shows a count and an expiry countdown only — never the command,
// diff, or any request plaintext. Tapping deep-links into the app, which renders the core-prepared
// WYSIWYS detail and gates Secure-Enclave signing. We never present an inline "Approve" affordance
// over content the lock screen cannot WYSIWYS-render (issue #143 scope note).
#if os(iOS)
import ActivityKit
import SwiftUI
import WidgetKit

@available(iOS 16.2, *)
public struct PendingApprovalsLiveActivity: Widget {
    public init() {}

    public var body: some WidgetConfiguration {
        ActivityConfiguration(for: PendingApprovalsActivityAttributes.self) { context in
            // Lock-screen / banner presentation.
            LockScreenView(
                accountLabel: context.attributes.accountLabel,
                state: context.state
            )
            .activityBackgroundTint(Color.black.opacity(0.4))
            .activitySystemActionForegroundColor(Color.primary)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label("\(context.state.pendingCount)", systemImage: "checkmark.shield.fill")
                        .font(.title2)
                        .foregroundStyle(.tint)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    countdown(for: context.state)
                        .font(.title3.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    Text(headline(for: context.state))
                        .font(.headline)
                }
            } compactLeading: {
                Image(systemName: "checkmark.shield.fill")
                    .foregroundStyle(.tint)
            } compactTrailing: {
                Text("\(context.state.pendingCount)")
                    .font(.caption.monospacedDigit())
            } minimal: {
                Text("\(context.state.pendingCount)")
                    .font(.caption2.monospacedDigit())
            }
            .keylineTint(.accentColor)
        }
    }

    private func headline(for state: PendingApprovalsActivityAttributes.ContentState) -> String {
        state.pendingCount == 1 ? "1 approval pending" : "\(state.pendingCount) approvals pending"
    }

    @ViewBuilder
    private func countdown(
        for state: PendingApprovalsActivityAttributes.ContentState
    ) -> some View {
        if let expiry = state.nextExpiryDate {
            Text(timerInterval: Date()...expiry, countsDown: true)
        } else {
            Text("—")
        }
    }
}

@available(iOS 16.2, *)
private struct LockScreenView: View {
    let accountLabel: String
    let state: PendingApprovalsActivityAttributes.ContentState

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "checkmark.shield.fill")
                .font(.title2)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(headline)
                    .font(.headline)
                Text(accountLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if let expiry = state.nextExpiryDate {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Expires in")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(timerInterval: Date()...expiry, countsDown: true)
                        .font(.title3.monospacedDigit())
                        .multilineTextAlignment(.trailing)
                }
            }
        }
        .padding()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(headline), \(accountLabel)")
    }

    private var headline: String {
        state.pendingCount == 1 ? "1 approval pending" : "\(state.pendingCount) approvals pending"
    }
}
#endif
