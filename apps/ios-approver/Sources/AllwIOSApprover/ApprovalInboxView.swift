import SwiftUI

/// Minimal SwiftUI shell for the native inbox.
///
/// The view is deliberately dumb: it renders `ApprovalListItem` values produced by
/// `ApprovalInboxStore` and sends selection back to the app target. Expiry, verification, and
/// signing eligibility stay in the store/core boundary so SwiftUI cannot accidentally make an
/// unsafe state approvable.
@available(iOS 17.0, macOS 14.0, *)
public struct ApprovalInboxView: View {
    private let items: [ApprovalListItem]
    private let onSelect: (String) -> Void

    public init(items: [ApprovalListItem], onSelect: @escaping (String) -> Void) {
        self.items = items
        self.onSelect = onSelect
    }

    public var body: some View {
        NavigationStack {
            List(items, id: \.id) { item in
                Button {
                    onSelect(item.id)
                } label: {
                    ApprovalInboxRow(item: item)
                }
                .buttonStyle(.plain)
                .disabled(item.status == .expired || item.status == .unverified)
            }
            .navigationTitle("Approvals")
        }
    }
}

@available(iOS 17.0, macOS 14.0, *)
private struct ApprovalInboxRow: View {
    let item: ApprovalListItem

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            statusGlyph
                .font(.title3)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(item.summary)
                    .font(.headline)
                    .lineLimit(2)
                Text(item.actor)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(statusColor)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(item.summary), \(item.actor), \(statusText)")
    }

    private var statusGlyph: some View {
        Image(systemName: systemImageName)
            .foregroundStyle(statusColor)
            .frame(width: 28)
    }

    private var systemImageName: String {
        switch item.status {
        case .pending:
            return item.denyOnly ? "exclamationmark.triangle.fill" : "checkmark.seal.fill"
        case .deciding:
            return "hourglass"
        case .expired:
            return "clock.badge.exclamationmark.fill"
        case .unverified:
            return "exclamationmark.shield.fill"
        case .approved:
            return "checkmark.circle.fill"
        case .denied:
            return "xmark.circle.fill"
        }
    }

    private var statusText: String {
        switch item.status {
        case .pending:
            return item.denyOnly ? "Review required before approval" : "Ready for decision"
        case .deciding:
            return "Signing verdict"
        case .expired:
            return "Expired"
        case .unverified:
            return "Unverified"
        case .approved:
            return "Approved"
        case .denied:
            return "Denied"
        }
    }

    private var statusColor: Color {
        switch item.status {
        case .pending:
            return item.denyOnly ? .orange : .accentColor
        case .deciding:
            return .blue
        case .expired, .unverified:
            return .red
        case .approved:
            return .green
        case .denied:
            return .secondary
        }
    }
}
