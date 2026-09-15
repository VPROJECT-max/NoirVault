import SwiftUI

struct CredentialProviderView: View {
    let title: String
    let message: String
    let items: [VaultItem]
    let onSelect: (VaultItem) -> Void
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                NoirTheme.ink.ignoresSafeArea()
                if items.isEmpty {
                    VStack(spacing: 18) {
                        Image(systemName: "externaldrive.badge.checkmark")
                            .font(.system(size: 50, weight: .semibold))
                            .foregroundStyle(NoirTheme.mint)
                        Text(title).font(.title2.bold())
                        Text(message).foregroundStyle(NoirTheme.muted).multilineTextAlignment(.center)
                    }
                    .padding(28)
                } else {
                    List(items) { item in
                        Button { onSelect(item) } label: {
                            HStack(spacing: 14) {
                                Image(systemName: item.itemType.symbol).foregroundStyle(NoirTheme.mint)
                                VStack(alignment: .leading) {
                                    Text(item.title).font(.headline)
                                    Text(item.description).font(.caption).foregroundStyle(NoirTheme.muted)
                                }
                                Spacer()
                                if item.hasTOTP { Image(systemName: "timer").foregroundStyle(NoirTheme.violet) }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                    .scrollContentBackground(.hidden)
                }
            }
            .navigationTitle(title)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel", action: onCancel) } }
        }
        .preferredColorScheme(.dark)
    }
}
