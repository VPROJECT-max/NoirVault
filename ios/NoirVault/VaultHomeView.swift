import SwiftUI
import UIKit

private struct EditorRequest: Identifiable {
    let id = UUID()
    let type: VaultItemType
    var item: VaultItem? = nil
}

struct VaultHomeView: View {
    @EnvironmentObject private var session: VaultSession
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let store: VaultStore
    @Binding var errorMessage: String?
    @State private var query = ""
    @State private var filter = VaultFilter.all
    @State private var sort = VaultSort.name
    @State private var editor: EditorRequest?
    @State private var showingSettings = false
    @State private var showingGenerator = false
    @State private var codesOnly = false
    @State private var pendingDelete: VaultItem?
    @State private var toast: String?
    @State private var toastID = UUID()

    private var filteredItems: [VaultItem] {
        VaultSearch.items(session.data.items, query: query, filter: codesOnly ? .all : filter, codesOnly: codesOnly, sort: sort)
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: "externaldrive.badge.checkmark").font(.title2).foregroundStyle(NoirTheme.mint)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Your USB vault").font(.headline)
                            Text("\(session.data.items.count) items · encrypted on your drive")
                                .font(.caption).foregroundStyle(NoirTheme.muted)
                        }
                        Spacer()
                        Image(systemName: "lock.open.fill").foregroundStyle(NoirTheme.mint).accessibilityLabel("Unlocked")
                    }
                    .padding(.vertical, 6)
                    Picker("Library", selection: $codesOnly) {
                        Text("Vault").tag(false)
                        Text("Authenticator").tag(true)
                    }.pickerStyle(.segmented).listRowSeparator(.hidden)
                    if !codesOnly {
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(VaultFilter.allCases) { value in
                                    Button {
                                        withAnimation(reduceMotion ? nil : .snappy(duration: 0.2)) { filter = value }
                                        session.touch()
                                    } label: {
                                        Text(value.title).font(.subheadline.weight(.medium))
                                            .padding(.horizontal, 14).frame(minHeight: 44)
                                            .background(filter == value ? NoirTheme.violet.opacity(0.25) : NoirTheme.elevated, in: Capsule())
                                            .foregroundStyle(filter == value ? NoirTheme.violet : .white)
                                    }
                                    .buttonStyle(.plain)
                                    .accessibilityAddTraits(filter == value ? .isSelected : [])
                                }
                            }
                        }
                    }
                }
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)

                Section {
                    if filteredItems.isEmpty { emptyState.listRowBackground(Color.clear).listRowSeparator(.hidden) }
                    ForEach(filteredItems) { item in
                        VStack(alignment: .leading, spacing: 14) {
                            Button { session.select(item); session.touch() } label: { VaultRow(item: item) }
                                .buttonStyle(.plain)
                                .accessibilityIdentifier("vault-row-\(item.id)")
                            if codesOnly, let configuration = item.totpConfiguration {
                                TOTPCodeView(configuration: configuration)
                            }
                        }
                        .padding(.vertical, codesOnly ? 8 : 0)
                        .listRowBackground(NoirTheme.panel)
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) { pendingDelete = item } label: { Label("Delete", systemImage: "trash") }
                            Button { edit(item) } label: { Label("Edit", systemImage: "pencil") }.tint(NoirTheme.violet)
                        }
                        .swipeActions(edge: .leading, allowsFullSwipe: false) {
                            Button { favorite(item) } label: {
                                Label(item.isFavorite ? "Unfavorite" : "Favorite", systemImage: item.isFavorite ? "star.slash" : "star")
                            }.tint(.orange)
                        }
                    }
                } header: {
                    HStack {
                        Text(codesOnly ? "Verification codes" : filter.title)
                        Spacer()
                        Text("\(filteredItems.count)").monospacedDigit()
                    }.textCase(nil)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden).background(NoirTheme.ink)
            .navigationTitle(codesOnly ? "Authenticator" : "NoirVault")
            .searchable(text: $query, prompt: codesOnly ? "Search accounts" : "Search names, accounts, tags")
            .onChange(of: query) { _, _ in session.touch() }
            .onChange(of: codesOnly) { _, _ in session.touch(); query = "" }
            .onScrollPhaseChange { _, phase in if phase != .idle { session.touch() } }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showingSettings = true; session.touch() } label: { Image(systemName: "gearshape") }
                        .accessibilityLabel("Settings")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Picker("Sort by", selection: $sort) { ForEach(VaultSort.allCases) { Text($0.title).tag($0) } }
                        Button("Password generator", systemImage: "wand.and.stars") { showingGenerator = true; session.touch() }
                        Button("Save and lock", systemImage: "lock.fill") { saveAndLock() }
                    } label: { Image(systemName: "ellipsis.circle") }.accessibilityLabel("Vault options")
                }
                ToolbarItem(placement: .bottomBar) {
                    HStack {
                        Label(session.lastSavedAt == nil ? "USB connected" : "Saved to USB", systemImage: "checkmark.shield.fill")
                            .font(.caption).foregroundStyle(NoirTheme.mint)
                        Spacer()
                        Menu {
                            ForEach(VaultItemType.allCases.filter { $0 != .passkey }) { type in
                                Button(type.title, systemImage: type.symbol) { editor = EditorRequest(type: type); session.touch() }
                            }
                        } label: { Label("New item", systemImage: "plus.circle.fill").font(.headline) }
                    }
                }
            }
            .navigationDestination(item: $session.selectedItemID) { id in
                if let item = session.data.items.first(where: { $0.id == id }) {
                    RecordDetailView(item: item, onEdit: { edit(item) }, onFavorite: { favorite(item) }, onDelete: { delete(item) })
                }
            }
            .sheet(item: $editor) { request in
                RecordEditorView(type: request.type, item: request.item) { item in
                    try session.upsert(item, using: store)
                    notify("Saved to USB")
                }
            }
            .sheet(isPresented: $showingSettings) { SecuritySettingsView() }
            .sheet(isPresented: $showingGenerator) { PasswordGeneratorView() }
            .confirmationDialog("Delete \(pendingDelete?.title ?? "item")?", isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }), titleVisibility: .visible) {
                Button("Delete from USB vault", role: .destructive) { if let item = pendingDelete { delete(item) }; pendingDelete = nil }
            } message: { Text("This cannot be undone.") }
            .overlay(alignment: .bottom) {
                if let toast {
                    Label(toast, systemImage: "checkmark.circle.fill")
                        .font(.callout.weight(.medium)).padding(.horizontal, 18).padding(.vertical, 12)
                        .background(NoirTheme.elevated, in: Capsule()).padding(.bottom, 12)
                        .allowsHitTesting(false)
                        .transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity))
                }
            }
            .task(id: toastID) {
                guard toast != nil else { return }
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
                withAnimation(reduceMotion ? nil : .easeOut(duration: 0.2)) { toast = nil }
            }
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label(query.isEmpty ? (codesOnly ? "Your codes belong here" : "A place for your secrets") : "No matches", systemImage: codesOnly ? "qrcode" : "lock.square.stack")
        } description: {
            Text(query.isEmpty ? (codesOnly ? "Add an authenticator on its own, or attach one to a login." : "Add an item or choose another filter.") : "Try another name, account, website or tag.")
        } actions: {
            if query.isEmpty {
                Button(codesOnly ? "Add authenticator" : "Add password") { editor = EditorRequest(type: codesOnly ? .authenticator : .password) }
                    .buttonStyle(.borderedProminent)
            } else { Button("Clear search") { query = "" } }
        }
    }
    private func edit(_ item: VaultItem) { session.touch(); editor = EditorRequest(type: item.itemType, item: item) }
    private func favorite(_ item: VaultItem) {
        var updated = item; updated.isFavorite.toggle()
        do { try session.upsert(updated, using: store); notify(updated.isFavorite ? "Added to favorites" : "Removed from favorites") }
        catch { errorMessage = "Not saved. \(error.localizedDescription)" }
    }
    private func delete(_ item: VaultItem) {
        do { try session.remove(item, using: store); notify("Deleted from USB") }
        catch { errorMessage = "Not deleted. \(error.localizedDescription)" }
    }
    private func saveAndLock() {
        do { try session.save(using: store); session.lock() }
        catch { errorMessage = "Could not save. \(error.localizedDescription)" }
    }
    private func notify(_ message: String) {
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        withAnimation(reduceMotion ? nil : .snappy(duration: 0.25)) { toast = message; toastID = UUID() }
    }
}

private struct SecuritySettingsView: View {
    @EnvironmentObject private var session: VaultSession
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            Form {
                Section("Protect secrets") {
                    Toggle("Face ID to reveal or copy", isOn: $session.requireBiometricsToCopy)
                    Text("Applies to passwords, notes, private keys and verification codes. Copied secrets expire after 15 seconds and stay on this device.")
                        .font(.footnote).foregroundStyle(NoirTheme.muted)
                }
                Section("Automatic lock") {
                    Picker("When inactive for", selection: $session.autoLockSeconds) {
                        Text("30 seconds").tag(30); Text("1 minute").tag(60); Text("5 minutes").tag(300)
                    }
                    Text("NoirVault also locks when you leave the app or disconnect your USB.").font(.footnote).foregroundStyle(NoirTheme.muted)
                }
                Section("AutoFill & passkeys") {
                    Label("Enable NoirVault in iOS Settings → General → AutoFill & Passwords.", systemImage: "key.fill")
                    Text("Create passkeys from a website or app's account settings, then choose NoirVault. Keep the paired USB connected. System integration requires your installer to preserve the AutoFill extension and its entitlements.")
                        .font(.footnote).foregroundStyle(NoirTheme.muted)
                }
                Section("Storage") {
                    Label("Vault contents stay encrypted on your USB.", systemImage: "externaldrive.fill")
                    Text("Only non-secret preferences and device pairing information persist on your phone. AutoFill uses a device-bound key protected by biometrics.")
                        .font(.footnote).foregroundStyle(NoirTheme.muted)
                }
            }
            .scrollContentBackground(.hidden).background(NoirTheme.ink)
            .navigationTitle("Settings")
            .onChange(of: session.autoLockSeconds) { _, _ in session.touch() }
            .onChange(of: session.requireBiometricsToCopy) { _, _ in session.touch() }
            .onScrollPhaseChange { _, phase in if phase != .idle { session.touch() } }
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

private struct VaultRow: View {
    let item: VaultItem
    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: item.itemType.symbol).font(.title3.weight(.semibold))
                .foregroundStyle(item.itemType == .authenticator ? NoirTheme.violet : NoirTheme.mint)
                .frame(width: 44, height: 44).background(NoirTheme.elevated, in: RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 5) {
                Text(item.title).font(.headline).foregroundStyle(.white).lineLimit(2)
                Text(item.subtitle).font(.subheadline).foregroundStyle(NoirTheme.muted).lineLimit(1)
            }
            Spacer(minLength: 8)
            if item.isFavorite { Image(systemName: "star.fill").font(.caption).foregroundStyle(.orange).accessibilityLabel("Favorite") }
            if item.hasTOTP && item.itemType != .authenticator { Image(systemName: "timer").foregroundStyle(NoirTheme.mint).accessibilityLabel("Has authenticator") }
            Image(systemName: "chevron.right").font(.caption.weight(.bold)).foregroundStyle(NoirTheme.muted)
        }
        .padding(.vertical, 10).frame(maxWidth: .infinity, minHeight: 64, alignment: .leading)
        .contentShape(Rectangle()).accessibilityElement(children: .combine)
    }
}
