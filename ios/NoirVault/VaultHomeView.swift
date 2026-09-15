import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct VaultHomeView: View {
    @EnvironmentObject private var session: VaultSession
    let store: VaultStore
    @Binding var errorMessage: String?
    @State private var query = ""
    @State private var category: VaultItemType?
    @State private var showingEditor = false
    @State private var editorType = VaultItemType.password
    @State private var showingSettings = false
    @State private var codesOnly = false

    private var filteredItems: [VaultItem] {
        session.data.items.filter { item in
            let matchesCategory = category == nil || category == item.itemType
            let matchesCodes = !codesOnly || item.hasTOTP
            let haystack = [item.title, item.description, item.tags.joined(separator: " ")].joined(separator: " ").lowercased()
            return matchesCategory && matchesCodes && (query.isEmpty || haystack.contains(query.lowercased()))
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 10) {
                            FilterChip(title: "All", symbol: "square.grid.2x2", selected: category == nil) { category = nil }
                            FilterChip(title: "Codes", symbol: "timer", selected: codesOnly) { codesOnly.toggle() }
                            ForEach(VaultItemType.allCases) { type in
                                FilterChip(title: type.title, symbol: type.symbol, selected: category == type) { category = type }
                            }
                        }
                    }
                    .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
                    .listRowBackground(Color.clear)
                }

                Section {
                    if filteredItems.isEmpty {
                        ContentUnavailableView("No matching items", systemImage: "magnifyingglass", description: Text("Add a password, note, file, or SSH key."))
                            .listRowBackground(Color.clear)
                    }
                    ForEach(filteredItems) { item in
                        Button {
                            session.select(item)
                            UISelectionFeedbackGenerator().selectionChanged()
                        } label: {
                            VaultRow(item: item)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(VaultRowButtonStyle())
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                session.delete(item)
                                save()
                            } label: { Label("Delete", systemImage: "trash") }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(NoirTheme.ink)
            .navigationTitle("NoirVault")
            .searchable(text: $query, prompt: "Search your vault")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    HStack {
                        Button { showingSettings = true } label: { Image(systemName: "gearshape.fill") }
                        Button { session.lock() } label: { Image(systemName: "lock.fill") }
                            .accessibilityLabel("Lock vault")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        ForEach(VaultItemType.allCases) { type in
                            Button(type.title, systemImage: type.symbol) {
                                editorType = type
                                showingEditor = true
                            }
                        }
                    } label: { Image(systemName: "plus.circle.fill") }
                }
                ToolbarItem(placement: .bottomBar) {
                    Button {
                        save()
                    } label: {
                        Label("Save to USB", systemImage: "externaldrive.fill")
                    }
                }
            }
            .navigationDestination(item: Binding(
                get: { session.selectedItem },
                set: { if $0 == nil { session.selectedItemID = nil } }
            )) { item in
                RecordDetailView(item: item, onDelete: {
                    session.delete(item)
                    save()
                })
            }
            .sheet(isPresented: $showingEditor) {
                RecordEditorView(type: editorType) { item in
                    session.add(item)
                    save()
                }
            }
            .sheet(isPresented: $showingSettings) { SecuritySettingsView() }
        }
    }

    private func save() {
        do {
            try session.save(using: store)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } catch {
            session.lock()
            errorMessage = error.localizedDescription
        }
    }
}

private struct SecuritySettingsView: View {
    @EnvironmentObject private var session: VaultSession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("Sensitive actions") {
                    Toggle("Require Face ID to copy secrets", isOn: $session.requireBiometricsToCopy)
                }
                Section("Automatic lock") {
                    Picker("Lock after", selection: $session.autoLockSeconds) {
                        Text("30 seconds").tag(30)
                        Text("1 minute").tag(60)
                        Text("5 minutes").tag(300)
                    }
                }
                Section {
                    Text("These preferences reset whenever NoirVault locks. The app does not keep vault data or your master password on this iPhone.")
                        .font(.footnote)
                        .foregroundStyle(NoirTheme.muted)
                }
            }
            .scrollContentBackground(.hidden)
            .background(NoirTheme.ink)
            .navigationTitle("Security")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

private struct FilterChip: View {
    let title: String
    let symbol: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.subheadline.weight(.semibold))
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(selected ? NoirTheme.violet : NoirTheme.elevated, in: Capsule())
        }
        .buttonStyle(.plain)
    }
}

private struct VaultRow: View {
    let item: VaultItem

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: item.itemType.symbol)
                .font(.title3.weight(.semibold))
                .foregroundStyle(NoirTheme.mint)
                .frame(width: 38, height: 38)
                .background(NoirTheme.elevated, in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 3) {
                Text(item.title).font(.headline)
                Text(item.description.isEmpty ? item.itemType.title : item.description)
                    .font(.subheadline)
                    .foregroundStyle(NoirTheme.muted)
            }
            Spacer()
            if item.hasTOTP { Image(systemName: "timer").foregroundStyle(NoirTheme.mint) }
            if !item.tags.isEmpty { Text(item.tags.first ?? "").font(.caption).foregroundStyle(NoirTheme.violet) }
        }
        .padding(.vertical, 5)
    }
}

private struct VaultRowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .opacity(configuration.isPressed ? 0.72 : 1)
            .animation(.snappy(duration: 0.18), value: configuration.isPressed)
    }
}
