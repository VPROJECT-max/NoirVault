import SwiftUI
import UIKit
import LocalAuthentication
import UniformTypeIdentifiers

struct VaultAttachmentDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

struct RecordDetailView: View {
    @EnvironmentObject private var session: VaultSession
    let item: VaultItem
    let onEdit: () -> Void
    let onFavorite: () -> Void
    let onDelete: () -> Void
    @State private var showingDeleteConfirmation = false
    @State private var copied = false
    @State private var exportDocument: VaultAttachmentDocument?
    @State private var exportError: String?
    @State private var revealed = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 14) {
                    Image(systemName: item.itemType.symbol)
                        .font(.title)
                        .foregroundStyle(NoirTheme.mint)
                    VStack(alignment: .leading) {
                        Text(item.title).font(.title2.bold())
                        if !item.description.isEmpty { Text(item.description).foregroundStyle(NoirTheme.muted) }
                    }
                }
                .noirCard()

                if !item.description.isEmpty && (item.itemType == .password || item.itemType == .authenticator) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Account").font(.caption).foregroundStyle(NoirTheme.muted)
                        Text(item.description).textSelection(.enabled)
                        Button("Copy account", systemImage: "doc.on.doc") { copy(item.description) }
                    }.noirCard()
                }
                if let url = item.websiteURL {
                    Link(destination: url) { Label(url.host ?? item.website, systemImage: "arrow.up.right.square").frame(maxWidth: .infinity, alignment: .leading) }
                        .noirCard()
                }

                if item.itemType == .passkey, let material = item.passkeyMaterial {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("USB-resident passkey", systemImage: "person.badge.key.fill")
                            .font(.headline).foregroundStyle(NoirTheme.mint)
                        LabeledContent("Website", value: material.relyingParty)
                        LabeledContent("Account", value: material.userName)
                        Text("The private key stays encrypted inside the paired USB vault and is never displayed or copied.")
                            .font(.footnote).foregroundStyle(NoirTheme.muted)
                    }
                    .noirCard()
                } else if item.itemType == .file {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("This attachment is encrypted inside your USB vault.")
                            .foregroundStyle(NoirTheme.muted)
                        Button("Export file", systemImage: "square.and.arrow.up") {
                            Task {
                                guard await session.authorizeSecretAccess() else { return }
                                guard let data = Data(base64Encoded: item.content) else {
                                    exportError = "The encrypted attachment is corrupted."
                                    return
                                }
                                exportDocument = VaultAttachmentDocument(data: data)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(NoirTheme.violet)
                    }
                    .noirCard()
                } else if item.itemType != .authenticator {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(item.itemType == .password ? "Password" : "Secret data")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(NoirTheme.muted)
                        if revealed {
                            Text(item.content)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                        } else {
                            Text("••••••••••••").font(.system(.title3, design: .monospaced))
                                .accessibilityLabel("Secret hidden")
                        }
                        Button(revealed ? "Hide" : "Reveal", systemImage: revealed ? "eye.slash" : "eye") {
                            if revealed { revealed = false }
                            else {
                                Task {
                                    guard await session.authorizeSecretAccess() else { return }
                                    withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) { revealed = true }
                                }
                            }
                        }
                        Button {
                            copy(item.content)
                        } label: {
                            Label(copied ? "Copied — clears in 15 seconds" : "Copy securely", systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(copied ? NoirTheme.mint : NoirTheme.violet)
                        .foregroundStyle(copied ? NoirTheme.ink : .white)
                    }
                    .noirCard()
                }

                if !item.tags.isEmpty {
                    Text(item.tags.map { "#\($0)" }.joined(separator: "  "))
                        .foregroundStyle(NoirTheme.violet)
                }

                if let configuration = item.totpConfiguration {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Verification code").font(.caption.bold()).foregroundStyle(NoirTheme.muted)
                        TOTPCodeView(configuration: configuration)
                    }
                    .noirCard()
                }

                if !item.notes.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Notes").font(.headline)
                        Text(item.notes).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading).noirCard()
                }

                Button(role: .destructive) { showingDeleteConfirmation = true } label: {
                    Label("Delete item", systemImage: "trash")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
            .padding(20)
        }
        .background(NoirTheme.ink)
        .navigationTitle(item.itemType.title)
        .navigationBarTitleDisplayMode(.inline)
        .onScrollPhaseChange { _, phase in if phase != .idle { session.touch() } }
        .onChange(of: item.content) { _, _ in revealed = false }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                HStack {
                    Button(action: onFavorite) { Image(systemName: item.isFavorite ? "star.fill" : "star") }
                        .accessibilityLabel(item.isFavorite ? "Remove from favorites" : "Add to favorites")
                    Button("Edit", action: onEdit)
                }
            }
        }
        .confirmationDialog("Delete \(item.title)?", isPresented: $showingDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete", role: .destructive, action: onDelete)
        }
        .fileExporter(
            isPresented: Binding(get: { exportDocument != nil }, set: { if !$0 { exportDocument = nil } }),
            document: exportDocument,
            contentType: .data,
            defaultFilename: item.title
        ) { result in
            if case .failure(let error) = result { exportError = error.localizedDescription }
            exportDocument = nil
        }
        .alert("Unable to export file", isPresented: Binding(get: { exportError != nil }, set: { if !$0 { exportError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: { Text(exportError ?? "") }
    }

    private func copy(_ value: String) {
        Task {
            guard await session.copySecret(value) else { return }
            copied = true
            try? await Task.sleep(for: .seconds(2))
            copied = false
        }
    }
}
