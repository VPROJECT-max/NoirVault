import SwiftUI
import UIKit
import LocalAuthentication
import UniformTypeIdentifiers

private struct VaultAttachmentDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

struct RecordDetailView: View {
    @EnvironmentObject private var session: VaultSession
    let item: VaultItem
    let onDelete: () -> Void
    @State private var showingDeleteConfirmation = false
    @State private var copied = false
    @State private var exportDocument: VaultAttachmentDocument?
    @State private var exportError: String?

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

                if item.itemType == .file {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("This attachment is encrypted inside your USB vault.")
                            .foregroundStyle(NoirTheme.muted)
                        Button("Export file", systemImage: "square.and.arrow.up") {
                            guard let data = Data(base64Encoded: item.content) else {
                                exportError = "The encrypted attachment is corrupted."
                                return
                            }
                            exportDocument = VaultAttachmentDocument(data: data)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(NoirTheme.violet)
                    }
                    .noirCard()
                } else {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(item.itemType == .password ? "Password" : "Secret data")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(NoirTheme.muted)
                        Text(item.content)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Button {
                            copy(item.content)
                        } label: {
                            Label(copied ? "Copied — clears in 15 seconds" : "Copy securely", systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(copied ? NoirTheme.mint : NoirTheme.violet)
                    }
                    .noirCard()
                }

                if !item.tags.isEmpty {
                    Text(item.tags.map { "#\($0)" }.joined(separator: "  "))
                        .foregroundStyle(NoirTheme.violet)
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
        if session.requireBiometricsToCopy {
            let context = LAContext()
            var authError: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else { return }
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Reveal and copy this NoirVault secret.") { success, _ in
                Task { @MainActor in
                    guard success else { return }
                    copyAfterAuthentication(value)
                }
            }
            return
        }
        copyAfterAuthentication(value)
    }

    private func copyAfterAuthentication(_ value: String) {
        UIPasteboard.general.string = value
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        copied = true
        Task {
            try? await Task.sleep(for: .seconds(15))
            if UIPasteboard.general.string == value { UIPasteboard.general.string = "" }
            copied = false
        }
    }
}
