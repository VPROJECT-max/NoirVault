import SwiftUI
import UniformTypeIdentifiers

struct RecordEditorView: View {
    let type: VaultItemType
    let onSave: (VaultItem) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var title = ""
    @State private var username = ""
    @State private var secret = ""
    @State private var tags = ""
    @State private var showingFileImporter = false
    @State private var errorMessage: String?
    @State private var totpSecret = ""
    @State private var showingScanner = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Details") {
                    TextField("Title", text: $title)
                    if type == .password {
                        TextField("Username", text: $username)
                            .textContentType(.username)
                    }
                    TextField("Tags, separated by commas", text: $tags)
                }

                if type == .file {
                    Section("Encrypted file") {
                        Button("Choose file", systemImage: "paperclip") { showingFileImporter = true }
                        if !secret.isEmpty { Label("File ready for USB vault", systemImage: "checkmark.circle.fill").foregroundStyle(NoirTheme.mint) }
                    }
                } else {
                    Section(type == .password ? "Password" : "Secret data") {
                        if type == .password {
                            SecureField("Password", text: $secret)
                                .textContentType(.newPassword)
                            HStack {
                                Text("Strength")
                                Spacer()
                                Text(PasswordGenerator.strength(of: secret)).foregroundStyle(NoirTheme.violet)
                            }
                            Button("Generate strong password", systemImage: "wand.and.stars") {
                                secret = PasswordGenerator.make(length: 24)
                            }
                        } else {
                            TextEditor(text: $secret).frame(minHeight: 140)
                        }
                    }
                }

                if type == .password {
                    Section("Rotating code (optional)") {
                        TextField("Base32 secret or otpauth:// URI", text: $totpSecret)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Scan QR code", systemImage: "qrcode.viewfinder") { showingScanner = true }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(NoirTheme.ink)
            .navigationTitle("New \(type.title)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || secret.isEmpty)
                }
            }
            .fileImporter(isPresented: $showingFileImporter, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls): loadAttachment(from: urls.first)
                case .failure(let error): errorMessage = error.localizedDescription
                }
            }
            .alert("Unable to add file", isPresented: Binding(
                get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } }
            )) { Button("OK", role: .cancel) {} } message: { Text(errorMessage ?? "") }
            .sheet(isPresented: $showingScanner) {
                ZStack(alignment: .topTrailing) {
                    TOTPScannerView { result in
                        switch result {
                        case .success(let value):
                            if (try? TOTPConfiguration.parse(value)) != nil {
                                totpSecret = value
                                showingScanner = false
                            } else { errorMessage = TOTPError.invalidSecret.localizedDescription }
                        case .failure(let error): errorMessage = error.localizedDescription
                        }
                    }
                    Button("Close", systemImage: "xmark.circle.fill") { showingScanner = false }
                        .labelStyle(.iconOnly).font(.title).padding()
                }
                .ignoresSafeArea()
            }
        }
    }

    private func loadAttachment(from url: URL?) {
        guard let url else { return }
        guard url.startAccessingSecurityScopedResource() else {
            errorMessage = VaultStoreError.usbUnavailable.localizedDescription
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let values = try url.resourceValues(forKeys: [.fileSizeKey])
            try Attachment.validate(size: values.fileSize ?? 0)
            secret = try Data(contentsOf: url).base64EncodedString()
            if title.isEmpty { title = url.lastPathComponent }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func save() {
        if !totpSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           (try? TOTPConfiguration.parse(totpSecret)) == nil {
            errorMessage = TOTPError.invalidSecret.localizedDescription
            return
        }
        let item = VaultItem(
            title: title.trimmingCharacters(in: .whitespacesAndNewlines),
            description: username.trimmingCharacters(in: .whitespacesAndNewlines),
            totpSecret: totpSecret.trimmingCharacters(in: .whitespacesAndNewlines),
            tags: tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty },
            itemType: type,
            content: secret
        )
        onSave(item)
        dismiss()
    }
}
