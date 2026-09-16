import SwiftUI
import UniformTypeIdentifiers

struct RecordEditorView: View {
    let original: VaultItem?
    let onSave: (VaultItem) throws -> Void
    @EnvironmentObject private var session: VaultSession
    @Environment(\.dismiss) private var dismiss
    @State private var draft: VaultItem
    @State private var tags: String
    @State private var showingFileImporter = false
    @State private var errorMessage: String?
    @State private var showingScanner = false
    @State private var showingGenerator = false
    @State private var showingDiscard = false
    @State private var showingPassword = false
    @State private var saving = false

    init(type: VaultItemType, item: VaultItem? = nil, onSave: @escaping (VaultItem) throws -> Void) {
        original = item
        self.onSave = onSave
        _draft = State(initialValue: item ?? VaultItem(title: "", itemType: type, content: ""))
        _tags = State(initialValue: item?.tags.joined(separator: ", ") ?? "")
    }

    private var hasChanges: Bool {
        if let original { return original != draft || tags != original.tags.joined(separator: ", ") }
        return !draft.title.isEmpty || !draft.content.isEmpty || !draft.totpSecret.isEmpty || !draft.description.isEmpty || !draft.website.isEmpty || !draft.notes.isEmpty || !tags.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label(draft.itemType == .authenticator ? "Just your code. No password needed." : "Encrypted on your USB", systemImage: draft.itemType.symbol)
                        .foregroundStyle(NoirTheme.mint).font(.subheadline)
                    TextField(draft.itemType == .authenticator ? "Name, e.g. GitHub" : "Item name", text: $draft.title)
                        .accessibilityIdentifier("item-name")
                    if draft.itemType == .password || draft.itemType == .authenticator {
                        TextField("Username or email (optional)", text: $draft.description)
                            .textContentType(.username).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Website (optional)", text: $draft.website)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    Toggle("Favorite", isOn: $draft.isFavorite)
                } header: { Text("Details") }

                if draft.itemType == .file {
                    Section("Attachment") {
                        Button(draft.content.isEmpty ? "Choose file" : "Replace file", systemImage: "paperclip") { showingFileImporter = true }
                        if !draft.content.isEmpty {
                            Label("File ready to save", systemImage: "checkmark.circle.fill").foregroundStyle(NoirTheme.mint)
                        }
                        Text("Up to 50 MB. Export a copy from the item's details.").font(.footnote).foregroundStyle(NoirTheme.muted)
                    }
                } else if draft.itemType == .password {
                    Section("Password") {
                        HStack {
                            Group {
                                if showingPassword { TextField("Password", text: $draft.content) }
                                else { SecureField("Password", text: $draft.content) }
                            }
                            .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                            Button { showingPassword.toggle() } label: { Image(systemName: showingPassword ? "eye.slash" : "eye") }
                                .accessibilityLabel(showingPassword ? "Hide password" : "Show password")
                                .buttonStyle(.borderless).frame(minWidth: 44, minHeight: 44)
                        }
                        if !draft.content.isEmpty { LabeledContent("Strength estimate", value: PasswordGenerator.strength(of: draft.content)) }
                        Button("Generate password", systemImage: "wand.and.stars") { showingGenerator = true }
                    }
                } else if draft.itemType == .note || draft.itemType == .sshKey {
                    Section(draft.itemType == .note ? "Note" : "Private key") {
                        TextEditor(text: $draft.content).frame(minHeight: 180)
                            .font(draft.itemType == .sshKey ? .system(.body, design: .monospaced) : .body)
                            .autocorrectionDisabled(draft.itemType == .sshKey)
                            .accessibilityLabel(draft.itemType == .note ? "Note content" : "Private key")
                    }
                }

                if draft.itemType == .password || draft.itemType == .authenticator {
                    Section {
                        TextField("Setup key or otpauth:// link", text: $draft.totpSecret, axis: .vertical)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("authenticator-key")
                        Button("Scan QR code", systemImage: "qrcode.viewfinder") { showingScanner = true }
                        if let configuration = draft.totpConfiguration {
                            TimelineView(.periodic(from: .now, by: 1)) { context in
                                LabeledContent("Preview", value: TOTPGenerator.code(configuration: configuration, at: context.date))
                                    .monospacedDigit().foregroundStyle(NoirTheme.mint)
                            }
                            Text("\(configuration.digits) digits · every \(configuration.period) seconds · \(configuration.algorithm.rawValue)")
                                .font(.footnote).foregroundStyle(NoirTheme.muted)
                        }
                    } header: { Text(draft.itemType == .authenticator ? "Authenticator" : "Authenticator (optional)") }
                    footer: { Text("Use the setup key supplied by the website, not its current six-digit code.") }
                }

                Section("Organize") {
                    TextField("Tags, separated by commas", text: $tags)
                    if draft.itemType != .note { TextField("Notes (optional)", text: $draft.notes, axis: .vertical).lineLimit(3...8) }
                }
                if let errorMessage {
                    Section { Label(errorMessage, systemImage: "exclamationmark.circle").foregroundStyle(.orange) }
                }
            }
            .scrollContentBackground(.hidden).background(NoirTheme.ink)
            .navigationTitle(original == nil ? "New \(draft.itemType.title)" : "Edit item")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { if hasChanges { showingDiscard = true } else { dismiss() } }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save).disabled(saving || draft.validationMessage != nil)
                        .accessibilityIdentifier("save-item")
                }
            }
            .interactiveDismissDisabled(hasChanges)
            .confirmationDialog("Discard your changes?", isPresented: $showingDiscard, titleVisibility: .visible) {
                Button("Discard changes", role: .destructive) { dismiss() }
                Button("Keep editing", role: .cancel) {}
            }
            .onChange(of: draft) { _, _ in session.touch(); errorMessage = nil }
            .onChange(of: tags) { _, _ in session.touch() }
            .fileImporter(isPresented: $showingFileImporter, allowedContentTypes: [.item]) { result in
                switch result {
                case .success(let url): loadAttachment(from: url)
                case .failure(let error): errorMessage = error.localizedDescription
                }
            }
            .sheet(isPresented: $showingGenerator) { PasswordGeneratorView { draft.content = $0 } }
            .sheet(isPresented: $showingScanner) {
                NavigationStack {
                    TOTPScannerView { result in
                        showingScanner = false
                        switch result {
                        case .success(let value):
                            do {
                                let configuration = try TOTPConfiguration.parse(value)
                                draft.totpSecret = value
                                if draft.title.isEmpty { draft.title = configuration.issuer.isEmpty ? configuration.account : configuration.issuer }
                                if draft.description.isEmpty { draft.description = configuration.account }
                            } catch { errorMessage = error.localizedDescription }
                        case .failure(let error): errorMessage = error.localizedDescription
                        }
                    }
                    .overlay(alignment: .bottom) {
                        Text("Point the camera at an authenticator QR code")
                            .font(.callout).padding().background(.ultraThinMaterial, in: Capsule()).padding()
                    }
                    .navigationTitle("Scan setup code").navigationBarTitleDisplayMode(.inline)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showingScanner = false } } }
                }
            }
        }
    }

    private func loadAttachment(from url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let values = try url.resourceValues(forKeys: [.fileSizeKey])
            try Attachment.validate(size: values.fileSize ?? 0)
            let data = try Data(contentsOf: url)
            try Attachment.validate(size: data.count)
            draft.content = data.base64EncodedString()
            if draft.title.isEmpty { draft.title = url.lastPathComponent }
            session.touch()
        } catch { errorMessage = error.localizedDescription }
    }

    private func save() {
        guard !saving else { return }
        draft.title = draft.title.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.website = draft.website.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.totpSecret = draft.totpSecret.trimmingCharacters(in: .whitespacesAndNewlines)
        var seen = Set<String>()
        draft.tags = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && seen.insert($0.lowercased()).inserted }
        if let message = draft.validationMessage { errorMessage = message; return }
        saving = true
        defer { saving = false }
        do { try onSave(draft); dismiss() }
        catch { errorMessage = "Not saved. \(error.localizedDescription) Your changes are still in this form." }
    }
}

struct PasswordGeneratorView: View {
    var onUse: ((String) -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var options = PasswordGenerator.Options()
    @State private var password = PasswordGenerator.make(length: 24)
    @State private var copied = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(password).font(.system(.title3, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, minHeight: 80, alignment: .leading).contentTransition(.opacity)
                    Button("Generate another", systemImage: "arrow.clockwise") { generate() }
                    Button(copied ? "Copied for 15 seconds" : "Copy password", systemImage: copied ? "checkmark" : "doc.on.doc") {
                        SecureClipboard.copy(password); copied = true
                    }
                }
                Section("Length") { Stepper("\(options.length) characters", value: $options.length, in: 8...128) }
                Section("Include") {
                    Toggle("Lowercase (a–z)", isOn: $options.lowercase)
                    Toggle("Uppercase (A–Z)", isOn: $options.uppercase)
                    Toggle("Numbers (2–9)", isOn: $options.numbers)
                    Toggle("Symbols (!@#)", isOn: $options.symbols)
                }
                if options.groups.isEmpty { Text("Choose at least one character group.").foregroundStyle(.orange) }
            }
            .scrollContentBackground(.hidden).background(NoirTheme.ink)
            .navigationTitle("Password generator").navigationBarTitleDisplayMode(.inline)
            .onChange(of: options.length) { _, _ in generate() }
            .onChange(of: options.groups) { _, _ in generate() }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                if let onUse {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Use password") { onUse(password); dismiss() }.disabled(options.groups.isEmpty)
                    }
                }
            }
        }
    }
    private func generate() {
        guard let result = PasswordGenerator.make(options: options) else { return }
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.15)) { password = result; copied = false }
    }
}
