import SwiftUI
import UIKit
import UniformTypeIdentifiers

enum VaultLaunchRoute: Equatable {
    case checking
    case setupRequired
    case unlockRequired
}

enum VaultLaunchPolicy {
    static func route(hasStoredPairing: Bool, probeError: VaultStoreError?) -> VaultLaunchRoute {
        guard hasStoredPairing else { return .setupRequired }
        switch probeError {
        case .wrongUSB, .vaultMissing:
            return .setupRequired
        default:
            return .unlockRequired
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var session: VaultSession
    @Environment(\.scenePhase) private var scenePhase
    let store: VaultStore
    @State private var errorMessage: String?
    @State private var launchRoute: VaultLaunchRoute = .checking
    @State private var pendingError: String?
    @State private var confirmingDiscard = false
    @State private var isRetryingPending = false

    var body: some View {
        Group {
            if session.pendingSave != nil {
                VStack(spacing: 24) {
                    Image(systemName: "externaldrive.badge.exclamationmark").font(.system(size: 54)).foregroundStyle(NoirTheme.violet)
                    Text("Reconnect to finish saving").font(.title2.bold())
                    Text("Your changes are encrypted in memory. Connect the same USB and NoirVault will save them automatically. Keep this app open until saving finishes.")
                        .multilineTextAlignment(.center).foregroundStyle(NoirTheme.muted)
                    ProgressView("Waiting for your USB…")
                    if let pendingError { Text(pendingError).font(.footnote).foregroundStyle(.orange) }
                    Button("Discard pending changes", role: .destructive) { confirmingDiscard = true }
                        .disabled(isRetryingPending)
                }.padding(28)
            } else if session.isLocked {
                switch launchRoute {
                case .checking:
                    ProgressView("Checking paired USB…")
                        .foregroundStyle(NoirTheme.muted)
                case .setupRequired:
                    USBSetupView(store: store, errorMessage: $errorMessage) {
                        launchRoute = .unlockRequired
                    }
                case .unlockRequired:
                    UnlockView(store: store, errorMessage: $errorMessage) {
                        launchRoute = .setupRequired
                    }
                }
            } else {
                VaultHomeView(store: store, errorMessage: $errorMessage)
            }
        }
        .tint(NoirTheme.violet)
        .background(NoirTheme.ink.ignoresSafeArea())
        .alert("NoirVault", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { session.lock() }
            if phase == .active { session.touch() }
        }
        .overlay {
            if scenePhase != .active {
                ZStack {
                    NoirTheme.ink.ignoresSafeArea()
                    Label("NoirVault", systemImage: "lock.shield.fill").font(.title2.bold()).foregroundStyle(NoirTheme.violet)
                }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UITextField.textDidChangeNotification)) { _ in session.touch() }
        .onReceive(NotificationCenter.default.publisher(for: UITextView.textDidChangeNotification)) { _ in session.touch() }
        .onChange(of: session.authenticationError) { _, value in
            if let value { errorMessage = value; session.authenticationError = nil }
        }
        .confirmationDialog("Discard changes that have not been saved?", isPresented: $confirmingDiscard, titleVisibility: .visible) {
            Button("Discard changes", role: .destructive) { session.discardPendingSave(); pendingError = nil }
            Button("Keep waiting", role: .cancel) {}
        } message: { Text("Your existing USB vault will remain unchanged.") }
        .task(id: session.pendingSave?.id) {
            guard let pending = session.pendingSave else { return }
            pendingError = nil
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
                guard !Task.isCancelled, session.pendingSave?.id == pending.id else { return }
                guard scenePhase == .active, !confirmingDiscard else { continue }
                isRetryingPending = true
                do {
                    let vaultStore = store
                    try await Task.detached { try vaultStore.persist(pending) }.value
                    isRetryingPending = false
                    guard session.pendingSave?.id == pending.id else { return }
                    session.finishPendingSave(id: pending.id)
                    errorMessage = "Your changes are saved on the USB. You can safely close NoirVault or unlock to continue."
                    return
                } catch let error as VaultStoreError {
                    isRetryingPending = false
                    pendingError = error.localizedDescription
                    if error == .vaultChanged { return }
                } catch { isRetryingPending = false; pendingError = error.localizedDescription }
            }
        }
        .task {
            let hasStoredPairing = store.isConfigured
            var probeError: VaultStoreError?
            if hasStoredPairing {
                do {
                    try store.probe()
                } catch let error as VaultStoreError {
                    probeError = error
                } catch {
                    probeError = .usbUnavailable
                }
            }
            launchRoute = VaultLaunchPolicy.route(
                hasStoredPairing: hasStoredPairing,
                probeError: probeError
            )
        }
        .task(id: session.isLocked) {
            guard !session.isLocked else { return }
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
                guard !Task.isCancelled, !session.isLocked else { return }
                if session.shouldAutoLock() {
                    session.lock()
                    return
                }
                do {
                    try store.probe()
                } catch {
                    await session.handleStorageUnavailable()
                    errorMessage = VaultStoreError.usbUnavailable.localizedDescription
                    return
                }
            }
        }
    }
}

private struct USBSetupView: View {
    @EnvironmentObject private var session: VaultSession
    let store: VaultStore
    @Binding var errorMessage: String?
    let onConfigured: () -> Void
    @State private var masterPassword = ""
    @State private var confirmation = ""
    @State private var showFolderPicker = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var openingExisting = false
    @State private var isWorking = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Spacer(minLength: 48)
                Image(systemName: "lock.doc.fill")
                    .font(.system(size: 54, weight: .semibold))
                    .foregroundStyle(NoirTheme.violet)
                    .symbolEffect(.pulse, options: .repeating, isActive: !reduceMotion)
                Text("A vault that leaves with you.")
                    .font(.largeTitle.bold())
                Text("Choose a folder on your NoirVault USB. Your encrypted vault, files, and secrets remain there—not on this iPhone.")
                    .foregroundStyle(NoirTheme.muted)
                VStack(spacing: 14) {
                    Picker("Vault setup", selection: $openingExisting) {
                        Text("Create new").tag(false)
                        Text("Open existing").tag(true)
                    }.pickerStyle(.segmented)
                    SecureField(openingExisting ? "Existing master password" : "Create master password", text: $masterPassword)
                        .textContentType(openingExisting ? .password : .newPassword)
                    if !openingExisting {
                        SecureField("Confirm master password", text: $confirmation).textContentType(.newPassword)
                        Text("Use at least 12 characters. Keep this password somewhere safe; NoirVault cannot reset it.")
                            .font(.footnote).foregroundStyle(NoirTheme.muted)
                    }
                    Button {
                        guard !masterPassword.isEmpty, openingExisting || (masterPassword.count >= 12 && masterPassword == confirmation) else {
                            errorMessage = "Use matching master passwords with at least 12 characters."
                            return
                        }
                        showFolderPicker = true
                    } label: {
                        HStack {
                            if isWorking { ProgressView() }
                            Text(isWorking ? "Opening your vault…" : "Choose USB folder")
                        }.frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(NoirTheme.violet)
                    .disabled(isWorking || masterPassword.isEmpty || (!openingExisting && (masterPassword.count < 12 || masterPassword != confirmation)))
                }
                .noirCard()
                Text(openingExisting ? "Choose the folder containing noirvault.vault. Your master password is verified before this iPhone is paired with it." : "Choose an empty folder on your USB. NoirVault will never replace an existing vault during setup.")
                    .font(.footnote)
                    .foregroundStyle(NoirTheme.muted)
            }
            .padding(24)
        }
        .sheet(isPresented: $showFolderPicker) {
            USBFolderPicker { directory in
                isWorking = true
                let password = masterPassword
                let existing = openingExisting
                let vaultStore = store
                Task { @MainActor in
                    defer { isWorking = false }
                    do {
                        let unlocked = try await Task.detached(priority: .userInitiated) {
                            if existing { return try vaultStore.openExisting(at: directory, masterPassword: password) }
                            try vaultStore.pair(with: directory)
                            return try vaultStore.create(masterPassword: password)
                        }.value
                        onConfigured()
                        if UIApplication.shared.applicationState == .active { session.unlock(unlocked) }
                        masterPassword = ""
                        confirmation = ""
                    } catch { errorMessage = error.localizedDescription }
                }
            }
        }
    }
}

private struct UnlockView: View {
    @EnvironmentObject private var session: VaultSession
    let store: VaultStore
    @Binding var errorMessage: String?
    let onReconfigure: () -> Void
    @State private var masterPassword = ""
    @State private var isUnlocking = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 58))
                .foregroundStyle(NoirTheme.mint)
            Text("Unlock NoirVault")
                .font(.title.bold())
            Text("Connect your paired USB drive, then enter your master password.")
                .multilineTextAlignment(.center)
                .foregroundStyle(NoirTheme.muted)
            SecureField("Master password", text: $masterPassword)
                .textContentType(.password)
                .submitLabel(.go)
                .onSubmit(unlock)
                .padding()
                .background(NoirTheme.panel, in: RoundedRectangle(cornerRadius: 16))
            Button(action: unlock) {
                HStack {
                    if isUnlocking { ProgressView() }
                    Text(isUnlocking ? "Unlocking…" : "Unlock vault")
                }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(NoirTheme.violet)
            .disabled(masterPassword.isEmpty || isUnlocking)
            Button("Set up a new or reformatted USB", systemImage: "externaldrive.badge.plus") {
                masterPassword = ""
                onReconfigure()
            }
            .buttonStyle(.bordered)
            Spacer()
        }
        .padding(28)
    }

    private func unlock() {
        guard !isUnlocking, !masterPassword.isEmpty else { return }
        isUnlocking = true
        let password = masterPassword
        let vaultStore = store
        Task { @MainActor in
            defer { isUnlocking = false }
            do {
                let unlocked = try await Task.detached(priority: .userInitiated) { try vaultStore.load(masterPassword: password) }.value
                guard UIApplication.shared.applicationState == .active else { return }
                session.unlock(unlocked)
                masterPassword = ""
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct USBFolderPicker: UIViewControllerRepresentable {
    let onSelect: (URL) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder], asCopy: false)
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(parent: self) }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: USBFolderPicker

        init(parent: USBFolderPicker) { self.parent = parent }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            parent.dismiss()
            parent.onSelect(url)
        }
    }
}
