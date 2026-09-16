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

    var body: some View {
        Group {
            if session.isLocked {
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
                    SecureField("Create master password", text: $masterPassword)
                        .textContentType(.newPassword)
                    SecureField("Confirm master password", text: $confirmation)
                        .textContentType(.newPassword)
                    Button {
                        guard !masterPassword.isEmpty, masterPassword == confirmation else {
                            errorMessage = "Enter matching master passwords before choosing your USB folder."
                            return
                        }
                        showFolderPicker = true
                    } label: {
                        Label("Choose NoirVault USB folder", systemImage: "externaldrive.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(NoirTheme.violet)
                }
                .noirCard()
                Text("NoirVault creates a paired marker and an encrypted vault in the selected USB folder. Removing that drive locks the app immediately.")
                    .font(.footnote)
                    .foregroundStyle(NoirTheme.muted)
            }
            .padding(24)
        }
        .sheet(isPresented: $showFolderPicker) {
            USBFolderPicker { directory in
                do {
                    try store.pair(with: directory)
                    let unlocked = try store.create(masterPassword: masterPassword)
                    session.unlock(unlocked)
                    onConfigured()
                    masterPassword = ""
                    confirmation = ""
                } catch {
                    errorMessage = error.localizedDescription
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
                isUnlocking ? AnyView(ProgressView()) : AnyView(Text("Unlock vault").frame(maxWidth: .infinity))
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
        isUnlocking = true
        defer { isUnlocking = false }
        do {
            let unlocked = try store.load(masterPassword: masterPassword)
            session.unlock(unlocked)
            masterPassword = ""
        } catch {
            session.lock()
            errorMessage = error.localizedDescription
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
