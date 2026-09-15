import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct RootView: View {
    @EnvironmentObject private var session: VaultSession
    @Environment(\.scenePhase) private var scenePhase
    let store: VaultStore
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if session.isLocked {
                if store.isConfigured {
                    UnlockView(store: store, errorMessage: $errorMessage)
                } else {
                    USBSetupView(store: store, errorMessage: $errorMessage)
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
            if phase != .active { session.lock() }
        }
        .simultaneousGesture(TapGesture().onEnded { session.touch() })
        .task(id: session.isLocked) {
            guard !session.isLocked else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
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
    @State private var masterPassword = ""
    @State private var confirmation = ""
    @State private var showFolderPicker = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Spacer(minLength: 48)
                Image(systemName: "lock.doc.fill")
                    .font(.system(size: 54, weight: .semibold))
                    .foregroundStyle(NoirTheme.violet)
                    .symbolEffect(.pulse, options: .repeating)
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
