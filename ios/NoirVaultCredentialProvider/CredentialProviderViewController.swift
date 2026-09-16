import AuthenticationServices
import LocalAuthentication
import SwiftUI
import UIKit

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let store = VaultStore()
    private var unlocked: UnlockedVault?
    private var childHost: UIViewController?

    override func prepareInterfaceForExtensionConfiguration() {
        show(title: "NoirVault AutoFill", message: "Ready. Keep your paired USB connected; Face ID unlocks only the device-bound vault key.", items: []) { _ in }
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        cancel(code: .userInteractionRequired)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        do {
            let vault = try unlockUSB()
            try complete(request: credentialRequest, vault: vault)
        } catch {
            showFailure(error)
        }
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        do {
            let vault = try unlockUSB()
            let items = CredentialIdentityIndexer.prioritized(vault.data.items.filter { $0.itemType == .password }, for: serviceIdentifiers)
            show(title: "Choose a login", message: "Select a USB-backed credential.", items: items) { [weak self] item in
                self?.completePassword(item)
            }
        } catch { showFailure(error) }
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        do {
            let vault = try unlockUSB()
            let items = CredentialIdentityIndexer.prioritized(vault.data.items.filter(\.hasTOTP), for: serviceIdentifiers)
            show(title: "Choose a code", message: "Select a rotating code.", items: items) { [weak self] item in
                self?.completeOTP(item)
            }
        } catch { showFailure(error) }
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        do {
            guard let request = registrationRequest as? ASPasskeyCredentialRequest,
                  let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
                  request.supportedAlgorithms.contains(.ES256) else {
                cancel(code: .failed)
                return
            }
            var vault = try unlockUSB()
            let registration = try WebAuthn.register(
                relyingParty: identity.relyingPartyIdentifier,
                userName: identity.userName,
                userHandle: identity.userHandle
            )
            let item = try VaultItem.passkey(registration.material)
            vault.data.items.append(item)
            unlocked = try store.save(vault.data, using: vault)
            Task { try? await CredentialIdentityIndexer.replaceAll(with: vault.data) }
            let credential = ASPasskeyRegistrationCredential(
                relyingParty: registration.material.relyingParty,
                clientDataHash: request.clientDataHash,
                credentialID: registration.material.credentialID,
                attestationObject: registration.attestationObject
            )
            extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        } catch { showFailure(error) }
    }

    private func unlockUSB() throws -> UnlockedVault {
        let context = LAContext()
        context.localizedReason = "Unlock the paired USB vault for AutoFill."
        let vault = try store.loadWithDeviceKey(context: context)
        unlocked = vault
        return vault
    }

    private func complete(request: any ASCredentialRequest, vault: UnlockedVault) throws {
        guard let recordID = request.credentialIdentity.recordIdentifier,
              let item = vault.data.items.first(where: { $0.id == recordID }) else {
            cancel(code: .credentialIdentityNotFound)
            return
        }
        if request is ASPasswordCredentialRequest {
            completePassword(item)
        } else if request is ASOneTimeCodeCredentialRequest {
            completeOTP(item)
        } else if let passkeyRequest = request as? ASPasskeyCredentialRequest {
            try completePasskey(item, request: passkeyRequest, vault: vault)
        } else {
            cancel(code: .failed)
        }
    }

    private func completePassword(_ item: VaultItem) {
        guard item.itemType == .password else { cancel(code: .credentialIdentityNotFound); return }
        do { try store.probe() } catch { showFailure(error); return }
        extensionContext.completeRequest(
            withSelectedCredential: ASPasswordCredential(user: item.description, password: item.content),
            completionHandler: nil
        )
    }

    private func completeOTP(_ item: VaultItem) {
        do { try store.probe() } catch { showFailure(error); return }
        guard let configuration = item.totpConfiguration else { cancel(code: .credentialIdentityNotFound); return }
        extensionContext.completeOneTimeCodeRequest(
            using: ASOneTimeCodeCredential(code: TOTPGenerator.code(configuration: configuration)),
            completionHandler: nil
        )
    }

    private func completePasskey(_ item: VaultItem, request: ASPasskeyCredentialRequest, vault: UnlockedVault) throws {
        guard let material = item.passkeyMaterial,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancel(code: .credentialIdentityNotFound)
            return
        }
        let assertion = try WebAuthn.assert(
            material: material,
            relyingParty: identity.relyingPartyIdentifier,
            clientDataHash: request.clientDataHash
        )
        var updatedVault = vault
        guard let index = updatedVault.data.items.firstIndex(where: { $0.id == item.id }) else {
            cancel(code: .credentialIdentityNotFound)
            return
        }
        // Keep user-edited title, notes, website, tags and favorite status during sign-counter updates.
        updatedVault.data.items[index].content = try VaultItem.passkey(assertion.updatedMaterial).content
        unlocked = try store.save(updatedVault.data, using: updatedVault)
        let credential = ASPasskeyAssertionCredential(
            userHandle: assertion.updatedMaterial.userHandle,
            relyingParty: assertion.updatedMaterial.relyingParty,
            signature: assertion.signature,
            clientDataHash: request.clientDataHash,
            authenticatorData: assertion.authenticatorData,
            credentialID: assertion.updatedMaterial.credentialID
        )
        extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
    }

    private func showFailure(_ error: Error) {
        show(title: "USB vault unavailable", message: error.localizedDescription, items: []) { _ in }
    }

    private func show(title: String, message: String, items: [VaultItem], selection: @escaping (VaultItem) -> Void) {
        childHost?.willMove(toParent: nil)
        childHost?.view.removeFromSuperview()
        childHost?.removeFromParent()
        let host = UIHostingController(rootView: CredentialProviderView(
            title: title,
            message: message,
            items: items,
            onSelect: selection,
            onCancel: { [weak self] in self?.cancel(code: .userCanceled) }
        ))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        childHost = host
    }

    private func cancel(code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }
}
