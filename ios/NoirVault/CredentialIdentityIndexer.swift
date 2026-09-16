import AuthenticationServices
import Foundation
import Security

enum CredentialIdentityIndexer {
    static func prioritized(_ items: [VaultItem], for services: [ASCredentialServiceIdentifier]) -> [VaultItem] {
        func host(_ value: String) -> String {
            let candidate = value.contains("://") ? value : "https://" + value
            return (URL(string: candidate)?.host ?? value).lowercased()
        }
        let requested = services.map { host($0.identifier) }
        func matches(_ item: VaultItem) -> Bool {
            let domain = host(item.website.isEmpty ? item.title : item.website)
            return !domain.isEmpty && requested.contains { $0 == domain || $0.hasSuffix("." + domain) }
        }
        return items.sorted {
            if matches($0) != matches($1) { return matches($0) }
            return $0.title.localizedStandardCompare($1.title) == .orderedAscending
        }
    }

    static func passwordIdentity(for item: VaultItem) -> ASPasswordCredentialIdentity {
        ASPasswordCredentialIdentity(
            serviceIdentifier: serviceIdentifier(for: item),
            user: item.description,
            recordIdentifier: item.id
        )
    }

    static func oneTimeCodeIdentity(for item: VaultItem) -> ASOneTimeCodeCredentialIdentity {
        ASOneTimeCodeCredentialIdentity(
            serviceIdentifier: serviceIdentifier(for: item),
            label: item.title,
            recordIdentifier: item.id
        )
    }

    static func passkeyIdentity(for item: VaultItem) -> ASPasskeyCredentialIdentity? {
        guard let material = item.passkeyMaterial else { return nil }
        return ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: material.relyingParty,
            userName: material.userName,
            credentialID: material.credentialID,
            userHandle: material.userHandle,
            recordIdentifier: item.id
        )
    }

    static func identities(for vault: VaultData) -> [any ASCredentialIdentity] {
        var result: [any ASCredentialIdentity] = []
        for item in vault.items {
            if item.itemType == .password {
                result.append(passwordIdentity(for: item))
            } else if let passkey = passkeyIdentity(for: item) {
                result.append(passkey)
            }
            if item.hasTOTP { result.append(oneTimeCodeIdentity(for: item)) }
        }
        return result
    }

    static func replaceAll(with vault: VaultData) async throws {
        let identities = identities(for: vault)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) { success, error in
                if let error { continuation.resume(throwing: error) }
                else if success { continuation.resume() }
                else { continuation.resume(throwing: VaultStoreError.keychainFailure(errSecInternalError)) }
            }
        }
    }

    private static func serviceIdentifier(for item: VaultItem) -> ASCredentialServiceIdentifier {
        let candidate = (item.websiteURL?.host ?? item.title).trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: candidate), let host = url.host {
            return ASCredentialServiceIdentifier(identifier: host, type: .domain)
        }
        return ASCredentialServiceIdentifier(identifier: candidate, type: .domain)
    }
}
