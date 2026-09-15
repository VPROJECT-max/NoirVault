import CryptoKit
import Foundation
import Security

enum VaultStoreError: LocalizedError, Equatable {
    case usbUnavailable
    case wrongUSB
    case vaultMissing
    case corruptVault
    case attachmentTooLarge
    case locked
    case keychainFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .usbUnavailable: "Connect the NoirVault USB drive, then try again."
        case .wrongUSB: "This is not the USB drive paired with NoirVault."
        case .vaultMissing: "No NoirVault vault was found in this USB folder."
        case .corruptVault: "The vault data is unreadable or has been modified."
        case .attachmentTooLarge: "Files must be 50 MB or smaller."
        case .locked: "Unlock NoirVault before saving."
        case .keychainFailure: "NoirVault could not securely save its USB pairing."
        }
    }
}

private enum KeychainStore {
    static func save(_ data: Data, account: String) throws {
        let identity: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.Tokyo.noirvault",
            kSecAttrAccount: account,
        ]
        SecItemDelete(identity as CFDictionary)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.Tokyo.noirvault",
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultStoreError.keychainFailure(status) }
    }

    static func read(account: String) throws -> Data {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.Tokyo.noirvault",
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { throw VaultStoreError.usbUnavailable }
        return data
    }
}

final class VaultStore {
    private static let bookmarkAccount = "usb-directory-bookmark"
    private static let pairingAccount = "usb-pairing-secret"
    private static let vaultFilename = "noirvault.vault"
    private static let markerFilename = ".noirvault-pairing"

    var isConfigured: Bool {
        (try? KeychainStore.read(account: Self.bookmarkAccount)) != nil
    }

    func pair(with directory: URL) throws {
        guard directory.startAccessingSecurityScopedResource() else { throw VaultStoreError.usbUnavailable }
        defer { directory.stopAccessingSecurityScopedResource() }

        let secret = try randomSecret()
        let marker = PairingMarker(secret: secret)
        let markerData = try JSONEncoder().encode(marker)
        try coordinateWrite(in: directory) { folder in
            try markerData.write(to: folder.appendingPathComponent(Self.markerFilename), options: .atomic)
        }
        try KeychainStore.save(secret, account: Self.pairingAccount)
        let bookmark = try directory.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        try KeychainStore.save(bookmark, account: Self.bookmarkAccount)
    }

    func load(masterPassword: String) throws -> VaultData {
        try withVaultDirectory { directory in
            let vaultURL = directory.appendingPathComponent(Self.vaultFilename)
            guard FileManager.default.fileExists(atPath: vaultURL.path) else { throw VaultStoreError.vaultMissing }
            let encrypted = try coordinateRead(at: vaultURL)
            let plaintext: Data
            do {
                plaintext = try VaultCore.decrypt(envelope: encrypted, password: masterPassword)
            } catch {
                throw VaultStoreError.corruptVault
            }
            do {
                return try JSONDecoder().decode(VaultData.self, from: plaintext)
            } catch {
                throw VaultStoreError.corruptVault
            }
        }
    }

    func create(masterPassword: String) throws -> VaultData {
        let data = VaultData()
        try save(data, masterPassword: masterPassword)
        return data
    }

    func save(_ data: VaultData, masterPassword: String) throws {
        let plaintext = try JSONEncoder().encode(data)
        let envelope = try VaultCore.encrypt(json: plaintext, password: masterPassword)
        try withVaultDirectory { directory in
            let vaultURL = directory.appendingPathComponent(Self.vaultFilename)
            try coordinateWrite(in: directory) { _ in
                try envelope.write(to: vaultURL, options: .atomic)
            }
        }
    }

    func probe() throws {
        try withVaultDirectory { _ in () }
    }

    private func withVaultDirectory<T>(_ work: (URL) throws -> T) throws -> T {
        let bookmark = try KeychainStore.read(account: Self.bookmarkAccount)
        var stale = false
        let directory = try URL(
            resolvingBookmarkData: bookmark,
            options: [.withoutUI],
            relativeTo: nil,
            bookmarkDataIsStale: &stale
        )
        guard directory.startAccessingSecurityScopedResource() else { throw VaultStoreError.usbUnavailable }
        defer { directory.stopAccessingSecurityScopedResource() }
        if stale {
            let refreshed = try directory.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            try KeychainStore.save(refreshed, account: Self.bookmarkAccount)
        }
        try verifyPairing(in: directory)
        return try work(directory)
    }

    private func verifyPairing(in directory: URL) throws {
        let secret = try KeychainStore.read(account: Self.pairingAccount)
        let markerURL = directory.appendingPathComponent(Self.markerFilename)
        guard FileManager.default.fileExists(atPath: markerURL.path) else { throw VaultStoreError.wrongUSB }
        let markerData = try coordinateRead(at: markerURL)
        guard let marker = try? JSONDecoder().decode(PairingMarker.self, from: markerData), marker.matches(secret: secret) else {
            throw VaultStoreError.wrongUSB
        }
    }

    private func coordinateRead(at url: URL) throws -> Data {
        var coordinatorError: NSError?
        var readError: Error?
        var data = Data()
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinatorError) { coordinatedURL in
            do { data = try Data(contentsOf: coordinatedURL) } catch { readError = error }
        }
        if let coordinatorError { throw coordinatorError }
        if let readError { throw readError }
        return data
    }

    private func coordinateWrite(in directory: URL, work: (URL) throws -> Void) throws {
        var coordinatorError: NSError?
        var writeError: Error?
        NSFileCoordinator().coordinate(writingItemAt: directory, options: .forMerging, error: &coordinatorError) { coordinatedURL in
            do { try work(coordinatedURL) } catch { writeError = error }
        }
        if let coordinatorError { throw coordinatorError }
        if let writeError { throw writeError }
    }

    private func randomSecret() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw VaultStoreError.keychainFailure(status) }
        return Data(bytes)
    }
}
