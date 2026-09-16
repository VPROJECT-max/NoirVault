import Foundation
import LocalAuthentication
import Security

enum VaultStoreError: LocalizedError, Equatable {
    case usbUnavailable
    case wrongUSB
    case vaultMissing
    case corruptVault
    case attachmentTooLarge
    case locked
    case keychainFailure(OSStatus)
    case vaultAlreadyExists
    case vaultChanged
    case authenticationFailed

    var errorDescription: String? {
        switch self {
        case .usbUnavailable: "Connect the NoirVault USB drive, then try again."
        case .wrongUSB: "This is not the USB drive paired with NoirVault."
        case .vaultMissing: "No NoirVault vault was found in this USB folder."
        case .corruptVault: "The vault data is unreadable or has been modified."
        case .attachmentTooLarge: "Files must be 50 MB or smaller."
        case .locked: "Unlock NoirVault before saving."
        case .keychainFailure: "NoirVault could not securely save its USB pairing."
        case .vaultAlreadyExists: "This folder already contains a vault. Choose an empty folder to create a new one; your existing vault has not been changed."
        case .vaultChanged: "The USB vault changed since it was opened. Unlock it again to load the latest version before making changes."
        case .authenticationFailed: "The master password is incorrect, or this vault could not be authenticated."
        }
    }
}

struct UnlockedVault: Sendable {
    var data: VaultData
    var envelope: Data
    var key: Data

    static let fixture = UnlockedVault(data: .fixture, envelope: Data([1]), key: Data(repeating: 2, count: 32))
}

/// Only ciphertext is retained while waiting for a USB; never the vault key or plaintext.
struct PendingVaultSave: Identifiable, Equatable, Sendable {
    let id = UUID()
    let envelope: Data
    let originalEnvelope: Data
}

final class VaultStore: Sendable {
    private static let bookmarkAccount = "usb-directory-bookmark"
    private static let pairingAccount = "usb-pairing-secret"
    private static let derivedKeyAccount = "vault-derived-key-v2"
    private static let vaultFilename = "noirvault.vault"
    private static let markerFilename = ".noirvault-pairing"

    var isConfigured: Bool {
        (try? SharedKeychain.readMigratingLegacy(account: Self.bookmarkAccount)) != nil
    }

    func pair(with directory: URL) throws {
        guard directory.startAccessingSecurityScopedResource() else { throw VaultStoreError.usbUnavailable }
        defer { directory.stopAccessingSecurityScopedResource() }

        guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent(Self.vaultFilename).path) else {
            throw VaultStoreError.vaultAlreadyExists
        }

        try persistPairing(in: directory)
    }

    /// Re-enrollment proves possession of the master password before replacing a pairing marker.
    func openExisting(at directory: URL, masterPassword: String) throws -> UnlockedVault {
        guard directory.startAccessingSecurityScopedResource() else { throw VaultStoreError.usbUnavailable }
        defer { directory.stopAccessingSecurityScopedResource() }
        let url = directory.appendingPathComponent(Self.vaultFilename)
        guard FileManager.default.fileExists(atPath: url.path) else { throw VaultStoreError.vaultMissing }
        let envelope = try coordinateRead(at: url)
        let plaintext: Data
        do { plaintext = try VaultCore.decrypt(envelope: envelope, password: masterPassword) }
        catch { throw VaultStoreError.authenticationFailed }
        let data = try JSONDecoder().decode(VaultData.self, from: plaintext)
        let key = try VaultCore.deriveKey(envelope: envelope, password: masterPassword)
        try persistPairing(in: directory, expectedEnvelope: envelope)
        try cacheDeviceKey(key)
        return UnlockedVault(data: data, envelope: envelope, key: key)
    }

    private func persistPairing(in directory: URL, expectedEnvelope: Data? = nil) throws {

        let secret = try randomSecret()
        let marker = PairingMarker(secret: secret)
        let markerData = try JSONEncoder().encode(marker)
        try coordinateWrite(in: directory) { folder in
            if let expectedEnvelope {
                guard try Data(contentsOf: folder.appendingPathComponent(Self.vaultFilename)) == expectedEnvelope else { throw VaultStoreError.vaultChanged }
            } else if FileManager.default.fileExists(atPath: folder.appendingPathComponent(Self.vaultFilename).path) {
                throw VaultStoreError.vaultAlreadyExists
            }
            try markerData.write(to: folder.appendingPathComponent(Self.markerFilename), options: .atomic)
        }
        try SharedKeychain.saveShared(secret, account: Self.pairingAccount)
        let bookmark = try directory.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        try SharedKeychain.saveShared(bookmark, account: Self.bookmarkAccount)
    }

    func load(masterPassword: String) throws -> UnlockedVault {
        try withVaultDirectory { directory in
            let vaultURL = directory.appendingPathComponent(Self.vaultFilename)
            guard FileManager.default.fileExists(atPath: vaultURL.path) else { throw VaultStoreError.vaultMissing }
            let encrypted = try coordinateRead(at: vaultURL)
            let plaintext: Data
            do {
                plaintext = try VaultCore.decrypt(envelope: encrypted, password: masterPassword)
            } catch {
                throw VaultStoreError.authenticationFailed
            }
            do {
                let data = try JSONDecoder().decode(VaultData.self, from: plaintext)
                let key = try VaultCore.deriveKey(envelope: encrypted, password: masterPassword)
                try cacheDeviceKey(key)
                return UnlockedVault(data: data, envelope: encrypted, key: key)
            } catch {
                throw VaultStoreError.corruptVault
            }
        }
    }

    func create(masterPassword: String) throws -> UnlockedVault {
        let data = VaultData()
        let plaintext = try JSONEncoder().encode(data)
        let envelope = try VaultCore.encrypt(json: plaintext, password: masterPassword)
        try writeEnvelope(envelope, createOnly: true)
        let key = try VaultCore.deriveKey(envelope: envelope, password: masterPassword)
        try cacheDeviceKey(key)
        return UnlockedVault(data: data, envelope: envelope, key: key)
    }

    func loadWithDeviceKey(context: LAContext) throws -> UnlockedVault {
        let key = try SharedKeychain.readShared(account: Self.derivedKeyAccount, context: context)
        return try withVaultDirectory { directory in
            let vaultURL = directory.appendingPathComponent(Self.vaultFilename)
            guard FileManager.default.fileExists(atPath: vaultURL.path) else { throw VaultStoreError.vaultMissing }
            let envelope = try coordinateRead(at: vaultURL)
            do {
                let plaintext = try VaultCore.decrypt(envelope: envelope, key: key)
                let data = try JSONDecoder().decode(VaultData.self, from: plaintext)
                return UnlockedVault(data: data, envelope: envelope, key: key)
            } catch {
                throw VaultStoreError.corruptVault
            }
        }
    }

    func save(_ data: VaultData, using unlocked: UnlockedVault) throws -> UnlockedVault {
        let pending = try prepareSave(data, using: unlocked)
        try persist(pending)
        return UnlockedVault(data: data, envelope: pending.envelope, key: unlocked.key)
    }

    func prepareSave(_ data: VaultData, using unlocked: UnlockedVault) throws -> PendingVaultSave {
        let plaintext = try JSONEncoder().encode(data)
        let envelope = try VaultCore.reencrypt(json: plaintext, existingEnvelope: unlocked.envelope, key: unlocked.key)
        return PendingVaultSave(envelope: envelope, originalEnvelope: unlocked.envelope)
    }

    func persist(_ pending: PendingVaultSave) throws {
        try writeEnvelope(pending.envelope, expectedEnvelope: pending.originalEnvelope)
    }

    private func writeEnvelope(_ envelope: Data, expectedEnvelope: Data? = nil, createOnly: Bool = false) throws {
        try withVaultDirectory { directory in
            let vaultURL = directory.appendingPathComponent(Self.vaultFilename)
            try coordinateWrite(in: directory) { _ in
                if createOnly && FileManager.default.fileExists(atPath: vaultURL.path) { throw VaultStoreError.vaultAlreadyExists }
                if let expectedEnvelope {
                    let current = try Data(contentsOf: vaultURL)
                    // A retry after a successful atomic write is already complete.
                    if current == envelope { return }
                    guard current == expectedEnvelope else { throw VaultStoreError.vaultChanged }
                }
                try envelope.write(to: vaultURL, options: .atomic)
            }
        }
    }

    private func cacheDeviceKey(_ key: Data) throws {
        // A phone without enrolled biometrics can still use its master password.
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return }
        try SharedKeychain.saveShared(key, account: Self.derivedKeyAccount, accessControl: SharedKeychain.biometricAccessControl())
    }

    func probe() throws {
        try withVaultDirectory { directory in
            let vaultURL = directory.appendingPathComponent(Self.vaultFilename)
            guard FileManager.default.fileExists(atPath: vaultURL.path) else {
                throw VaultStoreError.vaultMissing
            }
        }
    }

    private func withVaultDirectory<T>(_ work: (URL) throws -> T) throws -> T {
        let bookmark: Data
        do { bookmark = try SharedKeychain.readMigratingLegacy(account: Self.bookmarkAccount) }
        catch { throw VaultStoreError.usbUnavailable }
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
            try SharedKeychain.saveShared(refreshed, account: Self.bookmarkAccount)
        }
        try verifyPairing(in: directory)
        return try work(directory)
    }

    private func verifyPairing(in directory: URL) throws {
        let secret: Data
        do { secret = try SharedKeychain.readMigratingLegacy(account: Self.pairingAccount) }
        catch { throw VaultStoreError.wrongUSB }
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
