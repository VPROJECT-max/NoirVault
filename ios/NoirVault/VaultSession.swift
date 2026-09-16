import Combine
import Foundation
import LocalAuthentication
import UIKit

@MainActor
final class VaultSession: ObservableObject {
    @Published private(set) var data: VaultData
    @Published private(set) var isLocked: Bool
    @Published var selectedItemID: String?
    @Published var requireBiometricsToCopy: Bool { didSet { preferences.set(requireBiometricsToCopy, forKey: "requireBiometricsToCopy") } }
    @Published var autoLockSeconds: Int { didSet { preferences.set(autoLockSeconds, forKey: "autoLockSeconds") } }
    @Published private(set) var lastSavedAt: Date?
    @Published var authenticationError: String?
    private let preferences: UserDefaults
    private var unlocked: UnlockedVault?
    private var lastInteraction = Date()

    init(data: VaultData = VaultData(), masterPassword: String? = nil, unlocked: UnlockedVault? = nil, preferences: UserDefaults = .standard) {
        self.preferences = preferences
        requireBiometricsToCopy = preferences.bool(forKey: "requireBiometricsToCopy")
        let savedTimeout = preferences.integer(forKey: "autoLockSeconds")
        autoLockSeconds = [30, 60, 300].contains(savedTimeout) ? savedTimeout : 60
        self.data = unlocked?.data ?? data
        self.unlocked = unlocked
        isLocked = unlocked == nil
        lastInteraction = Date()
    }

    func unlock(_ unlocked: UnlockedVault) {
        self.data = unlocked.data
        self.unlocked = unlocked
        isLocked = false
        lastInteraction = Date()
        Task { try? await CredentialIdentityIndexer.replaceAll(with: unlocked.data) }
    }

    func lock() {
        unlocked = nil
        selectedItemID = nil
        data = VaultData()
        isLocked = true
        lastSavedAt = nil
        SecureClipboard.clearOwnedContent()
    }

    func handleStorageUnavailable() async {
        lock()
    }

    func touch() {
        lastInteraction = Date()
    }

    func shouldAutoLock(now: Date = Date()) -> Bool {
        !isLocked && now.timeIntervalSince(lastInteraction) >= TimeInterval(autoLockSeconds)
    }

    func save(using store: VaultStore) throws {
        guard let unlocked else { throw VaultStoreError.locked }
        self.unlocked = try store.save(data, using: unlocked)
        lastSavedAt = Date()
        touch()
        Task { try? await CredentialIdentityIndexer.replaceAll(with: data) }
    }

    /// Persist a candidate first. A failed write must not mutate the visible vault.
    func commit(_ candidate: VaultData, write: (VaultData, UnlockedVault) throws -> UnlockedVault) throws {
        guard let unlocked, !isLocked else { throw VaultStoreError.locked }
        let saved = try write(candidate, unlocked)
        self.unlocked = saved
        data = saved.data
        lastSavedAt = Date()
        touch()
        Task { try? await CredentialIdentityIndexer.replaceAll(with: saved.data) }
    }

    func upsert(_ item: VaultItem, using store: VaultStore) throws {
        var candidate = data
        if let index = candidate.items.firstIndex(where: { $0.id == item.id }) { candidate.items[index] = item }
        else { candidate.items.append(item) }
        try commit(candidate, write: store.save)
    }

    func remove(_ item: VaultItem, using store: VaultStore) throws {
        var candidate = data
        candidate.items.removeAll { $0.id == item.id }
        try commit(candidate, write: store.save)
        if selectedItemID == item.id { selectedItemID = nil }
    }

    func authorizeSecretAccess() async -> Bool {
        guard !isLocked else { return false }
        touch()
        guard requireBiometricsToCopy else { return true }
        do {
            let context = LAContext()
            let success = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Access this NoirVault secret.")
            guard success, !isLocked else { return false }
            touch()
            return true
        } catch {
            if (error as? LAError)?.code != .userCancel { authenticationError = error.localizedDescription }
            return false
        }
    }

    func copySecret(_ value: String) async -> Bool {
        guard await authorizeSecretAccess() else { return false }
        SecureClipboard.copy(value)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        return true
    }

    func add(_ item: VaultItem) {
        data.items.append(item)
    }

    func replace(_ item: VaultItem) {
        guard let index = data.items.firstIndex(where: { $0.id == item.id }) else { return }
        data.items[index] = item
    }

    func delete(_ item: VaultItem) {
        data.items.removeAll { $0.id == item.id }
        if selectedItemID == item.id { selectedItemID = nil }
    }

    func select(_ item: VaultItem) {
        selectedItemID = item.id
    }

    var selectedItem: VaultItem? {
        data.items.first { $0.id == selectedItemID }
    }

    var debugHasDerivedKey: Bool { unlocked?.key.isEmpty == false }
}

@MainActor
enum SecureClipboard {
    private static var ownedChangeCount: Int?
    static func copy(_ value: String) {
        let pasteboard = UIPasteboard.general
        pasteboard.setItems([["public.utf8-plain-text": value]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(15)])
        ownedChangeCount = pasteboard.changeCount
    }
    static func clearOwnedContent() {
        if let ownedChangeCount, UIPasteboard.general.changeCount == ownedChangeCount { UIPasteboard.general.items = [] }
        ownedChangeCount = nil
    }
}
