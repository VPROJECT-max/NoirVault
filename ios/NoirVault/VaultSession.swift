import Combine
import Foundation

@MainActor
final class VaultSession: ObservableObject {
    @Published private(set) var data: VaultData
    @Published private(set) var isLocked: Bool
    @Published var selectedItemID: String?
    @Published var requireBiometricsToCopy = false
    @Published var autoLockSeconds = 60
    private var unlocked: UnlockedVault?
    private var lastInteraction = Date()

    init(data: VaultData = VaultData(), masterPassword: String? = nil, unlocked: UnlockedVault? = nil) {
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
        Task { try? await CredentialIdentityIndexer.replaceAll(with: data) }
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
