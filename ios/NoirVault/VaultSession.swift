import Combine
import Foundation

@MainActor
final class VaultSession: ObservableObject {
    @Published private(set) var data: VaultData
    @Published private(set) var isLocked: Bool
    @Published var selectedItemID: String?
    @Published var requireBiometricsToCopy = false
    @Published var autoLockSeconds = 60
    private var masterPassword: String?
    private var lastInteraction = Date()

    init(data: VaultData = VaultData(), masterPassword: String? = nil) {
        self.data = data
        self.masterPassword = masterPassword
        isLocked = masterPassword == nil
        lastInteraction = Date()
    }

    func unlock(data: VaultData, masterPassword: String) {
        self.data = data
        self.masterPassword = masterPassword
        isLocked = false
        lastInteraction = Date()
    }

    func lock() {
        masterPassword = nil
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
        guard let masterPassword else { throw VaultStoreError.locked }
        try store.save(data, masterPassword: masterPassword)
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
}
