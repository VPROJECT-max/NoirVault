import Foundation
import LocalAuthentication
import Security

enum SharedKeychain {
    enum StorageScope: Equatable {
        case sharedWithExtension
        case privateToApp
    }

    static let accessGroup = "group.com.Tokyo.noirvault"
    static let service = "com.Tokyo.noirvault"

    static func saveShared(_ data: Data, account: String, accessControl: SecAccessControl? = nil) throws {
        _ = try performWriteWithFallback { scope in
            let identity = baseQuery(account: account, shared: scope == .sharedWithExtension)
            SecItemDelete(identity as CFDictionary)

            var query = identity
            query[kSecValueData] = data
            if let accessControl {
                query[kSecAttrAccessControl] = accessControl
            } else {
                query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            }
            return SecItemAdd(query as CFDictionary, nil)
        }
    }

    static func performWriteWithFallback(_ write: (StorageScope) -> OSStatus) throws -> StorageScope {
        let sharedStatus = write(.sharedWithExtension)
        if sharedStatus == errSecSuccess { return .sharedWithExtension }
        guard sharedStatus == errSecMissingEntitlement else {
            throw VaultStoreError.keychainFailure(sharedStatus)
        }

        let privateStatus = write(.privateToApp)
        guard privateStatus == errSecSuccess else {
            throw VaultStoreError.keychainFailure(privateStatus)
        }
        return .privateToApp
    }

    static func readShared(account: String, context: LAContext? = nil) throws -> Data {
        var query = baseQuery(account: account, shared: true)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        if let context { query[kSecUseAuthenticationContext] = context }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultStoreError.keychainFailure(status)
        }
        return data
    }

    static func readMigratingLegacy(account: String) throws -> Data {
        if let shared = try? readShared(account: account) { return shared }

        var legacy = baseQuery(account: account, shared: false)
        legacy[kSecReturnData] = true
        legacy[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(legacy as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultStoreError.keychainFailure(status)
        }
        try saveShared(data, account: account)
        return data
    }

    static func biometricAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet],
            &error
        ) else {
            if let error { throw error.takeRetainedValue() }
            throw VaultStoreError.keychainFailure(errSecParam)
        }
        return control
    }

    private static func baseQuery(account: String, shared: Bool) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if shared { query[kSecAttrAccessGroup] = accessGroup }
        return query
    }
}
