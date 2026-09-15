import Foundation
import LocalAuthentication
import Security

enum SharedKeychain {
    static let accessGroup = "group.com.Tokyo.noirvault"
    static let service = "com.Tokyo.noirvault"

    static func saveShared(_ data: Data, account: String, accessControl: SecAccessControl? = nil) throws {
        let identity = baseQuery(account: account, shared: true)
        SecItemDelete(identity as CFDictionary)

        var query = identity
        query[kSecValueData] = data
        if let accessControl {
            query[kSecAttrAccessControl] = accessControl
        } else {
            query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultStoreError.keychainFailure(status) }
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
            throw error?.takeRetainedValue() ?? VaultStoreError.keychainFailure(errSecParam)
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
