import Foundation

struct NvBuffer {
    var data: UnsafeMutablePointer<UInt8>?
    var len: Int
}

@_silgen_name("nv_encrypt_json")
private func nvEncryptJSON(_ password: UnsafePointer<CChar>, _ json: UnsafePointer<UInt8>?, _ jsonLength: Int) -> NvBuffer

@_silgen_name("nv_decrypt_json")
private func nvDecryptJSON(_ password: UnsafePointer<CChar>, _ envelope: UnsafePointer<UInt8>?, _ envelopeLength: Int) -> NvBuffer

@_silgen_name("nv_derive_vault_key")
private func nvDeriveVaultKey(_ password: UnsafePointer<CChar>, _ envelope: UnsafePointer<UInt8>?, _ envelopeLength: Int) -> NvBuffer

@_silgen_name("nv_decrypt_json_with_key")
private func nvDecryptJSONWithKey(_ key: UnsafePointer<UInt8>?, _ keyLength: Int, _ envelope: UnsafePointer<UInt8>?, _ envelopeLength: Int) -> NvBuffer

@_silgen_name("nv_reencrypt_json_with_key")
private func nvReencryptJSONWithKey(_ key: UnsafePointer<UInt8>?, _ keyLength: Int, _ existingEnvelope: UnsafePointer<UInt8>?, _ existingEnvelopeLength: Int, _ json: UnsafePointer<UInt8>?, _ jsonLength: Int) -> NvBuffer

@_silgen_name("nv_free_buffer")
private func nvFreeBuffer(_ buffer: NvBuffer)

@_silgen_name("nv_last_error")
private func nvLastError() -> UnsafePointer<CChar>?

enum VaultCoreError: LocalizedError {
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .operationFailed(let message): message
        }
    }
}

enum VaultCore {
    static func encrypt(json: Data, password: String) throws -> Data {
        let result = password.withCString { passwordPointer in
            json.withUnsafeBytes { bytes in
                nvEncryptJSON(passwordPointer, bytes.bindMemory(to: UInt8.self).baseAddress, json.count)
            }
        }
        return try data(from: result)
    }

    static func decrypt(envelope: Data, password: String) throws -> Data {
        let result = password.withCString { passwordPointer in
            envelope.withUnsafeBytes { bytes in
                nvDecryptJSON(passwordPointer, bytes.bindMemory(to: UInt8.self).baseAddress, envelope.count)
            }
        }
        return try data(from: result)
    }

    static func deriveKey(envelope: Data, password: String) throws -> Data {
        let result = password.withCString { passwordPointer in
            envelope.withUnsafeBytes { bytes in
                nvDeriveVaultKey(passwordPointer, bytes.bindMemory(to: UInt8.self).baseAddress, envelope.count)
            }
        }
        return try data(from: result)
    }

    static func decrypt(envelope: Data, key: Data) throws -> Data {
        let result = key.withUnsafeBytes { keyBytes in
            envelope.withUnsafeBytes { envelopeBytes in
                nvDecryptJSONWithKey(
                    keyBytes.bindMemory(to: UInt8.self).baseAddress,
                    key.count,
                    envelopeBytes.bindMemory(to: UInt8.self).baseAddress,
                    envelope.count
                )
            }
        }
        return try data(from: result)
    }

    static func reencrypt(json: Data, existingEnvelope: Data, key: Data) throws -> Data {
        let result = key.withUnsafeBytes { keyBytes in
            existingEnvelope.withUnsafeBytes { envelopeBytes in
                json.withUnsafeBytes { jsonBytes in
                    nvReencryptJSONWithKey(
                        keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        key.count,
                        envelopeBytes.bindMemory(to: UInt8.self).baseAddress,
                        existingEnvelope.count,
                        jsonBytes.bindMemory(to: UInt8.self).baseAddress,
                        json.count
                    )
                }
            }
        }
        return try data(from: result)
    }

    private static func data(from buffer: NvBuffer) throws -> Data {
        guard let pointer = buffer.data, buffer.len > 0 else {
            let message = nvLastError().map { String(cString: $0) } ?? "The vault operation failed."
            throw VaultCoreError.operationFailed(message)
        }
        defer { nvFreeBuffer(buffer) }
        return Data(bytes: pointer, count: buffer.len)
    }
}
