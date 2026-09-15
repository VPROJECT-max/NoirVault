import CryptoKit
import Foundation

struct PasskeyMaterial: Codable, Equatable {
    var relyingParty: String
    var userName: String
    var userHandle: Data
    var credentialID: Data
    var privateKey: Data
    var createdAt: Date
    var signCount: UInt32
}

struct PasskeyRegistration {
    var material: PasskeyMaterial
    var attestationObject: Data
}

struct PasskeyAssertion {
    var authenticatorData: Data
    var signature: Data
    var updatedMaterial: PasskeyMaterial
}

enum WebAuthnError: LocalizedError {
    case invalidKey
    case relyingPartyMismatch

    var errorDescription: String? {
        switch self {
        case .invalidKey: "This USB passkey is invalid."
        case .relyingPartyMismatch: "This passkey belongs to a different website."
        }
    }
}

enum WebAuthn {
    static func register(relyingParty: String, userName: String, userHandle: Data) throws -> PasskeyRegistration {
        let key = P256.Signing.PrivateKey()
        let credentialID = randomBytes(count: 32)
        let material = PasskeyMaterial(
            relyingParty: relyingParty,
            userName: userName,
            userHandle: userHandle,
            credentialID: credentialID,
            privateKey: key.rawRepresentation,
            createdAt: Date(),
            signCount: 0
        )
        let authData = try registrationAuthenticatorData(
            relyingParty: relyingParty,
            credentialID: credentialID,
            publicKey: key.publicKey.x963Representation
        )
        let attestation = CBOR.map([
            (.text("fmt"), .text("none")),
            (.text("attStmt"), .map([])),
            (.text("authData"), .bytes(authData)),
        ]).encoded()
        return PasskeyRegistration(material: material, attestationObject: attestation)
    }

    static func assert(material: PasskeyMaterial, relyingParty: String, clientDataHash: Data) throws -> PasskeyAssertion {
        guard material.relyingParty == relyingParty else { throw WebAuthnError.relyingPartyMismatch }
        let key: P256.Signing.PrivateKey
        do { key = try P256.Signing.PrivateKey(rawRepresentation: material.privateKey) }
        catch { throw WebAuthnError.invalidKey }
        var updated = material
        updated.signCount &+= 1
        let authenticatorData = assertionAuthenticatorData(relyingParty: relyingParty, signCount: updated.signCount)
        let signedData = authenticatorData + clientDataHash
        let signature = try key.signature(for: signedData).derRepresentation
        return PasskeyAssertion(authenticatorData: authenticatorData, signature: signature, updatedMaterial: updated)
    }

    static func registrationAuthenticatorData(relyingParty: String, credentialID: Data, publicKey: Data) throws -> Data {
        guard publicKey.count == 65, publicKey.first == 4 else { throw WebAuthnError.invalidKey }
        var data = Data(SHA256.hash(data: Data(relyingParty.utf8)))
        data.append(0x45) // user present, user verified, attested credential data
        appendUInt32(0, to: &data)
        data.append(Data(repeating: 0, count: 16)) // zero AAGUID for a software authenticator
        data.append(UInt8((credentialID.count >> 8) & 0xff))
        data.append(UInt8(credentialID.count & 0xff))
        data.append(credentialID)
        let x = publicKey.subdata(in: 1..<33)
        let y = publicKey.subdata(in: 33..<65)
        data.append(CBOR.map([
            (.negative(-1), .unsigned(2)), // kty: EC2
            (.negative(-2), .bytes(x)),
            (.negative(-3), .bytes(y)),
            (.unsigned(1), .unsigned(2)),
            (.unsigned(3), .negative(-7)), // alg: ES256
        ]).encoded())
        return data
    }

    static func assertionAuthenticatorData(relyingParty: String, signCount: UInt32) -> Data {
        var data = Data(SHA256.hash(data: Data(relyingParty.utf8)))
        data.append(0x05) // user present and user verified
        appendUInt32(signCount, to: &data)
        return data
    }

    private static func appendUInt32(_ value: UInt32, to data: inout Data) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }

    private static func randomBytes(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}

private indirect enum CBOR {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case map([(CBOR, CBOR)])

    func encoded() -> Data {
        switch self {
        case .unsigned(let value): return Self.header(major: 0, value: value)
        case .negative(let value): return Self.header(major: 1, value: UInt64(-1 - value))
        case .bytes(let value): return Self.header(major: 2, value: UInt64(value.count)) + value
        case .text(let value):
            let bytes = Data(value.utf8)
            return Self.header(major: 3, value: UInt64(bytes.count)) + bytes
        case .map(let pairs):
            let encodedPairs = pairs.map { ($0.0.encoded(), $0.1.encoded()) }.sorted {
                $0.0.lexicographicallyPrecedes($1.0)
            }
            return Self.header(major: 5, value: UInt64(pairs.count)) + encodedPairs.reduce(into: Data()) {
                $0.append($1.0); $0.append($1.1)
            }
        }
    }

    private static func header(major: UInt8, value: UInt64) -> Data {
        if value < 24 { return Data([(major << 5) | UInt8(value)]) }
        if value <= UInt8.max { return Data([(major << 5) | 24, UInt8(value)]) }
        if value <= UInt16.max {
            let number = UInt16(value)
            return Data([(major << 5) | 25, UInt8(number >> 8), UInt8(number & 0xff)])
        }
        if value <= UInt32.max {
            let number = UInt32(value)
            return Data([(major << 5) | 26, UInt8(number >> 24), UInt8((number >> 16) & 0xff), UInt8((number >> 8) & 0xff), UInt8(number & 0xff)])
        }
        return Data([(major << 5) | 27]) + withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}

extension VaultItem {
    var passkeyMaterial: PasskeyMaterial? {
        guard itemType == .passkey else { return nil }
        return try? JSONDecoder().decode(PasskeyMaterial.self, from: Data(content.utf8))
    }

    static func passkey(_ material: PasskeyMaterial) throws -> VaultItem {
        let content = String(decoding: try JSONEncoder().encode(material), as: UTF8.self)
        return VaultItem(title: material.relyingParty, description: material.userName, itemType: .passkey, content: content)
    }
}
