import CryptoKit
import Foundation

enum VaultItemType: String, Codable, CaseIterable, Identifiable {
    case password
    case note
    case file
    case sshKey = "ssh_key"
    case passkey

    var id: String { rawValue }
    var title: String {
        switch self {
        case .password: "Password"
        case .note: "Secure Note"
        case .file: "Encrypted File"
        case .sshKey: "SSH Key"
        case .passkey: "Passkey"
        }
    }

    var symbol: String {
        switch self {
        case .password: "key.fill"
        case .note: "note.text"
        case .file: "doc.fill"
        case .sshKey: "terminal.fill"
        case .passkey: "person.badge.key.fill"
        }
    }
}

struct VaultItem: Codable, Identifiable, Equatable, Hashable {
    var id: String
    var title: String
    var description: String
    var totpSecret: String
    var tags: [String]
    var itemType: VaultItemType
    var content: String

    enum CodingKeys: String, CodingKey {
        case id, title, description, tags, content
        case totpSecret = "totp_secret"
        case itemType = "item_type"
    }

    init(
        id: String = UUID().uuidString,
        title: String,
        description: String = "",
        totpSecret: String = "",
        tags: [String] = [],
        itemType: VaultItemType,
        content: String
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.totpSecret = totpSecret
        self.tags = tags
        self.itemType = itemType
        self.content = content
    }
}

extension VaultItem {
    var hasTOTP: Bool { (try? TOTPConfiguration.parse(totpSecret)) != nil }
    var totpConfiguration: TOTPConfiguration? { try? TOTPConfiguration.parse(totpSecret) }
}

struct VaultData: Codable, Equatable {
    var items: [VaultItem] = []
    var trustedMachines: [String] = []

    enum CodingKeys: String, CodingKey {
        case items
        case trustedMachines = "trusted_machines"
    }

    static let fixture = VaultData(items: [
        VaultItem(title: "Example", description: "Example item", tags: ["demo"], itemType: .password, content: "secret")
    ])
}

enum Attachment {
    static let maximumSize = 50 * 1024 * 1024

    static func validate(size: Int) throws {
        guard size <= maximumSize else { throw VaultStoreError.attachmentTooLarge }
    }
}

struct PairingMarker: Codable, Equatable {
    let vaultID: UUID
    let verifier: Data

    init(vaultID: UUID = UUID(), secret: Data) {
        self.vaultID = vaultID
        verifier = Data(SHA256.hash(data: secret))
    }

    init(vaultID: UUID, verifier: Data) {
        self.vaultID = vaultID
        self.verifier = verifier
    }

    func matches(secret: Data) -> Bool {
        verifier == Data(SHA256.hash(data: secret))
    }
}

enum PasswordGenerator {
    private static let alphabet = Array("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*_-+=")

    static func make(length: Int = 20) -> String {
        String((0..<max(1, length)).compactMap { _ in alphabet.randomElement() })
    }

    static func strength(of password: String) -> String {
        let categories = [
            password.rangeOfCharacter(from: .lowercaseLetters) != nil,
            password.rangeOfCharacter(from: .uppercaseLetters) != nil,
            password.rangeOfCharacter(from: .decimalDigits) != nil,
            password.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil,
        ].filter { $0 }.count

        if password.count >= 16 && categories >= 3 { return "Strong" }
        if password.count >= 10 && categories >= 2 { return "Good" }
        return "Weak"
    }
}
