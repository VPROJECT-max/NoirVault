import CryptoKit
import Foundation

enum VaultItemType: String, Codable, CaseIterable, Identifiable, Sendable {
    case password
    case authenticator
    case note
    case file
    case sshKey = "ssh_key"
    case passkey

    var id: String { rawValue }
    var title: String {
        switch self {
        case .password: "Password"
        case .authenticator: "Authenticator"
        case .note: "Secure Note"
        case .file: "Encrypted File"
        case .sshKey: "SSH Key"
        case .passkey: "Passkey"
        }
    }

    var symbol: String {
        switch self {
        case .password: "key.fill"
        case .authenticator: "timer"
        case .note: "note.text"
        case .file: "doc.fill"
        case .sshKey: "terminal.fill"
        case .passkey: "person.badge.key.fill"
        }
    }
}

struct VaultItem: Codable, Identifiable, Equatable, Hashable, Sendable {
    var id: String
    var title: String
    var description: String
    var totpSecret: String
    var tags: [String]
    var itemType: VaultItemType
    var content: String
    var website: String
    var notes: String
    var isFavorite: Bool

    enum CodingKeys: String, CodingKey {
        case id, title, description, tags, content, website, notes
        case isFavorite = "favorite"
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
        content: String,
        website: String = "",
        notes: String = "",
        isFavorite: Bool = false
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.totpSecret = totpSecret
        self.tags = tags
        self.itemType = itemType
        self.content = content
        self.website = website
        self.notes = notes
        self.isFavorite = isFavorite
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        title = try values.decode(String.self, forKey: .title)
        itemType = try values.decode(VaultItemType.self, forKey: .itemType)
        content = try values.decodeIfPresent(String.self, forKey: .content) ?? ""
        description = try values.decodeIfPresent(String.self, forKey: .description) ?? ""
        totpSecret = try values.decodeIfPresent(String.self, forKey: .totpSecret) ?? ""
        tags = try values.decodeIfPresent([String].self, forKey: .tags) ?? []
        website = try values.decodeIfPresent(String.self, forKey: .website) ?? ""
        notes = try values.decodeIfPresent(String.self, forKey: .notes) ?? ""
        isFavorite = try values.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
    }
}

extension VaultItem {
    var hasTOTP: Bool { (try? TOTPConfiguration.parse(totpSecret)) != nil }
    var totpConfiguration: TOTPConfiguration? { try? TOTPConfiguration.parse(totpSecret) }

    var subtitle: String {
        if !description.isEmpty { return description }
        if let account = totpConfiguration?.account, !account.isEmpty { return account }
        return website.isEmpty ? itemType.title : website
    }

    var websiteURL: URL? {
        let input = website.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty,
              let url = URL(string: input.contains("://") ? input : "https://" + input),
              ["https", "http"].contains(url.scheme?.lowercased() ?? ""),
              url.host?.isEmpty == false else { return nil }
        return url
    }

    var validationMessage: String? {
        if title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Give this item a name." }
        if itemType == .authenticator && !hasTOTP { return "Enter an authenticator setup key or scan its QR code." }
        if !totpSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !hasTOTP { return "The authenticator setup key is not valid." }
        if itemType != .authenticator && content.isEmpty { return "Add \(itemType == .password ? "a password" : "content") before saving." }
        if !website.isEmpty && websiteURL == nil { return "Enter a valid website, such as example.com." }
        return nil
    }
}

enum VaultFilter: String, CaseIterable, Identifiable {
    case all, favorites, passwords, notes, files, sshKeys, passkeys
    var id: String { rawValue }
    var title: String {
        switch self {
        case .all: "All items"
        case .favorites: "Favorites"
        case .passwords: "Passwords"
        case .notes: "Notes"
        case .files: "Files"
        case .sshKeys: "SSH keys"
        case .passkeys: "Passkeys"
        }
    }
    func includes(_ item: VaultItem) -> Bool {
        switch self {
        case .all: true
        case .favorites: item.isFavorite
        case .passwords: item.itemType == .password
        case .notes: item.itemType == .note
        case .files: item.itemType == .file
        case .sshKeys: item.itemType == .sshKey
        case .passkeys: item.itemType == .passkey
        }
    }
}

enum VaultSort: String, CaseIterable, Identifiable {
    case name, newest, favorites
    var id: String { rawValue }
    var title: String {
        switch self { case .name: "Name"; case .newest: "Newest first"; case .favorites: "Favorites first" }
    }
}

enum VaultSearch {
    static func items(_ items: [VaultItem], query: String, filter: VaultFilter = .all, codesOnly: Bool = false, sort: VaultSort = .name) -> [VaultItem] {
        let terms = query.split(whereSeparator: \.isWhitespace).map(String.init)
        let matches = items.filter { item in
            let searchable = [item.title, item.description, item.website, item.tags.joined(separator: " ")].joined(separator: " ")
            return filter.includes(item) && (!codesOnly || item.hasTOTP)
                && terms.allSatisfy { searchable.localizedStandardContains($0) }
        }
        if sort == .newest { return Array(matches.reversed()) }
        return matches.sorted {
            if sort == .favorites && $0.isFavorite != $1.isFavorite { return $0.isFavorite }
            let comparison = $0.title.localizedStandardCompare($1.title)
            return comparison == .orderedSame ? $0.id < $1.id : comparison == .orderedAscending
        }
    }
}

struct VaultData: Codable, Equatable, Sendable {
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

    struct Options {
        var length = 24
        var uppercase = true
        var lowercase = true
        var numbers = true
        var symbols = true
        var groups: [String] {
            [lowercase ? "abcdefghijkmnopqrstuvwxyz" : "", uppercase ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "",
             numbers ? "23456789" : "", symbols ? "!@#$%^&*_-+=" : ""].filter { !$0.isEmpty }
        }
    }

    static func make(options: Options) -> String? {
        let groups = options.groups
        guard !groups.isEmpty else { return nil }
        let count = min(128, max(groups.count, options.length))
        let characters = Array(groups.joined())
        var result = groups.compactMap { $0.randomElement() }
        result += (result.count..<count).compactMap { _ in characters.randomElement() }
        result.shuffle()
        return String(result)
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
