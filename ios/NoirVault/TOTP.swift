import CryptoKit
import Foundation

enum TOTPError: LocalizedError, Equatable {
    case invalidSecret
    case invalidDigits
    case invalidPeriod

    var errorDescription: String? {
        switch self {
        case .invalidSecret: "Enter a valid Base32 secret or otpauth:// URI."
        case .invalidDigits: "Rotating codes must contain 6 or 8 digits."
        case .invalidPeriod: "The rotating-code period must be greater than zero."
        }
    }
}

struct TOTPConfiguration: Equatable {
    enum Algorithm: String, Equatable { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }

    var secret: Data
    var issuer: String
    var account: String
    var algorithm: Algorithm
    var digits: Int
    var period: Int

    static func parse(_ value: String) throws -> TOTPConfiguration {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") {
            guard let components = URLComponents(string: trimmed),
                  components.host?.lowercased() == "totp" else { throw TOTPError.invalidSecret }
            let parameters = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map {
                ($0.name.lowercased(), $0.value ?? "")
            })
            let secret = try decodeBase32(parameters["secret"] ?? "")
            let digits = Int(parameters["digits"] ?? "6") ?? 0
            guard digits == 6 || digits == 8 else { throw TOTPError.invalidDigits }
            let period = Int(parameters["period"] ?? "30") ?? 0
            guard period > 0 else { throw TOTPError.invalidPeriod }
            guard let algorithm = Algorithm(rawValue: (parameters["algorithm"] ?? "SHA1").uppercased()) else {
                throw TOTPError.invalidSecret
            }
            let decodedPath = components.path.removingPercentEncoding ?? components.path
            let label = String(decodedPath.drop(while: { $0 == "/" }))
            let parts = label.split(separator: ":", maxSplits: 1).map(String.init)
            return TOTPConfiguration(
                secret: secret,
                issuer: parameters["issuer"] ?? (parts.count == 2 ? parts[0] : ""),
                account: parts.count == 2 ? parts[1] : (parts.first ?? ""),
                algorithm: algorithm,
                digits: digits,
                period: period
            )
        }

        return TOTPConfiguration(
            secret: try decodeBase32(trimmed), issuer: "", account: "", algorithm: .sha1, digits: 6, period: 30
        )
    }

    func with(digits: Int) -> TOTPConfiguration {
        var copy = self
        copy.digits = digits
        return copy
    }

    private static func decodeBase32(_ input: String) throws -> Data {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        let values = Dictionary(uniqueKeysWithValues: alphabet.enumerated().map { ($0.element, $0.offset) })
        let clean = input.uppercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }
        guard !clean.isEmpty else { throw TOTPError.invalidSecret }
        var buffer = 0
        var bitCount = 0
        var output = [UInt8]()
        for character in clean {
            guard let value = values[character] else { throw TOTPError.invalidSecret }
            buffer = (buffer << 5) | value
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                output.append(UInt8((buffer >> bitCount) & 0xff))
                buffer &= (1 << bitCount) - 1
            }
        }
        guard !output.isEmpty else { throw TOTPError.invalidSecret }
        return Data(output)
    }
}

enum TOTPGenerator {
    static func code(configuration: TOTPConfiguration, at date: Date = Date()) -> String {
        let counter = UInt64(max(0, Int64(date.timeIntervalSince1970)) / Int64(configuration.period))
        var bigEndian = counter.bigEndian
        let message = withUnsafeBytes(of: &bigEndian) { Data($0) }
        let key = SymmetricKey(data: configuration.secret)
        let digest: Data
        switch configuration.algorithm {
        case .sha1: digest = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: digest = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: digest = Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(digest.last! & 0x0f)
        let binary = (UInt32(digest[offset]) & 0x7f) << 24 |
            UInt32(digest[offset + 1]) << 16 |
            UInt32(digest[offset + 2]) << 8 |
            UInt32(digest[offset + 3])
        let modulus = configuration.digits == 8 ? 100_000_000 : 1_000_000
        return String(format: "%0*d", configuration.digits, Int(binary) % modulus)
    }

    static func remainingSeconds(configuration: TOTPConfiguration, at date: Date = Date()) -> TimeInterval {
        let elapsed = date.timeIntervalSince1970.truncatingRemainder(dividingBy: TimeInterval(configuration.period))
        return TimeInterval(configuration.period) - elapsed
    }
}
