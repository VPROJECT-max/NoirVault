import XCTest
import CryptoKit
import Security
@testable import NoirVault

final class NoirVaultTests: XCTestCase {
    func testPasswordGeneratorCreatesRequestedLength() {
        XCTAssertEqual(PasswordGenerator.make(length: 24).count, 24)
    }

    func testAttachmentOver50MBIsRejected() {
        XCTAssertThrowsError(try Attachment.validate(size: 50 * 1024 * 1024 + 1))
    }

    @MainActor
    func testUnavailableUSBImmediatelyLocksSession() async {
        let session = VaultSession(unlocked: .fixture)

        await session.handleStorageUnavailable()

        XCTAssertTrue(session.isLocked)
        XCTAssertTrue(session.data.items.isEmpty)
    }

    @MainActor
    func testLockClearsEnvelopeAndDerivedKey() {
        let session = VaultSession(unlocked: .fixture)
        session.lock()
        XCTAssertTrue(session.isLocked)
        XCTAssertFalse(session.debugHasDerivedKey)
    }

    @MainActor
    func testSelectingARecordSetsTheRecordID() {
        let session = VaultSession(unlocked: .fixture)
        session.select(session.data.items[0])
        XCTAssertEqual(session.selectedItemID, session.data.items[0].id)
    }

    func testPairingMarkerRejectsAnUnexpectedSecret() throws {
        let marker = PairingMarker(vaultID: UUID(), verifier: Data(repeating: 1, count: 32))
        XCTAssertFalse(marker.matches(secret: Data(repeating: 2, count: 32)))
    }

    func testMissingSharedEntitlementFallsBackToPrivateKeychain() throws {
        var attemptedScopes: [SharedKeychain.StorageScope] = []

        let selectedScope = try SharedKeychain.performWriteWithFallback { scope in
            attemptedScopes.append(scope)
            return scope == .sharedWithExtension ? errSecMissingEntitlement : errSecSuccess
        }

        XCTAssertEqual(attemptedScopes, [.sharedWithExtension, .privateToApp])
        XCTAssertEqual(selectedScope, .privateToApp)
    }

    func testMissingVaultFileRoutesLaunchToSetup() {
        XCTAssertEqual(
            VaultLaunchPolicy.route(hasStoredPairing: true, probeError: .vaultMissing),
            .setupRequired
        )
    }

    func testDisconnectedUSBKeepsExistingPairing() {
        XCTAssertEqual(
            VaultLaunchPolicy.route(hasStoredPairing: true, probeError: .usbUnavailable),
            .unlockRequired
        )
    }

    func testSHA1RFC6238VectorAt59Seconds() throws {
        let configuration = try TOTPConfiguration.parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").with(digits: 8)
        XCTAssertEqual(TOTPGenerator.code(configuration: configuration, at: Date(timeIntervalSince1970: 59)), "94287082")
    }

    func testTOTPURIParsesIssuerAlgorithmAndPeriod() throws {
        let configuration = try TOTPConfiguration.parse("otpauth://totp/Noir:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Noir&algorithm=SHA256&digits=8&period=45")
        XCTAssertEqual(configuration.issuer, "Noir")
        XCTAssertEqual(configuration.account, "me@example.com")
        XCTAssertEqual(configuration.algorithm, .sha256)
        XCTAssertEqual(configuration.digits, 8)
        XCTAssertEqual(configuration.period, 45)
    }

    func testSHA256AndSHA512RFC6238VectorsAt59Seconds() throws {
        let sha256 = TOTPConfiguration(secret: Data("12345678901234567890123456789012".utf8), issuer: "", account: "", algorithm: .sha256, digits: 8, period: 30)
        let sha512 = TOTPConfiguration(secret: Data("1234567890123456789012345678901234567890123456789012345678901234".utf8), issuer: "", account: "", algorithm: .sha512, digits: 8, period: 30)
        XCTAssertEqual(TOTPGenerator.code(configuration: sha256, at: Date(timeIntervalSince1970: 59)), "46119246")
        XCTAssertEqual(TOTPGenerator.code(configuration: sha512, at: Date(timeIntervalSince1970: 59)), "90693936")
    }

    func testRegistrationAuthenticatorDataContainsRPHashAndAttestedFlag() throws {
        let key = P256.Signing.PrivateKey()
        let data = try WebAuthn.registrationAuthenticatorData(
            relyingParty: "example.com",
            credentialID: Data(repeating: 1, count: 32),
            publicKey: key.publicKey.x963Representation
        )
        XCTAssertEqual(data.prefix(32), Data(SHA256.hash(data: Data("example.com".utf8))))
        XCTAssertEqual(data[32] & 0x40, 0x40)
    }

    func testAssertionRejectsWrongRelyingParty() throws {
        let registration = try WebAuthn.register(relyingParty: "example.com", userName: "me", userHandle: Data([1]))
        XCTAssertThrowsError(try WebAuthn.assert(material: registration.material, relyingParty: "evil.example", clientDataHash: Data(repeating: 0, count: 32)))
    }

    func testPasswordIdentityContainsOnlyMetadata() {
        let item = VaultItem(title: "example.com", description: "alice", itemType: .password, content: "super-secret")
        let identity = CredentialIdentityIndexer.passwordIdentity(for: item)
        XCTAssertEqual(identity.recordIdentifier, item.id)
        XCTAssertEqual(identity.user, "alice")
        XCTAssertFalse(identity.description.contains("super-secret"))
    }
}
