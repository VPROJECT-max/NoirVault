import XCTest
import CryptoKit
import Security
import AuthenticationServices
@testable import NoirVault

final class NoirVaultTests: XCTestCase {
    func testAuthenticatorSavesWithoutPasswordAndRoundTrips() throws {
        let item = VaultItem(title: "GitHub", description: "alice", totpSecret: "JBSWY3DPEHPK3PXP", itemType: .authenticator, content: "", website: "github.com", notes: "Recovery codes stored separately", isFavorite: true)
        XCTAssertNil(item.validationMessage)
        let decoded = try JSONDecoder().decode(VaultItem.self, from: JSONEncoder().encode(item))
        XCTAssertEqual(decoded, item)
        XCTAssertTrue(decoded.hasTOTP)
        XCTAssertTrue(decoded.content.isEmpty)
    }

    func testAuthenticatorRejectsMissingOrInvalidSecret() {
        var item = VaultItem(title: "GitHub", itemType: .authenticator, content: "")
        XCTAssertNotNil(item.validationMessage)
        item.totpSecret = "123456"
        XCTAssertNotNil(item.validationMessage)
        item.totpSecret = "JBSWY3DPEHPK3PXP"
        XCTAssertNil(item.validationMessage)
    }

    func testOldVaultItemsDecodeWithDefaults() throws {
        let json = Data(#"{"id":"legacy","title":"Old login","item_type":"password","content":"secret"}"#.utf8)
        let item = try JSONDecoder().decode(VaultItem.self, from: json)
        XCTAssertEqual(item.website, "")
        XCTAssertEqual(item.notes, "")
        XCTAssertFalse(item.isFavorite)
        XCTAssertEqual(item.tags, [])
    }

    func testStandaloneAuthenticatorIndexesOnlyOTPIdentity() {
        let item = VaultItem(title: "GitHub", totpSecret: "JBSWY3DPEHPK3PXP", itemType: .authenticator, content: "")
        let identities = CredentialIdentityIndexer.identities(for: VaultData(items: [item]))
        XCTAssertEqual(identities.count, 1)
        XCTAssertTrue(identities.first is ASOneTimeCodeCredentialIdentity)
    }

    func testLoginIdentityUsesWebsiteInsteadOfDisplayName() {
        let item = VaultItem(title: "Work account", description: "alice", itemType: .password, content: "secret", website: "https://example.com/login")
        XCTAssertEqual(CredentialIdentityIndexer.passwordIdentity(for: item).serviceIdentifier.identifier, "example.com")
    }

    func testWebsiteRejectsNonWebSchemes() {
        let item = VaultItem(title: "Bad URL", itemType: .password, content: "secret", website: "javascript://alert")
        XCTAssertNil(item.websiteURL)
        XCTAssertNotNil(item.validationMessage)
    }

    func testSearchUsesAllTermsAndNeverSearchesPasswords() {
        let item = VaultItem(title: "Work", description: "alice", tags: ["Team"], itemType: .password, content: "hidden-password", website: "example.com")
        XCTAssertEqual(VaultSearch.items([item], query: " ALICE example ").count, 1)
        XCTAssertTrue(VaultSearch.items([item], query: "hidden-password").isEmpty)
        XCTAssertTrue(VaultSearch.items([item], query: "alice missing").isEmpty)
    }

    func testFiltersAndFavoritesAreIndependentFromCodes() {
        let login = VaultItem(title: "Login", itemType: .password, content: "password")
        let code = VaultItem(title: "Code", totpSecret: "JBSWY3DPEHPK3PXP", itemType: .authenticator, content: "", isFavorite: true)
        XCTAssertEqual(VaultSearch.items([login, code], query: "", codesOnly: true), [code])
        XCTAssertEqual(VaultSearch.items([login, code], query: "", filter: .favorites), [code])
        XCTAssertEqual(VaultSearch.items([login, code], query: "", filter: .all).count, 2)
    }

    func testConfigurableGeneratorIncludesEverySelectedGroup() throws {
        var options = PasswordGenerator.Options()
        options.length = 32
        for _ in 0..<30 {
            let password = try XCTUnwrap(PasswordGenerator.make(options: options))
            XCTAssertEqual(password.count, 32)
            for group in options.groups { XCTAssertTrue(password.contains { group.contains($0) }) }
        }
        options.uppercase = false; options.lowercase = false; options.symbols = false
        XCTAssertTrue(try XCTUnwrap(PasswordGenerator.make(options: options)).allSatisfy(\.isNumber))
        options.numbers = false
        XCTAssertNil(PasswordGenerator.make(options: options))
    }

    @MainActor
    func testFailedWriteDoesNotChangeVisibleVault() throws {
        let session = VaultSession(unlocked: .fixture)
        let original = session.data
        var changed = original
        changed.items[0].content = "new-password"
        XCTAssertThrowsError(try session.commit(changed) { _, _ in throw VaultStoreError.usbUnavailable })
        XCTAssertEqual(session.data, original)
        XCTAssertFalse(session.isLocked)
        XCTAssertNil(session.lastSavedAt)
    }

    @MainActor
    func testSuccessfulWriteCommitsExactlyTheCandidate() throws {
        let session = VaultSession(unlocked: .fixture)
        var changed = session.data
        changed.items[0].isFavorite = true
        try session.commit(changed) { data, unlocked in
            var result = unlocked; result.data = data; return result
        }
        XCTAssertEqual(session.data, changed)
        XCTAssertNotNil(session.lastSavedAt)
        session.lock()
        XCTAssertThrowsError(try session.commit(changed) { _, _ in XCTFail("Locked session wrote data"); return .fixture })
    }

    @MainActor
    func testNonSecretPreferencesSurviveNewSession() throws {
        let name = "NoirVaultTests.\(UUID().uuidString)"
        let preferences = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { preferences.removePersistentDomain(forName: name) }
        let first = VaultSession(preferences: preferences)
        first.autoLockSeconds = 300
        first.requireBiometricsToCopy = true
        let second = VaultSession(preferences: preferences)
        XCTAssertEqual(second.autoLockSeconds, 300)
        XCTAssertTrue(second.requireBiometricsToCopy)
    }

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
