import XCTest
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
        let session = VaultSession(data: VaultData.fixture)

        await session.handleStorageUnavailable()

        XCTAssertTrue(session.isLocked)
        XCTAssertTrue(session.data.items.isEmpty)
    }

    func testPairingMarkerRejectsAnUnexpectedSecret() throws {
        let marker = PairingMarker(vaultID: UUID(), verifier: Data(repeating: 1, count: 32))
        XCTAssertFalse(marker.matches(secret: Data(repeating: 2, count: 32)))
    }
}
