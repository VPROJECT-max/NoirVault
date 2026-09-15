# NoirVault iOS Credential Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship NoirVault 2.0 as an unsigned IPA with reliable item navigation, a branded app icon, USB-backed rotating codes, password/OTP AutoFill, and passkey registration and authentication.

**Architecture:** Keep `NVLT` v2 and add key-based Rust APIs so an App Group Keychain item protected by biometrics can unlock only the currently paired USB envelope. Compile shared Swift vault, TOTP, indexing, and WebAuthn code into both the host app and a nested AutoFill Credential Provider Extension; keep all credential secrets and passkey private keys inside the encrypted USB vault.

**Tech Stack:** Swift 6, SwiftUI, UIKit, AuthenticationServices, CryptoKit, LocalAuthentication, AVFoundation, Security, Rust, Argon2id, XChaCha20-Poly1305, XCTest, GitHub Actions/macOS.

**Spec:** `docs/superpowers/specs/2026-09-15-ios-credential-provider-design.md`

## Global Constraints

- Deployment target is iOS 26.0 and the build output is an unsigned arm64 IPA.
- The paired USB is required for every credential reveal, fill, registration, assertion, or save.
- No password, TOTP seed, passkey private key, note, attachment, or plaintext vault cache may be written locally.
- App Group and Keychain access group are exactly `group.com.Tokyo.noirvault`.
- Existing `NVLT` v2 vaults and existing private Keychain pairing entries remain upgrade-compatible.
- The extension supports ES256 passkeys and 6/8-digit SHA1/SHA256/SHA512 TOTP.
- Every committed implementation slice must pass `git diff --check`; final completion requires a green GitHub Actions macOS run and uploaded IPA artifact.

---

### Task 1: Key-based portable vault operations

**Files:**
- Modify: `src/crypto.rs`
- Modify: `src/ffi.rs`
- Modify: `include/noirvault_core.h`
- Modify: `tests/portable_vault.rs`
- Modify: `ios/NoirVault/VaultCore.swift`

**Interfaces:**
- Produces Rust `derive_v2_key_for_envelope(password, envelope) -> Result<SecureBuffer, VaultError>`.
- Produces Rust `decrypt_v2_with_key(key, envelope) -> Result<SecureBuffer, VaultError>`.
- Produces Rust `reencrypt_v2_with_key(key, existing_envelope, plaintext) -> Result<Vec<u8>, VaultError>`.
- Produces C ABI `nv_derive_vault_key`, `nv_decrypt_json_with_key`, and `nv_reencrypt_json_with_key`.
- Produces Swift `VaultCore.deriveKey`, `VaultCore.decrypt(envelope:key:)`, and `VaultCore.reencrypt(json:existingEnvelope:key:)`.

- [ ] **Step 1: Write failing Rust tests for raw-key unlock and stable salt**

```rust
#[test]
fn derived_key_unlocks_and_reencrypts_without_rotating_salt() {
    let first = encrypt_v2("master", br#"{\"items\":[]}"#);
    let key = derive_v2_key_for_envelope("master", &first).unwrap();
    let second = reencrypt_v2_with_key(key.as_slice(), &first, br#"{\"items\":[1]}"#).unwrap();
    assert_eq!(&first[5..21], &second[5..21]);
    assert_ne!(&first[21..45], &second[21..45]);
    assert_eq!(decrypt_v2_with_key(key.as_slice(), &second).unwrap().as_slice(), br#"{\"items\":[1]}"#);
}
```

- [ ] **Step 2: Run the focused Rust test and confirm it fails because the APIs do not exist**

Run: `cargo test --locked --no-default-features --test portable_vault derived_key_unlocks_and_reencrypts_without_rotating_salt`

Expected: compile failure naming `derive_v2_key_for_envelope`, `decrypt_v2_with_key`, and `reencrypt_v2_with_key`.

- [ ] **Step 3: Implement strict envelope parsing and key-based operations**

```rust
pub fn derive_v2_key_for_envelope(password: &str, envelope: &[u8]) -> Result<SecureBuffer, VaultError>;
pub fn decrypt_v2_with_key(key: &[u8], envelope: &[u8]) -> Result<SecureBuffer, VaultError>;
pub fn reencrypt_v2_with_key(key: &[u8], existing: &[u8], data: &[u8]) -> Result<Vec<u8>, VaultError>;
```

Reject non-32-byte keys and malformed v2 headers, copy the existing 16-byte salt, always generate a fresh 24-byte nonce, and zero temporary key buffers.

- [ ] **Step 4: Expose the C and Swift wrappers and test null/wrong-length inputs**

```c
NvBuffer nv_derive_vault_key(const char *password, const uint8_t *envelope, size_t envelope_len);
NvBuffer nv_decrypt_json_with_key(const uint8_t *key, size_t key_len, const uint8_t *envelope, size_t envelope_len);
NvBuffer nv_reencrypt_json_with_key(const uint8_t *key, size_t key_len, const uint8_t *existing, size_t existing_len, const uint8_t *json, size_t json_len);
```

- [ ] **Step 5: Run all portable-core tests and commit**

Run: `cargo test --locked --no-default-features --lib --test portable_vault`

Commit: `feat: add biometric vault-key core operations`

---

### Task 2: Shared Keychain and USB transaction layer

**Files:**
- Create: `ios/NoirVault/SharedKeychain.swift`
- Modify: `ios/NoirVault/VaultStore.swift`
- Modify: `ios/NoirVault/VaultSession.swift`
- Modify: `ios/NoirVault/RootView.swift`
- Modify: `ios/NoirVaultTests/NoirVaultTests.swift`

**Interfaces:**
- Produces `SharedKeychain.saveShared(_:account:accessControl:)`, `readShared(account:context:)`, and migration from legacy private entries.
- Produces `UnlockedVault(data: VaultData, envelope: Data, key: Data)`.
- Produces `VaultStore.load(masterPassword:) -> UnlockedVault`, `loadWithDeviceKey(context:)`, and `save(_:using:) -> UnlockedVault`.

- [ ] **Step 1: Add tests for missing shared material, migration selection, and session key clearing**

```swift
@MainActor func testLockClearsEnvelopeAndDerivedKey() {
    let session = VaultSession(unlocked: .fixture)
    session.lock()
    XCTAssertTrue(session.isLocked)
    XCTAssertNil(session.debugHasDerivedKey)
}
```

- [ ] **Step 2: Run the simulator test target and confirm the new interfaces fail to compile**

Run: `xcodebuild test -project ios/NoirVault.xcodeproj -scheme NoirVault -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 16 Pro' CODE_SIGNING_ALLOWED=NO`

Expected: missing `UnlockedVault` and shared-keychain interfaces.

- [ ] **Step 3: Implement the shared App Group Keychain store**

```swift
enum SharedKeychain {
    static let accessGroup = "group.com.Tokyo.noirvault"
    static func saveShared(_ data: Data, account: String, accessControl: SecAccessControl? = nil) throws
    static func readShared(account: String, context: LAContext? = nil) throws -> Data
}
```

Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; for the derived key use a `SecAccessControl` requiring `.biometryCurrentSet` and `.userPresence`. Copy legacy bookmark and pairing values only after a successful shared write.

- [ ] **Step 4: Refactor `VaultStore` into atomic password/key unlock and save operations**

Preserve the current security-scoped bookmark, pairing-marker verification, `NSFileCoordinator`, 50 MB limit, and atomic envelope replacement. Saving with an unlocked key must preserve salt and rotate nonce.

- [ ] **Step 5: Update `VaultSession` to hold and clear the envelope/key, run tests, and commit**

Run: simulator unit tests plus `git diff --check`.

Commit: `feat: share biometric USB vault access`

---

### Task 3: Rotating-code engine

**Files:**
- Create: `ios/NoirVault/TOTP.swift`
- Modify: `ios/NoirVault/Models.swift`
- Modify: `ios/NoirVaultTests/NoirVaultTests.swift`

**Interfaces:**
- Produces `TOTPConfiguration.parse(_:) throws -> TOTPConfiguration`.
- Produces `TOTPGenerator.code(configuration:at:) -> String` and `remainingSeconds(configuration:at:) -> TimeInterval`.
- Produces `VaultItem.hasTOTP` and `VaultItem.totpConfiguration`.

- [ ] **Step 1: Add RFC 6238 vectors and URI/Base32 parser tests**

```swift
func testSHA1RFC6238VectorAt59Seconds() throws {
    let configuration = try TOTPConfiguration.parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    XCTAssertEqual(TOTPGenerator.code(configuration: configuration.with(digits: 8), at: Date(timeIntervalSince1970: 59)), "94287082")
}
```

- [ ] **Step 2: Run tests and confirm failure because `TOTPConfiguration` is absent**

Run: the `NoirVaultTests` simulator target.

- [ ] **Step 3: Implement Base32 decoding, `otpauth` parsing, HMAC algorithms, dynamic truncation, and countdown math**

```swift
struct TOTPConfiguration: Equatable {
    enum Algorithm: String { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }
    let secret: Data
    let issuer: String
    let account: String
    let algorithm: Algorithm
    let digits: Int
    let period: Int
}
```

- [ ] **Step 4: Add malformed-secret, invalid-digit, invalid-period, and lowercase-Base32 coverage**

- [ ] **Step 5: Run simulator tests and commit**

Commit: `feat: add standards-based rotating codes`

---

### Task 4: Host-app TOTP UI, row fix, and app icon

**Files:**
- Create: `ios/NoirVault/TOTPScannerView.swift`
- Create: `ios/NoirVault/TOTPCodeView.swift`
- Create: `ios/NoirVault/Assets.xcassets/Contents.json`
- Create: `ios/NoirVault/Assets.xcassets/AppIcon.appiconset/Contents.json`
- Create: `ios/NoirVault/Assets.xcassets/AppIcon.appiconset/NoirVault-1024.png`
- Modify: `ios/NoirVault/VaultHomeView.swift`
- Modify: `ios/NoirVault/RecordEditorView.swift`
- Modify: `ios/NoirVault/RecordDetailView.swift`
- Modify: `ios/NoirVault/Info.plist`
- Modify: `ios/NoirVault.xcodeproj/project.pbxproj`
- Modify: `ios/NoirVaultTests/NoirVaultTests.swift`

**Interfaces:**
- Produces full-width row `selectedItemID` navigation.
- Produces reusable `TOTPCodeView(configuration:)` and QR scanner callback `(Result<String, Error>) -> Void`.
- Produces a valid opaque 1024×1024 AppIcon asset.

- [ ] **Step 1: Add selection-state and TOTP-editor validation tests**

```swift
@MainActor func testSelectingAnyRowRegionSetsTheRecordID() {
    let session = VaultSession(unlocked: .fixture)
    session.select(session.data.items[0])
    XCTAssertEqual(session.selectedItemID, session.data.items[0].id)
}
```

- [ ] **Step 2: Replace value-based row links with full-width explicit navigation**

```swift
Button { session.select(item) } label: {
    VaultRow(item: item).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
}
.buttonStyle(VaultRowButtonStyle())
```

Drive `.navigationDestination(item:)` from `selectedItemID`, preserve swipe actions, add pressed scale/opacity and selection haptic.

- [ ] **Step 3: Add TOTP manual/URI entry, QR scanning, Codes filter, countdown, copy, edit, and validation**

Use `AVCaptureMetadataOutput` restricted to `.qr`, request camera access only after the Scan button, and add `NSCameraUsageDescription`.

- [ ] **Step 4: Generate and register the app icon**

Composite the existing white lion `icon.png` over an opaque noir/violet 1024×1024 field, do not apply a rounded mask, add the asset catalog to Resources, and set `ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon` in Debug and Release.

- [ ] **Step 5: Build the simulator app, inspect the compiled asset catalog, and commit**

Commit: `feat: polish vault rows codes and identity`

---

### Task 5: Passkey WebAuthn engine

**Files:**
- Create: `ios/NoirVault/WebAuthn.swift`
- Modify: `ios/NoirVault/Models.swift`
- Modify: `ios/NoirVaultTests/NoirVaultTests.swift`

**Interfaces:**
- Produces `PasskeyMaterial` Codable storage.
- Produces `WebAuthn.register(relyingParty:userName:userHandle:clientDataHash:)`.
- Produces `WebAuthn.assert(material:clientDataHash:)`.
- Produces deterministic CBOR, COSE EC2 key, registration auth data, assertion auth data, and ES256 signatures.

- [ ] **Step 1: Add deterministic CBOR/COSE/authenticator-data tests**

```swift
func testRegistrationAuthenticatorDataContainsRPHashAndAttestedFlag() throws {
    let data = try WebAuthn.registrationAuthenticatorData(relyingParty: "example.com", credentialID: Data(repeating: 1, count: 32), publicKey: fixturePublicKey)
    XCTAssertEqual(data.prefix(32), Data(SHA256.hash(data: Data("example.com".utf8))))
    XCTAssertEqual(data[32] & 0x40, 0x40)
}
```

- [ ] **Step 2: Run tests and confirm the engine is absent**

- [ ] **Step 3: Implement minimal canonical CBOR and WebAuthn ES256 registration**

```swift
struct PasskeyMaterial: Codable, Equatable {
    var relyingParty: String
    var userName: String
    var userHandle: Data
    var credentialID: Data
    var privateKey: Data
    var createdAt: Date
    var signCount: UInt32
}
```

- [ ] **Step 4: Implement assertion, RP/credential validation, counter increment, and DER signature output**

- [ ] **Step 5: Run all simulator tests and commit**

Commit: `feat: add USB-resident passkey engine`

---

### Task 6: Credential identity indexing and extension flows

**Files:**
- Create: `ios/NoirVault/CredentialIdentityIndexer.swift`
- Create: `ios/NoirVaultCredentialProvider/Info.plist`
- Create: `ios/NoirVaultCredentialProvider/NoirVaultCredentialProvider.entitlements`
- Create: `ios/NoirVaultCredentialProvider/CredentialProviderViewController.swift`
- Create: `ios/NoirVaultCredentialProvider/CredentialProviderView.swift`
- Create: `ios/NoirVault/NoirVault.entitlements`
- Modify: `ios/NoirVault/VaultSession.swift`
- Modify: `ios/NoirVault/VaultHomeView.swift`
- Modify: `ios/NoirVault/RootView.swift`
- Modify: `ios/NoirVaultTests/NoirVaultTests.swift`

**Interfaces:**
- Produces `CredentialIdentityIndexer.replaceAll(with:)`.
- Produces extension request states for configuration, USB unlock, credential selection, passkey registration, and errors.
- Consumes `VaultStore.loadWithDeviceKey`, `VaultStore.save`, `TOTPGenerator`, and `WebAuthn`.

- [ ] **Step 1: Add pure record-matching and identity-conversion tests**

```swift
func testPasswordIdentityContainsNoPassword() {
    let identity = CredentialIdentityIndexer.passwordIdentity(for: .fixture.items[0])
    XCTAssertEqual(identity.recordIdentifier, VaultData.fixture.items[0].id)
    XCTAssertFalse(String(describing: identity).contains("secret"))
}
```

- [ ] **Step 2: Implement password, passkey, and OTP identity replacement after every load/save/delete**

Only domain/account/credential identifiers and record IDs may enter `ASCredentialIdentityStore`.

- [ ] **Step 3: Implement provider configuration and USB/biometric unlock UI**

Subclass `ASCredentialProviderViewController`, host compact SwiftUI with `UIHostingController`, and map cancellation/missing USB/stale key to `ASExtensionError` codes.

- [ ] **Step 4: Implement password and OTP request completion**

Use `completeRequest(withSelectedCredential:)` for passwords and `completeOneTimeCodeRequest(using:)` for rotating codes after matching by `recordIdentifier`.

- [ ] **Step 5: Implement passkey registration and assertion completion**

Check `supportedAlgorithms` includes ES256, atomically save newly registered or counter-updated material on USB, refresh identities, and call `completeRegistrationRequest(using:)` or `completeAssertionRequest(using:)`.

- [ ] **Step 6: Run unit tests and commit**

Commit: `feat: add NoirVault AutoFill credential provider`

---

### Task 7: Xcode extension target and unsigned IPA validation

**Files:**
- Modify: `ios/NoirVault.xcodeproj/project.pbxproj`
- Modify: `.github/workflows/ios-unsigned-ipa.yml`
- Modify: `ios/scripts/package-unsigned-ipa.sh`

**Interfaces:**
- Produces `NoirVaultCredentialProvider.appex` embedded under `NoirVault.app/PlugIns`.
- Produces artifact `NoirVault-unsigned-ipa` containing IPA and SHA-256 checksum.

- [ ] **Step 1: Add the native extension target, embed phase, dependencies, shared sources, frameworks, build settings, entitlements, and product**

Use product type `com.apple.product-type.app-extension`, bundle ID `com.Tokyo.noirvault.credential-provider`, `APPLICATION_EXTENSION_API_ONLY = YES`, and skip install.

- [ ] **Step 2: Add CI structure checks before packaging**

```bash
test -d "$APP_PATH/PlugIns/NoirVaultCredentialProvider.appex"
plutil -extract NSExtension.NSExtensionPointIdentifier raw "$APP_PATH/PlugIns/NoirVaultCredentialProvider.appex/Info.plist" | grep -q 'com.apple.authentication-services-credential-provider-ui'
test -f "$APP_PATH/Assets.car"
```

- [ ] **Step 3: Run `git diff --check`, inspect the project with `xcodebuild -list`, then build simulator and unsigned device targets**

Expected: both targets compile; device app includes the nested extension and icon assets.

- [ ] **Step 4: Package the IPA, verify nested paths with `unzip -l`, and commit**

Commit: `ci: package credential-provider IPA`

---

### Task 8: Roadmap, user guide, and release verification

**Files:**
- Modify: `docs/ROADMAP.md`
- Create: `docs/IOS_TESTING.md`
- Modify: `Readme.md`

**Interfaces:**
- Produces the final capabilities list, sideload entitlement warning, enablement steps, and device acceptance checklist.

- [ ] **Step 1: Move delivered TOTP/passkey items out of the future roadmap and retain encrypted cloud plus cross-platform unlock 2FA**

- [ ] **Step 2: Write exact install/enable/test instructions**

Include upgrade compatibility, full-row tapping, manual and QR TOTP, code copy/expiry, password fill, OTP fill, passkey registration/assertion, wrong/missing USB, Face ID cancellation, desktop salt refresh, icon appearance, checksum, and extension entitlements.

- [ ] **Step 3: Run the full local checks available on Windows**

Run: `git diff --check`, JSON/plist structural checks available locally, and repository status inspection.

- [ ] **Step 4: Push `IOS`, monitor GitHub Actions to completion, and inspect the uploaded artifact**

Do not claim completion from a running job. Require every Rust, simulator, device, extension, icon, package, checksum, and upload step to be green.

- [ ] **Step 5: Fix any authoritative macOS error, repeat until green, and commit the release documentation**

Commit: `docs: add NoirVault 2.0 device test guide`

- [ ] **Step 6: Report the download location, complete capability list, and exact device tests**

The final response links the successful workflow run and clearly notes that the sideload signer must preserve the host and nested-extension entitlements.
