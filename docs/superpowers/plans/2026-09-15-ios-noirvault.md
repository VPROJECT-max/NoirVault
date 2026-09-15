# NoirVault iOS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an iPhone-only NoirVault app that stores an encrypted, master-password-only portable vault exclusively in a paired USB folder and produces an unsigned IPA artifact in GitHub Actions.

**Architecture:** A Rust static library owns the versioned portable vault envelope and is called from a native SwiftUI iOS app through a narrow C ABI. Swift owns the iOS document picker, security-scoped folder access, Keychain pairing state, Face ID/Touch ID, session locking, and the noir interface. The desktop app upgrades legacy keyfile vaults to the shared v2 format.

**Tech Stack:** Rust, Argon2id, XChaCha20-Poly1305, serde, C FFI, Swift 6, SwiftUI, LocalAuthentication, Security/Keychain, UIKit document picker, Xcode, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-15-ios-noirvault-design.md`

## Global Constraints

- Target iPhone and iOS 26.6.2 for V1; use `com.Tokyo.noirvault` and display name `NoirVault`.
- Store vault records, attachments, and the master password only on the selected USB folder; Keychain may contain only access and pairing metadata.
- Read existing desktop vaults only through desktop migration; write portable `NVLT` v2 envelopes using master password only.
- Lock immediately on USB access loss, protected-data loss, or app backgrounding.
- Enforce a 50 MB attachment maximum.
- Keep TOTP unlock and encrypted cloud sync in `docs/ROADMAP.md`, not V1 code.

---

### Task 1: Portable Rust vault core

**Files:**
- Create: `src/lib.rs`, `src/ffi.rs`, `include/noirvault_core.h`, `tests/portable_vault.rs`
- Modify: `Cargo.toml`, `src/crypto.rs`, `src/memory.rs`, `src/vault.rs`, `src/main.rs`

**Interfaces:**
- Produces `encrypt_v2(password: &str, data: &[u8]) -> Vec<u8>` and `decrypt_v2(password: &str, envelope: &[u8]) -> Result<SecureBuffer, VaultError>`.
- Produces C functions `nv_encrypt_json`, `nv_decrypt_json`, `nv_free_buffer`, and `nv_last_error`.

- [ ] **Step 1: Write failing portable-envelope tests**

```rust
#[test]
fn v2_round_trip_uses_only_the_master_password() {
    let encoded = encrypt_v2("correct horse", br#"{\"items\":[]}"#);
    assert_eq!(&encoded[..5], b"NVLT\x02");
    assert_eq!(decrypt_v2("correct horse", &encoded).unwrap().as_slice(), br#"{\"items\":[]}"#);
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `cargo test --test portable_vault v2_round_trip_uses_only_the_master_password`

- [ ] **Step 3: Implement the versioned Argon2id/XChaCha envelope and C ABI**

```rust
pub const V2_PREFIX: &[u8; 5] = b"NVLT\x02";
pub fn encrypt_v2(password: &str, data: &[u8]) -> Vec<u8> { /* prefix + salt + nonce + ciphertext */ }
pub fn decrypt_v2(password: &str, envelope: &[u8]) -> Result<SecureBuffer, VaultError> { /* authenticate */ }
```

- [ ] **Step 4: Run Rust unit and integration tests**

Run: `cargo test --locked`

- [ ] **Step 5: Commit**

Run: `git add Cargo.toml Cargo.lock src include tests && git commit -m "feat: add portable vault core"`

### Task 2: Desktop migration to v2

**Files:**
- Modify: `src/main.rs`, `ui/app.slint`, `Keyshorcuts.md`, `Readme.md`
- Test: `tests/portable_vault.rs`

**Interfaces:**
- Consumes `is_v2_envelope`, `decrypt_v2`, and `encrypt_v2` from Task 1.
- Produces optional-keyfile desktop unlock and automatic legacy-to-v2 save migration.

- [ ] **Step 1: Add failing tests for legacy detection and v2 re-save**

```rust
assert!(is_v2_envelope(&encrypt_v2("pass", b"payload")));
assert!(!is_v2_envelope(&legacy_envelope));
```

- [ ] **Step 2: Run the targeted test and confirm it fails**

Run: `cargo test --test portable_vault legacy_vault_requires_one_time_keyfile_migration`

- [ ] **Step 3: Make keyfile optional and select the decryption path by envelope marker**

```rust
let vault = if is_v2_envelope(&file_bytes) {
    decrypt_v2(&password, &file_bytes)?
} else {
    decrypt_legacy(&password, &keyfile_bytes?, &file_bytes)?
};
```

- [ ] **Step 4: Run desktop Rust tests**

Run: `cargo test --locked`

- [ ] **Step 5: Commit**

Run: `git add src ui Keyshorcuts.md Readme.md tests && git commit -m "feat: migrate desktop vaults to master-password format"`

### Task 3: iOS project, storage, and pairing

**Files:**
- Create: `ios/NoirVault.xcodeproj/project.pbxproj`, `ios/NoirVault/NoirVaultApp.swift`, `ios/NoirVault/Models.swift`, `ios/NoirVault/VaultCore.swift`, `ios/NoirVault/VaultStore.swift`, `ios/NoirVault/VaultSession.swift`, `ios/NoirVault/Info.plist`, `ios/NoirVaultTests/VaultStoreTests.swift`

**Interfaces:**
- Consumes `nv_encrypt_json` and `nv_decrypt_json` from Task 1.
- Produces `VaultStore.connect()`, `VaultStore.load(password:)`, `VaultStore.save(session:)`, and `VaultSession.lock()`.

- [ ] **Step 1: Write failing storage and lock tests**

```swift
func testUnavailableUSBLocksSession() async throws {
    let session = VaultSession.unlockedFixture
    await session.handleStorageUnavailable()
    XCTAssertTrue(session.isLocked)
}
```

- [ ] **Step 2: Run the iOS unit test and confirm it fails**

Run: `xcodebuild test -project ios/NoirVault.xcodeproj -scheme NoirVault -destination 'platform=iOS Simulator,name=iPhone 16'`

- [ ] **Step 3: Implement security-scoped bookmark, Keychain pairing, coordinated atomic save, and immediate lock**

```swift
func withVaultDirectory<T>(_ body: (URL) throws -> T) throws -> T {
    guard let directory = try resolveBookmark(), directory.startAccessingSecurityScopedResource() else { throw VaultStoreError.usbUnavailable }
    defer { directory.stopAccessingSecurityScopedResource() }
    return try body(directory)
}
```

- [ ] **Step 4: Run the storage tests**

Run: `xcodebuild test -project ios/NoirVault.xcodeproj -scheme NoirVault -destination 'platform=iOS Simulator,name=iPhone 16'`

- [ ] **Step 5: Commit**

Run: `git add ios && git commit -m "feat: add iOS USB vault storage"`

### Task 4: Native noir SwiftUI experience

**Files:**
- Create: `ios/NoirVault/NoirTheme.swift`, `ios/NoirVault/RootView.swift`, `ios/NoirVault/UnlockView.swift`, `ios/NoirVault/VaultListView.swift`, `ios/NoirVault/RecordEditorView.swift`, `ios/NoirVault/RecordDetailView.swift`, `ios/NoirVault/SettingsView.swift`, `ios/NoirVault/PasswordGenerator.swift`, `ios/NoirVault/Resources/*.svg`
- Modify: `ios/NoirVault.xcodeproj/project.pbxproj`

**Interfaces:**
- Consumes `VaultSession` and `VaultStore` from Task 3.
- Produces V1 password, note, file, and SSH-key UI with copy, generator, biometric unlock, auto-lock, and strength feedback.

- [ ] **Step 1: Write failing password-generator and attachment-limit tests**

```swift
func testGeneratorCreatesRequestedLength() { XCTAssertEqual(PasswordGenerator.make(length: 24).count, 24) }
func testAttachmentOver50MBIsRejected() { XCTAssertThrowsError(try Attachment.validate(size: 50 * 1024 * 1024 + 1)) }
```

- [ ] **Step 2: Implement the responsive dark SwiftUI views and security controls**

```swift
scenePhase.onChange { if $0 != .active { session.lock() } }
```

- [ ] **Step 3: Run simulator tests and build**

Run: `xcodebuild test -project ios/NoirVault.xcodeproj -scheme NoirVault -destination 'platform=iOS Simulator,name=iPhone 16' && xcodebuild build -project ios/NoirVault.xcodeproj -scheme NoirVault -sdk iphonesimulator`

- [ ] **Step 4: Commit**

Run: `git add ios && git commit -m "feat: add NoirVault iPhone experience"`

### Task 5: GitHub Actions artifact pipeline and verification

**Files:**
- Create: `.github/workflows/ios-unsigned-ipa.yml`, `ios/ExportOptions.plist`, `ios/scripts/build-rust-core.sh`, `ios/scripts/package-unsigned-ipa.sh`
- Modify: `Readme.md`, `.gitignore`

**Interfaces:**
- Consumes the Xcode project and Rust static library from Tasks 1-4.
- Produces `NoirVault-unsigned.ipa` and `NoirVault-unsigned.ipa.sha256` workflow artifacts.

- [ ] **Step 1: Add workflow validation commands**

```yaml
- run: rustup target add aarch64-apple-ios aarch64-apple-ios-sim
- run: cargo test --locked
- run: xcodebuild build -project ios/NoirVault.xcodeproj -scheme NoirVault -sdk iphonesimulator
```

- [ ] **Step 2: Implement archive, package, checksum, and upload steps**

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: NoirVault-unsigned-ipa
    path: ios/build/NoirVault-unsigned.ipa
```

- [ ] **Step 3: Validate YAML and inspect IPA contents**

Run: `ruby -e "require 'yaml'; YAML.load_file('.github/workflows/ios-unsigned-ipa.yml')"` and `unzip -l ios/build/NoirVault-unsigned.ipa`

- [ ] **Step 4: Commit**

Run: `git add .github ios Readme.md .gitignore && git commit -m "ci: build unsigned iOS IPA artifact"`
