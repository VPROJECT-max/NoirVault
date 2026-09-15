# NoirVault iOS Design

## Goal

Build NoirVault for iPhone running iOS 26.6.2. It provides a dark, native SwiftUI vault whose encrypted content exists only in a user-selected USB vault folder. The same USB vault is readable and writable by the desktop app after it has been migrated to the new portable vault format.

## Product boundaries

V1 supports passwords, secure notes, file attachments up to 50 MB, and SSH keys. A vault uses a master password only; no vault content, master password, or attachment is written to the iPhone. The app may keep only an iOS Keychain security-scoped bookmark and an opaque pairing secret. Face ID or Touch ID, automatic locking, clipboard expiry, password generation, copy username/password, and strength feedback are included. Authenticator-based second-factor unlock and encrypted cloud storage are explicitly deferred.

## USB storage and pairing

At setup, the person selects a folder on the USB volume through the iOS document picker. NoirVault creates `noirvault.vault` and a non-secret `.noirvault-pairing` marker. The marker contains a public vault identifier and a verifier for a random pairing secret; the matching secret stays in Keychain. The app stores the selected directory as a security-scoped bookmark.

On every unlock and save, the app resolves the bookmark, begins security-scoped access, verifies the marker, and coordinates access to the vault file. If the volume is unavailable, the app shows a USB-required screen. iOS cannot offer an arbitrary USB insertion callback, so foreground saves re-check the bookmark and offer the Files picker to restore access. A failed access attempt, protected-data loss, or scene-background transition locks and clears the session immediately. The app writes a temporary file in the selected USB folder, atomically replaces the vault only after encryption completes, and never writes a local fallback.

## Portable vault format

The existing desktop payload is JSON encrypted with Argon2id and XChaCha20-Poly1305, but it requires a keyfile and has no version marker. Introduce a versioned `NVLT` v2 envelope: magic `NVLT`, format version `2`, 16-byte salt, 24-byte nonce, then authenticated ciphertext. The v2 Argon2id input is the UTF-8 master password and no keyfile material. The encrypted plaintext remains the current `VaultData` JSON schema so record compatibility remains direct.

Desktop keeps legacy read support so an existing keyfile vault can be opened and migrated. Its unlock UI makes the keyfile optional: a legacy vault needs it once; the next successful save writes v2 and thereafter requires only the master password. iOS accepts only v2, because it intentionally has no keyfile flow.

## iOS architecture

Use a native SwiftUI app for an iPhone-first interface, backed by a small Rust static library shared with the desktop target. The Rust library owns portable envelope parsing, Argon2id derivation, XChaCha20-Poly1305 encryption, and `VaultData` serialization. A deliberately narrow C ABI accepts encrypted bytes and UTF-8 JSON/password inputs and returns allocated byte buffers or error strings; Swift owns document-picker access, Keychain pairing, LocalAuthentication, state, and UI.

`ios/NoirVault` contains focused Swift types: `VaultStore` for USB document access and pairing, `VaultCore` for the C ABI, `VaultSession` for transient unlocked state, and SwiftUI feature views. The app uses a noir palette, tactile cards, haptics, bottom sheets, native transitions, and selected SVG icons from `icons/`.

## GitHub Actions output

The workflow uses a macOS runner, installs the Rust iOS target, builds the Rust static library for an iPhone arm64 target, builds an Xcode archive with signing disabled, packages the resulting app bundle as a clearly named unsigned IPA artifact, and uploads it with its SHA-256 checksum. The workflow also builds the iOS simulator target and runs Rust tests. The unsigned IPA is a build artifact; installation and execution remain subject to the platform's signing rules.

## Error handling and tests

The UI distinguishes no USB, wrong USB, absent vault, corrupt vault, bad password, unavailable permission, insufficient USB space, and attachment-too-large. Sensitive fields are cleared after use and the app never logs secrets. Rust tests cover v2 round-trips, authentication failure, malformed headers, legacy migration, and compatibility JSON. Swift unit tests cover pairing verification, missing-drive handling, and lock transitions. CI validates the workflow inputs, Rust tests, and an iOS simulator build.
