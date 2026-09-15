# NoirVault iOS Credential Provider Design

## Goal

Deliver NoirVault 2.0 for iPhone with reliable vault-item navigation, a finished app icon, rotating TOTP codes, password and one-time-code AutoFill, and system passkey registration and authentication. The encrypted credential payload remains on the paired USB drive. GitHub Actions produces a tested unsigned IPA containing both the app and its Credential Provider Extension.

## Product decisions

- The paired USB is required to reveal, copy, fill, create, or update any credential.
- Passwords, TOTP seeds, passkey private keys, secure notes, SSH keys, and attachments remain only in `noirvault.vault` on the USB.
- The iPhone may keep the existing folder bookmark and pairing material plus a biometric-protected password-derived vault key in the shared Keychain. These values cannot reconstruct a vault without the paired USB.
- Apple may retain non-secret credential indexes—domain, account label, credential identifier, and record identifier—in `ASCredentialIdentityStore` so NoirVault appears in system AutoFill suggestions. No password, TOTP seed, passkey private key, note, or attachment is indexed.
- Removing the USB locks the main app. A credential extension request with no paired USB fails with an actionable “Connect your NoirVault USB” screen.
- Encrypted cloud synchronization and authenticator-as-a-second-factor vault unlock remain future work. This release manages rotating codes but does not use one to gate the vault itself.

## Delivery slices

### 1. Interaction and identity polish

Make every visible part of a vault row a single, full-width navigation target using explicit selection and a rectangular content shape. Keep swipe-to-delete and accessibility labels intact. Add regression coverage for item selection.

Create an iOS asset catalog with an opaque 1024×1024 NoirVault icon derived from the existing white lion mark on a dark violet-to-black brand field. Configure `ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon` and verify the compiled app contains its icon assets.

### 2. Rotating codes

Keep TOTP as an optional property of password records so existing portable vaults remain compatible. Accept a Base32 secret or an `otpauth://totp/...` URI. Parse issuer, account label, algorithm (`SHA1`, `SHA256`, or `SHA512`), digit count (`6` or `8`), and period while preserving the original setup value only inside the encrypted vault.

The editor provides paste/manual entry and QR scanning. The detail screen displays the current code, a smooth countdown ring, tap-to-copy, and the next code without saving generated values. A dedicated Codes filter shows records with TOTP configured. Invalid secrets are rejected before save and never logged.

`ASCredentialIdentityStore` receives one-time-code identities containing only the service identifier, display label, and NoirVault record identifier. The extension computes the requested code from the USB-resident TOTP seed and returns `ASOneTimeCodeCredential`.

### 3. USB-backed system credential provider

Add a Credential Provider Extension target embedded in `NoirVault.app`. Both targets use:

- AutoFill Credential Provider entitlement;
- App Group `group.com.Tokyo.noirvault`;
- shared Keychain access through the same App Group;
- `AuthenticationServices`, `CryptoKit`, and the shared Rust static library.

Refactor shared Swift code into files compiled by both targets: vault models, USB access, keychain bridge, portable-core wrapper, TOTP, credential indexing, and WebAuthn helpers. The host app still owns initial USB pairing and master-password entry. On a successful password unlock it derives the current v2 envelope key and stores that 32-byte key in the shared Keychain with `biometryCurrentSet`, `userPresence`, and `ThisDeviceOnly` protection. Existing private host-app bookmark and pairing items are migrated into the shared access group without deleting the originals until the shared writes succeed.

The Rust core gains narrowly scoped functions to derive the key for a v2 envelope, decrypt with a supplied 32-byte key, and re-encrypt with the existing salt and a fresh nonce. This keeps the stored biometric key valid across iPhone saves. A desktop save may rotate the salt; the next main-app master-password unlock refreshes the device key.

The extension handles these system requests:

- list matching password, passkey, and one-time-code records;
- fill a selected password;
- fill a selected rotating code;
- register a passkey for a relying party;
- assert a stored passkey for sign-in;
- configure/enable the provider.

It first resolves the shared bookmark, verifies the USB pairing marker, requests Face ID or Touch ID to read the derived key, decrypts the vault in memory, and performs only the requested operation. Plaintext is released when the request completes or is cancelled.

## Passkey representation and WebAuthn

A passkey is a `VaultItem` with `item_type = "passkey"`. Its encrypted `content` is Codable JSON containing:

- relying-party identifier;
- user name and user handle;
- random credential identifier;
- P-256 private-key raw representation;
- creation timestamp;
- signature counter.

Registration accepts ES256 (`-7`) requests, generates a `P256.Signing.PrivateKey`, and builds WebAuthn authenticator data plus a CBOR `none` attestation object. Assertion validates the relying party and requested credential, increments the signature counter, signs `authenticatorData || clientDataHash`, atomically saves the updated encrypted vault to USB, and returns `ASPasskeyAssertionCredential`. Unsupported algorithms, malformed requests, a wrong USB, failed biometrics, or a stale derived key produce specific extension errors without leaking credential data.

## Data compatibility

The portable `NVLT` v2 envelope remains the on-disk format. Rust’s `VaultItem.item_type` is already a string, and adding `passkey` is backward-compatible with serialization. Swift decoding supplies defaults for newly optional fields. Desktop versions that do not understand passkey content must preserve the record unchanged even if they cannot use it.

The existing `totp_secret` JSON field remains the source for TOTP. Password and note records created by V1 continue to decode without migration.

## Interface behavior

The home screen keeps the current noir design. It adds a Codes chip, a passkey symbol, and a small live-code treatment on records with TOTP. Item rows use full-width hit targets with a pressed animation and haptic confirmation.

Password details show username, concealed/revealable password, rotating code when configured, website/service, copy actions, edit, and delete. Passkey details show the relying party, account, creation date, and a non-exportable status; the private key is never rendered or copied.

Security settings show Credential Provider status and a button that opens Apple’s AutoFill settings when the API permits. They also explain that USB connection is mandatory for fills. The extension uses the same visual theme in a compact sheet: USB state, biometric unlock state, matching credentials, and cancellation.

## Error handling and privacy

- Distinguish missing USB, wrong USB, stale bookmark, stale device key, biometric cancellation, malformed TOTP, unsupported passkey algorithm, unavailable credential, and failed atomic save.
- Never log master passwords, derived keys, TOTP seeds/codes, passkey material, plaintext records, or clipboard values.
- Zero Rust-owned sensitive buffers and overwrite temporary Swift `Data` buffers where practical.
- Clipboard secrets expire after 15 seconds as in V1.
- App-group storage contains no vault copy or plaintext credential cache.

## Verification and distribution

Rust tests cover derived-key round trips, wrong-key rejection, salt preservation, nonce rotation, and malformed envelopes. Swift tests cover full-row selection state, Base32/URI parsing, RFC TOTP vectors, passkey CBOR/authenticator-data encoding, request matching, and USB/keychain failure mapping.

GitHub Actions performs locked Rust tests, simulator compilation, the unsigned device build, extension-embedding checks, Info.plist capability checks, app-icon checks, IPA packaging, checksum creation, and artifact upload. The produced IPA is unsigned. For AutoFill and passkeys to function after sideloading, the signer must preserve valid App Group, Keychain Sharing, and AutoFill Credential Provider entitlements for both the host app and nested extension.

## Manual acceptance tests

The final handoff includes device steps for upgrading the app, confirming existing vault compatibility, exercising every row hit area, creating/scanning and filling a TOTP, enabling NoirVault in AutoFill settings, filling a password in another app, registering and authenticating a passkey on a compatible service, testing wrong/missing USB states, and verifying the IPA checksum.
