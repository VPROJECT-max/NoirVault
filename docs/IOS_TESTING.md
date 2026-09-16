# NoirVault 2.0 iPhone Test Guide

## Install and enable

1. Download both files from the latest successful **Build NoirVault unsigned IPA** run on the `IOS` branch.
2. Confirm the IPA SHA-256 matches `NoirVault-unsigned.ipa.sha256`.
3. Sign and sideload the IPA with a method that preserves the host app and `NoirVaultCredentialProvider.appex` entitlements. Both bundles require the App Group and shared Keychain group `group.com.Tokyo.noirvault`; the credential-provider entitlement must remain enabled.
4. Open NoirVault, select the folder on the USB drive, and create or unlock the vault.
5. In iOS Settings, enable **NoirVault AutoFill** under credential/password provider settings.

If the signer removes the nested extension, App Group, Keychain Sharing, or AutoFill entitlement, the main vault may open while system password/passkey/OTP integration remains unavailable.

## Acceptance checklist

- Confirm the purple/noir lion app icon appears on the Home Screen.
- Tap the left, middle, and right side of several vault rows. Every position must open the same detail page reliably.
- Remove the USB while unlocked. NoirVault must lock and must not reveal or save records.
- Try the paired vault with another USB selected. NoirVault must reject it.
- Create a password record with a manual Base32 TOTP secret. Verify the code, circular countdown, rollover, and 15-second clipboard clearing.
- Scan an `otpauth://totp` QR code. Verify issuer/account, SHA-1/SHA-256/SHA-512, 6/8 digits, and custom period values when present.
- Switch to **Authenticator** and confirm only records with valid rotating-code material appear, including standalone authenticator records.
- Save, disconnect, reconnect, and unlock again. Password and TOTP data must persist only in the encrypted USB envelope.
- In Safari or an app sign-in screen, select NoirVault AutoFill. Face ID and the paired USB must be required before a password is returned.
- In an OTP field, select NoirVault and verify the current rotating code fills.
- Register a new passkey on a site that supports passkeys and ES256. Confirm the new passkey appears in NoirVault and the site accepts registration.
- Sign out, then sign in with that passkey. Confirm Face ID plus the paired USB are required and authentication succeeds.
- Cancel Face ID during password, OTP, registration, and assertion requests. No credential should be returned or written.
- Repeat password, OTP, and passkey requests with the USB removed. Each request must fail closed.
- Open a vault last saved by the desktop app. Unlock it on iPhone, save one change, then reopen it on desktop to verify portable-v2 compatibility.

## Artifact checks

The successful CI run verifies the Rust portable-core tests, compiles the iPhone simulator app, runs the XCTest suite, builds the arm64 device app, checks for `Assets.car`, checks the nested credential-provider extension and its extension point, packages the unsigned IPA, and uploads the IPA with its checksum.

## Experience upgrade acceptance

- Add **Authenticator** with only a name and setup key. Save must work with no password field. Scan a QR code and check that its issuer/account prefill the form. Invalid keys must have a clear inline message.
- Open **Authenticator** in the library. Verify live codes, expiry rings, secure copy, and rollover after biometric authentication.
- Edit each item type. Keep its ID, attachment or passkey material, tags, notes and favorite status. Cancel an edited form and verify the discard confirmation.
- Search multiple words across name, username, website and tags. Try Favorites, every item type, and every sort order. Switch back from Authenticator to Vault and verify All items includes everything.
- Toggle favorites from a row and from details; persist across lock/unlock. Delete through swipe and details, with confirmation.
- Generate passwords with custom length and each character group; verify empty character selection cannot be applied/copied. Use a generated password in an editor.
- Turn on biometric protection. Reveal/copy passwords, note content, private keys and codes, edit an existing record, and export a file. Cancel authentication and verify no protected action happens.
- Copy a secret then copy unrelated text in another app: NoirVault must never clear the unrelated clipboard. Copied secrets should expire after 15 seconds and not sync via Universal Clipboard.
- Verify temporary system interruptions cover the vault and allow returning to it. Backgrounding and USB removal still lock. Typing, scrolling and controls refresh activity.
- Disconnect during a requested save. Verify the locked **Reconnect to finish saving** screen, automatic retry on the paired USB, and the final saved message. Force-quitting before success intentionally loses the pending ciphertext, which exists only in memory.
- If another app changes the vault between opening and saving, NoirVault must refuse to overwrite the newer version. Do not discard pending changes until the desired data is backed up.
- Choose **Open existing** after reinstalling or changing pairing. A wrong password must not replace the marker or encrypted vault. **Create new** must refuse a folder that contains a vault.
- Inspect the `NoirVault-test-evidence` artifact's rendered screenshots, including accessibility text size. These render tests do not prove tap, camera, physical USB or signing behavior; complete the corresponding device checks above.
