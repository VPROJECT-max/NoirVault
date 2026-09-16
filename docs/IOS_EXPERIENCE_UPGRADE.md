# NoirVault iOS experience upgrade

The goal is a functional, polished USB password manager and authenticator in NoirVault's own visual style. This is a whole-app improvement, not only an OTP patch. Cloud sync and a second factor for master-password unlock remain future ideas in ROADMAP.md.

## Requirements and verification

- Standalone authenticator records: create manually or scan QR, preview and copy live codes, edit without supplying a password, index for OTP AutoFill. Verify parsing vectors, validation, serialization, indexing, simulator interactions.
- Complete item lifecycle: add, view, edit, favorite, search, sort, delete with confirmation, export attachments. Login websites and notes must survive encryption and portable serialization. Verify model and save transaction tests plus simulator flows.
- Reliable navigation and forms: full-row tap targets, stable item-ID navigation, one editor identity per sheet, validation and useful empty/error states, discard confirmation. Verify simulator interactions at multiple tap positions and with keyboard visible.
- Purposeful polish: preserve the noir/violet/mint palette, use native text styles, readable grouped code typography, action-driven transitions and feedback, reduced-motion support and accessibility labels. Inspect rendered simulator screens.
- Useful generator: adjustable length and character groups; generate, copy, and apply to a login. Verify requested composition and length.
- Security and lifecycle: masked secrets, consistent biometric copy/reveal handling, expiring local clipboard, persistent non-secret preferences, inactivity tracking that respects typing/scrolling, privacy cover for interruptions. Verify session tests and device behavior.
- USB reliability: safe setup/reconnect, no accidental replacement of an existing vault, honest save state, preserve recoverable changes on failed writes, safe disconnect and background behavior. Verify storage/session tests and physical USB acceptance steps.
- System integration: preserve password/passkey/OTP provider, service matching, extension entitlements, app icon; improve errors and search. Verify both targets and existing WebAuthn tests, then physical-device AutoFill acceptance.
- Delivery: GitHub Actions Rust tests, simulator build/tests, device build, unsigned IPA and checksum; report actual test evidence and any device-only limitations.

## Design direction

Retain ink #090A0E, panel #13151D, elevated #1D202A, violet #9978FF and mint #47E0B8. Native rounded headings and monospaced digits identify NoirVault without shrinking touch targets. Use a vault list for records, a dedicated authenticator surface for codes, and focused sheets for editing/generation. Align content left; center only empty states and unlock. Animation should acknowledge selection, reveal, save and code rollover; respect Reduce Motion.

## Findings from the starting code

OTP exists only as an optional login field; Save always requires content. No edit UI exists. Independent category/codes filters can contradict the All chip. Save mutates memory before disk success and clears the session on any error. Details reveal passwords immediately. The OTP copy path bypasses the security toggle. Settings promise resets but actually remain in the session. Any inactive scene locks, including system interruptions. The root tap gesture competes with controls. Pairing overwrites the marker without checking for an existing vault. Scanner permission failure reports an invalid secret.

## Progress

- Investigation complete; implementation and verification in progress.
- Implemented standalone authenticator records and indexing; editor with update/favorite/website/notes; separate authenticator browsing, search and sort; configurable generator; shared biometric/clipboard policy; persistent preferences and interruption cover.
- Added encrypted in-memory pending saves with reconnect retries and stale-envelope protection. Added existing-vault re-enrollment and non-overwriting creation. Unlock/setup derivation now runs off the main thread.
- First integrated run `35087785899` passed Rust tests, simulator compilation and XCTest; follow-up recovery/rendering run `35088393754` is in progress. Latest passkey corrections and polish still require CI.
- Added rendered screenshot attachments for vault browsing, authenticator editing/detail, generator, and large text. These are visual evidence, not substitutes for interaction/device tests.
- Found and corrected the pre-existing passkey COSE curve declaration (P-256 is curve 1, not 2); added encoded-key and signature-verification tests.
- No completion claim until the above requirements have corresponding evidence. Physical USB and signing-dependent provider behavior require device acceptance; simulator tests alone cannot establish them.

## References

- https://bitwarden.com/help/bitwarden-authenticator/ — independent authenticator entries, manual/QR creation and account labels.
- https://developer.apple.com/documentation/swiftui/scenephase/inactive — scene interruption behavior.
- https://www.w3.org/TR/webauthn-3/ — ES256/EC2 credentials use COSE curve 1 (P-256).
