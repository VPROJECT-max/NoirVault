# NoirVault

![NoirVault Banner](Readme.md%20assets/banner.png)

NoirVault is a high-security, memory-safe desktop password manager and TOTP authenticator. It prioritizes a keyboard-driven workflow, strictly RAM-only sensitive data handling, and hardware-bound encryption. Built natively in Rust and Slint, it compiles into a single, standalone executable that requires no installation and leaves zero footprint.

---

## ⚠️ Security Reality & Disclaimer

![Security Warning](Readme.md%20assets/security.png)

While this codebase utilizes strong, modern cryptographic primitives, we want to be completely transparent: **this is a side project**. 

If a bad actor has repeated physical access to your device (e.g., accessing it more than 5 times), it becomes incredibly easy to compromise your security. They do not need to break this code; they will break in through physical access vectors, hardware keyloggers, or memory scraping over time. 

Use this software responsibly and understand that ultimate security relies heavily on the physical security of your hardware.

---

## How to Use

![App Interface](Readme.md%20assets/interface.png)

NoirVault is designed to be 100% portable. You can install it on any standard USB flash drive and run it completely offline across both **Windows and Linux** environments.

1. **Launch**: Simply execute the `noirvault.exe` (or Linux binary) directly from your USB drive. No installation is required.
2. **Unlock**: Select your Keyfile from your filesystem and type in your Master Password to decrypt the vault into RAM.
3. **Navigate**: The app is heavily keyboard-driven. Press `Ctrl+K` to focus the search bar, use the `Up` and `Down` arrow keys to fly through your passwords, and hit `Enter` to instantly copy a password to your clipboard. For a full list, see our [Keyboard Shortcuts](Keyshorcuts.md) guide.
4. **Auto-Type**: Alternatively, use the Auto-Type button to have the vault directly inject your password into your browser, bypassing the clipboard entirely.

## How to Stay Safe
- **Protect your Physical Devices**: As mentioned in the disclaimer, physical access is the ultimate vulnerability. Never leave your unlocked vault unattended or your USB plugged into untrusted machines.
- **Keyfile Separation**: Never store your keyfile on the same physical drive as your `vault.dat` encrypted file. Keep them physically separated.
- **15-Second Rule**: The app will automatically wipe your clipboard 15 seconds after copying a password. Let it do its job, and do not manually paste sensitive data into persistent text editors.

---

## Interesting Techniques

![Code Architecture](Readme.md%20assets/architecture.png)

- **Memory-Safe Zeroization**: Cryptographic keys and plaintext passwords are held in custom buffers that automatically wipe themselves from RAM (using secure zeroization) the instant they fall out of scope, preventing memory-scraping attacks. 
- **Authenticated Encryption**: The vault data is secured using `XChaCha20Poly1305`, an [AEAD](https://developer.mozilla.org/en-US/docs/Glossary/AEAD) cipher that guarantees both the confidentiality and cryptographic integrity of your data.
- **Hardware Binding**: The encryption lifecycle integrates hardware fingerprinting, binding your encrypted vault to a specific host machine and automatically triggering silent backups when interacting with a trusted device.
- **Keystroke Injection**: The Auto-Type feature utilizes direct OS-level keystroke emulation to type your passwords into active windows, bypassing the system clipboard entirely to prevent clipboard-sniffing software from capturing your credentials.

## Technologies and Libraries
- **Slint**: A lightweight, high-performance declarative GUI toolkit that natively integrates with Rust and compiles the UI directly into the binary.
- **Argon2id**: The industry-standard memory-hard key derivation function used to convert the master password and salt into the primary cryptographic key.
- **totp-rs**: A library implementing RFC 6238 to generate Time-Based One-Time Passwords completely offline, calculating the live 6-digit codes directly from your system clock.
- **enigo**: A cross-platform library that handles the low-level API calls required to simulate physical keyboard input for the Auto-Type system.
- **winres**: A build-time dependency used to compile Windows Resource files, allowing us to permanently embed custom `.ico` logos directly into the executable header.

## Directory Structure
```text
.
├── src/
├── target/
└── ui/
    └── assets/
```
- `src/` - Contains the core Rust logic, handling cryptographic boundaries, state management, and memory protections.
- `target/` - The Rust compiler output directory where the final standalone `noirvault.exe` binary is generated.
- `ui/` - Houses the declarative `.slint` files that define the frontend architecture.
- `ui/assets/` - Contains the raw SVG vectors and PNG logos that are macro-injected into the compiled binary.

---

## License & Copyright

This project is fully Open Source. Anyone is free to read, use, modify, and distribute this codebase. 

However, if you choose to use this codebase, fork it, or use NoirVault as heavy inspiration for your own projects, we strictly require that you **tag us as the original inspiration and include our copyright notices** in your project's Terms of Service (ToS) or License files. 

This project is licensed under the standard MIT License, which legally mandates the inclusion of the original copyright notice in all substantial portions of the software.
