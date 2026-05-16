
# ColdVault

Version: 0.9.0-beta

A fully offline encrypted credential vault, built with Node.js and Blessed.

ColdVault combines:

- Password management
- TOTP/HOTP authentication
- Secure encrypted notes
- Clipboard integration
- Password breach checking
- otpauth:// import/export
- Terminal-first workflows

All wrapped inside a keyboard-driven TUI (Text User Interface).

---

# Features

## Encrypted Vault Storage

All vault data is encrypted at rest using modern authenticated encryption.

ColdVault uses:

- AES-256-GCM authenticated encryption
- Argon2id key derivation
- Per-vault random salts
- Per-encryption random IVs
- Authentication tags for tamper detection

The vault is never stored in plaintext once initialized.

The encrypted database contains metadata describing:

- encryption version
- cipher
- KDF settings
- authentication tag
- encrypted payload

Example envelope structure:

```json
{
  "encrypted": true,
  "version": 2,
  "kdf": "argon2id",
  "cipher": "aes-256-gcm",
  "argon2id": {
    "memoryCost": 65536,
    "timeCost": 3,
    "parallelism": 1,
    "hashLength": 32
  },
  "salt": "...",
  "iv": "...",
  "authTag": "...",
  "data": "..."
}
```

---

# Cryptography Details

## AES-256-GCM

ColdVault uses:

```text
AES-256-GCM
```

This provides:

- Strong confidentiality
- Integrity verification
- Tamper detection
- Authenticated encryption

If any encrypted data is modified, decryption fails safely.

---

## Argon2id Key Derivation

Your master password is never used directly as an encryption key.

Instead, ColdVault derives a secure encryption key using:

```text
Argon2id
```

Parameters:

```text
memoryCost = 65536
timeCost = 3
parallelism = 1
hashLength = 32
```

This helps protect against:

- brute force attacks
- GPU cracking
- rainbow tables

Each vault uses a unique random salt.

---

## Authentication Tags

AES-GCM generates authentication tags which detect:

- file corruption
- tampering
- invalid passwords

If verification fails:

- the vault will not decrypt
- corrupted data will not silently load

---

## Offline First

ColdVault is fully local.

No cloud syncing.
No telemetry.
No analytics.
No accounts.

Your vault remains entirely on your machine unless YOU choose to move it.

---

# Password Manager Features

## Account Storage

Store:

- usernames
- passwords
- URLs
- tags
- notes

Each account includes:

- timestamps
- unique IDs
- searchable metadata

---

## Password Generator

Generate strong random passwords using cryptographically secure randomness.

Generated passwords include:

- uppercase letters
- lowercase letters
- numbers
- symbols

Ambiguous characters are intentionally excluded where possible.

---

## Password Breach Checking

ColdVault integrates with Have I Been Pwned using the k-anonymity model.

Only the first 5 characters of a SHA-1 hash are sent.

Your actual password never leaves your machine.

This allows safe breach checking without exposing passwords.

---

# OTP Authenticator Features

Supports:

- TOTP
- HOTP

Compatible with:

- Google Authenticator
- Aegis
- Authy
- 2FAS
- Microsoft Authenticator
- Bitwarden
- most RFC-compatible OTP apps

---

## otpauth:// Support

Import:

```text
otpauth://
```

URIs directly.

Export OTP entries back into otpauth format for migration or backup.

---

## Supported Algorithms

- SHA1
- SHA256
- SHA512

---

## Custom OTP Settings

Per-entry support for:

- digits
- period
- counter
- algorithm

---

# Secure Notes

Store encrypted notes directly inside the vault.

Useful for:

- recovery codes
- API keys
- license keys
- SSH snippets
- private text

All notes are encrypted using the same vault encryption system.

---

# Auto Locking

ColdVault automatically locks itself after inactivity.

This helps protect against:

- unattended terminals
- accidental exposure
- shoulder surfing

The vault can also be manually locked at any time.

---

# Clipboard Integration

Quickly copy:

- passwords
- usernames
- URLs
- OTP codes

Supports:

- Windows
- macOS
- Linux

Linux clipboard support includes:

- wl-copy
- xclip
- xsel

---

# Crash Logging

Unhandled crashes are written to:

```text
ColdVault-crash.log
```

This helps with:

- debugging
- issue reporting
- troubleshooting

---

# Legacy Vault Migration

ColdVault can automatically import older:

- TOTP databases
- password databases
- notes databases

Legacy files are upgraded into the new encrypted unified vault format.

---

# Installation

## Requirements

- Node.js 18+
- npm

---

# Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ColdVault.git
cd ColdVault
```

---

# Install Dependencies

```bash
npm install
```

---

# Run the Application

```bash
node index.js
```

---

# Build Your Own Executable

ColdVault can also be packaged into a standalone executable using pkg.

Install pkg:

```bash
npm install -g pkg
```

Build:

```bash
npm run build
```

Example output:

- Windows EXE
- Linux binary
- macOS binary

---

## Recommended Build Platforms

For the best compatibility and reliability, it is strongly recommended to build ColdVault on the same operating system you intend to run it on.

Recommended:

- Build Windows binaries on Windows
- Build Linux binaries on Linux
- Build macOS binaries on macOS

ColdVault uses native cryptographic dependencies including:

```text
Argon2id
```

which may not package correctly when cross-compiling between operating systems.

While cross-platform builds can sometimes work, building directly on the target platform is the most reliable and supported approach.

Example:

```text
Windows target  → build on Windows
Linux target    → build on Linux
macOS target    → build on macOS
```

For the most reliable builds:

```bash
npm install
npm run build
```

should be executed directly on the target operating system.

---

# Download Prebuilt Releases

If you do not want to build manually, you can download the latest binaries from the repository Releases tab.

GitHub Releases include:

- Windows builds
- Linux builds
- macOS builds

---

# Data Storage

ColdVault stores all encrypted vault data locally using standard operating system application-data directories.

## Vault Database

### Windows
```text
%APPDATA%\IssyThePup\ColdVault\ColdVault.json
```

### Linux
```text
~/.config/IssyThePup/ColdVault/ColdVault.json
```

### macOS
```text
~/Library/Application Support/IssyThePup/ColdVault/ColdVault.json
```

## Crash Logs

### Windows
```text
%APPDATA%\IssyThePup\ColdVault\ColdVault-crash.log
```

### Linux
```text
~/.config/IssyThePup/ColdVault/ColdVault-crash.log
```

### macOS
```text
~/Library/Application Support/IssyThePup/ColdVault/ColdVault-crash.log
```

---

# Security Notes

## Important

If you forget your master password:

- your data cannot be recovered
- there are no backdoors
- there is no password reset system

This is intentional.

---

# Threat Model

ColdVault is designed to protect against:

- casual theft
- local data exposure
- stolen vault files
- password reuse risks
- accidental plaintext leaks

It is NOT intended to defend against:

- malware already running on your machine
- hardware keyloggers
- compromised operating systems

---

# Recommended Practices

- Use a strong master password
- Enable full disk encryption
- Keep backups
- Lock your terminal when away
- Avoid running untrusted software

---

# Dependencies

Main libraries used:

- argon2
- blessed
- otplib
- nanoid

---

# License

## MIT License

The MIT license is recommended for this project because it:

- is simple
- is developer friendly
- allows modification and redistribution
- encourages community contributions
- works well for open-source tooling

---
