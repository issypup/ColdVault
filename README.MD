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

# Build Your Own Executable

ColdVault can also be packaged into a standalone executable using:

## [pkg](https://github.com/vercel/pkg)

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
