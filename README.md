# piikey

Lightweight, fast PII masker for Windows. It detects PII with validated
regexes (checksums, context keywords), replaces each value with a believable
format-preserving proxy carrying an invisible keyed watermark, and keeps the
original↔proxy mapping in an encrypted vault whose key is protected by Windows
DPAPI. Deanonymize swaps issued proxies back to their originals.

Detected: emails, phone numbers (international/NANP/NL/EU), IBAN (mod-97),
credit cards (Luhn), IPv4/IPv6, MAC, US SSN, NL BSN (11-proof), URL
credentials, API keys/JWTs.

Inputs: any text encoding, DOCX/XLSX/PPTX and ODF (rewritten in place), PDF,
images (Windows OCR) and .eml/.msg (anonymized text output).

## Usage

```sh
piikey anonymize   [--vault PATH] [--out DIR] [PATH...]   # stdin -> stdout without paths
piikey deanonymize [--vault PATH] [--out DIR] [PATH...]
piikey serve       [--vault PATH] [--pipe NAME]           # default \\.\pipe\piikey
```

The default vault is `%LOCALAPPDATA%\piikey\vault.pkv`, readable only by the
Windows user who created it.

## Setup

Requires [rustup](https://rustup.rs) (the toolchain in `rust-toolchain.toml`
installs on first use) and Node.js (only for the git hooks).

```sh
npm install        # installs husky and the git hooks
cargo build --release
```

## Checks

```sh
cargo fmt          # format
cargo lint         # clippy, -D warnings
cargo test --all-targets
```

Hooks: `pre-commit` runs format check + lint, `pre-push` runs tests.
Agent instructions: [AGENTS.md](AGENTS.md).
