<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/piikey-logo-kit/horizontal/piikey-horizontal-mono-d6c9f9.svg">
  <img alt="piikey" src="assets/brand/piikey-logo-kit/horizontal/piikey-horizontal-mono-6f49b1.svg" height="72">
</picture>

Lightweight, fast PII masker for Windows. It detects PII with validated
regexes (checksums, context keywords) and then an on-device detection model
(token classifier on the CPU, joined by the GPU through DirectML for large batches) for what patterns
cannot find. It replaces each value with a believable format-preserving proxy
(the pattern kinds carry an invisible keyed watermark), and keeps the
original↔proxy mapping in an encrypted vault whose key is protected by Windows
DPAPI. Deanonymize swaps issued proxies back to their originals.

Regex: emails, phone numbers (international/NANP/NL/EU), IBAN (mod-97),
credit cards (Luhn), IPv4/IPv6, MAC, US SSN, NL BSN (11-proof), URL
credentials, API keys/JWTs.

Model ([`bardsai/eu-pii-anonimization-multilang-v2`](https://huggingface.co/bardsai/eu-pii-anonimization-multilang-v2),
Apache-2.0, INT8 ONNX, 24 EU languages, pinned revision): names, aliases,
addresses, places, coordinates, organizations, dates of birth, personal,
document, account, device and vehicle IDs, handles, links, passwords, amounts,
card codes and the GDPR special categories (health, biometric, ethnic origin,
political opinion, religion, sexual orientation, trade union, criminal record).
`piikey.exe` downloads it (about 343 MB, SHA-256 checked) to
`%LOCALAPPDATA%\piikey\models` on first start; the CLI uses it once it is
there and masks patterns only until then.

Inputs: any text encoding, DOCX/XLSX/PPTX and ODF (rewritten in place), PDF,
images (Windows OCR) and .eml/.msg (anonymized text output).

## Usage

The command-line tool is `piikey-cli.exe`:

```sh
piikey-cli anonymize   [--vault PATH] [--out DIR] [PATH...]   # stdin -> stdout without paths
piikey-cli deanonymize [--vault PATH] [--out DIR] [PATH...]
piikey-cli serve       [--vault PATH] [--pipe NAME]           # default \\.\pipe\piikey
```

The default vault is `%LOCALAPPDATA%\piikey\vault.pkv`, readable only by the
Windows user who created it.

The app loads the model only while protection is on and frees it when it turns off. Small calls (a
chat message) run on the CPU; large ones (documents, many messages) are shared between the CPU and
the GPU, which work through the batch from both ends. The first load checks whether the GPU helps
on a large batch and remembers the answer (`hybrid` or `cpu`) in `device.cfg` next to the model;
delete it to measure again, or write `cpu` to keep the GPU out. Both executables need
`DirectML.dll` beside them (dev builds get it copied automatically).

`eval/` holds the quality benchmark (accuracy, leakage, round trip, speed); see `eval/README.md`.

## App

`piikey-app` (workspace member `app/`, builds `piikey.exe`) is a Windows 11 app that puts piikey in front of the sites
and programs you pick, for example chatbots. A local proxy anonymizes what they receive and restores
what they send back, including streamed replies, a typo'd proxy and a partial name mention.

While protection is on, piikey masks only what you type or paste into those sites and programs
(plus the files you upload there). It reads the focused text field through Windows UI Automation,
the interface screen readers use, and the clipboard when you paste, finds the personal data in that
text, and replaces exactly those values in what the page sends, so scripts, ids and telemetry are
left alone. Password fields are never read, nothing needs installing in the browser, and browsers
switch their accessibility support on when something asks for it, which costs them a little extra
work. If UI Automation is not available, piikey says so and checks whole requests instead.

```sh
cargo run -p piikey-app --release   # first build downloads the Windows App SDK runtime (network)
```

- **Home**: the on/off switch, key numbers (values keyed, masked and restored today, protected
  sites and programs), a 14-day masked/restored chart, a by-kind chart and recent activity: the
  values most recently sent, with where and when. Daily counts persist in
  `%LOCALAPPDATA%\piikey\stats.cfg`.
- **Keyed values**: an activity feed of every value in the vault next to its stand-in, the most
  recently sent first (including values first keyed long ago), then the ones never sent. Search
  matches values, stand-ins, sites and programs; filters narrow it to a kind, a site (subdomains
  included) or a time (today, last 7 days, last 30 days). The feed persists in
  `%LOCALAPPDATA%\piikey\activity.cfg`, which holds stand-ins, sites, programs and times only;
  the values themselves stay in the encrypted vault.
- **Settings**: sites and programs to protect (everything else is tunnelled untouched; programs
  must follow the Windows proxy settings: browsers, Electron, .NET, curl), which kinds of personal
  data piikey masks (every kind has its own switch, all on by default; a value masked earlier still
  comes back after its kind is switched off), and the local certificate (Windows asks once).

Closing the window while the app is on leaves it running in the tray; Exit (tray) turns it off and
gives Windows its previous proxy settings back.

Windows points at piikey's proxy only while the app runs. If the app crashes or is killed, a small
watchdog process (a second `piikey.exe`) gives Windows its previous proxy settings back at
once. If a shutdown or sign-out ends both, a `RunOnce` entry does it at the next sign-in. With
piikey saved as on, the next start resumes it. Only one copy runs per Windows user.

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
