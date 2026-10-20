# How piikey works

piikey finds personal data in text, replaces each value with a believable stand-in of the same
shape, and keeps the original↔stand-in pairs in an encrypted vault on your PC. When text comes back
with stand-ins in it, piikey swaps the originals back in.

## Detection

piikey first looks for PII with validated regexes, which use checksums and context keywords. An
on-device detection model then finds what patterns cannot: a token classifier on the CPU, with the
GPU joining in through DirectML for large batches.

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

Each value is replaced with a believable format-preserving stand-in (the pattern kinds carry an
invisible keyed watermark). The original↔stand-in mapping is kept in an encrypted vault whose key is
protected by Windows DPAPI. Deanonymize swaps issued stand-ins back to their originals.

## Proxy and capture

`piikey.exe` puts piikey in front of the sites and programs you pick, for example chatbots. A local
proxy anonymizes what they receive and restores what they send back, including streamed replies, a
typo'd stand-in and a partial name mention.

While protection is on, piikey masks only what you type or paste into those sites and programs
(plus the files you upload there). It reads the focused text field through Windows UI Automation,
the interface screen readers use, and the clipboard when you paste, finds the personal data in that
text, and replaces exactly those values in what the page sends, so scripts, ids and telemetry are
left alone. Password fields are never read, nothing needs installing in the browser, and browsers
switch their accessibility support on when something asks for it, which costs them a little extra
work. If UI Automation is not available, piikey says so and checks whole requests instead.

Sites and programs that are not protected are tunnelled untouched. Programs must follow the Windows
proxy settings: browsers, Electron, .NET and curl do. The local certificate piikey uses to read
protected HTTPS traffic is created for your Windows user only; Windows asks once before trusting it.

## The app

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
- **Settings**: sites and programs to protect, which kinds of personal data piikey masks (every
  kind has its own switch, all on by default; a value masked earlier still comes back after its
  kind is switched off), and the local certificate.

Closing the window while the app is on leaves it running in the tray; Exit (tray) turns it off and
gives Windows its previous proxy settings back.

## Model and devices

The app loads the model only while protection is on and frees it when it turns off. Small calls (a
chat message) run on the CPU; large ones (documents, many messages) are shared between the CPU and
the GPU, which work through the batch from both ends. The first load checks whether the GPU helps
on a large batch and remembers the answer (`hybrid` or `cpu`) in `device.cfg` next to the model;
delete it to measure again, or write `cpu` to keep the GPU out. Both executables need
`DirectML.dll` beside them (dev builds get it copied automatically).

## Formats

Inputs: any text encoding, DOCX/XLSX/PPTX and ODF (rewritten in place), PDF,
images (Windows OCR) and .eml/.msg (anonymized text output).

## Crash safety

Windows points at piikey's proxy only while the app runs. If the app crashes or is killed, a small
watchdog process (a second `piikey.exe`) gives Windows its previous proxy settings back at
once. If a shutdown or sign-out ends both, a `RunOnce` entry does it at the next sign-in. With
piikey saved as on, the next start resumes it. Only one copy runs per Windows user.

## Files

Everything piikey keeps is in `%LOCALAPPDATA%\piikey`, readable only by your Windows user:

| File | What |
|---|---|
| `vault.pkv` | the encrypted original↔stand-in pairs (XChaCha20-Poly1305, key wrapped with DPAPI) |
| `models\` | the downloaded detection model and `device.cfg` |
| `guard.cfg` | protected sites and programs, kinds switched off, on/off |
| `activity.cfg`, `stats.cfg` | the activity feed (stand-ins only) and daily counts |
| `ca.crt`, `ca.key` | the local certificate; the key is wrapped with DPAPI |
| `proxy.prev` | the previous Windows proxy settings, only while piikey has them changed |
