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

## Highlight

With highlight on, the same UI Automation reader that feeds the proxy also checks the field you are
typing in, in any app. When it holds personal data, four thin bars in the theme's purple draw an
outline around the field. They are topmost windows that take no clicks and no focus. The mode is
`Off`, `Always` or `Hotkey`: with `Hotkey`, Ctrl+Alt+P checks the field once, and a field without
personal data gets a short green flash. In `Always`, Ctrl+Alt+P pauses and resumes the outline. The
check runs on your PC with the same detector as masking, even when protection is off, and nothing is
stored. Password fields are never read.

## Inventory and Explorer

The inventory records which files hold personal data. A background loop scans your folders (the
Documents, Desktop and Downloads folders unless you choose others) on a half-sized thread pool and
skips files that did not change since the last scan. For each file, `inventory.jsonl` keeps how many
values of each kind it holds, never the values, and the scan treats a file piikey masked as clean.
Home shows the result as a treemap: one tile per folder or file, sized by the number of values, and
clicking a folder opens it. A tile's side panel can open the file, show it in Explorer, rescan it,
make a masked copy (beside the file; it never replaces an existing file) or exclude it. A folder
excluded while a scan runs is dropped from the inventory when that scan ends.

"Scan for PII" in Explorer's right-click menu (under "Show more options" on Windows 11) starts
`piikey.exe --scan <path>`. It hands the paths to the running app, which scans them and, when the
scan ends, brings its window forward on Home at the scanned path, also when the app was only a
tray icon (a timer on the application thread looks four times a second); if the app is not
running, the command starts it.

## API

The CLI, the app and scripts all use one JSON API. The app serves it on the named pipe
`\\.\pipe\piikey-<user>` (requests are `P`, 2, a length and the JSON) and, when you switch it on,
on `http://127.0.0.1:<port>/v1/<op>` with a bearer token that refuses browser origins.
`piikey-cli` calls the app's pipe when it answers and otherwise does the same work in its own
process. The operations, their results and the error codes are in the
[README](../README.md#api).

## Vault management

You can search the vault, export it (JSON or CSV), forget values and wipe it. Forget and wipe
rewrite the vault file: the kept records are sealed again under a new vault id and the new file
replaces the old one through `vault.pkv.compact`, so a forgotten value is gone from disk and a crash
in between is completed at the next open or write. The app clears its typed-value cache afterwards. A second
process notices the new id and reloads.

## The app

- **Home**: the on/off switch, key numbers (values keyed, files with personal data, values found in
  files, protected sites and programs), the inventory treemap and recent activity: the values most
  recently sent, with where and when. The treemap is described under Inventory and Explorer above.
- **Keyed values**: an activity feed of every value in the vault next to its stand-in, the most
  recently sent first (including values first keyed long ago), then the ones never sent. Search
  matches values, stand-ins, sites and programs; filters narrow it to a kind, a site (subdomains
  included) or a time (today, last 7 days, last 30 days). The feed persists in
  `%LOCALAPPDATA%\piikey\activity.cfg`, which holds stand-ins, sites, programs and times only;
  the values themselves stay in the encrypted vault. Forgetting a value or wiping the vault also
  removes its lines from the feed.
- **Settings**: seven tabs, picked in a bar under the title. The app opens on General and remembers
  the tab you chose until the window closes.
  - **General** has a card for each feature with its own control: masking (a switch; it stays off
    until the certificate is installed, and the card says so), the highlight (off, always, or when
    you press Ctrl+Alt+P), the Explorer menu, the inventory and the local HTTP API. A feature
    with more settings links to its tab.
  - **Masking**: the certificate, the sites and the programs to protect.
  - **Detection**: which kinds of personal data piikey looks for (every kind has its own switch,
    all on by default; a value masked earlier still comes back after its kind is switched off).
    It applies to masking, the highlight, scans and the inventory.
  - **Inventory**: the folders to scan, what is left out and Rescan now.
  - **API**: the pipe name, the HTTP address with whether it listens, and the token (copy it or
    make a new one).
  - **Vault**: where the vault file is, how many records it holds, Export (CSV in Downloads) and
    Wipe, which takes two clicks.
  - **About**: the version and the state of the local proxy.

Closing the window while the app is on leaves it running in the tray; Exit (tray) turns it off and
gives Windows its previous proxy settings back.

## Model and devices

The app loads the model while protection is on, highlighting is on or the inventory is on, and
frees it when none is. Small calls (a chat message) run on the CPU; large ones (documents, many
messages) are shared between the CPU and the GPU, which work through the batch from both ends. The
first load checks whether the GPU helps
on a large batch and remembers the answer (`hybrid` or `cpu`) in `device.cfg` next to the model;
delete it to measure again, or write `cpu` to keep the GPU out. Both executables need
`DirectML.dll` beside them (dev builds get it copied automatically).

## Formats

Inputs: any text encoding, DOCX/XLSX/PPTX and ODF (rewritten in place), PDF,
images (Windows OCR) and .eml/.msg (anonymized text output). A rewritten Office or ODF package
loses its preview picture, which could show the original text; Office packages embedded in it (a
chart's workbook, an embedded document) are rewritten too, and other pictures and binary objects
are copied through unchanged. A message attached to a .msg is read like the message itself.

## Crash safety

Windows points at piikey's proxy only while the app runs. If the app crashes or is killed, a small
watchdog process (a second `piikey.exe`, not a child of the app, so ending the app's process tree
leaves it running) gives Windows its previous proxy settings back at once, exactly as they were:
values you never had are removed again. If a shutdown or sign-out ends both, a `RunOnce` entry
does it at the next sign-in. With piikey saved as on, the next start resumes it. Only one copy runs
per Windows user.

Windows runs nothing of the Microsoft Store (MSIX) build when it removes the package, so a proxy
that was on would stay pointed at a port nobody listens on. In that build the `RunOnce` entry is a
`cmd.exe` line that starts piikey through its execution alias, as the entry of the other builds
starts the exe, and switches the proxy off itself when the alias is gone. The Explorer menu starts
piikey through the alias too: the folder of the package changes with every version and Windows
keeps it closed to other programs.

## Files

Everything piikey keeps is in `%LOCALAPPDATA%\piikey`, readable only by your Windows user:

| File | What |
|---|---|
| `vault.pkv` | the encrypted original↔stand-in pairs (XChaCha20-Poly1305, key wrapped with DPAPI) |
| `models\` | the downloaded detection model and `device.cfg` |
| `guard.cfg` | protected sites and programs, kinds switched off, on/off, the highlight mode, the Explorer menu, inventory folders and the HTTP API |
| `activity.cfg` | the activity feed (stand-ins only) |
| `inventory.jsonl` | per file: size, change time and how many values of each kind it holds, never the values |
| `api.token` | the token the local HTTP API asks for |
| `ca.crt`, `ca.key` | the local certificate; the key is wrapped with DPAPI |
| `proxy.prev` | the previous Windows proxy settings, only while piikey has them changed |

The Microsoft Store build keeps all of this in the same folder, so `piikey-cli` from the zip or the
installer sees the same vault: the package declares the folder, and the registry keys and the
certificate store piikey changes on purpose (the Windows proxy, the sign-in entry, the certificate
and the Explorer menu), as ones Windows leaves out of the package's private copy. Removing the
package leaves the folder, the certificate and the Explorer menu behind:
[what an uninstall leaves](../packaging/windows/msix/CERTIFICATION.md#what-an-uninstall-leaves).
