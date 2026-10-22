# How piikey works

piikey finds personal data in text, replaces each value with a believable stand-in of the same
shape, and keeps the original↔stand-in pairs in an encrypted vault on your PC. When text comes back
with stand-ins in it, piikey swaps the originals back in.

## Detection

piikey first looks for personal data with validated regexes, which use checksums and context
keywords. An on-device detection model then finds what patterns cannot: a token classifier on the
CPU, with the GPU joining in through DirectML for large batches.

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

Each value is replaced with a believable format-preserving stand-in (the pattern types carry an
invisible keyed watermark). The original↔stand-in mapping is kept in an encrypted vault whose key is
protected by Windows DPAPI. Deanonymize swaps issued stand-ins back to their originals.

## Proxy and capture

`piikey.exe` puts piikey in front of the sites and apps you pick, for example chatbots. A local
proxy anonymizes what they receive and restores what they send back, including streamed replies, a
typo'd stand-in and a partial name mention.

While protection is on, piikey masks only what you type or paste into those sites and apps
(plus the files you upload there). It reads the focused text field through Windows UI Automation,
the interface screen readers use, and the clipboard when you paste, finds the personal data in that
text, and replaces exactly those values in what the page sends, so scripts, ids and telemetry are
left alone. Password fields are never read, nothing needs installing in the browser, and browsers
switch their accessibility support on when something asks for it, which costs them a little extra
work. If UI Automation is not available, piikey says so and checks whole requests instead.

Sites and apps that are not protected are tunnelled untouched. Apps must follow the Windows
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

The inventory records which files hold personal data. It scans only when somebody asks: the Scan
button on the Inventory page (which looks through your locations, the Documents, Desktop and
Downloads folders until you choose others), the box that adds one more folder or file, files and
folders dropped on the page, Explorer's menu, `explorer_scan`, `scan_files` and `inventory_rescan`
through the API and the CLI. Nothing scans on a timer. Scans run on one scan thread in a
half-sized thread pool, and a scan you asked for goes before whatever the watch has queued.

For each file, `inventory.jsonl` keeps its size, write time, a BLAKE3 fingerprint of its contents
and how many values of each type it holds, never the values. A scan is incremental. A file whose
size and write time are the ones stored is not read. A file that changed is read and fingerprinted;
when the fingerprint is the one stored (a sync client touched it, a save changed nothing) it is not
detected again, and only the new size, write time and scan time are kept. A file that failed
before, with no write time on record, is never trusted. Records from before the fingerprint
existed load fine and get one the next time the file changes. The scan treats a file piikey masked
as clean. The fingerprint is stored in the file but is never shown in the API, the CLI or a report.

The Inventory page shows the result as a dashboard, like a disk-usage viewer. A tree of folders and
files has a bar by type on each row; a legend lists the types found (a chip row in a narrow window,
a list in a wide one) and picking one shows only that type; a treemap has a tile for every file,
coloured by type (up to 400 tiles, the rest one "+N files" tile); and a details pane describes
what is selected. Selecting a tile opens the tree along the way to its file. For a file the details
can open it, show it in Explorer, show what was found, make a masked copy (beside the file; it
never replaces an existing file) or scan it again; for a folder
they can show only that folder, show it in Explorer or scan it. "Show what was found" runs
detection on that one file when asked and lists its values (at most 200) in a dialog: they are read
from the file at that moment and never stored. The inventory has no exclusions and no switch: what
is in it is what was scanned.

A scan started from the page, the box, a drop or Explorer opens a result dialog in the window
(scanning, then how much was found, with "Show in Inventory" when anything was). A newer scan
replaces an older dialog, and a window the user opens does not replay old results.

"Scan for personal data" in Explorer's right-click menu (under "Show more options" on Windows 11;
the General setting "Scan for personal data in Explorer" adds or removes it) starts
`piikey.exe --scan <path>`. It hands the paths to the running app, which scans them into the
inventory and shows the result dialog, bringing its window forward also when the app was only a
tray icon (a timer on the application thread looks four times a second); if the app is not
running, the command starts it.

## Watch

The Watch is a separate feature with its own switch, its own folders (`watch_folder` in
`guard.cfg`, none by default) and its own store, `watch.jsonl`, in the inventory's format but with
its own locks (`watch.lock`, `watch.save.lock`). It shares nothing with the inventory: what it
finds never appears there, and what the inventory scans never appears here.

While it is on, Windows reports changes in the watched folders (through the `notify` crate, because
the Windows call takes `unsafe` and the project's own code forbids it). Saving one document is a
dozen reports, so each path has to settle first: a path is looked at once it has been quiet for
two seconds, and one that never goes quiet (a log) at most every 30 seconds. Only the settled paths
are scanned, through the same incremental rule as the inventory, in the same pool and on the same
scan thread, behind any scan you asked for (a running watch scan is stopped and resumed). When 64
or more paths settle at once, or Windows says it may have lost reports, everything in the folders
is looked at, which still reads only what changed. Switching the watch on, adding a folder and
starting the app catch up the same way, because a folder is not watched while the app is not
running. Turning the watch off keeps what it found; removing a folder forgets that folder's
entries. The Watch page shows each folder as watching, scanning, not watched (the watch is off)
or not available, with the time of its last change, above the same dashboard as the inventory.

## API

The CLI, the app and scripts all use one JSON API. The app serves it on the named pipe
`\\.\pipe\piikey-<user>` (requests are `P`, 2, a length and the JSON) and, when you switch it on,
on `http://127.0.0.1:<port>/v1/<op>` with a bearer token that refuses browser origins.
`piikey-cli` calls the app's pipe when it answers and otherwise does the same work in its own
process. The operations, their results and the error codes are in the
[README](../README.md#api).

## Vault management

You can search the vault, export it (JSON or CSV), forget values and wipe it. In the app, tick
values on the Vault page (or Select all) and choose Forget, which asks before it does; the app has
no wipe, but the API (`vault_wipe`) and the CLI (`vault wipe --yes`) do. Forget and wipe
rewrite the vault file: the kept records are sealed again under a new vault id and the new file
replaces the old one through `vault.pkv.compact`, so a forgotten value is gone from disk and a crash
in between is completed at the next open or write. The app clears its typed-value cache afterwards. A second
process notices the new id and reloads.

## The app

One window with a navigation pane and six pages, a tray icon, and a controller behind both. The
pane has Overview, Protection, Inventory, Watch and Vault, Settings at its foot, and a status chip
under it that is a button to Overview.

- **Overview**: the status hero (a title, one sentence, and the one Turn on / Turn off button, which
  says why when it is unavailable; it is the only master switch in the window), at most one
  attention block with its single fix button, six clickable rows (Masking, Highlighting, Inventory,
  Watch, Vault, Detection, each with its own state and no switches) and the five most recent swaps
  with a link to the Vault.
- **Protection**: the highlighting mode, the protected sites and the protected apps. It has no
  switch of its own and no certificate section: turning masking on is the Overview button (and the
  tray menu), and installing the certificate is the fix button of Overview's attention block.
- **Inventory**: the Scan button, Export report, the locations (the folders the button looks
  through, as rows like Watch's folders: what each holds and a Remove button), the box that adds a
  folder or file and scans it, a status line (progress or what the inventory holds) and the
  dashboard described under Inventory and Explorer above. Files and folders dropped on the page are
  scanned.
- **Watch**: its switch, the folder list with each folder's state and a Remove button, the box that
  adds a folder (or "Watch Documents, Desktop and Downloads" when the list is empty), a status line
  and the same dashboard over the watch's store.
- **Vault**: an activity feed of every value in the vault next to its stand-in, the most recently
  sent first (including values first stored long ago), then the ones never sent. Search matches
  values, stand-ins, sites and apps; filters narrow it to a type, a site (subdomains included) or a
  time (today, last 7 days, last 30 days). Every row has a check box; Select all ticks the listed
  rows and Forget N removes the ticked ones after a confirmation. Export writes every value to a CSV
  file in Downloads. The feed persists in `%LOCALAPPDATA%\piikey\activity.cfg`, which holds
  stand-ins, sites, apps and times only; the values themselves stay in the encrypted vault.
  Forgetting a value also removes its lines from the feed.
- **Settings**: one scrolling page with five sections. General has Start piikey when I sign in,
  Scan for personal data in Explorer (the right-click menu entry) and Keep piikey running in the
  tray when I close the window. Types of personal data has a switch for every type, all on by
  default; a value masked earlier still comes back after its type is switched off, and the setting
  applies to masking, the highlight, scans and the inventory. When the detection model was skipped
  or failed, a row above the types says so and has a button to download it or try again; a model
  that is there needs no row. Developer access has the local HTTP API switch, its address and
  whether it listens, and the token (copy it or make a new one). Privacy & data shows the data
  folder, with Open folder, and links to the Vault and the Inventory. About has the version, the
  state of the local proxy and links to the source, the issue tracker and the license.

### Status

What protection is doing is one status, derived from the controller's snapshot (and the window's
optimistic wish while a command runs) in `app/src/ui/status.rs`. The hero, the chip under the pane,
the tray's tooltip, the header of the tray menu and the tray icon all render it, so they cannot
disagree:

| Status | Title | When |
|---|---|---|
| Off | Protection is off | Nothing runs; the sentence says so, and the hero's button says why it is unavailable while the certificate is missing |
| Busy | Starting / Stopping protection, Installing the certificate | A command is running |
| On | Protection is on | Masking runs, with the number of protected sites and apps and the latest swap |
| Needs attention | Protection is on, but needs attention / Protection needs attention | The certificate is missing, the model failed to download or an action failed |
| Downloading | Downloading the detection model | The first-run download is running |

The certificate is the one cause that a single click fixes, so it wins over an error it may be
behind.

### Tray and lifecycle

The tray icon is the key in grey while protection is off or the model downloads, the app icon while
it is on, and the app icon with an amber dot when it needs you. Its tooltip is the status in a
line, and its menu is the status as a header, Open piikey, Turn protection on or off, and Quit
piikey.

Closing the window leaves the app running in the tray when "Keep piikey running in the tray when I
close the window" is on, which is the default (`background` in `guard.cfg`): protection, the
highlight, the watch and the API keep working with the window closed. With it off, closing the
window quits piikey, as Quit piikey (tray) does either way; both give Windows its previous proxy
settings back.

Only one copy runs per Windows user. A second start of `piikey.exe` finds the running app over its
named pipe and asks it (`show_window`) to bring its window forward, then ends quietly;
`piikey-cli open` asks the same. If the first app is still opening its pipe, the second start asks
again for up to five seconds.

**Start at sign-in** is the General setting "Start piikey when I sign in". The zip and the
installer keep a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` that starts
`piikey.exe --background`; the setting counts as on only while that value starts this exe and
Windows has not been told (Settings > Apps > Startup) to skip it. The Microsoft Store build cannot
use the registry, so its manifest declares a startup task (`piikeyStartup`, off at install) that
the setting asks Windows to switch on; Windows refuses when the user turned it off in Settings >
Apps > Startup or a policy forbids it, and the setting says so. A startup task passes no
arguments, so the app tells such a start from the user's by the way Windows activated it. A
background start shows no window, only the tray icon (it shows the window anyway when there is no
tray icon to open it from), and when an app already runs, a background start leaves its window
alone. The uninstaller removes the `Run` and its skip entry.

## Model and devices

The app loads the model while protection is on, highlighting is on, the watch has folders to watch,
a scan is running or the findings of a file are being read, and
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
| `guard.cfg` | protected sites and apps, types switched off, on/off, the highlight mode, the Explorer menu, whether closing the window keeps piikey in the tray, the inventory locations, the watch switch and folders, and the HTTP API |
| `activity.cfg` | the activity feed (stand-ins only) |
| `inventory.jsonl` | per scanned file: size, write time, a fingerprint of the contents and how many values of each type it holds, never the values |
| `watch.jsonl` | the same for the files the watch looked at, with `watch.lock` and `watch.save.lock` beside it (the inventory has `inventory.lock` and `inventory.save.lock`) |
| `api.token` | the token the local HTTP API asks for |
| `ca.crt`, `ca.key` | the local certificate; the key is wrapped with DPAPI |
| `proxy.prev` | the previous Windows proxy settings, only while piikey has them changed |

The Microsoft Store build keeps all of this in the same folder, so `piikey-cli` from the zip or the
installer sees the same vault: the package declares the folder, and the registry keys and the
certificate store piikey changes on purpose (the Windows proxy, the sign-in entry, the certificate
and the Explorer menu), as ones Windows leaves out of the package's private copy. Removing the
package leaves the folder, the certificate and the Explorer menu behind:
[what an uninstall leaves](../packaging/windows/msix/CERTIFICATION.md#what-an-uninstall-leaves).
