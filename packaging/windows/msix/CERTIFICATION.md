# piikey in the Microsoft Store: certification notes

For whoever submits piikey to the Microsoft Store. The two sections called "Paste" go into
Partner Center as they are. The rest is for the person who submits.

## Before you submit

1. In Partner Center, reserve the name and open *Product management > Product identity*. Copy
   three values into the repository variables (Settings > Secrets and variables > Actions >
   Variables): `STORE_IDENTITY_NAME` (Package/Identity/Name), `STORE_PUBLISHER`
   (Package/Identity/Publisher, the `CN=...` line) and `STORE_PUBLISHER_DISPLAY_NAME`
   (Package/Properties/PublisherDisplayName). With all three set, the `release-assets` workflow
   builds the package with the identity of the listing. The name in the package is `piikey`
   (`AppxManifest.xml`, `DisplayName`): it must be the name you reserved.
2. Run `release-assets` (a release does, or run it by hand) and download the workflow artifact
   `piikey-<version>-msix`. Its `piikey-<version>-x64.msix` is unsigned on purpose and is the file
   to upload: the Store signs it. The package version is the release version with a fourth number
   0 (1.0.0 is 1.0.0.0); the Store keeps the fourth number for itself and takes no package whose
   first number is 0. Later packages must be higher, as releases are. The run
   installed a signed copy on a Windows runner, started it and removed it again before the
   artifact was uploaded.
3. Partner Center asks for a privacy policy URL for a desktop app (Store policy 10.5.1). Point it
   at a page that says what "Local-only processing" says below.
4. Under *Submission options > Restricted capabilities* paste the second section. Put the first one
   in *Notes for certification*.

## Paste: notes for certification

piikey is a local PII manager for Windows: it finds personal data (names, e-mail addresses, IBANs,
national ids, card numbers) in what the user types, sends and stores, and masks it. It needs no
account and shows no ads. It runs fully on the user's PC.

**How to test it.** Start piikey from the Start menu. On first start it downloads its detection
model (about 343 MB, from huggingface.co, checked against a SHA-256 hash it carries) to
`%LOCALAPPDATA%\piikey\models`; Home and the settings work before that. Masking (protection) is
off at first start, and so is everything that changes Windows, except the Explorer menu entry
described below.

- *Scan files*: in Explorer right-click a file or folder, then "Scan for PII" (Windows 11: under
  "Show more options"). piikey shows how much personal data it found, never the values.
- *Command line*: open a terminal and run `piikey-cli --version`, `piikey-cli --help` or
  `echo "Mail jan.jansen@example.com" | piikey-cli anonymize --local`.
- *Masking*: in Settings > Masking install the local certificate: Windows asks once whether to
  trust it (see below); accept to test it. Pick a site there, turn protection on at Home and type
  personal data into the site: it receives stand-ins and the page shows the real values again.
  Turn protection off (or Exit in the tray menu) and Windows has its previous proxy settings back.

**Local-only processing.** Detection, masking and restoring run on the device. The vault (the
pairs of real value and stand-in) is encrypted with a key that only the Windows user can unwrap
(DPAPI). piikey makes one network connection of its own, the model download above; it has no
telemetry, no account and no update check of its own. When protection is on, piikey is a local
proxy on 127.0.0.1 (loopback only). It passes the traffic the user has pointed at it to the sites
the user picked, with the personal data replaced, and reads the answer back. It reads the text
field that has focus through UI Automation for two features only: the highlight, which the user
can switch off, run on a hotkey or let run always (Settings > General), and masking of the sites
and programs the user protects. It never reads a password field and keeps nothing of what it reads
except the values it masks, which go into the encrypted vault.

**Root certificate.** Reading HTTPS traffic of the sites the user picks needs a certificate that
the clients of those sites trust. piikey makes its own ("piikey Guard CA") on the user's PC, with
a key that is wrapped with DPAPI for that Windows user and never leaves the PC, and adds it to the
user's own Root store (`certutil -user -addstore Root`), not the machine's, only when the user
asks for it in Settings > Masking (turning protection on without it says so and stops): Windows
shows its standard consent prompt, and the user can decline. It is used only for the sites and
programs the user selected; every other connection passes through untouched.

**What it changes outside its package, and why**: see the restricted capabilities text, which
lists every registry key and folder. Everything is per user; nothing needs administrator rights,
and there is no service, driver or scheduled task. piikey does not start with Windows; the one
`RunOnce` entry below exists only while protection is on and runs once, at the next sign-in.

**Dependencies.** The package depends on `Microsoft.VCLibs.140.00.UWPDesktop` (the Store installs
it). The Windows App SDK runtime is part of the package.

## Paste: restricted capabilities

**runFullTrust**: piikey is a desktop app (WinUI 3 and Win32). It runs a local proxy, changes the
Windows proxy settings the user switches on, reads the focused text field of other programs through
UI Automation, keeps a tray icon and a global hotkey, and scans the files the user chooses. None of
that works in an app container.

**unvirtualizedResources**: piikey's purpose is to change things that other programs read, which
the package's private copy of the registry and of AppData would hide from them. It declares exactly
these, and Windows keeps the rest of its writes private:

| Where | What piikey writes there | Why other programs must see it |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` | `ProxyEnable`, `ProxyServer`, `ProxyOverride` | The Windows (WinINET) proxy setting is where browsers and most programs look. Only while the user has protection on, it points at the local proxy `127.0.0.1:7979`; when it ends, piikey writes the user's previous values back exactly (they are saved in `%LOCALAPPDATA%\piikey\proxy.prev`) and never touches a proxy it did not set. |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | one value, `piikey proxy restore` | A safety net for a shutdown or sign-out that ends piikey while the proxy is on: Windows runs it once at the next sign-in, and it gives the proxy settings back. In this package it is a `cmd.exe` line that starts piikey's alias and, if the alias is gone because the package was removed, switches the proxy off. piikey deletes it when protection goes off. |
| `HKCU\Software\Microsoft\SystemCertificates\Root` | piikey's local certificate, with the user's consent | The user's Root store is where Windows, browsers and other programs read the trusted roots from. |
| `HKCU\Software\Classes\*\shell\piikey.scan`, `...\Directory\shell\piikey.scan`, `...\Directory\Background\shell\piikey.scan` | the Explorer verb "Scan for PII" (a classic registry verb; the user can switch it off under Settings > General) | Explorer, not piikey, reads these keys. They run piikey through its execution alias, because the folder of the package changes with every version and is closed to other programs. |
| `%LOCALAPPDATA%\piikey` (folder) | the encrypted vault, the settings, the local certificate and key, the downloaded model, the inventory | `piikey-cli.exe` exists in the package and as a download outside the Store; both must read the same vault, because a stand-in issued by one has to be restored by the other. The vault is also what lets the user restore earlier stand-ins after an update or a reinstall. |

Windows 10 has no such lists. There the package also states `RegistryWriteVirtualization` and
`FilesystemWriteVirtualization` as disabled, which switches virtualization of HKCU and AppData off
for the package (Windows 10 version 1903 and later is the minimum version of the package). On
Windows 11 Windows documents that the lists above take precedence over those two statements, so
the rest of piikey's writes stay in the private copy.

## What an uninstall leaves

Windows runs nothing of a package when it removes it. These stay, because the user's own data and
what other programs read are outside the package:

| Left behind | What it is | What the user can do |
|---|---|---|
| The Windows proxy | Only if protection was on when the package was removed. `ProxyEnable` stays 1 and `ProxyServer` stays `127.0.0.1:7979` until the next sign-in. Then the `RunOnce` entry (no piikey code) switches `ProxyEnable` off. The settings the user had before piikey stay in `proxy.prev` but are not put back. | Turn protection off (tray icon > Exit) before removing the package, or switch the proxy off in Settings > Network & internet > Proxy. |
| The local certificate | "piikey Guard CA" stays in the user's Root store, and its key (wrapped with DPAPI for the user) in `%LOCALAPPDATA%\piikey\ca.key`. The installer of the download version removes it at uninstall; the Store has no uninstall step. | `certutil -user -delstore Root "piikey Guard CA"`, or certmgr.msc > Trusted Root Certification Authorities > "piikey Guard CA". Deleting the data folder removes the key. |
| The Explorer verb | The three `piikey.scan` keys stay and point at an alias that no longer exists, so "Scan for PII" is still in the menu and does nothing. | Switch the Explorer menu off in Settings > General before removing the package, or remove the keys: `reg delete "HKCU\Software\Classes\*\shell\piikey.scan" /f`, the same for `Directory\shell` and `Directory\Background\shell`. |
| The data folder | `%LOCALAPPDATA%\piikey`: the vault (encrypted), settings, inventory (paths and counts, never values), the model (about 343 MB), the certificate and its key. It stays on purpose: the vault restores earlier stand-ins, and the installer of the download version shares the folder. | Delete the folder to remove everything piikey stored. |

Everything the package writes into its own private copy (Windows' per-package registry and AppData
files) is removed by Windows.
