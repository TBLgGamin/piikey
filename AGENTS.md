# piikey: agent instructions

Pure backend in Rust, Windows-only. CPU parallelism through rayon.
A lightweight PII masker: validated-regex detection, format-preserving
watermarked proxies, DPAPI-protected vault, reversible deanonymization.

## Learn the stack before writing code

- Rust: read [The Rust Book](https://doc.rust-lang.org/book/) (offline: `rustup doc --book`).
- rayon: [docs.rs/rayon](https://docs.rs/rayon). `par_iter`, `par_chunks`, `rayon::join`.
- regex-automata: [docs.rs/regex-automata](https://docs.rs/regex-automata) (`meta::Regex`, multi-pattern).
- WinRT (`windows` crate) APIs churn: read `cargo doc` for the pinned version, never write them from memory.
  The same goes for `zip`, `quick-xml`, `lopdf`, `mail-parser`, `cfb`, `chacha20poly1305`, `uiautomation`.
- App (`app/`): `hudsucker` (MITM proxy), `windows-reactor` (WinUI 3), `sysproxy`, `netstat2`, `sysinfo`,
  `uiautomation` (UI Automation, wrapped safely: raw `windows` UIA calls are `unsafe`), `clipboard-win`.
  `windows-reactor` is pinned to a windows-rs git revision because the tray/`Application` API
  (`App::run_application`, `NotifyIcon`) is not in a crates.io release. Read its source under
  `~/.cargo/git/checkouts/windows-rs-*/<rev>/crates/libs/reactor` and the samples in
  `crates/samples/reactor`; the docs.rs pages describe the older release.

## Rules

- **Parallelize whenever possible.**
  - Data-parallel CPU work: rayon (`par_iter`, `par_chunks`, `rayon::join` for divide-and-conquer).
    Keep splits balanced; never hand-roll threads or locks for data-parallel work.
- `unsafe` is forbidden (`Cargo.toml` `[lints.rust]`).
- Library code returns `Result`; no `unwrap`/`expect`/`todo!`/`dbg!` (clippy rejects them).
- Clippy runs `pedantic` with `-D warnings`. Fix the code, do not `#[allow]` it,
  unless the lint is wrong for that line; then allow on the narrowest item with a comment why.
- `EntityKind` discriminants and the vault file layout are on-disk formats: never renumber or reorder.
- Every proxy generator must produce values its own detector finds again (see `proxy` tests).
- Detectors implement `detect::Detector` (`detect_batch` for batch-aware ones such as `NerDetector`).
- CI has no detection model: every test must pass without it; model tests are `#[ignore]` (`tests/ner_model.rs`).
- Keep dependencies minimal; justify every new crate.
- The exe's own path (`current_exe()`) is for the process itself. A path that another program is to run (the Explorer verb, the sign-in `RunOnce` entry) comes from `sys::launch_path()`: in the Microsoft Store (MSIX) build the folder of the exe changes with every version and Windows keeps it closed to other programs, so only the execution alias works.

## Commits, versions and releases

- Every commit message is a [Conventional Commit](https://www.conventionalcommits.org):
  `feat|fix|perf|refactor|docs|build|ci|chore|style|test|revert`, optional `(scope)`, `!` for breaking.
  The `commit-msg` hook (commitlint) and CI reject anything else. PRs are squash-merged, so a PR title is a commit message too.
- `feat` bumps the minor version, `fix`/`perf` the patch (also before 1.0: `features_always_increment_minor`).
- Never edit `version` in any `Cargo.toml`, never edit `CHANGELOG.md`, never create or push tags.
  The version lives only in the root `Cargo.toml` `[workspace.package]`; both packages inherit it.
  release-plz keeps a `chore: release vX.Y.Z` PR open; merging it tags `vX.Y.Z`, publishes the GitHub Release
  and builds the portable zip and installer. `scripts/release-guard.mjs` (pre-commit, pre-push, CI) refuses the rest.

## Before committing

```sh
cargo fmt              # format
cargo lint             # clippy, all targets, -D warnings (alias in .cargo/config.toml)
cargo test --all-targets
```

Husky runs `cargo fmt-check` + `cargo lint` on commit and `cargo test --all-targets` on push.
CI runs all three on Windows. Never bypass hooks with `--no-verify`.

## Layout

|Path|Purpose|
|---|---|
|`src/detect/`|`EntityKind`, `Detector` trait, `RegexDetector`, validators|
|`src/detect/issued.rs`|`IssuedProxies`: finds the proxies the vault issued, of every kind, by exact whole-word lookup (a few automata "levels", so a growing vault is not rebuilt each time); the engine restores with it, and masks text that reads like an earlier proxy of a listed kind. `Words`: whether a candidate proxy would read like text that stays|
|`src/detect/composite.rs`|`CompositeDetector`: runs several detectors over a batch, the earlier span wins on overlap; each later detector is told what the earlier ones kept (`taken`)|
|`src/detect/ner/`|`NerDetector`: the on-device PII model (ONNX Runtime via `ort`, `tokenizers`); CPU session always, plus a DirectML GPU session in hybrid mode that takes large batches from the other end of the queue; `session.rs` (the sessions, the model with its tokenizer, the CPU/hybrid choice in `device.cfg`), `chunks.rs` (texts cut into chunks, data blobs left out), `windows.rs` (token windows, padded batches, reading the logits), `queue.rs` (the queue CPU and GPU pull from at opposite ends), `files.rs` (pinned model files, folder), `fetch.rs` (first-run download with `curl.exe` (resumes) and SHA-256 check with `certutil`; only a real hash mismatch deletes a file), `labels.rs` (model labels -> `EntityKind`, one `TYPES` table), `decode.rs` (token logits -> word spans), `gate.rs` (skips texts with nothing to find; per-text result cache that keeps the first answer)|
|`eval/`, `examples/pii_eval/`|quality benchmark: `fetch.py` (sampled public corpora), `handmade.py` (hand-labelled NL/EN/DE set), `labels.toml` (label mapping), `cargo run --release --example pii_eval`|
|`src/restore/`|streaming tolerant `Restorer`: exact, typo and component tiers over a session `Scope`, plus a `ProxyFinder` (the vault's own lookup, `Engine`) merged into the same single pass (the `_with` methods), so restored text is never read again and a value equal to another proxy comes back once|
|`src/proxy/`|format-preserving proxy generators, watermark|
|`src/vault/`|DPAPI-wrapped, encrypted append-only vault; `resolve(new, avoid)` never issues a proxy `avoid` turns down; `search`, `export` (JSON/CSV), and `forget`/`wipe`, the only rewrite path: it re-seals the kept records under a new vault id and swaps the file in through `<vault>.compact`, which `open` and every later write finish after a crash and other processes notice by the changed id|
|`src/engine.rs`|anonymize/deanonymize over batches; `scan` detects without touching the vault (and ignores proxies the vault issued); `forget`/`wipe`; `Engine::plan` documents what a round trip promises (new proxies avoid the text that stays, text equal to an earlier listed proxy is masked, every proxy is found by exact lookup)|
|`src/formats/`|format sniffing, text/OOXML/ODF/PDF/image/eml/msg; one `Pass` carries a rewrite (`process`), a restore through a `Restorer` (`restore`: the tolerant tiers and every proxy of the vault in one pass over each text, so documents and mail get typo and lone-name tolerance too) or a scan (`scan`) through every format; OOXML packages embedded in a package (`*/embeddings/`) and `.msg` attachments that are messages go through the same pass one level deeper; `thumbnail.rs` blanks a rewritten package's preview picture|
|`src/ocr.rs`|Windows.Media.Ocr + Windows.Data.Pdf rendering|
|`src/sys.rs`|Windows plumbing shared by the CLI and the app: `data_dir()`, `write_atomic` (a temporary file of its own per call, so two processes never share one), `write_new` (never replaces a file), `try_lock`/`lock_within`/`FileLock`, `fill_random`, `dpapi_protect`/`dpapi_unprotect` (the vault key and the app's CA key), `is_under`/`same_path`/`path_key` (Windows path comparison), `system_dir`/`system_command`/`run_system_tool` (System32 tools, no console window), `is_packaged` (the process runs from the Microsoft Store MSIX package) and `launch_path` (what the Explorer verb and the sign-in `RunOnce` entry run to start the exe: the exe itself, or in the package its execution alias under `ALIAS_DIR`, because the package folder changes with every version and is closed to other programs)|
|`src/policy.rs`|`Policy` (`guard.cfg`: sites, programs, kinds switched off, highlight mode, Explorer menu, inventory folders, HTTP API) and `SettingsPatch` for the API|
|`src/files.rs`|file jobs shared by the CLI, the API and the app: `collect`/`walk` (no symlinks; inputs that overlap in another letter case list a file once), `transform` (results written atomically, never over an input; a tolerant deanonymize goes through `formats::restore`), `masked_copy_path`, `tolerant_restorer` (a `Restorer` scoped to every proxy of the vault)|
|`src/inventory/`|PII inventory: per-file counts of what was found (never values) in `inventory.jsonl`, with `scan_paths` (skips unchanged files; only unreadable input stays failed, anything else is retried), `children` (the treemap's nodes) and `report`; a save (and `forget_under`) takes `inventory.save.lock` and keeps what another process wrote since, so the CLI and the app can both write it; `lock_scan` keeps two scans apart|
|`src/subject.rs`|subject search (DSAR): which files hold the given values, matched whole-word and by normalized detected values|
|`src/api/`|the one API: `Request` and its envelope, `Local` (the in-process handler; settings come from an injected `PolicySource`, `Policy::load` by default), `reply.rs` (the typed result of every operation: `Local` writes it, the CLI reads it, the app overrides fields of it), `token.rs` (the HTTP API's bearer token), `http.rs` (loopback HTTP with a bearer token); `answer` runs one request off the server thread for both the pipe and HTTP; the CLI is a client of it|
|`src/service.rs`|named-pipe server and client (`spawn`, `call`, `default_pipe`, `ask`: the running app's answer or `None` when nobody listens); framing `P`, 2, length, JSON|
|`src/cli.rs`, `src/cli/`, `src/main.rs`|command-line entry (`piikey-cli.exe`): one subcommand per API operation, so the CLI can offer nothing the API does not. `cli/parse.rs` turns the arguments (lexopt) into one `api::Request`, `cli/show.rs` prints the result as tables (an exhaustive match on the request picks the view); `cli.rs` makes paths absolute, asks the app's pipe, and answers in process with `api::Local` when nobody does (or with `--local`/`--vault`). Exit codes: 0 done, 1 `scan --fail-on` found personal data, 2 usage, 3 any API error|
|`tests/cli.rs`|`piikey-cli` as a process (arguments, stdin, exit codes, the pipe route through a `serve` child): every test has its own `LOCALAPPDATA` and `USERNAME`, so it never touches the user's vault, settings or a running app, and finds no model|
|`app/`|`piikey-app` (builds `piikey.exe`): local MITM proxy plus the Windows 11 app that controls it|
|`app/src/proxy/`|hudsucker proxy: decrypts only selected hosts/programs, anonymizes requests, restores responses; `response.rs` restores each response (raw bytes, or the delta text of event streams) in one `Restorer` pass, scoped to what the ledger says was sent to the host and finding every proxy of the vault through `ProxyFinder`; `events.rs` restores across SSE/NDJSON delta events (chatbot streams)|
|`app/src/capture/`|`piikey-capture` worker, the one UI Automation reader: while protection or highlighting is on, reads the focused text field (UI Automation: value or text pattern in one cached call per tick; the page's host from its document element; never a password field, and a field that turns into one is judged again) and the clipboard (a copy another program still holds open is read again at a later look), pushes the text to `proxy/typed.rs` only when protection is on and that element is in a protected site or program, and feeds the highlight overlay. `uia.rs` is the Windows side; `watcher.rs` and `outline.rs` decide without Windows, over the traits in `desktop.rs` and `sink.rs` that `testing.rs` scripts. `supervisor.rs` replaces a worker whose read hangs (a game in front made `GetFocusedElement` take 60 s) or that never gets going, makes the store blind meanwhile so the proxy checks whole requests, and gives up when UI Automation does not come up within 10 s|
|`app/src/proxy/typed.rs`|`Typed`: what the user typed or pasted, as the detected values with their proxies; a request is searched for exactly those values (three spellings, whole word) instead of running detection over the whole body, which is the fallback when capture could not start|
|`app/src/ca.rs`, `ledger.rs`, `sysproxy.rs`|local CA (DPAPI key), per-host session ledger, Windows proxy on/off; in the Store build the sign-in `RunOnce` entry is a `cmd.exe` line that starts the alias and, when the alias is gone (package removed: nothing of it runs on removal), switches the proxy off itself, in at most 260 characters|
|`app/src/ui/`|WinUI 3 app: `controller/` (state machine on a worker thread, unit-tested in `controller/tests/`; `protection.rs` start/stop, `settings.rs`, `edit.rs` (one settings change), `model.rs` (download state, model load/release while protection, highlight or the inventory needs it), `keyed.rs` (the activity feed with its filters, pruned of values the vault forgot), `inventory.rs` (Explorer scans and the inventory loop on one scan thread fed by `scanner.rs`, in one shared half-the-cores pool, `in_scan_pool`); `sync_capture`/`sync_highlight` run capture and the shortcut while protection or the highlight needs them), `system.rs` (the real `Backend`), `scanner.rs` (the scan thread's queue: scans somebody asked for first, the watched folders every hour, a request interrupts the background scan), `exports.rs` (vault and report CSV in Downloads, masked copy beside a file; nothing is overwritten), `explorer.rs` (opens or selects a path in Explorer), `window.rs` + `pages/` (`home.rs` with the inventory treemap (`inventory/`: card, `map.rs` tiles, `panel.rs` side panel), `keyed.rs` feed with kind/site/time filters and Forget, `settings.rs` in seven tabs (`SettingsTab`: General has a card per feature that links to Masking, Inventory or API, then Detection, Vault and About), `lists.rs` list cards, `loading.rs` first-run screen; the window's tests mount it on the reactor's recording adapter, so every page and tab is reconciled and checked without WinUI), `treemap.rs` (squarified treemap layout), `activity.rs` (which stand-in went to which site when, persisted in `activity.cfg`; no originals), `assets.rs` (brand logos per theme, `.ico`), tray icon in `mod.rs` (the app stays in the tray while protection, the highlight, the inventory or the local API runs, and ends when its window closes without a tray icon; `--scan` hands paths to the running app over the pipe), `ticker.rs` (`Application` has no cross-thread handle or timer, so with no window open nothing could wake the application thread: this timer, from windows-reactor's `test` feature, the only public way to the application thread's dispatcher, looks at `Controller::tray()` four times a second and sends `AppMessage::Sync` when the tray's state or the number of the latest scan that asks to be shown changed, so a finished Explorer scan opens the window and the tray follows the CLI/API), `instance.rs` (one app per user), `watchdog.rs` (restores the Windows proxy when the app dies; `--watchdog` / `--restore-proxy` modes)|
|`app/src/api.rs`|`AppApi`: serves the API over the pipe and HTTP; protection, settings, inventory and Explorer scans go through the controller, the rest to `Local` built with the app's live settings; answers with the `api::reply` types, and file operations run in the controller's scan pool|
|`app/src/shell.rs`|registers/unregisters the Explorer "Scan for PII" verb under `HKCU\Software\Classes` (`--scan` / `--unregister-shell`); the verb runs `sys::launch_path()` once for each selected item (the Store build has no readable icon in its alias: the verb's icon is the tray's `piikey.ico` in the data folder), and the folder background passes `%V\.` so a drive root survives the quoting|
|`app/src/main.rs`, `process.rs`|entry modes (`--scan`, `--watchdog`, `--restore-proxy`, `--unregister-shell`), `Res` and `Describe` (`.describe()` instead of `.map_err(\|e\| e.to_string())`); `process.rs` is the one `sysinfo` user: a program's exe name by pid and the running programs|
|`app/src/highlight.rs`|the live-highlight overlay: four click-through topmost bars (winit + softbuffer) around the focused field, and the Ctrl+Alt+P hotkey|
|`app/assets/`|`piikey.ico` (app icon at 16/20/24/32/40/48/64/256 px, generated by `assets/brand/make-icons.py`; embedded in both exes via `piikey.rc` + `build.rs` and in the app UI), `piikey.rc` (icon and version resource), `rc_macros.rs` (the version macros, `include!`d by both build scripts)|
|`assets/brand/`|`piikey-logo-kit/`: the full brand kit, kept verbatim (light `#6f49b1`, dark `#d6c9f9`; its README says which file to use); `make-icons.py` rebuilds `app/assets/piikey.ico` from it; `make-msix-assets.py` rebuilds the MSIX logos `packaging/windows/msix/Assets/*.png` (plated tile icons, and the key alone in lilac for dark and purple for light taskbars); `make-social-preview.py` rebuilds `social-preview.png` (GitHub social preview); `make-hero.py` rebuilds the README's before/after card `docs/assets/hero-{light,dark}.png` (its text is real `piikey-cli` output); `make-feature-icons.py` rebuilds the README's feature icons `docs/assets/icons/{light,dark}/*.svg`|
|`.cargo/config.toml`|`fmt-check` / `lint` aliases shared by hooks and CI|
|`.husky/`|git hooks: `pre-commit` (release guard, fmt, lint), `commit-msg` (commitlint), `pre-push` (no hand-pushed tags, tests)|
|`scripts/release-guard.mjs`|keeps versions, `CHANGELOG.md` and tags in release-plz's hands (modes `staged`, `pre-push`, `ci`)|
|`release-plz.toml`, `commitlint.config.mjs`|release automation (one shared version; the root package `piikey` carries `CHANGELOG.md`, the tag `vX.Y.Z` and the release) and commit message rules|
|`packaging/windows/`|`package.ps1` (release folder, zip, Inno Setup installer `piikey.iss`, `SHA256SUMS.txt`, and the MSIX through `package-msix.ps1`; `-SkipMsix`), `package-msix.ps1` (release folder + `msix/AppxManifest.xml` + `msix/Assets/` packed with `makeappx` into `dist\piikey-<version>-x64.msix`, unsigned, test identity `piikey.dev` unless given the Store identity; the package version is `x.y.z.0`, and a Store identity refuses `0.x` because the Store takes no first number 0), `msix/` (the manifest template, the committed logos, `CERTIFICATION.md`: what to paste into Partner Center), `smoke.ps1` (CI-only install/uninstall check), `smoke-msix.ps1` (CI-only: signs a copy with a throwaway certificate, installs it, starts it through its aliases, checks what reaches the real registry and the data folder, removes it), `about.hbs` (third-party license page)|
|`deny.toml`, `about.toml`|cargo-deny (licenses, advisories, sources) and cargo-about (`THIRD_PARTY_LICENSES.html`) settings|
|`.github/`|workflows (`ci`, `codeql`: Actions on every push, Rust weekly, `release` = release-plz + `release-assets`, which also builds the Store MSIX, smoke-tests a signed copy and uploads the unsigned one as an artifact), issue/PR templates, Dependabot, CODEOWNERS|
|`docs/`|`how-it-works.md` (detection, proxy and capture, highlight, inventory, API, devices, formats, crash safety), `assets/hero-*.png`, `assets/screenshots/` and `assets/icons/` (README images). The screenshots come from the debug app (`cargo build -p piikey-app`) on a private Windows desktop, so nothing shows on the user's screen and the Windows theme stays as it is: `PIIKEY_THEME` (`light` or `dark`) forces the theme and `PIIKEY_NO_TRAY` leaves out the tray icon (a desktop without a taskbar cannot add one); both are read in debug builds only|
