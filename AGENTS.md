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
|`src/detect/ner/`|`NerDetector`: the on-device PII model (ONNX Runtime via `ort`, `tokenizers`); CPU session always, plus a DirectML GPU session in hybrid mode that takes large batches from the other end of the queue; `files.rs` (pinned model files, folder), `fetch.rs` (first-run download with `curl.exe` (resumes) and SHA-256 check with `certutil`), `labels.rs` (model labels -> `EntityKind`), `decode.rs` (token logits -> word spans), `gate.rs` (skips texts with nothing to find; per-text result cache)|
|`eval/`, `examples/pii_eval/`|quality benchmark: `fetch.py` (sampled public corpora), `handmade.py` (hand-labelled NL/EN/DE set), `labels.toml` (label mapping), `cargo run --release --example pii_eval`|
|`src/restore/`|streaming tolerant `Restorer`: exact, typo and component tiers over a session `Scope`|
|`src/proxy/`|format-preserving proxy generators, watermark|
|`src/vault/`|DPAPI-wrapped, encrypted append-only vault; `resolve(new, avoid)` never issues a proxy `avoid` turns down; `search`, `export` (JSON/CSV), and `forget`/`wipe`, the only rewrite path: it re-seals the kept records under a new vault id and swaps the file in through `<vault>.compact`, which `open` finishes after a crash and other processes notice by the changed id|
|`src/engine.rs`|anonymize/deanonymize over batches; `scan` detects without touching the vault (and ignores proxies the vault issued); `forget`/`wipe`; `Engine::plan` documents what a round trip promises (new proxies avoid the text that stays, text equal to an earlier listed proxy is masked, every proxy is found by exact lookup)|
|`src/formats/`|format sniffing, text/OOXML/ODF/PDF/image/eml/msg; one `Pass` carries either a rewrite (`process`) or a scan (`scan`) through every format|
|`src/ocr.rs`|Windows.Media.Ocr + Windows.Data.Pdf rendering|
|`src/sys.rs`|Windows plumbing shared by the CLI and the app: `data_dir()`, `write_atomic`, `system_command`/`run_system_tool` (System32 tools, no console window)|
|`src/policy.rs`|`Policy` (`guard.cfg`: sites, programs, kinds switched off, highlight mode, Explorer menu, inventory folders, HTTP API) and `SettingsPatch` for the API|
|`src/files.rs`|file jobs shared by the CLI, the API and the app: `collect`/`walk` (no symlinks), `transform`, `masked_copy_path`, `tolerant_restorer`|
|`src/inventory/`|PII inventory: per-file counts of what was found (never values) in `inventory.jsonl`, with `scan_paths` (skips unchanged files), `children` (the treemap's nodes) and `report`; `lock_scan` keeps two scans apart|
|`src/subject.rs`|subject search (DSAR): which files hold the given values, matched whole-word and by normalized detected values|
|`src/api/`|the one API: `Request` and its envelope, `Local` (the in-process handler), `http.rs` (loopback HTTP with a bearer token); the CLI is a client of it|
|`src/service.rs`|named-pipe server and client (`spawn`, `call`, `default_pipe`); framing `P`, 2, length, JSON|
|`src/cli.rs`, `src/cli/`, `src/main.rs`|command-line entry (`piikey-cli.exe`): one subcommand per API operation, so the CLI can offer nothing the API does not. `cli/parse.rs` turns the arguments (lexopt) into one `api::Request`, `cli/show.rs` prints the result as tables (an exhaustive match on the request picks the view); `cli.rs` makes paths absolute, asks the app's pipe, and answers in process with `api::Local` when nobody does (or with `--local`/`--vault`). Exit codes: 0 done, 1 `scan --fail-on` found personal data, 2 usage, 3 any API error|
|`tests/cli.rs`|`piikey-cli` as a process (arguments, stdin, exit codes, the pipe route through a `serve` child): every test has its own `LOCALAPPDATA` and `USERNAME`, so it never touches the user's vault, settings or a running app, and finds no model|
|`app/`|`piikey-app` (builds `piikey.exe`): local MITM proxy plus the Windows 11 app that controls it|
|`app/src/proxy/`|hudsucker proxy: decrypts only selected hosts/programs, anonymizes requests, restores responses; `events.rs` restores across SSE/NDJSON delta events (chatbot streams)|
|`app/src/capture.rs`|`piikey-capture` worker, the one UI Automation reader: while protection or highlighting is on, reads the focused text field (UI Automation: value or text pattern in one cached call per tick; the page's host from its document element; never a password field) and the clipboard, pushes the text to `proxy/typed.rs` only when protection is on and that element is in a protected site or program, and feeds the highlight overlay. A supervisor replaces a worker whose read hangs (a game in front made `GetFocusedElement` take 60 s) and makes the store blind meanwhile, so the proxy checks whole requests|
|`app/src/proxy/typed.rs`|`Typed`: what the user typed or pasted, as the detected values with their proxies; a request is searched for exactly those values (three spellings, whole word) instead of running detection over the whole body, which is the fallback when capture could not start|
|`app/src/ca.rs`, `ledger.rs`, `sysproxy.rs`|local CA (DPAPI key), per-host session ledger, Windows proxy on/off|
|`app/src/ui/`|WinUI 3 app: `controller.rs` (state machine on a worker thread, unit-tested; model download state, model load/release while protection, highlight or the inventory needs it; `sync_capture`/`sync_highlight` run capture and the shortcut while protection or the highlight needs them; Explorer scans and the inventory loop run on one scan thread fed by `scanner.rs`; `keyed()` serves the activity feed with its filters), `scanner.rs` (the scan thread's queue: scans somebody asked for first, the watched folders every hour, a request interrupts the background scan), `exports.rs` (vault and report CSV in Downloads, masked copy beside a file; nothing is overwritten), `explorer.rs` (opens or selects a path in Explorer), `window.rs` + `pages.rs` (Home with the inventory treemap, Keyed values feed with kind/site/time filters and Forget, Settings in seven tabs (`SettingsTab`: General has a card per feature that links to Masking, Inventory or API, then Detection, Vault and About), first-run loading screen; the window's tests mount it on the reactor's recording adapter, so every page and tab is reconciled and checked without WinUI), `treemap.rs` (squarified treemap layout), `activity.rs` (which stand-in went to which site when, persisted in `activity.cfg`; no originals), `assets.rs` (brand logos per theme, `.ico`), tray icon in `mod.rs` (the app stays in the tray while protection, the highlight, the inventory or the local API runs; `--scan` hands paths to the running app over the pipe), `ticker.rs` (`Application` has no cross-thread handle or timer, so with no window open nothing could wake the application thread: this timer, from windows-reactor's `test` feature, the only public way to the application thread's dispatcher, looks at `Controller::tray()` four times a second and sends `AppMessage::Sync` when the tray's state or the number of the latest scan that asks to be shown changed, so a finished Explorer scan opens the window and the tray follows the CLI/API), `instance.rs` (one app per user), `watchdog.rs` (restores the Windows proxy when the app dies; `--watchdog` / `--restore-proxy` modes)|
|`app/src/api.rs`|`AppApi`: serves the API over the pipe and HTTP; protection, settings, inventory and Explorer scans go through the controller, the rest to `Local`|
|`app/src/shell.rs`|registers/unregisters the Explorer "Scan for PII" verb under `HKCU\Software\Classes` (`--scan` / `--unregister-shell`)|
|`app/src/highlight.rs`|the live-highlight overlay: four click-through topmost bars (winit + softbuffer) around the focused field, and the Ctrl+Alt+P hotkey|
|`app/assets/`|`piikey.ico` (app icon at 16/20/24/32/40/48/64/256 px, generated by `assets/brand/make-icons.py`; embedded in both exes via `piikey.rc` + `build.rs` and in the app UI), `piikey.rc` (icon and version resource), `rc_macros.rs` (the version macros, `include!`d by both build scripts)|
|`assets/brand/`|`piikey-logo-kit/`: the full brand kit, kept verbatim (light `#6f49b1`, dark `#d6c9f9`; its README says which file to use); `make-icons.py` rebuilds `app/assets/piikey.ico` from it; `make-social-preview.py` rebuilds `social-preview.png` (GitHub social preview); `make-hero.py` rebuilds the README's before/after card `docs/assets/hero-{light,dark}.png` (its text is real `piikey-cli` output); `make-feature-icons.py` rebuilds the README's feature icons `docs/assets/icons/{light,dark}/*.svg`|
|`.cargo/config.toml`|`fmt-check` / `lint` aliases shared by hooks and CI|
|`.husky/`|git hooks: `pre-commit` (release guard, fmt, lint), `commit-msg` (commitlint), `pre-push` (no hand-pushed tags, tests)|
|`scripts/release-guard.mjs`|keeps versions, `CHANGELOG.md` and tags in release-plz's hands (modes `staged`, `pre-push`, `ci`)|
|`release-plz.toml`, `commitlint.config.mjs`|release automation (one shared version; the root package `piikey` carries `CHANGELOG.md`, the tag `vX.Y.Z` and the release) and commit message rules|
|`packaging/windows/`|`package.ps1` (release folder, zip, Inno Setup installer `piikey.iss`, `SHA256SUMS.txt`), `smoke.ps1` (CI-only install/uninstall check), `about.hbs` (third-party license page)|
|`deny.toml`, `about.toml`|cargo-deny (licenses, advisories, sources) and cargo-about (`THIRD_PARTY_LICENSES.html`) settings|
|`.github/`|workflows (`ci`, `codeql`: Actions on every push, Rust weekly, `release` = release-plz + `release-assets`), issue/PR templates, Dependabot, CODEOWNERS|
|`docs/`|`how-it-works.md` (detection, proxy and capture, highlight, inventory, API, devices, formats, crash safety), `assets/hero-*.png`, `assets/screenshots/` and `assets/icons/` (README images). The screenshots come from the debug app (`cargo build -p piikey-app`) on a private Windows desktop, so nothing shows on the user's screen and the Windows theme stays as it is: `PIIKEY_THEME` (`light` or `dark`) forces the theme and `PIIKEY_NO_TRAY` leaves out the tray icon (a desktop without a taskbar cannot add one); both are read in debug builds only|
