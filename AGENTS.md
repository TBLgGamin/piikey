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
|`src/detect/ner/`|`NerDetector`: the on-device PII model (ONNX Runtime via `ort`, `tokenizers`); CPU session always, plus a DirectML GPU session in hybrid mode that takes large batches from the other end of the queue; `files.rs` (pinned model files, folder), `labels.rs` (model labels -> `EntityKind`), `decode.rs` (token logits -> word spans), `gate.rs` (skips texts with nothing to find; per-text result cache)|
|`eval/`, `examples/pii_eval/`|quality benchmark: `fetch.py` (sampled public corpora), `handmade.py` (hand-labelled NL/EN/DE set), `labels.toml` (label mapping), `cargo run --release --example pii_eval`|
|`src/restore/`|streaming tolerant `Restorer`: exact, typo and component tiers over a session `Scope`|
|`src/proxy/`|format-preserving proxy generators, watermark|
|`src/vault/`|DPAPI-wrapped, encrypted append-only vault; `resolve(new, avoid)` never issues a proxy `avoid` turns down|
|`src/engine.rs`|anonymize/deanonymize over batches; `Engine::plan` documents what a round trip promises (new proxies avoid the text that stays, text equal to an earlier listed proxy is masked, every proxy is found by exact lookup)|
|`src/formats/`|format sniffing, text/OOXML/ODF/PDF/image/eml/msg|
|`src/ocr.rs`|Windows.Media.Ocr + Windows.Data.Pdf rendering|
|`src/service.rs`|named-pipe server + wire protocol|
|`src/cli.rs`, `src/main.rs`|command-line entry (`piikey-cli.exe`)|
|`app/`|`piikey-app` (builds `piikey.exe`): local MITM proxy plus the Windows 11 app that controls it|
|`app/src/proxy/`|hudsucker proxy: decrypts only selected hosts/programs, anonymizes requests, restores responses; `events.rs` restores across SSE/NDJSON delta events (chatbot streams)|
|`app/src/capture.rs`|`piikey-capture` worker: while protection is on, reads the focused text field (UI Automation: value or text pattern in one cached call per tick; the page's host from its document element; never a password field) and the clipboard, only when that element is in a protected site or program, and pushes the text to `proxy/typed.rs`. A supervisor replaces a worker whose read hangs (a game in front made `GetFocusedElement` take 60 s) and makes the store blind meanwhile, so the proxy checks whole requests|
|`app/src/proxy/typed.rs`|`Typed`: what the user typed or pasted, as the detected values with their proxies; a request is searched for exactly those values (three spellings, whole word) instead of running detection over the whole body, which is the fallback when capture could not start|
|`app/src/ca.rs`, `policy.rs`, `ledger.rs`, `sysproxy.rs`|local CA (DPAPI key), saved settings (sites, programs, kinds switched off), per-host session ledger, Windows proxy on/off|
|`app/src/ui/`|WinUI 3 app: `controller.rs` (state machine on a worker thread, unit-tested; model download state, model load/release with protection; `keyed()` serves the activity feed with its filters), `window.rs` + `pages.rs` (Home, Keyed values feed with kind/site/time filters, Settings with per-kind switches, first-run loading screen), `activity.rs` (which stand-in went to which site when, persisted in `activity.cfg`; no originals), `stats.rs` (daily counts for the Home chart), `assets.rs` (brand logos per theme, `.ico`), tray icon in `mod.rs`, `instance.rs` (one app per user), `watchdog.rs` (restores the Windows proxy when the app dies; `--watchdog` / `--restore-proxy` modes)|
|`app/src/model.rs`|first-run model download with `curl.exe` (resumes) and SHA-256 check with `certutil`|
|`app/assets/`|`piikey.ico` (app icon at 16/20/24/32/40/48/64/256 px, generated by `assets/brand/make-icons.py`; embedded in both exes via `piikey.rc` + `build.rs` and in the app UI), `piikey.rc` (icon and version resource), `rc_macros.rs` (the version macros, `include!`d by both build scripts)|
|`assets/brand/`|`piikey-logo-kit/`: the full brand kit, kept verbatim (light `#6f49b1`, dark `#d6c9f9`; its README says which file to use); `make-icons.py` rebuilds `app/assets/piikey.ico` from it; `make-social-preview.py` rebuilds `social-preview.png` (GitHub social preview); `make-hero.py` rebuilds the README's before/after card `docs/assets/hero-{light,dark}.png` (its text is real `piikey-cli` output)|
|`.cargo/config.toml`|`fmt-check` / `lint` aliases shared by hooks and CI|
|`.husky/`|git hooks: `pre-commit` (release guard, fmt, lint), `commit-msg` (commitlint), `pre-push` (no hand-pushed tags, tests)|
|`scripts/release-guard.mjs`|keeps versions, `CHANGELOG.md` and tags in release-plz's hands (modes `staged`, `pre-push`, `ci`)|
|`release-plz.toml`, `commitlint.config.mjs`|release automation (one shared version; the root package `piikey` carries `CHANGELOG.md`, the tag `vX.Y.Z` and the release) and commit message rules|
|`packaging/windows/`|`package.ps1` (release folder, zip, Inno Setup installer `piikey.iss`, `SHA256SUMS.txt`), `smoke.ps1` (CI-only install/uninstall check), `about.hbs` (third-party license page)|
|`deny.toml`, `about.toml`|cargo-deny (licenses, advisories, sources) and cargo-about (`THIRD_PARTY_LICENSES.html`) settings|
|`.github/`|workflows (`ci`, `codeql`, `scorecard`, `release` = release-plz + `release-assets`), issue/PR templates, Dependabot, CODEOWNERS|
|`docs/`|`how-it-works.md` (detection, proxy and capture, devices, formats, crash safety), `assets/hero-*.png` and `assets/screenshots/` (README images)|
