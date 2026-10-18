# piikey: agent instructions

Pure backend in Rust, Windows-only. CPU parallelism through rayon.
A lightweight PII masker: validated-regex detection, format-preserving
watermarked proxies, DPAPI-protected vault, reversible deanonymization.

## Learn the stack before writing code

- Rust: read [The Rust Book](https://doc.rust-lang.org/book/) (offline: `rustup doc --book`).
- rayon: [docs.rs/rayon](https://docs.rs/rayon). `par_iter`, `par_chunks`, `rayon::join`.
- regex-automata: [docs.rs/regex-automata](https://docs.rs/regex-automata) (`meta::Regex`, multi-pattern).
- WinRT (`windows` crate) APIs churn: read `cargo doc` for the pinned version, never write them from memory.
  The same goes for `zip`, `quick-xml`, `lopdf`, `mail-parser`, `cfb`, `chacha20poly1305`.

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
- New detectors (e.g. an ML model) implement `detect::Detector`.
- Keep dependencies minimal; justify every new crate.

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
|`src/proxy/`|format-preserving proxy generators, watermark|
|`src/vault/`|DPAPI-wrapped, encrypted append-only vault|
|`src/engine.rs`|anonymize/deanonymize over batches|
|`src/formats/`|format sniffing, text/OOXML/ODF/PDF/image/eml/msg|
|`src/ocr.rs`|Windows.Media.Ocr + Windows.Data.Pdf rendering|
|`src/service.rs`|named-pipe server + wire protocol|
|`src/cli.rs`, `src/main.rs`|command-line entry|
|`.cargo/config.toml`|`fmt-check` / `lint` aliases shared by hooks and CI|
|`.husky/`|git hooks|
