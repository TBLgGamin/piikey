# Contributing to piikey

Thanks for helping. By taking part you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Questions go to
[Issues](https://github.com/TBLgGamin/piikey/issues); Discussions are off.
Security problems do not go there: see [SECURITY.md](SECURITY.md).

## Setup

You need Windows 10 or 11, [rustup](https://rustup.rs) (the toolchain pinned
in `rust-toolchain.toml` installs on first use) and Node.js, which is only
used for the git hooks.

```sh
git clone https://github.com/TBLgGamin/piikey
cd piikey
npm install        # installs husky and the git hooks
cargo build --release --workspace
```

The first build of `piikey-app` downloads the Windows App SDK runtime, so it
needs network access.

## Checks

Run these before you push. The hooks and CI run them too.

```sh
cargo fmt-check
cargo lint
cargo test --all-targets
```

`cargo lint` is clippy with `-D warnings`. `unsafe` code is forbidden.

Tests that need the downloaded detection model are marked `#[ignore]`. Run
them with `cargo test --all-targets -- --ignored` after `piikey.exe` has
downloaded the model once.

## Commit messages

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org):
`type(scope): summary`, where the type is one of `feat`, `fix`, `perf`,
`refactor`, `docs`, `build`, `ci`, `chore`, `style`, `test` or `revert`. The
scope is optional and `!` marks a breaking change. The `commit-msg` hook
(commitlint) and CI reject anything else.

```text
feat(cli): add --version
fix(app): restore the proxy when the watchdog starts late
docs: explain the device setting
feat(vault)!: change the record format
```

## Pull requests

- Keep a pull request to one change and describe why it is needed.
- Pull requests are squash-merged. The pull request title becomes the commit
  message on `main`, so it must be a conventional commit too.
- Update the docs, and `AGENTS.md` when behavior or the layout changes.

## Releases

Releases are automated. Do not do any of this by hand:

- Never edit `version` in any `Cargo.toml`. The version lives only in
  `[workspace.package]` of the root `Cargo.toml`, and both packages use
  `version.workspace = true`.
- Never edit `CHANGELOG.md`.
- Never create or push tags.

[release-plz](https://release-plz.dev) reads the commit messages and keeps a
pull request titled `chore: release vX.Y.Z` open. `feat` bumps the minor
version (also before 1.0) and `fix` and `perf` bump the patch version. When the
maintainer merges that pull request, release-plz tags `vX.Y.Z`, publishes the
GitHub Release, and the same workflow run builds the portable zip and the
installer, `SHA256SUMS.txt` and a build-provenance attestation. Its last job
submits the new installer to winget (`TBLgGamin.piikey`) as a pull request to
`microsoft/winget-pkgs`, using the `WINGET_TOKEN` secret.

`scripts/release-guard.mjs` (run by the `pre-commit` and `pre-push` hooks and
by CI) and commitlint enforce this. They fail a commit that changes a version
or `CHANGELOG.md`, and a push that creates a tag, unless it is the release
pull request.

### Microsoft Store package

`release-assets.yml` also builds the MSIX package for the Microsoft Store from the
same build, installs a copy signed with a throwaway certificate on the runner to
test it (`packaging/windows/smoke-msix.ps1`), and uploads the unsigned package as
a workflow artifact. It is not a release asset, and a failure there never keeps
the zip, the installer or the winget submission from going out. A run without a
tag (`gh workflow run release-assets.yml --ref <branch>`) builds and tests the
same package and uploads nothing to a release.

With the repository variables `STORE_IDENTITY_NAME`, `STORE_PUBLISHER` and
`STORE_PUBLISHER_DISPLAY_NAME` set (Partner Center: Product management, Product
identity) the package has the identity of the Store listing and is the file to
upload to Partner Center; without them it has a test identity (`piikey.dev`). The
package version is the release version with its first number raised by one (0.2.1
becomes 1.2.1.0), because the Store takes no package whose first number is 0;
everything else, `piikey-cli --version` included, keeps the release version.
[`packaging/windows/msix/CERTIFICATION.md`](packaging/windows/msix/CERTIFICATION.md)
holds what to paste into the submission. To build it by hand you need the Windows
SDK: `pwsh packaging/windows/package-msix.ps1 -Version X.Y.Z` after
`cargo build --release --workspace --locked` and `package.ps1`.

## Test data

Never commit real personal data, in tests, fixtures or docs. Use made-up
values:

- Email addresses on `example.com`, `example.org` or `example.nl`.
- IBAN `NL91ABNA0417164300`.
- Card `4111 1111 1111 1111`.
- BSN `111222333`.
- IP addresses from documentation ranges, such as `203.0.113.7`.

## Agents

[AGENTS.md](AGENTS.md) holds the layout of the repository and the rules for
coding agents. Humans can use it as an overview too.
