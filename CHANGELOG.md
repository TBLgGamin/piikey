# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/TBLgGamin/piikey/compare/v0.2.1...v0.3.0) - 2026-10-24

### Added

- *(app)* redesign the app around one status and five clear pages ([#7](https://github.com/TBLgGamin/piikey/pull/7))
- package piikey as an MSIX for the Microsoft Store ([#6](https://github.com/TBLgGamin/piikey/pull/6))

### Build

- submit each release's installer to winget

## [0.2.1](https://github.com/TBLgGamin/piikey/compare/v0.2.0...v0.2.1) - 2026-10-22

### Build

- triage the non-Windows advisories for OSV-Scanner

## [0.2.0](https://github.com/TBLgGamin/piikey/compare/v0.1.1...v0.2.0) - 2026-10-21

### Added

- [**breaking**] add the JSON and HTTP API, PII inventory, subject search and live highlight

### Documentation

- update README screenshots, feature icons and how-it-works for the new features

### Fixed

- restore in one pass, harden vault and proxy settings restore, and clean up the codebase

## [0.1.1](https://github.com/TBLgGamin/piikey/compare/v0.1.0...v0.1.1) - 2026-10-20

### Build

- drop Scorecard and run the Rust CodeQL scan weekly

### Documentation

- show the before/after as ChatGPT conversations
- lead the README with a before/after card, new tagline and fewer badges

## [0.1.0](https://github.com/TBLgGamin/piikey/releases/tag/v0.1.0) - 2026-10-20

### Added

- *(cli)* add --version
- on-device PII model, typed-input capture, Windows app and activity feed
- lightweight Windows PII masker

### Build

- release zip and installer through release-plz
- pin actions, add commit lint, cargo-deny, CodeQL and Scorecard
- embed version information in both executables
- share version and package metadata through the workspace

### Documentation

- rewrite README with screenshots and move details to docs/how-it-works.md
- add MIT license, code of conduct, security policy and contributing guide
