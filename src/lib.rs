//! piikey: lightweight PII masker for Windows.
//!
//! Detects PII with validated regexes ([`detect`]), swaps each value for a
//! believable, watermarked, format-preserving proxy ([`proxy`]) and keeps the
//! mapping in a DPAPI-protected vault ([`vault`]). [`engine`] ties them
//! together over batches; [`formats`] handles documents, [`ocr`] images and
//! scanned PDFs, [`service`] the named-pipe server.

#[cfg(not(windows))]
compile_error!("piikey is Windows-only: the vault uses DPAPI and OCR uses Windows.Media.Ocr");

pub mod detect;
pub mod engine;
pub mod error;
pub mod formats;
pub mod ocr;
pub mod proxy;
pub mod service;
pub mod vault;

pub use error::{Error, Result};
