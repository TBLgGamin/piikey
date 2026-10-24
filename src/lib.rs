//! piikey: lightweight PII masker for Windows.
//!
//! Detects PII with validated regexes ([`detect`]), swaps each value for a
//! believable, watermarked, format-preserving proxy ([`proxy`]) and keeps the
//! mapping in a DPAPI-protected vault ([`vault`]). [`engine`] ties them
//! together over batches; [`formats`] handles documents, [`ocr`] images and
//! scanned PDFs, [`service`] the named-pipe server and client. [`api`] is the one API (a
//! request type, a reply envelope, an in-process handler and the loopback HTTP server) that the
//! command line, the pipe and the app share. [`policy`] is the saved
//! settings and [`sys`] the Windows plumbing (data folder, atomic and exclusive writes, file
//! locks, DPAPI, System32 tools) the CLI and the app share. [`files`] turns inputs into
//! file jobs, [`inventory`] keeps what a scan of the user's folders found, [`sources`] reaches
//! the folders of cloud accounts (Microsoft 365, `OneDrive`, Google Drive, Dropbox, Box) so the
//! inventory scans them like the ones on this PC, and [`subject`] looks for one person's values
//! in files.

#[cfg(not(windows))]
compile_error!("piikey is Windows-only: the vault uses DPAPI and OCR uses Windows.Media.Ocr");

pub mod api;
pub mod detect;
pub mod engine;
pub mod error;
pub mod files;
pub mod formats;
pub mod inventory;
pub mod ocr;
pub mod policy;
pub mod proxy;
pub mod restore;
pub mod service;
pub mod sources;
pub mod subject;
pub mod sys;
#[cfg(test)]
mod testing;
pub mod vault;

pub use error::{Error, Result};
