//! Document formats: sniffing and per-format rewrite/extraction.
//!
//! [`process`] recognizes the format from the bytes (never the file name) and
//! hands the input to the matching module:
//!
//! | Format | Module | Output |
//! |---|---|---|
//! | text, any common encoding | `text` | [`Output::Same`] |
//! | Office Open XML | `ooxml` | [`Output::Same`] |
//! | `OpenDocument` | `odf` | [`Output::Same`] |
//! | PDF | `pdf` | [`Output::Text`] |
//! | images | `image` | [`Output::Text`] |
//! | `.eml` | `eml` | [`Output::Text`] |
//! | Outlook `.msg` | `msg` | [`Output::Text`] |

mod eml;
mod image;
mod msg;
mod odf;
mod ooxml;
mod package;
mod pdf;
#[cfg(test)]
mod tests;
mod text;
mod xmltext;

use crate::{Error, Result, detect::Mode, engine::Engine};

/// Result of processing one input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Rewritten file in its original format.
    Same(Vec<u8>),
    /// Transformed extracted text (PDF, image, email); written as `<name>.txt`.
    Text(String),
}

/// Deepest nesting (attachments inside attachments) that is processed.
const MAX_DEPTH: u8 = 4;
/// How much of a file is searched for the blank line that ends mail headers.
const MAIL_SNIFF_LEN: usize = 64 * 1024;
/// Header names a message may start with.
const MAIL_HEADERS: [&str; 9] = [
    "Received",
    "Return-Path",
    "From",
    "MIME-Version",
    "Message-ID",
    "Delivered-To",
    "Date",
    "Subject",
    "To",
];
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Sniffs `bytes` by magic and transforms it with `engine`.
///
/// `depth` is the nesting level (0 for a file; attachments inside emails count
/// up); beyond 4 the input is refused.
///
/// # Errors
/// `UnsupportedFormat` and per-format parse errors.
pub fn process(engine: &Engine, mode: Mode, bytes: &[u8], depth: u8) -> Result<Output> {
    if depth > MAX_DEPTH {
        return Err(Error::UnsupportedFormat("nesting too deep"));
    }
    match sniff(bytes) {
        Format::Zip => {
            let (archive, scope) = open_package(bytes)?;
            package::rewrite(engine, mode, archive, scope).map(Output::Same)
        }
        Format::Pdf => pdf::process(engine, mode, bytes),
        Format::Image => image::process(engine, mode, bytes),
        Format::Cfb => msg::process(engine, mode, bytes, depth),
        Format::Mail => eml::process(engine, mode, bytes, depth),
        Format::Text => text::process(engine, mode, bytes),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Zip,
    Pdf,
    Image,
    Cfb,
    Mail,
    Text,
}

fn sniff(bytes: &[u8]) -> Format {
    if bytes.starts_with(b"PK\x03\x04") {
        Format::Zip
    } else if bytes.starts_with(b"%PDF-") {
        Format::Pdf
    } else if is_image(bytes) {
        Format::Image
    } else if bytes.starts_with(&CFB_MAGIC) {
        Format::Cfb
    } else if is_mail(bytes) {
        Format::Mail
    } else {
        Format::Text
    }
}

fn is_image(b: &[u8]) -> bool {
    b.starts_with(b"\x89PNG")
        || b.starts_with(&[0xFF, 0xD8, 0xFF])
        || b.starts_with(b"GIF8")
        || is_bmp(b)
        || b.starts_with(b"II*\0")
        || b.starts_with(b"MM\0*")
        || (b.starts_with(b"RIFF") && b.get(8..12).is_some_and(|tag| tag == b"WEBP"))
        || (b.get(4..8).is_some_and(|tag| tag == b"ftyp")
            && matches!(b.get(8..12), Some(b"heic" | b"heix" | b"mif1")))
}

/// `BM`, then the file size, two reserved words, the pixel data offset and a
/// known DIB header size. Two letters alone would also match text like "BMW …".
fn is_bmp(b: &[u8]) -> bool {
    b.starts_with(b"BM")
        && b.get(6..10).is_some_and(|reserved| reserved == [0; 4])
        && b.get(14..18)
            .and_then(|size| size.first_chunk::<4>())
            .is_some_and(|size| {
                matches!(
                    u32::from_le_bytes(*size),
                    12 | 40 | 52 | 56 | 64 | 108 | 124
                )
            })
}

/// A message: the first non-empty line is a well-known header and a blank
/// line follows within the first 64 KiB.
fn is_mail(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(MAIL_SNIFF_LEN)];
    let head = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let mut seen_header = false;
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if seen_header {
            if line.is_empty() {
                return true;
            }
        } else if !line.trim_ascii().is_empty() {
            if !is_mail_header(line) {
                return false;
            }
            seen_header = true;
        }
    }
    false
}

fn is_mail_header(line: &[u8]) -> bool {
    MAIL_HEADERS.iter().any(|name| {
        line.get(..name.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(name.as_bytes()))
            && line.get(name.len()) == Some(&b':')
    })
}

/// Opens a zip file as an Office Open XML or `OpenDocument` package.
fn open_package(bytes: &[u8]) -> Result<(package::Archive<'_>, package::Scope)> {
    let mut archive = package::open(bytes)?;
    if ooxml::matches(&archive) {
        Ok((archive, ooxml::scope))
    } else if odf::matches(&mut archive)? {
        Ok((archive, odf::scope))
    } else {
        Err(Error::UnsupportedFormat("zip archive"))
    }
}

/// The text of a [`Output::Same`] result: decoded text, or for a package all
/// its segments joined with newlines.
fn same_text(bytes: &[u8]) -> Result<String> {
    if sniff(bytes) == Format::Zip {
        let (archive, scope) = open_package(bytes)?;
        package::texts(&archive, scope)
    } else {
        text::decode(bytes).map(|(text, _)| text.into_owned())
    }
}

/// Runs the engine over one text.
fn run_text(engine: &Engine, mode: Mode, text: &str) -> Result<String> {
    Ok(engine
        .run(mode, &[text])?
        .into_iter()
        .next()
        .unwrap_or_default())
}
