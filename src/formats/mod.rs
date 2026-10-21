//! Document formats: sniffing and per-format rewrite/extraction.
//!
//! [`process`] and [`restore`] recognize the format from the bytes (never the file name) and
//! hand the input to the matching module:
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
//!
//! [`scan`] reads the same inputs the same way but rewrites nothing: it reports what the
//! detector finds. All three go through one `Pass`, so a scan sees exactly the texts a rewrite
//! would change.

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
mod thumbnail;
mod xmltext;

use std::{fmt, sync::Mutex};

use rayon::prelude::*;

use crate::{
    Error, Result,
    detect::{EntityKind, Mode, Span},
    engine::{Engine, Replacement},
    restore::Restorer,
};

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
const MAIL_HEADERS: [&str; 18] = [
    "Received",
    "Return-Path",
    "Delivered-To",
    "From",
    "Sender",
    "Reply-To",
    "To",
    "Cc",
    "Bcc",
    "Date",
    "Subject",
    "Message-ID",
    "In-Reply-To",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "Authentication-Results",
    "Received-SPF",
];
/// Starts of header names only mail has: the `X-` headers that mail clients and servers add
/// (`X-Mozilla-Status`, `X-Original-To`), and the signature and forwarding headers.
const MAIL_HEADER_PREFIXES: [&str; 4] = ["X-", "ARC-", "DKIM-", "Resent-"];
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Sniffs `bytes` by magic and transforms it with `engine`.
///
/// `depth` is the nesting level (0 for a file; attachments inside emails count
/// up); beyond 4 the input is refused.
///
/// # Errors
/// `UnsupportedFormat` and per-format parse errors.
pub fn process(engine: &Engine, mode: Mode, bytes: &[u8], depth: u8) -> Result<Output> {
    process_pass(
        &Pass {
            engine,
            how: How::Rewrite(mode),
        },
        bytes,
        depth,
    )
}

/// [`process`] for [`Mode::Deanonymize`] that also restores with `restorer`: what it scopes comes
/// back when the text spells it with a typo or only as a first or last name, and so does every
/// proxy the vault of `engine` issued. Both are restored in one pass over each text, see
/// [`Restorer::plan_with`], so a value that equals the proxy of another comes back once. Every
/// format gets the same tolerance, documents and mail included, one text at a time: a name that
/// a document splits over two text nodes is restored part by part.
///
/// # Errors
/// `UnsupportedFormat` and per-format parse errors, as for [`process`].
pub fn restore(engine: &Engine, restorer: &Restorer, bytes: &[u8]) -> Result<Output> {
    process_pass(
        &Pass {
            engine,
            how: How::Restore(restorer),
        },
        bytes,
        0,
    )
}

/// What [`scan`] found in one file. Its values are personal data: keep them out of logs (the
/// `Debug` output only counts them).
#[derive(Default)]
pub struct Scanned {
    /// Every value the detector found, with its kind, in reading order.
    pub found: Vec<(EntityKind, Box<str>)>,
    /// The texts the detector read: for a package each part's segments, for an email its
    /// headers, bodies and attachments. Empty unless [`scan`] was asked to keep them.
    pub texts: Vec<String>,
}

impl fmt::Debug for Scanned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanned")
            .field("found", &self.found.len())
            .field("texts", &self.texts.len())
            .finish()
    }
}

/// Sniffs `bytes` like [`process`] and reports what the detector finds in it, without writing
/// anything: the vault is left as it was and no output is built. Values that are stand-ins
/// the vault issued are not reported (see [`Engine::scan`]), so a file piikey masked scans as
/// clean. `keep_texts` also returns the texts that were read, for callers that look for
/// something of their own in them.
///
/// # Errors
/// `UnsupportedFormat` and per-format parse errors, as for [`process`].
pub fn scan(engine: &Engine, bytes: &[u8], keep_texts: bool) -> Result<Scanned> {
    let collect = Collect {
        found: Mutex::new(Vec::new()),
        texts: keep_texts.then(|| Mutex::new(Vec::new())),
    };
    process_pass(
        &Pass {
            engine,
            how: How::Scan(&collect),
        },
        bytes,
        0,
    )?;
    Ok(Scanned {
        found: collect.found.into_inner()?,
        texts: collect
            .texts
            .map_or_else(|| Ok(Vec::new()), Mutex::into_inner)?,
    })
}

/// What a run over a file does with the texts it hands the engine: rewrite them, or only look
/// at them. Every format goes through one, which is why a scan reads exactly what a rewrite
/// would change, attachments and all.
struct Pass<'a> {
    engine: &'a Engine,
    how: How<'a>,
}

enum How<'a> {
    Rewrite(Mode),
    /// A deanonymize that restores through a restorer, which finds every proxy of the vault as
    /// well as the ones it scopes.
    Restore(&'a Restorer),
    Scan(&'a Collect),
}

/// What a scan has seen so far. Behind locks because a pass is shared by reference down the
/// formats; the scans of different files each have their own.
struct Collect {
    found: Mutex<Vec<(EntityKind, Box<str>)>>,
    texts: Option<Mutex<Vec<String>>>,
}

impl Collect {
    /// Takes note of what was found in `texts`, and of `texts` when they are kept.
    fn record(&self, texts: &[&str], found: &[Vec<Span>]) -> Result<()> {
        let mut values = self.found.lock()?;
        for (text, spans) in texts.iter().zip(found) {
            values.extend(
                spans
                    .iter()
                    .map(|s| (s.kind, Box::from(&text[s.start..s.end]))),
            );
        }
        if let Some(kept) = &self.texts {
            kept.lock()?
                .extend(texts.iter().map(|&text| text.to_owned()));
        }
        Ok(())
    }
}

impl Pass<'_> {
    /// [`Engine::plan`] for a rewrite; for a restore, what [`Restorer::plan_with`] makes of each
    /// text. A scan records what the engine finds and plans nothing.
    fn plan(&self, texts: &[&str]) -> Result<Vec<Vec<Replacement>>> {
        match &self.how {
            How::Rewrite(mode) => self.engine.plan(*mode, texts),
            How::Restore(restorer) => Ok(texts
                .par_iter()
                .map(|text| restorer.plan_with(text.as_bytes(), self.engine))
                .collect()),
            How::Scan(collect) => {
                collect.record(texts, &self.engine.scan(texts)?)?;
                Ok(vec![Vec::new(); texts.len()])
            }
        }
    }

    /// [`Engine::run`] for a rewrite and a restore. A scan has no output: it looks at the texts
    /// and answers with empty ones.
    fn run(&self, texts: &[&str]) -> Result<Vec<String>> {
        match &self.how {
            How::Rewrite(mode) => self.engine.run(*mode, texts),
            How::Restore(_) => Ok(texts
                .par_iter()
                .zip(self.plan(texts)?)
                .map(|(text, reps)| Engine::apply(text, &reps))
                .collect()),
            How::Scan(_) => {
                self.plan(texts)?;
                Ok(vec![String::new(); texts.len()])
            }
        }
    }

    /// `bytes` as the output of a file nothing was rewritten in: a copy of it, except for a
    /// scan, which has no output to copy into.
    fn unchanged(&self, bytes: &[u8]) -> Vec<u8> {
        match self.how {
            How::Rewrite(_) | How::Restore(_) => bytes.to_vec(),
            How::Scan(_) => Vec::new(),
        }
    }
}

/// [`process`], [`restore`] and [`scan`] for one input: picks the format and hands the input to it.
fn process_pass(pass: &Pass<'_>, bytes: &[u8], depth: u8) -> Result<Output> {
    if depth > MAX_DEPTH {
        return Err(Error::UnsupportedFormat("nesting too deep"));
    }
    match sniff(bytes) {
        Format::Zip => {
            let (archive, scope) = open_package(bytes)?;
            package::rewrite(pass, archive, scope, depth).map(Output::Same)
        }
        Format::Pdf => pdf::process(pass, bytes),
        Format::Image => image::process(pass, bytes),
        Format::Cfb => msg::process(pass, bytes, depth),
        Format::Mail => eml::process(pass, bytes, depth),
        Format::Text => text::process(pass, bytes),
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

/// A message: the first non-empty line is a header only mail has, after an mbox `From ` line
/// when there is one, and a blank line follows within the first 64 KiB.
fn is_mail(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(MAIL_SNIFF_LEN)];
    let head = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let mut first = lines.by_ref().find(|line| !line.trim_ascii().is_empty());
    if first.is_some_and(|line| line.starts_with(b"From ")) {
        first = lines.by_ref().find(|line| !line.trim_ascii().is_empty());
    }
    first.is_some_and(is_mail_header) && lines.any(<[u8]>::is_empty)
}

fn is_mail_header(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = &line[..colon];
    MAIL_HEADERS
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known.as_bytes()))
        || MAIL_HEADER_PREFIXES.iter().any(|prefix| {
            name.len() > prefix.len()
                && name
                    .get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
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

/// Runs the pass over one text; empty for a scan, which has no output.
fn run_text(pass: &Pass<'_>, text: &str) -> Result<String> {
    Ok(pass.run(&[text])?.into_iter().next().unwrap_or_default())
}
