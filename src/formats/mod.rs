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
//!
//! [`findings`] is a scan that keeps each value it finds with the text around it, in reading
//! order, and says where in the file the format puts it ([`Location`]): the line and column in
//! a text (and in an e-mail, whose rendering is looked up again in its file), the page of a PDF,
//! the cell of a workbook or of a sheet. Only the file itself has places: a value in an
//! attachment, in an embedded package or in a picture has none. A format says where its texts
//! stand by handing a `Layout` (`places.rs`) to the pass beside them, and a pass that was not
//! asked for findings never looks at it.

mod eml;
mod image;
mod msg;
mod odf;
mod ooxml;
mod package;
mod pdf;
mod places;
mod sheets;
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
use places::Layout;

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
        findings: None,
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

/// How many characters of text a [`Finding`]'s snippet shows on each side of the value.
const SNIPPET_CONTEXT: usize = 40;
/// How many characters of a value a [`Finding`]'s snippet shows: a secret can be a whole key block.
const SNIPPET_VALUE: usize = 120;
/// How many characters of a value a [`Finding`] keeps: more than any value a person reads, but a
/// run that a detector takes for a secret can be as long as the file.
const MAX_VALUE: usize = 4_096;

/// Where a value stands in its file, as far as the format says. A value in an attachment, in an
/// embedded document or in a picture has no place of the file's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// A line and a column of a text, both counted from 1. The text is the file as an editor
    /// shows it once decoded (a byte order mark is no column), a line ends at `\n`, at `\r\n` or
    /// at a lone `\r`, and the column counts characters (a tab is one). In a text file this is
    /// where the value is; in an `.eml` message the value is looked up in the file as it is
    /// written there (the `k`th finding of a value at its `k`th occurrence), so a value that the
    /// file encodes (a base64 body, a header word) or that spans a line break has no place.
    Line { line: u32, column: u32 },
    /// A page of a PDF, counted from 1; pages that were read by OCR count too.
    Page(u32),
    /// A cell of a sheet: the name of the sheet and the cell's address (`B7`). In a workbook
    /// (`.xlsx`) a shared string is at the first cell that shows it, in the order of the sheets
    /// and then of the cells; in an `OpenDocument` sheet (`.ods`) a cell that stands for several
    /// is at the first of them.
    Cell { sheet: Box<str>, cell: Box<str> },
}

/// A value the detector found in a file, with the text around it, for showing to the person who
/// asked. It is personal data: keep it out of logs and out of files (the `Debug` output only
/// names the kind).
#[derive(Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: EntityKind,
    /// The value, each run of white space (a line break, a tab) one space, and cut to the first
    /// 4,096 characters when it is longer, with `…` after them.
    pub value: Box<str>,
    /// The value with up to 40 characters of the text before and after it, white space
    /// collapsed as in `value`, and `…` where the text goes on beyond what is shown. The value
    /// in it is cut to 120 characters, with `…` after them, when it is longer.
    pub snippet: Box<str>,
    /// Where it is in the file, when the format has a place to name.
    pub location: Option<Location>,
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Sniffs `bytes` like [`scan`] and lists what the detector finds in it, each value with the
/// text around it, in reading order: the order in which the format hands its texts to the
/// detector (the parts of a package in the order of its entries, the headers of a message before
/// its bodies and these before its attachments), and within a text by position. Each finding
/// says where it stands in the file when the format has a place to name ([`Location`]). It
/// reads what a scan reads, and nothing is kept: the vault is left as it was and the values only
/// go to the caller.
///
/// # Errors
/// `UnsupportedFormat` and per-format parse errors, as for [`process`].
pub fn findings(engine: &Engine, bytes: &[u8]) -> Result<Vec<Finding>> {
    let collect = Collect {
        found: Mutex::new(Vec::new()),
        texts: None,
        findings: Some(Mutex::new(Vec::new())),
    };
    process_pass(
        &Pass {
            engine,
            how: How::Scan(&collect),
        },
        bytes,
        0,
    )?;
    let list = collect
        .findings
        .map_or_else(|| Ok(Vec::new()), Mutex::into_inner)?;
    Ok(list)
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
    /// The values with their surroundings, for a scan that was asked to show them.
    findings: Option<Mutex<Vec<Finding>>>,
}

impl Collect {
    /// Takes note of what was found in `texts`, and of `texts` when they are kept. A scan that
    /// was asked for findings also keeps each value with the place that `layout` says it is at.
    fn record(&self, layout: &Layout<'_>, texts: &[&str], spans: &[Vec<Span>]) -> Result<()> {
        let mut values = self.found.lock()?;
        for (text, spans) in texts.iter().zip(spans) {
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
        if let Some(shown) = &self.findings {
            let mut shown = shown.lock()?;
            let from = shown.len();
            for (text, spans) in texts.iter().zip(spans) {
                shown.extend(spans.iter().map(|span| finding(text, span)));
            }
            layout.locate(texts, spans, &mut shown[from..]);
        }
        Ok(())
    }
}

/// The finding for `span` of `text`.
fn finding(text: &str, span: &Span) -> Finding {
    let before = &text[..span.start];
    let value = &text[span.start..span.end];
    let after = &text[span.end..];
    let whole = collapse(value);
    let whole = whole.trim();
    let shown = shorten(whole, SNIPPET_VALUE);
    let (near, cut_before) = tail(before, SNIPPET_CONTEXT);
    let (far, cut_after) = head(after, SNIPPET_CONTEXT);
    let mut snippet = String::new();
    if cut_before {
        snippet.push('…');
    }
    snippet.push_str(collapse(near).trim_start());
    snippet.push_str(&shown);
    snippet.push_str(collapse(far).trim_end());
    if cut_after {
        snippet.push('…');
    }
    Finding {
        kind: span.kind,
        value: shorten(whole, MAX_VALUE).into(),
        snippet: snippet.into(),
        location: None,
    }
}

/// `text` with each run of white space one space.
fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut spaced = false;
    for c in text.chars() {
        if c.is_whitespace() {
            if !spaced {
                out.push(' ');
            }
            spaced = true;
        } else {
            out.push(c);
            spaced = false;
        }
    }
    out
}

/// The first `max` characters of `text`, and `…` when there are more.
fn shorten(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_owned(),
    }
}

/// The last `n` characters of `text`, and whether more came before them.
fn tail(text: &str, n: usize) -> (&str, bool) {
    let start = text
        .char_indices()
        .rev()
        .take(n)
        .last()
        .map_or(0, |(at, _)| at);
    (&text[start..], start > 0)
}

/// The first `n` characters of `text`, and whether more came after them.
fn head(text: &str, n: usize) -> (&str, bool) {
    match text.char_indices().nth(n) {
        Some((end, _)) => (&text[..end], true),
        None => (text, false),
    }
}

impl Pass<'_> {
    /// [`Engine::plan`] for a rewrite; for a restore, what [`Restorer::plan_with`] makes of each
    /// text. A scan records what the engine finds, and where `layout` says that is, and plans
    /// nothing.
    fn plan(&self, layout: &Layout<'_>, texts: &[&str]) -> Result<Vec<Vec<Replacement>>> {
        match &self.how {
            How::Rewrite(mode) => self.engine.plan(*mode, texts),
            How::Restore(restorer) => Ok(texts
                .par_iter()
                .map(|text| restorer.plan_with(text.as_bytes(), self.engine))
                .collect()),
            How::Scan(collect) => {
                collect.record(layout, texts, &self.engine.scan(texts)?)?;
                Ok(vec![Vec::new(); texts.len()])
            }
        }
    }

    /// [`Engine::run`] for a rewrite and a restore. A scan has no output: it looks at the texts
    /// and answers with empty ones.
    fn run(&self, layout: &Layout<'_>, texts: &[&str]) -> Result<Vec<String>> {
        match &self.how {
            How::Rewrite(mode) => self.engine.run(*mode, texts),
            How::Restore(_) => Ok(texts
                .par_iter()
                .zip(self.plan(layout, texts)?)
                .map(|(text, reps)| Engine::apply(text, &reps))
                .collect()),
            How::Scan(_) => {
                self.plan(layout, texts)?;
                Ok(vec![String::new(); texts.len()])
            }
        }
    }

    /// Whether the places of the texts of a file at nesting `depth` are wanted: only the file
    /// itself has places, and only a scan that was asked for findings works them out.
    fn wants_places(&self, depth: u8) -> bool {
        depth == 0 && matches!(&self.how, How::Scan(collect) if collect.findings.is_some())
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
        Format::Pdf => pdf::process(pass, bytes, depth),
        Format::Image => image::process(pass, bytes),
        Format::Cfb => msg::process(pass, bytes, depth),
        Format::Mail => eml::process(pass, bytes, depth),
        Format::Text => text::process(pass, bytes, depth),
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

/// Runs the pass over one text, which stands in its file as `layout` says; empty for a scan,
/// which has no output.
fn run_text(pass: &Pass<'_>, layout: &Layout<'_>, text: &str) -> Result<String> {
    Ok(pass
        .run(layout, &[text])?
        .into_iter()
        .next()
        .unwrap_or_default())
}
