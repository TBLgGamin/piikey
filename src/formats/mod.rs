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
//! [`findings`] is a scan that reports each value it finds with the text around it, and says
//! where in the file the format puts it ([`Location`]): the line and column in a text (and in an
//! e-mail, whose rendering is looked up again in its file), the page of a PDF, the cell of a
//! workbook or of a sheet, the slide and shape of a presentation, the paragraph and page of a
//! document. Only the file itself has places: a value in an attachment, in an embedded package
//! or in a picture has none. A format says where its texts stand by handing a `Layout`
//! (`places.rs`) to the pass beside them, and a pass that was not asked for findings never looks
//! at it.
//!
//! A read of findings reports as it goes ([`Report`]), because the model that reads the names
//! costs minutes where the patterns cost a second: the values the patterns find come first, in
//! reading order, then what the model finds in the text a group at a time, and meanwhile a line
//! of progress ([`Busy`]) says what the read is doing. The caller can end it at any report.

mod eml;
mod image;
mod msg;
mod odf;
mod ooxml;
mod package;
mod paragraphs;
mod pdf;
mod places;
mod sheets;
mod slides;
#[cfg(test)]
mod tests;
mod text;
mod thumbnail;
mod xmltext;

use std::{
    fmt,
    ops::ControlFlow,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use rayon::prelude::*;

use crate::{
    Error, Result,
    detect::{EntityKind, Mode, Span, Step},
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
        found: Some(Mutex::new(Vec::new())),
        texts: keep_texts.then(|| Mutex::new(Vec::new())),
        sink: None,
        watch: None,
    };
    run_scan(engine, bytes, &collect)
}

/// [`scan`] that tells `busy` what it is doing while it goes (the OCR of a picture or of the pages
/// of a PDF, how far the model is), the way [`findings`] does. `busy` answers whether to go on:
/// when it says no, the scan ends early (after the group of texts the model is in) and this
/// returns `Ok(None)`, as what it found by then is not all of the file.
///
/// # Errors
/// As [`scan`].
pub fn scan_with(
    engine: &Engine,
    bytes: &[u8],
    busy: &(dyn Fn(Busy) -> bool + Sync),
) -> Result<Option<Scanned>> {
    let collect = Collect {
        found: Some(Mutex::new(Vec::new())),
        texts: None,
        sink: None,
        watch: Some(Watch {
            busy,
            stopped: AtomicBool::new(false),
        }),
    };
    let scanned = run_scan(engine, bytes, &collect)?;
    Ok((!collect.stopped()).then_some(scanned))
}

/// Runs a scan pass over `bytes` into `collect` and takes out what it found.
fn run_scan(engine: &Engine, bytes: &[u8], collect: &Collect<'_>) -> Result<Scanned> {
    process_pass(
        &Pass {
            engine,
            how: How::Scan(collect),
        },
        bytes,
        0,
    )?;
    Ok(Scanned {
        found: match &collect.found {
            Some(found) => std::mem::take(&mut *found.lock()?),
            None => Vec::new(),
        },
        texts: match &collect.texts {
            Some(texts) => std::mem::take(&mut *texts.lock()?),
            None => Vec::new(),
        },
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
    /// A slide of a presentation, counted from 1 in the order the presentation shows its slides
    /// (not the number in the name of the slide's part), and the shape of the slide that holds the
    /// text: counted from 1 among the shapes that lie directly on the slide (a group is one
    /// shape, a table is one), in the order of the file, which is the order they are stacked in,
    /// back to front. `None` for text that is in no shape.
    Slide { slide: u32, shape: Option<u32> },
    /// The speaker notes of a slide, counted from 1 like [`Location::Slide`]. The notes are not
    /// on the slide: a presentation shows them in a pane of their own.
    Notes(u32),
    /// A paragraph of a word-processing document, counted from 1 among the paragraphs of its
    /// body (the ones in a table's cells count, and text in a text box counts as the paragraph
    /// it is anchored in), and the page the paragraph starts on when the file says: the program
    /// that wrote it marks where each page began when it laid the text out last (`.docx`), or
    /// the text breaks the page itself. Headers, footers, notes at the foot of a page and
    /// comments have no place.
    Paragraph { paragraph: u32, page: Option<u32> },
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

/// What a read of the findings of a file reports while it goes, see [`findings`].
#[derive(Debug)]
pub enum Report {
    /// What the read is busy with, for a line of progress.
    Busy(Busy),
    /// More values, each with the text around it and its place: those the patterns find come
    /// first, in reading order, and what the model finds follows, a group of texts at a time.
    Found(Vec<Finding>),
}

/// What a read of findings is busy with when that takes a while.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    /// Reading the text of a picture with the OCR of Windows.
    Picture,
    /// Reading the pages of a PDF that are pictures with OCR: `done` of the `total` that are.
    Pages { done: usize, total: usize },
    /// The model reads the text for what no pattern describes (names, addresses): `done` of the
    /// `total` bytes it reads, `total` being 0 while that is not known yet.
    Model { done: usize, total: usize },
}

/// Sniffs `bytes` like [`scan`] and reports what the detector finds in it to `report`, each value
/// with the text around it, as it is found: the values that patterns find come first, in the
/// order in which the format hands its texts to the detector (the parts of a package in the
/// order of its entries, the headers of a message before its bodies and these before its
/// attachments) and within a text by position, then what the model finds a group of texts at a
/// time, and from time to time what the read is busy with ([`Busy`]). Each finding says where
/// it stands in the file when the format has a place to name ([`Location`]). It reads what a
/// scan reads, and so finds what a scan counts, and nothing is kept: the vault is left as it was
/// and the values only go to `report`, which may be called from several threads (the pages of a
/// PDF are read at once). `report` answers whether to go on: when it says no, the read ends
/// early (after the group of texts the model is in) and this returns `Ok`.
///
/// # Errors
/// `UnsupportedFormat` and per-format parse errors, as for [`process`].
pub fn findings(
    engine: &Engine,
    bytes: &[u8],
    report: &(dyn Fn(Report) -> bool + Sync),
) -> Result<()> {
    let collect = Collect {
        found: None,
        texts: None,
        sink: Some(Sink {
            report,
            stopped: AtomicBool::new(false),
        }),
        watch: None,
    };
    process_pass(
        &Pass {
            engine,
            how: How::Scan(&collect),
        },
        bytes,
        0,
    )?;
    Ok(())
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
    Scan(&'a Collect<'a>),
}

/// How many findings go in one report: the first of a file with a hundred thousand reach the
/// reader while the rest are still being made ready.
const REPORT_BATCH: usize = 1_000;

/// The values a scan found, each with its kind.
type Values = Vec<(EntityKind, Box<str>)>;

/// What a scan has seen so far. Behind locks because a pass is shared by reference down the
/// formats; the scans of different files each have their own.
struct Collect<'a> {
    /// The values, for a scan that counts them.
    found: Option<Mutex<Values>>,
    texts: Option<Mutex<Vec<String>>>,
    /// Where the findings go, for a scan that was asked to show them.
    sink: Option<Sink<'a>>,
    /// Who follows a scan that counts, and may stop it: see [`scan_with`].
    watch: Option<Watch<'a>>,
}

/// The reader of a read of findings, and whether it asked to stop.
struct Sink<'a> {
    report: &'a (dyn Fn(Report) -> bool + Sync),
    stopped: AtomicBool,
}

/// Who follows a scan that counts (see [`scan_with`]), and whether it asked to stop.
struct Watch<'a> {
    busy: &'a (dyn Fn(Busy) -> bool + Sync),
    stopped: AtomicBool,
}

impl Collect<'_> {
    /// Takes note of what was found in `texts`, and of `texts` when they are kept.
    fn record(&self, texts: &[&str], spans: &[Vec<Span>]) -> Result<()> {
        if let Some(values) = &self.found {
            let mut values = values.lock()?;
            for (text, spans) in texts.iter().zip(spans) {
                values.extend(
                    spans
                        .iter()
                        .map(|s| (s.kind, Box::from(&text[s.start..s.end]))),
                );
            }
        }
        if let Some(kept) = &self.texts {
            kept.lock()?
                .extend(texts.iter().map(|&text| text.to_owned()));
        }
        Ok(())
    }

    /// Whether a read of findings, or whoever follows a scan, asked to stop.
    fn stopped(&self) -> bool {
        self.sink
            .as_ref()
            .is_some_and(|sink| sink.stopped.load(Ordering::Relaxed))
            || self
                .watch
                .as_ref()
                .is_some_and(|watch| watch.stopped.load(Ordering::Relaxed))
    }

    /// Gives `report` to the reader of the findings, and what the scan is busy with to whoever
    /// follows it; `false` once either has asked to stop, by this answer or an earlier one.
    /// Nothing is given after that.
    fn tell(&self, report: Report) -> bool {
        if self.stopped() {
            return false;
        }
        if let (Some(watch), Report::Busy(busy)) = (&self.watch, &report)
            && !(watch.busy)(*busy)
        {
            watch.stopped.store(true, Ordering::Relaxed);
            return false;
        }
        let Some(sink) = &self.sink else {
            return true;
        };
        let go = (sink.report)(report);
        if !go {
            sink.stopped.store(true, Ordering::Relaxed);
        }
        go
    }

    /// Reports the values that `spans` are in `texts`, each with the place `layout` says it is
    /// at, in reports of at most [`REPORT_BATCH`]. `false` once the reader asked to stop.
    fn found(&self, layout: &Layout<'_>, texts: &[&str], spans: &[Vec<Span>]) -> bool {
        let mut made: Vec<Finding> = texts
            .iter()
            .zip(spans)
            .flat_map(|(text, spans)| spans.iter().map(move |span| finding(text, span)))
            .collect();
        layout.locate(texts, spans, &mut made);
        let mut rest = made.into_iter();
        loop {
            let batch: Vec<Finding> = rest.by_ref().take(REPORT_BATCH).collect();
            if batch.is_empty() {
                return true;
            }
            if !self.tell(Report::Found(batch)) {
                return false;
            }
        }
    }

    /// One step of what the engine finds: its values, then how far the model is.
    fn step(&self, layout: &Layout<'_>, texts: &[&str], step: &Step) -> ControlFlow<()> {
        let mut go = self.found(layout, texts, &step.spans);
        if go && let Some((done, total)) = step.more {
            go = self.tell(Report::Busy(Busy::Model { done, total }));
        }
        if go {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
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
    /// text. A scan notes what the engine finds, or for findings reports it as it is found, with
    /// the place `layout` says it is at, and plans nothing.
    fn plan(&self, layout: &Layout<'_>, texts: &[&str]) -> Result<Vec<Vec<Replacement>>> {
        match &self.how {
            How::Rewrite(mode) => self.engine.plan(*mode, texts),
            How::Restore(restorer) => Ok(texts
                .par_iter()
                .map(|text| restorer.plan_with(text.as_bytes(), self.engine))
                .collect()),
            How::Scan(collect) => {
                if collect.sink.is_some() {
                    self.scan_in_steps(collect, layout, texts)?;
                } else if collect.watch.is_some() {
                    self.count_in_steps(collect, texts)?;
                } else {
                    collect.record(texts, &self.engine.scan(texts)?)?;
                }
                Ok(vec![Vec::new(); texts.len()])
            }
        }
    }

    /// Reports what the engine finds in `texts` as it finds it (see [`Engine::scan_steps`]). Where
    /// a value stands is worked out per step, except when the place of a value depends on the
    /// others of the call ([`Layout::Raw`]): those wait until the call is done, and the progress
    /// of the model goes on being reported meanwhile.
    fn scan_in_steps(
        &self,
        collect: &Collect<'_>,
        layout: &Layout<'_>,
        texts: &[&str],
    ) -> Result<()> {
        if collect.stopped() {
            return Ok(());
        }
        if !layout.needs_the_whole_call() {
            return self
                .engine
                .scan_steps(texts, |step| collect.step(layout, texts, &step));
        }
        let mut all: Vec<Vec<Span>> = vec![Vec::new(); texts.len()];
        self.engine.scan_steps(texts, |step| {
            for (mine, spans) in all.iter_mut().zip(step.spans) {
                mine.extend(spans);
            }
            match step.more {
                Some((done, total)) if !collect.tell(Report::Busy(Busy::Model { done, total })) => {
                    ControlFlow::Break(())
                }
                _ => ControlFlow::Continue(()),
            }
        })?;
        for spans in &mut all {
            spans.sort_by_key(|span| span.start);
        }
        collect.found(layout, texts, &all);
        Ok(())
    }

    /// Counts what the engine finds in `texts` a step at a time, telling whoever follows the scan
    /// how far the model is, and stopping when they say so.
    fn count_in_steps(&self, collect: &Collect<'_>, texts: &[&str]) -> Result<()> {
        if collect.stopped() {
            return Ok(());
        }
        let mut failed = None;
        self.engine.scan_steps(texts, |step| {
            if let Err(error) = collect.record(texts, &step.spans) {
                failed = Some(error);
                return ControlFlow::Break(());
            }
            match step.more {
                Some((done, total)) if !collect.tell(Report::Busy(Busy::Model { done, total })) => {
                    ControlFlow::Break(())
                }
                _ => ControlFlow::Continue(()),
            }
        })?;
        failed.map_or(Ok(()), Err)
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
    /// itself has places, and only a read of findings works them out.
    fn wants_places(&self, depth: u8) -> bool {
        depth == 0 && matches!(&self.how, How::Scan(collect) if collect.sink.is_some())
    }

    /// Tells a read of findings what the pass is busy with; any other pass has no one to tell.
    fn busy(&self, busy: Busy) {
        if let How::Scan(collect) = &self.how {
            collect.tell(Report::Busy(busy));
        }
    }

    /// Whether the reader of the findings has asked to stop: what is left to read can be left.
    fn stopped(&self) -> bool {
        matches!(&self.how, How::Scan(collect) if collect.stopped())
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
