//! Text segments of XML parts (OOXML, ODF) and rewriting them in place.
//!
//! A part is scanned into *segments*: the strings the detector sees. The
//! detector's byte offsets are mapped back onto the source events, the parts
//! of the text they cover are replaced, and every byte no replacement touches
//! is copied through unchanged.
//!
//! Segments:
//! - All text inside a paragraph-like container (`p`, `h`, `si`, `is`) is one
//!   segment, so a value split over formatting runs is still found whole.
//!   Whitespace elements (`tab`, `br`, `line-break`, …) and nested containers
//!   contribute a `\n`, so unrelated text never fuses.
//! - Text outside containers is one segment per run of text, entity
//!   references and CDATA between two markup events.
//! - Field instructions (`instrText`) are never merged into the paragraph they
//!   sit in, but are masked on their own: a `HYPERLINK "mailto:…"` field holds
//!   the same address as its visible text.
//! - Depending on [`Attrs`], the values of `Target` (OOXML relationships) or
//!   `href` (ODF links) attributes are segments too.
//!
//! Entity references are resolved for detection (`&amp;` is `&`) but copied
//! verbatim when no replacement covers them. Only the five predefined
//! entities and character references resolve; any other reference is opaque
//! and reads as `\n`.

use std::{collections::BTreeMap, ops::Range};

use quick_xml::{
    escape::{escape, partial_escape, resolve_xml_entity},
    events::{BytesRef, BytesStart, Event},
    reader::Reader,
};

use super::text::{self, Encoding};
use crate::{Error, Result, engine::Replacement};

/// Elements whose descendants' text reads as one paragraph (local names).
const CONTAINERS: [&str; 4] = ["p", "h", "si", "is"];
/// Elements that stand for whitespace inside a paragraph (local names).
const BREAKS: [&str; 6] = ["tab", "br", "cr", "ptab", "line-break", "s"];
/// Field instruction text (local name).
const INSTRUCTION: &str = "instrText";
/// What a break reads as in segment text.
const BREAK_TEXT: &str = "\n";

const CDATA_OPEN: &str = "<![CDATA[";
const CDATA_CLOSE: &str = "]]>";

/// Which attribute values are text, besides element content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Attrs {
    /// None.
    None,
    /// `Target` (OOXML relationship parts: `mailto:` links).
    Target,
    /// `xlink:href` and any other `href` (ODF links).
    Href,
}

impl Attrs {
    fn wants(self, key: &[u8]) -> bool {
        match self {
            Self::None => false,
            Self::Target => key == b"Target",
            Self::Href => key
                .rsplit(|&b| b == b':')
                .next()
                .is_some_and(|local| local == b"href"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Character data: its source bytes are its text.
    Text,
    /// `<![CDATA[…]]>`: the text is the content between the markers.
    CData,
    /// A resolved entity or character reference (`&amp;`).
    Ref,
    /// A virtual `\n` with no source bytes of its own.
    Break,
}

/// One piece of a segment's text and the source bytes it came from.
#[derive(Debug, Clone)]
struct Part {
    kind: Kind,
    /// The whole event (or attribute value piece) in `XmlDoc::src`; empty for breaks.
    src: Range<usize>,
    /// Start of this piece in the segment text.
    off: usize,
    /// Length of this piece in the segment text.
    len: usize,
}

#[derive(Debug)]
struct Seg {
    /// The segment text in `XmlDoc::buf`.
    text: Range<usize>,
    /// Its pieces in `XmlDoc::parts`.
    parts: Range<usize>,
}

/// An XML part scanned into segments; see the module docs.
#[derive(Debug)]
pub(super) struct XmlDoc {
    /// The document as UTF-8, BOM stripped.
    src: Vec<u8>,
    /// How to write the document back.
    encoding: Encoding,
    /// All segment texts, back to back.
    buf: String,
    segs: Vec<Seg>,
    parts: Vec<Part>,
}

impl XmlDoc {
    /// Number of segments.
    pub(super) fn len(&self) -> usize {
        self.segs.len()
    }

    /// The segment texts, in document order.
    pub(super) fn texts(&self) -> impl Iterator<Item = &str> {
        self.segs.iter().map(|s| &self.buf[s.text.clone()])
    }

    /// The document with `reps` (one list per segment, offsets into that
    /// segment's text) applied, or `None` when nothing changes.
    ///
    /// Per replacement, the text goes into the event holding its start (that
    /// event's text before the match is kept), the covered text is dropped
    /// from the events that follow, and the text after the match stays. All
    /// other bytes are copied unchanged.
    ///
    /// # Errors
    /// `Xml` when a replacement splits a character of a CDATA section.
    pub(super) fn rebuild(&self, reps: &[Vec<Replacement>]) -> Result<Option<Vec<u8>>> {
        let mut edits = Vec::new();
        for (seg, reps) in self.segs.iter().zip(reps) {
            if !reps.is_empty() {
                self.edit_segment(seg, reps, &mut edits)?;
            }
        }
        if edits.is_empty() {
            return Ok(None);
        }
        edits.sort_unstable_by_key(|e| e.range.start);
        let extra: usize = edits.iter().map(|e| e.bytes.len()).sum();
        let mut out = Vec::with_capacity(self.src.len() + extra);
        let mut at = 0;
        for edit in &edits {
            out.extend_from_slice(&self.src[at..edit.range.start]);
            out.extend_from_slice(&edit.bytes);
            at = edit.range.end;
        }
        out.extend_from_slice(&self.src[at..]);
        encode_utf8(out, self.encoding).map(Some)
    }

    fn edit_segment(&self, seg: &Seg, reps: &[Replacement], edits: &mut Vec<Edit>) -> Result<()> {
        let parts = &self.parts[seg.parts.clone()];
        // Per touched part, in text order: what to do with its text.
        let mut touched: BTreeMap<usize, Vec<Op<'_>>> = BTreeMap::new();
        for rep in reps {
            let first = parts.partition_point(|p| p.off + p.len <= rep.start);
            let mut placed = false;
            for (i, part) in parts.iter().enumerate().skip(first) {
                if part.off >= rep.end {
                    break;
                }
                if part.kind == Kind::Break {
                    continue;
                }
                let from = rep.start.max(part.off) - part.off;
                let to = rep.end.min(part.off + part.len) - part.off;
                let ops = touched.entry(i).or_default();
                if !placed {
                    ops.push(Op::Put(from, &rep.with));
                    placed = true;
                }
                ops.push(Op::Cut(from, to));
            }
        }
        for (i, ops) in touched {
            let part = &parts[i];
            edits.push(Edit {
                range: part.src.clone(),
                bytes: self.render(part, &ops)?,
            });
        }
        Ok(())
    }

    /// The new bytes for `part` after `ops`.
    fn render(&self, part: &Part, ops: &[Op<'_>]) -> Result<Vec<u8>> {
        let (raw, cdata) = match part.kind {
            Kind::Text => (&self.src[part.src.clone()], false),
            Kind::CData => (
                &self.src[part.src.start + CDATA_OPEN.len()..part.src.end - CDATA_CLOSE.len()],
                true,
            ),
            // A reference is atomic: any replacement drops it whole.
            Kind::Ref | Kind::Break => (&[][..], false),
        };
        let mut out = Vec::with_capacity(part.src.len());
        let mut at = 0;
        for op in ops {
            match *op {
                Op::Put(pos, with) => {
                    keep(&mut out, raw, at, pos, cdata)?;
                    at = at.max(pos);
                    out.extend_from_slice(escape(with).as_bytes());
                }
                Op::Cut(from, to) => {
                    keep(&mut out, raw, at, from, cdata)?;
                    at = at.max(to);
                }
            }
        }
        keep(&mut out, raw, at, raw.len(), cdata)?;
        Ok(out)
    }
}

/// Source bytes `range` become `bytes`.
#[derive(Debug)]
struct Edit {
    range: Range<usize>,
    bytes: Vec<u8>,
}

/// What happens to a part's text, as offsets into that text.
#[derive(Debug, Clone, Copy)]
enum Op<'a> {
    /// Insert this text here.
    Put(usize, &'a str),
    /// Drop `[from, to)`.
    Cut(usize, usize),
}

/// Appends `raw[from..to]` to `out`: verbatim, or escaped when it comes from
/// a CDATA section that is being rewritten as plain text.
fn keep(out: &mut Vec<u8>, raw: &[u8], from: usize, to: usize, cdata: bool) -> Result<()> {
    let to = to.min(raw.len());
    if from >= to {
        return Ok(());
    }
    let slice = &raw[from..to];
    if cdata {
        let text = std::str::from_utf8(slice)
            .map_err(|_| Error::Xml("replacement splits a character".into()))?;
        out.extend_from_slice(partial_escape(text).as_bytes());
    } else {
        out.extend_from_slice(slice);
    }
    Ok(())
}

/// Scans an XML part into segments.
///
/// `xml` may be UTF-8 (with or without BOM) or UTF-16 (with a BOM, or without one when the part
/// starts with `<`); it is written back the same way.
///
/// # Errors
/// `Xml` when the part is not well-formed XML or not valid text.
pub(super) fn segments(xml: Vec<u8>, attrs: Attrs) -> Result<XmlDoc> {
    let (src, encoding) = utf8_source(xml)?;
    let mut scan = Scanner::new(&src, attrs);
    let mut reader = Reader::from_reader(&src[..]);
    loop {
        let from = position(&reader);
        let event = reader.read_event()?;
        let to = position(&reader);
        match event {
            Event::Eof => break,
            Event::Text(_) => scan.text_event(from..to)?,
            Event::CData(_) => scan.cdata_event(from..to)?,
            Event::GeneralRef(_) => scan.ref_event(from..to)?,
            Event::Start(e) => scan.start_event(&e, &(from..to), false)?,
            Event::Empty(e) => scan.start_event(&e, &(from..to), true)?,
            Event::End(e) => scan.end_event(e.local_name().into_inner()),
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) | Event::DocType(_) => {
                scan.store.flush(&mut scan.text);
            }
        }
    }
    let Store { buf, segs, parts } = scan.finish();
    Ok(XmlDoc {
        src,
        encoding,
        buf,
        segs,
        parts,
    })
}

fn position(reader: &Reader<&[u8]>) -> usize {
    usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX)
}

/// Text collected for one segment, before it is stored.
#[derive(Debug, Default)]
struct Run {
    text: String,
    parts: Vec<Part>,
}

impl Run {
    fn push(&mut self, kind: Kind, src: Range<usize>, text: &str) {
        self.parts.push(Part {
            kind,
            src,
            off: self.text.len(),
            len: text.len(),
        });
        self.text.push_str(text);
    }

    fn push_break(&mut self) {
        self.push(Kind::Break, 0..0, BREAK_TEXT);
    }
}

/// Finished segments.
#[derive(Debug, Default)]
struct Store {
    buf: String,
    segs: Vec<Seg>,
    parts: Vec<Part>,
}

impl Store {
    /// Moves `run` into a segment, unless it is blank (nothing to detect),
    /// and leaves it empty.
    fn flush(&mut self, run: &mut Run) {
        if run.text.bytes().any(|b| !b.is_ascii_whitespace()) {
            let text_start = self.buf.len();
            self.buf.push_str(&run.text);
            let parts_start = self.parts.len();
            self.parts.append(&mut run.parts);
            self.segs.push(Seg {
                text: text_start..self.buf.len(),
                parts: parts_start..self.parts.len(),
            });
        }
        run.text.clear();
        run.parts.clear();
    }
}

struct Scanner<'a> {
    src: &'a [u8],
    attrs: Attrs,
    store: Store,
    /// Text outside containers, and field instructions.
    text: Run,
    /// Text of the outermost open container.
    para: Run,
    /// Open containers.
    depth: usize,
    in_instruction: bool,
}

impl<'a> Scanner<'a> {
    fn new(src: &'a [u8], attrs: Attrs) -> Self {
        Self {
            src,
            attrs,
            store: Store::default(),
            text: Run::default(),
            para: Run::default(),
            depth: 0,
            in_instruction: false,
        }
    }

    fn finish(mut self) -> Store {
        self.store.flush(&mut self.text);
        self.store.flush(&mut self.para);
        self.store
    }

    /// The run character data goes to.
    fn target(&mut self) -> &mut Run {
        if self.depth > 0 && !self.in_instruction {
            &mut self.para
        } else {
            &mut self.text
        }
    }

    fn text_event(&mut self, range: Range<usize>) -> Result<()> {
        let text = utf8(self.src, &range)?;
        if !text.is_empty() {
            self.target().push(Kind::Text, range, text);
        }
        Ok(())
    }

    fn cdata_event(&mut self, range: Range<usize>) -> Result<()> {
        let content = utf8(self.src, &range)?
            .strip_prefix(CDATA_OPEN)
            .and_then(|s| s.strip_suffix(CDATA_CLOSE))
            .ok_or_else(|| Error::Xml("malformed CDATA section".into()))?;
        if !content.is_empty() {
            self.target().push(Kind::CData, range, content);
        }
        Ok(())
    }

    fn ref_event(&mut self, range: Range<usize>) -> Result<()> {
        let name = utf8(self.src, &range)?
            .strip_prefix('&')
            .and_then(|s| s.strip_suffix(';'))
            .ok_or_else(|| Error::Xml("malformed reference".into()))?;
        let run = self.target();
        match resolve(name) {
            Some(c) => run.push(Kind::Ref, range, c.encode_utf8(&mut [0; 4])),
            None => run.push_break(),
        }
        Ok(())
    }

    fn start_event(&mut self, e: &BytesStart<'_>, tag: &Range<usize>, empty: bool) -> Result<()> {
        let local = e.local_name().into_inner();
        self.store.flush(&mut self.text);
        if self.depth > 0 && !self.in_instruction && BREAKS.contains(&local) {
            self.para.push_break();
        }
        if !empty {
            if CONTAINERS.contains(&local) {
                if self.depth > 0 {
                    self.para.push_break();
                }
                self.depth += 1;
            } else if local == INSTRUCTION {
                self.in_instruction = true;
            }
        }
        if self.attrs != Attrs::None {
            self.attributes(tag, e.name().into_inner().len())?;
        }
        Ok(())
    }

    fn end_event(&mut self, local: &str) {
        self.store.flush(&mut self.text);
        if CONTAINERS.contains(&local) && self.depth > 0 {
            self.depth -= 1;
            if self.depth == 0 {
                self.store.flush(&mut self.para);
            } else {
                self.para.push_break();
            }
        } else if local == INSTRUCTION {
            self.in_instruction = false;
        }
    }

    /// Every wanted attribute value of the start tag at `tag` becomes a segment.
    fn attributes(&mut self, tag: &Range<usize>, name_len: usize) -> Result<()> {
        let src = self.src;
        let bytes = src
            .get(tag.clone())
            .ok_or_else(|| Error::Xml("tag out of bounds".into()))?;
        let attrs = AttrIter {
            tag: bytes,
            at: 1 + name_len,
        };
        for (key, value) in attrs {
            if self.attrs.wants(key) {
                let mut run = Run::default();
                let range = tag.start + value.start..tag.start + value.end;
                split_raw(src, range, &mut run)?;
                self.store.flush(&mut run);
            }
        }
        Ok(())
    }
}

/// Attributes of a start tag as `(key, value range in the tag)`.
struct AttrIter<'a> {
    tag: &'a [u8],
    at: usize,
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = (&'a [u8], Range<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        let t = self.tag;
        let mut i = self.at;
        while t.get(i)?.is_ascii_whitespace() {
            i += 1;
        }
        let key_start = i;
        while t
            .get(i)
            .is_some_and(|&b| !b.is_ascii_whitespace() && !matches!(b, b'=' | b'>' | b'/'))
        {
            i += 1;
        }
        let key = &t[key_start..i];
        if key.is_empty() {
            return None;
        }
        while t.get(i)?.is_ascii_whitespace() {
            i += 1;
        }
        if *t.get(i)? != b'=' {
            return None;
        }
        i += 1;
        while t.get(i)?.is_ascii_whitespace() {
            i += 1;
        }
        let quote = *t.get(i)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let start = i + 1;
        let len = t[start..].iter().position(|&b| b == quote)?;
        self.at = start + len + 1;
        Some((key, start..start + len))
    }
}

/// Splits a raw attribute value into text and reference parts.
fn split_raw(src: &[u8], range: Range<usize>, run: &mut Run) -> Result<()> {
    let mut at = range.start;
    while at < range.end {
        let Some(amp) = src[at..range.end].iter().position(|&b| b == b'&') else {
            run.push(Kind::Text, at..range.end, utf8(src, &(at..range.end))?);
            break;
        };
        if amp > 0 {
            run.push(Kind::Text, at..at + amp, utf8(src, &(at..at + amp))?);
        }
        let start = at + amp;
        let Some(semi) = src[start..range.end].iter().position(|&b| b == b';') else {
            // A dangling `&` is not well-formed; keep it as plain text.
            run.push(
                Kind::Text,
                start..range.end,
                utf8(src, &(start..range.end))?,
            );
            break;
        };
        let end = start + semi + 1;
        match resolve(utf8(src, &(start + 1..end - 1))?) {
            Some(c) => run.push(Kind::Ref, start..end, c.encode_utf8(&mut [0; 4])),
            None => run.push_break(),
        }
        at = end;
    }
    Ok(())
}

/// The character a predefined entity or character reference stands for.
fn resolve(name: &str) -> Option<char> {
    if name.starts_with('#') {
        BytesRef::new(name).resolve_char_ref().ok().flatten()
    } else {
        resolve_xml_entity(name).and_then(|s| s.chars().next())
    }
}

/// `src[range]` as text.
fn utf8<'s>(src: &'s [u8], range: &Range<usize>) -> Result<&'s str> {
    src.get(range.clone())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or_else(|| Error::Xml("text is not UTF-8".into()))
}

/// `xml` as BOM-less UTF-8 and the encoding to write it back in.
///
/// A part is UTF-16 when it starts with a byte order mark or, as the XML specification detects
/// the encoding, with `<` as a 16-bit unit. Read as UTF-8, UTF-16 would be text with a NUL
/// between its letters that nothing is found in, so a part with NULs that is no UTF-16 is
/// refused: XML cannot hold a NUL character anyway.
fn utf8_source(mut xml: Vec<u8>) -> Result<(Vec<u8>, Encoding)> {
    let (src, encoding) = if starts_like_utf16(&xml) {
        let (text, encoding) = text::decode(&xml).map_err(|e| Error::Xml(e.to_string()))?;
        if !encoding.is_utf16() {
            return Err(Error::Xml("not valid UTF-16".into()));
        }
        (text.into_owned().into_bytes(), encoding)
    } else if xml.starts_with(&text::UTF8_BOM) {
        xml.drain(..text::UTF8_BOM.len());
        (xml, Encoding::Utf8Bom)
    } else {
        (xml, Encoding::Utf8)
    };
    // The reader skips a mark at the start without counting it, which would shift every offset;
    // a second one is not XML anyway.
    if src.starts_with(&text::UTF8_BOM) {
        return Err(Error::Xml("a second byte order mark".into()));
    }
    if src.contains(&0) {
        return Err(Error::Xml("a NUL character".into()));
    }
    Ok((src, encoding))
}

/// Whether `xml` starts with a UTF-16 byte order mark or with `<` as one 16-bit unit.
fn starts_like_utf16(xml: &[u8]) -> bool {
    xml.starts_with(&text::UTF16LE_BOM)
        || xml.starts_with(&text::UTF16BE_BOM)
        || xml.starts_with(b"<\0")
        || xml.starts_with(b"\0<")
}

/// UTF-8 `out` in `encoding`.
fn encode_utf8(out: Vec<u8>, encoding: Encoding) -> Result<Vec<u8>> {
    match encoding {
        Encoding::Utf8 => Ok(out),
        other => {
            let text = String::from_utf8(out)
                .map_err(|_| Error::Xml("rewritten part is not UTF-8".into()))?;
            text::encode(text, other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn rep(start: usize, end: usize, with: &str) -> Replacement {
        Replacement {
            start,
            end,
            with: with.into(),
        }
    }

    fn texts(doc: &XmlDoc) -> Vec<&str> {
        doc.texts().collect()
    }

    /// Replaces the first `find` in segment `seg` with `with`.
    fn replace(doc: &XmlDoc, seg: usize, find: &str, with: &str) -> Result<Option<Vec<u8>>> {
        let start = texts(doc)[seg]
            .find(find)
            .ok_or(Error::Xml("no such text".into()))?;
        let mut reps = vec![Vec::new(); doc.len()];
        reps[seg] = vec![rep(start, start + find.len(), with)];
        doc.rebuild(&reps)
    }

    const WORD: &str = concat!(
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<w:document xmlns:w="urn:w"><w:body>"#,
        "<w:p><w:r><w:t>Bel 06-12</w:t></w:r><w:r><w:t>34 5678 nu</w:t></w:r></w:p>",
        "<w:p><w:r><w:t>Tweede</w:t></w:r></w:p>",
        "</w:body></w:document>",
    );

    #[test]
    fn split_runs_are_one_segment() -> TestResult {
        let doc = segments(WORD.as_bytes().to_vec(), Attrs::None)?;
        assert_eq!(texts(&doc), ["Bel 06-1234 5678 nu", "Tweede"]);
        Ok(())
    }

    #[test]
    fn replacement_spans_runs_and_keeps_the_rest_byte_identical() -> TestResult {
        let doc = segments(WORD.as_bytes().to_vec(), Attrs::None)?;
        let out = replace(&doc, 0, "06-1234 5678", "0698765432")?.ok_or("no change")?;
        let expected = WORD
            .replace("<w:t>Bel 06-12</w:t>", "<w:t>Bel 0698765432</w:t>")
            .replace("<w:t>34 5678 nu</w:t>", "<w:t> nu</w:t>");
        assert_eq!(String::from_utf8(out)?, expected);
        Ok(())
    }

    #[test]
    fn untouched_documents_rebuild_to_none() -> TestResult {
        let doc = segments(WORD.as_bytes().to_vec(), Attrs::None)?;
        assert!(doc.rebuild(&vec![Vec::new(); doc.len()])?.is_none());
        Ok(())
    }

    #[test]
    fn several_replacements_in_one_event() -> TestResult {
        let xml = "<p>a 111 b 222 c</p>";
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let reps = vec![vec![rep(2, 5, "X"), rep(8, 11, "YYYY")]];
        let out = doc.rebuild(&reps)?.ok_or("no change")?;
        assert_eq!(String::from_utf8(out)?, "<p>a X b YYYY c</p>");
        Ok(())
    }

    #[test]
    fn entities_and_cdata_read_as_text_and_survive_when_untouched() -> TestResult {
        let xml =
            "<w:p><w:t>mail a&amp;b</w:t><w:t><![CDATA[ jan@x.nl]]> ok &#64; &lt;</w:t></w:p>";
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        assert_eq!(texts(&doc), ["mail a&b jan@x.nl ok @ <"]);
        // Replace the address: the CDATA keeps its leading space as escaped text,
        // everything after stays byte-identical.
        let out = replace(&doc, 0, "jan@x.nl", "pro@xy.nl")?.ok_or("no change")?;
        assert_eq!(
            String::from_utf8(out)?,
            "<w:p><w:t>mail a&amp;b</w:t><w:t> pro@xy.nl ok &#64; &lt;</w:t></w:p>"
        );
        Ok(())
    }

    #[test]
    fn replacement_over_an_entity_drops_it_whole() -> TestResult {
        let xml = "<p>pw: a&amp;b!</p>";
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        assert_eq!(texts(&doc), ["pw: a&b!"]);
        let out = replace(&doc, 0, "a&b", "q<z")?.ok_or("no change")?;
        assert_eq!(String::from_utf8(out)?, "<p>pw: q&lt;z!</p>");
        Ok(())
    }

    #[test]
    fn breaks_and_nested_containers_separate_text() -> TestResult {
        let xml = concat!(
            "<text:p>Tel<text:tab/>0612345678<text:line-break/>x",
            "<text:note><text:p>voet</text:p></text:note>y</text:p>",
        );
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        assert_eq!(texts(&doc), ["Tel\n0612345678\nx\nvoet\ny"]);
        Ok(())
    }

    #[test]
    fn replacement_next_to_a_break_leaves_the_break_alone() -> TestResult {
        let xml = "<text:p>Tel<text:tab/>0612345678</text:p>";
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let out = replace(&doc, 0, "0612345678", "0687654321")?.ok_or("no change")?;
        assert_eq!(
            String::from_utf8(out)?,
            "<text:p>Tel<text:tab/>0687654321</text:p>"
        );
        Ok(())
    }

    #[test]
    fn text_outside_containers_is_one_segment_per_run() -> TestResult {
        let xml = "<cp><dc:creator>jan@x.nl</dc:creator><dc:title>  </dc:title><v>a&amp;b</v></cp>";
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        assert_eq!(texts(&doc), ["jan@x.nl", "a&b"]);
        Ok(())
    }

    #[test]
    fn field_instructions_are_separate_segments() -> TestResult {
        let xml = concat!(
            "<w:p><w:r><w:t>See </w:t></w:r>",
            r#"<w:r><w:instrText> HYPERLINK "mailto:jan@x.nl" </w:instrText></w:r>"#,
            "<w:r><w:t>jan@x.nl</w:t></w:r></w:p>",
        );
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        assert_eq!(
            texts(&doc),
            [r#" HYPERLINK "mailto:jan@x.nl" "#, "See jan@x.nl"]
        );
        let out = replace(&doc, 0, "jan@x.nl", "pro@xy.nl")?.ok_or("no change")?;
        assert_eq!(
            String::from_utf8(out)?,
            xml.replace("mailto:jan@x.nl", "mailto:pro@xy.nl")
        );
        Ok(())
    }

    #[test]
    fn relationship_targets_are_segments() -> TestResult {
        let xml = concat!(
            r#"<Relationships><Relationship Id="rId1" Type="t" "#,
            r#"Target="mailto:jan@x.nl?subject=a&amp;b" TargetMode="External"/>"#,
            r#"<Relationship Id="rId2" Target='media/image1.png'/></Relationships>"#,
        );
        let doc = segments(xml.as_bytes().to_vec(), Attrs::Target)?;
        assert_eq!(
            texts(&doc),
            ["mailto:jan@x.nl?subject=a&b", "media/image1.png"]
        );
        let out = replace(&doc, 0, "jan@x.nl", "pro@xy.nl")?.ok_or("no change")?;
        assert_eq!(
            String::from_utf8(out)?,
            xml.replace("jan@x.nl", "pro@xy.nl")
        );
        // Without the attribute scope the same part has no segments.
        assert_eq!(segments(xml.as_bytes().to_vec(), Attrs::None)?.len(), 0);
        Ok(())
    }

    #[test]
    fn odf_links_are_segments_and_quotes_are_escaped() -> TestResult {
        let xml = r#"<text:p><text:a xlink:href="mailto:jan@x.nl">link</text:a></text:p>"#;
        let doc = segments(xml.as_bytes().to_vec(), Attrs::Href)?;
        assert_eq!(texts(&doc), ["mailto:jan@x.nl", "link"]);
        let out = replace(&doc, 0, "jan@x.nl", r#"a"b@x.nl"#)?.ok_or("no change")?;
        assert_eq!(
            String::from_utf8(out)?,
            r#"<text:p><text:a xlink:href="mailto:a&quot;b@x.nl">link</text:a></text:p>"#
        );
        Ok(())
    }

    #[test]
    fn utf16_and_utf8_bom_parts_are_written_back_the_same_way() -> TestResult {
        let xml = "<p>mail jan@x.nl</p>";
        let mut le = vec![0xFF, 0xFE];
        le.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let doc = segments(le, Attrs::None)?;
        let out = replace(&doc, 0, "jan@x.nl", "pro@xy.nl")?.ok_or("no change")?;
        let mut expected = vec![0xFF, 0xFE];
        expected.extend(
            "<p>mail pro@xy.nl</p>"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        assert_eq!(out, expected);

        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(xml.as_bytes());
        let doc = segments(bom, Attrs::None)?;
        let out = replace(&doc, 0, "jan@x.nl", "pro@xy.nl")?.ok_or("no change")?;
        let mut expected = vec![0xEF, 0xBB, 0xBF];
        expected.extend_from_slice(b"<p>mail pro@xy.nl</p>");
        assert_eq!(out, expected);
        Ok(())
    }

    fn utf16(text: &str, bom: &[u8], unit: fn(u16) -> [u8; 2]) -> Vec<u8> {
        let mut out = bom.to_vec();
        out.extend(text.encode_utf16().flat_map(unit));
        out
    }

    #[test]
    fn utf16_parts_without_a_bom_are_read_as_utf16_and_written_back_the_same() -> TestResult {
        // The XML specification detects UTF-16 by `<` as a 16-bit unit. Read as UTF-8 the part
        // would be text with a NUL between its letters, and nothing in it would be found.
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?><p>mail jan@x.nl</p>"#;
        let masked = xml.replace("jan@x.nl", "pro@xy.nl");
        for unit in [u16::to_le_bytes, u16::to_be_bytes] {
            let doc = segments(utf16(xml, &[], unit), Attrs::None)?;
            assert_eq!(texts(&doc), ["mail jan@x.nl"]);
            let out = replace(&doc, 0, "jan@x.nl", "pro@xy.nl")?.ok_or("no change")?;
            assert_eq!(out, utf16(&masked, &[], unit));
        }
        Ok(())
    }

    #[test]
    fn a_second_byte_order_mark_is_refused_not_misread() {
        // The reader skips a mark at the start without counting its bytes: every offset after
        // it would be three bytes off and a replacement would cut the wrong text.
        let mut utf8 = vec![0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF];
        utf8.extend_from_slice(b"<p>jan@x.nl</p>");
        let wide = utf16("\u{feff}<p>jan@x.nl</p>", &[0xFF, 0xFE], u16::to_le_bytes);
        for part in [utf8, wide] {
            assert!(matches!(
                segments(part, Attrs::None),
                Err(Error::Xml(m)) if m.contains("byte order mark")
            ));
        }
    }

    #[test]
    fn a_nul_that_is_no_utf16_and_utf32_are_refused_by_name() {
        assert!(matches!(
            segments(b"<p>jan@x.nl\0</p>".to_vec(), Attrs::None),
            Err(Error::Xml(m)) if m.contains("NUL")
        ));
        // A part that starts like UTF-16 but cannot be read as such is not read as UTF-8.
        assert!(matches!(
            segments(b"<\0p\0>\0x".to_vec(), Attrs::None),
            Err(Error::Xml(_))
        ));
        let utf32 = [
            0xFF, 0xFE, 0, 0, b'<', 0, 0, 0, b'p', 0, 0, 0, b'>', 0, 0, 0,
        ];
        assert!(matches!(
            segments(utf32.to_vec(), Attrs::None),
            Err(Error::Xml(m)) if m.contains("UTF-32")
        ));
    }

    #[test]
    fn malformed_xml_is_an_error() {
        assert!(matches!(
            segments(b"<p>a</q>".to_vec(), Attrs::None),
            Err(Error::Xml(_))
        ));
        assert!(matches!(
            segments(b"<p>\xFF\xFE</p>".to_vec(), Attrs::None),
            Err(Error::Xml(_))
        ));
    }

    #[test]
    fn event_offsets_cover_the_source_exactly() -> TestResult {
        // Replacing each part's text by itself must reproduce the source: it
        // proves every part's range starts and ends where its event does.
        let doc = segments(WORD.as_bytes().to_vec(), Attrs::None)?;
        let reps = vec![
            vec![rep(0, 9, "Bel 06-12"), rep(9, 19, "34 5678 nu")],
            vec![rep(0, 6, "Tweede")],
        ];
        let out = doc.rebuild(&reps)?.ok_or("no change")?;
        assert_eq!(String::from_utf8(out)?, WORD);
        Ok(())
    }

    /// Every kind of event, in awkward places.
    const KITCHEN_SINK: &str = concat!(
        r#"<?xml version="1.0"?><!DOCTYPE doc [<!ENTITY co "Acme">]><!-- c --><?pi data?>"#,
        "<doc a='x>y'>\r\n ",
        "<w:p>one &amp; two<!-- mid -->three<![CDATA[four <b>]]>&#x41;&co;<w:br/>five<w:t/>six</w:p>",
        "<x>plain &lt;text&gt;</x><y a=\"1\"/>trailing\n</doc>",
    );

    #[test]
    fn every_part_maps_to_exactly_its_event_bytes() -> TestResult {
        let doc = segments(KITCHEN_SINK.as_bytes().to_vec(), Attrs::None)?;
        assert!(!doc.segs.is_empty());
        for seg in &doc.segs {
            let text = &doc.buf[seg.text.clone()];
            let mut next = 0;
            for part in &doc.parts[seg.parts.clone()] {
                // The parts tile the segment text.
                assert_eq!(part.off, next);
                next += part.len;
                let own = &text.as_bytes()[part.off..part.off + part.len];
                let src = &doc.src[part.src.clone()];
                match part.kind {
                    Kind::Text => assert_eq!(src, own),
                    Kind::CData => {
                        assert!(src.starts_with(b"<![CDATA[") && src.ends_with(b"]]>"));
                        assert_eq!(&src[9..src.len() - 3], own);
                    }
                    Kind::Ref => assert!(src.starts_with(b"&") && src.ends_with(b";")),
                    Kind::Break => assert!(src.is_empty() && own == b"\n"),
                }
            }
            assert_eq!(next, text.len());
        }
        // The paragraph: the unknown entity `&co;` and the `<w:br/>` read as breaks.
        assert_eq!(
            texts(&doc),
            [
                "one & twothreefour <b>A\n\nfivesix",
                "plain <text>",
                "trailing\n"
            ]
        );
        Ok(())
    }
}
