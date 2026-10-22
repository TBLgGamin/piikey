//! Zip packages (OOXML, ODF): the XML parts are rewritten, the preview picture
//! is blanked, and the packages an OOXML package embeds are rewritten the same way.
//!
//! What is read: every XML part (`.xml`, and the `.rels` relationship parts of OOXML, whose
//! `Target` values are read), and every entry of an OOXML `embeddings` folder that is itself
//! a package piikey reads (a chart's workbook, an embedded document): those go through the
//! same pass one level deeper, so a chart masked in the document does not keep its values in
//! the workbook behind it. What is not read: pictures and other binary objects (OLE `.bin`,
//! fonts, media), and anything in an `embeddings` folder that is not such a package. They are
//! copied through.
//!
//! The XML parts are read and scanned in parallel, one engine call covers every segment of
//! the package, and the changed parts are rebuilt and compressed in parallel. The embedded
//! packages follow one at a time, in entry order, so a scan reports the values of the
//! package itself before those of what it embeds. The output keeps the original entry order;
//! entries without changes are copied compressed, byte for byte.
//!
//! A scan that is asked for findings also says which cell of a workbook or of an `OpenDocument`
//! sheet each text is in. Once the engine has found the values, the parts of the sheets are
//! walked again, for the texts that hold one and no others (`sheets.rs`, `ooxml::places`,
//! `odf::places`); what lies in an embedded package has no place.

use std::{
    collections::HashMap,
    io::{Cursor, Read, Write},
};

use rayon::prelude::*;
use zip::{
    ZipArchive, ZipWriter,
    write::{PreparedZipFile, ZipFileBuilder},
};

use super::{
    Output, Pass, odf, ooxml, open_package,
    places::Layout,
    process_pass,
    sheets::Docs,
    thumbnail,
    xmltext::{Attrs, XmlDoc, segments},
};
use crate::{Error, Result, engine::Replacement};

/// A package read from memory.
pub(super) type Archive<'a> = ZipArchive<Cursor<&'a [u8]>>;

/// Decides per entry name whether it is an XML part, and which attribute
/// values of it hold text.
pub(super) type Scope = fn(&str) -> Option<Attrs>;

/// The most the XML parts and embedded packages of one package may unpack to together, in
/// bytes. All of them are held at once (an XML part as source, text, and a record of where each
/// piece of text came from, several times its size), and the inventory reads many files at a
/// time: a package that unpacks to more is refused before anything is read, instead of taking
/// the process down.
const MAX_XML: u64 = 256 << 20;

/// The zip local file header signature, which every package starts with.
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

/// Opens `bytes` as a zip archive.
pub(super) fn open(bytes: &[u8]) -> Result<Archive<'_>> {
    Ok(ZipArchive::new(Cursor::new(bytes))?)
}

/// Anonymizes or deanonymizes every XML part of `archive` and every package it embeds,
/// returning the new package (the original bytes when nothing changes). A package that
/// changes loses its preview picture. A scan reads the same segments and returns nothing.
/// `depth` is the nesting level of `archive`; the packages it embeds are one deeper.
///
/// # Errors
/// `Zip` when the XML parts and embedded packages declare more than [`MAX_XML`] together;
/// whatever an embedded package fails with, including `UnsupportedFormat` once the nesting
/// is too deep: a package that cannot be read whole is never passed over.
pub(super) fn rewrite(
    pass: &Pass<'_>,
    mut archive: Archive<'_>,
    scope: Scope,
    depth: u8,
) -> Result<Vec<u8>> {
    let office = ooxml::matches(&archive);
    let Parts { xml, packages } = parts(&archive, scope, office, MAX_XML)?;
    let docs = read_docs(&archive, &xml)?;
    let texts: Vec<&str> = docs.iter().flat_map(|(_, doc)| doc.texts()).collect();
    let plans = if texts.is_empty() {
        Vec::new()
    } else {
        // Only the package itself has places, and only for the findings of a scan.
        let book = pass.wants_places(depth).then(|| Docs::new(&archive, &docs));
        let locate = |wanted: &[usize]| {
            book.as_ref().map_or_else(Vec::new, |book| {
                if office {
                    ooxml::places(book, wanted)
                } else {
                    odf::places(book, wanted)
                }
            })
        };
        let layout = if book.is_some() {
            Layout::Texts(&locate)
        } else {
            Layout::Nowhere
        };
        pass.plan(&layout, &texts)?
    };

    let mut jobs: Vec<(usize, &XmlDoc, &[Vec<Replacement>])> = Vec::new();
    let mut rest = plans.as_slice();
    for (index, doc) in &docs {
        let (mine, tail) = rest
            .split_at_checked(doc.len())
            .ok_or_else(|| Error::Xml("engine returned fewer plans than segments".into()))?;
        rest = tail;
        if mine.iter().any(|reps| !reps.is_empty()) {
            jobs.push((*index, doc, mine));
        }
    }

    let original = archive.clone().into_inner().into_inner();
    let mut prepared: HashMap<usize, PreparedZipFile> = jobs
        .par_iter()
        .map_init(
            || archive.clone(),
            |ar, &(index, doc, reps)| compress(ar, index, doc, reps),
        )
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let mut changed = !jobs.is_empty();
    // Embedded packages come after the package's own parts, so a scan reports in reading order.
    for index in packages {
        if let Some(file) = rewrite_embedded(pass, &mut archive, index, depth)? {
            prepared.insert(index, file);
            changed = true;
        }
    }
    if !changed {
        return Ok(pass.unchanged(original));
    }
    // The preview picture shows the page as it was before masking.
    for index in 0..archive.len() {
        let blank = archive
            .name_for_index(index)
            .transpose()?
            .and_then(|name| thumbnail::blank(&name));
        if let Some(blank) = blank {
            prepared.insert(index, replace(&mut archive, index, blank)?);
        }
    }

    let mut out = ZipWriter::new(Cursor::new(Vec::with_capacity(original.len())));
    out.set_raw_comment(archive.comment().into())?;
    for index in 0..archive.len() {
        match prepared.remove(&index) {
            Some(file) => out.add_prepared_file(file)?,
            None => out.raw_copy_file(archive.by_index_raw(index)?)?,
        }
    }
    Ok(out.finish()?.into_inner())
}

/// Runs the embedded package at `index` through the pass, one level below `depth`; the entry
/// rebuilt with the result, or `None` when the pass changed nothing (always for a scan, which
/// has no output).
fn rewrite_embedded(
    pass: &Pass<'_>,
    archive: &mut Archive<'_>,
    index: usize,
    depth: u8,
) -> Result<Option<PreparedZipFile>> {
    let mut file = archive.by_index(index)?;
    let name = file.name()?.into_owned();
    // The declared size bounds this (see `parts`).
    let mut bytes = Vec::with_capacity(usize::try_from(file.size()).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::Zip(format!("{name}: {e}")))?;
    drop(file);
    // A zip that is neither OOXML nor ODF is a binary object like any other.
    match open_package(&bytes) {
        Ok(_) => {}
        Err(Error::UnsupportedFormat("zip archive")) => return Ok(None),
        Err(e) => return Err(in_part(&name, e)),
    }
    match process_pass(pass, &bytes, depth.saturating_add(1)).map_err(|e| in_part(&name, e))? {
        Output::Same(new) if !new.is_empty() && new != bytes => {
            Ok(Some(replace(archive, index, &new)?))
        }
        Output::Same(_) => Ok(None),
        Output::Text(_) => Err(Error::Zip(format!("{name}: an embedded package gave text"))),
    }
}

/// All segment texts of the package's XML parts, one per line.
pub(super) fn texts(archive: &Archive<'_>, scope: Scope) -> Result<String> {
    let docs = read_docs(archive, &parts(archive, scope, false, MAX_XML)?.xml)?;
    let mut out = String::new();
    for text in docs.iter().flat_map(|(_, doc)| doc.texts()) {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(text);
    }
    Ok(out)
}

/// The entries of a package that are read, by entry index, in entry order.
#[derive(Debug)]
struct Parts {
    /// XML parts, with the attributes that hold text.
    xml: Vec<(usize, Attrs)>,
    /// Embedded packages.
    packages: Vec<usize>,
}

/// The XML parts of `archive` and, with `embedded`, its embedded packages: entries of an
/// `embeddings` folder that start with the zip magic.
///
/// The sizes are the ones the archive declares. Reading an entry fails once it yields more
/// than it declared, so their sum bounds what reading the entries can allocate. Only the
/// first bytes of an `embeddings` entry are read here, to see whether it is a zip.
///
/// # Errors
/// `Zip` when the entries declare more than `limit` bytes together.
fn parts(archive: &Archive<'_>, scope: Scope, embedded: bool, limit: u64) -> Result<Parts> {
    let mut found = Parts {
        xml: Vec::new(),
        packages: Vec::new(),
    };
    let mut total = 0_u64;
    let mut peek = archive.clone();
    for index in 0..archive.len() {
        let entry = archive.by_index_data(index)?;
        let name = entry.name()?;
        if let Some(attrs) = scope(&name) {
            total = total.saturating_add(entry.size());
            found.xml.push((index, attrs));
        } else if embedded && entry.size() > 0 && ooxml::in_embeddings(&name) {
            let mut magic = Vec::with_capacity(ZIP_MAGIC.len());
            peek.by_index(index)?
                .take(ZIP_MAGIC.len() as u64)
                .read_to_end(&mut magic)
                .map_err(|e| Error::Zip(format!("{name}: {e}")))?;
            if magic == ZIP_MAGIC {
                total = total.saturating_add(entry.size());
                found.packages.push(index);
            }
        }
    }
    if total > limit {
        return Err(Error::Zip(format!(
            "the XML parts and embedded packages unpack to {} MiB, more than the {} MiB that is read",
            total.div_ceil(1 << 20),
            limit >> 20,
        )));
    }
    Ok(found)
}

/// Reads and scans the XML parts `xml`, in parallel; `(entry index, document)` in entry order.
fn read_docs(archive: &Archive<'_>, xml: &[(usize, Attrs)]) -> Result<Vec<(usize, XmlDoc)>> {
    xml.par_iter()
        .map_init(
            || archive.clone(),
            |ar, &(index, attrs)| {
                let mut file = ar.by_index(index)?;
                let name = file.name()?.into_owned();
                let mut bytes = Vec::with_capacity(usize::try_from(file.size()).unwrap_or(0));
                file.read_to_end(&mut bytes)
                    .map_err(|e| Error::Zip(format!("{name}: {e}")))?;
                segments(bytes, attrs)
                    .map(|doc| (index, doc))
                    .map_err(|e| in_part(&name, e))
            },
        )
        .collect()
}

/// Rebuilds the part at `index` and compresses it with its original method,
/// timestamp and attributes; `None` when `reps` change nothing.
fn compress(
    archive: &mut Archive<'_>,
    index: usize,
    doc: &XmlDoc,
    reps: &[Vec<Replacement>],
) -> Result<Option<(usize, PreparedZipFile)>> {
    let Some(bytes) = doc.rebuild(reps)? else {
        return Ok(None);
    };
    Ok(Some((index, replace(archive, index, &bytes)?)))
}

/// `bytes` as the new content of the entry at `index`, compressed with the entry's method and
/// carrying its name, timestamp and attributes.
fn replace(archive: &mut Archive<'_>, index: usize, bytes: &[u8]) -> Result<PreparedZipFile> {
    let entry = archive.by_index_raw(index)?;
    let mut builder = ZipFileBuilder::new(entry.name()?, entry.options())?;
    builder.write_all(bytes)?;
    Ok(builder.finish()?)
}

/// Names the package part an XML error came from.
fn in_part(name: &str, error: Error) -> Error {
    match error {
        Error::Xml(message) => Error::Xml(format!("{name}: {message}")),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use zip::{CompressionMethod, write::SimpleFileOptions};

    use super::*;
    use crate::{
        detect::Mode,
        formats::{MAX_DEPTH, ooxml, process, scan},
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn zip_of(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for &(name, bytes) in entries {
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zip.start_file(name, options)?;
            zip.write_all(bytes)?;
        }
        Ok(zip.finish()?.into_inner())
    }

    /// An XML part of `len` bytes that packs to next to nothing.
    fn part(len: usize) -> Vec<u8> {
        let mut xml = b"<w:p>".to_vec();
        xml.resize(len - "</w:p>".len(), b'a');
        xml.extend_from_slice(b"</w:p>");
        xml
    }

    /// Reads the XML parts of `archive` under `limit`, counting its embedded packages too.
    fn docs(archive: &Archive<'_>, scope: Scope, limit: u64) -> Result<Vec<(usize, XmlDoc)>> {
        read_docs(archive, &parts(archive, scope, true, limit)?.xml)
    }

    fn refused<T: std::fmt::Debug>(result: Result<T>) -> std::result::Result<String, String> {
        match result {
            Err(Error::Zip(message)) => Ok(message),
            other => Err(format!("expected a zip error, got {other:?}")),
        }
    }

    #[test]
    fn the_xml_parts_may_unpack_to_the_limit_and_no_further() -> TestResult {
        let one = part(1 << 20);
        let picture = vec![0_u8; 1 << 20];
        let bytes = zip_of(&[
            ("word/document.xml", &one),
            ("word/media/image1.png", &picture),
        ])?;
        let archive = open(&bytes)?;
        let size = one.len() as u64;
        // The picture is as big as the part but is not XML: it does not count.
        assert_eq!(docs(&archive, ooxml::scope, size)?.len(), 1);
        let message = refused(docs(&archive, ooxml::scope, size - 1))?;
        assert!(message.contains("XML parts"), "{message}");

        // Several parts count together.
        let half = part(600 << 10);
        let bytes = zip_of(&[("word/a.xml", &half), ("word/b.xml", &half)])?;
        let archive = open(&bytes)?;
        assert_eq!(docs(&archive, ooxml::scope, 1200 << 10)?.len(), 2);
        refused(docs(&archive, ooxml::scope, 1 << 20))?;
        Ok(())
    }

    #[test]
    fn a_part_cannot_unpack_to_more_than_it_declares() -> TestResult {
        // The declared sizes are what the limit counts, so reading must stop at them.
        let xml = part(1 << 20);
        let mut bytes = zip_of(&[("word/document.xml", &xml)])?;
        let entry = bytes
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .ok_or("no central directory")?;
        // Uncompressed size, in the central directory entry.
        bytes[entry + 24..entry + 28].copy_from_slice(&100_u32.to_le_bytes());
        let archive = open(&bytes)?;
        let message = refused(docs(&archive, ooxml::scope, MAX_XML))?;
        assert!(message.starts_with("word/document.xml: "), "{message}");
        Ok(())
    }

    // -- embedded packages -------------------------------------------------------

    const EMAIL: &str = "jan.jansen@example.org";
    const INNER_EMAIL: &str = "piet.pieters@example.net";
    const CONTENT_TYPES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?><Types/>"#;
    const SHEET: &str = "xl/sharedStrings.xml";
    const DOCUMENT: &str = "word/document.xml";
    /// Where `wrap` puts the package it embeds.
    const EMBEDDED: &str = "word/embeddings/inner.docx";
    const STORED: CompressionMethod = CompressionMethod::Stored;
    const DEFLATED: CompressionMethod = CompressionMethod::Deflated;

    type Res<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    type Entry<'a> = (&'a str, &'a [u8], CompressionMethod);

    fn build(entries: &[Entry<'_>]) -> Res<Vec<u8>> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for &(name, bytes, method) in entries {
            zip.start_file(
                name,
                SimpleFileOptions::default().compression_method(method),
            )?;
            zip.write_all(bytes)?;
        }
        Ok(zip.finish()?.into_inner())
    }

    /// A workbook with one shared string that holds `email`.
    fn xlsx(email: &str) -> Res<Vec<u8>> {
        let strings = format!("<sst><si><t>mail {email}</t></si></sst>");
        build(&[
            ("[Content_Types].xml", CONTENT_TYPES, DEFLATED),
            (SHEET, strings.as_bytes(), DEFLATED),
        ])
    }

    /// A document that says `EMAIL`, with `embedded` entries after its own.
    fn docx_with(embedded: &[Entry<'_>]) -> Res<Vec<u8>> {
        let document =
            format!("<w:document><w:p><w:r><w:t>mail {EMAIL}</w:t></w:r></w:p></w:document>");
        let mut entries: Vec<Entry<'_>> = vec![
            ("[Content_Types].xml", CONTENT_TYPES, DEFLATED),
            (DOCUMENT, document.as_bytes(), DEFLATED),
        ];
        entries.extend_from_slice(embedded);
        build(&entries)
    }

    /// `inner` as the only embedded package of a new package.
    fn wrap(inner: &[u8]) -> Res<Vec<u8>> {
        build(&[
            ("[Content_Types].xml", CONTENT_TYPES, DEFLATED),
            (EMBEDDED, inner, STORED),
        ])
    }

    /// A workbook holding `INNER_EMAIL`, `levels` packages down.
    fn nested(levels: usize) -> Res<Vec<u8>> {
        let mut bytes = xlsx(INNER_EMAIL)?;
        for _ in 0..levels {
            bytes = wrap(&bytes)?;
        }
        Ok(bytes)
    }

    /// The workbook of `nested(levels)`, taken out of `bytes`.
    fn innermost(mut bytes: Vec<u8>, levels: usize) -> Res<Vec<u8>> {
        for _ in 0..levels {
            bytes = entry(&bytes, EMBEDDED)?;
        }
        Ok(bytes)
    }

    fn entry(zip: &[u8], name: &str) -> Res<Vec<u8>> {
        let mut bytes = Vec::new();
        open(zip)?.by_name(name)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// What an entry is stored as: compressed bytes and method.
    fn raw(zip: &[u8], name: &str) -> Res<(Vec<u8>, CompressionMethod)> {
        let mut archive = open(zip)?;
        let index = archive.index_for_name(name).ok_or("missing entry")?;
        let mut file = archive.by_index_raw(index)?;
        let method = file.compression();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok((bytes, method))
    }

    fn names(zip: &[u8]) -> Res<Vec<String>> {
        let archive = open(zip)?;
        let mut names = Vec::new();
        for name in archive.file_names() {
            names.push(name?.into_owned());
        }
        Ok(names)
    }

    fn engine() -> Res<crate::engine::Engine> {
        Ok(crate::engine::Engine::open(
            &crate::testing::temp_dir("package").join("vault.pkv"),
        )?)
    }

    fn same(engine: &crate::engine::Engine, mode: Mode, bytes: &[u8]) -> Res<Vec<u8>> {
        match process(engine, mode, bytes, 0)? {
            Output::Same(bytes) => Ok(bytes),
            Output::Text(_) => Err("expected a rewritten file, got text".into()),
        }
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn an_embedded_package_is_masked_and_restored_with_its_host() -> TestResult {
        let engine = engine()?;
        let workbook = xlsx(INNER_EMAIL)?;
        let note = format!("mail {INNER_EMAIL}");
        let not_a_package = zip_of(&[("note.txt", note.as_bytes())])?;
        let picture = [b"\x89PNG\r\n\x1a\n".as_slice(), note.as_bytes()].concat();
        let ole = [
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".as_slice(),
            note.as_bytes(),
        ]
        .concat();
        let original = docx_with(&[
            (
                "word/embeddings/Microsoft_Excel_Sheet1.xlsx",
                &workbook,
                STORED,
            ),
            ("word/embeddings/image1.png", &picture, DEFLATED),
            ("word/embeddings/oleObject1.bin", &ole, STORED),
            ("word/embeddings/archive.zip", &not_a_package, STORED),
        ])?;

        let masked = same(&engine, Mode::Anonymize, &original)?;
        assert_eq!(names(&masked)?, names(&original)?);
        assert!(!text(&entry(&masked, DOCUMENT)?).contains(EMAIL));
        let sheet = "word/embeddings/Microsoft_Excel_Sheet1.xlsx";
        let inner = entry(&masked, sheet)?;
        assert!(!text(&entry(&inner, SHEET)?).contains(INNER_EMAIL));
        assert_eq!(raw(&masked, sheet)?.1, STORED);
        // Everything that is not a package is copied, whatever its bytes say.
        for name in [
            "word/embeddings/image1.png",
            "word/embeddings/oleObject1.bin",
            "word/embeddings/archive.zip",
        ] {
            assert_eq!(raw(&masked, name)?, raw(&original, name)?, "{name}");
        }

        let restored = same(&engine, Mode::Deanonymize, &masked)?;
        assert_eq!(entry(&restored, DOCUMENT)?, entry(&original, DOCUMENT)?);
        assert_eq!(
            entry(&entry(&restored, sheet)?, SHEET)?,
            entry(&workbook, SHEET)?
        );
        Ok(())
    }

    #[test]
    fn a_scan_reports_the_package_before_what_it_embeds() -> TestResult {
        let engine = engine()?;
        let workbook = xlsx(INNER_EMAIL)?;
        let original = docx_with(&[("word/embeddings/Sheet1.xlsx", &workbook, STORED)])?;
        let found = scan(&engine, &original, false)?.found;
        let values: Vec<&str> = found.iter().map(|(_, value)| &**value).collect();
        assert_eq!(values, [EMAIL, INNER_EMAIL]);
        Ok(())
    }

    #[test]
    fn packages_inside_packages_work_down_to_the_depth_limit_and_fail_beyond() -> TestResult {
        let engine = engine()?;
        let deepest = usize::from(MAX_DEPTH);
        for levels in [3, deepest] {
            let original = nested(levels)?;
            let masked = same(&engine, Mode::Anonymize, &original)?;
            let sheet = entry(&innermost(masked.clone(), levels)?, SHEET)?;
            assert!(!text(&sheet).contains(INNER_EMAIL), "{levels} deep");
            let restored = same(&engine, Mode::Deanonymize, &masked)?;
            assert_eq!(
                entry(&innermost(restored, levels)?, SHEET)?,
                entry(&innermost(original, levels)?, SHEET)?,
                "{levels} deep"
            );
        }

        // One more is an error for the whole document, never a package left as it was.
        let too_deep = nested(deepest + 1)?;
        assert!(matches!(
            process(&engine, Mode::Anonymize, &too_deep, 0),
            Err(Error::UnsupportedFormat("nesting too deep"))
        ));
        assert!(matches!(
            scan(&engine, &too_deep, false),
            Err(Error::UnsupportedFormat("nesting too deep"))
        ));
        Ok(())
    }

    #[test]
    fn the_embedded_packages_count_towards_the_limit() -> TestResult {
        let workbook = xlsx(INNER_EMAIL)?;
        let document = part(1000);
        let picture = vec![0_u8; 1 << 20];
        let bytes = build(&[
            ("[Content_Types].xml", CONTENT_TYPES, DEFLATED),
            (DOCUMENT, &document, DEFLATED),
            ("word/embeddings/Sheet1.xlsx", &workbook, STORED),
            ("word/embeddings/image1.png", &picture, DEFLATED),
        ])?;
        let archive = open(&bytes)?;
        let xml = (CONTENT_TYPES.len() + document.len()) as u64;
        let total = xml + workbook.len() as u64;

        // The picture is as big as a megabyte but is not a package: it does not count.
        let found = parts(&archive, ooxml::scope, true, total)?;
        assert_eq!((found.xml.len(), found.packages.len()), (2, 1));
        let message = refused(parts(&archive, ooxml::scope, true, total - 1))?;
        assert!(message.contains("embedded packages"), "{message}");
        // Without packages to read the same limit is generous.
        assert!(
            parts(&archive, ooxml::scope, false, xml)?
                .packages
                .is_empty()
        );
        Ok(())
    }
}
