//! End-to-end tests: every format against a real engine and a temporary vault.
//! Fixtures are built in code.

use std::{
    fmt::Write as _,
    io::{Cursor, Read, Write},
    sync::{Mutex, PoisonError},
};

use cfb::CompoundFile;
use lopdf::{
    Dictionary, Document, Object, Stream,
    content::{Content, Operation},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use super::{
    Busy, Finding, Format, Location, Output, Report, Scanned, finding, msg, package, process,
    restore, same_text, scan, sniff,
};
use crate::{
    Error,
    detect::{EntityKind, Mode, Span},
    engine::Engine,
    restore::Restorer,
};

type Res<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const EMAIL: &str = "jan.jansen@example.org";
const MOBILE: &str = "+31 6 12345678";
const IBAN: &str = "NL91ABNA0417164300";
/// A Dutch number as Word stores it when formatting splits it over two runs.
const PHONE: &str = "06-1234 5678";

fn engine() -> Res<Engine> {
    Ok(Engine::open(
        &crate::testing::temp_dir("formats").join("vault.pkv"),
    )?)
}

/// What a read of the findings of `bytes` reports, in the order it reports it.
fn reports(engine: &Engine, bytes: &[u8]) -> crate::Result<Vec<Report>> {
    let seen = Mutex::new(Vec::new());
    super::findings(engine, bytes, &|report| {
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(report);
        true
    })?;
    Ok(seen.into_inner().unwrap_or_else(PoisonError::into_inner))
}

/// Every finding of `bytes`, in the order the read reports them.
fn findings(engine: &Engine, bytes: &[u8]) -> crate::Result<Vec<Finding>> {
    Ok(reports(engine, bytes)?
        .into_iter()
        .filter_map(|report| match report {
            Report::Found(list) => Some(list),
            Report::Busy(_) => None,
        })
        .flatten()
        .collect())
}

/// `process` expecting a rewritten file.
fn same(engine: &Engine, mode: Mode, bytes: &[u8]) -> Res<Vec<u8>> {
    match process(engine, mode, bytes, 0)? {
        Output::Same(bytes) => Ok(bytes),
        Output::Text(_) => Err("expected a rewritten file, got text".into()),
    }
}

/// `process` expecting extracted text.
fn text(engine: &Engine, mode: Mode, bytes: &[u8]) -> Res<String> {
    match process(engine, mode, bytes, 0)? {
        Output::Text(text) => Ok(text),
        Output::Same(_) => Err("expected text, got a rewritten file".into()),
    }
}

fn assert_absent(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !haystack.contains(needle),
            "{needle:?} leaked into {haystack:?}"
        );
    }
}

// -- fixtures ---------------------------------------------------------------

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Deterministic bytes that deflate poorly.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn build_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Res<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for &(name, bytes, method) in entries {
        if name.ends_with('/') {
            zip.add_directory(name, SimpleFileOptions::default())?;
        } else {
            zip.start_file(
                name,
                SimpleFileOptions::default().compression_method(method),
            )?;
            zip.write_all(bytes)?;
        }
    }
    Ok(zip.finish()?.into_inner())
}

const DEFLATED: CompressionMethod = CompressionMethod::Deflated;
const STORED: CompressionMethod = CompressionMethod::Stored;

const XML_HEAD: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#;

fn docx() -> Res<Vec<u8>> {
    let content_types = format!(
        "{XML_HEAD}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
         <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
         <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
         </Types>"
    );
    let root_rels = format!(
        "{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
         </Relationships>"
    );
    let document = format!(
        "{XML_HEAD}<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>\
         <w:p><w:r><w:t>Bel 06-12</w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>34 5678 of mail {EMAIL}</w:t></w:r></w:p>\
         <w:p><w:r><w:t>Zonder gegevens</w:t></w:r></w:p>\
         </w:body></w:document>"
    );
    let document_rels = format!(
        "{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"mailto:{EMAIL}\" TargetMode=\"External\"/>\
         </Relationships>"
    );
    let core = format!(
        "{XML_HEAD}<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator>{EMAIL}</dc:creator><dc:title>Offerte</dc:title></cp:coreProperties>"
    );
    let image = noise(4096);
    build_zip(&[
        ("[Content_Types].xml", content_types.as_bytes(), DEFLATED),
        ("_rels/.rels", root_rels.as_bytes(), DEFLATED),
        ("word/document.xml", document.as_bytes(), DEFLATED),
        (
            "word/_rels/document.xml.rels",
            document_rels.as_bytes(),
            DEFLATED,
        ),
        ("docProps/core.xml", core.as_bytes(), DEFLATED),
        ("word/media/image1.bin", &image, DEFLATED),
    ])
}

fn xlsx() -> Res<Vec<u8>> {
    let shared = format!(
        "{XML_HEAD}<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" count=\"3\" uniqueCount=\"3\">\
         <si><r><t>jan.jansen@</t></r><r><rPr><b/></rPr><t>example.org</t></r></si>\
         <si><t>{IBAN}</t></si><si><t>gewoon tekst</t></si></sst>"
    );
    let sheet = format!(
        "{XML_HEAD}<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
         <row r=\"1\"><c r=\"A1\" t=\"s\"><v>0</v></c><c r=\"B1\" t=\"inlineStr\"><is><t>{MOBILE}</t></is></c></row>\
         </sheetData></worksheet>"
    );
    build_zip(&[
        (
            "[Content_Types].xml",
            format!("{XML_HEAD}<Types/>").as_bytes(),
            DEFLATED,
        ),
        ("xl/sharedStrings.xml", shared.as_bytes(), DEFLATED),
        ("xl/worksheets/sheet1.xml", sheet.as_bytes(), DEFLATED),
    ])
}

/// The namespaces a presentation part names.
const PRESENTATION_NS: &str = "xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
     xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" \
     xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"";

/// `<p:sp>` showing `text`.
fn shape_with(text: &str) -> String {
    format!("<p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>")
}

/// A slide part with `shapes` in its shape tree.
fn slide_of(shapes: &str) -> String {
    format!(
        "{XML_HEAD}<p:sld {PRESENTATION_NS}><p:cSld><p:spTree><p:nvGrpSpPr/><p:grpSpPr/>{shapes}\
         </p:spTree></p:cSld></p:sld>"
    )
}

/// A relationships part with these `(id, type, target)`.
fn relationships_of(items: &[(&str, &str, &str)]) -> String {
    let list = items
        .iter()
        .fold(String::new(), |mut list, (id, kind, target)| {
            let _ = write!(
                list,
                "<Relationship Id=\"{id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}\" Target=\"{target}\"/>"
            );
            list
        });
    format!(
        "{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">{list}</Relationships>"
    )
}

/// A presentation of two slides whose parts are named the other way round: the slide that is
/// shown first is `slide2.xml`. It has a picture and then a shape with the address, and notes
/// with the IBAN. The slide that follows has a title and a table with the number in a cell. The
/// layout, the properties and the notes carry values too.
fn pptx() -> Res<Vec<u8>> {
    let presentation = format!(
        "{XML_HEAD}<p:presentation {PRESENTATION_NS}><p:sldMasterIdLst/><p:sldIdLst>\
         <p:sldId id=\"256\" r:id=\"rId2\"/><p:sldId id=\"257\" r:id=\"rId1\"/></p:sldIdLst></p:presentation>"
    );
    let presentation_rels = relationships_of(&[
        ("rId1", "slide", "slides/slide1.xml"),
        ("rId2", "slide", "slides/slide2.xml"),
        ("rId3", "slideMaster", "slideMasters/slideMaster1.xml"),
    ]);
    let second = slide_of(&format!(
        "{}<p:graphicFrame><a:tbl><a:tr><a:tc><a:txBody><a:p><a:r><a:t>Bel {MOBILE}</a:t></a:r></a:p></a:txBody></a:tc></a:tr></a:tbl></p:graphicFrame>",
        shape_with("Dag allemaal")
    ));
    let first = slide_of(&format!(
        "<p:pic><p:nvPicPr/></p:pic>{}",
        shape_with(&format!("Mail {EMAIL}"))
    ));
    let first_rels = relationships_of(&[
        ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
        ("rId2", "notesSlide", "../notesSlides/notesSlide1.xml"),
    ]);
    let notes = slide_of(&shape_with(&format!("Betaal {IBAN}")));
    let layout = slide_of(&shape_with(&format!("Vraag {EMAIL}")));
    let core = format!(
        "{XML_HEAD}<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator>{EMAIL}</dc:creator></cp:coreProperties>"
    );
    build_zip(&[
        (
            "[Content_Types].xml",
            format!("{XML_HEAD}<Types/>").as_bytes(),
            DEFLATED,
        ),
        ("ppt/presentation.xml", presentation.as_bytes(), DEFLATED),
        (
            "ppt/_rels/presentation.xml.rels",
            presentation_rels.as_bytes(),
            DEFLATED,
        ),
        ("ppt/slides/slide1.xml", second.as_bytes(), DEFLATED),
        ("ppt/slides/slide2.xml", first.as_bytes(), DEFLATED),
        (
            "ppt/slides/_rels/slide2.xml.rels",
            first_rels.as_bytes(),
            DEFLATED,
        ),
        (
            "ppt/notesSlides/notesSlide1.xml",
            notes.as_bytes(),
            DEFLATED,
        ),
        (
            "ppt/slideLayouts/slideLayout1.xml",
            layout.as_bytes(),
            DEFLATED,
        ),
        ("docProps/core.xml", core.as_bytes(), DEFLATED),
    ])
}

/// A document of five paragraphs over three pages as Word last laid it out, the fourth in the
/// cell of a table, with the address in the second and the fifth, and a header and the
/// properties that have it too.
fn paged_docx() -> Res<Vec<u8>> {
    let w = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"";
    let document = format!(
        "{XML_HEAD}<w:document {w}><w:body>\
         <w:p><w:r><w:t>Zonder gegevens</w:t></w:r></w:p>\
         <w:p><w:r><w:t>Mail {EMAIL}</w:t></w:r></w:p>\
         <w:p><w:r><w:lastRenderedPageBreak/><w:t>Bel {MOBILE}</w:t></w:r></w:p>\
         <w:tbl><w:tr><w:tc><w:p><w:r><w:t>IBAN {IBAN}</w:t></w:r></w:p></w:tc></w:tr></w:tbl>\
         <w:p><w:r><w:lastRenderedPageBreak/><w:t>Nog eens {EMAIL}</w:t></w:r></w:p>\
         </w:body></w:document>"
    );
    let header =
        format!("{XML_HEAD}<w:hdr {w}><w:p><w:r><w:t>Contact {EMAIL}</w:t></w:r></w:p></w:hdr>");
    let core = format!(
        "{XML_HEAD}<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator>{EMAIL}</dc:creator></cp:coreProperties>"
    );
    build_zip(&[
        (
            "[Content_Types].xml",
            format!("{XML_HEAD}<Types/>").as_bytes(),
            DEFLATED,
        ),
        ("word/document.xml", document.as_bytes(), DEFLATED),
        ("word/header1.xml", header.as_bytes(), DEFLATED),
        ("docProps/core.xml", core.as_bytes(), DEFLATED),
    ])
}

/// A workbook of two sheets, `Klanten` and `Q&A`, with personal data in shared strings, in an
/// inline string, in the plain value of a cell and in a header, and `extra` entries as well. The
/// workbook lists `Klanten` first, or `Q&A` first when `klanten_first` is false.
fn workbook_with(klanten_first: bool, extra: &[(&str, &[u8], CompressionMethod)]) -> Res<Vec<u8>> {
    let klanten = "<sheet name=\"Klanten\" sheetId=\"1\" r:id=\"rId1\"/>";
    let questions = "<sheet name=\"Q&amp;A\" sheetId=\"2\" r:id=\"rId2\"/>";
    let sheets = if klanten_first {
        format!("{klanten}{questions}")
    } else {
        format!("{questions}{klanten}")
    };
    let book = format!(
        "{XML_HEAD}<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
         <sheets>{sheets}</sheets></workbook>"
    );
    // One target relative to the workbook's folder, one from the root of the package.
    let relations = format!(
        "{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
         <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"/xl/worksheets/sheet2.xml\"/>\
         <Relationship Id=\"rId3\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings\" Target=\"sharedStrings.xml\"/>\
         </Relationships>"
    );
    // Strings 0 and 1 are shown by cells, 2 is plain text, and 3 is shown by none.
    let shared = format!(
        "{XML_HEAD}<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" count=\"5\" uniqueCount=\"4\">\
         <si><r><t>jan.jansen@</t></r><r><rPr><b/></rPr><t>example.org</t></r></si>\
         <si><t>{IBAN}</t></si><si><t>gewoon tekst</t></si><si><t>piet@example.com</t></si></sst>"
    );
    let first = format!(
        "{XML_HEAD}<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
         <row r=\"1\"><c r=\"A1\" t=\"s\"><v>2</v></c><c r=\"B1\" t=\"s\"><v>0</v></c></row>\
         <row r=\"3\"><c r=\"C3\" t=\"s\"><v>0</v></c><c r=\"D3\" t=\"inlineStr\"><is><t>{MOBILE}</t></is></c></row>\
         </sheetData><headerFooter><oddHeader>lotte@example.net</oddHeader></headerFooter></worksheet>"
    );
    let second = format!(
        "{XML_HEAD}<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>\
         <row r=\"7\"><c r=\"A7\" t=\"s\"><v>0</v></c><c r=\"B7\" t=\"s\"><v>1</v></c></row>\
         <row r=\"9\"><c r=\"C9\" t=\"str\"><f>A7</f><v>kees@example.net</v></c></row>\
         </sheetData></worksheet>"
    );
    let mut entries: Vec<(&str, &[u8], CompressionMethod)> = vec![
        ("[Content_Types].xml", CONTENT_TYPES.as_bytes(), DEFLATED),
        ("xl/workbook.xml", book.as_bytes(), DEFLATED),
        ("xl/_rels/workbook.xml.rels", relations.as_bytes(), DEFLATED),
        ("xl/sharedStrings.xml", shared.as_bytes(), DEFLATED),
        ("xl/worksheets/sheet1.xml", first.as_bytes(), DEFLATED),
        ("xl/worksheets/sheet2.xml", second.as_bytes(), DEFLATED),
    ];
    entries.extend_from_slice(extra);
    build_zip(&entries)
}

const ODT_MIME: &[u8] = b"application/vnd.oasis.opendocument.text";

fn odt() -> Res<Vec<u8>> {
    let content = format!(
        "{XML_HEAD}<office:document-content xmlns:office=\"o\" xmlns:text=\"t\" xmlns:xlink=\"x\"><office:body><office:text>\
         <text:p>Mail <text:span>{EMAIL}</text:span> of bel<text:tab/>06-12345678.</text:p>\
         <text:p><text:a xlink:href=\"mailto:{EMAIL}\">schrijf</text:a></text:p>\
         </office:text></office:body></office:document-content>"
    );
    let meta = format!(
        "{XML_HEAD}<office:document-meta xmlns:office=\"o\" xmlns:dc=\"d\"><office:meta><dc:creator>{EMAIL}</dc:creator></office:meta></office:document-meta>"
    );
    build_zip(&[
        ("mimetype", ODT_MIME, STORED),
        (
            "META-INF/manifest.xml",
            format!("{XML_HEAD}<manifest/>").as_bytes(),
            DEFLATED,
        ),
        ("Configurations2/", b"", STORED),
        ("content.xml", content.as_bytes(), DEFLATED),
        ("meta.xml", meta.as_bytes(), DEFLATED),
        ("Pictures/logo.bin", &noise(2048), DEFLATED),
        ("Thumbnails/thumbnail.png", &noise(1024), DEFLATED),
    ])
}

const ODS_MIME: &[u8] = b"application/vnd.oasis.opendocument.spreadsheet";

/// A spreadsheet of two sheets, `Klanten` and `Q&A`, whose cells use repeated rows and columns
/// and a covered cell, with personal data in the cells and in the meta data.
fn ods() -> Res<Vec<u8>> {
    let content = format!(
        "{XML_HEAD}<office:document-content xmlns:office=\"o\" xmlns:table=\"t\" xmlns:text=\"x\"><office:body><office:spreadsheet>\
         <table:table table:name=\"Klanten\">\
         <table:table-column table:number-columns-repeated=\"3\"/>\
         <table:table-row table:number-rows-repeated=\"2\"><table:table-cell/></table:table-row>\
         <table:table-row>\
         <table:table-cell table:number-columns-repeated=\"2\"/>\
         <table:table-cell><text:p>{EMAIL}</text:p></table:table-cell>\
         <table:covered-table-cell/>\
         <table:table-cell table:number-columns-repeated=\"3\"><text:p>{IBAN}</text:p></table:table-cell>\
         </table:table-row>\
         <table:table-row table:number-rows-repeated=\"3\"><table:table-cell><text:p>kees@example.net</text:p></table:table-cell></table:table-row>\
         </table:table>\
         <table:table table:name=\"Q&amp;A\"><table:table-row><table:table-cell><text:p>{MOBILE}</text:p></table:table-cell></table:table-row></table:table>\
         </office:spreadsheet></office:body></office:document-content>"
    );
    let meta = format!(
        "{XML_HEAD}<office:document-meta xmlns:office=\"o\" xmlns:dc=\"d\"><office:meta><dc:creator>{EMAIL}</dc:creator></office:meta></office:document-meta>"
    );
    build_zip(&[
        ("mimetype", ODS_MIME, STORED),
        (
            "META-INF/manifest.xml",
            format!("{XML_HEAD}<manifest/>").as_bytes(),
            DEFLATED,
        ),
        ("content.xml", content.as_bytes(), DEFLATED),
        ("meta.xml", meta.as_bytes(), DEFLATED),
    ])
}

fn eml() -> Vec<u8> {
    // "Bel me op +31 6 12345678\r\n" in base64.
    let body = base64(format!("Bel me op {MOBILE}\r\n").as_bytes());
    // Binary for sure: a NUL byte and no valid UTF-8.
    let mut blob = noise(300);
    blob[0] = 0x90;
    blob[5] = 0;
    let mail = format!(
        "From: Jan Jansen <{EMAIL}>\r\n\
         To: Piet <piet@example.com>\r\n\
         Subject: Offerte\r\n\
         Date: Sat, 20 Nov 2021 14:22:01 -0800\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
         \r\n\
         --BOUND\r\n\
         Content-Type: text/plain; charset=\"utf-8\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {body}\r\n\
         --BOUND\r\n\
         Content-Type: text/plain; name=\"{EMAIL}.txt\"\r\n\
         Content-Disposition: attachment; filename=\"{EMAIL}.txt\"\r\n\
         \r\n\
         Rekening {IBAN}\r\n\
         --BOUND\r\n\
         Content-Type: application/octet-stream; name=\"blob.bin\"\r\n\
         Content-Disposition: attachment; filename=\"blob.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {blob}\r\n\
         --BOUND--\r\n",
        blob = base64(&blob),
    );
    mail.into_bytes()
}

/// A message with a plain text body that holds the address of its header and a number.
fn located_eml() -> Vec<u8> {
    format!(
        "From: Jan Jansen <{EMAIL}>\r\n\
         To: Piet <piet@example.com>\r\n\
         Subject: Offerte\r\n\
         Date: Sat, 20 Nov 2021 14:22:01 -0800\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=\"utf-8\"\r\n\
         \r\n\
         Hallo,\r\n\
         \r\n\
         Bel me op {MOBILE} of mail {EMAIL}\r\n"
    )
    .into_bytes()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let at = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = at(0) << 16 | at(1) << 8 | at(2);
        let sextet =
            |shift: u32| char::from(ALPHABET[usize::try_from(n >> shift & 63).unwrap_or(0)]);
        encoded.push(sextet(18));
        encoded.push(sextet(12));
        encoded.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        encoded.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    // Lines of at most 76 characters.
    encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn put(file: &mut CompoundFile<Cursor<Vec<u8>>>, path: &str, bytes: &[u8]) -> Res {
    file.create_stream(path)?.write_all(bytes)?;
    Ok(())
}

fn msg() -> Res<Vec<u8>> {
    let mut file = CompoundFile::create(Cursor::new(Vec::new()))?;
    put(&mut file, "/__properties_version1.0", &[0; 32])?;
    put(&mut file, "/__substg1.0_0037001F", &utf16le("Offerte"))?;
    put(
        &mut file,
        "/__substg1.0_1000001F",
        &utf16le(&format!("Bel me op {MOBILE}\r\n")),
    )?;
    put(&mut file, "/__substg1.0_0C1A001F", &utf16le("Jan Jansen"))?;
    put(&mut file, "/__substg1.0_5D01001F", &utf16le(EMAIL))?;
    for (n, name, address, kind) in [
        (0_u8, "Piet", "piet@example.com", 1_u8),
        (1, "Kees", "kees@example.net", 2),
    ] {
        let dir = format!("/__recip_version1.0_#0000000{n}");
        file.create_storage(&dir)?;
        put(
            &mut file,
            &format!("{dir}/__substg1.0_3001001F"),
            &utf16le(name),
        )?;
        put(
            &mut file,
            &format!("{dir}/__substg1.0_39FE001F"),
            &utf16le(address),
        )?;
        // 8 reserved bytes, then PidTagRecipientType = kind.
        let mut props = vec![0_u8; 8];
        props.extend(0x0C15_0003_u32.to_le_bytes());
        props.extend([0; 4]);
        props.extend(u64::from(kind).to_le_bytes());
        put(&mut file, &format!("{dir}/__properties_version1.0"), &props)?;
    }
    file.create_storage("/__attach_version1.0_#00000000")?;
    put(
        &mut file,
        "/__attach_version1.0_#00000000/__substg1.0_3707001F",
        &utf16le("rekening.txt"),
    )?;
    put(
        &mut file,
        "/__attach_version1.0_#00000000/__substg1.0_37010102",
        format!("Rekening {IBAN}\r\n").as_bytes(),
    )?;
    file.flush()?;
    Ok(file.into_inner().into_inner())
}

type Cfile = CompoundFile<Cursor<Vec<u8>>>;

/// The properties, subject and plain body every message storage has: `dir` is `""` for the
/// file itself or the storage of an embedded message.
fn put_message(file: &mut Cfile, dir: &str, subject: &str, body: &str) -> Res {
    put(file, &format!("{dir}/__properties_version1.0"), &[0; 32])?;
    put(
        file,
        &format!("{dir}/__substg1.0_0037001F"),
        &utf16le(subject),
    )?;
    put(file, &format!("{dir}/__substg1.0_1000001F"), &utf16le(body))?;
    Ok(())
}

/// A message with nothing but a subject and a body, then whatever `add` puts in.
fn bare_msg(add: impl FnOnce(&mut Cfile) -> Res) -> Res<Vec<u8>> {
    let mut file = CompoundFile::create(Cursor::new(Vec::new()))?;
    put_message(&mut file, "", "Doorgestuurd", "Zie bijlage.")?;
    add(&mut file)?;
    file.flush()?;
    Ok(file.into_inner().into_inner())
}

const EMBEDDED_MESSAGE: &str = "__substg1.0_3701000D";

/// Attachment storage `attach` that holds an embedded message; returns the storage of that
/// message. `name` is the attachment's own name, if it has one.
fn embed(
    file: &mut Cfile,
    attach: &str,
    name: Option<&str>,
    subject: &str,
    body: &str,
) -> Res<String> {
    file.create_storage(attach)?;
    let inner = format!("{attach}/{EMBEDDED_MESSAGE}");
    file.create_storage(&inner)?;
    put_message(file, &inner, subject, body)?;
    if let Some(name) = name {
        put(
            file,
            &format!("{attach}/__substg1.0_3707001F"),
            &utf16le(name),
        )?;
    }
    Ok(inner)
}

/// A message that forwards another one as an attachment, with a text file attached to that.
fn msg_with_embedded(body: &str) -> Res<Vec<u8>> {
    bare_msg(|file| {
        let inner = embed(
            file,
            "/__attach_version1.0_#00000000",
            Some("doorgestuurd.msg"),
            "Voorstel",
            body,
        )?;
        put(
            file,
            &format!("{inner}/__substg1.0_5D01001F"),
            &utf16le(EMAIL),
        )?;
        let nested = format!("{inner}/__attach_version1.0_#00000000");
        file.create_storage(&nested)?;
        put(
            file,
            &format!("{nested}/__substg1.0_3707001F"),
            &utf16le("rekening.txt"),
        )?;
        put(
            file,
            &format!("{nested}/__substg1.0_37010102"),
            format!("Rekening {IBAN}\r\n").as_bytes(),
        )
    })
}

/// A message with a chain of `levels` embedded messages, each in the previous one.
fn msg_with_nested_messages(levels: usize) -> Res<Vec<u8>> {
    bare_msg(|file| {
        let mut attach = String::from("/__attach_version1.0_#00000000");
        for level in 1..=levels {
            let inner = embed(
                file,
                &attach,
                None,
                &format!("niveau {level}"),
                &format!("inhoud {level}\r\n"),
            )?;
            attach = format!("{inner}/__attach_version1.0_#00000000");
        }
        Ok(())
    })
}

/// The sum of the lengths of all streams of a compound file.
fn stream_bytes(compound: &[u8]) -> Res<u64> {
    let file = CompoundFile::open(Cursor::new(compound))?;
    Ok(file
        .walk()
        .filter(cfb::Entry::is_stream)
        .map(|entry| entry.len())
        .sum())
}

fn pdf(text: &str) -> Res<Vec<u8>> {
    pdf_pages(&[text])
}

/// A PDF with a page for each of `texts`, each showing its text at the top.
fn pdf_pages(texts: &[&str]) -> Res<Vec<u8>> {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let mut font = Dictionary::new();
    font.set("Type", "Font");
    font.set("Subtype", "Type1");
    font.set("BaseFont", "Courier");
    let font_id = doc.add_object(font);
    let mut fonts = Dictionary::new();
    fonts.set("F1", font_id);
    let mut resources = Dictionary::new();
    resources.set("Font", fonts);
    let resources_id = doc.add_object(resources);
    let mut kids = Vec::new();
    for &text in texts {
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 24.into()]),
                Operation::new("Td", vec![50.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal(text)]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(Dictionary::new(), content.encode()?));
        let mut page = Dictionary::new();
        page.set("Type", "Page");
        page.set("Parent", pages_id);
        page.set("Contents", content_id);
        kids.push(Object::from(doc.add_object(page)));
    }
    let mut pages = Dictionary::new();
    pages.set("Type", "Pages");
    pages.set("Count", i64::try_from(kids.len())?);
    pages.set("Kids", kids);
    pages.set("Resources", resources_id);
    pages.set("MediaBox", vec![0.into(), 0.into(), 595.into(), 842.into()]);
    doc.objects.insert(pages_id, Object::Dictionary(pages));
    let mut catalog = Dictionary::new();
    catalog.set("Type", "Catalog");
    catalog.set("Pages", pages_id);
    let catalog_id = doc.add_object(catalog);
    doc.trailer.set("Root", catalog_id);
    let mut out = Vec::new();
    doc.save_to(&mut out)?;
    Ok(out)
}

// -- zip helpers ----------------------------------------------------------------

/// An entry's stored bytes, compressed exactly as in the archive.
fn raw_entry(zip: &[u8], name: &str) -> Res<Vec<u8>> {
    let mut archive = package::open(zip)?;
    let index = archive.index_for_name(name).ok_or("missing entry")?;
    let mut raw = Vec::new();
    archive.by_index_raw(index)?.read_to_end(&mut raw)?;
    Ok(raw)
}

fn entry_text(zip: &[u8], name: &str) -> Res<String> {
    let mut archive = package::open(zip)?;
    let mut text = String::new();
    archive.by_name(name)?.read_to_string(&mut text)?;
    Ok(text)
}

fn entry_bytes(zip: &[u8], name: &str) -> Res<Vec<u8>> {
    let mut archive = package::open(zip)?;
    let mut bytes = Vec::new();
    archive.by_name(name)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn entry_names(zip: &[u8]) -> Res<Vec<String>> {
    let archive = package::open(zip)?;
    let mut names = Vec::new();
    for name in archive.file_names() {
        names.push(name?.into_owned());
    }
    Ok(names)
}

// -- sniffing -------------------------------------------------------------------

#[test]
fn magic_bytes_pick_the_format() {
    assert_eq!(sniff(b"PK\x03\x04..."), Format::Zip);
    assert_eq!(sniff(b"%PDF-1.7\n"), Format::Pdf);
    for image in [
        &b"\x89PNG\r\n\x1a\n"[..],
        b"\xFF\xD8\xFF\xE0",
        b"GIF89a",
        b"II*\0\x08\0\0\0",
        b"MM\0*\0\0\0\x08",
        b"RIFF\x24\0\0\0WEBPVP8 ",
        b"\0\0\0\x18ftypheic\0\0\0\0",
        b"\0\0\0\x18ftypmif1\0\0\0\0",
    ] {
        assert_eq!(sniff(image), Format::Image, "{image:?}");
    }
    assert_eq!(
        sniff(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0]),
        Format::Cfb
    );
    assert_eq!(sniff(b"just some text"), Format::Text);
    assert_eq!(sniff(b""), Format::Text);
}

#[test]
fn bmp_needs_more_than_two_letters() {
    let mut bmp = b"BM".to_vec();
    bmp.extend([0; 4]); // file size
    bmp.extend([0; 4]); // reserved
    bmp.extend([54, 0, 0, 0]); // pixel data offset
    bmp.extend(40_u32.to_le_bytes()); // BITMAPINFOHEADER
    assert_eq!(sniff(&bmp), Format::Image);
    assert_eq!(sniff(b"BMW is a car brand, not a bitmap."), Format::Text);
}

#[test]
fn mail_needs_a_first_header_only_mail_has_and_a_blank_line() {
    assert_eq!(
        sniff(b"From: a@b.nl\r\nSubject: x\r\n\r\nbody"),
        Format::Mail
    );
    assert_eq!(sniff(b"\n\nreceived: by x\nTo: y\n\nbody"), Format::Mail);
    assert_eq!(sniff(b"\xEF\xBB\xBFSubject: hi\n\nbody"), Format::Mail);
    // What clients, libraries and servers put first.
    for first in [
        "X-Mozilla-Status: 0001",
        "x-original-to: a@b.nl",
        "Content-Type: multipart/mixed; boundary=\"B\"",
        "Authentication-Results: mx.example.org; dkim=pass",
        "DKIM-Signature: v=1; a=rsa-sha256",
        "ARC-Seal: i=1",
        "Reply-To: a@b.nl",
        "Cc: a@b.nl",
        "In-Reply-To: <1@b.nl>",
    ] {
        let mail = format!("{first}\r\nSubject: x\r\n\r\nbody");
        assert_eq!(sniff(mail.as_bytes()), Format::Mail, "{first}");
    }
    // An mbox separator line only introduces the message.
    assert_eq!(
        sniff(b"From - Mon Jan  1 00:00:00 2024\nX-Mozilla-Status: 0001\n\nbody"),
        Format::Mail
    );
    assert_eq!(
        sniff(b"From jan@example.org Mon Jan  1 00:00:00 2024\r\nSubject: x\r\n\r\nbody"),
        Format::Mail
    );
    assert_eq!(
        sniff(b"From the desk of the mayor\n\nDear all,"),
        Format::Text
    );
    assert_eq!(sniff(b"Subject: no blank line follows"), Format::Text);
    assert_eq!(sniff(b"hello\nFrom: x\n\nbody"), Format::Text);
    assert_eq!(sniff(b"Frontier: x\n\nbody"), Format::Text);
    assert_eq!(sniff(b"Note: x\n\nbody"), Format::Text);
    assert_eq!(sniff(b"Xylophone: x\n\nbody"), Format::Text);
}

// -- Office Open XML ------------------------------------------------------------

#[test]
fn docx_round_trip() -> Res {
    let engine = engine()?;
    let original = docx()?;
    let anonymized = same(&engine, Mode::Anonymize, &original)?;

    let texts = same_text(&anonymized)?;
    assert_absent(&texts, &[EMAIL, PHONE, "1234 5678"]);
    assert!(texts.contains("Zonder gegevens"));
    assert_absent(
        &entry_text(&anonymized, "word/_rels/document.xml.rels")?,
        &[EMAIL],
    );
    assert_absent(&entry_text(&anonymized, "docProps/core.xml")?, &[EMAIL]);

    // Same entries in the same order; untouched ones are copied compressed, byte for byte.
    assert_eq!(entry_names(&anonymized)?, entry_names(&original)?);
    for name in [
        "[Content_Types].xml",
        "_rels/.rels",
        "word/media/image1.bin",
    ] {
        assert_eq!(
            raw_entry(&anonymized, name)?,
            raw_entry(&original, name)?,
            "{name}"
        );
    }
    assert_ne!(
        raw_entry(&anonymized, "word/document.xml")?,
        raw_entry(&original, "word/document.xml")?
    );

    // Anonymizing again changes nothing; deanonymizing restores the text.
    assert_eq!(same(&engine, Mode::Anonymize, &anonymized)?, anonymized);
    let restored = same(&engine, Mode::Deanonymize, &anonymized)?;
    assert_eq!(same_text(&restored)?, same_text(&original)?);
    assert_eq!(
        entry_text(&restored, "word/_rels/document.xml.rels")?,
        entry_text(&original, "word/_rels/document.xml.rels")?
    );
    Ok(())
}

#[test]
fn xlsx_shared_strings_are_rewritten() -> Res {
    let engine = engine()?;
    let original = xlsx()?;
    let anonymized = same(&engine, Mode::Anonymize, &original)?;
    let texts = same_text(&anonymized)?;
    assert_absent(&texts, &[EMAIL, IBAN, MOBILE, "jan.jansen@"]);
    assert!(texts.contains("gewoon tekst"));
    let restored = same(&engine, Mode::Deanonymize, &anonymized)?;
    assert_eq!(same_text(&restored)?, same_text(&original)?);
    Ok(())
}

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Types/>"#;

/// A package with one `word/document.xml`.
fn docx_with(document: &str) -> Res<Vec<u8>> {
    build_zip(&[
        ("[Content_Types].xml", CONTENT_TYPES.as_bytes(), DEFLATED),
        ("word/document.xml", document.as_bytes(), DEFLATED),
    ])
}

#[test]
fn package_without_pii_is_returned_byte_for_byte() -> Res {
    let engine = engine()?;
    let clean = docx_with(&format!(
        "{XML_HEAD}<w:document xmlns:w=\"w\"><w:body><w:p><w:r><w:t>Niets te zien</w:t></w:r></w:p></w:body></w:document>"
    ))?;
    assert_eq!(same(&engine, Mode::Anonymize, &clean)?, clean);
    Ok(())
}

#[test]
fn rewritten_parts_keep_their_method_and_timestamp() -> Res {
    let engine = engine()?;
    let stamp =
        zip::DateTime::from_date_and_time(2021, 5, 17, 13, 45, 30).map_err(|_| "bad date")?;
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("[Content_Types].xml", SimpleFileOptions::default())?;
    zip.write_all(CONTENT_TYPES.as_bytes())?;
    for (name, method) in [("word/stored.xml", STORED), ("word/deflated.xml", DEFLATED)] {
        let options = SimpleFileOptions::default()
            .compression_method(method)
            .last_modified_time(stamp);
        zip.start_file(name, options)?;
        zip.write_all(format!("{XML_HEAD}<w:p>mail {EMAIL}</w:p>").as_bytes())?;
    }
    let anonymized = same(&engine, Mode::Anonymize, &zip.finish()?.into_inner())?;

    let mut archive = package::open(&anonymized)?;
    for (name, method) in [("word/stored.xml", STORED), ("word/deflated.xml", DEFLATED)] {
        let entry = archive.by_name(name)?;
        assert_eq!(entry.compression(), method, "{name}");
        assert_eq!(entry.last_modified(), Some(stamp), "{name}");
    }
    assert_absent(&same_text(&anonymized)?, &[EMAIL]);
    Ok(())
}

#[test]
fn a_rewritten_package_loses_its_preview_picture_but_keeps_the_entry() -> Res {
    let engine = engine()?;
    let stamp =
        zip::DateTime::from_date_and_time(2021, 5, 17, 13, 45, 30).map_err(|_| "bad date")?;
    let previews = [
        ("docProps/thumbnail.jpeg", DEFLATED),
        ("docProps/thumbnail.png", STORED),
        ("docProps/thumbnail.emf", DEFLATED),
        ("docProps/thumbnail.wmf", STORED),
    ];
    let build = |text: &str| -> Res<Vec<u8>> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("[Content_Types].xml", SimpleFileOptions::default())?;
        zip.write_all(CONTENT_TYPES.as_bytes())?;
        zip.start_file("word/document.xml", SimpleFileOptions::default())?;
        zip.write_all(format!("{XML_HEAD}<w:p>{text}</w:p>").as_bytes())?;
        for (name, method) in previews {
            let options = SimpleFileOptions::default()
                .compression_method(method)
                .last_modified_time(stamp);
            zip.start_file(name, options)?;
            zip.write_all(&noise(4096))?;
        }
        // A picture inside the document is content, not a preview.
        zip.start_file("word/media/thumbnail.png", SimpleFileOptions::default())?;
        zip.write_all(&noise(512))?;
        Ok(zip.finish()?.into_inner())
    };
    let original = build(&format!("mail {EMAIL}"))?;
    let anonymized = same(&engine, Mode::Anonymize, &original)?;

    assert_eq!(entry_names(&anonymized)?, entry_names(&original)?);
    let mut archive = package::open(&anonymized)?;
    for (name, method) in previews {
        let entry = archive.by_name(name)?;
        assert_eq!(entry.compression(), method, "{name}");
        assert_eq!(entry.last_modified(), Some(stamp), "{name}");
    }
    for name in ["docProps/thumbnail.jpeg", "docProps/thumbnail.png"] {
        let picture = crate::ocr::first_pixel(&entry_bytes(&anonymized, name)?)?;
        assert_eq!(picture, (1, 1, [255; 4]), "{name}");
    }
    for name in ["docProps/thumbnail.emf", "docProps/thumbnail.wmf"] {
        assert!(entry_bytes(&anonymized, name)?.len() < 128, "{name}");
    }
    assert_eq!(
        raw_entry(&anonymized, "word/media/thumbnail.png")?,
        raw_entry(&original, "word/media/thumbnail.png")?
    );

    // Nothing was masked, so nothing is rewritten and the preview stays.
    let clean = build("niets te zien")?;
    assert_eq!(same(&engine, Mode::Anonymize, &clean)?, clean);
    Ok(())
}

#[test]
fn field_instruction_and_visible_text_get_the_same_proxy() -> Res {
    let engine = engine()?;
    let original = docx_with(&format!(
        "{XML_HEAD}<w:document xmlns:w=\"w\"><w:body><w:p>\
         <w:r><w:fldChar w:fldCharType=\"begin\"/></w:r>\
         <w:r><w:instrText xml:space=\"preserve\"> HYPERLINK \"mailto:{EMAIL}\" </w:instrText></w:r>\
         <w:r><w:fldChar w:fldCharType=\"separate\"/></w:r>\
         <w:r><w:t>{EMAIL}</w:t></w:r>\
         <w:r><w:fldChar w:fldCharType=\"end\"/></w:r>\
         </w:p></w:body></w:document>"
    ))?;
    let anonymized = same(&engine, Mode::Anonymize, &original)?;
    let xml = entry_text(&anonymized, "word/document.xml")?;
    assert_absent(&xml, &[EMAIL]);
    // `mailto:PROXY` in the instruction and `PROXY` in the run are the same address.
    let proxy = xml
        .split("mailto:")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("no field instruction")?;
    assert!(xml.contains(&format!("<w:t>{proxy}</w:t>")), "{xml}");
    Ok(())
}

#[test]
fn many_parts_are_rewritten_consistently() -> Res {
    let engine = engine()?;
    let sheets: Vec<(String, String)> = (0..40)
        .map(|i| {
            (
                format!("xl/worksheets/sheet{i}.xml"),
                format!(
                    "{XML_HEAD}<worksheet><sheetData><row><c t=\"inlineStr\"><is><t>row {i}: {EMAIL}</t></is></c></row></sheetData></worksheet>"
                ),
            )
        })
        .collect();
    let mut entries: Vec<(&str, &[u8], CompressionMethod)> =
        vec![("[Content_Types].xml", CONTENT_TYPES.as_bytes(), DEFLATED)];
    entries.extend(
        sheets
            .iter()
            .map(|(name, xml)| (name.as_str(), xml.as_bytes(), DEFLATED)),
    );
    let anonymized = same(&engine, Mode::Anonymize, &build_zip(&entries)?)?;

    let mut proxies = std::collections::HashSet::new();
    for i in 0..40 {
        let xml = entry_text(&anonymized, &format!("xl/worksheets/sheet{i}.xml"))?;
        assert_absent(&xml, &[EMAIL]);
        let proxy = xml
            .split(&format!("row {i}: "))
            .nth(1)
            .and_then(|rest| rest.split("</t>").next())
            .ok_or("no proxy")?;
        proxies.insert(proxy.to_owned());
    }
    assert_eq!(proxies.len(), 1, "one address, one proxy: {proxies:?}");
    Ok(())
}

#[test]
fn streamed_zip_entries_with_data_descriptors_are_copied() -> Res {
    let engine = engine()?;
    let mut zip = ZipWriter::new_stream(Vec::new());
    for (name, body) in [
        ("[Content_Types].xml", CONTENT_TYPES.to_owned()),
        (
            "word/document.xml",
            format!(
                "{XML_HEAD}<w:document xmlns:w=\"w\"><w:p><w:r><w:t>mail {EMAIL}</w:t></w:r></w:p></w:document>"
            ),
        ),
        ("word/note.txt", "left alone".to_owned()),
    ] {
        zip.start_file(
            name,
            SimpleFileOptions::default().compression_method(DEFLATED),
        )?;
        zip.write_all(body.as_bytes())?;
    }
    let original = zip.finish()?.into_inner();
    let anonymized = same(&engine, Mode::Anonymize, &original)?;
    assert_absent(&same_text(&anonymized)?, &[EMAIL]);
    assert_eq!(entry_text(&anonymized, "word/note.txt")?, "left alone");
    Ok(())
}

#[test]
fn a_malformed_part_names_itself_in_the_error() -> Res {
    let engine = engine()?;
    let broken = docx_with("<w:p>unclosed</w:q>")?;
    match process(&engine, Mode::Anonymize, &broken, 0) {
        Err(Error::Xml(message)) => {
            assert!(message.starts_with("word/document.xml: "), "{message}");
        }
        other => return Err(format!("expected an XML error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn documents_can_be_processed_in_parallel_through_one_engine() -> Res {
    use rayon::prelude::*;

    let engine = engine()?;
    let documents: Vec<Vec<u8>> = (0..48)
        .map(|i| {
            docx_with(&format!(
                "{XML_HEAD}<w:document xmlns:w=\"w\"><w:body><w:p><w:r><w:t>mail user{i}.name@example.org en {EMAIL}</w:t></w:r></w:p></w:body></w:document>"
            ))
        })
        .collect::<Res<_>>()?;

    let anonymized: Vec<Vec<u8>> = documents
        .par_iter()
        .map(|doc| same(&engine, Mode::Anonymize, doc).map_err(|e| e.to_string()))
        .collect::<Result<_, String>>()?;
    let restored: Vec<Vec<u8>> = anonymized
        .par_iter()
        .map(|doc| same(&engine, Mode::Deanonymize, doc).map_err(|e| e.to_string()))
        .collect::<Result<_, String>>()?;
    for ((original, anonymized), restored) in documents.iter().zip(&anonymized).zip(&restored) {
        assert_absent(&same_text(anonymized)?, &[EMAIL, "name@example.org"]);
        assert_eq!(same_text(restored)?, same_text(original)?);
    }
    Ok(())
}

// -- OpenDocument ---------------------------------------------------------------

#[test]
fn odt_round_trip_keeps_mimetype_first_and_stored() -> Res {
    let engine = engine()?;
    let original = odt()?;
    let anonymized = same(&engine, Mode::Anonymize, &original)?;

    assert_absent(&same_text(&anonymized)?, &[EMAIL, "06-12345678"]);
    assert_absent(
        &entry_text(&anonymized, "content.xml")?,
        &[EMAIL, "06-12345678"],
    );
    assert_eq!(entry_names(&anonymized)?, entry_names(&original)?);
    assert_eq!(entry_names(&anonymized)?[0], "mimetype");
    assert_eq!(
        raw_entry(&anonymized, "mimetype")?,
        ODT_MIME,
        "stored, so raw == content"
    );
    for name in ["META-INF/manifest.xml", "Pictures/logo.bin"] {
        assert_eq!(
            raw_entry(&anonymized, name)?,
            raw_entry(&original, name)?,
            "{name}"
        );
    }
    // The preview of the unmasked first page is replaced by a blank picture.
    assert_eq!(
        crate::ocr::first_pixel(&entry_bytes(&anonymized, "Thumbnails/thumbnail.png")?)?,
        (1, 1, [255; 4])
    );

    let restored = same(&engine, Mode::Deanonymize, &anonymized)?;
    assert_eq!(same_text(&restored)?, same_text(&original)?);
    assert_eq!(
        entry_text(&restored, "content.xml")?,
        entry_text(&original, "content.xml")?
    );
    Ok(())
}

#[test]
fn other_zip_files_are_unsupported() -> Res {
    let engine = engine()?;
    let zip = build_zip(&[("a.txt", b"hello", DEFLATED)])?;
    assert!(matches!(
        process(&engine, Mode::Anonymize, &zip, 0),
        Err(Error::UnsupportedFormat("zip archive"))
    ));
    Ok(())
}

// -- plain text -------------------------------------------------------------------

#[test]
fn utf16le_text_with_bom_keeps_its_encoding() -> Res {
    let engine = engine()?;
    let mut original = vec![0xFF, 0xFE];
    original.extend(utf16le(&format!("Bel {MOBILE} of mail {EMAIL}\r\n")));
    let anonymized = same(&engine, Mode::Anonymize, &original)?;
    assert_eq!(&anonymized[..2], [0xFF, 0xFE]);
    assert_eq!(anonymized.len() % 2, 0);
    assert_absent(&same_text(&anonymized)?, &[EMAIL, MOBILE]);
    assert_eq!(same(&engine, Mode::Deanonymize, &anonymized)?, original);
    Ok(())
}

#[test]
fn bomless_utf16le_text_is_found() -> Res {
    let engine = engine()?;
    let original = utf16le(&format!("mail {EMAIL}"));
    let anonymized = same(&engine, Mode::Anonymize, &original)?;
    assert_absent(&same_text(&anonymized)?, &[EMAIL]);
    assert_eq!(same(&engine, Mode::Deanonymize, &anonymized)?, original);
    Ok(())
}

#[test]
fn windows_1252_text_keeps_its_bytes() -> Res {
    let engine = engine()?;
    let mut original = b"Caf\xE9 \x80 5, mail ".to_vec();
    original.extend(EMAIL.as_bytes());
    original.extend(b" ok\r\n");
    let anonymized = same(&engine, Mode::Anonymize, &original)?;
    assert!(anonymized.starts_with(b"Caf\xE9 \x80 5, mail "));
    assert!(anonymized.ends_with(b" ok\r\n"));
    assert!(
        !anonymized
            .windows(EMAIL.len())
            .any(|w| w == EMAIL.as_bytes())
    );
    assert_eq!(same(&engine, Mode::Deanonymize, &anonymized)?, original);
    Ok(())
}

#[test]
fn utf8_text_without_pii_comes_back_identical() -> Res {
    let engine = engine()?;
    for original in [&b"plain \xC3\xA9 text\n"[..], b"\xEF\xBB\xBFwith bom", b""] {
        assert_eq!(same(&engine, Mode::Anonymize, original)?, original);
    }
    Ok(())
}

#[test]
fn random_bytes_are_unsupported() -> Res {
    let engine = engine()?;
    let mut bytes = noise(1000);
    bytes[0] = 0x90;
    bytes[500] = 0;
    assert!(matches!(
        process(&engine, Mode::Anonymize, &bytes, 0),
        Err(Error::UnsupportedFormat(_))
    ));
    Ok(())
}

#[test]
fn nesting_beyond_four_levels_is_refused() -> Res {
    let engine = engine()?;
    assert!(process(&engine, Mode::Anonymize, b"hello", 4).is_ok());
    assert!(matches!(
        process(&engine, Mode::Anonymize, b"hello", 5),
        Err(Error::UnsupportedFormat("nesting too deep"))
    ));
    Ok(())
}

// -- PDF --------------------------------------------------------------------------

#[test]
fn pdf_text_layer_is_anonymized() -> Res {
    let engine = engine()?;
    let out = text(&engine, Mode::Anonymize, &pdf(&format!("mail {EMAIL}"))?)?;
    assert_absent(&out, &[EMAIL]);
    assert!(out.contains("mail "), "{out:?}");
    // A PDF carrying the proxy text deanonymizes back to the address.
    let back = text(&engine, Mode::Deanonymize, &pdf(out.trim())?)?;
    assert!(back.contains(EMAIL), "{back:?}");
    Ok(())
}

#[test]
fn pdf_pages_with_next_to_no_text_go_through_ocr() -> Res {
    if !crate::ocr::available() {
        eprintln!("skipping: no OCR language");
        return Ok(());
    }
    let engine = engine()?;
    // Ten characters of text layer: below the threshold, so the page is rendered and read.
    let out = text(&engine, Mode::Anonymize, &pdf("Hello 4711")?)?;
    assert!(out.contains("Hello"), "{out:?}");
    Ok(())
}

#[test]
fn broken_pdf_is_a_pdf_error() -> Res {
    let engine = engine()?;
    assert!(matches!(
        process(&engine, Mode::Anonymize, b"%PDF-1.7 this is not a pdf", 0),
        Err(Error::Pdf(_))
    ));
    Ok(())
}

// -- email ------------------------------------------------------------------------

#[test]
fn eml_is_rendered_with_attachments() -> Res {
    let engine = engine()?;
    let out = text(&engine, Mode::Anonymize, &eml())?;
    assert_absent(&out, &[EMAIL, "piet@example.com", MOBILE, IBAN]);
    assert!(out.starts_with("From: Jan Jansen <"), "{out:?}");
    assert!(out.contains("\nSubject: Offerte\n"), "{out:?}");
    assert!(out.contains("Bel me op "), "{out:?}");
    assert!(out.contains("--- attachment: "), "{out:?}");
    assert!(out.contains(".txt ---\nRekening "), "{out:?}");
    // A binary attachment that is neither text nor an image-less format reads as unsupported.
    assert!(
        out.contains("--- attachment: blob.bin ---\n[unsupported: "),
        "{out:?}"
    );
    // The proxies deanonymize back to the original rendering.
    let back = text(&engine, Mode::Deanonymize, out.as_bytes())?;
    assert!(
        back.contains(EMAIL) && back.contains(MOBILE) && back.contains(IBAN),
        "{back:?}"
    );
    Ok(())
}

#[test]
fn an_eml_that_starts_with_a_client_header_is_read_as_mail() -> Res {
    let engine = engine()?;
    // Thunderbird writes its own headers before the message. The number is only in the
    // base64 body: read as plain text, the file would keep it.
    let body = base64(format!("Bel me op {MOBILE}\r\n").as_bytes());
    let mail = format!(
        "X-Mozilla-Status: 0001\r\nX-Mozilla-Keys:\r\nFrom: Jan <{EMAIL}>\r\nSubject: Offerte\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{body}\r\n"
    );
    let scanned = scan(&engine, mail.as_bytes(), false)?;
    assert!(
        found(&scanned).contains(&(EntityKind::Phone, MOBILE)),
        "{:?}",
        found(&scanned)
    );
    let out = text(&engine, Mode::Anonymize, mail.as_bytes())?;
    assert_absent(&out, &[EMAIL, MOBILE]);
    assert!(out.contains("Bel me op "), "{out:?}");
    Ok(())
}

#[test]
fn msg_is_rendered_like_eml() -> Res {
    let engine = engine()?;
    let out = text(&engine, Mode::Anonymize, &msg()?)?;
    assert_absent(
        &out,
        &[EMAIL, "piet@example.com", "kees@example.net", MOBILE, IBAN],
    );
    assert!(out.starts_with("From: Jan Jansen <"), "{out:?}");
    assert!(out.contains("\nTo: Piet <"), "{out:?}");
    assert!(out.contains("\nCc: Kees <"), "{out:?}");
    assert!(out.contains("\nSubject: Offerte\n"), "{out:?}");
    assert!(
        out.contains("--- attachment: rekening.txt ---\nRekening "),
        "{out:?}"
    );
    Ok(())
}

#[test]
fn an_embedded_message_is_rendered_like_the_message_that_carries_it() -> Res {
    let engine = engine()?;
    let body = format!("Bel mij op {MOBILE}\r\n");
    let out = text(&engine, Mode::Anonymize, &msg_with_embedded(&body)?)?;
    assert_absent(&out, &[EMAIL, MOBILE, IBAN]);
    assert!(
        out.contains("--- attachment: doorgestuurd.msg ---\nFrom: "),
        "{out:?}"
    );
    assert!(
        out.contains("\nSubject: Voorstel\n\nBel mij op "),
        "{out:?}"
    );
    assert!(
        out.contains("--- attachment: rekening.txt ---\nRekening "),
        "{out:?}"
    );

    // The stand-ins in the embedded message are restored when the message is read back.
    let masked = out
        .split("\nSubject: Voorstel\n\n")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .ok_or("no embedded body")?;
    let restored = text(
        &engine,
        Mode::Deanonymize,
        &msg_with_embedded(&format!("{masked}\r\n"))?,
    )?;
    assert!(
        restored.contains(&format!("Bel mij op {MOBILE}")),
        "{restored:?}"
    );
    Ok(())
}

#[test]
fn an_embedded_message_without_a_name_is_named_after_its_subject() -> Res {
    let engine = engine()?;
    let bytes = bare_msg(|file| {
        embed(file, "/__attach_version1.0_#00000000", None, "Offerte", "x")?;
        file.create_storage("/__attach_version1.0_#00000001")?;
        embed(file, "/__attach_version1.0_#00000002", None, "", "y").map(drop)
    })?;
    let out = text(&engine, Mode::Anonymize, &bytes)?;
    assert!(out.contains("--- attachment: Offerte ---\n"), "{out:?}");
    assert!(out.contains("--- attachment: attachment ---\n"), "{out:?}");
    Ok(())
}

#[test]
fn embedded_messages_stop_at_the_depth_limit() -> Res {
    let engine = engine()?;
    // Level 1 is attached at depth 1, like a file attachment would be: levels 1 to 4 are
    // rendered, 5 and deeper are not.
    let bytes = msg_with_nested_messages(8)?;
    let out = text(&engine, Mode::Anonymize, &bytes)?;
    assert!(out.contains("inhoud 4"), "{out:?}");
    assert_absent(&out, &["inhoud 5", "niveau 6"]);
    assert!(
        out.contains("--- attachment: niveau 5 ---\n[unsupported: "),
        "{out:?}"
    );
    assert!(out.contains("nesting too deep"), "{out:?}");
    Ok(())
}

#[test]
fn ole_objects_and_attachments_without_contents_are_skipped() -> Res {
    let engine = engine()?;
    let bytes = bare_msg(|file| {
        // An OLE object: a storage under the same name, but not a message.
        let ole = "/__attach_version1.0_#00000000";
        file.create_storage(ole)?;
        put(
            file,
            &format!("{ole}/__substg1.0_3707001F"),
            &utf16le("object.bin"),
        )?;
        file.create_storage(format!("{ole}/{EMBEDDED_MESSAGE}"))?;
        put(
            file,
            &format!("{ole}/{EMBEDDED_MESSAGE}/Contents"),
            EMAIL.as_bytes(),
        )?;
        // An attachment by reference: a name and nothing else.
        let by_reference = "/__attach_version1.0_#00000001";
        file.create_storage(by_reference)?;
        put(
            file,
            &format!("{by_reference}/__substg1.0_3707001F"),
            &utf16le("link.docx"),
        )
    })?;
    let out = text(&engine, Mode::Anonymize, &bytes)?;
    assert!(!out.contains("--- attachment:"), "{out:?}");
    Ok(())
}

#[test]
fn ansi_strings_lose_their_terminator_and_keep_their_text() -> Res {
    let engine = engine()?;
    let mut mail = format!("Bel {MOBILE}").into_bytes();
    mail.extend(b" \0 en mail ");
    mail.extend(EMAIL.as_bytes());
    mail.push(0);
    let bytes = bare_msg(|file| {
        // "Jan\0" has as many NULs as UTF-16 text has: left on, it was read as that.
        put(file, "/__substg1.0_0C1A001E", b"Jan\0")?;
        put(
            file,
            "/__substg1.0_5D01001E",
            format!("{EMAIL}\0").as_bytes(),
        )?;
        // An empty Unicode string does not hide the ANSI one next to it.
        file.remove_stream("/__substg1.0_0037001F")?;
        put(file, "/__substg1.0_0037001F", &[])?;
        put(file, "/__substg1.0_0037001E", b"Caf\xE9\0")?;
        file.remove_stream("/__substg1.0_1000001F")?;
        put(file, "/__substg1.0_1000001E", &mail)
    })?;
    let scanned = scan(&engine, &bytes, true)?;
    let head = scanned.texts.first().ok_or("no text")?;
    assert!(
        head.starts_with(&format!(
            "From: Jan <{EMAIL}>\nSubject: Caf\u{E9}\n\nBel {MOBILE} \0 en mail {EMAIL}\n"
        )),
        "{head:?}"
    );
    let values = found(&scanned);
    for expected in [(EntityKind::Email, EMAIL), (EntityKind::Phone, MOBILE)] {
        assert!(values.contains(&expected), "{expected:?} in {values:?}");
    }
    Ok(())
}

#[test]
fn the_streams_of_a_message_cannot_add_up_to_more_than_the_file() -> Res {
    let bytes = msg_with_embedded("Bel mij")?;
    let len = u64::try_from(bytes.len())?;
    let total = stream_bytes(&bytes)?;
    assert!(total <= len, "{total} streams in {len} bytes");
    assert!(msg::read(&bytes, len, 0).is_ok());
    assert!(msg::read(&bytes, total, 0).is_ok());
    assert!(matches!(
        msg::read(&bytes, total / 2, 0),
        Err(Error::Mail(_))
    ));

    // The streams of an embedded message count too.
    let big = msg_with_embedded(&"x".repeat(2000))?;
    assert!(matches!(msg::read(&big, 1000, 0), Err(Error::Mail(_))));
    assert!(msg::read(&big, u64::try_from(big.len())?, 0).is_ok());
    Ok(())
}

#[test]
fn legacy_compound_file_is_unsupported() -> Res {
    let engine = engine()?;
    let mut file = CompoundFile::create(Cursor::new(Vec::new()))?;
    put(&mut file, "/WordDocument", &[1, 2, 3])?;
    file.flush()?;
    let bytes = file.into_inner().into_inner();
    assert!(matches!(
        process(&engine, Mode::Anonymize, &bytes, 0),
        Err(Error::UnsupportedFormat(_))
    ));
    Ok(())
}

#[test]
fn nested_mail_attachments_stop_at_the_depth_limit() -> Res {
    let engine = engine()?;
    // Each level attaches the previous message as message/rfc822.
    let mut inner = eml();
    for _ in 0..6 {
        let mut outer = String::from(
            "From: a@example.com\r\nSubject: wrap\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\n\
             Content-Type: text/plain\r\n\r\nhi\r\n--B\r\n\
             Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"in.eml\"\r\n\r\n",
        );
        outer.push_str(&String::from_utf8(inner)?);
        outer.push_str("\r\n--B--\r\n");
        inner = outer.into_bytes();
    }
    let out = text(&engine, Mode::Anonymize, &inner)?;
    assert!(out.contains("nesting too deep"), "{out:?}");
    Ok(())
}

// -- restoring through a restorer ---------------------------------------------------

/// A restorer scoped to every proxy in the vault of `engine`, as a tolerant restore has.
fn scoped_to_the_vault(engine: &Engine) -> Res<Restorer> {
    crate::files::tolerant_restorer(engine, true)?.ok_or_else(|| "the vault holds no proxy".into())
}

#[test]
fn a_tolerant_restore_repairs_the_text_of_documents_and_mail_in_the_same_pass() -> Res {
    let engine = engine()?;
    let proxy = engine.run(Mode::Anonymize, &[EMAIL])?.remove(0);
    // A doubled letter: a typo that only the tolerant tiers of the restorer repair.
    let typo = format!("{}{}", &proxy[..3], &proxy[2..]);
    let tolerant = scoped_to_the_vault(&engine)?;

    let document = docx_with(&format!(
        "{XML_HEAD}<w:document xmlns:w=\"w\"><w:body><w:p><w:r><w:t>mail {typo}</w:t></w:r></w:p>\
         <w:p><w:r><w:t>and {proxy}</w:t></w:r></w:p></w:body></w:document>"
    ))?;
    // The exact restore reads the proxy but not the typo ...
    let exact = same(&engine, Mode::Deanonymize, &document)?;
    assert_eq!(same_text(&exact)?, format!("mail {typo}\nand {EMAIL}"));
    // ... the restorer reads both, a text node at a time.
    let Output::Same(restored) = restore(&engine, &tolerant, &document)? else {
        return Err("expected a rewritten file, got text".into());
    };
    assert_eq!(same_text(&restored)?, format!("mail {EMAIL}\nand {EMAIL}"));

    let mail = format!("From: piet@example.net\r\nSubject: Offerte\r\n\r\nmail {typo}\r\n");
    for (name, bytes) in [
        ("mail", mail.into_bytes()),
        ("pdf", pdf(&format!("mail {typo}"))?),
    ] {
        let Output::Text(restored) = restore(&engine, &tolerant, &bytes)? else {
            return Err(format!("{name}: expected text, got a rewritten file").into());
        };
        assert!(
            restored.contains(EMAIL) && !restored.contains(&typo),
            "{name}: {restored:?}"
        );
    }
    Ok(())
}

// -- scanning ---------------------------------------------------------------------

/// What a scan found, as sorted `(kind, value)` pairs.
fn found(scanned: &Scanned) -> Vec<(EntityKind, &str)> {
    let mut found: Vec<_> = scanned
        .found
        .iter()
        .map(|(kind, value)| (*kind, &**value))
        .collect();
    found.sort_unstable();
    found
}

fn records(engine: &Engine) -> Res<u64> {
    Ok(engine.vault().read()?.record_count())
}

#[test]
fn scanning_a_docx_reports_its_values_and_issues_nothing() -> Res {
    let engine = engine()?;
    let scanned = scan(&engine, &docx()?, false)?;
    let values = found(&scanned);
    // The address stands in the body, in the hyperlink target and in the core properties.
    let emails = values.iter().filter(|&&v| v == (EntityKind::Email, EMAIL));
    assert_eq!(emails.count(), 3, "{values:?}");
    assert!(values.contains(&(EntityKind::Phone, PHONE)), "{values:?}");
    assert!(scanned.texts.is_empty(), "texts are kept only when asked");
    assert_eq!(records(&engine)?, 0);
    Ok(())
}

#[test]
fn a_masked_file_scans_as_clean() -> Res {
    let engine = engine()?;
    let masked = same(&engine, Mode::Anonymize, &docx()?)?;
    let issued = records(&engine)?;
    assert!(issued > 0);
    let scanned = scan(&engine, &masked, false)?;
    assert!(found(&scanned).is_empty(), "{:?}", found(&scanned));
    assert_eq!(records(&engine)?, issued);
    Ok(())
}

#[test]
fn scanning_keeps_the_texts_it_read_when_asked() -> Res {
    let engine = engine()?;
    let scanned = scan(&engine, &xlsx()?, true)?;
    let values = found(&scanned);
    for expected in [
        (EntityKind::Email, EMAIL),
        (EntityKind::Iban, IBAN),
        (EntityKind::Phone, MOBILE),
    ] {
        assert!(values.contains(&expected), "{expected:?} in {values:?}");
    }
    // A value split over two runs is read as one text, so a search can find it.
    assert!(
        scanned.texts.iter().any(|t| t == EMAIL),
        "{:?}",
        scanned.texts
    );
    assert!(scanned.texts.iter().any(|t| t == "gewoon tekst"));
    assert_eq!(records(&engine)?, 0);
    Ok(())
}

#[test]
fn scanning_an_eml_reads_the_headers_the_bodies_and_the_attachments() -> Res {
    let engine = engine()?;
    let scanned = scan(&engine, &eml(), true)?;
    let values = found(&scanned);
    for expected in [
        (EntityKind::Email, EMAIL),
        (EntityKind::Email, "piet@example.com"),
        (EntityKind::Phone, MOBILE),
        (EntityKind::Iban, IBAN),
    ] {
        assert!(values.contains(&expected), "{expected:?} in {values:?}");
    }
    let texts = scanned.texts.join("\n");
    assert!(texts.contains("Subject: Offerte"), "{texts:?}");
    assert!(texts.contains(&format!("Rekening {IBAN}")), "{texts:?}");
    assert_eq!(records(&engine)?, 0);
    Ok(())
}

#[test]
fn scanning_a_msg_reads_it_like_an_eml() -> Res {
    let engine = engine()?;
    let scanned = scan(&engine, &msg()?, false)?;
    let values = found(&scanned);
    for expected in [
        (EntityKind::Email, EMAIL),
        (EntityKind::Email, "piet@example.com"),
        (EntityKind::Email, "kees@example.net"),
        (EntityKind::Phone, MOBILE),
        (EntityKind::Iban, IBAN),
    ] {
        assert!(values.contains(&expected), "{expected:?} in {values:?}");
    }
    assert_eq!(records(&engine)?, 0);
    Ok(())
}

#[test]
fn scanning_a_msg_reads_the_embedded_message_and_its_attachments_in_order() -> Res {
    let engine = engine()?;
    let bytes = msg_with_embedded(&format!("Bel mij op {MOBILE}\r\n"))?;
    let scanned = scan(&engine, &bytes, true)?;
    let values = found(&scanned);
    for expected in [
        (EntityKind::Email, EMAIL),
        (EntityKind::Phone, MOBILE),
        (EntityKind::Iban, IBAN),
    ] {
        assert!(values.contains(&expected), "{expected:?} in {values:?}");
    }
    let texts = scanned.texts.join("\n");
    let embedded = texts
        .find("Subject: Voorstel")
        .ok_or("no embedded message")?;
    let nested = texts.find("Rekening").ok_or("no nested attachment")?;
    assert!(embedded < nested, "{texts:?}");
    assert_eq!(records(&engine)?, 0);

    // Messages beyond the limit are not read by a scan either.
    let deep = scan(&engine, &msg_with_nested_messages(8)?, true)?;
    let texts = deep.texts.join("\n");
    assert!(texts.contains("inhoud 4"), "{texts:?}");
    assert!(!texts.contains("inhoud 5"), "{texts:?}");
    Ok(())
}

#[test]
fn scanning_reads_a_pdf_text_layer_and_text_in_its_encoding() -> Res {
    let engine = engine()?;
    let from_pdf = scan(&engine, &pdf(&format!("mail {EMAIL}"))?, true)?;
    assert_eq!(found(&from_pdf), [(EntityKind::Email, EMAIL)]);
    assert!(from_pdf.texts.iter().any(|t| t.contains(EMAIL)));

    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(utf16le(&format!("Bel {MOBILE} of mail {EMAIL}\r\n")));
    let scanned = scan(&engine, &utf16, false)?;
    let values = found(&scanned);
    assert_eq!(
        values,
        [(EntityKind::Email, EMAIL), (EntityKind::Phone, MOBILE)]
    );
    assert_eq!(records(&engine)?, 0);
    Ok(())
}

#[test]
fn scanning_a_clean_file_finds_nothing_and_what_cannot_be_read_is_an_error() -> Res {
    let engine = engine()?;
    let clean = scan(&engine, b"nothing to see here", true)?;
    assert!(clean.found.is_empty());
    assert_eq!(clean.texts, ["nothing to see here"]);
    let zip = build_zip(&[("a.txt", b"hello", DEFLATED)])?;
    assert!(matches!(
        scan(&engine, &zip, false),
        Err(Error::UnsupportedFormat("zip archive"))
    ));
    assert!(matches!(
        scan(&engine, b"%PDF-1.7 this is not a pdf", false),
        Err(Error::Pdf(_))
    ));
    Ok(())
}

/// The finding for the first occurrence of `value` in `text`, taken as an email.
fn finding_of(text: &str, value: &str) -> Res<Finding> {
    let start = text.find(value).ok_or("the value is not in the text")?;
    let span = Span {
        start,
        end: start + value.len(),
        kind: EntityKind::Email,
    };
    Ok(finding(text, &span))
}

#[test]
fn a_finding_shows_the_value_with_the_text_around_it() -> Res {
    let text = "Please send the invoice to jan.jansen@example.org before Friday.";
    let one = finding_of(text, EMAIL)?;
    assert_eq!(one.kind, EntityKind::Email);
    assert_eq!(&*one.value, EMAIL);
    assert_eq!(&*one.snippet, text, "short enough to show whole");

    // The value alone, at either end of the text.
    assert_eq!(&*finding_of(EMAIL, EMAIL)?.snippet, EMAIL);
    let at_start = finding_of(&format!("{EMAIL} wrote this"), EMAIL)?;
    assert_eq!(&*at_start.snippet, format!("{EMAIL} wrote this"));
    Ok(())
}

#[test]
fn a_finding_cuts_the_text_to_forty_characters_a_side_and_says_so() -> Res {
    let before = "a".repeat(55);
    let after = "b".repeat(55);
    let one = finding_of(&format!("{before} {EMAIL} {after}"), EMAIL)?;
    assert_eq!(
        &*one.snippet,
        format!("…{} {EMAIL} {}…", "a".repeat(39), "b".repeat(39))
    );
    // The same at the exact limit: forty characters on a side fit, a forty-first is cut.
    let fits = finding_of(
        &format!("{} {EMAIL} {}", "c".repeat(39), "d".repeat(39)),
        EMAIL,
    )?;
    assert!(!fits.snippet.contains('…'), "{}", fits.snippet);
    let cut = finding_of(
        &format!("{} {EMAIL} {}", "c".repeat(41), "d".repeat(41)),
        EMAIL,
    )?;
    assert!(cut.snippet.starts_with('…') && cut.snippet.ends_with('…'));
    Ok(())
}

#[test]
fn a_finding_collapses_white_space_and_never_cuts_a_character_in_two() -> Res {
    let text = "Name:\r\n\t  Jan\n\n\nmail:\t jan.jansen@example.org \r\n\r\n ok";
    let one = finding_of(text, EMAIL)?;
    assert_eq!(&*one.snippet, "Name: Jan mail: jan.jansen@example.org ok");

    // Multi-byte characters on both sides, and a value that holds a line break: the cut falls
    // between characters, and the value reads as one line.
    let wide = format!("{}é{EMAIL}é{}", "é".repeat(60), "\u{1f600}".repeat(60));
    let one = finding_of(&wide, EMAIL)?;
    assert_eq!(one.snippet.chars().filter(|&c| c == 'é').count(), 40 + 1);
    assert!(one.snippet.starts_with('…') && one.snippet.ends_with('…'));
    let broken = "see Jan\n  Jansen, thanks";
    let span = Span {
        start: 4,
        end: 17,
        kind: EntityKind::Person,
    };
    let one = finding(broken, &span);
    assert_eq!(&*one.value, "Jan Jansen,");
    assert_eq!(&*one.snippet, "see Jan Jansen, thanks");
    Ok(())
}

#[test]
fn a_long_value_is_kept_whole_and_shown_cut_in_its_snippet() {
    let key = format!("-----BEGIN KEY-----{}", "k".repeat(400));
    let span = Span {
        start: 5,
        end: 5 + key.len(),
        kind: EntityKind::Secret,
    };
    let one = finding(&format!("key: {key} end"), &span);
    // The value is whole; the snippet shows its first 120 characters, and says it goes on.
    assert_eq!(&*one.value, key);
    let shown: String = key.chars().take(120).collect();
    assert!(
        one.snippet.contains(&format!("{shown}\u{2026}")),
        "{}",
        one.snippet
    );
    assert!(one.snippet.chars().count() < 121 + 2 * 40 + 4);
    // A run longer than any value a person reads is cut at 4,096 characters.
    let huge = "k".repeat(super::MAX_VALUE + 10);
    let span = Span {
        start: 0,
        end: huge.len(),
        kind: EntityKind::Secret,
    };
    let one = finding(&huge, &span);
    assert_eq!(one.value.chars().count(), super::MAX_VALUE + 1);
    assert!(one.value.ends_with('\u{2026}'));
}

#[test]
fn findings_list_what_a_scan_counts_in_reading_order_and_touch_nothing() -> Res {
    let engine = engine()?;
    let text = format!("Mail {EMAIL}, call {MOBILE}, pay {IBAN}, or mail {EMAIL} again.");
    let listed = findings(&engine, text.as_bytes())?;
    let scanned = scan(&engine, text.as_bytes(), false)?;
    assert_eq!(
        listed.len(),
        scanned.found.len(),
        "the same values a scan counts"
    );
    // In the order of the text, not grouped by kind: by kind the address comes first, then the
    // IBAN, then the phone number.
    let order = values_among(&listed, &[EMAIL, MOBILE, IBAN]);
    assert_eq!(order, [EMAIL, MOBILE, IBAN, EMAIL]);
    let emails: Vec<&str> = listed
        .iter()
        .filter(|one| one.kind == EntityKind::Email)
        .map(|one| &*one.snippet)
        .collect();
    assert_eq!(emails.len(), 2);
    assert!(emails[0].starts_with("Mail jan.jansen"));
    assert!(emails[1].contains("or mail jan.jansen@example.org again."));
    assert_eq!(records(&engine)?, 0, "nothing was issued");
    assert!(findings(&engine, b"just words")?.is_empty());
    assert!(matches!(
        findings(&engine, &build_zip(&[("a.txt", b"hello", DEFLATED)])?),
        Err(Error::UnsupportedFormat("zip archive"))
    ));
    Ok(())
}

#[test]
fn findings_read_a_document_the_way_a_scan_does() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &pdf(&format!("mail {EMAIL}"))?)?;
    assert_eq!(listed.len(), 1);
    assert_eq!(&*listed[0].value, EMAIL);
    assert!(listed[0].snippet.contains(&format!("mail {EMAIL}")));
    Ok(())
}

// -- where a finding stands ---------------------------------------------------------------

/// The places of the findings that are exactly `value`, in reading order.
fn places_of(listed: &[Finding], value: &str) -> Vec<Option<Location>> {
    listed
        .iter()
        .filter(|one| &*one.value == value)
        .map(|one| one.location.clone())
        .collect()
}

/// The values of `listed`, in reading order, that are one of `of`.
fn values_among<'a>(listed: &'a [Finding], of: &[&str]) -> Vec<&'a str> {
    listed
        .iter()
        .map(|one| &*one.value)
        .filter(|value| of.contains(value))
        .collect()
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the helper stands for the Option that a finding carries, so tests compare like with like"
)]
fn at_line(line: u32, column: u32) -> Option<Location> {
    Some(Location::Line { line, column })
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the helper stands for the Option that a finding carries, so tests compare like with like"
)]
fn in_cell(sheet: &str, cell: &str) -> Option<Location> {
    Some(Location::Cell {
        sheet: sheet.into(),
        cell: cell.into(),
    })
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the helper stands for the Option that a finding carries, so tests compare like with like"
)]
fn on_slide(slide: u32, shape: Option<u32>) -> Option<Location> {
    Some(Location::Slide { slide, shape })
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the helper stands for the Option that a finding carries, so tests compare like with like"
)]
fn in_paragraph(paragraph: u32, page: Option<u32>) -> Option<Location> {
    Some(Location::Paragraph { paragraph, page })
}

#[test]
fn a_value_in_a_text_says_its_line_and_column() -> Res {
    let engine = engine()?;
    // Lines end at a line feed, at a carriage return and line feed, and at a lone carriage
    // return; the line feed and carriage return before the number are two breaks.
    let text = format!("Mail {EMAIL}\nsecond line\r\nMail {EMAIL}\rnog een\n\rBel {MOBILE}");
    let listed = findings(&engine, text.as_bytes())?;
    assert_eq!(places_of(&listed, EMAIL), [at_line(1, 6), at_line(3, 6)]);
    assert_eq!(places_of(&listed, MOBILE), [at_line(6, 5)]);

    // Characters of more than one byte and a tab each count as one column.
    let wide = format!("Zoë 🙂\t{EMAIL}");
    let listed = findings(&engine, wide.as_bytes())?;
    assert_eq!(places_of(&listed, EMAIL), [at_line(1, 7)]);
    Ok(())
}

#[test]
fn the_line_and_column_are_those_of_the_decoded_text() -> Res {
    let engine = engine()?;
    // UTF-8 with a byte order mark: the mark is no column.
    let mut utf8 = b"\xEF\xBB\xBF".to_vec();
    utf8.extend(format!("Mail {EMAIL}").bytes());
    assert_eq!(
        places_of(&findings(&engine, &utf8)?, EMAIL),
        [at_line(1, 6)]
    );

    // UTF-16 with a byte order mark, over two lines.
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(utf16le(&format!(
        "Bel {MOBILE} of mail {EMAIL}\r\nMail {EMAIL}"
    )));
    let listed = findings(&engine, &utf16)?;
    assert_eq!(places_of(&listed, MOBILE), [at_line(1, 5)]);
    assert_eq!(places_of(&listed, EMAIL), [at_line(1, 28), at_line(2, 6)]);

    // Windows-1252: a column is a character, not the bytes UTF-8 would spell it with.
    let mut ansi = b"Caf\xE9 \x80 5, mail ".to_vec();
    ansi.extend(EMAIL.as_bytes());
    assert_eq!(
        places_of(&findings(&engine, &ansi)?, EMAIL),
        [at_line(1, 16)]
    );
    Ok(())
}

#[test]
fn many_values_on_one_line_each_have_their_column() -> Res {
    let engine = engine()?;
    let pieces: Vec<String> = (0..3000).map(|i| format!("p{i}@example.org ")).collect();
    let listed = findings(&engine, pieces.concat().as_bytes())?;
    assert_eq!(listed.len(), pieces.len());
    let mut column = 1;
    for (one, piece) in listed.iter().zip(&pieces) {
        assert_eq!(one.location, at_line(1, column), "{}", one.value);
        column += u32::try_from(piece.chars().count())?;
    }
    Ok(())
}

#[test]
fn a_value_in_a_pdf_says_its_page() -> Res {
    let engine = engine()?;
    let first = format!("mail {EMAIL}");
    let third = format!("Rekening {IBAN}");
    let pages = [
        first.as_str(),
        "geen gegevens op deze pagina",
        third.as_str(),
    ];
    let listed = findings(&engine, &pdf_pages(&pages)?)?;
    // The page without anything counts too.
    assert_eq!(places_of(&listed, EMAIL), [Some(Location::Page(1))]);
    assert_eq!(places_of(&listed, IBAN), [Some(Location::Page(3))]);
    Ok(())
}

#[test]
fn a_value_in_a_message_is_looked_up_in_its_file() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &located_eml())?;
    // The address of the header is the first finding of it, so at the first place it is written
    // in the file; the one in the body is the second.
    assert_eq!(places_of(&listed, EMAIL), [at_line(1, 19), at_line(10, 34)]);
    assert_eq!(places_of(&listed, "piet@example.com"), [at_line(2, 11)]);
    assert_eq!(places_of(&listed, MOBILE), [at_line(10, 11)]);
    Ok(())
}

#[test]
fn a_value_in_an_encoded_body_or_in_an_attachment_has_no_place() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &eml())?;
    assert_eq!(
        places_of(&listed, EMAIL).into_iter().next().flatten(),
        at_line(1, 19)
    );
    assert_eq!(places_of(&listed, "piet@example.com"), [at_line(2, 11)]);
    // The number is in the base64 body only, and the IBAN in an attachment, which is a file of
    // its own: the IBAN is in the clear in this one, all the same.
    assert_eq!(places_of(&listed, MOBILE), [None]);
    assert_eq!(places_of(&listed, IBAN), [None]);
    // Headers, then bodies, then attachments.
    let order = values_among(&listed, &["piet@example.com", MOBILE, IBAN]);
    assert_eq!(order, ["piet@example.com", MOBILE, IBAN]);
    Ok(())
}

#[test]
fn a_value_in_a_workbook_says_its_sheet_and_cell() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &workbook_with(true, &[])?)?;
    // A shared string shown by cells of both sheets is at the first of them, going through the
    // sheets and then through the cells.
    assert_eq!(places_of(&listed, EMAIL), [in_cell("Klanten", "B1")]);
    // On the second sheet, whose name the workbook escapes.
    assert_eq!(places_of(&listed, IBAN), [in_cell("Q&A", "B7")]);
    // An inline string, and the plain value of a cell.
    assert_eq!(places_of(&listed, MOBILE), [in_cell("Klanten", "D3")]);
    assert_eq!(
        places_of(&listed, "kees@example.net"),
        [in_cell("Q&A", "C9")]
    );
    // A shared string that no cell shows, and a header.
    assert_eq!(places_of(&listed, "piet@example.com"), [None]);
    assert_eq!(places_of(&listed, "lotte@example.net"), [None]);
    // Reading order: the shared strings, then each sheet.
    let all = [
        EMAIL,
        IBAN,
        MOBILE,
        "piet@example.com",
        "lotte@example.net",
        "kees@example.net",
    ];
    assert_eq!(
        values_among(&listed, &all),
        [
            EMAIL,
            IBAN,
            "piet@example.com",
            MOBILE,
            "lotte@example.net",
            "kees@example.net"
        ]
    );

    // The sheets go by the order the workbook lists them in, not by the order of their parts.
    let listed = findings(&engine, &workbook_with(false, &[])?)?;
    assert_eq!(places_of(&listed, EMAIL), [in_cell("Q&A", "A7")]);
    assert_eq!(places_of(&listed, MOBILE), [in_cell("Klanten", "D3")]);
    Ok(())
}

#[test]
fn a_workbook_that_cannot_be_read_has_values_without_places_and_no_error() -> Res {
    let engine = engine()?;
    // This one has no workbook part to say what its sheets are.
    let listed = findings(&engine, &xlsx()?)?;
    assert!(listed.len() >= 3, "{listed:?}");
    assert!(listed.iter().all(|one| one.location.is_none()));
    Ok(())
}

#[test]
fn a_value_in_an_opendocument_sheet_says_its_sheet_and_cell() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &ods()?)?;
    // Counted over the repeated rows and columns, and the covered cell. The creator in the meta
    // data is in no cell.
    assert_eq!(places_of(&listed, EMAIL), [in_cell("Klanten", "C3"), None]);
    assert_eq!(places_of(&listed, IBAN), [in_cell("Klanten", "E3")]);
    assert_eq!(
        places_of(&listed, "kees@example.net"),
        [in_cell("Klanten", "A4")]
    );
    assert_eq!(places_of(&listed, MOBILE), [in_cell("Q&A", "A1")]);
    Ok(())
}

#[test]
fn what_an_embedded_package_holds_has_no_place() -> Res {
    let engine = engine()?;
    let inner = workbook_with(true, &[])?;
    let outer = workbook_with(true, &[("xl/embeddings/Inner.xlsx", &inner, STORED)])?;
    let listed = findings(&engine, &outer)?;
    // The outer workbook comes first, with its cells, then the one it embeds, with none.
    assert_eq!(places_of(&listed, EMAIL), [in_cell("Klanten", "B1"), None]);
    assert_eq!(places_of(&listed, IBAN), [in_cell("Q&A", "B7"), None]);
    assert_eq!(places_of(&listed, MOBILE), [in_cell("Klanten", "D3"), None]);
    Ok(())
}

#[test]
fn a_value_in_a_presentation_is_at_its_slide_and_shape() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &pptx()?)?;
    // The slide that is shown first is `slide2.xml`: its picture is the first shape and the text
    // with the address the second. The layout and the properties are on no slide.
    assert_eq!(
        places_of(&listed, EMAIL),
        [on_slide(1, Some(2)), None, None],
        "{listed:?}"
    );
    // The table is the second shape of the slide that follows it.
    assert_eq!(places_of(&listed, MOBILE), [on_slide(2, Some(2))]);
    // What the notes of the first slide say is a place of its own.
    assert_eq!(places_of(&listed, IBAN), [Some(Location::Notes(1))]);
    Ok(())
}

#[test]
fn a_value_in_a_document_is_at_its_paragraph_and_page() -> Res {
    let engine = engine()?;
    let listed = findings(&engine, &paged_docx()?)?;
    // The second and the fifth paragraph; the header and the properties are in no paragraph.
    assert_eq!(
        places_of(&listed, EMAIL),
        [
            in_paragraph(2, Some(1)),
            in_paragraph(5, Some(3)),
            None,
            None
        ]
    );
    assert_eq!(places_of(&listed, MOBILE), [in_paragraph(3, Some(2))]);
    // The cell of a table holds a paragraph too.
    assert_eq!(places_of(&listed, IBAN), [in_paragraph(4, Some(2))]);
    // A document nobody laid out says nothing of its pages, and still has its paragraphs: the
    // address is in the first one, and so is the number that Word split over two runs.
    let plain = findings(&engine, &docx()?)?;
    assert_eq!(places_of(&plain, PHONE), [in_paragraph(1, None)]);
    assert_eq!(
        places_of(&plain, EMAIL),
        [in_paragraph(1, None), None, None]
    );
    Ok(())
}

#[test]
fn open_documents_and_messages_without_places_have_none() -> Res {
    let engine = engine()?;
    for (name, bytes) in [("odt", odt()?), ("msg", msg()?)] {
        let listed = findings(&engine, &bytes)?;
        assert!(!listed.is_empty(), "{name}");
        assert!(listed.iter().all(|one| one.location.is_none()), "{name}");
    }
    // In the paragraph the number comes before the address, and by kind it would come after.
    let listed = findings(&engine, &docx()?)?;
    let number = listed
        .iter()
        .position(|one| one.kind == EntityKind::Phone)
        .ok_or("no number")?;
    let address = listed
        .iter()
        .position(|one| one.kind == EntityKind::Email)
        .ok_or("no address")?;
    assert!(number < address, "{listed:?}");
    Ok(())
}

#[test]
fn asking_for_places_changes_nothing_a_scan_reports() -> Res {
    let engine = engine()?;
    let page = format!("mail {EMAIL}");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("text", format!("Mail {EMAIL}\r\nBel {MOBILE}").into_bytes()),
        ("docx", docx()?),
        ("paged docx", paged_docx()?),
        ("pptx", pptx()?),
        ("workbook", workbook_with(true, &[])?),
        ("ods", ods()?),
        ("eml", eml()),
        ("eml in plain text", located_eml()),
        (
            "pdf",
            pdf_pages(&[page.as_str(), "geen gegevens op deze pagina"])?,
        ),
        ("msg", msg()?),
    ];
    for (name, bytes) in &cases {
        let scanned = scan(&engine, bytes, false)?;
        let listed = findings(&engine, bytes)?;
        let counted: Vec<(EntityKind, &str)> = scanned
            .found
            .iter()
            .map(|(kind, value)| (*kind, &**value))
            .collect();
        let shown: Vec<(EntityKind, &str)> =
            listed.iter().map(|one| (one.kind, &*one.value)).collect();
        assert_eq!(counted, shown, "{name}");
    }
    assert_eq!(records(&engine)?, 0);
    Ok(())
}

// -- a read of findings that reports as it goes ------------------------------------

/// Finds `Marieke de Vries` as a person: it stands in for the model, which reads after the
/// patterns.
#[derive(Debug)]
struct Names;

impl crate::detect::Detector for Names {
    fn detect(&self, text: &str, _mode: Mode) -> Vec<Span> {
        text.match_indices("Marieke de Vries")
            .map(|(start, name)| Span {
                start,
                end: start + name.len(),
                kind: EntityKind::Person,
            })
            .collect()
    }
}

/// An engine whose detector is the patterns and then [`Names`].
fn engine_with_names() -> Res<Engine> {
    let detector = crate::detect::CompositeDetector(vec![
        Box::new(crate::detect::RegexDetector::new()?),
        Box::new(Names),
    ]);
    let vault =
        crate::vault::Vault::open(&crate::testing::temp_dir("formats-names").join("vault.pkv"))?;
    Ok(Engine::new(Box::new(detector), vault))
}

/// What a report is, in a word: `found <kinds>` or what the read is busy with.
fn shape(report: &Report) -> String {
    match report {
        Report::Found(list) => {
            let kinds: Vec<&str> = list.iter().map(|one| one.kind.as_str()).collect();
            format!("found {}", kinds.join("+"))
        }
        Report::Busy(busy) => format!("{busy:?}"),
    }
}

#[test]
fn what_patterns_find_is_reported_before_what_the_model_finds_with_the_progress_between() -> Res {
    let engine = engine_with_names()?;
    let text = format!("Marieke de Vries mailt {EMAIL}\nen belt {MOBILE}");
    let seen = reports(&engine, text.as_bytes())?;
    let shapes: Vec<String> = seen.iter().map(shape).collect();
    assert_eq!(
        shapes,
        [
            "found email+phone".to_owned(),
            format!("{:?}", Busy::Model { done: 0, total: 0 }),
            "found person".to_owned(),
        ]
    );
    // Each value knows its place, whichever step it came in.
    let listed = findings(&engine, text.as_bytes())?;
    assert_eq!(places_of(&listed, EMAIL), [at_line(1, 24)]);
    assert_eq!(places_of(&listed, MOBILE), [at_line(2, 9)]);
    assert_eq!(places_of(&listed, "Marieke de Vries"), [at_line(1, 1)]);
    // What a scan counts is what the steps hold together.
    let scanned = scan(&engine, text.as_bytes(), false)?;
    let mut counted: Vec<(EntityKind, &str)> = scanned
        .found
        .iter()
        .map(|(kind, value)| (*kind, &**value))
        .collect();
    let mut shown: Vec<(EntityKind, &str)> =
        listed.iter().map(|one| (one.kind, &*one.value)).collect();
    counted.sort();
    shown.sort();
    assert_eq!(counted, shown);
    Ok(())
}

#[test]
fn the_values_of_a_message_wait_for_the_whole_call_because_they_are_placed_together() -> Res {
    let engine = engine_with_names()?;
    let mail =
        format!("From: Jan <{EMAIL}>\r\nSubject: Hallo\r\n\r\nMarieke de Vries belt {MOBILE}\r\n");
    let seen = reports(&engine, mail.as_bytes())?;
    // The progress of the model is still told, but every value comes in one report, once the
    // call is done, each with the place it has in the file.
    let shapes: Vec<String> = seen.iter().map(shape).collect();
    assert_eq!(shapes.len(), 2, "{shapes:?}");
    assert_eq!(
        shapes[0],
        format!("{:?}", Busy::Model { done: 0, total: 0 })
    );
    assert!(shapes[1].starts_with("found "), "{shapes:?}");
    let listed = findings(&engine, mail.as_bytes())?;
    assert_eq!(places_of(&listed, EMAIL), [at_line(1, 12)]);
    assert_eq!(places_of(&listed, "Marieke de Vries"), [at_line(4, 1)]);
    assert_eq!(places_of(&listed, MOBILE), [at_line(4, 23)]);
    Ok(())
}

#[test]
fn findings_come_in_reports_of_a_thousand_and_a_read_stops_when_its_reader_says_so() -> Res {
    let engine = engine()?;
    let many = (0..2_500).fold(String::new(), |mut all, i| {
        let _ = writeln!(all, "p{i}@example.org");
        all
    });
    let sizes: Vec<usize> = reports(&engine, many.as_bytes())?
        .iter()
        .filter_map(|report| match report {
            Report::Found(list) => Some(list.len()),
            Report::Busy(_) => None,
        })
        .collect();
    assert_eq!(sizes, [1_000, 1_000, 500]);

    // A reader that has had enough after the first report gets no second.
    let calls = std::sync::atomic::AtomicUsize::new(0);
    super::findings(&engine, many.as_bytes(), &|_| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        false
    })?;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}
