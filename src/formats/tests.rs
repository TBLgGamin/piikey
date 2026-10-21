//! End-to-end tests: every format against a real engine and a temporary vault.
//! Fixtures are built in code.

use std::io::{Cursor, Read, Write};

use cfb::CompoundFile;
use lopdf::{
    Dictionary, Document, Object, Stream,
    content::{Content, Operation},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use super::{Format, Output, Scanned, package, process, same_text, scan, sniff};
use crate::{
    Error,
    detect::{EntityKind, Mode},
    engine::Engine,
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

fn pdf(text: &str) -> Res<Vec<u8>> {
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
    let first_page = doc.add_object(page);
    let mut pages = Dictionary::new();
    pages.set("Type", "Pages");
    pages.set("Kids", vec![Object::from(first_page)]);
    pages.set("Count", 1);
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
fn mail_needs_a_known_first_header_and_a_blank_line() {
    assert_eq!(
        sniff(b"From: a@b.nl\r\nSubject: x\r\n\r\nbody"),
        Format::Mail
    );
    assert_eq!(sniff(b"\n\nreceived: by x\nTo: y\n\nbody"), Format::Mail);
    assert_eq!(sniff(b"\xEF\xBB\xBFSubject: hi\n\nbody"), Format::Mail);
    assert_eq!(sniff(b"Subject: no blank line follows"), Format::Text);
    assert_eq!(sniff(b"hello\nFrom: x\n\nbody"), Format::Text);
    assert_eq!(sniff(b"Frontier: x\n\nbody"), Format::Text);
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
