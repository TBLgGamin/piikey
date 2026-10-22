//! Plain text in any common encoding, rewritten in the encoding it came in.
//!
//! RTF, HTML, CSV, JSON, XML, Markdown and logs are all just text here.

use std::borrow::Cow;

use super::{Output, Pass, places::Layout};
use crate::{Error, Result, engine::Engine};

pub(super) const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
pub(super) const UTF16LE_BOM: [u8; 2] = [0xFF, 0xFE];
pub(super) const UTF16BE_BOM: [u8; 2] = [0xFE, 0xFF];
const UTF32LE_BOM: [u8; 4] = [0xFF, 0xFE, 0x00, 0x00];
const UTF32BE_BOM: [u8; 4] = [0x00, 0x00, 0xFE, 0xFF];

/// Share of the high bytes of 16-bit units that must be NUL before BOM-less data counts as
/// UTF-16.
const UTF16_NUL_SHARE: usize = 30;

/// Characters Windows-1252 puts at 0x80..=0x9F. The five undefined bytes map
/// to the C1 control of the same value, so every byte round-trips.
const CP1252_C1: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// How a byte string spells its text, so it can be written back the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Encoding {
    Utf8,
    Utf8Bom,
    /// UTF-16LE found by NUL density, no BOM.
    Utf16Le,
    Utf16LeBom,
    /// UTF-16BE found by NUL density, no BOM.
    Utf16Be,
    Utf16BeBom,
    Windows1252,
}

impl Encoding {
    /// Whether the text is spelled in 16-bit units.
    pub(super) fn is_utf16(self) -> bool {
        matches!(
            self,
            Self::Utf16Le | Self::Utf16LeBom | Self::Utf16Be | Self::Utf16BeBom
        )
    }
}

/// Decodes `bytes`, trying in order: UTF-8 BOM, UTF-16 BOMs, BOM-less UTF-16 (little endian,
/// then big), valid UTF-8, then Windows-1252 for data without NUL bytes.
///
/// BOM-less UTF-16 is tried before UTF-8 because ASCII text in UTF-16 is also valid UTF-8
/// (every other byte is NUL) and would otherwise hide all its PII from the detector. Real
/// UTF-8 text has no NULs.
///
/// # Errors
/// `UnsupportedFormat` for UTF-32, which is not read, and for invalid or binary data.
pub(super) fn decode(bytes: &[u8]) -> Result<(Cow<'_, str>, Encoding)> {
    if let Some(rest) = bytes.strip_prefix(&UTF8_BOM) {
        let text =
            std::str::from_utf8(rest).map_err(|_| Error::UnsupportedFormat("invalid UTF-8"))?;
        return Ok((Cow::Borrowed(text), Encoding::Utf8Bom));
    }
    // The UTF-32LE BOM starts with the UTF-16LE one: read as UTF-16 the text would be full of
    // NULs, and its PII would stay hidden.
    if bytes.starts_with(&UTF32LE_BOM) || bytes.starts_with(&UTF32BE_BOM) {
        return Err(Error::UnsupportedFormat("UTF-32"));
    }
    if let Some(rest) = bytes.strip_prefix(&UTF16LE_BOM) {
        let text = utf16(rest, u16::from_le_bytes)?;
        return Ok((Cow::Owned(text), Encoding::Utf16LeBom));
    }
    if let Some(rest) = bytes.strip_prefix(&UTF16BE_BOM) {
        let text = utf16(rest, u16::from_be_bytes)?;
        return Ok((Cow::Owned(text), Encoding::Utf16BeBom));
    }
    if looks_like_utf16(bytes, 1)
        && let Ok(text) = utf16(bytes, u16::from_le_bytes)
    {
        return Ok((Cow::Owned(text), Encoding::Utf16Le));
    }
    if looks_like_utf16(bytes, 0)
        && let Ok(text) = utf16(bytes, u16::from_be_bytes)
    {
        return Ok((Cow::Owned(text), Encoding::Utf16Be));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok((Cow::Borrowed(text), Encoding::Utf8));
    }
    if !bytes.contains(&0) {
        return Ok((Cow::Owned(windows_1252(bytes)), Encoding::Windows1252));
    }
    Err(Error::UnsupportedFormat("binary"))
}

/// Writes `text` the way `encoding` spells it.
///
/// # Errors
/// `UnsupportedFormat` when `text` holds a character Windows-1252 cannot spell.
pub(super) fn encode(text: String, encoding: Encoding) -> Result<Vec<u8>> {
    match encoding {
        Encoding::Utf8 => Ok(text.into_bytes()),
        Encoding::Utf8Bom => {
            let mut out = Vec::with_capacity(UTF8_BOM.len() + text.len());
            out.extend_from_slice(&UTF8_BOM);
            out.extend_from_slice(text.as_bytes());
            Ok(out)
        }
        Encoding::Utf16Le => Ok(utf16_bytes(&text, &[], u16::to_le_bytes)),
        Encoding::Utf16LeBom => Ok(utf16_bytes(&text, &UTF16LE_BOM, u16::to_le_bytes)),
        Encoding::Utf16Be => Ok(utf16_bytes(&text, &[], u16::to_be_bytes)),
        Encoding::Utf16BeBom => Ok(utf16_bytes(&text, &UTF16BE_BOM, u16::to_be_bytes)),
        Encoding::Windows1252 => text.chars().map(cp1252_byte).collect(),
    }
}

/// Anonymizes or deanonymizes a text file, keeping its encoding and BOM. A scan that is asked for
/// findings names the line and column of each value in the decoded text, when the file is not
/// one that sits inside another (`depth` above 0).
pub(super) fn process(pass: &Pass<'_>, bytes: &[u8], depth: u8) -> Result<Output> {
    let (text, encoding) = decode(bytes)?;
    let layout = if pass.wants_places(depth) {
        Layout::Lines
    } else {
        Layout::Nowhere
    };
    let reps = pass.plan(&layout, &[&*text])?.pop().unwrap_or_default();
    if reps.is_empty() {
        return Ok(Output::Same(pass.unchanged(bytes)));
    }
    let out = Engine::apply(&text, &reps);
    Ok(Output::Same(encode(out, encoding)?))
}

/// True when at least `UTF16_NUL_SHARE` percent of the high bytes of the 16-bit units (at
/// offset `high` in each pair) are NUL.
fn looks_like_utf16(bytes: &[u8], high: usize) -> bool {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let units = bytes.len() / 2;
    let nuls = bytes
        .iter()
        .skip(high)
        .step_by(2)
        .filter(|&&b| b == 0)
        .count();
    nuls * 100 >= units * UTF16_NUL_SHARE
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String> {
    let (pairs, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::UnsupportedFormat("truncated UTF-16"));
    }
    char::decode_utf16(pairs.iter().map(|&p| unit(p)))
        .collect::<Result<String, _>>()
        .map_err(|_| Error::UnsupportedFormat("invalid UTF-16"))
}

fn utf16_bytes(text: &str, bom: &[u8], unit: fn(u16) -> [u8; 2]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bom.len() + text.len() * 2);
    out.extend_from_slice(bom);
    for u in text.encode_utf16() {
        out.extend_from_slice(&unit(u));
    }
    out
}

fn windows_1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9F => CP1252_C1[usize::from(b - 0x80)],
            _ => char::from(b),
        })
        .collect()
}

fn cp1252_byte(c: char) -> Result<u8> {
    let code = u32::from(c);
    let byte = match code {
        0..=0x7F | 0xA0..=0xFF => u8::try_from(code).ok(),
        _ => CP1252_C1
            .iter()
            .position(|&x| x == c)
            .and_then(|i| u8::try_from(0x80 + i).ok()),
    };
    byte.ok_or(Error::UnsupportedFormat(
        "character not representable in Windows-1252",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn round_trip(bytes: &[u8]) -> Result<(String, Encoding)> {
        let (text, encoding) = decode(bytes)?;
        let again = encode(text.clone().into_owned(), encoding)?;
        assert_eq!(again, bytes, "re-encoding must reproduce the input");
        Ok((text.into_owned(), encoding))
    }

    #[test]
    fn utf8_with_and_without_bom() -> TestResult {
        assert_eq!(
            round_trip("héllo".as_bytes())?,
            ("héllo".into(), Encoding::Utf8)
        );
        let mut bom = UTF8_BOM.to_vec();
        bom.extend_from_slice("héllo".as_bytes());
        assert_eq!(round_trip(&bom)?, ("héllo".into(), Encoding::Utf8Bom));
        Ok(())
    }

    #[test]
    fn utf16_with_bom_both_orders() -> TestResult {
        let mut le = UTF16LE_BOM.to_vec();
        le.extend("a€😀".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(round_trip(&le)?, ("a€😀".into(), Encoding::Utf16LeBom));
        let mut be = UTF16BE_BOM.to_vec();
        be.extend("a€😀".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(round_trip(&be)?, ("a€😀".into(), Encoding::Utf16BeBom));
        Ok(())
    }

    #[test]
    fn bomless_utf16_beats_utf8_in_both_orders() -> TestResult {
        // ASCII in UTF-16 is valid UTF-8 too; the NUL density must win.
        let text = "mail jan@example.org";
        let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
        for bytes in [&le, &be] {
            assert!(std::str::from_utf8(bytes).is_ok());
        }
        assert_eq!(round_trip(&le)?, (text.into(), Encoding::Utf16Le));
        assert_eq!(round_trip(&be)?, (text.into(), Encoding::Utf16Be));
        Ok(())
    }

    #[test]
    fn utf32_is_refused_instead_of_read_as_text_full_of_nuls() {
        let mut le = UTF32LE_BOM.to_vec();
        le.extend(
            "mail jan@example.org"
                .chars()
                .flat_map(|c| u32::from(c).to_le_bytes()),
        );
        let mut be = UTF32BE_BOM.to_vec();
        be.extend(
            "mail jan@example.org"
                .chars()
                .flat_map(|c| u32::from(c).to_be_bytes()),
        );
        for bytes in [le, be] {
            assert!(matches!(
                decode(&bytes),
                Err(Error::UnsupportedFormat("UTF-32"))
            ));
        }
    }

    #[test]
    fn windows_1252_round_trips_every_byte() -> TestResult {
        let all: Vec<u8> = (1..=255).collect();
        let (text, encoding) = round_trip(&all)?;
        assert_eq!(encoding, Encoding::Windows1252);
        assert_eq!(text.chars().nth(0x80 - 1), Some('\u{20AC}'));
        assert_eq!(text.chars().nth(0xE9 - 1), Some('é'));
        Ok(())
    }

    #[test]
    fn windows_1252_rejects_characters_it_cannot_spell() {
        assert!(matches!(
            encode("łódź".to_owned(), Encoding::Windows1252),
            Err(Error::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn binary_is_unsupported() {
        let mut bytes = vec![0x90, 0x00, 0xFF, 0x13, 0x00, 0x80, 0x00];
        bytes.extend((0..200u8).map(|b| b.wrapping_mul(37)));
        assert!(matches!(
            decode(&bytes),
            Err(Error::UnsupportedFormat("binary"))
        ));
    }

    #[test]
    fn invalid_utf16_is_unsupported() {
        let lone_surrogate = [0xFF, 0xFE, 0x00, 0xD8];
        assert!(matches!(
            decode(&lone_surrogate),
            Err(Error::UnsupportedFormat(_))
        ));
        let odd = [0xFF, 0xFE, 0x41];
        assert!(matches!(decode(&odd), Err(Error::UnsupportedFormat(_))));
    }

    #[test]
    fn empty_input_is_empty_utf8() -> TestResult {
        assert_eq!(round_trip(b"")?, (String::new(), Encoding::Utf8));
        Ok(())
    }
}
