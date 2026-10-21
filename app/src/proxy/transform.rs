//! What outgoing request bodies become: the user's personal data replaced by proxies.
//!
//! While the user's input is captured ([`Typed`]) that is the values they typed or pasted,
//! wherever those occur in the body, and nothing else: scripts, ids and telemetry are not text
//! anyone wrote. Without capture it is every PII value detection finds in the body. Uploaded
//! files are always checked in full.
//!
//! Bodies are anonymized as bytes: JSON and text go to the engine as they
//! are (proxies are plain ASCII and a replaced value is never part of JSON
//! syntax), forms are decoded value by value, and multipart bodies are cut
//! into parts, text parts anonymized and file parts handed to the document
//! processors. Everything outside a replaced value is copied byte for byte.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    ops::Range,
};

use hudsucker::hyper::header::{CONTENT_TYPE, HeaderMap};

use super::{Typed, events::Framing};
use piikey::{
    Result,
    detect::{EntityKind, Mode},
    engine::{Engine, Resent},
    formats::{self, Output},
};

/// A request or response `Content-Type`, reduced to what routing needs.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ContentType {
    /// `type/subtype`, lowercase, without parameters.
    pub essence: String,
    pub boundary: Option<String>,
}

impl ContentType {
    /// `None` when the header is missing or has bytes a header value may not carry.
    pub(super) fn of(headers: &HeaderMap) -> Option<Self> {
        let raw = headers.get(CONTENT_TYPE)?.to_str().ok()?;
        let mut params = raw.split(';');
        let essence = params.next()?.trim().to_ascii_lowercase();
        let boundary = params.find_map(|param| {
            let (key, value) = param.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case("boundary")
                .then(|| value.trim().trim_matches('"').to_owned())
        });
        Some(Self { essence, boundary })
    }

    /// Text a person could read: where proxies can appear and be restored.
    pub(super) fn is_text(&self) -> bool {
        let essence = self.essence.as_str();
        essence.starts_with("text/")
            || matches!(
                essence,
                "application/json"
                    | "application/x-ndjson"
                    | "application/ndjson"
                    | "application/jsonl"
                    | "application/jsonlines"
                    | "application/x-jsonlines"
                    | "application/xml"
            )
            || essence.ends_with("+json")
            || essence.ends_with("+xml")
    }

    /// How the events of a response of this type are delimited; `None` when it
    /// is not an event stream.
    pub(super) fn framing(&self) -> Option<Framing> {
        match self.essence.as_str() {
            "text/event-stream" => Some(Framing::Sse),
            "application/x-ndjson"
            | "application/ndjson"
            | "application/jsonl"
            | "application/jsonlines"
            | "application/x-jsonlines" => Some(Framing::Ndjson),
            _ => None,
        }
    }

    /// Text whose proxies are worth restoring in a response: [`is_text`]
    /// minus the scripts and style sheets a site serves its pages with.
    ///
    /// [`is_text`]: Self::is_text
    pub(super) fn is_restorable(&self) -> bool {
        self.is_text()
            && !matches!(
                self.essence.as_str(),
                "text/css" | "text/javascript" | "text/ecmascript"
            )
    }

    /// How a request body of this type is anonymized; `None` when it is
    /// left alone (binary, or a multipart without a boundary).
    pub(super) fn body_kind(&self) -> Option<BodyKind> {
        match self.essence.as_str() {
            "application/x-www-form-urlencoded" => Some(BodyKind::Form),
            "multipart/form-data" => self
                .boundary
                .clone()
                .filter(|boundary| !boundary.is_empty())
                .map(BodyKind::Multipart),
            _ => self.is_text().then_some(BodyKind::Text),
        }
    }
}

/// How to read a request body.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BodyKind {
    /// JSON and other text.
    Text,
    /// `application/x-www-form-urlencoded`.
    Form,
    /// `multipart/form-data` with this boundary.
    Multipart(String),
}

/// An anonymized body.
#[derive(Debug)]
pub(super) struct Masked {
    pub body: Vec<u8>,
    /// Values replaced, by kind name, most frequent first; `attachment` counts
    /// uploaded files whose content changed.
    pub counts: Vec<(&'static str, usize)>,
    /// Every issued proxy the outgoing text carries, newly issued or sent
    /// before (a chat client resends its history with each message).
    pub proxies: Vec<String>,
}

/// Anonymizes `body`: the values the user typed or pasted while `typed` is active, every PII
/// value detection finds otherwise. Uploaded files are checked in full either way. The
/// stand-ins `resent` says yes to were sent to this site before: they go out as they are (a chat
/// client resends its history) instead of being masked as values of their own.
///
/// # Errors
/// Vault failures; the caller must not forward the original then.
pub(super) fn mask(
    engine: &Engine,
    typed: &Typed,
    resent: Resent<'_>,
    kind: &BodyKind,
    body: &[u8],
) -> Result<Masked> {
    let mut found = Found::default();
    let body = match kind {
        BodyKind::Text => mask_text(engine, typed, resent, body, &mut found)?,
        BodyKind::Form => mask_form(engine, typed, resent, body, &mut found)?,
        BodyKind::Multipart(boundary) => {
            mask_multipart(engine, typed, resent, body, boundary, &mut found)?
        }
    };
    Ok(Masked {
        body,
        counts: found.counts(),
        proxies: found.proxies.into_iter().collect(),
    })
}

/// What anonymizing one body turned up.
#[derive(Debug, Default)]
struct Found {
    replaced: BTreeMap<EntityKind, usize>,
    attachments: usize,
    proxies: BTreeSet<String>,
}

impl Found {
    fn counts(&self) -> Vec<(&'static str, usize)> {
        let mut counts: Vec<_> = self
            .replaced
            .iter()
            .map(|(kind, &n)| (kind.as_str(), n))
            .collect();
        if self.attachments > 0 {
            counts.push(("attachment", self.attachments));
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        counts
    }
}

/// Anonymizes `texts`, tallying what was replaced, and records every proxy the results carry.
fn mask_texts(
    engine: &Engine,
    typed: &Typed,
    resent: Resent<'_>,
    texts: &[&str],
    found: &mut Found,
) -> Result<Vec<String>> {
    if typed.is_active() {
        mask_typed(engine, typed, resent, texts, found)
    } else {
        mask_detected(engine, resent, texts, found)
    }
}

/// Replaces the values the user typed or pasted, and nothing else.
fn mask_typed(
    engine: &Engine,
    typed: &Typed,
    resent: Resent<'_>,
    texts: &[&str],
    found: &mut Found,
) -> Result<Vec<String>> {
    // What was typed just before sending may still wait for detection.
    typed.flush(engine)?;
    let masked: Vec<String> = match typed.matcher() {
        Some(matcher) => texts
            .iter()
            .map(|text| {
                let (masked, replaced) = typed.replace(&matcher, text);
                for (kind, proxy) in replaced {
                    *found.replaced.entry(kind).or_default() += 1;
                    found.proxies.insert(proxy.into_string());
                }
                masked
            })
            .collect(),
        // Values were typed but cannot be searched for, or capture stopped (and dropped them)
        // after the caller looked, or cannot see the screen: nothing says what is safe to send,
        // so the whole request is checked, as without capture.
        None if typed.has_values() || !typed.is_active() => {
            return mask_detected(engine, resent, texts, found);
        }
        // Nothing was typed, so there is nothing to hide.
        None => texts.iter().map(|&text| text.to_owned()).collect(),
    };
    // A chat client resends its history: the proxies in it reach the ledger as they always did.
    note_proxies(engine, &masked, found)?;
    Ok(masked)
}

/// Anonymizes `texts` in one engine call, replacing every PII value detection finds.
fn mask_detected(
    engine: &Engine,
    resent: Resent<'_>,
    texts: &[&str],
    found: &mut Found,
) -> Result<Vec<String>> {
    let plans = engine.anonymize(texts, resent)?;
    if plans.iter().any(|plan| !plan.is_empty()) {
        let view = engine.vault().read()?;
        for rep in plans.iter().flatten() {
            if let Some(kind) = view.kind_of(&rep.with) {
                *found.replaced.entry(kind).or_default() += 1;
            }
        }
    }
    let masked: Vec<String> = texts
        .iter()
        .zip(&plans)
        .map(|(text, reps)| Engine::apply(text, reps))
        .collect();
    note_proxies(engine, &masked, found)?;
    Ok(masked)
}

/// Adds every issued proxy found in `texts` to `found.proxies`. Only the vault's stand-ins are
/// looked up: no detection runs over the texts again.
fn note_proxies(engine: &Engine, texts: &[String], found: &mut Found) -> Result<()> {
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let spans = engine.proxies_in(&refs)?;
    for (text, spans) in refs.iter().zip(&spans) {
        for span in spans {
            found.proxies.insert(text[span.start..span.end].to_owned());
        }
    }
    Ok(())
}

/// JSON and other text. Invalid UTF-8 (a legacy charset, a stray binary
/// blob) is not an error: the valid stretches are anonymized and the rest
/// passes through.
fn mask_text(
    engine: &Engine,
    typed: &Typed,
    resent: Resent<'_>,
    bytes: &[u8],
    found: &mut Found,
) -> Result<Vec<u8>> {
    let chunks: Vec<_> = bytes.utf8_chunks().collect();
    let texts: Vec<&str> = chunks.iter().map(std::str::Utf8Chunk::valid).collect();
    let mut masked = mask_texts(engine, typed, resent, &texts, found)?;
    // Valid UTF-8, the usual case: the masked text is the whole body, as it is.
    if let ([chunk], 1) = (chunks.as_slice(), masked.len())
        && chunk.invalid().is_empty()
        && let Some(text) = masked.pop()
    {
        return Ok(text.into_bytes());
    }
    let mut out = Vec::with_capacity(bytes.len());
    for (chunk, text) in chunks.iter().zip(&masked) {
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(chunk.invalid());
    }
    Ok(out)
}

/// `key=value&key=value`: only values are anonymized, and only those that
/// change are re-encoded, so everything else keeps its exact spelling.
fn mask_form(
    engine: &Engine,
    typed: &Typed,
    resent: Resent<'_>,
    bytes: &[u8],
    found: &mut Found,
) -> Result<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return mask_text(engine, typed, resent, bytes, found);
    };
    let fields: Vec<(&str, Option<&str>)> = text
        .split('&')
        .map(|field| match field.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (field, None),
        })
        .collect();
    let plain: Vec<Option<String>> = fields
        .iter()
        .map(|&(_, value)| value.and_then(percent_decode))
        .collect();
    let to_mask: Vec<&str> = plain.iter().flatten().map(String::as_str).collect();
    let mut masked = mask_texts(engine, typed, resent, &to_mask, found)?.into_iter();

    let mut out = String::with_capacity(text.len());
    for (n, (&(key, value), plain)) in fields.iter().zip(&plain).enumerate() {
        if n > 0 {
            out.push('&');
        }
        out.push_str(key);
        let Some(raw) = value else { continue };
        out.push('=');
        match plain {
            Some(plain) => match masked.next() {
                Some(new) if new != *plain => out.push_str(&percent_encode(&new)),
                _ => out.push_str(raw),
            },
            None => out.push_str(raw),
        }
    }
    Ok(out.into_bytes())
}

/// Decodes `%XX` and `+` (space); `None` unless the result is UTF-8. A `%`
/// not followed by two hex digits stays as it is.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = |at: usize| bytes.get(at).and_then(|&b| char::from(b).to_digit(16));
                if let (Some(high), Some(low)) = (hex(i + 1), hex(i + 2)) {
                    out.push(u8::try_from(high * 16 + low).ok()?);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Everything but `A-Z a-z 0-9 - _ . ~` as `%XX`.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// One part of a multipart body, as byte ranges of that body.
#[derive(Debug)]
struct Part {
    /// Header lines, without the blank line that ends them.
    head: Range<usize>,
    body: Range<usize>,
}

/// A part's replacement.
struct Edit {
    /// New header block, when it changes.
    head: Option<Vec<u8>>,
    body: Vec<u8>,
}

/// Text parts are anonymized; parts with a `filename` are files and go to the
/// document processors, whether or not the user's input is captured: an
/// upload is the user's content by definition. A file in a format they do not
/// know (or cannot read) is forwarded unchanged: it cannot be inspected, and
/// blocking uploads is not this app's call. A body that does not parse as
/// multipart is treated as plain text.
fn mask_multipart(
    engine: &Engine,
    typed: &Typed,
    resent: Resent<'_>,
    bytes: &[u8],
    boundary: &str,
    found: &mut Found,
) -> Result<Vec<u8>> {
    let Some(parts) = split_multipart(bytes, boundary) else {
        return mask_text(engine, typed, resent, bytes, found);
    };
    let mut out = Vec::with_capacity(bytes.len());
    let mut copied = 0;
    for part in &parts {
        let head = &bytes[part.head.clone()];
        let body = &bytes[part.body.clone()];
        let edit = if let Some(name) = file_name(head) {
            mask_file(engine, head, body, &name, found)?
        } else {
            let masked = mask_text(engine, typed, resent, body, found)?;
            (masked != body).then_some(Edit {
                head: None,
                body: masked,
            })
        };
        let Some(edit) = edit else { continue };
        out.extend_from_slice(&bytes[copied..part.head.start]);
        match &edit.head {
            Some(head) => out.extend_from_slice(head),
            None => out.extend_from_slice(&bytes[part.head.clone()]),
        }
        out.extend_from_slice(&bytes[part.head.end..part.body.start]);
        out.extend_from_slice(&edit.body);
        copied = part.body.end;
    }
    out.extend_from_slice(&bytes[copied..]);
    Ok(out)
}

/// An uploaded file: same format back, or its text when the format only
/// yields text (PDF, images, mail).
fn mask_file(
    engine: &Engine,
    head: &[u8],
    body: &[u8],
    name: &str,
    found: &mut Found,
) -> Result<Option<Edit>> {
    match formats::process(engine, Mode::Anonymize, body, 0) {
        Ok(Output::Same(new)) if new != body => {
            found.attachments += 1;
            Ok(Some(Edit {
                head: None,
                body: new,
            }))
        }
        Ok(Output::Same(_)) | Err(_) => Ok(None),
        Ok(Output::Text(text)) => {
            found.attachments += 1;
            note_proxies(engine, std::slice::from_ref(&text), found)?;
            Ok(Some(Edit {
                head: Some(retarget_head(head, name)),
                body: text.into_bytes(),
            }))
        }
    }
}

/// Splits a multipart body at its delimiter lines. `None` when it does not
/// look like one (no delimiter, no closing delimiter, a part without headers
/// section).
fn split_multipart(data: &[u8], boundary: &str) -> Option<Vec<Part>> {
    let delimiter = [b"--".as_slice(), boundary.as_bytes()].concat();
    let mut at = find_line_start(data, &delimiter, 0)?;
    let mut parts = Vec::new();
    loop {
        let after = at + delimiter.len();
        if data[after..].starts_with(b"--") {
            return Some(parts);
        }
        // The rest of the delimiter line may hold transport padding.
        let start = find(data, b"\n", after)? + 1;
        let next = find_line_start(data, &delimiter, start)?;
        let mut end = next;
        for byte in [b'\n', b'\r'] {
            if end > start && data[end - 1] == byte {
                end -= 1;
            }
        }
        parts.push(split_part(data, start, end)?);
        at = next;
    }
}

/// Headers and body of `data[start..end]`, which are separated by an empty
/// line.
fn split_part(data: &[u8], start: usize, end: usize) -> Option<Part> {
    let part = &data[start..end];
    let (head_len, separator) = if part.starts_with(b"\r\n") {
        (0, 2)
    } else if part.starts_with(b"\n") {
        (0, 1)
    } else if let Some(i) = find(part, b"\r\n\r\n", 0) {
        (i, 4)
    } else {
        (find(part, b"\n\n", 0)?, 2)
    };
    Some(Part {
        head: start..start + head_len,
        body: start + head_len + separator..end,
    })
}

/// First occurrence of `needle` in `hay[from..]`.
fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|i| i + from)
}

/// First occurrence of `needle` at the start of a line.
fn find_line_start(hay: &[u8], needle: &[u8], mut from: usize) -> Option<usize> {
    loop {
        let at = find(hay, needle, from)?;
        if at == 0 || hay[at - 1] == b'\n' {
            return Some(at);
        }
        from = at + 1;
    }
}

/// The part's file name, from `Content-Disposition`; `None` for a plain
/// field. `filename*=UTF-8''...` wins over `filename=`.
fn file_name(head: &[u8]) -> Option<String> {
    let line = header_line(head, "content-disposition")?;
    let params = split_params(&line);
    let value_of = |key: &str| {
        params.iter().find_map(|param| {
            let (name, value) = param.split_once('=')?;
            name.trim().eq_ignore_ascii_case(key).then(|| value.trim())
        })
    };
    if let Some(extended) = value_of("filename*") {
        // charset'language'percent-encoded
        let encoded = extended.splitn(3, '\'').nth(2).unwrap_or(extended);
        if let Some(name) = percent_decode(&encoded.replace('+', "%2B")) {
            return Some(name);
        }
    }
    value_of("filename").map(unquote)
}

/// The value of header `name` (lowercase) in a part's header block.
fn header_line(head: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(head).lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

/// Splits a header value at `;` outside quotes.
fn split_params(value: &str) -> Vec<String> {
    let mut params = vec![String::new()];
    let (mut quoted, mut escaped) = (false, false);
    for c in value.chars() {
        let Some(current) = params.last_mut() else {
            break;
        };
        match c {
            ';' if !quoted => {
                params.push(String::new());
                continue;
            }
            '"' if !escaped => quoted = !quoted,
            _ => {}
        }
        escaped = c == '\\' && !escaped;
        current.push(c);
    }
    params.into_iter().map(|p| p.trim().to_owned()).collect()
}

/// `"a \"b\".txt"` -> `a "b".txt`.
fn unquote(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('\\', Some(next @ ('"' | '\\'))) => {
                out.push(next);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

/// The header block of a file turned into text: the name gets `.txt`
/// appended (like the command line does) and the type becomes `text/plain`.
fn retarget_head(head: &[u8], name: &str) -> Vec<u8> {
    let renamed = format!("{name}.txt")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let mut lines = Vec::new();
    let mut typed = false;
    for line in String::from_utf8_lossy(head).lines() {
        let key = line
            .split_once(':')
            .map(|(key, _)| key.trim().to_ascii_lowercase());
        match key.as_deref() {
            Some("content-disposition") => {
                let value = line.split_once(':').map_or("", |(_, value)| value);
                let mut params: Vec<String> = split_params(value)
                    .into_iter()
                    .filter_map(|param| {
                        let key = param
                            .split('=')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_ascii_lowercase();
                        match key.as_str() {
                            "filename*" => None,
                            "filename" => Some(format!("filename=\"{renamed}\"")),
                            _ => Some(param),
                        }
                    })
                    .collect();
                if !params.iter().any(|param| param.starts_with("filename=")) {
                    params.push(format!("filename=\"{renamed}\""));
                }
                lines.push(format!("Content-Disposition: {}", params.join("; ")));
            }
            Some("content-type") => {
                typed = true;
                lines.push("Content-Type: text/plain".to_owned());
            }
            _ => lines.push(line.to_owned()),
        }
    }
    if !typed {
        lines.push("Content-Type: text/plain".to_owned());
    }
    lines.join("\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use hudsucker::hyper::header::HeaderValue;

    use super::*;

    fn engine(tag: &str) -> Result<Engine> {
        Engine::open(&crate::ui::testing::temp_dir(tag).join("vault.pkv"))
    }

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(content_type) {
            headers.insert(CONTENT_TYPE, value);
        }
        headers
    }

    /// `engine.run(Deanonymize)` over one text.
    fn restore(engine: &Engine, text: &str) -> Result<String> {
        Ok(engine.run(Mode::Deanonymize, &[text])?.remove(0))
    }

    fn utf8(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap_or("<not utf-8>")
    }

    #[test]
    fn content_type_parsing() {
        let ct = ContentType::of(&headers(
            "Multipart/Form-Data; charset=x; Boundary=\"----abc\"",
        ));
        assert_eq!(
            ct,
            Some(ContentType {
                essence: "multipart/form-data".into(),
                boundary: Some("----abc".into()),
            })
        );
        assert_eq!(ContentType::of(&HeaderMap::new()), None);
        let json = ContentType::of(&headers("application/json; charset=utf-8"));
        assert_eq!(json.map(|c| c.essence), Some("application/json".to_owned()));
    }

    #[test]
    fn which_types_are_rewritten() {
        let kind = |s: &str| ContentType::of(&headers(s)).and_then(|c| c.body_kind());
        for text in [
            "application/json",
            "application/json; charset=utf-8",
            "application/vnd.api+json",
            "application/x-ndjson",
            "application/xml",
            "text/plain",
            "text/event-stream",
            "text/html; charset=utf-8",
            "image/svg+xml",
        ] {
            assert_eq!(kind(text), Some(BodyKind::Text), "{text}");
        }
        assert_eq!(
            kind("application/x-www-form-urlencoded"),
            Some(BodyKind::Form)
        );
        assert_eq!(
            kind("multipart/form-data; boundary=xyz"),
            Some(BodyKind::Multipart("xyz".into()))
        );
        for left_alone in [
            "multipart/form-data",
            "multipart/form-data; boundary=",
            "application/octet-stream",
            "image/png",
            "application/pdf",
            "application/x-protobuf",
            "video/mp4",
        ] {
            assert_eq!(kind(left_alone), None, "{left_alone}");
        }
        assert_eq!(
            ContentType::of(&headers("text/event-stream")).map(|c| c.is_text()),
            Some(true)
        );
        assert_eq!(
            ContentType::of(&headers("image/png")).map(|c| c.is_text()),
            Some(false)
        );
    }

    #[test]
    fn page_scripts_and_styles_are_not_restored() {
        let restorable = |s: &str| ContentType::of(&headers(s)).map(|c| c.is_restorable());
        for yes in [
            "application/json",
            "text/event-stream",
            "text/plain",
            "text/html; charset=utf-8",
            "application/x-ndjson",
        ] {
            assert_eq!(restorable(yes), Some(true), "{yes}");
        }
        for no in [
            "text/css",
            "text/javascript; charset=utf-8",
            "image/png",
            "application/octet-stream",
        ] {
            assert_eq!(restorable(no), Some(false), "{no}");
        }
    }

    #[test]
    fn json_keeps_its_shape_and_hides_the_email() -> Result<()> {
        let engine = engine("json")?;
        let body = br#"{"m":"mail jan.jansen@acme.nl","n":[1,2],"t":"a\nb"}"#;
        let masked = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Text, body)?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert!(out.starts_with(r#"{"m":"mail "#) && out.ends_with(r#"","n":[1,2],"t":"a\nb"}"#));
        assert_eq!(masked.counts, [("email", 1)]);
        assert_eq!(masked.proxies.len(), 1);
        assert!(out.contains(&masked.proxies[0]));
        assert_eq!(restore(&engine, out)?, utf8(body));
        Ok(())
    }

    #[test]
    fn text_without_pii_is_unchanged_and_reports_nothing() -> Result<()> {
        let engine = engine("clean")?;
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Text,
            b"hello world, nothing to see",
        )?;
        assert_eq!(masked.body, b"hello world, nothing to see");
        assert!(masked.counts.is_empty() && masked.proxies.is_empty());
        let empty = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Text, b"")?;
        assert!(empty.body.is_empty());
        Ok(())
    }

    #[test]
    fn earlier_proxies_in_a_resent_history_are_reported_but_not_counted() -> Result<()> {
        let engine = engine("history")?;
        let first = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Text,
            b"mail jan.jansen@acme.nl",
        )?;
        let again = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Text,
            &first.body,
        )?;
        assert_eq!(again.body, first.body, "idempotent");
        assert!(again.counts.is_empty(), "nothing newly masked");
        assert_eq!(
            again.proxies, first.proxies,
            "but the ledger still learns of it"
        );
        Ok(())
    }

    #[test]
    fn counts_are_per_kind_most_frequent_first() -> Result<()> {
        let engine = engine("counts")?;
        let body =
            b"anna@acme.nl bob@acme.nl carl@acme.nl call +31 6 12345678 iban NL91ABNA0417164300";
        let masked = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Text, body)?;
        assert_eq!(masked.counts, [("email", 3), ("iban", 1), ("phone", 1)]);
        Ok(())
    }

    #[test]
    fn invalid_utf8_passes_through_around_masked_text() -> Result<()> {
        let engine = engine("latin1")?;
        let body = b"caf\xE9 jan.jansen@acme.nl \xFF\xFE end";
        let masked = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Text, body)?;
        assert!(masked.body.starts_with(b"caf\xE9 "));
        assert!(masked.body.ends_with(b" \xFF\xFE end"));
        assert!(!utf8_lossy(&masked.body).contains("jan.jansen"));
        Ok(())
    }

    fn utf8_lossy(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn percent_coding_round_trips() {
        assert_eq!(
            percent_decode("a%40b.nl+c%20d").as_deref(),
            Some("a@b.nl c d")
        );
        assert_eq!(percent_decode("100%").as_deref(), Some("100%"));
        assert_eq!(percent_decode("%zz%4").as_deref(), Some("%zz%4"));
        assert_eq!(percent_decode("%FF"), None, "not UTF-8");
        assert_eq!(percent_decode("%C3%A9").as_deref(), Some("é"));
        assert_eq!(
            percent_encode("a@b.nl c/d~é-_"),
            "a%40b.nl%20c%2Fd~%C3%A9-_"
        );
        for s in ["", "plain", "a b&c=d", "ünïcode ✓", "x%y+z"] {
            assert_eq!(percent_decode(&percent_encode(s)).as_deref(), Some(s));
        }
    }

    #[test]
    fn form_values_are_decoded_masked_and_reencoded() -> Result<()> {
        let engine = engine("form")?;
        let body = b"mail=jan.jansen%40acme.nl&x=1&note=a+b%21&flag&empty=&bad=%FF";
        let masked = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Form, body)?;
        let out = utf8(&masked.body);
        let fields: Vec<&str> = out.split('&').collect();
        assert_eq!(fields.len(), 6);
        assert!(
            fields[0].starts_with("mail=") && !fields[0].contains("jansen"),
            "{out}"
        );
        assert!(
            fields[0].contains("%40"),
            "the proxy's @ is re-encoded: {out}"
        );
        // Untouched fields keep their exact spelling, `+` and all.
        assert_eq!(
            &fields[1..],
            ["x=1", "note=a+b%21", "flag", "empty=", "bad=%FF"]
        );
        assert_eq!(masked.counts, [("email", 1)]);
        assert_eq!(masked.proxies.len(), 1);
        let proxy = percent_decode(&fields[0]["mail=".len()..]).unwrap_or_default();
        assert_eq!(masked.proxies[0], proxy);
        assert_eq!(restore(&engine, &proxy)?, "jan.jansen@acme.nl");
        Ok(())
    }

    #[test]
    fn form_without_pii_is_byte_identical() -> Result<()> {
        let engine = engine("form-clean")?;
        let body = b"q=hello+world&lang=nl&p=%7E";
        let masked = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Form, body)?;
        assert_eq!(masked.body, body);
        Ok(())
    }

    #[test]
    fn form_with_invalid_utf8_falls_back_to_text() -> Result<()> {
        let engine = engine("form-bin")?;
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Form,
            b"a=jan.jansen@acme.nl&b=\xFF",
        )?;
        assert!(!utf8_lossy(&masked.body).contains("jansen"));
        assert!(masked.body.ends_with(b"&b=\xFF"));
        Ok(())
    }

    const BOUNDARY: &str = "----piikeyBoundary";

    fn multipart(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (head, content) in parts {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n{head}\r\n\r\n").as_bytes());
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    #[test]
    fn multipart_text_fields_are_masked_and_the_structure_survives() -> Result<()> {
        let engine = engine("multi-text")?;
        let body = multipart(&[
            (
                "Content-Disposition: form-data; name=\"prompt\"",
                b"mail jan.jansen@acme.nl please",
            ),
            ("Content-Disposition: form-data; name=\"lang\"", b"nl"),
        ]);
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            &body,
        )?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert_eq!(out.matches(&format!("--{BOUNDARY}\r\n")).count(), 2);
        assert!(out.ends_with(&format!("\r\n--{BOUNDARY}--\r\n")));
        assert!(out.contains("name=\"lang\"\r\n\r\nnl\r\n"), "{out}");
        assert_eq!(masked.counts, [("email", 1)]);
        assert_eq!(restore(&engine, out)?, utf8(&body));
        Ok(())
    }

    #[test]
    fn multipart_text_file_keeps_its_name_and_type() -> Result<()> {
        let engine = engine("multi-file")?;
        let head = "Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain";
        let body = multipart(&[(head, b"call jan.jansen@acme.nl\r\nbye")]);
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            &body,
        )?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert!(out.contains("filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\ncall "));
        assert!(out.contains("\r\nbye\r\n--"), "{out}");
        assert_eq!(masked.counts, [("attachment", 1)]);
        Ok(())
    }

    #[test]
    fn multipart_mail_file_becomes_a_text_file() -> Result<()> {
        let engine = engine("multi-eml")?;
        let eml = b"From: jan.jansen@acme.nl\r\nTo: piet@example.org\r\nSubject: Hi\r\n\r\nGroet, Jan\r\n";
        let head = "Content-Disposition: form-data; name=\"file\"; filename=\"mail \\\"1\\\".eml\"\r\nContent-Type: message/rfc822";
        let body = multipart(&[
            (head, eml),
            ("Content-Disposition: form-data; name=\"after\"", b"kept"),
        ]);
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            &body,
        )?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert!(
            out.contains("filename=\"mail \\\"1\\\".eml.txt\""),
            "name gets .txt appended, quotes stay escaped: {out}"
        );
        assert!(out.contains("Content-Type: text/plain\r\n\r\n"), "{out}");
        assert!(!out.contains("message/rfc822"), "{out}");
        assert!(
            out.contains("name=\"after\"\r\n\r\nkept\r\n--"),
            "later parts follow intact"
        );
        assert!(out.ends_with(&format!("--{BOUNDARY}--\r\n")));
        assert!(masked.counts.iter().any(|&(kind, _)| kind == "attachment"));
        assert!(
            !masked.proxies.is_empty(),
            "proxies in the converted text are noted"
        );
        Ok(())
    }

    #[test]
    fn multipart_file_without_a_content_type_gets_one() -> Result<()> {
        let engine = engine("multi-notype")?;
        let eml = b"From: a@acme.nl\r\nTo: b@example.org\r\nSubject: S\r\n\r\nBody\r\n";
        let body = multipart(&[(
            "Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''caf%C3%A9.eml",
            eml,
        )]);
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            &body,
        )?;
        let out = utf8(&masked.body);
        assert!(out.contains("filename=\"café.eml.txt\""), "{out}");
        assert!(!out.contains("filename*"), "{out}");
        assert!(out.contains("Content-Type: text/plain\r\n\r\n"), "{out}");
        Ok(())
    }

    #[test]
    fn multipart_unreadable_file_is_forwarded_unchanged() -> Result<()> {
        let engine = engine("multi-bin")?;
        let blob: &[u8] = b"\x00\x01\x02 binary \x00 jan.jansen@acme.nl \xFF\x00";
        let head = "Content-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream";
        let body = multipart(&[(head, blob)]);
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            &body,
        )?;
        assert_eq!(masked.body, body);
        assert!(masked.counts.is_empty());
        Ok(())
    }

    #[test]
    fn multipart_with_lf_line_ends_and_preamble() -> Result<()> {
        let engine = engine("multi-lf")?;
        let body = format!(
            "preamble\n--{BOUNDARY}\nContent-Disposition: form-data; name=\"a\"\n\nmail jan.jansen@acme.nl\n--{BOUNDARY}--\nepilogue\n"
        );
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            body.as_bytes(),
        )?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen"), "{out}");
        assert!(out.starts_with("preamble\n--"), "{out}");
        assert!(
            out.ends_with("\n------piikeyBoundary--\nepilogue\n"),
            "{out}"
        );
        Ok(())
    }

    #[test]
    fn malformed_multipart_is_masked_as_text() -> Result<()> {
        let engine = engine("multi-bad")?;
        // No closing delimiter, no blank line after the headers.
        let body =
            format!("--{BOUNDARY}\r\nContent-Disposition: x\r\n\r\nhello jan.jansen@acme.nl");
        let masked = mask(
            &engine,
            &Typed::new(),
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            body.as_bytes(),
        )?;
        assert!(!utf8(&masked.body).contains("jan.jansen"));
        assert!(utf8(&masked.body).starts_with(&format!("--{BOUNDARY}\r\nContent-Disposition: x")));
        Ok(())
    }

    #[test]
    fn split_multipart_finds_parts_and_empty_bodies() {
        let body = multipart(&[
            ("Content-Disposition: form-data; name=\"a\"", b""),
            (
                "Content-Disposition: form-data; name=\"b\"",
                b"line1\r\nline2",
            ),
        ]);
        let parts = split_multipart(&body, BOUNDARY).unwrap_or_default();
        assert_eq!(parts.len(), 2);
        assert_eq!(&body[parts[0].body.clone()], b"");
        assert_eq!(&body[parts[1].body.clone()], b"line1\r\nline2");
        assert_eq!(
            utf8(&body[parts[1].head.clone()]),
            "Content-Disposition: form-data; name=\"b\""
        );
        assert!(split_multipart(b"no boundary here", BOUNDARY).is_none());
        assert!(split_multipart(b"", BOUNDARY).is_none());
    }

    #[test]
    fn a_boundary_inside_a_line_is_not_a_delimiter() {
        let tricky = format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx--{BOUNDARY} not a delimiter\r\n--{BOUNDARY}--\r\n"
        );
        let parts = split_multipart(tricky.as_bytes(), BOUNDARY).unwrap_or_default();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            utf8(&tricky.as_bytes()[parts[0].body.clone()]),
            format!("x--{BOUNDARY} not a delimiter")
        );
    }

    #[test]
    fn disposition_parsing() {
        let name = |head: &str| file_name(head.as_bytes());
        assert_eq!(
            name("Content-Disposition: form-data; name=\"f\"").as_deref(),
            None
        );
        assert_eq!(
            name("content-disposition: form-data; name=\"f\"; filename=\"a; b.txt\"").as_deref(),
            Some("a; b.txt")
        );
        assert_eq!(
            name("Content-Disposition: form-data; filename=plain.txt").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(
            name("Content-Disposition: attachment; filename=\"x.bin\"; filename*=UTF-8''%E2%82%AC.bin")
                .as_deref(),
            Some("€.bin"),
            "filename* wins"
        );
        assert_eq!(name("X-Other: 1").as_deref(), None);
        assert_eq!(unquote(r#""say \"hi\" \\ now""#), r#"say "hi" \ now"#);
        assert_eq!(unquote("bare"), "bare");
    }

    /// A store that is capturing and was handed `typed_text`, which waits for detection.
    fn capturing(typed_text: &str) -> Typed {
        let typed = Typed::new();
        typed.set_active(true);
        typed.push(typed_text.to_owned());
        typed
    }

    #[test]
    fn capture_without_typed_values_leaves_the_body_alone() -> Result<()> {
        let engine = engine("typed-none")?;
        let typed = Typed::new();
        typed.set_active(true);
        let body = br#"{"m":"mail jan.jansen@acme.nl","build":"7f3a"}"#;
        let masked = mask(&engine, &typed, Resent::None, &BodyKind::Text, body)?;
        assert_eq!(masked.body, body, "no full detection while capturing");
        assert!(masked.counts.is_empty() && masked.proxies.is_empty());
        Ok(())
    }

    #[test]
    fn without_capture_the_whole_body_is_checked() -> Result<()> {
        let engine = engine("typed-off")?;
        let body = br#"{"m":"mail jan.jansen@acme.nl","build":"7f3a"}"#;
        let masked = mask(&engine, &Typed::new(), Resent::None, &BodyKind::Text, body)?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert_eq!(masked.counts, [("email", 1)]);
        Ok(())
    }

    /// `mask_texts` saw the store capturing; by the time `mask_typed` reads it, capture has
    /// stopped and dropped what it kept.
    #[test]
    fn a_store_that_stops_while_a_request_is_masked_does_not_wave_it_through() -> Result<()> {
        let engine = engine("typed-stopped")?;
        let stopped = Typed::new();
        let mut found = Found::default();
        let masked = mask_typed(
            &engine,
            &stopped,
            Resent::None,
            &["mail jan.jansen@acme.nl"],
            &mut found,
        )?;
        assert!(!masked[0].contains("jan.jansen@acme.nl"), "{masked:?}");
        assert_eq!(found.counts(), [("email", 1)]);
        Ok(())
    }

    #[test]
    fn capture_replaces_only_what_the_user_typed() -> Result<()> {
        let engine = engine("typed-one")?;
        // Still waiting for detection: the request itself reads it.
        let typed = capturing("mail jan.jansen@acme.nl");
        let body = br#"{"m":"mail jan.jansen@acme.nl","other":"piet@acme.nl"}"#;
        let masked = mask(&engine, &typed, Resent::None, &BodyKind::Text, body)?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert!(
            out.contains(r#""other":"piet@acme.nl""#),
            "that address was not typed: {out}"
        );
        assert_eq!(masked.counts, [("email", 1)]);
        assert_eq!(masked.proxies.len(), 1);
        assert_eq!(restore(&engine, out)?, utf8(body));

        // A chat client resends its history: nothing new is replaced, the ledger still learns.
        let again = mask(&engine, &typed, Resent::None, &BodyKind::Text, &masked.body)?;
        assert_eq!(again.body, masked.body);
        assert!(again.counts.is_empty());
        assert_eq!(again.proxies, masked.proxies);
        Ok(())
    }

    #[test]
    fn a_blind_capture_checks_the_whole_body_and_keeps_its_values() -> Result<()> {
        let engine = engine("typed-blind")?;
        let typed = capturing("mail jan.jansen@acme.nl");
        let body = br#"{"m":"mail jan.jansen@acme.nl","other":"piet@acme.nl"}"#;

        // A read is overdue: nothing says what was typed, so everything is checked.
        typed.set_blind(true);
        let blind = mask(&engine, &typed, Resent::None, &BodyKind::Text, body)?;
        let out = utf8(&blind.body);
        assert!(
            !out.contains("jan.jansen@acme.nl") && !out.contains("piet@acme.nl"),
            "{out}"
        );
        assert_eq!(blind.counts, [("email", 2)]);

        // It sees again: the text pushed meanwhile is still there, and only it is replaced.
        typed.set_blind(false);
        let masked = mask(&engine, &typed, Resent::None, &BodyKind::Text, body)?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert!(out.contains(r#""other":"piet@acme.nl""#), "{out}");
        assert_eq!(masked.counts, [("email", 1)]);
        Ok(())
    }

    #[test]
    fn capture_replaces_typed_values_in_form_fields() -> Result<()> {
        let engine = engine("typed-form")?;
        let typed = capturing("mail jan.jansen@acme.nl");
        let body = b"mail=jan.jansen%40acme.nl&other=piet%40acme.nl&x=1";
        let masked = mask(&engine, &typed, Resent::None, &BodyKind::Form, body)?;
        let out = utf8(&masked.body);
        let fields: Vec<&str> = out.split('&').collect();
        assert_eq!(fields.len(), 3);
        assert!(
            fields[0].starts_with("mail=") && !fields[0].contains("jansen"),
            "{out}"
        );
        assert_eq!(&fields[1..], ["other=piet%40acme.nl", "x=1"]);
        assert_eq!(masked.counts, [("email", 1)]);
        Ok(())
    }

    #[test]
    fn capture_still_checks_uploaded_files_in_full() -> Result<()> {
        let engine = engine("typed-multi")?;
        let typed = capturing("mail jan.jansen@acme.nl");
        let file = "Content-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain";
        let body = multipart(&[
            (
                "Content-Disposition: form-data; name=\"prompt\"",
                b"mail jan.jansen@acme.nl please",
            ),
            (
                "Content-Disposition: form-data; name=\"cc\"",
                b"piet@acme.nl",
            ),
            (file, b"call anna@acme.nl\r\nbye"),
        ]);
        let masked = mask(
            &engine,
            &typed,
            Resent::None,
            &BodyKind::Multipart(BOUNDARY.into()),
            &body,
        )?;
        let out = utf8(&masked.body);
        assert!(!out.contains("jan.jansen@acme.nl"), "{out}");
        assert!(
            out.contains("name=\"cc\"\r\n\r\npiet@acme.nl\r\n"),
            "not typed, not a file: {out}"
        );
        assert!(
            !out.contains("anna@acme.nl"),
            "an upload is checked in full: {out}"
        );
        assert_eq!(masked.counts, [("attachment", 1), ("email", 1)]);
        Ok(())
    }
}
