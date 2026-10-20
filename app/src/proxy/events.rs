//! Restoring proxies in event streams: server-sent events and JSON lines.
//!
//! A chatbot streams its reply as many small events, each carrying a few characters of
//! text in a JSON string (`choices[0].delta.content` for `OpenAI`, `delta.text` for
//! `Anthropic`, `message.content` for JSON lines, ...). A name or an email address is cut
//! across those events at arbitrary points, and the JSON between the pieces breaks the
//! token, so no mention can be matched in the raw bytes of the stream.
//!
//! [`EventStream`] reads the stream one event at a time and finds the delta strings: the
//! string values at [`DELTA_KEYS`]. The text of the strings that share a *channel* (the
//! JSON pointer of the string, so every content delta of one choice is one channel and a
//! second choice is another) goes to a [`Channels`] implementation as one continuous
//! text, and what it returns goes back into the event. A channel holds text back while a
//! mention may still be completed by later events. That text is released just before the
//! event that ends the reply (`[DONE]`, a `message_stop`, a finish reason, a `done`
//! flag, the end of the body) in an event of its own: a copy of the last event that
//! carried text on that channel, with only that text in it.
//!
//! Events that are not touched pass through byte for byte; a rewritten event keeps its
//! `event:` and `id:` lines, its place and its line endings. Rewritten JSON keeps its key
//! order but not its whitespace.
//!
//! A limitation of the design: it treats the strings of a channel as one text. That is
//! what deltas are; a JSON-lines file of unrelated records with a `text` field would have
//! its text shifted from one record to the next.

use std::{collections::BTreeMap, fmt::Write as _};

use serde_json::Value;

/// Keys whose string values carry the streamed text of a reply.
const DELTA_KEYS: [&str; 7] = [
    "content",
    "text",
    "delta",
    "v",
    "value",
    "output_text",
    "completion",
];
/// Keys that say why a reply ended; any value but null (or empty) ends it.
const FINISH_KEYS: [&str; 4] = ["finish_reason", "finishReason", "stop_reason", "stopReason"];
/// Name endings of events that close a piece of text.
const END_SUFFIXES: [&str; 7] = [
    ".done",
    ".completed",
    ".failed",
    ".incomplete",
    "_stop",
    "_done",
    "_complete",
];
/// An event or line longer than this without its end is passed on as it is: holding it
/// back would stall the stream and grow memory without limit.
const MAX_RECORD: usize = 1 << 20;
/// Most text channels one stream restores; text in further channels is not touched.
const MAX_CHANNELS: usize = 32;
/// Strings shorter than this cannot hold a proxy.
const MIN_RESTORE: usize = 3;
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// How the events of a stream are delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Framing {
    /// `text/event-stream`: events end at an empty line.
    Sse,
    /// One JSON value per line.
    Ndjson,
}

/// What restores the text of the channels of a stream.
pub(super) trait Channels {
    /// Adds `text` to `channel`; returns the text that can be sent now (often less,
    /// while a mention may still be completed; sometimes more).
    fn feed(&mut self, channel: &str, text: &str) -> String;

    /// Releases the text `channel` still holds back.
    fn flush(&mut self, channel: &str) -> String;

    /// Restores the mentions in `text` on its own, holding nothing back: for the text of
    /// an event that is not a delta (a title, an error, tool arguments, plain data).
    fn restore(&mut self, text: &str) -> String;
}

/// The last event that carried text on a channel, to copy for the text released later.
struct Template {
    value: Value,
    /// The SSE `event:` name.
    name: Option<String>,
    /// The line ending the event used.
    eol: Vec<u8>,
}

/// One event, as far as restoring it is concerned.
struct Item {
    /// The SSE `event:` name.
    name: Option<String>,
    /// The payload: the `data:` lines joined, or the line of a JSON-lines stream.
    data: Option<String>,
    /// The line ending of the payload.
    eol: Vec<u8>,
}

/// A line of a record: `start..content_end` is its text, `content_end..end` its ending.
struct Line {
    start: usize,
    content_end: usize,
    end: usize,
}

/// An event stream being restored.
pub(super) struct EventStream<C> {
    framing: Framing,
    channels: C,
    /// Input that does not make a complete record yet.
    buf: Vec<u8>,
    /// Everything in `buf` before this has been scanned and ends no record.
    resume: usize,
    started: bool,
    templates: BTreeMap<String, Template>,
}

impl<C: Channels> EventStream<C> {
    pub(super) fn new(framing: Framing, channels: C) -> Self {
        Self {
            framing,
            channels,
            buf: Vec::new(),
            resume: 0,
            started: false,
            templates: BTreeMap::new(),
        }
    }

    pub(super) fn channels(&self) -> &C {
        &self.channels
    }

    /// Adds `bytes`; returns the output that is ready.
    pub(super) fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        self.drain(false, &mut out);
        out
    }

    /// The end of the stream: the last record and all the text still held back.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.drain(true, &mut out);
        let rest = std::mem::take(&mut self.buf);
        self.resume = 0;
        if !rest.is_empty() {
            self.record(&rest, &mut out);
        }
        let mut tail = Vec::new();
        self.flush_all(&mut tail);
        if !tail.is_empty() {
            if !rest.is_empty() {
                close_record(self.framing, &rest, &mut out);
            }
            out.extend_from_slice(&tail);
        }
        out
    }

    fn drain(&mut self, eof: bool, out: &mut Vec<u8>) {
        if !self.started {
            if !eof && self.buf.len() < BOM.len() && BOM.starts_with(&self.buf) {
                return;
            }
            self.started = true;
            if self.buf.starts_with(BOM) {
                out.extend_from_slice(BOM);
                self.buf.drain(..BOM.len());
            }
        }
        while let Some(end) = self.record_end(eof) {
            let record: Vec<u8> = self.buf.drain(..end).collect();
            self.resume = 0;
            self.record(&record, out);
        }
        if self.buf.len() > MAX_RECORD {
            self.flush_all(out);
            out.append(&mut self.buf);
            self.resume = 0;
        }
    }

    /// Where the first complete record in `buf` ends.
    fn record_end(&mut self, eof: bool) -> Option<usize> {
        match self.framing {
            Framing::Ndjson => {
                if let Some(at) = self.buf[self.resume..].iter().position(|&b| b == b'\n') {
                    return Some(self.resume + at + 1);
                }
                self.resume = self.buf.len();
                None
            }
            Framing::Sse => {
                let mut pos = self.resume;
                loop {
                    let Some((content_end, after)) = next_line(&self.buf, pos, eof) else {
                        self.resume = pos;
                        return None;
                    };
                    if content_end == pos {
                        return Some(after);
                    }
                    pos = after;
                }
            }
        }
    }

    fn record(&mut self, raw: &[u8], out: &mut Vec<u8>) {
        match self.framing {
            Framing::Sse => self.sse_record(raw, out),
            Framing::Ndjson => self.json_line(raw, out),
        }
    }

    fn sse_record(&mut self, raw: &[u8], out: &mut Vec<u8>) {
        let lines = split_lines(raw);
        let mut name = None;
        let mut data: Vec<&[u8]> = Vec::new();
        let mut data_lines: Vec<usize> = Vec::new();
        let mut first_value = 0;
        let mut eol = Vec::new();
        for (n, line) in lines.iter().enumerate() {
            let Some((field_name, value, offset)) = field(&raw[line.start..line.content_end])
            else {
                continue;
            };
            match field_name {
                b"event" => name = Some(String::from_utf8_lossy(value).into_owned()),
                b"data" => {
                    if data.is_empty() {
                        first_value = line.start + offset;
                        eol = raw[line.content_end..line.end].to_vec();
                    }
                    data.push(value);
                    data_lines.push(n);
                }
                _ => {}
            }
        }
        let item = Item {
            name,
            data: join_lines(&data),
            eol: if eol.is_empty() { b"\n".to_vec() } else { eol },
        };
        // The record again with `payload` as its data: the first `data:` line keeps its
        // spacing and ending (and is repeated for each line of `payload`), further
        // `data:` lines go, everything else stays.
        let rebuild = |payload: &str| {
            let mut new = Vec::with_capacity(raw.len() + payload.len());
            for (n, line) in lines.iter().enumerate() {
                if data_lines.first() == Some(&n) {
                    let eol = &raw[line.content_end..line.end];
                    let parts: Vec<&str> = payload.split('\n').collect();
                    for (i, part) in parts.iter().enumerate() {
                        new.extend_from_slice(&raw[line.start..first_value]);
                        new.extend_from_slice(part.as_bytes());
                        if i + 1 < parts.len() && eol.is_empty() {
                            new.push(b'\n');
                        } else {
                            new.extend_from_slice(eol);
                        }
                    }
                } else if !data_lines.contains(&n) {
                    new.extend_from_slice(&raw[line.start..line.end]);
                }
            }
            Some(new)
        };
        self.handle(&item, raw, rebuild, out);
    }

    fn json_line(&mut self, raw: &[u8], out: &mut Vec<u8>) {
        let body = raw.strip_suffix(b"\n").unwrap_or(raw);
        let content = body.strip_suffix(b"\r").unwrap_or(body);
        let eol = &raw[content.len()..];
        let item = Item {
            name: None,
            data: std::str::from_utf8(content)
                .ok()
                .filter(|text| !text.trim().is_empty())
                .map(str::to_owned),
            eol: if eol.is_empty() {
                b"\n".to_vec()
            } else {
                eol.to_vec()
            },
        };
        // A line break in the new payload would split the record.
        let rebuild = |payload: &str| {
            if payload.contains(['\n', '\r']) {
                return None;
            }
            let mut new = payload.as_bytes().to_vec();
            new.extend_from_slice(eol);
            Some(new)
        };
        self.handle(&item, raw, rebuild, out);
    }

    /// Restores one record: the text it carries, and the text released before it when
    /// it ends the reply.
    fn handle(
        &mut self,
        item: &Item,
        raw: &[u8],
        rebuild: impl FnOnce(&str) -> Option<Vec<u8>>,
        out: &mut Vec<u8>,
    ) {
        let data = item.data.as_deref();
        let marker = data.is_some_and(|data| data.trim() == "[DONE]");
        let mut value = data
            .filter(|_| !marker)
            .and_then(|data| serde_json::from_str::<Value>(data).ok());
        let terminal = marker
            || item.name.as_deref().is_some_and(is_end_name)
            || value.as_ref().is_some_and(is_end_event);
        let mut changed = false;
        let mut touched = Vec::new();
        let mut text = None;
        if let Some(value) = value.as_mut() {
            // What the event says besides the deltas is restored on its own, first, so
            // that the copies made for released text are restored too.
            changed = self.restore_others(value);
            let (fed, paths) = self.feed_value(value, item.name.as_ref(), &item.eol);
            changed |= fed;
            touched = paths;
        } else if let Some(data) = data.filter(|data| !marker && data.len() >= MIN_RESTORE) {
            // Not JSON: plain data, restored on its own.
            text = Some(self.channels.restore(data)).filter(|restored| restored != data);
        }
        if terminal {
            // Other channels release their text in events of their own, ahead of this
            // one; the channels this event carries append it to their own strings, so
            // a mention that ends here is not cut short.
            self.flush_except(&touched, out);
            if let Some(value) = value.as_mut() {
                changed |= self.release(value, &touched);
            }
        }
        let payload = match (&value, text) {
            (Some(value), _) if changed => serde_json::to_string(value).ok(),
            (None, text) => text,
            _ => None,
        };
        match payload.as_deref().and_then(rebuild) {
            Some(new) => out.extend_from_slice(&new),
            None => out.extend_from_slice(raw),
        }
    }

    /// Feeds the delta strings of `value` to their channels and puts the answers in
    /// their place. Returns whether anything changed and the channels the value has.
    fn feed_value(
        &mut self,
        value: &mut Value,
        name: Option<&String>,
        eol: &[u8],
    ) -> (bool, Vec<String>) {
        let Self {
            channels,
            templates,
            ..
        } = self;
        let mut changed = false;
        let mut touched: Vec<String> = Vec::new();
        let mut fresh = 0;
        walk(value, &mut String::new(), &mut |path, text| {
            if !templates.contains_key(path) {
                if templates.len() + fresh >= MAX_CHANNELS {
                    // Too many channels to follow: this string is restored on its own.
                    let restored = channels.restore(text);
                    if restored != *text {
                        *text = restored;
                        changed = true;
                    }
                    return;
                }
                fresh += 1;
            }
            let fed = channels.feed(path, text);
            if fed != *text {
                *text = fed;
                changed = true;
            }
            touched.push(path.to_owned());
        });
        for path in &touched {
            let template = Template {
                value: value.clone(),
                name: name.cloned(),
                eol: eol.to_vec(),
            };
            templates.insert(path.clone(), template);
        }
        (changed, touched)
    }

    /// Restores the mentions in the strings of `value` that are not deltas, each on its
    /// own: an event's title, an error message, tool arguments.
    fn restore_others(&mut self, value: &mut Value) -> bool {
        let channels = &mut self.channels;
        let mut changed = false;
        walk_other(value, &mut |text| {
            if text.len() < MIN_RESTORE {
                return;
            }
            let restored = channels.restore(text);
            if restored != *text {
                *text = restored;
                changed = true;
            }
        });
        changed
    }

    /// Appends the text the channels in `here` hold back to their strings in `value`.
    fn release(&mut self, value: &mut Value, here: &[String]) -> bool {
        let mut changed = false;
        for path in here {
            let tail = self.channels.flush(path);
            if tail.is_empty() {
                continue;
            }
            if let Some(Value::String(text)) = value.pointer_mut(path) {
                text.push_str(&tail);
                changed = true;
            }
        }
        changed
    }

    fn flush_except(&mut self, here: &[String], out: &mut Vec<u8>) {
        let paths: Vec<String> = self
            .templates
            .keys()
            .filter(|path| !here.contains(path))
            .cloned()
            .collect();
        for path in paths {
            self.release_event(&path, out);
        }
    }

    fn flush_all(&mut self, out: &mut Vec<u8>) {
        let paths: Vec<String> = self.templates.keys().cloned().collect();
        for path in paths {
            self.release_event(&path, out);
        }
    }

    /// Emits the text `path` holds back as an event of its own: the last event that
    /// carried text on it, with every other delta string emptied.
    fn release_event(&mut self, path: &str, out: &mut Vec<u8>) {
        let tail = self.channels.flush(path);
        if tail.is_empty() {
            return;
        }
        let Some(template) = self.templates.get(path) else {
            return;
        };
        let mut value = template.value.clone();
        walk(&mut value, &mut String::new(), &mut |at, text| {
            if at == path {
                text.clone_from(&tail);
            } else {
                text.clear();
            }
        });
        let Ok(json) = serde_json::to_string(&value) else {
            return;
        };
        let eol = &template.eol;
        match self.framing {
            Framing::Sse => {
                if let Some(name) = &template.name {
                    out.extend_from_slice(b"event: ");
                    out.extend_from_slice(name.as_bytes());
                    out.extend_from_slice(eol);
                }
                out.extend_from_slice(b"data: ");
                out.extend_from_slice(json.as_bytes());
                out.extend_from_slice(eol);
                out.extend_from_slice(eol);
            }
            Framing::Ndjson => {
                out.extend_from_slice(json.as_bytes());
                out.extend_from_slice(eol);
            }
        }
    }
}

/// Ends the last record of a stream that stopped in the middle of it, so that an event
/// appended after it does not run into it.
fn close_record(framing: Framing, rest: &[u8], out: &mut Vec<u8>) {
    let ends_line = rest.last().is_some_and(|&b| b == b'\n' || b == b'\r');
    if !ends_line {
        out.push(b'\n');
    }
    if framing == Framing::Sse {
        out.push(b'\n');
    }
}

/// The line of `buf` that starts at `from`: where its text ends and where the next line
/// starts. `None` while its ending has not arrived (a `\r` at the very end may still be
/// the first half of `\r\n`).
fn next_line(buf: &[u8], from: usize, eof: bool) -> Option<(usize, usize)> {
    let content_end = from + buf[from..].iter().position(|&b| b == b'\n' || b == b'\r')?;
    let after = if buf[content_end] == b'\n' {
        content_end + 1
    } else {
        match buf.get(content_end + 1) {
            Some(b'\n') => content_end + 2,
            Some(_) => content_end + 1,
            None if eof => content_end + 1,
            None => return None,
        }
    };
    Some((content_end, after))
}

/// All the lines of a record.
fn split_lines(raw: &[u8]) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < raw.len() {
        let (content_end, end) = match raw[start..].iter().position(|&b| b == b'\n' || b == b'\r') {
            None => (raw.len(), raw.len()),
            Some(at) => {
                let content_end = start + at;
                let crlf = raw[content_end] == b'\r' && raw.get(content_end + 1) == Some(&b'\n');
                (content_end, content_end + 1 + usize::from(crlf))
            }
        };
        lines.push(Line {
            start,
            content_end,
            end,
        });
        start = end;
    }
    lines
}

/// The field name and value of an SSE line and the offset of the value in it; `None`
/// for comments.
fn field(line: &[u8]) -> Option<(&[u8], &[u8], usize)> {
    if line.first() == Some(&b':') {
        return None;
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return Some((line, &[], line.len()));
    };
    let start = colon + 1 + usize::from(line.get(colon + 1) == Some(&b' '));
    Some((&line[..colon], &line[start..], start))
}

/// The `data:` values of an event as one text, as the SSE specification joins them.
fn join_lines(lines: &[&[u8]]) -> Option<String> {
    if lines.is_empty() {
        return None;
    }
    String::from_utf8(lines.join(&b'\n')).ok()
}

/// Calls `on_text` with every string in `value` that is not a delta string.
fn walk_other(value: &mut Value, on_text: &mut dyn FnMut(&mut String)) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                match child {
                    Value::String(_) if DELTA_KEYS.contains(&key.as_str()) => {}
                    other => walk_other(other, on_text),
                }
            }
        }
        Value::Array(items) => {
            for child in items.iter_mut() {
                walk_other(child, on_text);
            }
        }
        Value::String(text) => on_text(text),
        _ => {}
    }
}

/// Calls `on_text` with the pointer and the text of every delta string in `value`.
fn walk(value: &mut Value, path: &mut String, on_text: &mut dyn FnMut(&str, &mut String)) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let mark = path.len();
                path.push('/');
                push_escaped(path, key);
                match child {
                    Value::String(text) if DELTA_KEYS.contains(&key.as_str()) => {
                        on_text(path, text);
                    }
                    other => walk(other, path, on_text),
                }
                path.truncate(mark);
            }
        }
        Value::Array(items) => {
            for (n, child) in items.iter_mut().enumerate() {
                let mark = path.len();
                let _ = write!(path, "/{n}");
                walk(child, path, on_text);
                path.truncate(mark);
            }
        }
        _ => {}
    }
}

/// `key` as a JSON pointer token.
fn push_escaped(path: &mut String, key: &str) {
    for c in key.chars() {
        match c {
            '~' => path.push_str("~0"),
            '/' => path.push_str("~1"),
            other => path.push(other),
        }
    }
}

/// Whether an event or `type` name says that a piece of text is complete.
fn is_end_name(name: &str) -> bool {
    matches!(name, "done" | "end" | "error") || END_SUFFIXES.iter().any(|end| name.ends_with(end))
}

/// Whether a JSON event says that its reply (or a piece of it) has ended.
fn is_end_event(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(is_end_name)
        || has_finish(value)
}

/// Whether `value` holds a finish reason, or `"done": true`, anywhere.
fn has_finish(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            let finished = FINISH_KEYS.contains(&key.as_str())
                && !child.is_null()
                && child.as_str() != Some("");
            let done = key == "done" && child.as_bool() == Some(true);
            finished || done || has_finish(child)
        }),
        Value::Array(items) => items.iter().any(has_finish),
        _ => false,
    }
}

/// Streams in the shapes of the services that matter, for the tests here and in
/// `response`.
#[cfg(test)]
pub(super) mod fixtures {
    use serde_json::json;

    use super::{Framing, Value};

    /// An `OpenAI` chat-completions stream whose content deltas are `pieces`.
    pub(in crate::proxy) fn openai(pieces: &[&str]) -> Vec<u8> {
        let chunk = |delta: Value, finish: Value| {
            let chunk = json!({
                "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "m",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
            });
            format!("data: {chunk}\n\n")
        };
        let mut out = chunk(json!({"role": "assistant", "content": ""}), Value::Null);
        for piece in pieces {
            out.push_str(&chunk(json!({"content": piece}), Value::Null));
        }
        out.push_str(&chunk(json!({}), json!("stop")));
        out.push_str("data: [DONE]\n\n");
        out.into_bytes()
    }

    /// An `Anthropic` messages stream whose text deltas are `pieces`.
    pub(in crate::proxy) fn anthropic(pieces: &[&str]) -> Vec<u8> {
        let event = |name: &str, data: Value| format!("event: {name}\ndata: {data}\n\n");
        let mut out = event(
            "message_start",
            json!({"type": "message_start", "message": {"id": "msg_1", "type": "message",
                "role": "assistant", "content": [], "model": "m", "stop_reason": null,
                "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        );
        out.push_str(&event(
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""}}),
        ));
        out.push_str(&event("ping", json!({"type": "ping"})));
        for piece in pieces {
            out.push_str(&event(
                "content_block_delta",
                json!({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": piece}}),
            ));
        }
        out.push_str(&event(
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ));
        out.push_str(&event(
            "message_delta",
            json!({"type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": 15}}),
        ));
        out.push_str(&event("message_stop", json!({"type": "message_stop"})));
        out.into_bytes()
    }

    /// A JSON-lines chat stream whose message content deltas are `pieces`.
    pub(in crate::proxy) fn ndjson(pieces: &[&str]) -> Vec<u8> {
        let line = |content: &str, done: bool| {
            let line = json!({"model": "m", "message": {"role": "assistant", "content": content},
                "done": done});
            format!("{line}\n")
        };
        let mut out = String::new();
        for piece in pieces {
            out.push_str(&line(piece, false));
        }
        out.push_str(&line("", true));
        out.into_bytes()
    }

    /// The events of an SSE stream as `(event name, data)`.
    pub(in crate::proxy) fn sse_events(stream: &[u8]) -> Vec<(Option<String>, String)> {
        let text = String::from_utf8_lossy(stream).replace("\r\n", "\n");
        text.split("\n\n")
            .filter(|event| !event.trim().is_empty())
            .map(|event| {
                let mut name = None;
                let mut data = Vec::new();
                for line in event.lines() {
                    if let Some(value) = line.strip_prefix("event:") {
                        name = Some(value.trim_start().to_owned());
                    } else if let Some(value) = line.strip_prefix("data:") {
                        data.push(value.strip_prefix(' ').unwrap_or(value).to_owned());
                    }
                }
                (name, data.join("\n"))
            })
            .collect()
    }

    /// The JSON of every event of a stream.
    pub(in crate::proxy) fn json_events(stream: &[u8], framing: Framing) -> Vec<Value> {
        let payloads: Vec<String> = match framing {
            Framing::Sse => sse_events(stream)
                .into_iter()
                .map(|(_, data)| data)
                .collect(),
            Framing::Ndjson => String::from_utf8_lossy(stream)
                .lines()
                .map(str::to_owned)
                .collect(),
        };
        payloads
            .iter()
            .filter_map(|payload| serde_json::from_str(payload).ok())
            .collect()
    }

    /// The text a stream carries: the strings at `pointer` of its events, in order.
    pub(in crate::proxy) fn texts(stream: &[u8], framing: Framing, pointer: &str) -> String {
        json_events(stream, framing)
            .iter()
            .filter_map(|event| event.pointer(pointer).and_then(Value::as_str))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::{
        fixtures::{anthropic, json_events, ndjson, openai, sse_events, texts},
        *,
    };

    /// Changes nothing.
    struct Identity;

    impl Channels for Identity {
        fn feed(&mut self, _channel: &str, text: &str) -> String {
            text.to_owned()
        }

        fn flush(&mut self, _channel: &str) -> String {
            String::new()
        }

        fn restore(&mut self, text: &str) -> String {
            text.to_owned()
        }
    }

    /// Holds back the last three characters of every channel.
    #[derive(Default)]
    struct Hold(HashMap<String, String>);

    impl Channels for Hold {
        fn feed(&mut self, channel: &str, text: &str) -> String {
            let held = self.0.entry(channel.to_owned()).or_default();
            held.push_str(text);
            let chars: Vec<char> = held.chars().collect();
            let cut = chars.len().saturating_sub(3);
            *held = chars[cut..].iter().collect();
            chars[..cut].iter().collect()
        }

        fn flush(&mut self, channel: &str) -> String {
            self.0.remove(channel).unwrap_or_default()
        }

        fn restore(&mut self, text: &str) -> String {
            text.to_owned()
        }
    }

    /// Answers with text that needs escaping everywhere.
    struct Nasty;

    impl Channels for Nasty {
        fn feed(&mut self, _channel: &str, text: &str) -> String {
            format!("\"{text}\"\\\n\u{1F600}\t</s>")
        }

        fn flush(&mut self, _channel: &str) -> String {
            String::new()
        }

        fn restore(&mut self, text: &str) -> String {
            text.to_owned()
        }
    }

    /// Restores strings on their own with a function; deltas pass through.
    struct Alone(fn(&str) -> String);

    impl Channels for Alone {
        fn feed(&mut self, _channel: &str, text: &str) -> String {
            text.to_owned()
        }

        fn flush(&mut self, _channel: &str) -> String {
            String::new()
        }

        fn restore(&mut self, text: &str) -> String {
            (self.0)(text)
        }
    }

    fn run<C: Channels>(framing: Framing, channels: C, input: &[u8], size: usize) -> Vec<u8> {
        let mut stream = EventStream::new(framing, channels);
        let mut out = Vec::new();
        for piece in input.chunks(size.max(1)) {
            out.extend(stream.push(piece));
        }
        out.extend(stream.finish());
        out
    }

    fn names(stream: &[u8]) -> Vec<String> {
        sse_events(stream)
            .into_iter()
            .map(|(name, _)| name.unwrap_or_default())
            .collect()
    }

    /// Mixed line endings, a lone `\r`, comments, ids, multi-line data, stray blank lines.
    const AWKWARD: &str = ": keep-alive\r\n\r\nid: 7\r\nevent: delta\r\ndata: {\"delta\": \"a\"}\r\n\r\n\ndata:{\"text\":\"b\"}\rdata: x\r\r: tail\n\nretry: 10\n\ndata: {\"v\":\n\n\ndata: [DONE]\n\n";

    #[test]
    fn untouched_streams_pass_byte_for_byte_whatever_the_chunking() {
        let mut input = AWKWARD.as_bytes().to_vec();
        input.extend(openai(&["Hello", " world"]));
        for size in 1..=11 {
            assert_eq!(
                run(Framing::Sse, Identity, &input, size),
                input,
                "size {size}"
            );
        }
        for at in 0..=input.len() {
            let mut stream = EventStream::new(Framing::Sse, Identity);
            let mut out = stream.push(&input[..at]);
            out.extend(stream.push(&input[at..]));
            out.extend(stream.finish());
            assert_eq!(out, input, "split at {at}");
        }
        let lines = ndjson(&["a", "b"]);
        assert_eq!(run(Framing::Ndjson, Identity, &lines, 3), lines);
        let mut bom = BOM.to_vec();
        bom.extend(openai(&["x"]));
        assert_eq!(run(Framing::Sse, Identity, &bom, 1), bom);
    }

    #[test]
    fn held_back_text_is_released_in_an_event_before_the_end_marker() {
        let input = openai(&["Hello wor", "ld, this is", " a test."]);
        let original = sse_events(&input);
        for size in [1, 5, 4096] {
            let out = run(Framing::Sse, Hold::default(), &input, size);
            assert_eq!(
                texts(&out, Framing::Sse, "/choices/0/delta/content"),
                "Hello world, this is a test."
            );
            let events = sse_events(&out);
            assert_eq!(
                events.len(),
                original.len() + 1,
                "one event for the held text"
            );
            let n = events.len();
            assert_eq!(events[n - 1].1, "[DONE]", "[DONE] stays last");
            assert!(events[n - 2].1.contains(r#""finish_reason":"stop""#));
            assert!(
                events[n - 3].1.contains(r#""content":"st.""#),
                "{}",
                events[n - 3].1
            );
            // The other events keep their order and are still there.
            assert_eq!(events[0], original[0]);
            assert_eq!(events[n - 2], original[original.len() - 2]);
        }
    }

    #[test]
    fn output_does_not_depend_on_how_the_bytes_arrive() {
        let input = anthropic(&["Hello wor", "ld, this is", " a test."]);
        let whole = run(Framing::Sse, Hold::default(), &input, input.len());
        for size in [1, 2, 3, 7, 64] {
            assert_eq!(
                run(Framing::Sse, Hold::default(), &input, size),
                whole,
                "size {size}"
            );
        }
    }

    #[test]
    fn text_is_released_before_the_block_it_belongs_to_stops() {
        let out = run(
            Framing::Sse,
            Hold::default(),
            &anthropic(&["Hello wor", "ld!!"]),
            11,
        );
        assert_eq!(
            names(&out),
            [
                "message_start",
                "content_block_start",
                "ping",
                "content_block_delta",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        assert_eq!(texts(&out, Framing::Sse, "/delta/text"), "Hello world!!");
        // The event for the held text is a copy of a delta: its name, no id.
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"d!!\"}}\n\n"));
    }

    #[test]
    fn json_lines_release_held_text_on_the_done_line() {
        let input = ndjson(&["Hello wor", "ld, this", " is it"]);
        let out = run(Framing::Ndjson, Hold::default(), &input, 6);
        assert_eq!(
            texts(&out, Framing::Ndjson, "/message/content"),
            "Hello world, this is it"
        );
        let events = json_events(&out, Framing::Ndjson);
        assert_eq!(
            events.len(),
            4,
            "three deltas; the held text rides on the done line"
        );
        assert_eq!(events[3]["done"], json!(true));
        assert_eq!(events[3]["message"]["content"], json!(" it"));
        assert_eq!(events[3]["model"], json!("m"));
        assert!(out.ends_with(b"\n"));
    }

    #[test]
    fn a_closing_event_with_its_own_text_gets_the_held_text_in_place() {
        let input = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello wor\"}]}}]}\n\ndata: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ld\"}]},\"finishReason\":\"STOP\"}]}\n\n";
        let out = run(Framing::Sse, Hold::default(), input.as_bytes(), 9);
        assert_eq!(sse_events(&out).len(), 2, "no extra event");
        let pointer = "/candidates/0/content/parts/0/text";
        assert_eq!(texts(&out, Framing::Sse, pointer), "Hello world");
    }

    #[test]
    fn channels_are_kept_apart() {
        let event = |a: &str, b: &str| {
            let data = json!({"choices": [
                {"index": 0, "delta": {"content": a}}, {"index": 1, "delta": {"content": b}}]});
            format!("data: {data}\n\n")
        };
        let input = format!(
            "{}{}{}data: [DONE]\n\n",
            event("aaaa", "bbbb"),
            event("AAAA", "BBBB"),
            event("1", "2")
        );
        let out = run(Framing::Sse, Hold::default(), input.as_bytes(), 8);
        assert_eq!(
            texts(&out, Framing::Sse, "/choices/0/delta/content"),
            "aaaaAAAA1"
        );
        assert_eq!(
            texts(&out, Framing::Sse, "/choices/1/delta/content"),
            "bbbbBBBB2"
        );
    }

    #[test]
    fn a_stream_cut_in_the_middle_of_an_event_still_gets_its_held_text() {
        let out = run(
            Framing::Sse,
            Hold::default(),
            b"data: {\"delta\":\"abcdef\"}\n",
            4,
        );
        let events = sse_events(&out);
        assert_eq!(events.len(), 2, "{}", String::from_utf8_lossy(&out));
        assert_eq!(texts(&out, Framing::Sse, "/delta"), "abcdef");
        assert!(out.ends_with(b"\n\n"));

        let out = run(
            Framing::Ndjson,
            Hold::default(),
            b"{\"content\":\"abcdef\"}",
            4,
        );
        assert_eq!(texts(&out, Framing::Ndjson, "/content"), "abcdef");
        assert_eq!(String::from_utf8_lossy(&out).matches('\n').count(), 2);
    }

    #[test]
    fn rewritten_and_released_events_keep_the_line_endings() {
        let input =
            "event: delta\r\nid: 5\r\ndata: {\"delta\":\"abcdef\"}\r\n\r\ndata: [DONE]\r\n\r\n";
        let out = run(Framing::Sse, Hold::default(), input.as_bytes(), 5);
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
        assert!(text.starts_with("event: delta\r\nid: 5\r\ndata: {\"delta\":\"abc\"}\r\n\r\n"));
        assert!(text.ends_with("data: [DONE]\r\n\r\n"));
        assert_eq!(texts(&out, Framing::Sse, "/delta"), "abcdef");
        // The released copy repeats the event name but not the id.
        assert_eq!(text.matches("id: 5").count(), 1);
        assert_eq!(text.matches("event: delta").count(), 2);
    }

    #[test]
    fn restored_text_is_escaped_and_stays_on_one_line() {
        let input = "event: delta\ndata: {\"delta\":\"x\",\"n\":1.5,\"k\":[1,{\"a\":null}]}\n\n";
        let out = run(Framing::Sse, Nasty, input.as_bytes(), 3);
        let text = String::from_utf8_lossy(&out).into_owned();
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("data:"))
                .count(),
            1
        );
        let events = json_events(&out, Framing::Sse);
        assert_eq!(events[0]["delta"], json!("\"x\"\\\n\u{1F600}\t</s>"));
        assert_eq!(events[0]["n"], json!(1.5));
        let keys: Vec<&String> = events[0]
            .as_object()
            .map(|map| map.keys().collect())
            .unwrap_or_default();
        assert_eq!(keys, ["delta", "n", "k"], "key order is kept");
    }

    #[test]
    fn events_without_delta_text_and_data_that_is_not_json_pass_through() {
        let input = "event: custom\ndata: plain text, not json\n\n: comment\n\ndata: {\"id\":\"x\",\"usage\":{\"n\":3}}\n\ndata: 42\n\n";
        assert_eq!(
            run(Framing::Sse, Hold::default(), input.as_bytes(), 5),
            input.as_bytes()
        );
    }

    #[test]
    fn several_data_lines_are_one_json_value() {
        let input = "data: {\"delta\":\ndata: \"abcdef\"}\n\ndata: [DONE]\n\n";
        let out = run(Framing::Sse, Hold::default(), input.as_bytes(), 4);
        assert_eq!(texts(&out, Framing::Sse, "/delta"), "abcdef");
        assert_eq!(
            sse_events(&out).last().map(|(_, data)| data.as_str()),
            Some("[DONE]")
        );
    }

    #[test]
    fn an_endless_event_is_passed_on_instead_of_held() {
        let mut input = b"data: ".to_vec();
        input.resize(MAX_RECORD + 10_000, b'a');
        input.extend_from_slice(b"\n\ndata: [DONE]\n\n");
        let out = run(Framing::Sse, Identity, &input, 64 * 1024);
        assert_eq!(out, input);
        let out = run(Framing::Ndjson, Identity, &input, 64 * 1024);
        assert_eq!(out, input);
    }

    #[test]
    fn end_markers_are_recognized() {
        for name in [
            "done",
            "message_stop",
            "content_block_stop",
            "response.completed",
            "response.output_text.done",
            "response.failed",
            "error",
        ] {
            assert!(is_end_name(name), "{name}");
        }
        for name in [
            "content_block_delta",
            "response.output_text.delta",
            "ping",
            "message_start",
        ] {
            assert!(!is_end_name(name), "{name}");
        }
        assert!(is_end_event(
            &json!({"choices": [{"finish_reason": "stop"}]})
        ));
        assert!(is_end_event(
            &json!({"candidates": [{"finishReason": "STOP"}]})
        ));
        assert!(is_end_event(
            &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}})
        ));
        assert!(is_end_event(&json!({"done": true})));
        assert!(!is_end_event(
            &json!({"choices": [{"finish_reason": null}]})
        ));
        assert!(!is_end_event(
            &json!({"choices": [{"finish_reason": ""}], "done": false})
        ));
        assert!(!is_end_event(&json!({"message": {"stop_reason": null}})));
    }

    #[test]
    fn channels_are_named_by_json_pointers() {
        let mut value =
            json!({"a/b": {"~": [{"text": "x"}, {"content": "y", "id": "z"}]}, "delta": "d"});
        let mut seen = Vec::new();
        walk(&mut value, &mut String::new(), &mut |path, text| {
            seen.push((path.to_owned(), text.clone()));
        });
        assert_eq!(
            seen,
            [
                ("/a~1b/~0/0/text".to_owned(), "x".to_owned()),
                ("/a~1b/~0/1/content".to_owned(), "y".to_owned()),
                ("/delta".to_owned(), "d".to_owned()),
            ]
        );
        for (path, text) in seen {
            assert_eq!(
                value.pointer(&path).and_then(Value::as_str),
                Some(text.as_str())
            );
        }
    }

    #[test]
    fn strings_that_are_not_deltas_are_restored_on_their_own() {
        let input = "event: title\ndata: {\"id\":\"x1\",\"delta\":\"keep\",\"n\":[\"lower\",\"ok\"],\"deep\":{\"title\":\"hello there\"}}\n\ndata: plain text\n\n";
        let out = run(Framing::Sse, Alone(str::to_uppercase), input.as_bytes(), 7);
        let events = json_events(&out, Framing::Sse);
        assert_eq!(
            events[0],
            json!({"id": "x1", "delta": "keep", "n": ["LOWER", "ok"], "deep": {"title": "HELLO THERE"}})
        );
        let all = sse_events(&out);
        assert_eq!(all[0].0.as_deref(), Some("title"));
        assert_eq!(all[1].1, "PLAIN TEXT");
    }

    #[test]
    fn restored_plain_data_may_span_lines_in_sse_but_not_in_json_lines() {
        let out = run(
            Framing::Sse,
            Alone(|_| "a\nb".to_owned()),
            b"data: xyz\n\n",
            4,
        );
        assert_eq!(out, b"data: a\ndata: b\n\n");
        let out = run(
            Framing::Ndjson,
            Alone(|_| "a\nb".to_owned()),
            b"not json\n",
            4,
        );
        assert_eq!(out, b"not json\n", "a line break would split the record");
        let input = b"not json\n{\"k\":\"abc\"}\n";
        let out = run(Framing::Ndjson, Alone(str::to_uppercase), input, 4);
        assert_eq!(out, b"NOT JSON\n{\"k\":\"ABC\"}\n");
    }
}
