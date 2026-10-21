//! Restoring proxies in a response while it streams.
//!
//! Two passes over the text, in this order:
//!
//! 1. The tolerant [`Restorer`], scoped to the proxies this app sent to the
//!    host (exact, typo'd and partial mentions).
//! 2. [`ExactStream`]: every proxy the vault ever issued, exactly. It covers
//!    what the ledger no longer (or does not yet) remember: a restarted app,
//!    a proxy sent more than a day ago, a chat history that the server stores
//!    and replays.
//!
//! Both are cut-safe: the output of any chunking equals the one-shot result.
//!
//! Event streams (server-sent events, JSON lines) are not restored as bytes: a
//! mention cut across two delta events has JSON between its pieces. The
//! [`events`](super::events) layer feeds the text of the delta strings, as one
//! continuous text per channel, through both passes ([`Restoring`]) and puts
//! the result back into the events.

use std::{
    collections::HashMap,
    sync::{Arc, mpsc::Sender},
};

use hudsucker::{Body, Error as BodyError, futures::stream, hyper::body::Bytes};
use piikey::{
    detect::{EntityKind, Mode},
    engine::{Engine, Replacement},
    restore::{Restorer, Scope},
};

use super::{
    Event,
    body::next_data,
    events::{Channels, EventStream, Framing},
};
use crate::ledger::Ledger;

/// The most the exact pass holds back for a proxy that may still be
/// arriving. A longer proxy (a JWT) can be missed when it straddles two
/// chunks; holding a whole token back would stall every stream for the sake
/// of one rare value.
const MAX_HOLD: usize = 1024;
/// Held back on top of the longest proxy, so the text after a proxy is
/// visible before the proxy is judged complete.
const SLACK: usize = 16;
/// Text with no place to cut (one huge token) is cut anyway past this size,
/// so rescanning it stays cheap.
const MAX_PENDING: usize = 1 << 20;
/// How far back from the ideal cut to look for a gap before cutting anyway.
/// Bounds the work of one push when a token has no gap for kilobytes.
const MAX_BACKTRACK: usize = 8 * 1024;

/// Restores exact vault proxies in text that arrives in pieces.
///
/// Each push rescans the not-yet-emitted text and emits what lies before a
/// cut: a point that is at least `hold` bytes from the end, right after a
/// byte no proxy runs through (space, quote, bracket, non-ASCII), and not
/// inside a proxy found in the text. Proxies are ASCII and the detectors
/// need no context before them, so splitting there changes nothing.
pub(super) struct ExactStream {
    engine: Arc<Engine>,
    pending: Vec<u8>,
    hold: usize,
    restored: usize,
}

impl ExactStream {
    pub(super) fn new(engine: Arc<Engine>) -> Self {
        let longest = longest_proxy(&engine);
        Self::with_longest(engine, longest)
    }

    /// An exact pass for a vault whose longest proxy is `longest` bytes.
    pub(super) fn with_longest(engine: Arc<Engine>, longest: usize) -> Self {
        Self {
            engine,
            pending: Vec::new(),
            hold: longest.min(MAX_HOLD) + SLACK,
            restored: 0,
        }
    }

    /// Adds `bytes`; returns the restored text that can be sent now.
    pub(super) fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        self.drain(false)
    }

    /// The end of the stream: everything still held back.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, last: bool) -> Vec<u8> {
        if self.pending.is_empty() || (!last && self.pending.len() <= self.hold) {
            return Vec::new();
        }
        let reps = self.scan();
        let cut = if last {
            self.pending.len()
        } else {
            choose_cut(
                &self.pending,
                &reps,
                self.pending.len() - self.hold,
                self.pending.len() > MAX_PENDING,
            )
        };
        if cut == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(cut);
        let mut at = 0;
        for rep in reps.iter().take_while(|rep| rep.end <= cut) {
            out.extend_from_slice(&self.pending[at..rep.start]);
            out.extend_from_slice(rep.with.as_bytes());
            at = rep.end;
            self.restored += 1;
        }
        out.extend_from_slice(&self.pending[at..cut]);
        self.pending.drain(..cut);
        out
    }

    /// Replacements for the pending text, as byte offsets into it. Text that
    /// is not UTF-8 is scanned stretch by stretch; the invalid bytes between
    /// are left as they are.
    fn scan(&self) -> Vec<Replacement> {
        let mut texts = Vec::new();
        let mut offsets = Vec::new();
        let mut at = 0;
        for chunk in self.pending.utf8_chunks() {
            offsets.push(at);
            texts.push(chunk.valid());
            at += chunk.valid().len() + chunk.invalid().len();
        }
        let Ok(plans) = self.engine.plan(Mode::Deanonymize, &texts) else {
            return Vec::new();
        };
        plans
            .into_iter()
            .zip(offsets)
            .flat_map(|(plan, offset)| {
                plan.into_iter().map(move |rep| Replacement {
                    start: rep.start + offset,
                    end: rep.end + offset,
                    with: rep.with,
                })
            })
            .collect()
    }
}

/// Byte length of the longest proxy in the vault, of any kind.
fn longest_proxy(engine: &Engine) -> usize {
    let Ok(view) = engine.vault().read() else {
        return MAX_HOLD;
    };
    EntityKind::ALL
        .iter()
        .flat_map(|&kind| view.proxies_of(kind))
        .map(str::len)
        .max()
        .unwrap_or(0)
}

/// Bytes after which the text may be cut: whitespace, quotes, brackets and
/// the like, and anything non-ASCII. Not `.`, `-`, `@`, `:` or `/`, which
/// occur inside emails, addresses and URLs.
fn is_gap(byte: u8) -> bool {
    byte >= 0x80
        || byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'`'
                | b','
                | b';'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'<'
                | b'>'
                | b'|'
                | b'!'
                | b'?'
                | b'*'
                | b'&'
                | b'#'
                | b'$'
                | b'^'
                | b'~'
                | b'\\'
        )
}

/// The replacement that contains the position `cut` strictly inside it.
fn straddler(reps: &[Replacement], cut: usize) -> Option<&Replacement> {
    // Replacements are sorted and do not overlap: only the last one that
    // starts before the cut can reach past it.
    let before = reps.partition_point(|rep| rep.start < cut);
    before
        .checked_sub(1)
        .map(|i| &reps[i])
        .filter(|rep| rep.end > cut)
}

/// The largest cut position `<= limit` that no replacement straddles and
/// that falls after a gap byte and on a character boundary. The gap rule is
/// waived when `forced`, and after [`MAX_BACKTRACK`] bytes without a gap.
/// `0` when there is no place to cut.
fn choose_cut(pending: &[u8], reps: &[Replacement], limit: usize, forced: bool) -> usize {
    let mut cut = limit;
    let floor = limit.saturating_sub(MAX_BACKTRACK);
    loop {
        if let Some(rep) = straddler(reps, cut) {
            cut = rep.start;
            continue;
        }
        let inside_char = pending.get(cut).is_some_and(|&b| (0x80..0xC0).contains(&b));
        let gapless_ok = forced || cut <= floor;
        if cut == 0 || (!inside_char && (gapless_ok || is_gap(pending[cut - 1]))) {
            return cut;
        }
        cut -= 1;
    }
}

/// Both restore passes for one response.
pub(super) struct Pipeline {
    inner: Inner,
}

enum Inner {
    /// The bytes of the response as they come.
    Raw {
        /// `None` when nothing was sent to the host: there is nothing tolerant
        /// matching may restore to, so the pass is skipped (it would only delay
        /// the stream by its holdback).
        restorer: Option<Restorer>,
        exact: ExactStream,
    },
    /// An event stream, delta text by delta text.
    Events(EventStream<Restoring>),
}

impl Pipeline {
    /// For a response that is an event stream when `framing` says how its events
    /// are delimited, and restored as bytes otherwise. The scope is what `ledger`
    /// knows was sent to `host`.
    ///
    /// # Errors
    /// The tolerant matcher cannot be built.
    pub(super) fn new(
        engine: Arc<Engine>,
        ledger: &Ledger,
        host: &str,
        framing: Option<Framing>,
    ) -> piikey::Result<Self> {
        let scope = ledger.scope_for(host, engine.vault());
        let inner = if let Some(framing) = framing {
            Inner::Events(EventStream::new(framing, Restoring::new(engine, scope)))
        } else {
            let restorer = if scope.entries().is_empty() {
                None
            } else {
                Some(Restorer::new(scope)?)
            };
            Inner::Raw {
                restorer,
                exact: ExactStream::new(engine),
            }
        };
        Ok(Self { inner })
    }

    /// Restored text that can be sent now (it may lag the input a little).
    pub(super) fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        match &mut self.inner {
            Inner::Raw { restorer, exact } => match restorer {
                Some(restorer) => exact.push(&restorer.feed(chunk)),
                None => exact.push(chunk),
            },
            Inner::Events(events) => events.push(chunk),
        }
    }

    /// The end of the response.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        match &mut self.inner {
            Inner::Raw { restorer, exact } => {
                let mut out = match restorer {
                    Some(restorer) => exact.push(&restorer.flush()),
                    None => Vec::new(),
                };
                out.extend(exact.finish());
                out
            }
            Inner::Events(events) => events.finish(),
        }
    }

    /// Proxies put back so far.
    pub(super) fn restored(&self) -> usize {
        match &self.inner {
            Inner::Raw { restorer, exact } => {
                restorer.as_ref().map_or(0, Restorer::restored_count) + exact.restored
            }
            Inner::Events(events) => events.channels().restored(),
        }
    }
}

/// The restore passes for the text of one channel of an event stream.
struct Channel {
    restorer: Option<Restorer>,
    exact: Option<ExactStream>,
    /// The first bytes of a character that a pass cut in two, until the rest
    /// comes: events carry strings, which must be whole characters.
    carry: Vec<u8>,
}

impl Channel {
    fn feed(&mut self, text: &str) -> String {
        let mut bytes = match &mut self.restorer {
            Some(restorer) => restorer.feed(text.as_bytes()),
            None => text.as_bytes().to_vec(),
        };
        if let Some(exact) = &mut self.exact {
            bytes = exact.push(&bytes);
        }
        take_text(&mut self.carry, bytes, false)
    }

    fn flush(&mut self) -> String {
        let mut bytes = self
            .restorer
            .as_mut()
            .map(Restorer::flush)
            .unwrap_or_default();
        if let Some(exact) = &mut self.exact {
            bytes = exact.push(&bytes);
            bytes.extend(exact.finish());
        }
        take_text(&mut self.carry, bytes, true)
    }

    fn restored(&self) -> usize {
        self.restorer.as_ref().map_or(0, Restorer::restored_count)
            + self.exact.as_ref().map_or(0, |exact| exact.restored)
    }
}

/// The channels of one event stream: each gets the tolerant pass (when the
/// ledger knows proxies for the host) and the exact pass (when the vault holds
/// proxies). Text that is not a delta is restored on its own.
pub(super) struct Restoring {
    engine: Arc<Engine>,
    /// `None` when nothing was sent to the host.
    scope: Option<Scope>,
    /// Bytes of the longest proxy in the vault; `0` for an empty vault.
    longest: usize,
    channels: HashMap<String, Channel>,
    /// The tolerant pass for text that stands alone.
    alone: Option<Restorer>,
    /// Texts restored on their own so far.
    alone_restored: usize,
}

impl Restoring {
    fn new(engine: Arc<Engine>, scope: Scope) -> Self {
        let longest = longest_proxy(&engine);
        let scope = (!scope.entries().is_empty()).then_some(scope);
        Self {
            engine,
            alone: scope.clone().and_then(|scope| Restorer::new(scope).ok()),
            scope,
            longest,
            channels: HashMap::new(),
            alone_restored: 0,
        }
    }

    /// Proxies put back so far, in all channels and in text on its own.
    pub(super) fn restored(&self) -> usize {
        self.channels.values().map(Channel::restored).sum::<usize>() + self.alone_restored
    }
}

impl Channels for Restoring {
    fn feed(&mut self, channel: &str, text: &str) -> String {
        let Self {
            engine,
            scope,
            longest,
            channels,
            ..
        } = self;
        channels
            .entry(channel.to_owned())
            .or_insert_with(|| Channel {
                restorer: scope.clone().and_then(|scope| Restorer::new(scope).ok()),
                exact: (*longest > 0)
                    .then(|| ExactStream::with_longest(Arc::clone(engine), *longest)),
                carry: Vec::new(),
            })
            .feed(text)
    }

    fn flush(&mut self, channel: &str) -> String {
        self.channels
            .get_mut(channel)
            .map(Channel::flush)
            .unwrap_or_default()
    }

    fn restore(&mut self, text: &str) -> String {
        if self.alone.is_none() && self.longest == 0 {
            return text.to_owned();
        }
        let mut restored = match &self.alone {
            Some(alone) => take_text(&mut Vec::new(), alone.restore(text.as_bytes()), true),
            None => text.to_owned(),
        };
        // The tolerant pass does not count what it restores here: a changed text is one.
        self.alone_restored += usize::from(restored != text);
        if self.longest > 0
            && let Ok(plans) = self.engine.plan(Mode::Deanonymize, &[restored.as_str()])
            && let Some(reps) = plans.first().filter(|reps| !reps.is_empty())
        {
            self.alone_restored += reps.len();
            restored = Engine::apply(&restored, reps);
        }
        restored
    }
}

/// `bytes` as text, after the `carry` of the last call. A character cut in two
/// at the end waits in `carry` for its rest, unless this is the `last` call.
fn take_text(carry: &mut Vec<u8>, mut bytes: Vec<u8>, last: bool) -> String {
    if !carry.is_empty() {
        let mut joined = std::mem::take(carry);
        joined.extend_from_slice(&bytes);
        bytes = joined;
    }
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let incomplete = error.utf8_error().error_len().is_none();
            let valid = error.utf8_error().valid_up_to();
            let mut bytes = error.into_bytes();
            if incomplete && !last {
                *carry = bytes.split_off(valid);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }
}

/// A response being restored. Dropping it (the response ended, or the client
/// went away) reports what was restored.
struct Live {
    pipeline: Pipeline,
    events: Sender<Event>,
    host: Arc<str>,
}

impl Drop for Live {
    fn drop(&mut self) {
        let count = self.pipeline.restored();
        if count > 0 {
            let _ = self.events.send(Event::Restored {
                host: self.host.to_string(),
                count,
            });
        }
    }
}

/// `body` with its text restored as it flows. The chunks are processed on
/// blocking threads: the vault and the regex scan are not for the async
/// workers.
pub(super) fn restoring_body(
    body: Body,
    pipeline: Pipeline,
    events: Sender<Event>,
    host: Arc<str>,
) -> Body {
    let live = Live {
        pipeline,
        events,
        host,
    };
    Body::from_stream(stream::unfold(Some((body, live)), step))
}

type Step = Option<(Result<Bytes, BodyError>, Option<(Body, Live)>)>;

/// The next non-empty piece of restored output.
async fn step(state: Option<(Body, Live)>) -> Step {
    let (mut body, mut live) = state?;
    loop {
        match next_data(&mut body).await {
            Some(Ok(data)) => {
                let worked = tokio::task::spawn_blocking(move || {
                    let piece = live.pipeline.push(&data);
                    (live, piece)
                })
                .await;
                let Ok((back, piece)) = worked else {
                    return Some((Err(BodyError::Unknown), None));
                };
                live = back;
                if !piece.is_empty() {
                    return Some((Ok(Bytes::from(piece)), Some((body, live))));
                }
            }
            Some(Err(e)) => return Some((Err(e), None)),
            None => {
                let worked = tokio::task::spawn_blocking(move || {
                    let tail = live.pipeline.finish();
                    (live, tail)
                })
                .await;
                return match worked {
                    Ok((_, tail)) if tail.is_empty() => None,
                    Ok((_, tail)) => Some((Ok(Bytes::from(tail)), None)),
                    Err(_) => Some((Err(BodyError::Unknown), None)),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
    };

    use hudsucker::futures::StreamExt as _;

    use super::*;
    use crate::proxy::{body::collect, test_names};

    const NAMES: &[&str] = &["Jeroen de Vries", "Haley van Zessen"];

    /// Sentences carrying one value of each kind; anonymized, they carry the
    /// proxies the streams must restore.
    const SOURCES: [&str; 11] = [
        "mail jan.jansen@acme.nl",
        "call +31 6 12345678",
        "IBAN NL91ABNA0417164300",
        "card 4111 1111 1111 1111",
        "host 203.0.113.42",
        "mac 00:1A:2B:3C:4D:5E",
        "SSN 123-45-6789",
        "BSN 111222333",
        "ask Jeroen de Vries",
        "also Haley van Zessen",
        "db https://admin:hunter2@db.example.com/x",
    ];

    fn temp_vault(tag: &str) -> PathBuf {
        crate::ui::testing::temp_dir(tag).join("vault.pkv")
    }

    /// An engine that finds `NAMES`, and the anonymized `SOURCES`.
    fn setup(tag: &str) -> piikey::Result<(Arc<Engine>, Vec<String>)> {
        let engine = test_names::engine(&temp_vault(tag), NAMES)?;
        let sentences = engine.run(Mode::Anonymize, &SOURCES)?;
        Ok((Arc::new(engine), sentences))
    }

    /// The issued proxies in `text`, in order.
    fn proxies_in(engine: &Engine, text: &str) -> piikey::Result<Vec<String>> {
        let plans = engine.plan(Mode::Deanonymize, &[text])?;
        Ok(plans
            .into_iter()
            .flatten()
            .map(|rep| text[rep.start..rep.end].to_owned())
            .collect())
    }

    /// A ledger that has been sent every proxy in `sentences` at `host`.
    fn sent_ledger(engine: &Engine, sentences: &[String], host: &str) -> piikey::Result<Ledger> {
        let ledger = Ledger::default();
        for sentence in sentences {
            for proxy in proxies_in(engine, sentence)? {
                ledger.touch(host, &proxy);
            }
        }
        Ok(ledger)
    }

    /// Small deterministic generator (xorshift64*).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % (n as u64)).unwrap_or(0)
        }
    }

    /// A proxy sentence, then prose, scraps of JSON and multibyte text with
    /// more proxy sentences among them.
    fn random_text(rng: &mut Rng, sentences: &[String]) -> String {
        const FILLER: [&str; 11] = [
            "lorem",
            "ipsum",
            "dolor",
            "é",
            "日本語",
            "😀",
            "x",
            "12",
            "a-b",
            "v1.2",
            "ok",
        ];
        const SEPARATORS: [&str; 9] = [" ", " ", "\n", ", ", " \"", "\", ", "  ", "\t", "}\n{"];
        let mut text = String::new();
        for n in 0..=rng.below(14) {
            let piece = if n == 0 || rng.below(3) == 0 {
                sentences[rng.below(sentences.len())].as_str()
            } else {
                FILLER[rng.below(FILLER.len())]
            };
            text.push_str(piece);
            text.push_str(SEPARATORS[rng.below(SEPARATORS.len())]);
        }
        text
    }

    /// Splits `bytes` into pieces of random length up to `max`.
    fn chunks<'a>(rng: &mut Rng, bytes: &'a [u8], max: usize) -> Vec<&'a [u8]> {
        let mut pieces = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let len = (rng.below(max) + 1).min(bytes.len() - at);
            pieces.push(&bytes[at..at + len]);
            at += len;
        }
        pieces
    }

    fn exact_stream(engine: &Arc<Engine>, pieces: &[&[u8]]) -> Vec<u8> {
        let mut stream = ExactStream::new(Arc::clone(engine));
        let mut out = Vec::new();
        for piece in pieces {
            out.extend(stream.push(piece));
        }
        out.extend(stream.finish());
        out
    }

    fn utf8(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap_or("<not utf-8>")
    }

    #[test]
    fn exact_stream_equals_one_shot_under_any_chunking() -> piikey::Result<()> {
        let (engine, sentences) = setup("equiv")?;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut changed = 0;
        for round in 0..200 {
            let text = random_text(&mut rng, &sentences);
            let expected = engine.run(Mode::Deanonymize, &[&text])?.remove(0);
            changed += usize::from(expected != text);
            for max in [1, 3, 17, 64, 4096] {
                let pieces = chunks(&mut rng, text.as_bytes(), max);
                let got = exact_stream(&engine, &pieces);
                assert_eq!(
                    utf8(&got),
                    expected,
                    "round {round}, chunks up to {max}: {text:?}"
                );
            }
        }
        // Digits next to a numeric proxy can hide it from the detector, one-shot
        // or streamed alike; most texts must still carry something to restore.
        assert!(
            changed > 150,
            "only {changed} of 200 texts had a proxy to restore"
        );
        Ok(())
    }

    #[test]
    fn a_proxy_split_at_every_offset_is_still_restored() -> piikey::Result<()> {
        let (engine, sentences) = setup("splits")?;
        // Phones, cards and names contain spaces: the hardest to keep whole.
        let text = format!(
            "start {} middle {} end {}",
            sentences[1], sentences[3], sentences[8]
        );
        let expected = engine.run(Mode::Deanonymize, &[&text])?.remove(0);
        for at in 0..=text.len() {
            let got = exact_stream(&engine, &[&text.as_bytes()[..at], &text.as_bytes()[at..]]);
            assert_eq!(utf8(&got), expected, "split at {at}");
        }
        Ok(())
    }

    #[test]
    fn invalid_utf8_passes_through_and_proxies_around_it_are_restored() -> piikey::Result<()> {
        let (engine, sentences) = setup("binary")?;
        let mut bytes = Vec::new();
        for sentence in &sentences[..4] {
            bytes.extend_from_slice(sentence.as_bytes());
            bytes.extend_from_slice(b" caf\xE9 \xFF\xFE ");
        }
        // The reference: restore each valid stretch on its own.
        let mut expected = Vec::new();
        for chunk in bytes.utf8_chunks() {
            let restored = engine.run(Mode::Deanonymize, &[chunk.valid()])?.remove(0);
            expected.extend_from_slice(restored.as_bytes());
            expected.extend_from_slice(chunk.invalid());
        }
        let mut rng = Rng(7);
        for max in [1, 5, 50] {
            let pieces = chunks(&mut rng, &bytes, max);
            assert_eq!(
                exact_stream(&engine, &pieces),
                expected,
                "chunks up to {max}"
            );
        }
        assert!(
            expected.windows(3).any(|w| w == b"\xFF\xFE "),
            "binary bytes survive"
        );
        Ok(())
    }

    #[test]
    fn the_tail_held_back_stays_small_so_streams_do_not_stall() -> piikey::Result<()> {
        let (engine, _) = setup("tail")?;
        let mut stream = ExactStream::new(Arc::clone(&engine));
        let hold = stream.hold;
        let prose = "lorem ipsum dolor sit amet, consectetur adipiscing elit ".repeat(400);
        let mut sent = 0;
        let mut emitted = 0;
        for piece in prose.as_bytes().chunks(100) {
            sent += piece.len();
            emitted += stream.push(piece).len();
            assert!(
                sent - emitted <= hold + 100 + 16,
                "{} bytes held at {sent}",
                sent - emitted
            );
        }
        assert!(
            emitted > prose.len() - hold - 200,
            "most of the text went out early"
        );
        assert_eq!(emitted + stream.finish().len(), prose.len());
        Ok(())
    }

    #[test]
    fn a_token_with_no_gaps_is_cut_once_it_grows_huge() -> piikey::Result<()> {
        let (engine, _) = setup("huge")?;
        let mut stream = ExactStream::new(engine);
        let blob = vec![b'a'; MAX_PENDING + 5_000];
        let mut emitted = stream.push(&blob).len();
        assert!(emitted > 0, "forced cut");
        emitted += stream.finish().len();
        assert_eq!(emitted, blob.len());
        Ok(())
    }

    #[test]
    fn nothing_to_restore_nothing_changes() -> piikey::Result<()> {
        let (engine, _) = setup("plain")?;
        let text = "just words, 42 of them, and a@b without a proxy";
        let mut stream = ExactStream::new(engine);
        let mut out = stream.push(text.as_bytes());
        out.extend(stream.finish());
        assert_eq!(utf8(&out), text);
        assert_eq!(stream.restored, 0);
        Ok(())
    }

    #[test]
    fn restored_proxies_are_counted() -> piikey::Result<()> {
        let (engine, sentences) = setup("count")?;
        let text = format!("{} and {}", sentences[0], sentences[1]);
        let mut stream = ExactStream::new(engine);
        stream.push(text.as_bytes());
        stream.finish();
        assert_eq!(stream.restored, 2);
        Ok(())
    }

    #[test]
    fn the_search_for_a_gap_is_bounded_and_straddlers_are_found_by_position() {
        let rep = |start, end| Replacement {
            start,
            end,
            with: "x".into(),
        };
        let long = vec![b'a'; 20_000];
        assert_eq!(
            choose_cut(&long, &[], 20_000, false),
            20_000 - MAX_BACKTRACK
        );
        let reps = [rep(1, 3), rep(10, 20), rep(30, 31)];
        assert_eq!(
            straddler(&reps, 15).map(|r| (r.start, r.end)),
            Some((10, 20))
        );
        assert!(straddler(&reps, 10).is_none() && straddler(&reps, 20).is_none());
        assert!(straddler(&reps, 0).is_none() && straddler(&[], 5).is_none());
    }

    #[test]
    fn cuts_avoid_replacements_and_character_interiors() {
        let rep = |start, end| Replacement {
            start,
            end,
            with: "x".into(),
        };
        let text = b"aa bbbb cc";
        // Limit 5 falls inside the replacement 3..7: cut before it, after the gap.
        assert_eq!(choose_cut(text, &[rep(3, 7)], 5, false), 3);
        // No gap at the limit and nothing straddling: back to the last gap.
        assert_eq!(choose_cut(text, &[], 6, false), 3);
        assert_eq!(
            choose_cut(text, &[], 2, false),
            0,
            "no gap before position 2"
        );
        assert_eq!(choose_cut(text, &[], 6, true), 6, "forced: any boundary");
        // Never inside a multibyte character: `é` is 0xC3 0xA9.
        let accented = "ab é cd".as_bytes();
        assert_eq!(
            choose_cut(accented, &[], 4, true),
            3,
            "not between the two bytes"
        );
        assert!(is_gap(b' ') && is_gap(0xC3) && is_gap(b'"'));
        assert!(!is_gap(b'a') && !is_gap(b'@') && !is_gap(b'.') && !is_gap(b':'));
    }

    // ---- the full pipeline ----

    /// Pipeline over `pieces`, plus how many proxies it restored.
    fn pipeline_run(
        engine: &Arc<Engine>,
        ledger: &Ledger,
        host: &str,
        pieces: &[&[u8]],
    ) -> piikey::Result<(Vec<u8>, usize)> {
        let mut pipeline = Pipeline::new(Arc::clone(engine), ledger, host, None)?;
        let mut out = Vec::new();
        for piece in pieces {
            out.extend(pipeline.push(piece));
        }
        out.extend(pipeline.finish());
        Ok((out, pipeline.restored()))
    }

    #[test]
    fn the_pipeline_equals_one_shot_under_any_chunking() -> piikey::Result<()> {
        let (engine, sentences) = setup("pipe-equiv")?;
        let host = "chat.example.com";
        let ledger = sent_ledger(&engine, &sentences, host)?;
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for round in 0..60 {
            let text = random_text(&mut rng, &sentences);
            let (whole, _) = pipeline_run(&engine, &ledger, host, &[text.as_bytes()])?;
            for max in [1, 7, 40, 4096] {
                let pieces = chunks(&mut rng, text.as_bytes(), max);
                let (got, _) = pipeline_run(&engine, &ledger, host, &pieces)?;
                assert_eq!(got, whole, "round {round}, chunks up to {max}: {text:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn exact_restore_works_with_an_empty_ledger() -> piikey::Result<()> {
        // A restarted app: nothing remembered, the vault still knows.
        let (engine, sentences) = setup("pipe-empty")?;
        let text = sentences.join(" | ");
        let expected = engine.run(Mode::Deanonymize, &[&text])?.remove(0);
        let (got, restored) = pipeline_run(
            &engine,
            &Ledger::default(),
            "chat.example.com",
            &[text.as_bytes()],
        )?;
        assert_eq!(utf8(&got), expected);
        assert_eq!(restored, proxies_in(&engine, &text)?.len());
        assert!(restored >= SOURCES.len());
        Ok(())
    }

    #[test]
    fn typos_and_partial_names_are_repaired_only_for_proxies_sent_to_the_host() -> piikey::Result<()>
    {
        let (engine, _) = setup("pipe-tolerant")?;
        let sent = engine.run(
            Mode::Anonymize,
            &["mail jan.jansen@acme.nl and Jeroen de Vries"],
        )?;
        let host = "chat.example.com";
        let ledger = sent_ledger(&engine, &sent, host)?;
        let proxies = proxies_in(&engine, &sent[0])?;
        let [email_proxy, name_proxy] = proxies.as_slice() else {
            return Err(piikey::Error::Protocol(
                "expected an email and a name proxy",
            ));
        };
        // A doubled letter in the email, and only the first name of the person.
        let typo = format!("{}{}", &email_proxy[..3], &email_proxy[2..]);
        let first = name_proxy.split(' ').next().unwrap_or(name_proxy);
        let reply = format!("Sure: write to {typo}, and ask {first} about it.");

        let (got, restored) = pipeline_run(&engine, &ledger, host, &[reply.as_bytes()])?;
        assert_eq!(
            utf8(&got),
            "Sure: write to jan.jansen@acme.nl, and ask Jeroen about it."
        );
        assert_eq!(restored, 2);
        // A host that was never sent these proxies gets no tolerance.
        let (other, _) = pipeline_run(
            &engine,
            &Ledger::default(),
            "elsewhere.org",
            &[reply.as_bytes()],
        )?;
        assert_eq!(
            utf8(&other),
            reply,
            "typo and bare first name stay as they are"
        );
        Ok(())
    }

    // ---- the streaming body ----

    fn body_of(pieces: Vec<Vec<u8>>) -> Body {
        let items: Vec<Result<Bytes, BodyError>> = pieces
            .into_iter()
            .map(|piece| Ok(Bytes::from(piece)))
            .collect();
        Body::from_stream(stream::iter(items))
    }

    #[tokio::test]
    async fn the_body_streams_restored_chunks_and_reports_the_count() -> piikey::Result<()> {
        let (engine, sentences) = setup("body")?;
        let unit = format!(
            "{} then {} and {} ;",
            sentences[0], sentences[1], sentences[2]
        );
        let text = unit.repeat(5);
        let expected = engine.run(Mode::Deanonymize, &[&text])?.remove(0);
        let pieces: Vec<Vec<u8>> = text.as_bytes().chunks(9).map(<[u8]>::to_vec).collect();
        let pipeline = Pipeline::new(
            Arc::clone(&engine),
            &Ledger::default(),
            "h.example.com",
            None,
        )?;
        let (tx, rx) = mpsc::channel();

        let restored = restoring_body(body_of(pieces), pipeline, tx, Arc::from("h.example.com"));
        let all = collect(restored, 1 << 20).await.ok();
        assert_eq!(all.as_deref().map(utf8), Some(expected.as_str()));

        match rx.try_recv() {
            Ok(Event::Restored { host, count }) => {
                assert_eq!(host, "h.example.com");
                assert_eq!(count, proxies_in(&engine, &text)?.len());
                assert!(count >= 15, "{count}");
            }
            other => panic!("expected one Restored event, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "one event per response");
        Ok(())
    }

    #[tokio::test]
    async fn a_response_without_proxies_reports_nothing() -> piikey::Result<()> {
        let (engine, _) = setup("body-quiet")?;
        let pipeline = Pipeline::new(engine, &Ledger::default(), "h.example.com", None)?;
        let (tx, rx) = mpsc::channel();
        let pieces = vec![b"{\"a\":1}".to_vec(), b"\n".to_vec()];
        let restored = restoring_body(body_of(pieces), pipeline, tx, Arc::from("h.example.com"));
        let all = collect(restored, 1 << 20).await.ok();
        assert_eq!(all.as_deref(), Some(b"{\"a\":1}\n".as_slice()));
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn output_starts_long_before_the_input_ends() -> piikey::Result<()> {
        // A ledger with entries keeps the tolerant pass (and its holdback) on.
        let (engine, sentences) = setup("body-early")?;
        let ledger = sent_ledger(&engine, &sentences, "h.example.com")?;
        let pipeline = Pipeline::new(engine, &ledger, "h.example.com", None)?;
        let (tx, _rx) = mpsc::channel();
        let words = "streaming words arrive steadily ".repeat(50);
        let total = words.len().div_ceil(32);
        let polled = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&polled);
        let upstream = Body::from_stream(
            stream::iter(
                words
                    .as_bytes()
                    .chunks(32)
                    .map(|piece| Ok::<_, BodyError>(Bytes::copy_from_slice(piece)))
                    .collect::<Vec<_>>(),
            )
            .inspect(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let mut restored = restoring_body(upstream, pipeline, tx, Arc::from("h"));
        let first = next_data(&mut restored).await.and_then(Result::ok);
        assert!(first.is_some_and(|data| !data.is_empty()));
        let consumed = polled.load(Ordering::SeqCst);
        assert!(
            consumed < total / 2,
            "{consumed} of {total} chunks read before the first output"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_upstream_error_ends_the_stream_with_an_error() -> piikey::Result<()> {
        let (engine, _) = setup("body-error")?;
        let pipeline = Pipeline::new(engine, &Ledger::default(), "h", None)?;
        let (tx, _rx) = mpsc::channel();
        let items: Vec<Result<Bytes, BodyError>> =
            vec![Ok(Bytes::from_static(b"partial ")), Err(BodyError::Unknown)];
        let upstream = Body::from_stream(stream::iter(items));
        let mut restored = restoring_body(upstream, pipeline, tx, Arc::from("h"));
        let mut seen_error = false;
        while let Some(data) = next_data(&mut restored).await {
            seen_error |= data.is_err();
        }
        assert!(seen_error);
        Ok(())
    }

    // ---- event streams ----

    use serde_json::Value;

    use super::super::events::fixtures::{anthropic, ndjson, openai, sse_events, texts};

    const HOST: &str = "chat.example.com";

    /// A reply that mentions an email address and two people, as the user should read
    /// it, and cut into pieces the way a service streams it.
    struct Reply {
        read: String,
        /// Cut inside every proxy, at its `@` and spaces, and inside a character.
        awkward: Vec<String>,
        /// One character each.
        chars: Vec<String>,
    }

    fn reply(engine: &Engine, sentences: &[String]) -> piikey::Result<Reply> {
        let email = proxies_in(engine, &sentences[0])?.remove(0);
        let name = proxies_in(engine, &sentences[8])?.remove(0);
        let other = proxies_in(engine, &sentences[9])?.remove(0);
        let sent = format!(
            "Sure! Write to {email} and ask {name} (or {other}) for the report. Café ☕ ok."
        );
        let read = sent
            .replace(&email, "jan.jansen@acme.nl")
            .replace(&name, "Jeroen de Vries")
            .replace(&other, "Haley van Zessen");
        let mut cuts = Vec::new();
        for proxy in [&email, &name, &other] {
            let start = sent.find(proxy.as_str()).unwrap_or(0);
            cuts.extend([start + 1, start + proxy.len() / 2, start + proxy.len() - 1]);
            for (at, _) in proxy.match_indices(['@', ' ']) {
                cuts.extend([start + at, start + at + 1]);
            }
        }
        cuts.extend(sent.find("Café").map(|at| at + 3));
        cuts.sort_unstable();
        cuts.dedup();
        cuts.retain(|&cut| cut > 0 && cut < sent.len() && sent.is_char_boundary(cut));
        let mut awkward = Vec::new();
        let mut from = 0;
        for cut in cuts.into_iter().chain([sent.len()]) {
            awkward.push(sent[from..cut].to_owned());
            from = cut;
        }
        let chars = sent.chars().map(String::from).collect();
        Ok(Reply {
            read,
            awkward,
            chars,
        })
    }

    fn event_run(
        engine: &Arc<Engine>,
        ledger: &Ledger,
        framing: Framing,
        input: &[u8],
        size: usize,
    ) -> piikey::Result<(Vec<u8>, usize)> {
        let mut pipeline = Pipeline::new(Arc::clone(engine), ledger, HOST, Some(framing))?;
        let mut out = Vec::new();
        for piece in input.chunks(size.max(1)) {
            out.extend(pipeline.push(piece));
        }
        out.extend(pipeline.finish());
        Ok((out, pipeline.restored()))
    }

    /// `build`s streams from the pieces of the reply and restores them in every
    /// scope (the ledger knows the proxies, or only the vault does) and chunking.
    /// Returns the input and output of the first stream, for further checks.
    fn check_stream(
        tag: &str,
        framing: Framing,
        pointer: &str,
        build: fn(&[&str]) -> Vec<u8>,
    ) -> piikey::Result<(Vec<u8>, Vec<u8>)> {
        let (engine, sentences) = setup(tag)?;
        let reply = reply(&engine, &sentences)?;
        let ledgers = [sent_ledger(&engine, &sentences, HOST)?, Ledger::default()];
        let mut first = None;
        for ledger in &ledgers {
            for pieces in [&reply.awkward, &reply.chars] {
                let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
                let input = build(&refs);
                let (whole, restored) = event_run(&engine, ledger, framing, &input, input.len())?;
                let got = texts(&whole, framing, pointer);
                assert_eq!(got, reply.read, "{tag}: {} events", refs.len());
                assert_eq!(restored, 3, "{tag}: one per mention");
                for size in [1, 5, 64] {
                    let (again, _) = event_run(&engine, ledger, framing, &input, size)?;
                    assert_eq!(again, whole, "{tag}: chunks of {size}");
                }
                first.get_or_insert((input, whole));
            }
        }
        first.ok_or(piikey::Error::Protocol("no stream was checked"))
    }

    #[test]
    fn openai_deltas_cut_inside_an_email_and_names_are_restored() -> piikey::Result<()> {
        let (input, out) = check_stream(
            "events-openai",
            Framing::Sse,
            "/choices/0/delta/content",
            openai,
        )?;
        let events = sse_events(&out);
        let original = sse_events(&input);
        assert_eq!(events.last().map(|(_, data)| data.as_str()), Some("[DONE]"));
        assert!(
            events[events.len() - 2]
                .1
                .contains(r#""finish_reason":"stop""#)
        );
        // Every event of the service is still there, in order; the text it held
        // back came out as events of their own before the finish chunk.
        assert_eq!(events[0], original[0]);
        assert_eq!(events[events.len() - 2..], original[original.len() - 2..]);
        assert!(events.len() >= original.len());
        Ok(())
    }

    #[test]
    fn anthropic_deltas_cut_inside_an_email_and_names_are_restored() -> piikey::Result<()> {
        let (input, out) =
            check_stream("events-anthropic", Framing::Sse, "/delta/text", anthropic)?;
        let names = |stream: &[u8]| -> Vec<String> {
            sse_events(stream)
                .into_iter()
                .map(|(name, _)| name.unwrap_or_default())
                .collect()
        };
        let got = names(&out);
        let stop = got.iter().position(|name| name == "content_block_stop");
        let stop = stop.ok_or(piikey::Error::Protocol("no content_block_stop"))?;
        assert!(
            got[stop..].iter().all(|name| name != "content_block_delta"),
            "no text after its block stopped: {got:?}"
        );
        let others = |names: Vec<String>| -> Vec<String> {
            names
                .into_iter()
                .filter(|name| name != "content_block_delta")
                .collect()
        };
        assert_eq!(
            others(got),
            others(names(&input)),
            "the other events keep their order"
        );
        Ok(())
    }

    #[test]
    fn json_lines_cut_inside_an_email_and_names_are_restored() -> piikey::Result<()> {
        let (input, out) =
            check_stream("events-ndjson", Framing::Ndjson, "/message/content", ndjson)?;
        let lines = |stream: &[u8]| -> Vec<Value> {
            String::from_utf8_lossy(stream)
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        };
        let (got, original) = (lines(&out), lines(&input));
        assert_eq!(
            got.len(),
            original.len(),
            "the text held back rides on the last line"
        );
        assert_eq!(
            got.last().map(|line| &line["done"]),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            got.last().map(|line| &line["model"]),
            original.last().map(|line| &line["model"])
        );
        assert!(out.ends_with(b"\n"));
        Ok(())
    }

    #[test]
    fn streams_that_cannot_hold_proxies_pass_untouched() -> piikey::Result<()> {
        // An empty vault and nothing sent: there is nothing to restore.
        let engine = Arc::new(Engine::open(&temp_vault("events-clean"))?);
        let pieces = ["Hello ", "wor", "ld, no ", "mentions here."];
        let streams = [
            (Framing::Sse, openai(&pieces)),
            (Framing::Sse, anthropic(&pieces)),
            (Framing::Ndjson, ndjson(&pieces)),
        ];
        for (framing, input) in &streams {
            for size in [1, 7, input.len()] {
                let (out, restored) =
                    event_run(&engine, &Ledger::default(), *framing, input, size)?;
                assert_eq!(&out, input, "{framing:?}, chunks of {size}");
                assert_eq!(restored, 0);
            }
        }

        // With proxies around but none in the reply, the text and the events are
        // the same, and `[DONE]` is still last.
        let (engine, sentences) = setup("events-unrelated")?;
        let ledger = sent_ledger(&engine, &sentences, HOST)?;
        let input = openai(&pieces);
        let (out, restored) = event_run(&engine, &ledger, Framing::Sse, &input, 9)?;
        assert_eq!(restored, 0);
        assert_eq!(
            texts(&out, Framing::Sse, "/choices/0/delta/content"),
            pieces.concat()
        );
        assert_eq!(
            sse_events(&out).last().map(|(_, data)| data.as_str()),
            Some("[DONE]")
        );
        assert_eq!(
            sse_events(&out).len(),
            sse_events(&input).len() + 1,
            "the held text"
        );
        Ok(())
    }

    #[test]
    fn a_typo_and_a_partial_name_cut_across_events_are_repaired() -> piikey::Result<()> {
        let (engine, sentences) = setup("events-tolerant")?;
        // Only the email and the person were sent. A bare first name stands for its person only
        // while no other proxy in the scope has it too, and the second person of `NAMES` draws
        // the same first name now and then (one time in 200).
        let sent = [sentences[0].clone(), sentences[8].clone()];
        let ledger = sent_ledger(&engine, &sent, HOST)?;
        let email = proxies_in(&engine, &sentences[0])?.remove(0);
        let name = proxies_in(&engine, &sentences[8])?.remove(0);
        // A doubled letter in the email, and only the first name of the person.
        let typo = format!("{}{}", &email[..3], &email[2..]);
        let first = name.split(' ').next().unwrap_or(&name);
        let text = format!("Mail {typo}, and ask {first} about it.");
        let pieces: Vec<String> = text
            .chars()
            .collect::<Vec<_>>()
            .chunks(3)
            .map(|chars| chars.iter().collect())
            .collect();
        let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
        let (out, restored) = event_run(&engine, &ledger, Framing::Sse, &openai(&refs), 11)?;
        assert_eq!(
            texts(&out, Framing::Sse, "/choices/0/delta/content"),
            "Mail jan.jansen@acme.nl, and ask Jeroen about it."
        );
        assert_eq!(restored, 2);
        Ok(())
    }

    #[test]
    fn mentions_in_events_that_are_not_deltas_are_restored_on_their_own() -> piikey::Result<()> {
        let (engine, sentences) = setup("events-others")?;
        let email = proxies_in(&engine, &sentences[0])?.remove(0);
        let name = proxies_in(&engine, &sentences[8])?.remove(0);
        let title = serde_json::json!({
            "type": "title", "title": format!("Mail to {email}"), "id": "t-1"
        });
        let stream = format!(
            "event: title\ndata: {title}\n\ndata: sent to {email}, ask {name}\n\ndata: [DONE]\n\n"
        );
        for ledger in [sent_ledger(&engine, &sentences, HOST)?, Ledger::default()] {
            for size in [1, 6, 4096] {
                let (out, restored) =
                    event_run(&engine, &ledger, Framing::Sse, stream.as_bytes(), size)?;
                let events = sse_events(&out);
                assert_eq!(events.len(), 3, "size {size}");
                let title: Value = serde_json::from_str(&events[0].1).unwrap_or_default();
                assert_eq!(title["title"], "Mail to jan.jansen@acme.nl");
                assert_eq!(title["id"], "t-1");
                assert_eq!(events[0].0.as_deref(), Some("title"));
                assert_eq!(
                    events[1].1,
                    "sent to jan.jansen@acme.nl, ask Jeroen de Vries"
                );
                assert_eq!(events[2].1, "[DONE]");
                assert!(restored >= 2, "{restored}");
            }
        }
        Ok(())
    }

    #[test]
    fn characters_cut_in_two_by_a_pass_are_completed_before_they_go_into_an_event() {
        let mut carry = Vec::new();
        // `é` is 0xC3 0xA9.
        assert_eq!(take_text(&mut carry, b"caf\xC3".to_vec(), false), "caf");
        assert_eq!(carry, [0xC3]);
        assert_eq!(take_text(&mut carry, b"\xA9 ok".to_vec(), false), "é ok");
        assert!(carry.is_empty());
        // At the end nothing may wait any longer.
        assert_eq!(
            take_text(&mut carry, b"x\xE2\x98".to_vec(), true),
            "x\u{FFFD}"
        );
        assert!(carry.is_empty());
    }
}
