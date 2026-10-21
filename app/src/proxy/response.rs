//! Restoring proxies in a response while it streams.
//!
//! One pass reads the text once: a [`Restorer`] that restores
//!
//! 1. the proxies this app sent to the host, which its scope holds (exact, typo'd and partial
//!    mentions), and
//! 2. every proxy the vault ever issued, exactly, which the engine finds in the same text
//!    ([`piikey::restore::ProxyFinder`]). It covers what the ledger no longer (or does not yet)
//!    remember: a restarted app, a proxy sent more than a day ago, a chat history that the
//!    server stores and replays.
//!
//! Both are found before anything is replaced, so a value that is restored is never read again:
//! a real value that equals the proxy of another comes back once, as itself. The output of any
//! chunking equals the one-shot result.
//!
//! Event streams (server-sent events, JSON lines) are not restored as bytes: a
//! mention cut across two delta events has JSON between its pieces. The
//! [`events`](super::events) layer feeds the text of the delta strings, as one
//! continuous text per channel, through a restorer ([`Restoring`]) and puts
//! the result back into the events.

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{Arc, mpsc::Sender},
};

use hudsucker::{Body, Error as BodyError, futures::stream, hyper::body::Bytes};
use piikey::{
    engine::Engine,
    restore::{Restorer, Scope},
};

use super::{
    Event,
    body::next_data,
    events::{Channels, EventStream, Framing},
};
use crate::ledger::Ledger;

/// The restore pass for one response.
pub(super) struct Pipeline {
    inner: Inner,
}

enum Inner {
    /// The bytes of the response as they come.
    Raw {
        engine: Arc<Engine>,
        /// Scoped to what was sent to the host. Nothing sent: it restores only what the engine
        /// finds, and with an empty vault as well it holds nothing back.
        restorer: Restorer,
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
        let inner = match framing {
            Some(framing) => {
                Inner::Events(EventStream::new(framing, Restoring::new(engine, scope)?))
            }
            None => Inner::Raw {
                restorer: Restorer::new(scope)?,
                engine,
            },
        };
        Ok(Self { inner })
    }

    /// Restored text that can be sent now (it may lag the input a little).
    pub(super) fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        match &mut self.inner {
            Inner::Raw { engine, restorer } => restorer.feed_with(chunk, &**engine),
            Inner::Events(events) => events.push(chunk),
        }
    }

    /// The end of the response.
    pub(super) fn finish(&mut self) -> Vec<u8> {
        match &mut self.inner {
            Inner::Raw { engine, restorer } => restorer.flush_with(&**engine),
            Inner::Events(events) => events.finish(),
        }
    }

    /// Proxies put back so far.
    pub(super) fn restored(&self) -> usize {
        match &self.inner {
            Inner::Raw { restorer, .. } => restorer.restored_count(),
            Inner::Events(events) => events.channels().restored(),
        }
    }
}

/// The restorer for the text of one channel of an event stream.
struct Channel {
    restorer: Restorer,
    /// The first bytes of a character that the restorer cut in two, until the rest
    /// comes: events carry strings, which must be whole characters.
    carry: Vec<u8>,
}

impl Channel {
    fn feed(&mut self, text: &str, engine: &Engine) -> String {
        let bytes = self.restorer.feed_with(text.as_bytes(), engine);
        take_text(&mut self.carry, bytes, false)
    }

    fn flush(&mut self, engine: &Engine) -> String {
        let bytes = self.restorer.flush_with(engine);
        take_text(&mut self.carry, bytes, true)
    }
}

/// The channels of one event stream: each gets a restorer of its own, scoped to the proxies the
/// ledger knows for the host and finding every proxy of the vault. Text that is not a delta is
/// restored on its own.
pub(super) struct Restoring {
    engine: Arc<Engine>,
    /// What was sent to the host; empty when nothing was.
    scope: Scope,
    channels: HashMap<String, Channel>,
    /// The restorer for text that stands alone.
    alone: Restorer,
    /// Proxies put back in text that stood alone so far.
    alone_restored: usize,
}

impl Restoring {
    /// # Errors
    /// The tolerant matcher cannot be built.
    fn new(engine: Arc<Engine>, scope: Scope) -> piikey::Result<Self> {
        Ok(Self {
            engine,
            alone: Restorer::new(scope.clone())?,
            scope,
            channels: HashMap::new(),
            alone_restored: 0,
        })
    }

    /// Proxies put back so far, in all channels and in text on its own.
    pub(super) fn restored(&self) -> usize {
        let channels: usize = self
            .channels
            .values()
            .map(|channel| channel.restorer.restored_count())
            .sum();
        channels + self.alone_restored
    }
}

impl Channels for Restoring {
    fn feed(&mut self, channel: &str, text: &str) -> String {
        let channel = match self.channels.entry(channel.to_owned()) {
            Entry::Occupied(channel) => channel.into_mut(),
            Entry::Vacant(slot) => match Restorer::new(self.scope.clone()) {
                Ok(restorer) => slot.insert(Channel {
                    restorer,
                    carry: Vec::new(),
                }),
                // The scope was built once already, for text on its own: not in practice.
                Err(_) => return text.to_owned(),
            },
        };
        channel.feed(text, &self.engine)
    }

    fn flush(&mut self, channel: &str) -> String {
        self.channels
            .get_mut(channel)
            .map(|channel| channel.flush(&self.engine))
            .unwrap_or_default()
    }

    fn restore(&mut self, text: &str) -> String {
        let reps = self.alone.plan_with(text.as_bytes(), &*self.engine);
        self.alone_restored += reps.len();
        Engine::apply(text, &reps)
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
    use piikey::{detect::Mode, restore::ProxyFinder};

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
        let found = engine.proxies_in(&[text])?;
        Ok(found
            .into_iter()
            .flatten()
            .map(|span| text[span.start..span.end].to_owned())
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

    /// What a response that comes in `pieces` is restored to when nothing was sent to its host:
    /// only the proxies the vault knows come back.
    fn vault_only(engine: &Arc<Engine>, pieces: &[&[u8]]) -> piikey::Result<Vec<u8>> {
        let (out, _) = pipeline_run(engine, &Ledger::default(), "chat.example.com", pieces)?;
        Ok(out)
    }

    fn utf8(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap_or("<not utf-8>")
    }

    #[test]
    fn vault_proxies_equal_one_shot_under_any_chunking() -> piikey::Result<()> {
        let (engine, sentences) = setup("equiv")?;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut changed = 0;
        for round in 0..200 {
            let text = random_text(&mut rng, &sentences);
            let expected = engine.run(Mode::Deanonymize, &[&text])?.remove(0);
            changed += usize::from(expected != text);
            for max in [1, 3, 17, 64, 4096] {
                let pieces = chunks(&mut rng, text.as_bytes(), max);
                let got = vault_only(&engine, &pieces)?;
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
            let got = vault_only(&engine, &[&text.as_bytes()[..at], &text.as_bytes()[at..]])?;
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
                vault_only(&engine, &pieces)?,
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
        // The longest proxy of the vault, and some slack after it.
        let hold = engine.longest() + 16;
        let mut pipeline = Pipeline::new(Arc::clone(&engine), &Ledger::default(), "h", None)?;
        let prose = "lorem ipsum dolor sit amet, consectetur adipiscing elit ".repeat(400);
        let mut sent = 0;
        let mut emitted = 0;
        for piece in prose.as_bytes().chunks(100) {
            sent += piece.len();
            emitted += pipeline.push(piece).len();
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
        assert_eq!(emitted + pipeline.finish().len(), prose.len());
        Ok(())
    }

    #[test]
    fn a_token_with_no_gaps_is_cut_once_it_grows_huge() -> piikey::Result<()> {
        let (engine, _) = setup("huge")?;
        let mut pipeline = Pipeline::new(engine, &Ledger::default(), "h", None)?;
        // More than a restorer holds back for one token.
        let blob = vec![b'a'; 2 << 20];
        let mut emitted = pipeline.push(&blob).len();
        assert!(emitted > 0, "forced cut");
        emitted += pipeline.finish().len();
        assert_eq!(emitted, blob.len());
        Ok(())
    }

    #[test]
    fn nothing_to_restore_nothing_changes() -> piikey::Result<()> {
        let (engine, _) = setup("plain")?;
        let text = "just words, 42 of them, and a@b without a proxy";
        let (out, restored) = pipeline_run(&engine, &Ledger::default(), "h", &[text.as_bytes()])?;
        assert_eq!(utf8(&out), text);
        assert_eq!(restored, 0);
        Ok(())
    }

    #[test]
    fn restored_proxies_are_counted() -> piikey::Result<()> {
        let (engine, sentences) = setup("count")?;
        let text = format!("{} and {}", sentences[0], sentences[1]);
        let (_, restored) = pipeline_run(&engine, &Ledger::default(), "h", &[text.as_bytes()])?;
        assert_eq!(restored, 2);
        Ok(())
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

    /// A ledger that has been sent each of `proxies` at `host`.
    fn ledger_with(host: &str, proxies: &[&str]) -> Ledger {
        let ledger = Ledger::default();
        for proxy in proxies {
            ledger.touch(host, proxy);
        }
        ledger
    }

    #[test]
    fn a_value_equal_to_another_stand_in_is_restored_once() -> piikey::Result<()> {
        let (engine, _) = setup("lookalike")?;
        let (first, second) = test_names::lookalike_stand_ins(&engine)?;
        let host = "chat.example.com";
        let reply = format!("{first} and {second}, {second} and {first}.");
        let want = format!("Jan Smit and {first}, {first} and Jan Smit.");
        // The app sent the host both of them, one of them or none: the vault knows both.
        let ledgers = [
            ledger_with(host, &[&first, &second]),
            ledger_with(host, &[&first]),
            ledger_with(host, &[&second]),
            Ledger::default(),
        ];
        for ledger in &ledgers {
            for size in [1, 3, reply.len()] {
                let pieces: Vec<&[u8]> = reply.as_bytes().chunks(size).collect();
                let (got, restored) = pipeline_run(&engine, ledger, host, &pieces)?;
                assert_eq!(utf8(&got), want, "chunks of {size}");
                assert_eq!(restored, 4, "chunks of {size}");
            }
        }
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
        // A ledger with entries gives the restorer a scope, and with it a longer holdback.
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
    fn a_value_equal_to_another_stand_in_is_restored_once_in_events_too() -> piikey::Result<()> {
        let (engine, _) = setup("events-lookalike")?;
        let (first, second) = test_names::lookalike_stand_ins(&engine)?;
        let said = format!("{first} and {second}");
        let want = format!("Jan Smit and {first}");
        // As deltas cut into pieces, and whole in an event that is not a delta.
        let chars: Vec<char> = said.chars().collect();
        let pieces: Vec<String> = chars
            .chunks(3)
            .map(|chars| chars.iter().collect())
            .collect();
        let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
        let deltas = openai(&refs);
        let title = serde_json::json!({ "type": "title", "title": said });
        let alone = format!("event: title\ndata: {title}\n\n");
        let ledgers = [
            sent_ledger(&engine, std::slice::from_ref(&said), HOST)?,
            Ledger::default(),
        ];
        for ledger in &ledgers {
            for size in [1, 7, deltas.len()] {
                let (out, restored) = event_run(&engine, ledger, Framing::Sse, &deltas, size)?;
                let got = texts(&out, Framing::Sse, "/choices/0/delta/content");
                assert_eq!(got, want, "chunks of {size}");
                assert_eq!(restored, 2, "chunks of {size}");
            }
            let (out, restored) = event_run(&engine, ledger, Framing::Sse, alone.as_bytes(), 5)?;
            let events = sse_events(&out);
            assert_eq!(events.len(), 1);
            let title: Value = serde_json::from_str(&events[0].1).unwrap_or_default();
            assert_eq!(title["title"], want);
            assert_eq!(restored, 2);
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
