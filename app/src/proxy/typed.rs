//! What the user typed or pasted, kept as the values the proxy masks.
//!
//! The capture thread (`crate::capture`) reads the focused text field and the clipboard and
//! [`push`](Typed::push)es what it sees. [`Typed::flush`] runs the engine's detection over that text
//! and keeps each value it finds with the proxy the vault issued for it. An outgoing request is then
//! searched for those exact values ([`Typed::replace`]), so whatever else the page sends (scripts,
//! ids, telemetry) is never taken for personal data, let alone rewritten.
//!
//! The store holds the user's text, so it keeps as little of it as it can, for as short a time as it
//! can: switching it off ([`Typed::set_active`]) drops everything, pending text goes with the flush
//! that reads it, a value goes [`TTL`] after it was last typed or sent, and no more than
//! [`MAX_VALUES`] are kept.
//!
//! A request body may be JSON, so a value is searched for in three spellings: as typed, as the inside
//! of a JSON string, and as that with every non-ASCII character written `\uXXXX`. The proxy that
//! replaces it is spelled the same way, so the JSON stays valid.

use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt::{self, Write as _},
    mem,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use aho_corasick::AhoCorasick;
use piikey::{
    Result,
    detect::{EntityKind, KindSet},
    engine::{Engine, Resent},
};

/// Texts waiting for detection; beyond this the oldest is dropped.
const MAX_PENDING: usize = 8;
/// Bytes of one text that are kept; the rest is cut off.
const MAX_TEXT: usize = 256 << 10;
/// Values kept; beyond this the one seen longest ago goes.
const MAX_VALUES: usize = 4_096;
/// How long a value is kept after it was last typed again or found in a request.
const TTL: Duration = Duration::from_hours(6);

/// What the user typed or pasted. Requests read it, the capture thread writes it.
#[derive(Default)]
pub struct Typed {
    /// Capture is running; when false the proxy falls back to full detection.
    active: AtomicBool,
    /// Capture cannot see the screen right now (a read is overdue): requests are checked whole
    /// until it can again; what was kept stays. Only ever set while `active` is.
    blind: AtomicBool,
    /// Held for the whole of a [`Typed::flush`]: a request that finds nothing pending still has to
    /// wait for the detection another thread has under way, or the text that thread is reading
    /// would go out as it was typed.
    flushing: Mutex<()>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Text captured but not yet run through detection, newest last.
    pending: Vec<String>,
    /// What detection found in it, by the text of the value.
    values: HashMap<Arc<str>, Value>,
    /// Finds every spelling of every value; built again when `values` changed.
    matcher: Option<Arc<Matcher>>,
}

impl Inner {
    /// Forgets the values last seen more than [`TTL`] before `now`, and those of a kind the
    /// engine no longer masks: switching a kind off stops it at once, as it does without capture.
    fn forget(&mut self, now: Instant, enabled: KindSet) {
        let before = self.values.len();
        self.values.retain(|_, value| {
            enabled.contains(value.kind) && now.saturating_duration_since(value.last_seen) <= TTL
        });
        if self.values.len() != before {
            self.matcher = None;
        }
    }

    /// Drops the values seen longest ago until no more than [`MAX_VALUES`] are left; whether any
    /// went.
    fn trim(&mut self) -> bool {
        let excess = self.values.len().saturating_sub(MAX_VALUES);
        if excess == 0 {
            return false;
        }
        let mut by_age: Vec<(Instant, Arc<str>)> = self
            .values
            .iter()
            .map(|(text, value)| (value.last_seen, Arc::clone(text)))
            .collect();
        by_age.sort_unstable_by_key(|&(seen, _)| seen);
        for (_, text) in by_age.into_iter().take(excess) {
            self.values.remove(&text);
        }
        true
    }
}

/// A value found in what the user typed.
struct Value {
    kind: EntityKind,
    /// The proxy the vault issued for it.
    proxy: Box<str>,
    /// When it was last typed again or found in a request.
    last_seen: Instant,
}

/// A value detection found in a text, on its way into the store.
struct Detected {
    text: Arc<str>,
    kind: EntityKind,
    proxy: Box<str>,
}

// Hand-written: a derived `Debug` would print the user's text.
impl fmt::Debug for Typed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Typed")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

impl Typed {
    /// An inactive store: it keeps nothing until [`Typed::set_active`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts or stops keeping what is pushed. Stopping drops everything kept, and the
    /// blindness ([`Typed::set_blind`]) with it.
    pub fn set_active(&self, on: bool) {
        let mut inner = self.lock();
        self.active.store(on, Ordering::Release);
        if !on {
            self.blind.store(false, Ordering::Release);
            *inner = Inner::default();
        }
    }

    /// Capture cannot see the screen right now (a read is overdue): requests are checked whole
    /// until it can again; what was kept stays. Pushing, flushing and replacing go on meanwhile.
    /// Ignored while capture is not running, so a call that comes after a stop cannot outlive it.
    pub fn set_blind(&self, blind: bool) {
        // Under the lock, like `set_active`: the two cannot interleave.
        let _inner = self.lock();
        self.blind
            .store(blind && self.capturing(), Ordering::Release);
    }

    /// Whether requests are masked by what was typed: capture is running and not
    /// [blind](Typed::set_blind). When it is not, the proxy checks whole requests instead.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.capturing() && !self.blind.load(Ordering::Acquire)
    }

    /// Capture is running, whether or not it can see the screen right now.
    fn capturing(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Keeps `text` for the next [`flush`](Typed::flush). Blank text is ignored, and so is any
    /// while capture is not running; while it is [blind](Typed::set_blind) text is kept as
    /// always. At most [`MAX_TEXT`] bytes are kept, [`MAX_PENDING`] texts wait (the oldest is
    /// dropped), and a text that only extends the newest one replaces it: the user was still
    /// typing.
    pub fn push(&self, mut text: String) {
        if text.trim().is_empty() {
            return;
        }
        text.truncate(text.floor_char_boundary(MAX_TEXT));
        let mut inner = self.lock();
        if !self.capturing() {
            return;
        }
        if let Some(newest) = inner.pending.last_mut()
            && text.starts_with(newest.as_str())
        {
            *newest = text;
            return;
        }
        if inner.pending.len() == MAX_PENDING {
            inner.pending.remove(0);
        }
        inner.pending.push(text);
    }

    /// Runs detection over the pending text and keeps the values it finds, each with the proxy the
    /// vault issued for it. Values not typed again or sent for [`TTL`], and those of a kind the
    /// engine no longer masks, are forgotten first.
    ///
    /// One flush runs at a time, and one that finds nothing pending waits for the one under way:
    /// when it returns, everything pushed before it was called has been read.
    ///
    /// # Errors
    /// Vault failures. The text goes back among the pending ones, so the next flush reads it again.
    pub fn flush(&self, engine: &Engine) -> Result<()> {
        self.flush_at(engine, Instant::now())
    }

    /// Whether any value is kept.
    #[must_use]
    pub fn has_values(&self) -> bool {
        !self.lock().values.is_empty()
    }

    /// Finds the kept values in a text; `None` when there are none, or when the search could not
    /// be built (the caller then checks the whole request, as without capture).
    #[must_use]
    pub fn matcher(&self) -> Option<Arc<Matcher>> {
        let mut inner = self.lock();
        if inner.matcher.is_none() && !inner.values.is_empty() {
            inner.matcher = Matcher::build(&inner.values).map(Arc::new);
        }
        inner.matcher.clone()
    }

    /// `text` with each value that stands alone in it replaced by its proxy, and the kind and proxy
    /// of every replacement. A value that is part of a longer word is not one that was typed.
    #[must_use]
    pub fn replace(&self, matcher: &Matcher, text: &str) -> (String, Vec<(EntityKind, Box<str>)>) {
        self.replace_at(matcher, text, Instant::now())
    }

    fn replace_at(
        &self,
        matcher: &Matcher,
        text: &str,
        now: Instant,
    ) -> (String, Vec<(EntityKind, Box<str>)>) {
        let hits = matcher.hits(text);
        let mut out = String::with_capacity(text.len());
        let mut replaced = Vec::with_capacity(hits.len());
        let mut done = 0;
        for hit in &hits {
            out.push_str(&text[done..hit.start]);
            out.push_str(&hit.target.with);
            done = hit.end;
            replaced.push((hit.target.kind, hit.target.proxy.clone()));
        }
        out.push_str(&text[done..]);
        if !hits.is_empty() {
            // A value that is still being sent is not forgotten.
            let mut inner = self.lock();
            for hit in &hits {
                if let Some(value) = inner.values.get_mut(&*hit.target.text) {
                    value.last_seen = now;
                }
            }
        }
        (out, replaced)
    }

    fn flush_at(&self, engine: &Engine, now: Instant) -> Result<()> {
        let _only_one = self.flushing.lock().unwrap_or_else(PoisonError::into_inner);
        let texts = {
            let mut inner = self.lock();
            inner.forget(now, engine.enabled());
            mem::take(&mut inner.pending)
        };
        if texts.is_empty() {
            return Ok(());
        }
        // Detection runs outside the lock: requests keep reading the values meanwhile.
        match detect(engine, &texts) {
            Ok(found) => {
                self.keep(found, now);
                Ok(())
            }
            Err(error) => {
                self.requeue(texts);
                Err(error)
            }
        }
    }

    /// Keeps `found` as typed at `now`.
    fn keep(&self, found: Vec<Detected>, now: Instant) {
        let mut inner = self.lock();
        if !self.capturing() {
            return;
        }
        let mut changed = false;
        for Detected { text, kind, proxy } in found {
            if text.is_empty() {
                continue;
            }
            if let Some(value) = inner.values.get_mut(&*text)
                && value.kind == kind
                && value.proxy == proxy
            {
                value.last_seen = now;
                continue;
            }
            inner.values.insert(
                text,
                Value {
                    kind,
                    proxy,
                    last_seen: now,
                },
            );
            changed = true;
        }
        changed |= inner.trim();
        if changed {
            inner.matcher = None;
        }
    }

    /// Puts texts a failed flush took back in front of the pending ones.
    fn requeue(&self, mut texts: Vec<String>) {
        let mut inner = self.lock();
        if !self.capturing() {
            return;
        }
        texts.append(&mut inner.pending);
        let excess = texts.len().saturating_sub(MAX_PENDING);
        inner.pending = texts.split_off(excess);
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves nothing half-updated that matters: the worst case
        // is a value that is missing and typed again.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What detection finds in `texts`: each value it replaces, with its kind and proxy. A stand-in
/// in what the user typed was copied from the page (a reply, the history), so it is no value of
/// its own.
fn detect(engine: &Engine, texts: &[String]) -> Result<Vec<Detected>> {
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let plans = engine.anonymize(&refs, Resent::All)?;
    let mut found = Vec::new();
    if plans.iter().any(|reps| !reps.is_empty()) {
        // One read of the vault, dropped before anything is kept.
        let view = engine.vault().read()?;
        for (text, reps) in refs.iter().zip(plans) {
            for rep in reps {
                if let Some(kind) = view.kind_of(&rep.with) {
                    found.push(Detected {
                        text: Arc::from(&text[rep.start..rep.end]),
                        kind,
                        proxy: rep.with,
                    });
                }
            }
        }
    }
    Ok(found)
}

/// Finds the values the user typed in a text, in every spelling a request may have them in.
/// Built by [`Typed::matcher`].
pub struct Matcher {
    ac: AhoCorasick,
    /// By pattern.
    targets: Vec<Target>,
}

/// What one pattern of a [`Matcher`] stands for.
struct Target {
    /// The value the pattern spells.
    text: Arc<str>,
    kind: EntityKind,
    /// The value's proxy, as the vault knows it.
    proxy: Box<str>,
    /// The proxy spelled the way the pattern is: what goes into the text.
    with: Box<str>,
}

/// One value found in a text, on its way to be replaced.
struct Hit<'m> {
    start: usize,
    end: usize,
    target: &'m Target,
}

// Hand-written: the values are the user's text.
impl fmt::Debug for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Matcher")
            .field("patterns", &self.targets.len())
            .finish_non_exhaustive()
    }
}

impl Matcher {
    /// `None` when the search cannot be built.
    fn build(values: &HashMap<Arc<str>, Value>) -> Option<Self> {
        let mut patterns: Vec<String> = Vec::new();
        let mut targets: Vec<Target> = Vec::new();
        for (text, value) in values {
            for (pattern, with) in spellings(text, &value.proxy) {
                patterns.push(pattern);
                targets.push(Target {
                    text: Arc::clone(text),
                    kind: value.kind,
                    proxy: value.proxy.clone(),
                    with: with.into_boxed_str(),
                });
            }
        }
        let ac = AhoCorasick::new(&patterns).ok()?;
        Some(Self { ac, targets })
    }

    /// The values to replace in `text`, in order, none overlapping. Of the occurrences that stand
    /// alone the leftmost wins, and the longest of those that start together. The automaton reports
    /// every occurrence, not only the leftmost-longest one, so a value that is the start of another
    /// (`Jan` and `Jan Jansen`) is still found when the longer one does not stand alone
    /// (`Jan Jansens`).
    fn hits(&self, text: &str) -> Vec<Hit<'_>> {
        let mut hits: Vec<Hit<'_>> = self
            .ac
            .find_overlapping_iter(text)
            .filter(|found| stands_alone(text, found.start(), found.end()))
            .filter_map(|found| {
                Some(Hit {
                    start: found.start(),
                    end: found.end(),
                    target: self.targets.get(found.pattern().as_usize())?,
                })
            })
            .collect();
        hits.sort_by_key(|hit| (hit.start, Reverse(hit.end)));
        let mut taken = 0;
        hits.retain(|hit| {
            let free = hit.start >= taken;
            if free {
                taken = hit.end;
            }
            free
        });
        hits
    }
}

/// The ways `text` may be written in a request, each with `proxy` written the same way: as it is,
/// as the inside of a JSON string, and as that with every non-ASCII character as `\uXXXX`.
fn spellings(text: &str, proxy: &str) -> Vec<(String, String)> {
    let mut spellings = vec![(text.to_owned(), proxy.to_owned())];
    let (Some(json), Some(json_proxy)) = (json_escaped(text), json_escaped(proxy)) else {
        return spellings;
    };
    if json != text {
        spellings.push((json.clone(), json_proxy.clone()));
    }
    let ascii = ascii_only(&json);
    if ascii != json {
        spellings.push((ascii, ascii_only(&json_proxy)));
    }
    spellings
}

/// `text` as the inside of a JSON string: what `serde_json` writes between the quotes.
fn json_escaped(text: &str) -> Option<String> {
    let quoted = serde_json::to_string(text).ok()?;
    Some(quoted.strip_prefix('"')?.strip_suffix('"')?.to_owned())
}

/// `escaped` with every non-ASCII character as `\uXXXX` in lowercase hex, one escape per UTF-16
/// code unit, the way an encoder that writes ASCII only does (`JSON.stringify` with an escaper,
/// Python's `ensure_ascii`).
fn ascii_only(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    for ch in escaped.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut units = [0; 2];
            for unit in ch.encode_utf16(&mut units).iter() {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// True when `text[start..end]` is not part of a longer word. The rule is the engine's for the
/// proxies it issued (`IssuedProxies`): the bytes just before and after it, if there are any, are
/// not ASCII letters or digits, so a value written straight against Chinese or accented text still
/// counts, which masks more than needed but never less. One more break than there: in a JSON text
/// `\nJan` is a line break and `Jan`, not the word `nJan`, so a JSON escape before the value does
/// not make it part of a word.
fn stands_alone(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    if bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
        return false;
    }
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    !before.is_some_and(u8::is_ascii_alphanumeric) || ends_with_json_escape(&bytes[..start])
}

/// True when `head` ends with a JSON escape that closes in a letter or digit: `\n`, `\r`, `\t`,
/// `\b`, `\f` or `\uXXXX`.
fn ends_with_json_escape(head: &[u8]) -> bool {
    // The backslash starts the escape unless it is the second half of `\\`: an odd run of them.
    let opens = |before: &[u8]| {
        before
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'\\')
            .count()
            % 2
            == 1
    };
    match head {
        [before @ .., b'u', a, b, c, d]
            if [a, b, c, d].into_iter().all(u8::is_ascii_hexdigit) && opens(before) =>
        {
            true
        }
        [before @ .., b'n' | b'r' | b't' | b'b' | b'f'] => opens(before),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{atomic::AtomicUsize, mpsc},
        thread,
    };

    use piikey::{
        detect::{Detector, Mode, Span},
        vault::Vault,
    };

    use super::*;
    use crate::proxy::test_names;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn vault_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piikey-typed-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir.join("vault.pkv")
    }

    /// An engine that finds what the regexes find, and `names`.
    fn engine(tag: &str, names: &'static [&'static str]) -> Result<Engine> {
        test_names::engine(&vault_path(tag), names)
    }

    fn found(text: &str, proxy: &str) -> Detected {
        Detected {
            text: Arc::from(text),
            kind: EntityKind::Person,
            proxy: Box::from(proxy),
        }
    }

    /// An active store that holds these (value, proxy) pairs, typed now.
    fn holding(values: &[(&str, &str)]) -> Typed {
        let typed = Typed::new();
        typed.set_active(true);
        typed.keep(
            values
                .iter()
                .map(|&(text, proxy)| found(text, proxy))
                .collect(),
            Instant::now(),
        );
        typed
    }

    /// `text` with what `typed` holds replaced.
    fn replaced(typed: &Typed, text: &str) -> String {
        typed.matcher().map_or_else(
            || text.to_owned(),
            |matcher| typed.replace(&matcher, text).0,
        )
    }

    fn hours(n: u64) -> Duration {
        Duration::from_hours(n)
    }

    #[test]
    fn only_what_was_typed_is_replaced() -> TestResult {
        let engine = engine("only", &["Jeroen de Vries"])?;
        let typed = Typed::new();
        typed.set_active(true);
        let said = "Ik ben Jeroen de Vries, mail jan.jansen@acme.nl";
        typed.push(said.to_owned());
        typed.flush(&engine)?;
        let matcher = typed.matcher().ok_or("nothing was kept")?;

        let body = [
            r#"{"messages":[{"content":""#,
            said,
            r#""}],"id":"Jeroen-build-7f3a","code":"const jan = 1"}"#,
        ]
        .concat();
        let (out, hits) = typed.replace(&matcher, &body);
        assert!(
            !out.contains("Jeroen de Vries") && !out.contains("jan.jansen@acme.nl"),
            "{out}"
        );
        assert!(
            out.ends_with(r#""}],"id":"Jeroen-build-7f3a","code":"const jan = 1"}"#),
            "what was not typed is byte for byte the same: {out}"
        );
        let mut kinds: Vec<EntityKind> = hits.iter().map(|&(kind, _)| kind).collect();
        kinds.sort();
        assert_eq!(kinds, [EntityKind::Email, EntityKind::Person]);
        assert_eq!(engine.run(Mode::Deanonymize, &[out.as_str()])?, [body]);
        Ok(())
    }

    #[test]
    fn a_non_ascii_value_is_found_in_the_spellings_of_a_json_encoder() -> TestResult {
        let engine = engine("ascii", &["Zoë Müller"])?;
        let typed = Typed::new();
        typed.set_active(true);
        typed.push("Hallo, ik ben Zoë Müller".to_owned());
        typed.flush(&engine)?;
        let matcher = typed.matcher().ok_or("nothing was kept")?;

        let escaped = r#"{"m":"Hallo, ik ben Zo\u00eb M\u00fcller"}"#;
        let (out, hits) = typed.replace(&matcher, escaped);
        let proxy = hits
            .first()
            .map(|(_, proxy)| proxy.clone())
            .ok_or("no hit")?;
        let spelled = ascii_only(&json_escaped(&proxy).ok_or("not JSON")?);
        assert_eq!(out, format!(r#"{{"m":"Hallo, ik ben {spelled}"}}"#));

        let plain = r#"{"m":"Hallo, ik ben Zoë Müller"}"#;
        assert_eq!(
            typed.replace(&matcher, plain).0,
            format!(r#"{{"m":"Hallo, ik ben {proxy}"}}"#)
        );
        Ok(())
    }

    #[test]
    fn spellings_are_what_json_encoders_write() {
        let one = |text: &str, proxy: &str| vec![(text.to_owned(), proxy.to_owned())];
        assert_eq!(
            spellings("jan.jansen@acme.nl", "x@y.example"),
            one("jan.jansen@acme.nl", "x@y.example")
        );
        // Quotes, backslashes and control characters are escaped; the rest is as typed.
        assert_eq!(
            spellings("a \"b\" \\ \n", "p\tq"),
            [
                ("a \"b\" \\ \n".to_owned(), "p\tq".to_owned()),
                (r#"a \"b\" \\ \n"#.to_owned(), r"p\tq".to_owned()),
            ]
        );
        // Every UTF-16 code unit of a non-ASCII character, in lowercase hex.
        assert_eq!(
            spellings("😀 Zoë", "Éva \"x\""),
            [
                ("😀 Zoë".to_owned(), "Éva \"x\"".to_owned()),
                (
                    r"\ud83d\ude00 Zo\u00eb".to_owned(),
                    r#"\u00c9va \"x\""#.to_owned()
                ),
            ]
        );
    }

    #[test]
    fn switching_off_forgets_everything() -> TestResult {
        let engine = engine("off", &["Jeroen de Vries"])?;
        let typed = Typed::new();
        assert!(!typed.is_active());
        typed.set_active(true);
        typed.push("Ik ben Jeroen de Vries".to_owned());
        typed.flush(&engine)?;
        typed.push("jan.jansen@acme.nl".to_owned());
        assert!(typed.matcher().is_some());

        typed.set_active(false);
        assert!(!typed.is_active());
        assert!(typed.matcher().is_none() && !typed.has_values());
        assert!(typed.lock().pending.is_empty());

        // And nothing is kept while it is off.
        typed.push("Ik ben Jeroen de Vries".to_owned());
        typed.flush(&engine)?;
        assert!(typed.matcher().is_none() && typed.lock().pending.is_empty());
        Ok(())
    }

    #[test]
    fn going_blind_keeps_what_was_kept_but_checks_requests_whole() -> TestResult {
        let engine = engine("blind", &["Jeroen de Vries"])?;
        let typed = Typed::new();
        typed.set_active(true);
        typed.push("Ik ben Jeroen de Vries".to_owned());
        typed.flush(&engine)?;
        assert!(typed.is_active() && typed.has_values());

        // A read is overdue: requests are checked whole, what was kept stays.
        typed.set_blind(true);
        assert!(!typed.is_active());
        assert!(typed.has_values());

        // Capture goes on meanwhile: text is kept, read, found and replaced as always.
        typed.push("mail jan.jansen@acme.nl".to_owned());
        assert_eq!(typed.lock().pending, ["mail jan.jansen@acme.nl"]);
        typed.flush(&engine)?;
        let out = replaced(&typed, "Jeroen de Vries, jan.jansen@acme.nl");
        assert!(!out.contains("Jeroen") && !out.contains("jansen"), "{out}");

        // It sees again: what was kept is used again.
        typed.set_blind(false);
        assert!(typed.is_active());
        let out = replaced(&typed, "Jeroen de Vries");
        assert!(!out.contains("Jeroen"), "{out}");

        // A stop drops the values, and the blindness with them.
        typed.set_blind(true);
        typed.set_active(false);
        assert!(!typed.is_active() && !typed.has_values());
        typed.set_active(true);
        assert!(typed.is_active(), "a new start sees the screen");
        Ok(())
    }

    #[test]
    fn a_store_that_is_not_running_cannot_go_blind() {
        let typed = Typed::new();
        typed.set_blind(true);
        typed.set_active(true);
        assert!(
            typed.is_active(),
            "a call before the start does not carry over"
        );
        typed.set_active(false);
        typed.set_blind(true);
        typed.set_active(true);
        assert!(typed.is_active(), "nor does one after a stop");
    }

    #[test]
    fn more_typing_replaces_the_newest_pending_text() {
        let typed = Typed::new();
        typed.set_active(true);
        for text in ["Ik", "Ik ben", "Ik ben Jeroen"] {
            typed.push(text.to_owned());
        }
        assert_eq!(typed.lock().pending, ["Ik ben Jeroen"]);
        // A text that is not an extension is a text of its own.
        typed.push("Zo".to_owned());
        assert_eq!(typed.lock().pending, ["Ik ben Jeroen", "Zo"]);
    }

    #[test]
    fn pending_text_is_bounded() {
        let typed = Typed::new();
        typed.push("while it is off".to_owned());
        assert!(typed.lock().pending.is_empty(), "nothing is kept while off");

        typed.set_active(true);
        for blank in ["", "   ", "\r\n\t "] {
            typed.push(blank.to_owned());
        }
        assert!(typed.lock().pending.is_empty(), "blank text is ignored");

        for n in 0..MAX_PENDING + 4 {
            typed.push(format!("{n} is a number"));
        }
        let pending = typed.lock().pending.clone();
        assert_eq!(pending.len(), MAX_PENDING, "the oldest are dropped");
        assert_eq!(pending[0], "4 is a number");
        assert_eq!(pending[MAX_PENDING - 1], "11 is a number");

        // Cut at a character boundary: 256 KiB is not a multiple of the 3 bytes of `€`.
        typed.push("€".repeat(MAX_TEXT));
        let kept = typed.lock().pending.last().cloned().unwrap_or_default();
        assert_eq!(kept.len(), MAX_TEXT / 3 * 3);
        assert!(kept.chars().all(|c| c == '€'));
    }

    #[test]
    fn a_failed_flush_gives_its_text_back() {
        let typed = Typed::new();
        typed.set_active(true);
        typed.push("newer".to_owned());
        typed.requeue(vec!["older".to_owned(), "oldest?".to_owned()]);
        assert_eq!(typed.lock().pending, ["older", "oldest?", "newer"]);

        let many: Vec<String> = (0..MAX_PENDING + 3).map(|n| format!("{n} early")).collect();
        typed.requeue(many);
        let pending = typed.lock().pending.clone();
        assert_eq!(pending.len(), MAX_PENDING);
        assert_eq!(pending.last().map(String::as_str), Some("newer"));
    }

    #[test]
    fn a_value_has_to_stand_alone() {
        let typed = holding(&[("Jeroen de Vries", "Pia Lund")]);
        for (text, expected) in [
            ("Jeroen de Vries", "Pia Lund"),
            ("(Jeroen de Vries)", "(Pia Lund)"),
            ("Jeroen de Vries's", "Pia Lund's"),
            ("Jeroen de Vries. Jeroen de Vries", "Pia Lund. Pia Lund"),
            ("Jeroen de Vriesx", "Jeroen de Vriesx"),
            ("xJeroen de Vries", "xJeroen de Vries"),
            ("7Jeroen de Vries", "7Jeroen de Vries"),
            ("Jeroen-build-7f3a", "Jeroen-build-7f3a"),
            ("jeroen de vries", "jeroen de vries"),
            // Anything that is not an ASCII letter or digit is a break, as for issued proxies.
            ("我是Jeroen de Vries先生", "我是Pia Lund先生"),
        ] {
            assert_eq!(replaced(&typed, text), expected, "{text}");
        }
    }

    #[test]
    fn a_json_escape_before_a_value_is_a_break() {
        let typed = holding(&[("Jeroen de Vries", "Pia Lund")]);
        for (text, expected) in [
            (r"Naam:\nJeroen de Vries", r"Naam:\nPia Lund"),
            (r"a\tJeroen de Vries\r\n", r"a\tPia Lund\r\n"),
            (
                r"\bJeroen de Vries\fJeroen de Vries",
                r"\bPia Lund\fPia Lund",
            ),
            (r"caf\u00e9Jeroen de Vries", r"caf\u00e9Pia Lund"),
            (r"\u00ebJeroen de Vries", r"\u00ebPia Lund"),
            (r"\\\nJeroen de Vries", r"\\\nPia Lund"),
            // `\\` is a backslash: what follows it is the letter `n` of a word.
            (r"\\nJeroen de Vries", r"\\nJeroen de Vries"),
            (r"\u00zzJeroen de Vries", r"\u00zzJeroen de Vries"),
            ("nJeroen de Vries", "nJeroen de Vries"),
        ] {
            assert_eq!(replaced(&typed, text), expected, "{text}");
        }
    }

    #[test]
    fn a_shorter_value_is_found_when_the_longer_one_does_not_stand_alone() {
        let typed = holding(&[("Jan", "Pim"), ("Jan Jansen", "Kees Bos")]);
        assert_eq!(replaced(&typed, "Jan Jansen"), "Kees Bos");
        assert_eq!(replaced(&typed, "Jan Jansens"), "Pim Jansens");
        assert_eq!(replaced(&typed, "Jan, Jan Jansen"), "Pim, Kees Bos");

        // Values that overlap: the leftmost wins and the other is left as it was.
        let typed = holding(&[("ab cd", "P"), ("cd ef", "Q")]);
        assert_eq!(replaced(&typed, "ab cd ef"), "P ef");
    }

    #[test]
    fn the_matcher_is_kept_until_the_values_change() {
        let typed = holding(&[("Jan", "Pim")]);
        let first = typed.matcher();
        assert!(first.is_some());
        let again = typed.matcher();
        assert!(matches!((&first, &again), (Some(a), Some(b)) if Arc::ptr_eq(a, b)));

        // The same value, typed again: nothing changed.
        typed.keep(vec![found("Jan", "Pim")], Instant::now());
        let same = typed.matcher();
        assert!(matches!((&first, &same), (Some(a), Some(b)) if Arc::ptr_eq(a, b)));

        typed.keep(vec![found("Piet", "Joe")], Instant::now());
        let more = typed.matcher();
        assert!(matches!((&first, &more), (Some(a), Some(b)) if !Arc::ptr_eq(a, b)));
        assert_eq!(replaced(&typed, "Jan en Piet"), "Pim en Joe");
    }

    #[test]
    fn the_oldest_values_go_beyond_the_cap() -> TestResult {
        let typed = Typed::new();
        typed.set_active(true);
        let base = Instant::now();
        for n in 0..=u32::try_from(MAX_VALUES)? {
            let at = base + Duration::from_millis(u64::from(n));
            typed.keep(
                vec![found(&format!("value {n}"), &format!("proxy {n}"))],
                at,
            );
        }
        let inner = typed.lock();
        assert_eq!(inner.values.len(), MAX_VALUES);
        assert!(!inner.values.contains_key("value 0"));
        assert!(inner.values.contains_key("value 1"));
        assert!(
            inner
                .values
                .contains_key(format!("value {MAX_VALUES}").as_str())
        );
        Ok(())
    }

    #[test]
    fn values_are_forgotten_six_hours_after_they_were_last_seen() -> TestResult {
        let engine = engine("ttl", &[])?;
        let typed = Typed::new();
        typed.set_active(true);
        let base = Instant::now();
        typed.keep(vec![found("Jan", "Pim"), found("Piet", "Joe")], base);
        // Found in a request four hours on: that counts as seen.
        let matcher = typed.matcher().ok_or("nothing was kept")?;
        let (out, _) = typed.replace_at(&matcher, "Jan", base + hours(4));
        assert_eq!(out, "Pim");

        typed.flush_at(&engine, base + hours(7))?;
        assert_eq!(replaced(&typed, "Jan Piet"), "Pim Piet");
        typed.flush_at(&engine, base + hours(11))?;
        assert!(!typed.has_values() && typed.matcher().is_none());
        Ok(())
    }

    #[test]
    fn switching_a_kind_off_stops_masking_its_values() -> TestResult {
        let engine = engine("kinds", &["Jeroen de Vries"])?;
        let typed = Typed::new();
        typed.set_active(true);
        typed.push("Ik ben Jeroen de Vries, mail jan.jansen@acme.nl".to_owned());
        typed.flush(&engine)?;
        let body = "Jeroen de Vries, jan.jansen@acme.nl";
        let both = replaced(&typed, body);
        assert!(
            !both.contains("Jeroen") && !both.contains("jansen"),
            "{both}"
        );

        engine.set_enabled(KindSet::ALL.without(EntityKind::Person));
        typed.flush(&engine)?;
        let email_only = replaced(&typed, body);
        assert!(email_only.starts_with("Jeroen de Vries, "), "{email_only}");
        assert!(!email_only.contains("jansen"), "{email_only}");

        engine.set_enabled(KindSet::EMPTY);
        typed.flush(&engine)?;
        assert!(!typed.has_values() && typed.matcher().is_none());
        Ok(())
    }

    /// Reports `Jeroen` as a name. Its first call tells the test it is in and then waits to be let
    /// go.
    #[derive(Debug)]
    struct Slow {
        calls: AtomicUsize,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Detector for Slow {
        fn detect(&self, text: &str, _mode: Mode) -> Vec<Span> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let _ = self.entered.send(());
                let release = self.release.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = release.recv();
            }
            text.find("Jeroen")
                .map(|start| Span {
                    start,
                    end: start + "Jeroen".len(),
                    kind: EntityKind::Person,
                })
                .into_iter()
                .collect()
        }
    }

    #[test]
    fn a_flush_waits_for_the_detection_under_way() -> TestResult {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let slow = Slow {
            calls: AtomicUsize::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        };
        let engine = Engine::new(Box::new(slow), Vault::open(&vault_path("gate"))?);
        let typed = Typed::new();
        typed.set_active(true);
        typed.push("Ik ben Jeroen".to_owned());

        let second_returned = AtomicBool::new(false);
        let (first, second, returned_early) = thread::scope(|scope| -> TestResult<_> {
            let first = scope.spawn(|| typed.flush(&engine));
            // The first flush has taken the text and is inside detection.
            entered_rx.recv()?;
            let second = scope.spawn(|| {
                let done = typed.flush(&engine);
                second_returned.store(true, Ordering::SeqCst);
                done
            });
            thread::sleep(Duration::from_millis(200));
            let returned_early = second_returned.load(Ordering::SeqCst);
            // Let go before anything is asserted, so a failure cannot hang the test.
            release_tx.send(())?;
            release_tx.send(())?;
            let first = first.join().map_err(|_| "the first flush panicked")?;
            let second = second.join().map_err(|_| "the second flush panicked")?;
            Ok((first, second, returned_early))
        })?;
        first?;
        second?;
        assert!(
            !returned_early,
            "the second flush returned while the first was still reading the text"
        );
        assert!(typed.has_values());
        Ok(())
    }

    #[test]
    fn debug_output_has_no_text() {
        let typed = holding(&[("Jeroen de Vries", "Pia Lund")]);
        typed.push("Ik ben Jeroen de Vries".to_owned());
        let matcher = typed.matcher();
        let shown = format!("{typed:?} {matcher:?}");
        assert!(
            !shown.contains("Jeroen") && !shown.contains("Pia"),
            "{shown}"
        );
    }
}
