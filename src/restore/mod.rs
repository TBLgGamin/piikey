//! Streaming, tolerant restore of proxies in service responses.
//!
//! A service sees proxies, never the user's real values, and its reply may mention them
//! imperfectly: with a typo, or as just a first or last name. A [`Restorer`] turns those
//! mentions back into the originals, but only for the proxies in its [`Scope`] (the ones
//! this app actually sent), so an unrelated genuine value is left alone.
//!
//! Three tiers run over the text; the first that hits wins and matches never overlap:
//!
//! 1. **Exact.** Any scoped proxy, ignoring ASCII case, between word boundaries. The
//!    boundary is ASCII only: an alphanumeric byte next to the match, or `.`, `-`, `_`, `+`,
//!    `@` or `'` followed by one, glues the match to a longer word and rejects it
//!    (`Haley.Brooks`, `xlotte@a.nl`). A trailing possessive `'s` / `’s` stays after the
//!    replacement. Proxies that differ only in case (`Haley Brooks`, `HALEY BROOKS`) stand
//!    for their own originals where the text spells them as the scope does; any other
//!    casing restores when they all stand for the same original, and is ambiguous otherwise,
//!    like a typo or a name part of them: nothing is replaced.
//! 2. **Typo.** A token (`[A-Za-z0-9@._+'-]+`), or up to six tokens separated by single
//!    spaces, of at least 6 bytes that is within one edit (two from 12 bytes up) of a
//!    scoped *text* proxy (email, person, URL credential): Optimal String Alignment
//!    distance, same first letter, length within 2. Two proxies at the best distance
//!    make the match ambiguous and nothing is replaced. Number-like kinds (phones, IBANs,
//!    cards, ...) are never fuzzy-matched: one wrong digit is a different number.
//! 3. **Component.** A bare token equal to one part of a scoped person or email proxy: the
//!    first or last name, either end of a one-word name (`Haley` of `Haley-Marian`), or the
//!    local part of an email. It becomes the same part of the original, but only when that
//!    part belongs to exactly one proxy, has three or more letters, is no stop word, and is
//!    capitalized when the proxy's part is (`Long` the surname, not `long` the word). Name
//!    parts are not proxies of their own, so `Haley Brooks` in the scope makes a bare `Haley`
//!    ambiguous. A first name that another capitalized word follows (`Haley Brooks`,
//!    `Haley van der Berg`) is a different person and stays, unless that word is a part of
//!    the same proxy (`Haley Zessen`).
//!
//! Whitespace must match: a name wrapped over two lines or split by a double space is only
//! restored part by part, and a hyphen that wraps a word across lines is not undone
//! (`Zes-\nsen` stays as it is).
//!
//! The scope is what one conversation sent; the vault knows every proxy it ever issued. The
//! `_with` methods ([`Restorer::restore_with`], [`Restorer::plan_with`], [`Restorer::feed_with`]
//! and [`Restorer::flush_with`]) restore those too: a [`ProxyFinder`] (the engine is one) looks
//! for them in the very text the three tiers read, and what it finds comes with the exact tier,
//! so that every part of the text is restored once. Two passes one after the other would restore
//! a value twice when it equals a proxy issued for another value: the first pass writes it, the
//! second reads it as that proxy.
//!
//! [`Restorer::feed_with`] restores a stream chunk by chunk and emits the same bytes as one
//! [`Restorer::restore_with`] over the whole text, however the text is chunked (unless one token
//! runs past 1 MiB, which is cut anyway, or a proxy of the finder is longer than its `longest`
//! and a cut falls inside it).

use std::cell::OnceCell;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::collections::hash_map::Entry as MapEntry;
use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Input, MatchKind};
use rayon::prelude::*;

use crate::detect::EntityKind;
use crate::engine::Replacement;
use crate::proxy::is_particle;
use crate::{Error, Result};

mod finder;
mod stopwords;

pub use finder::ProxyFinder;
pub(crate) use stopwords::STOPWORDS;

/// Held back on top of the longest proxy a [`ProxyFinder`] can find, so that the text after a
/// proxy is visible before the proxy is judged complete.
const FINDER_SLACK: usize = 16;

/// Most tokens that make up one typo candidate.
const MAX_SEQUENCE: usize = 6;

/// Shortest token or sequence that is typo-matched; shorter ones are too ambiguous.
const MIN_TYPO_LEN: usize = 6;

/// From this many bytes on, a typo candidate may be two edits away instead of one.
const TWO_EDITS_LEN: usize = 12;

/// Fewest letters a bare name part needs to stand for the whole name.
const MIN_COMPONENT_LETTERS: usize = 3;

/// Particles a bare first name may be followed by before the word that decides whether it
/// is part of a longer name.
const MAX_PARTICLES: usize = 3;

/// How many bytes after a bare first name are looked at for such a word. Part of what a stream
/// holds back, so a chunked text decides the same as a whole one.
const NAME_REACH: usize = 48;

/// A stream that holds more than this and has no place to cut (one huge token) is cut inside
/// the token instead. Nothing a restorer looks for is that long, and holding the token back
/// would stall the stream and grow without bound.
const MAX_HELD: usize = 1 << 20;

/// A one-shot restore of a text longer than this is split across rayon tasks. Shorter texts
/// are not worth it: callers already parallelize across texts.
const PARALLEL_FROM: usize = 2 << 20;

/// Bytes each rayon task owns when a longer text is split.
const CHUNK: usize = 1 << 20;

/// How far past an even split point to look for a place that can be cut.
const SPLIT_SEARCH: usize = 1 << 16;

/// One proxy this app sent, with its original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEntry {
    pub kind: EntityKind,
    pub proxy: Box<str>,
    pub original: Box<str>,
}

/// The proxies tolerant matching may restore to.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    entries: Vec<ScopeEntry>,
}

impl Scope {
    #[must_use]
    pub fn from_pairs(entries: impl IntoIterator<Item = ScopeEntry>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[ScopeEntry] {
        &self.entries
    }
}

/// Restores exact, typo'd and partial mentions of scoped proxies, one-shot
/// or over a chunked stream, and with a [`ProxyFinder`] every proxy of the vault in the same
/// pass.
pub struct Restorer {
    /// `None` when the scope has nothing to restore: text then passes through untouched, or
    /// carries only what a finder finds.
    matcher: Option<Matcher>,
    /// Streamed bytes not yet emitted; always starts at a cut (or the start of the stream).
    tail: Vec<u8>,
    /// No valid cut lies in `tail[1..probed]`, so a feed only scans what is new.
    probed: usize,
    restored: usize,
}

// Hand-written: the matcher holds the user's originals, which must never reach a log.
impl fmt::Debug for Restorer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Restorer")
            .field(
                "entries",
                &self.matcher.as_ref().map_or(0, |m| m.entries.len()),
            )
            .field("held", &self.tail.len())
            .field("restored", &self.restored)
            .finish_non_exhaustive()
    }
}

impl Restorer {
    /// # Errors
    /// Never in practice (matcher build over ASCII patterns).
    pub fn new(scope: Scope) -> Result<Self> {
        Ok(Self {
            matcher: Matcher::build(scope.entries)?,
            tail: Vec::new(),
            probed: 0,
            restored: 0,
        })
    }

    /// One-shot restore of the scope's proxies and of the proxies `finder` finds, in one pass
    /// over `text`: each part of it is restored once, and what is restored is never read again.
    /// Where what the finder found and the exact tier's matches overlap, the one that starts
    /// first stays, the longer one when they start together, and the finder's when they are the
    /// same span. The typo and component tiers look at what is left between them.
    #[must_use]
    pub fn restore_with(&self, text: &[u8], finder: &dyn ProxyFinder) -> Vec<u8> {
        let found = find(finder, text);
        let found = edits_of(&found, text);
        match &self.matcher {
            Some(matcher) => matcher.restore(text, &found).0,
            None => apply(text, &found).0,
        }
    }

    /// The replacements [`Restorer::restore_with`] makes in `text`, as byte offsets into it:
    /// sorted, none overlapping another. For a caller that has to make them itself, in the text
    /// nodes of a document, say.
    #[must_use]
    pub fn plan_with(&self, text: &[u8], finder: &dyn ProxyFinder) -> Vec<Replacement> {
        let found = find(finder, text);
        let found = edits_of(&found, text);
        let edits = match &self.matcher {
            Some(matcher) => matcher.plan_all(text, &found),
            None => found,
        };
        edits
            .iter()
            .map(|edit| Replacement {
                start: edit.start,
                end: edit.end,
                with: edit.with.into(),
            })
            .collect()
    }

    /// Streaming [`Restorer::restore_with`]: returns the restored output that is safe to emit
    /// now.
    ///
    /// The end of the stream is held back while later bytes could still complete or change a
    /// mention there: always the last `2 * longest proxy + 8` bytes (at least 56, to see what
    /// follows a bare first name; with a finder, at least the longest proxy it can find and 16
    /// more), and more while a token is longer than that or a replacement runs across the place
    /// to cut (a token longer than 1 MiB is cut anyway). [`Self::flush_with`] releases the rest.
    pub fn feed_with(&mut self, chunk: &[u8], finder: &dyn ProxyFinder) -> Vec<u8> {
        let reach = finder.longest();
        let finder_margin = if reach == 0 {
            0
        } else {
            reach.saturating_add(FINDER_SLACK)
        };
        let margin = self
            .matcher
            .as_ref()
            .map_or(0, |matcher| matcher.margin)
            .max(finder_margin);
        if margin == 0 {
            // Nothing to look for: what an earlier call still holds goes out with the chunk.
            let mut out = std::mem::take(&mut self.tail);
            self.probed = 0;
            out.extend_from_slice(chunk);
            return out;
        }
        self.tail.extend_from_slice(chunk);
        // A cut at `i` needs `len - i > margin`: every mention that could straddle it is
        // then fully visible, and so is the context its boundary checks look at.
        let limit = self.tail.len().saturating_sub(margin);
        let floor = self.probed.max(1);
        if limit <= floor {
            return Vec::new();
        }
        // Both are made when the first place to cut is found, not before: a long token with no
        // place to cut is not scanned again by every chunk.
        let found = OnceCell::new();
        let planned = OnceCell::new();
        let plan = || {
            planned.get_or_init(|| {
                let found = found.get_or_init(|| find(finder, &self.tail));
                let found = edits_of(found, &self.tail);
                plan_edits(self.matcher.as_ref(), &self.tail, &found)
            })
        };
        // A finder reads the byte before a proxy, and the one before a cut is gone from the next
        // tail: with a finder, a cut at a byte a proxy can start with (anything but white space)
        // needs a byte before it that is no letter or digit.
        let lookback = finder_margin > 0;
        let mut hi = limit;
        let cut = loop {
            if hi <= floor {
                break None;
            }
            let Some(at) = (floor..hi).rev().find(|&i| {
                let byte = self.tail[i];
                is_cut_byte(byte)
                    && !(lookback
                        && !byte.is_ascii_whitespace()
                        && self.tail[i - 1].is_ascii_alphanumeric())
            }) else {
                break None;
            };
            match straddler(plan(), at) {
                None => break Some(at),
                Some(start) => hi = start + 1,
            }
        };
        let cut = match cut {
            None if self.tail.len() > MAX_HELD => forced_cut(&self.tail, plan(), limit),
            cut => cut,
        };
        let (Some(cut), Some(edits)) = (cut, planned.get()) else {
            self.probed = limit;
            return Vec::new();
        };
        let mut out = Vec::with_capacity(cut);
        let mut pos = 0;
        for edit in edits.iter().take_while(|e| e.end <= cut) {
            out.extend_from_slice(&self.tail[pos..edit.start]);
            out.extend_from_slice(edit.with.as_bytes());
            pos = edit.end;
            self.restored += 1;
        }
        out.extend_from_slice(&self.tail[pos..cut]);
        self.tail.drain(..cut);
        self.probed = limit - cut;
        out
    }

    /// Emits everything held back, restored with `finder` as [`Restorer::feed_with`] does.
    pub fn flush_with(&mut self, finder: &dyn ProxyFinder) -> Vec<u8> {
        let tail = std::mem::take(&mut self.tail);
        self.probed = 0;
        if tail.is_empty() {
            return tail;
        }
        let found = find(finder, &tail);
        let found = edits_of(&found, &tail);
        let (out, restored) = match &self.matcher {
            Some(matcher) => matcher.restore_serial(&tail, &found),
            None => apply(&tail, &found),
        };
        self.restored += restored;
        out
    }

    /// Replacements made so far by `feed_with`/`flush_with`.
    #[must_use]
    pub fn restored_count(&self) -> usize {
        self.restored
    }
}

/// A scoped proxy as the matcher sees it.
struct Entry {
    /// The proxy in ASCII lower case: the Aho-Corasick pattern and the typo reference.
    lower: Box<str>,
    original: Box<str>,
}

/// What a bare token stands for.
enum Component {
    /// The one entry a name part belongs to, and the original's matching part.
    Unique {
        entry: usize,
        replacement: Box<str>,
        /// The proxy's part starts with a capital letter, so a mention must too: that is
        /// what keeps `Long` the surname apart from `long` the word.
        capitalized: bool,
        /// The part is a first name: another capitalized name right after it (`Haley
        /// Brooks`) means a different person.
        first_name: bool,
    },
    /// Two entries (or two parts) claim it: it stands for nothing.
    Ambiguous,
}

/// Bare name parts that restore to the original's part, keyed by lower-case part.
#[derive(Default)]
struct Components {
    parts: HashMap<Box<str>, Component>,
    longest: usize,
}

impl Components {
    fn add(&mut self, entry: usize, part: &str, replacement: &str, first_name: bool) {
        let letters = part.bytes().filter(u8::is_ascii_alphabetic).count();
        let lower = part.to_ascii_lowercase();
        if replacement.is_empty()
            || letters < MIN_COMPONENT_LETTERS
            || STOPWORDS.binary_search(&lower.as_str()).is_ok()
        {
            return;
        }
        let capitalized = part.bytes().next().is_some_and(|b| b.is_ascii_uppercase());
        self.longest = self.longest.max(lower.len());
        match self.parts.entry(lower.into_boxed_str()) {
            MapEntry::Vacant(slot) => {
                slot.insert(Component::Unique {
                    entry,
                    replacement: replacement.into(),
                    capitalized,
                    first_name,
                });
            }
            MapEntry::Occupied(mut slot) => match slot.get_mut() {
                // The same part again (a one-word proxy part, say): keep what either knows.
                Component::Unique {
                    entry: e,
                    replacement: r,
                    first_name: f,
                    ..
                } if *e == entry && **r == *replacement => *f |= first_name,
                _ => {
                    slot.insert(Component::Ambiguous);
                }
            },
        }
    }

    /// Registers the first- and last-name parts of a person proxy against the original's.
    fn add_person(&mut self, entry: usize, proxy: &str, original: &str) {
        let proxy: Vec<&str> = proxy.split_whitespace().collect();
        let original: Vec<&str> = original.split_whitespace().collect();
        let (Some(&proxy_last), Some(&first), Some(&last)) =
            (proxy.last(), original.first(), original.last())
        else {
            return;
        };
        if let [word] = proxy.as_slice() {
            // A one-word name is one hyphenated token (`Haley-Marian`); its two ends each
            // stand for the word (or for the matching end of a hyphenated word).
            let mut parts = word.split('-').filter(|p| !p.is_empty());
            if let (Some(head), Some(tail)) = (parts.next(), parts.next_back()) {
                let first = first.split('-').find(|p| !p.is_empty()).unwrap_or(first);
                let last = last.rsplit('-').find(|p| !p.is_empty()).unwrap_or(last);
                self.add(entry, head, first, true);
                self.add(entry, tail, last, false);
            }
        } else {
            let proxy_first = proxy.iter().find(|t| !is_particle(t));
            let original_first = original.iter().find(|t| !is_particle(t));
            if let (Some(proxy_first), Some(original_first)) = (proxy_first, original_first) {
                self.add(entry, proxy_first, original_first, true);
            }
            self.add(entry, proxy_last, last, false);
        }
    }

    /// Registers the local part of an email proxy against the original's.
    fn add_email(&mut self, entry: usize, proxy: &str, original: &str) {
        if let (Some((proxy_local, _)), Some((original_local, _))) =
            (proxy.rsplit_once('@'), original.rsplit_once('@'))
        {
            self.add(entry, proxy_local, original_local, false);
        }
    }
}

/// Letters and digits get a slot; no other byte can start a typo candidate.
const SLOTS: usize = 36;

fn slot(b: u8) -> Option<usize> {
    match b.to_ascii_lowercase() {
        c @ b'a'..=b'z' => Some(usize::from(c - b'a')),
        c @ b'0'..=b'9' => Some(26 + usize::from(c - b'0')),
        _ => None,
    }
}

/// The text-kind proxies a typo'd mention may be matched to, by first byte and length.
///
/// The typo tier only compares a candidate with proxies that start with the same byte and are
/// at most two bytes longer or shorter, so those are the only ones it needs to find.
struct TypoIndex {
    /// `buckets[slot * stride + len]`: the proxies of that length that start with that
    /// (lower-case) byte, each as its letter [`presence`] and entry index.
    buckets: Vec<Vec<(u64, usize)>>,
    stride: usize,
    /// Shortest and longest proxy indexed.
    shortest: usize,
    longest: usize,
    /// Which slots have a proxy at all.
    starts: [bool; SLOTS],
}

impl TypoIndex {
    /// `proxies` are `(entry index, lower-case proxy)`.
    fn build<'a>(proxies: impl Iterator<Item = (usize, &'a str)> + Clone) -> Self {
        let shortest = proxies.clone().map(|(_, p)| p.len()).min().unwrap_or(0);
        let longest = proxies.clone().map(|(_, p)| p.len()).max().unwrap_or(0);
        let stride = longest + 1;
        let mut buckets = vec![Vec::new(); SLOTS * stride];
        let mut starts = [false; SLOTS];
        for (id, proxy) in proxies {
            // A proxy that does not start with a letter or digit can never share its
            // first byte with a token's core.
            if let Some(slot) = proxy.bytes().next().and_then(slot) {
                buckets[slot * stride + proxy.len()].push((presence(proxy.as_bytes()), id));
                starts[slot] = true;
            }
        }
        Self {
            buckets,
            stride,
            shortest,
            longest,
            starts,
        }
    }

    fn is_empty(&self) -> bool {
        !self.starts.contains(&true)
    }

    /// Whether some proxy starts with the byte `first`.
    fn has_start(&self, first: u8) -> bool {
        slot(first).is_some_and(|s| self.starts[s])
    }
}

/// A proxy as the scope spells it, with its original.
struct Spelled {
    proxy: Box<str>,
    original: Box<str>,
}

/// The compiled scope.
struct Matcher {
    /// Exact tier: every proxy, ASCII case-insensitive, leftmost-longest. A proxy that differs
    /// from an earlier one only in case is not in it.
    ac: AhoCorasick,
    /// The first `ac.patterns_len()` are indexed by Aho-Corasick pattern id; the proxies that
    /// differ from one of those only in case follow, for the typo and component tiers.
    entries: Vec<Entry>,
    /// For an entry that has such variants: it and they, each as the scope spells the proxy and
    /// with its original. Rare, so a side table.
    spellings: HashMap<usize, Vec<Spelled>>,
    typo: TypoIndex,
    components: Components,
    /// Length of the longest proxy: no mention is longer, a typo'd one at most 2 more.
    longest: usize,
    /// Bytes a stream holds back: twice the longest proxy, plus slack for the boundary
    /// checks, and enough to see what a bare first name is followed by.
    margin: usize,
}

/// One replacement of `start..end` by `with`.
#[derive(Clone, Copy)]
struct Edit<'a> {
    start: usize,
    end: usize,
    with: &'a str,
}

/// What [`Matcher::build`] gathers from the scope before the automaton is compiled.
struct Collected {
    entries: Vec<Entry>,
    /// `entries[i]`'s proxy as the scope spells it.
    spelled: Vec<Box<str>>,
    /// Whether `entries[i]` is a kind the typo tier looks at, and one it can compare: it counts
    /// bytes, so a proxy with a non-ASCII byte (`\u{2019}t`) is matched exactly only.
    text_kind: Vec<bool>,
    components: Components,
    longest: usize,
}

impl Collected {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            spelled: Vec::with_capacity(capacity),
            text_kind: Vec::with_capacity(capacity),
            components: Components::default(),
            longest: 0,
        }
    }

    /// Adds `scoped` as the entry after the last; `lower` is its proxy in ASCII lower case.
    fn add(&mut self, scoped: ScopeEntry, lower: Box<str>) {
        let ScopeEntry {
            kind,
            proxy,
            original,
        } = scoped;
        let id = self.entries.len();
        self.longest = self.longest.max(lower.len());
        self.text_kind.push(
            lower.is_ascii()
                && matches!(
                    kind,
                    EntityKind::Email | EntityKind::Person | EntityKind::UrlCredential
                ),
        );
        match kind {
            EntityKind::Person => self.components.add_person(id, &proxy, &original),
            EntityKind::Email => self.components.add_email(id, &proxy, &original),
            _ => {}
        }
        self.entries.push(Entry { lower, original });
        self.spelled.push(proxy);
    }
}

impl Matcher {
    fn build(raw: Vec<ScopeEntry>) -> Result<Option<Self>> {
        let mut collected = Collected::with_capacity(raw.len());
        // The first entry of each proxy, by the proxy in lower case.
        let mut first_of: HashMap<String, usize> = HashMap::with_capacity(raw.len());
        // Proxies that differ from an earlier one only in case, with that entry.
        let mut cased = Vec::new();
        for scoped in raw {
            if scoped.proxy.is_empty()
                || scoped.original.is_empty()
                || scoped.proxy == scoped.original
            {
                continue;
            }
            match first_of.entry(scoped.proxy.to_ascii_lowercase()) {
                MapEntry::Vacant(slot) => {
                    let lower = Box::from(slot.key().as_str());
                    slot.insert(collected.entries.len());
                    collected.add(scoped, lower);
                }
                // Seen before: the same spelling again changes nothing, another casing is kept
                // apart.
                MapEntry::Occupied(slot) => {
                    if collected.spelled[*slot.get()] != scoped.proxy {
                        cased.push((*slot.get(), scoped));
                    }
                }
            }
        }
        drop(first_of);
        let patterns = collected.entries.len();
        let mut spellings: HashMap<usize, Vec<Spelled>> = HashMap::new();
        for (first, scoped) in cased {
            let group = spellings.entry(first).or_insert_with(|| {
                vec![Spelled {
                    proxy: std::mem::take(&mut collected.spelled[first]),
                    original: collected.entries[first].original.clone(),
                }]
            });
            // The same original as one that is there: nothing to tell apart, and a second entry
            // would only make a typo or a name part of the proxy a tie.
            if group.iter().any(|s| s.original == scoped.original) {
                continue;
            }
            group.push(Spelled {
                proxy: scoped.proxy.clone(),
                original: scoped.original.clone(),
            });
            let lower = collected.entries[first].lower.clone();
            collected.add(scoped, lower);
        }
        // The spellings that matter are in `spellings`; the automaton is the big allocation.
        let Collected {
            entries,
            spelled,
            text_kind,
            components,
            longest,
        } = collected;
        drop(spelled);
        if entries.is_empty() {
            return Ok(None);
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(entries[..patterns].iter().map(|e| e.lower.as_bytes()))
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        let typo = TypoIndex::build(
            entries
                .iter()
                .enumerate()
                .filter(|&(id, _)| text_kind[id])
                .map(|(id, e)| (id, &*e.lower)),
        );
        Ok(Some(Self {
            ac,
            entries,
            spellings,
            typo,
            components,
            longest,
            margin: (longest * 2 + 8).max(NAME_REACH + 8),
        }))
    }

    /// What the proxy found at `matched` as entry `id` stands for. `None` when proxies that
    /// differ only in case stand for different originals and the text spells none of them as the
    /// scope does: there is no telling which one was meant.
    fn original_of(&self, id: usize, matched: &[u8]) -> Option<&str> {
        let Some(group) = self.spellings.get(&id) else {
            return Some(&self.entries[id].original);
        };
        let first = &group.first()?.original;
        match group.iter().find(|s| s.proxy.as_bytes() == matched) {
            Some(spelled) => Some(&spelled.original),
            None => group
                .iter()
                .all(|s| s.original == *first)
                .then_some(&**first),
        }
    }

    /// Restores a whole text, in which a finder found `found` (sorted, none overlapping);
    /// returns it with the number of replacements.
    fn restore(&self, text: &[u8], found: &[Edit<'_>]) -> (Vec<u8>, usize) {
        apply(text, &self.plan_all(text, found))
    }

    /// Every replacement in a whole text, in which a finder found `found`. A long text is split
    /// across rayon tasks at places where the pieces cannot influence each other.
    fn plan_all<'a>(&'a self, text: &[u8], found: &[Edit<'a>]) -> Vec<Edit<'a>> {
        let parts = if text.len() > PARALLEL_FROM {
            text.len() / CHUNK
        } else {
            1
        };
        self.plan_split(text, parts, found)
    }

    /// [`Self::plan`] over about `parts` pieces; always equal to it.
    fn plan_split<'a>(&'a self, text: &[u8], parts: usize, found: &[Edit<'a>]) -> Vec<Edit<'a>> {
        let cuts = self.cuts(text, parts, found);
        if cuts.len() <= 2 {
            return self.plan(text, found);
        }
        let pieces: Vec<Vec<Edit<'a>>> = cuts
            .par_windows(2)
            .map(|w| {
                let mut edits = self.plan(&text[w[0]..w[1]], &edits_in(found, w[0], w[1]));
                for edit in &mut edits {
                    edit.start += w[0];
                    edit.end += w[0];
                }
                edits
            })
            .collect();
        pieces.concat()
    }

    /// `0`, then up to `parts - 1` offsets near the even split points where `text` can be
    /// cut, then `text.len()`.
    fn cuts(&self, text: &[u8], parts: usize, found: &[Edit<'_>]) -> Vec<usize> {
        let mut cuts = vec![0];
        for k in 1..parts {
            let from = text.len() / parts * k;
            let to = text.len().min(from + SPLIT_SEARCH);
            if let Some(at) = (from..to).find(|&i| self.can_cut(text, i, found))
                && cuts.last().is_some_and(|&last| at > last)
            {
                cuts.push(at);
            }
        }
        cuts.push(text.len());
        cuts
    }

    /// Whether a text can be cut at `at` without changing the result: `text[at]` is an ASCII
    /// byte no token or space-separated run can contain (a name before a `\u{2019}t` would lose
    /// its particle), and no proxy occurs near enough to straddle it, whether or not it would be
    /// accepted, and none found by a finder.
    fn can_cut(&self, text: &[u8], at: usize, found: &[Edit<'_>]) -> bool {
        let b = text[at];
        let window = at.saturating_sub(self.longest)..text.len().min(at + self.longest);
        is_cut_byte(b)
            && b.is_ascii()
            && b != b' '
            && straddler(found, at).is_none()
            && matches!(self.ac.try_find(Input::new(text).range(window)), Ok(None))
    }

    /// Restores a whole text on this thread.
    fn restore_serial(&self, text: &[u8], found: &[Edit<'_>]) -> (Vec<u8>, usize) {
        apply(text, &self.plan(text, found))
    }

    /// Every replacement in `text`, in order and without overlap.
    ///
    /// The exact tier, which is what `found` (sorted, none overlapping) joins, cuts the text
    /// into matches and the gaps between them; the typo and component tiers only look inside
    /// the gaps.
    fn plan<'a>(&'a self, text: &[u8], found: &[Edit<'a>]) -> Vec<Edit<'a>> {
        let exact = merge_exact(self.exact_tier(text), found);
        let mut edits = Vec::with_capacity(exact.len());
        let mut scratch = Vec::new();
        let mut gap = 0;
        for edit in exact {
            self.plan_gap(text, gap, edit.start, &mut edits, &mut scratch);
            gap = edit.end;
            edits.push(edit);
        }
        self.plan_gap(text, gap, text.len(), &mut edits, &mut scratch);
        edits
    }

    /// The matches of the scope's proxies, in order and without overlap.
    fn exact_tier(&self, text: &[u8]) -> Vec<Edit<'_>> {
        let mut edits = Vec::new();
        let mut from = 0;
        while let Ok(Some(found)) = self.ac.try_find(Input::new(text).range(from..)) {
            let (start, end) = (found.start(), found.end());
            let with = if bounded(text, start, end) {
                self.original_of(found.pattern().as_usize(), &text[start..end])
            } else {
                None
            };
            if let Some(with) = with {
                edits.push(Edit { start, end, with });
                from = end;
            } else {
                // Glued to a longer word, or one of proxies that differ only in case with
                // none spelled like the text; a match that starts inside may still be fine.
                from = start + 1;
            }
        }
        edits
    }

    /// The typo and component tiers over `text[lo..hi]`, token by token.
    fn plan_gap<'a>(
        &'a self,
        text: &[u8],
        lo: usize,
        hi: usize,
        edits: &mut Vec<Edit<'a>>,
        scratch: &mut Vec<u8>,
    ) {
        if self.typo.is_empty() && self.components.parts.is_empty() {
            return;
        }
        let mut at = lo;
        while let Some((a, b)) = next_run(text, at, hi) {
            at = b;
            let Some((start, end)) = core(text, a, b) else {
                continue;
            };
            if let Some((resume, edit)) = self.typo_at(text, (a, b), start, hi) {
                edits.push(edit);
                at = resume;
            } else if let Some(edit) = self.component_at(text, (a, b), (start, end), scratch) {
                edits.push(edit);
            }
        }
    }

    /// Typo tier at the token run `first`, whose core starts at `start`: the longest run of
    /// up to six space-separated tokens that is a typo of a scoped proxy. Returns the edit
    /// and where scanning resumes.
    fn typo_at<'a>(
        &'a self,
        text: &[u8],
        first: (usize, usize),
        start: usize,
        hi: usize,
    ) -> Option<(usize, Edit<'a>)> {
        if !self.typo.has_start(text[start]) {
            return None;
        }
        let mut runs = [first; MAX_SEQUENCE];
        let mut count = 1;
        while count < MAX_SEQUENCE {
            let after = runs[count - 1].1;
            if after + 1 < hi && text[after] == b' ' && is_token(text[after + 1]) {
                // A run that goes on into the exact match at `hi` is glued to it. How far it goes
                // would depend on how much of that match a stream has seen, so it is left out.
                let end = run_end(text, after + 1, text.len());
                if end > hi {
                    break;
                }
                runs[count] = (after + 1, end);
                count += 1;
            } else {
                break;
            }
        }
        for k in (1..=count).rev() {
            let (a, b) = runs[k - 1];
            let Some((_, end)) = core(text, a, b) else {
                continue;
            };
            if let Some(id) = self.typo_match(&text[start..end]) {
                let with = &self.entries[id].original;
                return Some((b, Edit { start, end, with }));
            }
        }
        None
    }

    /// The entry `candidate` is a typo of, if exactly one is closest.
    fn typo_match(&self, candidate: &[u8]) -> Option<usize> {
        let index = &self.typo;
        let len = candidate.len();
        if len < MIN_TYPO_LEN || len + 2 < index.shortest || len > index.longest + 2 {
            return None;
        }
        let slot = slot(candidate[0]).filter(|&s| index.starts[s])?;
        // The most edits allowed, and the most letters of presence they can change.
        let (limit, slack) = if len < TWO_EDITS_LEN { (1, 2) } else { (2, 4) };
        let mut prepared: Option<(u64, String)> = None;
        let mut best: Option<(usize, usize)> = None;
        let mut tied = false;
        for proxy_len in len.saturating_sub(2).max(index.shortest)..=(len + 2).min(index.longest) {
            let bucket = &index.buckets[slot * index.stride + proxy_len];
            if bucket.is_empty() {
                continue;
            }
            let (mask, lowered) = match &prepared {
                Some(p) => p,
                None => prepared.insert((
                    presence(candidate),
                    String::from_utf8(candidate.to_ascii_lowercase()).ok()?,
                )),
            };
            for &(proxy_mask, id) in bucket {
                // Two cheap necessary conditions before the real distance: an edit adds or
                // drops at most two letters, and a path of at most `limit` edits stays
                // within `limit` of the diagonal.
                let proxy = &self.entries[id].lower;
                if (mask ^ proxy_mask).count_ones() > slack
                    || !within(lowered.as_bytes(), proxy.as_bytes(), limit)
                {
                    continue;
                }
                let distance = strsim::osa_distance(lowered, proxy);
                if distance > limit {
                    continue;
                }
                match best {
                    Some((d, _)) if distance > d => {}
                    Some((d, _)) if distance == d => tied = true,
                    _ => {
                        best = Some((distance, id));
                        tied = false;
                    }
                }
            }
        }
        best.filter(|_| !tied).map(|(_, id)| id)
    }

    /// Component tier for the token core `text[start..end]` of the run `run`.
    fn component_at<'a>(
        &'a self,
        text: &[u8],
        run: (usize, usize),
        (start, end): (usize, usize),
        scratch: &mut Vec<u8>,
    ) -> Option<Edit<'a>> {
        let len = end - start;
        if len < MIN_COMPONENT_LETTERS || len > self.components.longest {
            return None;
        }
        scratch.clear();
        scratch.extend(text[start..end].iter().map(u8::to_ascii_lowercase));
        let key = std::str::from_utf8(scratch).ok()?;
        match self.components.parts.get(key)? {
            Component::Unique {
                entry,
                replacement,
                capitalized,
                first_name,
            } if (!*capitalized || text[start].is_ascii_uppercase())
                && !(*first_name && end == run.1 && self.name_follows(text, run.1, *entry)) =>
            {
                Some(Edit {
                    start,
                    end,
                    with: replacement,
                })
            }
            _ => None,
        }
    }

    /// Whether the bare first name of `entry` that ends at `from` is followed, after a single
    /// space and at most [`MAX_PARTICLES`] particles, by a capitalized word that is no stop
    /// word and no part of that entry's name: `Haley Brooks` is somebody else.
    ///
    /// Looks at the text as it stands, at most [`NAME_REACH`] bytes ahead, whatever the exact
    /// tier makes of it: a stream does not know yet where a match ahead ends. A word that the
    /// reach cuts off is not judged.
    fn name_follows(&self, text: &[u8], from: usize, entry: usize) -> bool {
        let reach = text.len().min(from + NAME_REACH);
        let mut at = from;
        for _ in 0..=MAX_PARTICLES {
            if at + 1 >= reach || text[at] != b' ' {
                return false;
            }
            if let Some(len) = curly_particle(&text[at + 1..]) {
                at += 1 + len;
                continue;
            }
            if !is_token(text[at + 1]) {
                return false;
            }
            let end = run_end(text, at + 1, reach);
            if end == reach && text.get(reach).copied().is_some_and(is_token) {
                return false;
            }
            // The run as a whole: `core` would take the apostrophe off `'t` and see a letter.
            if std::str::from_utf8(&text[at + 1..end]).is_ok_and(is_particle) {
                at = end;
                continue;
            }
            let Some((start, core_end)) = core(text, at + 1, end) else {
                return false;
            };
            let Ok(word) = std::str::from_utf8(&text[start..core_end]) else {
                return false;
            };
            let word = word.to_ascii_lowercase();
            if is_particle(&word) {
                at = end;
                continue;
            }
            return start == at + 1
                && core_end - start >= 2
                && text[start].is_ascii_uppercase()
                && STOPWORDS.binary_search(&word.as_str()).is_err()
                && !matches!(
                    self.components.parts.get(word.as_str()),
                    Some(Component::Unique { entry: e, .. }) if *e == entry
                );
        }
        false
    }
}

/// The length of `\u{2018}t` or `\u{2019}t` at the start of `rest` when it is a word of its
/// own: the particle `'t` as word processors spell it, which no token can hold.
fn curly_particle(rest: &[u8]) -> Option<usize> {
    const SPELLINGS: [&[u8]; 2] = ["\u{2018}t".as_bytes(), "\u{2019}t".as_bytes()];
    let len = SPELLINGS
        .iter()
        .find(|spelling| rest.starts_with(spelling))?
        .len();
    (!rest.get(len).copied().is_some_and(is_token)).then_some(len)
}

/// ASCII letters and digits.
const fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Punctuation that joins words into one token: `jan.jansen`, `well-known`, `a_b`, `'s`.
const fn is_joiner(b: u8) -> bool {
    matches!(b, b'.' | b'-' | b'_' | b'+' | b'@' | b'\'')
}

/// Bytes of a token: `[A-Za-z0-9@._+'-]`.
const fn is_token(b: u8) -> bool {
    is_word(b) || is_joiner(b)
}

/// A byte where the stream may be cut: not part of a token, and not the inside of a UTF-8
/// sequence.
const fn is_cut_byte(b: u8) -> bool {
    !is_token(b) && b & 0xC0 != 0x80
}

/// Whether `text[start..end]` stands on its own: not glued to a longer word. A match that
/// begins or ends with a non-word byte (`(555) 123`, `+31 6`) is its own delimiter there.
///
/// Reads at most two bytes before `start` and three after `end`, and never past the first
/// non-token byte: that is what makes cutting a stream at a non-token byte safe.
fn bounded(text: &[u8], start: usize, end: usize) -> bool {
    start_free(text, start) && end_free(text, end)
}

fn start_free(text: &[u8], start: usize) -> bool {
    if start == 0 || !is_word(text[start]) {
        return true;
    }
    let before = text[start - 1];
    !(is_word(before) || (is_joiner(before) && start >= 2 && is_word(text[start - 2])))
}

fn end_free(text: &[u8], end: usize) -> bool {
    if !is_word(text[end - 1]) {
        return true;
    }
    let Some(&next) = text.get(end) else {
        return true;
    };
    if is_word(next) {
        return false;
    }
    let after = |i: usize| text.get(end + i).copied();
    if next == b'\'' && matches!(after(1), Some(b's' | b'S')) && !after(2).is_some_and(is_word) {
        return true; // possessive: `Haley's`
    }
    !(is_joiner(next) && after(1).is_some_and(is_word))
}

/// The first token run in `text[from..hi]`.
fn next_run(text: &[u8], from: usize, hi: usize) -> Option<(usize, usize)> {
    let a = from + text[from..hi].iter().position(|&b| is_token(b))?;
    Some((a, run_end(text, a, hi)))
}

/// Where the token run that starts at `a` ends.
fn run_end(text: &[u8], a: usize, hi: usize) -> usize {
    text[a..hi]
        .iter()
        .position(|&b| !is_token(b))
        .map_or(hi, |n| a + n)
}

/// The alphanumeric core of the token run `text[a..b]`: edge punctuation and a trailing
/// possessive `'s` are not part of it. `None` when the run has no letter or digit.
fn core(text: &[u8], a: usize, b: usize) -> Option<(usize, usize)> {
    let run = &text[a..b];
    let start = run.iter().position(u8::is_ascii_alphanumeric)?;
    let mut end = run.iter().rposition(u8::is_ascii_alphanumeric)? + 1;
    if end - start > 2
        && matches!(run[end - 1], b's' | b'S')
        && run[end - 2] == b'\''
        && let Some(n) = run[start..end - 2]
            .iter()
            .rposition(u8::is_ascii_alphanumeric)
    {
        end = start + n + 1;
    }
    Some((a + start, a + end))
}

/// Which letters, digits and (hashed) other bytes occur in `bytes`, ignoring ASCII case.
///
/// One edit (insert, delete, substitute, transpose) changes at most two bits, so two strings
/// within `k` edits differ in at most `2 * k` bits: a one-instruction test that rules out
/// almost every typo candidate before the real distance is computed.
fn presence(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |mask, &b| {
        let slot = match b.to_ascii_lowercase() {
            c @ b'a'..=b'z' => c - b'a',
            c @ b'0'..=b'9' => 26 + c - b'0',
            c => 36 + c % 28,
        };
        mask | 1 << slot
    })
}

/// Proxies of this many bytes or more are not checked by [`within`]; the rows live on the stack.
const BAND_MAX: usize = 64;

/// Whether the optimal string alignment distance of `a` and `b` is at most `limit`.
///
/// This is `strsim::osa_distance`'s recurrence restricted to the cells within `limit` of the
/// diagonal, which is exact for this question: every edit that moves off the diagonal costs
/// one, so no path of cost `limit` or less ever leaves the band. Proxies of `BAND_MAX` bytes
/// or more are not checked and count as within, which leaves them to `strsim`.
fn within(a: &[u8], b: &[u8], limit: usize) -> bool {
    let (n, m) = (a.len(), b.len());
    if n.abs_diff(m) > limit {
        return false;
    }
    if m >= BAND_MAX {
        return true;
    }
    // Distances are capped just above `limit`: anything farther is equally out.
    let cap = u8::try_from(limit + 1).unwrap_or(u8::MAX);
    let capped = |d: usize| u8::try_from(d).map_or(cap, |d| d.min(cap));
    let mut older = [cap; BAND_MAX];
    let mut prev = [cap; BAND_MAX];
    for (j, cell) in prev.iter_mut().enumerate().take(m + 1) {
        *cell = capped(j);
    }
    for i in 1..=n {
        let mut cur = [cap; BAND_MAX];
        cur[0] = capped(i);
        for j in i.saturating_sub(limit).max(1)..=m.min(i + limit) {
            let differ = a[i - 1] != b[j - 1];
            let mut best = prev[j - 1]
                .saturating_add(u8::from(differ))
                .min(prev[j].saturating_add(1))
                .min(cur[j - 1].saturating_add(1));
            if differ && i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(older[j - 2].saturating_add(1));
            }
            cur[j] = best.min(cap);
        }
        older = prev;
        prev = cur;
    }
    usize::from(prev[m]) <= limit
}

/// Where to cut a stream that has no valid cut but grew past [`MAX_HELD`]: the last position
/// before `limit` that no edit straddles and that is not inside a UTF-8 sequence. A sequence has
/// three continuation bytes at most: more of them are no UTF-8, and cut anywhere.
fn forced_cut(tail: &[u8], edits: &[Edit<'_>], limit: usize) -> Option<usize> {
    let mut at = limit.checked_sub(1)?;
    let mut continuation = 0;
    while at > 0 {
        if let Some(start) = straddler(edits, at) {
            at = start;
            continuation = 0;
        } else if tail[at] & 0xC0 == 0x80 && continuation < 3 {
            at -= 1;
            continuation += 1;
        } else {
            return Some(at);
        }
    }
    None
}

/// The start of the edit that has `at` strictly inside it, if there is one.
fn straddler(edits: &[Edit<'_>], at: usize) -> Option<usize> {
    let before = edits.partition_point(|e| e.start < at);
    let edit = edits.get(before.checked_sub(1)?)?;
    (edit.end > at).then_some(edit.start)
}

/// What `finder` finds in `text`; nothing when it has nothing to find at all.
fn find(finder: &dyn ProxyFinder, text: &[u8]) -> Vec<Replacement> {
    if finder.longest() == 0 {
        Vec::new()
    } else {
        finder.find(text)
    }
}

/// `found` as edits of `text`, sorted and with none overlapping another (of two that do the
/// first, the longer one when they start together, stays): what a finder reports outside the
/// text, or inside a character, is dropped.
fn edits_of<'a>(found: &'a [Replacement], text: &[u8]) -> Vec<Edit<'a>> {
    let boundary = |at: usize| at == text.len() || text.get(at).is_some_and(|&b| b & 0xC0 != 0x80);
    let mut edits: Vec<Edit<'a>> = found
        .iter()
        .filter(|rep| {
            rep.start < rep.end && rep.end <= text.len() && boundary(rep.start) && boundary(rep.end)
        })
        .map(|rep| Edit {
            start: rep.start,
            end: rep.end,
            with: &rep.with,
        })
        .collect();
    edits.sort_by_key(|edit| (edit.start, Reverse(edit.end)));
    let mut taken = 0;
    edits.retain(|edit| {
        let free = edit.start >= taken;
        if free {
            taken = edit.end;
        }
        free
    });
    edits
}

/// The edits of `found` inside `lo..hi`, as edits of the text `text[lo..hi]`. No edit of
/// `found` straddles either end: the text was cut where none does.
fn edits_in<'a>(found: &[Edit<'a>], lo: usize, hi: usize) -> Vec<Edit<'a>> {
    let from = found.partition_point(|edit| edit.start < lo);
    let to = found.partition_point(|edit| edit.start < hi);
    found[from..to]
        .iter()
        .map(|edit| Edit {
            start: edit.start - lo,
            end: edit.end - lo,
            with: edit.with,
        })
        .collect()
}

/// The edits of the exact tier and the ones a finder found as one list, sorted and with none
/// overlapping another. Of two that overlap the one that starts first stays, the longer one
/// when they start together, and the finder's when they are the same span.
fn merge_exact<'a>(own: Vec<Edit<'a>>, found: &[Edit<'a>]) -> Vec<Edit<'a>> {
    if found.is_empty() {
        return own;
    }
    let mut merged: Vec<Edit<'a>> = Vec::with_capacity(own.len() + found.len());
    let mut own = own.into_iter().peekable();
    let mut found = found.iter().copied().peekable();
    loop {
        let next = match (own.peek(), found.peek()) {
            (Some(a), Some(b)) if (a.start, Reverse(a.end)) < (b.start, Reverse(b.end)) => {
                own.next()
            }
            (_, Some(_)) => found.next(),
            (Some(_), None) => own.next(),
            (None, None) => break,
        };
        if let Some(next) = next
            && merged.last().is_none_or(|last| last.end <= next.start)
        {
            merged.push(next);
        }
    }
    merged
}

/// The edits for `text`: what the scope's tiers make of it when there is a matcher, with `found`
/// joining the exact tier; `found` alone when there is none.
fn plan_edits<'a>(matcher: Option<&'a Matcher>, text: &[u8], found: &[Edit<'a>]) -> Vec<Edit<'a>> {
    match matcher {
        Some(matcher) => matcher.plan(text, found),
        None => found.to_vec(),
    }
}

/// `text` with `edits` (sorted, none overlapping) made, and how many there were.
fn apply(text: &[u8], edits: &[Edit<'_>]) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(text.len());
    let mut pos = 0;
    for edit in edits {
        out.extend_from_slice(&text[pos..edit.start]);
        out.extend_from_slice(edit.with.as_bytes());
        pos = edit.end;
    }
    out.extend_from_slice(&text[pos..]);
    (out, edits.len())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{ProxyFinder, Restorer, STOPWORDS, Scope, ScopeEntry, apply, edits_of};
    use crate::detect::EntityKind::{
        self, Email, Iban, Ipv6, Person, Phone, Secret, UrlCredential,
    };
    use crate::engine::{Engine, Replacement};

    type Entries<'a> = &'a [(EntityKind, &'a str, &'a str)];

    /// No finder: the scope alone.
    const NONE: &dyn ProxyFinder = &();

    fn restorer(entries: Entries<'_>) -> Restorer {
        let scope = Scope::from_pairs(entries.iter().map(|&(kind, proxy, original)| ScopeEntry {
            kind,
            proxy: proxy.into(),
            original: original.into(),
        }));
        match Restorer::new(scope) {
            Ok(r) => r,
            Err(e) => panic!("restorer build failed: {e:?}"),
        }
    }

    fn restore(r: &Restorer, text: &str) -> String {
        String::from_utf8_lossy(&r.restore_with(text.as_bytes(), NONE)).into_owned()
    }

    /// Everything `feed_with` and `flush_with` emit for `chunks`, the replacements made, and how many
    /// bytes came out before the flush. A flushed restorer starts a new stream.
    fn stream(r: &mut Restorer, chunks: &[&[u8]]) -> (Vec<u8>, usize, usize) {
        let before = r.restored_count();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(r.feed_with(chunk, NONE));
        }
        let early = out.len();
        out.extend(r.flush_with(NONE));
        (out, r.restored_count() - before, early)
    }

    // --- exact ---------------------------------------------------------------------

    #[test]
    fn exact_restores_scoped_proxies() {
        let r = restorer(&[(Email, "lotte.wilson56@thistlemill.nl", "jeroen@test.nl")]);
        assert_eq!(
            restore(&r, "Mail lotte.wilson56@thistlemill.nl, please."),
            "Mail jeroen@test.nl, please."
        );
        assert_eq!(
            restore(&r, "(lotte.wilson56@thistlemill.nl)"),
            "(jeroen@test.nl)"
        );
        assert_eq!(restore(&r, "nothing to see"), "nothing to see");
    }

    #[test]
    fn exact_ignores_case() {
        let r = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        assert_eq!(restore(&r, "To: JEROEN@TEST.NL"), "To: jan@acme.nl");
        assert_eq!(restore(&r, "Jeroen@Test.NL."), "jan@acme.nl.");
    }

    #[test]
    fn exact_keeps_possessive() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        assert_eq!(
            restore(&r, "Haley van Zessen's inbox"),
            "Jeroen de Vries's inbox"
        );
        assert_eq!(
            restore(&r, "Haley van Zessen\u{2019}s inbox"),
            "Jeroen de Vries\u{2019}s inbox"
        );
        assert_eq!(restore(&r, "HALEY VAN ZESSEN'S"), "Jeroen de Vries'S");
    }

    #[test]
    fn exact_needs_word_boundaries() {
        // Secrets are exact-only, so glued text cannot be rescued by the typo tier.
        let r = restorer(&[(Secret, "AKIA1234567890ABCDEF", "AKIAORIGINALORIGINAL")]);
        for text in [
            "xAKIA1234567890ABCDEF",
            "AKIA1234567890ABCDEFx",
            "AKIA1234567890ABCDEF9",
            "AKIA1234567890ABCDEF.com",
            "AKIA1234567890ABCDEF-2",
            "a.AKIA1234567890ABCDEF",
            "a_AKIA1234567890ABCDEF",
            "AKIA1234567890ABCDEF's2",
        ] {
            assert_eq!(restore(&r, text), text);
        }
        for (text, want) in [
            ("AKIA1234567890ABCDEF", "AKIAORIGINALORIGINAL"),
            ("key AKIA1234567890ABCDEF.", "key AKIAORIGINALORIGINAL."),
            ("(AKIA1234567890ABCDEF)", "(AKIAORIGINALORIGINAL)"),
            ("\"AKIA1234567890ABCDEF\"", "\"AKIAORIGINALORIGINAL\""),
            ("key=AKIA1234567890ABCDEF;", "key=AKIAORIGINALORIGINAL;"),
            ("é AKIA1234567890ABCDEFé", "é AKIAORIGINALORIGINALé"),
            ("AKIA1234567890ABCDEF's", "AKIAORIGINALORIGINAL's"),
        ] {
            assert_eq!(restore(&r, text), want);
        }
    }

    #[test]
    fn exact_match_may_start_or_end_with_a_delimiter() {
        let r = restorer(&[
            (Phone, "(555) 123-4567", "(202) 555-0100"),
            (Phone, "+31 6 29554691", "+31 6 12345678"),
        ]);
        assert_eq!(restore(&r, "call(555) 123-4567"), "call(202) 555-0100");
        assert_eq!(restore(&r, "x+31 6 29554691"), "x+31 6 12345678");
        assert_eq!(restore(&r, "+31 6 29554691."), "+31 6 12345678.");
        assert_eq!(restore(&r, "+31 6 295546910"), "+31 6 295546910");
    }

    #[test]
    fn longest_proxy_wins_and_matches_do_not_overlap() {
        let r = restorer(&[
            (Phone, "+31 6 29554691", "+31 6 12345678"),
            (Phone, "+31 6 2955469", "+31 6 87654321"),
        ]);
        assert_eq!(restore(&r, "+31 6 29554691"), "+31 6 12345678");
        assert_eq!(restore(&r, "+31 6 2955469 x"), "+31 6 87654321 x");
    }

    #[test]
    fn line_wrap_hyphen_is_not_handled() {
        let r = restorer(&[(Secret, "AKIA1234567890ABCDEF", "AKIAORIGINALORIGINAL")]);
        assert_eq!(
            restore(&r, "AKIA123456-\n7890ABCDEF"),
            "AKIA123456-\n7890ABCDEF"
        );
        let r = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        assert_eq!(restore(&r, "jeroen@te-\nst.nl"), "jeroen@te-\nst.nl");
    }

    #[test]
    fn duplicate_and_degenerate_entries_are_harmless() {
        let r = restorer(&[
            (Email, "jeroen@test.nl", "jan@acme.nl"),
            (Email, "JEROEN@test.nl", "other@acme.nl"),
            (Email, "same@x.nl", "same@x.nl"),
            (Email, "", "x@y.nl"),
            (Email, "empty@x.nl", ""),
        ]);
        assert_eq!(
            restore(&r, "jeroen@test.nl same@x.nl empty@x.nl"),
            "jan@acme.nl same@x.nl empty@x.nl"
        );
    }

    #[test]
    fn proxies_that_differ_only_in_case_restore_each_to_its_own_original() {
        // The vault hands a scope out in hash order, so neither order may matter.
        for scope in [
            [
                (Person, "Haley Brooks", "Anna Boer"),
                (Person, "HALEY BROOKS", "ANNA DE JONG"),
            ],
            [
                (Person, "HALEY BROOKS", "ANNA DE JONG"),
                (Person, "Haley Brooks", "Anna Boer"),
            ],
        ] {
            let r = restorer(&scope);
            let text = "Haley Brooks, HALEY BROOKS and Haley Brooks's cat";
            let want = "Anna Boer, ANNA DE JONG and Anna Boer's cat";
            assert_eq!(restore(&r, text), want);
            // Streamed byte by byte, the result is the same.
            let mut s = restorer(&scope);
            let chunks: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
            assert_eq!(stream(&mut s, &chunks).0, want.as_bytes());

            // Any other casing could be either person, and so could a typo or a first name.
            for text in [
                "haley brooks",
                "HaLey BrooKs",
                "Haley Brook",
                "HALEY BROOK",
                "Haley said",
            ] {
                assert_eq!(restore(&r, text), text);
            }
        }
    }

    #[test]
    fn proxies_that_differ_only_in_case_and_share_an_original_restore_in_any_casing() {
        let r = restorer(&[
            (Person, "Haley Brooks", "Anna Boer"),
            (Person, "HALEY BROOKS", "Anna Boer"),
        ]);
        assert_eq!(restore(&r, "haley brooks"), "Anna Boer");
        assert_eq!(restore(&r, "HALEY BROOKS"), "Anna Boer");
    }

    #[test]
    fn empty_scope_changes_nothing() {
        let mut r = restorer(&[]);
        assert_eq!(restore(&r, "Haley van Zessen"), "Haley van Zessen");
        assert_eq!(r.feed_with(b"abc", NONE), b"abc");
        assert!(r.flush_with(NONE).is_empty());
        assert_eq!(r.restored_count(), 0);
    }

    // --- typo ----------------------------------------------------------------------

    #[test]
    fn typo_restores_one_edit_off_proxies() {
        let r = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        assert_eq!(
            restore(&r, "write jeroeen@test.nl today"),
            "write jan@acme.nl today"
        );
        assert_eq!(
            restore(&r, "write jeroen@tset.nl today"),
            "write jan@acme.nl today"
        );
        assert_eq!(restore(&r, "write jeroen@test.nll."), "write jan@acme.nl.");
        assert_eq!(restore(&r, "write jeroen@tst.nl,"), "write jan@acme.nl,");
        // 14 bytes: two edits are allowed, three are not.
        assert_eq!(restore(&r, "jeroen@tsst.nl"), "jan@acme.nl");
        assert_eq!(restore(&r, "jeroen@tsxx.nl"), "jeroen@tsxx.nl");
        // A different first letter never gets compared.
        assert_eq!(restore(&r, "seroen@test.nl"), "seroen@test.nl");
    }

    #[test]
    fn typo_needs_six_bytes() {
        let r = restorer(&[(Person, "Haley", "Jeroen")]);
        assert_eq!(restore(&r, "Haley"), "Jeroen");
        // Five bytes: never fuzzed, even one transposition away.
        assert_eq!(restore(&r, "Haely"), "Haely");
        assert_eq!(restore(&r, "Haley!"), "Jeroen!");
        // Six bytes: one edit is enough.
        assert_eq!(restore(&r, "Hailey"), "Jeroen");
        assert_eq!(restore(&r, "Haleyy"), "Jeroen");
    }

    #[test]
    fn typo_allows_one_edit_when_short_and_two_when_long() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        // 16 bytes: two edits allowed.
        assert_eq!(restore(&r, "Haley van Zesen"), "Jeroen de Vries");
        assert_eq!(restore(&r, "Haley van Zesen's"), "Jeroen de Vries's");
        assert_eq!(restore(&r, "Haley van Zesn"), "Jeroen de Vries");
        let r = restorer(&[(Person, "Haley Brooks", "Jeroen Vries")]);
        // 11-byte candidate: one edit allowed. Two edits are too many, and a `Haley` that is
        // followed by a capitalized stranger stays.
        assert_eq!(restore(&r, "Haley Brook"), "Jeroen Vries");
        assert_eq!(restore(&r, "Haley Broo"), "Haley Broo");
        assert_eq!(restore(&r, "Haley broo"), "Jeroen broo");
    }

    #[test]
    fn typo_ties_are_left_alone() {
        let r = restorer(&[
            (Email, "jeroen@test.nl", "a@x.nl"),
            (Email, "jeroen@tent.nl", "b@x.nl"),
        ]);
        // One substitution from either proxy.
        assert_eq!(restore(&r, "jeroen@tert.nl"), "jeroen@tert.nl");
        // Closer to one than to the other.
        assert_eq!(restore(&r, "jeroen@tesx.nl"), "a@x.nl");
        assert_eq!(restore(&r, "jeroen@tenx.nl"), "b@x.nl");
    }

    #[test]
    fn typo_prefers_the_longest_sequence() {
        let r = restorer(&[
            (Person, "Haley van Zessen", "Jeroen de Vries"),
            (Person, "Haley vom", "Anna de"),
        ]);
        // Both proxies are a typo away from a prefix of the text: the longer one wins.
        assert_eq!(restore(&r, "Haley von Zesen said"), "Jeroen de Vries said");
        assert_eq!(restore(&r, "Haley von said"), "Anna de said");
    }

    #[test]
    fn exact_shorter_proxy_beats_typo_of_longer_one() {
        let r = restorer(&[
            (Person, "Haley van Zessen", "Jeroen de Vries"),
            (Person, "Haley van", "Anna de"),
        ]);
        assert_eq!(restore(&r, "Haley van Zesen said"), "Anna de Zesen said");
    }

    #[test]
    fn typo_never_touches_number_like_kinds() {
        let r = restorer(&[
            (Phone, "+31 6 29554691", "+31 6 12345678"),
            (Iban, "NL91 ABNA 0417 1643 00", "NL00 BANK 0000 0000 01"),
            (Ipv6, "2001:db8::7334", "fe80::1"),
        ]);
        assert_eq!(restore(&r, "+31 6 2955469"), "+31 6 2955469");
        assert_eq!(restore(&r, "+31 6 29554692"), "+31 6 29554692");
        assert_eq!(
            restore(&r, "NL91 ABNA 0417 1643 01"),
            "NL91 ABNA 0417 1643 01"
        );
        assert_eq!(restore(&r, "2001:db8::7335"), "2001:db8::7335");
    }

    #[test]
    fn typo_matches_one_word_name_tokens() {
        let r = restorer(&[(Person, "Haley-Marian", "Jeroen")]);
        assert_eq!(restore(&r, "Haley-Marien called"), "Jeroen called");
    }

    // --- component -----------------------------------------------------------------

    #[test]
    fn component_restores_first_and_last_names() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        assert_eq!(restore(&r, "Haley said hi"), "Jeroen said hi");
        assert_eq!(
            restore(&r, "hi Zessen, and Haley."),
            "hi Vries, and Jeroen."
        );
        assert_eq!(restore(&r, "Haley's inbox"), "Jeroen's inbox");
        assert_eq!(restore(&r, "(Zessen)"), "(Vries)");
        assert_eq!(restore(&r, "HALEY said hi"), "Jeroen said hi");
        // A particle never stands for the name.
        assert_eq!(restore(&r, "van and Zessen"), "van and Vries");
    }

    #[test]
    fn component_needs_a_single_owner() {
        let r = restorer(&[
            (Person, "Haley van Zessen", "Jeroen de Vries"),
            (Person, "Haley Brooks", "Anna Boer"),
        ]);
        assert_eq!(restore(&r, "Haley said hi"), "Haley said hi");
        // The other parts still belong to one proxy each.
        assert_eq!(restore(&r, "Zessen and Brooks"), "Vries and Boer");
        // A full proxy is exact, whatever the bare part means.
        assert_eq!(restore(&r, "Haley Brooks called"), "Anna Boer called");
        assert_eq!(
            restore(&r, "Haley van Zessen called"),
            "Jeroen de Vries called"
        );
    }

    #[test]
    fn component_is_inert_without_a_matching_scope() {
        assert_eq!(restore(&restorer(&[]), "Haley said hi"), "Haley said hi");
        let r = restorer(&[(Person, "Lotte Brooks", "Anna Boer")]);
        assert_eq!(restore(&r, "Haley said hi"), "Haley said hi");
    }

    #[test]
    fn component_skips_stopwords_and_short_parts() {
        let r = restorer(&[
            (Person, "May Brooks", "Anna Boer"),
            (Person, "K. Smit", "J. Jansen"),
        ]);
        assert_eq!(restore(&r, "you may call May"), "you may call May");
        assert_eq!(restore(&r, "Brooks said"), "Boer said");
        // `K.` has one letter; `Smit` is a fine last name.
        assert_eq!(restore(&r, "K said, Smit."), "K said, Jansen.");
        let r = restorer(&[(Person, "Will Smith", "Jan Smit")]);
        assert_eq!(restore(&r, "will do"), "will do");
        assert_eq!(restore(&r, "Smith will do"), "Smit will do");
    }

    #[test]
    fn component_capital_proxy_part_needs_capital_mention() {
        let r = restorer(&[(Person, "Haley Long", "Jeroen Vries")]);
        assert_eq!(restore(&r, "a long way"), "a long way");
        assert_eq!(restore(&r, "Long said"), "Vries said");
        assert_eq!(restore(&r, "LONG said"), "Vries said");
        // A lower-case proxy part takes any case.
        let r = restorer(&[(Person, "haley long", "jeroen vries")]);
        assert_eq!(restore(&r, "a long way"), "a vries way");
    }

    #[test]
    fn component_restores_email_local_parts() {
        let r = restorer(&[(Email, "lotte.wilson56@thistlemill.nl", "jeroen@test.nl")]);
        assert_eq!(
            restore(&r, "ask lotte.wilson56 about it"),
            "ask jeroen about it"
        );
        assert_eq!(restore(&r, "ask Lotte about it"), "ask Lotte about it");
        assert_eq!(
            restore(&r, "ask lotte.wilson56@thistlemill.org"),
            "ask lotte.wilson56@thistlemill.org"
        );
    }

    #[test]
    fn component_restores_parts_of_one_word_names() {
        let r = restorer(&[(Person, "Haley-Marian", "Jeroen")]);
        assert_eq!(restore(&r, "Haley-Marian called"), "Jeroen called");
        assert_eq!(restore(&r, "Haley called"), "Jeroen called");
        assert_eq!(restore(&r, "Marian called"), "Jeroen called");
        assert_eq!(restore(&r, "Haley-Brooks called"), "Haley-Brooks called");
        let r = restorer(&[(Person, "Haley-Marian", "Jan-Willem")]);
        assert_eq!(restore(&r, "Haley and Marian"), "Jan and Willem");
    }

    #[test]
    fn exact_beats_typo_beats_component() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        assert_eq!(
            restore(&r, "Haley van Zessen / Haley van Zesen / Haley / Zessen"),
            "Jeroen de Vries / Jeroen de Vries / Jeroen / Vries"
        );
    }

    // --- streaming -----------------------------------------------------------------

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn restorer_is_send_and_sync() {
        assert_send_sync::<Restorer>();
        assert_send_sync::<Scope>();
    }

    #[test]
    fn stopwords_are_sorted_unique_lowercase_ascii() {
        assert!(STOPWORDS.len() >= 300);
        for pair in STOPWORDS.windows(2) {
            assert!(pair[0] < pair[1], "{} !< {}", pair[0], pair[1]);
        }
        for word in STOPWORDS {
            assert!(
                !word.is_empty() && word.bytes().all(|b| b.is_ascii_lowercase()),
                "{word}"
            );
        }
        let unique: HashSet<&&str> = STOPWORDS.iter().collect();
        assert_eq!(unique.len(), STOPWORDS.len());
        for word in [
            "the", "and", "you", "will", "may", "can", "de", "het", "een", "van",
        ] {
            assert!(STOPWORDS.binary_search(&word).is_ok(), "{word}");
        }
    }

    #[test]
    fn feed_without_scope_passes_through_immediately() {
        let mut r = restorer(&[]);
        assert_eq!(r.feed_with(b"Hello ", NONE), b"Hello ");
        assert_eq!(r.feed_with(b"world", NONE), b"world");
        assert!(r.flush_with(NONE).is_empty());
    }

    #[test]
    fn feed_emits_while_streaming_and_counts_replacements() {
        let mut s = restorer(&[
            (Email, "jeroen@test.nl", "jan@acme.nl"),
            (Person, "Haley van Zessen", "Jeroen de Vries"),
        ]);
        let line = "mail jeroen@test.nl or ask Haley van Zessen about it,\n";
        let mut emitted = Vec::new();
        let mut early = false;
        for _ in 0..20 {
            let out = s.feed_with(line.as_bytes(), NONE);
            early |= !out.is_empty();
            emitted.extend(out);
        }
        assert!(early, "nothing was emitted before the end of the stream");
        emitted.extend(s.flush_with(NONE));
        let want = line
            .replace("jeroen@test.nl", "jan@acme.nl")
            .replace("Haley van Zessen", "Jeroen de Vries")
            .repeat(20);
        assert_eq!(String::from_utf8_lossy(&emitted), want);
        assert_eq!(s.restored_count(), 40);
    }

    #[test]
    fn feed_holds_back_an_unfinished_mention() {
        let mut s = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        let filler = "x, ".repeat(30);
        let mut out = s.feed_with(format!("{filler}jeroen@te").as_bytes(), NONE);
        out.extend(s.feed_with(b"st.nl and more", NONE));
        out.extend(s.flush_with(NONE));
        assert_eq!(
            String::from_utf8_lossy(&out),
            format!("{filler}jan@acme.nl and more")
        );
    }

    #[test]
    fn long_token_runs_are_not_rescanned_per_chunk() {
        let mut s = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        let chunk = vec![b'a'; 1024];
        let mut out = s.feed_with(b"start ", NONE);
        for _ in 0..400 {
            out.extend(s.feed_with(&chunk, NONE));
        }
        out.extend(s.feed_with(b" end", NONE));
        out.extend(s.flush_with(NONE));
        assert_eq!(out.len(), 6 + 400 * 1024 + 4);
    }

    #[test]
    fn emitted_pieces_are_valid_utf8_when_the_stream_is() {
        let mut s = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        let text = "héllo wörld — jeroen@test.nl 😀 ünïcödé, ".repeat(30);
        for chunk in text.as_bytes().chunks(1) {
            let piece = s.feed_with(chunk, NONE);
            assert!(std::str::from_utf8(&piece).is_ok());
        }
        assert!(std::str::from_utf8(&s.flush_with(NONE)).is_ok());
    }

    struct Rng(u64);

    impl Rng {
        fn step(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.step() % (n as u64)).unwrap_or(0)
        }

        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[self.below(items.len())]
        }
    }

    const RICH: Entries<'static> = &[
        (Email, "lotte.wilson56@thistlemill.nl", "jeroen@test.nl"),
        (Email, "anna.smit21@birchcliff.nl", "jan.jansen@acme.nl"),
        (Person, "Haley de Zessen", "Jeroen de Vries"),
        (Person, "Haley Brooks", "Anna Boer"),
        (Person, "Haley-Marian", "Piet"),
        (Person, "K. Smit", "J. Jansen"),
        (Person, "Lotte Fleming", "Sanne Bakker"),
        (Phone, "(555) 123-4567", "(202) 555-0100"),
        (Phone, "+31 6 29554691", "+31 6 12345678"),
        (Ipv6, "2001:db8::7334", "fe80::1"),
        (Secret, "AKIAIOSFODNN7EXAMPLE", "AKIAXXXXXXXXXXXXXXXX"),
        (UrlCredential, "anna12:pa$$w0rd", "bob:secret"),
        (
            Iban,
            "NL91 ABNA 0417 1643 00",
            "DE89 3704 0044 0532 0130 00",
        ),
    ];

    const PROXIES: [&str; 13] = [
        "lotte.wilson56@thistlemill.nl",
        "anna.smit21@birchcliff.nl",
        "Haley de Zessen",
        "Haley Brooks",
        "Haley-Marian",
        "K. Smit",
        "Lotte Fleming",
        "(555) 123-4567",
        "+31 6 29554691",
        "2001:db8::7334",
        "AKIAIOSFODNN7EXAMPLE",
        "anna12:pa$$w0rd",
        "NL91 ABNA 0417 1643 00",
    ];

    const BITS: [&str; 48] = [
        "Haley",
        "haley",
        "Zessen",
        "zessen",
        "Brooks",
        "Marian",
        "Fleming",
        "Lotte",
        "lotte.wilson56",
        "Smit",
        "K.",
        "de",
        "van",
        "the",
        "and",
        "may",
        "long",
        "Long",
        "said",
        "hello",
        "mail",
        "number",
        ",",
        ".",
        "!",
        "?",
        ":",
        ";",
        "(",
        ")",
        "\"",
        "'",
        "'s",
        "\u{2019}s",
        "-",
        "_",
        "/",
        "\n",
        "\t",
        "\u{2014}",
        "é",
        "😀",
        "@",
        "+",
        "2955469",
        "42",
        "-\n",
        "..",
    ];

    fn mutate(rng: &mut Rng, s: &str) -> String {
        let mut chars: Vec<char> = s.chars().collect();
        if chars.is_empty() {
            return String::new();
        }
        let i = rng.below(chars.len());
        match rng.below(4) {
            0 => {
                chars.remove(i);
            }
            1 => chars.insert(i, rng.pick(&['a', 'e', 'x', '.', '-', ' ', '1'])),
            2 if i + 1 < chars.len() => chars.swap(i, i + 1),
            _ => chars[i] = rng.pick(&['a', 'e', 'x', '.', '-', ' ', '1']),
        }
        chars.into_iter().collect()
    }

    fn random_text(rng: &mut Rng) -> String {
        let mut text = String::new();
        for _ in 0..(5 + rng.below(60)) {
            match rng.below(7) {
                0 | 1 => text.push_str(rng.pick(&PROXIES)),
                2 => {
                    let proxy = rng.pick(&PROXIES);
                    text.push_str(&mutate(rng, proxy));
                }
                3 => {
                    let proxy = rng.pick(&PROXIES);
                    match rng.below(3) {
                        0 => text.push_str(&proxy.to_ascii_uppercase()),
                        1 => text.push_str(&proxy.to_ascii_lowercase()),
                        _ => text.push_str(proxy),
                    }
                }
                _ => text.push_str(rng.pick(&BITS)),
            }
            match rng.below(6) {
                0 => {}
                1 => text.push_str("  "),
                _ => text.push(' '),
            }
        }
        text
    }

    fn chunked<'a>(rng: &mut Rng, text: &'a [u8], mode: usize) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            let n = match mode {
                0 => rest.len(),
                1 => 1,
                2 => 1 + rng.below(8),
                3 => 1 + rng.below(40),
                _ => 1 + rng.below(rest.len()),
            };
            let (head, tail) = rest.split_at(n.min(rest.len()));
            chunks.push(head);
            rest = tail;
        }
        chunks
    }

    #[test]
    fn streaming_equals_one_shot_for_random_texts_and_chunkings() {
        let r = restorer(RICH);
        let mut s = restorer(RICH);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut replaced = 0;
        let (mut emitted_early, mut emitted) = (0, 0);
        for round in 0..200 {
            let text = random_text(&mut rng);
            let (want, count) = match &r.matcher {
                Some(m) => m.restore(text.as_bytes(), &[]),
                None => panic!("rich scope has a matcher"),
            };
            replaced += count;
            for mode in 0..5 {
                let chunks = chunked(&mut rng, text.as_bytes(), mode);
                let (got, restored, early) = stream(&mut s, &chunks);
                assert_eq!(
                    String::from_utf8_lossy(&got),
                    String::from_utf8_lossy(&want),
                    "round {round} mode {mode} text {text:?}"
                );
                assert_eq!(restored, count, "round {round} mode {mode} text {text:?}");
                if mode > 0 {
                    emitted_early += early;
                    emitted += got.len();
                }
            }
        }
        assert!(replaced > 400, "the texts exercised too little: {replaced}");
        // The streams must not hold everything until the flush: that would be equivalent
        // for free.
        assert!(emitted_early * 2 > emitted, "{emitted_early} of {emitted}");
    }

    #[test]
    fn streaming_equals_one_shot_for_arbitrary_bytes() {
        let r = restorer(RICH);
        let mut s = restorer(RICH);
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        let alphabet: &[u8] =
            b"Haleyvn Zs.-_'@+ ,\n()\"\xC3\xA9\xE2\x80\x99\xF0\x9F\x98\x80\x80\xFF0123";
        for round in 0..200 {
            let mut text = Vec::new();
            for _ in 0..(10 + rng.below(300)) {
                if rng.below(9) == 0 {
                    text.extend_from_slice(rng.pick(&PROXIES).as_bytes());
                } else {
                    text.push(rng.pick(alphabet));
                }
            }
            let want = r.restore_with(&text, NONE);
            for mode in [1, 2, 3, 4] {
                let chunks = chunked(&mut rng, &text, mode);
                let (got, _, _) = stream(&mut s, &chunks);
                assert_eq!(got, want, "round {round} mode {mode}");
            }
        }
    }

    #[test]
    fn streaming_equals_one_shot_at_every_alignment() {
        let r = restorer(RICH);
        let mut s = restorer(RICH);
        let mentions = [
            "Haley de Zesen",
            "(555) 123-4567",
            "+31 6 29554691",
            "NL91 ABNA 0417 1643 00",
            "lotte.wilson56@thistlemill.nl",
            "Haley-Marian's",
            "anna12:pa$$w0rd",
        ];
        for mention in mentions {
            for pad in 0..160 {
                let text = format!(
                    "{}{}{mention} and {}",
                    "x ".repeat(pad / 2),
                    "y".repeat(pad % 2),
                    "z. ".repeat(40)
                );
                let want = r.restore_with(text.as_bytes(), NONE);
                for size in [1, 2, 3, 5, 8, 13, 64] {
                    let chunks: Vec<&[u8]> = text.as_bytes().chunks(size).collect();
                    let (got, _, early) = stream(&mut s, &chunks);
                    assert_eq!(got, want, "{mention:?} pad {pad} size {size}");
                    assert!(
                        early > 0,
                        "{mention:?} pad {pad} size {size}: nothing early"
                    );
                }
            }
        }
    }

    /// The edits a plan returns are in order, disjoint and inside the text, and on character
    /// boundaries when the text is UTF-8: a caller applies them to a `str`.
    fn assert_plan_sound(r: &Restorer, text: &[u8]) {
        let Some(m) = &r.matcher else {
            return;
        };
        let edits = m.plan(text, &[]);
        let valid = std::str::from_utf8(text).ok();
        let mut end = 0;
        for edit in &edits {
            assert!(edit.start >= end && edit.start < edit.end && edit.end <= text.len());
            if let Some(valid) = valid {
                assert!(
                    valid.is_char_boundary(edit.start) && valid.is_char_boundary(edit.end),
                    "edit {}..{} is not on a character boundary",
                    edit.start,
                    edit.end
                );
            }
            end = edit.end;
        }
    }

    #[test]
    fn plans_are_ordered_and_disjoint() {
        let r = restorer(RICH);
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        for _ in 0..300 {
            assert_plan_sound(&r, random_text(&mut rng).as_bytes());
        }
    }

    #[test]
    fn splitting_a_text_across_tasks_changes_nothing() {
        let r = restorer(RICH);
        let Some(m) = &r.matcher else {
            panic!("no matcher");
        };
        let mut rng = Rng(0xFEED_FACE_0BAD_F00D);
        let mut split = 0;
        for _ in 0..60 {
            let mut text = String::new();
            while text.len() < 20_000 {
                text.push_str(&random_text(&mut rng));
                text.push('\n');
            }
            let want = m.restore_serial(text.as_bytes(), &[]);
            for parts in [2, 3, 8, 40] {
                if m.cuts(text.as_bytes(), parts, &[]).len() > 2 {
                    split += 1;
                }
                assert_eq!(
                    apply(text.as_bytes(), &m.plan_split(text.as_bytes(), parts, &[])),
                    want,
                    "parts {parts}"
                );
            }
        }
        assert!(split > 100, "texts were hardly ever split: {split}");
    }

    #[test]
    fn long_texts_are_restored_in_parallel_pieces() {
        let r = restorer(RICH);
        let Some(m) = &r.matcher else {
            panic!("no matcher");
        };
        let mut rng = Rng(0xABAD_1DEA_5EED_5EED);
        let mut text = Vec::new();
        while text.len() <= super::PARALLEL_FROM {
            text.extend_from_slice(random_text(&mut rng).as_bytes());
            text.push(b'\n');
        }
        assert!(m.cuts(&text, text.len() / super::CHUNK, &[]).len() > 2);
        assert_eq!(m.restore(&text, &[]), m.restore_serial(&text, &[]));
        assert_eq!(r.restore_with(&text, NONE), m.restore_serial(&text, &[]).0);
    }

    #[test]
    fn debug_output_never_shows_originals() {
        let mut r = restorer(&[(Email, "jeroen@test.nl", "secret.original@example.org")]);
        let _ = r.feed_with(b"jeroen@test.nl", NONE);
        let shown = format!("{r:?}");
        assert!(!shown.contains("secret.original"), "{shown}");
        assert!(!shown.contains("jeroen@test.nl"), "{shown}");
    }

    #[test]
    fn presence_bounds_the_edit_distance() {
        let mut rng = Rng(0x5EED_0000_1234_5678);
        let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_@+' ABCZ:/";
        let random = |rng: &mut Rng| -> String {
            (0..=rng.below(16))
                .map(|_| char::from(rng.pick(alphabet)))
                .collect()
        };
        for _ in 0..20_000 {
            let a = random(&mut rng);
            // Half of the pairs are near each other, which is where the bound is tight.
            let b = if rng.below(2) == 0 {
                random(&mut rng)
            } else {
                mutate(&mut rng, &a)
            };
            let bits = (super::presence(a.as_bytes()) ^ super::presence(b.as_bytes())).count_ones();
            let distance = strsim::osa_distance(&a.to_ascii_lowercase(), &b.to_ascii_lowercase());
            assert!(
                usize::try_from(bits).unwrap_or(usize::MAX) <= 2 * distance,
                "{a:?} {b:?}"
            );
        }
    }

    /// Every string over `alphabet` of at most `max` bytes.
    fn strings(alphabet: &[u8], max: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut layer = vec![Vec::new()];
        for _ in 0..max {
            layer = layer
                .iter()
                .flat_map(|s: &Vec<u8>| {
                    alphabet.iter().map(move |&c| {
                        let mut t = s.clone();
                        t.push(c);
                        t
                    })
                })
                .collect();
            all.extend(layer.iter().cloned());
        }
        all
    }

    fn osa(a: &[u8], b: &[u8]) -> usize {
        strsim::osa_distance(&String::from_utf8_lossy(a), &String::from_utf8_lossy(b))
    }

    #[test]
    fn within_agrees_with_strsim_on_every_short_string() {
        for (alphabet, max) in [(&b"ab"[..], 7), (&b"abc"[..], 5), (&b"abcd"[..], 4)] {
            let all = strings(alphabet, max);
            for a in &all {
                for b in &all {
                    let distance = osa(a, b);
                    for limit in [1, 2] {
                        assert_eq!(
                            super::within(a, b, limit),
                            distance <= limit,
                            "{a:?} {b:?} limit {limit}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn within_agrees_with_strsim_on_long_and_near_strings() {
        let mut rng = Rng(0x1357_9BDF_2468_ACE0);
        let alphabet: &[u8] = b"abcde.@- ";
        for _ in 0..30_000 {
            let a: Vec<u8> = (0..6 + rng.below(40)).map(|_| rng.pick(alphabet)).collect();
            let mut b = a.clone();
            for _ in 0..rng.below(4) {
                let at = rng.below(b.len());
                match rng.below(4) {
                    0 => {
                        b.remove(at);
                    }
                    1 => b.insert(at, rng.pick(alphabet)),
                    2 if at + 1 < b.len() => b.swap(at, at + 1),
                    _ => b[at] = rng.pick(alphabet),
                }
                if b.is_empty() {
                    b.push(b'a');
                }
            }
            let distance = osa(&a, &b);
            for limit in [1, 2] {
                assert_eq!(
                    super::within(&a, &b, limit),
                    distance <= limit,
                    "{a:?} {b:?} limit {limit}"
                );
            }
        }
        // Too long for the stack rows: not filtered.
        let long = vec![b'a'; super::BAND_MAX];
        assert!(super::within(&long, &long, 1));
    }

    #[test]
    fn indexed_typo_matching_equals_comparing_with_every_proxy() {
        let mut rng = Rng(0xC0DE_D00D_FEED_BEEF);
        let alphabet: &[u8] = b"abcdefgh.@ -";
        let proxy = |rng: &mut Rng| -> String {
            let first = rng.pick(b"abcde");
            let rest: Vec<u8> = (0..5 + rng.below(14)).map(|_| rng.pick(alphabet)).collect();
            format!("{}{}", char::from(first), String::from_utf8_lossy(&rest))
        };
        for round in 0..40 {
            let mut entries: Vec<(EntityKind, String, String)> = Vec::new();
            for n in 0..(2 + rng.below(60)) {
                let kind = rng.pick(&[Email, Person, UrlCredential, Phone, Secret]);
                let p = proxy(&mut rng);
                if entries.iter().all(|(_, q, _)| !q.eq_ignore_ascii_case(&p)) {
                    entries.push((kind, p, format!("original{n}")));
                }
            }
            let scope: Vec<(EntityKind, &str, &str)> = entries
                .iter()
                .map(|(k, p, o)| (*k, p.as_str(), o.as_str()))
                .collect();
            let r = restorer(&scope);
            let Some(m) = &r.matcher else {
                panic!("no matcher");
            };
            for _ in 0..400 {
                // Mostly near-misses of a random proxy.
                let base = if rng.below(4) == 0 {
                    proxy(&mut rng)
                } else {
                    entries[rng.below(entries.len())].1.clone()
                };
                let mut cand: Vec<u8> = base.into_bytes();
                for _ in 0..rng.below(3) {
                    let at = rng.below(cand.len());
                    match rng.below(4) {
                        0 if cand.len() > 1 => {
                            cand.remove(at);
                        }
                        1 => cand.insert(at, rng.pick(alphabet)),
                        2 if at + 1 < cand.len() => cand.swap(at, at + 1),
                        _ => cand[at] = rng.pick(alphabet),
                    }
                }
                if rng.below(2) == 0 {
                    cand.make_ascii_uppercase();
                }
                let want = naive_typo(&entries, &cand);
                assert_eq!(
                    m.typo_match(&cand),
                    want,
                    "round {round} candidate {:?}",
                    String::from_utf8_lossy(&cand)
                );
            }
        }
    }

    /// The spec, read literally: compare with every text-kind proxy of similar length that
    /// starts with the same letter; the one closest within the limit, unless two tie.
    fn naive_typo(entries: &[(EntityKind, String, String)], candidate: &[u8]) -> Option<usize> {
        let len = candidate.len();
        if len < 6 || !candidate[0].is_ascii_alphanumeric() {
            return None;
        }
        let lowered = String::from_utf8_lossy(candidate).to_ascii_lowercase();
        let limit = if len < 12 { 1 } else { 2 };
        let mut best: Option<(usize, usize)> = None;
        let mut tied = false;
        for (id, (kind, proxy, _)) in entries.iter().enumerate() {
            if !matches!(kind, Email | Person | UrlCredential)
                || proxy.len().abs_diff(len) > 2
                || proxy.as_bytes()[0].to_ascii_lowercase() != lowered.as_bytes()[0]
            {
                continue;
            }
            let distance = strsim::osa_distance(&lowered, &proxy.to_ascii_lowercase());
            if distance > limit {
                continue;
            }
            match best {
                Some((d, _)) if distance > d => {}
                Some((d, _)) if distance == d => tied = true,
                _ => {
                    best = Some((distance, id));
                    tied = false;
                }
            }
        }
        best.filter(|_| !tied).map(|(_, id)| id)
    }

    #[test]
    fn component_first_name_followed_by_another_name_is_somebody_else() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        assert_eq!(restore(&r, "Haley Brooks called"), "Haley Brooks called");
        assert_eq!(restore(&r, "HALEY BROOKS called"), "HALEY BROOKS called");
        assert_eq!(
            restore(&r, "Haley van der Brooks called"),
            "Haley van der Brooks called"
        );
        // Nothing new and capitalized follows.
        assert_eq!(restore(&r, "Haley brooks called"), "Jeroen brooks called");
        assert_eq!(restore(&r, "Haley, Brooks called"), "Jeroen, Brooks called");
        assert_eq!(restore(&r, "Haley. Brooks called"), "Jeroen. Brooks called");
        assert_eq!(restore(&r, "Haley's Brooks"), "Jeroen's Brooks");
        assert_eq!(restore(&r, "Haley The end"), "Jeroen The end");
        assert_eq!(restore(&r, "Haley I think"), "Jeroen I think");
        assert_eq!(restore(&r, "Haley van brooks"), "Jeroen van brooks");
        assert_eq!(restore(&r, "Haley called Brooks"), "Jeroen called Brooks");
        // The same person's other name part is no stranger.
        assert_eq!(restore(&r, "Haley Zessen called"), "Jeroen Vries called");
        // A last name is judged on its own.
        assert_eq!(restore(&r, "Anna Zessen"), "Anna Vries");
        // Only a first name asks: the word must follow within reach.
        let far = format!("Haley {}Brooks", "van ".repeat(40));
        assert_eq!(restore(&r, &far), far.replacen("Haley", "Jeroen", 1));
    }

    #[test]
    fn component_first_name_followed_by_an_apostrophe_particle_is_somebody_else() {
        // `'t` is a particle like `van`, though its apostrophe is not a letter.
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        assert_eq!(restore(&r, "Haley 't Hart called"), "Haley 't Hart called");
        assert_eq!(
            restore(&r, "Haley 't van Hart called"),
            "Haley 't van Hart called"
        );
        assert_eq!(
            restore(&r, "Haley 't brooks called"),
            "Jeroen 't brooks called"
        );
    }

    #[test]
    fn component_first_name_check_applies_to_one_word_names() {
        let r = restorer(&[(Person, "Haley-Marian", "Jeroen")]);
        assert_eq!(restore(&r, "Haley Brooks called"), "Haley Brooks called");
        assert_eq!(restore(&r, "Haley called"), "Jeroen called");
        assert_eq!(restore(&r, "Marian Brooks called"), "Jeroen Brooks called");
    }

    /// A scope where `Haley` and `Lotte` are unique first names, so the first-name check runs.
    const VETO: Entries<'static> = &[
        (Person, "Haley van Zessen", "Jeroen de Vries"),
        (Person, "Lotte-Fleming", "Piet"),
        (Email, "lotte.wilson56@thistlemill.nl", "jeroen@test.nl"),
    ];

    const VETO_WORDS: [&str; 24] = [
        "Haley",
        "Lotte",
        "Brooks",
        "Zessen",
        "Fleming",
        "van",
        "der",
        "de",
        "said",
        "The",
        "I",
        "and",
        "Haley.",
        "Haley's",
        "Lotte,",
        "Brooks.",
        ",",
        ".",
        "-",
        "\n",
        "(",
        ")",
        "Zessen's",
        "lotte.wilson56",
    ];

    fn veto_text(rng: &mut Rng, words: usize) -> String {
        let mut text = String::new();
        for _ in 0..words {
            text.push_str(rng.pick(&VETO_WORDS));
            text.push_str(rng.pick(&[" ", " ", " ", "  ", ""]));
        }
        text
    }

    #[test]
    fn streaming_equals_one_shot_with_first_name_checks() {
        let r = restorer(VETO);
        let mut s = restorer(VETO);
        let mut rng = Rng(0x7E57_0F0F_1234_ABCD);
        let (mut vetoed, mut restored) = (0, 0);
        for round in 0..300 {
            let words = 3 + rng.below(40);
            let text = veto_text(&mut rng, words);
            let (want, count) = match &r.matcher {
                Some(m) => m.restore_serial(text.as_bytes(), &[]),
                None => panic!("no matcher"),
            };
            restored += count;
            vetoed += text.matches("Haley Brooks").count();
            for mode in [1, 2, 3, 4] {
                let chunks = chunked(&mut rng, text.as_bytes(), mode);
                let (got, n, _) = stream(&mut s, &chunks);
                assert_eq!(got, want, "round {round} mode {mode} text {text:?}");
                assert_eq!(n, count, "round {round} mode {mode} text {text:?}");
            }
        }
        assert!(vetoed > 5 && restored > 300, "{vetoed} {restored}");
    }

    #[test]
    fn splitting_a_text_with_first_name_checks_changes_nothing() {
        let r = restorer(VETO);
        let Some(m) = &r.matcher else {
            panic!("no matcher");
        };
        let mut rng = Rng(0x5911_7C0D_E5AF_E123);
        let mut split = 0;
        for _ in 0..60 {
            let mut text = String::new();
            while text.len() < 10_000 {
                text.push_str(&veto_text(&mut rng, 30));
                text.push('\n');
            }
            let want = m.restore_serial(text.as_bytes(), &[]);
            for parts in [2, 5, 40] {
                if m.cuts(text.as_bytes(), parts, &[]).len() > 2 {
                    split += 1;
                }
                assert_eq!(
                    apply(text.as_bytes(), &m.plan_split(text.as_bytes(), parts, &[])),
                    want,
                    "parts {parts}"
                );
            }
        }
        assert!(split > 100, "texts were hardly ever split: {split}");
    }

    #[test]
    fn first_name_checks_are_the_same_at_every_alignment() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        let mut s = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        for text in [
            "Haley van der Brooks",
            "Haley van der brooks",
            "Haley Zessen",
        ] {
            for pad in 0..100 {
                let text = format!(
                    "{}{text} called, {}",
                    "x ".repeat(pad / 2),
                    "z. ".repeat(30)
                );
                let want = r.restore_with(text.as_bytes(), NONE);
                for size in [1, 2, 3, 7, 16] {
                    let chunks: Vec<&[u8]> = text.as_bytes().chunks(size).collect();
                    let (got, _, _) = stream(&mut s, &chunks);
                    assert_eq!(got, want, "pad {pad} size {size} {text:?}");
                }
            }
        }
    }

    #[test]
    fn odd_scopes_never_panic_and_still_stream_consistently() {
        const PIECES: [&str; 28] = [
            "a", "Haley", "jan", "ZESSEN", "x", "-", ".", "_", "@", "+", "'", " ", "  ", "\n", "é",
            "ñ", "😀", "0", "42", ":", "(", ")", "van", "de", "Brooks", "test.nl", "’s", "/",
        ];
        const KINDS: [EntityKind; 6] = [Email, Person, UrlCredential, Phone, Secret, Iban];
        let mut rng = Rng(0x0DDB_A11C_0FFE_E042);
        let piece =
            |rng: &mut Rng| -> String { (0..rng.below(8)).map(|_| rng.pick(&PIECES)).collect() };
        for round in 0..150 {
            let mut entries: Vec<(EntityKind, String, String)> = Vec::new();
            for _ in 0..=rng.below(12) {
                let kind = rng.pick(&KINDS);
                let (proxy, original) = (piece(&mut rng), piece(&mut rng));
                entries.push((kind, proxy, original));
            }
            let scope: Vec<(EntityKind, &str, &str)> = entries
                .iter()
                .map(|(k, p, o)| (*k, p.as_str(), o.as_str()))
                .collect();
            let r = restorer(&scope);
            let mut s = restorer(&scope);
            for _ in 0..8 {
                let mut text = String::new();
                for _ in 0..rng.below(40) {
                    if rng.below(5) == 0 {
                        text.push_str(&entries[rng.below(entries.len())].1);
                    } else {
                        text.push_str(rng.pick(&PIECES));
                    }
                }
                let want = r.restore_with(text.as_bytes(), NONE);
                assert_plan_sound(&r, text.as_bytes());
                for mode in [1, 2, 3, 4] {
                    let chunks = chunked(&mut rng, text.as_bytes(), mode);
                    let (got, _, _) = stream(&mut s, &chunks);
                    assert_eq!(
                        String::from_utf8_lossy(&got),
                        String::from_utf8_lossy(&want),
                        "round {round} mode {mode} scope {scope:?} text {text:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_token_without_a_place_to_cut_is_cut_inside_once_it_grows_huge() {
        let mut s = restorer(&[
            (Email, "jeroen@test.nl", "jan@acme.nl"),
            (Phone, "+31 6 29554691", "+31 6 12345678"),
        ]);
        let chunk = vec![b'a'; 1 << 16];
        let mut out = s.feed_with(b"first jeroen@test.nl ", NONE);
        let mut most_held = 0;
        for _ in 0..40 {
            out.extend(s.feed_with(&chunk, NONE));
            most_held = most_held.max(s.tail.len());
        }
        out.extend(s.feed_with(b" last jeroen@test.nl and +31 6 29554691", NONE));
        out.extend(s.flush_with(NONE));
        assert!(most_held <= super::MAX_HELD + chunk.len(), "{most_held}");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("first jan@acme.nl a"), "{}", &text[..40]);
        assert!(text.ends_with("a last jan@acme.nl and +31 6 12345678"));
        assert_eq!(out.len(), 18 + 40 * chunk.len() + 36);
        assert_eq!(s.restored_count(), 3);
    }

    // --- a finder: the vault's own lookup, in the same pass ---------------------------

    /// The vault's lookup as a test can make it: these proxies, in the case they are written
    /// in, wherever one stands alone (no ASCII letter or digit next to it). Of the ones that
    /// start together the longest is found.
    struct Lookup(&'static [(&'static str, &'static str)]);

    impl ProxyFinder for Lookup {
        fn longest(&self) -> usize {
            self.0
                .iter()
                .map(|(proxy, _)| proxy.len())
                .max()
                .unwrap_or(0)
        }

        fn find(&self, text: &[u8]) -> Vec<Replacement> {
            let alnum = |at: Option<usize>| {
                at.and_then(|at| text.get(at))
                    .is_some_and(u8::is_ascii_alphanumeric)
            };
            let mut found = Vec::new();
            let mut at = 0;
            while at < text.len() {
                let hit = self
                    .0
                    .iter()
                    .filter(|(proxy, _)| {
                        text[at..].starts_with(proxy.as_bytes())
                            && !alnum(at.checked_sub(1))
                            && !alnum(Some(at + proxy.len()))
                    })
                    .max_by_key(|(proxy, _)| proxy.len());
                if let Some((proxy, original)) = hit {
                    found.push(Replacement {
                        start: at,
                        end: at + proxy.len(),
                        with: (*original).into(),
                    });
                    at += proxy.len();
                } else {
                    at += 1;
                }
            }
            found
        }
    }

    fn restore_with(r: &Restorer, text: &str, finder: &dyn ProxyFinder) -> String {
        String::from_utf8_lossy(&r.restore_with(text.as_bytes(), finder)).into_owned()
    }

    /// [`stream`] with a finder.
    fn stream_with(
        r: &mut Restorer,
        chunks: &[&[u8]],
        finder: &dyn ProxyFinder,
    ) -> (Vec<u8>, usize, usize) {
        let before = r.restored_count();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(r.feed_with(chunk, finder));
        }
        let early = out.len();
        out.extend(r.flush_with(finder));
        (out, r.restored_count() - before, early)
    }

    #[test]
    fn a_value_that_is_a_proxy_of_another_is_restored_once() {
        // The vault holds `Pieter Jansen` as the stand-in for `Jan Smit`, and `Haley Brooks` as
        // the stand-in for somebody who really is called `Pieter Jansen`: text equal to an
        // earlier proxy is masked like any other value.
        const VAULT: &[(&str, &str)] = &[
            ("Pieter Jansen", "Jan Smit"),
            ("Haley Brooks", "Pieter Jansen"),
        ];
        let finder = Lookup(VAULT);
        let reply = "Pieter Jansen and Haley Brooks";
        let want = "Jan Smit and Pieter Jansen";
        // What was sent to the host, or only part of it.
        for scope in [
            &[
                (Person, "Pieter Jansen", "Jan Smit"),
                (Person, "Haley Brooks", "Pieter Jansen"),
            ][..],
            &[(Person, "Haley Brooks", "Pieter Jansen")][..],
            &[(Person, "Pieter Jansen", "Jan Smit")][..],
            &[][..],
        ] {
            let r = restorer(scope);
            assert_eq!(restore_with(&r, reply, &finder), want, "{scope:?}");
            let mut s = restorer(scope);
            for mode in 1..4 {
                let chunks = chunked(&mut Rng(7), reply.as_bytes(), mode);
                let (got, restored, _) = stream_with(&mut s, &chunks, &finder);
                assert_eq!(String::from_utf8_lossy(&got), want, "{scope:?} mode {mode}");
                assert_eq!(restored, 2);
            }
        }

        // Two passes, one after the other, would not: the second reads the `Pieter Jansen` the
        // first wrote as the stand-in it also is.
        let r = restorer(&[(Person, "Pieter Jansen", "Jan Smit")]);
        let first = Engine::apply(reply, &Lookup(VAULT).find(reply.as_bytes()));
        assert_eq!(first, want);
        assert_eq!(restore(&r, &first), "Jan Smit and Jan Smit");
    }

    /// Proxies the vault knows and the scope of `RICH` does not. One stands for a value that is a
    /// proxy of the scope (`Haley Brooks`), one starts like another and one like a scope proxy.
    const KNOWN: &[(&str, &str)] = &[
        ("Mirjam Peeters", "Haley Brooks"),
        ("zx-99-q", "real code"),
        ("(555) 987-6543", "(202) 555-0199"),
        ("Haley Brooks Jr", "Brooks Junior"),
        ("Mirjam", "M."),
        (
            "long.vault.only.address.with.many.parts@some.very.long.domain.example",
            "x@y.nl",
        ),
    ];

    /// `text` with some of `known` put in between its words.
    fn with_known(rng: &mut Rng, text: &str) -> String {
        let mut out = String::new();
        for word in text.split(' ') {
            if rng.below(4) == 0 {
                out.push_str(rng.pick(KNOWN).0);
                out.push_str(rng.pick(&[" ", " ", "", ", ", "-"]));
            }
            out.push_str(word);
            out.push(' ');
        }
        out
    }

    #[test]
    fn streaming_with_a_finder_equals_one_shot_for_random_texts_and_chunkings() {
        let finder = Lookup(KNOWN);
        let r = restorer(RICH);
        let mut s = restorer(RICH);
        let mut rng = Rng(0xF1D0_5EED_0000_1234);
        let (mut found, mut early_bytes) = (0, 0);
        for round in 0..200 {
            let base = random_text(&mut rng);
            let text = with_known(&mut rng, &base);
            let want = r.restore_with(text.as_bytes(), &finder);
            found += finder.find(text.as_bytes()).len();
            for mode in 0..5 {
                let chunks = chunked(&mut rng, text.as_bytes(), mode);
                let (got, restored, early) = stream_with(&mut s, &chunks, &finder);
                assert_eq!(
                    String::from_utf8_lossy(&got),
                    String::from_utf8_lossy(&want),
                    "round {round} mode {mode} text {text:?}"
                );
                assert_eq!(
                    restored,
                    restored_by(&r, &finder, &text),
                    "round {round} mode {mode}"
                );
                early_bytes += early;
            }
        }
        assert!(found > 200, "{found} proxies of the finder in the texts");
        assert!(
            early_bytes > 0,
            "everything was held to the end of the streams"
        );
    }

    /// How many replacements a one-shot restore makes: those of the plan.
    fn restored_by(r: &Restorer, finder: &dyn ProxyFinder, text: &str) -> usize {
        let found = finder.find(text.as_bytes());
        let found = edits_of(&found, text.as_bytes());
        match &r.matcher {
            Some(m) => m.restore_serial(text.as_bytes(), &found).1,
            None => found.len(),
        }
    }

    #[test]
    fn splitting_a_text_with_a_finder_changes_nothing() {
        let finder = Lookup(KNOWN);
        let r = restorer(RICH);
        let Some(m) = &r.matcher else {
            panic!("no matcher");
        };
        let mut rng = Rng(0x5911_7F1D_0000_0042);
        let (mut split, mut found_edits) = (0, 0);
        for _ in 0..30 {
            let mut text = String::new();
            while text.len() < 20_000 {
                let base = random_text(&mut rng);
                text.push_str(&with_known(&mut rng, &base));
                text.push('\n');
            }
            let found = finder.find(text.as_bytes());
            let found = edits_of(&found, text.as_bytes());
            found_edits += found.len();
            let want = m.restore_serial(text.as_bytes(), &found);
            for parts in [2, 3, 8, 40] {
                if m.cuts(text.as_bytes(), parts, &found).len() > 2 {
                    split += 1;
                }
                assert_eq!(
                    apply(
                        text.as_bytes(),
                        &m.plan_split(text.as_bytes(), parts, &found)
                    ),
                    want,
                    "parts {parts}"
                );
            }
        }
        assert!(split > 0, "no text was ever split");
        assert!(found_edits > 1000, "{found_edits} proxies of the finder");
    }

    #[test]
    fn the_plan_of_a_restore_is_what_it_makes() {
        let finder = Lookup(KNOWN);
        let r = restorer(RICH);
        let mut rng = Rng(0x71A4_0000_0000_0007);
        let mut planned = 0;
        for _ in 0..100 {
            let base = random_text(&mut rng);
            let text = with_known(&mut rng, &base);
            let plan = r.plan_with(text.as_bytes(), &finder);
            planned += plan.len();
            assert_eq!(
                Engine::apply(&text, &plan).as_bytes(),
                r.restore_with(text.as_bytes(), &finder)
            );
            let mut end = 0;
            for rep in &plan {
                assert!(rep.start >= end && rep.start < rep.end && rep.end <= text.len());
                end = rep.end;
            }
        }
        assert!(planned > 200, "{planned} replacements in the texts");
        // Without a scope, the finder's alone.
        let text = "Mirjam Peeters, zx-99-q and Mirjam";
        let plan = restorer(&[]).plan_with(text.as_bytes(), &finder);
        assert_eq!(Engine::apply(text, &plan), "Haley Brooks, real code and M.");
    }

    #[test]
    fn a_finder_restores_a_stream_without_a_scope_and_holds_back_its_longest_proxy() {
        let finder = Lookup(&[("Mirjam Peeters", "Haley Brooks"), ("zx-99-q", "real code")]);
        let text = format!("{} zx-99-q and Mirjam Peeters.", "word ".repeat(20));
        let want = format!("{} real code and Haley Brooks.", "word ".repeat(20));
        let r = restorer(&[]);
        assert_eq!(restore_with(&r, &text, &finder), want);
        let mut s = restorer(&[]);
        for mode in 1..5 {
            let chunks = chunked(&mut Rng(11), text.as_bytes(), mode);
            let (got, restored, early) = stream_with(&mut s, &chunks, &finder);
            assert_eq!(String::from_utf8_lossy(&got), want, "mode {mode}");
            assert_eq!(restored, 2);
            assert!(early > 0, "mode {mode}: held to the end of the stream");
        }

        // The longest proxy and 16 bytes more are held back, however the text goes; without a
        // finder nothing is.
        let filler = "w ".repeat(60);
        let early = s.feed_with(filler.as_bytes(), &finder);
        assert!(!early.is_empty());
        assert!(
            filler.len() - early.len() >= finder.longest() + 16,
            "{}",
            early.len()
        );
        assert_eq!(early.len() + s.flush_with(&finder).len(), filler.len());
        assert_eq!(s.feed_with(filler.as_bytes(), NONE).len(), filler.len());
        // A finder that has nothing to find at all is not asked.
        assert_eq!(s.feed_with(b"abc", &Lookup(&[])), b"abc");
    }

    #[test]
    fn where_the_finder_and_the_scope_overlap_the_first_and_longer_one_wins() {
        let person = restorer(&[(Person, "Haley Brooks", "Anna Boer")]);
        // Together at the start: the longer one.
        let finds = Lookup(&[("Haley Brooks Jr", "Brooks Junior")]);
        assert_eq!(
            restore_with(&person, "Haley Brooks Jr said", &finds),
            "Brooks Junior said"
        );
        let scoped = restorer(&[(Person, "Haley Brooks Jr", "Anna Boer")]);
        let finds = Lookup(&[("Haley Brooks", "Somebody")]);
        assert_eq!(
            restore_with(&scoped, "Haley Brooks Jr said", &finds),
            "Anna Boer said"
        );

        // The same span: the finder's.
        let finds = Lookup(&[("Haley Brooks", "Somebody Else")]);
        assert_eq!(
            restore_with(&person, "Haley Brooks said", &finds),
            "Somebody Else said"
        );

        // Starting first: that one, and what is left of the other is not restored.
        let phone = restorer(&[(Phone, "+31 6 29554691", "+31 6 12345678")]);
        let finds = Lookup(&[("xx +31", "Y")]);
        assert_eq!(
            restore_with(&phone, "xx +31 6 29554691", &finds),
            "Y 6 29554691"
        );
        let finds = Lookup(&[("6 29554691 yy", "Z")]);
        assert_eq!(
            restore_with(&phone, "+31 6 29554691 yy", &finds),
            "+31 6 12345678 yy"
        );
    }

    #[test]
    fn what_a_finder_reports_outside_the_text_or_twice_is_ignored() {
        struct Odd;
        impl ProxyFinder for Odd {
            fn longest(&self) -> usize {
                9
            }

            fn find(&self, _text: &[u8]) -> Vec<Replacement> {
                let rep = |start, end, with: &str| Replacement {
                    start,
                    end,
                    with: with.into(),
                };
                // Out of order, overlapping, empty, inside out and past the end.
                vec![
                    rep(8, 11, "C"),
                    rep(0, 3, "A"),
                    rep(1, 4, "B"),
                    rep(5, 5, "-"),
                    rep(9, 8, "-"),
                    rep(8, 99, "-"),
                ]
            }
        }
        let r = restorer(&[]);
        assert_eq!(restore_with(&r, "abc def ghi", &Odd), "A def C");
        let mut s = restorer(&[]);
        let mut out = s.feed_with(b"abc def ghi", &Odd);
        out.extend(s.flush_with(&Odd));
        assert_eq!(String::from_utf8_lossy(&out), "A def C");
    }

    // --- what the random texts do not reach --------------------------------------------

    /// What `text` becomes streamed byte by byte, and what it becomes in one go.
    fn streamed_and_whole(
        entries: Entries<'_>,
        finder: &dyn ProxyFinder,
        text: &str,
    ) -> (String, String) {
        let whole = restorer(entries).restore_with(text.as_bytes(), finder);
        let mut s = restorer(entries);
        let chunks: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
        let (streamed, _, _) = stream_with(&mut s, &chunks, finder);
        (
            String::from_utf8_lossy(&streamed).into_owned(),
            String::from_utf8_lossy(&whole).into_owned(),
        )
    }

    #[test]
    fn a_typo_sequence_that_ends_in_a_run_glued_to_a_match_is_the_same_streamed_and_whole() {
        // The run after `Zesen` is punctuation up to the phone number, which arrives in pieces.
        let scope: Entries<'_> = &[
            (Person, "Haley van Zessen", "Jeroen de Vries"),
            (Phone, "+31 6 29554691", "+31 6 12345678"),
        ];
        for dashes in [1, 5, 45, 90] {
            let text = format!("Haley van Zesen{}+31 6 29554691 called", "-".repeat(dashes));
            let (streamed, whole) = streamed_and_whole(scope, NONE, &text);
            assert_eq!(streamed, whole, "{dashes} dashes");
        }
    }

    #[test]
    fn a_long_word_after_a_first_name_is_judged_the_same_streamed_and_whole() {
        // The word ends exactly where the name check stops looking, 48 bytes after `Haley`, and
        // a phone number starts right there.
        let scope: Entries<'_> = &[
            (Person, "Haley van Zessen", "Jeroen de Vries"),
            (Phone, "(555) 123-4567", "(202) 555-0100"),
        ];
        let word = "Brooks-Fleming-Smits-Jansen-Bakkers-Vissers-Vos";
        assert_eq!(word.len(), 47);
        for (glue, tail) in [("", "(555) 123-4567 called"), (", ", "said hi")] {
            let text = format!("Haley {word}{glue}{tail}");
            let (streamed, whole) = streamed_and_whole(scope, NONE, &text);
            assert_eq!(streamed, whole, "{text:?}");
        }
    }

    #[test]
    fn splitting_a_text_where_a_long_word_ends_at_the_name_reach_changes_nothing() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        let Some(m) = &r.matcher else {
            panic!("no matcher");
        };
        let text = b"Haley Brooks-Fleming-Smits-Jansen-Bakkers-Vissers-Vos, said hi";
        // Cut at the comma, which is where the check stops looking.
        let cuts = m.cuts(text, 2, &[]);
        assert_eq!(cuts, [0, 53, text.len()]);
        assert_eq!(
            apply(text, &m.plan_split(text, 2, &[])),
            m.restore_serial(text, &[])
        );
    }

    #[test]
    fn bytes_that_are_not_utf8_do_not_make_a_stream_grow_without_end() {
        let mut s = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        let chunk = vec![0x80u8; 1 << 16];
        let mut most_held = 0;
        let mut out = Vec::new();
        for _ in 0..40 {
            out.extend(s.feed_with(&chunk, NONE));
            most_held = most_held.max(s.tail.len());
        }
        out.extend(s.flush_with(NONE));
        assert!(most_held <= super::MAX_HELD + chunk.len(), "{most_held}");
        assert_eq!(out.len(), 40 * chunk.len());
    }

    #[test]
    fn a_proxy_that_starts_with_punctuation_is_found_only_where_the_finder_would_find_it() {
        // The finder wants a break before a proxy, and `x` is none: cutting the stream at the
        // bracket would give the proxy one.
        let finder = Lookup(&[("(555) 987-6543", "(202) 555-0199")]);
        let text = "x(555) 987-6543 and so on and so on and so on and so on";
        let (streamed, whole) = streamed_and_whole(&[], &finder, text);
        assert_eq!(whole, text);
        assert_eq!(streamed, whole);
        let text = "x (555) 987-6543 and so on and so on and so on and so on";
        let (streamed, whole) = streamed_and_whole(&[], &finder, text);
        assert!(whole.starts_with("x (202) 555-0199 and"));
        assert_eq!(streamed, whole);
    }

    #[test]
    fn a_first_name_before_a_curly_particle_and_a_name_is_somebody_else() {
        let r = restorer(&[(Person, "Haley van Zessen", "Jeroen de Vries")]);
        for text in ["Haley 't Hart called", "Haley \u{2019}t Hart called"] {
            assert_eq!(restore(&r, text), text);
        }
        assert_eq!(restore(&r, "Haley \u{2019}t said"), "Jeroen \u{2019}t said");
    }

    #[test]
    fn proxies_that_differ_only_in_case_and_share_an_original_keep_their_typos_and_name_parts() {
        let r = restorer(&[
            (Person, "Haley Brooks", "Anna Boer"),
            (Person, "HALEY BROOKS", "Anna Boer"),
        ]);
        assert_eq!(restore(&r, "Haley Brook called"), "Anna Boer called");
        assert_eq!(restore(&r, "Brooks said"), "Boer said");
    }

    #[test]
    fn a_proxy_with_a_non_ascii_apostrophe_is_matched_exactly_and_not_as_a_typo() {
        let r = restorer(&[(Person, "Haley \u{2019}t Zessen", "Jeroen de Vries")]);
        assert_eq!(
            restore(&r, "Haley \u{2019}t Zessen called"),
            "Jeroen de Vries called"
        );
        // The typo tier counts bytes, and `\u{2019}` is three of them: the whole name is not
        // matched as a typo, only its parts are restored.
        assert_eq!(
            restore(&r, "Haley 't Zessen called"),
            "Jeroen 't Vries called"
        );
    }
}
