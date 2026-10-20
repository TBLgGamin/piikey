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
//!    replacement.
//! 2. **Typo.** A token (`[A-Za-z0-9@._+'-]+`), or up to six tokens separated by single
//!    spaces, of at least 6 bytes that is within one edit (two from 12 bytes up) of a
//!    scoped *text* proxy (email, person, URL credential): Optimal String Alignment
//!    distance, same first letter, length within 2. Two proxies at the best distance
//!    make the match ambiguous and nothing is replaced. Number-like kinds (phones, IBANs,
//!    cards, ...) are never fuzzy-matched: one wrong digit is a different number.
//! 3. **Component.** A bare token equal to one part of a scoped person or email proxy: the
//!    first or last name, either end of a one-word name (`Haley` of `Haley-Marian`), or the
//!    local part of an email. It becomes the same part of the original, but only when that
//!    part belongs to exactly one proxy, has three or more letters, is no [`STOPWORDS`]
//!    entry, and is capitalized when the proxy's part is (`Long` the surname, not `long`
//!    the word). Name parts are not proxies of their own, so `Haley Brooks` in the scope
//!    makes a bare `Haley` ambiguous. A first name that another capitalized word follows
//!    (`Haley Brooks`, `Haley van der Berg`) is a different person and stays, unless that
//!    word is a part of the same proxy (`Haley Zessen`).
//!
//! Whitespace must match: a name wrapped over two lines or split by a double space is only
//! restored part by part, and a hyphen that wraps a word across lines is not undone
//! (`Zes-\nsen` stays as it is).
//!
//! [`Restorer::feed`] restores a stream chunk by chunk and emits the same bytes as one
//! [`Restorer::restore`] over the whole text, however the text is chunked (unless one token
//! runs past 1 MiB: that is cut anyway).

use std::collections::hash_map::Entry as MapEntry;
use std::collections::{HashMap, HashSet};
use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Input, MatchKind};
use rayon::prelude::*;

use crate::detect::EntityKind;
use crate::{Error, Result};

mod stopwords;

pub use stopwords::STOPWORDS;

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

/// Name particles. They stay verbatim in person proxies, so they never stand for a name.
const PARTICLES: [&str; 21] = [
    "van", "de", "der", "den", "het", "von", "zu", "du", "da", "la", "le", "di", "del", "bin",
    "ibn", "al", "el", "ter", "ten", "'t", "op",
];

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
/// or over a chunked stream.
pub struct Restorer {
    /// `None` when the scope has nothing to restore: text then passes through untouched.
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

    /// One-shot restore.
    #[must_use]
    pub fn restore(&self, text: &[u8]) -> Vec<u8> {
        self.matcher
            .as_ref()
            .map_or_else(|| text.to_vec(), |m| m.restore(text).0)
    }

    /// Streaming: returns the restored output that is safe to emit now.
    ///
    /// The end of the stream is held back while later bytes could still complete or change a
    /// mention there: always the last `2 * longest proxy + 8` bytes, and more while a token
    /// or a run of space-separated words is still open (a token longer than 1 MiB is cut
    /// anyway). [`Self::flush`] releases the rest.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(matcher) = &self.matcher else {
            return chunk.to_vec();
        };
        self.tail.extend_from_slice(chunk);
        // A cut at `i` needs `len - i > margin`: every mention that could straddle it is
        // then fully visible, and so is the context its boundary checks look at.
        let limit = self.tail.len().saturating_sub(matcher.margin);
        let floor = self.probed.max(1);
        if limit <= floor {
            return Vec::new();
        }
        let mut edits = None;
        let mut hi = limit;
        let cut = loop {
            if hi <= floor {
                break None;
            }
            let Some(at) = self.tail[floor..hi].iter().rposition(|&b| is_cut_byte(b)) else {
                break None;
            };
            let at = floor + at;
            let edits = edits.get_or_insert_with(|| matcher.plan(&self.tail));
            match straddler(edits, at) {
                None => break Some(at),
                Some(start) => hi = start + 1,
            }
        };
        let cut = match cut {
            None if self.tail.len() > MAX_HELD => {
                let edits = edits.get_or_insert_with(|| matcher.plan(&self.tail));
                forced_cut(&self.tail, edits, limit)
            }
            cut => cut,
        };
        let (Some(cut), Some(edits)) = (cut, edits) else {
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

    /// Emits everything held back.
    pub fn flush(&mut self) -> Vec<u8> {
        let tail = std::mem::take(&mut self.tail);
        self.probed = 0;
        let Some(matcher) = &self.matcher else {
            return tail;
        };
        let (out, restored) = matcher.restore_serial(&tail);
        self.restored += restored;
        out
    }

    /// Replacements made so far by `feed`/`flush`.
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

/// The compiled scope.
struct Matcher {
    /// Exact tier: every proxy, ASCII case-insensitive, leftmost-longest.
    ac: AhoCorasick,
    /// Indexed by Aho-Corasick pattern id.
    entries: Vec<Entry>,
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

impl Matcher {
    fn build(raw: Vec<ScopeEntry>) -> Result<Option<Self>> {
        let mut seen = HashSet::new();
        let mut entries: Vec<Entry> = Vec::with_capacity(raw.len());
        let mut text_kind = Vec::new();
        let mut components = Components::default();
        let mut longest = 0;
        for scoped in raw {
            let ScopeEntry {
                kind,
                proxy,
                original,
            } = scoped;
            if proxy.is_empty() || original.is_empty() || proxy == original {
                continue;
            }
            let lower = proxy.to_ascii_lowercase();
            if !seen.insert(lower.clone()) {
                continue;
            }
            let id = entries.len();
            longest = longest.max(lower.len());
            text_kind.push(matches!(
                kind,
                EntityKind::Email | EntityKind::Person | EntityKind::UrlCredential
            ));
            match kind {
                EntityKind::Person => components.add_person(id, &proxy, &original),
                EntityKind::Email => components.add_email(id, &proxy, &original),
                _ => {}
            }
            entries.push(Entry {
                lower: lower.into_boxed_str(),
                original,
            });
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(entries.iter().map(|e| e.lower.as_bytes()))
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
            typo,
            components,
            longest,
            margin: (longest * 2 + 8).max(NAME_REACH + 8),
        }))
    }

    /// Restores a whole text; returns it with the number of replacements. A long text is
    /// split across rayon tasks at places where the pieces cannot influence each other.
    fn restore(&self, text: &[u8]) -> (Vec<u8>, usize) {
        let parts = if text.len() > PARALLEL_FROM {
            text.len() / CHUNK
        } else {
            1
        };
        self.restore_split(text, parts)
    }

    /// [`Self::restore`] over about `parts` pieces; always equal to [`Self::restore_serial`].
    fn restore_split(&self, text: &[u8], parts: usize) -> (Vec<u8>, usize) {
        let cuts = self.cuts(text, parts);
        if cuts.len() <= 2 {
            return self.restore_serial(text);
        }
        let pieces: Vec<(Vec<u8>, usize)> = cuts
            .par_windows(2)
            .map(|w| self.restore_serial(&text[w[0]..w[1]]))
            .collect();
        let mut out = Vec::with_capacity(pieces.iter().map(|(piece, _)| piece.len()).sum());
        let mut restored = 0;
        for (piece, n) in &pieces {
            out.extend_from_slice(piece);
            restored += n;
        }
        (out, restored)
    }

    /// `0`, then up to `parts - 1` offsets near the even split points where `text` can be
    /// cut, then `text.len()`.
    fn cuts(&self, text: &[u8], parts: usize) -> Vec<usize> {
        let mut cuts = vec![0];
        for k in 1..parts {
            let from = text.len() / parts * k;
            let to = text.len().min(from + SPLIT_SEARCH);
            if let Some(at) = (from..to).find(|&i| self.can_cut(text, i))
                && cuts.last().is_some_and(|&last| at > last)
            {
                cuts.push(at);
            }
        }
        cuts.push(text.len());
        cuts
    }

    /// Whether a text can be cut at `at` without changing the result: `text[at]` is a byte
    /// no token or space-separated run can contain, and no proxy occurs near enough to
    /// straddle it, whether or not it would be accepted.
    fn can_cut(&self, text: &[u8], at: usize) -> bool {
        let b = text[at];
        let window = at.saturating_sub(self.longest)..text.len().min(at + self.longest);
        is_cut_byte(b)
            && b != b' '
            && matches!(self.ac.try_find(Input::new(text).range(window)), Ok(None))
    }

    /// Restores a whole text on this thread.
    fn restore_serial(&self, text: &[u8]) -> (Vec<u8>, usize) {
        let edits = self.plan(text);
        let mut out = Vec::with_capacity(text.len());
        let mut pos = 0;
        for edit in &edits {
            out.extend_from_slice(&text[pos..edit.start]);
            out.extend_from_slice(edit.with.as_bytes());
            pos = edit.end;
        }
        out.extend_from_slice(&text[pos..]);
        (out, edits.len())
    }

    /// Every replacement in `text`, in order and without overlap.
    ///
    /// The exact tier cuts the text into matches and the gaps between them; the typo and
    /// component tiers only look inside the gaps.
    fn plan(&self, text: &[u8]) -> Vec<Edit<'_>> {
        let mut edits = Vec::new();
        let mut scratch = Vec::new();
        let mut gap = 0;
        let mut from = 0;
        while let Ok(Some(found)) = self.ac.try_find(Input::new(text).range(from..)) {
            let (start, end) = (found.start(), found.end());
            if bounded(text, start, end) {
                self.plan_gap(text, gap, start, &mut edits, &mut scratch);
                edits.push(Edit {
                    start,
                    end,
                    with: &self.entries[found.pattern().as_usize()].original,
                });
                gap = end;
                from = end;
            } else {
                // Glued to a longer word; a match that starts inside it may still be fine.
                from = start + 1;
            }
        }
        self.plan_gap(text, gap, text.len(), &mut edits, &mut scratch);
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
            } else if let Some(edit) = self.component_at(text, hi, (a, b), (start, end), scratch) {
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
                runs[count] = (after + 1, run_end(text, after + 1, hi));
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

    /// Component tier for the token core `text[start..end]` of the run `run`, in the gap that
    /// ends at `hi`.
    fn component_at<'a>(
        &'a self,
        text: &[u8],
        hi: usize,
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
                && !(*first_name && end == run.1 && self.name_follows(text, run.1, hi, *entry)) =>
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
    /// Looks at most [`NAME_REACH`] bytes ahead, and not past `hi`. A word cut off by that
    /// reach is not judged.
    fn name_follows(&self, text: &[u8], from: usize, hi: usize, entry: usize) -> bool {
        let reach = hi.min(from + NAME_REACH);
        let mut at = from;
        for _ in 0..=MAX_PARTICLES {
            if at + 1 >= reach || text[at] != b' ' || !is_token(text[at + 1]) {
                return false;
            }
            let end = run_end(text, at + 1, reach);
            if end == reach && reach < hi {
                return false;
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

/// Longest proxy [`within`] checks, in bytes; the rows live on the stack.
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

fn is_particle(token: &str) -> bool {
    PARTICLES.iter().any(|p| p.eq_ignore_ascii_case(token))
}

/// Where to cut a stream that has no valid cut but grew past [`MAX_HELD`]: the last position
/// before `limit` that no edit straddles and that is not inside a UTF-8 sequence.
fn forced_cut(tail: &[u8], edits: &[Edit<'_>], limit: usize) -> Option<usize> {
    let mut at = limit.checked_sub(1)?;
    while at > 0 {
        if let Some(start) = straddler(edits, at) {
            at = start;
        } else if tail[at] & 0xC0 == 0x80 {
            at -= 1;
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Restorer, STOPWORDS, Scope, ScopeEntry};
    use crate::detect::EntityKind::{
        self, Email, Iban, Ipv6, Person, Phone, Secret, UrlCredential,
    };

    type Entries<'a> = &'a [(EntityKind, &'a str, &'a str)];

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
        String::from_utf8_lossy(&r.restore(text.as_bytes())).into_owned()
    }

    /// Everything `feed` and `flush` emit for `chunks`, the replacements made, and how many
    /// bytes came out before the flush. A flushed restorer starts a new stream.
    fn stream(r: &mut Restorer, chunks: &[&[u8]]) -> (Vec<u8>, usize, usize) {
        let before = r.restored_count();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(r.feed(chunk));
        }
        let early = out.len();
        out.extend(r.flush());
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
    fn empty_scope_changes_nothing() {
        let mut r = restorer(&[]);
        assert_eq!(restore(&r, "Haley van Zessen"), "Haley van Zessen");
        assert_eq!(r.feed(b"abc"), b"abc");
        assert!(r.flush().is_empty());
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
        assert_eq!(r.feed(b"Hello "), b"Hello ");
        assert_eq!(r.feed(b"world"), b"world");
        assert!(r.flush().is_empty());
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
            let out = s.feed(line.as_bytes());
            early |= !out.is_empty();
            emitted.extend(out);
        }
        assert!(early, "nothing was emitted before the end of the stream");
        emitted.extend(s.flush());
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
        let mut out = s.feed(format!("{filler}jeroen@te").as_bytes());
        out.extend(s.feed(b"st.nl and more"));
        out.extend(s.flush());
        assert_eq!(
            String::from_utf8_lossy(&out),
            format!("{filler}jan@acme.nl and more")
        );
    }

    #[test]
    fn long_token_runs_are_not_rescanned_per_chunk() {
        let mut s = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        let chunk = vec![b'a'; 1024];
        let mut out = s.feed(b"start ");
        for _ in 0..400 {
            out.extend(s.feed(&chunk));
        }
        out.extend(s.feed(b" end"));
        out.extend(s.flush());
        assert_eq!(out.len(), 6 + 400 * 1024 + 4);
    }

    #[test]
    fn emitted_pieces_are_valid_utf8_when_the_stream_is() {
        let mut s = restorer(&[(Email, "jeroen@test.nl", "jan@acme.nl")]);
        let text = "héllo wörld — jeroen@test.nl 😀 ünïcödé, ".repeat(30);
        for chunk in text.as_bytes().chunks(1) {
            let piece = s.feed(chunk);
            assert!(std::str::from_utf8(&piece).is_ok());
        }
        assert!(std::str::from_utf8(&s.flush()).is_ok());
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
                Some(m) => m.restore(text.as_bytes()),
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
            let want = r.restore(&text);
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
                let want = r.restore(text.as_bytes());
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

    /// The edits a plan returns are in order, disjoint and inside the text.
    fn assert_plan_sound(r: &Restorer, text: &[u8]) {
        let Some(m) = &r.matcher else {
            return;
        };
        let edits = m.plan(text);
        let mut end = 0;
        for edit in &edits {
            assert!(edit.start >= end && edit.start < edit.end && edit.end <= text.len());
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
            let want = m.restore_serial(text.as_bytes());
            for parts in [2, 3, 8, 40] {
                if m.cuts(text.as_bytes(), parts).len() > 2 {
                    split += 1;
                }
                assert_eq!(
                    m.restore_split(text.as_bytes(), parts),
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
        assert!(m.cuts(&text, text.len() / super::CHUNK).len() > 2);
        assert_eq!(m.restore(&text), m.restore_serial(&text));
        assert_eq!(r.restore(&text), m.restore_serial(&text).0);
    }

    #[test]
    fn debug_output_never_shows_originals() {
        let mut r = restorer(&[(Email, "jeroen@test.nl", "secret.original@example.org")]);
        let _ = r.feed(b"jeroen@test.nl");
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
                Some(m) => m.restore_serial(text.as_bytes()),
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
            let want = m.restore_serial(text.as_bytes());
            for parts in [2, 5, 40] {
                if m.cuts(text.as_bytes(), parts).len() > 2 {
                    split += 1;
                }
                assert_eq!(
                    m.restore_split(text.as_bytes(), parts),
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
                let want = r.restore(text.as_bytes());
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
                let want = r.restore(text.as_bytes());
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
        let mut out = s.feed(b"first jeroen@test.nl ");
        let mut most_held = 0;
        for _ in 0..40 {
            out.extend(s.feed(&chunk));
            most_held = most_held.max(s.tail.len());
        }
        out.extend(s.feed(b" last jeroen@test.nl and +31 6 29554691"));
        out.extend(s.flush());
        assert!(most_held <= super::MAX_HELD + chunk.len(), "{most_held}");
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("first jan@acme.nl a"), "{}", &text[..40]);
        assert!(text.ends_with("a last jan@acme.nl and +31 6 12345678"));
        assert_eq!(out.len(), 18 + 40 * chunk.len() + 36);
        assert_eq!(s.restored_count(), 3);
    }
}
