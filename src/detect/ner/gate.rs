//! What keeps the model from running when it cannot find anything new, and the cache of what it
//! found.
//!
//! Requests carry plenty of text that is no prose: JSON keys, enum values, model names, ids. And
//! chat clients resend the whole conversation every turn, so most texts of a request were
//! already seen. [`worth_running`] and [`Cache`] spare the model both.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use crate::{
    detect::{EntityKind, Span},
    restore::STOPWORDS,
};

/// Texts the cache remembers.
pub(super) const CACHE_CAPACITY: usize = 8192;

/// A span the model found in one text, after the type became a kind and before the caller's
/// kind filter and already-taken spans apply. Offsets are bytes of that text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RawSpan {
    pub(super) start: u32,
    pub(super) end: u32,
    pub(super) kind: EntityKind,
}

/// False when the model has nothing to add to `text`, given the spans earlier detectors `taken`
/// (sorted, disjoint). The model needs the sentence around a name to find it, so words are never
/// cut out of a text: a text runs whole or not at all.
///
/// - A text without whitespace or any capital is a single token: a key, an enum value, a model
///   name, an id. No sentence, no name.
/// - A text whose words are all stopwords, or already taken, or too short to be anything, has
///   nothing left to find.
pub(super) fn worth_running(text: &str, taken: &[Span]) -> bool {
    let loose = text.chars().any(|c| c.is_whitespace() || c.is_uppercase());
    loose && candidate_words(text).any(|(start, end)| !overlaps(taken, start, end))
}

/// Byte ranges of the words that could be an entity: runs of letters and digits (`'` and `-`
/// inside them are part of the word) with two or more characters, a letter among them, that are
/// no stopword.
fn candidate_words(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut at = 0;
    std::iter::from_fn(move || {
        while let Some((start, end)) = next_word(text, at) {
            at = end;
            let word = &text[start..end];
            if word.chars().nth(1).is_some()
                && word.chars().any(char::is_alphabetic)
                && !is_stopword(word)
            {
                return Some((start, end));
            }
        }
        None
    })
}

/// The first word that starts at or after `from`.
fn next_word(text: &str, from: usize) -> Option<(usize, usize)> {
    let start = from + text.get(from..)?.find(char::is_alphanumeric)?;
    let mut end = start;
    let mut chars = text[start..].char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let joins = matches!(c, '\'' | '\u{2019}' | '-')
            && chars.peek().is_some_and(|(_, next)| next.is_alphanumeric());
        if !(c.is_alphanumeric() || joins) {
            break;
        }
        end = start + i + c.len_utf8();
    }
    Some((start, end))
}

/// ASCII-case-insensitive lookup in the sorted stopword list, without building a lowercase copy.
fn is_stopword(word: &str) -> bool {
    STOPWORDS
        .binary_search_by(|stop| {
            stop.bytes()
                .cmp(word.bytes().map(|byte| byte.to_ascii_lowercase()))
        })
        .is_ok()
}

/// True when `start..end` shares a byte with a span of `taken`, which is sorted and disjoint.
fn overlaps(taken: &[Span], start: usize, end: usize) -> bool {
    let next = taken.partition_point(|span| span.end <= start);
    taken.get(next).is_some_and(|span| span.start < end)
}

/// The cache key of a text: its BLAKE3 hash. The cache keeps no text.
pub(super) fn key(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

/// What the model found per text, newest `CACHE_CAPACITY` texts. First in, first out: the model
/// is deterministic, so an entry never goes stale; the bound only caps memory.
///
/// The value is shared, so a hit costs a pointer copy and no lock is held while it is used.
#[derive(Debug)]
pub(super) struct Cache {
    map: HashMap<[u8; 32], Arc<[RawSpan]>>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl Cache {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub(super) fn get(&self, key: &[u8; 32]) -> Option<Arc<[RawSpan]>> {
        self.map.get(key).cloned()
    }

    /// Remembers `spans` for `key`, forgetting the oldest entry when full. An entry that is
    /// already there is replaced and keeps its place in the order.
    pub(super) fn insert(&mut self, key: [u8; 32], spans: Arc<[RawSpan]>) {
        if self.capacity == 0 {
            return;
        }
        if self.map.insert(key, spans).is_some() {
            return;
        }
        self.order.push_back(key);
        while self.map.len() > self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.map.remove(&oldest);
        }
    }

    pub(super) fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize) -> Span {
        Span {
            start,
            end,
            kind: EntityKind::Email,
        }
    }

    fn raw(start: u32, end: u32) -> RawSpan {
        RawSpan {
            start,
            end,
            kind: EntityKind::Person,
        }
    }

    #[test]
    fn single_lowercase_tokens_are_skipped() {
        for text in [
            "assistant",
            "gpt-4o",
            "gpt-4o-mini",
            "content_filter",
            "text-embedding-3-small",
            "3f2b8c1e-5a4d-4e6f-9b1a-0c2d3e4f5a6b",
        ] {
            assert!(!worth_running(text, &[]), "{text}");
        }
    }

    #[test]
    fn texts_of_stopwords_alone_are_skipped() {
        assert!(!worth_running("the and of", &[]));
        assert!(!worth_running("Ik heb een", &[]));
        assert!(
            !worth_running("a b c", &[]),
            "one-letter words are no entities"
        );
        assert!(
            !worth_running("12 345", &[]),
            "numbers alone have no letters"
        );
        assert!(!worth_running("   ", &[]));
        assert!(!worth_running("", &[]));
    }

    #[test]
    fn a_word_that_could_be_a_name_runs_the_model() {
        assert!(worth_running("call jan", &[]));
        assert!(worth_running("Jan", &[]), "one capitalised word");
        assert!(worth_running("Mijn naam is Jeroen de Vries", &[]));
        assert!(
            worth_running("in l'Haÿ-les-Roses", &[]),
            "the only free word is one with an apostrophe and hyphens"
        );
        assert!(worth_running("Zażółć gęślą jaźń", &[]));
    }

    #[test]
    fn stopwords_match_whatever_their_case() {
        assert!(!worth_running("THE AND OF", &[]));
        assert!(!worth_running("The And Of", &[]));
        assert!(worth_running("The Hague", &[]));
    }

    #[test]
    fn words_taken_by_an_earlier_detector_do_not_count() {
        // Capitals keep the single-token rule out of the way: only `taken` is tested here.
        let text = "Jan.Jansen@Acme.nl";
        assert!(worth_running(text, &[]));
        assert!(!worth_running(text, &[span(0, text.len())]));
        assert!(
            !worth_running(text, &[span(0, 3), span(4, text.len())]),
            "the dot between two taken spans is no word"
        );
        assert!(
            worth_running(text, &[span(0, 3)]),
            "`Jansen` and the rest are still free"
        );

        let sentence = "Mail Jan.Jansen@Acme.nl please";
        let email = span(5, 23);
        assert_eq!(&sentence[email.start..email.end], "Jan.Jansen@Acme.nl");
        assert!(worth_running(sentence, &[email]), "`Mail` is still free");
        assert!(
            !worth_running("Jan.Jansen@Acme.nl is", &[span(0, 18)]),
            "`is` is a stopword"
        );
    }

    #[test]
    fn a_word_touching_a_taken_span_is_free_only_outside_it() {
        // `Jan` is 0..3; a span from 3 on does not touch it.
        assert!(worth_running("Jan@x", &[span(3, 5)]));
        // A span that starts inside a word takes the word.
        assert!(!worth_running("Jan@x", &[span(1, 5)]));
    }

    #[test]
    fn word_scanning_joins_inner_apostrophes_and_hyphens_only() {
        let text = "l'Haÿ-les-Roses, -x- 'y'";
        let words: Vec<&str> = candidate_words(text).map(|(s, e)| &text[s..e]).collect();
        assert_eq!(words, ["l'Haÿ-les-Roses"]);
    }

    #[test]
    fn every_stopword_is_found_and_neighbours_are_not() {
        for stop in STOPWORDS {
            assert!(is_stopword(stop), "{stop}");
        }
        assert!(!is_stopword("thee"));
        assert!(!is_stopword("th"));
        assert!(!is_stopword(""));
        assert!(!is_stopword("théé"));
    }

    #[test]
    fn identical_text_shares_one_cache_entry() {
        let mut cache = Cache::new(CACHE_CAPACITY);
        let a = key("Mijn naam is Jeroen de Vries");
        assert_eq!(a, key("Mijn naam is Jeroen de Vries"));
        assert_ne!(a, key("Mijn naam is Jeroen de Vries."));
        assert!(cache.get(&a).is_none());

        let spans: Arc<[RawSpan]> = vec![raw(12, 28)].into();
        cache.insert(a, Arc::clone(&spans));
        let hit = cache.get(&a);
        assert!(hit.as_ref().is_some_and(|hit| Arc::ptr_eq(hit, &spans)));
        let again = cache.get(&a);
        assert!(again.is_some_and(|again| Arc::ptr_eq(&again, &spans)));
    }

    #[test]
    fn a_text_without_findings_is_cached_too() {
        let mut cache = Cache::new(4);
        let k = key("nothing to see");
        cache.insert(k, Vec::new().into());
        assert!(cache.get(&k).is_some_and(|hit| hit.is_empty()));
    }

    #[test]
    fn the_oldest_entry_goes_first_and_a_replacement_keeps_its_place() {
        let mut cache = Cache::new(3);
        let keys: Vec<[u8; 32]> = (0..5).map(|n| key(&format!("text {n}"))).collect();
        for k in &keys[..3] {
            cache.insert(*k, Vec::new().into());
        }
        // Replacing the oldest does not make it newer.
        cache.insert(keys[0], vec![raw(0, 4)].into());
        assert_eq!(cache.len(), 3);
        cache.insert(keys[3], Vec::new().into());
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&keys[0]).is_none(), "the oldest was evicted");
        assert!(cache.get(&keys[1]).is_some());
        cache.insert(keys[4], Vec::new().into());
        assert!(cache.get(&keys[1]).is_none());
        for k in &keys[2..] {
            assert!(cache.get(k).is_some());
        }
    }

    #[test]
    fn clearing_forgets_everything_and_a_zero_capacity_stores_nothing() {
        let mut cache = Cache::new(8);
        let k = key("x");
        cache.insert(k, Vec::new().into());
        cache.clear();
        assert!(cache.get(&k).is_none());
        assert_eq!(cache.len(), 0);

        let mut none = Cache::new(0);
        none.insert(k, Vec::new().into());
        assert!(none.get(&k).is_none());
    }
}
