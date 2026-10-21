//! Issued-proxy detector: finds the proxies the vault issued, wherever they occur.
//!
//! No pattern describes the proxy of a listed kind (a name, an address, an organization or any
//! other kind the detection model finds), so the engine looks for the proxies themselves. For the
//! patterned kinds the regexes find a proxy by its shape, but not always: a proxy can have a shape
//! the patterns do not describe, or sit where a longer match of another pattern hides it. Looking
//! for the proxies themselves finds them all the same, so the engine does that for every kind
//! when it restores a text.
//!
//! The search is literal, with an Aho-Corasick automaton and in the case the proxies were issued
//! in. A match counts only when it stands alone, that is when the bytes just before and after it
//! are not ASCII letters or digits: `Haley` is found in `Haley's` and `(Haley)` but not in
//! `Haleys`. Anything that is not ASCII counts as a break, so a proxy written straight against
//! Chinese or Japanese text is found too, and one against an accented letter (`Haleyé`) is found as
//! well, which restores more than needed but never less.
//!
//! The automaton reports every occurrence, not only the leftmost-longest one, so a proxy that is a
//! prefix of another (`Haley` and `Haley Brooks`) is still found when the longer one does not
//! stand alone (`Haley Brooksy`). Among the occurrences that stand alone, the leftmost wins and the
//! longest of those that start together.
//!
//! A proxy is matched with the spacing it was issued with, so one that came back with a line break
//! or a double space inside it is not found.
//!
//! A vault that keeps growing does not need an automaton rebuilt over all its proxies each time:
//! the proxies are kept in a few *levels*, one automaton each, and [`IssuedProxies::plus`] adds a
//! level to the ones there are. The levels are searched together and give the same spans as one
//! automaton over all the proxies.
//!
//! [`Words`] is the other way round: given the text that is going to stay as it is, it tells
//! whether a candidate proxy would be found in it.
//!
//! Texts of `PARALLEL_FROM` bytes or more (see the detector module) are scanned in parallel
//! pieces, like the regex detector does.

use std::{cmp::Reverse, collections::HashSet, fmt, sync::Arc};

use aho_corasick::{AhoCorasick, Input};
use rayon::prelude::*;

use super::{CHUNK, Detector, EntityKind, Mode, PARALLEL_FROM, Span, build_failed};
use crate::Result;

/// Finds the proxies a vault issued, each as the kind it was issued for.
#[derive(Default)]
pub(crate) struct IssuedProxies {
    /// Disjoint sets of proxies, one automaton each. None when there is nothing to look for.
    levels: Vec<Arc<Level>>,
}

/// The proxies of one automaton.
struct Level {
    ac: AhoCorasick,
    /// The kind of each pattern of `ac`, by pattern index.
    kinds: Vec<EntityKind>,
}

// Hand-written: a derived `Debug` would dump the whole automaton, and the proxies are what the
// vault keeps behind its key.
impl fmt::Debug for IssuedProxies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proxies: usize = self.levels.iter().map(|level| level.kinds.len()).sum();
        f.debug_struct("IssuedProxies")
            .field("proxies", &proxies)
            .finish_non_exhaustive()
    }
}

impl IssuedProxies {
    /// Detector for `proxies`, each with the kind it was issued for. They are taken as given:
    /// same case and spacing, no trimming or validation; only empty entries are dropped. No
    /// proxies at all is fine and finds nothing.
    ///
    /// # Errors
    /// Matcher build failure.
    pub(crate) fn new(proxies: &[(EntityKind, &str)]) -> Result<Self> {
        let (kinds, patterns): (Vec<EntityKind>, Vec<&str>) = proxies
            .iter()
            .copied()
            .filter(|(_, proxy)| !proxy.is_empty())
            .unzip();
        if patterns.is_empty() {
            return Ok(Self::default());
        }
        // `Standard` match semantics are the default and the only ones that allow the
        // overlapping search `spans` needs.
        let ac = AhoCorasick::new(&patterns).map_err(build_failed)?;
        Ok(Self {
            levels: vec![Arc::new(Level { ac, kinds })],
        })
    }

    /// These proxies and `more`, which must be none of them, as one more level. The levels
    /// already there are shared, not rebuilt.
    ///
    /// # Errors
    /// Matcher build failure.
    pub(crate) fn plus(&self, more: &[(EntityKind, &str)]) -> Result<Self> {
        let mut levels = self.levels.clone();
        levels.extend(Self::new(more)?.levels);
        Ok(Self { levels })
    }

    /// The proxies of both, shared and not rebuilt.
    #[must_use]
    pub(crate) fn union(&self, other: &Self) -> Self {
        Self {
            levels: self.levels.iter().chain(&other.levels).cloned().collect(),
        }
    }

    /// True when there is nothing to look for.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.levels.is_empty()
    }

    /// Where proxies stand alone in `text`, sorted and never overlapping.
    pub(crate) fn spans(&self, text: &str) -> Vec<Span> {
        let chunk = if text.len() < PARALLEL_FROM {
            usize::MAX
        } else {
            CHUNK
        };
        let mut spans: Vec<Span> = self
            .levels
            .iter()
            .flat_map(|level| {
                standalone_hits(&level.ac, text, chunk).into_iter().map(
                    move |(start, end, pattern)| Span {
                        start,
                        end,
                        kind: level.kinds[pattern],
                    },
                )
            })
            .collect();
        // Of the occurrences that start together the longest comes first.
        spans.sort_unstable_by_key(|span| (span.start, Reverse(span.end)));
        let mut taken = 0;
        spans.retain(|span| {
            let free = span.start >= taken;
            if free {
                taken = span.end;
            }
            free
        });
        spans
    }
}

impl Detector for IssuedProxies {
    fn detect(&self, text: &str, _mode: Mode) -> Vec<Span> {
        self.spans(text)
    }
}

/// Every occurrence of a pattern of `ac` in `text` that stands alone, as `(start, end, pattern)`
/// in no particular order. A text longer than `chunk` bytes is scanned in parallel pieces: a piece
/// owns the occurrences that start inside it and searches on past its end as far as the longest
/// pattern reaches, so an occurrence that runs over the end is found whole, and by that piece
/// only.
fn standalone_hits(ac: &AhoCorasick, text: &str, chunk: usize) -> Vec<(usize, usize, usize)> {
    if text.len() <= chunk {
        return scan(ac, text, 0, text.len()).collect();
    }
    let starts: Vec<usize> = (0..text.len()).step_by(chunk).collect();
    starts
        .par_iter()
        .flat_map_iter(|&lo| scan(ac, text, lo, (lo + chunk).min(text.len())))
        .collect()
}

/// The occurrences that start in `lo..hi` and stand alone.
fn scan<'a>(
    ac: &'a AhoCorasick,
    text: &'a str,
    lo: usize,
    hi: usize,
) -> impl Iterator<Item = (usize, usize, usize)> + 'a {
    let stop = hi.saturating_add(ac.max_pattern_len()).min(text.len());
    ac.find_overlapping_iter(Input::new(text).span(lo..stop))
        .map(|hit| (hit.start(), hit.end(), hit.pattern().as_usize()))
        .filter(move |&(start, end, _)| start < hi && stands_alone(text, start, end))
}

/// True when `text[start..end]` is not part of a longer word: the bytes on
/// either side of it, if there are any, are not ASCII letters or digits.
fn stands_alone(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    let after = bytes.get(end);
    !before.is_some_and(u8::is_ascii_alphanumeric) && !after.is_some_and(u8::is_ascii_alphanumeric)
}

/// Pieces of text that are going to stay as they are, and whether a string stands alone in one
/// of them: whether [`IssuedProxies`] with that string as a proxy would find it there. The edge of
/// a piece counts as a break.
///
/// Asked about many strings (the candidates for a new proxy) it avoids searching the text for
/// each. A string stands alone in a piece only if every run of ASCII letters and digits in it is
/// a whole run of that piece (the byte before such a run is a break, and so is the byte after
/// it), so a string with a run that no piece has is not in them, and a string that is one run
/// is in them when it is a run of one.
// No `Debug`: the pieces are the user's text.
pub(crate) struct Words<'a> {
    pieces: Vec<&'a str>,
    /// The runs of ASCII letters and digits of `pieces`.
    runs: HashSet<&'a str>,
}

impl<'a> Words<'a> {
    #[must_use]
    pub(crate) fn new(pieces: Vec<&'a str>) -> Self {
        let runs = pieces.iter().flat_map(|&piece| runs(piece)).collect();
        Self { pieces, runs }
    }

    /// True when `candidate` stands alone in a piece.
    #[must_use]
    pub(crate) fn contains(&self, candidate: &str) -> bool {
        let mut words = runs(candidate);
        match (words.next(), words.next()) {
            // No word to look up: only the text itself can tell.
            (None, _) => self.stands_in_a_piece(candidate),
            // One run and nothing around it: that is a run of a piece or it is not there.
            (Some(only), None) if only.len() == candidate.len() => self.runs.contains(only),
            (Some(first), second) => {
                std::iter::once(first)
                    .chain(second)
                    .chain(words)
                    .all(|run| self.runs.contains(run))
                    && self.stands_in_a_piece(candidate)
            }
        }
    }

    fn stands_in_a_piece(&self, candidate: &str) -> bool {
        self.pieces.iter().any(|piece| stands_in(piece, candidate))
    }
}

/// The maximal runs of ASCII letters and digits of `text`.
fn runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|run| !run.is_empty())
}

/// True when `needle` occurs in `piece` and stands alone there.
fn stands_in(piece: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(at) = piece[from..].find(needle) {
        let start = from + at;
        if stands_alone(piece, start, start + needle.len()) {
            return true;
        }
        // The next occurrence may overlap this one.
        from = start + piece[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERSON: EntityKind = EntityKind::Person;

    /// A detector for `names`, all issued as people.
    fn people(names: &[&str]) -> Result<IssuedProxies> {
        let proxies: Vec<(EntityKind, &str)> = names.iter().map(|&name| (PERSON, name)).collect();
        IssuedProxies::new(&proxies)
    }

    /// The text of every span `names` find in `text`.
    fn found<'a>(names: &[&str], text: &'a str) -> Result<Vec<&'a str>> {
        let spans = people(names)?.detect(text, Mode::Anonymize);
        Ok(spans.iter().map(|s| &text[s.start..s.end]).collect())
    }

    #[test]
    fn proxies_match_only_in_the_case_they_were_issued_in() -> Result<()> {
        let names = ["Jeroen de Vries", "haley"];
        let text =
            "Call JEROEN DE VRIES or Haley, not jeroen de vries, but Jeroen de Vries or haley.";
        assert_eq!(found(&names, text)?, ["Jeroen de Vries", "haley"]);
        let spans = people(&names)?.detect(text, Mode::Anonymize);
        assert!(spans.iter().all(|s| s.kind == PERSON));
        assert_eq!(Some(spans[0].start), text.find("Jeroen de Vries"));
        Ok(())
    }

    #[test]
    fn each_proxy_is_reported_as_the_kind_it_was_issued_for() -> Result<()> {
        let detector = IssuedProxies::new(&[
            (EntityKind::PostalAddress, "Straat 9\nAmsterdam"),
            (EntityKind::Person, "Haley Brooks"),
            (EntityKind::OrganizationName, "Acme Group"),
            (EntityKind::HealthData, "Health-7KQX"),
        ])?;
        let text = "Haley Brooks, Straat 9\nAmsterdam, works at Acme Group (Health-7KQX).";
        let spans = detector.detect(text, Mode::Deanonymize);
        let seen: Vec<(EntityKind, &str)> = spans
            .iter()
            .map(|s| (s.kind, &text[s.start..s.end]))
            .collect();
        assert_eq!(
            seen,
            [
                (EntityKind::Person, "Haley Brooks"),
                (EntityKind::PostalAddress, "Straat 9\nAmsterdam"),
                (EntityKind::OrganizationName, "Acme Group"),
                (EntityKind::HealthData, "Health-7KQX"),
            ]
        );
        Ok(())
    }

    #[test]
    fn both_modes_find_the_same_spans() -> Result<()> {
        let d = people(&["Jeroen de Vries"])?;
        let text = "x Jeroen de Vries y";
        assert_eq!(
            d.detect(text, Mode::Anonymize),
            d.detect(text, Mode::Deanonymize)
        );
        assert_eq!(d.detect(text, Mode::Anonymize).len(), 1);
        Ok(())
    }

    #[test]
    fn only_proxies_that_stand_alone_match() -> Result<()> {
        for (text, expected) in [
            ("Jan", vec!["Jan"]),
            ("Hi Jan.", vec!["Jan"]),
            ("Jan's bike", vec!["Jan"]),
            ("(Jan)", vec!["Jan"]),
            ("Jan\nPiet", vec!["Jan"]),
            ("Jan_x", vec!["Jan"]),
            ("Jan-Willem", vec!["Jan"]),
            ("Jan Jan", vec!["Jan", "Jan"]),
            ("Janssen", vec![]),
            ("Jans", vec![]),
            ("aJan", vec![]),
            ("Jan2", vec![]),
            ("2Jan", vec![]),
            ("", vec![]),
        ] {
            assert_eq!(found(&["Jan"], text)?, expected, "{text:?}");
        }
        Ok(())
    }

    #[test]
    fn the_longest_proxy_wins_and_a_shorter_one_is_the_fallback() -> Result<()> {
        let names = ["Jan", "Jan Willem"];
        assert_eq!(found(&names, "Jan Willem")?, ["Jan Willem"]);
        assert_eq!(found(&names, "Jan Willem and Jan")?, ["Jan Willem", "Jan"]);
        // The longer proxy does not stand alone here; the shorter one does.
        assert_eq!(found(&names, "Jan Willemse")?, ["Jan"]);
        assert_eq!(found(&names, "Jan Willem2")?, ["Jan"]);
        Ok(())
    }

    #[test]
    fn spans_are_sorted_and_never_overlap() -> Result<()> {
        // `Jan Willem` and `Willem de Vries` overlap in this text: the leftmost one wins.
        let names = [
            "Willem de Vries",
            "Jan Willem",
            "Anna",
            "Anna Maria",
            "Piet",
        ];
        let text = "Piet, Jan Willem de Vries, Anna Maria and Anna";
        let spans = people(&names)?.detect(text, Mode::Anonymize);
        let words: Vec<&str> = spans.iter().map(|s| &text[s.start..s.end]).collect();
        assert_eq!(words, ["Piet", "Jan Willem", "Anna Maria", "Anna"]);
        assert!(spans.windows(2).all(|w| w[0].end <= w[1].start));
        assert_eq!(found(&names, "Willem de Vries")?, ["Willem de Vries"]);
        Ok(())
    }

    #[test]
    fn no_proxies_find_nothing() -> Result<()> {
        assert!(found(&[], "Jeroen")?.is_empty());
        assert!(found(&[""], "Jeroen")?.is_empty());
        assert!(found(&["Jeroen"], "")?.is_empty());
        assert!(
            IssuedProxies::new(&[])?
                .detect("x", Mode::Anonymize)
                .is_empty()
        );
        assert!(
            IssuedProxies::new(&[(EntityKind::Email, "")])?
                .detect("x", Mode::Anonymize)
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn non_ascii_proxies_match_exactly() -> Result<()> {
        let names = ["Zoë de Vries", "José"];
        let text = "zoë de vries, ZOË DE VRIES, Zoë de Vries, JOSÉ";
        assert_eq!(found(&names, text)?, ["Zoë de Vries"]);
        for (text, expected) in [
            ("José,", vec!["José"]),
            ("Josée", vec![]),
            ("¡José!", vec!["José"]),
        ] {
            assert_eq!(found(&names, text)?, expected, "{text:?}");
        }
        Ok(())
    }

    #[test]
    fn only_ascii_letters_and_digits_join_a_proxy_to_the_word_around_it() -> Result<()> {
        // Chinese and Japanese text has no spaces: a proxy right against it must be found.
        for (text, expected) in [
            ("我给Jan发了邮件", vec!["Jan"]),
            ("今日はJanさんと", vec!["Jan"]),
            ("Jané", vec!["Jan"]),
            ("éJan", vec!["Jan"]),
            ("Jan2", vec![]),
            ("xJan", vec![]),
        ] {
            assert_eq!(found(&["Jan"], text)?, expected, "{text:?}");
        }
        Ok(())
    }

    #[test]
    fn many_proxies_still_match() -> Result<()> {
        // More patterns than the automaton keeps as a DFA.
        let letter = |n: u32| char::from(b'a' + u8::try_from(n % 26).unwrap_or(0));
        let owned: Vec<String> = (0..300u32)
            .map(|i| format!("Qx{}{}", letter(i), letter(i / 26)))
            .collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        let text = "so Qxaa met Qxzb and Qxmk, but not Qxaaa or Qxa";
        assert_eq!(found(&names, text)?, ["Qxaa", "Qxzb", "Qxmk"]);
        Ok(())
    }

    #[test]
    fn matching_is_exact_in_case_and_spacing() -> Result<()> {
        let d = people(&["Haley de Zessen", "Haley", "Marian  X"])?;
        let text = "HALEY, Haley, haley de zessen, Haley de Zessen, Marian  X, Marian X";
        let spans = d.detect(text, Mode::Deanonymize);
        let words: Vec<&str> = spans.iter().map(|s| &text[s.start..s.end]).collect();
        assert_eq!(words, ["Haley", "Haley de Zessen", "Marian  X"]);
        Ok(())
    }

    #[test]
    fn a_chunked_scan_finds_what_a_single_scan_finds() -> Result<()> {
        // Proxies of different lengths and kinds, so that some run over every piece boundary.
        let d = IssuedProxies::new(&[
            (PERSON, "Jan"),
            (PERSON, "Jan Willem"),
            (EntityKind::PersonAlias, "Willem de Vries"),
            (EntityKind::Location, "Zoë"),
            (EntityKind::OrganizationName, "Anna Maria"),
        ])?;
        let [level] = d.levels.as_slice() else {
            panic!("one level of proxies");
        };
        let ac = &level.ac;
        let text = "Jan Willem de Vries, Zoë and Anna Maria met Jan. Janssen left; ".repeat(30);
        let mut whole = standalone_hits(ac, &text, usize::MAX);
        whole.sort_unstable();
        assert!(whole.len() > 100, "{}", whole.len());
        for chunk in [1, 2, 3, 5, 7, 11, 13, 64, 100, 257, 1000] {
            let mut pieces = standalone_hits(ac, &text, chunk);
            pieces.sort_unstable();
            assert_eq!(pieces, whole, "pieces of {chunk} bytes");
        }
        Ok(())
    }

    #[test]
    fn long_texts_are_split_into_pieces_and_give_the_same_spans() -> Result<()> {
        let unit = "Jan Willem de Vries and Zoë met Anna Maria on Janssen street, Jan. ";
        let units = (PARALLEL_FROM + CHUNK) / unit.len() + 1;
        let text = unit.repeat(units);
        assert!(text.len() >= PARALLEL_FROM + CHUNK);
        let d = people(&["Jan", "Jan Willem", "Willem de Vries", "Zoë", "Anna Maria"])?;
        let spans = d.detect(&text, Mode::Anonymize);
        let words: Vec<&str> = spans.iter().map(|s| &text[s.start..s.end]).collect();
        assert_eq!(words.len(), 4 * units);
        for unit_words in words.chunks(4) {
            assert_eq!(unit_words, ["Jan Willem", "Zoë", "Anna Maria", "Jan"]);
        }
        Ok(())
    }

    #[test]
    fn debug_output_hides_the_proxies() -> Result<()> {
        let shown = format!("{:?}", people(&["Haley de Zessen"])?);
        assert!(
            !shown.contains("Haley") && !shown.contains("Zessen"),
            "{shown}"
        );
        Ok(())
    }

    /// Small deterministic generator (xorshift64*), so tests need no crate.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            let n = u64::try_from(n).unwrap_or(u64::MAX);
            usize::try_from(self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) % n).unwrap_or(0)
        }

        /// A string of `1..=max` characters of `alphabet`.
        fn string(&mut self, alphabet: &[&str], max: usize) -> String {
            (0..=self.below(max))
                .map(|_| alphabet[self.below(alphabet.len())])
                .collect()
        }
    }

    #[test]
    fn levels_find_what_one_automaton_over_all_the_proxies_finds() -> Result<()> {
        // Proxies that overlap one another, so that the leftmost-longest choice crosses levels.
        let all: Vec<(EntityKind, &str)> = vec![
            (PERSON, "Jan"),
            (PERSON, "Jan Willem"),
            (PERSON, "Willem de Vries"),
            (PERSON, "de Vries"),
            (EntityKind::Location, "Anna"),
            (EntityKind::OrganizationName, "Anna Maria"),
            (EntityKind::HealthData, "Maria"),
            (EntityKind::Phone, "+31 6 12"),
        ];
        let words = [
            "Jan ", "Willem ", "de ", "Vries", "Anna ", "Maria", "+31 6 12", ", ", "x",
        ];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let texts: Vec<String> = (0..150).map(|_| rng.string(&words, 9)).collect();
        let single = IssuedProxies::new(&all)?;
        for split in 0..1u32 << all.len() {
            let pick = |wanted: bool| -> Vec<(EntityKind, &str)> {
                all.iter()
                    .enumerate()
                    .filter(|(i, _)| ((split >> i) & 1 == 1) == wanted)
                    .map(|(_, &proxy)| proxy)
                    .collect()
            };
            let (first, second) = (pick(true), pick(false));
            let added = IssuedProxies::new(&first)?.plus(&second)?;
            let joined = IssuedProxies::new(&first)?.union(&IssuedProxies::new(&second)?);
            for text in &texts {
                let expected = single.spans(text);
                assert_eq!(added.spans(text), expected, "{split:b} plus, {text:?}");
                assert_eq!(joined.spans(text), expected, "{split:b} union, {text:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn a_level_added_to_a_set_shares_the_levels_it_has() -> Result<()> {
        let base = IssuedProxies::new(&[(PERSON, "Jan")])?;
        let grown = base.plus(&[(PERSON, "Piet")])?;
        assert_eq!(grown.levels.len(), 2);
        assert!(Arc::ptr_eq(&base.levels[0], &grown.levels[0]));
        assert_eq!(grown.spans("Jan en Piet").len(), 2);
        // Nothing to add, nothing added; nothing to start from, one level.
        assert_eq!(base.plus(&[])?.levels.len(), 1);
        assert_eq!(
            IssuedProxies::default()
                .plus(&[(PERSON, "Jan")])?
                .levels
                .len(),
            1
        );
        assert!(IssuedProxies::default().is_empty() && IssuedProxies::new(&[])?.is_empty());
        assert!(!base.is_empty());
        Ok(())
    }

    #[test]
    fn words_tell_whether_a_string_stands_alone_in_the_text_that_stays() {
        let pieces = vec![
            "born 1968, but 1984 stays",
            "see Jan-Willem.",
            "x\nAmsterdam 5",
            "a ( . ) b",
        ];
        let words = Words::new(pieces);
        for (candidate, expected) in [
            // One run: a whole run of a piece or not there.
            ("1984", true),
            ("198", false),
            ("1968", true),
            ("Jan", true),
            ("Willem", true),
            ("Amsterdam", true),
            ("stay", false),
            // Several runs: all of them, and next to one another.
            ("Jan-Willem", true),
            ("Jan Willem", false),
            ("1984 stays", true),
            ("1984 stay", false),
            ("1968, but", true),
            ("Amsterdam 5", true),
            ("x\nAmsterdam", true),
            // Not a whole run of the piece it is in.
            ("an-Willem", false),
            ("Jan-Wille", false),
            // Punctuation and non-ASCII letters are no words of their own; what stands next to
            // them decides.
            (", ", false),
            (".", true),
            ("é", false),
            ("…", false),
        ] {
            assert_eq!(words.contains(candidate), expected, "{candidate:?}");
        }
        assert!(!Words::new(Vec::new()).contains("1984"));
        assert!(!Words::new(vec![""]).contains(""));
    }

    #[test]
    fn the_edge_of_a_piece_is_a_break() {
        // Pieces are the stretches between what is replaced: the replacement is not a word that
        // can join them to what stands next to it.
        let words = Words::new(vec!["Haley", "Brooks"]);
        assert!(words.contains("Haley") && words.contains("Brooks"));
        assert!(!words.contains("HaleyBrooks") && !words.contains("Haley Brooks"));
    }

    #[test]
    fn words_agree_with_the_search_for_the_same_string_as_a_proxy() -> Result<()> {
        // For random pieces and strings: a string stands alone in a piece exactly when a
        // detector that knows it as a proxy finds it there.
        let alphabet = ["a", "b", "1", " ", "-", ".", "é", "ab", "\n"];
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        for _ in 0..4000 {
            let pieces: Vec<String> = (0..=rng.below(3))
                .map(|_| rng.string(&alphabet, 12))
                .collect();
            let candidate = rng.string(&alphabet, 5);
            let words = Words::new(pieces.iter().map(String::as_str).collect());
            let issued = IssuedProxies::new(&[(PERSON, candidate.as_str())])?;
            let found = pieces.iter().any(|piece| !issued.spans(piece).is_empty());
            assert_eq!(
                words.contains(&candidate),
                found,
                "{candidate:?} in {pieces:?}"
            );
        }
        Ok(())
    }
}
