//! Turns the model's per-token probabilities into entity spans.
//!
//! This ports the word decoder of the model's reference `pii_detector.py`, the one its published
//! scores use, to bytes:
//!
//! 1. Every token's logits become a softmax. The `B-` and `I-` probabilities of a type are added
//!    up, so a token has one probability per type plus one for "no entity" (`O`), and the
//!    probability that it begins an entity (the `B-` mass).
//! 2. A token counts at the byte where its first non-space character is. The windows overlap, so
//!    one position can be seen more than once; the probabilities add up and the visits are counted.
//! 3. Words are the runs of characters that are no whitespace and none of `,;|"<>()[]{}*^`, with
//!    quotes and punctuation trimmed off their edges. A word takes the type with the highest
//!    mean probability over its positions, or no type when that is `O`.
//! 4. A word joins the span before it when both have the same type, only spaces and `,-/.()`
//!    lie between them and the word's first position does not look like a new beginning (mean
//!    `B-` mass below one half).
//! 5. Spans whose text has too few digits for their type are dropped (a phone number needs five,
//!    the identifiers two), and the type becomes a kind through [`target`], which also drops what
//!    the kind's validator rejects (a link that is no link, a name that is no name).
//!
//! The reference also marks every email address its own regex finds. Not ported: the regex
//! detector runs first and owns those.

use super::{
    gate::RawSpan,
    labels::{COLUMNS, LABELS, O, TYPES, target},
};

/// Between two words of one span: spaces and `,-/.()` only.
const JOINERS: &str = " ,-/.()";

/// Besides whitespace, characters that end a word.
const SEPARATORS: &str = ",;|\"<>()[]{}*^";

/// Trimmed off the start of a word.
const LEADING: &str = "([{<\"'\u{ab}\u{201e}";

/// Trimmed off the end of a word.
const TRAILING: &str = ")]}>\"'\u{bb}.,;:!?";

/// The probabilities of one token, pooled per entity type.
#[derive(Debug, Clone, Copy)]
pub(super) struct Pooled {
    /// One column per type (its `B-` and `I-` tags added up), then `O`.
    probs: [f32; COLUMNS],
    /// The added probability of every `B-` tag: how much the token looks like a beginning.
    begin: f32,
}

/// Softmax over one token's logits, pooled per type. Logits that do not make a distribution
/// (not a number, infinite) mean "no entity".
pub(super) fn pool(logits: &[f32; LABELS]) -> Pooled {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exp = [0.0f32; LABELS];
    let mut sum = 0.0f32;
    for (e, &logit) in exp.iter_mut().zip(logits) {
        *e = (logit - max).exp();
        sum += *e;
    }
    let mut pooled = Pooled {
        probs: [0.0; COLUMNS],
        begin: 0.0,
    };
    if !(sum.is_finite() && sum > 0.0) {
        pooled.probs[O] = 1.0;
        return pooled;
    }
    let scale = sum.recip();
    pooled.probs[O] = exp[0] * scale;
    for (column, tags) in pooled.probs.iter_mut().zip(exp[1..].chunks_exact(2)) {
        let begin = tags[0] * scale;
        *column = begin + tags[1] * scale;
        pooled.begin += begin;
    }
    pooled
}

/// What the tokens that start at one byte add up to.
#[derive(Debug, Clone, Copy)]
struct Position {
    at: usize,
    probs: [f32; COLUMNS],
    begin: f32,
    count: f32,
}

/// The tokens of one text, in any order, from any number of overlapping windows.
#[derive(Debug, Default)]
pub(super) struct Tokens {
    positions: Vec<Position>,
}

impl Tokens {
    /// Adds the token the tokenizer put at bytes `start..end` of `text`. Special tokens have an
    /// empty range and are ignored.
    ///
    /// The range of a word's token can begin with the space before it, which is not the word's,
    /// so the position is the first character after leading whitespace (the last character stays
    /// even when it is whitespace). A token for a single byte of a multi-byte character begins
    /// inside the character; it counts at the character's first byte.
    pub(super) fn push(&mut self, text: &str, start: usize, end: usize, pooled: &Pooled) {
        let mut stop = end.min(text.len());
        if stop <= start {
            return;
        }
        let mut at = start;
        while !text.is_char_boundary(at) {
            at -= 1;
        }
        while !text.is_char_boundary(stop) {
            stop += 1;
        }
        for c in text[at..stop].chars() {
            if c.is_whitespace() && at + c.len_utf8() < stop {
                at += c.len_utf8();
            } else {
                break;
            }
        }
        self.positions.push(Position {
            at,
            probs: pooled.probs,
            begin: pooled.begin,
            count: 1.0,
        });
    }

    /// Takes over the tokens `other` gathered, for a text that was run in more than one place.
    pub(super) fn extend(&mut self, other: Self) {
        self.positions.extend(other.positions);
    }

    /// The entity spans of `text`, sorted by start and disjoint.
    pub(super) fn decode(mut self, text: &str) -> Vec<RawSpan> {
        let positions = merge(&mut self.positions);
        let mut spans: Vec<(usize, usize, usize)> = Vec::new();
        let mut next = 0;
        for (start, end) in Words::new(text) {
            while positions.get(next).is_some_and(|p| p.at < start) {
                next += 1;
            }
            let first = next;
            let mut sums = [0.0f32; COLUMNS];
            while let Some(p) = positions.get(next).filter(|p| p.at < end) {
                for (sum, prob) in sums.iter_mut().zip(&p.probs) {
                    *sum += prob;
                }
                next += 1;
            }
            let Some(head) = positions.get(first).filter(|_| next > first) else {
                continue;
            };
            let ty = argmax(&sums);
            if ty == O {
                continue;
            }
            let begins = head.begin / head.count.max(1.0);
            match spans.last_mut() {
                Some(last)
                    if last.2 == ty
                        && text.get(last.1..start).is_some_and(joins)
                        && begins < 0.5 =>
                {
                    last.1 = end;
                }
                _ => spans.push((start, end, ty)),
            }
        }
        spans
            .into_iter()
            .filter_map(|(start, end, ty)| {
                let value = text.get(start..end)?;
                if digits(value) < min_digits(TYPES[ty]) {
                    return None;
                }
                Some(RawSpan {
                    start: u32::try_from(start).ok()?,
                    end: u32::try_from(end).ok()?,
                    kind: target(ty, value)?,
                })
            })
            .collect()
    }
}

/// `positions` sorted by byte, the ones at the same byte added up.
fn merge(positions: &mut [Position]) -> Vec<Position> {
    positions.sort_unstable_by_key(|p| p.at);
    let mut merged: Vec<Position> = Vec::with_capacity(positions.len());
    for p in positions.iter() {
        match merged.last_mut() {
            Some(last) if last.at == p.at => {
                for (sum, prob) in last.probs.iter_mut().zip(&p.probs) {
                    *sum += prob;
                }
                last.begin += p.begin;
                last.count += p.count;
            }
            _ => merged.push(*p),
        }
    }
    merged
}

/// Index of the largest value; the first one on a tie.
fn argmax(values: &[f32; COLUMNS]) -> usize {
    values
        .iter()
        .enumerate()
        .fold(
            (0, values[0]),
            |best, (i, &v)| {
                if v > best.1 { (i, v) } else { best }
            },
        )
        .0
}

/// True when the gap between two words keeps them in one entity.
fn joins(gap: &str) -> bool {
    gap.chars().all(|c| JOINERS.contains(c)) && !gap.contains("\n\n")
}

fn digits(value: &str) -> usize {
    value.bytes().filter(u8::is_ascii_digit).count()
}

/// Digits a value of this type must have: a phone number five, an identifier two.
fn min_digits(type_name: &str) -> usize {
    match type_name {
        "PHONE_NUMBER" => 5,
        "PERSON_IDENTIFIER"
        | "BANK_ACCOUNT_IDENTIFIER"
        | "PAYMENT_CARD"
        | "ACCOUNT_IDENTIFIER"
        | "DOCUMENT_IDENTIFIER"
        | "VEHICLE_IDENTIFIER" => 2,
        _ => 0,
    }
}

/// The words of a text, as byte ranges, in order.
struct Words<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Words<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }
}

fn separates(c: char) -> bool {
    c.is_whitespace() || SEPARATORS.contains(c)
}

impl Iterator for Words<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        loop {
            let rest = self.text.get(self.at..)?;
            let start = self.at + rest.find(|c| !separates(c))?;
            let end = start
                + self.text[start..]
                    .find(separates)
                    .unwrap_or(self.text.len() - start);
            self.at = end;
            let word = &self.text[start..end];
            let front = word.trim_start_matches(|c| LEADING.contains(c));
            let trimmed = front.trim_end_matches(|c| TRAILING.contains(c));
            if !trimmed.is_empty() {
                let from = end - front.len();
                return Some((from, from + trimmed.len()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::EntityKind;

    /// The logit of a type's `B-` or `I-` tag.
    fn tag(type_name: &str, begin: bool) -> usize {
        match TYPES.iter().position(|t| *t == type_name) {
            Some(i) => 1 + 2 * i + usize::from(!begin),
            None => panic!("no type {type_name}"),
        }
    }

    /// Logits that put all the probability on one label (`0` is `O`).
    fn row(label: usize) -> [f32; LABELS] {
        let mut logits = [0.0; LABELS];
        logits[label] = 30.0;
        logits
    }

    fn add(tokens: &mut Tokens, text: &str, start: usize, end: usize, label: usize) {
        tokens.push(text, start, end, &pool(&row(label)));
    }

    fn span(start: u32, end: u32, kind: EntityKind) -> RawSpan {
        RawSpan { start, end, kind }
    }

    #[test]
    fn a_name_and_a_phone_number_come_out_as_one_span_each() {
        // J0 a1 n2 _3 K4 .. i11 ,12 _13 t14 e15 l16 .17 _18 6(19) .. 6(29)
        let text = "Jan Kowalski, tel. 600 123 456";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        // As byte-level BPE reports it: the range of a word holds the space before it.
        add(&mut tokens, text, 3, 12, tag("PERSON_NAME", false));
        add(&mut tokens, text, 12, 13, 0);
        add(&mut tokens, text, 13, 17, 0);
        add(&mut tokens, text, 17, 18, 0);
        add(&mut tokens, text, 18, 22, tag("PHONE_NUMBER", true));
        add(&mut tokens, text, 22, 26, tag("PHONE_NUMBER", false));
        add(&mut tokens, text, 26, 30, tag("PHONE_NUMBER", false));
        assert_eq!(
            tokens.decode(text),
            [
                span(0, 12, EntityKind::Person),
                // No `+` or leading 0: not a `Phone`, but a number all the same.
                span(19, 30, EntityKind::PhoneNumber),
            ]
        );
    }

    #[test]
    fn a_beginning_on_the_second_word_splits_two_adjacent_names() {
        let text = "Jan Piet";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", true));
        assert_eq!(
            tokens.decode(text),
            [
                span(0, 3, EntityKind::Person),
                span(4, 8, EntityKind::Person)
            ]
        );
    }

    #[test]
    fn a_line_break_between_words_ends_the_span() {
        let text = "Jan\nKowalski";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 12, tag("PERSON_NAME", false));
        assert_eq!(
            tokens.decode(text),
            [
                span(0, 3, EntityKind::Person),
                span(4, 12, EntityKind::Person)
            ]
        );
    }

    #[test]
    fn words_of_other_types_or_far_apart_do_not_merge() {
        let text = "Jan Amsterdam";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 13, tag("LOCATION", false));
        assert_eq!(
            tokens.decode(text),
            [
                span(0, 3, EntityKind::Person),
                span(4, 13, EntityKind::Location)
            ]
        );

        // A word of another kind of text in between keeps two numbers apart.
        let text = "tel 12345 en tel 67890";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, 0);
        add(&mut tokens, text, 3, 9, tag("PHONE_NUMBER", true));
        add(&mut tokens, text, 9, 12, 0);
        add(&mut tokens, text, 12, 16, 0);
        add(&mut tokens, text, 16, 22, tag("PHONE_NUMBER", true));
        assert_eq!(
            tokens.decode(text),
            [
                span(4, 9, EntityKind::PhoneNumber),
                span(17, 22, EntityKind::PhoneNumber)
            ]
        );
    }

    #[test]
    fn a_phone_number_with_four_digits_is_dropped() {
        let text = "tel 1234 en tel 12345";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, 0);
        add(&mut tokens, text, 3, 8, tag("PHONE_NUMBER", true));
        add(&mut tokens, text, 8, 11, 0);
        add(&mut tokens, text, 11, 15, 0);
        add(&mut tokens, text, 15, 21, tag("PHONE_NUMBER", true));
        assert_eq!(tokens.decode(text), [span(16, 21, EntityKind::PhoneNumber)]);
    }

    #[test]
    fn identifiers_need_two_digits() {
        let text = "id AB-CD en id AB-12";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 2, 0);
        add(&mut tokens, text, 2, 8, tag("ACCOUNT_IDENTIFIER", true));
        add(&mut tokens, text, 8, 11, 0);
        add(&mut tokens, text, 11, 14, 0);
        add(&mut tokens, text, 14, 20, tag("ACCOUNT_IDENTIFIER", true));
        assert_eq!(tokens.decode(text), [span(15, 20, EntityKind::AccountId)]);
    }

    #[test]
    fn what_the_kind_rejects_is_dropped() {
        // Not shaped like a name, though the model says so.
        let text = "agent 007";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 5, 0);
        add(&mut tokens, text, 5, 9, tag("PERSON_NAME", true));
        assert!(tokens.decode(text).is_empty());
    }

    #[test]
    fn the_mean_over_overlapping_windows_decides_the_type() {
        let text = "Jan";
        // Seen three times: twice a name, once nothing.
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 0, 3, 0);
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        assert_eq!(tokens.decode(text), [span(0, 3, EntityKind::Person)]);

        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 0, 3, 0);
        add(&mut tokens, text, 0, 3, 0);
        assert!(tokens.decode(text).is_empty());
    }

    #[test]
    fn the_mean_beginning_mass_decides_whether_a_word_starts_a_new_span() {
        let text = "Jan Piet";
        // `Piet` begins in one of three windows: the mean is a third, so the name goes on.
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", false));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", false));
        assert_eq!(tokens.decode(text), [span(0, 8, EntityKind::Person)]);

        // In two of three: it begins a new one.
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", true));
        add(&mut tokens, text, 3, 8, tag("PERSON_NAME", false));
        assert_eq!(
            tokens.decode(text),
            [
                span(0, 3, EntityKind::Person),
                span(4, 8, EntityKind::Person)
            ]
        );
    }

    #[test]
    fn windows_may_arrive_in_any_order() {
        let text = "Jan Kowalski";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 3, 12, tag("PERSON_NAME", false));
        add(&mut tokens, text, 0, 3, tag("PERSON_NAME", true));
        assert_eq!(tokens.decode(text), [span(0, 12, EntityKind::Person)]);
    }

    #[test]
    fn tokens_gathered_by_two_workers_decode_like_one_set() {
        let text = "Jan Kowalski, tel. 600 123 456";
        let tokens = [
            (0, 3, tag("PERSON_NAME", true)),
            (3, 12, tag("PERSON_NAME", false)),
            (18, 22, tag("PHONE_NUMBER", true)),
            (22, 26, tag("PHONE_NUMBER", false)),
            (26, 30, tag("PHONE_NUMBER", false)),
        ];
        let mut whole = Tokens::default();
        let (mut card, mut processor) = (Tokens::default(), Tokens::default());
        for (i, &(start, end, label)) in tokens.iter().enumerate() {
            add(&mut whole, text, start, end, label);
            // The card ran the odd ones, the processor the even ones.
            let side = if i % 2 == 1 {
                &mut card
            } else {
                &mut processor
            };
            add(side, text, start, end, label);
        }
        processor.extend(card);
        assert_eq!(processor.decode(text), whole.decode(text));
        let mut none = Tokens::default();
        none.extend(Tokens::default());
        assert!(none.decode(text).is_empty());
    }

    #[test]
    fn punctuation_is_trimmed_off_the_words() {
        let text = "Hi Jan.";
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 2, 0);
        add(&mut tokens, text, 2, 6, tag("PERSON_NAME", true));
        add(&mut tokens, text, 6, 7, 0);
        assert_eq!(tokens.decode(text), [span(3, 6, EntityKind::Person)]);
    }

    #[test]
    fn a_token_for_one_byte_of_a_character_does_not_panic_or_split_it() {
        // `ë` is the two bytes 2..4: byte-fallback tokens begin inside it.
        let text = "Zo\u{eb} Jansen";
        assert_eq!(text.len(), 11);
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 2, tag("PERSON_NAME", true));
        add(&mut tokens, text, 2, 3, tag("PERSON_NAME", false));
        add(&mut tokens, text, 3, 4, tag("PERSON_NAME", false));
        add(&mut tokens, text, 4, 11, tag("PERSON_NAME", false));
        assert_eq!(tokens.decode(text), [span(0, 11, EntityKind::Person)]);

        // Offsets past the end, backwards or empty (special tokens) are ignored.
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 0, 0, tag("PERSON_NAME", true));
        add(&mut tokens, text, 9, 4, tag("PERSON_NAME", true));
        add(&mut tokens, text, 40, 50, tag("PERSON_NAME", true));
        assert!(tokens.decode(text).is_empty());
        let mut tokens = Tokens::default();
        add(&mut tokens, text, 5, 99, tag("PERSON_NAME", true));
        assert_eq!(tokens.decode(text), [span(5, 11, EntityKind::Person)]);
    }

    #[test]
    fn a_range_that_is_only_whitespace_keeps_its_last_character() {
        let text = "a  b";
        let mut tokens = Tokens::default();
        // Spaces carry the "name" probability but are no word, so nothing comes of it.
        add(&mut tokens, text, 1, 3, tag("PERSON_NAME", true));
        assert!(tokens.decode(text).is_empty());
    }

    #[test]
    fn text_without_tokens_or_words_decodes_to_nothing() {
        assert!(Tokens::default().decode("").is_empty());
        assert!(Tokens::default().decode("Jan Kowalski").is_empty());
        let mut tokens = Tokens::default();
        add(&mut tokens, " ,; ", 0, 4, tag("PERSON_NAME", true));
        assert!(tokens.decode(" ,; ").is_empty());
    }

    #[test]
    fn the_address_of_the_reference_example_merges_across_its_comma() {
        // ul.=0..3 _=3 D=4 \u{142}=5..7 uga=7..10 _=10 5=11 ,=12 _=13 00-238=14..20 _=20 Warszawa=21..29
        let text = "ul. D\u{142}uga 5, 00-238 Warszawa";
        assert_eq!(text.len(), 29);
        let mut tokens = Tokens::default();
        let begin = tag("POSTAL_ADDRESS", true);
        let inside = tag("POSTAL_ADDRESS", false);
        add(&mut tokens, text, 0, 2, begin);
        add(&mut tokens, text, 2, 3, inside);
        add(&mut tokens, text, 3, 10, inside);
        add(&mut tokens, text, 10, 12, inside);
        add(&mut tokens, text, 12, 13, inside);
        add(&mut tokens, text, 13, 20, inside);
        add(&mut tokens, text, 20, 29, inside);
        assert_eq!(
            tokens.decode(text),
            [span(0, 29, EntityKind::PostalAddress)],
            "the comma and the spaces are all joiners"
        );
    }

    #[test]
    fn pooling_a_token_adds_the_tags_of_a_type_and_keeps_the_beginning_mass() {
        let begin = pool(&row(tag("PERSON_NAME", true)));
        let inside = pool(&row(tag("PERSON_NAME", false)));
        let outside = pool(&row(0));
        let person = TYPES.iter().position(|t| *t == "PERSON_NAME").unwrap_or(0);
        for pooled in [begin, inside] {
            assert!((pooled.probs[person] - 1.0).abs() < 1e-4);
            assert!((pooled.probs.iter().sum::<f32>() - 1.0).abs() < 1e-4);
        }
        assert!((begin.begin - 1.0).abs() < 1e-4);
        assert!(inside.begin < 1e-4);
        assert!((outside.probs[O] - 1.0).abs() < 1e-4);
        assert!(outside.begin < 1e-4);

        // No preference: every one of 71 labels equally likely.
        let flat = pool(&[0.0; LABELS]);
        assert!((flat.probs[O] - 1.0 / 71.0).abs() < 1e-6);
        assert!((flat.probs[0] - 2.0 / 71.0).abs() < 1e-6);
        assert!((flat.begin - 35.0 / 71.0).abs() < 1e-5);
    }

    #[test]
    fn logits_that_are_no_distribution_mean_no_entity() {
        for bad in [f32::NAN, f32::INFINITY] {
            let mut logits = [0.0; LABELS];
            logits[tag("PERSON_NAME", true)] = bad;
            let pooled = pool(&logits);
            assert!((pooled.probs[O] - 1.0).abs() < f32::EPSILON, "{bad}");
            assert!(pooled.begin.abs() < f32::EPSILON, "{bad}");
        }
    }

    #[test]
    fn words_split_on_whitespace_and_separators_and_lose_their_edge_punctuation() {
        let text = "(Jan), \u{ab}Piet\u{bb}; 'x'! a.b \"q\" ... ,";
        let words: Vec<&str> = Words::new(text).map(|(s, e)| &text[s..e]).collect();
        assert_eq!(words, ["Jan", "Piet", "x", "a.b", "q"]);
        assert_eq!(Words::new("").count(), 0);
        assert_eq!(Words::new("  \n ").count(), 0);
    }

    #[test]
    fn only_spaces_and_a_few_marks_join_words_into_one_span() {
        for gap in ["", " ", "  ", ", ", " - ", "/", ". ", " (", ") "] {
            assert!(joins(gap), "{gap:?}");
        }
        for gap in [
            "\n", " \n ", "\n\n", ": ", "; ", "! ", " ? ", "'", "\"", "x",
        ] {
            assert!(!joins(gap), "{gap:?}");
        }
    }

    #[test]
    fn digit_minimums_follow_the_reference() {
        assert_eq!(min_digits("PHONE_NUMBER"), 5);
        for name in [
            "PERSON_IDENTIFIER",
            "BANK_ACCOUNT_IDENTIFIER",
            "PAYMENT_CARD",
            "ACCOUNT_IDENTIFIER",
            "DOCUMENT_IDENTIFIER",
            "VEHICLE_IDENTIFIER",
        ] {
            assert_eq!(min_digits(name), 2, "{name}");
        }
        assert_eq!(min_digits("PERSON_NAME"), 0);
        assert_eq!(min_digits("IDENTIFYING_LINK"), 0);
        // Every name the minimums mention is a real type.
        for name in [
            "PHONE_NUMBER",
            "PERSON_IDENTIFIER",
            "BANK_ACCOUNT_IDENTIFIER",
            "PAYMENT_CARD",
            "ACCOUNT_IDENTIFIER",
            "DOCUMENT_IDENTIFIER",
            "VEHICLE_IDENTIFIER",
        ] {
            assert!(TYPES.contains(&name), "{name}");
        }
    }
}
