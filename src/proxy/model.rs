//! Proxy generators for the kinds only the detection model finds (discriminant 13 and up).
//!
//! These values have no fixed format, so a proxy keeps the *shape* of the original and swaps
//! its content: identifiers keep their layout, dates stay valid dates, places and organizations
//! become invented names, and the sensitive categories become an opaque tag. Every generator
//! ends in [`accepts`], so a proxy the validators would refuse is never handed out.
//!
//! Listed kinds are found again by exact vault lookup, not by watermark, so nothing here has
//! to carry one.

use super::{
    r#gen::{Case, Xof, case_of, digit_char, push_restyled},
    words::{LEGAL_FORMS, ORG_FORM, ORG_HEAD, ORG_TAIL, PLACE_HEAD, PLACE_TAIL, STREET_TAIL},
};
use crate::detect::{
    EntityKind,
    validate::{accepts, is_combining_mark},
};

/// Longest organization or brand name that is invented, in words.
const MAX_WORDS: usize = 3;

/// Characters of a [`tag`]: upper-case letters and digits without the look-alikes `I`, `O`, `0`
/// and `1`.
const TAG_CHARS: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Length of the random part of a [`tag`].
const TAG_LEN: usize = 4;

/// `value` when the validators of `kind` accept it.
fn checked(kind: EntityKind, value: String) -> Option<String> {
    accepts(kind, &value).then_some(value)
}

/// Rewrites letters and digits of `original`: each letter becomes a random ASCII one of its case
/// and each digit a random one, whatever the script, and every other character stays. A first
/// ASCII digit that was not `0` stays not `0`. With `digits_only` only the ASCII digits are
/// redrawn.
fn shape(original: &str, xof: &mut Xof, digits_only: bool) -> String {
    let mut out = String::with_capacity(original.len());
    let mut first_digit = true;
    for c in original.chars() {
        if c.is_ascii_digit() {
            let d = if first_digit && c != '0' {
                1 + xof.below(9)
            } else {
                xof.digit()
            };
            first_digit = false;
            out.push(digit_char(d));
        } else if digits_only {
            out.push(c);
        } else {
            out.push(xof.alnum_like(c));
        }
    }
    out
}

/// Gives `value` `widen` extra random digits. A value with few free characters (`12`, `A1`) has
/// only a handful of proxies and the vault gives each original its own; when it runs low it asks
/// for later, wider candidates, which cost the layout but never the round trip.
fn widened(mut value: String, widen: u32, xof: &mut Xof) -> String {
    for _ in 0..widen {
        value.push(digit_char(xof.digit()));
    }
    value
}

/// Identifiers, handles and references: letters and digits are redrawn, the layout stays.
/// `widen` (see [`widened`]) appends digits.
pub(super) fn shape_all(
    kind: EntityKind,
    original: &str,
    xof: &mut Xof,
    widen: u32,
) -> Option<String> {
    checked(kind, widened(shape(original, xof, false), widen, xof))
}

/// Phone numbers, coordinates, card numbers and amounts: only the digits are redrawn. `widen`
/// (see [`widened`]) appends digits.
pub(super) fn shape_digits(
    kind: EntityKind,
    original: &str,
    xof: &mut Xof,
    widen: u32,
) -> Option<String> {
    checked(kind, widened(shape(original, xof, true), widen, xof))
}

/// A date of birth. A four-digit year in 1900-2099 becomes one in 1940-2005, a one- or
/// two-digit group becomes a day or month valid in both roles (1-12, 1-9 when it has one digit),
/// any other digit group is redrawn, and letters such as month names stay.
///
/// A year alone has 66 proxies and a date with a year in it only a few thousand, so a larger
/// `widen` opens them up: 1900-2099 for the year at 1, any year in 1000-2999 and any day up to
/// 31 at 2 or more.
pub(super) fn date(kind: EntityKind, original: &str, xof: &mut Xof, widen: u32) -> Option<String> {
    let mut out = String::with_capacity(original.len());
    let mut rest = original;
    while let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
        out.push_str(&rest[..start]);
        let len = rest[start..]
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len() - start);
        let group = &rest[start..start + len];
        match (len, group.parse::<u32>()) {
            (4, Ok(1900..=2099)) => {
                let year = match widen {
                    0 => 1940 + xof.below(66),
                    1 => 1900 + xof.below(200),
                    _ => 1000 + xof.below(2000),
                };
                out.push_str(&year.to_string());
            }
            (1, _) => out.push_str(&(1 + xof.below(9)).to_string()),
            (2, _) => {
                let day_or_month = 1 + xof.below(if widen >= 2 { 31 } else { 12 });
                out.push(digit_char(day_or_month / 10));
                out.push(digit_char(day_or_month % 10));
            }
            _ => out.push_str(&shape(group, xof, true)),
        }
        rest = &rest[start + len..];
    }
    out.push_str(rest);
    checked(kind, out)
}

/// Splits `s` into alternating runs of separators (whitespace and `,`) and tokens, in order.
fn runs(s: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut previous: Option<bool> = None;
    for (i, c) in s.char_indices() {
        let separator = c.is_whitespace() || c == ',';
        if previous.is_some_and(|p| p != separator) {
            out.push((previous == Some(true), &s[start..i]));
            start = i;
        }
        previous = Some(separator);
    }
    if let Some(separator) = previous {
        out.push((separator, &s[start..]));
    }
    out
}

/// Splits `s` into alternating runs of non-word text and words, in order, as `(is_word, text)`.
/// A word is letters with `-` and apostrophes between them (`Sint-Michielsgestel`), and with the
/// combining marks that follow its letters in decomposed text (`u` and U+0308); digits, `:`,
/// `.`, `/` and the rest are never part of one, so `Sant'Antonio:IT` is two words.
fn segments(s: &str) -> Vec<(bool, &str)> {
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let mut out = Vec::new();
    let mut start = 0;
    let mut previous: Option<bool> = None;
    for (i, &(at, c)) in chars.iter().enumerate() {
        let inner = matches!(c, '-' | '\'' | '\u{2019}')
            && i > 0
            && (chars[i - 1].1.is_alphabetic() || is_combining_mark(chars[i - 1].1))
            && chars
                .get(i + 1)
                .is_some_and(|&(_, next)| next.is_alphabetic());
        let mark = is_combining_mark(c) && previous == Some(true);
        let word = c.is_alphabetic() || inner || mark;
        if previous.is_some_and(|p| p != word) {
            out.push((previous == Some(true), &s[start..at]));
            start = at;
        }
        previous = Some(word);
    }
    if let Some(word) = previous {
        out.push((word, &s[start..]));
    }
    out
}

/// Number of letters in `word`.
fn letters(word: &str) -> usize {
    word.chars().filter(|c| c.is_alphabetic()).count()
}

/// A word whose first letter is a capital.
fn is_capitalised(token: &str) -> bool {
    token
        .chars()
        .find(|c| c.is_alphabetic())
        .is_some_and(char::is_uppercase)
}

/// Appends `head` + `tail` to `out` as one invented word in the case of `like`.
fn push_invented(
    out: &mut String,
    head: &[&'static str],
    tail: &[&'static str],
    like: &str,
    xof: &mut Xof,
) {
    push_restyled(out, &[xof.pick(head), xof.pick(tail)], case_of(like));
}

/// `out` unless it is the original, which no proxy may be: then every letter and digit of the
/// original is redrawn instead. A value gets a proxy this way whenever it is still valid with
/// other letters and digits (a place such as `Sant'Antonio:IT` or `IT`, a link that is only a
/// scheme).
fn differing(original: &str, out: String, xof: &mut Xof) -> String {
    if out == original {
        shape(original, xof, false)
    } else {
        out
    }
}

/// A token that stays in an address because it only abbreviates a word: a dot after at most
/// three letters, and no digit (`ul.`, `St.`, `Nr.`). A longer one (`Hauptstr.`) is a name.
fn is_abbreviation(token: &str) -> bool {
    token.ends_with('.') && letters(token) <= 3 && !token.bytes().any(|b| b.is_ascii_digit())
}

/// A postal address. Separators stay. The first capitalised word of three letters or more (the
/// street) becomes `{org head}{street ending}`, later ones (the town) become invented places,
/// tokens with a digit are redrawn and everything else (`ul.`, `de`, `CJ`) stays. An address
/// without a capitalised word has its lower-case words treated the same way. When that leaves
/// the address as it was, every word is replaced, whatever its length or case. The invented words
/// are longer than most of those they replace: a value that would not fit the length limit that
/// way has its letters and digits redrawn instead, see [`shape`].
pub(super) fn address(kind: EntityKind, original: &str, xof: &mut Xof) -> Option<String> {
    let out = address_pass(original, xof, false);
    let out = if out == original {
        address_pass(original, xof, true)
    } else {
        out
    };
    checked(kind, differing(original, out, xof))
        .or_else(|| checked(kind, shape(original, xof, false)))
}

/// One rewrite of an address; `every_word` replaces all words and not only the long, capitalised
/// ones.
fn address_pass(original: &str, xof: &mut Xof, every_word: bool) -> String {
    let parts = runs(original);
    let capitalised = parts.iter().any(|&(sep, t)| {
        !sep && !is_abbreviation(t)
            && segments(t)
                .iter()
                .any(|&(w, s)| w && letters(s) >= 3 && is_capitalised(s))
    });
    let mut out = String::with_capacity(original.len());
    let mut street = true;
    for (separator, token) in parts {
        if separator || (!every_word && is_abbreviation(token)) {
            out.push_str(token);
        } else if token.bytes().any(|b| b.is_ascii_digit()) {
            out.push_str(&shape(token, xof, false));
        } else {
            for (word, part) in segments(token) {
                let replace = word
                    && (every_word
                        || (letters(part) >= 3 && (!capitalised || is_capitalised(part))));
                if !replace {
                    out.push_str(part);
                } else if street {
                    street = false;
                    push_invented(&mut out, &ORG_HEAD, &STREET_TAIL, part, xof);
                } else {
                    push_invented(&mut out, &PLACE_HEAD, &PLACE_TAIL, part, xof);
                }
            }
        }
    }
    out
}

/// A place: every capitalised word becomes an invented place in the case of the original word
/// (4096 combinations per word). A value without a capitalised word has its lower-case words of
/// three letters or more replaced instead. When that leaves the value as it was (`ab`, `Ab12`),
/// every word is replaced, and a value without any word has its letters and digits redrawn. So
/// does a value that would not fit the length limit with invented words in it, see [`shape`].
pub(super) fn place(kind: EntityKind, original: &str, xof: &mut Xof) -> Option<String> {
    let out = place_pass(original, xof, false);
    let out = if out == original {
        place_pass(original, xof, true)
    } else {
        out
    };
    checked(kind, differing(original, out, xof))
        .or_else(|| checked(kind, shape(original, xof, false)))
}

/// One rewrite of a place; `every_word` replaces all words, whatever their length or case.
fn place_pass(original: &str, xof: &mut Xof, every_word: bool) -> String {
    let parts = segments(original);
    let capitalised = parts
        .iter()
        .any(|&(word, s)| word && letters(s) >= 2 && is_capitalised(s));
    let mut out = String::with_capacity(original.len());
    for (word, part) in parts {
        let replace = word
            && (every_word
                || if capitalised {
                    letters(part) >= 2 && is_capitalised(part)
                } else {
                    letters(part) >= 3
                });
        if replace {
            push_invented(&mut out, &PLACE_HEAD, &PLACE_TAIL, part, xof);
        } else {
            out.push_str(part);
        }
    }
    out
}

/// True when `token` is a legal form (`B.V.`, `GmbH`, `Inc.`), ignoring case and a final dot.
fn is_legal_form(token: &str) -> bool {
    let lower = token.to_lowercase();
    let form = lower.trim_end_matches('.');
    LEGAL_FORMS.contains(&form)
}

/// Appends one invented word per word of `words`, at most [`MAX_WORDS`], in the case of each and
/// separated by spaces.
fn push_invented_words<'a>(out: &mut String, words: impl Iterator<Item = &'a str>, xof: &mut Xof) {
    for (i, word) in words.take(MAX_WORDS).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        push_invented(out, &ORG_HEAD, &ORG_TAIL, word, xof);
    }
}

/// An organization: one invented word per word of the name. A closing legal form stays as it was
/// written; without one, a name of two words or more gets a neutral ending (`Group`, `Labs`).
pub(super) fn organization(kind: EntityKind, original: &str, xof: &mut Xof) -> Option<String> {
    let words: Vec<&str> = original.split_whitespace().collect();
    let legal = words.len() > 1 && words.last().is_some_and(|w| is_legal_form(w));
    let body = if legal {
        &words[..words.len() - 1]
    } else {
        &words[..]
    };
    let mut out = String::new();
    push_invented_words(&mut out, body.iter().copied(), xof);
    if let Some(form) = words.last().filter(|_| legal) {
        out.push(' ');
        out.push_str(form);
    } else if words.len() >= 2 {
        out.push(' ');
        push_restyled(&mut out, &[xof.pick(&ORG_FORM)], Case::Title);
    }
    checked(kind, out)
}

/// A brand or other proper name: one invented word per word, at most [`MAX_WORDS`].
pub(super) fn brand(kind: EntityKind, original: &str, xof: &mut Xof) -> Option<String> {
    let mut out = String::new();
    push_invented_words(&mut out, original.split_whitespace(), xof);
    checked(kind, out)
}

/// A link. A leading `https://`, `http://` and `www.` and the final label of the host (the
/// top-level domain) stay; every other letter and digit, of any script, becomes an ASCII one. A
/// link that has nothing else to redraw (`http://.com`) loses the kept top-level domain too, and
/// one that is nothing but a scheme (`https://`) has its letters redrawn.
pub(super) fn link(kind: EntityKind, original: &str, xof: &mut Xof) -> Option<String> {
    let out = link_pass(original, xof, true);
    let out = if out == original {
        link_pass(original, xof, false)
    } else {
        out
    };
    checked(kind, differing(original, out, xof))
}

/// One rewrite of a link; `keep_tld` leaves the final host label as it is.
fn link_pass(original: &str, xof: &mut Xof, keep_tld: bool) -> String {
    let starts = |s: &str, prefix: &str| {
        s.as_bytes()
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix.as_bytes()))
    };
    let mut keep = ["https://", "http://"]
        .into_iter()
        .find(|p| starts(original, p))
        .map_or(0, str::len);
    if starts(&original[keep..], "www.") {
        keep += "www.".len();
    }
    let rest = &original[keep..];
    let host_end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    let tld_start = rest[..host_end].rfind('.').unwrap_or(host_end);
    let mut out = String::with_capacity(original.len());
    out.push_str(&original[..keep]);
    for (i, c) in rest.char_indices() {
        if keep_tld && (tld_start..host_end).contains(&i) {
            out.push(c);
        } else {
            out.push(xof.alnum_like(c));
        }
    }
    out
}

/// An opaque label such as `Health-7KQX` for the categories whose value says too much (a
/// diagnosis, a belief): the proxy shows only that something of this category was there.
pub(super) fn tag(kind: EntityKind, prefix: &str, xof: &mut Xof) -> Option<String> {
    let mut out = format!("{prefix}-");
    for _ in 0..TAG_LEN {
        let index = usize::try_from(xof.below(32)).unwrap_or_default();
        out.push(char::from(TAG_CHARS.get(index).copied().unwrap_or(b'X')));
    }
    checked(kind, out)
}
