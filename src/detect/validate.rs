//! Checksum and shape validators.
//!
//! The regexes of the pattern table only find candidates. A validator decides
//! whether a candidate really is a value of its kind. Each one is a pure
//! function of the whole haystack and the `[start, end)` span a pattern
//! matched, and returns the accepted, possibly trimmed, sub-span. They read
//! the bytes around the span as well (version strings, phone prefixes), so
//! they always take the full haystack and never a slice of it.
//!
//! Validators parse the span themselves instead of trusting the regex, which
//! keeps [`accepts`] meaningful for arbitrary strings.

use std::{net::Ipv6Addr, ops::RangeInclusive, str::FromStr};

use super::{EntityKind, patterns::PATTERNS};

/// Signature shared by every validator: `(haystack, start, end)` to the
/// accepted sub-span.
pub(super) type Validator = fn(&[u8], usize, usize) -> Option<(usize, usize)>;

/// True when `s` is, as a whole, a valid value of `kind`. Context rules (the
/// SSN and BSN keywords) are not applied. For [`EntityKind::UrlCredential`]
/// the value is the `user:pass` part, exactly as a [`super::Span`] covers it.
/// A [`EntityKind::Person`] is a name, see [`person`]. The kinds without a
/// watermark, which only the detection model finds, share one rule, see
/// [`model_value`].
#[must_use]
pub fn accepts(kind: EntityKind, s: &str) -> bool {
    let value = s.as_bytes();
    match kind {
        EntityKind::Person => person(s),
        EntityKind::UrlCredential => credential(value),
        _ if !kind.is_watermarked() => model_value(kind, s),
        _ => PATTERNS
            .iter()
            .find(|p| p.kind == kind)
            .is_some_and(|p| (p.validate)(value, 0, value.len()) == Some((0, value.len()))),
    }
}

/// Longest value of a model kind, in bytes.
const MODEL_MAX_BYTES: usize = 256;

/// Value of a kind the detection model finds: 1 to 256 bytes, no whitespace at
/// either end, no control characters (a [`EntityKind::PostalAddress`] may
/// hold `\n`), at least three alphanumeric characters, plus the extra rule of
/// the kind (a count of ASCII digits, or the shape of a link).
fn model_value(kind: EntityKind, s: &str) -> bool {
    if s.is_empty() || s.len() > MODEL_MAX_BYTES {
        return false;
    }
    if s.starts_with(char::is_whitespace) || s.ends_with(char::is_whitespace) {
        return false;
    }
    let newline_ok = kind == EntityKind::PostalAddress;
    if s.chars()
        .any(|c| c.is_control() && !(newline_ok && c == '\n'))
    {
        return false;
    }
    if s.chars().filter(|c| c.is_alphanumeric()).count() < 3 {
        return false;
    }
    let digits = s.bytes().filter(u8::is_ascii_digit).count();
    match kind {
        EntityKind::PersonIdentifier
        | EntityKind::AccountId
        | EntityKind::BankAccount
        | EntityKind::DocumentId
        | EntityKind::VehicleId => digits >= 2,
        EntityKind::DateOfBirth
        | EntityKind::GeoLocation
        | EntityKind::PaymentCard
        | EntityKind::CardSecurity
        | EntityKind::FinancialAmount => digits >= 3,
        EntityKind::PhoneNumber => digits >= 5,
        EntityKind::IdentifyingLink => url_ish(s),
        _ => true,
    }
}

/// True when `s` looks like a link: it has `://`, starts with `www.` (any case),
/// starts with `/` and an alphanumeric, or holds `label.tld` where the label ends
/// in an ASCII alphanumeric and the top-level label is at least two ASCII letters
/// that end the value or are followed by a byte that is not an ASCII alphanumeric.
fn url_ish(s: &str) -> bool {
    let b = s.as_bytes();
    if s.contains("://") || b.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"www.")) {
        return true;
    }
    if b.first() == Some(&b'/') && b.get(1).is_some_and(u8::is_ascii_alphanumeric) {
        return true;
    }
    (0..b.len().saturating_sub(1)).any(|i| {
        if !(b[i].is_ascii_alphanumeric() && b[i + 1] == b'.') {
            return false;
        }
        let letters = b[i + 2..]
            .iter()
            .take_while(|c| c.is_ascii_alphabetic())
            .count();
        letters >= 2
            && b.get(i + 2 + letters)
                .is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

/// Luhn checksum over ASCII digits. Empty input or any non-digit is invalid.
fn luhn(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        if !d.is_ascii_digit() {
            return false;
        }
        let mut value = u32::from(d - b'0');
        if i % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum.is_multiple_of(10)
}

/// IBAN length per country: every country of the SWIFT IBAN registry, release
/// 99 (December 2024). A country missing here falls back to [`IBAN_UNKNOWN`].
static IBAN_LENGTHS: [([u8; 2], usize); 89] = [
    (*b"AD", 24),
    (*b"AE", 23),
    (*b"AL", 28),
    (*b"AT", 20),
    (*b"AZ", 28),
    (*b"BA", 20),
    (*b"BE", 16),
    (*b"BG", 22),
    (*b"BH", 22),
    (*b"BI", 27),
    (*b"BR", 29),
    (*b"BY", 28),
    (*b"CH", 21),
    (*b"CR", 22),
    (*b"CY", 28),
    (*b"CZ", 24),
    (*b"DE", 22),
    (*b"DJ", 27),
    (*b"DK", 18),
    (*b"DO", 28),
    (*b"EE", 20),
    (*b"EG", 29),
    (*b"ES", 24),
    (*b"FI", 18),
    (*b"FK", 18),
    (*b"FO", 18),
    (*b"FR", 27),
    (*b"GB", 22),
    (*b"GE", 22),
    (*b"GI", 23),
    (*b"GL", 18),
    (*b"GR", 27),
    (*b"GT", 28),
    (*b"HN", 28),
    (*b"HR", 21),
    (*b"HU", 28),
    (*b"IE", 22),
    (*b"IL", 23),
    (*b"IQ", 23),
    (*b"IS", 26),
    (*b"IT", 27),
    (*b"JO", 30),
    (*b"KW", 30),
    (*b"KZ", 20),
    (*b"LB", 28),
    (*b"LC", 32),
    (*b"LI", 21),
    (*b"LT", 20),
    (*b"LU", 20),
    (*b"LV", 21),
    (*b"LY", 25),
    (*b"MC", 27),
    (*b"MD", 24),
    (*b"ME", 22),
    (*b"MK", 19),
    (*b"MN", 20),
    (*b"MR", 27),
    (*b"MT", 31),
    (*b"MU", 30),
    (*b"NI", 28),
    (*b"NL", 18),
    (*b"NO", 15),
    (*b"OM", 23),
    (*b"PK", 24),
    (*b"PL", 28),
    (*b"PS", 29),
    (*b"PT", 25),
    (*b"QA", 29),
    (*b"RO", 24),
    (*b"RS", 22),
    (*b"RU", 33),
    (*b"SA", 24),
    (*b"SC", 31),
    (*b"SD", 18),
    (*b"SE", 24),
    (*b"SI", 19),
    (*b"SK", 24),
    (*b"SM", 27),
    (*b"SO", 23),
    (*b"ST", 25),
    (*b"SV", 28),
    (*b"TL", 23),
    (*b"TN", 24),
    (*b"TR", 26),
    (*b"UA", 29),
    (*b"VA", 22),
    (*b"VG", 24),
    (*b"XK", 20),
    (*b"YE", 30),
];

/// Accepted IBAN lengths for a country outside [`IBAN_LENGTHS`]: a few
/// countries (Morocco, Algeria, Iran and others) issue IBANs without being in
/// the registry. 34 is the limit of ISO 13616, and the shortest registry
/// entry, Norway, has 15.
const IBAN_UNKNOWN: RangeInclusive<usize> = 15..=34;

/// One step of the mod-97 IBAN check: digits append themselves, letters append
/// their value `10..=35` as two decimal digits.
fn mod97_step(rem: u32, c: u8) -> u32 {
    if c.is_ascii_digit() {
        (rem * 10 + u32::from(c - b'0')) % 97
    } else {
        (rem * 100 + u32::from(c - b'A') + 10) % 97
    }
}

/// IBAN: the registry length of its country ([`IBAN_UNKNOWN`] for a country
/// outside the registry) after dropping spaces, and mod 97 equal to 1.
///
/// The pattern is greedy, so an IBAN followed by an uppercase word or number
/// (`BE68 5390 0754 7034 EXTRA`) is matched too long. Every prefix that ends
/// at a space is tried and the longest valid one wins; a prefix must end where
/// the next byte is a space, never inside a word.
pub(super) fn iban(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let &[c0, c1, d0, d1, ..] = v else {
        return None;
    };
    if !(c0.is_ascii_uppercase()
        && c1.is_ascii_uppercase()
        && d0.is_ascii_digit()
        && d1.is_ascii_digit())
    {
        return None;
    }
    let lengths = IBAN_LENGTHS
        .iter()
        .find(|(country, _)| *country == [c0, c1])
        .map_or(IBAN_UNKNOWN, |&(_, n)| n..=n);
    // Mod 97 of the rearranged number: account part first, then the country
    // and check digits. The account part is folded in while walking.
    let mut rem = 0u32;
    let mut count = 0;
    let mut best = None;
    for i in 0..=v.len() {
        match v.get(i).copied() {
            Some(c @ (b'A'..=b'Z' | b'0'..=b'9')) => {
                count += 1;
                if count > *lengths.end() {
                    break;
                }
                if count > 4 {
                    rem = mod97_step(rem, c);
                }
            }
            boundary @ (Some(b' ') | None) => {
                if lengths.contains(&count)
                    && [c0, c1, d0, d1].into_iter().fold(rem, mod97_step) == 1
                {
                    best = Some(i);
                }
                let continues = v
                    .get(i + 1)
                    .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
                if boundary.is_none() || !continues {
                    break;
                }
            }
            Some(_) => break,
        }
    }
    best.map(|n| (start, start + n))
}

/// Weights of the Dutch "11-proef": the last digit counts negatively.
const BSN_WEIGHTS: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];

/// Dutch BSN: nine digits, bare or as `dddd.dd.ddd`, passing the 11-proof and
/// not all zeros.
pub(super) fn bsn_11proof(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let mut digits = [0i32; 9];
    let mut count = 0;
    let mut dots = 0;
    for &b in v {
        match b {
            b'0'..=b'9' => {
                *digits.get_mut(count)? = i32::from(b - b'0');
                count += 1;
            }
            b'.' if matches!((dots, count), (0, 4) | (1, 6)) => dots += 1,
            _ => return None,
        }
    }
    if count != 9 || dots == 1 {
        return None;
    }
    let sum: i32 = digits.iter().zip(BSN_WEIGHTS).map(|(d, w)| d * w).sum();
    (sum % 11 == 0 && digits.iter().any(|&d| d != 0)).then_some((start, end))
}

/// US SSN: `ddd-dd-dddd` or `ddd dd dddd` (both separators the same) or nine
/// bare digits; area not 000, 666 or 900-999, group not 00, serial not 0000.
pub(super) fn ssn(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let (area, group, serial) = match *v {
        [a0, a1, a2, g0, g1, s0, s1, s2, s3] => ([a0, a1, a2], [g0, g1], [s0, s1, s2, s3]),
        [a0, a1, a2, x, g0, g1, y, s0, s1, s2, s3] if x == y && matches!(x, b'-' | b' ') => {
            ([a0, a1, a2], [g0, g1], [s0, s1, s2, s3])
        }
        _ => return None,
    };
    if !area
        .iter()
        .chain(&group)
        .chain(&serial)
        .all(u8::is_ascii_digit)
    {
        return None;
    }
    let bad_area = area == *b"000" || area == *b"666" || area[0] == b'9';
    (!bad_area && group != *b"00" && serial != *b"0000").then_some((start, end))
}

/// IPv4 dotted quad: octets 0..=255 without leading zeros, first octet not 0,
/// 127 (loopback) or 224 and up (multicast, reserved, broadcast). A quad that
/// touches another dotted number (`1.2.3.4.5`) is a version string.
pub(super) fn ipv4(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let mut octets = [0u16; 4];
    let mut parts = v.split(|&b| b == b'.');
    for octet in &mut octets {
        let part = parts.next()?;
        let leading_zero = part.len() > 1 && part[0] == b'0';
        if part.is_empty() || part.len() > 3 || leading_zero || !part.iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        *octet = part
            .iter()
            .fold(0, |acc, &d| acc * 10 + u16::from(d - b'0'));
        if *octet > 255 {
            return None;
        }
    }
    if parts.next().is_some() || matches!(octets[0], 0 | 127 | 224..) {
        return None;
    }
    let digit_before_dot =
        start >= 2 && hay.get(start - 1) == Some(&b'.') && hay[start - 2].is_ascii_digit();
    let dot_before_digit =
        hay.get(end) == Some(&b'.') && hay.get(end + 1).is_some_and(u8::is_ascii_digit);
    (!digit_before_dot && !dot_before_digit).then_some((start, end))
}

/// IPv6 text form accepted by [`Ipv6Addr`], an embedded IPv4 tail included (`::ffff:192.0.2.128`),
/// except `::` and `::1`, and the mapped form of a loopback or unspecified IPv4 address
/// (`::ffff:127.0.0.1`): those are not found as IPv4 either.
pub(super) fn ipv6(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let text = std::str::from_utf8(hay.get(start..end)?).ok()?;
    let addr = Ipv6Addr::from_str(text).ok()?.to_canonical();
    (!addr.is_unspecified() && !addr.is_loopback()).then_some((start, end))
}

/// MAC address: six hex pairs with one separator kind (`:` or `-`) throughout,
/// not all `0` and not all `f`.
pub(super) fn mac(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    if v.len() != 17 || !matches!(v[2], b':' | b'-') {
        return None;
    }
    let separator = v[2];
    let (mut all_zero, mut all_f) = (true, true);
    for (i, &b) in v.iter().enumerate() {
        if i % 3 == 2 {
            if b != separator {
                return None;
            }
        } else if b.is_ascii_hexdigit() {
            all_zero &= b == b'0';
            all_f &= matches!(b, b'f' | b'F');
        } else {
            return None;
        }
    }
    (!all_zero && !all_f).then_some((start, end))
}

/// Digits a payment card number may have.
const CARD_DIGITS: RangeInclusive<usize> = 13..=19;

/// True for digits that form a plausible card number: 13-19 of them, first
/// digit 2-6, Luhn.
fn card_digits(digits: &[u8]) -> bool {
    CARD_DIGITS.contains(&digits.len()) && matches!(digits[0], b'2'..=b'6') && luhn(digits)
}

/// Payment card: 13-19 digits, first digit 2-6, Luhn, with spaces or hyphens
/// (one kind only) between digits.
///
/// The pattern is greedy, so a card followed by an expiry date or CVV
/// (`4111 1111 1111 1111 12/25`) is matched too long. Every prefix that ends
/// at a separator is tried and the longest valid one wins.
pub(super) fn card(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    if !v.first()?.is_ascii_digit() {
        return None;
    }
    let mut digits = [0u8; 19];
    let mut count = 0;
    let mut separator = None;
    let mut best = None;
    for i in 0..=v.len() {
        match v.get(i).copied() {
            Some(d) if d.is_ascii_digit() => {
                let Some(slot) = digits.get_mut(count) else {
                    break;
                };
                *slot = d;
                count += 1;
            }
            boundary @ (Some(b' ' | b'-') | None) => {
                if card_digits(&digits[..count]) {
                    best = Some(i);
                }
                let Some(sep) = boundary else { break };
                let digit_follows = v.get(i + 1).is_some_and(u8::is_ascii_digit);
                if !digit_follows || separator.is_some_and(|first| first != sep) {
                    break;
                }
                separator = Some(sep);
            }
            Some(_) => break,
        }
    }
    best.map(|n| (start, start + n))
}

/// Bit for a phone separator character, so the kinds used can be counted.
fn separator_bit(b: u8) -> Option<u8> {
    Some(match b {
        b' ' => 1,
        b'(' => 2,
        b')' => 4,
        b'.' => 8,
        b'-' => 16,
        _ => return None,
    })
}

/// Phone number in one of three forms, each with its own digit count:
/// `+`/`00` international (8-15 digits after the prefix), leading-0 national
/// (9-12) and NANP (exactly 10, optionally opening with `(`). Only digits and
/// the separators space, `(`, `)`, `.` and `-` may appear.
///
/// The byte before the span must not be alphanumeric, `+` or `/`. A digit run
/// longer than 12 together with more than one kind of separator means a
/// number glued to something else, and is rejected.
pub(super) fn phone(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let before = start.checked_sub(1).and_then(|i| hay.get(i));
    if before.is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/')) {
        return None;
    }
    // Leading digits that are not part of the number, and the digits allowed.
    let (prefix_digits, allowed) = match v {
        [b'+', b'1'..=b'9', ..] => (0, 8..=15),
        [b'0', b'0', b'1'..=b'9', ..] => (2, 8..=15),
        [b'0', b'1'..=b'9', ..] => (0, 9..=12),
        [b'(', b'2'..=b'9', ..] | [b'2'..=b'9', ..] => (0, 10..=10),
        _ => return None,
    };
    let (mut digits, mut run, mut longest, mut kinds) = (0usize, 0usize, 0usize, 0u8);
    for &b in v.strip_prefix(b"+").unwrap_or(v) {
        if b.is_ascii_digit() {
            digits += 1;
            run += 1;
            longest = longest.max(run);
        } else {
            kinds |= separator_bit(b)?;
            run = 0;
        }
    }
    let glued = longest > 12 && kinds.count_ones() > 1;
    (allowed.contains(&(digits - prefix_digits)) && !glued).then_some((start, end))
}

/// Email: local part (1-64 bytes of `A-Za-z0-9._%+-`) that neither starts nor
/// ends with `.` and has no `..`, then `@`, then at least two dot-separated
/// labels (1-63 of `A-Za-z0-9-`) ending in an alphabetic label of 2-24 bytes.
pub(super) fn email(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let at = v.iter().position(|&b| b == b'@')?;
    let (local, domain) = (&v[..at], &v[at + 1..]);
    let local_ok = (1..=64).contains(&local.len())
        && local
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
        && !local.starts_with(b".")
        && !local.ends_with(b".")
        && !local.windows(2).any(|w| w == b"..");
    let mut labels = 0;
    let mut tld: &[u8] = &[];
    for label in domain.split(|&b| b == b'.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
        labels += 1;
        tld = label;
    }
    let tld_ok = (2..=24).contains(&tld.len()) && tld.iter().all(u8::is_ascii_alphabetic);
    (local_ok && labels >= 2 && tld_ok).then_some((start, end))
}

/// `user:pass` credential: user 1-64 bytes without whitespace, `:`, `/` or
/// `@`; password 1-128 bytes without whitespace, `/` or `@`.
fn credential(value: &[u8]) -> bool {
    let Some(colon) = value.iter().position(|&b| b == b':') else {
        return false;
    };
    // The first colon ends the user, so only the password can hold another.
    let plain = |part: &[u8]| {
        !part
            .iter()
            .any(|&b| b.is_ascii_whitespace() || matches!(b, b'/' | b'@'))
    };
    let (user, pass) = (&value[..colon], &value[colon + 1..]);
    (1..=64).contains(&user.len()) && (1..=128).contains(&pass.len()) && plain(user) && plain(pass)
}

/// Longest [`EntityKind::Person`] value, in characters. Characters, not bytes:
/// a Greek or Cyrillic letter takes two bytes, and the Greek name with a
/// patronymic (`Παναγιώτης Κωνσταντίνου Παπαδόπουλος`) is over 64 bytes.
const PERSON_MAX_CHARS: usize = 64;

/// Most tokens a [`EntityKind::Person`] value has.
const PERSON_MAX_TOKENS: usize = 6;

/// Person name: one to six tokens separated by whitespace, at most 64
/// characters, with no whitespace at either end. A token holds letters (of any
/// script, so `Zoë` and `José` pass), the combining marks of decomposed text
/// (`é` written as `e` and U+0301), `'`, `’`, `-` and `.` (initials such as
/// `J.`) and at least one letter. The first token has at least two characters
/// that are not marks: `J.` and `'t` can open a name, a lone `J` cannot.
fn person(s: &str) -> bool {
    // `nth` stops at the 65th character, so a huge string costs no more than a short one.
    if s.chars().nth(PERSON_MAX_CHARS).is_some()
        || s.starts_with(char::is_whitespace)
        || s.ends_with(char::is_whitespace)
    {
        return false;
    }
    let mut tokens = 0;
    for token in s.split_whitespace() {
        tokens += 1;
        let long_enough = tokens > 1
            || token
                .chars()
                .filter(|&c| !is_combining_mark(c))
                .nth(1)
                .is_some();
        if tokens > PERSON_MAX_TOKENS || !long_enough || !name_token(token) {
            return false;
        }
    }
    tokens > 0
}

/// Letters, combining marks, apostrophes, hyphens and dots, with at least one
/// letter.
fn name_token(token: &str) -> bool {
    token.chars().all(|c| {
        c.is_alphabetic() || is_combining_mark(c) || matches!(c, '\'' | '\u{2019}' | '-' | '.')
    }) && token.chars().any(char::is_alphabetic)
}

/// The combining diacritics of Latin, Greek and Cyrillic text, which follow their
/// letter once the text is decomposed. They are not letters themselves. The proxy
/// generators use it too, to keep a decomposed letter and its marks in one word.
pub(crate) fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
    )
}

/// URL with embedded credentials (`scheme://user:pass@`), trimmed to the bytes
/// between `://` and `@`, so the span is `user:pass`.
pub(super) fn url_credential(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let scheme = v.windows(3).position(|w| w == b"://")?;
    if v.last() != Some(&b'@') {
        return None;
    }
    let (from, to) = (start + scheme + 3, end - 1);
    (from < to && credential(&hay[from..to])).then_some((from, to))
}

/// True for the characters of a base64url segment.
fn url_safe(s: &[u8]) -> bool {
    s.iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// A JSON web token: `eyJ...` header, `eyJ...` payload, signature.
fn jwt(v: &[u8]) -> bool {
    let mut parts = v.split(|&b| b == b'.');
    let (Some(head), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let segment = |s: &[u8], max: usize| {
        s.strip_prefix(b"eyJ")
            .is_some_and(|rest| (8..=max).contains(&rest.len()) && url_safe(rest))
    };
    segment(head, 1400)
        && segment(payload, 1400)
        && (8..=1200).contains(&signature.len())
        && url_safe(signature)
}

/// Provider-issued secret in one of the known token formats: AWS access key
/// id, GitHub token, Slack token, Stripe live key, Google API key or JWT.
pub(super) fn secret(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let v = hay.get(start..end)?;
    let ok = if let Some(rest) = v.strip_prefix(b"AKIA") {
        rest.len() == 16
            && rest
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    } else if let Some([b'p' | b'o' | b'u' | b's' | b'r', b'_', rest @ ..]) = v.strip_prefix(b"gh")
    {
        rest.len() == 36 && rest.iter().all(u8::is_ascii_alphanumeric)
    } else if let Some([b'b' | b'a' | b'p' | b'r' | b's', b'-', rest @ ..]) = v.strip_prefix(b"xox")
    {
        (10..=72).contains(&rest.len())
            && rest.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    } else if let Some(rest) = v
        .strip_prefix(b"sk_live_")
        .or_else(|| v.strip_prefix(b"rk_live_"))
    {
        (24..=99).contains(&rest.len()) && rest.iter().all(u8::is_ascii_alphanumeric)
    } else if let Some(rest) = v.strip_prefix(b"AIza") {
        rest.len() == 35 && url_safe(rest)
    } else {
        jwt(v)
    };
    ok.then_some((start, end))
}

/// Distance in bytes from `start` back to the end of the closest keyword
/// occurrence inside the `window` bytes before `start` (ASCII case-insensitive),
/// or `None` when no keyword occurs there. An occurrence has to start a word,
/// see [`starts_word`]: `ssn` counts in `my ssn`, `user_ssn` and `userSSN`, not
/// in `className` or `businessNumber`.
pub(super) fn nearest_context(
    hay: &[u8],
    start: usize,
    keywords: &[&str],
    window: usize,
) -> Option<usize> {
    let from = start.saturating_sub(window);
    let before = hay.get(from..start)?;
    keywords
        .iter()
        .filter_map(|word| {
            let word = word.as_bytes();
            if word.is_empty() {
                return None;
            }
            let last = before.len().checked_sub(word.len())?;
            let at = (0..=last).rev().find(|&at| {
                before[at..at + word.len()].eq_ignore_ascii_case(word)
                    && starts_word(hay, from + at)
            })?;
            Some(before.len() - (at + word.len()))
        })
        .min()
}

/// True when a keyword found at `hay[at..]` starts a word: the byte before it is
/// not an ASCII letter or digit, or the keyword opens with an uppercase letter
/// after a lowercase letter or a digit (`userSSN`). Reads the byte before `at`
/// from the haystack, so the answer does not depend on where the window began.
fn starts_word(hay: &[u8], at: usize) -> bool {
    let Some(&prev) = at.checked_sub(1).and_then(|i| hay.get(i)) else {
        return true;
    };
    !prev.is_ascii_alphanumeric()
        || (hay.get(at).is_some_and(u8::is_ascii_uppercase) && !prev.is_ascii_uppercase())
}

/// True when one of `keywords` occurs (ASCII case-insensitive, at the start of
/// a word) in the `window` bytes before `start`.
pub(super) fn context(hay: &[u8], start: usize, keywords: &[&str], window: usize) -> bool {
    nearest_context(hay, start, keywords, window).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sub-span of `s` that `validator` accepts when given all of `s`.
    fn accepted(validator: Validator, s: &str) -> Option<&str> {
        validator(s.as_bytes(), 0, s.len()).map(|(a, b)| &s[a..b])
    }

    /// True when `validator` accepts all of `s` untrimmed.
    fn whole(validator: Validator, s: &str) -> bool {
        accepted(validator, s) == Some(s)
    }

    /// Runs `validator` on `needle` at its position inside `text`.
    fn within(validator: Validator, text: &str, needle: &str) -> Option<(usize, usize)> {
        let Some(start) = text.find(needle) else {
            panic!("{needle:?} does not occur in {text:?}");
        };
        validator(text.as_bytes(), start, start + needle.len())
    }

    #[test]
    fn luhn_accepts_valid_numbers_and_rejects_corrupted_ones() {
        for ok in [
            "79927398713",
            "4111111111111111",
            "5500005555555559",
            "378282246310005",
        ] {
            assert!(luhn(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "79927398710",
            "4111111111111112",
            "",
            "4111 1111",
            "41111111x1111111",
        ] {
            assert!(!luhn(bad.as_bytes()), "{bad}");
        }
    }

    /// The example IBAN of every country in the SWIFT IBAN registry, release
    /// 99 (December 2024), in electronic format.
    const REGISTRY_EXAMPLES: [&str; 89] = [
        "AD1200012030200359100100",
        "AE070331234567890123456",
        "AL47212110090000000235698741",
        "AT611904300234573201",
        "AZ21NABZ00000000137010001944",
        "BA391290079401028494",
        "BE68539007547034",
        "BG80BNBG96611020345678",
        "BH67BMAG00001299123456",
        "BI4210000100010000332045181",
        "BR9700360305000010009795493P1",
        "BY13NBRB3600900000002Z00AB00",
        "CH9300762011623852957",
        "CR05015202001026284066",
        "CY17002001280000001200527600",
        "CZ6508000000192000145399",
        "DE89370400440532013000",
        "DJ2100010000000154000100186",
        "DK5000400440116243",
        "DO28BAGR00000001212453611324",
        "EE382200221020145685",
        "EG380019000500000000263180002",
        "ES9121000418450200051332",
        "FI2112345600000785",
        "FK88SC123456789012",
        "FO2000400440116243",
        "FR1420041010050500013M02606",
        "GB29NWBK60161331926819",
        "GE29NB0000000101904917",
        "GI75NWBK000000007099453",
        "GL2000400440116243",
        "GR1601101250000000012300695",
        "GT82TRAJ01020000001210029690",
        "HN88CABF00000000000250005469",
        "HR1210010051863000160",
        "HU42117730161111101800000000",
        "IE29AIBK93115212345678",
        "IL620108000000099999999",
        "IQ98NBIQ850123456789012",
        "IS140159260076545510730339",
        "IT60X0542811101000000123456",
        "JO94CBJO0010000000000131000302",
        "KW81CBKU0000000000001234560101",
        "KZ86125KZT5004100100",
        "LB62099900000001001901229114",
        "LC55HEMM000100010012001200023015",
        "LI21088100002324013AA",
        "LT121000011101001000",
        "LU280019400644750000",
        "LV80BANK0000435195001",
        "LY83002048000020100120361",
        "MC5811222000010123456789030",
        "MD24AG000225100013104168",
        "ME25505000012345678951",
        "MK07250120000058984",
        "MN121234123456789123",
        "MR1300020001010000123456753",
        "MT84MALT011000012345MTLCAST001S",
        "MU17BOMM0101101030300200000MUR",
        "NI45BAPR00000013000003558124",
        "NL91ABNA0417164300",
        "NO9386011117947",
        "OM810180000001299123456",
        "PK36SCBL0000001123456702",
        "PL61109010140000071219812874",
        "PS92PALS000000000400123456702",
        "PT50000201231234567890154",
        "QA58DOHB00001234567890ABCDEFG",
        "RO49AAAA1B31007593840000",
        "RS35260005601001611379",
        "RU0304452522540817810538091310419",
        "SA0380000000608010167519",
        "SC18SSCB11010000000000001497USD",
        "SD2129010501234001",
        "SE4550000000058398257466",
        "SI56191000000123438",
        "SK3112000000198742637541",
        "SM86U0322509800000000270100",
        "SO211000001001000100141",
        "ST68000100010051845310112",
        "SV62CENR00000000000000700025",
        "TL380080012345678910157",
        "TN5910006035183598478831",
        "TR330006100519786457841326",
        "UA213996220000026007233566001",
        "VA59001123000012345678",
        "VG96VPVG0000012345678901",
        "XK051212012345678906",
        "YE15CBYE0001018861234567891234",
    ];

    /// An IBAN of `country` over `bban`, with the check digits that make it valid.
    fn iban_with_check_digits(country: &str, bban: &str) -> String {
        // The check digits are 98 minus the remainder of the BBAN, the country and `00`.
        let rem = bban
            .bytes()
            .chain(country.bytes())
            .chain(*b"00")
            .fold(0, mod97_step);
        format!("{country}{:02}{bban}", 98 - rem)
    }

    /// `value` in the printed layout of an IBAN: groups of four characters.
    fn grouped(value: &str) -> String {
        value
            .as_bytes()
            .chunks(4)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn iban_accepts_the_registry_example_of_every_country() {
        for example in REGISTRY_EXAMPLES {
            assert!(whole(iban, example), "{example}");
            let printed = grouped(example);
            assert!(whole(iban, &printed), "{printed}");
        }
    }

    #[test]
    fn iban_length_is_exact_in_the_registry_and_only_capped_outside_it() {
        for example in REGISTRY_EXAMPLES {
            // One BBAN character more or fewer, with check digits to match: only the
            // length is wrong.
            let (country, bban) = (&example[..2], &example[4..]);
            let longer = iban_with_check_digits(country, &format!("{bban}0"));
            let shorter = iban_with_check_digits(country, &bban[..bban.len() - 1]);
            assert!(!whole(iban, &longer), "{longer}");
            assert!(!whole(iban, &shorter), "{shorter}");
        }
        // Morocco issues IBANs but is not in the registry: the check digits and the
        // 34 characters of ISO 13616 are all there is to check.
        assert!(whole(iban, "MA64011519000001205000534921"));
        assert!(!whole(iban, "MA64011519000001205000534922"));
        assert!(whole(iban, &iban_with_check_digits("MA", &"1".repeat(30))));
        assert!(!whole(iban, &iban_with_check_digits("MA", &"1".repeat(31))));
    }

    #[test]
    fn iban_rejects_bad_checksum_length_and_shape() {
        for bad in [
            "NL92ABNA0417164300",         // check digits
            "NL91ABNA041716430",          // one short
            "NL91ABNA04171643000",        // one long
            "NL91ABNA0417164300EXTRA",    // glued to a word
            "nl91abna0417164300",         // lowercase
            "NL91  ABNA 0417 1643 00",    // double space
            "NL91 ABNA 0417 1643 00 ",    // trailing space is trimmed, not whole
            "XX00",                       // too short
            "TR330006100519786457841327", // check digits
            "N191ABNA0417164300",         // country is not two letters
        ] {
            assert!(!whole(iban, bad), "{bad:?}");
        }
    }

    #[test]
    fn iban_trims_trailing_words_and_numbers() {
        assert_eq!(
            accepted(iban, "BE68 5390 0754 7034 EXTRA"),
            Some("BE68 5390 0754 7034")
        );
        assert_eq!(
            accepted(iban, "AT61 1904 3002 3457 3201 ABC"),
            Some("AT61 1904 3002 3457 3201")
        );
        assert_eq!(
            accepted(iban, "NL91ABNA0417164300 "),
            Some("NL91ABNA0417164300")
        );
        assert_eq!(
            accepted(iban, "TR33 0006 1005 1978 6457 8413 26 EXTRA"),
            Some("TR33 0006 1005 1978 6457 8413 26")
        );
        // Not a word boundary: the prefix is not an IBAN of its own.
        assert_eq!(accepted(iban, "BE68 5390 0754 7034EXTRA"), None);
    }

    #[test]
    fn bsn_follows_the_11_proof() {
        for ok in ["111222333", "123456782", "912345676", "1234.56.782"] {
            assert!(whole(bsn_11proof, ok), "{ok}");
        }
        for bad in [
            "123456789",
            "000000000",
            "11122233",
            "1112223334",
            "1234.56782",
            "123.456.782",
            "1234..56.782",
            "12345678a",
        ] {
            assert!(!whole(bsn_11proof, bad), "{bad}");
        }
    }

    #[test]
    fn ssn_enforces_area_group_serial_and_separators() {
        for ok in [
            "123-45-6789",
            "123 45 6789",
            "123456789",
            "001-01-0001",
            "899-99-9999",
        ] {
            assert!(whole(ssn, ok), "{ok}");
        }
        for bad in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "999-12-3456",
            "123-00-6789",
            "123-45-0000",
            "123-45 6789", // mixed separators
            "123-456789",  // one separator only
            "12345-6789",
            "123-45-678",
            "123-45-67890",
            "12a-45-6789",
        ] {
            assert!(!whole(ssn, bad), "{bad}");
        }
    }

    #[test]
    fn ipv4_rejects_reserved_leading_zeros_and_version_strings() {
        for ok in [
            "203.0.113.42",
            "10.0.0.1",
            "192.168.1.10",
            "8.8.8.8",
            "223.255.255.254",
            "1.0.0.1",
        ] {
            assert!(whole(ipv4, ok), "{ok}");
        }
        for bad in [
            "0.1.2.3",
            "127.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "256.1.1.1",
            "01.2.3.4",
            "1.2.3.04",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            "1.2.3.4444",
        ] {
            assert!(!whole(ipv4, bad), "{bad}");
        }
        // Neighbouring dotted digits mark a version string.
        assert_eq!(within(ipv4, "1.2.3.4.5", "1.2.3.4"), None);
        assert_eq!(within(ipv4, "1.2.3.4.5", "2.3.4.5"), None);
        assert_eq!(within(ipv4, "v1.2.3.4.5.6", "2.3.4.5"), None);
        // A trailing sentence dot or a letter before it is fine.
        assert_eq!(within(ipv4, "host 10.1.2.3.", "10.1.2.3"), Some((5, 13)));
        assert_eq!(within(ipv4, "ip:10.1.2.3, ok", "10.1.2.3"), Some((3, 11)));
    }

    #[test]
    fn ipv6_uses_std_parser_but_not_loopback_or_unspecified() {
        for ok in [
            "2001:db8::1",
            "fe80::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:DB8:85A3::8A2E:370:7334",
            "1::2",
            "::ffff:192.0.2.128",
            "64:ff9b::192.0.2.33",
        ] {
            assert!(whole(ipv6, ok), "{ok}");
        }
        for bad in [
            "12:30:45",
            "::",
            "::1",
            "1:2:3",
            "2001:db8::1::2",
            "12345::1",
            "g::1",
            "00:1A:2B:3C:4D:5E",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::ffff:1.2.3",
        ] {
            assert!(!whole(ipv6, bad), "{bad}");
        }
    }

    #[test]
    fn mac_needs_one_separator_kind_and_a_real_address() {
        for ok in [
            "00:1A:2B:3C:4D:5E",
            "00-1a-2b-3c-4d-5e",
            "a0:b1:c2:d3:e4:f5",
        ] {
            assert!(whole(mac, ok), "{ok}");
        }
        for bad in [
            "00:1A-2B:3C:4D:5E",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "FF-FF-FF-FF-FF-FF",
            "00:1A:2B:3C:4D",
            "00:1A:2B:3C:4D:5G",
            "00 1A 2B 3C 4D 5E",
        ] {
            assert!(!whole(mac, bad), "{bad}");
        }
    }

    #[test]
    fn card_needs_length_leading_digit_luhn_and_one_separator_kind() {
        for ok in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "3782 822463 10005",
            "378282246310005",
            "6011111111111117",
            "5500005555555559",
            "2221000000000009",
            "4222222222222",
            "30569309025904",
            "4917610000000000003",
        ] {
            assert!(whole(card, ok), "{ok}");
        }
        for bad in [
            "4111111111111112",     // Luhn
            "411111111111",         // 12 digits
            "49176100000000000030", // 20 digits
            "1234567812345670",     // first digit 1
            "7992739871000000",     // first digit 7
            "4111 1111-1111 1111",  // mixed separators
            "4111  1111 1111 1111", // double separator
            "4111 1111 1111 1111 ", // trailing separator is trimmed, not whole
            "4111/1111/1111/1111",
        ] {
            assert!(!whole(card, bad), "{bad:?}");
        }
    }

    #[test]
    fn card_trims_trailing_groups() {
        assert_eq!(
            accepted(card, "4111 1111 1111 1111 12"),
            Some("4111 1111 1111 1111")
        );
        assert_eq!(
            accepted(card, "4111-1111-1111-1111-123"),
            Some("4111-1111-1111-1111")
        );
        assert_eq!(
            accepted(card, "4111111111111111 123"),
            Some("4111111111111111")
        );
        assert_eq!(
            accepted(card, "4111-1111-1111-1111 123"),
            Some("4111-1111-1111-1111")
        );
        assert_eq!(
            accepted(card, "4111 1111 1111 1111 "),
            Some("4111 1111 1111 1111")
        );
        // No prefix at a separator is valid.
        assert_eq!(accepted(card, "4111 1111 1111 1112 12"), None);
    }

    #[test]
    fn phone_checks_digit_counts_per_form() {
        for ok in [
            "+31 6 12345678",
            "+31612345678",
            "+44 20 7946 0958",
            "+1 (555) 123-4567",
            "0031612345678",
            "0044 20 7946 0958",
            "06-12345678",
            "0612345678",
            "020 7946 0958",
            "01234 567890",
            "020123456",
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567",
            "5551234567",
        ] {
            assert!(whole(phone, ok), "{ok}");
        }
        for bad in [
            "01-02-2024",        // national form, 8 digits
            "+1234567",          // 7 digits
            "+1234567890123456", // 16 digits
            "0612345",           // too short for the national form
            "06123456789012",    // 14 digits, national form
            "123-456-7890",      // NANP area code cannot start with 1
            "555-123-456",       // 9 digits, NANP form
            "+0 12345678",       // country code cannot start with 0
            "+31 6 1234 5678 x",
        ] {
            assert!(!whole(phone, bad), "{bad}");
        }
    }

    #[test]
    fn phone_rejects_a_long_digit_run_between_mixed_separators() {
        // The same run of 14 digits: bare, behind one kind of separator, behind two.
        assert!(whole(phone, "+112345678901234"));
        assert!(whole(phone, "+1 12345678901234"));
        assert!(!whole(phone, "+1 (12345678901234"));
        // Mixed separators between short runs are ordinary.
        assert!(whole(phone, "+31 (0)6 12345678"));
    }

    #[test]
    fn phone_looks_at_the_byte_before() {
        for (before, number, ok) in [
            ("", "+31 6 12345678", true),
            (" ", "+31 6 12345678", true),
            ("x", "+31 6 12345678", false),
            ("7", "+31 6 12345678", false),
            ("/", "+31 6 12345678", false),
            ("+", "+31 6 12345678", false),
            ("tel:", "06-12345678", true),
            ("a", "06-12345678", false),
            ("1/", "06-12345678", false),
            ("x", "(555) 123-4567", false),
            (":", "(555) 123-4567", true),
        ] {
            let text = format!("{before}{number}");
            let got = phone(text.as_bytes(), before.len(), text.len());
            assert_eq!(got.is_some(), ok, "{text:?}");
        }
    }

    #[test]
    fn email_rejects_bad_local_parts() {
        for ok in [
            "jan.jansen@acme.nl",
            "a+tag@sub.example.co.uk",
            "x@y.io",
            "first_last%x@ex-ample.com",
            "A@B.COM",
        ] {
            assert!(whole(email, ok), "{ok}");
        }
        for bad in [
            ".jan@acme.nl",
            "jan.@acme.nl",
            "ja..n@acme.nl",
            "@acme.nl",
            "jan@acme",
            "jan@acme.n",
            "jan@acme.n1",
            "jan@.acme.nl",
            "jan@acme..nl",
            "jan@acme.nl.",
            "ja n@acme.nl",
        ] {
            assert!(!whole(email, bad), "{bad}");
        }
    }

    #[test]
    fn url_credential_trims_to_user_and_password() {
        assert_eq!(
            accepted(url_credential, "https://admin:hunter2@"),
            Some("admin:hunter2")
        );
        assert_eq!(
            within(
                url_credential,
                "see postgres://u:p:q@db/x",
                "postgres://u:p:q@"
            ),
            Some((15, 20))
        );
        assert_eq!(accepted(url_credential, "https://admin:hunter2"), None);
        assert_eq!(accepted(url_credential, "https://:x@"), None);
        assert_eq!(accepted(url_credential, "admin:hunter2@"), None);
    }

    #[test]
    fn credential_parts_hold_no_whitespace_slash_or_at_sign() {
        // The first colon ends the user; the password may hold more.
        assert!(credential(b"user:pa:ss"));
        for bad in [
            "us er:pass",
            "user:pa ss",
            "us/er:pass",
            "user:pa/ss",
            "us@er:pass",
            "user:pa@ss",
            ":pass",
            "user:",
            "user",
        ] {
            assert!(!credential(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn secret_accepts_each_known_token_format() {
        let ghp = format!("ghp_{}", "a1".repeat(18));
        let stripe = format!("sk_live_{}", "Z9".repeat(12));
        let google = format!("AIza{}", "x-_".repeat(11) + "yz");
        for ok in [
            "AKIAIOSFODNN7EXAMPLE",
            ghp.as_str(),
            "xoxb-123456789012-abcdefghij",
            stripe.as_str(),
            google.as_str(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ] {
            assert!(whole(secret, ok), "{ok}");
        }
        let short_ghp = &ghp[..ghp.len() - 1];
        for bad in [
            "AKIAIOSFODNN7EXAMPL",
            "AKIAiosfodnn7example",
            short_ghp,
            "xoxb-123",
            "sk_live_short",
            "AIza123",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "hello world",
            "",
        ] {
            assert!(!whole(secret, bad), "{bad}");
        }
    }

    #[test]
    fn context_finds_keywords_in_the_window_ignoring_case() {
        let hay = b"Social Security no: 123456789";
        let start = hay.len() - 9;
        assert!(context(hay, start, &["ssn", "social security"], 48));
        assert!(context(hay, start, &["SOCIAL SECURITY"], 48));
        assert!(!context(hay, start, &["bsn"], 48));
        // A keyword outside the window does not count.
        assert!(!context(hay, start, &["social security"], 10));
        assert!(context(hay, start, &["no:"], 10));
        // Edges: the very start of the haystack and an empty window.
        assert!(!context(hay, 0, &["ssn"], 48));
        assert!(!context(hay, start, &["ssn", "social security"], 0));
        assert!(
            !context(hay, 1000, &["ssn"], 48),
            "start past the end is just no context"
        );
    }

    #[test]
    fn nearest_context_reports_the_closest_keyword() {
        let hay = b"SSN 123-45-6789, BSN 111222333";
        let start = hay.len() - 9;
        assert_eq!(nearest_context(hay, start, &["bsn"], 48), Some(1));
        assert_eq!(nearest_context(hay, start, &["ssn"], 48), Some(18));
        assert_eq!(nearest_context(hay, start, &["ssn", "bsn"], 48), Some(1));
        assert_eq!(nearest_context(hay, start, &["social security"], 48), None);
    }

    #[test]
    fn context_keywords_must_start_a_word() {
        // The nine digits at the end of `text`, and the keyword `ssn` before them.
        let nearest = |text: &str, window: usize| {
            nearest_context(text.as_bytes(), text.len() - 9, &["ssn"], window)
        };
        // In a word of its own, in a snake_case name and in a camelCase one.
        assert_eq!(nearest("my ssn: 123456789", 48), Some(2));
        assert_eq!(nearest("employee_ssn=123456789", 48), Some(1));
        assert_eq!(nearest("employeeSSN=123456789", 48), Some(1));
        // The same letters inside a word are no keyword.
        assert_eq!(nearest("className=\"row\" 123456789", 48), None);
        assert_eq!(nearest("businessNumber: 123456789", 48), None);
        // An occurrence inside a word does not hide an earlier one that starts a word.
        let text = "SSN: x classname 123456789";
        assert_eq!(nearest(text, 48), Some(text.len() - 9 - "SSN".len()));
        // The byte before a keyword is read outside the window too: this window begins
        // inside `class`, where `ssn` would look like the start of a word.
        assert_eq!(nearest("classn 123456789", 4), None);
    }

    #[test]
    fn accepts_needs_the_whole_string_to_be_a_valid_value() {
        // The scan trims these; as values they are not valid.
        assert!(!accepts(EntityKind::Iban, "BE68 5390 0754 7034 EXTRA"));
        assert!(!accepts(EntityKind::CreditCard, "4111 1111 1111 1111 12"));
        assert!(!accepts(
            EntityKind::UrlCredential,
            "https://admin:hunter2@"
        ));
        // A URL credential is its `user:pass`, as a span covers it.
        assert!(accepts(EntityKind::UrlCredential, "admin:hunter2"));
        assert!(!accepts(EntityKind::UrlCredential, ""));
        // No context rule applies: a bare SSN and a bare BSN are valid without a keyword.
        assert!(accepts(EntityKind::UsSsn, "123456789"));
        assert!(accepts(EntityKind::NlBsn, "111222333"));
    }

    #[test]
    fn person_accepts_one_to_six_name_tokens() {
        for ok in [
            "Jeroen",
            "Ed",
            "Jeroen de Vries",
            "J. Jansen",
            "J.R.R. Tolkien",
            "MARIA LOPEZ-GARCIA",
            "jan van der berg",
            "Jan 't Hart",
            "'t Hart",
            "Patrick O'Brien",
            "Patrick O\u{2019}Brien",
            "Anne-Marie",
            "Zoë de Vries",
            "José García",
            "Jeroen  de\tVries",
        ] {
            assert!(accepts(EntityKind::Person, ok), "{ok:?}");
        }
    }

    #[test]
    fn person_accepts_decomposed_text_and_other_scripts() {
        for ok in [
            // `é` as `e` and a combining acute, as macOS file names and PDFs spell it.
            "Jose\u{301} Garci\u{301}a",
            "Zoe\u{308} de Vries",
            // A Greek name with a patronymic: 36 characters, 70 bytes.
            "Παναγιώτης Κωνσταντίνου Παπαδόπουλος",
            "Александър Георгиев Петров",
            "王小明",
        ] {
            assert!(accepts(EntityKind::Person, ok), "{ok:?}");
        }
        // A mark is no letter: a token of marks, or one letter and its mark, is no name.
        for bad in ["\u{301}", "Jeroen \u{301}", "E\u{301} Jansen"] {
            assert!(!accepts(EntityKind::Person, bad), "{bad:?}");
        }
    }

    #[test]
    fn person_is_capped_in_characters_and_tokens() {
        let tokens = |n: usize| vec!["Aa"; n].join(" ");
        assert!(accepts(EntityKind::Person, &tokens(PERSON_MAX_TOKENS)));
        assert!(!accepts(EntityKind::Person, &tokens(PERSON_MAX_TOKENS + 1)));
        // Two bytes per letter: only the characters count.
        assert!(accepts(EntityKind::Person, &"é".repeat(PERSON_MAX_CHARS)));
        assert!(!accepts(
            EntityKind::Person,
            &"é".repeat(PERSON_MAX_CHARS + 1)
        ));
    }

    #[test]
    fn person_rejects_other_shapes() {
        for (bad, why) in [
            ("", "empty"),
            (" ", "only whitespace"),
            (" Jeroen", "leading whitespace"),
            ("Jeroen ", "trailing whitespace"),
            ("J", "one-character first token"),
            ("A de Vries", "one-character first token"),
            ("Jeroen 3", "digit"),
            ("Jeroen2 de Vries", "digit"),
            ("Jeroen, de Vries", "comma"),
            ("jeroen@test.nl", "email"),
            ("Jeroen - Vries", "token without a letter"),
            ("Jeroen ..", "token without a letter"),
            ("..", "no letter"),
        ] {
            assert!(!accepts(EntityKind::Person, bad), "{why}: {bad:?}");
        }
    }

    #[test]
    fn model_kinds_share_the_common_rule() {
        let long = "a".repeat(MODEL_MAX_BYTES + 1);
        for kind in EntityKind::ALL.into_iter().filter(|k| !k.is_watermarked()) {
            assert!(!accepts(kind, ""), "{kind:?}: empty");
            assert!(!accepts(kind, " Jan Jansen"), "{kind:?}: leading space");
            assert!(!accepts(kind, "Jan Jansen\t"), "{kind:?}: trailing tab");
            assert!(!accepts(kind, "Jan\u{7}Jansen"), "{kind:?}: control");
            assert!(!accepts(kind, "ab"), "{kind:?}: two alphanumerics");
            assert!(!accepts(kind, "a-b-"), "{kind:?}: two alphanumerics");
            assert!(!accepts(kind, &long), "{kind:?}: over the byte limit");
        }
        assert!(accepts(EntityKind::Location, "Den Haag"));
        assert!(accepts(EntityKind::Location, &"a".repeat(MODEL_MAX_BYTES)));
        assert!(!accepts(EntityKind::Location, "Den\nHaag"), "newline");
        assert!(accepts(
            EntityKind::PostalAddress,
            "Keizersgracht 123\n1015 CJ Amsterdam"
        ));
        assert!(!accepts(EntityKind::PostalAddress, "Keizersgracht\r123"));
    }

    #[test]
    fn model_values_of_numeric_kinds_need_ascii_digits() {
        // (kind, a value with plenty of digits, a value of the same shape with none).
        let table = [
            (EntityKind::PersonIdentifier, "ID 482913", "ID unknown"),
            (EntityKind::AccountId, "acct-482913", "acct-unknown"),
            (EntityKind::BankAccount, "BE 1234 5678", "BE bank account"),
            (EntityKind::DocumentId, "NR 482913", "NR unknown"),
            (EntityKind::VehicleId, "AB-123-CD", "AB-XYZ-CD"),
            (EntityKind::DateOfBirth, "14 mei 1990", "mei negentien"),
            (EntityKind::GeoLocation, "52.3676, 4.9041", "near the canal"),
            (EntityKind::PaymentCard, "5555 5555 5555", "five fives"),
            (EntityKind::CardSecurity, "1234", "abcd"),
            (EntityKind::FinancialAmount, "EUR 1000", "EUR plenty"),
            (EntityKind::PhoneNumber, "06 12345678", "call him"),
        ];
        for (kind, with, without) in table {
            assert!(accepts(kind, with), "{kind:?}: {with}");
            assert!(!accepts(kind, without), "{kind:?}: {without}");
        }
        // Non-ASCII digits are not counted.
        assert!(!accepts(
            EntityKind::PhoneNumber,
            "\u{661}\u{662}\u{663}\u{664}\u{665}"
        ));
    }

    #[test]
    fn identifying_links_must_look_like_links() {
        for ok in [
            "https://example.org/jan",
            "HTTP://x.y",
            "www.example",
            "WWW.Example",
            "/users/jan",
            "linkedin.com/in/jan",
            "example.nl",
            "a.co",
            "see jan.nl now",
        ] {
            assert!(accepts(EntityKind::IdentifyingLink, ok), "{ok}");
        }
        for bad in [
            "jan jansen",
            "//x",
            "/ jan",
            "v1.2.3",
            "example.n",
            "example.nl2",
            "jan.",
            "@jan_jansen",
            "wwwexample",
        ] {
            assert!(!accepts(EntityKind::IdentifyingLink, bad), "{bad}");
        }
        // The same text is fine for kinds without the link rule.
        assert!(accepts(EntityKind::ContactHandle, "@jan_jansen"));
    }
}
