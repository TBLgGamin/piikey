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
#[must_use]
pub fn accepts(kind: EntityKind, s: &str) -> bool {
    let value = s.as_bytes();
    if kind == EntityKind::UrlCredential {
        return credential(value);
    }
    PATTERNS
        .iter()
        .find(|p| p.kind == kind)
        .is_some_and(|p| (p.validate)(value, 0, value.len()) == Some((0, value.len())))
}

/// Luhn checksum over ASCII digits. Empty input or any non-digit is invalid.
pub(super) fn luhn(digits: &[u8]) -> bool {
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

/// IBAN length per country. Countries missing here fall back to
/// [`IBAN_UNKNOWN`].
const IBAN_LENGTHS: [([u8; 2], usize); 33] = [
    (*b"AD", 24),
    (*b"AT", 20),
    (*b"BE", 16),
    (*b"BG", 22),
    (*b"CH", 21),
    (*b"CY", 28),
    (*b"CZ", 24),
    (*b"DE", 22),
    (*b"DK", 18),
    (*b"EE", 20),
    (*b"ES", 24),
    (*b"FI", 18),
    (*b"FR", 27),
    (*b"GB", 22),
    (*b"GR", 27),
    (*b"HR", 21),
    (*b"HU", 28),
    (*b"IE", 22),
    (*b"IS", 26),
    (*b"IT", 27),
    (*b"LI", 21),
    (*b"LT", 20),
    (*b"LU", 20),
    (*b"LV", 21),
    (*b"MT", 31),
    (*b"NL", 18),
    (*b"NO", 15),
    (*b"PL", 28),
    (*b"PT", 25),
    (*b"RO", 24),
    (*b"SE", 24),
    (*b"SI", 19),
    (*b"SK", 24),
];

/// Accepted IBAN lengths for countries not in [`IBAN_LENGTHS`].
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

/// IBAN: country table length (or 15..=34 for unknown countries) after
/// dropping spaces, and mod 97 equal to 1.
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

/// IPv6 text form accepted by [`Ipv6Addr`], except `::` and `::1`.
pub(super) fn ipv6(hay: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let text = std::str::from_utf8(hay.get(start..end)?).ok()?;
    let addr = Ipv6Addr::from_str(text).ok()?;
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
    let (user, pass) = (&value[..colon], &value[colon + 1..]);
    (1..=64).contains(&user.len())
        && (1..=128).contains(&pass.len())
        && !user
            .iter()
            .any(|&b| b.is_ascii_whitespace() || matches!(b, b'/' | b'@'))
        && !pass
            .iter()
            .any(|&b| b.is_ascii_whitespace() || matches!(b, b'/' | b'@'))
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
/// or `None` when no keyword occurs there.
pub(super) fn nearest_context(
    hay: &[u8],
    start: usize,
    keywords: &[&str],
    window: usize,
) -> Option<usize> {
    let before = hay.get(start.saturating_sub(window)..start)?;
    keywords
        .iter()
        .filter_map(|word| {
            let word = word.as_bytes();
            if word.is_empty() {
                return None;
            }
            let at = before
                .windows(word.len())
                .rposition(|w| w.eq_ignore_ascii_case(word))?;
            Some(before.len() - (at + word.len()))
        })
        .min()
}

/// True when one of `keywords` occurs (ASCII case-insensitive) in the `window`
/// bytes before `start`.
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

    #[test]
    fn iban_accepts_registry_examples() {
        for ok in [
            "NL91ABNA0417164300",
            "NL91 ABNA 0417 1643 00",
            "DE89370400440532013000",
            "DE89 3704 0044 0532 0130 00",
            "GB82WEST12345698765432",
            "FR1420041010050500013M02606",
            "BE68539007547034",
            "BE68 5390 0754 7034",
            "ES9121000418450200051332",
            "IT60X0542811101000000123456",
            "CH9300762011623852957",
            "AT611904300234573201",
            "NO9386011117947",
            "MT84MALT011000012345MTLCAST001S",
            "LI21088100002324013AA",
            // Not in the length table: only 15..=34 and mod 97 apply.
            "TR330006100519786457841326",
            "SA0380000000608010167519",
        ] {
            assert!(whole(iban, ok), "{ok}");
        }
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
            "TR330006100519786457841327", // unknown country, bad checksum
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
    fn phone_rejects_digit_runs_glued_to_other_separators() {
        assert!(
            whole(phone, "+3161234567890"),
            "one long run, no separators"
        );
        assert!(
            whole(phone, "+31 6123456789012"),
            "one long run, one separator kind"
        );
        assert!(
            whole(phone, "+3 (612345678901)"),
            "runs of 12 are fine with mixed separators"
        );
        assert!(
            !whole(phone, "+3 (6123456789012"),
            "long run plus mixed separators"
        );
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
    fn accepts_applies_the_validator_to_the_whole_string() {
        let table: [(EntityKind, &str, &str); 11] = [
            (
                EntityKind::Secret,
                "AKIAIOSFODNN7EXAMPLE",
                "AKIAIOSFODNN7EXAMPL",
            ),
            (EntityKind::UrlCredential, "admin:hunter2", "admin"),
            (EntityKind::Email, "jan.jansen@acme.nl", "jan.jansen@acme"),
            (EntityKind::Iban, "NL91ABNA0417164300", "NL91ABNA0417164301"),
            (
                EntityKind::CreditCard,
                "4111 1111 1111 1111",
                "4111 1111 1111 1112",
            ),
            (EntityKind::Ipv6, "2001:db8::1", "12:30:45"),
            (EntityKind::Mac, "00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D"),
            (EntityKind::Ipv4, "203.0.113.42", "127.0.0.1"),
            (EntityKind::UsSsn, "123-45-6789", "000-12-3456"),
            (EntityKind::NlBsn, "111222333", "111222334"),
            (EntityKind::Phone, "+31 6 12345678", "+31"),
        ];
        for (kind, good, bad) in table {
            assert!(accepts(kind, good), "{kind:?} {good}");
            assert!(!accepts(kind, bad), "{kind:?} {bad}");
        }
        // Trimming is not acceptance: the value must be valid as it stands.
        assert!(!accepts(EntityKind::Iban, "BE68 5390 0754 7034 EXTRA"));
        assert!(!accepts(
            EntityKind::UrlCredential,
            "https://admin:hunter2@"
        ));
        assert!(!accepts(EntityKind::UrlCredential, ""));
    }
}
