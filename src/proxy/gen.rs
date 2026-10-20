//! Deterministic, format-preserving proxy candidates.
//!
//! A candidate is a pure function of `(gen key, kind, original, attempt)`. Those inputs feed
//! a keyed BLAKE3 XOF and every random choice is read from that stream, so the same inputs
//! always give the same proxy while different attempts give independent candidates. The vault
//! walks `attempt = 0, 1, 2, ...` until a candidate carries the watermark and is unused.
//!
//! Unless a kind says otherwise, non-alphanumeric characters keep their positions and every
//! digit, upper-case letter or lower-case letter stays in its class.
//!
//! Two kinds are shaped on purpose so that deanonymizing, which cannot ask for context, never
//! mistakes them for a kind that outranks them. A bare nine-digit run is claimed by `UsSsn`
//! first, so a bare `NlBsn` proxy always has an area number in 900-999, and a bare nine-digit
//! `Phone` proxy has group `00`; both are rejected as SSNs. See [`bsn`] and [`phone`].
//!
//! A `Person` keeps its particles and shape and takes every other word from the name lists.
//! See [`person`].

use std::net::Ipv6Addr;

use blake3::{BLOCK_LEN, Hasher, OutputReader};

use super::{
    ProxyKeys, model,
    words::{FIRST, FREEMAIL, LAST, WORDS},
};
use crate::detect::{EntityKind, validate::accepts};

/// Fresh derivations tried when a candidate is unusable or equals the original. Each retry is
/// an independent stream, so the odds of needing more than a few are negligible.
const ROUNDS: u8 = 32;

/// BSN 11-proof weights. The last digit counts as -1, which is 10 modulo 11.
const BSN_WEIGHTS: [u32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, 10];

/// Attempts after which a candidate space is widened one step (see [`model`]). A value with
/// few free characters (a year, a two-digit id) has only a handful of candidates, and the vault
/// hands each original its own; later attempts get more room instead of running out.
const WIDEN_EVERY: u32 = 1024;

/// A proxy candidate for `original`, never equal to it unless no other value exists.
pub(super) fn generate(keys: &ProxyKeys, kind: EntityKind, original: &str, attempt: u32) -> String {
    let widen = attempt / WIDEN_EVERY;
    for round in 0..ROUNDS {
        let mut xof = Xof::new(keys, kind, original, attempt, round);
        if let Some(candidate) = build(kind, original, &mut xof, widen)
            && candidate != original
        {
            return candidate;
        }
    }
    // Nothing differs from the original (a value with nothing left to randomize). Returning
    // it lets the vault's own `!= original` check report the value as unmaskable.
    original.to_owned()
}

/// One candidate, or `None` when this derivation is unusable and the next round should run.
fn build(kind: EntityKind, original: &str, xof: &mut Xof, widen: u32) -> Option<String> {
    match kind {
        EntityKind::Secret => Some(secret(original, xof)),
        EntityKind::UrlCredential => Some(url_credential(original, xof)),
        EntityKind::Email => Some(email(original, xof)),
        EntityKind::Iban => Some(iban(original, xof)),
        EntityKind::CreditCard => Some(card(original, xof)),
        EntityKind::Ipv6 => Some(ipv6(original, xof)),
        EntityKind::Mac => mac(original, xof),
        EntityKind::Ipv4 => Some(ipv4(original, xof)),
        EntityKind::UsSsn => Some(ssn(original, xof)),
        EntityKind::NlBsn => bsn(original, xof),
        EntityKind::Phone => phone(original, xof),
        EntityKind::Person => person(original, xof),
        EntityKind::PersonAlias => {
            if accepts(EntityKind::Person, original) {
                person(original, xof)
            } else {
                model::shape_all(kind, original, xof, widen)
            }
        }
        EntityKind::PersonIdentifier
        | EntityKind::ContactHandle
        | EntityKind::DeviceId
        | EntityKind::AccountId
        | EntityKind::AuthSecret
        | EntityKind::BankAccount
        | EntityKind::DocumentId
        | EntityKind::DocumentReference
        | EntityKind::VehicleId
        | EntityKind::OrganizationId => model::shape_all(kind, original, xof, widen),
        EntityKind::PhoneNumber
        | EntityKind::GeoLocation
        | EntityKind::PaymentCard
        | EntityKind::CardSecurity
        | EntityKind::FinancialAmount => model::shape_digits(kind, original, xof, widen),
        EntityKind::DateOfBirth => model::date(kind, original, xof, widen),
        EntityKind::PostalAddress => model::address(kind, original, xof),
        EntityKind::Location => model::place(kind, original, xof),
        EntityKind::IdentifyingLink => model::link(kind, original, xof),
        EntityKind::OrganizationName => model::organization(kind, original, xof),
        EntityKind::ProperName => model::brand(kind, original, xof),
        EntityKind::PersonAttribute => model::tag(kind, "Trait", xof),
        EntityKind::PersonRole => model::tag(kind, "Role", xof),
        EntityKind::HealthData => model::tag(kind, "Health", xof),
        EntityKind::BiometricData => model::tag(kind, "Biometric", xof),
        EntityKind::EthnicOrigin => model::tag(kind, "Origin", xof),
        EntityKind::PoliticalOpinion => model::tag(kind, "Opinion", xof),
        EntityKind::ReligionOrBelief => model::tag(kind, "Belief", xof),
        EntityKind::SexualOrientation => model::tag(kind, "Orientation", xof),
        EntityKind::TradeUnion => model::tag(kind, "Union", xof),
        EntityKind::CriminalOffence => model::tag(kind, "Record", xof),
    }
}

/// The random stream behind one candidate: a keyed BLAKE3 XOF. `OutputReader` does not
/// buffer, so bytes are served from one block at a time instead of recompressing per byte.
pub(super) struct Xof {
    reader: OutputReader,
    block: [u8; BLOCK_LEN],
    next: usize,
}

impl Xof {
    /// `round` is a retry counter kept apart from `attempt` so retries never alias a
    /// different attempt's candidate. The fixed-width tail keeps the encoding unambiguous.
    fn new(keys: &ProxyKeys, kind: EntityKind, original: &str, attempt: u32, round: u8) -> Self {
        let reader = Hasher::new_keyed(&keys.gen_key)
            .update(&[kind as u8])
            .update(original.as_bytes())
            .update(&attempt.to_le_bytes())
            .update(&[round])
            .finalize_xof();
        Self {
            reader,
            block: [0; BLOCK_LEN],
            next: BLOCK_LEN,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.next == BLOCK_LEN {
            self.reader.fill(&mut self.block);
            self.next = 0;
        }
        let byte = self.block[self.next];
        self.next += 1;
        byte
    }

    /// Uniform in `0..n` by rejection sampling over the narrowest big-endian word that
    /// covers `n`. The first `2^bits mod n` values are rejected so that the rest divide
    /// evenly into runs of `n`.
    pub(super) fn below(&mut self, n: u32) -> u32 {
        let n = n.max(1);
        let (width, reject) = if n <= 1 << 8 {
            (1, (1 << 8) % n)
        } else if n <= 1 << 16 {
            (2, (1 << 16) % n)
        } else {
            (4, n.wrapping_neg() % n)
        };
        loop {
            let value = (0..width).fold(0u32, |acc, _| (acc << 8) | u32::from(self.byte()));
            if value >= reject {
                return value % n;
            }
        }
    }

    pub(super) fn digit(&mut self) -> u32 {
        self.below(10)
    }

    fn hextet(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    /// A uniformly chosen entry; `""` only for an empty list.
    pub(super) fn pick(&mut self, items: &[&'static str]) -> &'static str {
        let len = u32::try_from(items.len()).unwrap_or(u32::MAX);
        let index = usize::try_from(self.below(len)).unwrap_or_default();
        items.get(index).copied().unwrap_or("")
    }

    /// A random character of the same class as `c`; anything but a letter or digit stays.
    pub(super) fn alnum_like(&mut self, c: char) -> char {
        let base = match c {
            'A'..='Z' => 'A',
            'a'..='z' => 'a',
            '0'..='9' => return digit_char(self.digit()),
            other => return other,
        };
        char::from_u32(u32::from(base) + self.below(26)).unwrap_or(base)
    }

    /// A random ASCII letter in the case of `c`, different from `c` itself.
    fn other_letter(&mut self, c: char) -> char {
        let base = if c.is_uppercase() { 'A' } else { 'a' };
        let own = c
            .is_ascii_alphabetic()
            .then(|| u32::from(c) - u32::from(base));
        // Another letter of the 26 means one of the other 25.
        let mut index = self.below(if own.is_some() { 25 } else { 26 });
        if own.is_some_and(|own| index >= own) {
            index += 1;
        }
        char::from_u32(u32::from(base) + index).unwrap_or(base)
    }
}

/// `d` as an ASCII digit; `d` is always below 10.
pub(super) fn digit_char(d: u32) -> char {
    char::from_digit(d, 10).unwrap_or('0')
}

/// Rewrites the ASCII digits of `original` with `digits`, in order, and keeps every other
/// character where it is. Digit slots beyond `digits` get random digits.
fn render_digits(original: &str, digits: impl IntoIterator<Item = char>, xof: &mut Xof) -> String {
    let mut digits = digits.into_iter();
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                digits.next().unwrap_or_else(|| digit_char(xof.digit()))
            } else {
                c
            }
        })
        .collect()
}

/// Keeps the token format's literal prefix, and `eyJ` at the start of every JWT segment.
/// Everything else is replaced by a random character of its own class, so `-`, `_` and `.`
/// stay where they are.
fn secret(original: &str, xof: &mut Xof) -> String {
    let mut keep = secret_literal_len(original);
    let mut out = String::with_capacity(original.len());
    for (i, c) in original.char_indices() {
        if i >= keep && (i == 0 || original[..i].ends_with('.')) && original[i..].starts_with("eyJ")
        {
            keep = i + 3;
        }
        out.push(if i < keep { c } else { xof.alnum_like(c) });
    }
    out
}

/// Length of the literal that identifies the token format: `AKIA`, `AIza`, `gh?_`, `xox?-`
/// or `?k_live_`. JWTs have none (their `eyJ` segment starts are handled per segment).
fn secret_literal_len(s: &str) -> usize {
    match s.as_bytes() {
        [b'A', b'K', b'I', b'A', ..]
        | [b'A', b'I', b'z', b'a', ..]
        | [b'g', b'h', b'p' | b'o' | b'u' | b's' | b'r', b'_', ..] => 4,
        [b'x', b'o', b'x', b'b' | b'a' | b'p' | b'r' | b's', b'-', ..] => 5,
        [b's' | b'r', b'k', b'_', b'l', b'i', b'v', b'e', b'_', ..] => 8,
        _ => 0,
    }
}

/// `user:pass`: the user becomes `{first}{dd}`, the password keeps its length and character
/// classes.
fn url_credential(original: &str, xof: &mut Xof) -> String {
    let mut out = String::with_capacity(original.len() + 8);
    out.push_str(fresh_word(xof, &FIRST, original, &mut Vec::new()));
    out.push(digit_char(xof.digit()));
    out.push(digit_char(xof.digit()));
    if let Some((_, password)) = original.split_once(':') {
        out.push(':');
        out.extend(password.chars().map(|c| xof.alnum_like(c)));
    }
    out
}

/// `{first}{sep}{last}{dd}@domain`, lower case. `sep` follows the original local part (`.`,
/// else `_`, else none). A public mailbox provider keeps its domain; any other domain becomes
/// two neutral words under the original's top-level label.
fn email(original: &str, xof: &mut Xof) -> String {
    let (local, domain) = original.rsplit_once('@').unwrap_or((original, ""));
    let sep = if local.contains('.') {
        "."
    } else if local.contains('_') {
        "_"
    } else {
        ""
    };
    let mut out = String::with_capacity(48);
    let mut placed = Vec::new();
    out.push_str(fresh_word(xof, &FIRST, local, &mut placed));
    out.push_str(sep);
    out.push_str(fresh_word(xof, &LAST, local, &mut placed));
    out.push(digit_char(xof.digit()));
    out.push(digit_char(xof.digit()));
    out.push('@');
    if FREEMAIL.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
        out.push_str(domain);
    } else {
        out.push_str(xof.pick(&WORDS));
        out.push_str(xof.pick(&WORDS));
        out.push('.');
        let tld = domain.rsplit_once('.').map(|(_, tld)| tld);
        out.push_str(tld.filter(|t| !t.is_empty()).unwrap_or("com"));
    }
    out
}

/// Keeps the country code and every letter, randomizes the other digits and recomputes the
/// two check digits (`98 - (BBAN ++ country ++ "00") mod 97`).
fn iban(original: &str, xof: &mut Xof) -> String {
    let mut alnum: Vec<char> = original
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    for (i, c) in alnum.iter_mut().enumerate() {
        if (2..4).contains(&i) {
            *c = '0';
        } else if c.is_ascii_digit() {
            *c = digit_char(xof.digit());
        }
    }
    // Letters count as the two digits 10..=35. Rearranged: BBAN, country, `00`.
    let rem = alnum
        .iter()
        .skip(4)
        .chain(alnum.iter().take(4))
        .fold(0u32, |acc, c| {
            let value = c.to_digit(36).unwrap_or(0);
            let radix = if value < 10 { 10 } else { 100 };
            (acc * radix + value) % 97
        });
    if let [_, _, tens, ones, ..] = alnum.as_mut_slice() {
        let check = 98 - rem;
        *tens = digit_char(check / 10);
        *ones = digit_char(check % 10);
    }
    let mut alnum = alnum.into_iter();
    original
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                alnum.next().unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Keeps the first digit and the separator layout; the last digit is the Luhn check digit.
fn card(original: &str, xof: &mut Xof) -> String {
    let total = original.chars().filter(char::is_ascii_digit).count();
    let mut out = String::with_capacity(original.len());
    let mut index = 0;
    let mut sum = 0;
    for c in original.chars() {
        let Some(first) = c.to_digit(10) else {
            out.push(c);
            continue;
        };
        let from_right = total - 1 - index;
        let digit = if index == 0 {
            first
        } else if from_right == 0 {
            (10 - sum % 10) % 10
        } else {
            xof.digit()
        };
        sum += luhn_term(digit, from_right);
        out.push(digit_char(digit));
        index += 1;
    }
    out
}

/// A digit's contribution to the Luhn sum; every second digit from the right is doubled.
fn luhn_term(digit: u32, from_right: usize) -> u32 {
    if from_right % 2 == 1 {
        let doubled = digit * 2;
        if doubled > 9 { doubled - 9 } else { doubled }
    } else {
        digit
    }
}

/// Keeps the first hextet; the other 112 bits are random. Upper case if the original had
/// `A-F`.
fn ipv6(original: &str, xof: &mut Xof) -> String {
    let first = match original.parse::<Ipv6Addr>() {
        Ok(addr) => addr.segments()[0],
        Err(_) => original
            .split(':')
            .next()
            .and_then(|h| u16::from_str_radix(h, 16).ok())
            .unwrap_or(0x2001),
    };
    let mut segments = [first, 0, 0, 0, 0, 0, 0, 0];
    for segment in segments.iter_mut().skip(1) {
        *segment = xof.hextet();
    }
    // Trailing zero hextets print as `::`, and the detector needs the text to end in a hex
    // digit; a non-zero last hextet rules that out.
    while segments[7] == 0 {
        segments[7] = xof.hextet();
    }
    let text = Ipv6Addr::from(segments).to_string();
    if original.bytes().any(|b| matches!(b, b'A'..=b'F')) {
        text.to_ascii_uppercase()
    } else {
        text
    }
}

/// Keeps the vendor prefix (first three octets), separators and case; the last three octets
/// are random. `None` for an all-zero or all-`f` address, which the detector rejects.
fn mac(original: &str, xof: &mut Xof) -> Option<String> {
    let upper = original.bytes().any(|b| matches!(b, b'A'..=b'F'));
    let mut out = String::with_capacity(original.len());
    let mut hex_digits = 0;
    for c in original.chars() {
        if c.is_ascii_hexdigit() {
            if hex_digits < 6 {
                out.push(c);
            } else {
                let nibble = char::from_digit(xof.below(16), 16).unwrap_or('0');
                out.push(if upper {
                    nibble.to_ascii_uppercase()
                } else {
                    nibble
                });
            }
            hex_digits += 1;
        } else {
            out.push(c);
        }
    }
    let uniform = |digit: char| {
        out.chars()
            .filter(char::is_ascii_hexdigit)
            .all(|c| c.eq_ignore_ascii_case(&digit))
    };
    (!uniform('0') && !uniform('f')).then_some(out)
}

/// Private ranges keep their prefix (`10/8`, `172.16/12`, `192.168/16`); anything else
/// becomes a public-looking address that avoids those ranges, loopback, link-local and
/// carrier-grade NAT space. The last octet is a host (1-254).
fn ipv4(original: &str, xof: &mut Xof) -> String {
    let mut octets = original.split('.').map(|o| o.parse::<u32>().ok());
    let first = octets.next().flatten();
    let second = octets.next().flatten();
    let (o1, o2) = match (first, second) {
        (Some(10), _) => (10, xof.below(256)),
        (Some(172), Some(16..=31)) => (172, 16 + xof.below(16)),
        (Some(192), Some(168)) => (192, 168),
        _ => (public_first_octet(xof), xof.below(256)),
    };
    let o3 = xof.below(256);
    let o4 = 1 + xof.below(254);
    format!("{o1}.{o2}.{o3}.{o4}")
}

fn public_first_octet(xof: &mut Xof) -> u32 {
    loop {
        let octet = 1 + xof.below(223);
        if !matches!(octet, 10 | 100 | 127 | 169 | 172 | 192) {
            return octet;
        }
    }
}

/// Area 001-899 except 666, group 01-99, serial 0001-9999, in the original's layout.
fn ssn(original: &str, xof: &mut Xof) -> String {
    let area = loop {
        let area = 1 + xof.below(899);
        if area != 666 {
            break area;
        }
    };
    let group = 1 + xof.below(99);
    let serial = 1 + xof.below(9999);
    let digits = format!("{area:03}{group:02}{serial:04}");
    render_digits(original, digits.chars(), xof)
}

/// Eight random digits plus the 11-proof check digit, in the original's layout. `None`
/// when the check digit would be 10.
///
/// A bare nine-digit proxy gets an area number in 900-999. Deanonymizing needs no keyword,
/// and a bare nine-digit run is claimed by `UsSsn` before `NlBsn`; SSNs never have such an
/// area, so the number falls through to `NlBsn`. A dotted layout can't be an SSN and keeps
/// a free first digit (1-9).
fn bsn(original: &str, xof: &mut Xof) -> Option<String> {
    let bare = original.bytes().all(|b| b.is_ascii_digit());
    let mut digits = [0u32; 9];
    for (i, digit) in digits.iter_mut().take(8).enumerate() {
        *digit = match i {
            0 if bare => 9,
            0 => 1 + xof.below(9),
            _ => xof.digit(),
        };
    }
    let sum: u32 = digits.iter().zip(BSN_WEIGHTS).map(|(d, w)| d * w).sum();
    let check = sum % 11;
    if check == 10 {
        return None;
    }
    digits[8] = check;
    Some(render_digits(
        original,
        digits.into_iter().map(digit_char),
        xof,
    ))
}

/// True when the nine digits of `s` pass the BSN 11-proof.
fn is_bsn(s: &str) -> bool {
    let sum: u32 = s
        .chars()
        .filter_map(|c| c.to_digit(10))
        .zip(BSN_WEIGHTS)
        .map(|(d, w)| d * w)
        .sum();
    sum.is_multiple_of(11)
}

/// `dddd.dd.ddd` BSN layout: four digits, a dot, two digits, a dot, three digits.
fn is_dotted_bsn_layout(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 11
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'.'
            } else {
                c.is_ascii_digit()
            }
        })
}

/// Keeps the `+`/`00`/trunk `0` prefix, the country code and the first national digit (the
/// mobile or landline marker); every other digit is random. NANP area codes and exchanges
/// start with 2-9.
///
/// Phones rank below SSN and BSN, which only demand a keyword when anonymizing. So a bare
/// nine-digit national number gets group `00` (never an SSN) and, like a dotted `4.2.3`
/// layout, is rejected when it happens to pass the BSN 11-proof.
fn phone(original: &str, xof: &mut Xof) -> Option<String> {
    let total = original.chars().filter(char::is_ascii_digit).count();
    let (keep, nanp_leads) = phone_lead(original, total);
    let bare_nine = total == 9 && original.len() == 9;
    let mut out = String::with_capacity(original.len());
    let mut index = 0;
    for c in original.chars() {
        let Some(orig) = c.to_digit(10) else {
            out.push(c);
            continue;
        };
        let digit = if index < keep {
            orig
        } else if nanp_leads.contains(&Some(index)) {
            2 + xof.below(8)
        } else if bare_nine && (index == 3 || index == 4) {
            0
        } else {
            xof.digit()
        };
        out.push(digit_char(digit));
        index += 1;
    }
    let bsn_shaped = bare_nine || is_dotted_bsn_layout(original);
    (!bsn_shaped || !is_bsn(&out)).then_some(out)
}

/// How many leading digits of a phone number are copied, and the digit indexes that must lie
/// in 2-9 (the NANP area code and exchange leads that are not copied).
fn phone_lead(original: &str, total: usize) -> (usize, [Option<usize>; 2]) {
    let mut lead = [0u32; 6];
    for (slot, digit) in lead
        .iter_mut()
        .zip(original.chars().filter_map(|c| c.to_digit(10)))
    {
        *slot = digit;
    }
    // `+` or `00` introduces a country code; `skip` is the number of `00` digits.
    let skip = if original.starts_with('+') {
        0
    } else if lead[..2] == [0, 0] {
        2
    } else if lead[0] == 0 {
        // National number with a trunk `0`: that and the marker after it.
        return (2, [None, None]);
    } else {
        // No prefix at all: NANP, `(AAA) EEE-LLLL`.
        return (0, [Some(0), (total == 10).then_some(3)]);
    };
    let national = skip + country_code_len(&lead[skip..]);
    // A trunk `0` after the country code (`+31 (0)6`) is followed by the real marker.
    let keep = national + 1 + usize::from(lead[national] == 0);
    let nanp = lead[skip] == 1 && national == skip + 1 && total == skip + 11;
    (keep, [nanp.then_some(skip + 4), None])
}

/// Digits in the country calling code that starts `digits` (ITU-T E.164 code lengths).
fn country_code_len(digits: &[u32]) -> usize {
    let first = digits.first().copied().unwrap_or(0);
    if matches!(first, 1 | 7) {
        return 1;
    }
    let two = first * 10 + digits.get(1).copied().unwrap_or(0);
    if matches!(
        two,
        20 | 27 | 30..=34 | 36 | 39..=41 | 43..=49 | 51..=58 | 60..=66 | 81 | 82 | 84 | 86 | 90..=95 | 98
    ) {
        2
    } else {
        3
    }
}

/// Name particles. A proxy keeps them: they say nothing about who the person is, and they
/// make `Jeroen de Vries` read as `Haley de Zessen`. Compared ignoring ASCII case.
const PARTICLES: [&str; 21] = [
    "van", "de", "der", "den", "het", "von", "zu", "du", "da", "la", "le", "di", "del", "bin",
    "ibn", "al", "el", "ter", "ten", "'t", "op",
];

/// One token more than a valid name has. Longer originals fail the validator anyway, so a huge
/// string is not rewritten token by token.
const TOKEN_CAP: usize = 7;

/// Draws made for one word in search of a list word that the original and the proxy do not
/// use yet.
const FRESH_TRIES: u32 = 16;

/// How one whitespace-separated token of a name is rewritten.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    /// Kept as it is.
    Particle,
    /// `J.` or `J.R.`: every letter becomes another letter.
    Initials,
    /// Replaced by a word from the lists.
    Word,
}

/// The list a word is drawn from.
#[derive(Clone, Copy)]
enum Role {
    Given,
    Family,
}

/// The letter case of a token, which the words that replace it copy.
#[derive(Clone, Copy)]
pub(super) enum Case {
    Upper,
    Lower,
    Title,
}

/// A name in the shape of `original`: tokens joined by single spaces, particles kept, initials
/// swapped for other initials and every other token swapped for a name from the lists, in the
/// letter case of the token it replaces. Words never repeat and never reuse a word of the
/// original, which would give part of the real name away.
///
/// The first word is a given name unless a particle or initials come before it (`de Vries`,
/// `J. Jansen`); every later word is a family name.
///
/// An original with exactly one word and no initials (`Jeroen`, `de Vries`) gets a hyphenated
/// pair (`Haley-Marian`) in place of that word. Only one candidate in sixteen carries the
/// watermark, so of the 200 words in a list about a dozen can ever be a proxy and the thirteenth
/// single-word name would find none; the 200 x 200 pairs leave room for thousands.
///
/// `None` when the result is not a valid name (the original has too many tokens, or it has none).
fn person(original: &str, xof: &mut Xof) -> Option<String> {
    let tokens: Vec<&str> = original.split_whitespace().take(TOKEN_CAP).collect();
    // Particles are only kept next to something else: a name made of nothing but particles
    // (`Al`) would otherwise have nothing to change.
    let anchored = tokens.iter().any(|t| !is_particle(t));
    let part = |token: &str| {
        if anchored && is_particle(token) {
            Part::Particle
        } else if is_initials(token) {
            Part::Initials
        } else {
            Part::Word
        }
    };
    let words = tokens.iter().filter(|t| part(t) == Part::Word).count();
    let has_initials = tokens.iter().any(|t| part(t) == Part::Initials);
    let pair = words == 1 && !has_initials;

    let mut role = Role::Given;
    let mut placed: Vec<&'static str> = Vec::new();
    let mut out = String::with_capacity(original.len() + 8);
    for token in tokens {
        if !out.is_empty() {
            out.push(' ');
        }
        match part(token) {
            Part::Particle => out.push_str(token),
            Part::Initials => out.extend(token.chars().map(|c| {
                if c.is_alphabetic() {
                    xof.other_letter(c)
                } else {
                    c
                }
            })),
            Part::Word => {
                let pool: &[&'static str] = match role {
                    Role::Given => &FIRST,
                    Role::Family => &LAST,
                };
                let case = case_of(token);
                let word = fresh_word(xof, pool, original, &mut placed);
                out.push_str(&restyle(word, case));
                if pair {
                    out.push('-');
                    let second = fresh_word(xof, pool, original, &mut placed);
                    out.push_str(&restyle(second, case));
                }
            }
        }
        role = Role::Family;
    }
    accepts(EntityKind::Person, &out).then_some(out)
}

/// True for a particle, also in its `\u{2019}t` spelling that word processors produce.
fn is_particle(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix(['\u{2018}', '\u{2019}']) {
        return rest.eq_ignore_ascii_case("t");
    }
    PARTICLES.iter().any(|p| p.eq_ignore_ascii_case(token))
}

/// True for initials: letters that are each followed by a dot, as in `J.` or `J.R.`.
fn is_initials(token: &str) -> bool {
    let mut chars = token.chars();
    let mut any = false;
    while let Some(letter) = chars.next() {
        if !letter.is_alphabetic() || chars.next() != Some('.') {
            return false;
        }
        any = true;
    }
    any
}

/// A word of `pool` that is neither a word of `original` nor in `placed` yet, when one of the
/// first [`FRESH_TRIES`] draws is such a word, else the last draw. The word is added to `placed`.
fn fresh_word(
    xof: &mut Xof,
    pool: &[&'static str],
    original: &str,
    placed: &mut Vec<&'static str>,
) -> &'static str {
    let mut word = xof.pick(pool);
    for _ in 1..FRESH_TRIES {
        let taken = placed.contains(&word)
            || original
                .split(|c: char| !c.is_alphabetic())
                .any(|part| part.eq_ignore_ascii_case(word));
        if !taken {
            break;
        }
        word = xof.pick(pool);
    }
    placed.push(word);
    word
}

/// All capitals (two letters or more), all lower case, or anything else, which reads as title
/// case (`McDonald` and `O'Brien` included).
pub(super) fn case_of(token: &str) -> Case {
    let upper = token.chars().filter(|c| c.is_uppercase()).count();
    let lower = token.chars().filter(|c| c.is_lowercase()).count();
    if upper == 0 && lower > 0 {
        Case::Lower
    } else if upper >= 2 && lower == 0 {
        Case::Upper
    } else {
        Case::Title
    }
}

/// `word`, a lower-case list word, in `case`.
pub(super) fn restyle(word: &str, case: Case) -> String {
    match case {
        Case::Lower => word.to_owned(),
        Case::Upper => word.to_ascii_uppercase(),
        Case::Title => {
            let (head, tail) = word.split_at(word.len().min(1));
            format!("{}{tail}", head.to_ascii_uppercase())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Case, FIRST, LAST, PARTICLES, Xof, country_code_len, generate, restyle};
    use crate::{
        detect::{EntityKind, validate::accepts},
        proxy::{ProxyKeys, watermark_ok},
    };

    fn xof() -> Xof {
        let keys = ProxyKeys::new([3; 32], [4; 32]);
        Xof::new(&keys, EntityKind::Phone, "x", 0, 0)
    }

    #[test]
    fn below_stays_in_range_for_every_width() {
        let mut xof = xof();
        for n in [
            0, 1, 2, 3, 10, 26, 200, 255, 256, 257, 899, 9999, 65_535, 65_536, 65_537,
        ] {
            for _ in 0..200 {
                assert!(xof.below(n) < n.max(1), "below({n})");
            }
        }
        for n in [100_000, u32::MAX / 2 + 1, u32::MAX] {
            for _ in 0..200 {
                assert!(xof.below(n) < n, "below({n})");
            }
        }
    }

    /// Draws `below(n)` repeatedly, folds the results into `buckets` equal ranges and checks
    /// each range got its fair share, within six standard deviations.
    fn assert_uniform(n: u32, buckets: u32, draws: u32) {
        let mut xof = xof();
        let mut counts = vec![0u32; usize::try_from(buckets).unwrap_or(1)];
        for _ in 0..draws {
            let bucket = usize::try_from(xof.below(n) / (n / buckets)).unwrap_or(0);
            counts[bucket] += 1;
        }
        let expected = f64::from(draws / buckets);
        let tolerance = 6.0 * expected.sqrt();
        for count in counts {
            assert!(
                (f64::from(count) - expected).abs() < tolerance,
                "below({n}): {count} draws in a range, expected {expected}"
            );
        }
    }

    #[test]
    fn below_is_uniform_on_every_sampling_width() {
        assert_uniform(3, 3, 30_000); // one byte, 1 value rejected
        assert_uniform(200, 200, 100_000); // one byte, 56 values rejected
        assert_uniform(300, 300, 90_000); // two bytes, 236 values rejected
        assert_uniform(100_000, 10, 100_000); // four bytes
    }

    #[test]
    fn stream_is_deterministic_and_attempt_sensitive() {
        let keys = ProxyKeys::new([3; 32], [4; 32]);
        let draw = |attempt, round| {
            let mut xof = Xof::new(&keys, EntityKind::Email, "a@b.co", attempt, round);
            (0..80).map(|_| xof.byte()).collect::<Vec<u8>>()
        };
        assert_eq!(draw(0, 0), draw(0, 0));
        assert_ne!(draw(0, 0), draw(1, 0));
        assert_ne!(draw(0, 0), draw(0, 1));
    }

    #[test]
    fn country_code_lengths() {
        assert_eq!(country_code_len(&[1, 4, 1]), 1);
        assert_eq!(country_code_len(&[7, 9, 5]), 1);
        assert_eq!(country_code_len(&[3, 1, 6]), 2);
        assert_eq!(country_code_len(&[4, 4, 2]), 2);
        assert_eq!(country_code_len(&[3, 5, 8]), 3);
        assert_eq!(country_code_len(&[9, 7, 1]), 3);
        assert_eq!(country_code_len(&[]), 3);
    }

    /// The proxy of `original` under fixed keys.
    fn make(original: &str, attempt: u32) -> String {
        let keys = ProxyKeys::new([3; 32], [4; 32]);
        generate(&keys, EntityKind::Person, original, attempt)
    }

    fn in_list(list: &[&str], word: &str) -> bool {
        list.iter().any(|w| w.eq_ignore_ascii_case(word))
    }

    /// First letter upper case, every other letter lower case.
    fn is_title(token: &str) -> bool {
        let mut letters = token.chars().filter(|c| c.is_alphabetic());
        letters.next().is_some_and(char::is_uppercase) && letters.all(char::is_lowercase)
    }

    #[test]
    fn person_keeps_particles_in_place_and_changes_every_other_token() {
        for (original, kept) in [
            ("Jeroen de Vries", vec![1]),
            ("Jan van der Berg", vec![1, 2]),
            ("Jan 't Hart", vec![1]),
            ("Jan \u{2019}t Hart", vec![1]),
            ("de Vries", vec![0]),
            ("Maria VAN DEN Berg", vec![1, 2]),
            ("Piet op de Beeck", vec![1, 2]),
            ("Jeroen Vries", vec![]),
            ("Jan Willem Karel Pieter Hendrik Jansen", vec![]),
        ] {
            let before: Vec<&str> = original.split(' ').collect();
            for attempt in 0..16 {
                let proxy = make(original, attempt);
                let after: Vec<&str> = proxy.split(' ').collect();
                assert_eq!(before.len(), after.len(), "{original} -> {proxy}");
                for (i, (b, a)) in before.iter().zip(&after).enumerate() {
                    if kept.contains(&i) {
                        assert_eq!(a, b, "{original} -> {proxy}");
                    } else {
                        assert!(!a.eq_ignore_ascii_case(b), "{original} -> {proxy}");
                    }
                }
            }
        }
    }

    #[test]
    fn person_takes_a_given_name_first_and_family_names_after_it() {
        for attempt in 0..32 {
            let proxy = make("Jan Willem Jansen", attempt);
            let words: Vec<&str> = proxy.split(' ').collect();
            assert_eq!(words.len(), 3, "{proxy}");
            assert!(in_list(&FIRST, words[0]), "{proxy}");
            assert!(
                in_list(&LAST, words[1]) && in_list(&LAST, words[2]),
                "{proxy}"
            );
        }
    }

    #[test]
    fn person_leading_particles_or_initials_make_the_next_word_a_family_name() {
        for attempt in 0..32 {
            let proxy = make("de Vries Jansen", attempt);
            let words: Vec<&str> = proxy.split(' ').collect();
            assert_eq!(words[0], "de", "{proxy}");
            assert!(
                in_list(&LAST, words[1]) && in_list(&LAST, words[2]),
                "{proxy}"
            );

            let proxy = make("J. Jansen", attempt);
            let words: Vec<&str> = proxy.split(' ').collect();
            assert!(in_list(&LAST, words[1]), "{proxy}");
        }
    }

    #[test]
    fn person_case_follows_each_original_token() {
        for attempt in 0..16 {
            for token in make("jeroen de vries", attempt).split(' ') {
                assert_eq!(token, token.to_lowercase());
            }
            for token in make("JEROEN DE VRIES", attempt).split(' ') {
                assert_eq!(token, token.to_uppercase());
            }
            let mixed = make("Jeroen DE vries", attempt);
            let tokens: Vec<&str> = mixed.split(' ').collect();
            assert!(is_title(tokens[0]), "{mixed}");
            assert_eq!(tokens[1], "DE");
            assert_eq!(tokens[2], tokens[2].to_lowercase(), "{mixed}");
            let double = make("MARIA LOPEZ-GARCIA", attempt);
            assert_eq!(double, double.to_uppercase());
            // Mixed case inside a token reads as title case.
            for token in make("McDonald O'Brien", attempt).split(' ') {
                assert!(is_title(token), "{token}");
            }
        }
        assert_eq!(restyle("haley", Case::Title), "Haley");
        assert_eq!(restyle("haley", Case::Upper), "HALEY");
        assert_eq!(restyle("haley", Case::Lower), "haley");
        assert_eq!(restyle("", Case::Title), "");
    }

    #[test]
    fn person_initials_become_other_initials_in_the_same_case() {
        for attempt in 0..64 {
            let proxy = make("J. Jansen", attempt);
            let (initial, family) = proxy.split_once(' ').unwrap_or_default();
            let mut letters = initial.chars();
            let (letter, dot) = (letters.next(), letters.next());
            assert!(
                letter.is_some_and(|l| l.is_ascii_uppercase() && l != 'J'),
                "{proxy}"
            );
            assert_eq!(dot, Some('.'), "{proxy}");
            assert_eq!(letters.next(), None, "{proxy}");
            assert!(is_title(family) && in_list(&LAST, family), "{proxy}");

            let lower = make("j. jansen", attempt);
            assert!(
                lower.starts_with(|c: char| c.is_ascii_lowercase() && c != 'j'),
                "{lower}"
            );
            assert!(lower[1..].starts_with(". "), "{lower}");

            let several = make("J.R.R. Tolkien", attempt);
            let first = several.split(' ').next().unwrap_or_default();
            assert_eq!(first.chars().count(), 6, "{several}");
            for (got, want) in first.chars().zip("J.R.R.".chars()) {
                if want == '.' {
                    assert_eq!(got, '.', "{several}");
                } else {
                    assert!(got.is_ascii_uppercase() && got != want, "{several}");
                }
            }

            // A middle initial in a longer name.
            let middle = make("Jeroen J. de Vries", attempt);
            let words: Vec<&str> = middle.split(' ').collect();
            assert_eq!(words.len(), 4, "{middle}");
            assert_eq!(words[2], "de", "{middle}");
            assert!(words[1].len() == 2 && words[1].ends_with('.'), "{middle}");

            // Initials with an accent: any ASCII letter of the same case will do.
            let accented = make("\u{c9}. Garc\u{ed}a", attempt);
            assert!(accented.is_ascii(), "{accented}");
            assert!(
                accented.starts_with(|c: char| c.is_ascii_uppercase()),
                "{accented}"
            );
        }
    }

    #[test]
    fn person_with_one_word_gets_one_hyphenated_pair() {
        for (original, pool, prefix) in [
            ("Jeroen", &FIRST, ""),
            ("de Vries", &LAST, "de "),
            ("van der Berg", &LAST, "van der "),
            ("'t Hart", &LAST, "'t "),
            ("Al", &FIRST, ""),
        ] {
            for attempt in 0..32 {
                let proxy = make(original, attempt);
                let rest = proxy.strip_prefix(prefix).unwrap_or_default();
                let (a, b) = rest.split_once('-').unwrap_or_default();
                assert!(is_title(a) && is_title(b), "{original} -> {proxy}");
                assert!(
                    in_list(pool, a) && in_list(pool, b),
                    "{original} -> {proxy}"
                );
                assert!(!a.eq_ignore_ascii_case(b), "{original} -> {proxy}");
                assert!(!rest.contains(' '), "{original} -> {proxy}");
            }
        }
        let upper = make("MARIA", 0);
        assert_eq!(upper, upper.to_uppercase());
        assert!(upper.contains('-'));
        // Two words, or a word and initials, stay a single word each.
        for original in ["Jeroen Vries", "J. Jansen", "Jan 't Hart"] {
            assert!(!make(original, 0).contains('-'), "{original}");
        }
    }

    #[test]
    fn person_made_of_particles_only_still_changes() {
        for original in ["Al", "De", "van der", "Op"] {
            for attempt in 0..8 {
                let proxy = make(original, attempt);
                assert!(
                    !proxy.eq_ignore_ascii_case(original),
                    "{original} -> {proxy}"
                );
                assert!(accepts(EntityKind::Person, &proxy), "{original} -> {proxy}");
            }
        }
    }

    #[test]
    fn person_proxy_reuses_no_word_of_the_original_and_repeats_none() {
        let first = restyle(FIRST[0], Case::Title);
        let last = restyle(LAST[0], Case::Title);
        let originals = [
            format!("{first} {last}"),
            format!("{last} {first}"),
            format!("{first} van {last}"),
            format!("{first}-{last}"),
            first.clone(),
            format!("{first} {first} {last} {last}"),
        ];
        for original in &originals {
            let own: Vec<String> = original
                .split(|c: char| !c.is_alphabetic())
                .map(str::to_lowercase)
                .collect();
            for attempt in 0..400 {
                let proxy = make(original, attempt);
                let words: Vec<String> = proxy
                    .split(|c: char| !c.is_alphabetic())
                    .filter(|w| !w.is_empty() && !in_list(&PARTICLES, w))
                    .map(str::to_lowercase)
                    .collect();
                for word in &words {
                    assert!(!own.contains(word), "{original} -> {proxy}");
                }
                let distinct: HashSet<&String> = words.iter().collect();
                assert_eq!(distinct.len(), words.len(), "{original} -> {proxy}");
            }
        }
    }

    #[test]
    fn person_proxies_are_valid_ascii_names_and_never_the_original() {
        for original in [
            "Jeroen de Vries",
            "Aa Bb Cc Dd Ee Ff",
            "Zo\u{eb} de Vries",
            "Jos\u{e9}",
            "\u{c9}. Garc\u{ed}a",
            "Patrick O\u{2019}Brien",
            "Anne-Marie",
            "Al",
        ] {
            for attempt in 0..200 {
                let proxy = make(original, attempt);
                assert!(accepts(EntityKind::Person, &proxy), "{original} -> {proxy}");
                assert!(proxy.is_ascii(), "{original} -> {proxy}");
                assert_ne!(proxy, original);
            }
        }
    }

    #[test]
    fn person_without_a_name_or_with_too_many_tokens_has_no_candidate() {
        for original in ["", " ", "\t\n", "a b c d e f g", "a b c d e f g h i j"] {
            assert_eq!(make(original, 0), original, "{original:?}");
        }
    }

    #[test]
    fn single_word_names_have_proxies_to_spare() {
        // The vault takes the first candidate that carries the watermark and is unused. One
        // list word per name would give out after about a dozen names; the pairs do not.
        let keys = ProxyKeys::new([3; 32], [4; 32]);
        let passing = FIRST
            .iter()
            .filter(|w| watermark_ok(&keys, EntityKind::Person, w))
            .count();
        assert!(
            (1..40).contains(&passing),
            "{passing} of 200 words pass the watermark"
        );

        let mut used = HashSet::new();
        for i in 0..400u32 {
            let letters: String = (0..4)
                .map(|d| char::from(b'a' + u8::try_from(i / 26u32.pow(d) % 26).unwrap_or(0)))
                .collect();
            let original = format!("Zq{letters}");
            let found = (0..4096)
                .map(|attempt| generate(&keys, EntityKind::Person, &original, attempt))
                .find(|p| watermark_ok(&keys, EntityKind::Person, p) && !used.contains(p));
            let Some(found) = found else {
                panic!("no proxy left for name number {i}");
            };
            used.insert(found);
        }
    }

    #[test]
    fn names_in_the_lists_are_not_particles() {
        // A list word that is a particle would be kept as it is when a proxy is read as a name.
        for (name, list) in [("FIRST", &FIRST), ("LAST", &LAST)] {
            for word in list {
                assert!(!in_list(&PARTICLES, word), "{name}: {word} is a particle");
            }
        }
    }
}
