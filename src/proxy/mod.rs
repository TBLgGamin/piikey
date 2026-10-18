//! Format-preserving proxy generation and the invisible keyed watermark.
//!
//! [`generate`] turns a PII value into a believable stand-in of the same shape: the same
//! separators and character classes and, where it matters for believability, the same
//! country code, vendor prefix or mailbox provider. A proxy is a pure function of the
//! vault's `gen` key, the value's kind, the value and an attempt counter, so a value always
//! maps to the same proxy.
//!
//! [`watermark_ok`] is the invisible mark. The vault only issues candidates that carry it
//! (a random value passes with probability 1/16), so deanonymizing can discard most strings
//! that merely look like PII without consulting the vault.

use std::fmt;

use blake3::Hasher;
use zeroize::Zeroizing;

use crate::detect::EntityKind;

// `gen` is a reserved keyword in edition 2024.
mod r#gen;
mod words;

/// Keys for proxy derivation (`gen`) and watermarking (`mark`).
pub struct ProxyKeys {
    gen_key: Zeroizing<[u8; 32]>,
    mark_key: Zeroizing<[u8; 32]>,
}

impl ProxyKeys {
    #[must_use]
    pub fn new(gen_key: [u8; 32], mark_key: [u8; 32]) -> Self {
        Self {
            gen_key: Zeroizing::new(gen_key),
            mark_key: Zeroizing::new(mark_key),
        }
    }
}

// Hand-written so that formatting a vault or an engine never prints key material.
impl fmt::Debug for ProxyKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyKeys").finish_non_exhaustive()
    }
}

/// True when `proxy` carries the keyed watermark for `kind` (1/16 chance for
/// a random value).
///
/// The tag is the low nibble of the first byte of `blake3_keyed(mark, kind ++ proxy)`. It is
/// a hash of the whole value, so nothing in the proxy's text reveals it.
#[must_use]
pub fn watermark_ok(keys: &ProxyKeys, kind: EntityKind, proxy: &str) -> bool {
    // Two updates hash `kind ++ proxy` without concatenating them into a buffer.
    let tag = Hasher::new_keyed(&keys.mark_key)
        .update(&[kind as u8])
        .update(proxy.as_bytes())
        .finalize();
    // Low nibble zero.
    tag.as_bytes()[0].trailing_zeros() >= 4
}

/// Deterministic candidate proxy for `original`; `attempt` selects the
/// candidate. Pure: same keys + inputs give the same output.
///
/// The candidate never equals `original` unless the value has nothing left to randomize,
/// in which case no candidate exists and the caller's own `!= original` check ends in
/// exhaustion. Candidates are not checked against the watermark; the caller walks
/// `attempt` upward until [`watermark_ok`] passes.
#[must_use]
pub fn generate(keys: &ProxyKeys, kind: EntityKind, original: &str, attempt: u32) -> String {
    r#gen::generate(keys, kind, original, attempt)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::Ipv6Addr};

    use super::{
        ProxyKeys, generate, watermark_ok,
        words::{FREEMAIL, WORDS},
    };
    use crate::{
        Result,
        detect::{Detector, EntityKind, Mode, RegexDetector, validate::accepts},
    };

    const EMAIL: &[&str] = &[
        "jan.jansen@acme.nl",
        "jane_doe@gmail.com",
        "jsmith@example.org",
        "Sales.Team@Contoso.com",
        "first.last@sub.domain.co.uk",
        "x@y.io",
        "a.b.c@hotmail.com",
        "user+tag@outlook.com",
        "info@xs4all.nl",
        "PETER@ZIGGO.NL",
        "anna-maria@planet.nl",
        "dev_ops@startup.dev",
    ];
    const IBAN: &[&str] = &[
        "NL91ABNA0417164300",
        "NL91 ABNA 0417 1643 00",
        "GB82WEST12345698765432",
        "GB82 WEST 1234 5698 7654 32",
        "DE89370400440532013000",
        "DE89 3704 0044 0532 0130 00",
        "FR1420041010050500013M02606",
        "FR14 2004 1010 0505 0001 3M02 606",
        "ES9121000418450200051332",
        "IT60X0542811101000000123456",
        "BE68539007547034",
        "CH9300762011623852957",
        "NO9386011117947",
        "AT611904300234573201",
        "PL61109010140000071219812874",
        "LU280019400644750000",
        "IE29AIBK93115212345678",
        "DK5000400440116243",
        "SE4550000000058398257466",
        "PT50000201231234567890154",
    ];
    const CARD: &[&str] = &[
        "4111111111111111",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "5500000000000004",
        "340000000000009",
        "3530111333300000",
        "6011000990139424",
        "2223000048410010",
        "5105105105105100",
        "4012888888881881",
        "378282246310005",
        "30569309025904",
        "4222222222222",
        "3714 496353 98431",
        "6011 1111 1111 1117",
    ];
    const IPV6: &[&str] = &[
        "2001:db8::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1ff:fe23:4567:890a",
        "2001:DB8::ff00:42:8329",
        "2a00:1450:4001:81b::200e",
        "2607:f8b0:4005:80a::200e",
        "fd00:1234:5678:9abc:def0:1234:5678:9abc",
        "fc00::1",
        "2001:4860:4860::8888",
        "2620:0:ccc::2",
        "2a02:2f0b:1::1",
        "FE80::ABCD:EF01:2345:6789",
        "::ffff:0:1",
        "2001:db8:0:1:1:1:1:1",
    ];
    const MAC: &[&str] = &[
        "00:1A:2B:3C:4D:5E",
        "00-1a-2b-3c-4d-5e",
        "a4:5e:60:c2:9b:11",
        "3C:22:FB:00:11:22",
        "DC-A6-32-01-02-03",
        "b8:27:eb:12:34:56",
        "00:0c:29:ab:cd:ef",
        "F0:18:98:AA:BB:CC",
        "ac-de-48-00-11-22",
        "52:54:00:12:34:56",
    ];
    const IPV4: &[&str] = &[
        "192.168.1.10",
        "10.0.0.1",
        "172.16.254.3",
        "172.31.0.9",
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.45",
        "198.51.100.7",
        "100.64.0.1",
        "169.254.10.20",
        "192.0.2.33",
        "34.120.55.9",
        "10.255.255.254",
        "192.168.100.200",
        "185.60.216.35",
        "20.50.100.150",
    ];
    const SSN: &[&str] = &[
        "123-45-6789",
        "123 45 6789",
        "123456789",
        "078-05-1120",
        "219-09-9999",
        "001-01-0001",
        "899-99-9999",
        "665-12-3456",
        "667-12-3456",
        "457-55-5462",
        "700 12 3456",
        "545-33-1234",
        "111-11-1111",
        "234 56 7890",
    ];
    const BSN: &[&str] = &[
        "111222333",
        "123456782",
        "100000010",
        "234567892",
        "314159265",
        "271828183",
        "987654329",
        "141421356",
        "577215668",
        "161803398",
        "202401017",
        "445566772",
        "808080805",
        "737373738",
        "1112.22.333",
        "1234.56.782",
        "2345.67.892",
        "3141.59.265",
        "9876.54.329",
    ];
    const PHONE: &[&str] = &[
        "+31 6 12345678",
        "+31612345678",
        "06-12345678",
        "0612345678",
        "+31 20 123 4567",
        "020-1234567",
        "+44 20 7946 0958",
        "+44 (0)20 7946 0958",
        "+49 151 12345678",
        "0049 151 12345678",
        "+1 415 555 2671",
        "+1 (415) 555-2671",
        "(555) 234-5678",
        "555-234-5678",
        "555.234.5678",
        "5552345678",
        "212 555 0199",
        "+33 1 23 45 67 89",
        "01 23 45 67 89",
        "+39 06 1234 5678",
        "+32 470 12 34 56",
        "+34 612 345 678",
        "+358 40 1234567",
        "+7 495 123-45-67",
        "+81 3-1234-5678",
        "+61 4 1234 5678",
        "+353 87 123 4567",
        "+86 138 0013 8000",
        "+91 98765 43210",
        "+971 50 123 4567",
        "+55 11 91234-5678",
        "+27 82 123 4567",
        "+90 532 123 45 67",
        "021234567",
        "089123456",
        "0612.34.567",
        "0031 6 12345678",
        "+4915112345678",
        "+1-415-555-2671",
    ];
    const URL_CREDENTIAL: &[&str] = &[
        "admin:hunter2",
        "bob:s3cr3t!pass",
        "deploy:Zx9$kLm2",
        "root:toor",
        "jan.jansen:W1nter2024!",
        "user:pass:with:colons",
        "ci-bot:ghp_abc123",
        "a:b",
        "db_admin:Passw0rd#1",
        "john:12345",
        "mail:Qwerty!23",
    ];

    /// Repeating pool of alphanumerics for building tokens of an exact length.
    fn pool(n: usize) -> String {
        "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9"
            .chars()
            .cycle()
            .take(n)
            .collect()
    }

    fn secrets() -> Vec<String> {
        let mut all: Vec<String> = [
            "AKIAIOSFODNN7EXAMPLE",
            "AKIAZ7XQ2LMP4TAB9CDE",
            "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
            "xoxp-1234567890-0987654321-AbCdEf",
            "xoxa-2-1234567890-0987654321-AbCdEf",
            "xoxr-1234567890-0987654321-AbCdEf",
            "xoxs-1234567890-0987654321-AbCdEf",
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzIn0.Xz9qLm2PvT4wRk8NfB3dYc7HsJ1aUe5g",
        ]
        .map(str::to_owned)
        .into();
        for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
            all.push(format!("{prefix}{}", pool(36)));
        }
        all.push(format!("rk_live_{}", pool(30)));
        all.push(format!(
            "AIza{}",
            "SyA-1234567890_abcdefghijklmnopqrstuvw"
                .chars()
                .take(35)
                .collect::<String>()
        ));
        all
    }

    /// Hand-written valid values in the layouts people write them.
    fn seeds(kind: EntityKind) -> Vec<String> {
        let list: &[&str] = match kind {
            EntityKind::Secret => return secrets(),
            EntityKind::UrlCredential => URL_CREDENTIAL,
            EntityKind::Email => EMAIL,
            EntityKind::Iban => IBAN,
            EntityKind::CreditCard => CARD,
            EntityKind::Ipv6 => IPV6,
            EntityKind::Mac => MAC,
            EntityKind::Ipv4 => IPV4,
            EntityKind::UsSsn => SSN,
            EntityKind::NlBsn => BSN,
            EntityKind::Phone => PHONE,
        };
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Seeds plus values derived from them under a different key: same layouts, new digits.
    fn samples(kind: EntityKind) -> Vec<String> {
        let other = ProxyKeys::new([0x55; 32], [0xaa; 32]);
        let mut all = seeds(kind);
        for seed in seeds(kind) {
            all.extend((0..6).map(|attempt| generate(&other, kind, &seed, attempt)));
        }
        all.sort();
        all.dedup();
        all
    }

    fn keys() -> ProxyKeys {
        ProxyKeys::new([1; 32], [2; 32])
    }

    /// The same characters at the same positions except that every digit and letter is
    /// replaced by one of its own class.
    fn same_layout(original: &str, proxy: &str) -> bool {
        original.chars().count() == proxy.chars().count()
            && original.chars().zip(proxy.chars()).all(|(o, p)| {
                if o.is_ascii_digit() {
                    p.is_ascii_digit()
                } else if o.is_ascii_uppercase() {
                    p.is_ascii_uppercase()
                } else if o.is_ascii_lowercase() {
                    p.is_ascii_lowercase()
                } else {
                    o == p
                }
            })
    }

    fn digits(s: &str) -> Vec<u32> {
        s.chars().filter_map(|c| c.to_digit(10)).collect()
    }

    // Reference checks, written independently of the generators. The seeds are real-world
    // sample values, so a formula that accepts them is the right formula.

    fn luhn_ok(s: &str) -> bool {
        let d = digits(s);
        let sum: u32 = d
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &v)| {
                if i % 2 == 1 {
                    v * 2 % 10 + v * 2 / 10
                } else {
                    v
                }
            })
            .sum();
        (13..=19).contains(&d.len()) && sum.is_multiple_of(10)
    }

    fn iban_ok(s: &str) -> bool {
        let compact: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
        let rem = compact
            .iter()
            .skip(4)
            .chain(compact.iter().take(4))
            .fold(0u32, |acc, c| {
                let v = c.to_digit(36).unwrap_or(0);
                (acc * if v < 10 { 10 } else { 100 } + v) % 97
            });
        rem == 1
    }

    fn bsn_ok(s: &str) -> bool {
        let d = digits(s);
        let weights = [9, 8, 7, 6, 5, 4, 3, 2, 10];
        d.len() == 9
            && d.iter()
                .zip(weights)
                .map(|(d, w)| d * w)
                .sum::<u32>()
                .is_multiple_of(11)
    }

    fn ssn_ok(s: &str) -> bool {
        let d = digits(s);
        if d.len() != 9 {
            return false;
        }
        let number = |r: &[u32]| r.iter().fold(0, |acc, d| acc * 10 + d);
        let (area, group, serial) = (number(&d[..3]), number(&d[3..5]), number(&d[5..]));
        area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
    }

    fn octets(s: &str) -> Vec<u32> {
        s.split('.').filter_map(|o| o.parse().ok()).collect()
    }

    #[test]
    fn samples_are_plentiful_and_the_reference_checks_accept_the_seeds() {
        for kind in EntityKind::ALL {
            assert!(
                samples(kind).len() >= 50,
                "{kind:?}: {}",
                samples(kind).len()
            );
        }
        assert!(CARD.iter().all(|s| luhn_ok(s)));
        assert!(IBAN.iter().all(|s| iban_ok(s)));
        assert!(BSN.iter().all(|s| bsn_ok(s)));
        assert!(SSN.iter().all(|s| ssn_ok(s)));
        assert!(!luhn_ok("4111111111111112"));
        assert!(!iban_ok("NL91ABNA0417164301"));
        assert!(!bsn_ok("111222334"));
        assert!(!ssn_ok("000-12-3456") && !ssn_ok("666-12-3456") && !ssn_ok("900-12-3456"));
    }

    #[test]
    fn generation_is_deterministic_distinct_and_attempt_sensitive() {
        let (a, b) = (keys(), ProxyKeys::new([7; 32], [2; 32]));
        for kind in EntityKind::ALL {
            for original in samples(kind) {
                let proxy = generate(&a, kind, &original, 0);
                assert_eq!(
                    proxy,
                    generate(&a, kind, &original, 0),
                    "{kind:?} {original}"
                );
                assert_ne!(proxy, original, "{kind:?}");
                assert_ne!(
                    proxy,
                    generate(&b, kind, &original, 0),
                    "gen key: {kind:?} {original}"
                );
            }
            for original in seeds(kind) {
                let distinct: HashSet<String> = (0..64)
                    .map(|attempt| generate(&a, kind, &original, attempt))
                    .collect();
                assert!(
                    distinct.len() >= 60,
                    "{kind:?} {original}: {}",
                    distinct.len()
                );
            }
        }
    }

    #[test]
    fn checksummed_kinds_stay_valid() {
        let k = keys();
        for original in samples(EntityKind::CreditCard) {
            let proxy = generate(&k, EntityKind::CreditCard, &original, 0);
            assert!(luhn_ok(&proxy), "{original} -> {proxy}");
            assert_eq!(original.chars().next(), proxy.chars().next());
        }
        for original in samples(EntityKind::Iban) {
            let proxy = generate(&k, EntityKind::Iban, &original, 0);
            assert!(iban_ok(&proxy), "{original} -> {proxy}");
            let letters = |s: &str| -> Vec<(usize, char)> {
                s.char_indices()
                    .filter(|(_, c)| c.is_ascii_alphabetic())
                    .collect()
            };
            assert_eq!(
                letters(&original),
                letters(&proxy),
                "letters stay: {original} -> {proxy}"
            );
        }
        for original in samples(EntityKind::NlBsn) {
            let proxy = generate(&k, EntityKind::NlBsn, &original, 0);
            assert!(bsn_ok(&proxy), "{original} -> {proxy}");
        }
        for original in samples(EntityKind::UsSsn) {
            let proxy = generate(&k, EntityKind::UsSsn, &original, 0);
            assert!(ssn_ok(&proxy), "{original} -> {proxy}");
        }
    }

    #[test]
    fn layouts_and_classes_are_preserved() {
        let k = keys();
        for kind in [
            EntityKind::CreditCard,
            EntityKind::Iban,
            EntityKind::UsSsn,
            EntityKind::NlBsn,
            EntityKind::Phone,
            EntityKind::Secret,
        ] {
            for original in samples(kind) {
                for attempt in 0..3 {
                    let proxy = generate(&k, kind, &original, attempt);
                    assert!(
                        same_layout(&original, &proxy),
                        "{kind:?}: {original} -> {proxy}"
                    );
                }
            }
        }
    }

    #[test]
    fn email_shape_follows_the_original() {
        let k = keys();
        for original in samples(EntityKind::Email) {
            let proxy = generate(&k, EntityKind::Email, &original, 0);
            let (local, domain) = proxy.split_once('@').unwrap_or_default();
            let (orig_local, orig_domain) = original.split_once('@').unwrap_or_default();
            assert!(local.len() > 4 && local.is_ascii(), "{proxy}");
            let (name, tail) = local.split_at(local.len() - 2);
            assert!(tail.bytes().all(|b| b.is_ascii_digit()), "{proxy}");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_'),
                "{proxy}"
            );
            let sep = if orig_local.contains('.') {
                Some('.')
            } else if orig_local.contains('_') {
                Some('_')
            } else {
                None
            };
            let seps: Vec<char> = name.chars().filter(|c| !c.is_ascii_lowercase()).collect();
            assert_eq!(seps, sep.into_iter().collect::<Vec<_>>(), "{proxy}");
            if FREEMAIL.iter().any(|d| d.eq_ignore_ascii_case(orig_domain)) {
                assert_eq!(domain, orig_domain, "{proxy}");
            } else {
                let (label, tld) = domain.rsplit_once('.').unwrap_or_default();
                assert_eq!(
                    Some(tld),
                    orig_domain.rsplit_once('.').map(|(_, t)| t),
                    "{proxy}"
                );
                let words_pair = WORDS.iter().any(|a| {
                    WORDS.iter().any(|b| {
                        label.len() == a.len() + b.len()
                            && label.starts_with(a)
                            && label.ends_with(b)
                    })
                });
                assert!(words_pair, "{proxy}");
            }
        }
    }

    #[test]
    fn ip_proxies_follow_their_ranges() {
        let k = keys();
        for original in samples(EntityKind::Ipv4) {
            let proxy = generate(&k, EntityKind::Ipv4, &original, 0);
            let (o, p) = (octets(&original), octets(&proxy));
            assert_eq!(p.len(), 4, "{proxy}");
            assert!(
                p.iter().all(|&x| x <= 255) && (1..=254).contains(&p[3]),
                "{proxy}"
            );
            match (o[0], o[1]) {
                (10, _) => assert_eq!(p[0], 10, "{original} -> {proxy}"),
                (172, 16..=31) => assert!(
                    p[0] == 172 && (16..=31).contains(&p[1]),
                    "{original} -> {proxy}"
                ),
                (192, 168) => assert!(p[0] == 192 && p[1] == 168, "{original} -> {proxy}"),
                _ => assert!(
                    (1..=223).contains(&p[0]) && ![10, 100, 127, 169, 172, 192].contains(&p[0]),
                    "{original} -> {proxy}"
                ),
            }
        }
        for original in samples(EntityKind::Ipv6) {
            let proxy = generate(&k, EntityKind::Ipv6, &original, 0);
            let (Ok(o), Ok(p)) = (original.parse::<Ipv6Addr>(), proxy.parse::<Ipv6Addr>()) else {
                panic!("{original} -> {proxy}");
            };
            assert_eq!(o.segments()[0], p.segments()[0], "{original} -> {proxy}");
            assert!(proxy.ends_with(|c: char| c.is_ascii_hexdigit()), "{proxy}");
            let upper = original.bytes().any(|b| matches!(b, b'A'..=b'F'));
            assert!(
                !proxy.bytes().any(|b| if upper {
                    matches!(b, b'a'..=b'f')
                } else {
                    matches!(b, b'A'..=b'F')
                }),
                "{original} -> {proxy}"
            );
        }
    }

    #[test]
    fn mac_keeps_vendor_prefix_and_case() {
        let k = keys();
        for original in samples(EntityKind::Mac) {
            let proxy = generate(&k, EntityKind::Mac, &original, 0);
            assert_eq!(original[..8], proxy[..8], "{original} -> {proxy}");
            let upper = original.bytes().any(|b| matches!(b, b'A'..=b'F'));
            assert!(
                !proxy.bytes().any(|b| if upper {
                    matches!(b, b'a'..=b'f')
                } else {
                    matches!(b, b'A'..=b'F')
                }),
                "{original} -> {proxy}"
            );
        }
    }

    #[test]
    fn phone_keeps_prefix_and_marker_and_nanp_leads() {
        let k = keys();
        let kept = [
            ("+31 6 12345678", "+31 6"),
            ("06-12345678", "06"),
            ("+44 (0)20 7946 0958", "+44 (0)2"),
            ("+44 20 7946 0958", "+44 2"),
            ("+1 415 555 2671", "+1 4"),
            ("0049 151 12345678", "0049 1"),
            ("+358 40 1234567", "+358 4"),
            ("+7 495 123-45-67", "+7 4"),
            ("+39 06 1234 5678", "+39 06"),
            ("+971 50 123 4567", "+971 5"),
        ];
        for (original, prefix) in kept {
            for attempt in 0..8 {
                let proxy = generate(&k, EntityKind::Phone, original, attempt);
                assert!(proxy.starts_with(prefix), "{original} -> {proxy}");
            }
        }
        // NANP: area code and exchange start with 2-9 (index 0 and 3 of the ten digits).
        for original in [
            "(555) 234-5678",
            "555-234-5678",
            "5552345678",
            "+1 (415) 555-2671",
        ] {
            for attempt in 0..32 {
                let proxy = generate(&k, EntityKind::Phone, original, attempt);
                let d = digits(&proxy);
                let ten = &d[d.len() - 10..];
                assert!(ten[0] >= 2 && ten[3] >= 2, "{original} -> {proxy}");
            }
        }
    }

    #[test]
    fn bsn_and_phone_proxies_never_read_as_an_ssn_when_bare() {
        let k = keys();
        for original in ["111222333", "123456782", "100000010", "987654329"] {
            for attempt in 0..64 {
                let proxy = generate(&k, EntityKind::NlBsn, original, attempt);
                assert!(
                    proxy.starts_with('9') && bsn_ok(&proxy) && !ssn_ok(&proxy),
                    "{proxy}"
                );
            }
        }
        for original in ["021234567", "089123456"] {
            for attempt in 0..64 {
                let proxy = generate(&k, EntityKind::Phone, original, attempt);
                assert!(!bsn_ok(&proxy) && !ssn_ok(&proxy), "{original} -> {proxy}");
            }
        }
        // Dotted `4.2.3` is not an SSN layout; it only has to dodge the BSN 11-proof.
        for attempt in 0..64 {
            let proxy = generate(&k, EntityKind::Phone, "0612.34.567", attempt);
            assert!(!bsn_ok(&proxy), "{proxy}");
        }
        // A dotted BSN can never be an SSN, so its first digit is free.
        let firsts: HashSet<char> = (0..64)
            .filter_map(|attempt| {
                generate(&k, EntityKind::NlBsn, "1112.22.333", attempt)
                    .chars()
                    .next()
            })
            .collect();
        assert!(firsts.len() > 3, "{firsts:?}");
    }

    #[test]
    fn secrets_keep_their_literals() {
        let k = keys();
        let literals = [
            "AKIA", "AIza", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "xoxb-", "xoxa-", "xoxp-",
            "xoxr-", "xoxs-", "sk_live_", "rk_live_",
        ];
        for original in secrets() {
            let proxy = generate(&k, EntityKind::Secret, &original, 0);
            if let Some(literal) = literals.iter().find(|l| original.starts_with(**l)) {
                assert!(proxy.starts_with(literal), "{original} -> {proxy}");
            }
            let segments =
                |s: &str| -> Vec<bool> { s.split('.').map(|p| p.starts_with("eyJ")).collect() };
            assert_eq!(
                segments(&original),
                segments(&proxy),
                "{original} -> {proxy}"
            );
            assert_ne!(original, proxy);
        }
    }

    #[test]
    fn url_credentials_get_a_fresh_user_and_a_same_shape_password() {
        let k = keys();
        for original in samples(EntityKind::UrlCredential) {
            let proxy = generate(&k, EntityKind::UrlCredential, &original, 0);
            let (user, pass) = proxy.split_once(':').unwrap_or_default();
            let (orig_user, orig_pass) = original.split_once(':').unwrap_or_default();
            assert_ne!(user, orig_user, "{original} -> {proxy}");
            let (name, tail) = user.split_at(user.len().saturating_sub(2));
            assert!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase()),
                "{proxy}"
            );
            assert!(tail.bytes().all(|b| b.is_ascii_digit()), "{proxy}");
            assert!(same_layout(orig_pass, pass), "{original} -> {proxy}");
        }
    }

    #[test]
    fn odd_inputs_never_panic() {
        let k = keys();
        let long_digits = "9".repeat(40);
        let odd = [
            "",
            " ",
            "\u{e9}",
            "+",
            "@",
            ":",
            "::",
            "...",
            "00",
            "0",
            "1",
            "9",
            "AKIA",
            "a:b:c",
            "eyJ.eyJ.",
            ".",
            "\u{0661}\u{0662}",
            long_digits.as_str(),
            "+0",
            "00 0",
            "a@",
            "@a",
            "a@b",
            "a@b.",
            "::::::::",
        ];
        for kind in EntityKind::ALL {
            for original in odd {
                for attempt in 0..4 {
                    let proxy = generate(&k, kind, original, attempt);
                    assert_eq!(proxy, generate(&k, kind, original, attempt));
                }
            }
        }
    }

    #[test]
    fn watermark_is_a_keyed_one_in_sixteen_tag_bound_to_the_kind() {
        let (a, other_mark, other_gen) = (
            keys(),
            ProxyKeys::new([1; 32], [9; 32]),
            ProxyKeys::new([8; 32], [2; 32]),
        );
        let values: Vec<String> = (0..16_000).map(|i| format!("value-{i}")).collect();
        let count = |f: &dyn Fn(&str) -> bool| values.iter().filter(|v| f(v)).count();
        let email = count(&|v| watermark_ok(&a, EntityKind::Email, v));
        assert!(
            (800..1200).contains(&email),
            "1000 +- 100 expected, got {email}"
        );
        // Independent per kind: about 1/256 pass both.
        let both = count(&|v| {
            watermark_ok(&a, EntityKind::Email, v) && watermark_ok(&a, EntityKind::Phone, v)
        });
        assert!((20..120).contains(&both), "62 expected, got {both}");
        // Bound to the mark key, not to the gen key.
        let same_mark = count(&|v| {
            watermark_ok(&a, EntityKind::Email, v)
                == watermark_ok(&other_mark, EntityKind::Email, v)
        });
        assert!(
            same_mark < values.len(),
            "a different mark key must change some outcomes"
        );
        let same_gen = count(&|v| {
            watermark_ok(&a, EntityKind::Email, v) == watermark_ok(&other_gen, EntityKind::Email, v)
        });
        assert_eq!(same_gen, values.len());
    }

    #[test]
    fn every_kind_reaches_a_watermarked_candidate() {
        let k = keys();
        for kind in EntityKind::ALL {
            for original in seeds(kind) {
                let found = (0..4096).find(|&attempt| {
                    watermark_ok(&k, kind, &generate(&k, kind, &original, attempt))
                });
                assert!(found.is_some(), "{kind:?} {original}");
            }
        }
    }

    #[test]
    fn debug_output_hides_key_material() {
        let shown = format!("{:?}", ProxyKeys::new([0x41; 32], [0x42; 32]));
        assert_eq!(shown, "ProxyKeys { .. }");
    }

    // The tests below need the detect agent's validators and detector.

    /// The text a proxy is detected in. A URL credential only exists inside a URL.
    fn context(kind: EntityKind, proxy: &str) -> String {
        if kind == EntityKind::UrlCredential {
            format!("Contact: https://{proxy}@example.org, thanks.")
        } else {
            format!("Contact: {proxy}, thanks.")
        }
    }

    #[test]
    fn seeds_and_proxies_pass_the_kind_validators() {
        let k = keys();
        for kind in EntityKind::ALL {
            for seed in seeds(kind) {
                assert!(accepts(kind, &seed), "seed {kind:?}: {seed}");
            }
            for original in samples(kind) {
                for attempt in 0..3 {
                    let proxy = generate(&k, kind, &original, attempt);
                    assert!(accepts(kind, &proxy), "{kind:?}: {original} -> {proxy}");
                }
            }
        }
    }

    #[test]
    fn detector_finds_each_proxy_exactly_once_with_the_same_kind() -> Result<()> {
        let k = keys();
        let detector = RegexDetector::new()?;
        for kind in EntityKind::ALL {
            for original in samples(kind) {
                for attempt in 0..3 {
                    let proxy = generate(&k, kind, &original, attempt);
                    let text = context(kind, &proxy);
                    let spans = detector.detect(&text, Mode::Deanonymize);
                    let exact = matches!(spans.as_slice(), [s] if s.kind == kind && text[s.start..s.end] == proxy);
                    assert!(
                        exact,
                        "{kind:?}: {original} -> {proxy}: {spans:?} in {text:?}"
                    );
                }
            }
        }
        Ok(())
    }
}
