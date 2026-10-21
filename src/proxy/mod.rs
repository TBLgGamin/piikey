//! Format-preserving proxy generation and the invisible keyed watermark.
//!
//! [`generate`] turns a PII value into a believable stand-in of the same shape: the same
//! separators and character classes and, where it matters for believability, the same
//! country code, vendor prefix or mailbox provider. A proxy is a pure function of the
//! vault's `gen` key, the value's kind, the value and an attempt counter, so a value always
//! maps to the same proxy.
//!
//! [`watermark_ok`] is the invisible mark. For the kinds that carry one
//! ([`EntityKind::is_watermarked`]) the vault only issues candidates that have it (a random
//! value passes with probability 1/16), so deanonymizing can discard most strings that merely
//! look like PII without consulting the vault. The other kinds are found by exact vault lookup.

use std::fmt;

use blake3::Hasher;
use zeroize::Zeroizing;

use crate::detect::EntityKind;

// `gen` is a reserved keyword in edition 2024.
mod r#gen;
mod model;
mod words;

pub(crate) use words::is_particle;

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
/// exhaustion. Candidates are not checked against the watermark; for a kind that carries one
/// the caller walks `attempt` upward until [`watermark_ok`] passes.
#[must_use]
pub fn generate(keys: &ProxyKeys, kind: EntityKind, original: &str, attempt: u32) -> String {
    r#gen::generate(keys, kind, original, attempt)
}

#[cfg(test)]
mod tests {
    use rayon::prelude::*;
    use std::{collections::HashSet, net::Ipv6Addr};

    use super::{
        ProxyKeys, generate, watermark_ok,
        words::{FIRST, FREEMAIL, LAST, WORDS},
    };
    use crate::{
        Result,
        detect::{Detector, EntityKind, IssuedProxies, Mode, RegexDetector, validate::accepts},
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
        "012-00-3456",
        "012 00 3456",
        "034-56-0000",
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
        "admin:Gr\u{fc}\u{df}e2024",
    ];
    /// Names as people write them: particles, initials, hyphens, apostrophes, accents, every
    /// letter case, one word and six, a particle first.
    const PERSON: &[&str] = &[
        "Jeroen de Vries",
        "J. Jansen",
        "MARIA LOPEZ-GARCIA",
        "Haley van Zessen",
        "Jan Willem Karel Pieter Hendrik Jansen",
        "Sanne de Boer",
        "Pieter van der Berg",
        "Kees 't Hart",
        "Fatima El Amrani",
        "Jean-Pierre Dubois",
        "Anne-Marie Visser",
        "Patrick O'Brien",
        "J.R.R. Tolkien",
        "john smith",
        "ANNA KOWALSKI",
        "Elon Reeve Musk",
        "Zo\u{eb} de Vries",
        "Jos\u{e9} Garc\u{ed}a",
        "Ren\u{e9}e M\u{fc}ller",
        "Jeroen",
        "Haley",
        "de Vries",
        "van der Berg",
        "'t Hart",
        "Mohammed bin Salman",
        "Ludwig von Beethoven",
        "Ed Op de Beeck",
        "Van Dijk",
        "T. de Groot",
        "A. B. C. Dekker",
        "Marie Louise Mulder-de Jong",
        "SMITH",
        "McDonald Jones",
        "Li Wei",
    ];

    // Values the detection model finds, in the layouts people write them.

    const PERSON_ALIAS: &[&str] = &[
        "Jantje",
        "Big Mike",
        "Coach Dave",
        "Sasha",
        "Kiki",
        "Bram",
        "Little Joe",
        "Hansje Brinker",
        "Tommy Gun",
        "Stevie B",
        "Pete",
        "Rocky",
    ];
    const PERSON_IDENTIFIER: &[&str] = &[
        "EMP-48213",
        "P1234567",
        "S/N 99-2231",
        "A12 345 678",
        "JD-2025-0042",
        "member #884-221",
        "ID 483920",
        "KLANT-77310",
        "GB-4821-X",
        "N123456789",
    ];
    const PERSON_ATTRIBUTE: &[&str] = &[
        "left-handed",
        "vegetarian",
        "tall",
        "wears glasses",
        "has two dogs",
        "nervous",
        "retired",
        "a wheelchair user",
        "very shy",
        "single mother",
    ];
    const PERSON_ROLE: &[&str] = &[
        "CEO",
        "Chief Financial Officer",
        "head of sales",
        "Prof. dr.",
        "burgemeester",
        "teamleider",
        "Senior Engineer",
        "chairman",
        "huisarts",
        "Managing Director",
    ];
    const DATE_OF_BIRTH: &[&str] = &[
        "1990-05-14",
        "14/05/1990",
        "05/14/1985",
        "14.05.1990",
        "1975-12-01",
        "02-11-1968",
        "31/12/1999",
        "1988-07-23",
        "23 07 1988",
        "1969-04-20",
        "20/04/1969",
    ];
    const PHONE_NUMBER: &[&str] = &[
        "020 123 4567",
        "+49 30 901820",
        "(0) 6 1234 5678",
        "0900-1234",
        "1800 555 0199",
        "+48 600 123 456",
        "06 12345678",
        "+33 1 42 68 53 00",
        "555-0142-77",
        "+1 202 555 0143",
    ];
    const CONTACT_HANDLE: &[&str] = &[
        "@jan_jansen",
        "@jeroen.dev",
        "@acme_support",
        "@maria92",
        "@JohnDoe",
        "skype:jan.jansen42",
        "t.me/janjansen",
        "@lotte_p",
        "@dev_null_1",
        "@kees.hart",
    ];
    const POSTAL_ADDRESS: &[&str] = &[
        "Keizersgracht 123, 1015 CJ Amsterdam",
        "Main Street 42, Springfield",
        "221B Baker Street, London NW1 6XE",
        "ul. D\u{142}uga 5, 00-238 Warszawa",
        "Hauptstra\u{df}e 12\n10115 Berlin",
        "Rue de Rivoli 99, 75001 Paris",
        "Damrak 1",
        "Calle Mayor 5, 28013 Madrid",
        "1600 Pennsylvania Avenue NW, Washington",
        "Stationsplein 9, 3511 CE Utrecht",
        "Lange Voorhout 3 2514 EA Den Haag",
        "Hauptstr. 12, 10115 Berlin",
    ];
    const LOCATION: &[&str] = &[
        "Amsterdam",
        "Den Haag",
        "New York",
        "Rotterdam",
        "Warszawa",
        "Utrecht",
        "Lower Saxony",
        "San Francisco",
        "Sint-Michielsgestel",
        "Nederland",
        "Bavaria",
        "Ede",
        "Groningen",
    ];
    const GEO_LOCATION: &[&str] = &[
        "52.3676, 4.9041",
        "51\u{b0}30'26\"N 0\u{b0}7'39\"W",
        "40.7128 -74.0060",
        "48.8566,2.3522",
        "N 52.37 E 4.90",
        "-33.8688, 151.2093",
        "35.6762 139.6503",
        "37.7749,-122.4194",
        "59.3293 18.0686",
        "55.7558, 37.6173",
    ];
    const DEVICE_ID: &[&str] = &[
        "A1B2C3D4E5F6",
        "IMEI 356938035643809",
        "iPhone-8F3A21",
        "SN: XK9-4482-LM",
        "device_id=7f3a9c",
        "F2:3D:7A:19:00:C4",
        "ANDROID-5d3f9a1c2b",
        "Pixel-7-8821AB",
        "3C5A-91F2",
        "UDID 00008030-001A2C3E0A90402E",
    ];
    const IDENTIFYING_LINK: &[&str] = &[
        "https://www.linkedin.com/in/jan-jansen",
        "www.example.nl/jan",
        "http://acme.nl/team/jan",
        "linkedin.com/in/lotte-peters",
        "/users/kees42",
        "https://twitter.com/janjansen",
        "facebook.com/jan.jansen.55",
        "https://github.com/jjansen",
        "instagram.com/lotte_p",
        "https://example.org/profile?id=4821",
    ];
    const ACCOUNT_ID: &[&str] = &[
        "ACC-4482-1190",
        "user_id 77123",
        "klantnummer 5512093",
        "NL-ACC 889210",
        "acct#00391",
        "member 4421",
        "UID: 8f3a9c21",
        "account 1234 5678",
        "CUST-009211",
        "login jan.jansen42",
    ];
    const AUTH_SECRET: &[&str] = &[
        "hunter2",
        "correct-horse-battery-staple",
        "P@ssw0rd!",
        "Zomer2024!",
        "letmein123",
        "8f3a9c21d7",
        "tr0ub4dor&3",
        "qwerty987",
        "Welkom01",
        "s3cr3t-Pa55",
    ];
    const BANK_ACCOUNT: &[&str] = &[
        "123456789",
        "12-34-56 98765432",
        "BE68 5390 0754 7034",
        "GB29 NWBK 6016 1331 9268 19",
        "1234.56.789",
        "0417164300",
        "ES91 2100 0418 4502 0005 1332",
        "rekening 9876543",
        "sort 20-00-00 acct 55779911",
        "FR14 2004 1010 0505 0001 3M02 606",
    ];
    const PAYMENT_CARD: &[&str] = &[
        "5555 5555 5555 4444",
        "3782 822463 10005",
        "6011-1111-1111-1117",
        "4012 8888 8888 1881",
        "card ending 4242",
        "**** **** **** 1881",
        "2223003122003222",
        "5105 1051 0510 5100",
        "9792 0000 0000 0001",
        "3530 1113 3330 0000",
    ];
    const CARD_SECURITY: &[&str] = &[
        "4821",
        "9921",
        "CVV 5738",
        "cvc: 9921",
        "7254",
        "3318",
        "CVV 6402",
        "cvc 8137",
        "1190",
        "2487",
    ];
    const FINANCIAL_AMOUNT: &[&str] = &[
        "\u{20ac}1.250,00",
        "EUR 4500",
        "$99.95",
        "12.500 euro",
        "USD 1,200,000",
        "\u{a3}3500",
        "salaris 3.250 euro",
        "5000 EUR",
        "\u{a5}120000",
        "\u{20ac} 75,50",
    ];
    const DOCUMENT_ID: &[&str] = &[
        "P1234567",
        "NL-12345678",
        "passport no. X4829301",
        "DL 99-2231-AA",
        "123456789",
        "AB1234567",
        "A12B34567",
        "ID-NL-2931845",
        "S1234567D",
        "rijbewijs 5123456789",
        "XD 482 913",
    ];
    const DOCUMENT_REFERENCE: &[&str] = &[
        "INV-2025-0042",
        "contract ref ABC-123",
        "Zaak 2024/1887",
        "PO#771204",
        "dossier 88-AB",
        "Case No. 22-cv-1043",
        "ref: KL/2024/0091",
        "Bestelling 559201",
        "RFC 2119",
        "Order 7781-QX",
    ];
    const VEHICLE_ID: &[&str] = &[
        "AB-123-C",
        "12-ABC-3",
        "WBA3A5C50CF256985",
        "1HGCM82633A004352",
        "BX-12-LK",
        "M-AB 1234",
        "GR 483 KL",
        "XYZ 1234",
        "KL-97-TT",
        "AA-11-BB",
    ];
    const ORGANIZATION_NAME: &[&str] = &[
        "Acme B.V.",
        "Philips",
        "Royal Dutch Shell plc",
        "Gemeente Amsterdam",
        "Stichting Voorbeeld",
        "Deutsche Bank AG",
        "Bol.com",
        "Albert Heijn",
        "Google LLC",
        "Jumbo Supermarkten",
        "Rijksmuseum",
        "Tesla Inc.",
    ];
    const ORGANIZATION_ID: &[&str] = &[
        "KvK 12345678",
        "VAT NL123456789B01",
        "DE123456789",
        "KVK-27312345",
        "EIN 12-3456789",
        "BTW NL8123.45.678.B01",
        "HRB 12345",
        "CHE-123.456.789",
        "company no. 00445790",
        "SIREN 552 100 554",
        "OrgID 99-8821",
    ];
    const PROPER_NAME: &[&str] = &[
        "Spotify",
        "Coca-Cola",
        "PlayStation",
        "Tesla Model S",
        "Big Mac",
        "Mount Everest",
        "Eiffel Tower",
        "Harry Potter",
        "Bitcoin",
        "Netflix",
        "Opera House",
    ];
    const HEALTH_DATA: &[&str] = &[
        "diabetes",
        "type 2 diabetes",
        "hypertension",
        "broken leg",
        "asthma",
        "depression",
        "chemotherapy",
        "HIV positive",
        "migraine",
        "pregnant",
        "kanker",
        "burn-out",
    ];
    const BIOMETRIC_DATA: &[&str] = &[
        "fingerprint",
        "iris scan",
        "face scan",
        "DNA profile",
        "voiceprint",
        "retina scan",
        "palm vein pattern",
        "gait signature",
        "facial template",
        "vingerafdruk",
    ];
    const ETHNIC_ORIGIN: &[&str] = &[
        "Moroccan",
        "Turkish descent",
        "Roma",
        "Kurdish",
        "Surinamese",
        "Chinese-Dutch",
        "of Polish origin",
        "Afro-Caribbean",
        "Ashkenazi",
        "Indonesian heritage",
    ];
    const POLITICAL_OPINION: &[&str] = &[
        "votes for the Labour party",
        "VVD",
        "left-wing",
        "far-right",
        "supports Brexit",
        "member of the Green Party",
        "conservative",
        "anarchist",
        "Democrat",
        "socialist",
    ];
    const RELIGION_OR_BELIEF: &[&str] = &[
        "Muslim",
        "Catholic",
        "atheist",
        "Jehovah's Witness",
        "Buddhist",
        "Jewish",
        "Hindu",
        "protestants",
        "Sikh",
        "humanist",
    ];
    const SEXUAL_ORIENTATION: &[&str] = &[
        "gay",
        "lesbian",
        "bisexual",
        "homosexual",
        "heterosexual",
        "asexual",
        "pansexual",
        "queer",
        "straight",
        "trans man",
    ];
    const TRADE_UNION: &[&str] = &[
        "FNV member",
        "member of the Teamsters",
        "CNV",
        "trade union member",
        "AFL-CIO",
        "Unite the union",
        "ver.di",
        "shop steward at FNV",
        "union rep",
        "vakbond lid",
    ];
    const CRIMINAL_OFFENCE: &[&str] = &[
        "convicted of fraud",
        "speeding fine",
        "prison sentence",
        "arrested in 2019",
        "criminal record",
        "theft",
        "drink driving",
        "probation",
        "shoplifting",
        "served 3 years",
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
            EntityKind::Person => PERSON,
            EntityKind::PersonAlias => PERSON_ALIAS,
            EntityKind::PersonIdentifier => PERSON_IDENTIFIER,
            EntityKind::PersonAttribute => PERSON_ATTRIBUTE,
            EntityKind::PersonRole => PERSON_ROLE,
            EntityKind::DateOfBirth => DATE_OF_BIRTH,
            EntityKind::PhoneNumber => PHONE_NUMBER,
            EntityKind::ContactHandle => CONTACT_HANDLE,
            EntityKind::PostalAddress => POSTAL_ADDRESS,
            EntityKind::Location => LOCATION,
            EntityKind::GeoLocation => GEO_LOCATION,
            EntityKind::DeviceId => DEVICE_ID,
            EntityKind::IdentifyingLink => IDENTIFYING_LINK,
            EntityKind::AccountId => ACCOUNT_ID,
            EntityKind::AuthSecret => AUTH_SECRET,
            EntityKind::BankAccount => BANK_ACCOUNT,
            EntityKind::PaymentCard => PAYMENT_CARD,
            EntityKind::CardSecurity => CARD_SECURITY,
            EntityKind::FinancialAmount => FINANCIAL_AMOUNT,
            EntityKind::DocumentId => DOCUMENT_ID,
            EntityKind::DocumentReference => DOCUMENT_REFERENCE,
            EntityKind::VehicleId => VEHICLE_ID,
            EntityKind::OrganizationName => ORGANIZATION_NAME,
            EntityKind::OrganizationId => ORGANIZATION_ID,
            EntityKind::ProperName => PROPER_NAME,
            EntityKind::HealthData => HEALTH_DATA,
            EntityKind::BiometricData => BIOMETRIC_DATA,
            EntityKind::EthnicOrigin => ETHNIC_ORIGIN,
            EntityKind::PoliticalOpinion => POLITICAL_OPINION,
            EntityKind::ReligionOrBelief => RELIGION_OR_BELIEF,
            EntityKind::SexualOrientation => SEXUAL_ORIENTATION,
            EntityKind::TradeUnion => TRADE_UNION,
            EntityKind::CriminalOffence => CRIMINAL_OFFENCE,
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
    /// replaced by an ASCII one of its own class: a letter of another script by a letter of its
    /// case, a digit of another script by a digit.
    fn same_layout(original: &str, proxy: &str) -> bool {
        original.chars().count() == proxy.chars().count()
            && original.chars().zip(proxy.chars()).all(|(o, p)| {
                if o.is_numeric() {
                    p.is_ascii_digit()
                } else if o.is_alphabetic() && o.is_uppercase() {
                    p.is_ascii_uppercase()
                } else if o.is_alphabetic() {
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

    /// The runs of letters of `text` with three letters or more, lower case: the names, domain
    /// labels and top-level domains that a proxy must not repeat. A shorter run (`de`, `nl`)
    /// sits inside too many words to count.
    fn name_parts(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphabetic())
            .filter(|part| part.chars().count() >= 3)
            .map(str::to_lowercase)
            .collect()
    }

    /// Whether the list name `word` is one of `parts`, sits inside one or holds one: `smith` and
    /// `devries` give `jsmith` and `Vries` away as much as the words themselves.
    fn echoes_any(word: &str, parts: &[String]) -> bool {
        parts
            .iter()
            .any(|part| word.contains(part.as_str()) || part.contains(word))
    }

    /// Every way to read the local part of an email proxy, `{first}{sep}{last}{dd}`, as a given
    /// name and a family name of the lists. Without a separator the two run together, so more
    /// than one reading can fit.
    fn email_names(local: &str) -> Vec<(&'static str, &'static str)> {
        let body = local
            .get(..local.len().saturating_sub(2))
            .unwrap_or_default();
        FIRST
            .into_iter()
            .filter_map(|first| {
                let rest = body.strip_prefix(first)?;
                let last = rest.strip_prefix(['.', '_']).unwrap_or(rest);
                LAST.into_iter().find(|&l| l == last).map(|l| (first, l))
            })
            .collect()
    }

    #[test]
    fn an_email_proxy_reuses_no_name_of_the_original() {
        // Names written together hide in each other (`smith` in `jsmith`, `john` and `smith`
        // in `johnsmith`), and a surname can be the domain.
        let originals = [
            "jan.jansen@acme.nl",
            "paul_jansen@acme.nl",
            "maria@gmail.com",
            "johnsmith@acme.nl",
            "jsmith@example.org",
            "jan@jansen.nl",
        ];
        for original in originals {
            let parts = name_parts(original);
            for seed in 0..=255u8 {
                let k = ProxyKeys::new([seed; 32], [2; 32]);
                for attempt in 0..4 {
                    let proxy = generate(&k, EntityKind::Email, original, attempt);
                    let local = proxy.split('@').next().unwrap_or_default();
                    assert!(
                        email_names(local).iter().any(|&(first, last)| {
                            !echoes_any(first, &parts) && !echoes_any(last, &parts)
                        }),
                        "{original} -> {proxy}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_person_proxy_reuses_no_name_of_the_original() {
        // `devries` holds `Vries`, and `janet` and `janssen` hold `Jan`.
        for original in ["Jeroen de Vries", "Jan Jansen"] {
            let parts = name_parts(original);
            for seed in 0..=255u8 {
                let k = ProxyKeys::new([seed; 32], [2; 32]);
                for attempt in 0..4 {
                    let proxy = generate(&k, EntityKind::Person, original, attempt);
                    for word in name_parts(&proxy) {
                        assert!(!echoes_any(&word, &parts), "{original} -> {proxy}");
                    }
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

    /// Allocates proxies the way the vault does: for each original in turn, the first attempt
    /// whose candidate is neither an original of the batch nor a proxy issued before. Returns
    /// the first original that finds none.
    fn first_unallocated(kind: EntityKind, originals: &[String]) -> Option<String> {
        let k = keys();
        let mut used: HashSet<String> = originals.iter().cloned().collect();
        for original in originals {
            let proxy = (0..4096).find_map(|attempt| {
                let proxy = generate(&k, kind, original, attempt);
                (!used.contains(&proxy)).then_some(proxy)
            });
            match proxy {
                Some(proxy) => {
                    assert!(accepts(kind, &proxy), "{kind:?} {original:?} -> {proxy:?}");
                    used.insert(proxy);
                }
                None => return Some(original.clone()),
            }
        }
        None
    }

    #[test]
    fn many_short_originals_of_one_kind_all_get_a_proxy() {
        // No proxy may equal an original of the batch, and the first candidates of these years
        // and numbers are all originals: the allocation relies on the widened ones.
        let years: Vec<String> = (1900..2100).map(|y| y.to_string()).collect();
        let dates: Vec<String> = (1..=12)
            .flat_map(|m| (1900..2100).step_by(7).map(move |y| format!("{m:02}/{y}")))
            .collect();
        let numbers: Vec<String> = (100..1000).map(|n| n.to_string()).collect();
        let jobs = [
            (EntityKind::DateOfBirth, &years),
            (EntityKind::DateOfBirth, &dates),
            (EntityKind::AccountId, &numbers),
            (EntityKind::DocumentId, &numbers),
            (EntityKind::PaymentCard, &numbers),
        ];
        // Each year and number is refused 1000 to 2000 candidates before one is free: the jobs
        // run side by side.
        let stuck: Vec<(EntityKind, String)> = jobs
            .par_iter()
            .filter_map(|&(kind, originals)| {
                first_unallocated(kind, originals).map(|original| (kind, original))
            })
            .collect();
        assert!(stuck.is_empty(), "no proxy left for {stuck:?}");
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

    /// Values the model emits that no list covers: all caps, two letters, digits, punctuation
    /// that is neither a space nor a comma, non-Latin scripts (in a link too), values whose only
    /// words are too short to be invented, a link with nothing but its scheme and a value whose
    /// invented words would not fit the length limit. Each is tried for every kind of the model;
    /// those a kind's validator accepts must get a proxy inside the vault's candidate budget.
    const AWKWARD: &[&str] = &[
        "Sant'Antonio:IT",
        "Villa Sant'Antonio:IT",
        "BANKCITY",
        "IT",
        "NL:IT",
        "Ab",
        "ab cd",
        "a.b.c",
        "St.",
        "Hamburg.",
        "Z\u{fc}rich-Altstetten",
        "\u{141}\u{f3}d\u{17a}",
        "\u{43c}\u{43e}\u{441}\u{43a}\u{432}\u{430}",
        "\u{4e1c}\u{4eac}\u{90fd}",
        "\u{661}\u{662}\u{663}\u{664}",
        "IT00B0123456789",
        "3 CANALE REMBRANDT",
        "ul. D\u{142}uga 5, 00-238 Warszawa",
        "12/10/1951",
        "1 jan 90",
        "5.5.55",
        "**** 962",
        "$12,50",
        "52.3676, 4.9041",
        "@x_y",
        "www.a.io",
        "http://.com",
        "https://example.com/a?b=c",
        "https://",
        "https://\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}",
        "https://\u{4f8b}\u{5b50}.\u{4e2d}\u{56fd}/\u{5f20}\u{4e09}",
        "/etc/passwd",
        "foo.bar",
        "A/B-C_D",
        "O'Brien & Sons B.V.",
        "HOLDING GMBH",
        "L1",
        "12345",
        "line one\nline two 7",
        // Fifty two-letter words: valid at 149 bytes, but every invented word is longer.
        concat!(
            "NY NJ CT MA RI VT NH ME PA DE MD VA WV NC SC GA FL AL MS TN KY OH IN IL MI ",
            "WI MN IA MO AR LA TX OK KS NE SD ND MT WY CO NM AZ UT ID NV CA OR WA AK HI"
        ),
    ];

    #[test]
    fn every_value_a_model_kind_accepts_gets_a_proxy_within_the_candidate_budget() {
        let k = keys();
        for kind in EntityKind::ALL
            .into_iter()
            .filter(|k| k.is_listed() && *k != EntityKind::Person)
        {
            let mut tried = 0;
            for &original in AWKWARD {
                if !accepts(kind, original) {
                    continue;
                }
                tried += 1;
                let found = (0..4096).find_map(|attempt| {
                    let proxy = generate(&k, kind, original, attempt);
                    (proxy != original).then_some(proxy)
                });
                let proxy = found.unwrap_or_else(|| panic!("{kind:?} {original:?}: no proxy"));
                assert!(accepts(kind, &proxy), "{kind:?} {original:?} -> {proxy:?}");
            }
            assert!(tried > 0, "{kind:?}: no awkward value was valid");
        }
    }

    #[test]
    fn a_place_with_punctuation_inside_a_word_is_still_replaced() {
        let k = keys();
        for original in ["Sant'Antonio:IT", "NL:IT", "Ab", "ab cd", "IT"] {
            let proxy = generate(&k, EntityKind::Location, original, 0);
            assert_ne!(proxy, original);
            assert!(accepts(EntityKind::Location, &proxy), "{proxy}");
        }
    }

    /// The tokens of an address, split at whitespace and commas.
    fn tokens(address: &str) -> Vec<&str> {
        address
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|token| !token.is_empty())
            .collect()
    }

    #[test]
    fn a_street_abbreviated_with_a_dot_is_still_replaced_with_the_town() {
        // `Hauptstr.` ends in a dot like `ul.` but is the street's name. Only a dot after up to
        // three letters marks an abbreviation, which stays.
        let k = keys();
        for (original, names, kept) in [
            ("Hauptstr. 12, 10115 Berlin", ["Hauptstr", "Berlin"], ""),
            (
                "Bahnhofstr. 3, 1011 Amsterdam",
                ["Bahnhofstr", "Amsterdam"],
                "",
            ),
            (
                "ul. D\u{142}uga 5, 00-238 Warszawa",
                ["D\u{142}uga", "Warszawa"],
                "ul. ",
            ),
        ] {
            assert!(accepts(EntityKind::PostalAddress, original), "{original}");
            for attempt in 0..16 {
                let proxy = generate(&k, EntityKind::PostalAddress, original, attempt);
                assert!(proxy.starts_with(kept), "{original} -> {proxy}");
                for name in names {
                    assert!(!proxy.contains(name), "{original} -> {proxy}");
                }
                assert!(
                    accepts(EntityKind::PostalAddress, &proxy),
                    "{original} -> {proxy}"
                );
            }
        }
    }

    #[test]
    fn a_dotted_number_in_an_address_is_redrawn() {
        // `3.` is a floor, not an abbreviation: its digit says where the person lives.
        let original = "Keizersgracht 123, Etage 3., 1015 CJ Amsterdam";
        let k = keys();
        let mut kept = 0;
        for attempt in 0..32 {
            let proxy = generate(&k, EntityKind::PostalAddress, original, attempt);
            let floor = tokens(&proxy)[3];
            assert!(
                floor.len() == 2
                    && floor.starts_with(|c: char| c.is_ascii_digit())
                    && floor.ends_with('.'),
                "{original} -> {proxy}"
            );
            kept += usize::from(floor == "3.");
        }
        assert!(kept < 16, "{kept} of 32 proxies keep the floor");
    }

    #[test]
    fn a_town_written_with_a_combining_mark_is_replaced_whole() {
        // `u` and U+0308 are one letter. Cut in two, `Zu` is too short for an address to
        // replace and `rich` is lower case among capitals, so the town came through as it was.
        let k = keys();
        for (kind, original, rest) in [
            (
                EntityKind::PostalAddress,
                "Bahnhofstrasse 5, 8001 Zu\u{308}rich",
                "rich",
            ),
            (EntityKind::Location, "Zu\u{308}rich", "rich"),
            (EntityKind::Location, "Mu\u{308}nchen", "nchen"),
        ] {
            assert!(accepts(kind, original), "{original}");
            for attempt in 0..16 {
                let proxy = generate(&k, kind, original, attempt);
                assert_ne!(proxy, original);
                assert!(
                    !proxy.contains('\u{308}') && !proxy.contains(rest),
                    "{original} -> {proxy}"
                );
                assert!(accepts(kind, &proxy), "{original} -> {proxy}");
            }
        }
    }

    #[test]
    fn a_link_in_another_script_keeps_only_its_scheme_and_top_level_domain() {
        // The host and path were not ASCII, and the proxy has to be: ASCII letters in their place.
        let k = keys();
        for (original, tld) in [
            (
                "https://\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}",
                ".\u{440}\u{444}",
            ),
            (
                "https://\u{4f8b}\u{5b50}.\u{4e2d}\u{56fd}/\u{5f20}\u{4e09}",
                ".\u{4e2d}\u{56fd}",
            ),
        ] {
            assert!(accepts(EntityKind::IdentifyingLink, original), "{original}");
            for attempt in 0..16 {
                let proxy = generate(&k, EntityKind::IdentifyingLink, original, attempt);
                assert!(
                    proxy.starts_with("https://") && proxy.contains(tld),
                    "{original} -> {proxy}"
                );
                assert!(
                    proxy.replacen(tld, "", 1).is_ascii(),
                    "{original} -> {proxy}"
                );
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
        for kind in EntityKind::ALL.into_iter().filter(|k| k.is_watermarked()) {
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
        // A derived `Debug` would print the bytes: as numbers, hex or the letters they are.
        for leaked in ["65", "66", "41", "42", "A", "B"] {
            assert!(!shown.contains(leaked), "{shown} shows {leaked}");
        }
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

    /// Whether `proxy` is found again, once and whole, in the text a service answers with it.
    /// Only the patterned kinds have a pattern; the proxies of the listed kinds are found by
    /// looking for the issued proxy itself.
    fn assert_found_again(
        regex: &RegexDetector,
        kind: EntityKind,
        original: &str,
        proxy: &str,
    ) -> Result<()> {
        let text = context(kind, proxy);
        let spans = if kind.is_listed() {
            IssuedProxies::new(&[(kind, proxy)])?.detect(&text, Mode::Deanonymize)
        } else {
            regex.detect(&text, Mode::Deanonymize)
        };
        let exact =
            matches!(spans.as_slice(), [s] if s.kind == kind && text[s.start..s.end] == *proxy);
        assert!(
            exact,
            "{kind:?}: {original} -> {proxy}: {spans:?} in {text:?}"
        );
        Ok(())
    }

    #[test]
    fn detector_finds_each_proxy_exactly_once_with_the_same_kind() -> Result<()> {
        let k = keys();
        let regex = RegexDetector::new()?;
        for kind in EntityKind::ALL {
            for original in samples(kind) {
                for attempt in 0..3 {
                    let proxy = generate(&k, kind, &original, attempt);
                    assert_found_again(&regex, kind, &original, &proxy)?;
                }
            }
        }
        Ok(())
    }

    /// A vault does not issue the first candidate but the first one that differs from the
    /// original and, for a kind that carries the watermark, has it: on average the sixteenth,
    /// far beyond the three attempts the test above looks at.
    #[test]
    fn the_candidates_a_vault_issues_are_valid_and_found_again() -> Result<()> {
        let k = keys();
        let regex = RegexDetector::new()?;
        for kind in EntityKind::ALL {
            for original in samples(kind).into_iter().take(30) {
                let issued = (0..4096)
                    .map(|attempt| generate(&k, kind, &original, attempt))
                    .find(|c| {
                        *c != original && (!kind.is_watermarked() || watermark_ok(&k, kind, c))
                    });
                let Some(proxy) = issued else {
                    panic!("{kind:?}: {original} has no candidate to issue");
                };
                assert!(accepts(kind, &proxy), "{kind:?}: {original} -> {proxy}");
                assert_found_again(&regex, kind, &original, &proxy)?;
            }
        }
        Ok(())
    }

    #[test]
    fn random_names_get_valid_proxies_that_are_found_again_as_issued() -> Result<()> {
        const TOKENS: &[&str] = &[
            "Jan",
            "jan",
            "JAN",
            "Willem",
            "de",
            "De",
            "DE",
            "van",
            "der",
            "'t",
            "\u{2019}t",
            "J.",
            "j.",
            "J.R.",
            "O'Brien",
            "Anne-Marie",
            "LOPEZ-GARCIA",
            "Zo\u{eb}",
            "M\u{fc}ller",
            "al",
            "Al",
            "bin",
            "St.",
            "Q",
            "Ed",
        ];
        let k = keys();
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut below = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(n).unwrap_or(1)).unwrap_or(0)
        };
        let mut checked = 0;
        for _ in 0..600 {
            let count = 1 + below(6);
            let original = (0..count)
                .map(|_| TOKENS[below(TOKENS.len())])
                .collect::<Vec<_>>()
                .join(" ");
            if !accepts(EntityKind::Person, &original) {
                continue;
            }
            checked += 1;
            for attempt in 0..3 {
                let proxy = generate(&k, EntityKind::Person, &original, attempt);
                assert_eq!(
                    proxy,
                    generate(&k, EntityKind::Person, &original, attempt),
                    "{original}"
                );
                assert_ne!(proxy, original);
                assert!(accepts(EntityKind::Person, &proxy), "{original} -> {proxy}");
                let text = context(EntityKind::Person, &proxy);
                let spans = IssuedProxies::new(&[(EntityKind::Person, proxy.as_str())])?
                    .detect(&text, Mode::Deanonymize);
                assert!(
                    matches!(spans.as_slice(), [s] if text[s.start..s.end] == proxy),
                    "{original} -> {proxy}: {spans:?} in {text:?}"
                );
            }
        }
        assert!(
            checked > 300,
            "only {checked} of the random names were valid"
        );
        Ok(())
    }
}
