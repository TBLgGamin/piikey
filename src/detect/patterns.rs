//! The pattern table. Order is priority: when several patterns match at the
//! same byte, the earliest one wins, and a rejected match falls back to the
//! patterns after it. The order is also [`EntityKind::ALL`].
//!
//! Every regex is ASCII (the detector compiles them with Unicode off, so `\b`
//! and `\s` are ASCII too), never uses the `.` wildcard, and bounds every
//! quantifier. That caps any match at [`super::MAX_MATCH`] bytes, which the
//! chunked scan relies on; a test checks it against the parsed patterns.

use super::{
    EntityKind, Mode,
    validate::{self, Validator},
};

/// Bytes before a value that are searched for a context keyword.
pub(super) const CONTEXT_WINDOW: usize = 48;

/// Keywords that mark a nearby nine-digit number as a US SSN.
const SSN_WORDS: &[&str] = &["ssn", "social security"];

/// Keywords that mark a nearby nine-digit number as a Dutch BSN.
const BSN_WORDS: &[&str] = &["bsn", "burgerservicenummer", "sofinummer", "sofi-nummer"];

/// Length of an SSN written without separators.
const SSN_BARE_LEN: usize = 9;

/// Kinds scanned by a regex of their own instead of the shared one.
///
/// Each of these patterns needs a literal in every match (a token prefix,
/// `://`, `@`), which only a single-pattern regex can exploit: the engine
/// jumps straight to it. Inside the shared regex, their bounded character
/// classes (an email's 64-byte local part above all) multiply the lazy DFA's
/// states on text like base64 until the engine gives up on the DFA, and
/// scanning drops by two orders of magnitude. The other patterns share one
/// regex; it is much faster on ordinary text than any split of it.
pub(super) const SOLO: [EntityKind; 3] = [
    EntityKind::Secret,
    EntityKind::UrlCredential,
    EntityKind::Email,
];

/// One detection rule: a regex that finds candidates and a validator that
/// confirms them.
#[derive(Debug)]
pub(super) struct Pattern {
    pub kind: EntityKind,
    pub regex: &'static str,
    pub validate: Validator,
    /// Keywords for the kind's context rule; empty when the kind has none.
    pub context: &'static [&'static str],
}

impl Pattern {
    /// Whether a value that passed [`Pattern::validate`] also passes the
    /// kind's context rule in `mode`.
    ///
    /// `Anonymize` is strict, since masking every nine-digit number would wreck
    /// ordinary text: a Dutch BSN needs a BSN keyword in the window before it,
    /// and so does a US SSN written without separators. When both kinds of
    /// keyword are in the window, the nearer one decides for the SSN, so
    /// `SSN 123-45-6789, BSN 111222333` reads the second number as a BSN.
    ///
    /// `Deanonymize` never needs a keyword: a proxy in model output may have
    /// lost it, and the vault lookup rejects false hits. A bare nine-digit value
    /// that is SSN-shaped is therefore claimed by `UsSsn` first; BSN proxies
    /// avoid that by using the SSN-invalid area codes 900-999.
    pub(super) fn permits(&self, mode: Mode, hay: &[u8], start: usize, end: usize) -> bool {
        if mode == Mode::Deanonymize {
            return true;
        }
        match self.kind {
            EntityKind::NlBsn => validate::context(hay, start, self.context, CONTEXT_WINDOW),
            EntityKind::UsSsn if end - start == SSN_BARE_LEN => {
                let Some(ssn) = validate::nearest_context(hay, start, self.context, CONTEXT_WINDOW)
                else {
                    return false;
                };
                validate::nearest_context(hay, start, BSN_WORDS, CONTEXT_WINDOW)
                    .is_none_or(|bsn| ssn < bsn)
            }
            _ => true,
        }
    }
}

/// Provider tokens: AWS access key id, GitHub, Slack, Stripe live and Google
/// API keys, JSON web tokens.
const SECRET: &str = concat!(
    r"\bAKIA[0-9A-Z]{16}\b",
    r"|\bgh[pousr]_[A-Za-z0-9]{36}\b",
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,72}\b",
    r"|\b[sr]k_live_[A-Za-z0-9]{24,99}\b",
    r"|\bAIza[0-9A-Za-z_-]{35}\b",
    r"|\beyJ[A-Za-z0-9_-]{8,1400}\.eyJ[A-Za-z0-9_-]{8,1400}\.[A-Za-z0-9_-]{8,1200}\b",
);

/// `scheme://user:pass@`; the validator trims it to `user:pass`.
const URL_CREDENTIAL: &str = r"\b[A-Za-z][A-Za-z0-9+.-]{1,16}://[^\s:/@]{1,64}:[^\s/@]{1,128}@";

const EMAIL: &str =
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b";

const IBAN: &str = r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b";

const CREDIT_CARD: &str = r"\b[2-6][0-9](?:[ -]?[0-9]){11,17}\b";

const IPV6: &str = r"(?:\b[0-9A-Fa-f]{1,4}|:)(?::[0-9A-Fa-f]{0,4}){2,7}\b";

const MAC: &str = r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b";

const IPV4: &str = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b";

const US_SSN: &str = r"\b[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{4}\b";

const NL_BSN: &str = r"\b[0-9]{9}\b|\b[0-9]{4}\.[0-9]{2}\.[0-9]{3}\b";

/// International (`+` or `00`), leading-0 national and NANP forms.
///
/// Only the NANP area code is held to its real range (first digit 2-9). The
/// exchange is any three digits, so documentation-style numbers such as
/// `(555) 123-4567`, whose exchange starts with 1, still match: people write
/// numbers like that all the time and masking them is the safe side.
const PHONE: &str = concat!(
    r"(?:\+|\b00)[1-9][0-9 ().-]{6,20}[0-9]\b",
    r"|\b0[1-9][0-9 ().-]{6,14}[0-9]\b",
    r"|\(?\b[2-9][0-9]{2}\)?[ .-]?[0-9]{3}[ .-]?[0-9]{4}\b",
);

/// Patterns in priority order, one per [`EntityKind`].
pub(super) static PATTERNS: [Pattern; 11] = [
    Pattern {
        kind: EntityKind::Secret,
        regex: SECRET,
        validate: validate::secret,
        context: &[],
    },
    Pattern {
        kind: EntityKind::UrlCredential,
        regex: URL_CREDENTIAL,
        validate: validate::url_credential,
        context: &[],
    },
    Pattern {
        kind: EntityKind::Email,
        regex: EMAIL,
        validate: validate::email,
        context: &[],
    },
    Pattern {
        kind: EntityKind::Iban,
        regex: IBAN,
        validate: validate::iban,
        context: &[],
    },
    Pattern {
        kind: EntityKind::CreditCard,
        regex: CREDIT_CARD,
        validate: validate::card,
        context: &[],
    },
    Pattern {
        kind: EntityKind::Ipv6,
        regex: IPV6,
        validate: validate::ipv6,
        context: &[],
    },
    Pattern {
        kind: EntityKind::Mac,
        regex: MAC,
        validate: validate::mac,
        context: &[],
    },
    Pattern {
        kind: EntityKind::Ipv4,
        regex: IPV4,
        validate: validate::ipv4,
        context: &[],
    },
    Pattern {
        kind: EntityKind::UsSsn,
        regex: US_SSN,
        validate: validate::ssn,
        context: SSN_WORDS,
    },
    Pattern {
        kind: EntityKind::NlBsn,
        regex: NL_BSN,
        validate: validate::bsn_11proof,
        context: BSN_WORDS,
    },
    Pattern {
        kind: EntityKind::Phone,
        regex: PHONE,
        validate: validate::phone,
        context: &[],
    },
];
