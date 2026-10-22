//! PII detection. [`Detector`] is the extension point: [`RegexDetector`] finds what has a format,
//! [`NerDetector`] what the on-device model reads out of prose, [`CompositeDetector`] runs several
//! of them, and `IssuedProxies` finds the proxies the vault issued.

mod composite;
mod issued;
mod kind;
pub mod ner;
mod patterns;
pub(crate) mod validate;

use std::ops::{ControlFlow, Range};

pub use composite::CompositeDetector;
pub(crate) use composite::{overlaps, overlaps_bytes};
pub(crate) use issued::{IssuedProxies, Words};
pub use kind::{EntityKind, KIND_GROUPS, KindSet, Span};
pub use ner::NerDetector;
use rayon::prelude::*;
use regex_automata::{Anchored, Input, meta, util::syntax};

use self::patterns::{PATTERNS, SOLO};
use crate::{Error, Result};

/// Which direction text is flowing. Deanonymize relaxes context rules so a
/// proxy that lost its keyword (e.g. in LLM output) is still found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Anonymize,
    Deanonymize,
}

/// What a detector found in one step of [`Detector::detect_batch_steps`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Per text, the spans found in this step: sorted by start, and overlapping neither each
    /// other, nor what an earlier step reported, nor what an earlier detector of a
    /// [`CompositeDetector`] kept.
    pub spans: Vec<Vec<Span>>,
    /// `Some((done, total))` while more steps follow: how many of the `total` bytes of text the
    /// rest of the work reads have been read (`total` is 0 while that is not known yet). `None`
    /// in the last step.
    pub more: Option<(usize, usize)>,
}

/// Finds PII spans in text.
pub trait Detector: Send + Sync + std::fmt::Debug {
    /// Spans sorted by start, never overlapping.
    fn detect(&self, text: &str, mode: Mode) -> Vec<Span>;

    /// Spans per text. `wanted`: kinds the caller keeps (a detector may skip
    /// work for others; the caller filters). `taken`: empty, or per text the
    /// sorted, disjoint spans earlier detectors already claimed.
    fn detect_batch(
        &self,
        texts: &[&str],
        mode: Mode,
        wanted: KindSet,
        taken: &[Vec<Span>],
    ) -> Vec<Vec<Span>> {
        let _ = (wanted, taken);
        texts.par_iter().map(|t| self.detect(t, mode)).collect()
    }

    /// [`Detector::detect_batch`] that hands over what it finds as it finds it, in steps, so that
    /// a caller can show the first of it while the rest is still being looked for (a model reads
    /// minutes of text where a pattern reads it in a second). Everything the steps hold
    /// together is what `detect_batch` returns. `step` may end the work by breaking: the
    /// detector then does no more than the step it is in. A detector that has no steps reports
    /// everything in one, as this does.
    fn detect_batch_steps(
        &self,
        texts: &[&str],
        mode: Mode,
        wanted: KindSet,
        taken: &[Vec<Span>],
        step: &mut dyn FnMut(Step) -> ControlFlow<()>,
    ) {
        let spans = self.detect_batch(texts, mode, wanted, taken);
        let _ = step(Step { spans, more: None });
    }
}

/// Upper bound on the length of any regex match. Every pattern bounds every
/// quantifier, so the longest possible match (a JSON web token) is 4008 bytes;
/// the tests check each pattern against this. The chunked scan needs it to
/// know how far past its own range a match that starts inside it can reach.
const MAX_MATCH: usize = 4096;

/// Texts up to this many bytes are scanned in one piece: the engine already
/// parallelizes across texts, and splitting small texts costs more than it saves.
const PARALLEL_FROM: usize = 2 << 20;

/// Bytes each rayon task owns when a longer text is split.
const CHUNK: usize = 1 << 20;

/// Regexes a scan keeps a pending candidate for: the shared one first, then
/// one per [`SOLO`] pattern.
const SEARCHERS: usize = SOLO.len() + 1;

/// Validated multi-pattern regex detector.
///
/// Candidates come from two kinds of regex. A few patterns (the `SOLO` list in
/// the pattern table) each have their own. The rest share `shared`, whose
/// leftmost-first semantics make pattern order the priority when several of
/// them match at the same byte. A scan takes the leftmost candidate of all of
/// them, an earlier pattern winning ties, which is exactly what one regex of
/// every pattern would return. A validator then confirms it. When one
/// rejects, the patterns after it get a chance at the same start through
/// `each` (anchored), so a nine-digit number that failed as an SSN can still
/// be a BSN.
pub struct RegexDetector {
    shared: meta::Regex,
    /// Table index of each shared pattern, by its pattern ID in `shared`.
    shared_ids: Vec<usize>,
    /// Table index of each solo pattern, in [`SOLO`] order.
    solo: Vec<usize>,
    /// Every pattern alone: the searchers of the solo ones, and the anchored
    /// fallback for all.
    each: Vec<meta::Regex>,
}

/// Lists the kinds only: the derived output would dump every compiled
/// automaton, megabytes of it, into any log line that prints an engine.
impl std::fmt::Debug for RegexDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kinds: Vec<EntityKind> = PATTERNS.iter().map(|p| p.kind).collect();
        f.debug_struct("RegexDetector")
            .field("kinds", &kinds)
            .finish_non_exhaustive()
    }
}

impl RegexDetector {
    /// Compiles the pattern table.
    ///
    /// # Errors
    /// Never in practice; the table is static and tested. A regex that fails
    /// to build is reported as [`Error::Io`].
    pub fn new() -> Result<Self> {
        // The patterns are ASCII. Without Unicode, `\b` and `\s` are ASCII and
        // negated classes may match any byte, which is only sound because a
        // match never ends inside a multi-byte character (see `Span`).
        let mut builder = meta::Regex::builder();
        builder.syntax(syntax::Config::new().unicode(false).utf8(false));
        let solo = SOLO
            .iter()
            .map(|kind| {
                PATTERNS
                    .iter()
                    .position(|p| p.kind == *kind)
                    .ok_or_else(|| build_failed(format!("no pattern for {}", kind.as_str())))
            })
            .collect::<Result<Vec<_>>>()?;
        let shared_ids: Vec<usize> = (0..PATTERNS.len())
            .filter(|id| !solo.contains(id))
            .collect();
        let shared_sources: Vec<&str> = shared_ids.iter().map(|&id| PATTERNS[id].regex).collect();
        let shared = builder.build_many(&shared_sources).map_err(build_failed)?;
        let each = PATTERNS
            .iter()
            .map(|p| builder.build(p.regex).map_err(build_failed))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            shared,
            shared_ids,
            solo,
            each,
        })
    }

    /// Spans of `hay` found by one sequential scan.
    fn scan_whole(&self, hay: &[u8], mode: Mode) -> Vec<Span> {
        self.scan(hay, mode, 0, hay.len(), hay.len()).collect()
    }

    /// Spans of `hay` found by scanning `chunk`-byte ranges in parallel; always
    /// equal to [`Self::scan_whole`].
    ///
    /// Every range is scanned independently, as if no earlier span reached
    /// into it. That is exactly right unless a span of the previous range runs
    /// past the boundary: then the sequential scan resumes where that span
    /// ended, not at the boundary. Such a range is rescanned from the true
    /// resume point until its result lines up with the independent one again
    /// (the scan state is only the resume point, so one shared span is enough),
    /// which normally takes a single step.
    fn scan_chunked(&self, hay: &[u8], mode: Mode, chunk: usize) -> Vec<Span> {
        let len = hay.len();
        let owners: Vec<Range<usize>> = (0..len)
            .step_by(chunk.max(1))
            .map(|from| from..len.min(from + chunk.max(1)))
            .collect();
        // Spans start inside their owner range but may end up to MAX_MATCH past it.
        let limit = |owner: &Range<usize>| len.min(owner.end + MAX_MATCH);
        let parts: Vec<Vec<Span>> = owners
            .par_iter()
            .map(|owner| {
                self.scan(hay, mode, owner.start, owner.end, limit(owner))
                    .collect()
            })
            .collect();

        let mut spans = Vec::with_capacity(parts.iter().map(Vec::len).sum());
        for (owner, part) in owners.iter().zip(parts) {
            let resume = spans.last().map_or(0, |last: &Span| last.end);
            if resume <= owner.start {
                spans.extend(part);
                continue;
            }
            let mut next = 0;
            for span in self.scan(hay, mode, resume, owner.end, limit(owner)) {
                while part.get(next).is_some_and(|p| p.start < span.start) {
                    next += 1;
                }
                if part.get(next) == Some(&span) {
                    spans.extend_from_slice(&part[next..]);
                    break;
                }
                spans.push(span);
            }
        }
        spans
    }

    /// Scan of `hay` that resumes at `pos` and reports spans starting before
    /// `owner_end`, searching no further than `limit`.
    fn scan<'a>(
        &'a self,
        hay: &'a [u8],
        mode: Mode,
        pos: usize,
        owner_end: usize,
        limit: usize,
    ) -> Scan<'a> {
        Scan {
            detector: self,
            hay,
            mode,
            pos,
            owner_end,
            limit,
            pending: [Pending::Unknown; SEARCHERS],
        }
    }

    /// Next candidate of searcher `searcher` within `input`: searcher 0 is the
    /// shared regex, searcher `k` the solo pattern `k - 1`.
    fn find(&self, searcher: usize, input: &Input<'_>) -> Option<Hit> {
        let (id, found) = match searcher.checked_sub(1) {
            None => {
                let found = self.shared.search(input)?;
                (*self.shared_ids.get(found.pattern().as_usize())?, found)
            }
            Some(solo) => {
                let id = *self.solo.get(solo)?;
                (id, self.each.get(id)?.search(input)?)
            }
        };
        Some(Hit {
            id,
            start: found.start(),
            end: found.end(),
        })
    }

    /// Turns a regex hit into an accepted span: the hit's own pattern first,
    /// then every lower-priority pattern anchored at the same start.
    fn resolve(&self, hay: &[u8], hit: Hit, limit: usize, mode: Mode) -> Option<Span> {
        accept(hay, hit.id, hit.start..hit.end, mode).or_else(|| {
            (hit.id + 1..PATTERNS.len()).find_map(|id| {
                let input = Input::new(hay)
                    .range(hit.start..limit)
                    .anchored(Anchored::Yes);
                let again = self.each.get(id)?.search(&input)?;
                accept(hay, id, again.range(), mode)
            })
        })
    }
}

/// Runs pattern `id`'s validator and context rule on `hit`.
fn accept(hay: &[u8], id: usize, hit: Range<usize>, mode: Mode) -> Option<Span> {
    let pattern = PATTERNS.get(id)?;
    let (start, end) = (pattern.validate)(hay, hit.start, hit.end)?;
    // A validator may only trim. Anything else would let the scan stall.
    if start < hit.start || end > hit.end || start >= end {
        return None;
    }
    pattern.permits(mode, hay, start, end).then_some(Span {
        start,
        end,
        kind: pattern.kind,
    })
}

/// Reports a regex that failed to compile.
fn build_failed(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
    Error::Io(std::io::Error::other(err))
}

impl Detector for RegexDetector {
    fn detect(&self, text: &str, mode: Mode) -> Vec<Span> {
        let hay = text.as_bytes();
        if hay.len() <= PARALLEL_FROM {
            self.scan_whole(hay, mode)
        } else {
            self.scan_chunked(hay, mode, CHUNK)
        }
    }
}

/// A regex candidate: pattern `id` (a table index) matched `start..end`.
#[derive(Debug, Clone, Copy)]
struct Hit {
    id: usize,
    start: usize,
    end: usize,
}

/// What a scan knows about one searcher's next candidate.
#[derive(Debug, Clone, Copy)]
enum Pending {
    /// Not searched for yet.
    Unknown,
    /// The leftmost candidate at or after some earlier resume point. It stays
    /// the answer for every later resume point up to its own start.
    Hit(Hit),
    /// Nothing left to find.
    Exhausted,
}

/// One sequential pass over a haystack, yielding accepted spans in order.
///
/// The only state that matters is the resume point; `pending` just avoids
/// searching twice for a candidate that is still ahead. Whether a candidate at
/// a given start is accepted does not depend on where the pass began, which is
/// what lets [`RegexDetector::scan_chunked`] split the work.
struct Scan<'a> {
    detector: &'a RegexDetector,
    hay: &'a [u8],
    mode: Mode,
    /// Next byte to search from.
    pos: usize,
    /// Only spans starting before this are reported.
    owner_end: usize,
    /// End of the searched window. Look-around still sees the whole haystack.
    limit: usize,
    /// Next candidate per searcher.
    pending: [Pending; SEARCHERS],
}

impl Scan<'_> {
    /// Leftmost candidate at or after `pos`, the earlier pattern winning ties.
    /// Only searchers whose pending candidate lies behind `pos` search again.
    fn next_hit(&mut self) -> Option<Hit> {
        let mut best: Option<Hit> = None;
        for (searcher, pending) in self.pending.iter_mut().enumerate() {
            let behind = match *pending {
                Pending::Unknown => true,
                Pending::Hit(hit) => hit.start < self.pos,
                Pending::Exhausted => false,
            };
            if behind {
                let input = Input::new(self.hay).range(self.pos..self.limit);
                *pending = self
                    .detector
                    .find(searcher, &input)
                    .map_or(Pending::Exhausted, Pending::Hit);
            }
            if let Pending::Hit(hit) = *pending
                && best.is_none_or(|b| (hit.start, hit.id) < (b.start, b.id))
            {
                best = Some(hit);
            }
        }
        best
    }
}

impl Iterator for Scan<'_> {
    type Item = Span;

    fn next(&mut self) -> Option<Span> {
        while self.pos < self.owner_end {
            let Some(hit) = self.next_hit() else {
                break;
            };
            if hit.start >= self.owner_end {
                break;
            }
            if let Some(span) = self.detector.resolve(self.hay, hit, self.limit, self.mode) {
                self.pos = span.end;
                return Some(span);
            }
            self.pos = hit.start + 1;
        }
        self.pos = self.owner_end;
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::{
        CHUNK, Detector, EntityKind as K, MAX_MATCH, Mode, PARALLEL_FROM, PATTERNS, RegexDetector,
        Span, syntax,
    };

    static DETECTOR: LazyLock<RegexDetector> = LazyLock::new(|| match RegexDetector::new() {
        Ok(detector) => detector,
        Err(err) => panic!("the pattern table does not build: {err}"),
    });

    fn detector() -> &'static RegexDetector {
        &DETECTOR
    }

    /// Kind and text of every span found in `text`.
    fn found(text: &str, mode: Mode) -> Vec<(K, &str)> {
        detector()
            .detect(text, mode)
            .into_iter()
            .map(|s| (s.kind, &text[s.start..s.end]))
            .collect()
    }

    /// Asserts that nothing is detected in `text`.
    fn assert_clean(text: &str, mode: Mode) {
        let got = found(text, mode);
        assert!(got.is_empty(), "{text:?} in {mode:?}: {got:?}");
    }

    /// Small deterministic generator (xorshift64*), so tests need no crate.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            let n = u64::try_from(n).unwrap_or(u64::MAX);
            usize::try_from(self.next() % n).unwrap_or(0)
        }
    }

    #[test]
    fn table_is_in_priority_order_with_one_pattern_per_kind() {
        let kinds: Vec<K> = PATTERNS.iter().map(|p| p.kind).collect();
        // Person and the model kinds come from other detectors, not the regex table.
        let regex_kinds: Vec<K> = K::ALL.into_iter().filter(|k| k.is_patterned()).collect();
        assert_eq!(kinds, regex_kinds);
    }

    #[test]
    fn every_pattern_has_a_bounded_match_length() {
        let config = syntax::Config::new().unicode(false).utf8(false);
        for pattern in &PATTERNS {
            let Ok(hir) = syntax::parse_with(pattern.regex, &config) else {
                panic!("{:?} does not parse", pattern.kind);
            };
            let max = hir.properties().maximum_len();
            assert!(
                max.is_some_and(|n| n <= MAX_MATCH),
                "{:?} can match {max:?} bytes",
                pattern.kind
            );
        }
    }

    #[test]
    fn long_runs_of_a_patterns_widest_class_never_give_oversized_matches() {
        let jwt_segment = "a-".repeat(2_000);
        let jwt = format!("eyJ{jwt_segment}.eyJ{jwt_segment}.{jwt_segment}");
        // (prefix, repeated unit, suffix) per pattern, about 10 000 bytes of unit.
        let cases: Vec<(String, &str, &str)> = vec![
            (jwt, "", ""),
            ("xoxb-".into(), "a-", " x"),
            ("AKIA".into(), "A", " x"),
            ("ghp_".into(), "a", " x"),
            ("sk_live_".into(), "a", " x"),
            ("AIza".into(), "a-", " x"),
            ("http://".into(), "a", ":b@x"),
            ("http://u:".into(), "b", "@x"),
            (String::new(), ".a", "@example.org"),
            ("a@".into(), "b.", "com"),
            ("NL91".into(), " ABNA", ""),
            ("4".into(), "1 ", "1"),
            ("1".into(), ":a", ""),
            ("00".into(), ":00", ""),
            ("1.".into(), "1.", "1"),
            ("1".into(), "1-", "1"),
            ("0".into(), "0", " x"),
            ("+3".into(), "1 ", "1"),
            ("(555) ".into(), "1.", "1"),
        ];
        let det = detector();
        for (prefix, unit, suffix) in cases {
            let filler = if unit.is_empty() {
                String::new()
            } else {
                unit.repeat(10_000 / unit.len())
            };
            let hay = format!("{prefix}{filler}{suffix}");
            let regexes = std::iter::once(&det.shared).chain(&det.each);
            for regex in regexes {
                for hit in regex.find_iter(hay.as_bytes()) {
                    assert!(
                        hit.len() <= MAX_MATCH,
                        "{prefix:.12} matched {} bytes",
                        hit.len()
                    );
                }
            }
        }
    }

    #[test]
    fn the_match_length_checks_do_catch_an_unbounded_pattern() {
        // Control for the two tests above: an email pattern with an unbounded
        // local part fails both the static bound and the long-run check.
        let config = syntax::Config::new().unicode(false).utf8(false);
        let unbounded = r"\b[A-Za-z0-9._%+-]+@example\.org\b";
        let Ok(hir) = syntax::parse_with(unbounded, &config) else {
            panic!("the control pattern does not parse");
        };
        assert_eq!(hir.properties().maximum_len(), None);
        let Ok(regex) = super::meta::Regex::builder()
            .syntax(config)
            .build(unbounded)
        else {
            panic!("the control pattern does not build");
        };
        let hay = format!("{}@example.org", ".a".repeat(5_000));
        assert!(
            regex
                .find_iter(hay.as_bytes())
                .any(|hit| hit.len() > MAX_MATCH)
        );
    }

    #[test]
    fn longest_legal_token_is_detected_within_the_bound() {
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(1400),
            "b".repeat(1400),
            "c".repeat(1200)
        );
        assert_eq!(jwt.len(), 4008);
        let text = format!("token {jwt} end");
        assert_eq!(found(&text, Mode::Anonymize), [(K::Secret, jwt.as_str())]);
    }

    /// A well-formed JSON web token.
    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    /// Text, and the kind and value found in it in both modes. BSNs have an
    /// SSN-invalid area (9xx) so both modes agree on the kind.
    const FOUND: &[(&str, K, &str)] = &[
        (
            "key AKIAIOSFODNN7EXAMPLE end",
            K::Secret,
            "AKIAIOSFODNN7EXAMPLE",
        ),
        (
            "token=ghp_1234567890abcdefghijklmnopqrstuvwxyz;",
            K::Secret,
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        ),
        (
            "slack xoxb-123456789012-abcdefghij ok",
            K::Secret,
            "xoxb-123456789012-abcdefghij",
        ),
        (
            "stripe sk_live_abcdefghijklmnopqrstuvwx.",
            K::Secret,
            "sk_live_abcdefghijklmnopqrstuvwx",
        ),
        (
            "key: AIzaSyA-1234567890abcdefghijklmnopqrstu",
            K::Secret,
            "AIzaSyA-1234567890abcdefghijklmnopqrstu",
        ),
        (
            "db https://admin:hunter2@db.example.com/x",
            K::UrlCredential,
            "admin:hunter2",
        ),
        ("ftp://u:p%40ss@host", K::UrlCredential, "u:p%40ss"),
        (
            "Mail jan.jansen@acme.nl, thanks",
            K::Email,
            "jan.jansen@acme.nl",
        ),
        (
            "<a+tag@sub.example.co.uk>",
            K::Email,
            "a+tag@sub.example.co.uk",
        ),
        ("IBAN NL91ABNA0417164300 ok", K::Iban, "NL91ABNA0417164300"),
        (
            "IBAN NL91 ABNA 0417 1643 00.",
            K::Iban,
            "NL91 ABNA 0417 1643 00",
        ),
        (
            "DE89 3704 0044 0532 0130 00",
            K::Iban,
            "DE89 3704 0044 0532 0130 00",
        ),
        ("GB82WEST12345698765432", K::Iban, "GB82WEST12345698765432"),
        (
            "card 4111 1111 1111 1111.",
            K::CreditCard,
            "4111 1111 1111 1111",
        ),
        (
            "card 4111-1111-1111-1111",
            K::CreditCard,
            "4111-1111-1111-1111",
        ),
        ("5500005555555559", K::CreditCard, "5500005555555559"),
        (
            "amex 3782 822463 10005!",
            K::CreditCard,
            "3782 822463 10005",
        ),
        ("host 2001:db8::1 up", K::Ipv6, "2001:db8::1"),
        ("fe80::1%eth0", K::Ipv6, "fe80::1"),
        ("peer ::ffff:192.0.2.128 up", K::Ipv6, "::ffff:192.0.2.128"),
        ("nat64 64:ff9b::192.0.2.33.", K::Ipv6, "64:ff9b::192.0.2.33"),
        (
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            K::Ipv6,
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        ),
        ("mac 00:1A:2B:3C:4D:5E ok", K::Mac, "00:1A:2B:3C:4D:5E"),
        ("mac 00-1a-2b-3c-4d-5e", K::Mac, "00-1a-2b-3c-4d-5e"),
        ("ip 203.0.113.42.", K::Ipv4, "203.0.113.42"),
        ("192.168.1.10:8080", K::Ipv4, "192.168.1.10"),
        ("id 123-45-6789 ok", K::UsSsn, "123-45-6789"),
        ("id 123 45 6789 ok", K::UsSsn, "123 45 6789"),
        ("SSN 123456789", K::UsSsn, "123456789"),
        ("Social Security: 123456789", K::UsSsn, "123456789"),
        ("BSN 912345676", K::NlBsn, "912345676"),
        ("bsn: 9123.45.676", K::NlBsn, "9123.45.676"),
        ("burgerservicenummer 999999990", K::NlBsn, "999999990"),
        ("SofiNummer: 900000004", K::NlBsn, "900000004"),
        ("Bel +31 6 12345678 of", K::Phone, "+31 6 12345678"),
        ("tel 06-12345678.", K::Phone, "06-12345678"),
        ("call (555) 123-4567 now", K::Phone, "(555) 123-4567"),
        ("+1 (555) 123-4567", K::Phone, "+1 (555) 123-4567"),
        ("0031612345678", K::Phone, "0031612345678"),
        ("+44 20 7946 0958", K::Phone, "+44 20 7946 0958"),
        ("020 7946 0958", K::Phone, "020 7946 0958"),
        ("555-123-4567", K::Phone, "555-123-4567"),
        ("555.123.4567", K::Phone, "555.123.4567"),
    ];

    #[test]
    fn finds_each_kind() {
        for &(text, kind, value) in FOUND {
            for mode in [Mode::Anonymize, Mode::Deanonymize] {
                assert_eq!(found(text, mode), [(kind, value)], "{text:?} in {mode:?}");
            }
        }
    }

    #[test]
    fn finds_a_json_web_token() {
        let text = format!("Authorization: Bearer {JWT}");
        assert_eq!(found(&text, Mode::Anonymize), [(K::Secret, JWT)]);
    }

    #[test]
    fn ignores_lookalikes() {
        for text in [
            "date 01-02-2024",
            "ts 2024-01-02 12:30:45",
            "time 12:30:45",
            "version 1.2.3.4.5",
            "loopback 127.0.0.1",
            "zero 0.0.0.0",
            "broadcast 255.255.255.255",
            "multicast 224.0.0.1",
            "bad iban NL91ABNA0417164301",
            "bad card 4111 1111 1111 1112",
            "short card 4111 1111 1111",
            "not ssn 123-45-678",
            "area 000 000-12-3456",
            "area 666 666-12-3456",
            "area 900 900-12-3456",
            "group 00 123-00-6789",
            "serial 0 123-45-0000",
            "bare 123456789",
            "bare 111222333",
            "className=\"row\" 123456789",
            "businessNumber: 123456789",
            "broadcast mac ff:ff:ff:ff:ff:ff",
            "zero mac 00:00:00:00:00:00",
            "mapped loopback ::ffff:127.0.0.1",
            "mapped zero ::ffff:0.0.0.0",
            "user@localhost",
            "eight digits 12345678",
            "short +1234",
            "price 1,234,567.89",
            "path /+31 6 12345678",
            "word x+31 6 12345678",
            "gluedNL91ABNA0417164300x",
            "short key AKIAIOSFODNN7EXAMPL",
            "lowercase key AKIAiosfodnn7example",
            "short token ghp_abc123",
            "port http://example.com:8080/path",
            "at-sign path https://example.com/@user",
            "handle @jan_jansen and a@b",
            "plain words and punctuation, nothing to see.",
            "",
        ] {
            assert_clean(text, Mode::Anonymize);
        }
    }

    #[test]
    fn context_rules_depend_on_mode() {
        // A bare SSN needs its keyword to be masked, but a bare proxy in
        // model output does not. Separated SSNs never need one.
        assert_eq!(
            found("SSN 123456789", Mode::Anonymize),
            [(K::UsSsn, "123456789")]
        );
        assert_clean("number 123456789", Mode::Anonymize);
        assert_eq!(
            found("number 234567891", Mode::Deanonymize),
            [(K::UsSsn, "234567891")]
        );
        assert_eq!(
            found("number 123-45-6789", Mode::Anonymize),
            [(K::UsSsn, "123-45-6789")]
        );

        // A BSN needs its keyword in Anonymize and never in Deanonymize. With
        // an SSN-invalid area (900-999) there is no competing kind.
        assert_clean("number 912345676", Mode::Anonymize);
        assert_eq!(
            found("number 912345676", Mode::Deanonymize),
            [(K::NlBsn, "912345676")]
        );
        assert_clean("number 1234.56.782", Mode::Anonymize);
        assert_eq!(
            found("number 1234.56.782", Mode::Deanonymize),
            [(K::NlBsn, "1234.56.782")]
        );
        assert_eq!(
            found("bsn 912345676", Mode::Anonymize),
            [(K::NlBsn, "912345676")]
        );

        // A bare number that is valid as both is claimed by the earlier
        // pattern, UsSsn, when no keyword is required.
        assert_eq!(
            found("number 111222333", Mode::Deanonymize),
            [(K::UsSsn, "111222333")]
        );
        assert_eq!(
            found("number 123456789", Mode::Deanonymize),
            [(K::UsSsn, "123456789")]
        );
        // A number that is neither stays undetected.
        assert_clean("number 999999999", Mode::Deanonymize);

        // The keyword must be close: beyond the 48-byte window it does not count.
        let far = format!("BSN{}111222333", " ".repeat(60));
        assert_clean(&far, Mode::Anonymize);
        let near = format!("BSN{}111222333", " ".repeat(40));
        assert_eq!(found(&near, Mode::Anonymize), [(K::NlBsn, "111222333")]);
    }

    #[test]
    fn bsn_is_found_after_the_ssn_pattern_rejected_the_same_digits() {
        // UsSsn matches first (priority) but has no SSN keyword here, so it is
        // rejected; NlBsn is then tried at the same start and accepts.
        assert_eq!(
            found("BSN 111222333", Mode::Anonymize),
            [(K::NlBsn, "111222333")]
        );
        assert_eq!(
            found("bsn:111222333.", Mode::Anonymize),
            [(K::NlBsn, "111222333")]
        );
        // The nearer keyword decides when both are present.
        assert_eq!(
            found("SSN 123-45-6789, BSN 111222333", Mode::Anonymize),
            [(K::UsSsn, "123-45-6789"), (K::NlBsn, "111222333")]
        );
        assert_eq!(
            found("BSN 123456782 / SSN 111222333", Mode::Anonymize),
            [(K::NlBsn, "123456782"), (K::UsSsn, "111222333")]
        );
        // A BSN keyword does not rescue digits that fail the 11-proof.
        assert_clean("BSN 123456789", Mode::Anonymize);
    }

    #[test]
    fn a_mac_address_is_not_an_ipv6_address_and_a_time_is_neither() {
        // Both start the same way; Ipv6 matches first, fails to parse, and the
        // anchored fallback finds Mac.
        assert_eq!(
            found("00:1A:2B:3C:4D:5E 2001:db8::1", Mode::Anonymize),
            [(K::Mac, "00:1A:2B:3C:4D:5E"), (K::Ipv6, "2001:db8::1")]
        );
        assert_clean("at 12:30:45 sharp", Mode::Anonymize);
        assert_clean("at 12:30 sharp", Mode::Anonymize);
    }

    #[test]
    fn a_greedy_match_is_trimmed_by_its_validator() {
        // The pattern runs on into the next token; the validator hands back
        // the valid prefix and the rest is scanned again.
        assert_eq!(
            found("IBAN BE68 5390 0754 7034 EXTRA", Mode::Anonymize),
            [(K::Iban, "BE68 5390 0754 7034")]
        );
        assert_eq!(
            found("card 4111 1111 1111 1111 12/25", Mode::Anonymize),
            [(K::CreditCard, "4111 1111 1111 1111")]
        );
        assert_eq!(
            found("4111111111111111 123", Mode::Anonymize),
            [(K::CreditCard, "4111111111111111")]
        );
        assert_eq!(
            found(
                "AT61 1904 3002 3457 3201 ABC and 4111 1111 1111 1111 123",
                Mode::Anonymize
            ),
            [
                (K::Iban, "AT61 1904 3002 3457 3201"),
                (K::CreditCard, "4111 1111 1111 1111")
            ]
        );
    }

    #[test]
    fn a_url_credential_hides_the_email_shaped_password() {
        assert_eq!(
            found("https://admin:hunter2@db.example.com/x", Mode::Anonymize),
            [(K::UrlCredential, "admin:hunter2")]
        );
        assert_eq!(
            found("https://x:y@a.io and bob@example.org", Mode::Anonymize),
            [(K::UrlCredential, "x:y"), (K::Email, "bob@example.org")]
        );
    }

    #[test]
    fn mixed_corpus_gives_sorted_disjoint_spans() {
        let text = "key AKIAIOSFODNN7EXAMPLE db https://admin:hunter2@db.example.com/x\n\
            Mail jan.jansen@acme.nl, IBAN NL91ABNA0417164300, card 4111 1111 1111 1111.\n\
            host 2001:db8:85a3::8a2e:370:7334 mac 00:1A:2B:3C:4D:5E ip 203.0.113.42\n\
            SSN 123-45-6789, BSN 111222333, bel +31 6 12345678 of jan.jansen@acme.nl";
        let expected = [
            (K::Secret, "AKIAIOSFODNN7EXAMPLE"),
            (K::UrlCredential, "admin:hunter2"),
            (K::Email, "jan.jansen@acme.nl"),
            (K::Iban, "NL91ABNA0417164300"),
            (K::CreditCard, "4111 1111 1111 1111"),
            (K::Ipv6, "2001:db8:85a3::8a2e:370:7334"),
            (K::Mac, "00:1A:2B:3C:4D:5E"),
            (K::Ipv4, "203.0.113.42"),
            (K::UsSsn, "123-45-6789"),
            (K::NlBsn, "111222333"),
            (K::Phone, "+31 6 12345678"),
            (K::Email, "jan.jansen@acme.nl"),
        ];
        assert_eq!(found(text, Mode::Anonymize), expected);
        let spans = detector().detect(text, Mode::Anonymize);
        assert!(spans.windows(2).all(|w| w[0].end <= w[1].start));
    }

    #[test]
    fn spans_sit_on_char_boundaries_next_to_non_ascii_text() {
        let text = "é+31 6 12345678é naïve jan@x.nl→ 4111 1111 1111 1111✓ \
            https://üser:pässword@host/ ¿203.0.113.42? 日本 BSN 111222333 語";
        let spans = detector().detect(text, Mode::Anonymize);
        assert_eq!(spans.len(), 6, "{spans:?}");
        for span in &spans {
            assert!(text.is_char_boundary(span.start), "{span:?}");
            assert!(text.is_char_boundary(span.end), "{span:?}");
        }
        assert_eq!(
            found(text, Mode::Anonymize)[3],
            (K::UrlCredential, "üser:pässword")
        );
    }

    #[test]
    fn scan_of_empty_and_tiny_inputs() {
        assert!(detector().detect("", Mode::Deanonymize).is_empty());
        assert!(detector().scan_chunked(b"", Mode::Anonymize, 4).is_empty());
        assert_eq!(found("a@b.io", Mode::Anonymize), [(K::Email, "a@b.io")]);
    }

    /// Filler without digits or `@`, so it never contains PII.
    fn filler(len: usize, rng: &mut Rng) -> Vec<u8> {
        const WORDS: [&str; 8] = [
            "alpha", "beta", "gamma", "delta", "lorem", "ipsum", "dolor", "amet",
        ];
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes());
            out.push(b' ');
        }
        out.truncate(len);
        out
    }

    #[test]
    fn chunked_scan_equals_single_scan_on_a_five_mib_text() -> crate::Result<()> {
        let plants: [(K, &str, &str); 8] = [
            (K::Email, "jan.jansen@acme.nl", "jan.jansen@acme.nl"),
            (K::Phone, "+31 6 12345678", "+31 6 12345678"),
            (K::Iban, "NL91 ABNA 0417 1643 00", "NL91 ABNA 0417 1643 00"),
            (K::CreditCard, "4111 1111 1111 1111", "4111 1111 1111 1111"),
            (K::Ipv4, "203.0.113.42", "203.0.113.42"),
            (K::Mac, "00:1A:2B:3C:4D:5E", "00:1A:2B:3C:4D:5E"),
            (K::NlBsn, "BSN 912345676", "912345676"),
            (K::Secret, "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ];
        // Offsets from each chunk boundary; the first is the one the plan names.
        let offsets: [isize; 6] = [-7, 30, -50, -100, 80, -150];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut hay = filler(5 << 20, &mut rng);
        let mut expected = Vec::new();
        let mut which = 0;
        for boundary in (1..5).map(|k| k * CHUNK) {
            for offset in offsets {
                let (kind, planted, value) = plants[which % plants.len()];
                which += 1;
                // Spaces around the value keep filler words from gluing onto it.
                let padded = format!(" {planted} ");
                let at = boundary.saturating_add_signed(offset);
                hay[at..at + padded.len()].copy_from_slice(padded.as_bytes());
                expected.push((at + 1 + planted.find(value).unwrap_or(0), kind, value));
            }
        }
        expected.sort_by_key(|&(at, ..)| at);
        let text = String::from_utf8(hay).map_err(std::io::Error::other)?;
        assert!(text.len() > PARALLEL_FROM);

        let det = detector();
        for mode in [Mode::Anonymize, Mode::Deanonymize] {
            let chunked = det.detect(&text, mode);
            assert_eq!(chunked, det.scan_whole(text.as_bytes(), mode), "{mode:?}");
            let seen: Vec<(usize, K, &str)> = chunked
                .iter()
                .map(|s| (s.start, s.kind, &text[s.start..s.end]))
                .collect();
            assert_eq!(seen, expected, "{mode:?}");
        }
        Ok(())
    }

    /// A text of PII-like tokens in random order, so tokens run into each
    /// other the way real separators allow.
    fn token_soup(rng: &mut Rng) -> String {
        const TOKENS: [&str; 36] = [
            "+31 6 12345678",
            "06-12345678",
            "0612345678",
            "020 7946 0958",
            "(555) 123-4567",
            "555.123.4567",
            "jan.jansen@acme.nl",
            "a@b.io",
            "NL91ABNA0417164300",
            "NL91 ABNA 0417 1643 00",
            "BE68 5390 0754 7034",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "123-45-6789",
            "123456789",
            "111222333",
            "1234.56.782",
            "BSN ",
            "SSN ",
            "10.1.2.3",
            "1.2.3.4.5",
            "00:1A:2B:3C:4D:5E",
            "2001:db8::1",
            "::ffff:192.0.2.128",
            "64:ff9b::192.0.2.33",
            "12:30:45",
            "AKIAIOSFODNN7EXAMPLE",
            "https://u:p@h.io/",
            "01-02-2024",
            "EXTRA",
            "12/25",
            " ",
            ", ",
            "x",
            "7",
            "-",
        ];
        let mut text = String::new();
        for _ in 0..rng.below(40) + 5 {
            text.push_str(TOKENS[rng.below(TOKENS.len())]);
            if rng.below(3) == 0 {
                text.push(' ');
            }
        }
        text
    }

    #[test]
    fn chunked_scan_equals_single_scan_for_every_small_chunk_size() {
        let det = detector();
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        let mut spans_seen = 0;
        for _ in 0..150 {
            let text = token_soup(&mut rng);
            for mode in [Mode::Anonymize, Mode::Deanonymize] {
                let whole = det.scan_whole(text.as_bytes(), mode);
                spans_seen += whole.len();
                for chunk in [1, 2, 3, 5, 8, 13, 21, 64, 200] {
                    assert_eq!(
                        det.scan_chunked(text.as_bytes(), mode, chunk),
                        whole,
                        "chunk {chunk}, {mode:?}, {text:?}"
                    );
                }
            }
        }
        assert!(
            spans_seen > 500,
            "the soup should contain plenty of PII: {spans_seen}"
        );
    }

    #[test]
    fn scans_resume_after_a_rejected_candidate() {
        // Nothing here may stall or skip the valid value behind rejects.
        let text = "1.2.3.4.5 0.0.0.0 127.0.0.1 192.168.0.1 12:30:45 NL00ABNA0417164300 jan@x.io";
        assert_eq!(
            found(text, Mode::Anonymize),
            [(K::Ipv4, "192.168.0.1"), (K::Email, "jan@x.io")]
        );
        let spans: Vec<Span> = detector().detect(text, Mode::Anonymize);
        assert!(spans.windows(2).all(|w| w[0].end <= w[1].start));
    }

    /// Spans found the plain way: one union regex of every pattern, searched
    /// again from each resume point. The scan must match it exactly.
    fn union_of_everything(det: &RegexDetector, hay: &[u8], mode: Mode) -> Vec<Span> {
        let sources: Vec<&str> = PATTERNS.iter().map(|p| p.regex).collect();
        let config = syntax::Config::new().unicode(false).utf8(false);
        let Ok(all) = super::meta::Regex::builder()
            .syntax(config)
            .build_many(&sources)
        else {
            panic!("the union does not build");
        };
        let mut spans = Vec::new();
        let mut pos = 0;
        while pos < hay.len() {
            let Some(found) = all.search(&super::Input::new(hay).range(pos..)) else {
                break;
            };
            let hit = super::Hit {
                id: found.pattern().as_usize(),
                start: found.start(),
                end: found.end(),
            };
            if let Some(span) = det.resolve(hay, hit, hay.len(), mode) {
                pos = span.end;
                spans.push(span);
            } else {
                pos = found.start() + 1;
            }
        }
        spans
    }

    #[test]
    fn scan_equals_one_union_of_every_pattern() {
        let det = detector();
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for _ in 0..200 {
            let text = token_soup(&mut rng);
            for mode in [Mode::Anonymize, Mode::Deanonymize] {
                assert_eq!(
                    det.scan_whole(text.as_bytes(), mode),
                    union_of_everything(det, text.as_bytes(), mode),
                    "{mode:?} {text:?}"
                );
            }
        }
        let corpus = FOUND
            .iter()
            .map(|(text, ..)| *text)
            .collect::<Vec<_>>()
            .join(" | ");
        for mode in [Mode::Anonymize, Mode::Deanonymize] {
            assert_eq!(
                det.scan_whole(corpus.as_bytes(), mode),
                union_of_everything(det, corpus.as_bytes(), mode),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn debug_output_stays_short() {
        let text = format!("{:?}", detector());
        assert!(text.len() < 500, "{} bytes", text.len());
    }

    /// Random text over an alphabet that mixes PII building blocks with
    /// multi-byte characters.
    fn char_soup(rng: &mut Rng) -> String {
        const ALPHABET: [char; 44] = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '4', '6', 'a', 'f', 'B',
            'N', 'L', 'S', '@', '.', ':', '-', '+', '/', ' ', ' ', '(', ')', '_', '%', 'é', '日',
            '€', 'x', 'A', 'K', 'I', 'e', 'y', 'J', 'h', 'p',
        ];
        (0..rng.below(300))
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect()
    }

    #[test]
    fn spans_are_ordered_on_char_boundaries_and_valid_for_their_kind() {
        let det = detector();
        let mut rng = Rng(0x0BAD_C0DE_1234_5678);
        let mut seen = [0usize; 11];
        for round in 0..3000 {
            let text = if round % 2 == 0 {
                token_soup(&mut rng)
            } else {
                char_soup(&mut rng)
            };
            for mode in [Mode::Anonymize, Mode::Deanonymize] {
                let spans = det.detect(&text, mode);
                let mut end = 0;
                for span in &spans {
                    assert!(
                        end <= span.start && span.start < span.end,
                        "{spans:?} {text:?}"
                    );
                    assert!(text.is_char_boundary(span.start), "{span:?} {text:?}");
                    assert!(text.is_char_boundary(span.end), "{span:?} {text:?}");
                    let value = &text[span.start..span.end];
                    assert!(
                        super::validate::accepts(span.kind, value),
                        "{:?} {value:?} in {text:?}",
                        span.kind
                    );
                    end = span.end;
                    seen[span.kind as usize - 1] += 1;
                }
            }
        }
        assert!(
            seen.iter().all(|&n| n > 0),
            "every kind should turn up: {seen:?}"
        );
    }
}
