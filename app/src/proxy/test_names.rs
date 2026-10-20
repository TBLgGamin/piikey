//! A stand-in for the detection model in the proxy tests: it finds fixed names, so the tests
//! need neither the model nor its download.

use std::{cmp::Reverse, path::Path};

use piikey::{
    Result,
    detect::{CompositeDetector, Detector, EntityKind, Mode, RegexDetector, Span},
    engine::Engine,
    vault::Vault,
};

/// Reports each of its names as a [`EntityKind::Person`], in any ASCII case and wherever it stands
/// alone: the bytes around it are not ASCII letters or digits. It reports in both modes, like the
/// literal matcher it replaces; the engine never restores what a detector reports as a name.
#[derive(Debug)]
pub(super) struct Names(pub(super) &'static [&'static str]);

impl Detector for Names {
    fn detect(&self, text: &str, _mode: Mode) -> Vec<Span> {
        let lower = text.to_ascii_lowercase();
        let bytes = text.as_bytes();
        let mut spans: Vec<Span> = Vec::new();
        for name in self.0 {
            for (start, found) in lower.match_indices(&name.to_ascii_lowercase()) {
                let end = start + found.len();
                let before = start.checked_sub(1).and_then(|i| bytes.get(i));
                let after = bytes.get(end);
                if !before.is_some_and(u8::is_ascii_alphanumeric)
                    && !after.is_some_and(u8::is_ascii_alphanumeric)
                {
                    spans.push(Span {
                        start,
                        end,
                        kind: EntityKind::Person,
                    });
                }
            }
        }
        // Sorted and never overlapping: the leftmost wins, the longest of those that start
        // together.
        spans.sort_by_key(|span| (span.start, Reverse(span.end)));
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

/// An engine on the vault at `vault_path` that finds what the regexes find and `names`. Where a
/// name overlaps a regex match, the regex match wins.
///
/// # Errors
/// Vault open failures.
pub(super) fn engine(vault_path: &Path, names: &'static [&'static str]) -> Result<Engine> {
    let detector = CompositeDetector(vec![
        Box::new(RegexDetector::new()?),
        Box::new(Names(names)),
    ]);
    Ok(Engine::new(Box::new(detector), Vault::open(vault_path)?))
}
