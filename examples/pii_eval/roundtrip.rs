//! The round trip through the real engine: anonymize a document, deanonymize the result, and
//! compare with the original. Also whether a gold value is still in the anonymized text.

use std::collections::{BTreeMap, HashSet};

use piikey::{
    detect::Mode,
    engine::{Engine, Replacement},
};

use crate::{data::Doc, taxonomy::Cat};

/// Documents the engine anonymizes and restores per call, like a few messages of one request.
const BATCH: usize = 32;

/// A gold value shorter than this many non-blank characters is not checked for surviving: a
/// number such as `5` or an initial turns up in the text by chance.
const MIN_VALUE_CHARS: usize = 3;

/// Examples of each failure kept: the counts are exact, the lists are for showing.
const KEEP: usize = 200;

/// A document that did not come back as it went in.
#[derive(Debug, Clone)]
pub struct Mismatch {
    pub doc: String,
    /// The original and the restored text around the first difference.
    pub original: String,
    pub restored: String,
    /// The replacements that touched the words where the two differ, one per line: what the engine
    /// put in and what it put back.
    pub trace: Vec<String>,
}

/// A gold value left verbatim in the anonymized text.
#[derive(Debug, Clone)]
pub struct Survivor {
    pub doc: String,
    pub cat: Cat,
    pub value: String,
}

/// Outcome of the round trip over a sample of documents.
#[derive(Debug, Default)]
pub struct RoundTrip {
    pub docs: usize,
    /// Documents anonymize changed.
    pub changed: usize,
    /// Documents that came back byte for byte, and of those the ones anonymize changed.
    pub exact: usize,
    pub exact_changed: usize,
    /// Documents the engine failed on (a vault or proxy error), with the first few messages.
    pub errors: usize,
    pub error_messages: Vec<String>,
    /// Documents with at least one gold value left in the anonymized text.
    pub survivor_docs: usize,
    /// Distinct gold values checked, and how many were left, per gold category.
    pub checked: BTreeMap<Cat, usize>,
    pub survived: BTreeMap<Cat, usize>,
    pub mismatches: Vec<Mismatch>,
    pub survivors: Vec<Survivor>,
}

/// What the engine did to one document: the text each way and the replacements behind them.
struct Done {
    anonymized: String,
    restored: String,
    /// Original to stand-in, positions in the original.
    forward: Vec<Replacement>,
    /// Stand-in to original, positions in the anonymized text.
    backward: Vec<Replacement>,
}

/// The sample `docs` anonymized, then deanonymized, by `engine`. A batch the engine fails on is
/// retried document by document so that one bad document costs one document. Engine failures are
/// counted in [`RoundTrip::errors`], never returned. A gold value is checked for surviving only
/// when `checked` accepts its category (piikey cannot mask the others, such as plain dates).
pub fn run(engine: &Engine, docs: &[&Doc], checked: &dyn Fn(Cat) -> bool) -> RoundTrip {
    let mut rt = RoundTrip::default();
    for chunk in docs.chunks(BATCH) {
        if let Ok(done) = batch(engine, chunk) {
            rt.add_all(chunk, &done, checked);
            continue;
        }
        for doc in chunk {
            match batch(engine, std::slice::from_ref(doc)) {
                Ok(done) => rt.add_all(std::slice::from_ref(doc), &done, checked),
                Err(e) => rt.fail(doc, &e),
            }
        }
    }
    rt
}

/// Each document of `chunk` anonymized and restored, as `Engine::run` does it.
fn batch(engine: &Engine, chunk: &[&Doc]) -> piikey::Result<Vec<Done>> {
    let texts: Vec<&str> = chunk.iter().map(|d| d.text.as_str()).collect();
    let forward = engine.plan(Mode::Anonymize, &texts)?;
    let anonymized: Vec<String> = texts
        .iter()
        .zip(&forward)
        .map(|(text, reps)| Engine::apply(text, reps))
        .collect();
    let again: Vec<&str> = anonymized.iter().map(String::as_str).collect();
    let backward = engine.plan(Mode::Deanonymize, &again)?;
    let restored: Vec<String> = again
        .iter()
        .zip(&backward)
        .map(|(text, reps)| Engine::apply(text, reps))
        .collect();
    Ok(anonymized
        .into_iter()
        .zip(restored)
        .zip(forward.into_iter().zip(backward))
        .map(|((anonymized, restored), (forward, backward))| Done {
            anonymized,
            restored,
            forward,
            backward,
        })
        .collect())
}

impl RoundTrip {
    fn add_all(&mut self, chunk: &[&Doc], done: &[Done], checked: &dyn Fn(Cat) -> bool) {
        for (doc, one) in chunk.iter().zip(done) {
            self.add(doc, one, checked);
        }
    }

    fn fail(&mut self, doc: &Doc, error: &piikey::Error) {
        self.docs += 1;
        self.errors += 1;
        if self.error_messages.len() < 5 {
            self.error_messages.push(format!("{}: {error}", doc.id));
        }
    }

    fn add(&mut self, doc: &Doc, done: &Done, checked: &dyn Fn(Cat) -> bool) {
        let (original, anonymized) = (doc.text.as_str(), done.anonymized.as_str());
        self.docs += 1;
        let changed = anonymized != original;
        self.changed += usize::from(changed);
        if done.restored == original {
            self.exact += 1;
            self.exact_changed += usize::from(changed);
        } else if self.mismatches.len() < KEEP {
            self.mismatches.push(Mismatch {
                doc: doc.id.clone(),
                ..first_difference(original, done)
            });
        }

        let mut seen = HashSet::new();
        let mut any = false;
        for g in &doc.gold {
            let value = &doc.text[g.start..g.end];
            let chars = value.chars().filter(|c| !c.is_whitespace()).count();
            if !checked(g.cat) || chars < MIN_VALUE_CHARS || !seen.insert(value) {
                continue;
            }
            *self.checked.entry(g.cat).or_insert(0) += 1;
            if contains_token(anonymized, value) {
                any = true;
                *self.survived.entry(g.cat).or_insert(0) += 1;
                if self.survivors.len() < KEEP {
                    self.survivors.push(Survivor {
                        doc: doc.id.clone(),
                        cat: g.cat,
                        value: value.to_owned(),
                    });
                }
            }
        }
        self.survivor_docs += usize::from(any);
    }
}

/// Where the restored text first differs from `original`: a window of each around that point,
/// and the replacements that touched the words there.
fn first_difference(original: &str, done: &Done) -> Mismatch {
    let restored = done.restored.as_str();
    let common = original
        .chars()
        .zip(restored.chars())
        .take_while(|(x, y)| x == y)
        .count();
    let window = |s: &str| -> String {
        let before: Vec<char> = s.chars().take(common).collect();
        let from = before.len().saturating_sub(24);
        let head: String = before[from..].iter().collect();
        let tail: String = s.chars().skip(common).take(48).collect();
        format!("{}{head}{tail}", if from > 0 { "…" } else { "" })
    };
    Mismatch {
        doc: String::new(),
        original: window(original),
        restored: window(restored),
        trace: trace(original, common, done),
    }
}

/// The word of `text` that holds its `at`-th character, without the punctuation around it.
fn word_at(text: &str, at: usize) -> &str {
    let start = text.char_indices().nth(at).map_or(text.len(), |(i, _)| i);
    let from = text[..start].rfind(char::is_whitespace).map_or(0, |i| {
        i + text[i..].chars().next().map_or(1, char::len_utf8)
    });
    let to = text[start..]
        .find(char::is_whitespace)
        .map_or(text.len(), |i| start + i);
    text[from..to].trim_matches(|c: char| !c.is_alphanumeric())
}

/// The replacements that explain a mismatch: what the engine put in for the word where the texts
/// first differ, and what it put back, as lines like `anonymize: "1942" -> "1962"`.
fn trace(original: &str, common: usize, done: &Done) -> Vec<String> {
    let word = word_at(original, common);
    let came_back = word_at(&done.restored, common);
    if word.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut stand_ins: HashSet<&str> = HashSet::new();
    for r in &done.forward {
        let from = &original[r.start..r.end];
        if from.contains(word) || word.contains(from) {
            stand_ins.insert(&r.with);
            lines.push(format!("anonymize: `{from}` -> `{}`", r.with));
        }
    }
    let mut put_back = false;
    for r in &done.backward {
        let proxy = &done.anonymized[r.start..r.end];
        if stand_ins.contains(proxy) || *r.with == *came_back {
            put_back = true;
            lines.push(format!("deanonymize: `{proxy}` -> `{}`", r.with));
        }
    }
    if !put_back && !stand_ins.is_empty() {
        lines.push("deanonymize: nothing was put back".to_owned());
    }
    lines.truncate(8);
    lines
}

/// Whether `needle` occurs in `hay` as a whole token: not glued to a letter or digit.
fn contains_token(hay: &str, needle: &str) -> bool {
    let first = needle.chars().next().is_some_and(char::is_alphanumeric);
    let last = needle
        .chars()
        .next_back()
        .is_some_and(char::is_alphanumeric);
    hay.match_indices(needle).any(|(at, found)| {
        let before = hay[..at].chars().next_back();
        let after = hay[at + found.len()..].chars().next();
        !(first && before.is_some_and(char::is_alphanumeric)
            || last && after.is_some_and(char::is_alphanumeric))
    })
}

#[cfg(test)]
mod tests {
    use super::{contains_token, word_at};

    #[test]
    fn a_value_counts_only_as_a_whole_token() {
        assert!(contains_token("mail Jan Jansen now", "Jan Jansen"));
        assert!(contains_token("(0612345678)", "0612345678"));
        assert!(!contains_token("Janssens", "Jan"));
        assert!(!contains_token("x06123456789", "0612345678"));
        assert!(contains_token("a@b.nl,", "a@b.nl"));
    }

    #[test]
    fn the_word_at_a_position_has_no_punctuation_around_it() {
        let text = "ben op 16 april, (1942) geboren";
        assert_eq!(word_at(text, 18), "1942");
        assert_eq!(word_at(text, 0), "ben");
        assert_eq!(word_at(text, 11), "april");
        assert_eq!(word_at("é à", 3), "à");
    }
}
