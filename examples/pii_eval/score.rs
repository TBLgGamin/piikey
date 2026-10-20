//! Scoring: predicted spans against gold spans, per category.
//!
//! Three span-level criteria, each with precision, recall and F1:
//!
//! - **strict**: the same start, the same end and the same category;
//! - **overlap**: the spans share a character and the category is the same (or one the label
//!   table calls compatible, such as a city inside an address);
//! - **any**: the spans share a character, whatever the category. Recall here is "was it masked
//!   at all", the only thing piikey's privacy promise needs; the category only picks the
//!   stand-in.
//!
//! Two character-level measures that do not depend on how a span is cut:
//!
//! - **leakage**: the share of gold characters no prediction covers;
//! - **false-positive masking**: the share of characters outside every gold span that a
//!   prediction masks (the cost to the usefulness of the text).
//!
//! Characters are Unicode scalar values that are not whitespace. Gold spans are disjoint and so
//! are predictions (a detector's contract; a violation is dropped and counted).

use std::{collections::BTreeMap, ops::AddAssign};

use piikey::detect::{EntityKind, Span};
use rayon::prelude::*;

use crate::{
    data::{Doc, Source},
    taxonomy::{Cat, Taxonomy},
};

/// A predicted span with its category.
#[derive(Debug, Clone, Copy)]
pub struct Pred {
    pub start: usize,
    pub end: usize,
    pub kind: EntityKind,
    pub cat: Cat,
}

/// Counts for one category. Gold-side counts belong to the gold span's category, prediction-side
/// counts to the predicted span's category.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatStats {
    /// Gold spans.
    pub gold: usize,
    /// Gold spans an identical span of the same category matches.
    pub strict: usize,
    /// Gold spans a prediction of a compatible category overlaps.
    pub gold_cat: usize,
    /// Gold spans any prediction overlaps.
    pub gold_any: usize,
    /// Gold spans with every character covered.
    pub gold_full: usize,
    /// Characters of the gold spans, and how many of them a prediction covers.
    pub gold_chars: usize,
    pub covered_chars: usize,
    /// Predictions the source can judge.
    pub pred: usize,
    /// ... that overlap a gold span of a compatible category, and of any category.
    pub pred_cat: usize,
    pub pred_any: usize,
    /// Characters of those predictions that lie outside every gold span.
    pub fp_chars: usize,
    /// Predictions the source cannot judge (it does not annotate the category), and their
    /// characters outside every gold span.
    pub unjudged: usize,
    pub unjudged_chars: usize,
}

impl AddAssign<&Self> for CatStats {
    fn add_assign(&mut self, o: &Self) {
        self.gold += o.gold;
        self.strict += o.strict;
        self.gold_cat += o.gold_cat;
        self.gold_any += o.gold_any;
        self.gold_full += o.gold_full;
        self.gold_chars += o.gold_chars;
        self.covered_chars += o.covered_chars;
        self.pred += o.pred;
        self.pred_cat += o.pred_cat;
        self.pred_any += o.pred_any;
        self.fp_chars += o.fp_chars;
        self.unjudged += o.unjudged;
        self.unjudged_chars += o.unjudged_chars;
    }
}

/// Precision, recall and F1 of one criterion. A side is `None` when nothing could be counted
/// (no predictions, or no gold spans).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Prf {
    pub p: Option<f64>,
    pub r: Option<f64>,
}

impl Prf {
    fn of(pred_ok: usize, pred: usize, gold_ok: usize, gold: usize) -> Self {
        Self {
            p: ratio(pred_ok, pred),
            r: ratio(gold_ok, gold),
        }
    }

    /// Harmonic mean. `None` when there are no gold spans (nothing to recall, however the
    /// predictions fared); zero when there are gold spans and nothing correct was predicted.
    #[must_use]
    pub fn f1(self) -> Option<f64> {
        let r = self.r?;
        let p = self.p.unwrap_or(0.0);
        Some(if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        })
    }
}

/// A count as a float. The counts here are far below `u32::MAX`.
#[must_use]
pub fn f(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// `n / d`, or `None` when `d` is zero.
#[must_use]
pub fn ratio(n: usize, d: usize) -> Option<f64> {
    (d > 0).then(|| f(n) / f(d))
}

impl CatStats {
    #[must_use]
    pub fn strict(&self) -> Prf {
        Prf::of(self.strict, self.pred, self.strict, self.gold)
    }

    #[must_use]
    pub fn overlap(&self) -> Prf {
        Prf::of(self.pred_cat, self.pred, self.gold_cat, self.gold)
    }

    #[must_use]
    pub fn any(&self) -> Prf {
        Prf::of(self.pred_any, self.pred, self.gold_any, self.gold)
    }

    /// Share of gold characters no prediction covers.
    #[must_use]
    pub fn leak(&self) -> Option<f64> {
        ratio(self.gold_chars - self.covered_chars, self.gold_chars)
    }

    /// Share of gold spans covered completely.
    #[must_use]
    pub fn full(&self) -> Option<f64> {
        ratio(self.gold_full, self.gold)
    }
}

/// Counts for a set of documents.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Per category, indexed like [`Taxonomy::cats`].
    pub cats: Vec<CatStats>,
    pub docs: usize,
    /// Characters of all the texts.
    pub chars: usize,
    /// Predictions dropped for breaking the contract of a detector (out of range, overlapping).
    pub dropped: usize,
}

impl Stats {
    #[must_use]
    pub fn new(cats: usize) -> Self {
        Self {
            cats: vec![CatStats::default(); cats],
            ..Self::default()
        }
    }

    /// The counts of the categories `keep` accepts, added up.
    pub fn sum(&self, keep: impl Fn(Cat) -> bool) -> CatStats {
        let mut total = CatStats::default();
        for (i, c) in self.cats.iter().enumerate() {
            if keep(Cat(i)) {
                total += c;
            }
        }
        total
    }

    /// Share of the characters outside every gold span that judged predictions mask.
    #[must_use]
    pub fn fp_rate(&self) -> Option<f64> {
        let all = self.sum(|_| true);
        ratio(all.fp_chars, self.chars - all.gold_chars)
    }

    /// The same for predictions the source cannot judge.
    #[must_use]
    pub fn unjudged_rate(&self) -> Option<f64> {
        let all = self.sum(|_| true);
        ratio(all.unjudged_chars, self.chars - all.gold_chars)
    }
}

impl AddAssign<&Self> for Stats {
    fn add_assign(&mut self, o: &Self) {
        for (mine, theirs) in self.cats.iter_mut().zip(&o.cats) {
            *mine += theirs;
        }
        self.docs += o.docs;
        self.chars += o.chars;
        self.dropped += o.dropped;
    }
}

/// A gold span or a prediction worth showing, with where it is.
#[derive(Debug, Clone)]
pub struct Example {
    pub doc: usize,
    pub start: usize,
    pub end: usize,
    pub cat: Cat,
    /// The gold label as the source wrote it, or the predicted kind's name.
    pub tag: String,
    /// For a wrong category: the category of the prediction that covers most of the span.
    pub other: Option<Cat>,
}

/// What went wrong in one document, as it was found.
#[derive(Debug, Default)]
pub struct Findings {
    /// Gold spans (indices into the document's) no prediction touches.
    pub missed: Vec<usize>,
    /// Gold spans touched but not covered completely.
    pub partial: Vec<usize>,
    /// Gold spans masked only by predictions of an incompatible category, with that category.
    pub wrong: Vec<(usize, Cat)>,
    /// Judged predictions that touch no gold span.
    pub false_pos: Vec<Pred>,
    /// For every gold span: its category and the category of the prediction covering most of it.
    pub confusion: Vec<(Cat, Option<Cat>)>,
}

/// The failures of a whole source, as examples.
#[derive(Debug, Default)]
pub struct Failures {
    pub missed: Vec<Example>,
    pub partial: Vec<Example>,
    pub wrong: Vec<Example>,
    pub false_pos: Vec<Example>,
    /// Count of gold spans per (gold category, category that covers most of it or none).
    pub confusion: BTreeMap<(Cat, Option<Cat>), usize>,
}

/// Everything scoring one source with one detector gives.
#[derive(Debug)]
pub struct Agg {
    pub total: Stats,
    pub by_lang: BTreeMap<String, Stats>,
    pub by_group: BTreeMap<String, Stats>,
    pub failures: Failures,
}

/// Scores `predictions` (one list of spans per document of `source`).
#[must_use]
pub fn score_source(tax: &Taxonomy, source: &Source, predictions: &[Vec<Span>]) -> Agg {
    let per_doc: Vec<(Stats, Findings)> = source
        .docs
        .par_iter()
        .zip(predictions)
        .map(|(doc, spans)| score_doc(tax, &source.judged, doc, spans))
        .collect();

    let new = || Stats::new(tax.cats.len());
    let mut agg = Agg {
        total: new(),
        by_lang: BTreeMap::new(),
        by_group: BTreeMap::new(),
        failures: Failures::default(),
    };
    for (i, ((stats, found), doc)) in per_doc.iter().zip(&source.docs).enumerate() {
        agg.total += stats;
        *agg.by_lang.entry(doc.lang.clone()).or_insert_with(new) += stats;
        if !doc.group.is_empty() {
            *agg.by_group.entry(doc.group.clone()).or_insert_with(new) += stats;
        }
        agg.failures.add(i, doc, found);
    }
    agg
}

impl Failures {
    fn add(&mut self, doc_idx: usize, doc: &Doc, found: &Findings) {
        let gold = |gi: usize, other: Option<Cat>| {
            let g = &doc.gold[gi];
            Example {
                doc: doc_idx,
                start: g.start,
                end: g.end,
                cat: g.cat,
                tag: g.label.clone(),
                other,
            }
        };
        self.missed
            .extend(found.missed.iter().map(|&gi| gold(gi, None)));
        self.partial
            .extend(found.partial.iter().map(|&gi| gold(gi, None)));
        self.wrong
            .extend(found.wrong.iter().map(|&(gi, other)| gold(gi, Some(other))));
        self.false_pos
            .extend(found.false_pos.iter().map(|p| Example {
                doc: doc_idx,
                start: p.start,
                end: p.end,
                cat: p.cat,
                tag: p.kind.as_str().to_owned(),
                other: None,
            }));
        for &pair in &found.confusion {
            *self.confusion.entry(pair).or_insert(0) += 1;
        }
    }
}

/// Characters of `text[a..b]` that are not whitespace.
fn nonblank(text: &str, a: usize, b: usize) -> usize {
    text[a..b].chars().filter(|c| !c.is_whitespace()).count()
}

/// The predictions of a detector as sorted, disjoint [`Pred`]s inside `text`, and how many it
/// broke the contract with.
fn clean(tax: &Taxonomy, text: &str, spans: &[Span]) -> (Vec<Pred>, usize) {
    let mut preds: Vec<Pred> = spans
        .iter()
        .filter(|s| {
            s.start < s.end
                && s.end <= text.len()
                && text.is_char_boundary(s.start)
                && text.is_char_boundary(s.end)
        })
        .map(|s| Pred {
            start: s.start,
            end: s.end,
            kind: s.kind,
            cat: tax.cat_of(s.kind),
        })
        .collect();
    let mut dropped = spans.len() - preds.len();
    preds.sort_by_key(|p| (p.start, p.end));
    let mut last_end = 0;
    preds.retain(|p| {
        let ok = p.start >= last_end;
        if ok {
            last_end = p.end;
        } else {
            dropped += 1;
        }
        ok
    });
    (preds, dropped)
}

/// Scores the predictions for one document.
#[must_use]
pub fn score_doc(tax: &Taxonomy, judged: &[bool], doc: &Doc, spans: &[Span]) -> (Stats, Findings) {
    let text = doc.text.as_str();
    let (preds, dropped) = clean(tax, text, spans);
    let mut stats = Stats::new(tax.cats.len());
    stats.docs = 1;
    stats.chars = nonblank(text, 0, text.len());
    stats.dropped = dropped;
    let mut found = Findings::default();

    for (gi, g) in doc.gold.iter().enumerate() {
        let total = nonblank(text, g.start, g.end);
        let (mut covered, mut by_cat, mut strict) = (0, false, false);
        let mut best: Option<(usize, Cat)> = None;
        for p in preds.iter().skip_while(|p| p.end <= g.start) {
            if p.start >= g.end {
                break;
            }
            let shared = nonblank(text, g.start.max(p.start), g.end.min(p.end));
            if shared == 0 {
                continue;
            }
            covered += shared;
            by_cat |= tax.compatible(p.cat, g.cat);
            strict |= p.start == g.start && p.end == g.end && p.cat == g.cat;
            if best.is_none_or(|(most, _)| shared > most) {
                best = Some((shared, p.cat));
            }
        }
        let c = &mut stats.cats[g.cat.0];
        c.gold += 1;
        c.gold_chars += total;
        c.covered_chars += covered;
        c.strict += usize::from(strict);
        c.gold_cat += usize::from(by_cat);
        c.gold_any += usize::from(best.is_some());
        c.gold_full += usize::from(covered == total);
        found.confusion.push((g.cat, best.map(|(_, cat)| cat)));
        match best {
            None => found.missed.push(gi),
            Some((_, other)) => {
                if covered < total {
                    found.partial.push(gi);
                }
                if !by_cat {
                    found.wrong.push((gi, other));
                }
            }
        }
    }

    for p in &preds {
        let len = nonblank(text, p.start, p.end);
        let (mut inside, mut touches, mut by_cat) = (0, false, false);
        for g in doc.gold.iter().skip_while(|g| g.end <= p.start) {
            if g.start >= p.end {
                break;
            }
            let shared = nonblank(text, g.start.max(p.start), g.end.min(p.end));
            if shared == 0 {
                continue;
            }
            inside += shared;
            touches = true;
            by_cat |= tax.compatible(p.cat, g.cat);
        }
        let c = &mut stats.cats[p.cat.0];
        if judged[p.cat.0] {
            c.pred += 1;
            c.pred_cat += usize::from(by_cat);
            c.pred_any += usize::from(touches);
            c.fp_chars += len - inside;
            if !touches {
                found.false_pos.push(*p);
            }
        } else {
            c.unjudged += 1;
            c.unjudged_chars += len - inside;
        }
    }
    (stats, found)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use piikey::detect::{EntityKind, Span};

    use super::{Cat, Doc, Prf, Stats, score_doc};
    use crate::{
        data::{Gold, merge_parts},
        taxonomy::Taxonomy,
    };

    type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn taxonomy() -> Res<Taxonomy> {
        Taxonomy::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("eval/labels.toml"))
    }

    fn cat(tax: &Taxonomy, name: &str) -> Res<Cat> {
        Ok(tax
            .all()
            .find(|c| tax.name(*c) == name)
            .ok_or(name.to_owned())?)
    }

    fn gold(tax: &Taxonomy, text: &str, parts: &[(&str, &str)]) -> Res<Vec<Gold>> {
        parts
            .iter()
            .map(|(value, category)| {
                let start = text.find(value).ok_or(value.to_string())?;
                Ok(Gold {
                    start,
                    end: start + value.len(),
                    label: (*category).to_owned(),
                    cat: cat(tax, category)?,
                })
            })
            .collect()
    }

    fn span(text: &str, value: &str, kind: EntityKind) -> Res<Span> {
        let start = text.find(value).ok_or(value.to_string())?;
        Ok(Span {
            start,
            end: start + value.len(),
            kind,
        })
    }

    fn doc(tax: &Taxonomy, text: &str, parts: &[(&str, &str)]) -> Res<Doc> {
        Ok(Doc {
            id: "t".into(),
            lang: "en".into(),
            group: String::new(),
            text: text.into(),
            gold: gold(tax, text, parts)?,
        })
    }

    fn all_judged(tax: &Taxonomy) -> Vec<bool> {
        vec![true; tax.cats.len()]
    }

    #[test]
    fn an_exact_match_counts_for_every_criterion() -> Res<()> {
        let tax = taxonomy()?;
        let text = "Mail Jan Jansen today";
        let d = doc(&tax, text, &[("Jan Jansen", "PERSON")])?;
        let spans = [span(text, "Jan Jansen", EntityKind::Person)?];
        let (stats, found) = score_doc(&tax, &all_judged(&tax), &d, &spans);
        let c = &stats.cats[cat(&tax, "PERSON")?.0];
        assert_eq!(
            (c.gold, c.strict, c.gold_cat, c.gold_any, c.gold_full),
            (1, 1, 1, 1, 1)
        );
        assert_eq!((c.pred, c.pred_cat, c.pred_any, c.fp_chars), (1, 1, 1, 0));
        assert_eq!(
            (c.gold_chars, c.covered_chars),
            (9, 9),
            "blanks do not count"
        );
        assert!(found.missed.is_empty() && found.partial.is_empty() && found.false_pos.is_empty());
        Ok(())
    }

    #[test]
    fn a_short_prediction_is_masked_but_leaks()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tax = taxonomy()?;
        let text = "Mail Jan Jansen today";
        let d = doc(&tax, text, &[("Jan Jansen", "PERSON")])?;
        let spans = [span(text, "Jan", EntityKind::Person)?];
        let (stats, found) = score_doc(&tax, &all_judged(&tax), &d, &spans);
        let c = &stats.cats[cat(&tax, "PERSON")?.0];
        assert_eq!(
            (c.strict, c.gold_cat, c.gold_any, c.gold_full),
            (0, 1, 1, 0)
        );
        assert_eq!((c.gold_chars, c.covered_chars), (9, 3));
        assert_eq!(found.partial, vec![0]);
        assert!(found.missed.is_empty());
        assert_eq!(c.fp_chars, 0, "the prediction lies inside the gold span");
        Ok(())
    }

    #[test]
    fn the_wrong_category_still_masks_but_is_not_a_category_match() -> Res<()> {
        let tax = taxonomy()?;
        let text = "id 123456782 ok";
        let d = doc(&tax, text, &[("123456782", "ID_NUMBER")])?;
        let spans = [span(text, "123456782", EntityKind::Phone)?];
        let (stats, found) = score_doc(&tax, &all_judged(&tax), &d, &spans);
        let id = &stats.cats[cat(&tax, "ID_NUMBER")?.0];
        assert_eq!(
            (id.strict, id.gold_cat, id.gold_any, id.gold_full),
            (0, 0, 1, 1)
        );
        let phone = &stats.cats[cat(&tax, "PHONE")?.0];
        assert_eq!((phone.pred, phone.pred_cat, phone.pred_any), (1, 0, 1));
        assert_eq!(found.wrong, vec![(0, cat(&tax, "PHONE")?)]);
        assert!(found.false_pos.is_empty(), "it touches a gold span");
        Ok(())
    }

    #[test]
    fn compatible_categories_match_unless_strict() -> Res<()> {
        let tax = taxonomy()?;
        let text = "lives in Amsterdam now";
        let d = doc(&tax, text, &[("Amsterdam", "LOCATION")])?;
        let spans = [span(text, "Amsterdam", EntityKind::PostalAddress)?];
        let (stats, _) = score_doc(&tax, &all_judged(&tax), &d, &spans);
        let c = &stats.cats[cat(&tax, "LOCATION")?.0];
        assert_eq!((c.strict, c.gold_cat, c.gold_any), (0, 1, 1));
        Ok(())
    }

    #[test]
    fn a_missed_span_leaks_completely_and_a_stray_one_costs_utility() -> Res<()> {
        let tax = taxonomy()?;
        let text = "call 0612345678 or ask Piet Pietersen";
        let d = doc(&tax, text, &[("0612345678", "PHONE")])?;
        let spans = [span(text, "Piet Pietersen", EntityKind::Person)?];
        let (stats, found) = score_doc(&tax, &all_judged(&tax), &d, &spans);
        let phone = &stats.cats[cat(&tax, "PHONE")?.0];
        assert_eq!(
            (phone.gold_any, phone.gold_full, phone.covered_chars),
            (0, 0, 0)
        );
        assert_eq!(found.missed, vec![0]);
        let person = &stats.cats[cat(&tax, "PERSON")?.0];
        assert_eq!((person.pred, person.pred_any, person.fp_chars), (1, 0, 13));
        assert_eq!(found.false_pos.len(), 1);
        let all = stats.sum(|_| true);
        assert_eq!(all.leak(), Some(1.0));
        assert_eq!(stats.chars, "call0612345678oraskPietPietersen".len());
        Ok(())
    }

    #[test]
    fn a_prediction_of_a_category_the_source_does_not_annotate_is_not_judged() -> Res<()> {
        let tax = taxonomy()?;
        let text = "works at Acme Corp";
        let d = doc(&tax, text, &[])?;
        let spans = [span(text, "Acme Corp", EntityKind::OrganizationName)?];
        let mut judged = all_judged(&tax);
        let org = cat(&tax, "ORG")?;
        judged[org.0] = false;
        let (stats, found) = score_doc(&tax, &judged, &d, &spans);
        let c = &stats.cats[org.0];
        assert_eq!(
            (c.pred, c.unjudged, c.fp_chars, c.unjudged_chars),
            (0, 1, 0, 8)
        );
        assert!(found.false_pos.is_empty());
        Ok(())
    }

    #[test]
    fn predictions_that_break_the_contract_are_dropped() -> Res<()> {
        let tax = taxonomy()?;
        let text = "ab Jan Jansen";
        let d = doc(&tax, text, &[])?;
        let spans = [
            span(text, "Jan Jansen", EntityKind::Person)?,
            span(text, "Jansen", EntityKind::Person)?,
            Span {
                start: 3,
                end: 99,
                kind: EntityKind::Person,
            },
        ];
        let (stats, _) = score_doc(&tax, &all_judged(&tax), &d, &spans);
        assert_eq!(stats.dropped, 2);
        assert_eq!(stats.sum(|_| true).pred, 1);
        Ok(())
    }

    #[test]
    fn parts_of_one_entity_join() -> Res<()> {
        let tax = taxonomy()?;
        let text = "Gitta Kriwanek, Keizersgracht 123, 1015 CJ Amsterdam";
        let parts = gold(
            &tax,
            text,
            &[
                ("Gitta", "PERSON"),
                ("Kriwanek", "PERSON"),
                ("Keizersgracht", "ADDRESS"),
                ("123", "ADDRESS"),
                ("1015 CJ", "ADDRESS"),
                ("Amsterdam", "LOCATION"),
            ],
        )?;
        let merged = merge_parts(&tax, text, parts);
        let shown: Vec<&str> = merged.iter().map(|g| &text[g.start..g.end]).collect();
        assert_eq!(
            shown,
            ["Gitta Kriwanek", "Keizersgracht 123, 1015 CJ", "Amsterdam"]
        );
        // A comma separates two people; only an address joins across one.
        let two = gold(&tax, "Jan, Piet", &[("Jan", "PERSON"), ("Piet", "PERSON")])?;
        assert_eq!(merge_parts(&tax, "Jan, Piet", two).len(), 2);
        Ok(())
    }

    #[test]
    fn f1_is_zero_without_predictions_and_undefined_without_gold() {
        let none = Prf { p: None, r: None };
        assert_eq!(none.f1(), None);
        assert_eq!(
            Prf {
                p: Some(1.0),
                r: None
            }
            .f1(),
            None,
            "no gold: nothing to recall"
        );
        assert_eq!(
            Prf {
                p: None,
                r: Some(0.0)
            }
            .f1(),
            Some(0.0)
        );
        assert_eq!(
            Prf {
                p: Some(0.5),
                r: Some(1.0)
            }
            .f1()
            .map(|v| (v * 1000.0).round()),
            Some(667.0)
        );
        assert_eq!(Stats::new(3).fp_rate(), None);
    }
}
