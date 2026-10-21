//! The report as JSON, for tools.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{Report, Run, cell, device_name, mb, verdict::PUBLISHED};
use crate::{
    bench::Choice,
    data::Source,
    roundtrip::RoundTrip,
    score::{CatStats, Example, Prf, Stats, f},
    taxonomy::Cat,
};

fn ratio_json(v: Option<f64>) -> Value {
    v.map_or(Value::Null, |x| json!(x))
}

fn prf_json(p: Prf) -> Value {
    json!({ "precision": ratio_json(p.p), "recall": ratio_json(p.r), "f1": ratio_json(p.f1()) })
}

fn cat_json(s: &CatStats) -> Value {
    json!({
        "gold": s.gold,
        "predicted": s.pred,
        "unjudged_predictions": s.unjudged,
        "strict": prf_json(s.strict()),
        "overlap": prf_json(s.overlap()),
        "any_category": prf_json(s.any()),
        "leakage": ratio_json(s.leak()),
        "fully_masked": ratio_json(s.full()),
        "counts": {
            "strict_matches": s.strict,
            "gold_overlapped_with_category": s.gold_cat,
            "gold_overlapped_any": s.gold_any,
            "gold_fully_covered": s.gold_full,
            "gold_chars": s.gold_chars,
            "gold_chars_covered": s.covered_chars,
            "pred_overlapping_gold_with_category": s.pred_cat,
            "pred_overlapping_gold_any": s.pred_any,
            "false_positive_chars": s.fp_chars,
            "unjudged_chars": s.unjudged_chars,
        },
    })
}

impl Report<'_> {
    fn stats_json(&self, s: &Stats) -> Value {
        let mut cats = serde_json::Map::new();
        for c in self.tax.all() {
            let cs = &s.cats[c.0];
            if cs.gold + cs.pred + cs.unjudged > 0 {
                cats.insert(self.tax.name(c).to_owned(), cat_json(cs));
            }
        }
        json!({
            "docs": s.docs,
            "chars": s.chars,
            "dropped_predictions": s.dropped,
            "false_positive_rate": ratio_json(s.fp_rate()),
            "unjudged_rate": ratio_json(s.unjudged_rate()),
            "all_supported": cat_json(&s.sum(|c| self.tax.supported(c))),
            "all": cat_json(&s.sum(|_| true)),
            "categories": cats,
        })
    }

    /// An example with its value and a window of the text around it.
    fn example_json(&self, source: &Source, e: &Example) -> Value {
        let doc = &source.docs[e.doc];
        let before: String = {
            let mut chars: Vec<char> = doc.text[..e.start].chars().rev().take(40).collect();
            chars.reverse();
            chars.into_iter().collect()
        };
        let after: String = doc.text[e.end..].chars().take(40).collect();
        let shown = cell(super::value(source, e), 200);
        json!({
            "doc": doc.id,
            "lang": doc.lang,
            "category": self.tax.name(e.cat),
            "tag": e.tag,
            "value": shown,
            "context": format!("{before}[[{shown}]]{after}"),
            "masked_as": e.other.map(|c| self.tax.name(c)),
        })
    }

    fn run_json(&self, run: &Run) -> Value {
        let keep = self.json_examples;
        let source = self.source(run);
        let fail = &run.agg.failures;
        let list = |v: &[Example]| -> Vec<Value> {
            v.iter()
                .take(keep)
                .map(|e| self.example_json(source, e))
                .collect()
        };
        let confusion: Vec<Value> = fail
            .confusion
            .iter()
            .map(|((gold, got), n)| {
                json!({ "gold": self.tax.name(*gold), "covered_mostly_by": got.map(|c| self.tax.name(c)), "spans": n })
            })
            .collect();
        let s = &run.speed;
        json!({
            "configuration": run.config.name(),
            "corpus": source.name,
            "scores": self.stats_json(&run.agg.total),
            "by_language": run.agg.by_lang.iter().map(|(l, st)| (l.clone(), self.stats_json(st))).collect::<BTreeMap<_, _>>(),
            "by_document_kind": run.agg.by_group.iter().map(|(g, st)| (g.clone(), self.stats_json(st))).collect::<BTreeMap<_, _>>(),
            "failures": {
                "counts": {
                    "missed": fail.missed.len(),
                    "partial": fail.partial.len(),
                    "wrong_category": fail.wrong.len(),
                    "false_positive": fail.false_pos.len(),
                },
                "missed": list(&fail.missed),
                "partial": list(&fail.partial),
                "wrong_category": list(&fail.wrong),
                "false_positive": list(&fail.false_pos),
                "confusion": confusion,
            },
            "speed": {
                "docs": s.docs,
                "bytes": s.bytes,
                "cold_seconds": s.cold_secs,
                "cold_docs_per_second": ratio_json((s.cold_secs > 0.0).then(|| f(s.docs) / s.cold_secs)),
                "cold_mb_per_second": ratio_json((s.cold_secs > 0.0).then(|| mb(s.bytes) / s.cold_secs)),
                "warm_seconds": s.warm_secs,
                "warm_docs_per_second": ratio_json(s.warm_secs.filter(|w| *w > 0.0).map(|w| f(s.docs) / w)),
                "warm_same_spans": s.warm_same,
                "latency_ms": s.latency.as_ref().map(|l| json!({
                    "docs": l.docs, "p50": l.p50_ms, "p95": l.p95_ms, "max": l.max_ms, "mean_bytes": l.mean_bytes,
                })),
                "reloads": { "count": s.reloads.count, "seconds": s.reloads.secs },
            },
            "round_trip": run.roundtrip.as_ref().map(|rt| self.round_trip_json(rt)),
        })
    }

    fn round_trip_json(&self, rt: &RoundTrip) -> Value {
        let by_cat = |m: &BTreeMap<Cat, usize>| -> BTreeMap<String, usize> {
            m.iter()
                .map(|(c, n)| (self.tax.name(*c).to_owned(), *n))
                .collect()
        };
        json!({
            "docs": rt.docs,
            "changed_by_anonymize": rt.changed,
            "exact": rt.exact,
            "exact_of_changed": rt.exact_changed,
            "engine_errors": rt.errors,
            "engine_error_messages": rt.error_messages,
            "docs_with_gold_value_left": rt.survivor_docs,
            "gold_values_checked": by_cat(&rt.checked),
            "gold_values_left": by_cat(&rt.survived),
            "did_not_restore": rt.mismatches.iter().take(self.json_examples).map(|m| json!({
                "doc": m.doc, "original": m.original, "restored": m.restored, "trace": m.trace,
            })).collect::<Vec<_>>(),
            "left_verbatim": rt.survivors.iter().take(self.json_examples).map(|s| json!({
                "doc": s.doc, "category": self.tax.name(s.cat), "value": cell(&s.value, 200),
            })).collect::<Vec<_>>(),
        })
    }

    /// The whole report as JSON.
    #[must_use]
    pub fn json(&self) -> Value {
        let m = &self.meta;
        let categories: Vec<Value> = self
            .tax
            .cats
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "about": c.about,
                    "piikey_kinds": c.kinds.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect();
        let sources: Vec<Value> = self
            .sources
            .iter()
            .map(|s| {
                let labels: BTreeMap<&str, Value> = s
                    .labels
                    .iter()
                    .map(|(l, (c, n))| {
                        (
                            l.as_str(),
                            json!({ "category": self.tax.name(*c), "spans": n, "piikey_counterpart": self.tax.supported(*c) }),
                        )
                    })
                    .collect();
                let note = m.notes.get(&s.name);
                json!({
                    "name": s.name,
                    "docs": s.docs.len(),
                    "bytes": s.bytes,
                    "gold_spans_after_merging": s.gold_spans(),
                    "parts_merged": s.merged,
                    "exhaustive": s.exhaustive,
                    "fingerprint": s.fingerprint,
                    "license": note.map(|n| n.license.as_str()),
                    "note": note.map(|n| n.note.as_str()),
                    "origin": note.map(|n| n.origin.as_str()),
                    "labels": labels,
                })
            })
            .collect();
        json!({
            "meta": {
                "timestamp": m.timestamp,
                "piikey": m.piikey,
                "machine": m.machine,
                "configurations": m.configs,
                "batch": m.batch,
                "latency_docs": m.latency_docs,
                "roundtrip_docs": m.roundtrip_docs,
                "wall_seconds": m.wall_secs,
                "model": m.model.as_ref().map(|i| json!({
                    "id": i.id,
                    "dir": i.dir,
                    "device": device_name(i.device),
                    "first_load_seconds": i.first_load_secs,
                    "calibrated_on_first_load": i.calibrated,
                    "device_choice": match i.choice {
                        Choice::Saved => "saved",
                        Choice::Forced(_) => "forced",
                        Choice::Measure => "re-measured",
                    },
                })),
            },
            "taxonomy": categories,
            "corpora": sources,
            "runs": self.runs.iter().map(|r| self.run_json(r)).collect::<Vec<_>>(),
            "published": PUBLISHED.iter().map(|(s, me, n, d)| json!({
                "source": s, "measure": me, "number": n, "data": d,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error, path::Path};

    use super::super::{Meta, Report};
    use crate::{
        roundtrip::{RoundTrip, Survivor},
        taxonomy::Taxonomy,
    };

    #[test]
    fn the_round_trip_lists_keep_as_many_examples_as_asked()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let tax = Taxonomy::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("eval/labels.toml"))?;
        let cat = tax
            .all()
            .next()
            .ok_or("the label table has no categories")?;
        let rt = RoundTrip {
            survivors: (0..5)
                .map(|i| Survivor {
                    doc: format!("d{i}"),
                    cat,
                    value: "value".to_owned(),
                })
                .collect(),
            ..RoundTrip::default()
        };
        let meta = Meta {
            timestamp: String::new(),
            piikey: String::new(),
            machine: String::new(),
            model: None,
            configs: Vec::new(),
            batch: 1,
            latency_docs: 0,
            roundtrip_docs: 0,
            wall_secs: 0.0,
            notes: BTreeMap::new(),
        };
        let report = Report {
            meta,
            tax: &tax,
            sources: &[],
            runs: Vec::new(),
            examples: 3,
            json_examples: 2,
        };
        let json = report.round_trip_json(&rt);
        assert_eq!(json["left_verbatim"].as_array().map(Vec::len), Some(2));
        Ok(())
    }
}
