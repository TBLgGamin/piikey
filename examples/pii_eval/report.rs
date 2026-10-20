//! The report: Markdown for people, JSON for tools.

use std::{collections::BTreeMap, fmt::Write as _};

use piikey::detect::ner::Device;
use serde_json::{Value, json};

use crate::{
    bench::{Choice, Config, Speed},
    data::Source,
    roundtrip::RoundTrip,
    score::{Agg, CatStats, Example, Prf, Stats, f, ratio},
    taxonomy::{Cat, Taxonomy},
};

/// Appends formatted text to a `String`. Writing to a `String` cannot fail.
macro_rules! put {
    ($out:expr, $($arg:tt)*) => {{
        let _ = write!($out, $($arg)*);
    }};
}

/// One detector configuration run over one corpus.
#[derive(Debug)]
pub struct Run {
    pub config: Config,
    /// Index into [`Report::sources`].
    pub source: usize,
    pub agg: Agg,
    pub speed: Speed,
    pub roundtrip: Option<RoundTrip>,
}

/// The detection model as this run used it.
#[derive(Debug)]
pub struct ModelInfo {
    pub id: &'static str,
    pub dir: String,
    pub device: Device,
    pub choice: Choice,
    pub first_load_secs: f64,
    pub calibrated: bool,
}

/// Where a corpus came from.
#[derive(Debug)]
pub struct SourceNote {
    pub license: String,
    pub note: String,
    /// Dataset, revision, fetch date and seed; empty for a corpus kept in this repository.
    pub origin: String,
}

/// What the run was.
#[derive(Debug)]
pub struct Meta {
    pub timestamp: String,
    pub piikey: String,
    pub machine: String,
    pub model: Option<ModelInfo>,
    pub configs: Vec<String>,
    pub batch: usize,
    pub latency_docs: usize,
    pub roundtrip_docs: usize,
    pub wall_secs: f64,
    pub notes: BTreeMap<String, SourceNote>,
}

/// Everything a run produced.
#[derive(Debug)]
pub struct Report<'a> {
    pub meta: Meta,
    pub tax: &'a Taxonomy,
    pub sources: &'a [Source],
    pub runs: Vec<Run>,
    /// Examples shown per failure list in the Markdown.
    pub examples: usize,
    /// Examples of each failure list written to the JSON.
    pub json_examples: usize,
}

/// How a device is named in the report. The names come from the `Debug` form of the device, so a
/// device the benchmark does not know yet still shows up under its own name.
#[must_use]
pub fn device_name(device: Device) -> String {
    match format!("{device:?}").as_str() {
        "Cpu" => "CPU".to_owned(),
        "Gpu" => "GPU (DirectML)".to_owned(),
        "Hybrid" => "hybrid (CPU, the GPU for large calls)".to_owned(),
        other => other.to_owned(),
    }
}

/// Bytes as megabytes (10^6).
#[must_use]
pub fn mb(bytes: usize) -> f64 {
    f(bytes) / 1e6
}

// --- formatting --------------------------------------------------------------------------------

/// `1234567` as `1,234,567`.
fn num(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn dec(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_owned(), |x| format!("{x:.3}"))
}

fn pct(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_owned(), |x| format!("{:.1}%", x * 100.0))
}

/// `P/R/F1` of one criterion.
fn prf(p: Prf) -> String {
    format!("{}/{}/{}", dec(p.p), dec(p.r), dec(p.f1()))
}

/// Per-second rate with about three significant digits, or `-` for a measurement that took no time.
fn rate(count: f64, secs: f64) -> String {
    if secs <= 0.0 {
        return "-".to_owned();
    }
    let v = count / secs;
    if v >= 100.0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{v:.1}")
    } else if v >= 1.0 {
        format!("{v:.2}")
    } else {
        format!("{v:.3}")
    }
}

/// Milliseconds with a precision that fits their size.
fn ms(v: f64) -> String {
    if v >= 10.0 {
        format!("{v:.1}")
    } else if v >= 0.1 {
        format!("{v:.2}")
    } else {
        format!("{v:.3}")
    }
}

/// What a value looks like: a template field, one word, a number, an identifier-like code or a
/// phrase. It tells apart the misses that are about the text (a name in a sentence) from the ones
/// that are about the corpus (a template field `[Phone Number]` labelled as a phone number).
fn shape(value: &str) -> &'static str {
    let v = value.trim();
    let fielded = [('[', ']'), ('<', '>'), ('{', '}')]
        .iter()
        .any(|&(open, close)| v.starts_with(open) && v.ends_with(close));
    if fielded {
        return "template field";
    }
    let words = v.split_whitespace().count();
    let digits = v.chars().any(|c| c.is_ascii_digit());
    let letters = v.chars().any(char::is_alphabetic);
    match (words, digits, letters) {
        (_, true, false) => "number",
        (1, false, _) => "one word",
        (1, true, true) => "code",
        _ => "phrase",
    }
}

/// `value` made safe for a Markdown table cell, cut to `max` characters.
fn cell(value: &str, max: usize) -> String {
    let mut out: String = value
        .chars()
        .take(max)
        .map(|c| match c {
            '\n' | '\r' => '⏎',
            '|' => '¦',
            '`' => '\'',
            c => c,
        })
        .collect();
    if value.chars().count() > max {
        out.push('…');
    }
    out
}

/// A Markdown table with padded columns.
struct Table {
    head: Vec<String>,
    right: Vec<bool>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Columns as `(header, right-aligned)`.
    fn new(cols: &[(&str, bool)]) -> Self {
        Self {
            head: cols.iter().map(|c| c.0.to_owned()).collect(),
            right: cols.iter().map(|c| c.1).collect(),
            rows: Vec::new(),
        }
    }

    fn row<I: IntoIterator<Item = String>>(&mut self, cells: I) {
        self.rows.push(cells.into_iter().collect());
    }

    fn render(&self) -> String {
        let width = |i: usize| {
            self.rows
                .iter()
                .map(|r| r.get(i).map_or(0, |c| c.chars().count()))
                .chain([self.head[i].chars().count(), 3])
                .max()
                .unwrap_or(3)
        };
        let widths: Vec<usize> = (0..self.head.len()).map(width).collect();
        let line = |cells: &[String]| {
            let mut out = String::from("|");
            for (i, w) in widths.iter().enumerate() {
                let text = cells.get(i).map_or("", String::as_str);
                let pad = w - text.chars().count();
                if self.right[i] {
                    put!(out, " {}{text} |", " ".repeat(pad));
                } else {
                    put!(out, " {text}{} |", " ".repeat(pad));
                }
            }
            out.push('\n');
            out
        };
        let mut out = line(&self.head);
        out.push('|');
        for (i, w) in widths.iter().enumerate() {
            let dashes = "-".repeat(w + 1);
            put!(out, "{dashes}{}|", if self.right[i] { ':' } else { '-' });
        }
        out.push('\n');
        for row in &self.rows {
            out.push_str(&line(row));
        }
        out
    }
}

// --- the report ----------------------------------------------------------------------------------

impl Report<'_> {
    fn source(&self, run: &Run) -> &Source {
        &self.sources[run.source]
    }

    fn title(&self, run: &Run) -> String {
        format!("{} on {}", run.config.name(), self.source(run).name)
    }

    /// The reloads between measurements, over all runs: total seconds and count.
    fn reloads(&self) -> (f64, usize) {
        self.runs.iter().fold((0.0, 0), |(secs, n), r| {
            (secs + r.speed.reloads.secs, n + r.speed.reloads.count)
        })
    }

    /// The model, its device, and what loading it cost.
    fn model_text(&self, i: &ModelInfo) -> String {
        let how = match (i.choice, i.calibrated) {
            (Choice::Forced(_), _) => "the device was forced for this run",
            (_, true) => "the first load included the GPU/CPU calibration",
            (_, false) => "the device was saved by an earlier load",
        };
        let (secs, count) = self.reloads();
        let later = if count > 0 {
            format!(
                ", later loads {:.1} s on average (n={count})",
                secs / f(count)
            )
        } else {
            String::new()
        };
        format!(
            "{} on {}; first load {:.1} s ({how}){later}",
            i.id,
            device_name(i.device),
            i.first_load_secs
        )
    }

    /// The whole report as Markdown.
    #[must_use]
    pub fn markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.setup());
        out.push_str(&self.corpora());
        out.push_str(&self.coverage());
        out.push_str(&self.headline());
        out.push_str(&self.leakage());
        out.push_str("\n## Details per configuration and corpus\n");
        for run in &self.runs {
            out.push_str(&self.details(run));
        }
        out.push_str(&self.round_trips());
        out.push_str(&self.speeds());
        out.push_str(&self.verdict());
        out
    }

    fn setup(&self) -> String {
        let m = &self.meta;
        let mut t = Table::new(&[("", false), ("", false)]);
        t.row(["Run".to_owned(), m.timestamp.clone()]);
        t.row(["piikey".to_owned(), m.piikey.clone()]);
        t.row(["Machine".to_owned(), m.machine.clone()]);
        t.row(["Configurations".to_owned(), m.configs.join(", ")]);
        t.row([
            "Detection model".to_owned(),
            m.model
                .as_ref()
                .map_or_else(|| "not loaded".to_owned(), |i| self.model_text(i)),
        ]);
        t.row([
            "Measuring".to_owned(),
            format!(
                "{} documents per call; {} single-document timings and {} engine round trips per corpus",
                m.batch, m.latency_docs, m.roundtrip_docs
            ),
        ]);
        t.row(["Wall time".to_owned(), format!("{:.0} s", m.wall_secs)]);
        format!("# piikey detection benchmark\n\n{}", t.render())
    }

    fn corpora(&self) -> String {
        let mut t = Table::new(&[
            ("corpus", false),
            ("docs", true),
            ("MB", true),
            ("gold spans", true),
            ("languages", false),
            ("judged", false),
            ("data", false),
        ]); // fmt: skip
        for s in self.sources {
            let mut langs: BTreeMap<&str, usize> = BTreeMap::new();
            for d in &s.docs {
                *langs.entry(d.lang.as_str()).or_insert(0) += 1;
            }
            let mut langs: Vec<(&str, usize)> = langs.into_iter().collect();
            langs.sort_by_key(|&(l, n)| (std::cmp::Reverse(n), l));
            let shown: Vec<String> = langs
                .iter()
                .take(6)
                .map(|(l, n)| format!("{l} {n}"))
                .collect();
            let more = if langs.len() > 6 {
                format!(" +{} more", langs.len() - 6)
            } else {
                String::new()
            };
            let note = self.meta.notes.get(&s.name);
            t.row([
                s.name.clone(),
                num(s.docs.len()),
                format!("{:.2}", mb(s.bytes)),
                format!("{} ({} parts merged)", num(s.gold_spans()), num(s.merged)),
                format!("{}{more}", shown.join(", ")),
                if s.exhaustive {
                    "everything"
                } else {
                    "own labels only"
                }
                .to_owned(),
                note.map_or_else(String::new, |n| {
                    [
                        n.license.as_str(),
                        n.note.as_str(),
                        n.origin.as_str(),
                        &format!("sha {}", s.fingerprint),
                    ]
                    .iter()
                    .filter(|part| !part.is_empty())
                    .map(|part| cell(part, 160))
                    .collect::<Vec<_>>()
                    .join("; ")
                }),
            ]);
        }
        format!("\n## Corpora\n\n{}", t.render())
    }

    /// Source labels grouped by category, and what piikey has for each category.
    fn coverage(&self) -> String {
        let mut out = String::from(
            "\n## Label coverage\n\nHow each corpus's labels fold into the shared categories, and \
             which piikey kinds can produce them. `*` marks a category piikey has no kind for: the \
             gold spans are reported, never silently dropped, and left out of the `supported` rows.\n",
        );
        for s in self.sources {
            let mut t = Table::new(&[
                ("category", false),
                ("corpus labels (spans)", false),
                ("piikey kinds", false),
            ]);
            for c in self.tax.all() {
                let labels: Vec<String> = s
                    .labels
                    .iter()
                    .filter(|(_, (cat, _))| *cat == c)
                    .map(|(l, (_, n))| format!("{l} ({})", num(*n)))
                    .collect();
                if labels.is_empty() {
                    continue;
                }
                let kinds: Vec<&str> = self.tax.cats[c.0]
                    .kinds
                    .iter()
                    .map(|k| k.as_str())
                    .collect();
                let mark = if self.tax.supported(c) { "" } else { "*" };
                t.row([
                    format!("{}{mark}", self.tax.name(c)),
                    labels.join(", "),
                    if kinds.is_empty() {
                        "none".to_owned()
                    } else {
                        kinds.join(", ")
                    },
                ]);
            }
            let silent: Vec<&str> = self
                .tax
                .all()
                .filter(|c| !s.labels.values().any(|(cat, _)| cat == c))
                .map(|c| self.tax.name(c))
                .collect();
            put!(out, "\n### {}\n\n{}", s.name, t.render());
            if !silent.is_empty() && !s.exhaustive {
                put!(
                    out,
                    "\nNot annotated by this corpus (a prediction in these categories is not judged): {}.\n",
                    silent.join(", ")
                );
            }
        }
        out
    }

    /// One row per run: the numbers that matter most.
    fn headline(&self) -> String {
        let mut t = Table::new(&[
            ("configuration", false),
            ("corpus", false),
            ("gold", true),
            ("strict F1", true),
            ("overlap F1", true),
            ("any-cat F1", true),
            ("any-cat recall", true),
            ("leak", true),
            ("fully masked", true),
            ("FP masked", true),
        ]); // fmt: skip
        for run in &self.runs {
            let s = run.agg.total.sum(|c| self.tax.supported(c));
            t.row([
                run.config.name().to_owned(),
                self.source(run).name.clone(),
                num(s.gold),
                dec(s.strict().f1()),
                dec(s.overlap().f1()),
                dec(s.any().f1()),
                dec(s.any().r),
                pct(s.leak()),
                pct(s.full()),
                pct(run.agg.total.fp_rate()),
            ]);
        }
        format!(
            "\n## Headline\n\nGold spans of the categories piikey can produce (`ALL supported`). \
             *strict*: same span and category. *overlap*: shared characters and the same (or a \
             compatible) category. *any-cat*: shared characters, whatever the category: its recall is \
             \"was it masked at all\". *leak*: share of gold characters no prediction covers. *fully \
             masked*: share of gold spans covered completely. *FP masked*: share of non-PII \
             characters masked, over the predictions this corpus can judge.\n\n{}",
            t.render()
        )
    }

    /// Leakage per category for each configuration, one column per corpus.
    fn leakage(&self) -> String {
        let mut out = String::from(
            "\n## Leakage by category\n\nShare of the gold characters of a category that no prediction \
             covers (lower is better; `-`: no gold spans). The number to watch for privacy.\n",
        );
        for config in Config::ALL {
            let runs: Vec<&Run> = self.runs.iter().filter(|r| r.config == config).collect();
            if runs.is_empty() {
                continue;
            }
            let mut cols: Vec<(&str, bool)> = vec![("category", false)];
            cols.extend(runs.iter().map(|r| (self.source(r).name.as_str(), true)));
            let mut t = Table::new(&cols);
            for c in self.tax.all() {
                if runs.iter().all(|r| r.agg.total.cats[c.0].gold == 0) {
                    continue;
                }
                let mark = if self.tax.supported(c) { "" } else { "*" };
                let mut row = vec![format!("{}{mark}", self.tax.name(c))];
                row.extend(runs.iter().map(|r| {
                    let s = &r.agg.total.cats[c.0];
                    if s.gold == 0 {
                        "-".to_owned()
                    } else {
                        format!("{} (n={})", pct(s.leak()), num(s.gold))
                    }
                }));
                t.row(row);
            }
            let mut row = vec!["ALL supported".to_owned()];
            row.extend(
                runs.iter()
                    .map(|r| pct(r.agg.total.sum(|c| self.tax.supported(c)).leak())),
            );
            t.row(row);
            put!(out, "\n### {}\n\n{}", config.name(), t.render());
        }
        out
    }

    fn details(&self, run: &Run) -> String {
        let source = self.source(run);
        let stats = &run.agg.total;
        let mut out = format!("\n### {}\n\n", self.title(run));
        out.push_str(&self.category_table(stats));
        let unjudged: Vec<String> = self
            .tax
            .all()
            .filter(|c| stats.cats[c.0].unjudged > 0)
            .map(|c| format!("{} {}", self.tax.name(c), num(stats.cats[c.0].unjudged)))
            .collect();
        put!(
            out,
            "\nFalse-positive masking: {} of the characters outside every gold span.",
            pct(stats.fp_rate())
        );
        if !unjudged.is_empty() {
            put!(
                out,
                " Predictions in categories this corpus does not annotate, not judged: {} ({} of the non-gold characters).",
                unjudged.join(", "),
                pct(stats.unjudged_rate())
            );
        }
        if stats.dropped > 0 {
            put!(
                out,
                " {} predictions broke the detector contract (overlap or out of range) and were dropped.",
                num(stats.dropped)
            );
        }
        out.push_str("\n\n");
        out.push_str(&self.language_table(run));
        if run.agg.by_group.len() > 1 {
            out.push_str(&self.group_table(run));
        }
        out.push_str(&self.failures(run, source));
        out
    }

    fn category_table(&self, stats: &Stats) -> String {
        let mut t = Table::new(&[
            ("category", false),
            ("gold", true),
            ("pred", true),
            ("strict P/R/F1", true),
            ("overlap P/R/F1", true),
            ("any-cat P/R/F1", true),
            ("leak", true),
            ("fully masked", true),
        ]); // fmt: skip
        let row = |name: String, s: &CatStats| {
            [
                name,
                num(s.gold),
                num(s.pred),
                prf(s.strict()),
                prf(s.overlap()),
                prf(s.any()),
                pct(s.leak()),
                pct(s.full()),
            ]
        };
        for c in self.tax.all() {
            let s = &stats.cats[c.0];
            if s.gold == 0 && s.pred == 0 {
                continue;
            }
            let mark = if self.tax.supported(c) { "" } else { "*" };
            t.row(row(format!("{}{mark}", self.tax.name(c)), s));
        }
        let supported = stats.sum(|c| self.tax.supported(c));
        t.row(row("ALL supported".to_owned(), &supported));
        let all = stats.sum(|_| true);
        if all.gold != supported.gold {
            t.row(row("ALL".to_owned(), &all));
        }
        t.render()
    }

    fn language_table(&self, run: &Run) -> String {
        let mut rows: Vec<(&String, &Stats)> = run.agg.by_lang.iter().collect();
        if rows.len() < 2 {
            return String::new();
        }
        rows.sort_by_key(|(lang, s)| (std::cmp::Reverse(s.docs), (*lang).clone()));
        let mut t = Table::new(&[
            ("language", false),
            ("docs", true),
            ("gold", true),
            ("overlap F1", true),
            ("any-cat recall", true),
            ("leak", true),
            ("FP masked", true),
        ]); // fmt: skip
        for (lang, s) in rows {
            let sup = s.sum(|c| self.tax.supported(c));
            t.row([
                lang.clone(),
                num(s.docs),
                num(sup.gold),
                dec(sup.overlap().f1()),
                dec(sup.any().r),
                pct(sup.leak()),
                pct(s.fp_rate()),
            ]);
        }
        format!("By language:\n\n{}\n", t.render())
    }

    /// The document kinds with the most gold, worst leakage first among them.
    fn group_table(&self, run: &Run) -> String {
        let mut rows: Vec<(&String, CatStats, &Stats)> = run
            .agg
            .by_group
            .iter()
            .map(|(g, s)| (g, s.sum(|c| self.tax.supported(c)), s))
            .filter(|(_, sup, _)| sup.gold >= 20)
            .collect();
        rows.sort_by(|a, b| {
            b.1.leak()
                .partial_cmp(&a.1.leak())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(b.0))
        });
        if rows.is_empty() {
            return String::new();
        }
        let mut t = Table::new(&[
            ("document kind", false),
            ("docs", true),
            ("gold", true),
            ("overlap F1", true),
            ("leak", true),
            ("FP masked", true),
        ]); // fmt: skip
        for (group, sup, s) in rows.iter().take(8) {
            t.row([
                cell(group, 40),
                num(s.docs),
                num(sup.gold),
                dec(sup.overlap().f1()),
                pct(sup.leak()),
                pct(s.fp_rate()),
            ]);
        }
        format!(
            "Document kinds with the worst leakage (at least 20 gold spans):\n\n{}\n",
            t.render()
        )
    }

    /// Where it fails: what is missed, what is masked as the wrong thing, and what is masked
    /// that should not be.
    fn failures(&self, run: &Run, source: &Source) -> String {
        let fail = &run.agg.failures;
        let k = self.examples;
        let mut out = String::new();

        let mut t = Table::new(&[
            ("gold category", false),
            ("missed", true),
            ("partial", true),
            ("masked as another category", true),
            ("examples missed", false),
        ]); // fmt: skip
        for c in self.tax.all().filter(|c| self.tax.supported(*c)) {
            let (missed, partial, wrong) = (
                of_cat(&fail.missed, c),
                of_cat(&fail.partial, c),
                of_cat(&fail.wrong, c),
            );
            if missed.len() + partial.len() + wrong.len() == 0 {
                continue;
            }
            t.row([
                self.tax.name(c).to_owned(),
                num(missed.len()),
                num(partial.len()),
                num(wrong.len()),
                top_values(source, &missed, k),
            ]);
        }
        if !t.rows.is_empty() {
            put!(
                out,
                "Gold spans of supported categories that leak: *missed* (no prediction touches them), \
                 *partial* (touched, not covered completely), *another category* (masked, but only by \
                 a prediction of an incompatible category):\n\n{}\n",
                t.render()
            );
        }
        out.push_str(&self.shapes(run, source));

        let mut by_kind: BTreeMap<&str, Vec<&Example>> = BTreeMap::new();
        for e in &fail.false_pos {
            by_kind.entry(e.tag.as_str()).or_default().push(e);
        }
        let mut kinds: Vec<(&str, Vec<&Example>)> = by_kind.into_iter().collect();
        kinds.sort_by_key(|(name, v)| (std::cmp::Reverse(v.len()), *name));
        if !kinds.is_empty() {
            let mut t = Table::new(&[
                ("predicted kind", false),
                ("false positives", true),
                ("examples", false),
            ]);
            for (name, list) in kinds.iter().take(8) {
                t.row([
                    (*name).to_owned(),
                    num(list.len()),
                    top_values(source, list, k),
                ]);
            }
            put!(
                out,
                "Masked although no gold span is there (over the categories this corpus annotates):\n\n{}\n",
                t.render()
            );
        }

        let mut pairs: Vec<(&(Cat, Option<Cat>), &usize)> = fail
            .confusion
            .iter()
            .filter(|((gold, got), _)| got.is_none_or(|g| g != *gold))
            .filter(|((gold, _), _)| self.tax.supported(*gold))
            .collect();
        pairs.sort_by_key(|(pair, n)| (std::cmp::Reverse(**n), **pair));
        if !pairs.is_empty() {
            let mut t = Table::new(&[
                ("gold", false),
                ("covered mostly by", false),
                ("spans", true),
            ]);
            for ((gold, got), n) in pairs.iter().take(8) {
                t.row([
                    self.tax.name(*gold).to_owned(),
                    got.map_or("nothing".to_owned(), |c| self.tax.name(c).to_owned()),
                    num(**n),
                ]);
            }
            put!(out, "Most common confusions:\n\n{}\n", t.render());
        }
        out
    }

    fn round_trips(&self) -> String {
        let runs: Vec<&Run> = self.runs.iter().filter(|r| r.roundtrip.is_some()).collect();
        if runs.is_empty() {
            return String::new();
        }
        let mut t = Table::new(&[
            ("configuration", false),
            ("corpus", false),
            ("docs", true),
            ("changed", true),
            ("exact round trip", true),
            ("exact, changed only", true),
            ("engine errors", true),
            ("docs with a gold value left", true),
            ("gold values left", true),
        ]); // fmt: skip
        let mut notes = String::new();
        for run in &runs {
            let Some(rt) = &run.roundtrip else { continue };
            let checked: usize = rt.checked.values().sum();
            let left: usize = rt.survived.values().sum();
            t.row([
                run.config.name().to_owned(),
                self.source(run).name.clone(),
                num(rt.docs),
                num(rt.changed),
                pct(ratio(rt.exact, rt.docs)),
                pct(ratio(rt.exact_changed, rt.changed)),
                num(rt.errors),
                format!(
                    "{} ({})",
                    num(rt.survivor_docs),
                    pct(ratio(rt.survivor_docs, rt.docs))
                ),
                format!(
                    "{} of {} ({})",
                    num(left),
                    num(checked),
                    pct(ratio(left, checked))
                ),
            ]);
            notes.push_str(&self.round_trip_notes(run, rt));
        }
        format!(
            "\n## Engine round trip\n\nA sample of each corpus through the real `Engine`: anonymize, then \
             deanonymize, on a throw-away vault. *exact*: the restored text equals the original byte for \
             byte. *gold value left*: a labelled value of a category piikey can produce, at least 3 \
             characters long, still appears as a whole token in the anonymized text (checked by string, \
             so a value masked in one place and not in another counts).\n\n{}{notes}",
            t.render()
        )
    }

    fn round_trip_notes(&self, run: &Run, rt: &RoundTrip) -> String {
        let mut out = String::new();
        let left: Vec<String> = rt
            .survived
            .iter()
            .map(|(c, n)| {
                format!(
                    "{} {}/{}",
                    self.tax.name(*c),
                    num(*n),
                    num(rt.checked.get(c).copied().unwrap_or(0))
                )
            })
            .collect();
        if !left.is_empty() {
            put!(
                out,
                "\n{} - gold values left, by category: {}.",
                self.title(run),
                left.join(", ")
            );
            let shown: Vec<String> = rt
                .survivors
                .iter()
                .take(self.examples)
                .map(|s| format!("`{}` ({})", cell(&s.value, 40), self.tax.name(s.cat)))
                .collect();
            put!(out, " For example {}.\n", shown.join(", "));
        }
        for m in rt.mismatches.iter().take(self.examples) {
            put!(
                out,
                "\n{} - did not restore ({}): `{}` came back as `{}`\n",
                self.title(run),
                m.doc,
                cell(&m.original, 90),
                cell(&m.restored, 90)
            );
            for line in &m.trace {
                put!(out, "  - {}\n", cell(line, 160));
            }
        }
        for e in &rt.error_messages {
            put!(
                out,
                "\n{} - engine error: {}\n",
                self.title(run),
                cell(e, 160)
            );
        }
        out
    }

    fn speeds(&self) -> String {
        let mut t = Table::new(&[
            ("configuration", false),
            ("corpus", false),
            ("docs", true),
            ("MB", true),
            ("cold docs/s", true),
            ("cold MB/s", true),
            ("warm docs/s", true),
            ("warm MB/s", true),
            ("single doc p50 / p95 / max ms", true),
        ]); // fmt: skip
        for run in &self.runs {
            let s = &run.speed;
            let docs = f(s.docs);
            let megabytes = mb(s.bytes);
            t.row([
                run.config.name().to_owned(),
                self.source(run).name.clone(),
                num(s.docs),
                format!("{megabytes:.2}"),
                rate(docs, s.cold_secs),
                rate(megabytes, s.cold_secs),
                s.warm_secs
                    .map_or_else(|| "-".to_owned(), |w| rate(docs, w)),
                s.warm_secs
                    .map_or_else(|| "-".to_owned(), |w| rate(megabytes, w)),
                s.latency.as_ref().map_or_else(
                    || "-".to_owned(),
                    |l| {
                        format!(
                            "{} / {} / {} (n={}, {} B avg)",
                            ms(l.p50_ms),
                            ms(l.p95_ms),
                            ms(l.max_ms),
                            l.docs,
                            l.mean_bytes
                        )
                    },
                ),
            ]);
        }
        let model_line = self.meta.model.as_ref().map_or_else(String::new, |m| {
            format!(
                "\nModel: {}. Reloads between measurements are not counted below.\n",
                self.model_text(m)
            )
        });
        let same: Vec<String> = self
            .runs
            .iter()
            .filter(|r| r.speed.warm_same == Some(false))
            .map(|r| self.title(r))
            .collect();
        let warn = if same.is_empty() {
            String::new()
        } else {
            format!(
                "\nWarning: the warm pass returned different spans than the cold pass for: {}.\n",
                same.join(", ")
            )
        };
        format!(
            "\n## Speed\n\n*cold*: one pass over the corpus, {} documents per call, model cache empty. \
             *warm*: the same pass again with the cache full (a chat client resending its history). \
             *single doc*: one document per call, cold. All with the whole machine, nothing else tuned.\n{model_line}\n{}{warn}",
            self.meta.batch,
            t.render()
        )
    }
}

/// The examples of `list` in category `c`.
fn of_cat(list: &[Example], c: Cat) -> Vec<&Example> {
    list.iter().filter(|e| e.cat == c).collect()
}

/// The most common values of `examples`, as `` `value` ×n ``, `k` of them.
fn top_values(source: &Source, examples: &[&Example], k: usize) -> String {
    let mut seen: Vec<(String, usize)> = Vec::new();
    for e in examples {
        let value = source.docs[e.doc].text[e.start..e.end].to_owned();
        match seen.iter_mut().find(|(v, _)| *v == value) {
            Some((_, n)) => *n += 1,
            None => seen.push((value, 1)),
        }
    }
    // Most common first; ties keep the order they were found in (stable sort).
    seen.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    seen.iter()
        .take(k)
        .map(|(v, n)| {
            if *n > 1 {
                format!("`{}` ×{n}", cell(v, 36))
            } else {
                format!("`{}`", cell(v, 36))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// --- verdict ---------------------------------------------------------------------------------------

impl Report<'_> {
    /// The run of `source` for the headline configuration: regex+model when it ran.
    fn headline_run(&self, source: usize) -> Option<&Run> {
        [Config::RegexModel, Config::Model, Config::Regex]
            .into_iter()
            .find_map(|c| {
                self.runs
                    .iter()
                    .find(|r| r.source == source && r.config == c)
            })
    }

    fn verdict(&self) -> String {
        let mut t = Table::new(&[
            ("corpus", false),
            ("configuration", false),
            ("strict F1", true),
            ("overlap F1", true),
            ("any-cat recall", true),
            ("leak", true),
            ("FP masked", true),
            ("overlap F1, card types", true),
            ("any-cat recall, card types", true),
        ]); // fmt: skip
        let mut reading = String::new();
        for (i, s) in self.sources.iter().enumerate() {
            let Some(run) = self.headline_run(i) else {
                continue;
            };
            let total = &run.agg.total;
            let sup = total.sum(|c| self.tax.supported(c));
            let card = total.sum(|c| self.tax.supported(c) && self.tax.is_card_type(c));
            t.row([
                s.name.clone(),
                run.config.name().to_owned(),
                dec(sup.strict().f1()),
                dec(sup.overlap().f1()),
                dec(sup.any().r),
                pct(sup.leak()),
                pct(total.fp_rate()),
                dec(card.overlap().f1()),
                dec(card.any().r),
            ]);
            let nearest = COUNTERPARTS
                .iter()
                .find(|(name, _)| *name == s.name)
                .map_or("none: no published number for this corpus", |(_, text)| {
                    *text
                });
            put!(
                reading,
                "- **{}** ({}): overlap F1 {} over every supported category and {} over the card's type groups; \
                 {} of the gold characters leak. Nearest published number: {nearest}.\n",
                s.name,
                run.config.name(),
                dec(sup.overlap().f1()),
                dec(card.overlap().f1()),
                pct(sup.leak()),
            );
        }
        let mut published = Table::new(&[
            ("source", false),
            ("measure", false),
            ("number", true),
            ("data", false),
        ]);
        for (source, measure, number, data) in PUBLISHED {
            published.row([
                (*source).to_owned(),
                (*measure).to_owned(),
                (*number).to_owned(),
                (*data).to_owned(),
            ]);
        }
        format!(
            "\n## Verdict\n\nThis run (best configuration per corpus, categories piikey can produce). \
             *card types* restricts the same scores to the categories that this benchmark reads the model \
             card's seven type groups as (`[card]` in `labels.toml`).\n\n{}\n{reading}\n\
             Published numbers, for orientation only:\n\n{}\n{VERDICT_CAVEATS}",
            t.render(),
            published.render()
        )
    }

    /// What the leaking gold values look like, over the categories piikey can produce.
    fn shapes(&self, run: &Run, source: &Source) -> String {
        let fail = &run.agg.failures;
        let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        let value = |e: &Example| source.docs[e.doc].text[e.start..e.end].to_owned();
        for e in fail.missed.iter().filter(|e| self.tax.supported(e.cat)) {
            counts.entry(shape(&value(e))).or_default().0 += 1;
        }
        for e in fail.partial.iter().filter(|e| self.tax.supported(e.cat)) {
            counts.entry(shape(&value(e))).or_default().1 += 1;
        }
        if counts.is_empty() {
            return String::new();
        }
        let mut rows: Vec<(&str, (usize, usize))> = counts.into_iter().collect();
        rows.sort_by_key(|(name, (missed, partial))| (std::cmp::Reverse(missed + partial), *name));
        let mut t = Table::new(&[("value shape", false), ("missed", true), ("partial", true)]);
        for (name, (missed, partial)) in rows {
            t.row([name.to_owned(), num(missed), num(partial)]);
        }
        format!(
            "What the leaking gold values look like:\n\n{}\n",
            t.render()
        )
    }
}

/// The nearest published number for a corpus. `(corpus, what and where)`.
const COUNTERPARTS: &[(&str, &str)] = &[
    (
        "finance_multilingual",
        "the model card's 0.692 on the same dataset (strict, word level, 7 type groups, out of distribution)",
    ),
    (
        "openpii",
        "the model card's 0.997 on the same dataset (strict, word level, 7 type groups, its train split is in the training data)",
    ),
    (
        "gretel_en",
        "arXiv 2608.02616's 0.554 (OpenAI Privacy Filter) and 0.388 (Presidio) on the same dataset (zero-shot, English, n=2000, its own F1)",
    ),
];

/// Numbers other people measured. `(source, measure, number, data)`.
const PUBLISHED: &[(&str, &str, &str, &str)] = &[
    (
        "model card, bardsai/eu-pii-anonimization-multilang-v2",
        "strict span F1, 7 coarse types, FP32",
        "0.973",
        "455 hand-checked spans of real web text (held-out domains)",
    ),
    (
        "same model card",
        "same, INT8 `model_quantized.onnx` (the file piikey ships)",
        "0.968",
        "same 455 spans",
    ),
    (
        "same model card",
        "span F1 on gretelai finance PII multilingual (out of distribution)",
        "0.692",
        "the corpus behind our `finance_multilingual`",
    ),
    (
        "same model card",
        "span F1 on nvidia/Nemotron-PII (its train split is in the training data)",
        "0.933",
        "not run here",
    ),
    (
        "same model card",
        "span F1 on ai4privacy OpenPII (its train split is in the training data)",
        "0.997",
        "the corpus behind our `openpii`",
    ),
    (
        "arXiv 2608.02616",
        "OpenAI Privacy Filter, zero-shot span F1 on AI4Privacy (Presidio 0.431)",
        "0.855",
        "English, n=2000",
    ),
    (
        "arXiv 2608.02616",
        "OpenAI Privacy Filter, zero-shot span F1 on gretel_en (Presidio 0.388)",
        "0.554",
        "English, n=2000",
    ),
];

const VERDICT_CAVEATS: &str = "\
These are not apples to apples, and none of them is a number to \"beat\":

- **Matching.** The model card scores *strict at the word level over 7 coarse types* (a gold span \
counts as found only if every letter and digit is predicted with the right type; a prediction is \
right if it lies inside a gold span of the same type). The arXiv paper reports a span F1 of its own. \
This benchmark reports three criteria over the categories of `labels.toml`, and its *strict* needs \
the exact span too. None of the three is the card's scorer, and the *card types* columns only \
restrict our scores to the categories the card's seven groups are read as here.
- **Gold.** Our gold is after joining parts of an entity (`GIVENNAME` + `SURNAME`), only for the \
categories piikey can produce, and a prediction in a category a corpus does not annotate is not \
judged. The corpora label differently from each other and from the model: OpenPII calls every date \
`DATE`, and the finance corpus labels timestamps, template fields such as `[Phone Number]`, plain \
words such as `Damen` and fragments such as `:` as PII.
- **Data.** The samples are language-balanced (Dutch, English, German weighted up), capped and fixed \
by a seed; the published numbers are on full test sets or other samples. `openpii` is in-distribution: \
the model was trained on its train split, so read it as an upper bound. `finance_multilingual` is \
the one the card calls out of distribution.
- **System.** piikey is not the bare model: the regex pass and its validators run first and win \
overlaps, the model's types go through validators that can drop them (a name must look like a name), \
the file is INT8 and its decoding is piikey's own port of the reference word decoder.
- **Hand-made set.** 200 short prompts is small: one span moves a percentage by a fraction of a \
point, a category with ten spans by ten. It is the only corpus that is labelled exhaustively, so \
its false-positive numbers are the only ones that are not an upper bound.
";

// --- JSON ----------------------------------------------------------------------------------------

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
        json!({
            "doc": doc.id,
            "lang": doc.lang,
            "category": self.tax.name(e.cat),
            "tag": e.tag,
            "value": cell(&doc.text[e.start..e.end], 200),
            "context": format!("{before}[[{}]]{after}", cell(&doc.text[e.start..e.end], 200)),
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
            "did_not_restore": rt.mismatches.iter().take(60).map(|m| json!({
                "doc": m.doc, "original": m.original, "restored": m.restored, "trace": m.trace,
            })).collect::<Vec<_>>(),
            "left_verbatim": rt.survivors.iter().take(60).map(|s| json!({
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
    use super::{cell, num};

    #[test]
    fn numbers_get_separators() {
        assert_eq!(num(0), "0");
        assert_eq!(num(999), "999");
        assert_eq!(num(1_000), "1,000");
        assert_eq!(num(1_234_567), "1,234,567");
    }

    #[test]
    fn cells_cannot_break_a_table() {
        assert_eq!(cell("a|b\nc`d", 20), "a¦b⏎c'd");
        assert_eq!(cell("abcdef", 3), "abc…");
    }
}
