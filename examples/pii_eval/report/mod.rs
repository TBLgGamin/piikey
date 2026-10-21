//! The report: Markdown for people (here, with the verdict in [`verdict`]), JSON for tools
//! ([`json`]).

use std::collections::{BTreeMap, HashMap};

use piikey::detect::ner::Device;

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
        let _ = ::std::fmt::Write::write_fmt(&mut $out, format_args!($($arg)*));
    }};
}

mod json;
mod verdict;

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

/// How a device is named in the report.
#[must_use]
pub const fn device_name(device: Device) -> &'static str {
    match device {
        Device::Cpu => "CPU",
        Device::Hybrid => "hybrid (CPU, the GPU for large calls)",
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

    /// The category's name, starred when piikey has no kind for it.
    fn cat_label(&self, c: Cat) -> String {
        let mark = if self.tax.supported(c) { "" } else { "*" };
        format!("{}{mark}", self.tax.name(c))
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
            let sha = format!("sha {}", s.fingerprint);
            let mut data: Vec<&str> = Vec::new();
            if let Some(n) = self.meta.notes.get(&s.name) {
                data.extend([n.license.as_str(), n.note.as_str(), n.origin.as_str()]);
            }
            data.push(&sha);
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
                data.iter()
                    .filter(|part| !part.is_empty())
                    .map(|part| cell(part, 160))
                    .collect::<Vec<_>>()
                    .join("; "),
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
                t.row([
                    self.cat_label(c),
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
                let mut row = vec![self.cat_label(c)];
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
            t.row(row(self.cat_label(c), s));
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

    /// What the leaking gold values look like, over the categories piikey can produce.
    fn shapes(&self, run: &Run, source: &Source) -> String {
        let fail = &run.agg.failures;
        let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for e in fail.missed.iter().filter(|e| self.tax.supported(e.cat)) {
            counts.entry(shape(value(source, e))).or_default().0 += 1;
        }
        for e in fail.partial.iter().filter(|e| self.tax.supported(e.cat)) {
            counts.entry(shape(value(source, e))).or_default().1 += 1;
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

/// The examples of `list` in category `c`.
fn of_cat(list: &[Example], c: Cat) -> Vec<&Example> {
    list.iter().filter(|e| e.cat == c).collect()
}

/// The text an example points at.
fn value<'a>(source: &'a Source, e: &Example) -> &'a str {
    &source.docs[e.doc].text[e.start..e.end]
}

/// The most common values of `examples`, as `` `value` ×n ``, `k` of them.
fn top_values(source: &Source, examples: &[&Example], k: usize) -> String {
    let mut seen: Vec<(&str, usize)> = Vec::new();
    let mut at: HashMap<&str, usize> = HashMap::new();
    for e in examples {
        let i = *at.entry(value(source, e)).or_insert_with(|| {
            seen.push((value(source, e), 0));
            seen.len() - 1
        });
        seen[i].1 += 1;
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
