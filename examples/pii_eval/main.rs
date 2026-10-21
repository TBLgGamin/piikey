//! Quality benchmark of piikey's detection against ground-truth corpora.
//!
//! ```sh
//! python eval/fetch.py                           # once: download and convert the corpora
//! cargo run --release --example pii_eval         # regex, then regex+model, on every corpus
//! cargo run --release --example pii_eval -- --help
//! ```
//!
//! It scores what piikey would mask against labelled spans (per category: precision, recall and
//! F1 three ways, leakage, false-positive masking), runs real `Engine` round trips, times the
//! detectors, prints Markdown and writes `eval/results/<timestamp>.json` and `.md`.
//! `eval/README.md` explains how to read them.

mod bench;
mod data;
mod report;
mod roundtrip;
mod score;
mod taxonomy;

use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use lexopt::{Arg, Parser, ValueExt};
use piikey::detect::ner::files;
use serde_json::Value;

use crate::{
    bench::{Choice, Config, DeviceFile, Model, Plan},
    data::{Doc, Source, evenly},
    report::{Meta, ModelInfo, Report, Run, SourceNote},
    taxonomy::Taxonomy,
};

pub type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

const USAGE: &str = "\
piikey detection benchmark (see eval/README.md)

USAGE:
    cargo run --release --example pii_eval -- [OPTIONS]

OPTIONS:
    --sources A,B      corpora to score (default: every one in eval/data, plus handmade)
    --configs A,B      regex | regex+model | model (default: regex,regex+model)
    --limit N          documents per corpus (default: all the file holds)
    --batch N          documents per detector call in the throughput passes (default 32)
    --latency-docs N   single-document calls timed per corpus (default 100; 0 skips)
    --roundtrip N      documents per corpus through the real Engine (default 300; 0 skips)
    --examples N       examples shown per failure list (default 3)
    --json-examples N  examples of each failure list kept in the JSON (default 60)
    --model-dir DIR    detection model folder (default: the app's, in %LOCALAPPDATA%\\piikey\\models)
    --device D         run the model on cpu, gpu or hybrid instead of the saved choice (restored afterwards)
    --recalibrate      measure GPU against CPU again on the first load (the old choice is restored)
    --eval-dir DIR     the eval folder (default: eval/ of this repository)
    --out DIR          results folder (default: <eval-dir>/results)
    --no-write         print only; write no result files
    --note TEXT        a line about this machine or run, kept in the report
    -h, --help         this text
";

/// The order corpora are reported in: the hand-made set first, the in-distribution one last.
const ORDER: [&str; 4] = ["handmade", "finance_multilingual", "gretel_en", "openpii"];

#[derive(Debug)]
struct Args {
    eval_dir: PathBuf,
    sources: Option<Vec<String>>,
    configs: Option<Vec<Config>>,
    limit: Option<usize>,
    batch: usize,
    latency_docs: usize,
    roundtrip_docs: usize,
    examples: usize,
    json_examples: usize,
    model_dir: Option<PathBuf>,
    choice: Choice,
    out: Option<PathBuf>,
    write: bool,
    note: String,
}

fn parse_args() -> Res<Option<Args>> {
    let mut args = Args {
        eval_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("eval"),
        sources: None,
        configs: None,
        limit: None,
        batch: 32,
        latency_docs: 100,
        roundtrip_docs: 300,
        examples: 3,
        json_examples: 60,
        model_dir: None,
        choice: Choice::Saved,
        out: None,
        write: true,
        note: String::new(),
    };
    let mut parser = Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('h') | Arg::Long("help") => {
                print!("{USAGE}");
                return Ok(None);
            }
            Arg::Long("sources") => args.sources = Some(list(&parser.value()?.string()?)),
            Arg::Long("configs") => {
                let names = list(&parser.value()?.string()?);
                let configs: Option<Vec<Config>> = names.iter().map(|n| Config::parse(n)).collect();
                args.configs = Some(configs.ok_or("--configs takes regex, regex+model, model")?);
            }
            Arg::Long("limit") => args.limit = Some(parser.value()?.parse()?),
            Arg::Long("batch") => args.batch = parser.value()?.parse()?,
            Arg::Long("latency-docs") => args.latency_docs = parser.value()?.parse()?,
            Arg::Long("roundtrip") => args.roundtrip_docs = parser.value()?.parse()?,
            Arg::Long("examples") => args.examples = parser.value()?.parse()?,
            Arg::Long("json-examples") => args.json_examples = parser.value()?.parse()?,
            Arg::Long("model-dir") => args.model_dir = Some(parser.value()?.into()),
            Arg::Long("device") => {
                let word = parser.value()?.string()?;
                args.choice = Choice::forced(&word).ok_or("--device takes cpu, gpu or hybrid")?;
            }
            Arg::Long("recalibrate") => args.choice = Choice::Measure,
            Arg::Long("eval-dir") => args.eval_dir = parser.value()?.into(),
            Arg::Long("out") => args.out = Some(parser.value()?.into()),
            Arg::Long("no-write") => args.write = false,
            Arg::Long("note") => args.note = parser.value()?.string()?,
            other => return Err(other.unexpected().into()),
        }
    }
    Ok(Some(args))
}

fn list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn main() -> Res<()> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };
    let started = Instant::now();
    let tax = Taxonomy::load(&args.eval_dir.join("labels.toml"))?;
    let sources = load_sources(&args, &tax)?;
    for s in &sources {
        eprintln!(
            "{}: {} documents, {:.1} MB, {} gold spans",
            s.name,
            s.docs.len(),
            report::mb(s.bytes),
            s.gold_spans()
        );
    }

    let (configs, model, _device_file) = setup(&args)?;
    let plan = Plan {
        batch: args.batch,
        latency_docs: args.latency_docs,
    };
    let mut runs = Vec::new();
    for &config in &configs {
        let detector = bench::detector(config, model.as_ref())?;
        for (si, source) in sources.iter().enumerate() {
            eprintln!("{} on {} ...", config.name(), source.name);
            let using = model.as_ref().filter(|_| config.uses_model());
            let (spans, speed) = bench::measure(detector.as_ref(), using, &source.docs, plan)?;
            let agg = score::score_source(&tax, source, &spans);
            let roundtrip = round_trip(&tax, config, source, model.as_ref(), args.roundtrip_docs)?;
            runs.push(Run {
                config,
                source: si,
                agg,
                speed,
                roundtrip,
            });
        }
    }

    let meta = Meta {
        timestamp: utc_now(),
        piikey: piikey_version(&args.eval_dir),
        machine: machine(&args.note),
        model: model.as_ref().map(|m| ModelInfo {
            id: files::MODEL_ID,
            dir: m.dir.display().to_string(),
            device: m.device,
            choice: m.choice,
            first_load_secs: m.first_load_secs,
            calibrated: m.calibrated,
        }),
        configs: configs.iter().map(|c| c.name().to_owned()).collect(),
        batch: args.batch,
        latency_docs: args.latency_docs,
        roundtrip_docs: args.roundtrip_docs,
        wall_secs: started.elapsed().as_secs_f64(),
        notes: source_notes(&args.eval_dir),
    };
    let report = Report {
        meta,
        tax: &tax,
        sources: &sources,
        runs,
        examples: args.examples,
        json_examples: args.json_examples,
    };
    let markdown = report.markdown();
    print!("{markdown}");
    if args.write {
        let dir = args
            .out
            .clone()
            .unwrap_or_else(|| args.eval_dir.join("results"));
        fs::create_dir_all(&dir)?;
        let stamp = file_stamp();
        let json = serde_json::to_string_pretty(&report.json())?;
        fs::write(dir.join(format!("{stamp}.json")), json)?;
        fs::write(dir.join(format!("{stamp}.md")), &markdown)?;
        eprintln!("wrote {}\\{stamp}.json and .md", dir.display());
    }
    Ok(())
}

/// The corpora to score: `eval/data/*.jsonl` and `eval/handmade.jsonl`, in report order.
fn load_sources(args: &Args, tax: &Taxonomy) -> Res<Vec<Source>> {
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(args.eval_dir.join("data")) {
        for path in entries.flatten().map(|e| e.path()) {
            if path.extension().is_some_and(|e| e == "jsonl")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                found.push((stem.to_owned(), path));
            }
        }
    }
    let handmade = args.eval_dir.join("handmade.jsonl");
    if handmade.exists() {
        found.push(("handmade".to_owned(), handmade));
    }
    found.sort_by_key(|(name, _)| {
        (
            ORDER.iter().position(|o| o == name).unwrap_or(ORDER.len()),
            name.clone(),
        )
    });
    if let Some(wanted) = &args.sources {
        let known: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        if let Some(missing) = wanted.iter().find(|w| !known.contains(&w.as_str())) {
            return Err(format!(
                "no corpus {missing:?} (found: {known:?}); `python eval/fetch.py` downloads them"
            )
            .into());
        }
        found.retain(|(name, _)| wanted.contains(name));
    }
    if found.is_empty() {
        return Err("no corpus found: run `python eval/fetch.py` first".into());
    }
    found
        .iter()
        .map(|(name, path)| Source::load(tax, name, path, args.limit))
        .collect()
}

/// The configurations to run and the model they need: the model is loaded (and timed) once. The
/// returned guard keeps `device.cfg` as the run set it until the end of `main`.
fn setup(args: &Args) -> Res<(Vec<Config>, Option<Model>, Option<DeviceFile>)> {
    let explicit = args.configs.is_some();
    let mut configs = args
        .configs
        .clone()
        .unwrap_or_else(|| vec![Config::Regex, Config::RegexModel]);
    if !configs.iter().any(|c| c.uses_model()) {
        return Ok((configs, None, None));
    }
    let Some(dir) = bench::find_model_dir(args.model_dir.clone()) else {
        if explicit {
            return Err("the detection model is not installed (start piikey.exe once, or run `cargo test --release --test ner_model -- --ignored`)".into());
        }
        eprintln!(
            "note: the detection model is not installed; running the regex configuration only"
        );
        configs.retain(|c| !c.uses_model());
        return Ok((configs, None, None));
    };
    eprintln!("loading the detection model from {} ...", dir.display());
    let device_file = DeviceFile::apply(&dir, args.choice)?;
    let model = Model::start(dir, args.choice)?;
    eprintln!(
        "  loaded in {:.1} s on {}{}",
        model.first_load_secs,
        report::device_name(model.device),
        if model.calibrated {
            " (including the GPU/CPU calibration)"
        } else {
            ""
        }
    );
    Ok((configs, Some(model), Some(device_file)))
}

/// A sample of `n` documents of `source` through the real engine on a throw-away vault.
fn round_trip(
    tax: &Taxonomy,
    config: Config,
    source: &Source,
    model: Option<&Model>,
    n: usize,
) -> Res<Option<roundtrip::RoundTrip>> {
    if n == 0 {
        return Ok(None);
    }
    let dir = std::env::temp_dir().join(format!(
        "piikey-eval-{}-{}",
        std::process::id(),
        source.name
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let result = round_trip_in(&dir, tax, config, source, model, n);
    // The vault holds the original and its stand-in of every value: never leave it behind.
    let _ = fs::remove_dir_all(&dir);
    result
}

fn round_trip_in(
    dir: &Path,
    tax: &Taxonomy,
    config: Config,
    source: &Source,
    model: Option<&Model>,
    n: usize,
) -> Res<Option<roundtrip::RoundTrip>> {
    let Some(engine) = bench::engine(config, &dir.join("vault.pkv"), model)? else {
        return Ok(None);
    };
    let sample: Vec<&Doc> = evenly(&source.docs, n);
    let checked = |c| tax.supported(c);
    Ok(Some(roundtrip::run(&engine, &sample, &checked)))
}

fn source_notes(eval_dir: &Path) -> BTreeMap<String, SourceNote> {
    let mut notes = BTreeMap::new();
    notes.insert(
        "handmade".to_owned(),
        SourceNote {
            license: "this repository".to_owned(),
            note: "hand-written NL/EN/DE prompts, every PII value labelled, hard negatives left unlabelled"
                .to_owned(),
            origin: String::new(),
        },
    );
    let manifest = fs::read_to_string(eval_dir.join("data").join("MANIFEST.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    if let Some(Value::Object(map)) = manifest {
        for (name, entry) in map {
            let text = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default();
            let sha: String = entry
                .get("revision")
                .and_then(|r| r.get("sha"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .chars()
                .take(10)
                .collect();
            let seed = entry.get("seed").map(Value::to_string).unwrap_or_default();
            let origin = format!(
                "{} @ {sha}, fetched {}, seed {seed}",
                text("dataset"),
                text("fetched_at").split('T').next().unwrap_or_default()
            );
            notes.insert(
                name,
                SourceNote {
                    license: text("license").to_owned(),
                    note: text("note").to_owned(),
                    origin,
                },
            );
        }
    }
    notes
}

/// `0.1.0 (abc1234, uncommitted changes)`, from git when it is there.
fn piikey_version(eval_dir: &Path) -> String {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(eval_dir.parent()?)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let version = env!("CARGO_PKG_VERSION");
    match git(&["rev-parse", "--short", "HEAD"]) {
        Some(sha) => {
            let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
            format!(
                "{version} ({sha}{})",
                if dirty { ", uncommitted changes" } else { "" }
            )
        }
        None => version.to_owned(),
    }
}

fn machine(note: &str) -> String {
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let cpu =
        std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| std::env::consts::ARCH.to_owned());
    let base = format!("{cpu}, {threads} logical processors");
    if note.is_empty() {
        base
    } else {
        format!("{note} ({base})")
    }
}

/// Days since 1970-01-01 as `(year, month, day)` (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// The current UTC time as `(year, month, day, hour, minute, second)`.
fn now_parts() -> (i64, i64, i64, i64, i64, i64) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let (y, m, d) = civil(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    (y, m, d, rest / 3600, rest % 3600 / 60, rest % 60)
}

fn utc_now() -> String {
    let (y, mo, d, h, mi, s) = now_parts();
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn file_stamp() -> String {
    let (y, mo, d, h, mi, s) = now_parts();
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

#[cfg(test)]
mod tests {
    use super::civil;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        assert_eq!(civil(20_381), (2025, 10, 20));
    }
}
