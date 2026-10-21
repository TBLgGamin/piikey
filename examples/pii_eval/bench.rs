//! Running detectors: the configurations, the life cycle of the detection model, and timings.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use piikey::{
    detect::{
        CompositeDetector, Detector, KindSet, Mode, NerDetector, RegexDetector, Span,
        ner::{Device, files},
    },
    engine::Engine,
};

use crate::{
    Res,
    data::{Doc, evenly},
};

/// A way of putting detectors together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Config {
    /// The validated regex patterns alone (what piikey does before the model is downloaded).
    Regex,
    /// The regex pass, then the model over what it left: what `Engine::open_with_model` builds.
    RegexModel,
    /// The model alone, to see what it finds without the patterns.
    Model,
}

impl Config {
    pub const ALL: [Self; 3] = [Self::Regex, Self::RegexModel, Self::Model];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::RegexModel => "regex+model",
            Self::Model => "model",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    #[must_use]
    pub const fn uses_model(self) -> bool {
        !matches!(self, Self::Regex)
    }
}

/// How the device of the model was settled for this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Whatever an earlier load saved in `device.cfg` (the first load measures when there is none).
    Saved,
    /// Forced by `--device`: the word written to `device.cfg` (see [`Choice::forced`]).
    Forced(&'static str),
    /// Measured again by `--recalibrate`.
    Measure,
}

/// The model folder's `device.cfg` as this run needs it. Dropping it puts back what was there:
/// a benchmark must not change which device the app uses.
#[derive(Debug)]
pub struct DeviceFile {
    path: PathBuf,
    previous: Option<Vec<u8>>,
    restore: bool,
}

impl DeviceFile {
    /// Writes or removes `device.cfg` in `dir` for `choice`.
    ///
    /// # Errors
    /// The file cannot be written.
    pub fn apply(dir: &Path, choice: Choice) -> Res<Self> {
        let path = dir.join(files::DEVICE_FILE);
        let previous = fs::read(&path).ok();
        match choice {
            Choice::Saved => {}
            Choice::Forced(word) => fs::write(&path, word)?,
            Choice::Measure => {
                let _ = fs::remove_file(&path);
            }
        }
        Ok(Self {
            path,
            previous,
            restore: choice != Choice::Saved,
        })
    }
}

impl Drop for DeviceFile {
    fn drop(&mut self) {
        if !self.restore {
            return;
        }
        let _ = match &self.previous {
            Some(bytes) => fs::write(&self.path, bytes),
            None => fs::remove_file(&self.path),
        };
    }
}

impl Choice {
    /// The choice that forces the device named `word` (`cpu`, `gpu` or `hybrid`: what `device.cfg`
    /// accepts, depending on the version of piikey).
    #[must_use]
    pub fn forced(word: &str) -> Option<Self> {
        ["cpu", "gpu", "hybrid"]
            .into_iter()
            .find(|w| *w == word)
            .map(Self::Forced)
    }
}

/// The detection model in memory, and what loading it cost.
#[derive(Debug)]
pub struct Model {
    pub ner: NerDetector,
    pub dir: PathBuf,
    pub device: Device,
    pub choice: Choice,
    /// Seconds the first load took.
    pub first_load_secs: f64,
    /// Whether that load had to measure the GPU against the CPU (no `device.cfg` was there).
    pub calibrated: bool,
}

impl Model {
    /// Loads the model in `dir` and times it. `choice` is how [`DeviceFile`] already set up
    /// `device.cfg`; it is only recorded here.
    ///
    /// # Errors
    /// The model is not installed or fails to load.
    pub fn start(dir: PathBuf, choice: Choice) -> Res<Self> {
        let calibrated = !dir.join(files::DEVICE_FILE).exists();
        let ner = NerDetector::new(dir.clone());
        let started = Instant::now();
        let device = ner.load()?;
        Ok(Self {
            ner,
            dir,
            device,
            choice,
            first_load_secs: started.elapsed().as_secs_f64(),
            calibrated,
        })
    }

    /// Frees the model and everything it remembered, then loads it again, so that the next
    /// measurement starts cold. Returns the seconds the reload took.
    ///
    /// # Errors
    /// The model fails to load again.
    pub fn reset(&self) -> Res<f64> {
        self.ner.release();
        let started = Instant::now();
        self.ner.load()?;
        Ok(started.elapsed().as_secs_f64())
    }
}

/// The model folder to use: `explicit`, else the one the app installs in
/// `%LOCALAPPDATA%\piikey\models`. Only a folder that is fully installed counts; the benchmark
/// never downloads or copies the model.
#[must_use]
pub fn find_model_dir(explicit: Option<PathBuf>) -> Option<PathBuf> {
    explicit
        .into_iter()
        .chain(files::default_dir().ok())
        .find(|dir| files::is_installed(dir))
}

/// The detector of `config`. The model configurations need `model`.
///
/// # Errors
/// A model configuration without a model, or the regex table fails to compile.
pub fn detector(config: Config, model: Option<&Model>) -> Res<Box<dyn Detector>> {
    let need = || {
        model
            .map(|m| m.ner.clone())
            .ok_or("the detection model is not installed")
    };
    Ok(match config {
        Config::Regex => Box::new(RegexDetector::new()?),
        Config::RegexModel => Box::new(CompositeDetector(vec![
            Box::new(RegexDetector::new()?),
            Box::new(need()?),
        ])),
        Config::Model => Box::new(need()?),
    })
}

/// The real engine of `config` over the vault at `vault`, for the round trip. The model alone
/// has no engine (the engine always runs the patterns first).
///
/// # Errors
/// The vault cannot be opened.
pub fn engine(config: Config, vault: &Path, model: Option<&Model>) -> Res<Option<Engine>> {
    Ok(match (config, model) {
        (Config::Regex, _) => Some(Engine::open(vault)?),
        (Config::RegexModel, Some(m)) => Some(Engine::open_with_model(vault, m.ner.clone())?),
        _ => None,
    })
}

/// How long single documents take, one call each.
#[derive(Debug, Clone)]
pub struct Latency {
    pub docs: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub mean_bytes: usize,
}

/// The timings of one detector over one source.
#[derive(Debug, Clone)]
pub struct Speed {
    pub docs: usize,
    pub bytes: usize,
    /// One pass over every document in batches, from a cold model cache.
    pub cold_secs: f64,
    /// The same pass again with the cache full (a chat client resending its history). Models only.
    pub warm_secs: Option<f64>,
    /// Whether the warm pass returned exactly the cold pass's spans.
    pub warm_same: Option<bool>,
    pub latency: Option<Latency>,
    /// The reloads of the model between measurements (not part of any timing above).
    pub reloads: Reloads,
}

/// Reloads of the model between measurements, to start each one cold.
#[derive(Debug, Clone, Copy, Default)]
pub struct Reloads {
    pub count: usize,
    pub secs: f64,
}

impl Reloads {
    /// Empties the model's cache by loading it afresh. Nothing to do without a model.
    fn cold(&mut self, model: Option<&Model>) -> Res<()> {
        if let Some(m) = model {
            self.secs += m.reset()?;
            self.count += 1;
        }
        Ok(())
    }
}

/// What a source run needs to know about how to measure.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    /// Documents per detector call in the throughput passes.
    pub batch: usize,
    /// Documents timed one call at a time (0: none).
    pub latency_docs: usize,
}

/// The spans of every document, found `batch` documents per call.
#[must_use]
pub fn detect_batches(det: &dyn Detector, docs: &[Doc], batch: usize) -> Vec<Vec<Span>> {
    let mut out = Vec::with_capacity(docs.len());
    for chunk in docs.chunks(batch.max(1)) {
        let texts: Vec<&str> = chunk.iter().map(|d| d.text.as_str()).collect();
        out.extend(det.detect_batch(&texts, Mode::Anonymize, KindSet::ALL, &[]));
    }
    out
}

/// Runs `det` over `docs`: a latency sample, then the cold pass (whose spans are returned for
/// scoring), then, for a model, the warm pass.
///
/// # Errors
/// The model fails to reload between measurements.
pub fn measure(
    det: &dyn Detector,
    model: Option<&Model>,
    docs: &[Doc],
    plan: Plan,
) -> Res<(Vec<Vec<Span>>, Speed)> {
    let mut reloads = Reloads::default();
    let latency = if plan.latency_docs > 0 {
        reloads.cold(model)?;
        Some(time_single(det, docs, plan.latency_docs))
    } else {
        None
    };

    reloads.cold(model)?;
    let started = Instant::now();
    let spans = detect_batches(det, docs, plan.batch);
    let cold_secs = started.elapsed().as_secs_f64();

    let (warm_secs, warm_same) = if model.is_some() {
        let started = Instant::now();
        let again = detect_batches(det, docs, plan.batch);
        (Some(started.elapsed().as_secs_f64()), Some(again == spans))
    } else {
        (None, None)
    };

    let speed = Speed {
        docs: docs.len(),
        bytes: docs.iter().map(|d| d.text.len()).sum(),
        cold_secs,
        warm_secs,
        warm_same,
        latency,
        reloads,
    };
    Ok((spans, speed))
}

/// Times `count` documents spread evenly over `docs`, each in a call of its own.
fn time_single(det: &dyn Detector, docs: &[Doc], count: usize) -> Latency {
    let sample = evenly(docs, count);
    let mut ms: Vec<f64> = sample
        .iter()
        .map(|d| {
            let started = Instant::now();
            let _ = det.detect_batch(&[d.text.as_str()], Mode::Anonymize, KindSet::ALL, &[]);
            started.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    ms.sort_by(f64::total_cmp);
    Latency {
        docs: sample.len(),
        p50_ms: percentile(&ms, 50),
        p95_ms: percentile(&ms, 95),
        max_ms: ms.last().copied().unwrap_or(0.0),
        mean_bytes: sample.iter().map(|d| d.text.len()).sum::<usize>() / sample.len().max(1),
    }
}

/// The `pct`-th percentile (nearest rank) of `sorted`, which is in ascending order.
fn percentile(sorted: &[f64], pct: usize) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    sorted[(n * pct).div_ceil(100).saturating_sub(1).min(n - 1)]
}
