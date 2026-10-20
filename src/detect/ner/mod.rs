//! On-device detection with a token-classification model.
//!
//! The regex detector finds what has a format. This finds the rest: names, addresses,
//! organizations, health data and the other free-text kinds. The model is
//! `bardsai/eu-pii-anonimization-multilang-v2` (Apache-2.0, 24 EU languages, INT8 ONNX), run in
//! ONNX Runtime. Nothing leaves the machine.
//!
//! [`NerDetector`] loads on demand, or explicitly with [`NerDetector::load`], and frees the model
//! again with [`NerDetector::release`]: the app keeps it in memory only while protection is on.
//!
//! # CPU and GPU together
//!
//! The model always runs on the CPU. When `DirectML` can drive a GPU and that GPU is clearly faster
//! than the CPU on a large batch, the model is loaded on the GPU as well ([`Device::Hybrid`]). The
//! first load measures that and writes the outcome to [`files::DEVICE_FILE`].
//!
//! A GPU is no use for a small call: a run costs it about 70 ms before it computes anything, where
//! the CPU answers one chat message in under 10 ms. So a call that the CPU answers in about 300 ms
//! (some 85 short messages, or three windows of 512 positions) stays on the CPU. A bigger one is
//! split by window length: the windows are sorted, the GPU takes batches from the longest end (it
//! is about three times faster than the CPU on windows of 512 positions, and slower on short ones)
//! and the CPU from the shortest end, until they meet. A GPU that fails a run is given up for
//! good: the CPU runs that batch and everything after it.
//!
//! # A text goes through these steps
//!
//! 1. Runs of data (base64, hex: a kilobyte or more without whitespace) are cut out of it,
//!    `gate::worth_running` spares the model texts it cannot add to (a lone JSON key, only
//!    stopwords), and the cache spares it texts it has seen (chat clients resend the whole
//!    conversation every turn).
//! 2. The tokenizer cuts the rest into windows of 510 tokens that overlap by 128, because the model
//!    reads 512 positions at most.
//! 3. The windows of a group of texts, longest first, are packed into batches that the CPU and the
//!    GPU take from the two ends of the list. ONNX Runtime sessions do not run concurrently, so each
//!    runs one batch at a time, and never inside a rayon task.
//! 4. `decode` turns the probabilities into spans, and `labels` the model's types into kinds.
//!
//! The model is INT8 with dynamic quantization: how a batch is quantized depends on everything in
//! it, so a borderline decision (does `ul.` belong to the address after it?) can differ between
//! two batches, and between the CPU and the GPU. The cache keeps the first answer for a text, which
//! also keeps a conversation consistent from one turn to the next.

pub mod files;

mod decode;
mod gate;
mod labels;

use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt, fs,
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use ort::{
    environment::Environment,
    ep,
    session::{
        Session,
        builder::{GraphOptimizationLevel, SessionBuilder},
    },
    value::Tensor,
};
use rayon::prelude::*;
use tokenizers::Tokenizer;

use self::{
    decode::{Tokens, pool},
    gate::{CACHE_CAPACITY, Cache, RawSpan, key, worth_running},
    labels::{LABELS, MODEL_KINDS},
};
use super::{Detector, KindSet, Mode, Span};
use crate::{Error, Result};

/// Longest text the model reads in one piece. A longer one is cut after a whitespace.
const CHUNK_BYTES: usize = 256 << 10;

/// A run of this many bytes without whitespace is data, not prose: the model never reads it.
const BLOB_BYTES: usize = 1024;

/// Text the model reads at a time, in a call with more: it keeps the tokens of one group in
/// memory, not of all texts of the call.
const GROUP_BYTES: usize = 1 << 20;

/// Tokens of text in a window: the model reads 512 positions, two of them `<bos>` and `<eos>`.
const WINDOW: usize = 510;

/// Tokens two neighbouring windows share, so an entity at a seam is whole in one of them.
const OVERLAP: usize = 128;

/// How far a window starts after the one before it.
const STEP: usize = WINDOW - OVERLAP;

/// Token ids of the model's vocabulary.
const PAD: i64 = 0;
const EOS: i64 = 1;
const BOS: i64 = 2;

/// The text the warm-up and the measurement repeat up to the width they need.
const CALIBRATION_TEXT: &str =
    "Kontakt: Jan Kowalski, tel. 600 123 456, ul. D\u{142}uga 5, 00-238 Warszawa.";

/// The first shape a GPU runs is the one it runs fast, so it is spent on a tiny one, as
/// `(windows, positions per window)`, while the model loads.
const WARM_UP_SHAPE: (usize, usize) = (1, 8);

/// What the first load times on both devices: a large batch, where a GPU does best.
const PROBE_SHAPE: (usize, usize) = (8, 512);

/// The GPU is kept next to the CPU only when it runs the probe in at most this percent of the
/// CPU's time. The two together cost memory and a CPU thread to drive the GPU.
const GPU_MUST_TAKE_PERCENT: u32 = 80;

/// What one run of the model takes.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Windows.
    rows: usize,
    /// Positions: the windows times the width of the longest, which every one is padded to.
    positions: usize,
}

/// The CPU costs least per position at about a thousand positions a run and more beyond
/// (measured, for windows of 256 to 512 positions: 125 to 167 ms per 1000 positions at a
/// thousand, 200 to 235 at four thousand; short windows cost the same either way).
const CPU_LIMITS: Limits = Limits {
    rows: 64,
    positions: 1024,
};

/// The GPU wants as many as it can get: a run costs it about 70 ms to start, 4.5 ms per window and
/// 0.07 ms per position (RTX 3070). The row limit keeps a run of short windows from taking seconds.
const GPU_LIMITS: Limits = Limits {
    rows: 128,
    positions: 16384,
};

/// The least a run on the GPU is given, as what it would cost the CPU (see [`cost`]): below it the
/// run is mostly start-up. A call that would cost the CPU less than `GPU_SHARE` times this stays
/// on the CPU: about 85 short messages (measured: the GPU began to pay off between 80 and 100),
/// or three windows of 512 positions.
const GPU_FLOOR: usize = 1600;

/// The GPU takes at most one in this many of what is left (by cost). It is the slower of the two
/// on short windows and the faster on long ones, and takes the long ones; half of what is left
/// keeps the CPU busy until the GPU's last run is done. (Measured on 600 short messages and on a
/// document of 40 windows: a third was 12 to 14% slower, and a quarter or a sixth slower still.)
const GPU_SHARE: usize = 2;

/// Threads of the GPU's session, for the few operators `DirectML` leaves to the CPU: the CPU's
/// own session needs the cores.
const GPU_THREADS: usize = 2;

/// Where the model runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    /// The CPU only.
    Cpu,
    /// The CPU and the GPU (through `DirectML`) together: a small call runs on the CPU alone, a
    /// big one also gives the longest windows to the GPU.
    Hybrid,
}

impl Device {
    /// How [`files::DEVICE_FILE`] spells it.
    const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Hybrid => "hybrid",
        }
    }

    /// The device a [`files::DEVICE_FILE`] names. `gpu`, as an older version wrote it, is hybrid.
    fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "hybrid" | "gpu" => Some(Self::Hybrid),
            "cpu" => Some(Self::Cpu),
            _ => None,
        }
    }
}

/// What a [`NerDetector`] is up to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NerState {
    /// The model files are not on disk (or not verified): download them first.
    Missing,
    /// On disk, not in memory.
    Unloaded,
    /// In memory and detecting.
    Ready(Device),
    /// Loading or running failed. The detector finds nothing until [`NerDetector::release`] and
    /// a new [`NerDetector::load`].
    Failed(String),
}

/// The detection model as a [`Detector`]. Cloning shares the model.
#[derive(Clone)]
pub struct NerDetector {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    loaded: RwLock<Option<Arc<Loaded>>>,
    /// Held while loading, so two threads do not load the model twice.
    loading: Mutex<()>,
    failed: Mutex<Option<String>>,
    /// Why the GPU was given up, when it was.
    gpu_error: Mutex<Option<String>>,
    cache: Mutex<Cache>,
}

/// Something that runs the model on a batch: an ONNX Runtime session, or a stand-in in tests.
trait Runner: Send {
    /// Runs `input` and hands the logits (`rows * width * LABELS` values, window by window,
    /// position by position) to `read`.
    fn execute(&mut self, input: Input, read: &mut dyn FnMut(&[f32])) -> Result<()>;
}

impl Runner for Session {
    fn execute(&mut self, input: Input, read: &mut dyn FnMut(&[f32])) -> Result<()> {
        let Input {
            ids,
            mask,
            rows,
            width,
        } = input;
        let shape = [rows, width];
        let ids = Tensor::from_array((shape, ids)).map_err(model_err)?;
        let mask = Tensor::from_array((shape, mask)).map_err(model_err)?;
        let outputs = self
            .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
            .map_err(model_err)?;
        let logits = outputs
            .get("logits")
            .ok_or_else(|| Error::Model("the model gave no `logits`".into()))?;
        let (_, data) = logits.try_extract_tensor::<f32>().map_err(model_err)?;
        if data.len() != rows * width * LABELS {
            return Err(Error::Model(format!(
                "the model gave {} logits for {rows} windows of {width} tokens, not {LABELS} each",
                data.len(),
            )));
        }
        read(data);
        Ok(())
    }
}

/// One session and what it takes per run.
struct Lane {
    /// One run at a time.
    runner: Mutex<Box<dyn Runner>>,
    limits: Limits,
}

impl Lane {
    fn new(runner: impl Runner + 'static, limits: Limits) -> Self {
        Self {
            runner: Mutex::new(Box::new(runner)),
            limits,
        }
    }

    /// Runs `input`, waiting for the lane when something else is running on it.
    fn execute(&self, input: Input, read: &mut dyn FnMut(&[f32])) -> Result<()> {
        lock(&self.runner).execute(input, read)
    }
}

/// The model in memory.
struct Loaded {
    tokenizer: Tokenizer,
    /// Always there.
    cpu: Lane,
    /// There when the GPU helps.
    gpu: Option<Lane>,
    /// False once a run on the GPU failed: the CPU does everything from then on.
    gpu_works: AtomicBool,
}

impl Loaded {
    /// The GPU's lane, unless there is none or it was given up.
    fn gpu(&self) -> Option<&Lane> {
        self.gpu
            .as_ref()
            .filter(|_| self.gpu_works.load(Ordering::Relaxed))
    }

    fn device(&self) -> Device {
        if self.gpu().is_some() {
            Device::Hybrid
        } else {
            Device::Cpu
        }
    }

    fn open(dir: &Path) -> Result<Self> {
        let mut tokenizer =
            Tokenizer::from_file(dir.join(files::TOKENIZER_FILE)).map_err(model_err)?;
        // Windows are cut here, not by the tokenizer.
        tokenizer.with_truncation(None).map_err(model_err)?;
        tokenizer.with_padding(None);
        let sentence = tokenizer
            .encode(CALIBRATION_TEXT, false)
            .map_err(model_err)?;
        let (cpu, gpu) = lanes(dir, sentence.get_ids())?;
        Ok(Self {
            tokenizer,
            cpu,
            gpu_works: AtomicBool::new(gpu.is_some()),
            gpu,
        })
    }
}

// Hand-written: the model and its tokenizer have no useful `Debug`, and the state says it all.
impl fmt::Debug for NerDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NerDetector")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl NerDetector {
    /// A detector for the model in `dir` (see [`files::default_dir`]). Loads nothing.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                dir,
                loaded: RwLock::new(None),
                loading: Mutex::new(()),
                failed: Mutex::new(None),
                gpu_error: Mutex::new(None),
                cache: Mutex::new(Cache::new(CACHE_CAPACITY)),
            }),
        }
    }

    #[must_use]
    pub fn state(&self) -> NerState {
        if let Some(loaded) = self.loaded() {
            return NerState::Ready(loaded.device());
        }
        if let Some(message) = lock(&self.inner.failed).clone() {
            return NerState::Failed(message);
        }
        if files::is_installed(&self.inner.dir) {
            NerState::Unloaded
        } else {
            NerState::Missing
        }
    }

    /// Why the GPU stopped being used, when a run on it failed: the CPU has done everything since,
    /// and [`Self::state`] says [`Device::Cpu`]. Cleared by [`Self::release`] and by a load.
    #[must_use]
    pub fn gpu_error(&self) -> Option<String> {
        lock(&self.inner.gpu_error).clone()
    }

    /// Loads the model into memory and returns where it runs. Does nothing when it is loaded
    /// already. The first load on a machine also measures the GPU against the CPU, which takes a
    /// few seconds more; later loads read the outcome from [`files::DEVICE_FILE`].
    ///
    /// A failure is also remembered: [`Self::state`] reports it, and detecting finds nothing
    /// until [`Self::release`].
    ///
    /// # Errors
    /// `Model` when the model is not downloaded, or fails to load.
    pub fn load(&self) -> Result<Device> {
        let _loading = lock(&self.inner.loading);
        if let Some(loaded) = self.loaded() {
            return Ok(loaded.device());
        }
        if !files::is_installed(&self.inner.dir) {
            return Err(Error::Model("not downloaded".into()));
        }
        match Loaded::open(&self.inner.dir) {
            Ok(loaded) => {
                let device = loaded.device();
                *write(&self.inner.loaded) = Some(Arc::new(loaded));
                *lock(&self.inner.failed) = None;
                *lock(&self.inner.gpu_error) = None;
                Ok(device)
            }
            Err(error) => {
                *lock(&self.inner.failed) = Some(message(&error));
                Err(error)
            }
        }
    }

    /// Frees the model and everything remembered from it, and forgets a failure so that the next
    /// [`Self::load`] starts clean. Waits for a load in progress.
    pub fn release(&self) {
        let _loading = lock(&self.inner.loading);
        *write(&self.inner.loaded) = None;
        lock(&self.inner.cache).clear();
        *lock(&self.inner.failed) = None;
        *lock(&self.inner.gpu_error) = None;
    }

    fn loaded(&self) -> Option<Arc<Loaded>> {
        read(&self.inner.loaded).clone()
    }

    /// The loaded model, loading it first when nobody has yet (so the command line needs no
    /// setup). `None` when it failed earlier or fails now: the caller finds nothing.
    fn ready(&self) -> Option<Arc<Loaded>> {
        if let Some(loaded) = self.loaded() {
            return Some(loaded);
        }
        if lock(&self.inner.failed).is_some() {
            return None;
        }
        self.load().ok()?;
        self.loaded()
    }

    /// Records a failure of the model and drops it from memory.
    fn fail(&self, error: &Error) {
        *write(&self.inner.loaded) = None;
        *lock(&self.inner.failed) = Some(message(error));
    }
}

impl Detector for NerDetector {
    fn detect(&self, text: &str, mode: Mode) -> Vec<Span> {
        self.detect_batch(&[text], mode, KindSet::ALL, &[])
            .pop()
            .unwrap_or_default()
    }

    fn detect_batch(
        &self,
        texts: &[&str],
        mode: Mode,
        wanted: KindSet,
        taken: &[Vec<Span>],
    ) -> Vec<Vec<Span>> {
        let mut spans = vec![Vec::new(); texts.len()];
        if mode == Mode::Deanonymize || !wanted.intersects(MODEL_KINDS) {
            return spans;
        }
        let jobs = plan(texts, taken);
        if jobs.is_empty() {
            return spans;
        }
        let found = self.find(&jobs);
        for (job, raw) in jobs.iter().zip(&found) {
            spans[job.text].extend(
                raw.iter()
                    .filter(|r| wanted.contains(r.kind))
                    .map(|r| Span {
                        start: job.base + r.start as usize,
                        end: job.base + r.end as usize,
                        kind: r.kind,
                    }),
            );
        }
        for (own, claimed) in spans.iter_mut().zip(taken) {
            own.retain(|span| !overlaps(claimed, span));
        }
        spans
    }
}

impl NerDetector {
    /// What the model finds in each job's text: from the cache, else from the model.
    fn find(&self, jobs: &[Job<'_>]) -> Vec<Arc<[RawSpan]>> {
        let mut found: Vec<Option<Arc<[RawSpan]>>> = {
            let cache = lock(&self.inner.cache);
            jobs.iter().map(|job| cache.get(&job.key)).collect()
        };
        // Equal texts in one call run once.
        let mut first_of: HashMap<[u8; 32], usize> = HashMap::new();
        let mut misses: Vec<usize> = Vec::new();
        for (i, job) in jobs.iter().enumerate() {
            if found[i].is_none() && *first_of.entry(job.key).or_insert(i) == i {
                misses.push(i);
            }
        }
        let sizes: Vec<usize> = misses.iter().map(|&i| jobs[i].chunk.len()).collect();
        for group in groups(&sizes, GROUP_BYTES) {
            // A failure in an earlier group leaves nothing to run on.
            let Some(loaded) = self.ready() else {
                break;
            };
            let members = &misses[group];
            let texts: Vec<&str> = members.iter().map(|&i| jobs[i].chunk).collect();
            let computed = self.compute(&loaded, &texts);
            let mut cache = lock(&self.inner.cache);
            for (&i, spans) in members.iter().zip(computed) {
                if let Some(spans) = spans {
                    let spans: Arc<[RawSpan]> = spans.into();
                    cache.insert(jobs[i].key, Arc::clone(&spans));
                    found[i] = Some(spans);
                }
            }
        }
        for (i, job) in jobs.iter().enumerate() {
            if found[i].is_none()
                && let Some(&first) = first_of.get(&job.key)
            {
                let shared = found[first].clone();
                found[i] = shared;
            }
        }
        found
            .into_iter()
            .map(|spans| spans.unwrap_or_else(|| Arc::from([])))
            .collect()
    }

    /// Runs the model over `texts`. `None` for a text the model could not finish, after an error
    /// that is recorded and leaves the detector failed.
    fn compute(&self, loaded: &Loaded, texts: &[&str]) -> Vec<Option<Vec<RawSpan>>> {
        let encoded: Vec<Result<tokenizers::Encoding>> = texts
            .par_iter()
            .map(|text| loaded.tokenizer.encode(*text, false).map_err(model_err))
            .collect();
        let mut encodings = Vec::with_capacity(texts.len());
        for encoding in encoded {
            match encoding {
                Ok(encoding) => encodings.push(encoding),
                Err(error) => {
                    self.fail(&error);
                    return vec![None; texts.len()];
                }
            }
        }

        let mut windows: Vec<Window> = Vec::new();
        for (text, encoding) in encodings.iter().enumerate() {
            for tokens in windows_of(encoding.len()) {
                windows.push(Window { text, tokens });
            }
        }
        // Longest first: a batch pads little, and the two ends of the list are what the GPU and
        // the CPU are each best at.
        windows.sort_by_key(|w| Reverse(w.tokens.len()));
        let lens: Vec<usize> = windows.iter().map(|w| w.tokens.len()).collect();
        let queue = Queue::new(&lens);
        let shared = Shared {
            texts,
            encodings: &encodings,
            windows: &windows,
        };

        let mut pending = vec![0usize; texts.len()];
        for window in &windows {
            pending[window.text] += 1;
        }
        let mut tokens: Vec<Tokens> = texts.iter().map(|_| Tokens::default()).collect();
        for part in self.run_windows(loaded, &shared, &queue) {
            if let Some(error) = &part.failure {
                self.fail(error);
            }
            for range in &part.done {
                for window in &windows[range.clone()] {
                    pending[window.text] = pending[window.text].saturating_sub(1);
                }
            }
            for (all, theirs) in tokens.iter_mut().zip(part.tokens) {
                all.extend(theirs);
            }
        }

        tokens
            .into_par_iter()
            .zip(texts.par_iter())
            .zip(pending)
            .map(|((tokens, text), pending)| (pending == 0).then(|| tokens.decode(text)))
            .collect()
    }

    /// Runs the windows `queue` holds. The CPU always works on them, from the shortest end; a call
    /// that is big enough also starts the GPU, from the longest end. Returns what each did.
    fn run_windows(&self, loaded: &Loaded, shared: &Shared<'_>, queue: &Queue<'_>) -> Vec<Worked> {
        let gpu = loaded
            .gpu()
            .filter(|_| queue.remaining() >= GPU_FLOOR * GPU_SHARE);
        let mut parts = std::thread::scope(|scope| {
            let gpu =
                gpu.map(|lane| scope.spawn(move || self.gpu_worker(loaded, lane, shared, queue)));
            let cpu = cpu_worker(&loaded.cpu, shared, queue);
            let mut parts = vec![cpu];
            if let Some(handle) = gpu {
                parts.push(match handle.join() {
                    Ok(part) => part,
                    Err(payload) => std::panic::resume_unwind(payload),
                });
            }
            parts
        });
        // Windows the GPU handed back when a run on it failed are still in the queue: the CPU
        // runs them now.
        let cpu_works = parts.first().is_some_and(|cpu| cpu.failure.is_none());
        if cpu_works && !queue.is_empty() {
            parts.push(cpu_worker(&loaded.cpu, shared, queue));
        }
        parts
    }

    /// Takes batches off the longest end of the queue and runs them on the GPU, until there are
    /// no more that are worth it. A run that fails gives its windows back and ends the GPU's work
    /// for good.
    fn gpu_worker(
        &self,
        loaded: &Loaded,
        lane: &Lane,
        shared: &Shared<'_>,
        queue: &Queue<'_>,
    ) -> Worked {
        let mut part = Worked::new(shared.texts.len());
        // Another call may be using the GPU: this one leaves it alone and the CPU does the work.
        let Some(mut runner) = try_lock(&lane.runner) else {
            return part;
        };
        while let Some(batch) = queue.take_front(lane.limits, GPU_FLOOR, GPU_SHARE) {
            match run_batch(&mut **runner, shared, &batch, &mut part.tokens) {
                Ok(()) => part.done.push(batch),
                Err(error) => {
                    queue.give_back(batch.start);
                    loaded.gpu_works.store(false, Ordering::Relaxed);
                    *lock(&self.inner.gpu_error) = Some(message(&error));
                    break;
                }
            }
        }
        part
    }
}

/// Takes batches off the shortest end of the queue and runs them on the CPU, until the queue is
/// empty. A failure here is the model's: it ends the CPU's work and is reported.
fn cpu_worker(lane: &Lane, shared: &Shared<'_>, queue: &Queue<'_>) -> Worked {
    let mut part = Worked::new(shared.texts.len());
    while let Some(batch) = queue.take_back(lane.limits) {
        // Not held between batches, so that other calls get their turn.
        let mut runner = lock(&lane.runner);
        match run_batch(&mut **runner, shared, &batch, &mut part.tokens) {
            Ok(()) => part.done.push(batch),
            Err(error) => {
                part.failure = Some(error);
                break;
            }
        }
    }
    part
}

/// Runs the windows `batch` of `shared` and adds what the model made of them to `tokens`, which
/// has an entry per text.
fn run_batch(
    runner: &mut dyn Runner,
    shared: &Shared<'_>,
    batch: &Range<usize>,
    tokens: &mut [Tokens],
) -> Result<()> {
    let windows = &shared.windows[batch.clone()];
    let input = Input::of(windows, shared.encodings);
    let width = input.width;
    runner.execute(input, &mut |logits| {
        absorb(
            logits,
            width,
            windows,
            shared.encodings,
            shared.texts,
            tokens,
        );
    })
}

/// What the workers of one call read: the texts, their tokens and the windows over them.
struct Shared<'a> {
    texts: &'a [&'a str],
    encodings: &'a [tokenizers::Encoding],
    windows: &'a [Window],
}

/// What one worker did in a call.
struct Worked {
    /// What the model made of the windows it ran, per text of the call.
    tokens: Vec<Tokens>,
    /// The windows it ran, as ranges of the sorted list.
    done: Vec<Range<usize>>,
    /// Why it stopped early. Only the CPU sets it: the GPU's failures are not the model's.
    failure: Option<Error>,
}

impl Worked {
    fn new(texts: usize) -> Self {
        Self {
            tokens: (0..texts).map(|_| Tokens::default()).collect(),
            done: Vec::new(),
            failure: None,
        }
    }
}

/// What a window of `positions` positions costs the CPU, in positions of a short window. The
/// model reads every position and each one attends over the whole window, so a long window costs
/// more per position (measured on a Ryzen 5 9600X: 0.10 ms per position at 35 positions a window,
/// 0.23 at 512). The GPU is started for a call, and given its share of it, by what the call would
/// cost the CPU: two long windows are worth it, as are a hundred short ones.
fn cost(positions: usize) -> usize {
    positions + positions * positions / 380
}

/// The windows of a call that wait to be run, longest first. The GPU takes from the front (the
/// longest, which it runs best), the CPU from the back (the shortest). Each takes a batch at a
/// time, so the two meet in the middle, whatever their speeds.
struct Queue<'a> {
    /// Tokens per window, longest first.
    lens: &'a [usize],
    /// `prefix[i]`: what the first `i` windows cost the CPU (see [`cost`]).
    prefix: Vec<usize>,
    /// The windows not taken yet.
    open: Mutex<Range<usize>>,
}

impl<'a> Queue<'a> {
    fn new(lens: &'a [usize]) -> Self {
        let mut prefix = Vec::with_capacity(lens.len() + 1);
        let mut total = 0;
        prefix.push(total);
        for len in lens {
            // Plus `<bos>` and `<eos>`.
            total += cost(len + 2);
            prefix.push(total);
        }
        Self {
            lens,
            prefix,
            open: Mutex::new(0..lens.len()),
        }
    }

    /// What the windows not taken yet cost the CPU.
    fn remaining(&self) -> usize {
        let open = lock(&self.open);
        self.cost_of(&open)
    }

    fn cost_of(&self, open: &Range<usize>) -> usize {
        self.prefix[open.end] - self.prefix[open.start]
    }

    fn is_empty(&self) -> bool {
        lock(&self.open).is_empty()
    }

    /// The longest windows left, as many as fit `limits`, for the GPU. It is given at most one in
    /// `share` of what is left (by cost), so that the CPU, which gets the rest, finishes about
    /// when it does, and nothing under `floor`: a run that small is mostly start-up, and the CPU
    /// is quicker.
    fn take_front(&self, limits: Limits, floor: usize, share: usize) -> Option<Range<usize>> {
        let mut open = lock(&self.open);
        if open.is_empty() {
            return None;
        }
        let budget = self.cost_of(&open) / share;
        if budget < floor {
            return None;
        }
        // The batch is padded to its longest window, the first.
        let width = self.lens[open.start] + 2;
        let each = cost(width);
        let mut rows = 1;
        while rows < limits.rows
            && open.start + rows < open.end
            && (rows + 1) * width <= limits.positions
            && (rows + 1) * each <= budget
        {
            rows += 1;
        }
        let batch = open.start..open.start + rows;
        open.start += rows;
        Some(batch)
    }

    /// The shortest windows left, as many as fit `limits`, for the CPU.
    fn take_back(&self, limits: Limits) -> Option<Range<usize>> {
        let mut open = lock(&self.open);
        if open.is_empty() {
            return None;
        }
        // The batch is padded to its longest window, the first of it: the one before the batch
        // so far is what the next window would make the width.
        let mut rows = 1;
        while rows < limits.rows
            && open.end - rows > open.start
            && (rows + 1) * (self.lens[open.end - rows - 1] + 2) <= limits.positions
        {
            rows += 1;
        }
        open.end -= rows;
        Some(open.end..open.end + rows)
    }

    /// Puts back the windows from `from` on, which the GPU took and could not run. Only the GPU
    /// moves the front, and `from` is where its last batch began.
    fn give_back(&self, from: usize) {
        let mut open = lock(&self.open);
        open.start = open.start.min(from);
    }
}

/// The session of the CPU, and the one of the GPU when it helps: what an earlier load chose,
/// else what a measurement of both says.
fn lanes(dir: &Path, ids: &[u32]) -> Result<(Lane, Option<Lane>)> {
    let graph = dir.join(files::GRAPH_FILE);
    let choice_file = dir.join(files::DEVICE_FILE);
    let saved = fs::read_to_string(&choice_file)
        .ok()
        .and_then(|text| Device::parse(&text));
    if saved == Some(Device::Cpu) {
        return Ok((build_cpu(&graph)?, None));
    }
    let warm_up = Input::filled(ids, WARM_UP_SHAPE.0, WARM_UP_SHAPE.1).ok_or_else(no_tokens)?;
    let (cpu, gpu) = build_both(&graph, &warm_up);
    let cpu = cpu?;
    if saved.is_some() {
        if gpu.is_err() {
            // The GPU or its driver changed: measure again next time, run on the CPU now.
            let _ = fs::remove_file(&choice_file);
        }
        return Ok((cpu, gpu.ok()));
    }
    let gpu = match gpu {
        Ok(gpu) if gpu_helps(&cpu, &gpu, ids)? => Some(gpu),
        _ => None,
    };
    let device = if gpu.is_some() {
        Device::Hybrid
    } else {
        Device::Cpu
    };
    // Best effort: without the file the next load measures again.
    let _ = fs::write(&choice_file, device.name());
    Ok((cpu, gpu))
}

/// Builds the CPU's session and the GPU's at the same time, the GPU's in a thread of its own:
/// it takes the longest, and its warm-up run (a GPU builds its kernels on the first run) goes in
/// the same thread. A GPU that does not build or run is no GPU.
fn build_both(graph: &Path, warm_up: &Input) -> (Result<Lane>, Result<Lane>) {
    std::thread::scope(|scope| {
        let gpu = scope.spawn(|| -> Result<Lane> {
            let lane = build_gpu(graph)?;
            lane.execute(warm_up.clone(), &mut |_| ())?;
            Ok(lane)
        });
        let cpu = build_cpu(graph);
        let gpu = match gpu.join() {
            Ok(gpu) => gpu,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        (cpu, gpu)
    })
}

/// Whether the GPU is worth keeping next to the CPU: on a large batch, where it does best, it
/// must be clearly faster. A GPU that fails the batch is no help; a CPU that fails it is an
/// error.
fn gpu_helps(cpu: &Lane, gpu: &Lane, ids: &[u32]) -> Result<bool> {
    let probe = Input::filled(ids, PROBE_SHAPE.0, PROBE_SHAPE.1).ok_or_else(no_tokens)?;
    let start = Instant::now();
    cpu.execute(probe.clone(), &mut |_| ())?;
    let cpu_time = start.elapsed();
    // The better of two runs: a GPU may need one to bring its clocks up.
    let mut gpu_time = Duration::MAX;
    for _ in 0..2 {
        let start = Instant::now();
        if gpu.execute(probe.clone(), &mut |_| ()).is_err() {
            return Ok(false);
        }
        gpu_time = gpu_time.min(start.elapsed());
    }
    Ok(gpu_time * 100 < cpu_time * GPU_MUST_TAKE_PERCENT)
}

fn no_tokens() -> Error {
    Error::Model("the calibration text has no tokens".into())
}

fn build_cpu(graph: &Path) -> Result<Lane> {
    let mut builder = session_builder(GraphOptimizationLevel::Level3)?
        .with_intra_threads(cpu_threads())
        .map_err(model_err)?;
    lane(
        builder.commit_from_file(graph).map_err(model_err)?,
        CPU_LIMITS,
    )
}

fn build_gpu(graph: &Path) -> Result<Lane> {
    // `DirectML` allows neither memory patterns nor parallel execution. The basic graph
    // optimizations: on an RTX 3070 they ran batches of up to 4096 positions 13 to 27% faster
    // than the higher levels, and the biggest ones (16384) about 8% slower; on whole calls the
    // highest level was 15 to 30% slower than the basic one. One to six threads made no
    // difference, nor did spinning.
    let mut builder = session_builder(GraphOptimizationLevel::Level1)?
        .with_intra_threads(GPU_THREADS)
        .map_err(model_err)?
        .with_intra_op_spinning(false)
        .map_err(model_err)?
        .with_execution_providers([ep::DirectML::default()
            .with_performance_preference(ep::directml::PerformancePreference::HighPerformance)
            .build()
            .error_on_failure()])
        .map_err(model_err)?
        .with_memory_pattern(false)
        .map_err(model_err)?
        .with_parallel_execution(false)
        .map_err(model_err)?;
    lane(
        builder.commit_from_file(graph).map_err(model_err)?,
        GPU_LIMITS,
    )
}

fn session_builder(level: GraphOptimizationLevel) -> Result<SessionBuilder> {
    Session::builder(environment()?)
        .map_err(model_err)?
        .with_optimization_level(level)
        .map_err(model_err)?
        .with_inter_threads(1)
        .map_err(model_err)
}

/// `session` as a lane, after a look at its inputs and outputs.
fn lane(session: Session, limits: Limits) -> Result<Lane> {
    for input in ["input_ids", "attention_mask"] {
        if !session.inputs().iter().any(|i| i.name() == input) {
            return Err(Error::Model(format!("the model has no `{input}` input")));
        }
    }
    if !session.outputs().iter().any(|o| o.name() == "logits") {
        return Err(Error::Model("the model has no `logits` output".into()));
    }
    Ok(Lane::new(session, limits))
}

/// Two thirds of the logical processors, so that the model leaves some to what the user is doing.
/// Measured on 12 logical processors, 8 threads against 6: a call of a few messages 13% faster,
/// big calls 4 to 6% faster, one message 5% slower (8.1 ms against 7.7); 12 threads made one
/// message 17% slower.
fn cpu_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| (n.get() * 2 / 3).max(1))
}

/// The one ONNX Runtime environment of the process (there can be only one), without telemetry.
fn environment() -> Result<&'static Environment> {
    static ENVIRONMENT: LazyLock<std::result::Result<Environment, String>> = LazyLock::new(|| {
        ort::init()
            .with_name("piikey")
            .with_telemetry(false)
            .build()
            .map_err(|error| error.to_string())
    });
    ENVIRONMENT
        .as_ref()
        .map_err(|error| Error::Model(error.clone()))
}

/// One text to run: a text of the batch, or a piece of a long one.
struct Job<'a> {
    /// Index into the texts of the call.
    text: usize,
    /// Where `chunk` starts in that text.
    base: usize,
    chunk: &'a str,
    key: [u8; 32],
}

/// The pieces of `texts` the model should read, in order.
fn plan<'a>(texts: &[&'a str], taken: &[Vec<Span>]) -> Vec<Job<'a>> {
    let mut jobs = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        let claimed: &[Span] = taken.get(i).map_or(&[], Vec::as_slice);
        for (base, chunk) in chunks(text) {
            let free = if chunk.len() == text.len() {
                worth_running(chunk, claimed)
            } else {
                worth_running(chunk, &relative(claimed, base, chunk.len()))
            };
            if free {
                jobs.push(Job {
                    text: i,
                    base,
                    chunk,
                    key: key(chunk),
                });
            }
        }
    }
    jobs
}

/// The parts of `text` the model reads, each with its offset: the text without its blobs, cut
/// into pieces of at most `CHUNK_BYTES`.
fn chunks(text: &str) -> impl Iterator<Item = (usize, &str)> {
    prose(text)
        .into_iter()
        .flat_map(|(base, part)| split(part).map(move |(at, piece)| (base + at, piece)))
}

/// `text` without its blobs, as `(offset, part)`. A blob is a run of `BLOB_BYTES` or more bytes
/// without ASCII whitespace: base64, hex, a minified file. It says nothing about people and, run
/// through the model, would cost minutes. Every part starts and ends at whitespace or at the
/// edge of the text, so no word is cut; a part of whitespace only is dropped.
fn prose(text: &str) -> Vec<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut keep = |from: usize, to: usize| {
        let part = &text[from..to];
        if !part.trim_ascii().is_empty() {
            parts.push((from, part));
        }
    };
    let mut part_start = 0;
    let mut run_start = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if !byte.is_ascii_whitespace() {
            continue;
        }
        if i - run_start >= BLOB_BYTES {
            keep(part_start, run_start);
            part_start = i;
        }
        run_start = i + 1;
    }
    if bytes.len() - run_start >= BLOB_BYTES {
        keep(part_start, run_start);
        part_start = bytes.len();
    }
    keep(part_start, bytes.len());
    parts
}

/// `text` as pieces of at most `CHUNK_BYTES`, each with its offset. A piece ends after a
/// whitespace when it can, so no word is cut.
fn split(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let rest = text.get(at..).filter(|rest| !rest.is_empty())?;
        let len = if rest.len() <= CHUNK_BYTES {
            rest.len()
        } else {
            let mut limit = CHUNK_BYTES;
            while !rest.is_char_boundary(limit) {
                limit -= 1;
            }
            rest[..limit]
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace())
                .map_or(limit, |(i, c)| i + c.len_utf8())
        };
        let piece = (at, &rest[..len]);
        at += len;
        Some(piece)
    })
}

/// `sizes` as runs of consecutive entries that together stay within `limit`, as ranges of
/// indices. An entry over the limit is a run of its own.
fn groups(sizes: &[usize], limit: usize) -> Vec<Range<usize>> {
    let mut groups = Vec::new();
    let mut from = 0;
    let mut total = 0;
    for (i, &size) in sizes.iter().enumerate() {
        if total > 0 && total + size > limit {
            groups.push(from..i);
            from = i;
            total = 0;
        }
        total += size;
    }
    if from < sizes.len() {
        groups.push(from..sizes.len());
    }
    groups
}

/// The part of `claimed` that lies in `base..base + len`, relative to `base`.
fn relative(claimed: &[Span], base: usize, len: usize) -> Vec<Span> {
    claimed
        .iter()
        .filter(|span| span.end > base && span.start < base + len)
        .map(|span| Span {
            start: span.start.saturating_sub(base),
            end: (span.end - base).min(len),
            kind: span.kind,
        })
        .collect()
}

/// True when `span` shares a byte with a span of `claimed`, which is sorted and disjoint.
fn overlaps(claimed: &[Span], span: &Span) -> bool {
    let next = claimed.partition_point(|c| c.end <= span.start);
    claimed.get(next).is_some_and(|c| c.start < span.end)
}

/// A window: some of the tokens of one text.
struct Window {
    /// Index into the texts being run.
    text: usize,
    tokens: Range<usize>,
}

/// The windows over `tokens` tokens: each `WINDOW` long, each starting `STEP` after the one
/// before, the last one reaching the end.
fn windows_of(tokens: usize) -> Vec<Range<usize>> {
    let mut windows = Vec::new();
    let mut from = 0;
    while from < tokens {
        let to = (from + WINDOW).min(tokens);
        windows.push(from..to);
        if to == tokens {
            break;
        }
        from += STEP;
    }
    windows
}

/// The inputs of one run: `rows` windows of `width` positions, padded on the right.
#[derive(Clone)]
struct Input {
    ids: Vec<i64>,
    mask: Vec<i64>,
    rows: usize,
    width: usize,
}

impl Input {
    /// Each window wrapped in `<bos>` and `<eos>`; the longest, first, sets the width.
    fn of(batch: &[Window], encodings: &[tokenizers::Encoding]) -> Self {
        let width = batch.first().map_or(2, |w| w.tokens.len() + 2);
        let mut ids = vec![PAD; batch.len() * width];
        let mut mask = vec![0; batch.len() * width];
        for (row, window) in batch.iter().enumerate() {
            let tokens = encodings[window.text]
                .get_ids()
                .get(window.tokens.clone())
                .unwrap_or_default();
            let line = row * width;
            ids[line] = BOS;
            for (slot, &id) in ids[line + 1..].iter_mut().zip(tokens) {
                *slot = i64::from(id);
            }
            ids[line + 1 + tokens.len()] = EOS;
            mask[line..line + tokens.len() + 2].fill(1);
        }
        Self {
            ids,
            mask,
            rows: batch.len(),
            width,
        }
    }

    /// `rows` copies of `ids`, cycled to fill the width, in `<bos>` and `<eos>`.
    fn filled(ids: &[u32], rows: usize, width: usize) -> Option<Self> {
        if ids.is_empty() || width < 2 {
            return None;
        }
        let mut all = Vec::with_capacity(rows * width);
        for _ in 0..rows {
            all.push(BOS);
            all.extend(ids.iter().cycle().take(width - 2).map(|&id| i64::from(id)));
            all.push(EOS);
        }
        Some(Self {
            mask: vec![1; all.len()],
            ids: all,
            rows,
            width,
        })
    }
}

/// Feeds the probabilities of every token of a batch to the text it belongs to.
fn absorb(
    logits: &[f32],
    width: usize,
    batch: &[Window],
    encodings: &[tokenizers::Encoding],
    texts: &[&str],
    tokens: &mut [Tokens],
) {
    let (positions, _) = logits.as_chunks::<LABELS>();
    for (row, window) in batch.iter().enumerate() {
        let offsets = encodings[window.text]
            .get_offsets()
            .get(window.tokens.clone())
            .unwrap_or_default();
        let first = row * width + 1;
        for (&(start, end), logits) in offsets.iter().zip(&positions[first..]) {
            tokens[window.text].push(texts[window.text], start, end, &pool(logits));
        }
    }
}

fn model_err(error: impl fmt::Display) -> Error {
    Error::Model(error.to_string())
}

/// An error as shown to the user, without the "detection model:" prefix of its `Display`.
fn message(error: &Error) -> String {
    match error {
        Error::Model(text) => text.clone(),
        other => other.to_string(),
    }
}

// A panic while holding one of these locks cannot leave the data half-written: take it anyway.
fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The lock when nobody holds it, `None` when somebody does.
fn try_lock<T: ?Sized>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use tokenizers::{models::wordlevel::WordLevel, pre_tokenizers::whitespace::Whitespace};

    use super::*;
    use crate::detect::EntityKind;

    fn missing() -> NerDetector {
        NerDetector::new(
            std::env::temp_dir().join(format!("piikey-ner-missing-{}", std::process::id())),
        )
    }

    fn text_of(len: usize) -> String {
        "word ".repeat(len / 5 + 1)
    }

    #[test]
    fn windows_cover_the_tokens_with_the_overlap_and_end_at_the_last_token() {
        assert!(windows_of(0).is_empty());
        assert_eq!(windows_of(1).first(), Some(&(0..1)));
        assert_eq!(windows_of(1).len(), 1);
        assert_eq!(windows_of(510).first(), Some(&(0..510)));
        assert_eq!(windows_of(510).len(), 1);
        assert_eq!(windows_of(511), [0..510, 382..511]);
        assert_eq!(windows_of(892), [0..510, 382..892]);
        assert_eq!(windows_of(893), [0..510, 382..892, 764..893]);
        for tokens in [1, 100, 509, 510, 511, 1000, 5000, 100_000] {
            let windows = windows_of(tokens);
            assert_eq!(windows.first().map(|w| w.start), Some(0));
            assert_eq!(windows.last().map(|w| w.end), Some(tokens));
            for w in &windows {
                assert!(!w.is_empty() && w.len() <= WINDOW);
            }
            for pair in windows.windows(2) {
                assert_eq!(pair[1].start, pair[0].start + STEP);
                assert!(pair[0].end - pair[1].start >= OVERLAP || pair[0].end == tokens);
            }
        }
    }

    // --- the queue the CPU and the GPU share ----------------------------------------------

    fn limits(rows: usize, positions: usize) -> Limits {
        Limits { rows, positions }
    }

    /// Window lengths from 1 to 510, longest first, from a seed.
    fn lens_of(count: usize, seed: u64) -> Vec<usize> {
        let mut state = seed;
        let mut lens: Vec<usize> = (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                usize::try_from((state >> 33) % 510).unwrap_or(0) + 1
            })
            .collect();
        lens.sort_unstable_by(|a, b| b.cmp(a));
        lens
    }

    #[test]
    fn the_cpu_takes_the_shortest_windows_padded_to_the_longest_of_the_batch() {
        let lens = [510, 510, 400, 300, 120, 50, 3, 1];
        let queue = Queue::new(&lens);
        let cpu = limits(64, 1024);
        // 1, 3, 50 and 120 tokens: 4 x 122 = 488 positions; the 300 would make it 5 x 302.
        assert_eq!(queue.take_back(cpu), Some(4..8));
        // 300 and 400: 2 x 402 = 804; a 510 would make it 3 x 512.
        assert_eq!(queue.take_back(cpu), Some(2..4));
        // Two windows of 512 positions are exactly 1024.
        assert_eq!(queue.take_back(cpu), Some(0..2));
        assert_eq!(queue.take_back(cpu), None);
        assert!(queue.is_empty());
        assert_eq!(queue.remaining(), 0);
    }

    #[test]
    fn the_row_limit_binds_for_short_windows_and_one_window_is_always_taken() {
        let lens = [10; 100];
        let queue = Queue::new(&lens);
        assert_eq!(queue.take_back(limits(16, 16384)), Some(84..100));
        // A window wider than the whole budget is still run, alone.
        let wide = [510, 510];
        let queue = Queue::new(&wide);
        assert_eq!(queue.take_back(limits(64, 100)), Some(1..2));
        assert_eq!(queue.take_back(limits(64, 100)), Some(0..1));
    }

    #[test]
    fn a_long_window_costs_the_cpu_more_per_position_than_a_short_one() {
        assert_eq!(cost(0), 0);
        assert_eq!(cost(10), 10);
        // 512 positions cost what 1200 short ones do.
        assert_eq!(cost(512), 1201);
        for width in 1..512 {
            assert!(cost(width + 1) > cost(width), "{width}");
        }
        let per_position = |width: usize| cost(width) * 1000 / width;
        assert!(per_position(512) > 2 * per_position(35));
    }

    #[test]
    fn the_gpu_takes_the_longest_windows_but_never_more_than_its_share() {
        let lens = [510; 10];
        let queue = Queue::new(&lens);
        let one = cost(512);
        assert_eq!(queue.remaining(), 10 * one);
        let gpu = limits(128, 16384);
        // Half of ten windows: five.
        assert_eq!(queue.take_front(gpu, one, 2), Some(0..5));
        // Half of five windows is two and a half: two.
        assert_eq!(queue.take_front(gpu, one, 2), Some(5..7));
        assert_eq!(queue.take_front(gpu, one, 2), Some(7..8));
        assert_eq!(queue.take_front(gpu, one, 2), Some(8..9));
        // Half of one window is under the floor: the last window is the CPU's.
        assert_eq!(queue.take_front(gpu, one, 2), None);
        assert_eq!(queue.remaining(), one);
        assert_eq!(queue.take_back(limits(64, 1024)), Some(9..10));
    }

    #[test]
    fn the_gpu_is_not_started_for_a_call_that_costs_the_cpu_little() {
        let start = |lens: &[usize]| {
            let queue = Queue::new(lens);
            let big_enough = queue.remaining() >= GPU_FLOOR * GPU_SHARE;
            let taken = queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE);
            assert_eq!(big_enough, taken.is_some());
            big_enough
        };
        // Two windows of 512 positions are not worth it, three are.
        assert!(!start(&[510; 2]));
        assert!(start(&[510; 3]));
        // Nor are a few dozen short messages, while a few hundred are.
        assert!(!start(&[33; 60]));
        assert!(start(&[33; 120]));
        assert!(!start(&[]));
    }

    #[test]
    fn a_batch_the_gpu_could_not_run_goes_back_to_the_front() {
        let lens = [510; 12];
        let queue = Queue::new(&lens);
        let first = queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE);
        assert!(first.is_some());
        queue.give_back(0);
        assert_eq!(queue.remaining(), 12 * cost(512));
        assert_eq!(
            queue.take_front(GPU_LIMITS, GPU_FLOOR, GPU_SHARE),
            first,
            "the same windows again"
        );
    }

    #[test]
    fn both_ends_together_take_every_window_once_and_stay_within_their_limits() {
        let (gpu, cpu) = (limits(128, 16384), limits(64, 1024));
        for (seed, count) in [(1, 5), (2, 40), (3, 300), (4, 1000), (5, 4000)] {
            let lens = lens_of(count, seed);
            let queue = Queue::new(&lens);
            let mut times = vec![0u8; count];
            let mut state = seed;
            loop {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let (batch, allowed) = if (state >> 40) % 3 == 0 {
                    (queue.take_front(gpu, 64, 2), gpu)
                } else {
                    (None, cpu)
                };
                let (batch, allowed) = match batch {
                    Some(batch) => (batch, allowed),
                    None => match queue.take_back(cpu) {
                        Some(batch) => (batch, cpu),
                        None => break,
                    },
                };
                assert!(batch.len() <= allowed.rows);
                // Sorted longest first: the first window of a batch sets the width.
                assert!(
                    batch.len() == 1 || batch.len() * (lens[batch.start] + 2) <= allowed.positions
                );
                for i in batch {
                    times[i] += 1;
                }
            }
            assert!(times.iter().all(|&n| n == 1), "seed {seed}");
            assert!(queue.is_empty());
        }
    }

    #[test]
    fn two_workers_pulling_from_both_ends_never_run_a_window_twice() {
        let lens = lens_of(30_000, 7);
        let queue = Queue::new(&lens);
        let seen: Vec<AtomicUsize> = lens.iter().map(|_| AtomicUsize::new(0)).collect();
        let note = |batch: Range<usize>| {
            for i in batch {
                seen[i].fetch_add(1, Ordering::SeqCst);
            }
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while let Some(batch) = queue.take_front(limits(128, 16384), 1024, 3) {
                    note(batch);
                }
            });
            while let Some(batch) = queue.take_back(limits(64, 1024)) {
                note(batch);
            }
        });
        assert!(queue.is_empty());
        assert!(seen.iter().all(|n| n.load(Ordering::SeqCst) == 1));
    }

    // --- the chunks the model reads -------------------------------------------------------

    #[test]
    fn short_texts_are_one_chunk() {
        let chunks: Vec<_> = chunks("Jan Jansen").collect();
        assert_eq!(chunks, [(0, "Jan Jansen")]);
        assert_eq!(super::chunks("").count(), 0);
        let big = text_of(CHUNK_BYTES);
        assert!(big.len() > CHUNK_BYTES);
        assert!(super::chunks(&big[..CHUNK_BYTES]).count() == 1);
    }

    #[test]
    fn long_texts_are_cut_after_whitespace_without_losing_or_repeating_a_byte() {
        let text = text_of(CHUNK_BYTES * 3 + 1234);
        let pieces: Vec<(usize, &str)> = chunks(&text).collect();
        assert!(pieces.len() >= 4);
        let mut rebuilt = String::new();
        let mut at = 0;
        for (base, piece) in &pieces {
            assert_eq!(*base, at);
            assert!(piece.len() <= CHUNK_BYTES);
            assert!(!piece.is_empty());
            at += piece.len();
            rebuilt.push_str(piece);
        }
        assert_eq!(rebuilt, text);
        for (_, piece) in &pieces[..pieces.len() - 1] {
            assert!(piece.ends_with(' '), "a piece ends after a whitespace");
        }
    }

    #[test]
    fn cutting_never_splits_a_character_and_copes_with_text_without_whitespace() {
        // Two-byte characters straddling the limit, and no whitespace at all.
        let text = "\u{e9}".repeat(CHUNK_BYTES);
        let pieces: Vec<(usize, &str)> = split(&text).collect();
        assert_eq!(
            pieces.iter().map(|(_, p)| p.len()).sum::<usize>(),
            text.len()
        );
        assert!(pieces.iter().all(|(_, p)| p.len() <= CHUNK_BYTES));
        assert!(pieces.len() >= 2);
        // Four-byte characters, whitespace first.
        let text = format!(" {}", "\u{1f600}".repeat(CHUNK_BYTES / 2));
        let total: usize = split(&text).map(|(_, p)| p.len()).sum();
        assert_eq!(total, text.len());
    }

    #[test]
    fn blobs_are_cut_out_and_the_text_around_them_keeps_its_offsets() {
        let blob = "A1b2".repeat(BLOB_BYTES / 4 + 1);
        assert!(blob.len() > BLOB_BYTES);
        let text = format!("Hello Jan {blob} and Piet {blob}\n{blob}");
        let pieces: Vec<(usize, &str)> = chunks(&text).collect();
        for (base, piece) in &pieces {
            assert_eq!(&text[*base..*base + piece.len()], *piece);
            assert!(!piece.contains("A1b2"), "a blob reached the model");
        }
        let words: Vec<&str> = pieces
            .iter()
            .flat_map(|(_, p)| p.split_whitespace())
            .collect();
        assert_eq!(words, ["Hello", "Jan", "and", "Piet"]);

        // Nothing but data: nothing to read.
        assert_eq!(chunks(&blob).count(), 0);
        assert_eq!(chunks(&format!("{blob} {blob}")).count(), 0);
        assert_eq!(chunks(&format!("  {blob}\n")).count(), 0);
    }

    #[test]
    fn a_run_is_data_from_the_blob_size_up_and_text_below_it() {
        let almost = "x".repeat(BLOB_BYTES - 1);
        assert_eq!(chunks(&almost).count(), 1);
        assert_eq!(chunks(&"x".repeat(BLOB_BYTES)).count(), 0);
        // Only ASCII whitespace ends a run: other runs of the size are data too.
        assert_eq!(chunks(&"\u{e9}".repeat(BLOB_BYTES / 2)).count(), 0);
        // Whitespace inside the data makes it prose again.
        let lines = format!(
            "{}\n{}",
            "x".repeat(BLOB_BYTES - 1),
            "y".repeat(BLOB_BYTES - 1)
        );
        assert_eq!(chunks(&lines).count(), 1);
    }

    #[test]
    fn blobs_at_the_edges_leave_the_prose_between() {
        let blob = "z".repeat(BLOB_BYTES);
        let text = format!("{blob} Jan Piet {blob}");
        let pieces: Vec<(usize, &str)> = chunks(&text).collect();
        assert_eq!(pieces, [(BLOB_BYTES, " Jan Piet ")]);
    }

    #[test]
    fn work_is_grouped_by_size_without_splitting_a_text() {
        let ranges = |pairs: &[(usize, usize)]| -> Vec<Range<usize>> {
            pairs.iter().map(|&(from, to)| from..to).collect()
        };
        assert!(groups(&[], 10).is_empty());
        assert_eq!(groups(&[3, 3, 3], 10), ranges(&[(0, 3)]));
        assert_eq!(groups(&[4, 4, 4], 10), ranges(&[(0, 2), (2, 3)]));
        assert_eq!(groups(&[20, 1, 1], 10), ranges(&[(0, 1), (1, 3)]));
        assert_eq!(groups(&[5, 20, 5], 10), ranges(&[(0, 1), (1, 2), (2, 3)]));
        assert_eq!(groups(&[10, 10], 10), ranges(&[(0, 1), (1, 2)]));
        assert_eq!(groups(&[10], 10), ranges(&[(0, 1)]));
        // Whatever the sizes, every entry is in exactly one group, in order.
        let sizes: Vec<usize> = (0..100).map(|i| (i * 37) % 23).collect();
        let all = groups(&sizes, 40);
        let mut next = 0;
        for group in &all {
            assert_eq!(group.start, next);
            assert!(group.end > group.start);
            next = group.end;
            let total: usize = sizes[group.clone()].iter().sum();
            assert!(total <= 40 || group.len() == 1, "{group:?}");
        }
        assert_eq!(next, sizes.len());
    }

    #[test]
    fn claimed_spans_are_made_relative_to_a_chunk() {
        let span = |start, end| Span {
            start,
            end,
            kind: EntityKind::Email,
        };
        let claimed = [span(2, 6), span(10, 20), span(30, 40)];
        let rel = relative(&claimed, 8, 20);
        assert_eq!(rel, [span(2, 12)]);
        assert_eq!(rel[0].kind, EntityKind::Email);
        assert_eq!(relative(&claimed, 6, 4), []);
        assert_eq!(relative(&claimed, 0, 100), claimed);
    }

    #[test]
    fn spans_that_share_a_byte_with_a_claimed_span_are_dropped() {
        let span = |start, end| Span {
            start,
            end,
            kind: EntityKind::Person,
        };
        let claimed = [span(5, 10), span(20, 30)];
        assert!(overlaps(&claimed, &span(0, 6)));
        assert!(overlaps(&claimed, &span(9, 12)));
        assert!(overlaps(&claimed, &span(22, 24)));
        assert!(overlaps(&claimed, &span(0, 100)));
        assert!(!overlaps(&claimed, &span(0, 5)));
        assert!(!overlaps(&claimed, &span(10, 20)));
        assert!(!overlaps(&claimed, &span(30, 40)));
        assert!(!overlaps(&[], &span(0, 5)));
    }

    #[test]
    fn calibration_input_is_cycled_and_wrapped() {
        let input = Input::filled(&[10, 11, 12], 2, 8);
        let Some(input) = input else {
            panic!("input for a non-empty sentence");
        };
        assert_eq!((input.rows, input.width), (2, 8));
        assert_eq!(input.ids.len(), 16);
        assert_eq!(&input.ids[..8], [BOS, 10, 11, 12, 10, 11, 12, EOS]);
        assert_eq!(&input.ids[8..], &input.ids[..8]);
        assert!(input.mask.iter().all(|&m| m == 1));
        assert!(Input::filled(&[], 2, 8).is_none());
        assert!(Input::filled(&[1], 2, 1).is_none());
    }

    #[test]
    fn the_device_choice_file_is_read_leniently() {
        assert_eq!(Device::parse("hybrid"), Some(Device::Hybrid));
        assert_eq!(Device::parse("cpu\r\n"), Some(Device::Cpu));
        assert_eq!(Device::parse(" hybrid "), Some(Device::Hybrid));
        // What an older version wrote for a GPU that won.
        assert_eq!(Device::parse("gpu"), Some(Device::Hybrid));
        assert_eq!(Device::parse(""), None);
        assert_eq!(Device::parse("tpu"), None);
        for device in [Device::Hybrid, Device::Cpu] {
            assert_eq!(Device::parse(device.name()), Some(device));
        }
    }

    // --- the whole pipeline, on stand-ins for the sessions --------------------------------

    /// The token the stand-in model takes for the start of a name.
    const NAME: u32 = 5;

    /// What a stand-in lane did.
    #[derive(Clone, Default)]
    struct Seen {
        runs: Arc<AtomicUsize>,
        windows: Arc<AtomicUsize>,
        started: Arc<AtomicBool>,
    }

    impl Seen {
        fn runs(&self) -> usize {
            self.runs.load(Ordering::SeqCst)
        }

        fn windows(&self) -> usize {
            self.windows.load(Ordering::SeqCst)
        }
    }

    /// Stands in for a session: marks every position whose token is `NAME` as the beginning of a
    /// person's name and every other as no entity.
    struct Fake {
        seen: Seen,
        /// Each run takes this long.
        pause: Duration,
        /// Runs from this one on (counting from 1) fail; 0 for never.
        fail_from: usize,
        /// Waits for this to be set before its first run, for at most two seconds, so that a test
        /// does not depend on which thread is quicker to start.
        wait_for: Option<Arc<AtomicBool>>,
    }

    impl Fake {
        fn new(pause: Duration) -> (Self, Seen) {
            let seen = Seen::default();
            let fake = Self {
                seen: seen.clone(),
                pause,
                fail_from: 0,
                wait_for: None,
            };
            (fake, seen)
        }
    }

    impl Runner for Fake {
        fn execute(&mut self, input: Input, read: &mut dyn FnMut(&[f32])) -> Result<()> {
            let run = self.seen.runs.fetch_add(1, Ordering::SeqCst) + 1;
            self.seen.started.store(true, Ordering::SeqCst);
            if run == 1
                && let Some(flag) = &self.wait_for
            {
                let start = Instant::now();
                while !flag.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(2) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            std::thread::sleep(self.pause);
            if self.fail_from != 0 && run >= self.fail_from {
                return Err(Error::Model("fake failure".into()));
            }
            self.seen.windows.fetch_add(input.rows, Ordering::SeqCst);
            let name = 1 + 2 * labels::TYPES
                .iter()
                .position(|t| *t == "PERSON_NAME")
                .unwrap_or(0);
            let mut logits = vec![0.0f32; input.rows * input.width * LABELS];
            for (token, row) in input.ids.iter().zip(logits.chunks_exact_mut(LABELS)) {
                let label = if *token == i64::from(NAME) { name } else { 0 };
                row[label] = 30.0;
            }
            read(&logits);
            Ok(())
        }
    }

    /// A detector over stand-in lanes, as if the model was loaded.
    fn detector(cpu: Fake, gpu: Option<Fake>) -> Result<NerDetector> {
        let vocab = [("[UNK]".to_owned(), 3), ("Jan".to_owned(), NAME)]
            .into_iter()
            .collect();
        let model = WordLevel::builder()
            .vocab(vocab)
            .unk_token("[UNK]".to_owned())
            .build()
            .map_err(model_err)?;
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(Whitespace));
        let ner = missing();
        *write(&ner.inner.loaded) = Some(Arc::new(Loaded {
            tokenizer,
            cpu: Lane::new(cpu, CPU_LIMITS),
            gpu_works: AtomicBool::new(gpu.is_some()),
            gpu: gpu.map(|gpu| Lane::new(gpu, GPU_LIMITS)),
        }));
        Ok(ner)
    }

    /// `count` different texts of 7 tokens (9 positions) and two names each.
    fn texts_of(count: usize, tag: &str) -> Vec<String> {
        (0..count)
            .map(|i| format!("Jan {tag}{i} wrote to Jan about {i}"))
            .collect()
    }

    /// The spans every text of `texts_of` has.
    fn names_in(text: &str) -> Vec<Span> {
        text.match_indices("Jan")
            .map(|(start, name)| Span {
                start,
                end: start + name.len(),
                kind: EntityKind::Person,
            })
            .collect()
    }

    fn detect_all(ner: &NerDetector, texts: &[String]) -> Vec<Vec<Span>> {
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        ner.detect_batch(&refs, Mode::Anonymize, KindSet::ALL, &[])
    }

    fn expected(texts: &[String]) -> Vec<Vec<Span>> {
        texts.iter().map(|text| names_in(text)).collect()
    }

    #[test]
    fn the_cpu_alone_finds_every_name() -> Result<()> {
        let (cpu, cpu_seen) = Fake::new(Duration::ZERO);
        let ner = detector(cpu, None)?;
        assert_eq!(ner.state(), NerState::Ready(Device::Cpu));
        let texts = texts_of(600, "a");
        assert_eq!(detect_all(&ner, &texts), expected(&texts));
        assert_eq!(cpu_seen.windows(), 600);
        Ok(())
    }

    #[test]
    fn a_big_call_uses_both_lanes_and_a_small_one_only_the_cpu() -> Result<()> {
        let (mut cpu, cpu_seen) = Fake::new(Duration::from_millis(2));
        let (gpu, gpu_seen) = Fake::new(Duration::from_millis(2));
        // The CPU does not start before the GPU has: both lanes are in use whoever is quicker.
        cpu.wait_for = Some(Arc::clone(&gpu_seen.started));
        let ner = detector(cpu, Some(gpu))?;
        assert_eq!(ner.state(), NerState::Ready(Device::Hybrid));

        // 600 windows of 9 positions are 5400: enough for the GPU to be started.
        let big = texts_of(600, "a");
        assert_eq!(detect_all(&ner, &big), expected(&big));
        assert!(gpu_seen.runs() >= 1, "the GPU ran nothing");
        assert!(cpu_seen.runs() >= 1, "the CPU ran nothing");
        assert_eq!(
            gpu_seen.windows() + cpu_seen.windows(),
            600,
            "every window ran exactly once"
        );

        // 20 windows are 180 positions: no reason to wake the GPU.
        let before = gpu_seen.runs();
        let small = texts_of(20, "b");
        assert_eq!(detect_all(&ner, &small), expected(&small));
        assert_eq!(gpu_seen.runs(), before);
        assert_eq!(ner.state(), NerState::Ready(Device::Hybrid));
        assert_eq!(ner.gpu_error(), None);
        Ok(())
    }

    #[test]
    fn a_gpu_that_fails_hands_its_windows_to_the_cpu_and_is_given_up() -> Result<()> {
        let (mut cpu, cpu_seen) = Fake::new(Duration::ZERO);
        let (mut gpu, gpu_seen) = Fake::new(Duration::from_millis(40));
        gpu.fail_from = 1;
        // The CPU does not start before the GPU has, and is done with everything else long
        // before the GPU's first run fails: what the GPU hands back is left for the CPU to find
        // in the queue afterwards.
        cpu.wait_for = Some(Arc::clone(&gpu_seen.started));
        let ner = detector(cpu, Some(gpu))?;
        let texts = texts_of(600, "a");
        assert_eq!(detect_all(&ner, &texts), expected(&texts));
        assert_eq!(gpu_seen.windows(), 0);
        assert_eq!(cpu_seen.windows(), 600, "the CPU ran all of it");
        assert_eq!(ner.gpu_error().as_deref(), Some("fake failure"));
        assert_eq!(ner.state(), NerState::Ready(Device::Cpu));

        // From then on the GPU is left alone, and the detector still works.
        let runs = gpu_seen.runs();
        let more = texts_of(600, "b");
        assert_eq!(detect_all(&ner, &more), expected(&more));
        assert_eq!(gpu_seen.runs(), runs);

        // A release forgets the error.
        ner.release();
        assert_eq!(ner.gpu_error(), None);
        Ok(())
    }

    #[test]
    fn a_gpu_that_fails_while_the_cpu_still_works_costs_nothing() -> Result<()> {
        let (mut cpu, cpu_seen) = Fake::new(Duration::from_millis(3));
        let (mut gpu, gpu_seen) = Fake::new(Duration::ZERO);
        gpu.fail_from = 1;
        cpu.wait_for = Some(Arc::clone(&gpu_seen.started));
        let ner = detector(cpu, Some(gpu))?;
        let texts = texts_of(600, "a");
        assert_eq!(detect_all(&ner, &texts), expected(&texts));
        assert_eq!(cpu_seen.windows(), 600);
        assert_eq!(ner.state(), NerState::Ready(Device::Cpu));
        Ok(())
    }

    #[test]
    fn a_cpu_that_fails_fails_the_detector_and_nothing_is_found() -> Result<()> {
        let (mut cpu, _) = Fake::new(Duration::ZERO);
        cpu.fail_from = 1;
        let ner = detector(cpu, None)?;
        let texts = texts_of(50, "a");
        assert_eq!(detect_all(&ner, &texts), vec![Vec::<Span>::new(); 50]);
        assert_eq!(ner.state(), NerState::Failed("fake failure".into()));
        Ok(())
    }

    #[test]
    fn two_calls_at_once_share_the_lanes_and_both_get_every_name() -> Result<()> {
        let (cpu, _) = Fake::new(Duration::from_millis(1));
        let (gpu, _) = Fake::new(Duration::from_millis(1));
        let ner = detector(cpu, Some(gpu))?;
        let (first, second) = (texts_of(600, "a"), texts_of(600, "b"));
        let (one, two) = std::thread::scope(|scope| {
            let other = scope.spawn(|| detect_all(&ner, &second));
            let one = detect_all(&ner, &first);
            let two = match other.join() {
                Ok(spans) => spans,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            (one, two)
        });
        assert_eq!(one, expected(&first));
        assert_eq!(two, expected(&second));
        Ok(())
    }

    // --- states and errors ----------------------------------------------------------------

    #[test]
    fn without_the_model_nothing_is_found_and_nothing_breaks() {
        let ner = missing();
        assert_eq!(ner.state(), NerState::Missing);
        let texts = [
            "Mijn naam is Jeroen de Vries",
            "Jan Kowalski, tel. 600 123 456",
        ];
        let found = ner.detect_batch(&texts, Mode::Anonymize, KindSet::ALL, &[]);
        assert_eq!(found, [vec![], vec![]]);
        assert!(ner.detect(texts[0], Mode::Anonymize).is_empty());
        assert_eq!(ner.state(), NerState::Missing, "no model is no failure");
        assert!(matches!(ner.load(), Err(Error::Model(m)) if m == "not downloaded"));
    }

    #[test]
    fn deanonymize_and_unwanted_kinds_do_not_touch_the_model() {
        let ner = missing();
        ner.fail(&Error::Model("sentinel".into()));
        // A failed detector finds nothing, so these would be empty anyway: the point is that
        // they return before anything is gated, hashed or loaded.
        let texts = ["Mijn naam is Jeroen de Vries"];
        assert!(ner.detect(texts[0], Mode::Deanonymize).is_empty());
        let none = KindSet::EMPTY.with(EntityKind::UrlCredential);
        assert_eq!(
            ner.detect_batch(&texts, Mode::Anonymize, none, &[]),
            [vec![]]
        );
        assert!(
            ner.detect_batch(&[], Mode::Anonymize, KindSet::ALL, &[])
                .is_empty()
        );
    }

    #[test]
    fn a_failure_is_remembered_until_release() {
        let ner = missing();
        ner.fail(&Error::Model("out of memory".into()));
        assert_eq!(ner.state(), NerState::Failed("out of memory".into()));
        assert!(ner.ready().is_none(), "no reload while failed");
        assert!(
            ner.detect("Mijn naam is Jeroen de Vries", Mode::Anonymize)
                .is_empty()
        );
        ner.release();
        assert_eq!(ner.state(), NerState::Missing);
    }

    #[test]
    fn clones_share_one_model() {
        let ner = missing();
        let clone = ner.clone();
        ner.fail(&Error::Model("shared".into()));
        assert_eq!(clone.state(), NerState::Failed("shared".into()));
        clone.release();
        assert_eq!(ner.state(), NerState::Missing);
    }

    #[test]
    fn debug_shows_the_state_and_nothing_else() {
        let ner = missing();
        let shown = format!("{ner:?}");
        assert!(
            shown.contains("NerDetector") && shown.contains("Missing"),
            "{shown}"
        );
        assert!(!shown.contains("piikey-ner-missing"), "no paths: {shown}");
    }

    #[test]
    fn errors_show_without_the_detection_model_prefix() {
        assert_eq!(message(&Error::Model("boom".into())), "boom");
        assert!(message(&Error::Poisoned).contains("poisoned"));
    }
}
