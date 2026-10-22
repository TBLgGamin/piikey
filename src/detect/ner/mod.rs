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
//! 1. `chunks` cuts runs of data (base64, hex: a kilobyte or more without whitespace) out of it,
//!    `gate::worth_running` spares the model texts it cannot add to (a lone JSON key, only
//!    stopwords), and the cache spares it texts it has seen (chat clients resend the whole
//!    conversation every turn).
//! 2. The tokenizer cuts the rest into windows of 510 tokens that overlap by 128, because the model
//!    reads 512 positions at most (`windows`).
//! 3. The windows of a group of texts, longest first, are packed into batches that the CPU and the
//!    GPU take from the two ends of the list (`queue`). ONNX Runtime sessions (`session`) do not
//!    run concurrently, so each runs one batch at a time, and never inside a rayon task.
//! 4. `decode` turns the probabilities into spans, and `labels` the model's types into kinds.
//!
//! The model is INT8 with dynamic quantization: how a batch is quantized depends on everything in
//! it, so a borderline decision (does `ul.` belong to the address after it?) can differ between
//! two batches, and between the CPU and the GPU. The cache keeps the first answer for a text, which
//! also keeps a conversation consistent from one turn to the next.

pub mod files;

mod chunks;
mod decode;
mod fetch;
mod gate;
mod labels;
mod queue;
mod session;
mod windows;

pub use fetch::fetch;
use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt,
    ops::{ControlFlow, Range},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        TryLockError, atomic::Ordering,
    },
};

use rayon::prelude::*;

use self::{
    chunks::{GROUP_BYTES, Job, groups, plan},
    decode::Tokens,
    gate::{CACHE_CAPACITY, Cache, RawSpan},
    labels::MODEL_KINDS,
    queue::{GPU_FLOOR, GPU_SHARE, Queue},
    session::{Lane, Loaded, Runner},
    windows::{Input, Window, absorb, windows_of},
};
use super::{Detector, KindSet, Mode, Span, Step, overlaps};
use crate::{Error, Result};

/// What the model found in one text, once it is known.
type Answer = Option<Arc<[RawSpan]>>;

/// What [`NerDetector::find_with`] tells: the jobs that have an answer now, and the answers.
type Answered<'a> = dyn FnMut(&[usize], &[Answer]) -> ControlFlow<()> + 'a;

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
    cache: Mutex<Cache>,
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
                cache: Mutex::new(Cache::new(CACHE_CAPACITY)),
            }),
        }
    }

    /// What the detector is up to right now: see [`NerState`].
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
        let found = self.find_with(&jobs, &mut |_, _| ControlFlow::Continue(()));
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

    /// As [`Detector::detect_batch`], but a step for the texts the cache knew, and one for each
    /// group of texts the model has read, so that a caller gets the first names while the model is
    /// still at the rest (its cost is in proportion to the text: some 0.15 ms for each token).
    fn detect_batch_steps(
        &self,
        texts: &[&str],
        mode: Mode,
        wanted: KindSet,
        taken: &[Vec<Span>],
        step: &mut dyn FnMut(Step) -> ControlFlow<()>,
    ) {
        let jobs = if mode == Mode::Deanonymize || !wanted.intersects(MODEL_KINDS) {
            Vec::new()
        } else {
            plan(texts, taken)
        };
        if jobs.is_empty() {
            let _ = step(Step {
                spans: vec![Vec::new(); texts.len()],
                more: None,
            });
            return;
        }
        let total: usize = jobs.iter().map(|job| job.chunk.len()).sum();
        let (mut done, mut answered_jobs) = (0, 0);
        self.find_with(&jobs, &mut |answered, found| {
            let mut spans: Vec<Vec<Span>> = vec![Vec::new(); texts.len()];
            for &i in answered {
                let job = &jobs[i];
                done += job.chunk.len();
                if let Some(raw) = &found[i] {
                    spans[job.text].extend(raw.iter().filter(|r| wanted.contains(r.kind)).map(
                        |r| Span {
                            start: job.base + r.start as usize,
                            end: job.base + r.end as usize,
                            kind: r.kind,
                        },
                    ));
                }
            }
            answered_jobs += answered.len();
            for (own, claimed) in spans.iter_mut().zip(taken) {
                own.retain(|span| !overlaps(claimed, span));
            }
            step(Step {
                spans,
                more: (answered_jobs < jobs.len()).then_some((done, total)),
            })
        });
    }
}

impl NerDetector {
    /// What the model finds in each job's text: from the cache, else from the model. `answered`
    /// is told which jobs have their answers, with the answers (by job): first the ones the cache
    /// had, then, after each group of texts the model reads, the ones in it, and the jobs with
    /// the same text as one of them. It ends the work by breaking, and the jobs not answered then
    /// have no spans.
    fn find_with(&self, jobs: &[Job<'_>], answered: &mut Answered<'_>) -> Vec<Arc<[RawSpan]>> {
        let mut found: Vec<Option<Arc<[RawSpan]>>> = {
            let cache = lock(&self.inner.cache);
            jobs.iter().map(|job| cache.get(&job.key)).collect()
        };
        let known: Vec<usize> = (0..jobs.len()).filter(|&i| found[i].is_some()).collect();
        let mut flow = if known.is_empty() {
            ControlFlow::Continue(())
        } else {
            answered(&known, &found)
        };
        // Equal texts in one call run once: the first of them runs, the others take its answer.
        let mut first_of: HashMap<[u8; 32], usize> = HashMap::new();
        let mut twins: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut misses: Vec<usize> = Vec::new();
        for (i, job) in jobs.iter().enumerate() {
            if found[i].is_some() {
                continue;
            }
            let first = *first_of.entry(job.key).or_insert(i);
            if first == i {
                misses.push(i);
            } else {
                twins.entry(first).or_default().push(i);
            }
        }
        let sizes: Vec<usize> = misses.iter().map(|&i| jobs[i].chunk.len()).collect();
        for group in groups(&sizes, GROUP_BYTES) {
            if flow.is_break() {
                break;
            }
            // A failure in an earlier group leaves nothing to run on.
            let Some(loaded) = self.ready() else {
                break;
            };
            let members = &misses[group];
            let texts: Vec<&str> = members.iter().map(|&i| jobs[i].chunk).collect();
            let computed = self.compute(&loaded, &texts);
            let mut now: Vec<usize> = Vec::new();
            {
                let mut cache = lock(&self.inner.cache);
                for (&i, spans) in members.iter().zip(computed) {
                    let Some(spans) = spans else {
                        continue;
                    };
                    // Two calls that ran the same text meanwhile end with the first answer.
                    let answer = cache.insert(jobs[i].key, spans.into());
                    for &twin in twins.get(&i).into_iter().flatten() {
                        found[twin] = Some(Arc::clone(&answer));
                        now.push(twin);
                    }
                    found[i] = Some(answer);
                    now.push(i);
                }
            }
            if !now.is_empty() {
                now.sort_unstable();
                flow = answered(&now, &found);
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
        for part in run_windows(loaded, &shared, &queue) {
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
}

/// Runs the windows `queue` holds. The CPU always works on them, from the shortest end; a call
/// that is big enough also starts the GPU, from the longest end. Returns what each did.
fn run_windows(loaded: &Loaded, shared: &Shared<'_>, queue: &Queue<'_>) -> Vec<Worked> {
    let gpu = loaded
        .gpu()
        .filter(|_| queue.remaining() >= GPU_FLOOR * GPU_SHARE);
    let mut parts = std::thread::scope(|scope| {
        let gpu = gpu.map(|lane| scope.spawn(move || gpu_worker(loaded, lane, shared, queue)));
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
/// for good: the CPU runs them, and everything after.
fn gpu_worker(loaded: &Loaded, lane: &Lane, shared: &Shared<'_>, queue: &Queue<'_>) -> Worked {
    let mut part = Worked::new(shared.texts.len());
    // Another call may be using the GPU: this one leaves it alone and the CPU does the work.
    let Some(mut runner) = try_lock(&lane.runner) else {
        return part;
    };
    while let Some(batch) = queue.take_front(lane.limits, GPU_FLOOR, GPU_SHARE) {
        if run_batch(&mut **runner, shared, &batch, &mut part.tokens).is_ok() {
            part.done.push(batch);
        } else {
            queue.give_back(batch.start);
            loaded.gpu_works.store(false, Ordering::Relaxed);
            break;
        }
    }
    part
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
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize},
        time::{Duration, Instant},
    };

    use tokenizers::{
        Tokenizer, models::wordlevel::WordLevel, pre_tokenizers::whitespace::Whitespace,
    };

    use super::{
        labels::LABELS,
        queue::{CPU_LIMITS, GPU_LIMITS},
        *,
    };
    use crate::detect::EntityKind;

    fn missing() -> NerDetector {
        NerDetector::new(
            std::env::temp_dir().join(format!("piikey-ner-missing-{}", std::process::id())),
        )
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
                .position(|(name, ..)| *name == "PERSON_NAME")
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
        assert_eq!(ner.state(), NerState::Ready(Device::Cpu));

        // From then on the GPU is left alone, and the detector still works.
        let runs = gpu_seen.runs();
        let more = texts_of(600, "b");
        assert_eq!(detect_all(&ner, &more), expected(&more));
        assert_eq!(gpu_seen.runs(), runs);
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

    // --- steps ----------------------------------------------------------------------------

    /// What `detect_batch_steps` reports for `texts`, one entry per step, until `stop_after`
    /// steps have come.
    fn steps_of(ner: &NerDetector, texts: &[String], stop_after: usize) -> Vec<Step> {
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let mut steps = Vec::new();
        ner.detect_batch_steps(&refs, Mode::Anonymize, KindSet::ALL, &[], &mut |step| {
            steps.push(step);
            if steps.len() >= stop_after {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        steps
    }

    /// What the spans of all `steps` come to, per text.
    fn together(steps: &[Step], texts: usize) -> Vec<Vec<Span>> {
        let mut all: Vec<Vec<Span>> = vec![Vec::new(); texts];
        for step in steps {
            for (mine, spans) in all.iter_mut().zip(&step.spans) {
                mine.extend(spans.iter().copied());
            }
        }
        for spans in &mut all {
            spans.sort_by_key(|span| span.start);
        }
        all
    }

    #[test]
    fn the_model_reports_a_group_of_texts_at_a_time_and_the_steps_are_what_one_call_finds()
    -> Result<()> {
        let (cpu, seen) = Fake::new(Duration::ZERO);
        let ner = detector(cpu, None)?;
        // Some 360 KB: more than a group holds.
        let texts = texts_of(10_000, "a");
        let steps = steps_of(&ner, &texts, usize::MAX);
        assert_eq!(steps.len(), 2, "two groups, two steps");
        // The first says how far the model has got of the text it reads; the last says that nothing
        // follows.
        let total: usize = texts.iter().map(String::len).sum();
        let Some((done, of)) = steps[0].more else {
            return Err(Error::Model("the first step says nothing follows".into()));
        };
        assert!(0 < done && done < of && of == total, "{done} of {of}");
        assert_eq!(steps[1].more, None);
        assert_eq!(together(&steps, texts.len()), expected(&texts));
        assert_eq!(seen.windows(), texts.len());
        Ok(())
    }

    #[test]
    fn what_the_cache_knows_is_the_first_step_and_costs_no_run() -> Result<()> {
        let (cpu, seen) = Fake::new(Duration::ZERO);
        let ner = detector(cpu, None)?;
        // Fewer than the cache keeps (8192), and no more than one group holds.
        let texts = texts_of(5_000, "a");
        assert_eq!(detect_all(&ner, &texts), expected(&texts));
        let runs = seen.runs();
        let steps = steps_of(&ner, &texts, usize::MAX);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].more, None);
        assert_eq!(together(&steps, texts.len()), expected(&texts));
        assert_eq!(seen.runs(), runs, "the model did not run again");
        Ok(())
    }

    #[test]
    fn a_stop_ends_the_model_after_the_group_it_is_in() -> Result<()> {
        let (cpu, seen) = Fake::new(Duration::ZERO);
        let ner = detector(cpu, None)?;
        let texts = texts_of(10_000, "a");
        let steps = steps_of(&ner, &texts, 1);
        assert_eq!(steps.len(), 1);
        assert!(steps[0].more.is_some());
        assert!(
            0 < seen.windows() && seen.windows() < texts.len(),
            "{}",
            seen.windows()
        );
        Ok(())
    }

    #[test]
    fn texts_that_are_equal_run_once_and_are_answered_together() -> Result<()> {
        let (cpu, seen) = Fake::new(Duration::ZERO);
        let ner = detector(cpu, None)?;
        let mut texts = texts_of(3, "t");
        texts.push(texts[0].clone());
        texts.push(texts[0].clone());
        let steps = steps_of(&ner, &texts, usize::MAX);
        assert_eq!(steps.len(), 1);
        assert_eq!(together(&steps, texts.len()), expected(&texts));
        assert_eq!(seen.windows(), 3, "the repeats were not run");
        Ok(())
    }

    #[test]
    fn with_nothing_for_the_model_to_read_the_one_step_is_empty() -> Result<()> {
        let (cpu, seen) = Fake::new(Duration::ZERO);
        let ner = detector(cpu, None)?;
        let texts = ["ik ben het".to_owned()];
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let mut steps = Vec::new();
        ner.detect_batch_steps(&refs, Mode::Deanonymize, KindSet::ALL, &[], &mut |step| {
            steps.push(step);
            ControlFlow::Continue(())
        });
        assert_eq!(
            steps,
            [Step {
                spans: vec![Vec::new()],
                more: None
            }]
        );
        assert_eq!(seen.runs(), 0);
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
        assert!(matches!(ner.load(), Err(Error::Model(_))));
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
    fn debug_leaves_out_the_model_folder() {
        let shown = format!("{:?}", missing());
        assert!(!shown.contains("piikey-ner-missing"), "{shown}");
    }

    #[test]
    fn errors_show_without_the_detection_model_prefix() {
        assert_eq!(message(&Error::Model("boom".into())), "boom");
        assert_eq!(message(&Error::Poisoned), Error::Poisoned.to_string());
    }
}
