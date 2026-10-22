//! The ONNX Runtime sessions: a lane per session, the model in memory with its tokenizer, and the
//! choice between the CPU alone and the CPU with the GPU.

use std::{
    fs,
    path::Path,
    sync::{
        LazyLock, Mutex,
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
use tokenizers::Tokenizer;

use super::{
    Device, files,
    labels::LABELS,
    lock, model_err,
    queue::{CPU_LIMITS, GPU_LIMITS, Limits},
    windows::Input,
};
use crate::{Error, Result};

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

/// Threads of the GPU's session, for the few operators `DirectML` leaves to the CPU: the CPU's
/// own session needs the cores.
const GPU_THREADS: usize = 2;

/// Something that runs the model on a batch: an ONNX Runtime session, or a stand-in in tests.
pub(super) trait Runner: Send {
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
pub(super) struct Lane {
    /// One run at a time.
    pub(super) runner: Mutex<Box<dyn Runner>>,
    pub(super) limits: Limits,
}

impl Lane {
    pub(super) fn new(runner: impl Runner + 'static, limits: Limits) -> Self {
        Self {
            runner: Mutex::new(Box::new(runner)),
            limits,
        }
    }

    /// Runs `input`, waiting for the lane when something else is running on it.
    pub(super) fn execute(&self, input: Input, read: &mut dyn FnMut(&[f32])) -> Result<()> {
        lock(&self.runner).execute(input, read)
    }
}

/// The model in memory.
pub(super) struct Loaded {
    pub(super) tokenizer: Tokenizer,
    /// Always there.
    pub(super) cpu: Lane,
    /// There when the GPU helps.
    pub(super) gpu: Option<Lane>,
    /// False once a run on the GPU failed: the CPU does everything from then on.
    pub(super) gpu_works: AtomicBool,
}

impl Loaded {
    /// The GPU's lane, unless there is none or it was given up.
    pub(super) fn gpu(&self) -> Option<&Lane> {
        self.gpu
            .as_ref()
            .filter(|_| self.gpu_works.load(Ordering::Relaxed))
    }

    pub(super) fn device(&self) -> Device {
        if self.gpu().is_some() {
            Device::Hybrid
        } else {
            Device::Cpu
        }
    }

    pub(super) fn open(dir: &Path) -> Result<Self> {
        let graph = dir.join(files::GRAPH_FILE);
        let choice_file = dir.join(files::DEVICE_FILE);
        let saved = saved_choice(&choice_file);
        // Reading the tokenizer takes about as long as building a session (more, in a build
        // without optimizations), so the two go side by side: the tokenizer in a thread of its
        // own, the sessions here and in `build_sessions`.
        let (tokenizer, built) = std::thread::scope(|scope| {
            let tokenizer = scope.spawn(|| read_tokenizer(dir));
            let built = build_sessions(&graph, saved);
            let tokenizer = match tokenizer.join() {
                Ok(tokenizer) => tokenizer,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            (tokenizer, built)
        });
        let (tokenizer, sentence) = tokenizer?;
        let (cpu, gpu) = settle(built, &sentence, &choice_file, saved)?;
        Ok(Self {
            tokenizer,
            cpu,
            gpu_works: AtomicBool::new(gpu.is_some()),
            gpu,
        })
    }
}

/// The tokenizer of the model, and the token ids of the calibration text.
fn read_tokenizer(dir: &Path) -> Result<(Tokenizer, Vec<u32>)> {
    let mut tokenizer = Tokenizer::from_file(dir.join(files::TOKENIZER_FILE)).map_err(model_err)?;
    // Windows are cut here, not by the tokenizer.
    tokenizer.with_truncation(None).map_err(model_err)?;
    tokenizer.with_padding(None);
    let sentence = tokenizer
        .encode(CALIBRATION_TEXT, false)
        .map_err(model_err)?
        .get_ids()
        .to_vec();
    Ok((tokenizer, sentence))
}

/// The sessions of a load, built and not yet run.
struct Built {
    cpu: Result<Lane>,
    /// The GPU's, unless `device.cfg` says the CPU alone.
    gpu: Option<Result<Lane>>,
}

/// Builds the session of the CPU, and the GPU's at the same time (in a thread of its own: it takes
/// the longest) unless an earlier load chose the CPU alone.
fn build_sessions(graph: &Path, saved: Option<Device>) -> Built {
    if saved == Some(Device::Cpu) {
        return Built {
            cpu: build_cpu(graph),
            gpu: None,
        };
    }
    std::thread::scope(|scope| {
        let gpu = scope.spawn(|| build_gpu(graph));
        let cpu = build_cpu(graph);
        let gpu = match gpu.join() {
            Ok(gpu) => gpu,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        Built {
            cpu,
            gpu: Some(gpu),
        }
    })
}

/// The session of the CPU, and the one of the GPU when it helps: what an earlier load chose,
/// else what a measurement of both says. A GPU builds its kernels on the first run, so that run
/// is a tiny one made here, and a GPU that does not build or run is no GPU.
fn settle(
    built: Built,
    sentence: &[u32],
    choice_file: &Path,
    saved: Option<Device>,
) -> Result<(Lane, Option<Lane>)> {
    let cpu = built.cpu?;
    let Some(gpu) = built.gpu else {
        return Ok((cpu, None));
    };
    let gpu = gpu.and_then(|lane| {
        let warm_up =
            Input::filled(sentence, WARM_UP_SHAPE.0, WARM_UP_SHAPE.1).ok_or_else(no_tokens)?;
        lane.execute(warm_up, &mut |_| ())?;
        Ok(lane)
    });
    if saved.is_some() {
        if gpu.is_err() {
            // The GPU or its driver changed: measure again next time, run on the CPU now.
            let _ = fs::remove_file(choice_file);
        }
        return Ok((cpu, gpu.ok()));
    }
    let gpu = match gpu {
        Ok(gpu) if gpu_helps(&cpu, &gpu, sentence)? => Some(gpu),
        _ => None,
    };
    let device = if gpu.is_some() {
        Device::Hybrid
    } else {
        Device::Cpu
    };
    // Best effort: without the file the next load measures again.
    let _ = fs::write(choice_file, device.name());
    Ok((cpu, gpu))
}

/// The device `device.cfg` names, if it names one. People write this file by hand, and what
/// `echo cpu > device.cfg` leaves in Windows `PowerShell` is UTF-16 with a byte-order mark: read
/// as UTF-8 that is no text at all, so the choice would be ignored and the next measurement
/// would overwrite it.
fn saved_choice(file: &Path) -> Option<Device> {
    Device::parse(&text_of(&fs::read(file).ok()?))
}

/// `bytes` as text: UTF-8 or UTF-16 (either byte order, marked as such), with or without the
/// byte-order mark of UTF-8.
fn text_of(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    char::decode_utf16(pairs.iter().copied().map(unit))
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::ner::files::Scratch;

    /// What `echo cpu > device.cfg` writes in Windows `PowerShell` 5.1: UTF-16 with a mark.
    const POWERSHELL: [u8; 12] = [
        0xFF, 0xFE, 0x63, 0x00, 0x70, 0x00, 0x75, 0x00, 0x0D, 0x00, 0x0A, 0x00,
    ];

    #[test]
    fn a_choice_written_by_hand_is_read_in_every_encoding_windows_writes() {
        let marked = |mark: [u8; 2], unit: fn(u16) -> [u8; 2], text: &str| -> Vec<u8> {
            mark.into_iter()
                .chain(text.encode_utf16().flat_map(unit))
                .collect()
        };
        let cases: [(&str, Vec<u8>, Option<Device>); 7] = [
            ("plain", b"cpu".to_vec(), Some(Device::Cpu)),
            ("line end", b"hybrid\r\n".to_vec(), Some(Device::Hybrid)),
            (
                "utf-8 with mark",
                [&[0xEF, 0xBB, 0xBF][..], b"cpu\r\n"].concat(),
                Some(Device::Cpu),
            ),
            ("powershell", POWERSHELL.to_vec(), Some(Device::Cpu)),
            (
                "utf-16 big endian",
                marked([0xFE, 0xFF], u16::to_be_bytes, "hybrid"),
                Some(Device::Hybrid),
            ),
            // A lone surrogate is no text.
            ("garbage", vec![0xFF, 0xFE, 0x00, 0xD8, 0x63], None),
            ("empty", Vec::new(), None),
        ];
        for (name, bytes, want) in cases {
            assert_eq!(Device::parse(&text_of(&bytes)), want, "{name}");
        }
    }

    #[test]
    fn the_choice_is_read_from_the_file_and_a_missing_file_is_no_choice() -> Result<()> {
        let scratch = Scratch::new("choice");
        let file = scratch.0.join(files::DEVICE_FILE);
        assert_eq!(saved_choice(&file), None);
        fs::write(&file, POWERSHELL)?;
        assert_eq!(saved_choice(&file), Some(Device::Cpu));
        Ok(())
    }
}
