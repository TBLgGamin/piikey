//! Command-line entry: `anonymize`, `deanonymize` and `serve`.

use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use lexopt::{Arg, Parser, ValueExt};
use piikey::{
    detect::Mode,
    engine::Engine,
    formats::{self, Output},
    service,
    vault::default_path,
};
use rayon::prelude::*;

const USAGE: &str = "\
usage:
  piikey anonymize   [--vault PATH] [--out DIR] [PATH...]
  piikey deanonymize [--vault PATH] [--out DIR] [PATH...]
  piikey serve       [--vault PATH] [--pipe NAME]      (default \\\\.\\pipe\\piikey)

With no PATH, stdin is processed and the result goes to stdout.
With PATHs, --out DIR is required; directories are walked recursively.";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    /// Process stdin to stdout.
    Stdin {
        mode: Mode,
        vault: Option<PathBuf>,
    },
    /// Process files and directories into `out`.
    Files {
        mode: Mode,
        vault: Option<PathBuf>,
        out: PathBuf,
        inputs: Vec<PathBuf>,
    },
    Serve {
        vault: Option<PathBuf>,
        pipe: Option<String>,
    },
}

/// Why a command line was rejected (always exit code 2).
#[derive(Debug, PartialEq, Eq)]
enum ParseError {
    /// Print the message followed by the usage text.
    Usage(String),
    /// Input paths were given without `--out`.
    OutRequired,
}

impl From<lexopt::Error> for ParseError {
    fn from(e: lexopt::Error) -> Self {
        Self::Usage(e.to_string())
    }
}

#[derive(Clone, Copy)]
enum Sub {
    Run(Mode),
    Serve,
}

fn parse<I>(args: I) -> Result<Command, ParseError>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut parser = Parser::from_args(args);
    let mut sub: Option<Sub> = None;
    let mut vault: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut pipe: Option<String> = None;
    let mut inputs: Vec<PathBuf> = Vec::new();

    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('h') | Arg::Long("help") => return Ok(Command::Help),
            Arg::Long("vault") => vault = Some(PathBuf::from(parser.value()?)),
            Arg::Long("out") => out = Some(PathBuf::from(parser.value()?)),
            Arg::Long("pipe") => pipe = Some(parser.value()?.string()?),
            Arg::Value(value) => {
                if sub.is_none() {
                    sub = Some(match value.to_str() {
                        Some("anonymize") => Sub::Run(Mode::Anonymize),
                        Some("deanonymize") => Sub::Run(Mode::Deanonymize),
                        Some("serve") => Sub::Serve,
                        _ => {
                            return Err(ParseError::Usage(format!(
                                "unknown command '{}'",
                                value.to_string_lossy()
                            )));
                        }
                    });
                } else {
                    inputs.push(PathBuf::from(value));
                }
            }
            other => return Err(other.unexpected().into()),
        }
    }

    match sub {
        None => Err(ParseError::Usage("missing command".into())),
        Some(Sub::Serve) => {
            if out.is_some() {
                return Err(ParseError::Usage("--out is not valid for serve".into()));
            }
            if !inputs.is_empty() {
                return Err(ParseError::Usage("serve takes no input paths".into()));
            }
            Ok(Command::Serve { vault, pipe })
        }
        Some(Sub::Run(mode)) => {
            if pipe.is_some() {
                return Err(ParseError::Usage("--pipe is only valid for serve".into()));
            }
            if inputs.is_empty() {
                if out.is_some() {
                    return Err(ParseError::Usage(
                        "--out is only valid with input paths".into(),
                    ));
                }
                Ok(Command::Stdin { mode, vault })
            } else {
                let out = out.ok_or(ParseError::OutRequired)?;
                Ok(Command::Files {
                    mode,
                    vault,
                    out,
                    inputs,
                })
            }
        }
    }
}

/// Entry point called by `main`.
pub fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(command) => execute(command),
        Err(ParseError::OutRequired) => {
            eprintln!("piikey: --out is required with input paths");
            ExitCode::from(2)
        }
        Err(ParseError::Usage(msg)) => {
            eprintln!("piikey: {msg}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn open_engine(vault: Option<PathBuf>) -> piikey::Result<Engine> {
    let path = match vault {
        Some(path) => path,
        None => default_path()?,
    };
    Engine::open(&path)
}

fn execute(command: Command) -> ExitCode {
    match command {
        Command::Help => ExitCode::SUCCESS,
        Command::Stdin { mode, vault } => {
            let result = open_engine(vault).and_then(|engine| run_stdin(&engine, mode));
            finish(result)
        }
        Command::Files {
            mode,
            vault,
            out,
            inputs,
        } => run_files_command(mode, vault, &out, &inputs),
        Command::Serve { vault, pipe } => {
            let pipe = pipe.unwrap_or_else(|| service::DEFAULT_PIPE.to_owned());
            let result = open_engine(vault).and_then(|engine| {
                eprintln!("piikey: serving on {pipe}");
                service::serve(Arc::new(engine), &pipe)
            });
            finish(result)
        }
    }
}

fn finish(result: piikey::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("piikey: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_stdin(engine: &Engine, mode: Mode) -> piikey::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().lock().read_to_end(&mut bytes)?;
    let output = formats::process(engine, mode, &bytes, 0)?;
    let mut stdout = io::stdout().lock();
    match &output {
        Output::Same(raw) => stdout.write_all(raw)?,
        Output::Text(text) => stdout.write_all(text.as_bytes())?,
    }
    stdout.flush()?;
    Ok(())
}

fn run_files_command(
    mode: Mode,
    vault: Option<PathBuf>,
    out: &Path,
    inputs: &[PathBuf],
) -> ExitCode {
    match out_inside_inputs(out, inputs) {
        Ok(None) => {}
        Ok(Some(dir)) => {
            eprintln!(
                "piikey: --out {} must not be inside input directory {}",
                out.display(),
                dir.display()
            );
            return ExitCode::from(2);
        }
        Err(err) => {
            eprintln!("piikey: {}: {err}", out.display());
            return ExitCode::FAILURE;
        }
    }
    let engine = match open_engine(vault) {
        Ok(engine) => engine,
        Err(err) => {
            eprintln!("piikey: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (jobs, walk_errors) = collect_jobs(inputs);
    for (path, err) in &walk_errors {
        eprintln!("piikey: {}: {err}", path.display());
    }
    let any_failed = jobs
        .par_iter()
        .map(|job| match process_file(&engine, mode, job, out) {
            Ok(()) => false,
            Err(err) => {
                eprintln!("piikey: {}: {err}", job.src.display());
                true
            }
        })
        .reduce(|| false, |a, b| a || b);

    if any_failed || !walk_errors.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// One input file and its path relative to the `--out` root.
#[derive(Debug, PartialEq, Eq)]
struct Job {
    src: PathBuf,
    rel: PathBuf,
}

fn process_file(engine: &Engine, mode: Mode, job: &Job, out: &Path) -> piikey::Result<()> {
    let bytes = fs::read(&job.src)?;
    let output = formats::process(engine, mode, &bytes, 0)?;
    let (dest, data) = match &output {
        Output::Same(raw) => (output_path(out, &job.rel, false), raw.as_slice()),
        Output::Text(text) => (output_path(out, &job.rel, true), text.as_bytes()),
    };
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(dest, data)?;
    Ok(())
}

/// Destination of `rel` under `out`; text results get a `.txt` suffix appended
/// to the full file name.
fn output_path(out: &Path, rel: &Path, text: bool) -> PathBuf {
    let mut joined = out.join(rel).into_os_string();
    if text {
        joined.push(".txt");
    }
    PathBuf::from(joined)
}

/// Gathers files from `inputs`. A file input maps to its file name, a
/// directory is walked recursively with paths relative to it. Symlinks and
/// junctions found while walking are skipped. Unreadable entries are returned
/// as errors instead of aborting the walk.
fn collect_jobs(inputs: &[PathBuf]) -> (Vec<Job>, Vec<(PathBuf, io::Error)>) {
    let mut jobs = Vec::new();
    let mut errors = Vec::new();
    for input in inputs {
        match fs::metadata(input) {
            Err(err) => errors.push((input.clone(), err)),
            Ok(meta) if meta.is_file() => {
                if let Some(name) = input.file_name() {
                    jobs.push(Job {
                        src: input.clone(),
                        rel: PathBuf::from(name),
                    });
                } else {
                    errors.push((
                        input.clone(),
                        io::Error::new(io::ErrorKind::InvalidInput, "no file name"),
                    ));
                }
            }
            Ok(meta) if meta.is_dir() => walk_dir(input, &mut jobs, &mut errors),
            Ok(_) => errors.push((
                input.clone(),
                io::Error::new(io::ErrorKind::InvalidInput, "not a file or directory"),
            )),
        }
    }
    // Windows paths are case-insensitive: two inputs mapping to the same
    // output would silently overwrite each other, so later ones fail.
    let mut seen = std::collections::HashMap::new();
    jobs.retain(|job| {
        let key = job.rel.to_string_lossy().to_lowercase();
        match seen.entry(key) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(job.src.clone());
                true
            }
            std::collections::hash_map::Entry::Occupied(first) => {
                errors.push((
                    job.src.clone(),
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("output collides with {}", first.get().display()),
                    ),
                ));
                false
            }
        }
    });
    (jobs, errors)
}

fn walk_dir(root: &Path, jobs: &mut Vec<Job>, errors: &mut Vec<(PathBuf, io::Error)>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                errors.push((dir, err));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    errors.push((dir.clone(), err));
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    errors.push((path, err));
                    continue;
                }
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && let Ok(rel) = path.strip_prefix(root)
            {
                jobs.push(Job {
                    rel: rel.to_path_buf(),
                    src: path,
                });
            }
        }
    }
}

/// Canonicalizes `path` even when its tail does not exist yet: the longest
/// existing ancestor is canonicalized and the missing components are
/// re-appended.
fn canonical_lenient(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut missing = Vec::new();
    let mut current = absolute.as_path();
    loop {
        match current.canonicalize() {
            Ok(mut base) => {
                base.extend(missing.iter().rev());
                return Ok(base);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                match (current.parent(), current.file_name()) {
                    (Some(parent), Some(name)) => {
                        missing.push(name.to_owned());
                        current = parent;
                    }
                    _ => return Err(err),
                }
            }
            Err(err) => return Err(err),
        }
    }
}

/// The first input directory that equals or contains `out`, if any. Inputs
/// that cannot be resolved are ignored here; they fail later with their own
/// error.
fn out_inside_inputs<'a>(out: &Path, inputs: &'a [PathBuf]) -> io::Result<Option<&'a Path>> {
    let out = canonical_lenient(out)?;
    for input in inputs {
        if fs::metadata(input).is_ok_and(|m| m.is_dir())
            && let Ok(dir) = input.canonicalize()
            && out.starts_with(&dir)
        {
            return Ok(Some(input.as_path()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn args(list: &[&str]) -> Result<Command, ParseError> {
        parse(list.iter().map(OsString::from))
    }

    fn usage(list: &[&str]) -> bool {
        matches!(args(list), Err(ParseError::Usage(_)))
    }

    /// Temp directory removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> io::Result<Self> {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "piikey-cli-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_stdin_mode() {
        assert_eq!(
            args(&["anonymize"]),
            Ok(Command::Stdin {
                mode: Mode::Anonymize,
                vault: None
            })
        );
        assert_eq!(
            args(&["deanonymize", "--vault", "v.pkv"]),
            Ok(Command::Stdin {
                mode: Mode::Deanonymize,
                vault: Some(PathBuf::from("v.pkv"))
            })
        );
    }

    #[test]
    fn parses_file_mode() {
        assert_eq!(
            args(&["anonymize", "--out", "o", "a.txt", "dir", "--vault=v"]),
            Ok(Command::Files {
                mode: Mode::Anonymize,
                vault: Some(PathBuf::from("v")),
                out: PathBuf::from("o"),
                inputs: vec![PathBuf::from("a.txt"), PathBuf::from("dir")],
            })
        );
    }

    #[test]
    fn paths_without_out_is_rejected() {
        assert_eq!(args(&["anonymize", "a.txt"]), Err(ParseError::OutRequired));
    }

    #[test]
    fn parses_serve() {
        assert_eq!(
            args(&["serve", "--pipe", r"\\.\pipe\x", "--vault", "v"]),
            Ok(Command::Serve {
                vault: Some(PathBuf::from("v")),
                pipe: Some(r"\\.\pipe\x".to_owned()),
            })
        );
        assert_eq!(
            args(&["serve"]),
            Ok(Command::Serve {
                vault: None,
                pipe: None
            })
        );
    }

    #[test]
    fn help_wins() {
        assert_eq!(args(&["--help"]), Ok(Command::Help));
        assert_eq!(args(&["anonymize", "-h"]), Ok(Command::Help));
    }

    #[test]
    fn bad_args_are_usage_errors() {
        assert!(usage(&[]));
        assert!(usage(&["frobnicate"]));
        assert!(usage(&["anonymize", "--bogus"]));
        assert!(usage(&["anonymize", "--vault"]));
        assert!(usage(&["anonymize", "--pipe", "x"]));
        assert!(usage(&["anonymize", "--out", "o"]));
        assert!(usage(&["serve", "a.txt"]));
        assert!(usage(&["serve", "--out", "o"]));
    }

    #[test]
    fn output_path_mapping() {
        let out = Path::new("out");
        let rel = Path::new("sub").join("x.docx");
        assert_eq!(
            output_path(out, &rel, false),
            out.join("sub").join("x.docx")
        );
        assert_eq!(
            output_path(out, &rel, true),
            out.join("sub").join("x.docx.txt")
        );
    }

    #[test]
    fn out_inside_input_is_detected() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let input = tmp.0.join("in");
        fs::create_dir_all(input.join("nested"))?;
        let inputs = vec![input.clone()];

        assert_eq!(out_inside_inputs(&input, &inputs)?, Some(input.as_path()));
        assert_eq!(
            out_inside_inputs(&input.join("nested"), &inputs)?,
            Some(input.as_path())
        );
        // Not created yet, but would live inside the input.
        assert_eq!(
            out_inside_inputs(&input.join("new").join("deeper"), &inputs)?,
            Some(input.as_path())
        );
        // `..` must not fool the check.
        assert_eq!(
            out_inside_inputs(&input.join("nested").join("..").join("x"), &inputs)?,
            Some(input.as_path())
        );
        assert_eq!(out_inside_inputs(&tmp.0.join("out"), &inputs)?, None);
        // A sibling that merely shares a name prefix is not inside.
        assert_eq!(out_inside_inputs(&tmp.0.join("in2"), &inputs)?, None);
        Ok(())
    }

    #[test]
    fn file_inputs_never_contain_out() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let file = tmp.0.join("a.txt");
        fs::write(&file, b"x")?;
        assert_eq!(out_inside_inputs(&tmp.0.join("out"), &[file])?, None);
        Ok(())
    }

    #[test]
    fn collects_files_recursively() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.0.join("in");
        fs::create_dir_all(dir.join("a").join("b"))?;
        fs::write(dir.join("top.txt"), b"1")?;
        fs::write(dir.join("a").join("b").join("deep.txt"), b"2")?;
        let single = tmp.0.join("single.txt");
        fs::write(&single, b"3")?;

        let (mut jobs, errors) = collect_jobs(&[dir.clone(), single.clone()]);
        assert!(errors.is_empty());
        jobs.sort_by(|x, y| x.rel.cmp(&y.rel));
        let rels: Vec<PathBuf> = jobs.iter().map(|j| j.rel.clone()).collect();
        assert_eq!(
            rels,
            vec![
                PathBuf::from("a").join("b").join("deep.txt"),
                PathBuf::from("single.txt"),
                PathBuf::from("top.txt"),
            ]
        );
        assert!(jobs.iter().any(|j| j.src == single));
        Ok(())
    }

    #[test]
    fn missing_input_is_reported() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let missing = tmp.0.join("nope");
        let (jobs, errors) = collect_jobs(std::slice::from_ref(&missing));
        assert!(jobs.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, missing);
        Ok(())
    }
}
