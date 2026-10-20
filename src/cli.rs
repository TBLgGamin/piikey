//! Command-line entry: `anonymize`, `deanonymize` and `serve`.

use std::{
    ffi::OsString,
    fmt::Display,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use lexopt::{Arg, Parser, ValueExt};
use piikey::{
    detect::{EntityKind, Mode, NerDetector, ner},
    engine::Engine,
    formats::{self, Output},
    restore::{Restorer, Scope, ScopeEntry},
    service,
    vault::default_path,
};
use rayon::prelude::*;

const USAGE: &str = "\
usage:
  piikey-cli anonymize   [--vault PATH] [--out DIR] [PATH...]
  piikey-cli deanonymize [--vault PATH] [--tolerant] [--out DIR] [PATH...]
  piikey-cli serve       [--vault PATH] [--pipe NAME]      (default \\\\.\\pipe\\piikey)

With no PATH, stdin is processed and the result goes to stdout.
With PATHs, --out DIR is required; directories are walked recursively.

--tolerant     also restores proxies that came back with a typo, and first or last
               names that came back alone; only for text, not for zip documents";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    /// Process stdin to stdout.
    Stdin {
        mode: Mode,
        vault: Option<PathBuf>,
        tolerant: bool,
    },
    /// Process files and directories into `out`.
    Files {
        mode: Mode,
        vault: Option<PathBuf>,
        tolerant: bool,
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
    let mut tolerant = false;

    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('h') | Arg::Long("help") => return Ok(Command::Help),
            Arg::Long("vault") => vault = Some(PathBuf::from(parser.value()?)),
            Arg::Long("out") => out = Some(PathBuf::from(parser.value()?)),
            Arg::Long("pipe") => pipe = Some(parser.value()?.string()?),
            Arg::Long("tolerant") => tolerant = true,
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
            if tolerant {
                return Err(ParseError::Usage(
                    "--tolerant is not valid for serve".into(),
                ));
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
            if tolerant && mode != Mode::Deanonymize {
                return Err(ParseError::Usage(
                    "--tolerant is only valid for deanonymize".into(),
                ));
            }
            if inputs.is_empty() {
                if out.is_some() {
                    return Err(ParseError::Usage(
                        "--out is only valid with input paths".into(),
                    ));
                }
                Ok(Command::Stdin {
                    mode,
                    vault,
                    tolerant,
                })
            } else {
                let out = out.ok_or(ParseError::OutRequired)?;
                Ok(Command::Files {
                    mode,
                    vault,
                    tolerant,
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
            eprintln!("piikey-cli: --out is required with input paths");
            ExitCode::from(2)
        }
        Err(ParseError::Usage(msg)) => {
            eprintln!("piikey-cli: {msg}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Opens the engine for `vault` (the default vault when `None`), with the
/// detection model when the app has downloaded it.
fn open_engine(vault: Option<PathBuf>) -> piikey::Result<Engine> {
    let path = match vault {
        Some(path) => path,
        None => default_path()?,
    };
    match ner::files::default_dir() {
        Ok(dir) if ner::files::is_installed(&dir) => {
            Engine::open_with_model(&path, NerDetector::new(dir))
        }
        _ => {
            eprintln!(
                "note: the detection model is not downloaded yet (start piikey.exe once); \
                 only emails, phone numbers, IBANs and other patterns are masked"
            );
            Engine::open(&path)
        }
    }
}

/// The restorer behind `--tolerant`: scoped to every proxy in the vault. `None` when the flag
/// is off or the vault holds no proxy.
fn tolerant_restorer(engine: &Engine, wanted: bool) -> piikey::Result<Option<Restorer>> {
    if !wanted {
        return Ok(None);
    }
    let scope = vault_scope(engine)?;
    if scope.entries().is_empty() {
        return Ok(None);
    }
    Restorer::new(scope).map(Some)
}

/// Every proxy the vault has issued, with its kind and original, in a fixed order.
fn vault_scope(engine: &Engine) -> piikey::Result<Scope> {
    let guard = engine.vault().read()?;
    let view = &guard;
    let mut entries: Vec<ScopeEntry> = EntityKind::ALL
        .into_iter()
        .flat_map(|kind| {
            view.proxies_of(kind).filter_map(move |proxy| {
                view.original_for(proxy).map(|original| ScopeEntry {
                    kind,
                    proxy: proxy.into(),
                    original: original.into(),
                })
            })
        })
        .collect();
    entries.sort_unstable_by(|a, b| (a.kind, &a.proxy).cmp(&(b.kind, &b.proxy)));
    Ok(Scope::from_pairs(entries))
}

/// The result of the exact pass, run through `restorer` when there is one. A zip document
/// keeps its exact result: its XML is compressed and cannot be edited as a byte string.
fn tolerate(restorer: Option<&Restorer>, output: Output, label: &dyn Display) -> Output {
    let Some(restorer) = restorer else {
        return output;
    };
    match output {
        Output::Text(text) => {
            let bytes = restorer.restore(text.as_bytes());
            Output::Text(
                String::from_utf8(bytes)
                    .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
            )
        }
        Output::Same(raw) if raw.starts_with(b"PK\x03\x04") => {
            eprintln!(
                "piikey-cli: {label}: --tolerant skipped, documents are restored exactly only"
            );
            Output::Same(raw)
        }
        Output::Same(raw) => Output::Same(restorer.restore(&raw)),
    }
}

fn execute(command: Command) -> ExitCode {
    match command {
        Command::Help => ExitCode::SUCCESS,
        Command::Stdin {
            mode,
            vault,
            tolerant,
        } => {
            let result = open_engine(vault).and_then(|engine| {
                let restorer = tolerant_restorer(&engine, tolerant)?;
                run_stdin(&engine, mode, restorer.as_ref())
            });
            finish(result)
        }
        Command::Files {
            mode,
            vault,
            tolerant,
            out,
            inputs,
        } => run_files_command(mode, vault, tolerant, &out, &inputs),
        Command::Serve { vault, pipe } => {
            let pipe = pipe.unwrap_or_else(|| service::DEFAULT_PIPE.to_owned());
            let result = open_engine(vault).and_then(|engine| {
                eprintln!("piikey-cli: serving on {pipe}");
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
            eprintln!("piikey-cli: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_stdin(engine: &Engine, mode: Mode, restorer: Option<&Restorer>) -> piikey::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().lock().read_to_end(&mut bytes)?;
    let output = formats::process(engine, mode, &bytes, 0)?;
    let output = tolerate(restorer, output, &"stdin");
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
    tolerant: bool,
    out: &Path,
    inputs: &[PathBuf],
) -> ExitCode {
    match out_inside_inputs(out, inputs) {
        Ok(None) => {}
        Ok(Some(dir)) => {
            eprintln!(
                "piikey-cli: --out {} must not be inside input directory {}",
                out.display(),
                dir.display()
            );
            return ExitCode::from(2);
        }
        Err(err) => {
            eprintln!("piikey-cli: {}: {err}", out.display());
            return ExitCode::FAILURE;
        }
    }
    let opened = open_engine(vault).and_then(|engine| {
        let restorer = tolerant_restorer(&engine, tolerant)?;
        Ok((engine, restorer))
    });
    let (engine, restorer) = match opened {
        Ok(opened) => opened,
        Err(err) => {
            eprintln!("piikey-cli: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (jobs, walk_errors) = collect_jobs(inputs);
    for (path, err) in &walk_errors {
        eprintln!("piikey-cli: {}: {err}", path.display());
    }
    let any_failed = jobs
        .par_iter()
        .map(
            |job| match process_file(&engine, mode, restorer.as_ref(), job, out) {
                Ok(()) => false,
                Err(err) => {
                    eprintln!("piikey-cli: {}: {err}", job.src.display());
                    true
                }
            },
        )
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

fn process_file(
    engine: &Engine,
    mode: Mode,
    restorer: Option<&Restorer>,
    job: &Job,
    out: &Path,
) -> piikey::Result<()> {
    let bytes = fs::read(&job.src)?;
    let output = formats::process(engine, mode, &bytes, 0)?;
    let output = tolerate(restorer, output, &job.src.display());
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
                vault: None,
                tolerant: false,
            })
        );
        assert_eq!(
            args(&["deanonymize", "--vault", "v.pkv"]),
            Ok(Command::Stdin {
                mode: Mode::Deanonymize,
                vault: Some(PathBuf::from("v.pkv")),
                tolerant: false,
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
                tolerant: false,
                out: PathBuf::from("o"),
                inputs: vec![PathBuf::from("a.txt"), PathBuf::from("dir")],
            })
        );
    }

    #[test]
    fn parses_tolerant() {
        assert_eq!(
            args(&["deanonymize", "--tolerant", "--vault", "v"]),
            Ok(Command::Stdin {
                mode: Mode::Deanonymize,
                vault: Some(PathBuf::from("v")),
                tolerant: true,
            })
        );
        assert_eq!(
            args(&["deanonymize", "--tolerant", "--out", "o", "a.txt"]),
            Ok(Command::Files {
                mode: Mode::Deanonymize,
                vault: None,
                tolerant: true,
                out: PathBuf::from("o"),
                inputs: vec![PathBuf::from("a.txt")],
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
        assert!(usage(&["anonymize", "--tolerant"]));
        assert!(usage(&["anonymize", "--tolerant", "--out", "o", "a.txt"]));
        assert!(usage(&["serve", "--tolerant"]));
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

    #[test]
    fn the_tolerant_scope_holds_every_proxy_with_its_kind_and_original() -> piikey::Result<()> {
        let tmp = TempDir::new()?;
        let engine = Engine::open(&tmp.0.join("v.pkv"))?;
        engine.run(
            Mode::Anonymize,
            &["NL91ABNA0417164300 mailt jan.jansen@acme.nl"],
        )?;
        let scope = vault_scope(&engine)?;
        let mut found: Vec<(EntityKind, &str)> = scope
            .entries()
            .iter()
            .map(|e| (e.kind, &*e.original))
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                (EntityKind::Email, "jan.jansen@acme.nl"),
                (EntityKind::Iban, "NL91ABNA0417164300")
            ]
        );
        let view = engine.vault().read()?;
        for entry in scope.entries() {
            assert_eq!(view.original_for(&entry.proxy), Some(&*entry.original));
            assert_eq!(view.kind_of(&entry.proxy), Some(entry.kind));
        }
        Ok(())
    }

    #[test]
    fn the_tolerant_restorer_needs_the_flag_and_a_proxy() -> piikey::Result<()> {
        let tmp = TempDir::new()?;
        let engine = Engine::open(&tmp.0.join("v.pkv"))?;
        assert!(tolerant_restorer(&engine, true)?.is_none(), "empty vault");
        engine.run(Mode::Anonymize, &["jan.jansen@acme.nl"])?;
        assert!(tolerant_restorer(&engine, false)?.is_none(), "flag off");
        assert!(tolerant_restorer(&engine, true)?.is_some());
        Ok(())
    }

    #[test]
    fn tolerate_leaves_documents_alone_and_does_nothing_without_a_restorer() -> piikey::Result<()> {
        let tmp = TempDir::new()?;
        let engine = Engine::open(&tmp.0.join("v.pkv"))?;
        engine.run(Mode::Anonymize, &["jan.jansen@acme.nl"])?;
        let restorer = tolerant_restorer(&engine, true)?;
        let zip = Output::Same(b"PK\x03\x04 pretend this is a zip".to_vec());
        assert_eq!(tolerate(restorer.as_ref(), zip.clone(), &"x.docx"), zip);
        let text = Output::Text("plain text".to_owned());
        assert_eq!(tolerate(None, text.clone(), &"x.txt"), text);
        Ok(())
    }
}
