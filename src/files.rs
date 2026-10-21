//! File jobs shared by the CLI, the API and the app: which files an input names, where the result
//! of each goes, and running a rewrite over them.
//!
//! Directories are walked recursively. Symlinks and junctions found on the way are never
//! followed, so a link cannot lead out of the tree or round in a circle.

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, Metadata},
    io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
};

use rayon::prelude::*;

use crate::{
    Error, Result,
    detect::{EntityKind, Mode},
    engine::Engine,
    formats::{self, Output},
    restore::{Restorer, Scope, ScopeEntry},
    sys::io_context,
};

/// `FILE_ATTRIBUTE_OFFLINE`, `_RECALL_ON_OPEN` and `_RECALL_ON_DATA_ACCESS`: the attributes a
/// cloud file that is not on this PC carries.
const ONLINE_ONLY: u32 = 0x1000 | 0x4_0000 | 0x40_0000;

/// Whether `meta` is of a file or folder that is online only (a `OneDrive` file that is not on
/// this PC): reading it would download it, so a crawl leaves it alone.
#[must_use]
pub fn is_online_only(meta: &Metadata) -> bool {
    meta.file_attributes() & ONLINE_ONLY != 0
}

/// One input file and where its result goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub input: PathBuf,
    /// The output folder joined with the input's path relative to the input it was found under
    /// (a file input is named by its file name). Empty when [`collect`] was given no output
    /// folder. A result that is text is written beside it with `.txt` added, see [`transform`].
    pub output: PathBuf,
}

/// The files `inputs` name: a file as itself, a directory as every file in it, below it too.
/// With an output folder, each job says where its result goes; with `None` (a scan writes
/// nothing) the outputs are empty.
///
/// This is for work the caller asked for by name, so it fails rather than skips: on the first
/// input or entry that does not exist or cannot be listed, on an output folder inside an input
/// directory (the output would be processed in turn), and on two files that would be written to
/// the same file (Windows paths are not case sensitive).
///
/// # Errors
/// `Io` naming the path that cannot be read; `BadRequest` for the output problems above.
pub fn collect(inputs: &[PathBuf], out: Option<&Path>) -> Result<Vec<Job>> {
    if let Some(out) = out {
        match out_inside_inputs(out, inputs) {
            Ok(None) => {}
            Ok(Some(dir)) => {
                return Err(Error::BadRequest(format!(
                    "the output folder {} must not be inside the input folder {}",
                    out.display(),
                    dir.display()
                )));
            }
            Err(err) => return Err(io_context(&err, "resolve", out)),
        }
    }
    let mut jobs = Vec::new();
    for input in inputs {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        crawl(input, &|_, _| false, &mut found, &mut errors);
        if let Some((path, err)) = errors.first() {
            return Err(io_context(err, "read", path));
        }
        for (path, _) in found {
            let output = match out {
                Some(out) => out.join(relative_to(input, &path)?),
                None => PathBuf::new(),
            };
            jobs.push(Job {
                input: path,
                output,
            });
        }
    }
    if out.is_some() {
        refuse_collisions(&jobs)?;
    }
    Ok(jobs)
}

/// `path`, a file found under `input`, relative to it; for the input itself (a file) its name.
fn relative_to(input: &Path, path: &Path) -> Result<PathBuf> {
    if path == input {
        return input.file_name().map(PathBuf::from).ok_or_else(|| {
            io_context(
                &io::Error::new(io::ErrorKind::InvalidInput, "no file name"),
                "read",
                input,
            )
        });
    }
    Ok(path
        .strip_prefix(input)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf))
}

/// Windows paths are not case sensitive: two inputs mapping to the same output would silently
/// overwrite each other.
fn refuse_collisions(jobs: &[Job]) -> Result<()> {
    let mut seen: HashMap<String, &Path> = HashMap::with_capacity(jobs.len());
    for job in jobs {
        let key = job.output.to_string_lossy().to_lowercase();
        if let Some(first) = seen.insert(key, &job.input) {
            return Err(Error::BadRequest(format!(
                "{} and {} would be written to the same file",
                first.display(),
                job.input.display()
            )));
        }
    }
    Ok(())
}

/// Every regular file under `inputs`, with its metadata, each once and in path order: a file
/// input as itself, a directory recursively. `skip` is asked about every entry found while
/// walking, not about the inputs, and says whether to leave it out (a directory with
/// everything below it). The metadata is the directory listing's, so no entry costs a system
/// call of its own.
///
/// This is for crawls that do what they can: an input that does not exist and a directory
/// that cannot be listed are left out. [`collect`] is the strict one.
#[must_use]
pub fn walk(
    inputs: &[PathBuf],
    skip: &dyn Fn(&Path, &Metadata) -> bool,
) -> Vec<(PathBuf, Metadata)> {
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for input in inputs {
        crawl(input, skip, &mut found, &mut errors);
    }
    found.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    found.dedup_by(|a, b| a.0 == b.0);
    found
}

/// Adds every file under `root` to `found`, and what cannot be read to `errors`; both are
/// unordered. A `root` that is a file is added as itself.
fn crawl(
    root: &Path,
    skip: &dyn Fn(&Path, &Metadata) -> bool,
    found: &mut Vec<(PathBuf, Metadata)>,
    errors: &mut Vec<(PathBuf, io::Error)>,
) {
    let meta = match fs::metadata(root) {
        Ok(meta) => meta,
        Err(err) => {
            errors.push((root.to_path_buf(), err));
            return;
        }
    };
    if meta.is_file() {
        found.push((root.to_path_buf(), meta));
        return;
    }
    if !meta.is_dir() {
        errors.push((
            root.to_path_buf(),
            io::Error::new(io::ErrorKind::InvalidInput, "not a file or directory"),
        ));
        return;
    }
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
            // On Windows both come with the listing: no system call.
            let (file_type, meta) = match entry.file_type().and_then(|t| Ok((t, entry.metadata()?)))
            {
                Ok(both) => both,
                Err(err) => {
                    errors.push((path, err));
                    continue;
                }
            };
            if file_type.is_symlink() || skip(&path, &meta) {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                found.push((path, meta));
            }
        }
    }
}

/// Runs `mode` over every job's input and writes the result to its output, in parallel. One
/// result per job, in order: the file written (a result that is text, from a PDF, an image or a
/// mail, goes to `<output>.txt`) or why that job failed; the other jobs go on. Missing folders
/// are created and an existing output is overwritten.
///
/// `tolerant` also restores proxies that came back with a typo, and names that came back alone;
/// it only applies to [`Mode::Deanonymize`] (after an anonymize it would undo the masking), and
/// only to text, not to zip documents, which are restored exactly.
#[must_use]
pub fn transform(
    engine: &Engine,
    mode: Mode,
    tolerant: bool,
    jobs: &[Job],
) -> Vec<(PathBuf, Result<PathBuf>)> {
    let restorer = match tolerant_restorer(engine, tolerant && mode == Mode::Deanonymize) {
        Ok(restorer) => restorer,
        Err(err) => {
            let why = err.to_string();
            return jobs
                .iter()
                .map(|job| {
                    let failed =
                        io::Error::other(format!("cannot prepare the tolerant restore: {why}"));
                    (job.input.clone(), Err(Error::Io(failed)))
                })
                .collect();
        }
    };
    jobs.par_iter()
        .map(|job| {
            (
                job.input.clone(),
                process_file(engine, mode, restorer.as_ref(), job),
            )
        })
        .collect()
}

fn process_file(
    engine: &Engine,
    mode: Mode,
    restorer: Option<&Restorer>,
    job: &Job,
) -> Result<PathBuf> {
    let bytes = fs::read(&job.input)?;
    let output = tolerate(restorer, formats::process(engine, mode, &bytes, 0)?);
    let (dest, data) = match &output {
        Output::Same(raw) => (job.output.clone(), raw.as_slice()),
        Output::Text(text) => (text_path(&job.output), text.as_bytes()),
    };
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| io_context(&e, "create", parent))?;
    }
    fs::write(&dest, data).map_err(|e| io_context(&e, "write", &dest))?;
    Ok(dest)
}

/// `output` with `.txt` added to the full file name: where a result that is text goes.
fn text_path(output: &Path) -> PathBuf {
    let mut joined = output.as_os_str().to_owned();
    joined.push(".txt");
    PathBuf::from(joined)
}

/// Where a masked copy of `input` goes: beside it as `<stem>.masked.<ext>`, or
/// `<stem>.masked.txt` when the result is text (a PDF, an image or a mail is written as text).
#[must_use]
pub fn masked_copy_path(input: &Path, output: &Output) -> PathBuf {
    let mut name = input.file_stem().unwrap_or_default().to_owned();
    name.push(".masked");
    let ext = match output {
        Output::Text(_) => Some(OsStr::new("txt")),
        Output::Same(_) => input.extension(),
    };
    if let Some(ext) = ext {
        name.push(".");
        name.push(ext);
    }
    input.with_file_name(name)
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

/// The restorer behind a tolerant deanonymize: scoped to every proxy in the vault. `None` when
/// `wanted` is false or the vault holds no proxy.
///
/// # Errors
/// `Poisoned`, or the restorer's matcher failing to build.
pub fn tolerant_restorer(engine: &Engine, wanted: bool) -> Result<Option<Restorer>> {
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
fn vault_scope(engine: &Engine) -> Result<Scope> {
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
#[must_use]
pub fn tolerate(restorer: Option<&Restorer>, output: Output) -> Output {
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
        Output::Same(raw) if raw.starts_with(b"PK\x03\x04") => Output::Same(raw),
        Output::Same(raw) => Output::Same(restorer.restore(&raw)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Temp directory removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> io::Result<Self> {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "piikey-files-test-{}-{}",
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

    fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)
    }

    fn names(walked: &[(PathBuf, Metadata)], root: &Path) -> Vec<PathBuf> {
        walked
            .iter()
            .filter_map(|(path, _)| path.strip_prefix(root).ok().map(Path::to_path_buf))
            .collect()
    }

    #[test]
    fn output_paths_add_txt_to_the_full_name_of_a_text_result() {
        let output = Path::new("out").join("sub").join("x.pdf");
        assert_eq!(
            text_path(&output),
            Path::new("out").join("sub").join("x.pdf.txt")
        );
    }

    #[test]
    fn masked_copies_sit_beside_the_input() {
        let docx = Path::new("dir").join("report.docx");
        let same = Output::Same(Vec::new());
        let text = Output::Text(String::new());
        assert_eq!(
            masked_copy_path(&docx, &same),
            Path::new("dir").join("report.masked.docx")
        );
        assert_eq!(
            masked_copy_path(&Path::new("dir").join("scan.pdf"), &text),
            Path::new("dir").join("scan.masked.txt")
        );
        assert_eq!(
            masked_copy_path(&Path::new("dir").join("notes.txt"), &text),
            Path::new("dir").join("notes.masked.txt")
        );
        assert_eq!(
            masked_copy_path(Path::new("README"), &same),
            Path::new("README.masked")
        );
        assert_eq!(
            masked_copy_path(Path::new("a.tar.gz"), &same),
            Path::new("a.tar.masked.gz")
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
    fn collects_files_recursively_with_their_outputs() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir = tmp.0.join("in");
        write(&dir.join("top.txt"), b"1")?;
        write(&dir.join("a").join("b").join("deep.txt"), b"2")?;
        let single = tmp.0.join("single.txt");
        write(&single, b"3")?;
        let out = tmp.0.join("out");

        let mut jobs = collect(&[dir.clone(), single.clone()], Some(&out))?;
        jobs.sort_by(|x, y| x.output.cmp(&y.output));
        let outputs: Vec<PathBuf> = jobs.iter().map(|j| j.output.clone()).collect();
        assert_eq!(
            outputs,
            [
                out.join("a").join("b").join("deep.txt"),
                out.join("single.txt"),
                out.join("top.txt"),
            ]
        );
        assert!(jobs.iter().any(|j| j.input == single));
        assert!(jobs.iter().any(|j| j.input == dir.join("top.txt")));
        Ok(())
    }

    #[test]
    fn a_scan_needs_no_output_folder_and_files_of_one_name_are_fine() -> Result<()> {
        let tmp = TempDir::new()?;
        write(&tmp.0.join("one").join("same.txt"), b"1")?;
        write(&tmp.0.join("two").join("same.txt"), b"2")?;
        let jobs = collect(&[tmp.0.join("one"), tmp.0.join("two")], None)?;
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|job| job.output.as_os_str().is_empty()));
        Ok(())
    }

    #[test]
    fn a_missing_input_is_an_error_that_names_it() -> Result<()> {
        let tmp = TempDir::new()?;
        let missing = tmp.0.join("nope");
        match collect(std::slice::from_ref(&missing), None) {
            Err(Error::Io(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::NotFound);
                assert!(err.to_string().contains("nope"), "{err}");
            }
            other => panic!("expected a not-found error, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn two_files_for_one_output_are_refused_whatever_the_case() -> Result<()> {
        let tmp = TempDir::new()?;
        write(&tmp.0.join("a").join("Same.txt"), b"1")?;
        write(&tmp.0.join("b").join("same.TXT"), b"2")?;
        let inputs = [
            tmp.0.join("a").join("Same.txt"),
            tmp.0.join("b").join("same.TXT"),
        ];
        let Err(Error::BadRequest(message)) = collect(&inputs, Some(&tmp.0.join("out"))) else {
            panic!("expected a bad request");
        };
        assert!(message.contains("same file"), "{message}");
        Ok(())
    }

    #[test]
    fn an_output_folder_inside_an_input_is_a_bad_request() -> Result<()> {
        let tmp = TempDir::new()?;
        write(&tmp.0.join("in").join("a.txt"), b"1")?;
        let result = collect(&[tmp.0.join("in")], Some(&tmp.0.join("in").join("out")));
        assert!(matches!(result, Err(Error::BadRequest(_))), "{result:?}");
        Ok(())
    }

    #[test]
    fn walking_lists_each_file_once_in_path_order_and_honours_skip() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let root = tmp.0.join("root");
        for file in [
            "b.txt",
            "a.txt",
            "keep/c.txt",
            "node_modules/d.txt",
            "keep/skip.me",
        ] {
            write(&root.join(file), b"x")?;
        }
        let skip = |path: &Path, meta: &Metadata| {
            (meta.is_dir() && path.ends_with("node_modules")) || path.ends_with("skip.me")
        };
        // The root twice, and a folder of it as well: still once each.
        let walked = walk(&[root.clone(), root.clone(), root.join("keep")], &skip);
        assert_eq!(
            names(&walked, &root),
            [
                PathBuf::from("a.txt"),
                PathBuf::from("b.txt"),
                Path::new("keep").join("c.txt"),
            ]
        );
        assert!(
            walked
                .iter()
                .all(|(_, meta)| meta.is_file() && meta.len() == 1)
        );
        Ok(())
    }

    #[test]
    fn walking_takes_a_file_input_as_it_is_and_forgives_what_is_missing() -> io::Result<()> {
        let tmp = TempDir::new()?;
        let file = tmp.0.join("only.txt");
        write(&file, b"x")?;
        let walked = walk(&[file.clone(), tmp.0.join("gone")], &|_, _| true);
        assert_eq!(walked.len(), 1);
        assert_eq!(walked[0].0, file);
        Ok(())
    }

    /// An engine whose vault lives in `tmp`.
    fn engine_in(tmp: &TempDir) -> Result<Engine> {
        Engine::open(&tmp.0.join("v.pkv"))
    }

    #[test]
    fn transform_masks_files_into_the_output_folder_and_restores_them() -> Result<()> {
        let tmp = TempDir::new()?;
        let engine = engine_in(&tmp)?;
        write(
            &tmp.0.join("in").join("sub").join("a.txt"),
            b"mail jan.jansen@acme.nl",
        )?;
        write(&tmp.0.join("in").join("b.txt"), b"nothing here")?;
        let out = tmp.0.join("out");
        let jobs = collect(&[tmp.0.join("in")], Some(&out))?;

        let results = transform(&engine, Mode::Anonymize, false, &jobs);
        assert_eq!(results.len(), 2);
        for (input, written) in &results {
            match written {
                Ok(path) => assert!(path.starts_with(&out), "{input:?} -> {path:?}"),
                Err(err) => panic!("{input:?} failed: {err}"),
            }
        }
        let masked = fs::read_to_string(out.join("sub").join("a.txt"))?;
        assert!(
            masked.starts_with("mail ") && !masked.contains("jan.jansen"),
            "{masked}"
        );
        assert_eq!(fs::read_to_string(out.join("b.txt"))?, "nothing here");

        let back = tmp.0.join("back");
        let jobs = collect(std::slice::from_ref(&out), Some(&back))?;
        for (_, written) in transform(&engine, Mode::Deanonymize, false, &jobs) {
            written?;
        }
        assert_eq!(
            fs::read_to_string(back.join("sub").join("a.txt"))?,
            "mail jan.jansen@acme.nl"
        );
        Ok(())
    }

    #[test]
    fn transform_reports_each_failure_and_goes_on() -> Result<()> {
        let tmp = TempDir::new()?;
        let engine = engine_in(&tmp)?;
        write(&tmp.0.join("good.txt"), b"mail jan.jansen@acme.nl")?;
        let good = Job {
            input: tmp.0.join("good.txt"),
            output: tmp.0.join("out").join("good.txt"),
        };
        let bad = Job {
            input: tmp.0.join("vanished.txt"),
            output: tmp.0.join("out").join("vanished.txt"),
        };
        let results = transform(&engine, Mode::Anonymize, false, &[bad, good]);
        assert!(matches!(&results[0].1, Err(Error::Io(_))));
        assert!(results[1].1.is_ok());
        assert_eq!(results[0].0, tmp.0.join("vanished.txt"));
        Ok(())
    }

    #[test]
    fn tolerant_never_applies_to_an_anonymize() -> Result<()> {
        let tmp = TempDir::new()?;
        let engine = engine_in(&tmp)?;
        engine.run(Mode::Anonymize, &["jan.jansen@acme.nl"])?;
        write(&tmp.0.join("a.txt"), b"mail jan.jansen@acme.nl")?;
        let jobs = collect(&[tmp.0.join("a.txt")], Some(&tmp.0.join("out")))?;
        for (_, written) in transform(&engine, Mode::Anonymize, true, &jobs) {
            written?;
        }
        let masked = fs::read_to_string(tmp.0.join("out").join("a.txt"))?;
        assert!(!masked.contains("jan.jansen@acme.nl"), "{masked}");
        Ok(())
    }

    #[test]
    fn the_tolerant_scope_holds_every_proxy_with_its_kind_and_original() -> Result<()> {
        let tmp = TempDir::new()?;
        let engine = engine_in(&tmp)?;
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
    fn the_tolerant_restorer_needs_the_flag_and_a_proxy() -> Result<()> {
        let tmp = TempDir::new()?;
        let engine = engine_in(&tmp)?;
        assert!(tolerant_restorer(&engine, true)?.is_none(), "empty vault");
        engine.run(Mode::Anonymize, &["jan.jansen@acme.nl"])?;
        assert!(tolerant_restorer(&engine, false)?.is_none(), "flag off");
        assert!(tolerant_restorer(&engine, true)?.is_some());
        Ok(())
    }

    #[test]
    fn tolerate_leaves_documents_alone_and_does_nothing_without_a_restorer() -> Result<()> {
        let tmp = TempDir::new()?;
        let engine = engine_in(&tmp)?;
        engine.run(Mode::Anonymize, &["jan.jansen@acme.nl"])?;
        let restorer = tolerant_restorer(&engine, true)?;
        let zip = Output::Same(b"PK\x03\x04 pretend this is a zip".to_vec());
        assert_eq!(tolerate(restorer.as_ref(), zip.clone()), zip);
        let text = Output::Text("plain text".to_owned());
        assert_eq!(tolerate(None, text.clone()), text);
        Ok(())
    }
}
