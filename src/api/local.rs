//! [`Local`]: the handler that answers a request in this process, and the API token.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value;

use super::{ApiError, Format, Handler, Request, object};
use crate::{
    Error, Result,
    detect::{
        EntityKind, Mode, NerDetector,
        ner::{self, Device, NerState},
    },
    engine::Engine,
    files,
    inventory::{Entry, Inventory, Progress},
    policy::{Policy, SettingsPatch, default_inventory_roots},
    restore::Restorer,
    subject,
    sys::{self, io_context},
    vault,
};

/// Hands out the engine a request runs on, each time one does. The command line holds one
/// engine for the whole run; the app hands out the engine it has at that moment, which is
/// another one after the model was loaded or released.
pub type EngineSource = Arc<dyn Fn() -> Arc<Engine> + Send + Sync>;

/// Told how far a download is, in bytes done and bytes in all.
type DownloadProgress = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// The token's file in the data folder.
const TOKEN_FILE: &str = "api.token";
/// A token is this many random bytes, written in hex.
const TOKEN_BYTES: usize = 32;
/// A token on file shorter than this is not one piikey made (or someone cut it): it is replaced.
const MIN_TOKEN: usize = 32;
/// How many records or entries a list returns when it is not told.
const LIST_DEFAULT: usize = 100;
/// The most a list returns at once.
const LIST_MAX: usize = 10_000;

/// Answers every request in this process, on the engine, the inventory and the saved settings
/// it was given. Only what needs the app is refused: `protection` and `explorer_scan` answer
/// `app_required`.
///
/// The settings and the token are read from and written to the data folder
/// (`%LOCALAPPDATA%\piikey`), so they are the user's, like the app's. The kinds of personal data
/// a scan or a masking looks for are the engine's ([`Engine::set_enabled`]), not read from the
/// settings here: whoever hands over the engine sets them from [`Policy::enabled_kinds`].
pub struct Local {
    engine: EngineSource,
    inventory: Arc<Inventory>,
    /// The model the engine detects with, if it has one: it tells how the model is doing.
    ner: Option<NerDetector>,
    /// Where the model lives when it is not in the data folder (tests).
    model_dir: Option<PathBuf>,
    on_download: Option<DownloadProgress>,
    /// Held while the model downloads: two downloads would write the same files.
    downloading: Mutex<()>,
    /// What the rescan of this process has done, and whether it runs.
    rescan: Progress,
    rescanning: AtomicBool,
}

impl fmt::Debug for Local {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Local").finish_non_exhaustive()
    }
}

impl Local {
    /// A handler over `engine` and `inventory`. `ner` is the detection model the engine was
    /// opened with, if any (a clone shares the model): the model's status reads it.
    #[must_use]
    pub fn new(engine: EngineSource, inventory: Arc<Inventory>, ner: Option<NerDetector>) -> Self {
        Self {
            engine,
            inventory,
            ner,
            model_dir: None,
            on_download: None,
            downloading: Mutex::new(()),
            rescan: Progress::default(),
            rescanning: AtomicBool::new(false),
        }
    }

    /// Calls `progress(done, total)`, in bytes, while `model_download` runs.
    #[must_use]
    pub fn with_progress(mut self, progress: Arc<dyn Fn(u64, u64) + Send + Sync>) -> Self {
        self.on_download = Some(progress);
        self
    }

    /// Looks for the model, and downloads it, in `dir` instead of the data folder.
    #[must_use]
    pub fn with_model_dir(mut self, dir: PathBuf) -> Self {
        self.model_dir = Some(dir);
        self
    }

    fn engine(&self) -> Arc<Engine> {
        (self.engine)()
    }

    fn model_dir(&self) -> Result<PathBuf> {
        match &self.model_dir {
            Some(dir) => Ok(dir.clone()),
            None => ner::files::default_dir(),
        }
    }

    fn scan_text(&self, texts: &[String]) -> Result<Value, ApiError> {
        let found = self.engine().scan(&refs(texts))?;
        let results: Vec<Value> = texts
            .iter()
            .zip(&found)
            .map(|(text, spans)| {
                spans
                    .iter()
                    .map(|span| {
                        object([
                            ("start", span.start.into()),
                            ("end", span.end.into()),
                            ("kind", span.kind.as_str().into()),
                            (
                                "value",
                                text.get(span.start..span.end).unwrap_or_default().into(),
                            ),
                        ])
                    })
                    .collect()
            })
            .collect();
        Ok(object([("results", results.into())]))
    }

    fn rewrite_text(
        &self,
        mode: Mode,
        texts: &[String],
        tolerant: bool,
    ) -> Result<Value, ApiError> {
        let engine = self.engine();
        let mut out = engine.run(mode, &refs(texts))?;
        let restorer = files::tolerant_restorer(&engine, tolerant && mode == Mode::Deanonymize)?;
        if let Some(restorer) = &restorer {
            out.par_iter_mut()
                .for_each(|text| *text = restore_text(restorer, text));
        }
        Ok(object([("texts", out.into())]))
    }

    fn scan_files(&self, paths: &[PathBuf], record: bool) -> Result<Value, ApiError> {
        all_absolute(paths)?;
        let mut jobs = files::collect(paths, None)?;
        // A folder and a file inside it are both named: the file is one file, not two.
        jobs.sort_unstable_by(|a, b| a.input.cmp(&b.input));
        jobs.dedup_by(|a, b| a.input == b.input);
        let engine = self.engine();
        let entries: Vec<Entry> = jobs
            .par_iter()
            .map(|job| Entry::scan(&engine, &job.input))
            .collect();
        let hits: u64 = entries.iter().map(Entry::hits).sum();
        let shown = to_json(&entries)?;
        if record {
            self.inventory.record(entries)?;
        }
        Ok(object([("files", shown), ("hits", hits.into())]))
    }

    fn rewrite_files(
        &self,
        mode: Mode,
        paths: &[PathBuf],
        out: &Path,
        tolerant: bool,
    ) -> Result<Value, ApiError> {
        all_absolute(paths)?;
        absolute(out)?;
        let jobs = files::collect(paths, Some(out))?;
        let engine = self.engine();
        let mut written = Vec::new();
        let mut failed = Vec::new();
        for (input, result) in files::transform(&engine, mode, tolerant, &jobs) {
            match result {
                Ok(output) => written.push(object([
                    ("input", lossy(&input).into()),
                    ("output", lossy(&output).into()),
                ])),
                Err(error) => failed.push(object([
                    ("input", lossy(&input).into()),
                    ("error", error.to_string().into()),
                ])),
            }
        }
        Ok(object([
            ("written", written.into()),
            ("failed", failed.into()),
        ]))
    }

    fn subject_search(&self, values: &[String], paths: &[PathBuf]) -> Result<Value, ApiError> {
        all_absolute(paths)?;
        let roots;
        let paths = if paths.is_empty() {
            roots = effective_roots(&Policy::load()?);
            roots.as_slice()
        } else {
            paths
        };
        let found = subject::search(&self.engine(), values, paths, &AtomicBool::new(false))?;
        Ok(object([("matches", to_json(&found)?)]))
    }

    fn vault_list(
        &self,
        query: Option<&str>,
        kind: Option<&str>,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<Value, ApiError> {
        let kind = kind.map(parse_kind).transpose()?;
        let limit = limit.unwrap_or(LIST_DEFAULT).min(LIST_MAX);
        let engine = self.engine();
        let view = engine.vault().read()?;
        let mut total = 0_usize;
        let mut records = Vec::new();
        for (at, (kind, original, proxy)) in
            view.search(query.unwrap_or_default(), kind).enumerate()
        {
            total += 1;
            if at >= offset && records.len() < limit {
                records.push(object([
                    ("kind", kind.as_str().into()),
                    ("original", original.into()),
                    ("proxy", proxy.into()),
                ]));
            }
        }
        Ok(object([
            ("records", records.into()),
            ("total", total.into()),
        ]))
    }

    fn vault_forget(&self, values: &[String]) -> Result<Value, ApiError> {
        let forgotten = self.engine().forget(&refs(values))?;
        Ok(object([("forgotten", forgotten.into())]))
    }

    fn vault_wipe(&self, confirm: bool) -> Result<Value, ApiError> {
        if !confirm {
            return Err(ApiError::bad_request(
                "vault_wipe removes every record from the vault and needs confirm: true",
            ));
        }
        let forgotten = self.engine().wipe()?;
        Ok(object([("forgotten", forgotten.into())]))
    }

    fn vault_export(&self, path: &Path, format: Format) -> Result<Value, ApiError> {
        absolute(path)?;
        let engine = self.engine();
        let records = write_new(path, |out| {
            vault::export(&engine.vault().read()?, format.into(), out)
        })?;
        Ok(object([
            ("records", records.into()),
            ("path", lossy(path).into()),
        ]))
    }

    fn inventory_status(&self) -> Result<Value, ApiError> {
        let policy = Policy::load()?;
        let totals = self.inventory.totals();
        let scanning = self.rescanning.load(Ordering::Relaxed).then(|| {
            object([
                ("done", self.rescan.done.load(Ordering::Relaxed).into()),
                ("total", self.rescan.total.load(Ordering::Relaxed).into()),
            ])
        });
        Ok(object([
            ("enabled", policy.inventory.into()),
            ("roots", paths_json(&effective_roots(&policy))),
            ("files", totals.files.into()),
            ("files_with_pii", totals.files_with_pii.into()),
            ("hits", totals.hits.into()),
            ("scanning", scanning.into()),
        ]))
    }

    fn inventory_list(
        &self,
        under: Option<&Path>,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<Value, ApiError> {
        under.map(absolute).transpose()?;
        let mut entries = self.inventory.entries(under, 1);
        entries.sort_by(|a, b| b.hits().cmp(&a.hits()).then_with(|| a.path.cmp(&b.path)));
        let total = entries.len();
        let page = entries
            .iter()
            .skip(offset)
            .take(limit.unwrap_or(LIST_DEFAULT).min(LIST_MAX))
            .map(to_json)
            .collect::<Result<Vec<Value>, ApiError>>()?;
        Ok(object([("entries", page.into()), ("total", total.into())]))
    }

    fn inventory_tree(&self, under: Option<&Path>) -> Result<Value, ApiError> {
        under.map(absolute).transpose()?;
        let roots = effective_roots(&Policy::load()?);
        let nodes = self.inventory.children(under, &roots);
        Ok(object([("nodes", to_json(&nodes)?)]))
    }

    fn inventory_rescan(&self) -> Result<Value, ApiError> {
        let policy = Policy::load()?;
        let roots = effective_roots(&policy);
        let _lock = self.inventory.lock_scan()?;
        let _running = Running::start(&self.rescanning);
        self.inventory.scan_paths(
            &self.engine(),
            &roots,
            &policy.inventory_exclude,
            &self.rescan,
            &AtomicBool::new(false),
        )?;
        to_json(&self.inventory.totals())
    }

    fn inventory_report(&self, path: &Path, format: Format) -> Result<Value, ApiError> {
        absolute(path)?;
        let rows = write_new(path, |out| self.inventory.report(None, format.into(), out))?;
        Ok(object([
            ("rows", rows.into()),
            ("path", lossy(path).into()),
        ]))
    }

    fn model_status(&self) -> Result<Value, ApiError> {
        let dir = self.model_dir()?;
        let state = match &self.ner {
            Some(ner) => ner.state(),
            None if ner::files::is_installed(&dir) => NerState::Unloaded,
            None => NerState::Missing,
        };
        let (name, device, error) = match &state {
            NerState::Missing => ("missing", None, None),
            NerState::Unloaded => ("unloaded", None, None),
            NerState::Ready(Device::Cpu) => ("ready", Some("cpu"), None),
            NerState::Ready(Device::Hybrid) => ("ready", Some("hybrid"), None),
            NerState::Failed(message) => ("failed", None, Some(message.as_str())),
        };
        let mut status = object([
            ("state", name.into()),
            ("device", device.into()),
            ("dir", lossy(&dir).into()),
        ]);
        if let (Some(error), Some(fields)) = (error, status.as_object_mut()) {
            fields.insert("error".to_owned(), error.into());
        }
        Ok(status)
    }

    fn model_download(&self) -> Result<Value, ApiError> {
        let _downloading = match self.downloading.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(ApiError::busy("the model is already being downloaded"));
            }
        };
        let dir = self.model_dir()?;
        let report = |done: u64, total: u64| {
            if let Some(progress) = &self.on_download {
                progress(done, total);
            }
        };
        ner::fetch(&dir, &report).map_err(|error| match error {
            // A tool the download needs is missing: for the caller that is the model failing.
            Error::Tool(message) => ApiError::new("model", message),
            other => ApiError::from(other),
        })?;
        Ok(object([]))
    }

    fn status(&self) -> Result<Value, ApiError> {
        let policy = Policy::load()?;
        let records = self.engine().vault().read()?.record_count();
        Ok(object([
            ("app", false.into()),
            ("protection", Value::Null),
            ("version", env!("CARGO_PKG_VERSION").into()),
            ("vault_records", records.into()),
            ("model", self.model_status()?),
            ("highlight", policy.highlight.as_str().into()),
            ("explorer_menu", policy.explorer_menu.into()),
            ("inventory", policy.inventory.into()),
            ("http_api", policy.http_api.into()),
        ]))
    }
}

impl Handler for Local {
    fn handle(&self, request: Request) -> Result<Value, ApiError> {
        match request {
            Request::ScanText { texts } => self.scan_text(&texts),
            Request::Anonymize { texts } => self.rewrite_text(Mode::Anonymize, &texts, false),
            Request::Deanonymize { texts, tolerant } => {
                self.rewrite_text(Mode::Deanonymize, &texts, tolerant)
            }
            Request::ScanFiles { paths, record } => self.scan_files(&paths, record),
            Request::AnonymizeFiles { paths, out } => {
                self.rewrite_files(Mode::Anonymize, &paths, &out, false)
            }
            Request::DeanonymizeFiles {
                paths,
                out,
                tolerant,
            } => self.rewrite_files(Mode::Deanonymize, &paths, &out, tolerant),
            Request::SubjectSearch { values, paths } => self.subject_search(&values, &paths),
            Request::VaultList {
                query,
                kind,
                limit,
                offset,
            } => self.vault_list(query.as_deref(), kind.as_deref(), limit, offset),
            Request::VaultForget { values } => self.vault_forget(&values),
            Request::VaultExport { path, format } => self.vault_export(&path, format),
            Request::VaultWipe { confirm } => self.vault_wipe(confirm),
            Request::InventoryStatus => self.inventory_status(),
            Request::InventoryList {
                under,
                limit,
                offset,
            } => self.inventory_list(under.as_deref(), limit, offset),
            Request::InventoryTree { under } => self.inventory_tree(under.as_deref()),
            Request::InventoryRescan => self.inventory_rescan(),
            Request::InventoryReport { path, format } => self.inventory_report(&path, format),
            Request::SettingsGet => to_json(&Policy::load()?),
            Request::SettingsSet { settings } => settings_set(&settings),
            Request::Kinds => kinds(),
            Request::ModelStatus => self.model_status(),
            Request::ModelDownload => self.model_download(),
            Request::ApiToken { rotate } => {
                Ok(object([("token", read_or_create_token(rotate)?.into())]))
            }
            Request::Status => self.status(),
            Request::Protection { .. } => Err(app_required("protection")),
            Request::ExplorerScan { .. } => Err(app_required("explorer_scan")),
        }
    }
}

fn app_required(op: &str) -> ApiError {
    ApiError::app_required(format!(
        "{op} needs the piikey app: start piikey.exe and try again"
    ))
}

fn settings_set(patch: &SettingsPatch) -> Result<Value, ApiError> {
    let mut policy = Policy::load()?;
    patch.apply(&mut policy)?;
    policy.save()?;
    to_json(&policy)
}

fn kinds() -> Result<Value, ApiError> {
    let enabled = Policy::load()?.enabled_kinds();
    let kinds: Vec<Value> = EntityKind::ALL
        .into_iter()
        .map(|kind| {
            object([
                ("kind", kind.as_str().into()),
                ("label", kind.label().into()),
                ("group", kind.group().into()),
                ("enabled", enabled.contains(kind).into()),
            ])
        })
        .collect();
    Ok(kinds.into())
}

/// The folders the inventory scans: the saved ones, or the usual ones when none were saved.
fn effective_roots(policy: &Policy) -> Vec<PathBuf> {
    if policy.inventory_roots.is_empty() {
        default_inventory_roots()
    } else {
        policy.inventory_roots.clone()
    }
}

fn parse_kind(name: &str) -> Result<EntityKind, ApiError> {
    EntityKind::parse(&name.trim().to_ascii_lowercase())
        .ok_or_else(|| ApiError::bad_request(format!("Not a valid kind: {name}")))
}

fn refs(texts: &[String]) -> Vec<&str> {
    texts.iter().map(String::as_str).collect()
}

/// `text` with the proxies in it restored by `restorer`.
fn restore_text(restorer: &Restorer, text: &str) -> String {
    let bytes = restorer.restore(text.as_bytes());
    String::from_utf8(bytes)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn paths_json(paths: &[PathBuf]) -> Value {
    paths
        .iter()
        .map(|path| Value::from(lossy(path)))
        .collect::<Vec<_>>()
        .into()
}

fn to_json<T: Serialize + ?Sized>(value: &T) -> Result<Value, ApiError> {
    serde_json::to_value(value)
        .map_err(|e| ApiError::internal(format!("cannot encode the result: {e}")))
}

/// A path in a request is absolute: the process that answers is not always the one that asked,
/// and a relative path means the folder it runs in.
fn absolute(path: &Path) -> Result<(), ApiError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "Not an absolute path: {}",
            path.display()
        )))
    }
}

fn all_absolute(paths: &[PathBuf]) -> Result<(), ApiError> {
    paths.iter().try_for_each(|path| absolute(path))
}

/// Creates the file `path`, which must not exist, lets `write` fill it and returns what it
/// returns. A file that was not written whole is removed again.
fn write_new(path: &Path, write: impl FnOnce(&mut dyn Write) -> Result<usize>) -> Result<usize> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io_context(&e, "create", path))?;
    let written = write(&mut file);
    drop(file);
    if written.is_err() {
        // Best effort: the file is ours, and half of it is of no use to anyone.
        let _ = fs::remove_file(path);
    }
    written
}

/// Says a rescan runs for as long as it lives.
struct Running<'a>(&'a AtomicBool);

impl<'a> Running<'a> {
    fn start(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Relaxed);
        Self(flag)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Where the HTTP API's token is kept: `%LOCALAPPDATA%\piikey\api.token`.
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` when the folder cannot be made.
pub fn token_path() -> Result<PathBuf> {
    Ok(sys::data_dir()?.join(TOKEN_FILE))
}

/// The token the HTTP API wants as `Authorization: Bearer <token>`: 32 random bytes in hex,
/// kept in [`token_path`]. It is made the first time it is asked for, and again when `rotate`
/// says so. A running HTTP server keeps the token it was started with, so start it again
/// after a rotation.
///
/// # Errors
/// `Io` when the token cannot be read or written, or no random bytes can be had.
pub fn read_or_create_token(rotate: bool) -> Result<String> {
    token_in(&token_path()?, rotate)
}

fn token_in(path: &Path, rotate: bool) -> Result<String> {
    if !rotate {
        match fs::read_to_string(path) {
            Ok(text) => {
                let token = text.trim();
                if token.len() >= MIN_TOKEN && token.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Ok(token.to_owned());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_context(&e, "read", path)),
        }
    }
    let mut bytes = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| Error::Io(io::Error::other(e)))?;
    let token = hex(&bytes);
    sys::write_atomic(path, token.as_bytes())?;
    Ok(token)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xF)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::{error::Error as StdError, sync::atomic::AtomicUsize};

    use serde_json::json;

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    /// A scratch folder under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> io::Result<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "piikey-test-{}-api-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn write(&self, name: &str, text: &str) -> io::Result<PathBuf> {
            let path = self.file(name);
            fs::write(&path, text)?;
            Ok(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A handler over a vault and an inventory in a scratch folder.
    struct Fixture {
        dir: TempDir,
        local: Local,
        inventory: Arc<Inventory>,
    }

    impl Fixture {
        fn new() -> std::result::Result<Self, Box<dyn StdError>> {
            let dir = TempDir::new()?;
            let engine = Arc::new(Engine::open(&dir.file("vault.pkv"))?);
            let inventory = Arc::new(Inventory::open(&dir.file("inventory.jsonl"))?);
            let source: EngineSource = Arc::new(move || Arc::clone(&engine));
            let local =
                Local::new(source, Arc::clone(&inventory), None).with_model_dir(dir.file("model"));
            Ok(Self {
                dir,
                local,
                inventory,
            })
        }

        fn ask(&self, request: Request) -> Result<Value, ApiError> {
            self.local.handle(request)
        }

        fn vault_total(&self) -> std::result::Result<u64, Box<dyn StdError>> {
            let list = self.ask(Request::VaultList {
                query: None,
                kind: None,
                limit: Some(1),
                offset: 0,
            })?;
            Ok(list["total"].as_u64().ok_or("no total")?)
        }

        fn mask(&self, text: &str) -> std::result::Result<String, Box<dyn StdError>> {
            let out = self.ask(Request::Anonymize {
                texts: vec![text.to_owned()],
            })?;
            Ok(out["texts"][0].as_str().ok_or("no text")?.to_owned())
        }
    }

    fn texts(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn scan_text_reports_spans_and_leaves_the_vault_alone() -> TestResult {
        let fx = Fixture::new()?;
        let before = fx.vault_total()?;
        let text = "mail jan.jansen@acme.nl, thanks";
        let reply = fx.ask(Request::ScanText {
            texts: texts(&[text, "nothing here"]),
        })?;
        let first = &reply["results"][0];
        assert_eq!(first.as_array().map(Vec::len), Some(1), "{reply}");
        assert_eq!(first[0]["kind"], "email");
        assert_eq!(first[0]["value"], "jan.jansen@acme.nl");
        assert_eq!(first[0]["start"], 5);
        assert_eq!(first[0]["end"], 5 + "jan.jansen@acme.nl".len());
        assert_eq!(reply["results"][1], json!([]));
        // The fields come in the order the README lists them.
        assert!(
            reply
                .to_string()
                .contains(r#"{"start":5,"end":23,"kind":"email","value":"jan.jansen@acme.nl"}"#),
            "{reply}"
        );
        assert_eq!(fx.vault_total()?, before);
        Ok(())
    }

    #[test]
    fn a_masked_text_scans_clean_and_restores() -> TestResult {
        let fx = Fixture::new()?;
        let original = "mail jan.jansen@acme.nl";
        let masked = fx.mask(original)?;
        assert!(!masked.contains("jan.jansen"), "{masked}");
        let scanned = fx.ask(Request::ScanText {
            texts: vec![masked.clone()],
        })?;
        assert_eq!(scanned["results"][0], json!([]));
        for tolerant in [false, true] {
            let back = fx.ask(Request::Deanonymize {
                texts: vec![masked.clone()],
                tolerant,
            })?;
            assert_eq!(back["texts"][0], original, "tolerant {tolerant}");
        }
        Ok(())
    }

    #[test]
    fn the_vault_lists_filters_and_pages() -> TestResult {
        let fx = Fixture::new()?;
        fx.mask("a.b@acme.nl and c.d@acme.org and 8.8.4.4")?;
        let all = fx.ask(Request::VaultList {
            query: None,
            kind: None,
            limit: None,
            offset: 0,
        })?;
        assert_eq!(all["total"], 3, "{all}");
        let one = fx.ask(Request::VaultList {
            query: Some("ACME.org".into()),
            kind: None,
            limit: None,
            offset: 0,
        })?;
        assert_eq!(one["total"], 1);
        assert_eq!(one["records"][0]["original"], "c.d@acme.org");
        assert_eq!(one["records"][0]["kind"], "email");
        let emails = fx.ask(Request::VaultList {
            query: None,
            kind: Some("Email".into()),
            limit: None,
            offset: 0,
        })?;
        assert_eq!(emails["total"], 2);
        // `total` counts every match, the page only what was asked for.
        let page = fx.ask(Request::VaultList {
            query: None,
            kind: None,
            limit: Some(1),
            offset: 1,
        })?;
        assert_eq!(page["total"], 3);
        assert_eq!(page["records"].as_array().map(Vec::len), Some(1));
        let bad = fx.ask(Request::VaultList {
            query: None,
            kind: Some("colour".into()),
            limit: None,
            offset: 0,
        });
        assert_eq!(bad.err().map(|e| e.code()), Some("bad_request"));
        Ok(())
    }

    #[test]
    fn forgetting_and_wiping_need_what_they_say() -> TestResult {
        let fx = Fixture::new()?;
        fx.mask("a.b@acme.nl and c.d@acme.org")?;
        assert_eq!(fx.vault_total()?, 2);

        let refused = fx.ask(Request::VaultWipe { confirm: false });
        let code = refused.as_ref().err().map(ApiError::code);
        assert_eq!(code, Some("bad_request"), "{refused:?}");
        assert_eq!(fx.vault_total()?, 2, "a refused wipe changed the vault");

        let forgotten = fx.ask(Request::VaultForget {
            values: texts(&["a.b@acme.nl", "nobody@acme.nl"]),
        })?;
        assert_eq!(forgotten, json!({"forgotten": 1}));
        assert_eq!(fx.vault_total()?, 1);

        let wiped = fx.ask(Request::VaultWipe { confirm: true })?;
        assert_eq!(wiped, json!({"forgotten": 1}));
        assert_eq!(fx.vault_total()?, 0);
        Ok(())
    }

    #[test]
    fn the_vault_exports_to_a_new_file_only() -> TestResult {
        let fx = Fixture::new()?;
        fx.mask("a.b@acme.nl")?;
        let csv = fx.dir.file("vault.csv");
        let reply = fx.ask(Request::VaultExport {
            path: csv.clone(),
            format: Format::Csv,
        })?;
        assert_eq!(reply["records"], 1);
        let text = fs::read_to_string(&csv)?;
        assert!(text.starts_with("kind,original,proxy\r\n"), "{text}");
        assert!(text.contains("a.b@acme.nl"));

        let again = fx.ask(Request::VaultExport {
            path: csv,
            format: Format::Csv,
        });
        assert_eq!(again.err().map(|e| e.code()), Some("io"));

        let json_path = fx.dir.file("vault.json");
        fx.ask(Request::VaultExport {
            path: json_path.clone(),
            format: Format::Json,
        })?;
        let parsed: Value = serde_json::from_str(&fs::read_to_string(json_path)?)?;
        assert_eq!(parsed[0]["original"], "a.b@acme.nl");
        Ok(())
    }

    #[test]
    fn files_are_scanned_recorded_masked_and_found() -> TestResult {
        let fx = Fixture::new()?;
        let folder = fx.dir.file("docs");
        fs::create_dir_all(&folder)?;
        let a = fx.dir.write(
            r"docs\a.txt",
            "Pay NL91ABNA0417164300 or mail jan.jansen@acme.nl",
        )?;
        fx.dir
            .write(r"docs\b.txt", "bel +31 6 1234 5678 voor Marie")?;
        fx.dir.write(r"docs\clean.txt", "nothing to see")?;
        let before = fx.vault_total()?;

        let scanned = fx.ask(Request::ScanFiles {
            paths: vec![folder.clone()],
            record: false,
        })?;
        assert_eq!(
            scanned["files"].as_array().map(Vec::len),
            Some(3),
            "{scanned}"
        );
        let entry = scanned["files"]
            .as_array()
            .and_then(|files| files.iter().find(|f| f["path"] == lossy(&a).as_str()))
            .ok_or("a.txt not listed")?;
        assert_eq!(entry["status"], "ok");
        assert_eq!(entry["counts"]["iban"], 1);
        assert_eq!(entry["counts"]["email"], 1);
        assert!(scanned["hits"].as_u64().is_some_and(|hits| hits >= 3));
        assert_eq!(fx.inventory.totals().files, 0, "record: false recorded");
        assert_eq!(fx.vault_total()?, before, "a scan wrote to the vault");

        // A file named twice (as a folder's file, and by itself) is one file.
        let twice = fx.ask(Request::ScanFiles {
            paths: vec![a.clone(), folder.clone()],
            record: false,
        })?;
        assert_eq!(twice["files"].as_array().map(Vec::len), Some(3), "{twice}");
        assert_eq!(twice["hits"], scanned["hits"]);

        fx.ask(Request::ScanFiles {
            paths: vec![folder.clone()],
            record: true,
        })?;
        assert_eq!(fx.inventory.totals().files, 3);
        let listed = fx.ask(Request::InventoryList {
            under: None,
            limit: None,
            offset: 0,
        })?;
        assert_eq!(
            listed["total"], 2,
            "only files with data are listed: {listed}"
        );
        assert_eq!(
            listed["entries"][0]["path"],
            lossy(&a).as_str(),
            "most hits first"
        );

        let found = fx.ask(Request::SubjectSearch {
            values: texts(&["+31612345678"]),
            paths: vec![folder.clone()],
        })?;
        assert_eq!(
            found["matches"].as_array().map(Vec::len),
            Some(1),
            "{found}"
        );
        assert_eq!(found["matches"][0]["count"], 1);

        let out = fx.dir.file("out");
        let masked = fx.ask(Request::AnonymizeFiles {
            paths: vec![folder.clone()],
            out: out.clone(),
        })?;
        assert_eq!(
            masked["written"].as_array().map(Vec::len),
            Some(3),
            "{masked}"
        );
        assert_eq!(masked["failed"], json!([]));
        let masked_text = fs::read_to_string(out.join("a.txt"))?;
        assert!(!masked_text.contains("jan.jansen"), "{masked_text}");
        let rescanned = fx.ask(Request::ScanFiles {
            paths: vec![out.clone()],
            record: false,
        })?;
        assert_eq!(rescanned["hits"], 0, "masked files scan clean: {rescanned}");

        let restored_dir = fx.dir.file("restored");
        fx.ask(Request::DeanonymizeFiles {
            paths: vec![out],
            out: restored_dir.clone(),
            tolerant: false,
        })?;
        let restored = fs::read_to_string(restored_dir.join("a.txt"))?;
        assert!(restored.contains("jan.jansen@acme.nl"), "{restored}");
        Ok(())
    }

    #[test]
    fn the_inventory_reports_its_tree_and_status() -> TestResult {
        let fx = Fixture::new()?;
        let folder = fx.dir.file("docs");
        fs::create_dir_all(&folder)?;
        fx.dir.write(r"docs\a.txt", "mail jan.jansen@acme.nl")?;
        fx.ask(Request::ScanFiles {
            paths: vec![folder.clone()],
            record: true,
        })?;

        let tree = fx.ask(Request::InventoryTree {
            under: Some(folder.clone()),
        })?;
        assert_eq!(tree["nodes"][0]["name"], "a.txt", "{tree}");
        assert_eq!(tree["nodes"][0]["is_dir"], false);
        assert_eq!(tree["nodes"][0]["hits"], 1);

        let status = fx.ask(Request::InventoryStatus)?;
        assert_eq!(status["files"], 1);
        assert_eq!(status["files_with_pii"], 1);
        assert_eq!(status["hits"], 1);
        assert_eq!(status["scanning"], Value::Null);
        assert!(status["roots"].is_array());

        let report = fx.dir.file("report.csv");
        let written = fx.ask(Request::InventoryReport {
            path: report.clone(),
            format: Format::Csv,
        })?;
        assert_eq!(written["rows"], 1);
        let csv = fs::read_to_string(report)?;
        assert!(csv.starts_with("path,status,hits,email,scanned"), "{csv}");
        Ok(())
    }

    #[test]
    fn a_rescan_waits_for_no_one() -> TestResult {
        let fx = Fixture::new()?;
        let _held = fx.inventory.lock_scan()?;
        let busy = fx.ask(Request::InventoryRescan);
        assert_eq!(busy.err().map(|e| e.code()), Some("busy"));
        Ok(())
    }

    #[test]
    fn paths_must_be_absolute_and_exist() -> TestResult {
        let fx = Fixture::new()?;
        for request in [
            Request::ScanFiles {
                paths: vec![PathBuf::from("docs")],
                record: false,
            },
            Request::AnonymizeFiles {
                paths: vec![fx.dir.file("x")],
                out: PathBuf::from("out"),
            },
            Request::VaultExport {
                path: PathBuf::from("v.csv"),
                format: Format::Csv,
            },
            Request::InventoryTree {
                under: Some(PathBuf::from(r"\rooted")),
            },
        ] {
            let op = request.op();
            let error = fx.ask(request).err();
            assert_eq!(error.map(|e| e.code()), Some("bad_request"), "{op}");
        }
        let missing = fx.ask(Request::ScanFiles {
            paths: vec![fx.dir.file("not-there")],
            record: false,
        });
        assert_eq!(missing.err().map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    #[test]
    fn settings_and_kinds_read_the_saved_settings() -> TestResult {
        let fx = Fixture::new()?;
        let settings = fx.ask(Request::SettingsGet)?;
        assert!(settings["http_port"].is_u64(), "{settings}");
        assert!(settings["highlight"].is_string());

        // A bad patch is refused before anything is written.
        let bad = fx.ask(Request::SettingsSet {
            settings: SettingsPatch {
                sites: Some(vec!["not a site".into()]),
                ..SettingsPatch::default()
            },
        });
        assert_eq!(bad.err().map(|e| e.code()), Some("bad_request"));

        let kinds = fx.ask(Request::Kinds)?;
        let kinds = kinds.as_array().ok_or("kinds is not a list")?;
        assert_eq!(kinds.len(), EntityKind::ALL.len());
        let email = kinds
            .iter()
            .find(|k| k["kind"] == "email")
            .ok_or("no email")?;
        assert_eq!(email["label"], "Email");
        assert_eq!(email["group"], "Contact");
        assert!(email["enabled"].is_boolean());
        Ok(())
    }

    #[test]
    fn the_model_status_reads_the_model_folder() -> TestResult {
        let fx = Fixture::new()?;
        let status = fx.ask(Request::ModelStatus)?;
        assert_eq!(status["state"], "missing", "{status}");
        assert_eq!(status["device"], Value::Null);
        assert_eq!(status["dir"], lossy(&fx.dir.file("model")).as_str());
        assert!(status.get("error").is_none());
        Ok(())
    }

    #[test]
    fn status_says_the_app_is_not_there() -> TestResult {
        let fx = Fixture::new()?;
        fx.mask("a.b@acme.nl")?;
        let status = fx.ask(Request::Status)?;
        assert_eq!(status["app"], false);
        assert_eq!(status["protection"], Value::Null);
        assert_eq!(status["vault_records"], 1);
        assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["model"]["state"], "missing");
        for key in ["highlight", "explorer_menu", "inventory", "http_api"] {
            assert!(status.get(key).is_some(), "{key} missing: {status}");
        }
        Ok(())
    }

    #[test]
    fn what_needs_the_app_says_so() -> TestResult {
        let fx = Fixture::new()?;
        for request in [
            Request::Protection { on: true },
            Request::ExplorerScan {
                paths: vec![fx.dir.file("x")],
            },
        ] {
            let error = fx.ask(request).err().ok_or("answered without the app")?;
            assert_eq!(error.code(), "app_required");
            assert!(error.message().contains("piikey.exe"), "{error}");
        }
        Ok(())
    }

    #[test]
    fn the_token_is_made_once_and_replaced_on_request() -> TestResult {
        let dir = TempDir::new()?;
        let path = dir.file("api.token");
        let first = token_in(&path, false)?;
        assert_eq!(first.len(), TOKEN_BYTES * 2);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(token_in(&path, false)?, first);
        let second = token_in(&path, true)?;
        assert_ne!(second, first);
        assert_eq!(token_in(&path, false)?, second);
        // A file that is no token (cut short, edited) is replaced.
        fs::write(&path, "abc")?;
        let third = token_in(&path, false)?;
        assert_eq!(third.len(), TOKEN_BYTES * 2);
        assert_eq!(fs::read_to_string(&path)?, third);
        Ok(())
    }

    #[test]
    fn hex_writes_two_lowercase_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0F, 0xA5, 0xFF]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }
}
