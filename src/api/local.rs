//! [`Local`]: the handler that answers a request in this process.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

use rayon::prelude::*;
use serde_json::{Value, json};

use super::{
    ApiError, Code, Format, Handler, Request, reply, require_absolute, to_json,
    token::read_or_create_token,
};
use crate::{
    Error, Result,
    detect::{
        EntityKind, Mode, NerDetector,
        ner::{self, Device, NerState},
    },
    engine::Engine,
    files,
    inventory::{Entry, Inventory, Progress},
    policy::{Policy, SettingsPatch},
    subject, sys, vault,
};

/// Hands out the engine a request runs on, each time one does. The command line holds one
/// engine for the whole run; the app hands out the engine it has at that moment, which is
/// another one after the model was loaded or released.
pub type EngineSource = Arc<dyn Fn() -> Arc<Engine> + Send + Sync>;

/// Told how far a download is, in bytes done and bytes in all.
pub type DownloadProgress = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Hands out the settings a request runs on, each time one does. The command line reads them
/// from the data folder; the app hands out the ones it holds, which are the ones that apply
/// while a change is still being saved.
pub type PolicySource = Arc<dyn Fn() -> Result<Policy> + Send + Sync>;

/// How many records or entries a list returns when it is not told.
const LIST_DEFAULT: usize = 100;
/// The most a list returns at once.
const LIST_MAX: usize = 10_000;

/// Answers every request in this process, on the engine, the inventory and the saved settings
/// it was given. Only what needs the app is refused: `protection`, `explorer_scan` and
/// `show_window` answer `app_required`.
///
/// The settings and the token are read from and written to the data folder
/// (`%LOCALAPPDATA%\piikey`), so they are the user's, like the app's. The kinds of personal data
/// a scan or a masking looks for are the engine's ([`Engine::set_enabled`]), not read from the
/// settings here: whoever hands over the engine sets them from [`Policy::enabled_kinds`].
///
/// The app answers `status`, `model_status` and `inventory_status` with what these give, and the
/// facts only it knows put in.
pub struct Local {
    engine: EngineSource,
    settings: PolicySource,
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
            settings: Arc::new(Policy::load),
            inventory,
            ner,
            model_dir: None,
            on_download: None,
            downloading: Mutex::new(()),
            rescan: Progress::default(),
            rescanning: AtomicBool::new(false),
        }
    }

    /// Reads the settings from `settings` instead of the data folder.
    #[must_use]
    pub fn with_policy(mut self, settings: PolicySource) -> Self {
        self.settings = settings;
        self
    }

    /// Calls `progress(done, total)`, in bytes, while `model_download` runs.
    #[must_use]
    pub fn with_progress(mut self, progress: DownloadProgress) -> Self {
        self.on_download = Some(progress);
        self
    }

    /// Looks for the model, and downloads it, in `dir` instead of the data folder. For tests,
    /// which must not see the model of the machine they run on.
    #[doc(hidden)]
    #[must_use]
    pub fn with_model_dir(mut self, dir: PathBuf) -> Self {
        self.model_dir = Some(dir);
        self
    }

    fn engine(&self) -> Arc<Engine> {
        (self.engine)()
    }

    fn policy(&self) -> Result<Policy> {
        (self.settings)()
    }

    fn model_dir(&self) -> Result<PathBuf> {
        match &self.model_dir {
            Some(dir) => Ok(dir.clone()),
            None => ner::files::default_dir(),
        }
    }

    fn scan_text(&self, texts: &[String]) -> Result<Value, ApiError> {
        let found = self.engine().scan(&refs(texts))?;
        let results = texts
            .iter()
            .zip(found)
            .map(|(text, spans)| {
                spans
                    .into_iter()
                    .map(|span| reply::Span {
                        start: span.start,
                        end: span.end,
                        kind: span.kind.as_str().to_owned(),
                        value: text
                            .get(span.start..span.end)
                            .unwrap_or_default()
                            .to_owned(),
                    })
                    .collect()
            })
            .collect();
        to_json(&reply::Spans { results })
    }

    fn rewrite_text(
        &self,
        mode: Mode,
        texts: &[String],
        tolerant: bool,
    ) -> Result<Value, ApiError> {
        let engine = self.engine();
        let restorer = files::tolerant_restorer(&engine, tolerant && mode == Mode::Deanonymize)?;
        let out = match &restorer {
            // The vault's proxies and the scope's, typos and lone names included, in one pass
            // over each text.
            Some(restorer) => texts
                .par_iter()
                .map(|text| Engine::apply(text, &restorer.plan_with(text.as_bytes(), &*engine)))
                .collect(),
            None => engine.run(mode, &refs(texts))?,
        };
        to_json(&reply::Texts { texts: out })
    }

    fn scan_files(&self, paths: &[PathBuf], record: bool) -> Result<Value, ApiError> {
        all_absolute(paths)?;
        let mut jobs = files::collect(paths, None)?;
        // A folder and a file inside it are both named: the file is one file, not two.
        jobs.sort_unstable_by(|a, b| a.input.cmp(&b.input));
        jobs.dedup_by(|a, b| a.input == b.input);
        let engine = self.engine();
        let files: Vec<Entry> = jobs
            .par_iter()
            .map(|job| Entry::scan(&engine, &job.input))
            .collect();
        let hits = files.iter().map(Entry::hits).sum();
        let scanned = reply::Scanned { files, hits };
        let shown = to_json(&scanned)?;
        if record {
            self.inventory.record(scanned.files)?;
        }
        Ok(shown)
    }

    fn rewrite_files(
        &self,
        mode: Mode,
        paths: &[PathBuf],
        out: &Path,
        tolerant: bool,
    ) -> Result<Value, ApiError> {
        all_absolute(paths)?;
        require_absolute(out)?;
        let jobs = files::collect(paths, Some(out))?;
        let engine = self.engine();
        let mut done = reply::Written {
            written: Vec::new(),
            failed: Vec::new(),
        };
        for (input, result) in files::transform(&engine, mode, tolerant, &jobs) {
            let input = lossy(&input);
            match result {
                Ok(output) => done.written.push(reply::Moved {
                    input,
                    output: lossy(&output),
                }),
                Err(error) => done.failed.push(reply::Failed {
                    input,
                    error: error.to_string(),
                }),
            }
        }
        to_json(&done)
    }

    fn subject_search(&self, values: &[String], paths: &[PathBuf]) -> Result<Value, ApiError> {
        all_absolute(paths)?;
        let roots;
        let paths = if paths.is_empty() {
            roots = self.policy()?.inventory_roots_or_default();
            roots.as_slice()
        } else {
            paths
        };
        let matches = subject::search(&self.engine(), values, paths, &AtomicBool::new(false))?;
        to_json(&reply::Found { matches })
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
                records.push(reply::Record {
                    kind: kind.as_str().to_owned(),
                    original: original.to_owned(),
                    proxy: proxy.to_owned(),
                });
            }
        }
        to_json(&reply::Records { records, total })
    }

    fn vault_forget(&self, values: &[String]) -> Result<Value, ApiError> {
        let forgotten = self.engine().forget(&refs(values))?;
        to_json(&reply::Forgotten { forgotten })
    }

    fn vault_wipe(&self, confirm: bool) -> Result<Value, ApiError> {
        if !confirm {
            return Err(ApiError::bad_request(
                "vault_wipe removes every record from the vault and needs confirm: true",
            ));
        }
        let forgotten = self.engine().wipe()?;
        to_json(&reply::Forgotten { forgotten })
    }

    fn vault_export(&self, path: &Path, format: Format) -> Result<Value, ApiError> {
        require_absolute(path)?;
        let engine = self.engine();
        let records = sys::write_new(path, |out| {
            vault::export(&engine.vault().read()?, format.into(), out)
        })?;
        to_json(&reply::Exported {
            records,
            path: lossy(path),
        })
    }

    /// The inventory in numbers, with the progress of the rescan this process runs, if any.
    ///
    /// # Errors
    /// `Io` when the saved settings cannot be read.
    pub fn inventory_status(&self) -> Result<reply::InventoryStatus, ApiError> {
        let policy = self.policy()?;
        let totals = self.inventory.totals();
        Ok(reply::InventoryStatus {
            roots: policy
                .inventory_roots_or_default()
                .iter()
                .map(|root| lossy(root))
                .collect(),
            files: totals.files,
            files_with_pii: totals.files_with_pii,
            hits: totals.hits,
            scanning: self
                .rescanning
                .load(Ordering::Relaxed)
                .then(|| reply::Progress {
                    done: self.rescan.done.load(Ordering::Relaxed),
                    total: self.rescan.total.load(Ordering::Relaxed),
                }),
        })
    }

    fn inventory_list(
        &self,
        under: Option<&Path>,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<Value, ApiError> {
        under.map(require_absolute).transpose()?;
        let mut entries = self.inventory.entries(under, 1);
        entries.sort_by(|a, b| b.hits().cmp(&a.hits()).then_with(|| a.path.cmp(&b.path)));
        let total = entries.len();
        let entries = entries
            .into_iter()
            .skip(offset)
            .take(limit.unwrap_or(LIST_DEFAULT).min(LIST_MAX))
            .collect();
        to_json(&reply::Entries { entries, total })
    }

    fn inventory_tree(&self, under: Option<&Path>) -> Result<Value, ApiError> {
        under.map(require_absolute).transpose()?;
        let roots = self.policy()?.inventory_roots_or_default();
        let nodes = self.inventory.children(under, &roots);
        to_json(&reply::Nodes { nodes })
    }

    fn inventory_rescan(&self) -> Result<Value, ApiError> {
        let roots = self.policy()?.inventory_roots_or_default();
        let _lock = self.inventory.lock_scan()?;
        let _running = Running::start(&self.rescanning);
        self.inventory.scan_paths(
            &self.engine(),
            &roots,
            &self.rescan,
            &AtomicBool::new(false),
        )?;
        to_json(&self.inventory.totals())
    }

    fn inventory_report(&self, path: &Path, format: Format) -> Result<Value, ApiError> {
        require_absolute(path)?;
        let rows = sys::write_new(path, |out| self.inventory.report(None, format.into(), out))?;
        to_json(&reply::Reported {
            rows,
            path: lossy(path),
        })
    }

    /// Where the detection model stands: on disk or not, loaded, or failed.
    ///
    /// # Errors
    /// `VaultPathUnavailable` when there is no data folder to look in.
    pub fn model_status(&self) -> Result<reply::Model, ApiError> {
        let dir = self.model_dir()?;
        let state = match &self.ner {
            Some(ner) => ner.state(),
            None if ner::files::is_installed(&dir) => NerState::Unloaded,
            None => NerState::Missing,
        };
        let (state, device, error) = match state {
            NerState::Missing => (reply::ModelState::Missing, None, None),
            NerState::Unloaded => (reply::ModelState::Unloaded, None, None),
            NerState::Ready(device) => (reply::ModelState::Ready, Some(device_of(device)), None),
            NerState::Failed(message) => (reply::ModelState::Failed, None, Some(message)),
        };
        Ok(reply::Model {
            state,
            device,
            error,
            downloading: None,
            dir: lossy(&dir),
        })
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
            Error::Tool(message) => ApiError::new(Code::Model, message),
            other => ApiError::from(other),
        })?;
        Ok(json!({}))
    }

    /// How piikey is doing, as a process without the app sees it: no app, and no word on
    /// protection.
    ///
    /// # Errors
    /// `Io` when the saved settings cannot be read; `Vault` when the vault cannot be read.
    pub fn status(&self) -> Result<reply::Status, ApiError> {
        let policy = self.policy()?;
        Ok(reply::Status {
            app: false,
            protection: None,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            vault_records: self.engine().vault().read()?.record_count(),
            model: self.model_status()?,
            highlight: policy.highlight,
            explorer_menu: policy.explorer_menu,
            watch: policy.watch,
            http_api: policy.http_api,
        })
    }

    fn settings_set(&self, patch: &SettingsPatch) -> Result<Value, ApiError> {
        let mut policy = self.policy()?;
        patch.apply(&mut policy)?;
        policy.save()?;
        to_json(&policy)
    }

    fn kinds(&self) -> Result<Value, ApiError> {
        let enabled = self.policy()?.enabled_kinds();
        let kinds: Vec<reply::Kind> = EntityKind::ALL
            .into_iter()
            .map(|kind| reply::Kind {
                kind: kind.as_str().to_owned(),
                label: kind.label().to_owned(),
                group: kind.group().to_owned(),
                enabled: enabled.contains(kind),
            })
            .collect();
        to_json(&kinds)
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
            Request::InventoryStatus => to_json(&self.inventory_status()?),
            Request::InventoryList {
                under,
                limit,
                offset,
            } => self.inventory_list(under.as_deref(), limit, offset),
            Request::InventoryTree { under } => self.inventory_tree(under.as_deref()),
            Request::InventoryRescan => self.inventory_rescan(),
            Request::InventoryReport { path, format } => self.inventory_report(&path, format),
            Request::SettingsGet => to_json(&self.policy()?),
            Request::SettingsSet { settings } => self.settings_set(&settings),
            Request::Kinds => self.kinds(),
            Request::ModelStatus => to_json(&self.model_status()?),
            Request::ModelDownload => self.model_download(),
            Request::ApiToken { rotate } => to_json(&reply::Token {
                token: read_or_create_token(rotate)?,
            }),
            Request::Status => to_json(&self.status()?),
            Request::Protection { .. } => Err(app_required("protection")),
            Request::ExplorerScan { .. } => Err(app_required("explorer_scan")),
            Request::ShowWindow => Err(app_required("show_window")),
        }
    }
}

fn app_required(op: &str) -> ApiError {
    ApiError::app_required(format!(
        "{op} needs the piikey app: start piikey.exe and try again"
    ))
}

fn device_of(device: Device) -> reply::Device {
    match device {
        Device::Cpu => reply::Device::Cpu,
        Device::Hybrid => reply::Device::Hybrid,
    }
}

fn parse_kind(name: &str) -> Result<EntityKind, ApiError> {
    EntityKind::parse(&name.trim().to_ascii_lowercase())
        .ok_or_else(|| ApiError::bad_request(format!("Not a valid kind: {name}")))
}

fn refs(texts: &[String]) -> Vec<&str> {
    texts.iter().map(String::as_str).collect()
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn all_absolute(paths: &[PathBuf]) -> Result<(), ApiError> {
    paths.iter().try_for_each(|path| require_absolute(path))
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

#[cfg(test)]
mod tests {
    use std::{error::Error as StdError, fs, io};

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    /// A scratch folder, removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            Self(crate::testing::temp_dir("api"))
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

    /// A handler over a vault, an inventory and settings in a scratch folder: the settings are
    /// the ones in `policy`, not the user's.
    struct Fixture {
        dir: TempDir,
        engine: Arc<Engine>,
        local: Local,
        inventory: Arc<Inventory>,
        policy: Arc<Mutex<Policy>>,
    }

    impl Fixture {
        fn new() -> std::result::Result<Self, Box<dyn StdError>> {
            let dir = TempDir::new();
            let engine = Arc::new(Engine::open(&dir.file("vault.pkv"))?);
            let inventory = Arc::new(Inventory::open(&dir.file("inventory.jsonl"))?);
            let held = Arc::clone(&engine);
            let source: EngineSource = Arc::new(move || Arc::clone(&engine));
            let policy = Arc::new(Mutex::new(Policy::default()));
            let live = Arc::clone(&policy);
            let local = Local::new(source, Arc::clone(&inventory), None)
                .with_policy(Arc::new(move || Ok(live.lock()?.clone())))
                .with_model_dir(dir.file("model"));
            Ok(Self {
                dir,
                engine: held,
                local,
                inventory,
                policy,
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

        /// The stand-in the vault holds for the person `original`, issued now when it has none.
        fn stand_in(&self, original: &str) -> std::result::Result<String, Box<dyn StdError>> {
            let vault = self.engine.vault();
            vault.resolve(vec![(EntityKind::Person, original.into())], &|_, _| false)?;
            let view = vault.read()?;
            let stand_in = view.proxy_for(EntityKind::Person, original);
            Ok(stand_in.ok_or("the vault issued no stand-in")?.to_owned())
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
    fn a_value_that_is_another_stand_in_is_restored_once() -> TestResult {
        let fx = Fixture::new()?;
        // `Jan Smit` has a stand-in, and so has somebody whose real name is that stand-in.
        let first = fx.stand_in("Jan Smit")?;
        let second = fx.stand_in(&first)?;
        for tolerant in [false, true] {
            let back = fx.ask(Request::Deanonymize {
                texts: vec![format!("{first} and {second}")],
                tolerant,
            })?;
            assert_eq!(
                back["texts"][0],
                format!("Jan Smit and {first}"),
                "tolerant {tolerant}"
            );
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
    fn settings_and_kinds_are_listed_and_a_bad_patch_is_refused() -> TestResult {
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

    /// The app answers with the settings it holds, which may not be on disk yet: every answer
    /// that depends on a setting reads the same ones.
    #[test]
    fn every_answer_follows_the_settings_the_source_hands_out() -> TestResult {
        let fx = Fixture::new()?;
        let folder = fx.dir.file("watched");
        {
            let mut policy = fx.policy.lock().map_err(|_| "settings poisoned")?;
            policy.watch = true;
            policy.background = false;
            policy.inventory_roots = vec![folder.clone()];
            policy.watch_folders = vec![folder.clone()];
            policy.disabled_kinds = vec![EntityKind::Email];
        }
        let settings = fx.ask(Request::SettingsGet)?;
        assert_eq!(settings["watch"], true);
        assert_eq!(settings["background"], false);
        assert_eq!(settings["watch_folders"], json!([lossy(&folder)]));
        assert!(settings.get("inventory").is_none() && settings.get("inventory_exclude").is_none());
        let status = fx.ask(Request::InventoryStatus)?;
        assert_eq!(status["roots"], json!([lossy(&folder)]));
        assert!(
            status.get("enabled").is_none(),
            "the inventory has no switch: {status}"
        );
        let kinds = fx.ask(Request::Kinds)?;
        let email = kinds
            .as_array()
            .and_then(|all| all.iter().find(|k| k["kind"] == "email"))
            .ok_or("no email")?;
        assert_eq!(email["enabled"], false);
        assert_eq!(fx.ask(Request::Status)?["watch"], true);
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
        for key in ["highlight", "explorer_menu", "watch", "http_api"] {
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
            Request::ShowWindow,
        ] {
            let error = fx.ask(request).err().ok_or("answered without the app")?;
            assert_eq!(error.code(), "app_required");
            assert!(error.message().contains("piikey.exe"), "{error}");
        }
        Ok(())
    }
}
