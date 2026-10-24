//! [`Local`]: the handler that answers a request in this process.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

use rayon::prelude::*;
use serde_json::{Value, json};

use super::{
    ApiError, Code, Format, Handler, Request, reply, require_absolute, require_on_this_pc, to_json,
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
    sources::{self, Account, Accounts, Connector, TokenStore},
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

/// Told the address a person is to open to finish signing in to a cloud account. The app opens
/// the browser; the command line prints the address.
pub type UrlOpener = Arc<dyn Fn(&str) + Send + Sync>;

/// Makes the connector that reads a cloud account. Without one, [`Local`] makes the real one
/// ([`sources::connector`]); tests hand out one that lives in memory.
pub type ConnectorSource =
    Arc<dyn Fn(&Account) -> sources::Result<Box<dyn Connector>> + Send + Sync>;

/// How many records or entries a list returns when it is not told.
const LIST_DEFAULT: usize = 100;
/// The most a list returns at once.
const LIST_MAX: usize = 10_000;

/// Answers every request in this process, on the engine, the inventory and the saved settings
/// it was given. Only what needs the app is refused: `protection`, `explorer_scan` and
/// `show_window` answer `app_required`.
///
/// The settings, the cloud accounts and the token are read from and written to the data folder
/// (`%LOCALAPPDATA%\piikey`), so they are the user's, like the app's ([`Local::with_data_dir`]
/// says another). The types of personal data a scan or a masking looks for are the engine's
/// ([`Engine::set_enabled`]), not read from the settings here: whoever hands over the engine
/// sets them from [`Policy::enabled_kinds`].
///
/// The app answers `status`, `model_status` and `inventory_status` with what these give, and the
/// facts only it knows put in.
pub struct Local {
    engine: EngineSource,
    /// Where the settings come from; `None`: `guard.cfg` of the data folder.
    settings: Option<PolicySource>,
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
    /// Where `sources.json`, the tokens, the cursors and `guard.cfg` live; `None`: the data
    /// folder.
    data_dir: Option<PathBuf>,
    /// What `account_connect` does with the address of a sign-in.
    opener: UrlOpener,
    /// Where the connector of an account comes from; `None`: the real one.
    connectors: Option<ConnectorSource>,
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
            settings: None,
            inventory,
            ner,
            model_dir: None,
            on_download: None,
            downloading: Mutex::new(()),
            rescan: Progress::default(),
            rescanning: AtomicBool::new(false),
            data_dir: None,
            opener: Arc::new(|_| {}),
            connectors: None,
        }
    }

    /// Reads the settings from `settings` instead of the data folder.
    #[must_use]
    pub fn with_policy(mut self, settings: PolicySource) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Keeps `sources.json`, the tokens, the cursors and the settings (unless [`Local::with_policy`]
    /// says where they come from) in `dir` instead of the data folder.
    #[must_use]
    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = Some(dir);
        self
    }

    /// Has `account_connect` hand the address of a sign-in to `opener`. Without one nothing
    /// is done with it.
    #[must_use]
    pub fn with_opener(mut self, opener: UrlOpener) -> Self {
        self.opener = opener;
        self
    }

    /// Makes the connector of an account with `connectors` instead of talking to the real
    /// service. For tests.
    #[doc(hidden)]
    #[must_use]
    pub fn with_connectors(mut self, connectors: ConnectorSource) -> Self {
        self.connectors = Some(connectors);
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
        match &self.settings {
            Some(settings) => settings(),
            None => Policy::load_in(&self.data()?),
        }
    }

    /// The data folder this handler keeps its accounts and settings in.
    fn data(&self) -> Result<PathBuf> {
        match &self.data_dir {
            Some(dir) => {
                fs::create_dir_all(dir).map_err(|e| sys::io_context(&e, "create", dir))?;
                Ok(dir.clone())
            }
            None => sys::data_dir(),
        }
    }

    /// The account `id`, or `not_found`.
    fn account(data: &Path, id: &str) -> Result<Account, ApiError> {
        Accounts::open(data)?
            .get(id)
            .cloned()
            .ok_or_else(|| ApiError::not_found(format!("no cloud account has the id {id}")))
    }

    /// The connector that reads `account`.
    fn connector(&self, account: &Account) -> sources::Result<Box<dyn Connector>> {
        match &self.connectors {
            Some(connectors) => connectors(account),
            None => sources::connector(account, &TokenStore::new(&self.data()?)),
        }
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
        on_this_pc(paths)?;
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
        on_this_pc(paths)?;
        require_on_this_pc(out)?;
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
        on_this_pc(paths)?;
        let roots;
        let paths = if paths.is_empty() {
            // The cloud locations are not searched: nothing of them is on this PC to read.
            roots = sources::split_roots(&self.policy()?.inventory_roots).0;
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
                .inventory_roots
                .iter()
                .map(|root| lossy(root))
                .collect(),
            monitored: policy
                .monitored_roots
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
        let nodes = self.inventory.children(under);
        to_json(&reply::Nodes { nodes })
    }

    fn inventory_rescan(&self) -> Result<Value, ApiError> {
        let roots = self.policy()?.inventory_roots;
        let (local, cloud) = sources::split_roots(&roots);
        let data = self.data()?;
        let _lock = self.inventory.lock_scan()?;
        let _running = Running::start(&self.rescanning);
        let engine = self.engine();
        let cancel = AtomicBool::new(false);
        self.inventory
            .scan_paths(&engine, &local, &self.rescan, &cancel)?;
        let scans = sources::scan_clouds(
            &data,
            &|account| self.connector(account),
            &self.inventory,
            &engine,
            &cloud,
            &self.rescan,
            &cancel,
        );
        // A location that failed does not stop the others; the first failure is what is told.
        if let Some(failed) = scans.into_iter().find_map(|scan| scan.result.err()) {
            return Err(Error::from(failed).into());
        }
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
            monitoring: !policy.monitored_roots.is_empty(),
            http_api: policy.http_api,
        })
    }

    fn settings_set(&self, patch: &SettingsPatch) -> Result<Value, ApiError> {
        let data = self.data()?;
        let accounts = Accounts::open(&data)?;
        let mut policy = self.policy()?;
        patch.apply_with(&mut policy, &|path| accounts.of(path).is_some())?;
        policy.save_in(&data)?;
        to_json(&policy)
    }

    fn accounts_list(&self) -> Result<Value, ApiError> {
        let data = self.data()?;
        let tokens = TokenStore::new(&data);
        let mut accounts = Vec::new();
        for account in Accounts::open(&data)?.list() {
            accounts.push(reply::AccountInfo::new(
                account,
                account.is_connected(&tokens)?,
            ));
        }
        to_json(&reply::Accounts { accounts })
    }

    fn account_add(
        &self,
        provider: sources::Provider,
        label: &str,
        sign_in: sources::SignIn,
        client_secret: Option<&str>,
    ) -> Result<Value, ApiError> {
        let data = self.data()?;
        let account = sources::add_account(&data, provider, label, sign_in, client_secret)?;
        let connected = account.is_connected(&TokenStore::new(&data))?;
        to_json(&reply::AccountInfo::new(&account, connected))
    }

    fn account_connect(&self, id: &str) -> Result<Value, ApiError> {
        let data = self.data()?;
        let account = Self::account(&data, id)?;
        let tokens = TokenStore::new(&data);
        sources::connect(
            &account,
            &tokens,
            &|url| (self.opener)(url),
            &AtomicBool::new(false),
        )
        .map_err(Error::from)?;
        to_json(&reply::AccountInfo::new(
            &account,
            account.is_connected(&tokens)?,
        ))
    }

    fn account_remove(&self, id: &str) -> Result<Value, ApiError> {
        let data = self.data()?;
        let account = Self::account(&data, id)?;
        let top = account.root();
        // The locations first: with the account gone they would only fail at every scan.
        let mut policy = self.policy()?;
        let locations = policy.remove_under(&top);
        if !locations.is_empty() {
            policy.save_in(&data)?;
        }
        let forgotten = self.inventory.forget_under(&top)?;
        sources::remove_account(&data, &account.id)?;
        to_json(&reply::AccountRemoved {
            id: account.id,
            locations: locations.iter().map(|location| lossy(location)).collect(),
            forgotten: u64::try_from(forgotten).unwrap_or(u64::MAX),
        })
    }

    fn account_browse(&self, id: &str, under: Option<&Path>) -> Result<Value, ApiError> {
        let data = self.data()?;
        let account = Self::account(&data, id)?;
        if let Some(under) = under {
            require_absolute(under)?;
            if !sys::is_under(under, &account.root()) {
                return Err(ApiError::bad_request(format!(
                    "{} is not in the account {}",
                    under.display(),
                    account.label
                )));
            }
        }
        let connector = self.connector(&account).map_err(Error::from)?;
        let folders = sources::browse(&*connector, under)
            .map_err(Error::from)?
            .into_iter()
            .map(|folder| reply::FolderInfo {
                name: folder.path.file_name().map_or_else(
                    || lossy(&folder.path),
                    |name| name.to_string_lossy().into_owned(),
                ),
                path: lossy(&folder.path),
            })
            .collect();
        to_json(&reply::Folders { folders })
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
            Request::AccountsList => self.accounts_list(),
            Request::AccountAdd {
                provider,
                label,
                sign_in,
                client_secret,
            } => self.account_add(provider, &label, sign_in, client_secret.as_deref()),
            Request::AccountConnect { id } => self.account_connect(&id),
            Request::AccountRemove { id } => self.account_remove(&id),
            Request::AccountBrowse { id, under } => self.account_browse(&id, under.as_deref()),
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

/// Checks that every path is absolute and on this PC (see [`require_on_this_pc`]).
fn on_this_pc(paths: &[PathBuf]) -> Result<(), ApiError> {
    paths.iter().try_for_each(|path| require_on_this_pc(path))
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
    use std::{
        error::Error as StdError,
        fs,
        io::{self, Read, Write},
        net::TcpStream,
        thread,
        time::{Duration, UNIX_EPOCH},
    };

    use super::*;
    use crate::sources::{Changes, Cursors, Provider, RemoteFolder, RemoteItem, Resolved, SignIn};

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

    const MAIL: &str = "mail jan.jansen@acme.nl";

    /// A cloud account that lives in memory: `Docs` (holding the folder `Sub` and the file
    /// `a.txt`) and `Site` at its top. An account called `Broken` has to sign in again.
    struct Fake {
        top: PathBuf,
        provider: Provider,
        broken: bool,
    }

    impl Fake {
        fn new(account: &Account) -> Self {
            Self {
                top: account.root(),
                provider: account.provider,
                broken: account.label == "Broken",
            }
        }

        /// The folder of the account that is `names` below its top.
        fn folder(&self, names: &[&str]) -> RemoteFolder {
            RemoteFolder {
                id: names.join("/"),
                path: names
                    .iter()
                    .fold(self.top.clone(), |path, name| sources::child(&path, name)),
                web_url: String::new(),
            }
        }

        fn file(&self) -> RemoteItem {
            RemoteItem {
                id: "a".to_owned(),
                path: self.top.join("Docs").join("a.txt"),
                size: u64::try_from(MAIL.len()).unwrap_or(0),
                modified: UNIX_EPOCH + Duration::from_secs(1_000),
                version: "v1".to_owned(),
                web_url: String::new(),
                export: None,
            }
        }
    }

    impl Connector for Fake {
        fn provider(&self) -> Provider {
            self.provider
        }

        fn browse(&self, under: Option<&RemoteFolder>) -> sources::Result<Vec<RemoteFolder>> {
            Ok(match under.map(|folder| folder.id.as_str()) {
                None => vec![self.folder(&["Docs"]), self.folder(&["Site"])],
                Some("Docs") => vec![self.folder(&["Docs", "Sub"])],
                Some(_) => Vec::new(),
            })
        }

        fn resolve(&self, path: &Path) -> sources::Result<Resolved> {
            let folders: [&[&str]; 4] = [&[], &["Docs"], &["Site"], &["Docs", "Sub"]];
            if let Some(folder) = folders
                .into_iter()
                .map(|names| self.folder(names))
                .find(|folder| sys::same_path(&folder.path, path))
            {
                return Ok(Resolved::Folder(folder));
            }
            let file = self.file();
            if sys::same_path(&file.path, path) {
                return Ok(Resolved::File(file));
            }
            Err(sources::Error::not_found(self.provider, "no such item"))
        }

        fn changes(
            &self,
            root: &RemoteFolder,
            cursor: Option<&str>,
            _: &AtomicBool,
        ) -> sources::Result<Changes> {
            if self.broken {
                return Err(sources::Error::sign_in_needed(self.provider, "expired"));
            }
            let file = self.file();
            Ok(Changes {
                items: if sys::is_under(&file.path, &root.path) {
                    vec![file]
                } else {
                    Vec::new()
                },
                removed: Vec::new(),
                cursor: "c1".to_owned(),
                full: cursor.is_none(),
            })
        }

        fn download(&self, _: &RemoteItem, _: u64, _: &AtomicBool) -> sources::Result<Vec<u8>> {
            Ok(MAIL.as_bytes().to_vec())
        }
    }

    /// What the fake handler asks a connector of: the in-memory account.
    fn fake_connector(account: &Account) -> Box<dyn Connector> {
        Box::new(Fake::new(account))
    }

    /// The part of `url`'s query named `name`, decoded.
    fn query_field(url: &str, name: &str) -> Option<String> {
        let (_, query) = url.split_once('?')?;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| unescape(value))
        })
    }

    fn unescape(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut at = 0;
        while let Some(&byte) = bytes.get(at) {
            let escaped = bytes
                .get(at + 1..at + 3)
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .filter(|_| byte == b'%');
            if let Some(value) = escaped {
                out.push(value);
                at += 3;
            } else {
                out.push(if byte == b'+' { b' ' } else { byte });
                at += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Where a person who refuses to sign in sends the browser: the address the sign-in listens
    /// on, and the target that says no.
    fn refusal(url: &str) -> Option<(String, String)> {
        let redirect = query_field(url, "redirect_uri")?;
        let state = query_field(url, "state")?;
        let rest = redirect.strip_prefix("http://")?;
        let (address, path) = rest.split_once('/').unwrap_or((rest, ""));
        Some((
            address.to_owned(),
            format!("/{path}?error=access_denied&state={state}"),
        ))
    }

    /// One visit of the browser to `address`; what answers is not looked at.
    fn visit(address: &str, target: &str) {
        if let Ok(mut stream) = TcpStream::connect(address) {
            let sent = write!(
                stream,
                "GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            );
            if sent.is_ok() {
                let mut answer = String::new();
                let _ = stream.read_to_string(&mut answer);
            }
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
            let policy = Arc::new(Mutex::new(Policy::default()));
            let local = Self::local_over(&dir, &engine, &inventory, &policy);
            Ok(Self {
                dir,
                engine,
                local,
                inventory,
                policy,
            })
        }

        /// A handler over this vault, inventory and settings, with its accounts in the scratch
        /// folder and a connector that lives in memory (see [`Fake`]).
        fn local_over(
            dir: &TempDir,
            engine: &Arc<Engine>,
            inventory: &Arc<Inventory>,
            policy: &Arc<Mutex<Policy>>,
        ) -> Local {
            let held = Arc::clone(engine);
            let source: EngineSource = Arc::new(move || Arc::clone(&held));
            let live = Arc::clone(policy);
            Local::new(source, Arc::clone(inventory), None)
                .with_policy(Arc::new(move || Ok(live.lock()?.clone())))
                .with_model_dir(dir.file("model"))
                .with_data_dir(dir.file("data"))
                .with_connectors(Arc::new(
                    |account: &Account| -> sources::Result<Box<dyn Connector>> {
                        Ok(fake_connector(account))
                    },
                ))
        }

        /// The folder of the accounts, the settings file and the tokens.
        fn data(&self) -> PathBuf {
            self.dir.file("data")
        }

        /// Adds a Google Drive account `label` that signs in with a key file, which holds
        /// nothing secret and is there.
        fn add_google(
            &self,
            label: &str,
        ) -> std::result::Result<reply::AccountInfo, Box<dyn StdError>> {
            let key_file = self.dir.write("key.json", "{}")?;
            let added = self.ask(Request::AccountAdd {
                provider: Provider::GoogleDrive,
                label: label.to_owned(),
                sign_in: SignIn::GoogleServiceAccount {
                    key_file,
                    users: vec!["jan@acme.nl".to_owned()],
                },
                client_secret: None,
            })?;
            Ok(serde_json::from_value(added)?)
        }

        /// Adds a Dropbox account `label`, which nobody has signed in to.
        fn add_dropbox(
            &self,
            label: &str,
        ) -> std::result::Result<reply::AccountInfo, Box<dyn StdError>> {
            let added = self.ask(Request::AccountAdd {
                provider: Provider::Dropbox,
                label: label.to_owned(),
                sign_in: SignIn::DropboxDelegated {
                    app_key: "key-1".to_owned(),
                },
                client_secret: None,
            })?;
            Ok(serde_json::from_value(added)?)
        }

        /// The locations of the settings the handler reads.
        fn set_locations(&self, roots: Vec<PathBuf>) -> TestResult {
            self.policy
                .lock()
                .map_err(|_| "settings poisoned")?
                .inventory_roots = roots;
            Ok(())
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

        // Without a folder the tree starts at the drive the files are on, with its root as the
        // path.
        let top = fx.ask(Request::InventoryTree { under: None })?;
        let drive = folder
            .components()
            .next()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .ok_or("the folder has no drive")?;
        assert_eq!(top["nodes"].as_array().map(Vec::len), Some(1), "{top}");
        assert_eq!(top["nodes"][0]["name"], drive.as_str());
        assert_eq!(top["nodes"][0]["path"], format!(r"{drive}\"));
        assert_eq!(top["nodes"][0]["is_dir"], true);
        assert_eq!(top["nodes"][0]["hits"], 1);

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
        let folder = fx.dir.file("monitored");
        {
            let mut policy = fx.policy.lock().map_err(|_| "settings poisoned")?;
            policy.background = false;
            policy.inventory_roots = vec![folder.clone()];
            policy.monitored_roots = vec![folder.clone()];
            policy.disabled_kinds = vec![EntityKind::Email];
        }
        let settings = fx.ask(Request::SettingsGet)?;
        assert!(settings.get("watch").is_none() && settings.get("watch_folders").is_none());
        assert_eq!(settings["background"], false);
        assert_eq!(settings["monitored_roots"], json!([lossy(&folder)]));
        assert!(settings.get("inventory").is_none() && settings.get("inventory_exclude").is_none());
        let status = fx.ask(Request::InventoryStatus)?;
        assert_eq!(status["roots"], json!([lossy(&folder)]));
        assert_eq!(status["monitored"], json!([lossy(&folder)]));
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
        assert_eq!(fx.ask(Request::Status)?["monitoring"], true);
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
        for key in ["highlight", "explorer_menu", "monitoring", "http_api"] {
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

    #[test]
    fn accounts_are_added_and_listed_in_the_order_they_were_added() -> TestResult {
        let fx = Fixture::new()?;
        assert_eq!(fx.ask(Request::AccountsList)?, json!({"accounts": []}));
        let work = fx.add_google("Work")?;
        assert_eq!(work.id.len(), 16);
        assert_eq!(work.provider, Provider::GoogleDrive);
        assert_eq!(work.label, "Work");
        assert_eq!(work.path, r"\\Google Drive\Work");
        assert!(
            work.connected,
            "a key file that is there is all the account needs"
        );

        let personal = fx.ask(Request::AccountAdd {
            provider: Provider::Dropbox,
            label: "Personal".into(),
            sign_in: SignIn::DropboxDelegated {
                app_key: "key-1".into(),
            },
            client_secret: None,
        })?;
        assert_eq!(personal["connected"], false, "nobody has signed in yet");
        assert_eq!(
            personal["sign_in"],
            json!({"mode": "dropbox_delegated", "app_key": "key-1"})
        );
        assert_eq!(personal["path"], r"\\Dropbox\Personal");

        let list = fx.ask(Request::AccountsList)?;
        let typed: reply::Accounts = serde_json::from_value(list.clone())?;
        assert_eq!(typed.accounts.len(), 2);
        assert_eq!(
            typed.accounts.first(),
            Some(&work),
            "in the order they were added"
        );
        assert_eq!(list["accounts"][1], personal);
        Ok(())
    }

    #[test]
    fn an_account_that_cannot_work_is_refused_and_not_added() -> TestResult {
        let fx = Fixture::new()?;
        fx.add_google("Work")?;
        fx.add_dropbox("Personal")?;
        let key = fx.dir.file("key.json");
        for (provider, label, sign_in, wanted) in [
            (
                Provider::GoogleDrive,
                "Work",
                SignIn::GoogleServiceAccount {
                    key_file: key.clone(),
                    users: vec!["jan@acme.nl".into()],
                },
                "already",
            ),
            (
                Provider::Dropbox,
                "Other",
                SignIn::GoogleServiceAccount {
                    key_file: key,
                    users: vec!["jan@acme.nl".into()],
                },
                "cannot be signed in",
            ),
            (
                Provider::Dropbox,
                "Empty",
                SignIn::DropboxDelegated {
                    app_key: String::new(),
                },
                "Fill in the app key",
            ),
            (
                Provider::Box,
                "Team",
                SignIn::BoxDelegated {
                    client_id: "id-1".into(),
                },
                "client secret",
            ),
            (
                Provider::Dropbox,
                "a/b",
                SignIn::DropboxDelegated {
                    app_key: "key-2".into(),
                },
                "account name",
            ),
        ] {
            let error = fx
                .ask(Request::AccountAdd {
                    provider,
                    label: label.into(),
                    sign_in,
                    client_secret: None,
                })
                .err()
                .ok_or("an account that cannot work was added")?;
            assert_eq!(error.code(), "bad_request", "{label}");
            assert!(error.message().contains(wanted), "{error}");
        }
        let after = fx.ask(Request::AccountsList)?;
        assert_eq!(after["accounts"].as_array().map(Vec::len), Some(2));
        Ok(())
    }

    #[test]
    fn a_client_secret_goes_to_the_token_store_and_is_deleted_with_the_account() -> TestResult {
        let fx = Fixture::new()?;
        let added = fx.ask(Request::AccountAdd {
            provider: Provider::Box,
            label: "Team".into(),
            sign_in: SignIn::BoxDelegated {
                client_id: "id-1".into(),
            },
            client_secret: Some("s3cret-xyz".into()),
        })?;
        assert!(!added.to_string().contains("s3cret"), "{added}");
        assert_eq!(added["connected"], false, "a person still has to sign in");
        let id = added["id"].as_str().ok_or("no id")?.to_owned();
        let settings = fs::read_to_string(fx.data().join("sources.json"))?;
        assert!(!settings.contains("s3cret"), "{settings}");
        let listed = fx.ask(Request::AccountsList)?;
        assert!(!listed.to_string().contains("s3cret"), "{listed}");
        let tokens = TokenStore::new(&fx.data());
        assert_eq!(
            tokens.load(&id)?.client_secret.as_deref(),
            Some("s3cret-xyz")
        );

        fx.ask(Request::AccountRemove { id: id.clone() })?;
        assert_eq!(tokens.load(&id)?.client_secret, None);
        Ok(())
    }

    #[test]
    fn removing_an_account_takes_its_locations_and_what_the_inventory_held_of_it() -> TestResult {
        let fx = Fixture::new()?;
        let work = fx.add_google("Work")?;
        fx.add_dropbox("Personal")?;
        let local = fx.dir.file("docs");
        fs::create_dir_all(&local)?;
        fs::write(local.join("a.txt"), MAIL)?;
        let docs = PathBuf::from(r"\\Google Drive\Work\Docs");
        let personal = PathBuf::from(r"\\Dropbox\Personal");
        {
            let mut policy = fx.policy.lock().map_err(|_| "settings poisoned")?;
            policy.inventory_roots = vec![local.clone(), docs.clone(), personal.clone()];
            policy.monitored_roots = vec![docs.clone(), local.clone()];
        }
        fx.ask(Request::InventoryRescan)?;
        assert_eq!(fx.inventory.totals().files, 3);
        let cursors = Cursors::new(&fx.data());
        assert!(
            cursors.get(&docs)?.is_some(),
            "a finished scan keeps its cursor"
        );

        let removed = fx.ask(Request::AccountRemove {
            id: work.id.clone(),
        })?;
        assert_eq!(
            removed,
            json!({"id": work.id, "locations": [lossy(&docs)], "forgotten": 1})
        );
        assert_eq!(fx.inventory.totals().files, 2);
        assert_eq!(cursors.get(&docs)?, None, "its cursors went too");
        let saved = Policy::load_in(&fx.data())?;
        assert_eq!(saved.inventory_roots.len(), 2);
        assert!(
            saved
                .inventory_roots
                .iter()
                .all(|root| !sys::is_under(root, Path::new(&work.path)))
        );
        assert_eq!(saved.monitored_roots.len(), 1);
        let list = fx.ask(Request::AccountsList)?;
        assert_eq!(list["accounts"].as_array().map(Vec::len), Some(1));
        assert_eq!(list["accounts"][0]["label"], "Personal");

        let again = fx.ask(Request::AccountRemove { id: work.id });
        assert_eq!(again.err().map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    #[test]
    fn a_cloud_location_is_accepted_for_a_known_account_and_for_one_already_listed() -> TestResult {
        let fx = Fixture::new()?;
        fx.add_google("Work")?;
        let known = PathBuf::from(r"\\Google Drive\Work\Docs");
        let stranger = PathBuf::from(r"\\Google Drive\Nobody\Docs");
        let set = |root: &Path| {
            fx.ask(Request::SettingsSet {
                settings: SettingsPatch {
                    inventory_roots: Some(vec![root.to_path_buf()]),
                    ..SettingsPatch::default()
                },
            })
        };

        let saved = set(&known)?;
        assert_eq!(saved["inventory_roots"], json!([lossy(&known)]));
        assert_eq!(
            Policy::load_in(&fx.data())?.inventory_roots,
            std::slice::from_ref(&known)
        );

        let refused = set(&stranger)
            .err()
            .ok_or("a stranger's folder was accepted")?;
        assert_eq!(refused.code(), "bad_request");
        assert!(
            refused.message().contains("add the account first"),
            "{refused}"
        );
        assert_eq!(Policy::load_in(&fx.data())?.inventory_roots, [known]);

        // A location the list already has is kept, whatever became of its account.
        fx.set_locations(vec![stranger.clone()])?;
        set(&stranger)?;
        Ok(())
    }

    #[test]
    fn a_rescan_is_one_run_over_this_pc_and_every_cloud_location() -> TestResult {
        let fx = Fixture::new()?;
        fx.add_google("Work")?;
        let local = fx.dir.file("docs");
        fs::create_dir_all(&local)?;
        fs::write(local.join("a.txt"), MAIL)?;
        let docs = PathBuf::from(r"\\Google Drive\Work\Docs");
        fx.set_locations(vec![local, docs.clone()])?;

        let totals = fx.ask(Request::InventoryRescan)?;
        assert_eq!(totals["files"], 2, "{totals}");
        assert_eq!(totals["hits"], 2);
        let listed = fx.ask(Request::InventoryList {
            under: Some(docs.clone()),
            limit: None,
            offset: 0,
        })?;
        assert_eq!(listed["total"], 1, "{listed}");
        assert_eq!(
            listed["entries"][0]["path"],
            lossy(&docs.join("a.txt")).as_str()
        );
        let tree = fx.ask(Request::InventoryTree { under: Some(docs) })?;
        assert_eq!(tree["nodes"][0]["name"], "a.txt", "{tree}");
        assert_eq!(fx.ask(Request::InventoryStatus)?["files"], 2);
        assert_eq!(fx.ask(Request::InventoryStatus)?["scanning"], Value::Null);
        Ok(())
    }

    #[test]
    fn a_cloud_location_that_fails_is_told_after_the_others_were_scanned() -> TestResult {
        let fx = Fixture::new()?;
        fx.add_google("Broken")?;
        fx.add_google("Work")?;
        let local = fx.dir.file("docs");
        fs::create_dir_all(&local)?;
        fs::write(local.join("a.txt"), MAIL)?;
        let broken = PathBuf::from(r"\\Google Drive\Broken\Docs");
        let work = PathBuf::from(r"\\Google Drive\Work\Docs");
        fx.set_locations(vec![broken.clone(), local, work.clone()])?;

        let error = fx
            .ask(Request::InventoryRescan)
            .err()
            .ok_or("a location that failed was told as a success")?;
        assert_eq!(error.code(), "bad_request");
        assert_eq!(error.message(), "Sign in to Google Drive again.");
        assert_eq!(fx.inventory.totals().files, 2, "the others were scanned");
        let cursors = Cursors::new(&fx.data());
        assert!(cursors.get(&work)?.is_some());
        assert_eq!(cursors.get(&broken)?, None);
        assert!(!fx.local.rescanning.load(Ordering::Relaxed));
        Ok(())
    }

    #[test]
    fn a_location_of_an_account_that_is_gone_is_an_error_and_the_rest_is_scanned() -> TestResult {
        let fx = Fixture::new()?;
        let local = fx.dir.file("docs");
        fs::create_dir_all(&local)?;
        fs::write(local.join("a.txt"), MAIL)?;
        fx.set_locations(vec![PathBuf::from(r"\\Dropbox\Ghost\Docs"), local])?;
        let error = fx
            .ask(Request::InventoryRescan)
            .err()
            .ok_or("a location without an account was scanned")?;
        assert_eq!(error.code(), "bad_request");
        assert!(
            error.message().contains("not connected any more"),
            "{error}"
        );
        assert_eq!(fx.inventory.totals().files, 1);
        Ok(())
    }

    #[test]
    fn the_folders_of_an_account_are_browsed_from_its_top_and_below() -> TestResult {
        let fx = Fixture::new()?;
        let work = fx.add_google("Work")?;
        let browse = |under: Option<&str>| {
            fx.ask(Request::AccountBrowse {
                id: work.id.clone(),
                under: under.map(PathBuf::from),
            })
        };
        let top = json!({"folders": [
            {"path": r"\\Google Drive\Work\Docs", "name": "Docs"},
            {"path": r"\\Google Drive\Work\Site", "name": "Site"},
        ]});
        assert_eq!(browse(None)?, top);
        assert_eq!(browse(Some(r"\\Google Drive\Work"))?, top);
        assert_eq!(
            browse(Some(r"\\Google Drive\Work\Docs"))?,
            json!({"folders": [{"path": r"\\Google Drive\Work\Docs\Sub", "name": "Sub"}]})
        );
        assert_eq!(
            browse(Some(r"\\Google Drive\Work\Site"))?,
            json!({"folders": []})
        );

        for (under, code) in [
            (r"\\Dropbox\Other\Docs", "bad_request"),
            ("Docs", "bad_request"),
            (r"\\Google Drive\Work\Missing", "bad_request"),
        ] {
            let error = browse(Some(under))
                .err()
                .ok_or("browsed where nothing is")?;
            assert_eq!(error.code(), code, "{under}");
        }
        let unknown = fx.ask(Request::AccountBrowse {
            id: "0000000000000000".into(),
            under: None,
        });
        assert_eq!(unknown.err().map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    #[test]
    fn signing_in_gives_the_address_to_the_opener_and_what_the_person_does_comes_back() -> TestResult
    {
        let fx = Fixture::new()?;
        let added = fx.ask(Request::AccountAdd {
            provider: Provider::OneDrive,
            label: "Me".into(),
            sign_in: SignIn::MicrosoftDelegated {
                tenant: "consumers".into(),
                client_id: "client-1".into(),
            },
            client_secret: None,
        })?;
        let id = added["id"].as_str().ok_or("no id")?.to_owned();

        let urls: Arc<Mutex<Vec<String>>> = Arc::default();
        let visitors: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::default();
        let opener: UrlOpener = {
            let (urls, visitors) = (Arc::clone(&urls), Arc::clone(&visitors));
            Arc::new(move |url: &str| {
                if let Ok(mut urls) = urls.lock() {
                    urls.push(url.to_owned());
                }
                // The person at the browser says no, as the browser would: by visiting the
                // address the sign-in listens on.
                if let Some((address, target)) = refusal(url)
                    && let Ok(mut visitors) = visitors.lock()
                {
                    visitors.push(thread::spawn(move || visit(&address, &target)));
                }
            })
        };
        let local =
            Fixture::local_over(&fx.dir, &fx.engine, &fx.inventory, &fx.policy).with_opener(opener);
        let error = local
            .handle(Request::AccountConnect { id })
            .err()
            .ok_or("signed in with nobody there")?;
        assert_eq!(error.code(), "bad_request");
        assert!(error.message().contains("does not allow"), "{error}");
        let visitors = std::mem::take(&mut *visitors.lock().map_err(|_| "poisoned")?);
        for visitor in visitors {
            visitor.join().map_err(|_| "the visitor panicked")?;
        }
        let urls = urls.lock().map_err(|_| "poisoned")?;
        assert_eq!(urls.len(), 1, "{urls:?}");
        let url = urls.first().ok_or("nothing was opened")?;
        assert!(url.starts_with("https://"), "{url}");
        assert!(url.contains("client_id=client-1"), "{url}");

        let unknown = fx.ask(Request::AccountConnect {
            id: "0000000000000000".into(),
        });
        assert_eq!(unknown.err().map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    #[test]
    fn what_walks_the_file_system_refuses_a_path_in_a_cloud_account() -> TestResult {
        let fx = Fixture::new()?;
        let cloud = PathBuf::from(r"\\Google Drive\Work\Docs");
        for request in [
            Request::ScanFiles {
                paths: vec![cloud.clone()],
                record: true,
            },
            Request::AnonymizeFiles {
                paths: vec![cloud.clone()],
                out: fx.dir.file("out"),
            },
            Request::AnonymizeFiles {
                paths: vec![fx.dir.file("x")],
                out: cloud.clone(),
            },
            Request::DeanonymizeFiles {
                paths: vec![fx.dir.file("x"), cloud.clone()],
                out: fx.dir.file("out"),
                tolerant: false,
            },
            Request::SubjectSearch {
                values: texts(&["Jan"]),
                paths: vec![cloud.clone()],
            },
        ] {
            let op = request.op();
            let error = fx.ask(request).err().ok_or("a cloud path was walked")?;
            assert_eq!(error.code(), "bad_request", "{op}");
            assert!(error.message().contains("cloud account"), "{op}: {error}");
        }
        assert_eq!(fx.inventory.totals().files, 0);

        // The inventory's own views take a path of an account as they take any other.
        let listed = fx.ask(Request::InventoryList {
            under: Some(cloud.clone()),
            limit: None,
            offset: 0,
        })?;
        assert_eq!(listed["total"], 0);
        let tree = fx.ask(Request::InventoryTree { under: Some(cloud) })?;
        assert_eq!(tree["nodes"], json!([]));
        Ok(())
    }

    #[test]
    fn a_subject_search_without_paths_looks_only_at_the_locations_on_this_pc() -> TestResult {
        let fx = Fixture::new()?;
        let folder = fx.dir.file("docs");
        fs::create_dir_all(&folder)?;
        fs::write(folder.join("b.txt"), "bel +31 6 1234 5678 voor Marie")?;
        fx.set_locations(vec![PathBuf::from(r"\\Google Drive\Work\Docs"), folder])?;
        let found = fx.ask(Request::SubjectSearch {
            values: texts(&["+31612345678"]),
            paths: vec![],
        })?;
        assert_eq!(
            found["matches"].as_array().map(Vec::len),
            Some(1),
            "{found}"
        );
        Ok(())
    }
}
