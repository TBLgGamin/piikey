//! The inventory as the controller serves it: the scans that fill it and the thread that runs
//! them, what the dialog of a scan shows, the views of it, the findings of the files a result
//! names, and the files written from it.
//!
//! The inventory is scanned when somebody asks: the Scan button, a folder or file the user
//! points at, Explorer's menu, the API. Nothing is scanned on a timer. What changes in the
//! monitored locations is scanned into it too, see [`watch`](super::watch).
//!
//! A location is a folder on this PC or a folder of a cloud account, and one scan runs over
//! both: the folders on this PC first, then the cloud locations, with one count of files, one
//! result and one thread. A path in a cloud account is never looked at on this PC's file system:
//! Windows would take `\\Google Drive\...` for a network share and wait for a server of that
//! name. A cloud file's contents are downloaded into memory, scanned and dropped: the inventory
//! keeps counts and paths of it, as of any file.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use piikey::{
    engine::Engine,
    inventory::{self, Busy, Entry, Finding, Inventory, Node, Progress, Report, Tiles, TypeTotal},
    sources::{self, Accounts, CloudScan, Connector, Cursors, Scanned},
    sys,
};

use super::{
    Controller, Edit, FolderStatus, Notice, PROGRESS_EVERY, ScanSummary, State, watch::unix_now,
};
use crate::{
    Describe, Res,
    ui::{
        exports,
        scanner::{Changes, Job, Kind, Request, Scanner},
    },
};

/// How long a quitting app waits for the scan it cancelled to save what it did.
const SCAN_STOP_WAIT: Duration = Duration::from_secs(2);

/// The most files a findings view reads: a folder can hold thousands that have personal data.
pub const MOST_FILES: usize = 500;

/// How many files the findings of a view are read for at once.
const FINDINGS_PARALLEL: usize = 4;

/// What a read of findings reports as it goes, see [`Controller::read_findings`].
#[derive(Debug)]
pub enum FindingsEvent {
    /// The detection model is being loaded: nothing is read before it is there.
    Loading,
    /// What a file is busy with when that takes a while.
    Busy(PathBuf, Busy),
    /// More values of a file, in the order they are found.
    Found(PathBuf, Vec<Finding>),
    /// The file is read, or could not be: the message says why, for the user.
    Done(PathBuf, Res<()>),
}

/// A scan somebody asked to see the result of: the window comes forward, at once, and shows a
/// dialog that follows the scan from the queue to its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    /// Grows with every request, so the window can tell a new one from one it handled. It is
    /// given when the scan is queued.
    pub seq: u64,
    /// What was asked to be scanned, as it was given.
    pub paths: Vec<PathBuf>,
    /// How far the scan is. Its progress is [`Snapshot::scan`](super::Snapshot::scan).
    pub state: RevealState,
}

/// How far the scan of a [`Reveal`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealState {
    /// Queued behind another scan.
    Waiting,
    /// Running.
    Scanning,
    /// Done: what the inventory holds of what was scanned.
    Done(ScanSummary),
    /// It did not happen: the message says why, for the user.
    Failed(String),
}

/// One level of an inventory's tree, see [`Controller::inventory_view`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryView {
    /// What lies directly under the folder asked for, the one with the most values first.
    pub nodes: Vec<Node>,
    /// What the inventory knows of the selected file.
    pub entry: Option<Entry>,
}

/// `path` as the `Option` the inventories take: the empty path means all of it.
fn under(path: &Path) -> Option<&Path> {
    (!path.as_os_str().is_empty()).then_some(path)
}

/// A file whose findings a view lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFile {
    pub path: PathBuf,
    /// What the view calls the file: its name, or its path below the folder it was found in; the
    /// whole path when two files would have the same.
    pub label: String,
}

/// The files a findings view reads, see [`Controller::finding_files`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingFiles {
    /// The files to read, in the order the view lists them.
    pub files: Vec<FindingFile>,
    /// How many more there are than the view reads.
    pub left_out: usize,
}

/// Keeps the detection model loaded while the findings of files are read, and gives it back when
/// the read ends, however it ends.
struct FindingsRead<'a>(&'a Controller);

impl<'a> FindingsRead<'a> {
    fn start(controller: &'a Controller) -> Self {
        controller.update(|state| state.findings += 1);
        controller.sync_model();
        Self(controller)
    }
}

impl Drop for FindingsRead<'_> {
    fn drop(&mut self) {
        self.0
            .update(|state| state.findings = state.findings.saturating_sub(1));
        self.0.sync_model_after_use();
    }
}

/// The accounts the cloud files of a read of findings are in, each with the connector that reads
/// it. A connector is made once for an account and shared by the threads of the read, as one run
/// of a scan shares one.
struct CloudReaders {
    /// The accounts, or why they could not be read; none when no file of the read is in one.
    accounts: Res<Accounts>,
    /// The connector of each account a file of the read is in, by the account's id, or why it
    /// has none.
    connectors: HashMap<String, Res<Box<dyn Connector>>>,
}

impl CloudReaders {
    /// The readers `files` need. Nothing is opened when none of them is in a cloud account.
    fn of(controller: &Controller, files: &[PathBuf]) -> Self {
        let mut readers = Self {
            accounts: Ok(Accounts::default()),
            connectors: HashMap::new(),
        };
        if !files.iter().any(|file| sources::is_virtual(file)) {
            return readers;
        }
        let accounts = match Accounts::open(controller.data_dir()) {
            Ok(accounts) => accounts,
            Err(error) => {
                readers.accounts = Err(format!("Could not read the connected accounts: {error}"));
                return readers;
            }
        };
        for account in files.iter().filter_map(|file| accounts.of(file)) {
            readers
                .connectors
                .entry(account.id.clone())
                .or_insert_with(|| {
                    controller
                        .backend
                        .connector(account)
                        .map_err(|error| controller.cloud_failed(Some(account), &error))
                });
        }
        readers.accounts = Ok(accounts);
        readers
    }

    /// Reads what the detector finds in the cloud file at `path` to `report`, through the
    /// connector of its account.
    fn read(
        &self,
        controller: &Controller,
        engine: &Engine,
        path: &Path,
        stopped: &AtomicBool,
        report: &(dyn Fn(Report) -> bool + Sync),
    ) -> Res<()> {
        let accounts = self.accounts.as_ref().map_err(Clone::clone)?;
        let Some(account) = accounts.of(path) else {
            return Err(not_connected(path));
        };
        let connector = self
            .connectors
            .get(&account.id)
            .ok_or_else(|| not_connected(path))?
            .as_ref()
            .map_err(Clone::clone)?;
        sources::findings(connector.as_ref(), engine, path, stopped, report).map_err(|error| {
            // What goes wrong with the file (it is gone, or no format piikey reads) is about the
            // file; an account that has to sign in again is about the account.
            if matches!(error, sources::Error::SignInNeeded { .. }) {
                controller.cloud_failed(Some(account), &error)
            } else {
                error.to_string()
            }
        })
    }
}

/// Why a file of a cloud account cannot be read when no connected account has its name.
fn not_connected(path: &Path) -> String {
    format!(
        "The account of {} is not connected any more. Connect it again in Settings, or remove the location.",
        shown(path)
    )
}

/// `path` as a person reads it: a cloud path as the account's name and its folders
/// ([`sources::display_path`]), any other as Windows writes it.
fn shown(path: &Path) -> String {
    sources::display_path(path).unwrap_or_else(|| path.display().to_string())
}

/// The name of the file or folder at `path`; the whole path for one that has none (a drive, or the
/// top of a cloud account, which reads as the account's name).
fn name_of(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| shown(path), |name| name.to_string_lossy().into_owned())
}

/// `path` as seen from the folder `root` it was found in; its name when it is not below it. The
/// folders of a cloud path are told apart with `›`, as everywhere else.
fn label_under(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|rest| !rest.as_os_str().is_empty())
        .map_or_else(
            || name_of(path),
            |rest| {
                if sources::is_virtual(path) {
                    let parts: Vec<_> = rest
                        .components()
                        .map(|part| part.as_os_str().to_string_lossy())
                        .collect();
                    parts.join(" \u{203a} ")
                } else {
                    rest.display().to_string()
                }
            },
        )
}

/// What identifies a file among the ones listed: its path as Windows compares it.
fn key_of(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

/// The files of a findings view: the `named` ones first, then the ones found in folders as
/// `(values, path, label)`, the one with the most values first; a file listed twice is listed
/// once. At most `most` files are kept.
fn pick_files(
    named: Vec<(PathBuf, String)>,
    mut held: Vec<(u64, PathBuf, String)>,
    most: usize,
) -> FindingFiles {
    held.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut seen: HashSet<String> = HashSet::new();
    let mut files: Vec<FindingFile> = Vec::new();
    let mut all = 0_usize;
    for (path, label) in named
        .into_iter()
        .chain(held.into_iter().map(|(_, path, label)| (path, label)))
    {
        if !seen.insert(key_of(&path)) {
            continue;
        }
        all += 1;
        if files.len() < most {
            files.push(FindingFile { path, label });
        }
    }
    let mut labels: HashMap<String, usize> = HashMap::new();
    for file in &files {
        *labels.entry(file.label.to_lowercase()).or_default() += 1;
    }
    for file in &mut files {
        if labels
            .get(&file.label.to_lowercase())
            .is_some_and(|&n| n > 1)
        {
            file.label = shown(&file.path);
        }
    }
    FindingFiles {
        left_out: all - files.len(),
        files,
    }
}

/// How the scan of one cloud location came out, for the window.
struct Settled {
    /// The location, as it was given.
    root: PathBuf,
    /// No connected account has the name of the location any more.
    orphan: bool,
    /// What the scan did, or why it could not: the plain words of the account's error.
    result: Result<Scanned, String>,
}

impl Controller {
    /// The inventory: which files hold personal data.
    pub fn inventory(&self) -> Arc<Inventory> {
        Arc::clone(&self.inventory)
    }

    /// One level of the inventory's tree, the real folders of the computer: what lies directly
    /// under `at` or, for an empty `at`, one node for each drive or network share that holds
    /// findings. `selected` is a file whose entry is wanted.
    pub fn inventory_view(&self, at: &Path, selected: Option<&Path>) -> InventoryView {
        InventoryView {
            nodes: self.inventory.children(under(at)),
            entry: selected.and_then(|file| self.inventory.entry(file)),
        }
    }

    /// What the inventory found in each of its locations, counted by path: one node for each
    /// that holds anything. Locations inside one another each count what lies in them.
    pub fn places(&self) -> Vec<Node> {
        self.policy()
            .inventory_roots
            .iter()
            .filter_map(|root| self.inventory.node(root))
            .collect()
    }

    /// Every file of the inventory that holds personal data at and under `under` (all of it for
    /// an empty path), as the treemap's tiles: the `limit` with the most values first, and the
    /// others added up.
    pub fn tiles(&self, at: &Path, limit: usize) -> Tiles {
        self.inventory.tiles(under(at), limit)
    }

    /// How much there is of each kind at and under `under` (all of it for an empty path): the
    /// legend of the treemap.
    pub fn type_totals(&self, at: &Path) -> Vec<TypeTotal> {
        self.inventory.type_totals(under(at))
    }

    /// The files the findings view of `roots` reads: every file that was named, and for each folder
    /// the files the inventory found personal data in (or, outside the locations, the last asked
    /// scan found), the ones with the most first. A folder holds thousands of files at worst, so
    /// the list stops at [`MOST_FILES`] and says how many it left out. Waits on the disk (a root
    /// may be a folder or a file), so it is for the background. A root in a cloud account is not
    /// on the disk: the inventory says what it is, a file when it has an entry of its own and a
    /// folder otherwise.
    pub fn finding_files(&self, roots: &[PathBuf]) -> FindingFiles {
        let outside = self
            .asked_outside
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut named: Vec<(PathBuf, String)> = Vec::new();
        let mut held: Vec<(u64, PathBuf, String)> = Vec::new();
        for root in roots {
            let folder = if sources::is_virtual(root) {
                self.inventory.entry(root).is_none()
            } else {
                root.is_dir()
            };
            if folder {
                let stored = self
                    .inventory
                    .entries(Some(root), 1)
                    .into_iter()
                    .map(|entry| (entry.hits(), entry.path));
                let elsewhere = outside
                    .iter()
                    .filter(|(_, path)| sys::is_under(path, root))
                    .cloned();
                for (hits, path) in stored.chain(elsewhere) {
                    let label = label_under(root, &path);
                    held.push((hits, path, label));
                }
            } else {
                named.push((root.clone(), name_of(root)));
            }
        }
        pick_files(named, held, MOST_FILES)
    }

    /// Forgets what the inventory holds outside its locations, and shows the totals that leave:
    /// the Inventory lists what lies in its locations and nothing else.
    pub(super) fn keep_to_locations(&self) {
        let roots = self.policy().inventory_roots;
        if let Err(error) = self.inventory.forget_outside(&roots) {
            self.notify(Notice::error(format!(
                "Could not tidy the inventory: {error}"
            )));
        }
        let totals = self.inventory.totals();
        self.update(|state| state.inventory_totals = totals);
    }

    /// Reads what the detector finds in each of `files`, four at a time in the scan pool, and
    /// reports it to `report` as it is found: what the file is busy with, more of its values
    /// (the ones patterns find come first, then what the model finds, see
    /// [`inventory::findings`]) and, last for each file, that it is done or why it could not be
    /// read. `report` says whether to go on, and the read stops there (after the group of texts
    /// the model is in); it also stops once `limit` values were reported. It is for showing:
    /// nothing is stored, not by the inventory and not anywhere else. The detection model stays
    /// loaded from the first file to the last, as for a scan, and a while after it. A file that
    /// cannot be read, is bigger than piikey reads or is not a format it understands comes with a
    /// message for the user instead of its findings. A file in a cloud account is downloaded into
    /// memory through its account, read and dropped.
    pub fn read_findings(
        &self,
        files: &[PathBuf],
        limit: usize,
        report: impl FnMut(FindingsEvent) -> bool + Send,
    ) {
        if files.is_empty() {
            return;
        }
        let report = Mutex::new(report);
        let stopped = AtomicBool::new(false);
        let found = AtomicUsize::new(0);
        let tell = |event: FindingsEvent| -> bool {
            if stopped.load(Ordering::Relaxed) {
                return false;
            }
            let more = (report.lock().unwrap_or_else(PoisonError::into_inner))(event);
            if !more {
                stopped.store(true, Ordering::Relaxed);
            }
            more
        };
        tell(FindingsEvent::Loading);
        let _reading = FindingsRead::start(self);
        let engine = self.engine();
        let clouds = CloudReaders::of(self, files);
        let next = AtomicUsize::new(0);
        self.in_scan_pool(|| {
            rayon::scope(|scope| {
                for _ in 0..FINDINGS_PARALLEL.min(files.len()) {
                    scope.spawn(|_| {
                        while !stopped.load(Ordering::Relaxed) {
                            let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) else {
                                break;
                            };
                            let on_report = |report: Report| match report {
                                Report::Busy(busy) => tell(FindingsEvent::Busy(path.clone(), busy)),
                                Report::Found(list) => {
                                    let total =
                                        found.fetch_add(list.len(), Ordering::Relaxed) + list.len();
                                    let more = tell(FindingsEvent::Found(path.clone(), list));
                                    if total >= limit {
                                        stopped.store(true, Ordering::Relaxed);
                                    }
                                    more && !stopped.load(Ordering::Relaxed)
                                }
                            };
                            let result = if sources::is_virtual(path) {
                                clouds.read(self, &engine, path, &stopped, &on_report)
                            } else {
                                inventory::findings(&engine, path, &on_report).describe()
                            };
                            tell(FindingsEvent::Done(path.clone(), result));
                        }
                    });
                }
            });
        });
    }

    /// Writes what the inventory found under `under` (everything for an empty path) as CSV to a
    /// new file in Downloads and returns where it is.
    ///
    /// # Errors
    /// A message when the file cannot be written.
    pub fn export_report(&self, under: &Path) -> Res<PathBuf> {
        exports::report_csv(
            &self.inventory,
            under,
            &exports::downloads()?,
            &exports::stamp(),
        )
    }

    /// Writes the masked copy of `file` beside it and returns where it is.
    ///
    /// # Errors
    /// A message when the file cannot be read, is not a format piikey reads, or the copy cannot
    /// be written; and for a file in a cloud account, which is not on this PC to write beside.
    pub fn masked_copy(&self, file: &Path) -> Res<PathBuf> {
        if sources::is_virtual(file) {
            return Err("A masked copy can only be made of a file on this PC.".to_owned());
        }
        exports::masked_copy(&self.engine(), file)
    }

    /// Runs `work` in the pool the scans use: half the cores, so the PC stays responsive. The
    /// pool is made the first time it is needed and shared by everything that asks for it, the
    /// scan thread and the API alike. When the system will not start its threads, `work` runs
    /// where it is called.
    pub fn in_scan_pool<R: Send>(&self, work: impl FnOnce() -> R + Send) -> R {
        match &*self.pool {
            Some(pool) => pool.install(work),
            None => work(),
        }
    }

    /// Blocks until every scan that was asked for is done and none runs, monitoring's included;
    /// `false` on timeout.
    pub fn wait_scans(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let (state, result) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                state.scan.is_some() || state.watch.scan.is_some() || !self.scanner.idle()
            })
            .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        !result.timed_out()
    }

    /// Cancels the scan that runs and gives it a moment to save what it did.
    pub(super) fn stop_scans(&self) {
        self.scanner.stop();
        let state = self.lock();
        let _ = self
            .changed
            .wait_timeout_while(state, SCAN_STOP_WAIT, |state| {
                state.scan.is_some() || state.watch.scan.is_some()
            })
            .unwrap_or_else(PoisonError::into_inner);
    }

    /// Stops the scan of what monitoring saw, if one runs, drops what it had still to look at,
    /// and gives the scan a moment to save what it did. What a removed location held is
    /// forgotten once that scan has saved, so the scan cannot add it again.
    pub(super) fn stop_watch_scan(&self) {
        self.scanner.stop_watch();
        let state = self.lock();
        let _ = self
            .changed
            .wait_timeout_while(state, SCAN_STOP_WAIT, |state| state.watch.scan.is_some())
            .unwrap_or_else(PoisonError::into_inner);
    }

    /// Starts the scan thread the first time something needs it.
    pub(super) fn ensure_scanner(self: &Arc<Self>) {
        if !self.scanner.start_once() {
            return;
        }
        let controller = Arc::downgrade(self);
        let scanner = Arc::clone(&self.scanner);
        let spawned = thread::Builder::new()
            .name("piikey-scan".into())
            .spawn(move || scan_loop(&controller, &scanner));
        if let Err(error) = spawned {
            self.scanner.start_failed();
            self.notify(Notice::error(format!(
                "Could not start the scan thread: {error}"
            )));
        }
    }

    /// Queues a scan of `paths` into the inventory: it runs before what monitoring has to do.
    /// With `reveal` the window is asked to come forward at once, with a dialog for it.
    pub(super) fn ask_scan(self: &Arc<Self>, paths: Vec<PathBuf>, reveal: bool) {
        let reveal = reveal.then(|| self.begin_reveal(&paths));
        self.scanner.ask(Request { paths, reveal });
        self.ensure_scanner();
    }

    /// Makes the [`Reveal`] of a scan that was just asked for, which replaces the last one.
    pub(super) fn begin_reveal(&self, paths: &[PathBuf]) -> u64 {
        self.update(|state| {
            let seq = state.reveal.as_ref().map_or(0, |reveal| reveal.seq) + 1;
            state.reveal = Some(Reveal {
                seq,
                paths: paths.to_vec(),
                state: RevealState::Waiting,
            });
            seq
        })
    }

    /// Scans the inventory's locations now, whether or not anything changed in them; only files
    /// that did are read.
    pub(super) fn scan_all(self: &Arc<Self>) {
        let roots = self.policy().inventory_roots;
        if roots.is_empty() {
            self.notify(Notice::warning(
                "There is no folder to scan yet. Add one first.",
            ));
            return;
        }
        self.ask_scan(roots, false);
    }

    /// Adds `path` to the inventory's folders and scans it with a dialog. Nothing is scanned
    /// when `path` is refused (it is no folder).
    pub(super) fn add_location(self: &Arc<Self>, path: PathBuf) {
        let added = self.edit(&Edit::InventoryRoot {
            path: path.clone(),
            on: true,
        });
        if added {
            self.ask_scan(vec![path], true);
        }
    }

    /// Runs one job, on the scan thread. A scan that was asked to be shown leaves its result in
    /// the [`Reveal`]; either way the store is saved.
    pub(super) fn run_scan(&self, job: &Job) {
        match &job.kind {
            Kind::Asked(request) => self.run_asked(job, request),
            Kind::Watch(changes) => self.run_watch(job, changes),
            Kind::Forget { folder } => self.run_forget(folder),
        }
    }

    /// A cancelled job whose rest is not run: a scan that was to be shown says it was stopped.
    pub(super) fn scan_stopped(&self, job: &Job) {
        if let Kind::Asked(Request {
            reveal: Some(seq), ..
        }) = &job.kind
        {
            self.reveals_stopped(&[*seq]);
        }
    }

    /// The scans shown as `seqs` will not run (to the end): their dialogs say so.
    pub(super) fn reveals_stopped(&self, seqs: &[u64]) {
        self.update(|state| {
            for &seq in seqs {
                set_reveal(
                    state,
                    seq,
                    RevealState::Failed("The scan was stopped.".to_owned()),
                );
            }
        });
    }

    /// Stops the scan shown as `seq`: its dialog was closed while it waited or ran. A queued scan
    /// is dropped and its dialog told so here; a running one stops within the file it is in, keeps
    /// what it scanned before, and the scan thread tells the dialog once it has saved.
    pub(super) fn stop_scan(&self, seq: u64) {
        if self.scanner.stop_request(seq) {
            self.reveals_stopped(&[seq]);
        }
    }

    /// `folder` was removed from the locations: what the inventory holds under it goes, unless a
    /// location that is still listed holds it. For a folder in a cloud account where the last
    /// scan of it left off goes too, so that adding it again lists it in full.
    fn run_forget(&self, folder: &Path) {
        let still = self
            .policy()
            .inventory_roots
            .iter()
            .any(|root| sys::is_under(folder, root));
        if !still && let Err(error) = self.inventory.forget_under(folder) {
            self.notify(Notice::error(format!(
                "Could not forget what was found in {}: {error}",
                shown(folder)
            )));
        }
        if sources::is_virtual(folder)
            && let Err(error) = Cursors::new(self.data_dir()).forget_under(folder)
        {
            self.notify(Notice::error(format!(
                "Could not forget where the scan of {} left off: {error}",
                shown(folder)
            )));
        }
        let totals = self.inventory.totals();
        self.update(|state| state.inventory_totals = totals);
    }

    /// Scans what `request` names into the inventory: the folders on this PC, then the cloud
    /// locations among them, as one run with one count. What it found outside the locations is
    /// shown by its dialog and findings view, then forgotten by the inventory.
    fn run_asked(&self, job: &Job, request: &Request) {
        // A `piikey-cli` run on its own may be scanning the same inventory.
        let _lock = match self.inventory.lock_scan() {
            Ok(lock) => lock,
            Err(error) => {
                let text = format!("Could not scan: {error}");
                self.notify(Notice::error(text.clone()));
                if let Some(seq) = request.reveal {
                    self.update(|state| set_reveal(state, seq, RevealState::Failed(text)));
                }
                return;
            }
        };
        let progress = Arc::new(Progress::default());
        self.update(|state| {
            state.scan = Some(Arc::clone(&progress));
            if let Some(seq) = request.reveal {
                set_reveal(state, seq, RevealState::Scanning);
            }
        });
        self.sync_model();
        let engine = self.engine();
        let (local, cloud) = sources::split_roots(&request.paths);
        let (result, scans) = self.with_progress(|| {
            // The folders on this PC first: that starts the count the cloud locations add to.
            let result = if local.is_empty() {
                Ok(())
            } else {
                self.inventory
                    .scan_paths(&engine, &local, &progress, &job.cancel)
            };
            let scans = self.scan_cloud_roots(&engine, &cloud, &progress, &job.cancel);
            (result, scans)
        });
        let clouds = self.settle_clouds(scans);
        // Nobody else would hear of a location whose account is gone: the dialog tells only
        // when nothing else was scanned.
        for lost in clouds.iter().filter(|one| one.orphan) {
            if let Err(text) = &lost.result {
                self.notify(Notice::error(text.clone()));
            }
        }
        // The result comes from the inventory before it forgets what lies outside the locations.
        // A scan that was stopped either goes on later (its dialog keeps waiting) or is told so
        // by `scan_stopped`.
        let local_result = (!local.is_empty()).then_some(&result);
        let outcome = request.reveal.filter(|_| !job.cancelled()).map(|seq| {
            let state = self.scan_result(request, local_result, &clouds, &progress);
            (seq, state)
        });
        let roots = self.policy().inventory_roots;
        let outside: Vec<(u64, PathBuf)> = request
            .paths
            .iter()
            .flat_map(|path| self.inventory.entries(Some(path), 1))
            .filter(|entry| !roots.iter().any(|root| sys::is_under(&entry.path, root)))
            .map(|entry| (entry.hits(), entry.path))
            .collect();
        *self
            .asked_outside
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = outside;
        let forgot = self.inventory.forget_outside(&roots);
        // What lies outside the locations is not kept, and neither is where its scan left off.
        let forgot_cursors = self.forget_unplaced(&cloud, &roots);
        let totals = self.inventory.totals();
        self.update(|state| {
            state.scan = None;
            state.inventory_totals = totals;
            if let Some((seq, outcome)) = outcome {
                set_reveal(state, seq, outcome);
            }
        });
        if let Err(error) = result.and(forgot.map(drop)).and(forgot_cursors) {
            self.notify(Notice::error(format!(
                "Could not save the inventory: {error}"
            )));
        }
        self.sync_model_after_use();
    }

    /// Scans what monitoring saw change into the inventory: everything, or the paths that were
    /// reported, and the cloud locations that were asked about. Only the monitored locations are
    /// looked at.
    fn run_watch(&self, job: &Job, changes: &Changes) {
        let policy = self.policy();
        if policy.monitored_roots.is_empty() {
            return;
        }
        // A `piikey-cli` run on its own may be scanning the same inventory.
        let _lock = match self.inventory.lock_scan() {
            Ok(lock) => lock,
            Err(error) => {
                self.notify(Notice::error(format!(
                    "Could not scan what changed in your monitored locations: {error}"
                )));
                return;
            }
        };
        let progress = Arc::new(Progress::default());
        self.update(|state| state.watch.scan = Some(Arc::clone(&progress)));
        self.sync_model();
        let engine = self.engine();
        // The system reports on the folders on this PC; a cloud location is asked, never looked
        // at on the file system. Of those, the ones that were asked about and are still monitored.
        let (local, cloud) = sources::split_roots(&policy.monitored_roots);
        let asked: Vec<PathBuf> = cloud
            .into_iter()
            .filter(|root| {
                changes.everything || changes.clouds().any(|polled| sys::same_path(polled, root))
            })
            .collect();
        let touched = changes.list();
        let (result, scans) = self.with_progress(|| {
            // The count starts with the folders on this PC, if there is anything to look at there.
            let result = if local.is_empty() || (!changes.everything && touched.is_empty()) {
                Ok(())
            } else if changes.everything {
                self.inventory
                    .scan_paths(&engine, &local, &progress, &job.cancel)
            } else {
                self.inventory
                    .refresh(&engine, &local, &touched, &progress, &job.cancel)
            };
            let scans = self.scan_cloud_roots(&engine, &asked, &progress, &job.cancel);
            (result, scans)
        });
        self.settle_clouds(scans);
        let totals = self.inventory.totals();
        self.update(|state| {
            state.watch.scan = None;
            state.inventory_totals = totals;
        });
        if let Err(error) = result {
            self.notify(Notice::error(format!(
                "Could not save the inventory: {error}"
            )));
        }
        self.sync_model_after_use();
    }

    /// Scans the cloud locations among `roots` into the inventory, as the part of a run that
    /// `progress` and `cancel` belong to (see [`sources::scan_clouds`]). Nothing happens, and no
    /// account is read, without one.
    fn scan_cloud_roots(
        &self,
        engine: &Engine,
        roots: &[PathBuf],
        progress: &Progress,
        cancel: &AtomicBool,
    ) -> Vec<CloudScan> {
        if roots.is_empty() {
            return Vec::new();
        }
        sources::scan_clouds(
            self.data_dir(),
            &|account| self.backend.connector(account),
            &self.inventory,
            engine,
            roots,
            progress,
            cancel,
        )
    }

    /// Tells what the scans of cloud locations came to. An account whose scan worked is as good
    /// as it was; one whose scan failed is remembered with what is wrong with it, and the user is
    /// told once (see [`Controller::cloud_failed`]). A monitored location stands as its scan
    /// found it, and has a change to show when the scan read or forgot something. A scan that was
    /// stopped says nothing.
    fn settle_clouds(&self, scans: Vec<CloudScan>) -> Vec<Settled> {
        let settled: Vec<Settled> = scans
            .into_iter()
            .filter_map(|scan| {
                let CloudScan {
                    root,
                    account,
                    result,
                } = scan;
                let result = match result {
                    Ok(scanned) => {
                        if let Some(account) = &account {
                            self.cloud_worked(account);
                        }
                        Ok(scanned)
                    }
                    Err(sources::Error::Cancelled) => return None,
                    Err(error) => Err(self.cloud_failed(account.as_ref(), &error)),
                };
                Some(Settled {
                    root,
                    orphan: account.is_none(),
                    result,
                })
            })
            .collect();
        if !settled.is_empty() {
            let now = unix_now();
            self.update(|state| {
                for one in &settled {
                    let (status, changed) = match &one.result {
                        Ok(scanned) => (
                            FolderStatus::Watching,
                            (scanned.read > 0 || scanned.forgotten > 0).then_some(now),
                        ),
                        Err(text) => (FolderStatus::Unavailable(text.clone()), None),
                    };
                    state.watch.cloud_scanned(&one.root, status, changed);
                }
            });
        }
        settled
    }

    /// What the dialog of a scan shows once it is over: what the inventory holds of what was asked
    /// for or, when none of it could be scanned, why not. `local` is how the folders on this PC
    /// went, `None` when none was asked for. The reason is the first one, in the order they were
    /// tried: the inventory's, then each cloud location's.
    fn scan_result(
        &self,
        request: &Request,
        local: Option<&Result<(), piikey::Error>>,
        clouds: &[Settled],
        progress: &Progress,
    ) -> RevealState {
        let saved = local
            .and_then(|result| result.as_ref().err())
            .map(|error| format!("Could not save the inventory: {error}"));
        let worked =
            local.is_some_and(Result::is_ok) || clouds.iter().any(|one| one.result.is_ok());
        let why = saved.or_else(|| {
            clouds
                .iter()
                .find_map(|one| one.result.as_ref().err().cloned())
        });
        match why {
            Some(why) if !worked => RevealState::Failed(why),
            _ => RevealState::Done(ScanSummary {
                cloud_only: progress.cloud_only.load(Ordering::Relaxed),
                ..self.inventory.summary(&request.paths)
            }),
        }
    }

    /// Forgets where the scans of the cloud locations among `scanned` left off, for those that no
    /// location of `locations` holds: what lies outside the locations is not kept, so the next
    /// scan of one lists it in full.
    fn forget_unplaced(&self, scanned: &[PathBuf], locations: &[PathBuf]) -> piikey::Result<()> {
        let cursors = Cursors::new(self.data_dir());
        scanned
            .iter()
            .filter(|root| {
                !locations
                    .iter()
                    .any(|location| sys::is_under(root, location))
            })
            .try_for_each(|root| cursors.forget_under(root))
    }

    /// Runs `work` in the scan pool while the progress it makes reaches the window a few times a
    /// second.
    fn with_progress<R: Send>(&self, work: impl FnOnce() -> R + Send) -> R {
        let finished = AtomicBool::new(false);
        thread::scope(|scope| {
            let ticker = scope.spawn(|| {
                while !finished.load(Ordering::Acquire) {
                    thread::park_timeout(PROGRESS_EVERY);
                    self.update(|_| {});
                }
            });
            let _stop = StopTicker {
                finished: &finished,
                ticker: ticker.thread().clone(),
            };
            self.in_scan_pool(work)
        })
    }
}

/// Gives the [`Reveal`] numbered `seq` its new state, unless a newer request has replaced it.
fn set_reveal(state: &mut State, seq: u64, new: RevealState) {
    if let Some(reveal) = state.reveal.as_mut().filter(|reveal| reveal.seq == seq) {
        reveal.state = new;
    }
}

/// Ends the progress ticker when it goes out of scope, also when the scan panics: a thread scope
/// waits for its threads, and the ticker would never end.
struct StopTicker<'a> {
    finished: &'a AtomicBool,
    ticker: thread::Thread,
}

impl Drop for StopTicker<'_> {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
        self.ticker.unpark();
    }
}

/// Half the cores, so the PC stays responsive while it scans.
pub(super) fn scan_pool() -> Option<rayon::ThreadPool> {
    let cores = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads((cores / 2).max(1))
        .thread_name(|index| format!("piikey-scan-{index}"))
        .build()
        .ok()
}

/// The scan thread: runs what the [`Scanner`] hands it, one scan at a time, until the scanner is
/// stopped or the controller goes away.
fn scan_loop(controller: &Weak<Controller>, scanner: &Scanner) {
    while let Some(job) = scanner.next() {
        let Some(controller) = controller.upgrade() else {
            return;
        };
        controller.run_scan(&job);
        let goes_on = scanner.done(&job);
        if job.cancelled() && !goes_on {
            controller.scan_stopped(&job);
        }
        // Whoever waits for the scans to be over looks again.
        controller.update(|_| {});
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{FindingFiles, label_under, name_of, pick_files, shown, under};

    #[test]
    fn the_empty_path_means_all_of_an_inventory() {
        assert_eq!(under(Path::new("")), None);
        let some = Path::new(r"C:\a");
        assert_eq!(under(some), Some(some));
    }

    fn held(hits: u64, path: &str, label: &str) -> (u64, PathBuf, String) {
        (hits, PathBuf::from(path), label.to_owned())
    }

    fn labels(files: &FindingFiles) -> Vec<&str> {
        files.files.iter().map(|file| file.label.as_str()).collect()
    }

    #[test]
    fn a_view_reads_the_named_files_first_then_the_folders_files_with_the_most_values() {
        let named = vec![(PathBuf::from(r"C:\Other\a.txt"), "a.txt".to_owned())];
        let picked = pick_files(
            named,
            vec![
                held(1, r"C:\Docs\small.txt", "small.txt"),
                held(9, r"C:\Docs\sub\big.txt", r"sub\big.txt"),
                held(5, r"C:\Docs\mid.txt", "mid.txt"),
                held(5, r"C:\Docs\also-mid.txt", "also-mid.txt"),
            ],
            10,
        );
        assert_eq!(
            labels(&picked),
            [
                "a.txt",
                r"sub\big.txt",
                "also-mid.txt",
                "mid.txt",
                "small.txt"
            ]
        );
        assert_eq!(picked.left_out, 0);
    }

    #[test]
    fn a_view_stops_at_the_most_files_and_counts_the_ones_it_leaves_out() {
        let many: Vec<_> = (0..7)
            .map(|i| held(100 - i, &format!(r"C:\Docs\f{i}.txt"), &format!("f{i}.txt")))
            .collect();
        let picked = pick_files(Vec::new(), many, 3);
        assert_eq!(labels(&picked), ["f0.txt", "f1.txt", "f2.txt"]);
        assert_eq!(picked.left_out, 4);
        assert_eq!(
            pick_files(Vec::new(), Vec::new(), 3),
            FindingFiles::default()
        );
    }

    #[test]
    fn a_file_that_two_roots_hold_is_listed_once_whatever_its_letter_case() {
        let picked = pick_files(
            vec![(PathBuf::from(r"C:\DOCS\A.txt"), "A.txt".to_owned())],
            vec![
                held(3, r"c:\docs\a.TXT", "a.TXT"),
                held(2, r"C:\Docs\b.txt", "b.txt"),
            ],
            10,
        );
        assert_eq!(labels(&picked), ["A.txt", "b.txt"]);
        assert_eq!(picked.left_out, 0);
    }

    #[test]
    fn a_cloud_file_is_labelled_by_the_account_and_its_folders_never_by_its_address() {
        let root = Path::new(r"\\Box\Example cloud\Shared");
        let file = Path::new(r"\\Box\Example cloud\Shared\Clients\contacts.csv");
        assert_eq!(
            label_under(root, file),
            "Clients \u{203a} contacts.csv".to_owned()
        );
        assert_eq!(name_of(file), "contacts.csv");
        assert_eq!(name_of(Path::new(r"\\Box\Example cloud")), "Example cloud");
        assert_eq!(
            shown(file),
            "Example cloud \u{203a} Shared \u{203a} Clients \u{203a} contacts.csv"
        );
        assert_eq!(shown(Path::new(r"C:\Docs\a.txt")), r"C:\Docs\a.txt");
        let same = |name: &str| held(1, &format!(r"\\Box\Example cloud\{name}\a.txt"), "a.txt");
        let picked = pick_files(Vec::new(), vec![same("One"), same("Two")], 10);
        assert_eq!(
            labels(&picked),
            [
                "Example cloud \u{203a} One \u{203a} a.txt",
                "Example cloud \u{203a} Two \u{203a} a.txt"
            ]
        );
    }

    #[test]
    fn two_files_that_would_have_the_same_label_are_told_apart_by_their_paths() {
        let picked = pick_files(
            Vec::new(),
            vec![
                held(4, r"C:\One\notes.txt", "notes.txt"),
                held(3, r"C:\Two\notes.txt", "notes.txt"),
                held(2, r"C:\Two\other.txt", "other.txt"),
            ],
            10,
        );
        assert_eq!(
            labels(&picked),
            [r"C:\One\notes.txt", r"C:\Two\notes.txt", "other.txt"]
        );
    }

    #[test]
    fn a_label_is_the_path_below_the_folder_or_the_name() {
        let root = Path::new(r"C:\Docs");
        assert_eq!(
            label_under(root, Path::new(r"C:\Docs\sub\a.txt")),
            r"sub\a.txt"
        );
        assert_eq!(label_under(root, Path::new(r"C:\Docs\a.txt")), "a.txt");
        assert_eq!(label_under(root, Path::new(r"D:\Elsewhere\a.txt")), "a.txt");
        assert_eq!(label_under(root, root), "Docs");
        assert_eq!(name_of(Path::new(r"C:\")), r"C:\");
    }
}
