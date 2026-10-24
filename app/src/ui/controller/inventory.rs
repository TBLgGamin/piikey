//! The inventory as the controller serves it: the scans that fill it and the thread that runs
//! them, what the dialog of a scan shows, the views of it, the findings of the files a result
//! names, and the files written from it.
//!
//! The inventory is scanned when somebody asks: the Scan button, a folder or file the user
//! points at, Explorer's menu, the API. Nothing is scanned on a timer. What changes in the
//! monitored locations is scanned into it too, see [`watch`](super::watch).

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
    inventory::{self, Busy, Entry, Finding, Inventory, Node, Progress, Report, Tiles, TypeTotal},
    sys,
};

use super::{Controller, Edit, Notice, PROGRESS_EVERY, ScanSummary, State};
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
    /// The folder to show in the Inventory: what was scanned, or the folder of the file that was.
    pub at: PathBuf,
    /// The file that was scanned, when the first path is one.
    pub select: Option<PathBuf>,
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

/// The name of the file or folder at `path`; the whole path for one that has none (a drive).
fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// `path` as seen from the folder `root` it was found in; its name when it is not below it.
fn label_under(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|rest| !rest.as_os_str().is_empty())
        .map_or_else(|| name_of(path), |rest| rest.display().to_string())
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
            file.label = file.path.display().to_string();
        }
    }
    FindingFiles {
        left_out: all - files.len(),
        files,
    }
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
    /// may be a folder or a file), so it is for the background.
    pub fn finding_files(&self, roots: &[PathBuf]) -> FindingFiles {
        let outside = self
            .asked_outside
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut named: Vec<(PathBuf, String)> = Vec::new();
        let mut held: Vec<(u64, PathBuf, String)> = Vec::new();
        for root in roots {
            if root.is_dir() {
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
    /// message for the user instead of its findings.
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
        let go = AtomicBool::new(true);
        let found = AtomicUsize::new(0);
        let tell = |event: FindingsEvent| -> bool {
            if !go.load(Ordering::Relaxed) {
                return false;
            }
            let more = (report.lock().unwrap_or_else(PoisonError::into_inner))(event);
            if !more {
                go.store(false, Ordering::Relaxed);
            }
            more
        };
        tell(FindingsEvent::Loading);
        let _reading = FindingsRead::start(self);
        let engine = self.engine();
        let next = AtomicUsize::new(0);
        self.in_scan_pool(|| {
            rayon::scope(|scope| {
                for _ in 0..FINDINGS_PARALLEL.min(files.len()) {
                    scope.spawn(|_| {
                        while go.load(Ordering::Relaxed) {
                            let Some(path) = files.get(next.fetch_add(1, Ordering::Relaxed)) else {
                                break;
                            };
                            let result =
                                inventory::findings(&engine, path, &|report| match report {
                                    Report::Busy(busy) => {
                                        tell(FindingsEvent::Busy(path.clone(), busy))
                                    }
                                    Report::Found(list) => {
                                        let total = found.fetch_add(list.len(), Ordering::Relaxed)
                                            + list.len();
                                        let more = tell(FindingsEvent::Found(path.clone(), list));
                                        if total >= limit {
                                            go.store(false, Ordering::Relaxed);
                                        }
                                        more && go.load(Ordering::Relaxed)
                                    }
                                });
                            tell(FindingsEvent::Done(path.clone(), result.describe()));
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
    /// be written.
    pub fn masked_copy(&self, file: &Path) -> Res<PathBuf> {
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
        let (at, select) = paths
            .first()
            .map_or_else(|| (PathBuf::new(), None), |first| reveal_target(first));
        self.update(|state| {
            let seq = state.reveal.as_ref().map_or(0, |reveal| reveal.seq) + 1;
            state.reveal = Some(Reveal {
                seq,
                paths: paths.to_vec(),
                at,
                select,
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
    /// location that is still listed holds it.
    fn run_forget(&self, folder: &Path) {
        let still = self
            .policy()
            .inventory_roots
            .iter()
            .any(|root| sys::is_under(folder, root));
        if !still && let Err(error) = self.inventory.forget_under(folder) {
            self.notify(Notice::error(format!(
                "Could not forget what was found in {}: {error}",
                folder.display()
            )));
        }
        let totals = self.inventory.totals();
        self.update(|state| state.inventory_totals = totals);
    }

    /// Scans what `request` names into the inventory. What it found outside the locations is
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
        let result = self.with_progress(|| {
            self.inventory
                .scan_paths(&engine, &request.paths, &progress, &job.cancel)
        });
        // The result comes from the inventory before it forgets what lies outside the locations.
        // A scan that was stopped either goes on later (its dialog keeps waiting) or is told so
        // by `scan_stopped`.
        let outcome = request.reveal.filter(|_| !job.cancelled()).map(|seq| {
            let state = match &result {
                Err(error) => RevealState::Failed(format!("Could not save the inventory: {error}")),
                Ok(()) => RevealState::Done(self.inventory.summary(&request.paths)),
            };
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
        let totals = self.inventory.totals();
        self.update(|state| {
            state.scan = None;
            state.inventory_totals = totals;
            if let Some((seq, outcome)) = outcome {
                set_reveal(state, seq, outcome);
            }
        });
        if let Err(error) = result.and(forgot.map(drop)) {
            self.notify(Notice::error(format!(
                "Could not save the inventory: {error}"
            )));
        }
        self.sync_model_after_use();
    }

    /// Scans what monitoring saw change into the inventory: everything, or the paths that were
    /// reported. Only the monitored locations are looked at.
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
        let roots = policy.monitored_roots;
        let result = self.with_progress(|| {
            if changes.everything {
                self.inventory
                    .scan_paths(&engine, &roots, &progress, &job.cancel)
            } else {
                self.inventory
                    .refresh(&engine, &roots, &changes.list(), &progress, &job.cancel)
            }
        });
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

/// Where the window shows the result of scanning `first`: the folder, or for a file its folder
/// with the file selected.
fn reveal_target(first: &Path) -> (PathBuf, Option<PathBuf>) {
    match (first.is_file(), first.parent()) {
        (true, Some(folder)) => (folder.to_path_buf(), Some(first.to_path_buf())),
        _ => (first.to_path_buf(), None),
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
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::{FindingFiles, label_under, name_of, pick_files, reveal_target, under};
    use crate::{Describe, ui::testing::TempDir};

    #[test]
    fn a_scanned_file_is_shown_in_its_folder() -> Result<(), String> {
        let dir = TempDir::new()?;
        let file = dir.0.join("a.txt");
        fs::write(&file, "x").describe()?;
        assert_eq!(reveal_target(&file), (dir.0.clone(), Some(file.clone())));
        assert_eq!(reveal_target(&dir.0), (dir.0.clone(), None));
        let gone = dir.0.join("gone");
        assert_eq!(reveal_target(&gone), (gone.clone(), None));
        Ok(())
    }

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
