//! The inventory as the controller serves it: the treemap's levels, the scans that fill it and
//! the thread that runs them, and the files written from it.

use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use piikey::{
    inventory::{Entry, Inventory, Node, Progress},
    policy::Policy,
};

use super::{Controller, Notice, PROGRESS_EVERY};
use crate::{
    Res,
    ui::{
        exports,
        scanner::{Job, Kind, Request, Scanner},
    },
};

/// How long a quitting app waits for the scan it cancelled to save what it did.
const SCAN_STOP_WAIT: Duration = Duration::from_secs(2);

/// A request to show the result of a scan: the window comes forward, on Inventory, at `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    /// Grows with every request, so the window can tell a new one from one it handled.
    pub seq: u64,
    /// The folder to show: what was scanned, or the folder of the file that was.
    pub at: PathBuf,
    /// The file that was scanned, when it was one.
    pub select: Option<PathBuf>,
}

/// One level of the inventory's treemap, see [`Controller::inventory_view`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryView {
    pub nodes: Vec<Node>,
    /// What the inventory knows of the selected file.
    pub entry: Option<Entry>,
    /// The folders the inventory watches, as the tiles were grouped by them: the breadcrumb
    /// names a folder below one of them by it, not by its whole path.
    pub roots: Vec<PathBuf>,
}

impl Controller {
    /// The inventory: which files hold personal data.
    pub fn inventory(&self) -> Arc<Inventory> {
        Arc::clone(&self.inventory)
    }

    /// The latest request to show the result of a scan.
    pub fn reveal(&self) -> Option<Reveal> {
        self.lock().reveal.clone()
    }

    /// The treemap's tiles at one level: what lies directly under `at`, or, for an empty `at`,
    /// one tile per watched folder that has findings, and one for the scans outside them (the
    /// node with an empty path). `selected` is a file whose entry is wanted.
    pub fn inventory_view(&self, at: &Path, selected: Option<&Path>) -> InventoryView {
        let roots = self.policy().inventory_roots_or_default();
        let under = (!at.as_os_str().is_empty()).then_some(at);
        let nodes = self.inventory.children(under, &roots);
        let entry = selected.and_then(|file| {
            self.inventory
                .entries(Some(file), 0)
                .into_iter()
                .find(|entry| entry.path == file)
        });
        InventoryView {
            nodes,
            entry,
            roots,
        }
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

    /// Blocks until every scan that was asked for is done and none runs; `false` on timeout.
    pub fn wait_scans(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let (state, result) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                state.scan.is_some() || !self.scanner.idle()
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
            .wait_timeout_while(state, SCAN_STOP_WAIT, |state| state.scan.is_some())
            .unwrap_or_else(PoisonError::into_inner);
    }

    /// Follows the inventory switch and the folders it watches or leaves out: what is newly
    /// left out is forgotten, and the watched folders are scanned (again) or no longer.
    pub(super) fn sync_inventory(self: &Arc<Self>, old: &Policy, new: &Policy) {
        self.forget_left_out(&old.inventory_exclude, &new.inventory_exclude);
        let totals = self.inventory.totals();
        self.update(|state| state.inventory_totals = totals);
        self.scanner.watch(new.inventory);
        if new.inventory {
            self.ensure_scanner();
        }
    }

    /// Forgets what the inventory knows of the paths that `now` leaves out and `before` did not.
    fn forget_left_out(&self, before: &[PathBuf], now: &[PathBuf]) {
        for path in now.iter().filter(|path| !before.contains(path)) {
            if let Err(error) = self.inventory.forget_under(path) {
                self.notify(Notice::error(format!(
                    "Could not update the inventory: {error}"
                )));
            }
        }
    }

    /// Starts the scan thread the first time something needs it.
    fn ensure_scanner(self: &Arc<Self>) {
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

    /// Queues a scan of `paths`: it runs before the scan of the watched folders.
    pub(super) fn ask_scan(self: &Arc<Self>, paths: Vec<PathBuf>, reveal: bool) {
        self.scanner.ask(Request { paths, reveal });
        self.ensure_scanner();
    }

    /// Scans the watched folders now, whether or not the inventory is on.
    pub(super) fn rescan(self: &Arc<Self>) {
        let roots = self.policy().inventory_roots_or_default();
        self.ask_scan(roots, false);
    }

    /// Runs one scan, on the scan thread. It leaves the window with the result when it was
    /// asked to, and the inventory saved.
    pub(super) fn run_scan(&self, job: &Job) {
        let policy = self.policy();
        let (paths, reveal) = match &job.kind {
            Kind::Asked(request) => (request.paths.clone(), request.reveal),
            Kind::Watched => (policy.inventory_roots_or_default(), false),
        };
        // A `piikey-cli` run on its own may be scanning the same inventory. A scan nobody asked
        // for waits for the next turn.
        let _lock = match self.inventory.lock_scan() {
            Ok(lock) => lock,
            Err(error) => {
                if matches!(job.kind, Kind::Asked(_)) {
                    self.notify(Notice::error(format!("Could not scan: {error}")));
                }
                return;
            }
        };
        let progress = Arc::new(Progress::default());
        self.update(|state| state.scan = Some(Arc::clone(&progress)));
        self.sync_model();
        let engine = self.engine();
        let finished = AtomicBool::new(false);
        let result = thread::scope(|scope| {
            // Progress reaches the window a few times a second.
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
            self.in_scan_pool(|| {
                self.inventory.scan_paths(
                    &engine,
                    &paths,
                    &policy.inventory_exclude,
                    &progress,
                    &job.cancel,
                )
            })
        });
        // The scan went by the list of what to leave out that it began with: a path put on it
        // since was scanned all the same.
        self.forget_left_out(&policy.inventory_exclude, &self.policy().inventory_exclude);
        let totals = self.inventory.totals();
        let target = paths
            .first()
            .filter(|_| reveal && !job.cancelled())
            .map(|first| reveal_target(first));
        self.update(|state| {
            state.scan = None;
            state.inventory_totals = totals;
            if let Some((at, select)) = target {
                let seq = state.reveal.as_ref().map_or(0, |reveal| reveal.seq) + 1;
                state.reveal = Some(Reveal { seq, at, select });
            }
        });
        if let Err(error) = result {
            self.notify(Notice::error(format!(
                "Could not save the inventory: {error}"
            )));
        }
        self.sync_model();
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
        scanner.done(&job);
        // Whoever waits for the scans to be over looks again.
        controller.update(|_| {});
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::reveal_target;
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
}
