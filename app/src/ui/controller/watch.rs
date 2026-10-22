//! The watch: an eye on the folders the user picked, and what the controller does with what it
//! sees.
//!
//! The system reports a change per file and per write ([`Backend::start_watch`]): saving one
//! document is a dozen reports, copying a folder in is thousands. They go to a thread of their
//! own, through a [`Debouncer`], which lets a path settle before it is looked at and merges
//! what it sees into one batch; the batch goes to the scan thread, which scans only what it
//! names, into the watch's own inventory (see [`Inventory::refresh`]). When the system may have
//! lost reports (a burst, or it says so), the batch is everything, scanned the way the
//! inventory's scans are: only what changed is read.
//!
//! Switching the watch on, adding a folder and starting the app catch up the same way, with
//! everything, because a folder is not watched while the app is not running.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::Ordering,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use piikey::{
    inventory::{Progress, Totals, Touched},
    policy::Policy,
    sys,
};

use super::{Controller, Notice, Running, Store};
use crate::ui::scanner::Changes;

/// How long a path must be quiet before it is scanned: a file that is being written is scanned
/// when the writing is over, not at every write.
const QUIET: Duration = Duration::from_secs(2);
/// A path that never goes quiet (a log that is written to all day) is scanned this often at
/// most.
const CAP: Duration = Duration::from_secs(30);
/// This many paths settling at once and the system may have lost reports (it keeps a short list
/// of them for each folder): everything is looked at. Looking at everything only reads what
/// changed, and walking a folder costs far less than reading its files.
const BURST: usize = 64;

/// One report of the system: something changed in a watched folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A file or folder at this path was written, created, renamed or removed. `fresh`: it was
    /// created, or renamed to this name.
    Path { path: PathBuf, fresh: bool },
    /// Reports were lost: anything may have changed.
    Everything,
}

/// What [`Backend::start_watch`] gives.
pub struct Started {
    /// Ends the watch, and drops the sender of the changes.
    pub running: Box<dyn Running>,
    /// The folders that could not be watched, and why; the others are.
    pub failed: Vec<(PathBuf, String)>,
}

/// How a watched folder stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderStatus {
    /// The watch is switched off.
    Off,
    /// Changes in it are seen as they happen.
    Watching,
    /// It cannot be watched: the message says why (the folder is gone, or not allowed).
    Unavailable(String),
}

/// One of the folders the watch is asked to keep an eye on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedFolder {
    pub path: PathBuf,
    pub status: FolderStatus,
    /// When a change under it was last seen, in seconds since the Unix epoch; `None` until one
    /// is, in this session.
    pub last_change: Option<u64>,
}

/// How the watch stands, for the window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watch {
    /// The folders it is asked to watch, in the order of the settings.
    pub folders: Vec<WatchedFolder>,
    /// Files scanned and files to scan, while the watch scans: catching up, or handling changes.
    pub scanning: Option<(u64, u64)>,
    /// Files in the watch's inventory that hold personal data, and the values found in them.
    pub totals: (u64, u64),
}

/// What the controller keeps of the watch.
#[derive(Default)]
pub(super) struct WatchState {
    /// The system's watcher while the watch runs.
    pub running: Option<Box<dyn Running>>,
    /// How each folder it started for stands; a folder that is not here is not watched.
    pub statuses: Vec<(PathBuf, FolderStatus)>,
    /// How far the scan that runs now has got.
    pub scan: Option<Arc<Progress>>,
    /// When a change was last seen under each folder (as the settings spell it).
    pub last_change: HashMap<PathBuf, u64>,
    pub totals: Totals,
}

impl WatchState {
    /// The `Watch` the window reads, for `policy`.
    pub fn view(&self, policy: &Policy) -> Watch {
        let find = |path: &Path| {
            self.statuses
                .iter()
                .find(|(known, _)| sys::same_path(known, path))
                .map(|(_, status)| status.clone())
        };
        let last = |path: &Path| {
            self.last_change
                .iter()
                .find(|(known, _)| sys::same_path(known, path))
                .map(|(_, &at)| at)
        };
        Watch {
            folders: policy
                .watch_folders
                .iter()
                .map(|path| WatchedFolder {
                    path: path.clone(),
                    status: if policy.watch {
                        find(path).unwrap_or(FolderStatus::Watching)
                    } else {
                        FolderStatus::Off
                    },
                    last_change: last(path),
                })
                .collect(),
            scanning: self.scan.as_ref().map(|progress| {
                (
                    progress.done.load(Ordering::Relaxed),
                    progress.total.load(Ordering::Relaxed),
                )
            }),
            totals: (self.totals.files_with_pii, self.totals.hits),
        }
    }
}

/// Collects reports until their paths settle. Pure: it is given the time.
#[derive(Debug)]
pub struct Debouncer {
    quiet: Duration,
    cap: Duration,
    burst: usize,
    seen: HashMap<PathBuf, Seen>,
    /// Reports were lost, or the watch wants a catch-up.
    everything: Option<Seen>,
    /// No path settles before this: it only moves later as a path is reported again, so it is
    /// early at worst, and checking it costs nothing per report.
    deadline: Option<Instant>,
}

/// What was seen of one path, or of everything.
#[derive(Debug, Clone, Copy)]
struct Seen {
    first: Instant,
    last: Instant,
    fresh: bool,
}

impl Seen {
    fn new(now: Instant, fresh: bool) -> Self {
        Self {
            first: now,
            last: now,
            fresh,
        }
    }

    /// When it settles if it is not reported again.
    fn due(&self, quiet: Duration, cap: Duration) -> Instant {
        (self.last + quiet).min(self.first + cap)
    }

    fn settled(&self, now: Instant, quiet: Duration, cap: Duration) -> bool {
        self.due(quiet, cap) <= now
    }
}

impl Debouncer {
    pub fn new(quiet: Duration, cap: Duration, burst: usize) -> Self {
        Self {
            quiet,
            cap,
            burst,
            seen: HashMap::new(),
            everything: None,
            deadline: None,
        }
    }

    /// Takes note of `change`, reported at `now`.
    pub fn push(&mut self, change: Change, now: Instant) {
        let (quiet, cap) = (self.quiet, self.cap);
        let due = match change {
            Change::Everything => {
                let seen = self.everything.get_or_insert_with(|| Seen::new(now, false));
                seen.last = now;
                seen.due(quiet, cap)
            }
            Change::Path { path, fresh } => {
                let seen = self
                    .seen
                    .entry(path)
                    .or_insert_with(|| Seen::new(now, fresh));
                seen.last = now;
                seen.fresh |= fresh;
                seen.due(quiet, cap)
            }
        };
        self.deadline = Some(self.deadline.map_or(due, |deadline| deadline.min(due)));
    }

    /// How long until something may have settled, from `now`; `None` while nothing is waiting.
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    /// What has settled by `now`, and no longer waits: a path that was quiet for the quiet time,
    /// or that was reported for the cap. When reports may have been lost (they said so, or a
    /// burst of paths settled together) it is everything, which covers the paths too.
    pub fn take(&mut self, now: Instant) -> Changes {
        if self.deadline.is_none_or(|deadline| now < deadline) {
            return Changes::default();
        }
        let (quiet, cap) = (self.quiet, self.cap);
        let lost = self
            .everything
            .is_some_and(|seen| seen.settled(now, quiet, cap));
        let settled: Vec<PathBuf> = self
            .seen
            .iter()
            .filter(|(_, seen)| seen.settled(now, quiet, cap))
            .map(|(path, _)| path.clone())
            .collect();
        let burst = settled.len() >= self.burst;
        let mut touched = Vec::with_capacity(settled.len());
        for path in settled {
            if let Some(seen) = self.seen.remove(&path) {
                touched.push(Touched {
                    path,
                    fresh: seen.fresh,
                });
            }
        }
        let changes = if lost || burst {
            self.everything = None;
            Changes::everything()
        } else {
            Changes::touched(touched)
        };
        self.deadline = self
            .seen
            .values()
            .chain(self.everything.iter())
            .map(|seen| seen.due(quiet, cap))
            .min();
        changes
    }
}

impl Controller {
    /// Brings the watch in line with the settings: what is no longer watched is forgotten, the
    /// system's watcher starts again over the folders there are now (or ends, with the watch off
    /// or no folder to watch), and everything is caught up on, because what happened while
    /// nothing watched is unknown.
    pub(super) fn sync_watch(self: &Arc<Self>, old: &Policy, new: &Policy) {
        // What runs for folders that went is broken off, and what they held is forgotten once
        // that scan saved; with the watch off nothing it saw is scanned any more.
        self.withdraw_removed(Store::Watch, &old.watch_folders, &new.watch_folders);
        if !new.watch {
            self.stop_watch_scan();
        }
        self.stop_watching();
        if !new.watch || new.watch_folders.is_empty() {
            let totals = self.watch_store.totals();
            self.update(|state| {
                state.watch.statuses.clear();
                state.watch.totals = totals;
            });
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let started = match self.backend.start_watch(&new.watch_folders, sender) {
            Ok(started) => started,
            Err(error) => {
                self.notify(Notice::error(format!(
                    "Could not watch your folders: {error}"
                )));
                let statuses = new
                    .watch_folders
                    .iter()
                    .map(|folder| (folder.clone(), FolderStatus::Unavailable(error.clone())))
                    .collect();
                self.update(|state| state.watch.statuses = statuses);
                return;
            }
        };
        let statuses: Vec<(PathBuf, FolderStatus)> = new
            .watch_folders
            .iter()
            .map(|folder| {
                let failed = started
                    .failed
                    .iter()
                    .find(|(path, _)| sys::same_path(path, folder));
                let status = failed.map_or(FolderStatus::Watching, |(_, why)| {
                    FolderStatus::Unavailable(why.clone())
                });
                (folder.clone(), status)
            })
            .collect();
        let any = statuses
            .iter()
            .any(|(_, status)| *status == FolderStatus::Watching);
        let controller = Arc::downgrade(self);
        let spawned = thread::Builder::new()
            .name("piikey-watch".into())
            .spawn(move || watch_loop(&controller, &receiver));
        if let Err(error) = spawned {
            started.running.stop();
            self.notify(Notice::error(format!("Could not start watching: {error}")));
            return;
        }
        self.update(|state| {
            state.watch.running = Some(started.running);
            state.watch.statuses = statuses;
        });
        if any {
            self.scanner.changed(Changes::everything());
            self.ensure_scanner();
        }
    }

    /// Ends the system's watcher, if one runs; its thread ends with it.
    pub(super) fn stop_watching(&self) {
        if let Some(running) = self.update(|state| state.watch.running.take()) {
            running.stop();
        }
    }

    /// The watch saw `changes` settle: they go to the scan thread, and the folders they are
    /// under have a change to show.
    fn watch_saw(self: &Arc<Self>, changes: Changes) {
        let roots = self.policy().watch_folders;
        let now = unix_now();
        self.update(|state| {
            for path in changes.paths() {
                let root = roots
                    .iter()
                    .filter(|root| sys::is_under(path, root))
                    .max_by_key(|root| root.components().count());
                if let Some(root) = root {
                    state.watch.last_change.insert(root.clone(), now);
                }
            }
            if changes.everything {
                // Reports were lost or a burst came: a change somewhere, and nothing says where.
                for root in &roots {
                    state.watch.last_change.insert(root.clone(), now);
                }
            }
        });
        self.scanner.changed(changes);
        self.ensure_scanner();
    }
}

/// Seconds since the Unix epoch.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The thread of the watch: lets what the system reports settle and hands it over, until the
/// system's watcher ends (its sender is dropped) or the controller goes away.
fn watch_loop(controller: &Weak<Controller>, reports: &Receiver<Change>) {
    let mut debounce = Debouncer::new(QUIET, CAP, BURST);
    loop {
        let received = match debounce.wait(Instant::now()) {
            Some(wait) => reports.recv_timeout(wait),
            None => reports.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(change) => {
                debounce.push(change, Instant::now());
                // A burst is taken in at once.
                while let Ok(more) = reports.try_recv() {
                    debounce.push(more, Instant::now());
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let settled = debounce.take(Instant::now());
        if settled.is_empty() {
            continue;
        }
        let Some(controller) = controller.upgrade() else {
            return;
        };
        controller.watch_saw(settled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    fn path(name: &str, fresh: bool) -> Change {
        Change::Path {
            path: PathBuf::from(name),
            fresh,
        }
    }

    fn touched(name: &str, fresh: bool) -> Touched {
        Touched {
            path: PathBuf::from(name),
            fresh,
        }
    }

    fn debouncer() -> Debouncer {
        Debouncer::new(Duration::from_secs(2), Duration::from_secs(30), 3)
    }

    #[test]
    fn a_path_settles_when_it_has_been_quiet_and_not_before() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        assert_eq!(debounce.wait(start), None, "nothing waits");
        assert!(debounce.take(start).is_empty());

        debounce.push(path("a", false), start);
        assert_eq!(debounce.wait(start), Some(Duration::from_secs(2)));
        assert!(
            debounce.take(at(start, 1)).is_empty(),
            "still being written"
        );
        assert_eq!(
            debounce.take(at(start, 2)),
            Changes::touched([touched("a", false)])
        );
        // Taken once: it is gone, and nothing waits any more.
        assert!(debounce.take(at(start, 40)).is_empty());
        assert_eq!(debounce.wait(at(start, 40)), None);
    }

    #[test]
    fn a_path_that_is_reported_again_waits_for_the_writing_to_stop() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        debounce.push(path("a", false), start);
        debounce.push(path("a", false), at(start, 1));
        debounce.push(path("a", false), at(start, 2));
        // The first deadline passes with nothing to take, and the next one is later.
        assert!(debounce.take(at(start, 2)).is_empty());
        assert_eq!(debounce.wait(at(start, 2)), Some(Duration::from_secs(2)));
        assert!(!debounce.take(at(start, 4)).is_empty());
    }

    #[test]
    fn a_path_that_never_goes_quiet_is_taken_at_the_cap() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        for second in 0..=30 {
            debounce.push(path("log", false), at(start, second));
        }
        assert!(debounce.take(at(start, 29)).is_empty());
        assert_eq!(
            debounce.take(at(start, 30)),
            Changes::touched([touched("log", false)])
        );
        // And it starts again: reported once more, it is a new wait.
        debounce.push(path("log", false), at(start, 31));
        assert_eq!(debounce.wait(at(start, 31)), Some(Duration::from_secs(2)));
    }

    #[test]
    fn what_is_fresh_stays_fresh_and_each_path_is_taken_once() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        debounce.push(path("a", true), start);
        debounce.push(path("a", false), at(start, 1));
        debounce.push(path("b", false), at(start, 1));
        assert_eq!(
            debounce.take(at(start, 3)),
            Changes::touched([touched("a", true), touched("b", false)])
        );
    }

    #[test]
    fn only_what_has_settled_is_taken_and_the_rest_waits() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        debounce.push(path("early", false), start);
        debounce.push(path("late", false), at(start, 5));
        assert_eq!(
            debounce.take(at(start, 3)),
            Changes::touched([touched("early", false)])
        );
        assert_eq!(debounce.wait(at(start, 3)), Some(Duration::from_secs(4)));
        assert_eq!(
            debounce.take(at(start, 7)),
            Changes::touched([touched("late", false)])
        );
    }

    #[test]
    fn lost_reports_and_a_burst_mean_everything() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        debounce.push(path("a", false), start);
        debounce.push(Change::Everything, at(start, 1));
        // What settled is taken as it is; everything follows when it has settled itself.
        assert_eq!(
            debounce.take(at(start, 2)),
            Changes::touched([touched("a", false)])
        );
        assert_eq!(debounce.take(at(start, 3)), Changes::everything());
        assert_eq!(debounce.wait(at(start, 3)), None);

        // Three paths (the burst of this debouncer) settling together.
        for name in ["a", "b", "c"] {
            debounce.push(path(name, false), at(start, 10));
        }
        assert_eq!(debounce.take(at(start, 12)), Changes::everything());
        // Two are not a burst.
        for name in ["a", "b"] {
            debounce.push(path(name, false), at(start, 20));
        }
        assert_eq!(
            debounce.take(at(start, 22)),
            Changes::touched([touched("a", false), touched("b", false)])
        );
    }

    #[test]
    fn a_burst_leaves_what_is_still_being_written_to_settle_by_itself() {
        let (mut debounce, start) = (debouncer(), Instant::now());
        for name in ["a", "b", "c"] {
            debounce.push(path(name, false), start);
        }
        debounce.push(path("busy", false), at(start, 2));
        assert_eq!(debounce.take(at(start, 2)), Changes::everything());
        assert_eq!(debounce.wait(at(start, 2)), Some(Duration::from_secs(2)));
        assert_eq!(
            debounce.take(at(start, 4)),
            Changes::touched([touched("busy", false)])
        );
    }
}
