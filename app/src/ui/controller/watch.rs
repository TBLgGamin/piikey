//! Monitoring: an eye on the locations the user switched Monitor on for, and what the controller
//! does with what it sees.
//!
//! The system reports a change per file and per write ([`Backend::start_watch`]): saving one
//! document is a dozen reports, copying a folder in is thousands. They go to a thread of their
//! own, through a [`Debouncer`], which lets a path settle before it is looked at and merges
//! what it sees into one batch; the batch goes to the scan thread, which scans only what it
//! names, into the inventory (see [`Inventory::refresh`]). When the system may have lost reports
//! (a burst, or it says so), the batch is everything, scanned the way the inventory's scans are:
//! only what changed is read.
//!
//! A location in a cloud account has no files on this PC and reports nothing, so the system is
//! never asked to watch it. A thread of its own, the poll, asks every monitored cloud location
//! what changed every [`Backend::cloud_poll`] (five minutes): a batch for the scan thread like
//! any other, which asks the account's change feed and reads only what that names. The poll
//! ends with monitoring, and starts again when the monitored locations change.
//!
//! Turning Monitor on, adding or removing a monitored location and starting the app catch up the
//! same way, with everything, because a location is not watched while the app is not running.
//! For a cloud location that catch-up is its first poll.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::Ordering,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use piikey::{
    inventory::{Progress, Touched},
    policy::Policy,
    sources, sys,
};

use super::{Controller, Notice, Running};
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

/// One report of the system: something changed in a monitored location.
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

/// How a monitored location stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderStatus {
    /// Changes in it are seen as they happen; in a cloud account, as they are asked for every few
    /// minutes.
    Watching,
    /// It cannot be watched: the message says why (the folder is gone, or not allowed; for a
    /// cloud account, what is wrong with reading it).
    Unavailable(String),
}

/// One of the locations that are monitored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedFolder {
    pub path: PathBuf,
    pub status: FolderStatus,
    /// When a change under it was last seen, in seconds since the Unix epoch; `None` until one
    /// is, in this session.
    pub last_change: Option<u64>,
}

/// How monitoring stands, for the window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watch {
    /// The monitored locations, in the order of the settings.
    pub folders: Vec<WatchedFolder>,
    /// Files scanned and files to scan, while monitoring scans: catching up, or handling changes.
    /// What it finds goes into the inventory.
    pub scanning: Option<(u64, u64)>,
}

/// What the controller keeps of monitoring.
#[derive(Default)]
pub(super) struct WatchState {
    /// The system's watcher while monitoring runs over folders on this PC.
    pub running: Option<Box<dyn Running>>,
    /// Ends the thread that asks the monitored cloud locations what changed: dropping it wakes
    /// the thread, which ends. Held while a cloud location is monitored.
    pub poll: Option<Sender<()>>,
    /// How each location it started for stands; a location that is not here is not watched.
    pub statuses: Vec<(PathBuf, FolderStatus)>,
    /// How far the scan that runs now has got.
    pub scan: Option<Arc<Progress>>,
    /// When a change was last seen under each location (as the settings spell it).
    pub last_change: HashMap<PathBuf, u64>,
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
                .monitored_roots
                .iter()
                .map(|path| WatchedFolder {
                    path: path.clone(),
                    status: find(path).unwrap_or(FolderStatus::Watching),
                    last_change: last(path),
                })
                .collect(),
            scanning: self.scan.as_ref().map(|progress| {
                (
                    progress.done.load(Ordering::Relaxed),
                    progress.total.load(Ordering::Relaxed),
                )
            }),
        }
    }

    /// A scan of the cloud location `root` ended. If the location is monitored it stands as
    /// `status` now, and when `changed` holds a time (the scan read or forgot something) a change
    /// was seen in it then. Nothing is kept of a location that is not monitored.
    pub fn cloud_scanned(&mut self, root: &Path, status: FolderStatus, changed: Option<u64>) {
        let Some((spelled, standing)) = self
            .statuses
            .iter_mut()
            .find(|(known, _)| sys::same_path(known, root))
        else {
            return;
        };
        *standing = status;
        if let Some(at) = changed {
            self.last_change.insert(spelled.clone(), at);
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

/// What starting the system's watcher over the folders on this PC came to.
#[derive(Default)]
struct LocalWatch {
    /// The watcher; `None` when there is no folder to watch, or it could not start.
    running: Option<Box<dyn Running>>,
    /// How each folder stands.
    statuses: Vec<(PathBuf, FolderStatus)>,
}

impl Controller {
    /// Brings monitoring in line with the settings: what was queued or running for the old set of
    /// locations is dropped (the catch-up below looks at every monitored location again, and
    /// reads only what changed), the system's watcher starts again over the folders on this PC
    /// there are now (or ends, with none), the poll of the cloud locations starts again (or ends,
    /// with none), and everything is caught up on, because what happened while nothing watched
    /// is unknown. What a removed location held is forgotten when the location is withdrawn,
    /// which happens before this.
    pub(super) fn sync_watch(self: &Arc<Self>, new: &Policy) {
        self.stop_watch_scan();
        self.stop_watching();
        if new.monitored_roots.is_empty() {
            self.update(|state| state.watch.statuses.clear());
            return;
        }
        // The system reports on the folders on this PC. A cloud location reports nothing and
        // never reaches the system's watcher: Windows would look for a server of that name.
        let (local, cloud) = sources::split_roots(&new.monitored_roots);
        let LocalWatch {
            running,
            statuses: watched,
        } = if local.is_empty() {
            LocalWatch::default()
        } else {
            self.start_local_watch(&local)
        };
        let (poll, polled) = if cloud.is_empty() {
            (None, FolderStatus::Watching)
        } else {
            self.start_poll()
        };
        let statuses: Vec<(PathBuf, FolderStatus)> = new
            .monitored_roots
            .iter()
            .map(|folder| {
                let status = if sources::is_virtual(folder) {
                    polled.clone()
                } else {
                    watched
                        .iter()
                        .find(|(path, _)| sys::same_path(path, folder))
                        .map_or(FolderStatus::Watching, |(_, status)| status.clone())
                };
                (folder.clone(), status)
            })
            .collect();
        let any = statuses
            .iter()
            .any(|(_, status)| *status == FolderStatus::Watching);
        self.update(|state| {
            state.watch.running = running;
            state.watch.poll = poll;
            state.watch.statuses = statuses;
        });
        if any {
            self.scanner.changed(Changes::everything());
            self.ensure_scanner();
        }
    }

    /// Starts the system's watcher over `folders` on this PC, with the thread that settles what
    /// it reports. When it cannot start, every folder is unavailable, and a notice says why.
    fn start_local_watch(self: &Arc<Self>, folders: &[PathBuf]) -> LocalWatch {
        let unavailable = |why: &str| -> Vec<(PathBuf, FolderStatus)> {
            folders
                .iter()
                .map(|folder| (folder.clone(), FolderStatus::Unavailable(why.to_owned())))
                .collect()
        };
        let (sender, receiver) = mpsc::channel();
        let started = match self.backend.start_watch(folders, sender) {
            Ok(started) => started,
            Err(error) => {
                self.notify(Notice::error(format!(
                    "Could not monitor your locations: {error}"
                )));
                return LocalWatch {
                    running: None,
                    statuses: unavailable(&error),
                };
            }
        };
        let controller = Arc::downgrade(self);
        let spawned = thread::Builder::new()
            .name("piikey-watch".into())
            .spawn(move || watch_loop(&controller, &receiver));
        if let Err(error) = spawned {
            started.running.stop();
            let why = format!("Could not start monitoring: {error}");
            self.notify(Notice::error(why.clone()));
            return LocalWatch {
                running: None,
                statuses: unavailable(&why),
            };
        }
        let statuses = folders
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
        LocalWatch {
            running: Some(started.running),
            statuses,
        }
    }

    /// Starts the thread that asks the monitored cloud locations what changed, every
    /// [`Backend::cloud_poll`]. Returns what ends it (drop it) and how the locations stand: all of
    /// them unavailable, with the notice that says why, when it cannot start.
    fn start_poll(self: &Arc<Self>) -> (Option<Sender<()>>, FolderStatus) {
        let (end, ended) = mpsc::channel();
        let controller = Arc::downgrade(self);
        let every = self.backend.cloud_poll();
        let spawned = thread::Builder::new()
            .name("piikey-poll".into())
            .spawn(move || poll_loop(&controller, &ended, every));
        match spawned {
            Ok(_) => (Some(end), FolderStatus::Watching),
            Err(error) => {
                let why = format!("Could not start monitoring: {error}");
                self.notify(Notice::error(why.clone()));
                (None, FolderStatus::Unavailable(why))
            }
        }
    }

    /// Ends the system's watcher and the poll, if they run; their threads end with them.
    pub(super) fn stop_watching(&self) {
        let (running, poll) =
            self.update(|state| (state.watch.running.take(), state.watch.poll.take()));
        // The poll thread ends when its sender is dropped.
        drop(poll);
        if let Some(running) = running {
            running.stop();
        }
    }

    /// Monitoring saw `changes` settle: they go to the scan thread, and the locations they are
    /// under have a change to show.
    fn watch_saw(self: &Arc<Self>, changes: Changes) {
        let roots = self.policy().monitored_roots;
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
                // Reports were lost or a burst came: a change somewhere on this PC, and nothing
                // says where. A cloud location says it for itself, when it is asked.
                for root in roots.iter().filter(|root| !sources::is_virtual(root)) {
                    state.watch.last_change.insert(root.clone(), now);
                }
            }
        });
        self.scanner.changed(changes);
        self.ensure_scanner();
    }

    /// The poll's time is up: the monitored cloud locations are to be asked what changed. The
    /// scan thread does it after what was asked for, and together with whatever else it saw.
    fn poll_clouds(self: &Arc<Self>) {
        let (_, cloud) = sources::split_roots(&self.policy().monitored_roots);
        self.scanner.changed(Changes::polled(cloud));
        self.ensure_scanner();
    }
}

/// Seconds since the Unix epoch.
pub(super) fn unix_now() -> u64 {
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

/// The thread of the poll: every `every` it asks the monitored cloud locations what changed,
/// until its sender is dropped (monitoring ended, or its locations changed) or the controller
/// goes away. Nothing is ever sent: the sender going away is the signal.
fn poll_loop(controller: &Weak<Controller>, ended: &Receiver<()>, every: Duration) {
    while let Err(RecvTimeoutError::Timeout) = ended.recv_timeout(every) {
        let Some(controller) = controller.upgrade() else {
            return;
        };
        controller.poll_clouds();
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

    #[test]
    fn a_scan_of_a_cloud_location_sets_the_status_and_the_change_of_a_monitored_one_only() {
        let location = PathBuf::from(r"\\Dropbox\work\Files");
        let mut state = WatchState::default();
        state
            .statuses
            .push((location.clone(), FolderStatus::Watching));
        let unavailable = FolderStatus::Unavailable("Sign in to Dropbox again.".to_owned());

        // A location that is not monitored keeps nothing.
        state.cloud_scanned(
            Path::new(r"\\Dropbox\work\Other"),
            unavailable.clone(),
            Some(5),
        );
        assert_eq!(state.statuses, [(location.clone(), FolderStatus::Watching)]);
        assert!(state.last_change.is_empty());

        // A monitored one is found in any letter case, stands as the scan found it, and keeps
        // the change as the settings spell the location.
        state.cloud_scanned(
            Path::new(r"\\DROPBOX\WORK\FILES"),
            unavailable.clone(),
            None,
        );
        assert_eq!(state.statuses, [(location.clone(), unavailable)]);
        assert!(state.last_change.is_empty(), "a scan that found nothing");
        state.cloud_scanned(
            Path::new(r"\\dropbox\work\files"),
            FolderStatus::Watching,
            Some(7),
        );
        assert_eq!(state.statuses, [(location.clone(), FolderStatus::Watching)]);
        assert_eq!(state.last_change.get(&location), Some(&7));
    }
}
