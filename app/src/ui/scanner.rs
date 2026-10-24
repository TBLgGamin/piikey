//! The work queue of the scan thread. First what a removed location leaves behind is forgotten,
//! then the scans somebody asked for run in the order they were asked, and then what monitoring
//! has seen change in the monitored locations. Nothing is scanned that nobody asked for, and
//! nothing on a timer.
//!
//! Removing a location ([`Scanner::withdraw`]) breaks off at once: what waits under it is
//! dropped, the scan that runs under it stops within the file it is in and goes on without that
//! folder, and forgetting what the folder held waits until that scan has saved, so nothing it
//! found comes back.
//!
//! The thread itself belongs to the controller, which has the engine, the inventory and the state
//! that shows progress; this is only the queue and its rules, so they are tested without a thread.

use std::{
    collections::{BTreeMap, VecDeque},
    mem,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use piikey::{inventory::Touched, sys};

/// A scan somebody asked for: Explorer's "Scan for personal data", the Scan button, the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub paths: Vec<PathBuf>,
    /// The number of the [`Reveal`](super::controller::Reveal) that shows its result to the
    /// user, when somebody is to see it.
    pub reveal: Option<u64>,
}

/// What monitoring has seen change in the monitored locations, and no scan has looked at yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Everything may have changed (monitoring just started, or events were lost): look at all
    /// of it.
    pub everything: bool,
    /// The paths that were reported, and whether each is fresh: see [`Touched`].
    touched: BTreeMap<PathBuf, bool>,
}

impl Changes {
    /// All of the monitored locations.
    pub fn everything() -> Self {
        Self {
            everything: true,
            touched: BTreeMap::new(),
        }
    }

    /// These paths, as reported.
    pub fn touched(paths: impl IntoIterator<Item = Touched>) -> Self {
        let mut changes = Self::default();
        for Touched { path, fresh } in paths {
            *changes.touched.entry(path).or_insert(false) |= fresh;
        }
        changes
    }

    pub fn is_empty(&self) -> bool {
        !self.everything && self.touched.is_empty()
    }

    /// The paths that were reported.
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.touched.keys()
    }

    /// Drops what was reported under `folder`.
    fn drop_under(&mut self, folder: &Path) {
        self.touched.retain(|path, _| !sys::is_under(path, folder));
    }

    /// Adds `other`. A path reported twice is fresh when either said so; with everything to be
    /// looked at, single paths say nothing more.
    pub fn merge(&mut self, other: Self) {
        self.everything |= other.everything;
        for (path, fresh) in other.touched {
            *self.touched.entry(path).or_insert(false) |= fresh;
        }
        if self.everything {
            self.touched.clear();
        }
    }

    /// The reported paths, for [`Inventory::refresh`](piikey::inventory::Inventory::refresh).
    pub fn list(&self) -> Vec<Touched> {
        self.touched
            .iter()
            .map(|(path, &fresh)| Touched {
                path: path.clone(),
                fresh,
            })
            .collect()
    }
}

/// What a [`Job`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// What a [`Request`] names, into the inventory.
    Asked(Request),
    /// What monitoring saw change, into the inventory.
    Watch(Changes),
    /// `folder` was removed from the locations: forget what the inventory holds under it.
    Forget { folder: PathBuf },
}

impl Kind {
    /// What is left to do of this once `folder` is gone, and whether that is less than before.
    fn without(&self, folder: &Path) -> (Self, bool) {
        match self {
            Self::Asked(request) => {
                let mut rest = request.clone();
                rest.paths.retain(|path| !sys::is_under(path, folder));
                let less = rest.paths.len() != request.paths.len();
                (Self::Asked(rest), less)
            }
            Self::Watch(changes) => {
                let mut rest = changes.clone();
                rest.drop_under(folder);
                // A scan of everything reads the locations when it starts: it has to start again.
                let less = changes.everything || rest.touched.len() != changes.touched.len();
                (Self::Watch(rest), less)
            }
            Self::Forget { .. } => (self.clone(), false),
        }
    }

    /// Whether nothing is left to do.
    fn is_empty(&self) -> bool {
        match self {
            Self::Asked(request) => request.paths.is_empty(),
            Self::Watch(changes) => changes.is_empty(),
            Self::Forget { .. } => false,
        }
    }
}

/// One scan for the thread to run. Setting `cancel` stops it within the file it is in.
#[derive(Debug)]
pub struct Job {
    pub kind: Kind,
    pub cancel: Arc<AtomicBool>,
}

impl Job {
    /// Whether the scan was stopped before it was done.
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct Jobs {
    /// Folders to forget, before any scan: see [`Scanner::withdraw`].
    forget: VecDeque<PathBuf>,
    asked: VecDeque<Request>,
    /// What monitoring has seen that no scan took yet.
    watch: Changes,
    /// The scan that runs now.
    running: Option<Running>,
    thread: Thread,
}

/// What became of the scan thread.
#[derive(Default, PartialEq, Eq)]
enum Thread {
    #[default]
    NotStarted,
    Started,
    /// [`Scanner::stop`] was called: no more scans.
    Stopped,
}

struct Running {
    cancel: Arc<AtomicBool>,
    /// What it does.
    kind: Kind,
    /// What runs instead of the rest once it is stopped: it was stopped for a request, which
    /// comes first (a scan of what monitoring saw starts again), or because a folder was removed
    /// (it goes on without that folder). `None`: nothing, as when monitoring was switched off.
    rest: Option<Kind>,
}

enum Pick {
    Run(Job),
    /// Nothing to do.
    Wait,
    Stop,
}

impl Jobs {
    fn pick(&mut self) -> Pick {
        if self.thread == Thread::Stopped {
            return Pick::Stop;
        }
        if let Some(folder) = self.forget.pop_front() {
            return Pick::Run(self.begin(Kind::Forget { folder }));
        }
        if let Some(request) = self.asked.pop_front() {
            return Pick::Run(self.begin(Kind::Asked(request)));
        }
        if self.watch.is_empty() {
            return Pick::Wait;
        }
        let changes = mem::take(&mut self.watch);
        Pick::Run(self.begin(Kind::Watch(changes)))
    }

    fn begin(&mut self, kind: Kind) -> Job {
        let cancel = Arc::new(AtomicBool::new(false));
        let rest = matches!(kind, Kind::Watch(_)).then(|| kind.clone());
        self.running = Some(Running {
            cancel: Arc::clone(&cancel),
            kind: kind.clone(),
            rest,
        });
        Job { kind, cancel }
    }

    /// The scan `job` is over, to the end or cancelled. What a cancelled scan was to go on with
    /// waits for its turn: a request goes first in line again. Returns whether there was such a
    /// rest.
    fn finish(&mut self, job: &Job) -> bool {
        let running = self.running.take();
        if !job.cancelled() || self.thread == Thread::Stopped {
            return false;
        }
        match running.and_then(|running| running.rest) {
            Some(rest) if rest.is_empty() => false,
            Some(Kind::Asked(request)) => {
                self.asked.push_front(request);
                true
            }
            Some(Kind::Watch(changes)) => {
                self.watch.merge(changes);
                true
            }
            Some(Kind::Forget { .. }) | None => false,
        }
    }

    /// Stops the scan of what monitoring saw if that is what runs; it starts again later.
    fn interrupt(&self) {
        if let Some(running) = self
            .running
            .as_ref()
            .filter(|running| matches!(running.kind, Kind::Watch(_)))
        {
            running.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// See [`Scanner::withdraw`]. Returns the reveals of the requests that are dropped whole.
    fn withdraw(&mut self, folder: &Path) -> Vec<u64> {
        let mut dropped = Vec::new();
        self.asked.retain_mut(|request| {
            request.paths.retain(|path| !sys::is_under(path, folder));
            let keep = !request.paths.is_empty();
            if !keep {
                dropped.extend(request.reveal);
            }
            keep
        });
        self.watch.drop_under(folder);
        if let Some(running) = self.running.as_mut() {
            let (rest, less) = running.kind.without(folder);
            if less {
                running.rest = Some(rest);
                running.cancel.store(true, Ordering::Relaxed);
            }
        }
        self.forget.push_back(folder.to_path_buf());
        dropped
    }
}

/// The queue the scan thread works through; see the module docs.
#[derive(Default)]
pub struct Scanner {
    jobs: Mutex<Jobs>,
    wake: Condvar,
}

impl Scanner {
    fn lock(&self) -> MutexGuard<'_, Jobs> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the caller has to start the thread: `true` the first time, until
    /// [`Scanner::start_failed`].
    pub fn start_once(&self) -> bool {
        let mut jobs = self.lock();
        let first = jobs.thread == Thread::NotStarted;
        if first {
            jobs.thread = Thread::Started;
        }
        first
    }

    /// The thread could not be started: the next [`Scanner::start_once`] says so again.
    pub fn start_failed(&self) {
        let mut jobs = self.lock();
        if jobs.thread == Thread::Started {
            jobs.thread = Thread::NotStarted;
        }
    }

    /// Queues `request`. A scan of what monitoring saw that runs is stopped and starts again once
    /// the requests are done: the user is waiting for these.
    pub fn ask(&self, request: Request) {
        let mut jobs = self.lock();
        jobs.asked.push_back(request);
        jobs.interrupt();
        drop(jobs);
        self.wake.notify_all();
    }

    /// Monitoring saw `changes`: they are scanned after the requests, together with whatever
    /// else it saw meanwhile.
    pub fn changed(&self, changes: Changes) {
        if changes.is_empty() {
            return;
        }
        let mut jobs = self.lock();
        jobs.watch.merge(changes);
        drop(jobs);
        self.wake.notify_all();
    }

    /// `folder` is no longer one of the locations. Nothing under it is scanned any more: queued
    /// scans lose it (a request with nothing else is dropped), the scan that runs under it stops
    /// and goes on without it, and then what the inventory holds under it is forgotten.
    /// Returns the reveals of the requests that were dropped whole: nobody will scan them.
    pub fn withdraw(&self, folder: &Path) -> Vec<u64> {
        let mut jobs = self.lock();
        let dropped = jobs.withdraw(folder);
        drop(jobs);
        self.wake.notify_all();
        dropped
    }

    /// Stops the scan that is shown as `reveal`: a queued one is dropped, and `true` is returned
    /// (nobody will scan it); a running one is broken off, and not picked up again.
    pub fn stop_request(&self, reveal: u64) -> bool {
        let mut jobs = self.lock();
        let queued = jobs.asked.len();
        jobs.asked.retain(|request| request.reveal != Some(reveal));
        let dropped = jobs.asked.len() != queued;
        if let Some(running) = jobs.running.as_mut().filter(|running| {
            matches!(&running.kind, Kind::Asked(request) if request.reveal == Some(reveal))
        }) {
            running.rest = None;
            running.cancel.store(true, Ordering::Relaxed);
        }
        drop(jobs);
        self.wake.notify_all();
        dropped
    }

    /// Monitoring was switched off or its locations changed: what it saw is not scanned, and the
    /// scan of it that runs is stopped and not started again.
    pub fn stop_watch(&self) {
        let mut jobs = self.lock();
        jobs.watch = Changes::default();
        if let Some(running) = jobs
            .running
            .as_mut()
            .filter(|running| matches!(running.kind, Kind::Watch(_)))
        {
            running.rest = None;
            running.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Blocks until there is a scan to run; `None` once the scanner was [stopped](Self::stop).
    pub fn next(&self) -> Option<Job> {
        let mut jobs = self.lock();
        loop {
            match jobs.pick() {
                Pick::Run(job) => return Some(job),
                Pick::Stop => return None,
                Pick::Wait => {
                    jobs = self.wake.wait(jobs).unwrap_or_else(PoisonError::into_inner);
                }
            }
        }
    }

    /// The scan `next` returned is over, to the end or [cancelled](Job::cancelled). Returns
    /// whether the rest of a cancelled scan waits to run: then it is not over for its user.
    pub fn done(&self, job: &Job) -> bool {
        self.lock().finish(job)
    }

    /// Ends the thread, and stops the scan that runs.
    pub fn stop(&self) {
        let mut jobs = self.lock();
        jobs.thread = Thread::Stopped;
        if let Some(running) = &jobs.running {
            running.cancel.store(true, Ordering::Relaxed);
        }
        drop(jobs);
        self.wake.notify_all();
    }

    /// Nothing runs and nothing waits to run.
    pub fn idle(&self) -> bool {
        let jobs = self.lock();
        jobs.forget.is_empty()
            && jobs.asked.is_empty()
            && jobs.watch.is_empty()
            && jobs.running.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str) -> Request {
        Request {
            paths: vec![PathBuf::from(path)],
            reveal: Some(1),
        }
    }

    fn touched(path: &str, fresh: bool) -> Touched {
        Touched {
            path: PathBuf::from(path),
            fresh,
        }
    }

    fn changes(paths: &[(&str, bool)]) -> Changes {
        Changes::touched(paths.iter().map(|&(path, fresh)| touched(path, fresh)))
    }

    /// The job `pick` gives, or why there is none.
    fn run(jobs: &mut Jobs) -> Result<Job, String> {
        match jobs.pick() {
            Pick::Run(job) => Ok(job),
            Pick::Wait => Err("waits".to_owned()),
            Pick::Stop => Err("stops".to_owned()),
        }
    }

    #[test]
    fn closing_the_dialog_of_a_scan_drops_it_from_the_queue_or_breaks_it_off_for_good()
    -> Result<(), String> {
        let scanner = Scanner::default();
        let shown = |reveal| Request {
            paths: vec![PathBuf::from(r"C:\a")],
            reveal: Some(reveal),
        };
        scanner.ask(shown(1));
        scanner.ask(shown(2));
        let running = run(&mut scanner.lock())?;
        assert!(scanner.stop_request(2), "a queued scan is dropped");
        assert!(!running.cancelled(), "and the one that runs is another");
        assert!(!scanner.stop_request(1), "a running scan is not queued");
        assert!(running.cancelled(), "it stops at once");
        assert!(!scanner.done(&running), "and nothing of it is run again");
        assert!(matches!(scanner.lock().pick(), Pick::Wait));
        Ok(())
    }

    #[test]
    fn requests_run_first_and_in_order_and_what_the_watch_saw_after_them() -> Result<(), String> {
        let mut jobs = Jobs::default();
        jobs.watch.merge(changes(&[("w", false)]));
        jobs.asked.push_back(request("a"));
        jobs.asked.push_back(request("b"));
        let kinds: Vec<Kind> = (0..3)
            .map(|_| run(&mut jobs).map(|job| job.kind))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            kinds,
            [
                Kind::Asked(request("a")),
                Kind::Asked(request("b")),
                Kind::Watch(changes(&[("w", false)]))
            ]
        );
        assert!(
            matches!(jobs.pick(), Pick::Wait),
            "and then nothing: no timer"
        );
        Ok(())
    }

    #[test]
    fn nothing_is_scanned_that_nobody_asked_for() {
        let mut jobs = Jobs::default();
        assert!(matches!(jobs.pick(), Pick::Wait));
        // Not even a long time later: there is no timer to wait for.
        assert!(matches!(jobs.pick(), Pick::Wait));
    }

    #[test]
    fn what_the_watch_saw_is_merged_while_it_waits() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.changed(changes(&[("a", false), ("b", false)]));
        scanner.changed(changes(&[("a", true), ("c", false)]));
        scanner.changed(Changes::default());
        let job = run(&mut scanner.lock())?;
        assert_eq!(
            job.kind,
            Kind::Watch(changes(&[("a", true), ("b", false), ("c", false)])),
            "one scan, and a path that was fresh once is fresh"
        );
        // With everything to be looked at, single paths say nothing more.
        scanner.changed(changes(&[("x", false)]));
        scanner.changed(Changes::everything());
        scanner.changed(changes(&[("y", true)]));
        let all = run(&mut scanner.lock())?;
        assert_eq!(all.kind, Kind::Watch(Changes::everything()));
        assert!(!Changes::everything().is_empty());
        assert!(Changes::default().is_empty());
        Ok(())
    }

    #[test]
    fn the_changes_are_listed_in_path_order_with_their_freshness() {
        let list = changes(&[("b", false), ("a", true), ("b", true)]).list();
        assert_eq!(list, [touched("a", true), touched("b", true)]);
    }

    #[test]
    fn a_request_stops_the_scan_of_the_watch_which_goes_on_afterwards() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.changed(changes(&[("w", true)]));
        let watched = run(&mut scanner.lock())?;
        assert!(!watched.cancelled());
        scanner.changed(changes(&[("later", false)]));

        scanner.ask(request("a"));
        assert!(
            watched.cancelled(),
            "the user waits: what the watch does yields"
        );
        let mut jobs = scanner.lock();
        jobs.finish(&watched);
        let asked = run(&mut jobs)?;
        assert_eq!(asked.kind, Kind::Asked(request("a")));
        assert!(!asked.cancelled());
        jobs.finish(&asked);
        // What the stopped scan did not finish, and what came meanwhile, is one scan.
        assert_eq!(
            run(&mut jobs)?.kind,
            Kind::Watch(changes(&[("later", false), ("w", true)]))
        );
        Ok(())
    }

    #[test]
    fn a_request_leaves_alone_a_scan_that_is_not_the_watch() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.ask(request("a"));
        let first = run(&mut scanner.lock())?;
        assert_eq!(first.kind, Kind::Asked(request("a")));
        scanner.ask(request("b"));
        assert!(!first.cancelled());
        Ok(())
    }

    #[test]
    fn a_scan_of_the_watch_that_ran_to_the_end_is_not_scanned_again() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.changed(changes(&[("w", false)]));
        let watched = run(&mut scanner.lock())?;
        scanner.done(&watched);
        assert!(matches!(scanner.lock().pick(), Pick::Wait));
        assert!(scanner.idle());
        Ok(())
    }

    #[test]
    fn stopping_monitoring_drops_what_it_saw_and_stops_its_scan_for_good() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.changed(changes(&[("w", false)]));
        let watched = run(&mut scanner.lock())?;
        scanner.changed(changes(&[("more", false)]));
        scanner.stop_watch();
        assert!(watched.cancelled());
        let mut jobs = scanner.lock();
        jobs.finish(&watched);
        assert!(
            matches!(jobs.pick(), Pick::Wait),
            "nothing follows: not what was left, not what came after"
        );

        // A request that is not for the watch is not touched by it.
        drop(jobs);
        scanner.ask(request("a"));
        let asked = run(&mut scanner.lock())?;
        scanner.stop_watch();
        assert!(!asked.cancelled());
        Ok(())
    }

    #[test]
    fn stopping_ends_the_queue_and_cancels_what_runs() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.ask(request("a"));
        let running = run(&mut scanner.lock())?;
        scanner.ask(request("b"));
        scanner.stop();
        assert!(running.cancelled());
        assert!(matches!(scanner.lock().pick(), Pick::Stop));
        assert!(scanner.next().is_none());
        // What was stopped is not queued again.
        let watched = {
            let other = Scanner::default();
            other.changed(changes(&[("w", false)]));
            let job = run(&mut other.lock())?;
            other.stop();
            other.done(&job);
            assert!(other.idle());
            job
        };
        assert!(watched.cancelled());
        Ok(())
    }

    #[test]
    fn idle_means_nothing_runs_or_waits() -> Result<(), String> {
        let scanner = Scanner::default();
        assert!(scanner.idle());
        scanner.ask(request("a"));
        assert!(!scanner.idle());
        let job = scanner.next().ok_or("a request was queued")?;
        assert!(!scanner.idle());
        scanner.done(&job);
        assert!(scanner.idle());
        scanner.changed(changes(&[("w", false)]));
        assert!(!scanner.idle(), "what the watch saw is work too");
        let job = scanner.next().ok_or("the watch saw something")?;
        scanner.done(&job);
        assert!(scanner.idle());
        Ok(())
    }

    fn asked(paths: &[&str], reveal: Option<u64>) -> Request {
        Request {
            paths: paths.iter().map(PathBuf::from).collect(),
            reveal,
        }
    }

    #[test]
    fn removing_a_location_breaks_off_its_scan_which_goes_on_without_it_after_the_forget()
    -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.ask(asked(&[r"C:\a", r"C:\b"], Some(1)));
        let running = run(&mut scanner.lock())?;
        assert!(scanner.withdraw(Path::new(r"C:\a")).is_empty());
        assert!(running.cancelled(), "the scan under it stops at once");
        assert!(scanner.done(&running), "and the rest of it waits to run");
        let mut jobs = scanner.lock();
        assert_eq!(
            run(&mut jobs)?.kind,
            Kind::Forget {
                folder: PathBuf::from(r"C:\a")
            },
            "first what it held is forgotten, after the stopped scan saved"
        );
        assert_eq!(
            run(&mut jobs)?.kind,
            Kind::Asked(asked(&[r"C:\b"], Some(1)))
        );
        Ok(())
    }

    #[test]
    fn queued_scans_lose_a_removed_location_and_one_with_nothing_left_is_dropped()
    -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.ask(asked(&[r"C:\a\file.txt"], Some(7)));
        scanner.ask(asked(&[r"C:\A", r"C:\c"], None));
        assert_eq!(
            scanner.withdraw(Path::new(r"C:\a")),
            [7],
            "its dialog is told nobody will scan it"
        );
        let mut jobs = scanner.lock();
        assert!(matches!(run(&mut jobs)?.kind, Kind::Forget { .. }));
        assert_eq!(run(&mut jobs)?.kind, Kind::Asked(asked(&[r"C:\c"], None)));
        assert!(matches!(jobs.pick(), Pick::Wait), "nothing else is left");
        Ok(())
    }

    #[test]
    fn removing_a_location_breaks_off_the_watch_scan_under_it_and_keeps_the_rest()
    -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.changed(changes(&[(r"C:\w\a.txt", false), (r"C:\v\b.txt", true)]));
        let running = run(&mut scanner.lock())?;
        scanner.changed(changes(&[(r"C:\w\later.txt", false)]));
        scanner.withdraw(Path::new(r"C:\w"));
        assert!(running.cancelled());
        assert!(scanner.done(&running));
        let mut jobs = scanner.lock();
        assert!(matches!(run(&mut jobs)?.kind, Kind::Forget { .. }));
        assert_eq!(
            run(&mut jobs)?.kind,
            Kind::Watch(changes(&[(r"C:\v\b.txt", true)])),
            "nothing under the removed folder is scanned any more"
        );
        Ok(())
    }

    #[test]
    fn removing_a_folder_leaves_scans_elsewhere_alone() -> Result<(), String> {
        let scanner = Scanner::default();
        scanner.ask(asked(&[r"C:\c"], None));
        let running = run(&mut scanner.lock())?;
        scanner.withdraw(Path::new(r"C:\a"));
        assert!(!running.cancelled(), "another folder");
        assert!(!scanner.done(&running));
        Ok(())
    }

    #[test]
    fn the_thread_is_started_once() {
        let scanner = Scanner::default();
        assert!(scanner.start_once());
        assert!(!scanner.start_once());
        scanner.start_failed();
        assert!(scanner.start_once());
    }
}
