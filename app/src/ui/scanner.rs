//! The work queue of the scan thread: the scans somebody asked for come first, in the order they
//! were asked, and the folders the inventory watches are scanned when the inventory is on, again
//! every [`EVERY`].
//!
//! The thread itself belongs to the controller, which has the engine, the inventory and the state
//! that shows progress; this is only the queue and its rules, so they are tested without a thread.

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// How long the watched folders go without a scan.
pub const EVERY: Duration = Duration::from_hours(1);

/// A scan somebody asked for: Explorer's "Scan for PII", a rescan, the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub paths: Vec<PathBuf>,
    /// The window comes forward with the result when the scan is done.
    pub reveal: bool,
}

/// What a [`Job`] scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// What a [`Request`] names.
    Asked(Request),
    /// The folders the inventory watches.
    Watched,
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
    asked: VecDeque<Request>,
    /// The watched folders are due now, whatever [`EVERY`] says: the inventory was switched on,
    /// what it watches changed, or its scan was interrupted.
    due: bool,
    /// The inventory is on.
    watching: bool,
    /// When the watched folders were last scanned to the end.
    last: Option<Instant>,
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
    watched: bool,
}

enum Pick {
    Run(Job),
    /// Nothing to do for this long; for ever when `None`.
    Wait(Option<Duration>),
    Stop,
}

impl Jobs {
    fn pick(&mut self, now: Instant) -> Pick {
        if self.thread == Thread::Stopped {
            return Pick::Stop;
        }
        if let Some(request) = self.asked.pop_front() {
            return Pick::Run(self.begin(Kind::Asked(request)));
        }
        if !self.watching {
            return Pick::Wait(None);
        }
        let age = self.last.map(|at| now.saturating_duration_since(at));
        match age {
            Some(age) if !self.due && age < EVERY => Pick::Wait(Some(EVERY.saturating_sub(age))),
            _ => {
                self.due = false;
                Pick::Run(self.begin(Kind::Watched))
            }
        }
    }

    fn begin(&mut self, kind: Kind) -> Job {
        let cancel = Arc::new(AtomicBool::new(false));
        self.running = Some(Running {
            cancel: Arc::clone(&cancel),
            watched: kind == Kind::Watched,
        });
        Job { kind, cancel }
    }

    /// Stops the scan of the watched folders if that is what runs; whether it was.
    fn interrupt(&self) -> bool {
        match &self.running {
            Some(running) if running.watched => {
                running.cancel.store(true, Ordering::Relaxed);
                true
            }
            _ => false,
        }
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

    /// Queues `request`. A scan of the watched folders that runs is stopped and starts again once
    /// the requests are done: the user is waiting for these.
    pub fn ask(&self, request: Request) {
        let mut jobs = self.lock();
        jobs.asked.push_back(request);
        if jobs.interrupt() && jobs.watching {
            jobs.due = true;
        }
        drop(jobs);
        self.wake.notify_all();
    }

    /// The inventory was switched on or off, or what it watches changed: with `on` the watched
    /// folders are scanned now (again, when a scan of them runs); without, that scan is stopped
    /// and none follows.
    pub fn watch(&self, on: bool) {
        let mut jobs = self.lock();
        jobs.watching = on;
        jobs.due = on;
        jobs.interrupt();
        drop(jobs);
        self.wake.notify_all();
    }

    /// Blocks until there is a scan to run; `None` once the scanner was [stopped](Self::stop).
    pub fn next(&self) -> Option<Job> {
        let mut jobs = self.lock();
        loop {
            match jobs.pick(Instant::now()) {
                Pick::Run(job) => return Some(job),
                Pick::Stop => return None,
                Pick::Wait(None) => {
                    jobs = self.wake.wait(jobs).unwrap_or_else(PoisonError::into_inner);
                }
                Pick::Wait(Some(left)) => {
                    jobs = self
                        .wake
                        .wait_timeout(jobs, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }

    /// The scan `next` returned is over, to the end or [cancelled](Job::cancelled).
    pub fn done(&self, job: &Job) {
        let mut jobs = self.lock();
        jobs.running = None;
        if job.kind == Kind::Watched && !job.cancelled() {
            jobs.last = Some(Instant::now());
        }
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

    /// Nothing runs and nothing waits to run, except the watched folders' next turn.
    pub fn idle(&self) -> bool {
        let jobs = self.lock();
        jobs.asked.is_empty() && jobs.running.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str) -> Request {
        Request {
            paths: vec![PathBuf::from(path)],
            reveal: true,
        }
    }

    /// The job `pick` gives, or why there is none.
    fn run(jobs: &mut Jobs, now: Instant) -> Result<Job, String> {
        match jobs.pick(now) {
            Pick::Run(job) => Ok(job),
            Pick::Wait(left) => Err(format!("waits for {left:?}")),
            Pick::Stop => Err("stops".to_owned()),
        }
    }

    fn finish(jobs: &mut Jobs, job: &Job, now: Instant) {
        jobs.running = None;
        if job.kind == Kind::Watched && !job.cancelled() {
            jobs.last = Some(now);
        }
    }

    #[test]
    fn requests_run_first_and_in_order() -> Result<(), String> {
        let mut jobs = Jobs {
            watching: true,
            due: true,
            ..Jobs::default()
        };
        let now = Instant::now();
        jobs.asked.push_back(request("a"));
        jobs.asked.push_back(request("b"));
        let kinds: Vec<Kind> = (0..3)
            .map(|_| run(&mut jobs, now).map(|job| job.kind))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            kinds,
            [
                Kind::Asked(request("a")),
                Kind::Asked(request("b")),
                Kind::Watched
            ]
        );
        Ok(())
    }

    #[test]
    fn nothing_is_watched_until_the_inventory_is_on() {
        let mut jobs = Jobs::default();
        assert!(matches!(jobs.pick(Instant::now()), Pick::Wait(None)));
    }

    #[test]
    fn the_watched_folders_are_scanned_at_once_then_every_hour() -> Result<(), String> {
        let mut jobs = Jobs {
            watching: true,
            ..Jobs::default()
        };
        let start = Instant::now();
        let job = run(&mut jobs, start)?;
        assert_eq!(job.kind, Kind::Watched);
        finish(&mut jobs, &job, start);

        let soon = start + Duration::from_mins(1);
        match jobs.pick(soon) {
            Pick::Wait(Some(left)) => {
                assert_eq!(left, EVERY.saturating_sub(Duration::from_mins(1)));
            }
            _ => return Err("it should wait for the hour".to_owned()),
        }
        let later = start + EVERY;
        assert_eq!(run(&mut jobs, later)?.kind, Kind::Watched);
        Ok(())
    }

    #[test]
    fn a_change_of_what_is_watched_scans_again_at_once() -> Result<(), String> {
        let scanner = Scanner::default();
        let start = Instant::now();
        {
            let mut jobs = scanner.lock();
            jobs.watching = true;
            let job = run(&mut jobs, start)?;
            finish(&mut jobs, &job, start);
            assert!(matches!(jobs.pick(start), Pick::Wait(Some(_))));
        }
        scanner.watch(true);
        let mut jobs = scanner.lock();
        assert_eq!(run(&mut jobs, start)?.kind, Kind::Watched);
        Ok(())
    }

    #[test]
    fn a_request_interrupts_the_watched_scan_which_then_starts_again() -> Result<(), String> {
        let scanner = Scanner::default();
        let now = Instant::now();
        scanner.watch(true);
        let watched = run(&mut scanner.lock(), now)?;
        assert!(!watched.cancelled());

        scanner.ask(request("a"));
        assert!(
            watched.cancelled(),
            "the user waits: the background scan yields"
        );
        let mut jobs = scanner.lock();
        finish(&mut jobs, &watched, now);
        let asked = run(&mut jobs, now)?;
        assert_eq!(asked.kind, Kind::Asked(request("a")));
        assert!(!asked.cancelled());
        finish(&mut jobs, &asked, now);
        // The interrupted scan did not count as a scan to the end: it is due again.
        assert_eq!(run(&mut jobs, now)?.kind, Kind::Watched);
        Ok(())
    }

    #[test]
    fn a_request_leaves_alone_a_scan_that_is_not_the_watched_one() -> Result<(), String> {
        let scanner = Scanner::default();
        let now = Instant::now();
        scanner.watch(true);
        scanner.ask(request("a"));
        let first = run(&mut scanner.lock(), now)?;
        assert_eq!(first.kind, Kind::Asked(request("a")));
        scanner.ask(request("b"));
        assert!(!first.cancelled());
        Ok(())
    }

    #[test]
    fn a_request_without_a_watched_scan_does_not_make_one_due() -> Result<(), String> {
        let scanner = Scanner::default();
        let now = Instant::now();
        scanner.ask(request("a"));
        let mut jobs = scanner.lock();
        let asked = run(&mut jobs, now)?;
        finish(&mut jobs, &asked, now);
        assert!(matches!(jobs.pick(now), Pick::Wait(None)));
        Ok(())
    }

    #[test]
    fn switching_the_inventory_off_stops_its_scan_and_nothing_follows() -> Result<(), String> {
        let scanner = Scanner::default();
        let now = Instant::now();
        scanner.watch(true);
        let watched = run(&mut scanner.lock(), now)?;
        scanner.watch(false);
        assert!(watched.cancelled());
        let mut jobs = scanner.lock();
        finish(&mut jobs, &watched, now);
        assert!(matches!(jobs.pick(now), Pick::Wait(None)));
        Ok(())
    }

    #[test]
    fn stopping_ends_the_queue_and_cancels_what_runs() -> Result<(), String> {
        let scanner = Scanner::default();
        let now = Instant::now();
        scanner.ask(request("a"));
        let running = run(&mut scanner.lock(), now)?;
        scanner.ask(request("b"));
        scanner.stop();
        assert!(running.cancelled());
        assert!(matches!(scanner.lock().pick(now), Pick::Stop));
        assert!(scanner.next().is_none());
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
