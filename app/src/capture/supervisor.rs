//! Runs capture on threads: a worker that reads, and a supervisor that replaces it when a read
//! hangs.

use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::{
    desktop::{Clip, Desktop, Field, Focus},
    sink::{Sink, Store},
    uia::Uia,
    watcher::Watcher,
};
use crate::{
    Res,
    highlight::{Mark, Overlay, Rect},
    proxy::{Shared, Typed},
};

/// Workers of one capture that may be alive at once: the one that sees, and those replaced while
/// they were stuck in a read that has not come back.
const MAX_WORKERS: usize = 4;

/// When capture counts as blind, and how often that is looked at. The tests use shorter times.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// A read that has not come back after this long means capture cannot see.
    stall: Duration,
    /// How often the supervisor looks.
    watch: Duration,
    /// How long [`start`] waits for UI Automation to come up.
    start: Duration,
}

const TIMING: Timing = Timing {
    stall: Duration::from_secs(1),
    watch: Duration::from_millis(250),
    start: Duration::from_secs(10),
};

/// Makes a [`Desktop`] on the thread that will use it (UI Automation objects stay on their
/// thread); the error is a message for the user.
type Make = dyn Fn() -> Res<Box<dyn Desktop>> + Send + Sync;

/// A running capture: workers read the screen, and a supervisor watches them.
#[derive(Debug)]
pub(crate) struct Capture {
    control: Arc<Control>,
    thread: Option<JoinHandle<()>>,
}

impl Capture {
    /// Stops reading and waits for the supervisor, not for a worker that is stuck in a read: that
    /// one ends when Windows lets it go. Requests are checked whole again from then on, and
    /// everything captured is forgotten.
    pub(crate) fn stop(mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop.store(true, Ordering::Release);
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

impl Drop for Capture {
    /// A capture that is let go stops all the same, without being waited for.
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }
}

/// Starts capture and makes [`Typed`] active, so the proxy masks only what was typed.
///
/// # Errors
/// The thread cannot start, or UI Automation is not available.
pub(crate) fn start(shared: &Arc<Shared>) -> Res<Capture> {
    let make = {
        let shared = Arc::clone(shared);
        move || {
            Uia::new(Arc::clone(&shared))
                .map(|uia| Box::new(uia) as Box<dyn Desktop>)
                .map_err(|error| format!("UI Automation is not available: {error}"))
        }
    };
    launch(shared, Arc::new(make), TIMING)
}

/// [`start`] with the desktop and the timing given.
fn launch(shared: &Arc<Shared>, make: Arc<Make>, timing: Timing) -> Res<Capture> {
    let control = Arc::new(Control::new());
    let (ready, started) = mpsc::channel();
    spawn_worker(shared, &control, &make, 0, Some(ready))
        .map_err(|error| format!("cannot start the capture thread: {error}"))?;
    match started.recv_timeout(timing.start) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(RecvTimeoutError::Timeout) => {
            // Nobody waits for the worker any more: it ends as soon as it gets going.
            control.stop.store(true, Ordering::Release);
            return Err("UI Automation did not start in time".to_owned());
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err("the capture thread ended before it started".to_owned());
        }
    }
    let supervisor = thread::Builder::new()
        .name("piikey-capture-watch".to_owned())
        .spawn({
            let (shared, control) = (Arc::clone(shared), Arc::clone(&control));
            move || watch(&shared, &control, &make, timing)
        });
    match supervisor {
        Ok(thread) => Ok(Capture {
            control,
            thread: Some(thread),
        }),
        Err(error) => {
            control.stop.store(true, Ordering::Release);
            shared.typed.set_active(false);
            Err(format!("cannot start the capture thread: {error}"))
        }
    }
}

/// What the supervisor and the workers of one capture share.
#[derive(Debug)]
struct Control {
    /// Set by [`Capture::stop`].
    stop: AtomicBool,
    /// The worker whose reads count; the ones before it were replaced.
    current: AtomicU64,
    /// The current worker ended without being asked to.
    lost: AtomicBool,
    /// The current worker has completed a read.
    seen: AtomicBool,
    /// Workers that have not returned yet.
    alive: AtomicUsize,
    /// When the current worker began the read it is in, in microseconds after `epoch`; 0 when it is
    /// in none. A worker that has just been made counts as in a read until its first one is done:
    /// UI Automation may be stuck coming up for it.
    reading: AtomicU64,
    /// Whether the store was last made active: it follows
    /// [`Purpose::mask`](crate::proxy::Purpose::mask), protection.
    masking: AtomicBool,
    epoch: Instant,
}

impl Control {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            current: AtomicU64::new(0),
            lost: AtomicBool::new(false),
            seen: AtomicBool::new(false),
            alive: AtomicUsize::new(0),
            reading: AtomicU64::new(0),
            masking: AtomicBool::new(false),
            epoch: Instant::now(),
        }
    }

    /// Whether worker `id` is the one whose reads count, and nobody asked to stop.
    fn is_current(&self, id: u64) -> bool {
        !self.stop.load(Ordering::Acquire) && self.current.load(Ordering::Acquire) == id
    }

    fn now(&self) -> u64 {
        micros(self.epoch.elapsed()).max(1)
    }

    /// Worker `id` begins or ends a read.
    fn reading(&self, id: u64, on: bool) {
        if self.is_current(id) {
            self.reading
                .store(if on { self.now() } else { 0 }, Ordering::Release);
        }
    }

    /// A read of the current worker, or one that died in it, has taken longer than `after`.
    fn stalled(&self, after: Duration) -> bool {
        if self.lost.load(Ordering::Acquire) {
            return true;
        }
        let since = self.reading.load(Ordering::Acquire);
        since != 0 && self.now().saturating_sub(since) > micros(after)
    }

    /// Makes a new worker the current one and returns its number.
    fn replace(&self) -> u64 {
        // First, so that the worker it replaces cannot touch what follows any more.
        let id = self.current.fetch_add(1, Ordering::AcqRel) + 1;
        self.seen.store(false, Ordering::Release);
        self.lost.store(false, Ordering::Release);
        self.reading.store(self.now(), Ordering::Release);
        id
    }

    /// Makes the store active exactly while protection is on, as worker `id`: what is typed is
    /// kept for the proxy only then. A change takes effect within one look at the focus.
    fn follow_mask(&self, shared: &Shared, id: u64) {
        if !self.is_current(id) {
            return;
        }
        let mask = shared.purpose.mask();
        if self.masking.swap(mask, Ordering::AcqRel) != mask {
            shared.typed.set_active(mask);
        }
    }
}

fn micros(time: Duration) -> u64 {
    u64::try_from(time.as_micros()).unwrap_or(u64::MAX)
}

/// Starts worker `id`. The first one (`ready` is given) reports whether UI Automation started, and
/// makes the store active, when protection is on, before it reads anything: an inactive store
/// ignores what is pushed.
fn spawn_worker(
    shared: &Arc<Shared>,
    control: &Arc<Control>,
    make: &Arc<Make>,
    id: u64,
    ready: Option<Sender<Res<()>>>,
) -> std::io::Result<()> {
    control.alive.fetch_add(1, Ordering::AcqRel);
    let (shared, control_here, make) = (Arc::clone(shared), Arc::clone(control), Arc::clone(make));
    let spawned = thread::Builder::new()
        .name("piikey-capture".to_owned())
        .spawn(move || {
            let _alive = Alive {
                control: &control_here,
                id,
            };
            let desktop = match make() {
                Ok(desktop) => desktop,
                Err(error) => {
                    if let Some(ready) = ready {
                        let _ = ready.send(Err(error));
                    }
                    return;
                }
            };
            if let Some(ready) = ready {
                control_here.follow_mask(&shared, id);
                let _ = ready.send(Ok(()));
            }
            work(&shared, &control_here, id, desktop);
        });
    if spawned.is_err() {
        control.alive.fetch_sub(1, Ordering::AcqRel);
    }
    spawned.map(drop)
}

/// Counts a worker out when it ends, and notes it when it was the current one and nobody asked.
struct Alive<'a> {
    control: &'a Control,
    id: u64,
}

impl Drop for Alive<'_> {
    fn drop(&mut self) {
        self.control.alive.fetch_sub(1, Ordering::AcqRel);
        if self.control.is_current(self.id) {
            self.control.lost.store(true, Ordering::Release);
        }
    }
}

/// A worker: reads until it is replaced or told to stop.
fn work(shared: &Shared, control: &Control, id: u64, desktop: Box<dyn Desktop>) {
    let mut desktop = Watched {
        desktop,
        control,
        id,
    };
    let sink = Gate {
        store: Store(shared),
        control,
        id,
    };
    // A press of the shortcut wakes this thread: the outline need not wait for the next look. A
    // worker that was given up on while it started must not take the place of the one that runs.
    if control.is_current(id) {
        shared.purpose.set_worker(thread::current());
    }
    let mut watcher = Watcher::new(Arc::clone(&shared.purpose));
    while control.is_current(id) {
        control.follow_mask(shared, id);
        watcher.tick(Instant::now(), &mut desktop, &sink);
        pause(watcher.period(), &control.stop, || watcher.pressed());
    }
}

/// The supervisor. A read of the focused element can take a minute: measured here with a game in
/// front, `GetFocusedElement` came back after 60 s. A worker stuck in one sees nothing, and the
/// user may be typing into a protected page meanwhile. So when the current worker's read is overdue
/// the store goes blind, which makes the proxy check whole requests (the values kept stay), and a
/// new worker takes over. It stays blind until that worker has completed a read.
fn watch(shared: &Arc<Shared>, control: &Arc<Control>, make: &Arc<Make>, timing: Timing) {
    let _end = End {
        control,
        typed: &shared.typed,
    };
    let mut blind = false;
    let mut replaced = Instant::now();
    while !control.stop.load(Ordering::Acquire) {
        pause(timing.watch, &control.stop, || false);
        if control.stalled(timing.stall) {
            if !blind {
                blind = true;
                shared.typed.set_blind(true);
            }
            if control.alive.load(Ordering::Acquire) < MAX_WORKERS
                && replaced.elapsed() >= timing.stall
            {
                replaced = Instant::now();
                let id = control.replace();
                if spawn_worker(shared, control, make, id, None).is_err() {
                    control.lost.store(true, Ordering::Release);
                }
            }
        } else if blind && control.seen.load(Ordering::Acquire) {
            blind = false;
            shared.typed.set_blind(false);
        }
    }
}

/// Ends capture when dropped, panic included: the proxy checks whole requests once the store is
/// inactive, and would send everything unmasked if capture died with the store still active. An
/// outline that is up goes too: nobody is looking at the field any more.
struct End<'a> {
    control: &'a Control,
    typed: &'a Typed,
}

impl Drop for End<'_> {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::Release);
        self.typed.set_active(false);
        Overlay::hide_any();
    }
}

/// A [`Desktop`] whose reads the supervisor times.
struct Watched<'a> {
    desktop: Box<dyn Desktop>,
    control: &'a Control,
    id: u64,
}

impl Watched<'_> {
    fn timed<R>(&mut self, read: impl FnOnce(&mut dyn Desktop) -> R) -> R {
        self.control.reading(self.id, true);
        let result = read(&mut *self.desktop);
        self.control.reading(self.id, false);
        if self.control.is_current(self.id) {
            self.control.seen.store(true, Ordering::Release);
        }
        result
    }
}

impl Desktop for Watched<'_> {
    fn focus(&mut self, with_text: bool) -> Option<Focus> {
        let focus = self.timed(|desktop| desktop.focus(with_text));
        // A worker that was replaced while it waited knows nothing that is true now.
        focus.filter(|_| self.control.is_current(self.id))
    }

    fn protected(&mut self) -> bool {
        self.timed(|desktop| desktop.protected())
    }

    fn text(&mut self) -> Option<String> {
        self.timed(|desktop| desktop.text())
    }

    fn field(&mut self) -> Option<Field> {
        self.timed(|desktop| desktop.field())
    }

    fn bounds(&mut self) -> Option<Rect> {
        self.timed(|desktop| desktop.bounds())
    }

    fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
        self.timed(|desktop| desktop.clipboard_seq())
    }

    fn clipboard_text(&mut self) -> Clip {
        self.timed(|desktop| desktop.clipboard_text())
    }
}

/// Lets only the current worker reach the store and the overlay.
struct Gate<'a> {
    store: Store<'a>,
    control: &'a Control,
    id: u64,
}

impl Sink for Gate<'_> {
    fn push(&self, text: String) {
        if self.control.is_current(self.id) {
            self.store.push(text);
        }
    }

    fn flush(&self) {
        if self.control.is_current(self.id) {
            self.store.flush();
        }
    }

    fn holds_pii(&self, text: &str) -> Option<bool> {
        self.control
            .is_current(self.id)
            .then(|| self.store.holds_pii(text))
            .flatten()
    }

    fn show(&self, field: Rect, mark: Mark) {
        if self.control.is_current(self.id) {
            self.store.show(field, mark);
        }
    }

    fn hide(&self) {
        if self.control.is_current(self.id) {
            self.store.hide();
        }
    }
}

/// Sleeps `period`, or until [`Capture::stop`] wakes the thread, or until `early` says so once
/// something has: a press of the shortcut wakes the worker.
fn pause(period: Duration, stop: &AtomicBool, early: impl Fn() -> bool) {
    let end = Instant::now() + period;
    while !stop.load(Ordering::Acquire) && !early() {
        let Some(left) = end.checked_duration_since(Instant::now()) else {
            return;
        };
        thread::park_timeout(left);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Describe,
        capture::testing::{EMAIL, shared},
    };
    use piikey::policy::Highlight;

    /// What a scripted desktop does when it is asked for the focus.
    enum Read {
        /// Waits until the gate opens, then sees nothing.
        Hang(Arc<AtomicBool>),
        /// Sees a protected field that holds `text`; the first read takes `first_delay`.
        Field {
            first_delay: Duration,
            text: &'static str,
        },
        /// Sees a protected field that holds `text`, and counts every look.
        Watching {
            looks: Arc<AtomicUsize>,
            text: &'static str,
        },
        /// Panics.
        Die,
    }

    struct Scripted {
        read: Read,
        calls: usize,
    }

    impl Desktop for Scripted {
        fn focus(&mut self, _with_text: bool) -> Option<Focus> {
            self.calls += 1;
            let element = || {
                Some(Focus {
                    id: vec![42, 1],
                    password: false,
                })
            };
            match &self.read {
                Read::Hang(gate) => {
                    while !gate.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(5));
                    }
                    None
                }
                Read::Field { first_delay, .. } => {
                    if self.calls == 1 {
                        thread::sleep(*first_delay);
                    }
                    element()
                }
                Read::Watching { looks, .. } => {
                    looks.fetch_add(1, Ordering::AcqRel);
                    element()
                }
                Read::Die => panic!("the reader crashed"),
            }
        }

        fn protected(&mut self) -> bool {
            true
        }

        fn text(&mut self) -> Option<String> {
            match &self.read {
                Read::Field { text, .. } | Read::Watching { text, .. } => Some((*text).to_owned()),
                Read::Hang(_) | Read::Die => None,
            }
        }

        fn field(&mut self) -> Option<Field> {
            None
        }

        fn bounds(&mut self) -> Option<Rect> {
            None
        }

        fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
            None
        }

        fn clipboard_text(&mut self) -> Clip {
            Clip::NoText
        }
    }

    /// A maker whose first desktop reads as `first` says and every later one as `then` says.
    fn script(
        first: impl Fn() -> Read + Send + Sync + 'static,
        then: impl Fn() -> Read + Send + Sync + 'static,
    ) -> Arc<Make> {
        let made = AtomicUsize::new(0);
        Arc::new(move || {
            let read = if made.fetch_add(1, Ordering::AcqRel) == 0 {
                first()
            } else {
                then()
            };
            Ok(Box::new(Scripted { read, calls: 0 }) as Box<dyn Desktop>)
        })
    }

    fn timing(stall_millis: u64) -> Timing {
        Timing {
            stall: Duration::from_millis(stall_millis),
            watch: Duration::from_millis(10),
            start: Duration::from_secs(20),
        }
    }

    fn wait_until(what: &str, done: impl Fn() -> bool) -> Result<(), String> {
        let end = Instant::now() + Duration::from_secs(20);
        while !done() {
            if Instant::now() > end {
                return Err(format!("timed out waiting until {what}"));
            }
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }

    #[test]
    fn stopping_wakes_a_sleeping_thread() -> Result<(), String> {
        let stop = Arc::new(AtomicBool::new(false));
        let sleeper = thread::spawn({
            let stop = Arc::clone(&stop);
            move || pause(Duration::from_mins(1), &stop, || false)
        });
        thread::sleep(Duration::from_millis(50));
        let asked = Instant::now();
        stop.store(true, Ordering::Release);
        sleeper.thread().unpark();
        sleeper.join().map_err(|_| "the sleeper panicked")?;
        assert!(asked.elapsed() < Duration::from_secs(10), "it slept on");
        Ok(())
    }

    #[test]
    fn a_press_of_the_shortcut_ends_the_wait_for_the_next_look() -> Result<(), String> {
        let purpose = Arc::new(crate::proxy::Purpose::default());
        let (ready, registered) = mpsc::channel();
        let waiter = thread::spawn({
            let purpose = Arc::clone(&purpose);
            move || {
                purpose.set_worker(thread::current());
                let _ = ready.send(());
                let seen = purpose.presses();
                let started = Instant::now();
                pause(Duration::from_mins(1), &AtomicBool::new(false), || {
                    purpose.presses() != seen
                });
                started.elapsed()
            }
        });
        registered.recv().describe()?;
        thread::sleep(Duration::from_millis(50));
        purpose.press();
        let lasted = waiter.join().map_err(|_| "the waiter panicked")?;
        assert!(lasted < Duration::from_secs(30), "it waited on: {lasted:?}");
        Ok(())
    }

    #[test]
    fn a_capture_that_dies_hands_requests_back_to_full_detection() {
        let typed = Typed::new();
        typed.set_active(true);
        let control = Control::new();
        let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _end = End {
                control: &control,
                typed: &typed,
            };
            panic!("the supervisor crashed");
        }));
        assert!(died.is_err());
        assert!(!typed.is_active());
        assert!(control.stop.load(Ordering::Acquire), "the workers stop too");
    }

    #[test]
    fn the_store_is_active_exactly_while_capture_runs() -> Result<(), String> {
        let (shared, _dir) = shared("run")?;
        assert!(!shared.typed.is_active());
        // Without UI Automation nothing starts, and requests are checked whole.
        if let Ok(capture) = start(&shared) {
            assert!(shared.typed.is_active());
            capture.stop();
        }
        assert!(!shared.typed.is_active());
        Ok(())
    }

    #[test]
    fn a_desktop_that_cannot_start_leaves_the_store_inactive() -> Result<(), String> {
        let (shared, _dir) = shared("nostart")?;
        let make: Arc<Make> = Arc::new(|| Err("UI Automation is not available: test".to_owned()));
        let error = launch(&shared, make, timing(50)).err();
        assert_eq!(
            error.as_deref(),
            Some("UI Automation is not available: test")
        );
        assert!(!shared.typed.is_active());
        Ok(())
    }

    #[test]
    fn a_desktop_that_is_stuck_coming_up_is_given_up() -> Result<(), String> {
        let (shared, _dir) = shared("slowstart")?;
        let gate = Arc::new(AtomicBool::new(false));
        let make: Arc<Make> = Arc::new({
            let gate = Arc::clone(&gate);
            move || {
                while !gate.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(5));
                }
                let read = Read::Field {
                    first_delay: Duration::ZERO,
                    text: EMAIL,
                };
                Ok(Box::new(Scripted { read, calls: 0 }) as Box<dyn Desktop>)
            }
        });
        let timing = Timing {
            start: Duration::from_millis(100),
            ..timing(50)
        };
        // On a thread of its own: without an end to the wait, it is the caller that hangs.
        let (answered, answer) = mpsc::channel();
        let caller = thread::spawn({
            let shared = Arc::clone(&shared);
            move || {
                let _ = answered.send(launch(&shared, make, timing).is_err());
            }
        });
        let given_up = answer.recv_timeout(Duration::from_secs(10));
        gate.store(true, Ordering::Release);
        caller.join().map_err(|_| "the caller panicked")?;
        assert_eq!(given_up, Ok(true), "it waited on");
        assert!(!shared.typed.is_active());
        // It comes up at last, and finds nobody wants it: it reads nothing.
        thread::sleep(Duration::from_millis(300));
        assert!(!shared.typed.is_active() && !shared.typed.has_values());
        Ok(())
    }

    #[test]
    fn a_read_that_hangs_makes_requests_check_whole_until_another_reader_sees() -> Result<(), String>
    {
        let (shared, _dir) = shared("hang")?;
        let gate = Arc::new(AtomicBool::new(false));
        let make = script(
            {
                let gate = Arc::clone(&gate);
                move || Read::Hang(Arc::clone(&gate))
            },
            || Read::Field {
                first_delay: Duration::from_millis(250),
                text: EMAIL,
            },
        );
        let capture = launch(&shared, make, timing(400))?;
        assert!(shared.typed.is_active());
        // The first reader hangs: nothing can be seen, so requests are checked whole.
        wait_until("the store is blind", || !shared.typed.is_active())?;
        // The second one takes over: what it reads is kept, and the store is trusted again.
        wait_until("the store sees again", || shared.typed.is_active())?;
        wait_until("the value is kept", || shared.typed.has_values())?;
        // The first one comes back late and changes nothing.
        gate.store(true, Ordering::Release);
        thread::sleep(Duration::from_millis(100));
        assert!(shared.typed.is_active() && shared.typed.has_values());
        capture.stop();
        assert!(!shared.typed.is_active());
        Ok(())
    }

    #[test]
    fn stopping_does_not_wait_for_a_reader_that_hangs() -> Result<(), String> {
        let (shared, _dir) = shared("stop")?;
        let gate = Arc::new(AtomicBool::new(false));
        let make = script(
            {
                let gate = Arc::clone(&gate);
                move || Read::Hang(Arc::clone(&gate))
            },
            || Read::Die,
        );
        let capture = launch(&shared, make, timing(40))?;
        thread::sleep(Duration::from_millis(30));
        let asked = Instant::now();
        capture.stop();
        assert!(asked.elapsed() < Duration::from_secs(5), "stop waited");
        assert!(!shared.typed.is_active());
        gate.store(true, Ordering::Release);
        Ok(())
    }

    #[test]
    fn a_capture_that_is_let_go_stops() -> Result<(), String> {
        let (shared, _dir) = shared("drop")?;
        let field = || Read::Field {
            first_delay: Duration::ZERO,
            text: EMAIL,
        };
        let capture = launch(&shared, script(field, field), timing(400))?;
        wait_until("the value is kept", || shared.typed.has_values())?;
        drop(capture);
        wait_until("the store is inactive", || !shared.typed.is_active())?;
        assert!(!shared.typed.has_values());
        Ok(())
    }

    #[test]
    fn a_reader_that_dies_is_replaced() -> Result<(), String> {
        let (shared, _dir) = shared("die")?;
        let make = script(
            || Read::Die,
            || Read::Field {
                first_delay: Duration::ZERO,
                text: EMAIL,
            },
        );
        let capture = launch(&shared, make, timing(40))?;
        wait_until("the value is kept", || shared.typed.has_values())?;
        wait_until("the store is trusted", || shared.typed.is_active())?;
        capture.stop();
        Ok(())
    }

    #[test]
    fn a_reader_that_never_gets_going_is_replaced() -> Result<(), String> {
        let (shared, _dir) = shared("never")?;
        let gate = Arc::new(AtomicBool::new(false));
        let created = AtomicUsize::new(0);
        let make: Arc<Make> = Arc::new({
            let gate = Arc::clone(&gate);
            move || {
                let read = match created.fetch_add(1, Ordering::AcqRel) {
                    // The first reader hangs in a read, and the second while it comes up.
                    0 => Read::Hang(Arc::clone(&gate)),
                    1 => {
                        while !gate.load(Ordering::Acquire) {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Read::Die
                    }
                    _ => Read::Field {
                        first_delay: Duration::ZERO,
                        text: EMAIL,
                    },
                };
                Ok(Box::new(Scripted { read, calls: 0 }) as Box<dyn Desktop>)
            }
        });
        let capture = launch(&shared, make, timing(40))?;
        wait_until("the value is kept", || shared.typed.has_values())?;
        wait_until("the store is trusted", || shared.typed.is_active())?;
        capture.stop();
        gate.store(true, Ordering::Release);
        Ok(())
    }

    #[test]
    fn readers_that_hang_are_limited() -> Result<(), String> {
        let (shared, _dir) = shared("limit")?;
        let gate = Arc::new(AtomicBool::new(false));
        let make = script(
            {
                let gate = Arc::clone(&gate);
                move || Read::Hang(Arc::clone(&gate))
            },
            {
                let gate = Arc::clone(&gate);
                move || Read::Hang(Arc::clone(&gate))
            },
        );
        let capture = launch(&shared, make, timing(30))?;
        wait_until("every worker is in use", || {
            capture.control.alive.load(Ordering::Acquire) == MAX_WORKERS
        })?;
        // No more come, however long they hang.
        thread::sleep(Duration::from_millis(300));
        assert_eq!(capture.control.alive.load(Ordering::Acquire), MAX_WORKERS);
        assert!(!shared.typed.is_active(), "blind all the while");
        let control = Arc::clone(&capture.control);
        capture.stop();
        gate.store(true, Ordering::Release);
        wait_until("the workers are gone", || {
            control.alive.load(Ordering::Acquire) == 0
        })?;
        Ok(())
    }

    #[test]
    fn highlighting_without_protection_keeps_the_store_inactive() -> Result<(), String> {
        let (shared, _dir) = shared("lamp")?;
        shared.purpose.set_mask(false);
        shared.purpose.set_highlight(Highlight::Always);
        let looks = Arc::new(AtomicUsize::new(0));
        let field = {
            let looks = Arc::clone(&looks);
            move || Read::Watching {
                looks: Arc::clone(&looks),
                text: EMAIL,
            }
        };
        let capture = launch(&shared, script(field.clone(), field), timing(400))?;
        // The reader looks at a protected field that holds an email, over and over: none of it
        // reaches the store.
        wait_until("the field was looked at", || {
            looks.load(Ordering::Acquire) >= 4
        })?;
        assert!(!shared.typed.is_active() && !shared.typed.has_values());
        // With protection on, the same field is kept.
        shared.purpose.set_mask(true);
        wait_until("the store is active", || shared.typed.is_active())?;
        wait_until("the value is kept", || shared.typed.has_values())?;
        // And off again: everything kept goes.
        shared.purpose.set_mask(false);
        wait_until("the store is inactive again", || !shared.typed.is_active())?;
        assert!(!shared.typed.has_values());
        capture.stop();
        assert!(!shared.typed.is_active());
        Ok(())
    }
}
