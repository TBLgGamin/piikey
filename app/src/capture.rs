//! Reads the focused text field: what the user types or pastes into a protected site or program,
//! and whether the field holds personal data, to outline it.
//!
//! While protection or highlighting is on, [`start`] runs a `piikey-capture` worker thread, watched
//! by a `piikey-capture-watch` supervisor (see [`watch`]). A few times a second the worker asks
//! Windows UI Automation, the interface screen readers use, for the element that has the keyboard
//! focus: one call, which returns the handful of properties the thread needs along with it.
//! Only when the focus moves to another element does it work out whether that element sits in a
//! protected page or program (and is no password field); until then nothing else is asked of the
//! system. For an element that does, and while protection is on, it reads the text of the field and,
//! when the clipboard changed, the clipboard, and hands both to [`Typed`](crate::proxy::Typed),
//! which keeps the personal data in them so the proxy can mask exactly those values in what the
//! page sends.
//!
//! The highlight ([`Purpose::highlight`](crate::proxy::Purpose::highlight)) uses the same reader.
//! In `Always` mode the text of every field in focus that is no password and not piikey's own is
//! checked for personal data a moment after it stops changing; in `Hotkey` mode the field is
//! checked when the shortcut is pressed. [`Engine::scan`](piikey::engine::Engine::scan) does the
//! checking, which keeps nothing and writes nothing to the vault. The verdict goes to the
//! [overlay](crate::highlight::Overlay), which outlines the field's rectangle on the screen.
//!
//! No browser setting or extension is needed: Chromium builds its accessibility tree by itself when
//! a UI Automation client asks for it, and its page element carries the page's address as its value.
//! Text the thread reads goes nowhere but into `Typed` and detection, and is never logged.

use std::{
    num::NonZeroU32,
    sync::{
        Arc, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use piikey::policy::{Highlight, Policy};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use uiautomation::{
    UIAutomation, UIElement, UITreeWalker,
    core::{UICacheRequest, UICondition},
    patterns::UITextPattern,
    types::{ControlType, TreeScope, UIProperty},
    variants::{Value, Variant},
};

use crate::{
    Res,
    highlight::{Mark, Overlay, Rect},
    proxy::{Purpose, Shared, Typed},
};

/// How often the focus is read while it is in a protected page or program: a paste or a message
/// sent right after typing must still find its text.
const FAST: Duration = Duration::from_millis(100);
/// How often it is read anywhere else.
const SLOW: Duration = Duration::from_millis(400);
/// Text that has not changed for this long goes to detection.
const SETTLE: Duration = Duration::from_millis(300);
/// Ancestors looked at to find the page an element is in.
const PAGE_STEPS: usize = 40;
/// Characters read from a field through its text pattern; [`Typed`] keeps less than this anyway.
const MAX_CHARS: i32 = 1 << 18;
/// Characters of a field's value from which Chromium may have cut the rest off: it keeps 10,000.
const VALUE_CUT: usize = 10_000;
/// Bytes of a field that are checked for personal data; a field with more is checked as far as
/// that, as [`Typed`] keeps no more of a text either.
const MAX_SCAN: usize = 256 << 10;
/// How long the outline that answers the shortcut stays, unless something ends it sooner.
const SHOW_FOR: Duration = Duration::from_secs(10);
/// How long the green flash that says a field holds no personal data stays.
const FLASH_FOR: Duration = Duration::from_millis(1_200);

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
}

const TIMING: Timing = Timing {
    stall: Duration::from_secs(1),
    watch: Duration::from_millis(250),
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
        self.control.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
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
    match started.recv() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err("the capture thread ended before it started".to_owned()),
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
    /// in none.
    reading: AtomicU64,
    /// Whether the store was last made active: it follows [`Purpose::mask`], protection.
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
        self.reading.store(0, Ordering::Release);
        self.seen.store(false, Ordering::Release);
        self.lost.store(false, Ordering::Release);
        self.current.fetch_add(1, Ordering::AcqRel) + 1
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
    // A press of the shortcut wakes this thread: the outline need not wait for the next look.
    shared.purpose.set_worker(thread::current());
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
    fn focus(&mut self, with_text: bool) -> Option<Vec<i32>> {
        let id = self.timed(|desktop| desktop.focus(with_text));
        // A worker that was replaced while it waited knows nothing that is true now.
        id.filter(|_| self.control.is_current(self.id))
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

    fn clipboard_text(&mut self) -> Option<String> {
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

impl Desktop for Box<dyn Desktop> {
    fn focus(&mut self, with_text: bool) -> Option<Vec<i32>> {
        (**self).focus(with_text)
    }

    fn protected(&mut self) -> bool {
        (**self).protected()
    }

    fn text(&mut self) -> Option<String> {
        (**self).text()
    }

    fn field(&mut self) -> Option<Field> {
        (**self).field()
    }

    fn bounds(&mut self) -> Option<Rect> {
        (**self).bounds()
    }

    fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
        (**self).clipboard_seq()
    }

    fn clipboard_text(&mut self) -> Option<String> {
        (**self).clipboard_text()
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

/// What the loop reads from Windows. [`Uia`] is the real one; the tests script one.
trait Desktop {
    /// Reads the element with the keyboard focus and returns what identifies it: it differs from
    /// the last one when the focus moved. `None` when nothing readable has the focus. `with_text`
    /// asks for the element's text along with it, which the caller wants when it will read that.
    fn focus(&mut self, with_text: bool) -> Option<Vec<i32>>;
    /// Whether the element [`focus`](Self::focus) returned is in a protected page or program and
    /// is no password field.
    fn protected(&mut self) -> bool;
    /// What the user has typed into that element; `None` when it is no text field, cannot be read
    /// or is read-only.
    fn text(&mut self) -> Option<String>;
    /// That element as a field to outline: where it is on the screen and what it holds. `None` when
    /// it is no text field the user can type in (a page, a read-only field, a password field),
    /// belongs to piikey itself, or is not on the screen in one piece.
    fn field(&mut self) -> Option<Field>;
    /// Where that element is on the screen now; `None` when that cannot be told.
    fn bounds(&mut self) -> Option<Rect>;
    /// Changes whenever the clipboard does; `None` when Windows will not tell.
    fn clipboard_seq(&mut self) -> Option<NonZeroU32>;
    /// The text on the clipboard; `None` when there is none or it cannot be read.
    fn clipboard_text(&mut self) -> Option<String>;
}

/// Where what was read goes.
trait Sink {
    /// Keeps the text for the next [`flush`](Self::flush).
    fn push(&self, text: String);
    /// Runs detection over everything pushed so far.
    fn flush(&self);
    /// Whether detection finds personal data in `text`, keeping nothing and writing nothing to the
    /// vault; `None` when it cannot tell.
    fn holds_pii(&self, text: &str) -> Option<bool>;
    /// Outlines the field at `field` in the colour of `mark`; asked again at every look, because
    /// the overlay lets an outline that is not asked for go.
    fn show(&self, field: Rect, mark: Mark);
    /// Takes the outline away.
    fn hide(&self);
}

/// The real sink: the store the proxy reads, flushed with the engine that is current now, the
/// engine that checks fields, and the overlay once it runs.
struct Store<'a>(&'a Shared);

impl Store<'_> {
    /// The engine that is current now. Never kept: it can be swapped under a running proxy.
    fn engine(&self) -> Arc<piikey::engine::Engine> {
        Arc::clone(&self.0.engine.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl Sink for Store<'_> {
    fn push(&self, text: String) {
        self.0.typed.push(text);
    }

    fn flush(&self) {
        // A failed flush keeps its text, and every request flushes before it reads the store.
        let _ = self.0.typed.flush(&self.engine());
    }

    fn holds_pii(&self, text: &str) -> Option<bool> {
        let found = self.engine().scan(&[text]).ok()?;
        Some(found.iter().any(|spans| !spans.is_empty()))
    }

    fn show(&self, field: Rect, mark: Mark) {
        // Before the overlay runs, or after it died, nothing is drawn.
        if let Some(overlay) = Overlay::get() {
            overlay.show(field, mark);
        }
    }

    fn hide(&self) {
        Overlay::hide_any();
    }
}

/// What the loop knows about the field it is looking at, and when to hand its text on.
struct Watcher {
    purpose: Arc<Purpose>,
    /// The element that has the focus.
    focus: Option<Vec<i32>>,
    /// That element is in a protected page or program: its text and the clipboard are read.
    protected: bool,
    /// What the field held when it was last read.
    text: String,
    /// When the field last changed, while what it held has been pushed but not yet flushed.
    pushed: Option<Instant>,
    /// The clipboard as last seen.
    clipboard: Option<NonZeroU32>,
    /// Protection as last seen: when it changes, whether the element is protected is judged afresh.
    masking: bool,
    /// The highlight mode as last seen: when it changes, the outline starts over.
    mode: Highlight,
    outline: Outline,
}

// A watcher of a purpose that masks and does not highlight: capture as it was before highlighting.
#[cfg(test)]
impl Default for Watcher {
    fn default() -> Self {
        Self::new(Arc::default())
    }
}

impl Watcher {
    fn new(purpose: Arc<Purpose>) -> Self {
        Self {
            focus: None,
            protected: false,
            text: String::new(),
            pushed: None,
            clipboard: None,
            masking: purpose.mask(),
            mode: purpose.highlight(),
            outline: Outline::new(purpose.presses()),
            purpose,
        }
    }

    /// How long to wait before the next [`tick`](Self::tick).
    fn period(&self) -> Duration {
        if self.protected || self.mode == Highlight::Always || self.outline.up.is_some() {
            FAST
        } else {
            SLOW
        }
    }

    /// Whether the shortcut was pressed since the last look: the worker does not wait for it.
    fn pressed(&self) -> bool {
        self.purpose.presses() != self.outline.presses
    }

    /// One look at the focus. Text is pushed as soon as it changes, so a request sent a moment
    /// later finds it; detection runs once the text has been still for [`SETTLE`], when it is
    /// cleared (a chat box empties as its message is sent), when the focus leaves it, and for a
    /// paste at once. Then the outline of the field is brought up to date.
    fn tick(&mut self, now: Instant, desktop: &mut impl Desktop, sink: &impl Sink) {
        let (mask, mode) = (self.purpose.mask(), self.purpose.highlight());
        if mask != self.masking {
            self.masking = mask;
            self.leave(sink);
        }
        if mode != self.mode {
            self.mode = mode;
            // Another mode starts afresh: its pause is not the old one's.
            self.purpose.set_paused(false);
            self.outline.end(sink);
        }
        // The value and the place of the element come with it when either use will read them.
        let Some(id) = desktop.focus(self.protected || mode == Highlight::Always) else {
            self.leave(sink);
            return;
        };
        if self.focus.as_ref() != Some(&id) {
            self.leave(sink);
            self.protected = mask && desktop.protected();
            self.focus = Some(id);
        }
        if self.protected {
            self.read(now, desktop, sink);
        }
        self.outline.look(now, mode, desktop, sink, &self.purpose);
    }

    /// Hands what was typed or pasted into a protected element on.
    fn read(&mut self, now: Instant, desktop: &mut impl Desktop, sink: &impl Sink) {
        if let Some(text) = desktop.text() {
            self.typed(now, text, sink);
        }
        self.pasted(desktop, sink);
        if self
            .pushed
            .is_some_and(|at| now.saturating_duration_since(at) >= SETTLE)
        {
            self.pushed = None;
            sink.flush();
        }
    }

    /// The focus left its element: what was typed there is read now, the outline goes, and the
    /// element is forgotten.
    fn leave(&mut self, sink: &impl Sink) {
        self.focus = None;
        self.protected = false;
        self.text.clear();
        if self.pushed.take().is_some() {
            sink.flush();
        }
        self.outline.end(sink);
    }

    fn typed(&mut self, now: Instant, text: String, sink: &impl Sink) {
        if text == self.text {
            return;
        }
        if text.trim().is_empty() {
            self.text = text;
            if self.pushed.take().is_some() {
                sink.flush();
            }
            return;
        }
        sink.push(text.clone());
        self.text = text;
        self.pushed = Some(now);
    }

    fn pasted(&mut self, desktop: &mut impl Desktop, sink: &impl Sink) {
        let Some(seq) = desktop.clipboard_seq() else {
            return;
        };
        if self.clipboard == Some(seq) {
            return;
        }
        self.clipboard = Some(seq);
        if let Some(text) = desktop.clipboard_text() {
            // The clipboard keeps Windows line ends; a page has only `\n`.
            sink.push(text.replace("\r\n", "\n"));
            sink.flush();
            self.pushed = None;
        }
    }
}

/// A text field the user can type in, as the outline sees it.
struct Field {
    /// Where it is on the screen.
    rect: Rect,
    /// What it holds.
    text: String,
}

/// The part of `text` that is checked for personal data.
fn checked(text: &str) -> &str {
    &text[..text.floor_char_boundary(MAX_SCAN)]
}

/// What the loop knows about the outline of the field in focus.
struct Outline {
    /// What the field held when it was last looked at; only [`Highlight::Always`] reads it at every
    /// look.
    text: String,
    /// When `text` last changed, until it has been checked.
    changed: Option<Instant>,
    /// Whether the field held personal data when it was last checked.
    pii: bool,
    /// The outline that is up.
    up: Option<Up>,
    /// Presses of the shortcut taken in so far.
    presses: u64,
}

/// An outline that is up.
struct Up {
    mark: Mark,
    /// When it goes by itself; `None` for the one that stays as long as the field holds personal
    /// data.
    until: Option<Instant>,
}

impl Outline {
    fn new(presses: u64) -> Self {
        Self {
            text: String::new(),
            changed: None,
            pii: false,
            up: None,
            presses,
        }
    }

    /// Takes the outline away and forgets what was known of the field.
    fn end(&mut self, sink: &impl Sink) {
        self.text.clear();
        self.changed = None;
        self.pii = false;
        if self.up.take().is_some() {
            sink.hide();
        }
    }

    /// Brings the outline of the field in focus up to date.
    ///
    /// - [`Highlight::Always`]: the field is checked once its text has been still for [`SETTLE`]
    ///   and outlined while it holds personal data. The shortcut pauses this and brings it back.
    /// - [`Highlight::Hotkey`]: the shortcut checks the field and outlines it for [`SHOW_FOR`], or
    ///   flashes it green for [`FLASH_FOR`] when it holds none; pressed again, the outline goes.
    ///
    /// The outline is shown again at every look, so that it follows a window that moves.
    fn look(
        &mut self,
        now: Instant,
        mode: Highlight,
        desktop: &mut impl Desktop,
        sink: &impl Sink,
        purpose: &Purpose,
    ) {
        // Every mode takes the presses in, so one from before a switch is not acted on after it.
        let presses = purpose.presses();
        let odd = presses.wrapping_sub(self.presses) % 2 == 1;
        self.presses = presses;
        match mode {
            Highlight::Off => {}
            Highlight::Always => self.always(now, odd, desktop, sink, purpose),
            Highlight::Hotkey => self.hotkey(now, odd, desktop, sink),
        }
    }

    fn always(
        &mut self,
        now: Instant,
        odd: bool,
        desktop: &mut impl Desktop,
        sink: &impl Sink,
        purpose: &Purpose,
    ) {
        if odd {
            // The shortcut pauses the outline, and brings it back.
            purpose.set_paused(!purpose.paused());
            self.end(sink);
        }
        if purpose.paused() {
            return;
        }
        let Some(Field { rect, text }) = desktop.field() else {
            self.end(sink);
            return;
        };
        if text != self.text {
            self.text = text;
            self.changed = Some(now);
        }
        if self.text.trim().is_empty() {
            self.changed = None;
            self.pii = false;
        } else if self
            .changed
            .is_some_and(|at| now.saturating_duration_since(at) >= SETTLE)
        {
            self.changed = None;
            // A check that failed keeps the verdict of the last one.
            if let Some(found) = sink.holds_pii(checked(&self.text)) {
                self.pii = found;
            }
        }
        if self.pii {
            sink.show(rect, Mark::Pii);
            self.up = Some(Up {
                mark: Mark::Pii,
                until: None,
            });
        } else if self.up.take().is_some() {
            sink.hide();
        }
    }

    fn hotkey(&mut self, now: Instant, odd: bool, desktop: &mut impl Desktop, sink: &impl Sink) {
        if odd {
            if self.up.take().is_some() {
                // Pressed again: it goes.
                sink.hide();
                return;
            }
            let Some(Field { rect, text }) = desktop.field() else {
                return;
            };
            let (mark, stays) = match sink.holds_pii(checked(&text)) {
                Some(true) => (Mark::Pii, SHOW_FOR),
                Some(false) => (Mark::Clean, FLASH_FOR),
                None => return,
            };
            sink.show(rect, mark);
            self.up = Some(Up {
                mark,
                until: Some(now + stays),
            });
            return;
        }
        let Some((mark, until)) = self.up.as_ref().map(|up| (up.mark, up.until)) else {
            return;
        };
        if until.is_some_and(|end| now >= end) {
            self.end(sink);
        } else if let Some(rect) = desktop.bounds() {
            sink.show(rect, mark);
        } else {
            self.end(sink);
        }
    }
}

/// The real desktop: UI Automation and the clipboard.
struct Uia {
    shared: Arc<Shared>,
    automation: UIAutomation,
    /// The control view: what a screen reader walks.
    walker: UITreeWalker,
    /// What is asked of the focused element.
    focus: UICacheRequest,
    /// The same with the element's value and place, for while a protected element has the focus, or
    /// the highlight reads every field in focus.
    focus_value: UICacheRequest,
    /// What is asked of the ancestors walked to find the page.
    ancestors: UICacheRequest,
    /// Matches text fields.
    edits: UICondition,
    /// The element that has the focus.
    current: Option<Current>,
    /// The address bar of the last browser window that needed one.
    address_bar: Option<AddressBar>,
}

/// The focused element and what was asked of it.
struct Current {
    element: UIElement,
    /// Its value and its rectangle came with it.
    value_cached: bool,
    /// Whether [`Desktop::text`] has looked, and what it found: a look costs a call into the other
    /// program for some elements, and protection and highlight may both ask.
    text_read: bool,
    text: Option<String>,
}

/// A browser window's address bar, for browsers whose page element does not carry its address.
struct AddressBar {
    /// Identifies the window.
    window: Vec<i32>,
    edit: UIElement,
}

impl Uia {
    fn new(shared: Arc<Shared>) -> uiautomation::Result<Self> {
        let automation = UIAutomation::new()?;
        let request = |properties: &[UIProperty]| -> uiautomation::Result<UICacheRequest> {
            let request = automation.create_cache_request()?;
            for &property in properties {
                request.add_property(property)?;
            }
            Ok(request)
        };
        let focus_properties = [
            UIProperty::RuntimeId,
            UIProperty::ProcessId,
            UIProperty::ControlType,
            UIProperty::IsPassword,
            UIProperty::IsValuePatternAvailable,
            UIProperty::ValueIsReadOnly,
            UIProperty::IsTextPatternAvailable,
        ];
        let focus = request(&focus_properties)?;
        let focus_value = request(
            &[
                &focus_properties[..],
                &[UIProperty::ValueValue, UIProperty::BoundingRectangle],
            ]
            .concat(),
        )?;
        let ancestors = request(&[
            UIProperty::RuntimeId,
            UIProperty::ControlType,
            UIProperty::ValueValue,
        ])?;
        let edits = automation.create_property_condition(
            UIProperty::ControlType,
            Variant::from(ControlType::Edit as i32),
            None,
        )?;
        Ok(Self {
            shared,
            walker: automation.get_control_view_walker()?,
            automation,
            focus,
            focus_value,
            ancestors,
            edits,
            current: None,
            address_bar: None,
        })
    }

    /// The host of the page `element` is in: the address its page element carries. `None` outside
    /// a page, and for pages that are not on a web host.
    fn page_host(&mut self, element: &UIElement) -> Option<String> {
        let mut below = element.clone();
        // The page was found but says nothing about its address.
        let mut nameless = false;
        for _ in 0..PAGE_STEPS {
            let parent = self
                .walker
                .get_parent_build_cache(&below, &self.ancestors)
                .ok()?;
            match parent.get_cached_control_type().ok() {
                Some(ControlType::Document) if !nameless => {
                    match cached_string(&parent, UIProperty::ValueValue) {
                        Some(address) if !address.trim().is_empty() => return host_of(&address),
                        _ => nameless = true,
                    }
                }
                Some(ControlType::Window) if nameless => return self.address_bar_host(&parent),
                _ => {}
            }
            below = parent;
        }
        None
    }

    /// The host in the first text field of a browser window: its address bar.
    fn address_bar_host(&mut self, window: &UIElement) -> Option<String> {
        let id = runtime_id(window)?;
        if let Some(bar) = self.address_bar.as_ref().filter(|bar| bar.window == id)
            && let Some(host) = value_host(&bar.edit)
        {
            return Some(host);
        }
        let edit = window
            .find_first(TreeScope::Descendants, &self.edits)
            .ok()?;
        let host = value_host(&edit)?;
        self.address_bar = Some(AddressBar { window: id, edit });
        Some(host)
    }
}

impl Desktop for Uia {
    fn focus(&mut self, with_text: bool) -> Option<Vec<i32>> {
        self.current = None;
        let request = if with_text {
            &self.focus_value
        } else {
            &self.focus
        };
        let element = self
            .automation
            .get_focused_element_build_cache(request)
            .ok()?;
        let id = runtime_id(&element)?;
        self.current = Some(Current {
            element,
            value_cached: with_text,
            text_read: false,
            text: None,
        });
        Some(id)
    }

    fn protected(&mut self) -> bool {
        let Some(element) = self.current.as_ref().map(|c| c.element.clone()) else {
            return false;
        };
        // Unreadable counts as a password: nothing is lost by leaving a field alone.
        if cached_bool(&element, UIProperty::IsPassword).unwrap_or(true) {
            return false;
        }
        let policy = self
            .shared
            .policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !policy.enabled {
            return false;
        }
        let host = if policy.sites.is_empty() {
            None
        } else {
            self.page_host(&element)
        };
        if let Some(host) = &host
            && policy.intercepts(host, None)
        {
            return true;
        }
        if policy.programs.is_empty() {
            return false;
        }
        let exe = element
            .get_cached_process_id()
            .ok()
            .and_then(|pid| u32::try_from(pid).ok())
            .and_then(exe_of);
        policy.intercepts(host.as_deref().unwrap_or_default(), exe.as_deref())
    }

    fn text(&mut self) -> Option<String> {
        let current = self.current.as_mut()?;
        if !current.text_read {
            current.text_read = true;
            current.text = read_text(current);
        }
        current.text.clone()
    }

    fn field(&mut self) -> Option<Field> {
        let (element, cached) = self
            .current
            .as_ref()
            .map(|current| (current.element.clone(), current.value_cached))?;
        // Unreadable counts as a password: nothing is lost by leaving a field alone, and the text of
        // one is not even read.
        let password = cached_bool(&element, UIProperty::IsPassword).unwrap_or(true);
        let own = element
            .get_cached_process_id()
            .ok()
            .and_then(|pid| u32::try_from(pid).ok())
            == Some(std::process::id());
        let hidden = password || own;
        let text = if hidden { None } else { self.text() };
        let rect = if hidden {
            None
        } else {
            bounds_of(&element, cached)
        };
        field_of(password, own, text, rect)
    }

    fn bounds(&mut self) -> Option<Rect> {
        let current = self.current.as_ref()?;
        bounds_of(&current.element, current.value_cached)
    }

    fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
        clipboard_win::raw::seq_num()
    }

    fn clipboard_text(&mut self) -> Option<String> {
        clipboard_win::get_clipboard_string().ok()
    }
}

/// What the user typed into the focused element: its value, or its text pattern for an editable
/// block. `None` when it is no text field, cannot be read, or is read-only.
fn read_text(current: &Current) -> Option<String> {
    let element = &current.element;
    if cached_bool(element, UIProperty::IsValuePatternAvailable) == Some(true) {
        // A page's address and a read-only field are not something the user typed.
        if cached_bool(element, UIProperty::ValueIsReadOnly) != Some(false) {
            return None;
        }
        let value = if current.value_cached {
            element.get_cached_property_value(UIProperty::ValueValue)
        } else {
            element.get_property_value(UIProperty::ValueValue)
        };
        let value = value.ok()?.get_string().ok()?;
        if value.chars().take(VALUE_CUT).count() < VALUE_CUT {
            return Some(value);
        }
        // Chromium cuts the value of a long field short; its text pattern has all of it.
        return Some(
            range_text(element)
                .filter(|text| text.len() > value.len())
                .unwrap_or(value),
        );
    }
    // An editable block (`contenteditable`) has only a text pattern. A page element has one too,
    // and holds the whole page.
    if element.get_cached_control_type().ok() == Some(ControlType::Document)
        || cached_bool(element, UIProperty::IsTextPatternAvailable) != Some(true)
    {
        return None;
    }
    range_text(element)
}

/// The field the outline is about, from what was read of the focused element: none for a password
/// field, one of piikey's own windows, an element that holds no text the user can type, or one
/// that has no place on the screen.
fn field_of(password: bool, own: bool, text: Option<String>, rect: Option<Rect>) -> Option<Field> {
    if password || own {
        return None;
    }
    Some(Field {
        rect: rect?,
        text: text?,
    })
}

/// Where `element` is on the screen: from what came with it, or else asked for now.
fn bounds_of(element: &UIElement, cached: bool) -> Option<Rect> {
    let rect = if cached {
        element.get_cached_bounding_rectangle()
    } else {
        element.get_bounding_rectangle()
    }
    .ok()?;
    Rect::field(
        rect.get_left(),
        rect.get_top(),
        rect.get_right(),
        rect.get_bottom(),
    )
}

/// What identifies `element` among the elements on the desktop: the id that came with it, or else
/// the live one.
fn runtime_id(element: &UIElement) -> Option<Vec<i32>> {
    let cached = element
        .get_cached_property_value(UIProperty::RuntimeId)
        .ok()
        .and_then(|id| id.get_value().ok());
    match cached {
        Some(Value::ArrayI4(id)) => Some(id),
        _ => element.get_runtime_id().ok(),
    }
}

/// The text of `element` through its text pattern.
fn range_text(element: &UIElement) -> Option<String> {
    element
        .get_pattern::<UITextPattern>()
        .ok()?
        .get_document_range()
        .ok()?
        .get_text(MAX_CHARS)
        .ok()
}

fn cached_bool(element: &UIElement, property: UIProperty) -> Option<bool> {
    let value = element.get_cached_property_value(property).ok()?;
    let flag: Result<bool, _> = (&value).try_into();
    flag.ok()
}

fn cached_string(element: &UIElement, property: UIProperty) -> Option<String> {
    element
        .get_cached_property_value(property)
        .ok()?
        .get_string()
        .ok()
}

/// The host in the value of `element`, which is an address bar or a page element.
fn value_host(element: &UIElement) -> Option<String> {
    element
        .get_property_value(UIProperty::ValueValue)
        .ok()?
        .get_string()
        .ok()
        .and_then(|address| host_of(&address))
}

/// The host of a page's address, as a page element carries it (`https://chat.openai.com/c/1?x`) or
/// an address bar shows it (`chat.openai.com/c/1`). `None` for what is not on a web host:
/// `chrome://settings`, `file:///C:/a.html`, `about:blank`, or text that is no address.
fn host_of(address: &str) -> Option<String> {
    Policy::parse_site(address).filter(|host| !host.starts_with('*'))
}

/// The lowercase name of the program running as process `pid`.
fn exe_of(pid: u32) -> Option<String> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system
        .process(pid)
        .map(|process| process.name().to_string_lossy().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        sync::RwLock,
    };

    use piikey::engine::Engine;

    use super::*;
    use crate::ledger::Ledger;

    /// A desktop the test scripts: what has the focus, its text and the clipboard.
    #[derive(Default)]
    struct Fake {
        /// The element with the focus and whether it is protected.
        focus: Option<(Vec<i32>, bool)>,
        text: Option<String>,
        seq: Option<NonZeroU32>,
        clipboard: Option<String>,
        /// The element as a field to outline: where it is and what it holds.
        field: Option<(Rect, String)>,
        /// The element is a password field.
        password: bool,
        /// `with_text` of every `focus` call.
        asked: Vec<bool>,
        protected_calls: usize,
        text_calls: usize,
        clipboard_reads: usize,
        field_calls: usize,
        bounds_calls: usize,
    }

    impl Fake {
        fn on(id: i32, protected: bool) -> Self {
            Self {
                focus: Some((vec![42, id], protected)),
                ..Self::default()
            }
        }

        fn types(&mut self, text: &str) {
            self.text = Some(text.to_owned());
        }

        /// The element is a field at `rect` holding `text`.
        fn shows(&mut self, rect: Rect, text: &str) {
            self.field = Some((rect, text.to_owned()));
        }

        fn copies(&mut self, seq: u32, text: &str) {
            self.seq = NonZeroU32::new(seq);
            self.clipboard = Some(text.to_owned());
        }
    }

    impl Desktop for Fake {
        fn focus(&mut self, with_text: bool) -> Option<Vec<i32>> {
            self.asked.push(with_text);
            self.focus.as_ref().map(|(id, _)| id.clone())
        }

        fn protected(&mut self) -> bool {
            self.protected_calls += 1;
            self.focus.as_ref().is_some_and(|&(_, protected)| protected)
        }

        fn text(&mut self) -> Option<String> {
            self.text_calls += 1;
            self.text.clone()
        }

        fn field(&mut self) -> Option<Field> {
            self.field_calls += 1;
            let (rect, text) = self.field.clone()?;
            // As the real desktop does: a password field is none.
            field_of(self.password, false, Some(text), Some(rect))
        }

        fn bounds(&mut self) -> Option<Rect> {
            self.bounds_calls += 1;
            self.field.as_ref().map(|&(rect, _)| rect)
        }

        fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
            self.seq
        }

        fn clipboard_text(&mut self) -> Option<String> {
            self.clipboard_reads += 1;
            self.clipboard.clone()
        }
    }

    /// Records what reached the store and the overlay, in order. It checks fields for personal
    /// data with the detection of a real store, when it has one.
    #[derive(Default)]
    struct Log {
        lines: RefCell<Vec<String>>,
        store: Option<Arc<Shared>>,
        /// Texts checked for personal data.
        scans: Cell<usize>,
    }

    impl Log {
        fn with(shared: &Arc<Shared>) -> Self {
            Self {
                store: Some(Arc::clone(shared)),
                ..Self::default()
            }
        }

        fn take(&self) -> Vec<String> {
            std::mem::take(&mut self.lines.borrow_mut())
        }
    }

    impl Sink for Log {
        fn push(&self, text: String) {
            self.lines.borrow_mut().push(format!("push {text}"));
        }

        fn flush(&self) {
            self.lines.borrow_mut().push("flush".to_owned());
        }

        fn holds_pii(&self, text: &str) -> Option<bool> {
            self.scans.set(self.scans.get() + 1);
            Store(self.store.as_ref()?).holds_pii(text)
        }

        fn show(&self, field: Rect, mark: Mark) {
            self.lines.borrow_mut().push(show(mark, field));
        }

        fn hide(&self) {
            self.lines.borrow_mut().push("hide".to_owned());
        }
    }

    /// What [`Log`] writes for an outline.
    fn show(mark: Mark, field: Rect) -> String {
        format!(
            "show {mark:?} ({},{},{},{})",
            field.left, field.top, field.right, field.bottom
        )
    }

    /// A text field at the top of the screen.
    const FIELD: Rect = Rect {
        left: 100,
        top: 200,
        right: 500,
        bottom: 240,
    };

    /// A purpose that only outlines, the way `mode` says: no protection.
    fn lamp(mode: Highlight) -> Arc<Purpose> {
        let purpose = Arc::new(Purpose::default());
        purpose.set_mask(false);
        purpose.set_highlight(mode);
        purpose
    }

    fn after(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn a_field_outside_protected_pages_is_never_read() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, false), Log::default(), Watcher::default());
        desktop.types("jan.jansen@acme.nl");
        desktop.copies(7, "NL91ABNA0417164300");
        let start = Instant::now();
        for step in 0..5 {
            watcher.tick(after(start, step * 400), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!((desktop.text_calls, desktop.clipboard_reads), (0, 0));
        assert_eq!(desktop.protected_calls, 1, "decided once per element");
        assert_eq!(watcher.period(), SLOW);
    }

    #[test]
    fn typed_text_is_pushed_at_once_and_detected_when_it_stops_changing() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.types("mail jan");
        watcher.tick(start, &mut desktop, &log);
        desktop.types("mail jan.jansen@acme.nl");
        watcher.tick(after(start, 100), &mut desktop, &log);
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(
            log.take(),
            ["push mail jan", "push mail jan.jansen@acme.nl"]
        );
        watcher.tick(after(start, 399), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "still settling");
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(log.take(), ["flush"]);
        watcher.tick(after(start, 900), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "one flush per change");
        assert_eq!(watcher.period(), FAST);
    }

    #[test]
    fn the_value_is_asked_for_only_once_the_element_is_known_to_be_protected() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(desktop.asked, [false, true]);
    }

    #[test]
    fn a_cleared_field_is_detected_at_once() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.types("ik ben Jeroen de Vries");
        watcher.tick(start, &mut desktop, &log);
        // The message was sent and the box emptied, long before the text had settled.
        desktop.types("");
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), ["push ik ben Jeroen de Vries", "flush"]);
        watcher.tick(after(start, 200), &mut desktop, &log);
        desktop.types("  \n");
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "blank text is not text");
    }

    #[test]
    fn moving_the_focus_detects_what_was_typed_and_starts_over() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.types("Zoë Müller");
        watcher.tick(start, &mut desktop, &log);
        desktop.focus = Some((vec![42, 2], true));
        watcher.tick(after(start, 100), &mut desktop, &log);
        // The new field holds the same words: it is another field, so they are read again.
        assert_eq!(log.take(), ["push Zoë Müller", "flush", "push Zoë Müller"]);
        assert_eq!(desktop.protected_calls, 2);
        desktop.focus = Some((vec![42, 3], false));
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(log.take(), ["flush"]);
        assert_eq!(watcher.period(), SLOW);
    }

    #[test]
    fn a_paste_is_pushed_and_detected_once_per_clipboard_change() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.copies(5, "NL91ABNA0417164300\r\nZoë");
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), ["push NL91ABNA0417164300\nZoë", "flush"]);
        assert_eq!(desktop.clipboard_reads, 1);
        desktop.copies(6, "jan.jansen@acme.nl");
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(log.take(), ["push jan.jansen@acme.nl", "flush"]);
        // Windows will not say what the clipboard holds: nothing to read, nothing to wait for.
        desktop.seq = None;
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
    }

    #[test]
    fn a_clipboard_without_text_is_skipped() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        desktop.seq = NonZeroU32::new(9);
        watcher.tick(Instant::now(), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(desktop.clipboard_reads, 1);
    }

    #[test]
    fn a_field_that_cannot_be_read_pushes_nothing() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 500), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(desktop.text_calls, 2);
    }

    #[test]
    fn losing_the_focus_detects_what_is_pending_and_waits_slowly() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.types("iban NL91ABNA0417164300");
        watcher.tick(start, &mut desktop, &log);
        desktop.focus = None;
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), ["push iban NL91ABNA0417164300", "flush"]);
        assert_eq!(watcher.period(), SLOW);
        // Back on a protected element: decided afresh.
        desktop.focus = Some((vec![42, 1], true));
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(desktop.protected_calls, 2);
    }

    #[test]
    fn addresses_give_their_host() {
        assert_eq!(
            host_of("https://Chat.OpenAI.com/c/abc?x=1#y").as_deref(),
            Some("chat.openai.com")
        );
        assert_eq!(
            host_of("http://localhost:3000/").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            host_of("https://user:pw@example.com:8443/p").as_deref(),
            Some("example.com")
        );
        // What an address bar shows has no scheme.
        assert_eq!(host_of("claude.ai/chat/1").as_deref(), Some("claude.ai"));
        assert_eq!(host_of("192.168.1.1/admin").as_deref(), Some("192.168.1.1"));
        for other in [
            "",
            "chrome://settings/",
            "edge://sync-confirmation-dialog/",
            "file:///C:/page.html",
            "about:blank",
            "view-source:https://example.com/",
            "two words typed in the address bar",
            "*.example.com",
        ] {
            assert_eq!(host_of(other), None, "{other}");
        }
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

    /// A vault folder that goes away with the test.
    struct Folder(std::path::PathBuf);

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A store over a real engine, with protection on but nothing protected.
    fn shared(tag: &str) -> Result<(Arc<Shared>, Folder), String> {
        let dir = std::env::temp_dir().join(format!("piikey-capture-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let folder = Folder(dir);
        let engine = Engine::open(&folder.0.join("vault.pkv")).map_err(|e| e.to_string())?;
        let shared = Arc::new(Shared {
            engine: RwLock::new(Arc::new(engine)),
            policy: RwLock::new(Policy {
                enabled: true,
                ..Policy::default()
            }),
            ledger: Ledger::default(),
            typed: Typed::new(),
            purpose: Arc::default(),
        });
        Ok((shared, folder))
    }

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
        fn focus(&mut self, _with_text: bool) -> Option<Vec<i32>> {
            self.calls += 1;
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
                    Some(vec![42, 1])
                }
                Read::Watching { looks, .. } => {
                    looks.fetch_add(1, Ordering::AcqRel);
                    Some(vec![42, 1])
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

        fn clipboard_text(&mut self) -> Option<String> {
            None
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

    const EMAIL: &str = "mail jan.jansen@acme.nl";

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
        match start(&shared) {
            Ok(capture) => {
                assert!(shared.typed.is_active());
                capture.stop();
            }
            // No UI Automation here: nothing starts, and requests are checked whole.
            Err(error) => assert!(
                error.starts_with("UI Automation is not available"),
                "{error}"
            ),
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
    fn without_highlighting_no_field_is_read_for_an_outline() {
        let (mut desktop, log) = (Fake::on(1, false), Log::default());
        let mut watcher = Watcher::new(lamp(Highlight::Off));
        desktop.shows(FIELD, EMAIL);
        let start = Instant::now();
        for step in 0..5 {
            watcher.tick(after(start, step * 400), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!((desktop.field_calls, desktop.bounds_calls), (0, 0));
        assert_eq!(desktop.asked, [false; 5], "not even the value is asked for");
        assert_eq!(watcher.period(), SLOW);
    }

    #[test]
    fn always_outlines_a_field_that_holds_personal_data() -> Result<(), String> {
        let (shared, _dir) = shared("always")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        let outline = show(Mark::Pii, FIELD);
        let start = Instant::now();
        desktop.shows(FIELD, EMAIL);
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 299), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "the text is settling");
        assert_eq!(
            desktop.asked,
            [true, true],
            "the value comes with the focus"
        );
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), std::slice::from_ref(&outline));
        // It is shown again at every look, because windows move, but checked once.
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(log.take(), std::slice::from_ref(&outline));
        assert_eq!(log.scans.get(), 1);
        assert_eq!(watcher.period(), FAST);
        // More typing: the outline stays while the new text settles.
        desktop.shows(FIELD, "mail jan.jansen@acme.nl en nog iets");
        watcher.tick(after(start, 500), &mut desktop, &log);
        assert_eq!(log.take(), std::slice::from_ref(&outline));
        // The email is deleted: once the text has settled the outline goes.
        desktop.shows(FIELD, "hallo");
        watcher.tick(after(start, 600), &mut desktop, &log);
        watcher.tick(after(start, 899), &mut desktop, &log);
        assert_eq!(log.take(), [outline.clone(), outline], "the old verdict");
        watcher.tick(after(start, 900), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        assert_eq!(log.scans.get(), 2);
        // Nothing more is said while the field holds nothing.
        watcher.tick(after(start, 1_000), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn a_field_without_personal_data_gets_no_outline() -> Result<(), String> {
        let (shared, _dir) = shared("clean")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, "goedemorgen allemaal");
        let start = Instant::now();
        for step in 0..8 {
            watcher.tick(after(start, step * 100), &mut desktop, &log);
        }
        assert_eq!(
            log.take(),
            Vec::<String>::new(),
            "no bars for a clean field"
        );
        assert_eq!(log.scans.get(), 1, "but it was checked");
        Ok(())
    }

    #[test]
    fn an_empty_field_is_not_even_checked() {
        let (mut desktop, log) = (Fake::on(1, false), Log::default());
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        let start = Instant::now();
        for (step, text) in (0..).zip(["", "  \n", ""]) {
            desktop.shows(FIELD, text);
            watcher.tick(after(start, 400 * step), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(log.scans.get(), 0);
    }

    #[test]
    fn hotkey_mode_outlines_nothing_until_the_shortcut_is_pressed() -> Result<(), String> {
        let (shared, _dir) = shared("hotkey")?;
        let purpose = lamp(Highlight::Hotkey);
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        let start = Instant::now();
        desktop.shows(FIELD, EMAIL);
        for step in 0..4 {
            watcher.tick(after(start, step * 400), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!((desktop.field_calls, log.scans.get()), (0, 0), "not read");
        assert_eq!(desktop.asked, [false; 4]);
        assert_eq!(watcher.period(), SLOW);
        assert!(!watcher.pressed());

        purpose.press();
        assert!(watcher.pressed(), "the worker does not wait for it");
        watcher.tick(after(start, 2_000), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        assert!(!watcher.pressed());
        assert_eq!(watcher.period(), FAST);

        // A window that moves: the outline follows, without reading the field again.
        let moved = Rect {
            left: 160,
            top: 260,
            right: 560,
            bottom: 300,
        };
        desktop.shows(moved, EMAIL);
        watcher.tick(after(start, 2_100), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, moved)]);
        assert_eq!((desktop.field_calls, log.scans.get()), (1, 1));
        // It stays for ten seconds.
        watcher.tick(after(start, 11_999), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, moved)]);
        watcher.tick(after(start, 12_000), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        assert_eq!(watcher.period(), SLOW);
        Ok(())
    }

    #[test]
    fn the_shortcut_flashes_a_field_without_personal_data_green_for_a_moment() -> Result<(), String>
    {
        let (shared, _dir) = shared("flash")?;
        let purpose = lamp(Highlight::Hotkey);
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        let start = Instant::now();
        desktop.shows(FIELD, "goedemorgen allemaal");
        purpose.press();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Clean, FIELD)]);
        watcher.tick(after(start, 1_199), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Clean, FIELD)]);
        watcher.tick(after(start, 1_200), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        Ok(())
    }

    #[test]
    fn pressing_the_shortcut_again_takes_the_outline_away() -> Result<(), String> {
        let (shared, _dir) = shared("again")?;
        let purpose = lamp(Highlight::Hotkey);
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        let start = Instant::now();
        desktop.shows(FIELD, EMAIL);
        purpose.press();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        purpose.press();
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(desktop.field_calls, 1, "the second press read nothing");
        // And a third brings it back.
        purpose.press();
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        Ok(())
    }

    #[test]
    fn the_outline_goes_when_the_focus_moves() -> Result<(), String> {
        for (mode, tag) in [(Highlight::Always, "move-a"), (Highlight::Hotkey, "move-h")] {
            let (shared, _dir) = shared(tag)?;
            let purpose = lamp(mode);
            let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
            let mut watcher = Watcher::new(Arc::clone(&purpose));
            let start = Instant::now();
            desktop.shows(FIELD, EMAIL);
            if mode == Highlight::Hotkey {
                purpose.press();
            }
            watcher.tick(start, &mut desktop, &log);
            watcher.tick(after(start, 300), &mut desktop, &log);
            let lines = log.take();
            assert!(
                lines.last() == Some(&show(Mark::Pii, FIELD)),
                "{mode:?}: {lines:?}"
            );
            desktop.focus = Some((vec![42, 2], false));
            watcher.tick(after(start, 400), &mut desktop, &log);
            assert_eq!(log.take(), ["hide"], "{mode:?}");
            desktop.focus = None;
            watcher.tick(after(start, 500), &mut desktop, &log);
            assert_eq!(log.take(), Vec::<String>::new(), "{mode:?}");
        }
        Ok(())
    }

    #[test]
    fn in_always_mode_the_shortcut_pauses_and_resumes_the_outline() -> Result<(), String> {
        let (shared, _dir) = shared("pause")?;
        let purpose = lamp(Highlight::Always);
        let changes = Arc::new(AtomicUsize::new(0));
        purpose.on_pause({
            let changes = Arc::clone(&changes);
            move || {
                changes.fetch_add(1, Ordering::AcqRel);
            }
        });
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        let start = Instant::now();
        desktop.shows(FIELD, EMAIL);
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);

        purpose.press();
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        assert!(purpose.paused());
        assert_eq!(changes.load(Ordering::Acquire), 1);
        // Paused: nothing is read, checked or shown.
        let reads = desktop.field_calls;
        watcher.tick(after(start, 500), &mut desktop, &log);
        watcher.tick(after(start, 900), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(desktop.field_calls, reads);

        purpose.press();
        watcher.tick(after(start, 1_000), &mut desktop, &log);
        assert!(!purpose.paused());
        assert_eq!(changes.load(Ordering::Acquire), 2);
        assert_eq!(
            log.take(),
            Vec::<String>::new(),
            "the field is checked again"
        );
        watcher.tick(after(start, 1_300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        Ok(())
    }

    #[test]
    fn changing_the_mode_takes_the_outline_away_and_ends_the_pause() -> Result<(), String> {
        let (shared, _dir) = shared("mode")?;
        let purpose = lamp(Highlight::Always);
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        let start = Instant::now();
        desktop.shows(FIELD, EMAIL);
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        purpose.set_highlight(Highlight::Off);
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        watcher.tick(after(start, 800), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "off is off");

        // A pause belongs to the mode it was made in.
        purpose.set_highlight(Highlight::Always);
        purpose.press();
        watcher.tick(after(start, 900), &mut desktop, &log);
        assert!(purpose.paused());
        purpose.set_highlight(Highlight::Hotkey);
        watcher.tick(after(start, 1_000), &mut desktop, &log);
        assert!(!purpose.paused());
        Ok(())
    }

    #[test]
    fn what_is_no_field_gets_no_outline() -> Result<(), String> {
        let (shared, _dir) = shared("nofield")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        let start = Instant::now();
        // A page, a read-only field: there is a focus but no field.
        for step in 0..5 {
            watcher.tick(after(start, step * 100), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(log.scans.get(), 0);
        // It becomes one, is outlined, and stops being one.
        desktop.shows(FIELD, EMAIL);
        watcher.tick(after(start, 1_000), &mut desktop, &log);
        watcher.tick(after(start, 1_300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        desktop.field = None;
        watcher.tick(after(start, 1_400), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        Ok(())
    }

    #[test]
    fn a_password_field_is_never_checked_or_outlined() -> Result<(), String> {
        for (mode, tag) in [(Highlight::Always, "pw-a"), (Highlight::Hotkey, "pw-h")] {
            let (shared, _dir) = shared(tag)?;
            let purpose = lamp(mode);
            let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
            let mut watcher = Watcher::new(Arc::clone(&purpose));
            desktop.password = true;
            desktop.shows(FIELD, EMAIL);
            purpose.press();
            let start = Instant::now();
            for step in 0..6 {
                watcher.tick(after(start, step * 100), &mut desktop, &log);
            }
            assert_eq!(log.take(), Vec::<String>::new(), "{mode:?}");
            assert_eq!(log.scans.get(), 0, "{mode:?}: its text is not even checked");
        }
        Ok(())
    }

    #[test]
    fn highlighting_without_protection_keeps_nothing_for_the_store() -> Result<(), String> {
        let (shared, _dir) = shared("nomask")?;
        let (mut desktop, log) = (Fake::on(1, true), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        // A protected element, as far as the desktop is asked.
        desktop.types(EMAIL);
        desktop.copies(3, "NL91ABNA0417164300");
        desktop.shows(FIELD, EMAIL);
        let start = Instant::now();
        for step in 0..5 {
            watcher.tick(after(start, step * 100), &mut desktop, &log);
        }
        let lines = log.take();
        assert_eq!(lines.last(), Some(&show(Mark::Pii, FIELD)), "{lines:?}");
        assert!(
            lines.iter().all(|line| line.starts_with("show")),
            "nothing was pushed or flushed: {lines:?}"
        );
        assert_eq!(
            (
                desktop.protected_calls,
                desktop.text_calls,
                desktop.clipboard_reads
            ),
            (0, 0, 0),
            "protection is off: nothing is read for the store"
        );
        Ok(())
    }

    #[test]
    fn protection_and_highlighting_read_the_same_field() -> Result<(), String> {
        let (shared, _dir) = shared("both")?;
        let purpose = lamp(Highlight::Always);
        purpose.set_mask(true);
        let (mut desktop, log) = (Fake::on(1, true), Log::with(&shared));
        let mut watcher = Watcher::new(purpose);
        desktop.types(EMAIL);
        desktop.shows(FIELD, EMAIL);
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [format!("push {EMAIL}")]);
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), ["flush".to_owned(), show(Mark::Pii, FIELD)]);
        assert_eq!(desktop.protected_calls, 1);
        Ok(())
    }

    #[test]
    fn switching_protection_judges_the_field_afresh() {
        let purpose = lamp(Highlight::Off);
        let (mut desktop, log) = (Fake::on(1, true), Log::default());
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        desktop.types(EMAIL);
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(desktop.protected_calls, 0, "off: not even asked");
        purpose.set_mask(true);
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(
            desktop.protected_calls, 1,
            "on: asked about the field in focus"
        );
        assert_eq!(log.take(), [format!("push {EMAIL}")]);
        purpose.set_mask(false);
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(
            log.take(),
            ["flush"],
            "what was typed is read when protection ends"
        );
        assert_eq!(watcher.period(), SLOW);
    }

    #[test]
    fn a_password_field_is_no_field() {
        let rect = Some(FIELD);
        let text = || Some(EMAIL.to_owned());
        assert!(field_of(true, false, text(), rect).is_none(), "password");
        assert!(field_of(true, true, text(), rect).is_none(), "both");
        assert!(
            field_of(false, true, text(), rect).is_none(),
            "piikey's own window"
        );
        assert!(
            field_of(false, false, None, rect).is_none(),
            "no text to type in"
        );
        assert!(
            field_of(false, false, text(), None).is_none(),
            "not on the screen"
        );
        let field = field_of(false, false, text(), rect).map(|field| (field.rect, field.text));
        assert_eq!(field, Some((FIELD, EMAIL.to_owned())));
    }

    #[test]
    fn a_long_field_is_checked_as_far_as_the_limit_and_not_through_a_character() {
        let text = "é".repeat(MAX_SCAN);
        let part = checked(&text);
        assert!(part.len() <= MAX_SCAN && MAX_SCAN - part.len() < 4);
        assert_eq!(checked("kort"), "kort");
    }

    #[test]
    fn a_press_of_the_shortcut_ends_the_wait_for_the_next_look() -> Result<(), String> {
        let purpose = Arc::new(Purpose::default());
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
        registered.recv().map_err(|error| error.to_string())?;
        thread::sleep(Duration::from_millis(50));
        purpose.press();
        let lasted = waiter.join().map_err(|_| "the waiter panicked")?;
        assert!(lasted < Duration::from_secs(30), "it waited on: {lasted:?}");
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
