//! The half of "Open at this place" that talks to the app that has the file open, through UI
//! Automation: finds the window of the file, the text control in it that holds the value, selects
//! the value there, and tells the highlight overlay where it is.
//!
//! All of it runs on a thread of its own ([`Search`]): an app that does not answer holds up that
//! thread and nobody else. It first looks for a window that has the file open already (a title with
//! the name of the file, see `titles`) and goes straight to the value in it, so that the file is not
//! opened a second time; only when no window has it is the caller told to open the file
//! ([`Search::first`]), and the search waits for the window that is new and looks in it, a few
//! times a second, until the app has read the file.
//!
//! It only reads and selects. It sends no keystroke and no click, and touches nothing but the
//! text control that holds the value; the window that had the file open already is brought forward
//! by asking it for the focus, after the outline is up. A password field is left alone entirely:
//! not its text, not its value, not its place; a field that cannot say whether it is one counts as
//! one. Nothing is logged, and no value leaves this module but as the text that is looked for in
//! the control. Where the apps differ, `office` (`PowerPoint` and Excel show no one text control) and
//! `crate::uia_text` (the text controls of the others) know how.

use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use piikey::formats::Location;
use uiautomation::{
    UIAutomation, UIElement,
    core::{UICacheRequest, UICondition},
    types::{TreeScope, UIProperty},
    variants::{Value, Variant},
};

use super::{
    Outcome, Target,
    editors::Editor,
    needles::{self, Needle},
    office, start,
    titles::{self, Before, Names, Window},
};
use crate::{
    highlight::{Mark, Overlay, Rect},
    process,
    proxy::Purpose,
    uia_text::{Control, Found},
};

/// How often the windows are looked at while the file's window is awaited.
const POLL: Duration = Duration::from_millis(50);
/// How long the file's window is awaited.
const WINDOW_WAIT: Duration = Duration::from_secs(8);
/// How long a window that already had the file's name is left alone, in case a new window for the
/// file is still on its way.
const GRACE: Duration = Duration::from_millis(2_500);
/// How long the value is looked for in the window of a file that was just opened (the app may
/// still be reading the file), and how often.
const LOOK_FOR: Duration = Duration::from_secs(6);
const RETRY: Duration = Duration::from_millis(60);
/// How long a window that shows no text control at all is looked in: one that has none after this
/// is not going to (Chromium needs a moment to show its page, hence this long).
const NO_TEXT: Duration = Duration::from_millis(1_200);
/// How long the outline of the value stays.
const FLASH: Duration = Duration::from_secs(2);
/// How long finding the rectangles of a text may take.
const MEASURE: Duration = Duration::from_millis(700);
/// How long a text that was scrolled to is waited for to be laid out (Word lays out a page when it
/// is shown), and how often it is looked at meanwhile.
const LAYOUT: Duration = Duration::from_millis(1_500);
const LAYOUT_POLL: Duration = Duration::from_millis(40);
/// The most text controls of a window that are looked in.
const MAX_CONTROLS: usize = 40;

/// What a search is for.
pub(super) struct Job {
    /// The file, for an editor that is told where to go in it.
    pub(super) file: PathBuf,
    pub(super) names: Names,
    pub(super) needles: Vec<Needle>,
    /// Where the format says the value is.
    pub(super) place: Option<Location>,
    pub(super) purpose: Arc<Purpose>,
}

impl Job {
    /// The job for `target`; `None` when there is nothing to look for, or nothing to tell the
    /// window by.
    pub(super) fn of(target: &Target, purpose: &Arc<Purpose>) -> Option<Self> {
        let needles = needles::needles(&target.value);
        if needles.is_empty() {
            return None;
        }
        Some(Self {
            file: target.file.clone(),
            names: Names::of(&target.file)?,
            needles,
            place: target.place.clone(),
            purpose: Arc::clone(purpose),
        })
    }
}

/// What the search thread tells the caller.
enum Event {
    /// No window that had the file open held the value: the file is to be opened now.
    Looked,
    /// It is done.
    Done(Outcome),
}

/// Tells the caller what became of the search, once.
pub(super) struct Reporter {
    events: mpsc::Sender<Event>,
    sent: Cell<bool>,
}

impl Reporter {
    /// The caller may stop waiting: this is how it ended. What is done after this is the app's
    /// business (bringing its window forward, selecting a cell) and takes as long as the app takes.
    pub(super) fn done(&self, outcome: Outcome) {
        if !self.sent.replace(true) {
            // The caller may have stopped waiting.
            let _ = self.events.send(Event::Done(outcome));
        }
    }
}

/// A search that runs on a thread of its own, and ends with it: dropping the search tells the
/// thread to stop looking.
pub(super) struct Search {
    events: mpsc::Receiver<Event>,
    cancel: Arc<AtomicBool>,
    /// The answer, when it came before anyone asked for it.
    done: Option<Outcome>,
}

impl Search {
    /// Starts the search; `None` when the thread cannot be made.
    pub(super) fn start(job: Job) -> Option<Self> {
        let (sender, events) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancel);
        thread::Builder::new()
            .name("piikey-goto".to_owned())
            .spawn(move || run(&job, sender, &stop))
            .ok()?;
        Some(Self {
            events,
            cancel,
            done: None,
        })
    }

    /// Waits until the thread has looked in the windows that may have the file open already, for
    /// at most `wait`: [`Outcome::Marked`] when one had the value, which was then pointed at, and
    /// the file is not to be opened again; [`Outcome::Opened`] when none had it, or it took too
    /// long to tell, and the file is to be opened now.
    pub(super) fn first(&mut self, wait: Duration) -> Outcome {
        match self.events.recv_timeout(wait) {
            Ok(Event::Done(Outcome::Marked)) => {
                self.done = Some(Outcome::Marked);
                Outcome::Marked
            }
            Ok(Event::Done(outcome)) => {
                self.done = Some(outcome);
                Outcome::Opened
            }
            Ok(Event::Looked) | Err(_) => Outcome::Opened,
        }
    }

    /// What the search found, waiting for it until `deadline`: [`Outcome::Opened`] when it is not
    /// done by then. The thread ends by itself.
    pub(super) fn finish(&mut self, deadline: Instant) -> Outcome {
        if let Some(outcome) = self.done {
            return outcome;
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(Event::Done(outcome)) => return outcome,
                Ok(Event::Looked) => {}
                Err(_) => return Outcome::Opened,
            }
        }
    }
}

impl Drop for Search {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// The search thread.
fn run(job: &Job, events: mpsc::Sender<Event>, cancel: &AtomicBool) {
    // The overlay takes a moment to start (a thread, an event loop, windows); it does while the
    // windows are looked at.
    let purpose = Arc::clone(&job.purpose);
    let _ = thread::Builder::new()
        .name("piikey-goto-overlay".to_owned())
        .spawn(move || {
            let _ = Overlay::get_or_start(&purpose);
        });
    let report = Reporter {
        events,
        sent: Cell::new(false),
    };
    let outcome = search(job, &report, cancel);
    report.done(outcome);
}

/// Looks at the windows that are open, tells the caller whether one had the file and the value,
/// then waits for the window of the file and looks in it.
fn search(job: &Job, report: &Reporter, cancel: &AtomicBool) -> Outcome {
    let Some(desk) = Desk::new() else {
        let _ = report.events.send(Event::Looked);
        return Outcome::Opened;
    };
    let listing = desk.windows();
    let before = listing
        .as_ref()
        .map(|listing| Before::of(&listing.windows))
        .unwrap_or_default();
    // The file may be open already: then the value is looked for there, and the file not opened.
    if let Some(listing) = &listing {
        for at in titles::open_in(&listing.windows, &job.names) {
            let Some(frame) = listing.frames.get(at) else {
                continue;
            };
            match look(&desk, frame, job, report, cancel, None) {
                Outcome::Marked => {
                    bring_forward(frame);
                    return Outcome::Marked;
                }
                // An editor that was told the place goes there, and comes forward, by itself.
                Outcome::Placed => return Outcome::Placed,
                Outcome::Opened => {}
            }
        }
    }
    let _ = report.events.send(Event::Looked);
    let started = Instant::now();
    while started.elapsed() < WINDOW_WAIT && !cancel.load(Ordering::Relaxed) {
        if let Some(listing) = desk.windows()
            && let Some(at) = titles::pick(
                &listing.windows,
                &before,
                &job.names,
                started.elapsed() >= GRACE,
            )
            && let Some(frame) = listing.frames.get(at)
        {
            return look(
                &desk,
                frame,
                job,
                report,
                cancel,
                Some(Instant::now() + LOOK_FOR),
            );
        }
        thread::sleep(POLL);
    }
    Outcome::Opened
}

/// Looks for the value in `frame`, a window: once, or, with `until`, as often as it takes until
/// then, as an app that has just opened the file may not have read it yet.
fn look(
    desk: &Desk,
    frame: &Frame,
    job: &Job,
    report: &Reporter,
    cancel: &AtomicBool,
    until: Option<Instant>,
) -> Outcome {
    if let Some(outcome) = goto_in_editor(frame, job) {
        return outcome;
    }
    let started = Instant::now();
    // The window has a text control: PowerPoint and Excel have their own ways to wait.
    let mut text_seen = matches!(frame.class.as_str(), office::POWERPOINT | office::EXCEL);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Outcome::Opened;
        }
        let outcome = match frame.class.as_str() {
            office::POWERPOINT => office::powerpoint(desk, frame, job, report),
            office::EXCEL => office::excel(desk, frame, job, report),
            _ => {
                let controls = text_controls(desk, &frame.element);
                text_seen |= !controls.is_empty();
                mark_in(&controls, job, report)
            }
        };
        if outcome == Outcome::Marked {
            return outcome;
        }
        // An app that has not read the file yet is waited for; one whose window shows no text
        // control at all after a while (a Notepad that has none) is not worth it.
        let waiting = text_seen || started.elapsed() < NO_TEXT;
        match until {
            Some(end) if waiting && Instant::now() < end => thread::sleep(RETRY),
            _ => return Outcome::Opened,
        }
    }
}

/// When `frame` is a window of an editor that takes a place on its command line (VS Code, Notepad++,
/// Sublime Text) and the value has a line: the editor is started again with the place, which its
/// running window takes, and the file is shown there at the value. Its text is not readable to UI
/// Automation (VS Code shows it only to screen readers), so this is the way to it. This also covers
/// an editor that Windows starts for the file through a packaged app, whose exe the registry
/// does not name.
fn goto_in_editor(frame: &Frame, job: &Job) -> Option<Outcome> {
    let Some(Location::Line { line, column }) = job.place else {
        return None;
    };
    let exe = process::exe_path(frame.process?)?;
    let arguments = Editor::of(&exe)?.arguments(&job.file, line, column);
    start(&exe, &arguments).then_some(Outcome::Placed)
}

/// Asks a window that had the file open already for the focus, which brings it to the front. The
/// app may take its time, and may refuse: the outline is up by now.
fn bring_forward(frame: &Frame) {
    let _ = frame.element.set_focus();
}

/// UI Automation, and what the search asks of the windows on the desktop.
pub(super) struct Desk {
    pub(super) automation: UIAutomation,
    /// What is read of every window in one go: its title, process, class, identity and whether it
    /// is on the screen.
    request: UICacheRequest,
    /// Matches every element.
    pub(super) all: UICondition,
    /// Matches the elements that have a text pattern.
    has_text: UICondition,
    /// What is read of a text control before it is looked at: whether it is a password field.
    text_request: UICacheRequest,
    /// The `PowerPoint` window whose slides were asked to show themselves (see `office`).
    pub(super) awake: RefCell<Vec<Vec<i32>>>,
}

/// A top-level window of another program: the element, its class and its process.
pub(super) struct Frame {
    pub(super) element: UIElement,
    pub(super) class: String,
    pub(super) process: Option<u32>,
}

/// The top-level windows of the other programs, from the top of the stack: the elements, and what
/// the search needs to know of each, in the same order.
struct Listing {
    frames: Vec<Frame>,
    windows: Vec<Window>,
}

impl Desk {
    fn new() -> Option<Self> {
        let automation = UIAutomation::new().ok()?;
        let request = |properties: &[UIProperty]| -> Option<UICacheRequest> {
            let request = automation.create_cache_request().ok()?;
            for &property in properties {
                request.add_property(property).ok()?;
            }
            Some(request)
        };
        let all = automation.create_true_condition().ok()?;
        let has_text = automation
            .create_property_condition(
                UIProperty::IsTextPatternAvailable,
                Variant::from(true),
                None,
            )
            .ok()?;
        Some(Self {
            request: request(&[
                UIProperty::Name,
                UIProperty::ProcessId,
                UIProperty::RuntimeId,
                UIProperty::ClassName,
                UIProperty::IsOffscreen,
            ])?,
            text_request: request(&[UIProperty::IsPassword])?,
            automation,
            all,
            has_text,
            awake: RefCell::new(Vec::new()),
        })
    }

    fn windows(&self) -> Option<Listing> {
        let root = self.automation.get_root_element().ok()?;
        let children = root
            .find_all_build_cache(TreeScope::Children, &self.all, &self.request)
            .ok()?;
        let own = std::process::id();
        let (frames, windows) = children
            .into_iter()
            .filter_map(|element| {
                let process = element
                    .get_cached_process_id()
                    .ok()
                    .and_then(|process| u32::try_from(process).ok());
                if process == Some(own) {
                    return None;
                }
                let window = Window {
                    id: runtime_id(&element)?,
                    title: element.get_cached_name().ok()?,
                    // A window that cannot say counts as one that is not on the screen: the
                    // file is opened, and brings it back.
                    shown: cached_flag(&element, UIProperty::IsOffscreen) == Some(false),
                };
                let class = element.get_cached_classname().unwrap_or_default();
                Some((
                    Frame {
                        element,
                        class,
                        process,
                    },
                    window,
                ))
            })
            .unzip();
        Some(Listing { frames, windows })
    }

    /// The first element below `parent` that has the automation id.
    pub(super) fn with_id(&self, parent: &UIElement, id: &str) -> Option<UIElement> {
        let condition = self
            .automation
            .create_property_condition(UIProperty::AutomationId, Variant::from(id), None)
            .ok()?;
        parent.find_first(TreeScope::Descendants, &condition).ok()
    }

    /// The first element below `parent` of the class.
    pub(super) fn with_class(&self, parent: &UIElement, class: &str) -> Option<UIElement> {
        let condition = self
            .automation
            .create_property_condition(UIProperty::ClassName, Variant::from(class), None)
            .ok()?;
        parent.find_first(TreeScope::Descendants, &condition).ok()
    }
}

impl Drop for Desk {
    fn drop(&mut self) {
        // Event handlers that were put up to wake an app live as long as the automation.
        let _ = self.automation.remove_all_event_handlers();
    }
}

/// What identifies `element` on the desktop: the id that came with it, or else the live one.
pub(super) fn runtime_id(element: &UIElement) -> Option<Vec<i32>> {
    let cached = element
        .get_cached_property_value(UIProperty::RuntimeId)
        .ok()
        .and_then(|id| id.get_value().ok());
    match cached {
        Some(Value::ArrayI4(id)) => Some(id),
        _ => element.get_runtime_id().ok(),
    }
}

/// A flag that came with `element`.
fn cached_flag(element: &UIElement, property: UIProperty) -> Option<bool> {
    let value = element.get_cached_property_value(property).ok()?;
    let flag: Result<bool, _> = (&value).try_into();
    flag.ok()
}

/// The text controls of `element` that may be read, in the order of the tree: not a password
/// field, and with a text pattern.
pub(super) fn text_controls(desk: &Desk, element: &UIElement) -> Vec<Control> {
    let Ok(elements) =
        element.find_all_build_cache(TreeScope::Descendants, &desk.has_text, &desk.text_request)
    else {
        return Vec::new();
    };
    elements
        .into_iter()
        // A password field is left alone entirely, before anything else is asked of it. A field
        // that cannot say what it is counts as one.
        .filter(|element| cached_flag(element, UIProperty::IsPassword) == Some(false))
        .filter_map(Control::of)
        .take(MAX_CONTROLS)
        .collect()
}

/// Looks for the value in `controls`, the most exact way first in all of them before the next way,
/// and points at the first place it is found. [`Outcome::Marked`] when it was found.
pub(super) fn mark_in(controls: &[Control], job: &Job, report: &Reporter) -> Outcome {
    for needle in &job.needles {
        for control in controls {
            if let Some(found) = control.find(&needle.text, needle.ignore_case, 0) {
                return point_at(control, &found, &job.purpose, report);
            }
        }
    }
    Outcome::Opened
}

/// Selects `found` in `control`, brings it into view, and outlines it on the screen.
fn point_at(
    control: &Control,
    found: &Found,
    purpose: &Arc<Purpose>,
    report: &Reporter,
) -> Outcome {
    // Selected before it is boxed: a shape of `PowerPoint` says where its text is once some of it
    // is selected.
    let selected = found.select();
    found.scroll_into_view();
    let outlined = outline(&measure(control, found), purpose);
    let outcome = if selected || outlined {
        Outcome::Marked
    } else {
        Outcome::Opened
    };
    report.done(outcome);
    outcome
}

/// Outlines `rects` on the screen for a moment. `false` when there are none or no overlay to draw
/// them.
pub(super) fn outline(rects: &[Rect], purpose: &Arc<Purpose>) -> bool {
    if rects.is_empty() {
        return false;
    }
    let Ok(overlay) = Overlay::get_or_start(purpose) else {
        return false;
    };
    overlay.flash(rects, Mark::Pii, FLASH);
    true
}

/// A rectangle around each line of `found` that is in view, once it is: it was scrolled to, and a
/// control that lays a page out when it is shown (Word) is asked again for a moment. None when the
/// control cannot say.
fn measure(control: &Control, found: &Found) -> Vec<Rect> {
    let end = Instant::now() + LAYOUT;
    let mut scrolled = false;
    loop {
        match found.rects(control, MEASURE) {
            Some(rects) if !rects.is_empty() => return rects,
            // Not in view: a control whose range does not scroll (Chromium) is asked through the
            // element around the text.
            Some(_) if !scrolled => {
                scrolled = true;
                found.scroll_enclosing();
            }
            Some(_) => {}
            None => return Vec::new(),
        }
        if Instant::now() >= end {
            return Vec::new();
        }
        thread::sleep(LAYOUT_POLL);
    }
}
