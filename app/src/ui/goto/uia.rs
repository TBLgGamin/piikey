//! The half of "Open at this place" that talks to the app that has the file open, through UI
//! Automation: finds the window of the file, the text control in it that holds the value, selects
//! the value there, and tells the highlight overlay where it is.
//!
//! All of it runs on a thread of its own ([`Search`]): an app that does not answer holds up that
//! thread and nobody else. It only reads and selects. It sends no keystroke and no click, never
//! gives anything the focus, and touches nothing but the text control that holds the value. A
//! password field is left alone entirely: not its text, not its value, not its place; a field that
//! cannot say whether it is one counts as one. Nothing is logged, and no value leaves this module
//! but as the text that is looked for in the control.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use uiautomation::{
    UIAutomation, UIElement,
    core::{UICacheRequest, UICondition},
    patterns::{UITextPattern, UITextRange},
    types::{Point, TextPatternRangeEndpoint, TreeScope, UIProperty},
    variants::{Value, Variant},
};

use super::{
    Outcome, Target,
    measure::{self, Probe},
    needles::{self, Needle},
    titles::{self, Before, Names, Window},
};
use crate::{
    highlight::{Mark, Overlay, Rect},
    proxy::Purpose,
};

/// How often the windows are looked at while the file's window is awaited.
const POLL: Duration = Duration::from_millis(250);
/// How long the file's window is awaited.
const WINDOW_WAIT: Duration = Duration::from_secs(8);
/// How long a window that already had the file's name is left alone, in case a new window for the
/// file is still on its way.
const GRACE: Duration = Duration::from_millis(2_500);
/// How many times the value is looked for in the window (the app may still be reading the file),
/// and how long between.
const ATTEMPTS: usize = 3;
const RETRY: Duration = Duration::from_millis(500);
/// How long a text control is given to stop scrolling before its points are asked about.
const SETTLE: Duration = Duration::from_millis(120);
/// How long the outline of the value stays.
const FLASH: Duration = Duration::from_secs(2);
/// The most text controls of a window that are looked in.
const MAX_CONTROLS: usize = 32;

/// What a search is for.
pub(super) struct Job {
    names: Names,
    needles: Vec<Needle>,
    purpose: Arc<Purpose>,
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
            names: Names::of(&target.file)?,
            needles,
            purpose: Arc::clone(purpose),
        })
    }
}

/// What the search thread tells the caller.
enum Event {
    /// It knows which windows are open. The file is opened after that, so that its window is told
    /// from them.
    Looked,
    /// It is done.
    Done(Outcome),
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
            .spawn(move || run(&job, &sender, &stop))
            .ok()?;
        Some(Self {
            events,
            cancel,
            done: None,
        })
    }

    /// Waits until the thread knows which windows are open, for at most `wait`.
    pub(super) fn wait_until_looked(&mut self, wait: Duration) {
        if let Ok(Event::Done(outcome)) = self.events.recv_timeout(wait) {
            self.done = Some(outcome);
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
fn run(job: &Job, events: &mpsc::Sender<Event>, cancel: &AtomicBool) {
    let outcome = search(job, events, cancel);
    // The caller may have stopped waiting.
    let _ = events.send(Event::Done(outcome));
}

/// Looks at the windows that are open, tells the caller, then waits for the window of the file and
/// looks in it.
fn search(job: &Job, events: &mpsc::Sender<Event>, cancel: &AtomicBool) -> Outcome {
    let Some(desk) = Desk::new() else {
        let _ = events.send(Event::Looked);
        return Outcome::Opened;
    };
    let before = desk
        .windows()
        .map(|(_, windows)| Before::of(&windows))
        .unwrap_or_default();
    let _ = events.send(Event::Looked);
    let started = Instant::now();
    while started.elapsed() < WINDOW_WAIT && !cancel.load(Ordering::Relaxed) {
        if let Some((elements, windows)) = desk.windows()
            && let Some(at) =
                titles::pick(&windows, &before, &job.names, started.elapsed() >= GRACE)
            && let Some(window) = elements.get(at)
        {
            return look_in(&desk.automation, window, job, cancel);
        }
        thread::sleep(POLL);
    }
    Outcome::Opened
}

/// Looks for the value in `window`, a few times: an app that has just opened the file may not
/// have read it yet.
fn look_in(
    automation: &UIAutomation,
    window: &UIElement,
    job: &Job,
    cancel: &AtomicBool,
) -> Outcome {
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            thread::sleep(RETRY);
        }
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if mark(automation, window, job) == Outcome::Marked {
            return Outcome::Marked;
        }
    }
    Outcome::Opened
}

/// UI Automation, and what the search asks of the windows on the desktop.
struct Desk {
    automation: UIAutomation,
    /// What is read of every window in one go: its title, process and identity.
    request: UICacheRequest,
    /// Matches every element.
    all: UICondition,
}

impl Desk {
    fn new() -> Option<Self> {
        let automation = UIAutomation::new().ok()?;
        let request = automation.create_cache_request().ok()?;
        for property in [
            UIProperty::Name,
            UIProperty::ProcessId,
            UIProperty::RuntimeId,
        ] {
            request.add_property(property).ok()?;
        }
        let all = automation.create_true_condition().ok()?;
        Some(Self {
            automation,
            request,
            all,
        })
    }

    /// The top-level windows of the other programs, from the top of the stack: the elements, and
    /// what the search needs to know of each, in the same order.
    fn windows(&self) -> Option<(Vec<UIElement>, Vec<Window>)> {
        let root = self.automation.get_root_element().ok()?;
        let children = root
            .find_all_build_cache(TreeScope::Children, &self.all, &self.request)
            .ok()?;
        let own = std::process::id();
        Some(
            children
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
                    };
                    Some((element, window))
                })
                .unzip(),
        )
    }
}

/// What identifies `element` on the desktop: the id that came with it, or else the live one.
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

/// A text control that may be read: not a password field, and it has a text pattern.
struct Control {
    element: UIElement,
    pattern: UITextPattern,
    /// All of its text.
    document: UITextRange,
}

/// The text controls of `window` that may be read, in the order of the window.
fn text_controls(automation: &UIAutomation, window: &UIElement) -> Vec<Control> {
    let Ok(has_text) = automation.create_property_condition(
        UIProperty::IsTextPatternAvailable,
        Variant::from(true),
        None,
    ) else {
        return Vec::new();
    };
    let Ok(elements) = window.find_all(TreeScope::Descendants, &has_text) else {
        return Vec::new();
    };
    elements
        .into_iter()
        // A password field is left alone entirely, before anything else is asked of it. A field
        // that cannot say what it is counts as one.
        .filter(|element| matches!(element.is_password(), Ok(false)))
        .filter_map(|element| {
            let pattern = element.get_pattern::<UITextPattern>().ok()?;
            let document = pattern.get_document_range().ok()?;
            Some(Control {
                element,
                pattern,
                document,
            })
        })
        .take(MAX_CONTROLS)
        .collect()
}

/// Looks for the value in the text controls of `window`, the most exact way first in all of them
/// before the next way, and points at the first place it is found. [`Outcome::Marked`] when it
/// was found.
fn mark(automation: &UIAutomation, window: &UIElement, job: &Job) -> Outcome {
    let controls = text_controls(automation, window);
    for needle in &job.needles {
        for control in &controls {
            if let Ok(found) = control
                .document
                .find_text(&needle.text, false, needle.ignore_case)
            {
                return point_at(control, &found, &job.purpose);
            }
        }
    }
    Outcome::Opened
}

/// Selects `found` in `control`, brings it into view, and outlines it on the screen.
fn point_at(control: &Control, found: &UITextRange, purpose: &Arc<Purpose>) -> Outcome {
    let selected = found.select().is_ok();
    // Wherever it is, it is in view after this, if the control lets it be.
    if found.scroll_into_view(false).is_ok() {
        thread::sleep(SETTLE);
    }
    // Both are tried: a control that will not select can still be outlined.
    let outlined = outline(control, found, purpose);
    if selected || outlined {
        Outcome::Marked
    } else {
        Outcome::Opened
    }
}

/// Outlines `found` on the screen for a moment. `false` when its place cannot be told or there is
/// no overlay to draw it.
fn outline(control: &Control, found: &UITextRange, purpose: &Arc<Purpose>) -> bool {
    let Some(area) = bounds(&control.element) else {
        return false;
    };
    let mut hits = Hits {
        pattern: &control.pattern,
        found,
    };
    let Some(field) = measure::locate(&mut hits, area) else {
        return false;
    };
    let Ok(overlay) = Overlay::get_or_start(purpose) else {
        return false;
    };
    overlay.flash(field, Mark::Pii, FLASH);
    true
}

/// Where `element` is on the screen.
fn bounds(element: &UIElement) -> Option<Rect> {
    let rect = element.get_bounding_rectangle().ok()?;
    Rect::field(
        rect.get_left(),
        rect.get_top(),
        rect.get_right(),
        rect.get_bottom(),
    )
}

/// The found text in its control, as the hit tests of [`measure`] ask about it.
struct Hits<'a> {
    pattern: &'a UITextPattern,
    found: &'a UITextRange,
}

impl Hits<'_> {
    /// Where the text position at the point is against `end` of the found text: below zero before
    /// it, zero at it, above zero after it. `None` when the control does not say.
    fn order(&self, x: i32, y: i32, end: TextPatternRangeEndpoint) -> Option<i32> {
        let at = self.pattern.get_range_from_point(Point::new(x, y)).ok()?;
        at.compare_endpoints(TextPatternRangeEndpoint::Start, self.found, end)
            .ok()
    }
}

impl Probe for Hits<'_> {
    fn at_or_after_start(&mut self, x: i32, y: i32) -> Option<bool> {
        let order = self.order(x, y, TextPatternRangeEndpoint::Start)?;
        Some(order >= 0)
    }

    fn before_end(&mut self, x: i32, y: i32) -> Option<bool> {
        let order = self.order(x, y, TextPatternRangeEndpoint::End)?;
        Some(order < 0)
    }
}
