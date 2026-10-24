//! [`Outline`]: when the field in focus is outlined, around what, and in which colour.

use std::time::{Duration, Instant};

use piikey::policy::Highlight;

use super::{
    FLASH_FOR, SETTLE, SHOW_FOR,
    desktop::{Desktop, Field, Value},
    sink::Sink,
};
use crate::{
    highlight::{Mark, Rect},
    proxy::Purpose,
};

/// Bytes of a field that are checked for personal data; a field with more is checked as far as
/// that, as [`Typed`](crate::proxy::Typed) keeps no more of a text either.
const MAX_SCAN: usize = 256 << 10;
/// Looks in a row that find no field to outline before the outline goes: the focus or the field
/// can be unreadable for a moment while an app redraws, and the outline would blink.
const MISSES: u8 = 3;
/// How often a check that could not tell is tried again, and how many times in all.
const RETRY_CHECK: Duration = Duration::from_millis(250);
const TRIES: u8 = 5;
/// How long a field whose text control could not say where its values are is outlined whole
/// before that is asked again.
const RETRY_PLACE: Duration = Duration::from_secs(2);
/// How long outlines that were just found are taken as they are, before they are checked against
/// the text again: a check is a few calls into the other program at every look.
const TRUST: Duration = Duration::from_millis(400);

/// The part of `text` that is checked for personal data.
fn checked(text: &str) -> &str {
    &text[..text.floor_char_boundary(MAX_SCAN)]
}

/// What the loop knows about the outline of the field in focus.
pub(super) struct Outline {
    /// What the field held when it was last looked at; `None` before the first look at the
    /// element. Only [`Highlight::Always`] reads it at every look.
    text: Option<String>,
    /// When `text` is next checked for personal data; `None` while no check is due.
    due: Option<Instant>,
    /// How many checks in a row could not tell.
    unsure: u8,
    /// The personal data the field held when it was last checked.
    values: Vec<Value>,
    /// Where the outlines of `values` went last.
    placed: Option<Placed>,
    /// The outline that is up.
    up: Option<Up>,
    /// Looks in a row that found no field.
    missed: u8,
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

/// Where the outlines of the values of a field went, and for which place of the field.
struct Placed {
    /// A rectangle around each line of each value; or the field itself, when its text control
    /// could not say where the values are.
    rects: Vec<Rect>,
    /// Where the field was then.
    field: Rect,
    /// The rectangles are around the values; else they are the field.
    exact: bool,
    /// When the text control was asked.
    at: Instant,
}

impl Placed {
    /// The rectangles for the field as it is now, as long as they still hold for it: a field that
    /// moved takes its values along, one that changed size lays its text out again. `None` when
    /// the text control is to be asked again.
    fn follow(&self, field: Rect, now: Instant) -> Option<Vec<Rect>> {
        if !self.exact {
            // The whole field is outlined where it is, and asked about again after a while.
            let asked_lately = now.saturating_duration_since(self.at) < RETRY_PLACE;
            return asked_lately.then(|| vec![field]);
        }
        if (field.width(), field.height()) != (self.field.width(), self.field.height()) {
            return None;
        }
        let (dx, dy) = (
            field.left.saturating_sub(self.field.left),
            field.top.saturating_sub(self.field.top),
        );
        Some(self.rects.iter().map(|rect| rect.shifted(dx, dy)).collect())
    }
}

impl Outline {
    pub(super) fn new(presses: u64) -> Self {
        Self {
            text: None,
            due: None,
            unsure: 0,
            values: Vec::new(),
            placed: None,
            up: None,
            missed: 0,
            presses,
        }
    }

    /// Whether an outline is up.
    pub(super) fn is_up(&self) -> bool {
        self.up.is_some()
    }

    /// Whether the shortcut was pressed since the presses were last taken in.
    pub(super) fn pressed(&self, purpose: &Purpose) -> bool {
        purpose.presses() != self.presses
    }

    /// Takes the presses of the shortcut in, and says whether an odd number of them came since the
    /// last time: two within one look cancel out.
    pub(super) fn take_presses(&mut self, purpose: &Purpose) -> bool {
        let presses = purpose.presses();
        let odd = presses.wrapping_sub(self.presses) % 2 == 1;
        self.presses = presses;
        odd
    }

    /// Takes the outline away and forgets what was known of the field.
    pub(super) fn end(&mut self, sink: &impl Sink) {
        self.text = None;
        self.due = None;
        self.unsure = 0;
        self.values.clear();
        self.placed = None;
        self.missed = 0;
        if self.up.take().is_some() {
            sink.hide();
        }
    }

    /// Brings the outline of the field in focus up to date.
    ///
    /// - [`Highlight::Always`]: the field is checked as soon as it is first looked at, and again
    ///   once its text has been still for [`SETTLE`] after a change, and the personal data in it
    ///   is outlined while it holds any. The shortcut pauses this and brings it back.
    /// - [`Highlight::Hotkey`]: the shortcut checks the field and outlines its personal data for
    ///   [`SHOW_FOR`], or flashes the field green for [`FLASH_FOR`] when it holds none; pressed
    ///   again, the outlines go.
    ///
    /// The outlines are shown again at every look, so that they follow a window that moves.
    pub(super) fn look(
        &mut self,
        now: Instant,
        mode: Highlight,
        desktop: &mut impl Desktop,
        sink: &impl Sink,
        purpose: &Purpose,
    ) {
        // Every mode takes the presses in, so one from before a switch is not acted on after it.
        let odd = self.take_presses(purpose);
        match mode {
            Highlight::Off => {}
            Highlight::Always => self.always(now, odd, desktop, sink, purpose),
            Highlight::Hotkey => self.hotkey(now, odd, desktop, sink),
        }
    }

    /// A look that found no field to outline: the outline stays for [`MISSES`] looks, and goes
    /// after them.
    fn miss(&mut self, sink: &impl Sink) {
        self.missed = self.missed.saturating_add(1);
        if self.missed >= MISSES {
            self.end(sink);
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
            self.miss(sink);
            return;
        };
        self.missed = 0;
        self.read(now, text);
        self.check(now, sink);
        if self.values.is_empty() {
            if self.up.take().is_some() {
                sink.hide();
            }
            return;
        }
        self.draw(now, rect, Mark::Pii, None, desktop, sink);
    }

    /// Takes the text of the field in. A field met for the first time is checked at once, as
    /// nothing is being typed in it; one that changes is checked once it has been still.
    fn read(&mut self, now: Instant, text: String) {
        if self.text.as_deref() == Some(text.as_str()) {
            return;
        }
        let first = self.text.is_none();
        self.text = Some(text);
        self.unsure = 0;
        self.due = Some(if first { now } else { now + SETTLE });
    }

    /// Checks the text for personal data when that is due. A check that cannot tell keeps the
    /// verdict of the last one and is tried again a few times.
    fn check(&mut self, now: Instant, sink: &impl Sink) {
        let Some(text) = self.text.as_deref() else {
            return;
        };
        if text.trim().is_empty() {
            self.due = None;
            self.values.clear();
            self.placed = None;
            return;
        }
        if self.due.is_none_or(|at| now < at) {
            return;
        }
        self.due = None;
        if let Some(values) = sink.values(checked(text)) {
            self.unsure = 0;
            if values != self.values {
                self.values = values;
                self.placed = None;
            }
        } else {
            self.unsure = self.unsure.saturating_add(1);
            if self.unsure < TRIES {
                self.due = Some(now + RETRY_CHECK);
            }
        }
    }

    /// Outlines the values of the field, which is at `field` now, in the colour of `mark`; `until`
    /// is when the outline goes by itself, if it does.
    fn draw(
        &mut self,
        now: Instant,
        field: Rect,
        mark: Mark,
        until: Option<Instant>,
        desktop: &mut impl Desktop,
        sink: &impl Sink,
    ) {
        let rects = self.rects(now, field, desktop);
        sink.show(&rects, mark);
        self.up = Some(Up { mark, until });
    }

    /// Where the outlines of the values go: where they were found, moved with the field, and for
    /// a moment after that taken as they are; later they are kept while the first value is still
    /// there (the text may have scrolled); else the text control is asked, and when it cannot say,
    /// the field is what is outlined.
    fn rects(&mut self, now: Instant, field: Rect, desktop: &mut impl Desktop) -> Vec<Rect> {
        if let Some(placed) = &self.placed
            && let Some(rects) = placed.follow(field, now)
            && (!placed.exact
                || now.saturating_duration_since(placed.at) < TRUST
                || rects.first().is_some_and(|&first| desktop.still_at(first)))
        {
            return rects;
        }
        let rects = desktop.places(&self.values);
        let exact = !rects.is_empty();
        let rects = if exact { rects } else { vec![field] };
        self.placed = Some(Placed {
            rects: rects.clone(),
            field,
            exact,
            at: now,
        });
        rects
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
            let Some(values) = sink.values(checked(&text)) else {
                return;
            };
            self.missed = 0;
            if values.is_empty() {
                sink.show(&[rect], Mark::Clean);
                self.up = Some(Up {
                    mark: Mark::Clean,
                    until: Some(now + FLASH_FOR),
                });
                return;
            }
            self.values = values;
            self.placed = None;
            self.draw(now, rect, Mark::Pii, Some(now + SHOW_FOR), desktop, sink);
            return;
        }
        let Some((mark, until)) = self.up.as_ref().map(|up| (up.mark, up.until)) else {
            return;
        };
        if until.is_some_and(|end| now >= end) {
            self.end(sink);
            return;
        }
        let Some(rect) = desktop.bounds() else {
            self.miss(sink);
            return;
        };
        self.missed = 0;
        if mark == Mark::Pii {
            self.draw(now, rect, mark, until, desktop, sink);
        } else {
            sink.show(&[rect], mark);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{
        capture::{
            FAST, SLOW,
            testing::{EMAIL, FIELD, Fake, Log, after, lamp, shared, show},
            watcher::Watcher,
        },
        highlight::Rect,
    };

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
        // A field met for the first time is checked at once: nothing is being typed in it.
        assert_eq!(log.take(), std::slice::from_ref(&outline));
        assert_eq!(desktop.asked, [true], "the value comes with the focus");
        // It is shown again at every look, because windows move, but checked once.
        watcher.tick(after(start, 100), &mut desktop, &log);
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
    fn a_change_is_checked_once_the_text_has_been_still() -> Result<(), String> {
        let (shared, _dir) = shared("settle")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        let start = Instant::now();
        // An empty box is seen and has nothing to check.
        desktop.shows(FIELD, "");
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.scans.get(), 0);
        // The text arrives; it has to be still for 300 ms first.
        desktop.shows(FIELD, EMAIL);
        watcher.tick(after(start, 100), &mut desktop, &log);
        watcher.tick(after(start, 399), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "the text is settling");
        assert_eq!(log.scans.get(), 0);
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        assert_eq!(log.scans.get(), 1);
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
            // To an element that holds no field: a button. One that holds the same words would be
            // outlined at once, as a field met for the first time is.
            desktop.moves_to(2, false);
            desktop.field = None;
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
            [show(Mark::Pii, FIELD)],
            "the field is checked again, and outlined at once"
        );
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
        // It becomes one and is outlined at once.
        desktop.shows(FIELD, EMAIL);
        watcher.tick(after(start, 1_000), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        // Unreadable for a moment, as an app that redraws can be: the outline stays.
        desktop.field = None;
        watcher.tick(after(start, 1_100), &mut desktop, &log);
        watcher.tick(after(start, 1_200), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        // It stays that way: it stops being a field and the outline goes.
        watcher.tick(after(start, 1_300), &mut desktop, &log);
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
    fn a_long_field_is_checked_as_far_as_the_limit_and_not_through_a_character() {
        let text = "é".repeat(MAX_SCAN);
        let part = checked(&text);
        assert!(part.len() <= MAX_SCAN && MAX_SCAN - part.len() < 4);
        assert_eq!(checked("kort"), "kort");
    }

    /// Two pieces of personal data in one text.
    const TWO: &str = "mail jan.jansen@acme.nl en NL91ABNA0417164300";
    /// Where a text control says they are, in the field `FIELD`.
    const EMAIL_AT: Rect = Rect {
        left: 140,
        top: 208,
        right: 280,
        bottom: 232,
    };
    const IBAN_AT: Rect = Rect {
        left: 300,
        top: 208,
        right: 420,
        bottom: 232,
    };

    fn value(text: &str) -> Value {
        Value {
            text: text.to_owned(),
            nth: 0,
        }
    }

    /// What [`Log`] writes for these outlines.
    fn shows(rects: &[Rect]) -> String {
        crate::capture::testing::shows(Mark::Pii, rects)
    }

    #[test]
    fn the_values_are_outlined_and_not_the_field() -> Result<(), String> {
        let (shared, _dir) = shared("values")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, TWO);
        desktop.placed = vec![EMAIL_AT, IBAN_AT];
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [shows(&[EMAIL_AT, IBAN_AT])]);
        assert_eq!(
            desktop.asked_values,
            [vec![
                value("jan.jansen@acme.nl"),
                value("NL91ABNA0417164300")
            ]]
        );
        // Asked once: the same outlines are shown again at every look.
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), [shows(&[EMAIL_AT, IBAN_AT])]);
        assert_eq!(desktop.asked_values.len(), 1);
        Ok(())
    }

    #[test]
    fn a_value_that_goes_takes_its_outline_with_it() -> Result<(), String> {
        let (shared, _dir) = shared("goes")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, TWO);
        desktop.placed = vec![EMAIL_AT, IBAN_AT];
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        // The email is deleted; once the text has settled only the IBAN is outlined.
        desktop.shows(FIELD, "mail en NL91ABNA0417164300");
        desktop.placed = vec![IBAN_AT];
        watcher.tick(after(start, 500), &mut desktop, &log);
        watcher.tick(after(start, 799), &mut desktop, &log);
        assert_eq!(
            log.take()
                .iter()
                .filter(|line| **line == shows(&[EMAIL_AT, IBAN_AT]))
                .count(),
            3,
            "the old verdict stays up while the text settles"
        );
        watcher.tick(after(start, 800), &mut desktop, &log);
        assert_eq!(log.take(), [shows(&[IBAN_AT])]);
        assert_eq!(
            desktop.asked_values.last(),
            Some(&vec![value("NL91ABNA0417164300")])
        );
        Ok(())
    }

    #[test]
    fn a_text_control_that_cannot_say_gets_the_whole_field_and_is_asked_again_later()
    -> Result<(), String> {
        let (shared, _dir) = shared("whole")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        watcher.tick(after(start, 1_900), &mut desktop, &log);
        assert_eq!(desktop.asked_values.len(), 1, "not asked at every look");
        // The control may have been busy: it is asked again after a while.
        desktop.placed = vec![EMAIL_AT];
        watcher.tick(after(start, 2_000), &mut desktop, &log);
        assert_eq!(desktop.asked_values.len(), 2);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD), shows(&[EMAIL_AT])]);
        Ok(())
    }

    #[test]
    fn the_outlines_follow_a_window_that_moves_without_measuring_again() -> Result<(), String> {
        let (shared, _dir) = shared("moves")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        desktop.placed = vec![EMAIL_AT];
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        // The window moves 60 across and 30 down, and keeps its size.
        desktop.shows(FIELD.shifted(60, 30), EMAIL);
        watcher.tick(after(start, 100), &mut desktop, &log);
        watcher.tick(after(start, 500), &mut desktop, &log);
        let moved = shows(&[EMAIL_AT.shifted(60, 30)]);
        assert_eq!(log.take(), [shows(&[EMAIL_AT]), moved.clone(), moved]);
        assert_eq!(desktop.asked_values.len(), 1, "no new measurement");
        // Just placed: taken as it is; later the value is looked for where it should be.
        assert_eq!(desktop.still_calls, 1);
        Ok(())
    }

    #[test]
    fn a_field_that_changes_size_is_placed_again() -> Result<(), String> {
        let (shared, _dir) = shared("resize")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        desktop.placed = vec![EMAIL_AT];
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        // The text lays itself out again in a field that is wider.
        let wider = Rect {
            right: FIELD.right + 200,
            ..FIELD
        };
        let again = EMAIL_AT.shifted(0, -20);
        desktop.shows(wider, EMAIL);
        desktop.placed = vec![again];
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), [shows(&[EMAIL_AT]), shows(&[again])]);
        assert_eq!(desktop.asked_values.len(), 2);
        Ok(())
    }

    #[test]
    fn text_that_scrolled_away_is_placed_again() -> Result<(), String> {
        let (shared, _dir) = shared("scroll")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        desktop.placed = vec![EMAIL_AT];
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        let scrolled = EMAIL_AT.shifted(0, -50);
        desktop.scrolled = true;
        desktop.placed = vec![scrolled];
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(desktop.asked_values.len(), 1, "just placed: taken as it is");
        watcher.tick(after(start, 500), &mut desktop, &log);
        assert_eq!(desktop.asked_values.len(), 2);
        assert_eq!(
            log.take(),
            [shows(&[EMAIL_AT]), shows(&[EMAIL_AT]), shows(&[scrolled])]
        );
        // Placed again, and checked again at the look after: it is where it should be.
        desktop.scrolled = false;
        watcher.tick(after(start, 1_000), &mut desktop, &log);
        assert_eq!(log.take(), [shows(&[scrolled])]);
        assert_eq!(desktop.asked_values.len(), 2);
        Ok(())
    }

    #[test]
    fn a_check_that_cannot_tell_is_tried_again_and_in_the_end_given_up() -> Result<(), String> {
        let (shared, _dir) = shared("unsure")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        log.unsure.set(2);
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!((log.scans.get(), log.take()), (1, Vec::<String>::new()));
        watcher.tick(after(start, 250), &mut desktop, &log);
        assert_eq!(log.scans.get(), 2, "tried again after a moment");
        watcher.tick(after(start, 500), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)], "and it could tell");

        // Never able to tell: a few tries, then no more until the text changes.
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        log.unsure.set(usize::MAX);
        for step in 0..40 {
            watcher.tick(after(start, step * 250), &mut desktop, &log);
        }
        assert_eq!(log.scans.get(), usize::from(TRIES));
        assert_eq!(log.take(), Vec::<String>::new());
        desktop.shows(FIELD, "mail jan.jansen@acme.nl nog eens");
        log.unsure.set(0);
        watcher.tick(after(start, 10_000), &mut desktop, &log);
        watcher.tick(after(start, 10_300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        Ok(())
    }

    #[test]
    fn a_focus_that_cannot_be_read_for_a_moment_does_not_make_the_outline_blink()
    -> Result<(), String> {
        let (shared, _dir) = shared("blink")?;
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(lamp(Highlight::Always));
        desktop.shows(FIELD, EMAIL);
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)]);
        // Two looks find nothing; the element and its verdict are kept.
        let focus = desktop.focus.take();
        watcher.tick(after(start, 100), &mut desktop, &log);
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "nothing is hidden");
        desktop.focus = focus;
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), [show(Mark::Pii, FIELD)], "back as it was");
        assert_eq!(log.scans.get(), 1, "the field was not checked again");
        // The third look in a row is the end of it.
        desktop.focus = None;
        for step in 4..7 {
            watcher.tick(after(start, step * 100), &mut desktop, &log);
        }
        assert_eq!(log.take(), ["hide"]);
        Ok(())
    }

    #[test]
    fn the_shortcut_outlines_the_values_and_they_follow_the_window() -> Result<(), String> {
        let (shared, _dir) = shared("hotkey-values")?;
        let purpose = lamp(Highlight::Hotkey);
        let (mut desktop, log) = (Fake::on(1, false), Log::with(&shared));
        let mut watcher = Watcher::new(Arc::clone(&purpose));
        desktop.shows(FIELD, TWO);
        desktop.placed = vec![EMAIL_AT, IBAN_AT];
        purpose.press();
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), [shows(&[EMAIL_AT, IBAN_AT])]);
        // The window moves: its bounds are read, the values are not looked for again.
        desktop.shows(FIELD.shifted(10, 20), TWO);
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(
            log.take(),
            [shows(&[EMAIL_AT.shifted(10, 20), IBAN_AT.shifted(10, 20)])]
        );
        assert_eq!(desktop.asked_values.len(), 1);
        assert_eq!((desktop.field_calls, log.scans.get()), (1, 1));
        // They stay for ten seconds.
        watcher.tick(after(start, 10_000), &mut desktop, &log);
        assert_eq!(log.take(), ["hide"]);
        Ok(())
    }
}
