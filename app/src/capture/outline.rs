//! [`Outline`]: when the field in focus is outlined, and in which colour.

use std::time::Instant;

use piikey::policy::Highlight;

use super::{
    FLASH_FOR, SETTLE, SHOW_FOR,
    desktop::{Desktop, Field},
    sink::Sink,
};
use crate::{highlight::Mark, proxy::Purpose};

/// Bytes of a field that are checked for personal data; a field with more is checked as far as
/// that, as [`Typed`](crate::proxy::Typed) keeps no more of a text either.
const MAX_SCAN: usize = 256 << 10;

/// The part of `text` that is checked for personal data.
fn checked(text: &str) -> &str {
    &text[..text.floor_char_boundary(MAX_SCAN)]
}

/// What the loop knows about the outline of the field in focus.
pub(super) struct Outline {
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
    pub(super) fn new(presses: u64) -> Self {
        Self {
            text: String::new(),
            changed: None,
            pii: false,
            up: None,
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
            desktop.moves_to(2, false);
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
    fn a_long_field_is_checked_as_far_as_the_limit_and_not_through_a_character() {
        let text = "é".repeat(MAX_SCAN);
        let part = checked(&text);
        assert!(part.len() <= MAX_SCAN && MAX_SCAN - part.len() < 4);
        assert_eq!(checked("kort"), "kort");
    }
}
