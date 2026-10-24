//! [`Watcher`]: what the loop does with each look at the focus.

use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use piikey::policy::Highlight;

use super::{
    FAST, SETTLE, SLOW,
    desktop::{Clip, Desktop, Focus},
    outline::Outline,
    sink::Sink,
};
use crate::proxy::Purpose;

/// Looks at a clipboard change that another program held open, this many times before it is
/// given up: a copy keeps the clipboard open for a moment while it is written.
const CLIP_TRIES: u8 = 10;
/// Looks in a row that find nothing readable in focus before the element is let go of.
const LOST_AFTER: u8 = 3;

/// What the loop knows about the field it is looking at, and when to hand its text on.
pub(super) struct Watcher {
    purpose: Arc<Purpose>,
    /// The element that has the focus.
    focus: Option<Focus>,
    /// Looks in a row that found nothing readable in focus.
    lost: u8,
    /// That element is in a protected page or program: its text and the clipboard are read.
    protected: bool,
    /// What the field held when it was last read.
    text: String,
    /// When the field last changed, while what it held has been pushed but not yet flushed.
    pushed: Option<Instant>,
    /// The clipboard as last seen.
    clipboard: Option<NonZeroU32>,
    /// The clipboard change that was found busy, and how many looks found it so.
    busy: Option<(NonZeroU32, u8)>,
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
    pub(super) fn new(purpose: Arc<Purpose>) -> Self {
        Self {
            focus: None,
            lost: 0,
            protected: false,
            text: String::new(),
            pushed: None,
            clipboard: None,
            busy: None,
            masking: purpose.mask(),
            mode: purpose.highlight(),
            outline: Outline::new(purpose.presses()),
            purpose,
        }
    }

    /// How long to wait before the next [`tick`](Self::tick).
    pub(super) fn period(&self) -> Duration {
        if self.protected || self.mode == Highlight::Always || self.outline.is_up() {
            FAST
        } else {
            SLOW
        }
    }

    /// Whether the shortcut was pressed since the last look: the worker does not wait for it.
    pub(super) fn pressed(&self) -> bool {
        self.outline.pressed(&self.purpose)
    }

    /// One look at the focus. Text is pushed as soon as it changes, so a request sent a moment
    /// later finds it; detection runs once the text has been still for [`SETTLE`], when it is
    /// cleared (a chat box empties as its message is sent), when the focus leaves it, and for a
    /// paste at once. Then the outline of the field is brought up to date.
    pub(super) fn tick(&mut self, now: Instant, desktop: &mut impl Desktop, sink: &impl Sink) {
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
        let Some(focus) = desktop.focus(self.protected || mode == Highlight::Always) else {
            // The focus can be unreadable for a moment while an app redraws: the element is let go
            // of only when it stays so for a few looks, or the outline would blink.
            self.lost = self.lost.saturating_add(1);
            if self.lost >= LOST_AFTER {
                self.leave(sink);
            }
            // A press has nothing to outline now. It is taken in all the same: while it is not,
            // the worker does not wait for the next look, and would look again at once, and again.
            self.outline.take_presses(&self.purpose);
            return;
        };
        self.lost = 0;
        if self.focus.as_ref() != Some(&focus) {
            self.leave(sink);
            self.protected = mask && !focus.password && desktop.protected();
            self.focus = Some(focus);
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
        self.lost = 0;
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
        match desktop.clipboard_text() {
            Clip::Text(text) => {
                self.clipboard = Some(seq);
                // The clipboard keeps Windows line ends; a page has only `\n`.
                sink.push(text.replace("\r\n", "\n"));
                sink.flush();
                self.pushed = None;
            }
            Clip::NoText => self.clipboard = Some(seq),
            // The change is looked at again at the next look, until it is given up.
            Clip::Busy => {
                let looks = match self.busy {
                    Some((busy, looks)) if busy == seq => looks + 1,
                    _ => 1,
                };
                if looks < CLIP_TRIES {
                    self.busy = Some((seq, looks));
                } else {
                    self.busy = None;
                    self.clipboard = Some(seq);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capture::testing::{EMAIL, FIELD, Fake, Log, after, lamp, shared, show},
        highlight::Mark,
    };

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
        desktop.moves_to(2, true);
        watcher.tick(after(start, 100), &mut desktop, &log);
        // The new field holds the same words: it is another field, so they are read again.
        assert_eq!(log.take(), ["push Zoë Müller", "flush", "push Zoë Müller"]);
        assert_eq!(desktop.protected_calls, 2);
        desktop.moves_to(3, false);
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
        let start = Instant::now();
        watcher.tick(start, &mut desktop, &log);
        watcher.tick(after(start, 100), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(desktop.clipboard_reads, 1, "nothing to ask again");
    }

    #[test]
    fn a_clipboard_another_program_holds_open_is_read_at_a_later_look() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        // The program that copied still writes the clipboard when it is first looked at.
        desktop.copies(5, "NL91ABNA0417164300");
        desktop.busy = 3;
        for step in 0..3 {
            watcher.tick(after(start, step * 100), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new(), "not yet readable");
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), ["push NL91ABNA0417164300", "flush"]);
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(log.take(), Vec::<String>::new(), "read once");
        assert_eq!(desktop.clipboard_reads, 4);
    }

    #[test]
    fn a_clipboard_that_stays_busy_is_given_up() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        desktop.copies(5, "NL91ABNA0417164300");
        desktop.busy = usize::MAX;
        let start = Instant::now();
        for step in 0..u64::from(CLIP_TRIES) * 3 {
            watcher.tick(after(start, step * 100), &mut desktop, &log);
        }
        assert_eq!(log.take(), Vec::<String>::new());
        assert_eq!(desktop.clipboard_reads, usize::from(CLIP_TRIES));
        // The next change starts with a clean slate.
        desktop.busy = 0;
        desktop.copies(6, "jan.jansen@acme.nl");
        watcher.tick(after(start, 10_000), &mut desktop, &log);
        assert_eq!(log.take(), ["push jan.jansen@acme.nl", "flush"]);
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
        // Unreadable for a moment is not gone: the element is let go of at the third look.
        for step in 1..LOST_AFTER {
            watcher.tick(after(start, u64::from(step) * 100), &mut desktop, &log);
        }
        assert_eq!(log.take(), ["push iban NL91ABNA0417164300"]);
        assert_eq!(watcher.period(), FAST);
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), ["flush"]);
        assert_eq!(watcher.period(), SLOW);
        // Back on a protected element: decided afresh.
        desktop.moves_to(1, true);
        watcher.tick(after(start, 400), &mut desktop, &log);
        assert_eq!(desktop.protected_calls, 2);
    }

    #[test]
    fn a_focus_that_comes_back_at_once_is_the_same_element() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.types("iban NL91ABNA0417164300");
        watcher.tick(start, &mut desktop, &log);
        let focus = desktop.focus.take();
        watcher.tick(after(start, 100), &mut desktop, &log);
        desktop.focus = focus;
        watcher.tick(after(start, 200), &mut desktop, &log);
        // Nothing was flushed or decided again: the field was not left.
        assert_eq!(log.take(), ["push iban NL91ABNA0417164300"]);
        assert_eq!(desktop.protected_calls, 1);
    }

    #[test]
    fn a_field_that_turns_into_a_password_field_is_read_no_more() {
        let (mut desktop, log, mut watcher) =
            (Fake::on(1, true), Log::default(), Watcher::default());
        let start = Instant::now();
        desktop.types("mail jan.jansen@acme.nl");
        watcher.tick(start, &mut desktop, &log);
        assert_eq!(log.take(), ["push mail jan.jansen@acme.nl"]);
        // The same element, now hiding what it holds.
        desktop.password = true;
        desktop.types("hunter2 NL91ABNA0417164300");
        watcher.tick(after(start, 100), &mut desktop, &log);
        watcher.tick(after(start, 200), &mut desktop, &log);
        assert_eq!(log.take(), ["flush"], "what was typed before is read now");
        assert_eq!(desktop.text_calls, 1, "the password field is not read");
        assert_eq!(desktop.protected_calls, 1, "and not even asked about");
        assert_eq!(watcher.period(), SLOW);
        // It shows its text again: judged afresh, and read.
        desktop.password = false;
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), ["push hunter2 NL91ABNA0417164300"]);
        assert_eq!(desktop.protected_calls, 2);
    }

    #[test]
    fn a_press_with_nothing_in_focus_does_not_keep_the_worker_looking() {
        for mode in [Highlight::Off, Highlight::Always, Highlight::Hotkey] {
            let purpose = lamp(mode);
            let (mut desktop, log) = (Fake::on(1, false), Log::default());
            desktop.focus = None;
            let mut watcher = Watcher::new(Arc::clone(&purpose));
            purpose.press();
            assert!(watcher.pressed(), "{mode:?}: it wakes the worker");
            watcher.tick(Instant::now(), &mut desktop, &log);
            assert!(
                !watcher.pressed(),
                "{mode:?}: the worker would look again at once"
            );
            assert_eq!(log.take(), Vec::<String>::new(), "{mode:?}");
        }
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
        // The field is met for the first time: its text goes to the store and is checked at once.
        assert_eq!(
            log.take(),
            [format!("push {EMAIL}"), show(Mark::Pii, FIELD)]
        );
        watcher.tick(after(start, 300), &mut desktop, &log);
        assert_eq!(log.take(), ["flush".to_owned(), show(Mark::Pii, FIELD)]);
        assert_eq!(desktop.protected_calls, 1);
        Ok(())
    }
}
