//! Finding a piece of text in a UI Automation text control and saying where it is on the screen:
//! the one path that "Open at this place" (`crate::ui::goto`) and the live highlight
//! (`crate::capture`) both take, and the one place that knows how the controls of the programs
//! differ. Each draws what it finds with `crate::highlight::Overlay`.
//!
//! A [`Control`] is an element with a text pattern that is no password field (a password field is
//! never read, its text, its value or its place; one that cannot say what it is counts as one).
//! [`Control::find`] looks for a text in it and gives a [`Found`], which can be selected, scrolled
//! into view and boxed: [`Found::rects`] gives a rectangle around each line of it, as close to the
//! glyphs as the control lets it be (see [`rects`]: UI Automation's call for the rectangles of a
//! range is `unsafe`, so they are found by asking the control what text is at a point).
//!
//! What the controls of the programs do, as far as it was measured (Edge, Notepad, Word,
//! `PowerPoint`):
//!
//! - **Chromium** (Edge, Chrome, every Electron app: framework `Chrome`) answers a hit test with
//!   the character under the point. Its `FindText` over a whole page returns a range that is a
//!   character or more too late for each block of the page before it, which is put right by
//!   comparing the text of the range with the text looked for. Its range `ScrollIntoView` does
//!   nothing; the scroll item pattern of the element that encloses the range works. A hit test in
//!   one very big text node takes seconds a call, so a text in one is not boxed.
//! - **Win32 edit controls, Word and `PowerPoint`** answer with the nearest insertion point.
//! - **`PowerPoint`** reports the rectangle of the text of a shape, and not of the shape, as its
//!   rectangle once a range of it is selected; and a point beside the text gives the start of it.
//! - **Word** lays a page out when it is shown, so the rectangles of a text on another page exist
//!   after the page is scrolled to, a moment later.

mod rects;

use std::time::Duration;

use uiautomation::{
    UIElement,
    patterns::{UIScrollItemPattern, UITextPattern, UITextRange},
    types::{Point, TextPatternRangeEndpoint},
};

use self::rects::{Budget, Model, Probe, Rel};
use crate::highlight::Rect;

/// The name of the framework of Chromium's UI Automation provider.
const CHROMIUM: &str = "Chrome";
/// How many characters Chromium's reading of the text of a found range is asked for beyond the
/// text that was looked for, to see how far the range is off.
const SLACK: usize = 24;
/// The most characters of the text around a found range for which Chromium is asked where it is:
/// a hit test in a text node of more takes far too long (a node of 200,000 characters: 30 seconds
/// a call).
const MOST_AROUND: i32 = 8_000;

/// A text control that may be read: it has a text pattern and is no password field.
#[derive(Debug)]
pub(crate) struct Control {
    element: UIElement,
    pattern: UITextPattern,
    /// All of its text.
    document: UITextRange,
    /// How it answers a hit test.
    model: Model,
    /// It is a Chromium element.
    chromium: bool,
}

impl Control {
    /// The text control `element` is; `None` for a password field, a field that cannot say whether
    /// it is one, and an element without a text pattern.
    pub(crate) fn of(element: UIElement) -> Option<Self> {
        // Before anything else is asked of it: a password field is left alone entirely.
        if !matches!(element.is_password(), Ok(false)) {
            return None;
        }
        let pattern = element.get_pattern::<UITextPattern>().ok()?;
        let document = pattern.get_document_range().ok()?;
        let chromium = element
            .get_framework_id()
            .is_ok_and(|framework| framework == CHROMIUM);
        Some(Self {
            element,
            pattern,
            document,
            model: if chromium {
                Model::Under
            } else {
                Model::Nearest
            },
            chromium,
        })
    }

    /// Where `text` is in the control: the `nth` of the places that hold it, counted from 0, in
    /// the order of the text. `None` when it is not there that many times.
    pub(crate) fn find(&self, text: &str, ignore_case: bool, nth: usize) -> Option<Found> {
        let mut range = self.document.find_text(text, false, ignore_case).ok()?;
        for _ in 0..nth {
            // The text after the one found, which is the one a new range of the control is cut
            // to. The range found is not moved.
            let rest = self.pattern.get_document_range().ok()?;
            rest.move_endpoint_by_range(
                TextPatternRangeEndpoint::Start,
                &range,
                TextPatternRangeEndpoint::End,
            )
            .ok()?;
            range = rest.find_text(text, false, ignore_case).ok()?;
        }
        if self.chromium {
            put_right(&range, text, ignore_case)?;
        }
        Some(Found {
            range,
            chars: text.chars().count(),
        })
    }
}

/// Chromium's `FindText` over a page returns a range that starts `k` characters after the text
/// looked for, and has the same length: its text is the text without its first `k` characters and
/// then `k` characters that follow it. Moves both ends of `range` back by `k`, and checks what is
/// there. `None` when the text of the range is not the text looked for, that way or any other.
fn put_right(range: &UITextRange, text: &str, ignore_case: bool) -> Option<()> {
    let wanted = text.chars().count();
    let longest = i32::try_from(text.encode_utf16().count() + SLACK).ok()?;
    let read = range.get_text(longest).ok()?;
    let same = |read: &str, text: &str| {
        let head: String = read.chars().take(text.chars().count()).collect();
        if ignore_case {
            head.to_lowercase() == text.to_lowercase()
        } else {
            head == text
        }
    };
    if same(&read, text) {
        return Some(());
    }
    // The first `k` characters of the text are not in what was read.
    let back = (1..wanted).find(|&k| {
        let rest: String = text.chars().skip(k).collect();
        read.chars().take(wanted - k).collect::<String>() == rest
            || (ignore_case
                && read
                    .chars()
                    .take(wanted - k)
                    .collect::<String>()
                    .to_lowercase()
                    == rest.to_lowercase())
    })?;
    let back = i32::try_from(back).ok()?;
    for end in [
        TextPatternRangeEndpoint::Start,
        TextPatternRangeEndpoint::End,
    ] {
        range
            .move_endpoint_by_unit(end, uiautomation::types::TextUnit::Character, -back)
            .ok()?;
    }
    let now = range.get_text(longest).ok()?;
    same(&now, text).then_some(())
}

/// A piece of text found in a [`Control`].
#[derive(Debug)]
pub(crate) struct Found {
    range: UITextRange,
    /// How many characters it has.
    chars: usize,
}

impl Found {
    /// Selects it, as a user would: the control shows it selected. Whether that worked.
    pub(crate) fn select(&self) -> bool {
        self.range.select().is_ok()
    }

    /// Brings it into view, as far as the control lets it be done through the range.
    pub(crate) fn scroll_into_view(&self) {
        // Wherever it is, it is in view after this, if the control lets it be.
        let _ = self.range.scroll_into_view(false);
    }

    /// Brings the element that encloses it into view: for the controls whose range does not scroll
    /// (Chromium's). Whether there was such an element that could.
    pub(crate) fn scroll_enclosing(&self) -> bool {
        let Ok(element) = self.range.get_enclosing_element() else {
            return false;
        };
        element
            .get_pattern::<UIScrollItemPattern>()
            .and_then(|item| item.scroll_into_view())
            .is_ok()
    }

    /// A rectangle around each line of it that is in view, in reading order, found within `within`;
    /// `Some` and empty when none of it is in view. `None` when the control cannot say, or is too
    /// slow to ask.
    pub(crate) fn rects(&self, control: &Control, within: Duration) -> Option<Vec<Rect>> {
        let area = self.area(control)?;
        if control.chromium && self.around_is_big() {
            return None;
        }
        rects::locate(
            &mut Hits::new(control, &self.range),
            area,
            control.model,
            self.chars,
            Budget::within(within),
        )
    }

    /// Whether it is still at `rect`, where [`Found::rects`] said it was: the text may have
    /// scrolled or moved since.
    pub(crate) fn is_at(&self, control: &Control, rect: Rect) -> bool {
        // A point a little in from the start of the rectangle: a text of one character has no more
        // of it before the middle.
        let x = rect.left + rect.width() / 4;
        let y = rect.top + rect.height() / 2;
        matches!(
            Hits::new(control, &self.range).rel(x, y),
            Some(Rel::At | Rel::Inside)
        )
    }

    /// Where the control is asked about the text: its own rectangle, cut to the one of the element
    /// that encloses the text when there is one (Chromium answers a point of a page's background
    /// with the start of the page, and a rectangle of a page of Word is the text of it).
    fn area(&self, control: &Control) -> Option<Rect> {
        let element = bounds(&control.element)?;
        let enclosing = self
            .range
            .get_enclosing_element()
            .ok()
            .and_then(|enclosing| bounds(&enclosing));
        Some(
            enclosing
                .and_then(|enclosing| intersection(element, enclosing))
                .unwrap_or(element),
        )
    }

    /// Whether the text node around it is too big for hit tests in Chromium.
    fn around_is_big(&self) -> bool {
        let Ok(element) = self.range.get_enclosing_element() else {
            return false;
        };
        element
            .get_pattern::<UITextPattern>()
            .ok()
            .and_then(|pattern| pattern.get_document_range().ok())
            .and_then(|range| range.get_text(MOST_AROUND).ok())
            .is_some_and(|text| {
                text.encode_utf16().count() >= usize::try_from(MOST_AROUND).unwrap_or(usize::MAX)
            })
    }
}

/// The hit tests of a [`Control`] against a [`Found`].
struct Hits<'a> {
    pattern: &'a UITextPattern,
    found: &'a UITextRange,
    /// The range at the point that [`Probe::pin`] was asked about.
    pinned: Option<UITextRange>,
}

impl<'a> Hits<'a> {
    fn new(control: &'a Control, found: &'a UITextRange) -> Self {
        Self {
            pattern: &control.pattern,
            found,
            pinned: None,
        }
    }

    /// The text at the screen point; `None` when the control does not say.
    fn at(&self, x: i32, y: i32) -> Option<UITextRange> {
        self.pattern.get_range_from_point(Point::new(x, y)).ok()
    }
}

impl Probe for Hits<'_> {
    fn rel(&mut self, x: i32, y: i32) -> Option<Rel> {
        let at = self.at(x, y)?;
        let start = TextPatternRangeEndpoint::Start;
        let from_start = at.compare_endpoints(start, self.found, start).ok()?;
        if from_start < 0 {
            return Some(Rel::Before);
        }
        if from_start == 0 {
            return Some(Rel::At);
        }
        let to_end = at
            .compare_endpoints(start, self.found, TextPatternRangeEndpoint::End)
            .ok()?;
        Some(if to_end < 0 { Rel::Inside } else { Rel::After })
    }

    fn pin(&mut self, x: i32, y: i32) -> Option<()> {
        self.pinned = Some(self.at(x, y)?);
        Some(())
    }

    fn same(&mut self, x: i32, y: i32) -> Option<bool> {
        let at = self.at(x, y)?;
        let pinned = self.pinned.as_ref()?;
        let start = TextPatternRangeEndpoint::Start;
        Some(at.compare_endpoints(start, pinned, start).ok()? == 0)
    }
}

/// Where `element` is on the screen.
pub(crate) fn bounds(element: &UIElement) -> Option<Rect> {
    let rect = element.get_bounding_rectangle().ok()?;
    Rect::field(
        rect.get_left(),
        rect.get_top(),
        rect.get_right(),
        rect.get_bottom(),
    )
}

/// What `one` and `other` have in common; `None` when it is nothing, or too little to ask about.
fn intersection(one: Rect, other: Rect) -> Option<Rect> {
    Rect::field(
        one.left.max(other.left),
        one.top.max(other.top),
        one.right.min(other.right),
        one.bottom.min(other.bottom),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect {
            left,
            top,
            right,
            bottom,
        }
    }

    #[test]
    fn what_two_rectangles_share_is_where_a_text_is_asked_about() {
        // A page's text column inside the pane of the document.
        let pane = rect(0, 100, 1600, 1200);
        let column = rect(300, 90, 1300, 900);
        assert_eq!(intersection(pane, column), Some(rect(300, 100, 1300, 900)));
        // Next to each other, or only a sliver in common: nothing.
        assert_eq!(intersection(pane, rect(1600, 100, 1800, 900)), None);
        assert_eq!(intersection(pane, rect(0, 1195, 1600, 1400)), None);
    }
}
