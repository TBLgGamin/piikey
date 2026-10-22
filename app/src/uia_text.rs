//! Finding a piece of text in a UI Automation text control and saying where it is on the screen:
//! the one path that "Open at this place" (`crate::ui::goto`) and the live highlight
//! (`crate::capture`) both take, and the one place that knows how the controls of the programs
//! differ. Each draws what it finds with `crate::highlight::Overlay`.
//!
//! A [`Control`] is an element with a text pattern that is no password field (a password field is
//! never read, its text, its value or its place; one that cannot say what it is counts as one).
//! [`Control::find`] looks for a text in it and gives a [`Found`], which can be selected, scrolled
//! into view and boxed: [`Found::rects`] gives a rectangle around each line of it, exactly where the
//! control draws it ([`UITextRange::get_bounding_rectangles`], from the patched `uiautomation`; see
//! the root `Cargo.toml`). A control that cannot report them is measured by asking it what text is
//! at a point ([`rects`]). [`Control::at_caret`] gives the text at the caret, for an editor that was
//! sent to the value.
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

    /// `text` where the caret of the control is, when it starts there: what an editor that was
    /// sent to the place of the value (VS Code's `--goto`) shows. `None` when the control has no
    /// caret, or the text after it is another.
    pub(crate) fn at_caret(&self, text: &str, ignore_case: bool) -> Option<Found> {
        let range = self.pattern.get_selection().ok()?.into_iter().next()?;
        let start = TextPatternRangeEndpoint::Start;
        // The caret, not a selection that starts somewhere else.
        if range
            .compare_endpoints(start, &range, TextPatternRangeEndpoint::End)
            .ok()?
            != 0
        {
            return None;
        }
        let chars = text.chars().count();
        range
            .move_endpoint_by_unit(
                TextPatternRangeEndpoint::End,
                uiautomation::types::TextUnit::Character,
                i32::try_from(chars).ok()?,
            )
            .ok()?;
        let read = range
            .get_text(i32::try_from(text.encode_utf16().count()).ok()?)
            .ok()?;
        let same = if ignore_case {
            read.to_lowercase() == text.to_lowercase()
        } else {
            read == text
        };
        same.then_some(Found { range, chars })
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
    ///
    /// The control is asked for them ([`UITextRange::get_bounding_rectangles`]): that is exact, and
    /// one call. Only a control that cannot answer is found out by hit tests ([`rects`]).
    pub(crate) fn rects(&self, control: &Control, within: Duration) -> Option<Vec<Rect>> {
        let area = self.area(control)?;
        if let Some(lines) = self.reported(area) {
            return Some(lines);
        }
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

    /// The rectangles the control reports for the range, a line each, cut to `area`; `None` when
    /// it cannot report them.
    fn reported(&self, area: Rect) -> Option<Vec<Rect>> {
        let rects = self.range.get_bounding_rectangles().ok()?;
        Some(lines(
            rects
                .iter()
                .filter_map(|rect| {
                    Rect::text(
                        rect.get_left(),
                        rect.get_top(),
                        rect.get_right(),
                        rect.get_bottom(),
                    )
                })
                .filter_map(|rect| text_in(rect, area))
                .collect(),
        ))
    }

    /// Whether it is still at `rect`, where [`Found::rects`] said it was: the text may have
    /// scrolled or moved since.
    pub(crate) fn is_at(&self, control: &Control, rect: Rect) -> bool {
        if let Ok(now) = self.range.get_bounding_rectangles() {
            return now.first().is_some_and(|first| {
                near(first.get_left(), rect.left) && near(first.get_top(), rect.top)
            });
        }
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

/// The part of the text rectangle `rect` that lies in `area`; `None` when none does (a line
/// scrolled out of the control).
fn text_in(rect: Rect, area: Rect) -> Option<Rect> {
    Rect::text(
        rect.left.max(area.left),
        rect.top.max(area.top),
        rect.right.min(area.right),
        rect.bottom.min(area.bottom),
    )
}

/// One rectangle per line: a control may report a line in pieces (Chromium reports each run of
/// text), which are joined when they share most of their height.
fn lines(rects: Vec<Rect>) -> Vec<Rect> {
    let mut joined: Vec<Rect> = Vec::new();
    for rect in rects {
        match joined.last_mut() {
            Some(line) if same_line(*line, rect) => {
                *line = Rect {
                    left: line.left.min(rect.left),
                    top: line.top.min(rect.top),
                    right: line.right.max(rect.right),
                    bottom: line.bottom.max(rect.bottom),
                };
            }
            _ => joined.push(rect),
        }
    }
    joined
}

/// Whether two rectangles of text are on one line: they share more than half of the smaller one's
/// height.
fn same_line(one: Rect, other: Rect) -> bool {
    let shared = one.bottom.min(other.bottom) - one.top.max(other.top);
    shared * 2 > one.height().min(other.height())
}

/// Whether two coordinates are the same place, give or take a pixel or two of rounding.
fn near(one: i32, other: i32) -> bool {
    (one - other).abs() <= 2
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

    #[test]
    fn the_pieces_a_control_reports_of_a_line_are_one_rectangle_and_lines_stay_apart() {
        // Chromium reports "jan.jansen" and "@example.nl" as two runs of one line, then a wrapped
        // second line.
        let reported = vec![
            rect(100, 200, 180, 218),
            rect(180, 201, 260, 219),
            rect(20, 220, 90, 238),
        ];
        assert_eq!(
            lines(reported),
            [rect(100, 200, 260, 219), rect(20, 220, 90, 238)]
        );
        assert!(lines(Vec::new()).is_empty());
    }

    #[test]
    fn a_line_is_cut_to_the_control_and_a_line_outside_it_is_left_out() {
        let area = rect(0, 100, 500, 400);
        // Half scrolled out at the top: the part in view.
        assert_eq!(
            text_in(rect(50, 90, 200, 110), area),
            Some(rect(50, 100, 200, 110))
        );
        // Scrolled out entirely.
        assert_eq!(text_in(rect(50, 20, 200, 40), area), None);
    }
}
