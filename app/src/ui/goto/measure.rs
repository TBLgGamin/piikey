//! Where on the screen a piece of text is, for a text control that cannot say.
//!
//! UI Automation can give the rectangles of a range of text, but only through a call that is
//! `unsafe` to make, and `unsafe` is forbidden here. What the safe wrapper does offer is a hit
//! test: the text position nearest to a point of the screen, and whether that position lies before
//! the start of the found text or before its end. [`Probe`] is that, and [`locate`] finds the
//! rectangle of the found text by asking it about points. It knows nothing of Windows: the tests run
//! it against a text control made of a grid of cells.
//!
//! The text positions along a column of points grow from the top to the bottom of the control, and
//! along a row of points from the left to the right, so each edge of the box is where an answer
//! turns over, found by halving (see [`first_true`] and [`last_true`]):
//!
//! - **top**: at the right side, the first row whose last position is at or after the start. That
//!   row holds the start.
//! - **single line**: at the right side of that row, a last position that is at or after the end
//!   means the text ends on the row too.
//! - **bottom**: at the left side, the last row whose first position is before the end. That row
//!   holds the end.
//! - **left and right**, for a text on one row, along its middle: the first point whose position
//!   is at or after the start, and the last whose position is before the end.
//!
//! A text over several rows is boxed as those rows over the whole width of the control. The box of
//! a text on one row is checked: its middle must hold the text, and it must lie in the control.
//! Anything that fails the check falls back to the whole rows, and a control that stops answering
//! before the rows are known gives no box at all.
//!
//! Controls differ in what they answer for a point that is between two characters, or past the
//! end of a row: the nearest insertion point (the end of the row), or the character that is there
//! (the last of the row). The box is therefore made a little bigger than the text on both sides,
//! which covers half a character either way. A text that ends at the end of its row in a control
//! of the second kind cannot be told from a text that goes on in the next row, and gets the whole
//! row. Likewise a text that starts at the very start of a row that wraps the line above, in a
//! control of the first kind, gets that line too.

use crate::highlight::Rect;

/// The most questions asked of the control: each is a call or two into the program that owns it,
/// and each of the four searches needs about a dozen, a few more in the biggest control.
const BUDGET: u32 = 64;
/// By how many pixels an edge may be off, on the side that makes the box bigger.
const PRECISION: i32 = 3;
/// Pixels between the left edge of the control and the points asked at its left: its border.
const LEFT_GAP: i32 = 4;
/// Pixels between the top and bottom edges of the control and the rows asked about.
const EDGE_GAP: i32 = 2;
/// The room left at the right of the control, a tenth of its width between these: its scroll bar
/// is inside its rectangle and says nothing about the text.
const MIN_INSET: i32 = 12;
const MAX_INSET: i32 = 48;
/// The fewest pixels, across and down, the points asked about must span.
const MIN_SPAN: i32 = 8;
/// What a box around the text of one row grows by to the left and right, a fifth of the height of
/// the row between these: half a character is about that much.
const MIN_PAD: i32 = 2;
const MAX_PAD: i32 = 8;

/// What a text control says about the text position at a point of the screen, against the found
/// text. `None` is "cannot say".
pub(super) trait Probe {
    /// Whether the text position at the point is at or after the start of the found text.
    fn at_or_after_start(&mut self, x: i32, y: i32) -> Option<bool>;
    /// Whether the text position at the point is before the end of the found text.
    fn before_end(&mut self, x: i32, y: i32) -> Option<bool>;
}

/// The rectangle of the found text in `control`, a rectangle on the screen: the text itself when it
/// is on one row, else its rows over the whole width of the control. `None` when the control
/// cannot say (or is too small to ask), and the text is then not outlined.
pub(super) fn locate(probe: &mut impl Probe, control: Rect) -> Option<Rect> {
    Asked {
        probe,
        left: BUDGET,
    }
    .locate(control)
}

/// The probe, counted: a search stops when the control does not answer and when the budget is
/// spent.
struct Asked<'a, P: Probe> {
    probe: &'a mut P,
    left: u32,
}

/// Why a search ends without an answer: the control did not say, or too much was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stop;

type Answer<T> = Result<T, Stop>;

/// The points that may be asked about: `left..right` across and `top..bottom` down, in the
/// control.
#[derive(Debug, Clone, Copy)]
struct Area {
    left: i32,
    right: i32,
    top: i32,
    bottom: i32,
}

impl Area {
    /// What of `control` is asked about; `None` when that is too little.
    fn of(control: Rect) -> Option<Self> {
        let inset = ((control.right - control.left) / 10).clamp(MIN_INSET, MAX_INSET);
        let area = Self {
            left: control.left + LEFT_GAP,
            right: control.right - inset,
            top: control.top + EDGE_GAP,
            bottom: control.bottom - EDGE_GAP,
        };
        (area.right - area.left >= MIN_SPAN && area.bottom - area.top >= MIN_SPAN).then_some(area)
    }
}

/// The rows the found text is on.
#[derive(Debug, Clone, Copy)]
struct Rows {
    top: i32,
    /// The first pixel below the last row.
    bottom: i32,
    /// The text ends on the row it starts on.
    single: bool,
}

/// Where an answer turns over, found to within [`PRECISION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Edge {
    /// At or beyond the turn, on the side of the bigger box: the edge to draw at.
    outer: i32,
    /// A value that the answer was `true` for.
    inner: i32,
}

impl<P: Probe> Asked<'_, P> {
    fn spend(&mut self) -> Answer<()> {
        self.left = self.left.checked_sub(1).ok_or(Stop)?;
        Ok(())
    }

    fn at_or_after_start(&mut self, x: i32, y: i32) -> Answer<bool> {
        self.spend()?;
        self.probe.at_or_after_start(x, y).ok_or(Stop)
    }

    fn before_end(&mut self, x: i32, y: i32) -> Answer<bool> {
        self.spend()?;
        self.probe.before_end(x, y).ok_or(Stop)
    }

    fn locate(&mut self, control: Rect) -> Option<Rect> {
        let area = Area::of(control)?;
        let rows = self.rows(area).ok()??;
        let band = Rect {
            left: control.left,
            top: rows.top,
            right: control.right,
            bottom: rows.bottom,
        };
        if !rows.single {
            return Some(band);
        }
        // Whatever goes wrong from here on, the rows are known: that is the fallback.
        let text = self.text_box(area, rows, control).ok().flatten();
        Some(text.unwrap_or(band))
    }

    /// The rows of the found text, in the area.
    fn rows(&mut self, area: Area) -> Answer<Option<Rows>> {
        let column = area.right - 1;
        let Some(top) = first_true(area.top, area.bottom, |y| self.at_or_after_start(column, y))?
        else {
            return Ok(None);
        };
        // `top.inner` is on the row of the start. Its last position is at or after the end when
        // the text ends there too.
        let single = !self.before_end(column, top.inner)?;
        let Some(bottom) = last_true(top.inner, area.bottom, |y| self.before_end(area.left, y))?
        else {
            return Ok(None);
        };
        let (top, bottom) = (top.outer, bottom.outer + 1);
        Ok((bottom > top).then_some(Rows {
            top,
            bottom,
            single,
        }))
    }

    /// The box of the found text on its one row: its characters, a little bigger. `None` when the
    /// answers do not make a box that is in the control and holds the text at its middle.
    fn text_box(&mut self, area: Area, rows: Rows, control: Rect) -> Answer<Option<Rect>> {
        let y = rows.top + (rows.bottom - rows.top) / 2;
        let Some(left) = first_true(area.left, area.right, |x| self.at_or_after_start(x, y))?
        else {
            return Ok(None);
        };
        let Some(right) = last_true(left.outer, area.right, |x| self.before_end(x, y))? else {
            return Ok(None);
        };
        let text = Rect {
            left: left.outer,
            top: rows.top,
            right: right.outer + 1,
            bottom: rows.bottom,
        };
        if text.right <= text.left || !contains(control, text) {
            return Ok(None);
        }
        let pad = ((rows.bottom - rows.top) / 5).clamp(MIN_PAD, MAX_PAD);
        let field = Rect {
            left: (text.left - pad).max(control.left),
            right: (text.right + pad).min(control.right),
            ..text
        };
        let (x, y) = (
            i32::midpoint(field.left, field.right),
            i32::midpoint(field.top, field.bottom),
        );
        Ok((self.at_or_after_start(x, y)? && self.before_end(x, y)?).then_some(field))
    }
}

/// Whether `inner` lies within `outer`.
fn contains(outer: Rect, inner: Rect) -> bool {
    inner.left >= outer.left
        && inner.right <= outer.right
        && inner.top >= outer.top
        && inner.bottom <= outer.bottom
}

/// Where `yes`, which is `false` below some value and `true` from it, turns `true`, for the values
/// `lo..hi`. `None` when it is `true` for none of them. The turn is found by halving: `outer` is
/// at most [`PRECISION`] before the turn, and `yes` held at `inner`.
fn first_true(lo: i32, hi: i32, mut yes: impl FnMut(i32) -> Answer<bool>) -> Answer<Option<Edge>> {
    let (mut outer, mut inner) = (lo, hi - 1);
    if lo >= hi || !yes(inner)? {
        return Ok(None);
    }
    while inner - outer > PRECISION {
        let middle = outer + (inner - outer) / 2;
        if yes(middle)? {
            inner = middle;
        } else {
            outer = middle + 1;
        }
    }
    Ok(Some(Edge { outer, inner }))
}

/// Where `yes`, which is `true` up to some value and `false` after it, turns `false`, for the
/// values `lo..hi`. `None` when it is not `true` at `lo`. `outer` is at most [`PRECISION`] after
/// the last value it held for, and `yes` held at `inner`.
fn last_true(lo: i32, hi: i32, mut yes: impl FnMut(i32) -> Answer<bool>) -> Answer<Option<Edge>> {
    let (mut inner, mut outer) = (lo, hi - 1);
    if lo >= hi || !yes(inner)? {
        return Ok(None);
    }
    while outer - inner > PRECISION {
        let middle = outer - (outer - inner) / 2;
        if yes(middle)? {
            inner = middle;
        } else {
            outer = middle - 1;
        }
    }
    Ok(Some(Edge { outer, inner }))
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;

    /// The control: 600 × 300 pixels. It is asked about the points `104..652` across (its width
    /// less a gap at the left and, at the right, a tenth of its width, but 48 pixels at most) and
    /// `52..348` down.
    const CONTROL: Rect = Rect {
        left: 100,
        top: 50,
        right: 700,
        bottom: 350,
    };
    /// Where the first character is, and the size of a cell.
    const ORIGIN: (i32, i32) = (104, 52);
    const CELL: (i32, i32) = (8, 20);
    /// The columns of a row.
    const COLUMNS: usize = 60;

    /// A text control made of rows of 60 cells of 8 × 20 pixels. It says what text position lies
    /// at a point, and counts what it is asked.
    struct Grid {
        rows: usize,
        /// Every row is a line of its own, with a line break after it that takes one text
        /// position; else the rows are one line that wraps, and each starts at the text position
        /// where the one before ends.
        breaks: bool,
        /// The found text, as text positions.
        found: Range<usize>,
        /// A point between two characters belongs to the nearer one, and one past the end of a row
        /// to its end, as for a control that answers with the nearest insertion point; else it
        /// belongs to the character it is on, and one past the end of a row to the last one.
        nearest: bool,
        asked: usize,
        /// The number of questions it answers; none after.
        answers: Option<usize>,
    }

    impl Grid {
        fn new(rows: usize, breaks: bool, found: Range<usize>, nearest: bool) -> Self {
            Self {
                rows,
                breaks,
                found,
                nearest,
                asked: 0,
                answers: None,
            }
        }

        /// The text position at the screen point.
        fn position(&self, x: i32, y: i32) -> usize {
            let row = index((y - ORIGIN.1) / CELL.1).min(self.rows.saturating_sub(1));
            let half = if self.nearest { CELL.0 / 2 } else { 0 };
            let column = index((x - ORIGIN.0 + half) / CELL.0);
            let last = if self.nearest { COLUMNS } else { COLUMNS - 1 };
            row * (COLUMNS + usize::from(self.breaks)) + column.min(last)
        }

        /// Counts a question; `None` once the control has answered all it does.
        fn ask(&mut self) -> Option<()> {
            self.asked += 1;
            self.answers
                .is_none_or(|answers| self.asked <= answers)
                .then_some(())
        }
    }

    fn index(value: i32) -> usize {
        usize::try_from(value.max(0)).unwrap_or_default()
    }

    impl Probe for Grid {
        fn at_or_after_start(&mut self, x: i32, y: i32) -> Option<bool> {
            self.ask()?;
            Some(self.position(x, y) >= self.found.start)
        }

        fn before_end(&mut self, x: i32, y: i32) -> Option<bool> {
            self.ask()?;
            Some(self.position(x, y) < self.found.end)
        }
    }

    /// A control that answers right at the edges of the area that is asked about (`104` and
    /// `651`), where the rows are found, and in between says what contradicts them: nothing is at
    /// or after the start, everything is before the end.
    struct Edges(Grid);

    impl Probe for Edges {
        fn at_or_after_start(&mut self, x: i32, y: i32) -> Option<bool> {
            if x == 104 || x == 651 {
                self.0.at_or_after_start(x, y)
            } else {
                Some(false)
            }
        }

        fn before_end(&mut self, x: i32, y: i32) -> Option<bool> {
            if x == 104 || x == 651 {
                self.0.before_end(x, y)
            } else {
                Some(true)
            }
        }
    }

    /// The pixels of the cells `from..to` (columns) of the row `row`.
    fn cells(row: i32, from: i32, to: i32) -> Rect {
        Rect {
            left: ORIGIN.0 + from * CELL.0,
            top: ORIGIN.1 + row * CELL.1,
            right: ORIGIN.0 + to * CELL.0,
            bottom: ORIGIN.1 + (row + 1) * CELL.1,
        }
    }

    fn grown(rect: Rect, across: i32, down: i32) -> Rect {
        Rect {
            left: rect.left - across,
            top: rect.top - down,
            right: rect.right + across,
            bottom: rect.bottom + down,
        }
    }

    /// The box `locate` gives for text in a grid of `rows` rows, from a control of each kind: what
    /// it says about points past the end of a row differs (`nearest`, see [`Grid`]). Each is
    /// listed with the number of questions it took.
    fn boxes(
        rows: usize,
        breaks: bool,
        found: Range<usize>,
    ) -> Result<Vec<(bool, Rect, usize)>, String> {
        [false, true]
            .into_iter()
            .map(|nearest| {
                let mut grid = Grid::new(rows, breaks, found.clone(), nearest);
                locate(&mut grid, CONTROL)
                    .map(|rect| (nearest, rect, grid.asked))
                    .ok_or_else(|| format!("no box (nearest: {nearest})"))
            })
            .collect()
    }

    /// The box of rows that fills the width of the control.
    fn line(top: i32, bottom: i32) -> Rect {
        Rect {
            left: CONTROL.left,
            top,
            right: CONTROL.right,
            bottom,
        }
    }

    #[test]
    fn a_value_on_one_line_gets_a_box_around_its_characters() -> Result<(), String> {
        // Characters 10 to 21 of the second row, whose first character is the 61st.
        let characters = cells(1, 10, 21);
        for (nearest, found, asked) in boxes(5, true, 71..82)? {
            assert!(
                contains(found, characters),
                "{found:?} is not around {characters:?} (nearest: {nearest})"
            );
            // Not much bigger: a few pixels each way.
            assert!(
                contains(grown(characters, 12, 4), found),
                "{found:?} is too big for {characters:?} (nearest: {nearest})"
            );
            assert!(asked <= 45, "{asked} questions (nearest: {nearest})");
        }
        Ok(())
    }

    #[test]
    fn a_value_over_two_lines_gets_the_whole_width_of_both() -> Result<(), String> {
        // The last 20 characters of the second row and the first 10 of the third, as one line
        // that wraps: the pixels 72..92 and 92..112, found to within three pixels.
        for (nearest, found, _) in boxes(5, false, 100..130)? {
            assert_eq!(found, line(71, 115), "nearest: {nearest}");
        }
        Ok(())
    }

    #[test]
    fn a_value_at_the_very_start_of_a_line_is_boxed_from_its_first_column() -> Result<(), String> {
        let characters = cells(1, 0, 11);
        for (nearest, found, _) in boxes(5, true, 61..72)? {
            assert!(
                contains(found, characters),
                "{found:?} is not around {characters:?} (nearest: {nearest})"
            );
            assert!(
                contains(grown(characters, 12, 4), found),
                "{found:?} is too big for {characters:?} (nearest: {nearest})"
            );
            // Its left side reaches the control's and no further.
            assert_eq!(found.left, CONTROL.left, "nearest: {nearest}");
        }
        Ok(())
    }

    #[test]
    fn a_value_at_the_end_of_a_line_is_boxed_to_its_last_column() -> Result<(), String> {
        // The last 20 characters of the second row.
        let characters = cells(1, 40, 60);
        for (nearest, found, _) in boxes(5, true, 101..121)? {
            if nearest {
                // A control that answers with the insertion point at the end of the row says
                // that the text ends there.
                assert!(contains(found, characters), "{found:?}");
                assert!(contains(grown(characters, 12, 4), found), "{found:?}");
            } else {
                // One that answers with the last character of the row for every point past it
                // cannot tell the end of the text from more text on the next row: the whole row.
                assert_eq!(found, line(71, 94));
            }
        }
        Ok(())
    }

    #[test]
    fn the_whole_line_is_what_a_box_that_does_not_hold_up_falls_back_to() {
        // The answers between the edges contradict the answers at them: the box is not around
        // the text.
        assert_eq!(
            locate(&mut Edges(Grid::new(5, true, 71..82, false)), CONTROL),
            Some(line(71, 94))
        );
        // The control stops answering after the rows are known.
        let mut grid = Grid::new(5, true, 71..82, false);
        grid.answers = Some(20);
        assert_eq!(locate(&mut grid, CONTROL), Some(line(71, 94)));
    }

    #[test]
    fn nothing_is_boxed_when_there_is_nothing_to_go_by() {
        // The text is not in the control.
        let mut grid = Grid::new(5, true, 500..510, false);
        assert_eq!(locate(&mut grid, CONTROL), None);
        // The control stops answering at once.
        let mut grid = Grid::new(5, true, 71..82, false);
        grid.answers = Some(3);
        assert_eq!(locate(&mut grid, CONTROL), None);
        // The control is too small to ask: nothing is asked.
        let small = Rect {
            left: 100,
            top: 50,
            right: 120,
            bottom: 70,
        };
        let mut grid = Grid::new(5, true, 71..82, false);
        assert_eq!(locate(&mut grid, small), None);
        assert_eq!(grid.asked, 0);
    }

    #[test]
    fn a_field_of_one_row_is_boxed_over_its_height() -> Result<(), String> {
        let field = Rect {
            left: 100,
            top: 50,
            right: 400,
            bottom: 80,
        };
        let mut grid = Grid::new(1, true, 10..20, false);
        let found = locate(&mut grid, field).ok_or("no box")?;
        assert!(contains(found, cells(0, 10, 20)), "{found:?}");
        assert!(contains(field, found), "{found:?}");
        Ok(())
    }

    #[test]
    fn the_biggest_control_is_asked_about_within_the_budget() -> Result<(), String> {
        let control = Rect {
            left: 100,
            top: 50,
            right: 1700,
            bottom: 16_400,
        };
        // Characters 5 to 10 of row 400 of 800.
        let start = 400 * (COLUMNS + 1);
        let mut grid = Grid::new(800, true, start + 5..start + 10, false);
        let found = locate(&mut grid, control).ok_or("no box")?;
        assert!(contains(found, cells(400, 5, 10)), "{found:?}");
        assert!(contains(control, found), "{found:?}");
        let budget = usize::try_from(BUDGET).unwrap_or_default();
        assert!(grid.asked <= budget, "{} questions", grid.asked);
        Ok(())
    }

    #[test]
    fn an_edge_is_found_to_within_the_precision() -> Result<(), Stop> {
        // Off below 37, on from there.
        let edge = first_true(0, 100, |value| Ok(value >= 37))?.ok_or(Stop)?;
        assert!((edge.outer..=edge.inner).contains(&37), "{edge:?}");
        assert!(edge.inner - edge.outer <= PRECISION, "{edge:?}");
        // On up to 61, off after.
        let edge = last_true(0, 100, |value| Ok(value <= 61))?.ok_or(Stop)?;
        assert!((edge.inner..=edge.outer).contains(&61), "{edge:?}");
        assert!(edge.outer - edge.inner <= PRECISION, "{edge:?}");
        // On everywhere: the first and the last value of the range.
        assert_eq!(first_true(10, 50, |_| Ok(true))?.map(|e| e.outer), Some(10));
        assert_eq!(last_true(10, 50, |_| Ok(true))?.map(|e| e.outer), Some(49));
        // On nowhere, and nothing to look at.
        assert_eq!(first_true(0, 100, |_| Ok(false))?, None);
        assert_eq!(last_true(0, 100, |_| Ok(false))?, None);
        assert_eq!(first_true(5, 5, |_| Ok(true))?, None);
        assert_eq!(last_true(5, 5, |_| Ok(true))?, None);
        // No answer ends the search.
        assert_eq!(first_true(0, 100, |_| Err(Stop)), Err(Stop));
        assert_eq!(last_true(0, 100, |_| Err(Stop)), Err(Stop));
        Ok(())
    }

    #[test]
    fn a_search_is_cut_short_when_the_budget_is_spent() {
        let mut grid = Grid::new(5, true, 71..82, false);
        let mut asked = Asked {
            probe: &mut grid,
            left: 2,
        };
        assert_eq!(asked.at_or_after_start(651, 100), Ok(true));
        assert_eq!(asked.before_end(651, 100), Ok(false));
        assert_eq!(asked.at_or_after_start(651, 100), Err(Stop));
    }
}
