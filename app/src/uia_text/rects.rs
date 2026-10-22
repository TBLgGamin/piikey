//! Where on the screen a piece of text is, for a text control that cannot say.
//!
//! UI Automation can give the rectangles of a range of text, but only through a call that is
//! `unsafe` to make, and `unsafe` is forbidden here. What the safe wrapper does offer is a hit test:
//! the text position at a point of the screen, which can be compared with the start and the end of
//! the found text. [`Probe`] is that, and [`locate`] finds the rectangles of the found text by
//! asking it about points. It knows nothing of Windows: the tests run it against text controls made
//! of rows of glyphs.
//!
//! What the real controls do (measured in Notepad, Edge, Word and `PowerPoint`):
//!
//! - Rows are contiguous bands, and the text position along a column of points grows from the top
//!   to the bottom of the control; along a row it grows from the left to the right. Every point of a
//!   row's band, at one column, gives the same position.
//! - Where the position flips from one character to the next differs. Chromium gives the character
//!   under the point, so the position flips at the left edge of a glyph ([`Model::Under`]). Win32
//!   edit controls, Word and `PowerPoint` give the nearest insertion point, so it flips in the middle
//!   of the glyph before ([`Model::Nearest`]): the text starts half a glyph further right than where
//!   the position flips to its first character, and ends half a glyph further right than where it
//!   flips to the one after its last.
//! - Past the last glyph of a row the position is that of the end of the row (Chromium: only right
//!   after it), and below the last row, or above the first, it is that of the row there: the blank
//!   part of a control looks like a taller row. `PowerPoint` answers with the start of its text
//!   for a point beside the text.
//!
//! So the search goes: **rows** first, by halving down the left column (the row the text starts on,
//! the rows below it, how far each reaches down: a row's band is where the position stays the same);
//! then, **on a row**, by stepping along it with doubling steps and halving the last one (where the
//! position reaches the start of the text, and where it reaches its end). Each edge is found to the
//! pixel. A text over several rows is one rectangle per row. Where a row goes on past the text, or
//! the text goes on from before a row, the rectangle reaches as far as the position says the text
//! of the row does (the position at the far side of the area is the end of the row, or its start,
//! for the controls that answer so), or else to the side of the area.
//!
//! The vertical edges are those of the line box, which leads the glyphs by about a tenth of its
//! height on each side, so the rectangle is that much smaller at the top and bottom. A row next to
//! the blank part of a control may be a taller band than it is; it is then cut to the height that a
//! row of this text has.

use std::time::{Duration, Instant};

use crate::highlight::Rect;

/// The most points asked about for one text. One row of text takes about fifty.
const MAX_PROBES: u32 = 200;
/// The most rows a text may span and still be boxed row by row.
const MAX_ROWS: usize = 12;
/// Pixels between the left edge of the control and the points asked at its left: its padding.
const LEFT_GAP: i32 = 3;
/// Pixels between the top and bottom edges of the control and the rows asked about.
const EDGE_GAP: i32 = 2;
/// Pixels between the right edge of the control and the points asked at its right: a scroll bar is
/// inside the rectangle of some controls.
const RIGHT_GAP: i32 = 6;
/// The fewest pixels, across and down, the points asked about must span.
const MIN_SPAN: i32 = 8;
/// The first step along a row, which doubles with each point.
const FIRST_STEP: i32 = 8;
/// The tallest row there is looked for: bigger than any line of type.
const MAX_ROW: i32 = 400;
/// How many glyph widths a row is at most high, for the type there is: a band that is taller is
/// next to the blank part of the control.
const TALLEST_ROW: i32 = 3;

/// What the position at a point is, against the found text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rel {
    /// Before its start.
    Before,
    /// At its start.
    At,
    /// After its start, before its end.
    Inside,
    /// At its end or after it.
    After,
}

/// How a text control answers for a point that is between two characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Model {
    /// The character under the point (Chromium): the position flips at the left edge of a glyph.
    Under,
    /// The nearest insertion point (Win32 edit controls, Office): it flips in the middle of the
    /// glyph before.
    Nearest,
}

/// What a text control says about the text position at a point of the screen. `None` is "cannot
/// say" (an error of the control, a point outside it).
pub(crate) trait Probe {
    /// Where the position at the point is against the found text.
    fn rel(&mut self, x: i32, y: i32) -> Option<Rel>;
    /// Keeps the position at the point, for [`Probe::same`] to compare with.
    fn pin(&mut self, x: i32, y: i32) -> Option<()>;
    /// Whether the position at the point is the one that was kept.
    fn same(&mut self, x: i32, y: i32) -> Option<bool>;
}

/// How many points may be asked about, and until when.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    probes: u32,
    until: Instant,
}

impl Budget {
    /// The most points, within `time` from now.
    pub(crate) fn within(time: Duration) -> Self {
        Self {
            probes: MAX_PROBES,
            until: Instant::now() + time,
        }
    }

    /// Counts a point asked about; fails when the points or the time are spent.
    fn spend(&mut self) -> Answer<()> {
        self.probes = self.probes.checked_sub(1).ok_or(Stop)?;
        if Instant::now() >= self.until {
            return Err(Stop);
        }
        Ok(())
    }
}

/// The rectangles of the found text in `control`, a rectangle on the screen: one around each row
/// of it that is in view, in reading order. `chars` is how many characters it has. `Some` and
/// empty when none of it is in view; `None` when the control cannot say (or is too small to ask,
/// or the answers contradict each other), and the text is then not outlined.
pub(crate) fn locate(
    probe: &mut impl Probe,
    control: Rect,
    model: Model,
    chars: usize,
    budget: Budget,
) -> Option<Vec<Rect>> {
    let area = Area::of(control)?;
    Search {
        probe,
        budget,
        model,
        chars,
    }
    .run(area)
    .ok()
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
        let area = Self {
            left: control.left + LEFT_GAP,
            right: control.right - RIGHT_GAP,
            top: control.top + EDGE_GAP,
            bottom: control.bottom - EDGE_GAP,
        };
        (area.right - area.left >= MIN_SPAN && area.bottom - area.top >= MIN_SPAN).then_some(area)
    }
}

/// One row of text: the pixels `top..bottom` it takes up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    top: i32,
    /// The first pixel below the row.
    bottom: i32,
}

impl Row {
    fn height(self) -> i32 {
        self.bottom - self.top
    }

    fn middle(self) -> i32 {
        self.top + self.height() / 2
    }
}

/// Where along a row the position reaches an end of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// It has, at the left of the area already: the text starts the row, or is cut by it.
    Left,
    /// At this pixel.
    At(i32),
    /// It does not within the area.
    Past,
}

/// Which end of the text a flip along a row is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Start,
    End,
}

struct Search<'a, P: Probe> {
    probe: &'a mut P,
    budget: Budget,
    model: Model,
    chars: usize,
}

impl<P: Probe> Search<'_, P> {
    fn rel(&mut self, x: i32, y: i32) -> Answer<Rel> {
        self.budget.spend()?;
        self.probe.rel(x, y).ok_or(Stop)
    }

    fn pin(&mut self, x: i32, y: i32) -> Answer<()> {
        self.budget.spend()?;
        self.probe.pin(x, y).ok_or(Stop)
    }

    fn same(&mut self, x: i32, y: i32) -> Answer<bool> {
        self.budget.spend()?;
        self.probe.same(x, y).ok_or(Stop)
    }

    fn run(&mut self, area: Area) -> Answer<Vec<Rect>> {
        let x0 = area.left;
        // The row the text starts on: the last row whose first position is at or before the start.
        // There is none when the first row is already inside the text (it starts above the area),
        // and all of the text is above when the first row is after it.
        let (start_above, start) = match self.rel(x0, area.top)? {
            Rel::After => return Ok(Vec::new()),
            Rel::Inside => (true, area.top),
            Rel::Before | Rel::At => {
                let found = last_true(area.top, area.bottom, |y| {
                    Ok(matches!(self.rel(x0, y)?, Rel::Before | Rel::At))
                })?;
                (false, found.ok_or(Stop)?)
            }
        };
        let first = self.band(x0, start, area, None, (!start_above).then_some(start))?;
        let (mut rows, next_row) = self.rows(x0, area, first)?;
        let first_reach = if start_above {
            Reach::Left
        } else {
            self.reach(area, first.middle(), Edge::Start, area.left)?
        };
        let from = match first_reach {
            Reach::At(flip) if rows.len() == 1 => flip,
            Reach::Past => return Ok(Vec::new()),
            Reach::At(_) | Reach::Left => area.left,
        };
        let last = rows.last().copied().ok_or(Stop)?;
        let last_reach = self.reach(area, last.middle(), Edge::End, from)?;
        // The width of a glyph, from the text if it is on one row; else about what it is for
        // type of this height.
        let glyph = match (first_reach, last_reach) {
            (Reach::At(left), Reach::At(right)) if rows.len() == 1 && self.chars >= 2 => {
                let across = i32::try_from(self.chars).unwrap_or(i32::MAX);
                ((right - left) / across).max(1)
            }
            _ => (first.height() * 9 / 20).max(1),
        };
        trim(&mut rows, area, glyph, next_row);
        let sides = self.sides(area, &rows, from == area.left, glyph)?;
        let pad = self.pad(glyph);
        let count = rows.len();
        let rects: Vec<Rect> = rows
            .iter()
            .enumerate()
            .filter_map(|(at, row)| {
                let left = match (at, first_reach) {
                    (0, Reach::At(flip)) => flip + pad,
                    _ => sides.left,
                };
                let right = match (at + 1 == count, last_reach) {
                    (true, Reach::At(flip)) => flip + pad,
                    _ => sides.right.get(at).copied().unwrap_or(area.right),
                };
                let lead = row.height() / 10;
                Rect::text(left, row.top + lead, right, row.bottom - lead)
            })
            .collect();
        self.hold(rects, area)
    }

    /// How far a glyph's edge is from the position flip: half a glyph for the nearest insertion
    /// point, and for a flip at a glyph's left edge (to the pixel at most) none.
    fn pad(&self, glyph: i32) -> i32 {
        match self.model {
            Model::Under => -1,
            Model::Nearest => glyph / 2,
        }
    }

    /// Where the rows of a text over several rows begin and end, for the controls whose position
    /// at the left and the right of the area is the start and the end of the row: the left of the
    /// text, and the right of each row but the last. The edge of the area for those that do not.
    fn sides(&mut self, area: Area, rows: &[Row], from_left: bool, glyph: i32) -> Answer<Sides> {
        let mut sides = Sides {
            left: area.left - 1,
            right: Vec::new(),
        };
        if rows.len() < 2 && !from_left || self.model == Model::Under {
            return Ok(sides);
        }
        let Some(&last) = rows.last() else {
            return Ok(sides);
        };
        // A row that is not the first starts where the text of the control does.
        if rows.len() > 1 || from_left {
            self.pin(area.left, last.middle())?;
            let flip = first_true(
                area.left + 1,
                area.right,
                |x| Ok(!self.same(x, last.middle())?),
                false,
            )?;
            if let Some(flip) = flip {
                sides.left = (flip - glyph / 2).max(area.left - 1);
            }
        }
        // Each of the first two rows, but the last, ends where the position becomes the end of it.
        for row in rows.iter().take(rows.len().saturating_sub(1)).take(2) {
            let y = row.middle();
            self.pin(area.right - 1, y)?;
            let from = sides.left.max(area.left);
            let flip = first_true(from, area.right, |x| self.same(x, y), true)?;
            sides.right.push(match flip {
                Some(flip) if flip < area.right - 1 => flip + glyph / 2,
                _ => area.right,
            });
        }
        // The rows between take the reach of the ones measured.
        let widest = sides.right.iter().copied().max().unwrap_or(area.right);
        sides.right.resize(rows.len().saturating_sub(1), widest);
        Ok(sides)
    }

    /// Checks the rectangles against the control: a point in the first one, near its start, is in
    /// the text. Without that the answers made no sense, and nothing is said.
    fn hold(&mut self, rects: Vec<Rect>, area: Area) -> Answer<Vec<Rect>> {
        let Some(first) = rects.first() else {
            return Err(Stop);
        };
        let x = (first.left + first.width() / 4).clamp(area.left, area.right - 1);
        let y = first.top + first.height() / 2;
        match self.rel(x, y)? {
            Rel::At | Rel::Inside => Ok(rects),
            // A text of one character has no more than half of it before that point, and the
            // nearest insertion point to it can be the one after.
            Rel::After if self.chars <= 1 => Ok(rects),
            Rel::Before | Rel::After => Err(Stop),
        }
    }

    /// The band of the row that has the pixel `y` of the left column: the pixels at which the
    /// position is the same as it is at `y`. `top` and `bottom` are the first and the last of
    /// them, when they are known.
    fn band(
        &mut self,
        x0: i32,
        y: i32,
        area: Area,
        top: Option<i32>,
        bottom: Option<i32>,
    ) -> Answer<Row> {
        self.pin(x0, y)?;
        let top = match top {
            Some(top) => top,
            None => first_true(
                (y - MAX_ROW).max(area.top),
                y + 1,
                |at| self.same(x0, at),
                true,
            )?
            .ok_or(Stop)?,
        };
        let last = match bottom {
            Some(last) => last,
            None => {
                last_true(y, (y + MAX_ROW).min(area.bottom), |at| self.same(x0, at))?.ok_or(Stop)?
            }
        };
        Ok(Row {
            top,
            bottom: last + 1,
        })
    }

    /// The rows from `first` down to the one the text ends on, or to the bottom of the area, and
    /// whether there is a row below the last of them that the text does not reach.
    fn rows(&mut self, x0: i32, area: Area, first: Row) -> Answer<(Vec<Row>, bool)> {
        // There is no row below when the area ends, or the pixel below is in the same row (blank
        // space), and the row below is not the text's when its first position is at or after the
        // end of the text.
        let below = first.bottom;
        if below >= area.bottom || self.same(x0, below)? {
            return Ok((vec![first], false));
        }
        if self.rel(x0, below)? == Rel::After {
            return Ok((vec![first], true));
        }
        // The text goes on: the last row whose first position is before its end.
        let end =
            last_true(below, area.bottom, |y| Ok(self.rel(x0, y)? != Rel::After))?.ok_or(Stop)?;
        let mut rows = vec![first];
        while rows.last().is_some_and(|row| row.bottom <= end) {
            let top = rows.last().map_or(below, |row| row.bottom);
            if rows.len() >= MAX_ROWS || top >= area.bottom {
                return Err(Stop);
            }
            let row = self.band(x0, top, area, Some(top), None)?;
            rows.push(row);
        }
        Ok((rows, false))
    }

    /// Where along the row at height `y` the position reaches the start of the text
    /// ([`Edge::Start`]) or its end ([`Edge::End`]): the first pixel at which it is at or after
    /// the start, or past the start and not inside the text. Asked at `from`, then at points that
    /// double their step from there, and in the last step by halving, so that no point is asked
    /// about far beyond the text, where a control may say anything.
    fn reach(&mut self, area: Area, y: i32, edge: Edge, from: i32) -> Answer<Reach> {
        // At the end of the text a position before the start is not possible; a control that says
        // so (`PowerPoint`, beside its text) is past the text.
        let reached = |rel: Rel| match edge {
            Edge::Start => rel != Rel::Before,
            Edge::End => !matches!(rel, Rel::At | Rel::Inside),
        };
        if edge == Edge::Start && reached(self.rel(from, y)?) {
            return Ok(Reach::Left);
        }
        let (mut low, mut step) = (from, FIRST_STEP);
        let high = loop {
            let at = (low + step).min(area.right - 1);
            if reached(self.rel(at, y)?) {
                break at;
            }
            if at >= area.right - 1 {
                return Ok(Reach::Past);
            }
            low = at;
            step = step.saturating_mul(2);
        };
        let flip = first_true(low + 1, high + 1, |x| Ok(reached(self.rel(x, y)?)), true)?;
        Ok(flip.map_or(Reach::Past, Reach::At))
    }
}

/// Where the rows of a text begin and end.
#[derive(Debug)]
struct Sides {
    /// The left of the rows that the text does not start on.
    left: i32,
    /// The right of each row but the last, from the first.
    right: Vec<i32>,
}

/// Cuts the rows next to the blank part of a control that are taller than a row of this text is: the
/// position there is that of the row, which makes the band look taller. The rows in the middle are
/// boxed in on both sides and tell how tall a row is; else a row is at most [`TALLEST_ROW`] glyphs
/// high. The first row is cut at the top, where the blank part is, when the row below it is real
/// (`next_row`, or the other rows); the last at the bottom; one that has blank space on both sides
/// around its middle.
fn trim(rows: &mut [Row], area: Area, glyph: i32, next_row: bool) {
    let count = rows.len();
    let tallest = rows
        .get(1..count.saturating_sub(1))
        .and_then(|middle| middle.iter().map(|row| row.height()).min())
        .unwrap_or_else(|| glyph.saturating_mul(TALLEST_ROW));
    if let Some(row) = rows.first_mut().filter(|row| row.height() > tallest) {
        if count > 1 || next_row {
            row.top = row.bottom - tallest;
        } else if row.top > area.top {
            row.bottom = row.top + tallest;
        } else {
            row.top = row.middle() - tallest / 2;
            row.bottom = row.top + tallest;
        }
    }
    if count > 1
        && let Some(row) = rows.last_mut().filter(|row| row.height() > tallest)
    {
        row.bottom = row.top + tallest;
    }
}

/// The first value of `lo..hi` at which `yes` holds, for a `yes` that is `false` below some value
/// and `true` from it, found by halving. `None` when it holds at none of them. `hi - 1` is asked
/// first, unless `assume_end`: it is then taken to hold.
fn first_true(
    lo: i32,
    hi: i32,
    mut yes: impl FnMut(i32) -> Answer<bool>,
    assume_end: bool,
) -> Answer<Option<i32>> {
    if lo >= hi || (!assume_end && !yes(hi - 1)?) {
        return Ok(None);
    }
    let (mut low, mut high) = (lo, hi - 1);
    while low < high {
        let middle = low + (high - low) / 2;
        if yes(middle)? {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(Some(high))
}

/// The last value of `lo..hi` at which `yes` holds, for a `yes` that is `true` up to some value
/// and `false` after it, found by halving. `None` when it does not hold at `lo`.
fn last_true(lo: i32, hi: i32, mut yes: impl FnMut(i32) -> Answer<bool>) -> Answer<Option<i32>> {
    if lo >= hi || !yes(lo)? {
        return Ok(None);
    }
    let (mut low, mut high) = (lo, hi - 1);
    while low < high {
        let middle = low + (high - low + 1) / 2;
        if yes(middle)? {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Ok(Some(low))
}

#[cfg(test)]
mod tests;
