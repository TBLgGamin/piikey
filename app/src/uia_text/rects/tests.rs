use std::ops::Range;

use super::*;

/// The control: 600 × 300 pixels, with text from (110, 60): 10 pixels in from the left and 8
/// down, as a text control pads its text.
const CONTROL: Rect = Rect {
    left: 100,
    top: 52,
    right: 700,
    bottom: 352,
};
/// Where the first glyph's left edge is, and the height of a row.
const ORIGIN: (i32, i32) = (110, 60);
const ROW: i32 = 22;
/// A line box leads the glyphs by this much at the top and at the bottom.
const LEAD: i32 = ROW / 10;

/// One row of the text: the characters it starts with, and the widths of its glyphs.
struct Line {
    start: usize,
    widths: Vec<i32>,
}

impl Line {
    fn end(&self) -> usize {
        self.start + self.widths.len()
    }

    /// The left edge of the glyph `at` (or the right edge of the last one).
    fn edge(&self, at: usize) -> i32 {
        ORIGIN.0 + self.widths.iter().take(at).sum::<i32>()
    }
}

/// A text control made of rows of glyphs, `ROW` pixels high with no gaps. It says what text
/// position lies at a point, as the real ones do, and counts what it is asked.
struct Grid {
    lines: Vec<Line>,
    found: Range<usize>,
    model: Model,
    control: Rect,
    /// The first row is this many rows above where it is not scrolled.
    scrolled: i32,
    asked: u32,
    /// The number of questions it answers; none after.
    answers: Option<u32>,
    pinned: Option<usize>,
    /// Says "before" for the points of these columns, whatever is there.
    lie: Option<Range<i32>>,
    /// Says "before" for every point past the end of the text of a row, as `PowerPoint` does for a
    /// point beside its text: the position is that of the start of the text.
    start_beside: bool,
}

impl Grid {
    /// Rows of `counts` glyphs of `width` pixels each, with the found text in them.
    fn even(counts: &[usize], width: i32, found: Range<usize>, model: Model) -> Self {
        let mut start = 0;
        let lines = counts
            .iter()
            .map(|&count| {
                let line = Line {
                    start,
                    widths: vec![width; count],
                };
                start += count;
                line
            })
            .collect();
        Self::of(lines, found, model)
    }

    fn of(lines: Vec<Line>, found: Range<usize>, model: Model) -> Self {
        Self {
            lines,
            found,
            model,
            control: CONTROL,
            scrolled: 0,
            asked: 0,
            answers: None,
            pinned: None,
            lie: None,
            start_beside: false,
        }
    }

    /// The top of row `at`.
    fn top(&self, at: usize) -> i32 {
        ORIGIN.1 + (i32::try_from(at).unwrap_or_default() - self.scrolled) * ROW
    }

    /// The text position at the point; `None` outside the control.
    fn position(&self, x: i32, y: i32) -> Option<usize> {
        let control = self.control;
        if x < control.left || x >= control.right || y < control.top || y >= control.bottom {
            return None;
        }
        let band = (y - ORIGIN.1).div_euclid(ROW) + self.scrolled;
        let at = usize::try_from(band.max(0)).unwrap_or_default();
        let line = self.lines.get(at.min(self.lines.len().checked_sub(1)?))?;
        let end = line.edge(line.widths.len());
        if self.start_beside && x >= end + 2 {
            return Some(0);
        }
        Some(match self.model {
            // The glyph under the point; before the first it is the first; past the last, the
            // end of the row.
            Model::Under => {
                if x < ORIGIN.0 {
                    line.start
                } else if x >= end {
                    line.end()
                } else {
                    let glyph = (0..line.widths.len()).find(|&glyph| x < line.edge(glyph + 1));
                    line.start + glyph.unwrap_or(0)
                }
            }
            // The nearest edge between glyphs.
            Model::Nearest => {
                let nearest = (0..=line.widths.len())
                    .min_by_key(|&glyph| (line.edge(glyph) - x).abs())
                    .unwrap_or(0);
                line.start + nearest
            }
        })
    }

    fn spend(&mut self) -> Option<()> {
        self.asked += 1;
        self.answers
            .is_none_or(|answers| self.asked <= answers)
            .then_some(())
    }

    /// The pixels the found text really covers on each row it is on, for the line box shrunk by
    /// its lead at the top and bottom.
    fn truth(&self) -> Vec<Rect> {
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| self.found.start < line.end() && self.found.end > line.start)
            .map(|(at, line)| {
                let from = self.found.start.saturating_sub(line.start);
                let to = self.found.end.min(line.end()) - line.start;
                Rect {
                    left: line.edge(from),
                    top: self.top(at) + LEAD,
                    right: line.edge(to),
                    bottom: self.top(at) + ROW - LEAD,
                }
            })
            .collect()
    }
}

impl Probe for Grid {
    fn rel(&mut self, x: i32, y: i32) -> Option<Rel> {
        self.spend()?;
        let at = self.position(x, y)?;
        if self
            .lie
            .as_ref()
            .is_some_and(|columns| columns.contains(&x))
        {
            return Some(Rel::Before);
        }
        Some(if at < self.found.start {
            Rel::Before
        } else if at == self.found.start {
            Rel::At
        } else if at < self.found.end {
            Rel::Inside
        } else {
            Rel::After
        })
    }

    fn pin(&mut self, x: i32, y: i32) -> Option<()> {
        self.spend()?;
        self.pinned = Some(self.position(x, y)?);
        Some(())
    }

    fn same(&mut self, x: i32, y: i32) -> Option<bool> {
        self.spend()?;
        Some(self.position(x, y)? == self.pinned?)
    }
}

fn locate_in(grid: &mut Grid, chars: usize) -> Option<Vec<Rect>> {
    let (model, control) = (grid.model, grid.control);
    let budget = Budget::within(Duration::from_mins(1));
    locate(grid, control, model, chars, budget)
}

/// Whether `found` is within `slack` pixels of `truth` on every side.
fn near(found: Rect, truth: Rect, slack: i32) -> bool {
    near_by(found, truth, slack, slack)
}

/// Whether `found` is within `across` pixels of `truth` on its left and right and `down` on its
/// top and bottom.
fn near_by(found: Rect, truth: Rect, across: i32, down: i32) -> bool {
    (found.left - truth.left).abs() <= across
        && (found.right - truth.right).abs() <= across
        && (found.top - truth.top).abs() <= down
        && (found.bottom - truth.bottom).abs() <= down
}

const MODELS: [Model; 2] = [Model::Under, Model::Nearest];

/// The right of the area asked about, in `CONTROL`.
const AREA_RIGHT: i32 = CONTROL.right - RIGHT_GAP;
const AREA_LEFT: i32 = CONTROL.left + LEFT_GAP;

#[test]
fn a_value_in_the_middle_of_a_row_is_boxed_by_its_glyphs() -> Result<(), String> {
    for model in MODELS {
        // The second of four rows of 60 glyphs of 8 pixels: glyphs 80 to 98 of the text.
        let mut grid = Grid::even(&[60, 60, 60, 60], 8, 80..98, model);
        let truth = grid.truth();
        let found = locate_in(&mut grid, 18).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1, "{model:?}");
        assert!(
            near(found[0], truth[0], 1),
            "{model:?}: {:?} is not {:?}",
            found[0],
            truth[0]
        );
        assert!(grid.asked <= 70, "{model:?}: {} points", grid.asked);
    }
    Ok(())
}

#[test]
fn the_first_row_is_as_tall_as_it_is_but_for_the_padding_above_it() -> Result<(), String> {
    for model in MODELS {
        let mut grid = Grid::even(&[60, 60, 60], 8, 20..38, model);
        let truth = grid.truth();
        let found = locate_in(&mut grid, 18).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1);
        // The padding above the first row counts as part of it: eight pixels of a row of 22.
        assert!(
            found[0].left.abs_diff(truth[0].left) <= 1,
            "{model:?}: {found:?}"
        );
        assert!(
            found[0].right.abs_diff(truth[0].right) <= 1,
            "{model:?}: {found:?}"
        );
        assert_eq!(found[0].bottom, truth[0].bottom);
        assert!(found[0].top <= truth[0].top && truth[0].top - found[0].top <= 8);
    }
    Ok(())
}

#[test]
fn a_proportional_font_is_a_pixel_or_two_off_at_most() -> Result<(), String> {
    for model in MODELS {
        let widths: Vec<i32> = (0..70).map(|n| 5 + (n * 7) % 9).collect();
        // A second row under it, so that the first is a row of its own.
        let lines = vec![
            Line {
                start: 0,
                widths: vec![8; 10],
            },
            Line { start: 10, widths },
        ];
        let mut grid = Grid::of(lines, 30..44, model);
        let truth = grid.truth();
        let found = locate_in(&mut grid, 14).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1);
        assert!(
            near_by(found[0], truth[0], 3, 6),
            "{model:?}: {:?} is not {:?}",
            found[0],
            truth[0]
        );
    }
    Ok(())
}

#[test]
fn a_value_that_starts_the_row_is_boxed_from_the_left_of_the_area() -> Result<(), String> {
    for model in MODELS {
        let mut grid = Grid::even(&[60, 60, 60], 8, 60..71, model);
        let found = locate_in(&mut grid, 11).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1, "{model:?}");
        let truth = grid.truth()[0];
        // Its right side is exact; its left is at the left of what is asked about, or where the
        // text control says its text starts, a few pixels from the first glyph.
        assert!(
            found[0].right.abs_diff(truth.right) <= 1,
            "{model:?}: {found:?}"
        );
        assert!(
            found[0].left.abs_diff(truth.left) <= 2
                || (found[0].left < truth.left && truth.left - found[0].left <= 8),
            "{model:?}: {found:?}"
        );
    }
    Ok(())
}

#[test]
fn a_value_that_ends_the_row_is_boxed_to_its_last_glyph() -> Result<(), String> {
    for model in MODELS {
        // The last 12 glyphs of the second row.
        let mut grid = Grid::even(&[60, 60, 60], 8, 108..120, model);
        let truth = grid.truth()[0];
        let found = locate_in(&mut grid, 12).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1, "{model:?}");
        assert!(
            near(found[0], truth, 1),
            "{model:?}: {:?} is not {truth:?}",
            found[0]
        );
    }
    Ok(())
}

#[test]
fn a_value_on_the_last_row_is_not_boxed_over_the_blank_space_below_it() -> Result<(), String> {
    for model in MODELS {
        // The text is three rows in a control of 300 pixels: the points below them are the last
        // row's, as in a real control, and the band of that row looks 230 pixels high.
        let mut grid = Grid::even(&[60, 60, 60], 8, 150..168, model);
        let truth = grid.truth()[0];
        let found = locate_in(&mut grid, 18).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1, "{model:?}");
        assert!(
            near_by(found[0], truth, 1, 4),
            "{model:?}: {:?} is not {truth:?}",
            found[0]
        );
    }
    Ok(())
}

#[test]
fn a_value_in_a_control_of_one_row_is_boxed_over_its_height() -> Result<(), String> {
    for model in MODELS {
        let mut grid = Grid::even(&[70], 8, 10..30, model);
        grid.control = Rect {
            left: 100,
            top: 52,
            right: 700,
            bottom: 82,
        };
        let found = locate_in(&mut grid, 20).ok_or("no rectangles")?;
        let truth = grid.truth()[0];
        assert_eq!(found.len(), 1, "{model:?}");
        // The row is the control's height, 30 pixels, with its 22 in the middle: the value is
        // as high as the type is, not higher than the control.
        assert!(
            found[0].left.abs_diff(truth.left) <= 1,
            "{model:?}: {found:?}"
        );
        assert!(
            found[0].right.abs_diff(truth.right) <= 1,
            "{model:?}: {found:?}"
        );
        assert!(found[0].height() >= ROW - 2 * LEAD, "{model:?}: {found:?}");
        assert!(found[0].height() <= 30, "{model:?}: {found:?}");
    }
    Ok(())
}

#[test]
fn a_value_over_two_rows_is_a_box_on_each() -> Result<(), String> {
    for model in MODELS {
        // The last 20 glyphs of the second row and the first 10 of the third.
        let mut grid = Grid::even(&[60, 60, 60, 60], 8, 100..130, model);
        let truth = grid.truth();
        let found = locate_in(&mut grid, 30).ok_or("no rectangles")?;
        assert_eq!(found.len(), 2, "{model:?}: {found:?}");
        // The first starts where the value does and goes on as far as the row does, the second
        // ends where the value ends and starts where the rows do.
        assert!(
            found[0].left.abs_diff(truth[0].left) <= 1,
            "{model:?}: {found:?}"
        );
        assert!(
            found[1].right.abs_diff(truth[1].right) <= 1,
            "{model:?}: {found:?}"
        );
        match model {
            // A control that says where the rows end: the text of the rows, to the pixel or two.
            Model::Nearest => {
                assert!(found[0].right.abs_diff(truth[0].right) <= 2, "{found:?}");
                assert!(found[1].left.abs_diff(truth[1].left) <= 2, "{found:?}");
            }
            // One that does not (Chromium's rows have a container that is as wide): the area.
            Model::Under => {
                assert_eq!(found[0].right, AREA_RIGHT);
                assert_eq!(found[1].left, AREA_LEFT - 1);
            }
        }
        // Each is as high as its own row, and they are on rows that follow each other.
        assert_eq!(found[0].height(), ROW - 2 * LEAD);
        assert_eq!(found[1].top - found[0].top, ROW);
    }
    Ok(())
}

#[test]
fn a_value_over_three_rows_has_a_whole_row_in_the_middle() -> Result<(), String> {
    for model in MODELS {
        let mut grid = Grid::even(&[30, 30, 30, 30, 30], 8, 55..110, model);
        let found = locate_in(&mut grid, 55).ok_or("no rectangles")?;
        assert_eq!(found.len(), 3, "{model:?}: {found:?}");
        assert_eq!(found[1].left, found[2].left);
        assert_eq!(found[1].top - found[0].top, ROW);
        assert_eq!(found[2].top - found[1].top, ROW);
        // The rows in the middle reach as far as the first does.
        assert_eq!(found[1].right, found[0].right);
    }
    Ok(())
}

#[test]
fn a_text_that_started_above_the_area_is_boxed_from_the_first_row() -> Result<(), String> {
    for model in MODELS {
        // Scrolled by two rows: the value starts on the first row, which is off the top, and ends
        // on the second, of which the lower eight pixels are in view.
        let mut grid = Grid::even(&[30, 30, 30, 30], 8, 25..50, model);
        grid.scrolled = 2;
        let found = locate_in(&mut grid, 25).ok_or("no rectangles")?;
        let truth = grid.truth();
        assert_eq!(found.len(), 1, "{model:?}: {found:?}");
        // The row is mostly above the area, so the width of a glyph is a guess: roughly.
        assert!(
            found[0].right.abs_diff(truth[1].right) <= 4,
            "{model:?}: {found:?}"
        );
        assert!(found[0].left <= truth[1].left + 8, "{model:?}: {found:?}");
    }
    Ok(())
}

#[test]
fn a_text_that_goes_on_below_the_area_is_boxed_down_to_it() -> Result<(), String> {
    for model in MODELS {
        // Thirty rows in a control that shows twelve: the value starts on the fifth and goes on
        // far below the area.
        let mut grid = Grid::even(&[30; 30], 8, 130..600, model);
        let found = locate_in(&mut grid, 470).ok_or("no rectangles")?;
        assert!(found.len() > 5, "{model:?}: {found:?}");
        let last = found[found.len() - 1];
        assert!(last.bottom <= CONTROL.bottom, "{model:?}: {found:?}");
        // It goes on past the row and below the area: the last row reaches the side of the area.
        assert_eq!(last.right, AREA_RIGHT, "{model:?}: {found:?}");
    }
    Ok(())
}

#[test]
fn a_text_that_is_out_of_view_has_no_rectangles() {
    for model in MODELS {
        // Above: scrolled far down.
        let mut grid = Grid::even(&[30, 30, 30, 30], 8, 0..10, model);
        grid.scrolled = 3;
        assert_eq!(
            locate_in(&mut grid, 10),
            Some(Vec::new()),
            "{model:?} above"
        );
        // Below: more rows than the control shows.
        let mut grid = Grid::even(&[30; 30], 8, 800..810, model);
        assert_eq!(
            locate_in(&mut grid, 10),
            Some(Vec::new()),
            "{model:?} below"
        );
        // Along the row: further right than the text control shows (it is scrolled across).
        let mut grid = Grid::even(&[200, 200], 8, 100..110, model);
        assert_eq!(
            locate_in(&mut grid, 10),
            Some(Vec::new()),
            "{model:?} right"
        );
    }
}

#[test]
fn a_single_character_is_boxed_too() -> Result<(), String> {
    for model in MODELS {
        let mut grid = Grid::even(&[60, 60, 60], 9, 80..81, model);
        let truth = grid.truth()[0];
        let found = locate_in(&mut grid, 1).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1);
        // The width of a glyph is not known from one character: half of it is a guess.
        assert!(
            found[0].left.abs_diff(truth.left) <= 6 && found[0].right.abs_diff(truth.right) <= 6,
            "{model:?}: {:?} is not {truth:?}",
            found[0]
        );
    }
    Ok(())
}

#[test]
fn a_control_that_says_the_start_of_its_text_beside_the_text_is_boxed_all_the_same()
-> Result<(), String> {
    // `PowerPoint`: a point beside the text of a shape answers with the start of the text, which is
    // before the found text. The value ends its text, so the end of it is reached in a few
    // pixels, and the points after that are beside the text.
    let mut grid = Grid::even(&[40, 40, 40], 8, 100..120, Model::Nearest);
    grid.start_beside = true;
    let truth = grid.truth()[0];
    let found = locate_in(&mut grid, 20).ok_or("no rectangles")?;
    assert_eq!(found.len(), 1);
    assert!(
        near_by(found[0], truth, 2, 4),
        "{:?} is not {truth:?}",
        found[0]
    );
    Ok(())
}

#[test]
fn nothing_is_said_when_the_control_does_not_answer() {
    for answers in [0, 1, 5, 20] {
        let mut grid = Grid::even(&[60, 60, 60, 60], 8, 80..98, Model::Under);
        grid.answers = Some(answers);
        assert_eq!(locate_in(&mut grid, 18), None, "{answers} answers");
    }
}

#[test]
fn nothing_is_said_when_the_points_or_the_time_are_spent() {
    let mut grid = Grid::even(&[60, 60, 60, 60], 8, 80..98, Model::Under);
    let control = grid.control;
    let spent = Budget {
        probes: 0,
        until: Instant::now() + Duration::from_mins(1),
    };
    assert_eq!(locate(&mut grid, control, Model::Under, 18, spent), None);
    assert_eq!(grid.asked, 0);
    let late = Budget {
        probes: 100,
        until: Instant::now(),
    };
    assert_eq!(locate(&mut grid, control, Model::Under, 18, late), None);
}

#[test]
fn nothing_is_said_when_the_answers_contradict_the_rectangle() {
    // Between the left and the right of the control, wherever the text is asked about, the
    // control says the position is before the text: no rectangle holds up.
    let mut grid = Grid::even(&[60, 60, 60, 60], 8, 80..98, Model::Under);
    grid.lie = Some(ORIGIN.0 + 1..CONTROL.right - 60);
    assert_eq!(locate_in(&mut grid, 18), None);
}

#[test]
fn a_control_that_is_too_small_is_not_asked() {
    let small = Rect {
        left: 100,
        top: 50,
        right: 110,
        bottom: 70,
    };
    let mut grid = Grid::even(&[60], 8, 10..20, Model::Under);
    let budget = Budget::within(Duration::from_mins(1));
    assert_eq!(locate(&mut grid, small, Model::Under, 10, budget), None);
    assert_eq!(grid.asked, 0);
}

#[test]
fn the_biggest_control_is_asked_about_within_the_budget() -> Result<(), String> {
    for model in MODELS {
        // Row 60 of 63, in a control 1,400 pixels high and 1,600 wide.
        let mut grid = Grid::even(&[190; 63], 8, 60 * 190 + 20..60 * 190 + 40, model);
        grid.control = Rect {
            left: 100,
            top: 52,
            right: 1700,
            bottom: 1452,
        };
        let truth = grid.truth()[0];
        let found = locate_in(&mut grid, 20).ok_or("no rectangles")?;
        assert_eq!(found.len(), 1, "{model:?}");
        assert!(
            near(found[0], truth, 1),
            "{model:?}: {:?} is not {truth:?}",
            found[0]
        );
        assert!(grid.asked <= MAX_PROBES, "{model:?}: {} points", grid.asked);
    }
    Ok(())
}

#[test]
fn an_edge_is_found_to_the_pixel() -> Result<(), Stop> {
    // Off below 37, on from there.
    assert_eq!(
        first_true(0, 100, |value| Ok(value >= 37), false)?,
        Some(37)
    );
    // On up to 61, off after.
    assert_eq!(last_true(0, 100, |value| Ok(value <= 61))?, Some(61));
    // On everywhere: the first and the last value of the range.
    assert_eq!(first_true(10, 50, |_| Ok(true), false)?, Some(10));
    assert_eq!(last_true(10, 50, |_| Ok(true))?, Some(49));
    // On nowhere, and nothing to look at.
    assert_eq!(first_true(0, 100, |_| Ok(false), false)?, None);
    assert_eq!(last_true(0, 100, |_| Ok(false))?, None);
    assert_eq!(first_true(5, 5, |_| Ok(true), false)?, None);
    assert_eq!(last_true(5, 5, |_| Ok(true))?, None);
    // No answer ends the search.
    assert_eq!(first_true(0, 100, |_| Err(Stop), false), Err(Stop));
    assert_eq!(last_true(0, 100, |_| Err(Stop)), Err(Stop));
    // The end taken as on is not asked about.
    let mut asked = Vec::new();
    let found = first_true(
        0,
        16,
        |value| {
            asked.push(value);
            Ok(value >= 9)
        },
        true,
    )?;
    assert_eq!(found, Some(9));
    assert!(!asked.contains(&15));
    Ok(())
}

#[test]
fn rows_next_to_the_blank_part_of_a_control_are_cut_to_the_height_of_a_row() {
    let area = Area {
        left: 103,
        right: 640,
        top: 54,
        bottom: 350,
    };
    // One row with blank space above and below it: as high as five glyphs of 8 pixels at most,
    // around its middle.
    let mut rows = [Row {
        top: 54,
        bottom: 350,
    }];
    trim(&mut rows, area, 8, false);
    assert_eq!(rows[0].height(), 24);
    assert_eq!(rows[0].middle(), 54 + (350 - 54) / 2);
    // One with a row below it that is not the text's: the blank part is above.
    let mut rows = [Row {
        top: 54,
        bottom: 104,
    }];
    trim(&mut rows, area, 8, true);
    assert_eq!(
        rows[0],
        Row {
            top: 80,
            bottom: 104
        }
    );
    // One with blank space below it only: the row keeps its top.
    let mut rows = [Row {
        top: 82,
        bottom: 350,
    }];
    trim(&mut rows, area, 8, false);
    assert_eq!(
        rows[0],
        Row {
            top: 82,
            bottom: 106
        }
    );
    // The last of several is as tall as the rows that are boxed in.
    let mut rows = [
        Row {
            top: 54,
            bottom: 82,
        },
        Row {
            top: 82,
            bottom: 104,
        },
        Row {
            top: 104,
            bottom: 350,
        },
    ];
    trim(&mut rows, area, 8, false);
    assert_eq!(
        rows[2],
        Row {
            top: 104,
            bottom: 126
        }
    );
    // Rows that are not taller than that are left alone.
    let mut rows = [
        Row {
            top: 82,
            bottom: 104,
        },
        Row {
            top: 104,
            bottom: 126,
        },
    ];
    trim(&mut rows, area, 8, false);
    assert_eq!(
        rows,
        [
            Row {
                top: 82,
                bottom: 104
            },
            Row {
                top: 104,
                bottom: 126
            }
        ]
    );
}
