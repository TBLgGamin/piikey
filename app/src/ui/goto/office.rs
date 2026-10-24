//! The apps that show a document as more than one text control: `PowerPoint` (a slide is a few
//! shapes that have text, and one slide at a time is in the tree) and Excel (a sheet is a grid of
//! cells, the visible ones in the tree). Word and the browsers show one text control, which
//! `crate::uia_text` finds the text in.
//!
//! What they do, as measured (Office 16 on Windows 11):
//!
//! - **`PowerPoint`** shows UI Automation nothing of the area of its slides, not the thumbnails, the
//!   slide, nor its shapes, until a client has put up an event handler; one for a change of the
//!   structure of the window is enough, and the area is there a few milliseconds later. Then the
//!   thumbnails are list items, in the order of the slides (`ThumbnailsPane`), and the slide in
//!   view is `SlidePane`, with a shape for each of its text boxes whose text is in its text
//!   pattern. The slide in view is changed by selecting its thumbnail, which takes the app a
//!   moment. The speaker notes are `SlideNotesPane`, of the slide in view.
//! - **Excel** has a cell element for each cell in view, named by its address (`B7`) and holding
//!   its text as its value, in the grid of the sheet in view, whose tab is selected to change it.

use std::{
    thread,
    time::{Duration, Instant},
};

use piikey::formats::Location;
use uiautomation::{
    UIElement,
    events::{CustomStructureChangedEventHandlerFn, UIStructureChangeEventHandler},
    patterns::UISelectionItemPattern,
    types::{ControlType, StructureChangeType, TreeScope, UIProperty},
    variants::Variant,
};

use super::{
    Outcome,
    needles::Needle,
    uia::{Desk, Frame, Job, Reporter, mark_in, outline, runtime_id, text_controls},
};
use crate::{highlight::Rect, uia_text::Control};

/// The class of the window of `PowerPoint`, and of Excel.
pub(super) const POWERPOINT: &str = "PPTFrameClass";
pub(super) const EXCEL: &str = "XLMAIN";

/// What `PowerPoint` calls the panes of its thumbnails, its slide in view and its notes.
const THUMBNAILS: &str = "ThumbnailsPane";
const SLIDE: &str = "SlidePane";
const NOTES: &str = "SlideNotesPane";
/// What Excel calls the grid of a sheet, and the tabs of its sheets.
const GRID: &str = "XLSpreadsheetGrid";
/// How long the panes of `PowerPoint` are awaited after it was woken, and a slide after its
/// thumbnail was selected; and how often they are looked at meanwhile.
const PANES: Duration = Duration::from_millis(1_500);
const SWITCH: Duration = Duration::from_secs(4);
const POLL: Duration = Duration::from_millis(25);

/// Looks for the value in the shapes of the slide of `frame`, a window of `PowerPoint`, that the
/// format says it is on, and points at it.
pub(super) fn powerpoint(desk: &Desk, frame: &Frame, job: &Job, report: &Reporter) -> Outcome {
    wake(desk, frame);
    let Some((thumbnails, slide)) = panes(desk, &frame.element) else {
        return Outcome::Opened;
    };
    let wanted = match job.place {
        Some(Location::Slide { slide, .. } | Location::Notes(slide)) => Some(slide),
        _ => None,
    };
    if let Some(wanted) = wanted
        && !show_slide(desk, &thumbnails, &slide, wanted)
    {
        return Outcome::Opened;
    }
    // The notes are of the slide in view, and have a pane of their own.
    let pane = if matches!(job.place, Some(Location::Notes(_))) {
        desk.with_id(&frame.element, NOTES)
    } else {
        Some(slide)
    };
    let Some(pane) = pane else {
        return Outcome::Opened;
    };
    // The shape the format says the value is in is looked in first: the elements of a slide are its
    // shapes, in the order of the file.
    if let Some(Location::Slide {
        shape: Some(shape), ..
    }) = job.place
        && in_shape(desk, &pane, shape, job, report) == Outcome::Marked
    {
        return Outcome::Marked;
    }
    mark_in(&text_controls(desk, &pane), job, report)
}

/// Looks for the value in shape `shape`, counted from 1, of the slide in the pane, and in what is
/// in the shape (the members of a group, the cells of a table).
fn in_shape(desk: &Desk, pane: &UIElement, shape: u32, job: &Job, report: &Reporter) -> Outcome {
    let element = (|| {
        let slide = pane.find_first(TreeScope::Children, &desk.all).ok()?;
        let shapes = slide.find_all(TreeScope::Children, &desk.all).ok()?;
        shapes
            .into_iter()
            .nth(usize::try_from(shape.checked_sub(1)?).ok()?)
    })();
    let Some(element) = element else {
        return Outcome::Opened;
    };
    let mut controls: Vec<Control> = Control::of(element.clone()).into_iter().collect();
    controls.extend(text_controls(desk, &element));
    mark_in(&controls, job, report)
}

/// Asks `PowerPoint` to show UI Automation its slides: it does once a client listens for a change of
/// the structure of the window. Once for each window; the handler stays until the search is over.
fn wake(desk: &Desk, frame: &Frame) {
    let Some(id) = runtime_id(&frame.element) else {
        return;
    };
    if desk.awake.borrow().contains(&id) {
        return;
    }
    let handler = UIStructureChangeEventHandler::from(Box::new(
        |_: &UIElement, _: StructureChangeType, _: Option<&[i32]>| Ok(()),
    )
        as Box<CustomStructureChangedEventHandlerFn>);
    if desk
        .automation
        .add_structure_changed_event_handler(&frame.element, TreeScope::Subtree, None, &handler)
        .is_ok()
    {
        desk.awake.borrow_mut().push(id);
    }
}

/// The pane of the thumbnails and the pane of the slide in view, once `PowerPoint` shows them.
fn panes(desk: &Desk, window: &UIElement) -> Option<(UIElement, UIElement)> {
    let end = Instant::now() + PANES;
    loop {
        if let (Some(thumbnails), Some(slide)) = (
            desk.with_id(window, THUMBNAILS),
            desk.with_id(window, SLIDE),
        ) {
            return Some((thumbnails, slide));
        }
        if Instant::now() >= end {
            return None;
        }
        thread::sleep(POLL);
    }
}

/// Brings slide `wanted`, counted from 1, into view by selecting its thumbnail, which are in the
/// order of the slides. Whether it is in view when `PowerPoint` has done.
fn show_slide(desk: &Desk, thumbnails: &UIElement, slide: &UIElement, wanted: u32) -> bool {
    if shown_slide(desk, slide) == Some(wanted) {
        return true;
    }
    let Ok(children) = thumbnails.find_all(TreeScope::Children, &desk.all) else {
        return false;
    };
    let item = children
        .into_iter()
        .filter(|child| child.get_control_type().ok() == Some(ControlType::ListItem))
        .nth(usize::try_from(wanted.saturating_sub(1)).unwrap_or(usize::MAX));
    let Some(item) = item else {
        return false;
    };
    let selected = item
        .get_pattern::<UISelectionItemPattern>()
        .and_then(|pattern| pattern.select())
        .is_ok();
    if !selected {
        return false;
    }
    let end = Instant::now() + SWITCH;
    while Instant::now() < end {
        if shown_slide(desk, slide) == Some(wanted) {
            return true;
        }
        thread::sleep(POLL);
    }
    false
}

/// The number of the slide the slide pane shows: its first element is named `Slide 3 - Title`.
fn shown_slide(desk: &Desk, slide: &UIElement) -> Option<u32> {
    let shown = slide.find_first(TreeScope::Children, &desk.all).ok()?;
    let name = shown.get_name().ok()?;
    let digits: String = name
        .strip_prefix("Slide ")?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Looks for the value in the cells of the sheet in view of `frame`, a window of Excel, or goes to
/// the cell the format says it is in, and outlines the cell.
pub(super) fn excel(desk: &Desk, frame: &Frame, job: &Job, report: &Reporter) -> Outcome {
    let cell_at = match &job.place {
        Some(Location::Cell { sheet, cell }) => {
            if !show_sheet(desk, &frame.element, sheet, cell) {
                return Outcome::Opened;
            }
            Some(cell.as_ref())
        }
        _ => None,
    };
    let Some(grid) = desk.with_class(&frame.element, GRID) else {
        return Outcome::Opened;
    };
    let cell = match cell_at {
        Some(address) => desk.with_id(&grid, address),
        None => cell_with(desk, &grid, &job.needles),
    };
    let Some(cell) = cell else {
        return Outcome::Opened;
    };
    let outlined = bounds(&cell).is_some_and(|rect| outline(&[rect], &job.purpose));
    if !outlined {
        return Outcome::Opened;
    }
    report.done(Outcome::Marked);
    // The cell becomes the active one, which takes Excel a moment: the outline is up already.
    let _ = cell
        .get_pattern::<UISelectionItemPattern>()
        .and_then(|pattern| pattern.select());
    Outcome::Marked
}

/// Brings the sheet called `sheet` into view by selecting its tab, which takes Excel a moment, and
/// waits for `cell` of it to be in the tree. Whether the sheet is in view.
fn show_sheet(desk: &Desk, window: &UIElement, sheet: &str, cell: &str) -> bool {
    let Some(tab) = sheet_tab(desk, window, sheet) else {
        return false;
    };
    let Ok(selection) = tab.get_pattern::<UISelectionItemPattern>() else {
        return false;
    };
    if selection.is_selected() != Ok(true) && selection.select().is_err() {
        return false;
    }
    let end = Instant::now() + SWITCH;
    while Instant::now() < end {
        if desk
            .with_class(window, GRID)
            .and_then(|grid| desk.with_id(&grid, cell))
            .is_some()
        {
            return true;
        }
        thread::sleep(POLL);
    }
    false
}

/// The tab of the sheet called `sheet`.
fn sheet_tab(desk: &Desk, window: &UIElement, sheet: &str) -> Option<UIElement> {
    let named = desk
        .automation
        .create_property_condition(UIProperty::Name, Variant::from(sheet), None)
        .ok()?;
    let tabs = desk
        .automation
        .create_property_condition(
            UIProperty::ControlType,
            Variant::from(ControlType::TabItem as i32),
            None,
        )
        .ok()?;
    let both = desk.automation.create_and_condition(named, tabs).ok()?;
    window.find_first(TreeScope::Descendants, &both).ok()
}

/// The cell of `grid` that holds the value: the first whose text has what to look for, the most
/// exact way first. Only the cells in view are in the tree.
fn cell_with(desk: &Desk, grid: &UIElement, needles: &[Needle]) -> Option<UIElement> {
    let request = desk.automation.create_cache_request().ok()?;
    request.add_property(UIProperty::ValueValue).ok()?;
    request.add_property(UIProperty::BoundingRectangle).ok()?;
    let cells = grid
        .find_all_build_cache(TreeScope::Children, &desk.all, &request)
        .ok()?;
    let texts: Vec<(String, UIElement)> = cells
        .into_iter()
        .filter_map(|cell| {
            let text = cell
                .get_cached_property_value(UIProperty::ValueValue)
                .ok()?
                .get_string()
                .ok()?;
            Some((words(&text), cell))
        })
        .collect();
    for needle in needles {
        let wanted = words(&needle.text);
        let found = texts.iter().find(|(text, _)| {
            if needle.ignore_case {
                text.to_lowercase().contains(&wanted.to_lowercase())
            } else {
                text.contains(&wanted)
            }
        });
        if let Some((_, cell)) = found {
            return Some(cell.clone());
        }
    }
    None
}

/// `text` with every run of white space one space, as the findings list shows values.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Where `element` is on the screen.
fn bounds(element: &UIElement) -> Option<Rect> {
    crate::uia_text::bounds(element)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn white_space_is_one_space_as_in_the_findings_list() {
        assert_eq!(words("  Jan \t de\r\nVries "), "Jan de Vries");
        assert_eq!(words(""), "");
    }
}
