//! The findings view: every value found in the files of a result, with its type, the text around
//! it, the file it is in and where in the file, and a button that opens the file at that place.
//!
//! It takes the room of the page that is on show, under a way back, a search box, a row of chips for
//! the types (and, for a folder, a list of its files). The rows are made as they scroll into view
//! (`ItemsRepeater` over a [`VirtualSource`]), so a list of a hundred thousand values costs no more
//! than a screenful. The values are on screen and nowhere else: see
//! [`FindingsView`](crate::ui::window::FindingsView).

use piikey::inventory::{Busy, Location};
use windows_reactor::{
    Border, Button, ButtonStyle, Callback, ComboBox, FontIcon, FontWeight, Grid, GridLength,
    HorizontalAlignment, ItemsRepeater, KeyedView, Orientation, ProgressRing, ScrollViewer,
    StackPanel, TextBlock, TextBox, TextTrimming, TextWrapping, ThemeBrush, Thickness, TooltipExt,
    VerticalAlignment, View, VirtualSource,
};

use super::{
    legend,
    palette::{kind_color, text_on},
    report::scanned_what,
};
use crate::ui::{
    pages::kit::{Context, caption, counted, glyph, kind_glyph, measured, subtitle, thousands},
    window::{FindingsView, Msg, Reading, Row, Working},
};

/// How high a row is.
const ROW: f64 = 60.0;
/// The most a file's name takes of a row, so a long one leaves room for the value.
const FILE_WIDTH: f64 = 190.0;
/// What the search box asks for.
const SEARCH_HINT: &str = "Search values, types, files or the text around them";
/// What the button of a row does.
const OPEN_HINT: &str = "Open at this place";
/// What the button of a row says once it could only open the file.
const OPENED_ONLY: &str =
    "Opened the file. piikey cannot jump to the value in this app: search for it there.";

/// Where a value is in its file, in words: `line 12`, `page 3`, `Sheet1, cell B7`, `slide 4`,
/// `slide 4, notes`. A paragraph is named by its page when the file knows it (the page is what a
/// reader finds in a document), by its number when not.
pub(super) fn place_text(location: &Location) -> String {
    match location {
        Location::Line { line, .. } => format!("line {line}"),
        Location::Page(page)
        | Location::Paragraph {
            page: Some(page), ..
        } => format!("page {page}"),
        Location::Cell { sheet, cell } => format!("{sheet}, cell {cell}"),
        Location::Slide { slide, .. } => format!("slide {slide}"),
        Location::Notes(slide) => format!("slide {slide}, notes"),
        Location::Paragraph { paragraph, .. } => format!("paragraph {paragraph}"),
    }
}

/// [`place_text`] with all there is to say, for a tooltip: `Line 12, column 5`.
pub(super) fn place_detail(location: &Location) -> String {
    match location {
        Location::Line { line, column } => format!("Line {line}, column {column}"),
        Location::Page(page) => format!("Page {page}"),
        Location::Cell { sheet, cell } => format!("Sheet {sheet}, cell {cell}"),
        Location::Slide {
            slide,
            shape: Some(shape),
        } => format!("Slide {slide}, shape {shape}"),
        Location::Slide { slide, shape: None } => format!("Slide {slide}"),
        Location::Notes(slide) => format!("Notes of slide {slide}"),
        Location::Paragraph {
            paragraph,
            page: Some(page),
        } => format!("Page {page}, paragraph {paragraph}"),
        Location::Paragraph {
            paragraph,
            page: None,
        } => format!("Paragraph {paragraph}"),
    }
}

/// What the line over the list says about the reading of file number `done + 1` of `total`: which
/// file it is, and what the reading is doing when that takes a while. A view of one file leaves
/// the first out when the second is there.
fn reading_parts(view: &FindingsView, done: usize, total: usize, parts: &mut Vec<String>) {
    let working = view.working.as_ref().map(working_text);
    if working.is_none() || !view.single() {
        parts.push(format!(
            "Reading file {} of {total}\u{2026}",
            (done + 1).min(total)
        ));
    }
    parts.extend(working);
}

/// What a reading says it is doing, in words.
fn working_text(working: &Working) -> String {
    match working {
        Working::Model => "Loading the detection model\u{2026}".to_owned(),
        Working::File(_, busy) => busy_text(*busy),
    }
}

/// What the reading of a file is busy with, in words: the findings view and a scan's dialog say
/// it alike.
pub(super) fn busy_text(busy: Busy) -> String {
    match busy {
        Busy::Picture => "Reading a picture\u{2026}".to_owned(),
        Busy::Pages { done, total } => {
            format!(
                "Reading scanned page {} of {total}\u{2026}",
                (done + 1).min(total)
            )
        }
        Busy::Model { done, total } if total > 0 => format!(
            "Looking for names and addresses\u{2026} {} %",
            (done * 100 / total).min(100)
        ),
        Busy::Model { .. } => "Looking for names and addresses\u{2026}".to_owned(),
    }
}

/// What the line over the list says: how much there is, how far the reading is and what is left
/// out.
pub(super) fn tally(view: &FindingsView) -> String {
    if view.reading == Reading::Listing {
        return "Looking for the files\u{2026}".to_owned();
    }
    let wide = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let values = wide(view.rows.len());
    let mut parts: Vec<String> = Vec::new();
    if view.rows.is_empty() {
        if let Reading::Files { done, total } = view.reading {
            reading_parts(view, done, total, &mut parts);
        } else {
            parts.push(nothing(view));
        }
    } else {
        let counted_values = counted(values, "value", "values");
        parts.push(if view.narrowed() {
            format!("{} of {counted_values}", thousands(wide(view.shown.len())))
        } else if view.single() {
            counted_values
        } else {
            format!(
                "{counted_values} in {}",
                counted(wide(view.files.len()), "file", "files")
            )
        });
        if let Reading::Files { done, total } = view.reading {
            reading_parts(view, done, total, &mut parts);
        }
    }
    if view.left_out_files > 0 {
        parts.push(format!(
            "{} left out",
            counted(wide(view.left_out_files), "more file", "more files")
        ));
    }
    if view.left_out_values > 0 {
        parts.push(format!(
            "The list stops at {}",
            counted(wide(view.rows.len()), "value", "values")
        ));
    }
    if !view.failed.is_empty() && !view.rows.is_empty() {
        parts.push(format!(
            "{} could not be read",
            counted(wide(view.failed.len()), "file", "files")
        ));
    }
    parts.join(" \u{b7} ")
}

/// What there is to say when nothing was found and the reading is over: that nothing was, or why
/// the files could not be read.
fn nothing(view: &FindingsView) -> String {
    match view.failed.as_slice() {
        [] => "No personal data found.".to_owned(),
        [(_, error)] if view.files.len() == 1 => error.clone(),
        failed if failed.len() == view.files.len() => format!(
            "None of the {} could be read.",
            counted(
                u64::try_from(failed.len()).unwrap_or(u64::MAX),
                "file",
                "files"
            )
        ),
        _ => "No personal data found.".to_owned(),
    }
}

/// What the list says when it has no row to show.
fn empty_text(view: &FindingsView) -> String {
    if !view.rows.is_empty() {
        "No value matches. Change the search, the type or the file.".to_owned()
    } else if view.reading == Reading::Done {
        nothing(view)
    } else {
        "Reading\u{2026}".to_owned()
    }
}

/// The way back and what the view is about.
fn header(view: &FindingsView, context: Context<'_>) -> View {
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR])
        .column_spacing(12.0)
        .children((
            Button::new()
                .style(ButtonStyle::Subtle)
                .automation_name("Back")
                .vertical_alignment(VerticalAlignment::Center)
                .on_click(context.message(Msg::FindingsClose))
                .content(glyph("\u{E72B}", 16.0))
                .tooltip("Back"),
            StackPanel::new()
                .grid_column(1)
                .vertical_alignment(VerticalAlignment::Center)
                .children((
                    subtitle("What was found"),
                    caption(scanned_what(&view.roots))
                        .is_text_selection_enabled(true)
                        .max_lines(2)
                        .text_trimming(TextTrimming::CharacterEllipsis),
                )),
        ))
        .into()
}

/// The list of files to pick one from, for a result of more than one.
fn file_filter(view: &FindingsView, context: Context<'_>) -> Grid {
    let labels = view.files.iter().map(|file| file.label.as_str());
    let choice = ComboBox::new()
        .items_source(std::iter::once("All files").chain(labels))
        .selected_index(Some(view.file.map_or(0, |index| index + 1)))
        .width(240.0)
        .automation_name("File")
        .on_selection_changed(context.callback(|index: Option<usize>| {
            Msg::FindingsFile(index.and_then(|i| i.checked_sub(1)))
        }));
    // The files are known once; a list that is made again would clear the choice.
    Grid::new().keyed_children([KeyedView::new(
        format!("files-{}", view.files.len()),
        choice,
    )])
}

/// The search box, and for a result of several files the list of them.
fn filters(view: &FindingsView, context: Context<'_>) -> View {
    let search = TextBox::new()
        .text(&view.search)
        .placeholder_text(SEARCH_HINT)
        .automation_name("Search what was found")
        .on_text_changed(
            context.callback(|text: std::rc::Rc<str>| Msg::FindingsSearch(text.to_string())),
        );
    if view.single() {
        return search.into();
    }
    Grid::new()
        .columns([GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((search, file_filter(view, context).grid_column(1)))
        .into()
}

/// One chip for every type the search and the file leave, and the one for all of them first.
fn chips(view: &FindingsView, context: Context<'_>) -> View {
    if view.rows.is_empty() {
        return StackPanel::new().into();
    }
    let all: u64 = view.counts.iter().map(|&(_, n)| n).sum();
    let asks = |kind| context.message(Msg::FindingsType(kind));
    let mut chips: Vec<View> = vec![legend::chip(
        None,
        "All types",
        all,
        view.kind.is_none(),
        asks(None),
    )];
    chips.extend(view.counts.iter().map(|&(kind, n)| {
        let active = view.kind == Some(kind);
        legend::chip(
            Some(kind),
            kind.label(),
            n,
            active,
            asks(if active { None } else { Some(kind) }),
        )
    }));
    legend::strip_of(chips)
}

/// The line over the list: its tally, with a ring while the files are read.
fn status(view: &FindingsView) -> View {
    let text = caption(tally(view)).vertical_alignment(VerticalAlignment::Center);
    let busy = matches!(view.reading, Reading::Listing | Reading::Files { .. });
    let mut parts: Vec<View> = Vec::new();
    if busy {
        parts.push(
            ProgressRing::new()
                .is_active(true)
                .width(14.0)
                .height(14.0)
                .into(),
        );
    }
    parts.push(text.into());
    let line = StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(8.0)
        .children(parts);
    // The files that could not be read, and why: the line says how many.
    if view.failed.is_empty() {
        line.into()
    } else {
        let why: Vec<String> = view
            .failed
            .iter()
            .take(8)
            .map(|(file, error)| format!("{}: {error}", file.name))
            .collect();
        line.tooltip(why.join("\n"))
    }
}

/// The icon of a type: a tile in its colour with its glyph, the same colours as the map.
fn type_tile(row: &Row) -> Border {
    let kind = row.finding.kind;
    let color = kind_color(kind);
    Border::new()
        .width(32.0)
        .height(32.0)
        .corner_radius(6.0)
        .background(color)
        .vertical_alignment(VerticalAlignment::Center)
        .content(
            FontIcon::new()
                .glyph(kind_glyph(kind))
                .font_size(16.0)
                .foreground(text_on(color))
                .horizontal_alignment(HorizontalAlignment::Center)
                .vertical_alignment(VerticalAlignment::Center),
        )
}

/// The value over its type and the text around it.
fn words(row: &Row) -> View {
    let finding = &row.finding;
    StackPanel::new()
        .grid_column(1)
        .vertical_alignment(VerticalAlignment::Center)
        .children((
            TextBlock::new()
                .text(&*finding.value)
                .font_weight(FontWeight::SEMI_BOLD)
                .text_trimming(TextTrimming::CharacterEllipsis),
            caption(format!(
                "{} \u{b7} {}",
                finding.kind.label(),
                finding.snippet
            ))
            .text_wrapping(TextWrapping::NoWrap)
            .text_trimming(TextTrimming::CharacterEllipsis),
        ))
        .tooltip(&*finding.value)
}

/// Which file and where in it, on the right of a row; the file is left out when the result is
/// about one.
fn whereabouts(row: &Row, single: bool) -> StackPanel {
    let mut lines: Vec<View> = Vec::new();
    if !single {
        lines.push(
            TextBlock::new()
                .text(&row.file.name)
                .max_width(FILE_WIDTH)
                .horizontal_alignment(HorizontalAlignment::Right)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .tooltip(row.file.path.display().to_string()),
        );
    }
    if let Some(location) = &row.finding.location {
        lines.push(
            caption(place_text(location))
                .max_width(FILE_WIDTH)
                .horizontal_alignment(HorizontalAlignment::Right)
                .text_wrapping(TextWrapping::NoWrap)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .tooltip(place_detail(location)),
        );
    }
    StackPanel::new()
        .grid_column(2)
        .vertical_alignment(VerticalAlignment::Center)
        .children(lines)
}

/// The button that opens the file at the place of the value. While one row is being opened every
/// button waits, and the row itself shows a ring.
fn open_button(row: &Row, opened_only: bool, opening: Option<u32>, open: &Callback<Msg>) -> View {
    let id = row.id;
    let open = open.clone();
    let hint = if opened_only { OPENED_ONLY } else { OPEN_HINT };
    let icon: View = if opening == Some(id) {
        ProgressRing::new()
            .is_active(true)
            .width(16.0)
            .height(16.0)
            .into()
    } else {
        glyph("\u{E8A7}", 16.0).into()
    };
    Button::new()
        .style(ButtonStyle::Subtle)
        .grid_column(3)
        .vertical_alignment(VerticalAlignment::Center)
        .is_enabled(opening.is_none())
        .automation_name(format!("Open {} at this place", row.file.name))
        .on_click(move || open.call(Msg::FindingsOpen(id)))
        .content(icon)
        .tooltip(hint)
}

/// How wide the place of a value is in a row of a result of one file.
const PLACE_ALONE: f64 = 120.0;

/// One value as a row of the list.
fn row_view(
    row: &Row,
    single: bool,
    opened_only: bool,
    opening: Option<u32>,
    open: &Callback<Msg>,
) -> View {
    Border::new()
        .height(ROW)
        .padding(Thickness::new(12.0, 0.0, 6.0, 0.0))
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(Thickness::new(0.0, 0.0, 0.0, 1.0))
        .content(
            Grid::new()
                .columns([
                    GridLength::Auto,
                    GridLength::STAR,
                    GridLength::Pixel(if single { PLACE_ALONE } else { FILE_WIDTH }),
                    GridLength::Auto,
                ])
                .column_spacing(12.0)
                .children((
                    type_tile(row),
                    words(row),
                    whereabouts(row, single),
                    open_button(row, opened_only, opening, open),
                )),
        )
        .into()
}

/// The card around the list, with `content` in it.
fn card(content: impl Into<View>) -> Border {
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .content(content)
}

/// The rows the search, the type and the file leave, made as they scroll into view; or what there
/// is to say when there are none.
fn list(view: &FindingsView, context: Context<'_>) -> View {
    if view.shown.is_empty() {
        return card(
            caption(empty_text(view))
                .margin(Thickness::uniform(16.0))
                .text_wrapping(TextWrapping::Wrap),
        )
        .into();
    }
    let shown = std::rc::Rc::clone(&view.shown);
    let keys = std::rc::Rc::clone(&shown);
    let opened_only = std::rc::Rc::clone(&view.opened_only);
    let (single, opening) = (view.single(), view.opening);
    let open = context.forward();
    let source = VirtualSource::new(
        view.revision,
        shown.len(),
        move |index| keys.get(index).map_or(0, |row| row.id),
        move |index| -> View {
            match shown.get(index) {
                Some(row) => row_view(row, single, opened_only.contains(&row.id), opening, &open),
                None => Border::new().into(),
            }
        },
    );
    card(ScrollViewer::new().content(ItemsRepeater::new().virtual_source(source))).into()
}

/// `child` in row `row` of the panel's grid: a view has no row of its own to set.
fn in_row(row: i32, child: View) -> Grid {
    Grid::new().grid_row(row).children((child,))
}

/// The findings view as a page body: the way back, the search, the types, the tally and the list.
pub(in crate::ui) fn panel(view: &FindingsView, context: Context<'_>) -> View {
    measured(
        Grid::new()
            .rows([
                GridLength::Auto,
                GridLength::Auto,
                GridLength::Auto,
                GridLength::Auto,
                GridLength::STAR,
            ])
            .row_spacing(10.0)
            .children((
                header(view, context),
                in_row(1, filters(view, context)),
                in_row(2, chips(view, context)),
                in_row(3, status(view)),
                in_row(4, list(view, context)),
            )),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use piikey::{detect::EntityKind, inventory::Finding};

    use super::*;
    use crate::ui::controller::{FindingFile, FindingFiles};

    fn finding(value: &str) -> Finding {
        Finding {
            kind: EntityKind::Email,
            value: value.into(),
            snippet: value.into(),
            location: None,
        }
    }

    fn files(names: &[&str]) -> FindingFiles {
        FindingFiles {
            files: names
                .iter()
                .map(|name| FindingFile {
                    path: PathBuf::from(format!(r"C:\Docs\{name}")),
                    label: (*name).to_owned(),
                })
                .collect(),
            left_out: 0,
        }
    }

    fn view(names: &[&str]) -> FindingsView {
        let mut view = FindingsView::new(vec![PathBuf::from(r"C:\Docs")], 1);
        assert_eq!(view.reading, Reading::Listing);
        view.list(files(names));
        view
    }

    fn batch(name: &str, values: &[&str]) -> (PathBuf, Result<Vec<Finding>, String>) {
        (
            PathBuf::from(format!(r"C:\Docs\{name}")),
            Ok(values.iter().map(|value| finding(value)).collect()),
        )
    }

    #[test]
    fn a_place_is_a_line_a_page_a_cell_a_slide_or_a_paragraph_in_words() {
        let line = Location::Line {
            line: 12,
            column: 5,
        };
        assert_eq!(place_text(&line), "line 12");
        assert_eq!(place_detail(&line), "Line 12, column 5");
        assert_eq!(place_text(&Location::Page(3)), "page 3");
        assert_eq!(place_detail(&Location::Page(3)), "Page 3");
        let cell = Location::Cell {
            sheet: "Klanten".into(),
            cell: "B7".into(),
        };
        assert_eq!(place_text(&cell), "Klanten, cell B7");
        assert_eq!(place_detail(&cell), "Sheet Klanten, cell B7");
        let shape = Location::Slide {
            slide: 4,
            shape: Some(2),
        };
        assert_eq!(place_text(&shape), "slide 4");
        assert_eq!(place_detail(&shape), "Slide 4, shape 2");
        let loose = Location::Slide {
            slide: 4,
            shape: None,
        };
        assert_eq!(place_text(&loose), "slide 4");
        assert_eq!(place_detail(&loose), "Slide 4");
        assert_eq!(place_text(&Location::Notes(4)), "slide 4, notes");
        assert_eq!(place_detail(&Location::Notes(4)), "Notes of slide 4");
        // A paragraph is named by its page when the file says which, else by its number.
        let paged = Location::Paragraph {
            paragraph: 12,
            page: Some(3),
        };
        assert_eq!(place_text(&paged), "page 3");
        assert_eq!(place_detail(&paged), "Page 3, paragraph 12");
        let bare = Location::Paragraph {
            paragraph: 12,
            page: None,
        };
        assert_eq!(place_text(&bare), "paragraph 12");
        assert_eq!(place_detail(&bare), "Paragraph 12");
    }

    #[test]
    fn the_tally_follows_the_reading_from_the_search_for_files_to_the_last_value() {
        let mut view = FindingsView::new(vec![PathBuf::from(r"C:\Docs")], 1);
        assert_eq!(tally(&view), "Looking for the files\u{2026}");
        view.list(files(&["a.txt", "b.txt", "c.txt"]));
        assert_eq!(tally(&view), "Reading file 1 of 3\u{2026}");
        view.take(vec![batch("a.txt", &["jan@acme.nl", "piet@acme.nl"])]);
        assert_eq!(
            tally(&view),
            "2 values in 3 files \u{b7} Reading file 2 of 3\u{2026}"
        );
        view.take(vec![batch("b.txt", &["x@acme.nl"]), batch("c.txt", &[])]);
        assert_eq!(tally(&view), "3 values in 3 files");
    }

    #[test]
    fn a_narrowed_list_says_how_many_of_all_it_shows() {
        let mut view = view(&["a.txt"]);
        view.take(vec![batch(
            "a.txt",
            &["jan@acme.nl", "piet@acme.nl", "kees@x.nl"],
        )]);
        assert_eq!(tally(&view), "3 values");
        view.search = "acme".to_owned();
        view.refilter();
        assert_eq!(tally(&view), "2 of 3 values");
        view.search = "zzz".to_owned();
        view.refilter();
        assert_eq!(tally(&view), "0 of 3 values");
        assert_eq!(
            empty_text(&view),
            "No value matches. Change the search, the type or the file."
        );
    }

    #[test]
    fn nothing_found_says_so_and_a_file_that_could_not_be_read_says_why() {
        let mut empty = view(&["a.txt"]);
        assert_eq!(empty_text(&empty), "Reading\u{2026}");
        empty.take(vec![batch("a.txt", &[])]);
        assert_eq!(tally(&empty), "No personal data found.");
        assert_eq!(empty_text(&empty), "No personal data found.");
        let mut none = view(&[]);
        none.finish();
        assert_eq!(tally(&none), "No personal data found.");

        let mut broken = view(&["a.bin"]);
        broken.take(vec![(
            PathBuf::from(r"C:\Docs\a.bin"),
            Err("piikey does not read this type of file".to_owned()),
        )]);
        assert_eq!(tally(&broken), "piikey does not read this type of file");

        let mut all_broken = view(&["a.bin", "b.bin"]);
        all_broken.take(vec![
            (PathBuf::from(r"C:\Docs\a.bin"), Err("no".to_owned())),
            (PathBuf::from(r"C:\Docs\b.bin"), Err("no".to_owned())),
        ]);
        assert_eq!(tally(&all_broken), "None of the 2 files could be read.");

        let mut some = view(&["a.txt", "b.bin"]);
        some.take(vec![
            batch("a.txt", &["jan@acme.nl"]),
            (PathBuf::from(r"C:\Docs\b.bin"), Err("no".to_owned())),
        ]);
        assert_eq!(
            tally(&some),
            "1 value in 2 files \u{b7} 1 file could not be read"
        );
    }

    #[test]
    fn what_was_left_out_is_said() {
        let mut view = view(&["a.txt"]);
        view.left_out_files = 12;
        view.take(vec![batch("a.txt", &["jan@acme.nl"])]);
        view.left_out_values = 3;
        assert_eq!(
            tally(&view),
            "1 value \u{b7} 12 more files left out \u{b7} The list stops at 1 value"
        );
    }
}
