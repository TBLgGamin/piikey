//! Inventory: where personal data is stored on this PC. The inventory is what was scanned: the
//! Scan button looks through the locations, the box beside it scans one more folder or file, and
//! Explorer's "Scan for personal data" adds to it too. What was found is shown by the dashboard of
//! [`super::dashboard`]; nothing here runs by itself.

use std::path::Path;

use piikey::{inventory::Node, sys::same_path};
use windows_reactor::{
    Border, Button, ButtonStyle, Color, DragDropAction, DragDropOperation, DragDropPolicy,
    DroppedData, Orientation, ProgressBar, ProgressRing, StackPanel, VerticalAlignment, View,
};

use super::{
    dashboard::{self, dashboard, has_data, room},
    kit::{Context, caption, card, counted, form_error, page_header, thousands, wide_column},
    lists::{add_row, place_row, places_card},
};
use crate::ui::{
    controller::Store,
    status::Tone,
    window::{Dash, MainWindow, Msg, Page},
};

/// What the page is, in a sentence.
const DEFINITION: &str = "Where personal data is stored on this PC. Only what you scan is listed.";

/// What the dashboard has to leave room for on this page: the header, the box that adds a folder or
/// file, the line under it, and the gaps between them.
const CHROME: f64 = 150.0;
/// The width of the bar of a scan in DIPs.
const BAR_WIDTH: f64 = 240.0;

/// `712 found in 51 files · 3 locations`.
fn found_text(hits: u64, files: u64, locations: usize) -> String {
    format!(
        "{} found in {} \u{b7} {}",
        thousands(hits),
        counted(files, "file", "files"),
        counted(
            u64::try_from(locations).unwrap_or(u64::MAX),
            "location",
            "locations"
        ),
    )
}

/// The progress of a scan, in one row: a ring and "Looking for files…" while the files are still
/// being looked for (an indeterminate bar would draw a lone moving dot), a bar and how many are
/// scanned once they are counted.
fn scan_progress(done: u64, total: u64) -> View {
    let (indicator, text): (View, String) = if total == 0 {
        (
            ProgressRing::new()
                .is_active(true)
                .width(16.0)
                .height(16.0)
                .into(),
            "Looking for files\u{2026}".to_owned(),
        )
    } else {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a progress bar needs no precision beyond 2^53 files"
        )]
        let (done_f, total_f) = (done as f64, total as f64);
        (
            ProgressBar::new()
                .minimum(0.0)
                .maximum(total_f)
                .value(done_f)
                .width(BAR_WIDTH)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
            format!(
                "Scanned {} of {} files\u{2026}",
                thousands(done),
                thousands(total)
            ),
        )
    };
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(12.0)
        .children((
            indicator,
            caption(text).vertical_alignment(VerticalAlignment::Center),
        ))
        .into()
}

/// What stands under the box that adds a folder: the progress of a scan, or what the inventory
/// holds. A line of the height of the other keeps the page from jumping when a scan starts.
fn status_line(window: &MainWindow) -> View {
    let snap = &window.snap;
    if let Some((done, total)) = snap.scan {
        return scan_progress(done, total);
    }
    let (files, hits) = snap.inventory_totals;
    let text = if hits > 0 {
        found_text(hits, files, snap.policy.inventory_roots_or_default().len())
    } else {
        "Nothing found yet.".to_owned()
    };
    caption(text).into()
}

/// What the inventory found in `location`, for the row of the location: how much, or that nothing
/// was found there yet.
fn location_state(top: &[Node], location: &Path) -> (String, Tone) {
    match top.iter().find(|node| same_path(&node.path, location)) {
        Some(node) => (
            format!(
                "{} found in {}",
                thousands(node.hits),
                counted(u64::from(node.files), "file", "files")
            ),
            Tone::Good,
        ),
        None => ("Nothing found yet".to_owned(), Tone::Neutral),
    }
}

/// The locations the Scan button looks through, one row each like the folders of Watch: with what
/// was found in it and the button that takes it off. Also the room the card takes.
fn locations(window: &MainWindow, context: Context<'_>) -> (View, f64) {
    let top: &[Node] = window
        .inventory
        .loaded
        .as_ref()
        .map_or(&[], |loaded| &loaded.top);
    places_card(
        window
            .snap
            .policy
            .inventory_roots_or_default()
            .iter()
            .map(|location| {
                let (state, tone) = location_state(top, location);
                place_row(
                    location,
                    &state,
                    tone,
                    window.dark,
                    Msg::RemoveLocation(location.clone()),
                    context,
                )
            })
            .collect(),
    )
}

/// What the dashboard says when nothing was found: at the top, how to find something; in a folder,
/// that it holds nothing.
fn nothing(top: bool, context: Context<'_>) -> View {
    if !top {
        return dashboard::empty_card("No personal data found in this folder.").into();
    }
    card(
        StackPanel::new().spacing(10.0).children((
            caption(
                "Scan your locations to see which files hold personal data, or right-click a file or folder in Explorer and choose Scan for personal data.",
            ),
            Button::new()
                .content("Scan")
                .style(ButtonStyle::Accent)
                .on_click(context.message(Msg::ScanAll)),
        )),
    )
    .into()
}

pub(super) fn inventory(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let scanning = snap.scan.is_some();
    let exportable = has_data(window, Store::Inventory) == Some(true);
    let controls: Vec<View> = vec![
        Button::new()
            .content("Scan")
            .style(ButtonStyle::Accent)
            .is_enabled(!scanning)
            .on_click(context.message(Msg::ScanAll))
            .into(),
        Button::new()
            .content("Export report")
            .is_enabled(exportable)
            .on_click(context.message(Msg::Dash(Store::Inventory, Dash::Report)))
            .into(),
    ];
    let (places, listed) = locations(window, context);
    let mut children: Vec<View> = vec![page_header(Page::Inventory.title(), DEFINITION, controls)];
    children.extend(form_error(window, context));
    children.push(places);
    children.push(add_row(
        "A folder or file to scan, e.g. C:\\Users\\you\\Documents",
        &window.root_draft,
        "Add and scan",
        Msg::RootDraft,
        Msg::AddRoot,
        context,
    ));
    children.push(status_line(window));
    children.push(dashboard(
        window,
        Store::Inventory,
        room(window, CHROME + listed),
        |top| nothing(top, context),
        context,
    ));
    // What is dropped on the page from Explorer is scanned, and its result shown, as for the box.
    Border::new()
        .background(Color::transparent())
        .drop_policy(DragDropPolicy::new().storage_items(
            DragDropAction::new(DragDropOperation::Copy).caption("Scan for personal data"),
        ))
        .on_drop(context.callback(|dropped: DroppedData| match dropped {
            DroppedData::StorageItems(items) => {
                Msg::Dropped(items.into_iter().map(|item| item.path).collect())
            }
            DroppedData::Text(_) | DroppedData::Unsupported => Msg::Noop,
        }))
        .content(wide_column(children))
        .into()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn a_location_says_what_was_found_in_it_or_that_nothing_was() {
        let node = Node {
            path: PathBuf::from(r"C:\Users\me\Documents"),
            name: "Documents".to_owned(),
            is_dir: true,
            hits: 711,
            files: 51,
            counts: Vec::new(),
        };
        let top = [node];
        assert_eq!(
            location_state(&top, Path::new(r"c:\users\ME\documents")),
            ("711 found in 51 files".to_owned(), Tone::Good)
        );
        assert_eq!(
            location_state(&top, Path::new(r"C:\Users\me\Desktop")),
            ("Nothing found yet".to_owned(), Tone::Neutral)
        );
        assert_eq!(location_state(&[], Path::new(r"C:\Docs")).1, Tone::Neutral);
    }

    #[test]
    fn the_status_line_counts_values_files_and_locations() {
        assert_eq!(
            found_text(1234, 3, 3),
            "1,234 found in 3 files \u{b7} 3 locations"
        );
        assert_eq!(found_text(1, 1, 1), "1 found in 1 file \u{b7} 1 location");
    }
}
