//! Inventory: where personal data is stored on this PC. The inventory is what was scanned: the
//! Scan button looks through the locations, the box beside it scans one more folder or file, and
//! Explorer's "Scan for personal data" adds to it too. A location's Monitor switch has its file
//! changes scanned as they happen. What was found is shown by the dashboard of
//! [`super::dashboard`].

use std::path::Path;

use piikey::{inventory::Node, sys::same_path};
use windows_reactor::{
    Border, Button, ButtonStyle, Color, DragDropAction, DragDropOperation, DragDropPolicy,
    DroppedData, Orientation, ProgressBar, ProgressRing, StackPanel, VerticalAlignment, View,
};

use super::{
    dashboard::{self, dashboard, has_data, room},
    kit::{Context, caption, card, counted, form_error, page_header, thousands, when, wide_column},
    lists::{add_row_with, place_row, places_card},
};
use crate::ui::{
    controller::{FolderStatus, WatchedFolder},
    status::Tone,
    window::{Browse, Dash, MainWindow, Msg, Page},
};

/// What the page is, in a sentence.
const DEFINITION: &str = "Where personal data is stored on this PC: what you scan, kept up to date in the locations you monitor.";

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
    if let Some((done, total)) = snap.scan.or(snap.watch.scanning) {
        return scan_progress(done, total);
    }
    let (files, hits) = snap.inventory_totals;
    let text = if hits > 0 {
        found_text(hits, files, snap.policy.inventory_roots.len())
    } else {
        "Nothing found yet.".to_owned()
    };
    caption(text).into()
}

/// What monitoring a location is doing: how far the scan of its changes has got (`scanning`), when
/// a change was last seen, or why it cannot be monitored. `None` when there is nothing to say.
fn monitor_status(folder: &WatchedFolder, scanning: Option<(u64, u64)>) -> Option<String> {
    match &folder.status {
        FolderStatus::Unavailable(why) => Some(format!("Cannot monitor: {why}")),
        FolderStatus::Watching => {
            let scan = scanning.map(|(done, total)| {
                if total > 0 {
                    format!("Scanning {} of {}", thousands(done), thousands(total))
                } else {
                    "Scanning\u{2026}".to_owned()
                }
            });
            let change = folder
                .last_change
                .map(|at| format!("last change {}", when(at)));
            let parts: Vec<String> = scan.into_iter().chain(change).collect();
            (!parts.is_empty()).then(|| parts.join(" \u{b7} "))
        }
    }
}

/// What the inventory found in `location`, and what monitoring it is doing, for the row of the
/// location: how much, or that nothing was found there yet, then what `folder` (the location's
/// monitoring, if it is monitored) says. `places` is what a load counted for each location.
fn location_state(
    places: &[Node],
    location: &Path,
    folder: Option<&WatchedFolder>,
    scanning: Option<(u64, u64)>,
) -> (String, Tone) {
    let (found, something) = match places.iter().find(|node| same_path(&node.path, location)) {
        Some(node) => (
            format!(
                "{} found in {}",
                thousands(node.hits),
                counted(u64::from(node.files), "file", "files")
            ),
            true,
        ),
        None => ("Nothing found yet".to_owned(), false),
    };
    let text = match folder.and_then(|folder| monitor_status(folder, scanning)) {
        Some(status) => format!("{found} \u{b7} {status}"),
        None => found,
    };
    let unavailable =
        folder.is_some_and(|folder| matches!(folder.status, FolderStatus::Unavailable(_)));
    let tone = if unavailable {
        Tone::Caution
    } else if something {
        Tone::Good
    } else {
        Tone::Neutral
    };
    (text, tone)
}

/// The locations the Scan button looks through, one row each: with what was found in it, its
/// Monitor switch and the button that takes it off; or, with none, what to do. Also the room the
/// card takes.
fn locations(window: &MainWindow, context: Context<'_>) -> (View, f64) {
    let snap = &window.snap;
    let roots = &snap.policy.inventory_roots;
    if roots.is_empty() {
        return (
            card(caption(
                "No locations yet. Add a folder or file below, or drop one on this page.",
            ))
            .into(),
            60.0,
        );
    }
    let places: &[Node] = window
        .inventory
        .loaded
        .as_ref()
        .map_or(&[], |loaded| &loaded.places);
    places_card(
        roots
            .iter()
            .map(|location| {
                let monitored = snap
                    .policy
                    .monitored_roots
                    .iter()
                    .any(|root| same_path(root, location));
                let folder = snap
                    .watch
                    .folders
                    .iter()
                    .find(|folder| monitored && same_path(&folder.path, location));
                let (state, tone) = location_state(places, location, folder, snap.watch.scanning);
                let path = location.clone();
                place_row(
                    location,
                    &state,
                    tone,
                    window.dark,
                    monitored,
                    move |on| Msg::Monitor(path.clone(), on),
                    Msg::RemoveLocation(location.clone()),
                    context,
                )
            })
            .collect(),
    )
}

/// What the dashboard says when nothing was found: at the top, how to find something (the Scan
/// button sits in the page header already); in a folder, that it holds nothing.
fn nothing(top: bool) -> View {
    if !top {
        return dashboard::empty_card("No personal data found in this folder.").into();
    }
    card(caption(
        "Scan your locations to see which files hold personal data. Only what lies in your locations is listed here.",
    ))
    .into()
}

pub(super) fn inventory(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let scanning = snap.scan.is_some();
    let exportable = has_data(window) == Some(true);
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
            .on_click(context.message(Msg::Dash(Dash::Report)))
            .into(),
    ];
    let (places, listed) = locations(window, context);
    let mut children: Vec<View> = vec![page_header(Page::Inventory.title(), DEFINITION, controls)];
    children.extend(form_error(window, context));
    children.push(places);
    children.push(add_row_with(
        "A folder or file to scan, e.g. C:\\Users\\you\\Documents",
        &window.root_draft,
        "Add and scan",
        Msg::RootDraft,
        Msg::AddRoot,
        &[
            ("Browse folder\u{2026}", Browse::Location),
            ("Browse file\u{2026}", Browse::File),
        ],
        context,
    ));
    children.push(status_line(window));
    children.push(dashboard(
        window,
        room(window, CHROME + listed),
        nothing,
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

    fn node(path: &str, hits: u64, files: u32) -> Node {
        Node {
            path: PathBuf::from(path),
            name: "Documents".to_owned(),
            is_dir: true,
            hits,
            files,
            counts: Vec::new(),
        }
    }

    fn folder(status: FolderStatus, last_change: Option<u64>) -> WatchedFolder {
        WatchedFolder {
            path: PathBuf::from(r"C:\Users\me\Documents"),
            status,
            last_change,
        }
    }

    #[test]
    fn a_location_says_what_was_found_in_it_or_that_nothing_was() {
        let places = [node(r"C:\Users\me\Documents", 711, 51)];
        assert_eq!(
            location_state(&places, Path::new(r"c:\users\ME\documents"), None, None),
            ("711 found in 51 files".to_owned(), Tone::Good)
        );
        assert_eq!(
            location_state(&places, Path::new(r"C:\Users\me\Desktop"), None, None),
            ("Nothing found yet".to_owned(), Tone::Neutral)
        );
        assert_eq!(
            location_state(&[], Path::new(r"C:\Docs"), None, None).1,
            Tone::Neutral
        );
    }

    #[test]
    fn a_monitored_location_says_it_is_scanning_and_when_it_last_changed() {
        let location = Path::new(r"C:\Users\me\Documents");
        let idle = folder(FolderStatus::Watching, None);
        assert_eq!(
            location_state(&[], location, Some(&idle), None),
            ("Nothing found yet".to_owned(), Tone::Neutral)
        );
        assert_eq!(
            location_state(&[], location, Some(&idle), Some((3, 10))),
            (
                "Nothing found yet \u{b7} Scanning 3 of 10".to_owned(),
                Tone::Neutral
            )
        );
        assert_eq!(
            monitor_status(&idle, Some((0, 0))),
            Some("Scanning\u{2026}".to_owned())
        );
        let places = [node(r"C:\Users\me\Documents", 2, 1)];
        let changed = folder(FolderStatus::Watching, Some(1_700_000_000));
        let (text, tone) = location_state(&places, location, Some(&changed), None);
        assert!(
            text.starts_with("2 found in 1 file \u{b7} last change "),
            "{text}"
        );
        assert_eq!(tone, Tone::Good);
    }

    #[test]
    fn a_location_that_cannot_be_monitored_says_why() {
        let location = Path::new(r"C:\Users\me\Documents");
        let gone = folder(
            FolderStatus::Unavailable("The folder is not there.".to_owned()),
            None,
        );
        assert_eq!(
            location_state(&[], location, Some(&gone), None),
            (
                "Nothing found yet \u{b7} Cannot monitor: The folder is not there.".to_owned(),
                Tone::Caution
            )
        );
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
