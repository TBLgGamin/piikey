//! The details pane of a dashboard: what the selected folder or file holds, by type, and what can
//! be done with it. With nothing selected it describes the folder on show.

use std::path::{Path, PathBuf};

use piikey::{
    detect::EntityKind,
    inventory::{Entry, MAX_FILE, Node, Status},
};
use windows_reactor::{
    Border, Button, FontWeight, Grid, GridLength, HorizontalAlignment, ScrollViewer, StackPanel,
    TextBlock, TextTrimming, ThemeBrush, Thickness, VerticalAlignment, View,
};

use super::{
    crumbs::{name_of, top_label},
    palette::swatch,
};
use crate::ui::{
    controller::Store,
    pages::kit::{Context, caption, counted, glyph, thousands, when},
    window::{Dash, Dashboard, Loaded, Msg},
};

/// What the details are about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    /// Everything the dashboard covers, with no folder chosen.
    Top,
    /// The scans of files outside every location: no folder to open or show.
    Other,
    Folder,
    File,
}

/// What the details pane says, apart from how it looks.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Subject {
    pub(super) target: Target,
    /// The name of the folder or file.
    pub(super) title: String,
    /// Where it is; empty for the top and the scans outside every location.
    pub(super) path: PathBuf,
    /// "12 found in 3 files", or why a file has none.
    pub(super) summary: String,
    /// What it holds, by type, the most first.
    pub(super) types: Vec<(EntityKind, u64)>,
    /// When it was scanned and how big it is, for a file.
    pub(super) note: Option<String>,
}

/// What the details pane lets the user do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Open,
    Show,
    Found,
    Mask,
    Scan,
    /// Show only this folder.
    Enter,
}

impl Action {
    /// The words on the button.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Show => "Show in Explorer",
            Self::Found => "Show what was found",
            Self::Mask => "Make masked copy",
            Self::Scan => "Scan this",
            Self::Enter => "Show only this folder",
        }
    }

    /// What pressing it asks of the window, for the file or folder at `path`.
    fn message(self, store: Store, path: &Path) -> Msg {
        let path = path.to_path_buf();
        Msg::Dash(
            store,
            match self {
                Self::Open => Dash::Open(path),
                Self::Show => Dash::Show(path),
                Self::Found => Dash::Found(path),
                Self::Mask => Dash::Mask(path),
                Self::Scan => Dash::Scan(path),
                Self::Enter => Dash::Enter(path),
            },
        )
    }
}

/// What can be done with a `target` of `store`. The watch looks at its files by itself, so it has
/// nothing to scan; a folder already on show cannot be shown again (`on_show`).
pub(super) fn actions(target: Target, store: Store, on_show: bool) -> Vec<Action> {
    let mut list = match target {
        Target::File => vec![Action::Open, Action::Show, Action::Found, Action::Mask],
        Target::Folder => vec![Action::Show],
        Target::Top | Target::Other => Vec::new(),
    };
    if target == Target::Folder && !on_show {
        list.insert(0, Action::Enter);
    }
    if store == Store::Inventory && matches!(target, Target::File | Target::Folder) {
        list.push(Action::Scan);
    }
    list
}

/// `12 found in 3 files`.
fn found_in(hits: u64, files: u64) -> String {
    format!(
        "{} found in {}",
        thousands(hits),
        counted(files, "file", "files")
    )
}

/// The size of a file in the largest unit that keeps it above one: `1.4 KB`, `12 KB`, `4.7 MB`.
pub(super) fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut tenths = bytes.saturating_mul(10);
    let mut unit = 0;
    while tenths >= 10_240 && unit + 1 < UNITS.len() {
        tenths /= 1024;
        unit += 1;
    }
    match unit {
        0 => format!("{bytes} B"),
        _ if tenths >= 100 => format!("{} {}", tenths / 10, UNITS[unit]),
        _ => format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit]),
    }
}

/// "Last scanned 14:05": when a scan looked at the file, told the way the vault's list tells
/// times.
pub(super) fn scanned_text(scanned: u64) -> String {
    format!("Last scanned {}", when(scanned))
}

/// What the scan of a file came to, as the details put it.
fn entry_summary(entry: &Entry) -> String {
    match &entry.status {
        Status::Ok if entry.hits() == 0 => "No personal data found.".to_owned(),
        Status::Ok => format!("{} found", thousands(entry.hits())),
        Status::Unsupported => "piikey cannot read this type of file.".to_owned(),
        Status::TooLarge => format!(
            "Too large to scan: piikey skips files over {} MB.",
            MAX_FILE >> 20
        ),
        Status::Failed(error) => format!("Could not be scanned: {error}"),
    }
}

/// The node of `path` in the levels the last load brought.
fn node_in<'a>(loaded: &'a Loaded, path: &Path) -> Option<&'a Node> {
    loaded
        .levels
        .values()
        .flatten()
        .find(|node| node.path == path)
}

/// `counts` with their numbers as 64 bit.
fn wide(counts: &[(EntityKind, u32)]) -> Vec<(EntityKind, u64)> {
    counts
        .iter()
        .map(|&(kind, n)| (kind, u64::from(n)))
        .collect()
}

/// What the folder on show holds: the types the legend counts, and the files under its rows.
fn on_show(dash: &Dashboard, loaded: &Loaded, store: Store) -> Subject {
    let top = dash.at.as_os_str().is_empty();
    let hits: u64 = loaded.totals.iter().map(|total| total.hits).sum();
    let files: u64 = loaded.levels.get(&dash.at).map_or(0, |nodes| {
        nodes.iter().map(|node| u64::from(node.files)).sum()
    });
    Subject {
        target: if top { Target::Top } else { Target::Folder },
        title: if top {
            top_label(store).to_owned()
        } else {
            name_of(&dash.at)
        },
        path: dash.at.clone(),
        summary: if hits == 0 {
            "No personal data found.".to_owned()
        } else {
            found_in(hits, files)
        },
        types: loaded
            .totals
            .iter()
            .map(|total| (total.kind, total.hits))
            .collect(),
        note: None,
    }
}

/// The subject of a file: what its entry says when the store knows it, else what its tile or its
/// row says.
fn file_subject(loaded: &Loaded, path: &Path) -> Subject {
    let entry = loaded.entry.as_ref().filter(|entry| entry.path == path);
    let tile = loaded.tiles.tiles.iter().find(|tile| tile.path == path);
    let node = node_in(loaded, path);
    let (summary, counts) = match (entry, tile, node) {
        (Some(entry), _, _) => (entry_summary(entry), wide(&entry.counts)),
        (None, Some(tile), _) => (
            format!("{} found", thousands(tile.hits)),
            wide(&tile.counts),
        ),
        (None, None, Some(node)) => (
            format!("{} found", thousands(node.hits)),
            wide(&node.counts),
        ),
        (None, None, None) => ("No scan of this file yet.".to_owned(), Vec::new()),
    };
    let mut notes: Vec<String> = Vec::new();
    if let Some(entry) = entry {
        notes.push(scanned_text(entry.scanned));
        notes.push(size_text(entry.size));
    } else if let Some(tile) = tile {
        notes.push(size_text(tile.size));
    }
    Subject {
        target: Target::File,
        title: name_of(path),
        path: path.to_path_buf(),
        summary,
        types: counts,
        note: (!notes.is_empty()).then(|| notes.join(" \u{b7} ")),
    }
}

/// The subject of a folder that is selected: what its row says, or what is known of it.
fn folder_subject(dash: &Dashboard, loaded: &Loaded, store: Store, path: &Path) -> Subject {
    if path == dash.at {
        return on_show(dash, loaded, store);
    }
    let node = node_in(loaded, path);
    Subject {
        target: Target::Folder,
        title: name_of(path),
        path: path.to_path_buf(),
        summary: node.map_or_else(String::new, |node| {
            found_in(node.hits, u64::from(node.files))
        }),
        types: node.map_or_else(Vec::new, |node| wide(&node.counts)),
        note: None,
    }
}

/// What the details describe: the selection, or the folder on show.
pub(super) fn subject(dash: &Dashboard, loaded: &Loaded, store: Store) -> Subject {
    let Some(selected) = dash.selected.as_deref() else {
        return on_show(dash, loaded, store);
    };
    if selected.as_os_str().is_empty() {
        let node = node_in(loaded, selected);
        return Subject {
            target: Target::Other,
            title: "Other scans".to_owned(),
            path: PathBuf::new(),
            summary: node.map_or_else(String::new, |node| {
                found_in(node.hits, u64::from(node.files))
            }),
            types: node.map_or_else(Vec::new, |node| wide(&node.counts)),
            note: Some("Scans of files outside the folders piikey looks through.".to_owned()),
        };
    }
    if dash.is_folder(selected) {
        folder_subject(dash, loaded, store, selected)
    } else {
        file_subject(loaded, selected)
    }
}

/// One type with how many were found: its colour, its name and the number.
fn type_row(kind: EntityKind, n: u64) -> View {
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((
            swatch(kind),
            TextBlock::new()
                .text(kind.label())
                .text_trimming(TextTrimming::CharacterEllipsis)
                .grid_column(1),
            TextBlock::new()
                .text(thousands(n))
                .opacity(0.72)
                .grid_column(2),
        ))
        .into()
}

/// The buttons of `actions`, two in a row.
fn buttons(list: &[Action], store: Store, path: &Path, context: Context<'_>) -> Option<View> {
    if list.is_empty() {
        return None;
    }
    let rows: Vec<View> = list
        .chunks(2)
        .map(|pair| {
            let cells: Vec<View> = pair
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    Button::new()
                        .content(action.label())
                        .horizontal_alignment(HorizontalAlignment::Stretch)
                        .grid_column(i32::try_from(i).unwrap_or(0))
                        .on_click(context.message(action.message(store, path)))
                        .into()
                })
                .collect();
            Grid::new()
                .columns([GridLength::STAR, GridLength::STAR])
                .column_spacing(8.0)
                .children(cells)
                .into()
        })
        .collect();
    Some(
        StackPanel::new()
            .spacing(8.0)
            .margin(Thickness::new(0.0, 6.0, 0.0, 0.0))
            .children(rows)
            .into(),
    )
}

/// How many types the details list in `height` DIPs: what the pane says besides them takes room,
/// the rest is for them, two at least.
fn type_rows(height: f64, target: Target, buttons: usize) -> usize {
    // Whole DIPs are all this needs.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a height in DIPs, floored and not below zero"
    )]
    let room = height.max(0.0).floor() as usize;
    // The card's padding, the title, the summary and the gaps between them.
    let mut taken = 90;
    if matches!(target, Target::File | Target::Folder) {
        // The path, in two lines at most.
        taken += 34;
    }
    if target == Target::File {
        // When it was scanned and how big it is.
        taken += 18;
    }
    taken += buttons.div_ceil(2) * 44;
    (room.saturating_sub(taken) / 26).max(2)
}

/// The details pane: a card that scrolls when what it says does not fit `height`.
pub(super) fn details(dash: &Dashboard, store: Store, height: f64, context: Context<'_>) -> Border {
    let Some(loaded) = dash.loaded.as_ref() else {
        return super::empty_card("Looking\u{2026}");
    };
    let subject = subject(dash, loaded, store);
    let icon = match subject.target {
        Target::File => "\u{E7C3}",
        Target::Top | Target::Other | Target::Folder => "\u{E8B7}",
    };
    let on_show = subject.path == dash.at;
    let todo = actions(subject.target, store, on_show);
    let rows = type_rows(height, subject.target, todo.len());
    let mut parts: Vec<View> = vec![
        Grid::new()
            .columns([GridLength::Auto, GridLength::STAR])
            .column_spacing(10.0)
            .children((
                glyph(icon, 20.0).vertical_alignment(VerticalAlignment::Center),
                TextBlock::new()
                    .text(&subject.title)
                    .font_size(16.0)
                    .font_weight(FontWeight::SEMI_BOLD)
                    .text_trimming(TextTrimming::CharacterEllipsis)
                    .vertical_alignment(VerticalAlignment::Center)
                    .grid_column(1),
            ))
            .into(),
    ];
    if !subject.path.as_os_str().is_empty() {
        parts.push(
            caption(subject.path.display().to_string())
                .is_text_selection_enabled(true)
                .max_lines(2)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .into(),
        );
    }
    parts.push(
        TextBlock::new()
            .text(&subject.summary)
            .text_wrapping(windows_reactor::TextWrapping::Wrap)
            .into(),
    );
    if let Some(note) = &subject.note {
        parts.push(caption(note).into());
    }
    parts.extend(
        subject
            .types
            .iter()
            .take(rows)
            .map(|&(kind, n)| type_row(kind, n)),
    );
    if subject.types.len() > rows {
        parts.push(
            caption(format!(
                "and {} more",
                counted(
                    u64::try_from(subject.types.len() - rows).unwrap_or(u64::MAX),
                    "type",
                    "types"
                )
            ))
            .into(),
        );
    }
    parts.extend(buttons(&todo, store, &subject.path, context));
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .padding(Thickness::new(14.0, 12.0, 6.0, 12.0))
        .content(
            ScrollViewer::new().content(
                StackPanel::new()
                    .spacing(6.0)
                    .margin(Thickness::new(0.0, 0.0, 8.0, 0.0))
                    .children(parts),
            ),
        )
}

#[cfg(test)]
mod tests {
    use piikey::inventory::{Rest, Tile, Tiles, TypeTotal};

    use super::*;

    fn node(path: &str, is_dir: bool, counts: &[(EntityKind, u32)]) -> Node {
        Node {
            path: PathBuf::from(path),
            name: name_of(Path::new(path)),
            is_dir,
            hits: counts.iter().map(|&(_, n)| u64::from(n)).sum(),
            files: 2,
            counts: counts.to_vec(),
        }
    }

    fn entry(path: &str, status: Status, counts: &[(EntityKind, u32)]) -> Entry {
        Entry {
            path: PathBuf::from(path),
            size: 12_345,
            modified: 0,
            scanned: 1_700_000_000,
            status,
            counts: counts.to_vec(),
            hash: None,
        }
    }

    fn loaded() -> Loaded {
        let mut levels = std::collections::HashMap::new();
        levels.insert(
            PathBuf::new(),
            vec![
                node(
                    r"C:\Docs",
                    true,
                    &[(EntityKind::Email, 5), (EntityKind::Person, 2)],
                ),
                node("", true, &[(EntityKind::Iban, 1)]),
            ],
        );
        levels.insert(
            PathBuf::from(r"C:\Docs"),
            vec![node(r"C:\Docs\a.pdf", false, &[(EntityKind::Email, 5)])],
        );
        Loaded {
            at: PathBuf::new(),
            levels,
            roots: vec![PathBuf::from(r"C:\Docs")],
            tiles: Tiles {
                tiles: vec![Tile {
                    path: PathBuf::from(r"C:\Docs\a.pdf"),
                    size: 2_048,
                    hits: 5,
                    counts: vec![(EntityKind::Email, 5)],
                }],
                rest: Rest::default(),
            },
            totals: vec![
                TypeTotal {
                    kind: EntityKind::Email,
                    hits: 5,
                    files: 1,
                },
                TypeTotal {
                    kind: EntityKind::Person,
                    hits: 2,
                    files: 1,
                },
            ],
            entry: Some(entry(
                r"C:\Docs\a.pdf",
                Status::Ok,
                &[(EntityKind::Email, 5)],
            )),
        }
    }

    fn dashboard(selected: Option<&str>, at: &str) -> Dashboard {
        let mut dash = Dashboard::new();
        dash.at = PathBuf::from(at);
        dash.selected = selected.map(PathBuf::from);
        dash.loaded = Some(loaded());
        dash
    }

    fn subject_of(dash: &Dashboard) -> Subject {
        let Some(loaded) = dash.loaded.as_ref() else {
            panic!("the dashboard has a load");
        };
        subject(dash, loaded, Store::Inventory)
    }

    #[test]
    fn with_nothing_selected_the_details_describe_what_is_on_show() {
        let top = subject_of(&dashboard(None, ""));
        assert_eq!(top.target, Target::Top);
        assert_eq!(top.title, "This PC");
        assert_eq!(top.summary, "7 found in 4 files");
        assert_eq!(top.types, [(EntityKind::Email, 5), (EntityKind::Person, 2)]);
        let inside = subject_of(&dashboard(None, r"C:\Docs"));
        assert_eq!(inside.target, Target::Folder);
        assert_eq!(inside.title, "Docs");
    }

    #[test]
    fn a_selected_file_says_what_its_scan_found_and_when() {
        let subject = subject_of(&dashboard(Some(r"C:\Docs\a.pdf"), ""));
        assert_eq!(subject.target, Target::File);
        assert_eq!(subject.title, "a.pdf");
        assert_eq!(subject.summary, "5 found");
        assert_eq!(subject.types, [(EntityKind::Email, 5)]);
        let Some(note) = subject.note else {
            panic!("a file has a note");
        };
        assert!(note.starts_with("Last scanned "), "{note}");
        assert!(note.ends_with("12 KB"), "{note}");
    }

    #[test]
    fn a_file_the_scan_could_not_read_says_why() {
        let mut dash = dashboard(Some(r"C:\Docs\a.pdf"), "");
        let Some(loaded) = dash.loaded.as_mut() else {
            panic!("a load");
        };
        loaded.entry = Some(entry(r"C:\Docs\a.pdf", Status::Unsupported, &[]));
        assert_eq!(
            subject_of(&dash).summary,
            "piikey cannot read this type of file."
        );
        let Some(loaded) = dash.loaded.as_mut() else {
            panic!("a load");
        };
        loaded.entry = Some(entry(r"C:\Docs\a.pdf", Status::Ok, &[]));
        assert_eq!(subject_of(&dash).summary, "No personal data found.");
        let Some(loaded) = dash.loaded.as_mut() else {
            panic!("a load");
        };
        loaded.entry = Some(entry(
            r"C:\Docs\a.pdf",
            Status::Failed("locked".into()),
            &[],
        ));
        assert_eq!(subject_of(&dash).summary, "Could not be scanned: locked");
    }

    #[test]
    fn a_file_without_an_entry_is_described_by_its_tile() {
        let mut dash = dashboard(Some(r"C:\Docs\a.pdf"), "");
        if let Some(loaded) = dash.loaded.as_mut() {
            loaded.entry = None;
        }
        let subject = subject_of(&dash);
        assert_eq!(subject.summary, "5 found");
        assert_eq!(subject.note.as_deref(), Some("2.0 KB"));
    }

    #[test]
    fn a_selected_folder_is_described_by_its_row() {
        let subject = subject_of(&dashboard(Some(r"C:\Docs"), ""));
        assert_eq!(subject.target, Target::Folder);
        assert_eq!(subject.summary, "7 found in 2 files");
        assert_eq!(subject.title, "Docs");
    }

    #[test]
    fn the_scans_outside_every_location_have_nothing_to_open() {
        let subject = subject_of(&dashboard(Some(""), ""));
        assert_eq!(subject.target, Target::Other);
        assert_eq!(subject.title, "Other scans");
        assert!(subject.path.as_os_str().is_empty());
        assert_eq!(subject.summary, "1 found in 2 files");
        assert!(actions(Target::Other, Store::Inventory, false).is_empty());
    }

    #[test]
    fn each_target_offers_what_applies_to_it() {
        let labels = |list: Vec<Action>| list.into_iter().map(Action::label).collect::<Vec<_>>();
        assert_eq!(
            labels(actions(Target::File, Store::Inventory, false)),
            [
                "Open",
                "Show in Explorer",
                "Show what was found",
                "Make masked copy",
                "Scan this"
            ]
        );
        assert_eq!(
            labels(actions(Target::Folder, Store::Inventory, false)),
            ["Show only this folder", "Show in Explorer", "Scan this"]
        );
        // The folder on show cannot be shown again.
        assert_eq!(
            labels(actions(Target::Folder, Store::Inventory, true)),
            ["Show in Explorer", "Scan this"]
        );
        // The watch keeps its files scanned by itself.
        assert_eq!(
            labels(actions(Target::File, Store::Watch, false)),
            [
                "Open",
                "Show in Explorer",
                "Show what was found",
                "Make masked copy"
            ]
        );
        assert!(actions(Target::Top, Store::Inventory, true).is_empty());
    }

    #[test]
    fn the_types_listed_are_what_the_height_leaves_after_the_rest_of_the_pane() {
        // Nothing selected: no path, no buttons.
        assert_eq!(type_rows(300.0, Target::Top, 0), 8);
        // A file with all its buttons leaves less.
        assert_eq!(type_rows(300.0, Target::File, 5), 2);
        assert_eq!(type_rows(500.0, Target::File, 5), 8);
        // Never fewer than two, however small the pane.
        assert_eq!(type_rows(0.0, Target::File, 5), 2);
        assert_eq!(type_rows(-5.0, Target::Top, 0), 2);
    }

    #[test]
    fn sizes_use_the_unit_that_keeps_them_short() {
        assert_eq!(size_text(0), "0 B");
        assert_eq!(size_text(1_023), "1023 B");
        assert_eq!(size_text(1_024), "1.0 KB");
        assert_eq!(size_text(1_500), "1.4 KB");
        assert_eq!(size_text(12_345), "12 KB");
        assert_eq!(size_text(5_000_000), "4.7 MB");
        assert_eq!(size_text(3 << 30), "3.0 GB");
        assert!(size_text(u64::MAX).ends_with("GB"));
    }
}
