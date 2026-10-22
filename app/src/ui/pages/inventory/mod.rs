//! The Inventory page: where personal data is stored on this PC. The header with its switch, the
//! status line, the map (breadcrumbs, treemap and side panel) and the lists of watched and left-out
//! folders. [`map`] decides which tiles there are and where they lie, [`panel`] what the side panel
//! says; this file draws all of it.

mod map;
mod panel;

use piikey::{detect::EntityKind, inventory::Node};
use windows_reactor::{
    Button, ButtonStyle, Canvas, Color, CornerRadius, DataItem, FontIcon, FontWeight, Grid,
    GridLength, HorizontalAlignment, HyperlinkButton, ListView, ListViewSelectionMode, Orientation,
    ProgressBar, ProgressRing, ResourceOverrides, StackPanel, Stretch, TextBlock, TextTrimming,
    TextWrapping, Thickness, TooltipExt, VerticalAlignment, View, Viewbox,
};

use self::{
    map::{
        MAP_H, MAP_W, Tile, TileOf, hover_color, is_selected, label_sizes, pressed_color,
        shows_label, tiles,
    },
    panel::{Buttons, Panel, crumbs, panel, scanned_text},
};
use super::{
    kit::{
        Context, Row, caption, card, column, counted, feature_switch, form_error, page_header,
        section, section_with, thousands,
    },
    lists::{add_row, list_height, path_list},
};
use crate::ui::window::{MainWindow, Msg, Selection};

/// Width of the side panel in DIPs.
const SIDE_WIDTH: f64 = 300.0;
/// Nodes the "+N more" list shows at most; it scrolls.
const MORE_ROWS: usize = 1000;
/// Rows of the "+N more" list that show without scrolling.
const MORE_VISIBLE: usize = 8;
/// The folders the inventory watches when none are chosen: Documents, Desktop and Downloads.
const DEFAULT_FOLDERS: usize = 3;
/// Width of the bar of a scan in DIPs.
const BAR_WIDTH: f64 = 240.0;

/// The Inventory page: the map of where personal data is stored on this PC.
pub(super) fn inventory(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let mapped = !window.inv_view.nodes.is_empty();
    let mut rows: Vec<View> = vec![page_header(
        "Inventory",
        "Where personal data is stored on this PC",
        [feature_switch("Inventory", policy.inventory, Msg::Inventory, context).into()],
    )];
    rows.extend(form_error(window, context));
    rows.push(status_line(window, context));
    rows.push(section_with(
        "Map",
        vec![
            Button::new()
                .content("Export report")
                .is_enabled(mapped)
                .on_click(context.message(Msg::InvReport))
                .into(),
            Button::new()
                .content("Rescan")
                .is_enabled(policy.inventory)
                .on_click(context.message(Msg::RescanAll))
                .into(),
        ],
        vec![map_card(window, context)],
    ));
    rows.push(section(
        "Watched folders",
        vec![
            caption("The inventory looks through these folders and everything in them.").into(),
            card(
                StackPanel::new().spacing(12.0).children((
                    path_list(
                        &policy.inventory_roots,
                        "root",
                        "None chosen: switching the inventory on scans your Documents, Desktop and Downloads.",
                        |path| Msg::Root(path, false),
                        context,
                    ),
                    add_row(
                        "C:\\Users\\you\\Documents",
                        &window.root_draft,
                        "Add folder",
                        Msg::RootDraft,
                        Msg::AddRoot,
                        context,
                    ),
                )),
            )
            .into(),
        ],
    ));
    rows.push(section(
        "Left out",
        vec![
            caption("The inventory skips these files and folders, and everything in them. To add one, choose Exclude on the map.").into(),
            card(path_list(
                &policy.inventory_exclude,
                "exclude",
                "Nothing is left out.",
                |path| Msg::Exclude(path, false),
                context,
            ))
            .into(),
        ],
    ));
    rows.push(section(
        "Explorer menu",
        vec![
            Row::new("Scan for personal data")
                .icon("\u{E8B7}")
                .description("Adds it to the right-click menu of files and folders, to see what personal data they hold. On Windows 11 it is under Show more options.")
                .control(feature_switch(
                    "Scan for personal data",
                    policy.explorer_menu,
                    Msg::ExplorerMenu,
                    context,
                ))
                .build(),
        ],
    ));
    column(rows)
}

/// What the page says about the inventory under its header: the progress of a scan, what the
/// inventory has found, or why there is nothing to see.
fn status_line(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    if let Some((done, total)) = snap.scan {
        return scan_progress(done, total);
    }
    // Until the first load has come back the page does not claim that there is nothing to see; an
    // inventory that is off has nothing to wait for.
    let nothing = window.inv_view.nodes.is_empty() && (window.inv_loaded || !snap.policy.inventory);
    if nothing {
        return inventory_empty(window, context);
    }
    if snap.policy.inventory {
        let (files, hits) = snap.inventory_totals;
        let folders = match snap.policy.inventory_roots.len() {
            0 => DEFAULT_FOLDERS,
            n => n,
        };
        return caption(found_text(hits, files, folders)).into();
    }
    caption("The inventory is off. The map shows what it found before.").into()
}

/// `12 found in 3 files · watching 3 folders.`
fn found_text(hits: u64, files: u64, folders: usize) -> String {
    let folders = u64::try_from(folders).unwrap_or(u64::MAX);
    format!(
        "{} found in {} \u{b7} watching {}.",
        thousands(hits),
        counted(files, "file", "files"),
        counted(folders, "folder", "folders"),
    )
}

/// The progress of a scan, in one row: a ring and "Looking for files…" while the files are still
/// being looked for (an indeterminate bar would draw a lone moving dot), a bar and how many are
/// scanned once they are counted. The row is as high as the line that follows a scan, so the page
/// does not jump when a scan starts or ends.
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

/// What the page says when there is nothing to draw and no scan is running.
fn inventory_empty(window: &MainWindow, context: Context<'_>) -> View {
    // The file an Explorer scan was about, else the folder on show.
    let scanned = match &window.inv_selected {
        Some(Selection::Node(file)) if !file.as_os_str().is_empty() => file.as_path(),
        _ => window.inv_at.as_path(),
    };
    if !scanned.as_os_str().is_empty() {
        return caption(format!("No personal data found in {}.", scanned.display())).into();
    }
    if window.snap.policy.inventory {
        return caption("Nothing found yet. piikey checks your folders in the background; the files that hold personal data show up here.").into();
    }
    StackPanel::new()
        .spacing(8.0)
        .children((
            caption(
                "Turn on the inventory to see which files in your folders hold personal data, or right-click a file or folder in Explorer and choose Scan for personal data.",
            ),
            Button::new()
                .content("Turn on inventory")
                .style(ButtonStyle::Accent)
                .on_click(context.message(Msg::Inventory(true))),
        ))
        .into()
}

/// The card of the map: the way back up and, when there is something to show, the treemap with its
/// side panel.
fn map_card(window: &MainWindow, context: Context<'_>) -> View {
    let mut rows: Vec<View> = vec![breadcrumbs(window, context)];
    if !window.inv_view.nodes.is_empty() {
        rows.push(inventory_map(window, context));
    }
    card(StackPanel::new().spacing(12.0).children(rows)).into()
}

/// The way back up: every crumb but the last is a link.
fn breadcrumbs(window: &MainWindow, context: Context<'_>) -> View {
    let trail = crumbs(&window.inv_at, &window.inv_view.roots);
    let mut steps: Vec<View> = Vec::new();
    for (i, crumb) in trail.iter().enumerate() {
        if i > 0 {
            steps.push(
                FontIcon::new()
                    .glyph("\u{E76C}")
                    .font_size(10.0)
                    .opacity(0.6)
                    .vertical_alignment(VerticalAlignment::Center)
                    .into(),
            );
        }
        if i + 1 == trail.len() {
            steps.push(
                TextBlock::new()
                    .text(&crumb.label)
                    .font_weight(FontWeight::SEMI_BOLD)
                    .vertical_alignment(VerticalAlignment::Center)
                    .margin(Thickness::new(8.0, 0.0, 8.0, 0.0))
                    .into(),
            );
        } else {
            steps.push(
                HyperlinkButton::new()
                    .content(crumb.label.as_str())
                    .on_click(context.message(Msg::InvNav(crumb.target.clone())))
                    .into(),
            );
        }
    }
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .children(steps)
        .into()
}

/// The treemap with its side panel.
fn inventory_map(window: &MainWindow, context: Context<'_>) -> View {
    let selected = window.inv_selected.as_ref();
    let buttons: Vec<View> = tiles(&window.inv_view.nodes, window.dark)
        .iter()
        .map(|tile| tile_button(tile, is_selected(&tile.of, selected), context))
        .collect();
    Grid::new()
        .columns([GridLength::STAR, GridLength::Pixel(SIDE_WIDTH)])
        .column_spacing(16.0)
        .children((
            Viewbox::new()
                .stretch(Stretch::Uniform)
                .vertical_alignment(VerticalAlignment::Top)
                .content(Canvas::new().width(MAP_W).height(MAP_H).children(buttons)),
            side_panel(window, context).grid_column(1),
        ))
        .into()
}

/// One tile as a button on the canvas, in the colour of its tile. The theme's button colours are
/// replaced for this button only, so hover and press keep the tile's colour, and the label keeps
/// the tile's label colour in every state.
fn tile_button(tile: &Tile, selected: bool, context: Context<'_>) -> View {
    let message = match &tile.of {
        TileOf::Node(path) => Msg::InvOpen(path.clone()),
        TileOf::More => Msg::InvMore,
    };
    // The label colour reads on the tile, so the frame does too.
    let ring = if selected {
        tile.text
    } else {
        Color::transparent()
    };
    let resources = ResourceOverrides::new()
        .set("ButtonBackground", tile.color)
        .set("ButtonBackgroundPointerOver", hover_color(tile))
        .set("ButtonBackgroundPressed", pressed_color(tile))
        .set("ButtonForeground", tile.text)
        .set("ButtonForegroundPointerOver", tile.text)
        .set("ButtonForegroundPressed", tile.text)
        .set("ButtonBorderBrush", ring)
        .set("ButtonBorderBrushPointerOver", ring)
        .set("ButtonBorderBrushPressed", ring)
        .set(
            "ButtonBorderThemeThickness",
            Thickness::uniform(if selected { 3.0 } else { 0.0 }),
        )
        .set("ControlCornerRadius", CornerRadius::uniform(4.0));
    let said = format!("{}: {}", tile.title, tile.detail);
    let mut button = Button::new()
        .canvas_left(tile.rect.x)
        .canvas_top(tile.rect.y)
        .width(tile.rect.w)
        .height(tile.rect.h)
        .min_width(0.0)
        .min_height(0.0)
        .background(tile.color)
        .horizontal_content_alignment(HorizontalAlignment::Left)
        .vertical_content_alignment(VerticalAlignment::Top)
        .resource_overrides(resources)
        .automation_name(&said)
        .on_click(context.message(message));
    if shows_label(&tile.rect) {
        button = button.content(tile_label(tile));
    }
    button.tooltip(said)
}

/// A tile's name over its counts, in the tile's label colour.
fn tile_label(tile: &Tile) -> View {
    let (name_size, detail_size) = label_sizes(&tile.rect);
    StackPanel::new()
        .children((
            TextBlock::new()
                .text(&tile.title)
                .font_size(name_size)
                .font_weight(FontWeight::SEMI_BOLD)
                .foreground(tile.text)
                .text_trimming(TextTrimming::CharacterEllipsis),
            TextBlock::new()
                .text(&tile.detail)
                .font_size(detail_size)
                .foreground(tile.text)
                .text_trimming(TextTrimming::CharacterEllipsis),
        ))
        .into()
}

/// The side panel: what is selected (the folder on show when nothing is), its numbers, and what
/// can be done with it.
fn side_panel(window: &MainWindow, context: Context<'_>) -> StackPanel {
    let subject = panel(
        &window.inv_view,
        &window.inv_at,
        window.inv_selected.as_ref(),
        window.snap.policy.inventory,
    );
    let mut children: Vec<View> = vec![
        TextBlock::new()
            .text(&subject.title)
            .font_size(16.0)
            .font_weight(FontWeight::SEMI_BOLD)
            .text_trimming(TextTrimming::CharacterEllipsis)
            .into(),
        caption(&subject.detail)
            .is_text_selection_enabled(true)
            .into(),
        TextBlock::new()
            .text(&subject.summary)
            .text_wrapping(TextWrapping::Wrap)
            .into(),
    ];
    if !subject.kinds.is_empty() {
        children.push(caption("Types of personal data").into());
    }
    children.extend(subject.kinds.iter().map(|&(kind, n)| kind_row(kind, n)));
    if let Some(scanned) = subject.scanned {
        children.push(caption(scanned_text(scanned)).into());
    }
    if !subject.rest.is_empty() {
        children.push(rest_list(subject.rest, context));
    }
    children.extend(action_buttons(&subject, context));
    StackPanel::new().spacing(6.0).children(children)
}

/// One type of personal data found, with how many.
fn kind_row(kind: EntityKind, n: u32) -> View {
    Grid::new()
        .columns([GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((
            TextBlock::new()
                .text(kind.label())
                .text_trimming(TextTrimming::CharacterEllipsis),
            TextBlock::new()
                .text(thousands(u64::from(n)))
                .opacity(0.72)
                .grid_column(1),
        ))
        .into()
}

/// The nodes of the "+N more" tile, each a link that does what its tile would have done.
fn rest_list(rest: &[Node], context: Context<'_>) -> View {
    let shown = rest.len().min(MORE_ROWS);
    let list = ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(list_height(shown.min(MORE_VISIBLE)))
        .items(rest.iter().take(shown).map(|node| {
            DataItem::new(format!("more:{}", node.path.display()), &node.name).content(
                Grid::new()
                    .columns([GridLength::STAR, GridLength::Auto])
                    .column_spacing(8.0)
                    .children((
                        HyperlinkButton::new()
                            .content(node.name.as_str())
                            .on_click(context.message(Msg::InvOpen(node.path.clone()))),
                        TextBlock::new()
                            .text(thousands(node.hits))
                            .opacity(0.72)
                            .vertical_alignment(VerticalAlignment::Center)
                            .grid_column(1),
                    )),
            )
        }));
    if rest.len() > shown {
        let more = u64::try_from(rest.len() - shown).unwrap_or(u64::MAX);
        return StackPanel::new()
            .spacing(4.0)
            .children((
                list,
                caption(format!("and {} smaller ones.", thousands(more))),
            ))
            .into();
    }
    list.into()
}

/// The buttons that apply to what the panel describes, or none.
fn action_buttons(panel: &Panel<'_>, context: Context<'_>) -> Option<View> {
    let button = |label: &str, message: Msg| -> View {
        Button::new()
            .content(label)
            .horizontal_alignment(HorizontalAlignment::Stretch)
            .horizontal_content_alignment(HorizontalAlignment::Left)
            .on_click(context.message(message))
            .into()
    };
    let buttons: Vec<View> = match (panel.buttons, panel.target) {
        (Buttons::File, Some(file)) => vec![
            button("Open", Msg::InvLaunch(file.to_path_buf())),
            button("Show in Explorer", Msg::InvShow(file.to_path_buf())),
            button("Rescan", Msg::InvRescan(file.to_path_buf())),
            button("Make masked copy", Msg::InvMask(file.to_path_buf())),
            button("Exclude", Msg::InvExclude(file.to_path_buf())),
        ],
        (Buttons::Folder, Some(folder)) => vec![
            button("Show in Explorer", Msg::InvShow(folder.to_path_buf())),
            button("Rescan", Msg::InvRescan(folder.to_path_buf())),
            button("Exclude", Msg::InvExclude(folder.to_path_buf())),
        ],
        (Buttons::All, _) => vec![button("Rescan", Msg::RescanAll)],
        _ => Vec::new(),
    };
    (!buttons.is_empty()).then(|| {
        StackPanel::new()
            .spacing(6.0)
            .margin(Thickness::new(0.0, 6.0, 0.0, 0.0))
            .children(buttons)
            .into()
    })
}

#[cfg(test)]
mod tests {
    use super::found_text;

    #[test]
    fn the_status_line_counts_values_files_and_folders() {
        assert_eq!(
            found_text(1234, 3, 3),
            "1,234 found in 3 files \u{b7} watching 3 folders."
        );
        assert_eq!(
            found_text(1, 1, 1),
            "1 found in 1 file \u{b7} watching 1 folder."
        );
    }
}

/// Nodes the tests of [`map`] and [`panel`] build their views from.
#[cfg(test)]
mod fixtures {
    use std::path::PathBuf;

    use piikey::{detect::EntityKind, inventory::Node};

    /// A file node of `C:\Data` with `hits` values of `kind`.
    pub(super) fn node(name: &str, hits: u64, kind: EntityKind) -> Node {
        Node {
            path: PathBuf::from(format!(r"C:\Data\{name}")),
            name: name.to_owned(),
            is_dir: false,
            hits,
            files: 1,
            counts: vec![(kind, u32::try_from(hits).unwrap_or(u32::MAX))],
        }
    }

    /// `n` nodes with the most values first.
    pub(super) fn nodes(n: usize) -> Vec<Node> {
        (0..n)
            .map(|i| {
                let hits = u64::try_from(n - i).unwrap_or(1) * 10;
                node(&format!("n{i}"), hits, EntityKind::Email)
            })
            .collect()
    }
}
