//! Home's map of where the personal data is: the card with its breadcrumbs, the treemap and the
//! side panel. [`map`] decides which tiles there are and where they lie, [`panel`] what the side
//! panel says; this file draws both.

mod map;
mod panel;

use piikey::{detect::EntityKind, inventory::Node};
use windows_reactor::{
    Button, ButtonStyle, Canvas, Color, CornerRadius, DataItem, FontIcon, FontWeight, Grid,
    GridLength, HorizontalAlignment, HyperlinkButton, ListView, ListViewSelectionMode, Orientation,
    ProgressBar, ResourceOverrides, StackPanel, Stretch, TextBlock, TextTrimming, TextWrapping,
    Thickness, TooltipExt, VerticalAlignment, View, Viewbox,
};

use self::{
    map::{
        BLACK, MAP_H, MAP_W, Tile, TileOf, WHITE, blend, is_selected, label_sizes, selection_ring,
        shows_label, tiles,
    },
    panel::{Buttons, Panel, crumbs, panel, scanned_text},
};
use super::{Context, caption, card, heading, list_height, thousands};
use crate::ui::window::{MainWindow, Msg, Selection};

/// Width of the side panel in DIPs.
const SIDE_WIDTH: f64 = 300.0;
/// Nodes the "+N more" list shows at most; it scrolls.
const MORE_ROWS: usize = 1000;
/// Rows of the "+N more" list that show without scrolling.
const MORE_VISIBLE: usize = 8;

/// Home's map of where the personal data is: a treemap of the folder on show, with a side panel
/// for what is selected in it.
pub(super) fn inventory_card(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut rows: Vec<View> = vec![inventory_header(window, context)];
    if let Some((done, total)) = snap.scan {
        rows.push(scan_progress(done, total));
    }
    // Until the first load has come back the card does not claim that there is nothing to see.
    if window.inv_loaded {
        if window.inv_view.nodes.is_empty() {
            if snap.scan.is_none() {
                rows.push(inventory_empty(window, context));
            }
        } else {
            rows.push(inventory_map(window, context));
        }
    }
    card(StackPanel::new().spacing(12.0).children(rows)).into()
}

/// The heading, the way back up (every crumb but the last is a link) and the report button.
fn inventory_header(window: &MainWindow, context: Context<'_>) -> View {
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
        .spacing(4.0)
        .children((
            Grid::new()
                .columns([GridLength::STAR, GridLength::Auto])
                .column_spacing(12.0)
                .children((
                    heading("Where your personal data is"),
                    Button::new()
                        .content("Export report")
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Center)
                        .is_enabled(!window.inv_view.nodes.is_empty())
                        .on_click(context.message(Msg::InvReport)),
                )),
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .children(steps),
        ))
        .into()
}

/// The progress of a scan: the bar, and what it has done.
fn scan_progress(done: u64, total: u64) -> View {
    let (bar, text) = if total == 0 {
        (
            ProgressBar::new().is_indeterminate(true),
            "Looking for files…".to_owned(),
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
                .value(done_f),
            format!("Scanned {} of {} files…", thousands(done), thousands(total)),
        )
    };
    StackPanel::new()
        .spacing(4.0)
        .children((bar, caption(text)))
        .into()
}

/// What the card says when there is nothing to draw and no scan is running.
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
                "Turn on the PII inventory to see which files in your folders hold personal data, or right-click a file or folder in Explorer and choose Scan for PII.",
            ),
            Button::new()
                .content("Turn on inventory")
                .style(ButtonStyle::Accent)
                .on_click(context.message(Msg::Inventory(true))),
        ))
        .into()
}

/// The treemap with its side panel.
fn inventory_map(window: &MainWindow, context: Context<'_>) -> View {
    let selected = window.inv_selected.as_ref();
    let buttons: Vec<View> = tiles(&window.inv_view.nodes)
        .iter()
        .map(|tile| tile_button(tile, is_selected(&tile.of, selected), window.dark, context))
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
/// replaced for this button only, so hover and press keep the tile's colour.
fn tile_button(tile: &Tile, selected: bool, dark: bool, context: Context<'_>) -> View {
    let message = match &tile.of {
        TileOf::Node(path) => Msg::InvOpen(path.clone()),
        TileOf::More => Msg::InvMore,
    };
    let ring = if selected {
        selection_ring(dark)
    } else {
        Color::transparent()
    };
    let resources = ResourceOverrides::new()
        .set("ButtonBackground", tile.color)
        .set("ButtonBackgroundPointerOver", blend(tile.color, WHITE, 18))
        .set("ButtonBackgroundPressed", blend(tile.color, BLACK, 18))
        .set("ButtonForeground", WHITE)
        .set("ButtonForegroundPointerOver", WHITE)
        .set("ButtonForegroundPressed", WHITE)
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

/// A tile's name over its counts, in white.
fn tile_label(tile: &Tile) -> View {
    let (name_size, detail_size) = label_sizes(&tile.rect);
    StackPanel::new()
        .children((
            TextBlock::new()
                .text(&tile.title)
                .font_size(name_size)
                .font_weight(FontWeight::SEMI_BOLD)
                .foreground(WHITE)
                .text_trimming(TextTrimming::CharacterEllipsis),
            TextBlock::new()
                .text(&tile.detail)
                .font_size(detail_size)
                .foreground(WHITE)
                .opacity(0.9)
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

/// One kind found, with how many.
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
