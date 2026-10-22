//! The dashboard of the Inventory and Watch pages: a tree of the folders and files that hold
//! personal data, the types found (the legend), a map with a tile for every file, and details of
//! what is selected. The pages around it differ; this is the same for both, and takes the store it
//! shows from the window.
//!
//! Two shapes, by the room there is. Wide: the tree, the map, and a column with the legend and the
//! details side by side. Narrow (the default window): the legend as one row of chips above the tree
//! on the left and the map over the details on the right. The map is laid out for the room it gets,
//! which the window works out from its own size.

mod crumbs;
mod details;
mod findings;
mod legend;
mod map;
mod palette;
mod report;
mod tree;
mod types;

use std::path::{Path, PathBuf};

use piikey::detect::EntityKind;
use windows_reactor::{
    Border, Button, ButtonStyle, Color, DataItem, FontIcon, FontWeight, Grid, GridLength,
    HyperlinkButton, KeyedView, ListView, ListViewSelectionMode, Orientation, StackPanel,
    TextBlock, TextTrimming, TextWrapping, ThemeBrush, Thickness, TooltipExt, VerticalAlignment,
    View,
};

use self::{
    crumbs::{crumbs, top_label},
    tree::{Line, Row, lines, position, segments},
};
pub(in crate::ui) use self::{findings::panel as findings_panel, report::dialog};
use super::kit::{Context, caption, card, counted, glyph, thousands};
use crate::ui::{
    controller::Store,
    treemap::Rect,
    window::{Dash, Dashboard, Loaded, Msg, Origin, PANE_WIDTH},
};

/// The dashboard has three columns from this width on, two below it.
const WIDE_FROM: f64 = 1_200.0;
/// Space between the parts of the dashboard.
const GAP: f64 = 12.0;
/// The height of the breadcrumb.
const CRUMBS: f64 = 32.0;
/// The least the tree, the map and the details are high.
const MIN_MAIN: f64 = 300.0;
/// What the card around the map takes of its canvas: padding and stroke.
const MAP_CARD: f64 = 14.0;
/// The least the canvas of the map is wide and high.
const MIN_CANVAS: (f64, f64) = (120.0, 80.0);
/// How far a row of the tree is indented for each folder it lies in.
const INDENT: f64 = 16.0;
/// The width of the bar of a row.
const BAR: f64 = 84.0;
/// The height of the bar of a row.
const BAR_HEIGHT: f64 = 6.0;

/// The height of the title bar above the pages.
const TITLE_BAR: f64 = 32.0;
/// What the page frame keeps clear around the page: at the sides, and above and below.
const PAGE_MARGIN: (f64, f64) = (48.0, 24.0);
/// The room the scroll bar of a page takes at its right.
const SCROLL_BAR: f64 = 16.0;
/// The least wide a dashboard is made.
const MIN_WIDTH: f64 = 480.0;

/// How much room a dashboard has, in DIPs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Space {
    pub(super) width: f64,
    pub(super) height: f64,
}

/// Where the parts of a dashboard go in the room it has.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Plan {
    wide: bool,
    /// The width of the tree.
    tree: f64,
    /// Wide: the width of the column with the legend and the details.
    side: f64,
    /// The height of the part below the breadcrumb (and, narrow, the chips).
    main: f64,
    /// The canvas of the map.
    canvas: (f64, f64),
    /// Narrow: the height of the map above the details.
    map_height: f64,
    /// Wide: the height of the legend's list.
    legend: f64,
    /// The height of the details.
    details: f64,
}

impl Plan {
    /// The plan for a dashboard of `space` that lists `types` types in its legend.
    fn of(space: Space, types: usize) -> Self {
        let canvas = |width: f64, height: f64| {
            (
                (width - MAP_CARD).max(MIN_CANVAS.0),
                (height - MAP_CARD).max(MIN_CANVAS.1),
            )
        };
        if space.width >= WIDE_FROM {
            let tree = (space.width * 0.30).clamp(340.0, 460.0);
            let side = (space.width * 0.25).clamp(300.0, 380.0);
            let main = (space.height - CRUMBS - GAP).max(MIN_MAIN);
            Self {
                wide: true,
                tree,
                side,
                main,
                canvas: canvas(space.width - tree - side - 2.0 * GAP, main),
                map_height: main,
                legend: legend::list_height(types, main * 0.45),
                details: main - legend::list_height(types, main * 0.45) - GAP,
            }
        } else {
            let tree = (space.width * 0.43).clamp(300.0, 420.0);
            let main = (space.height - CRUMBS - legend::STRIP - 2.0 * GAP).max(MIN_MAIN);
            let map_height = (main * 0.5).round();
            Self {
                wide: false,
                tree,
                side: 0.0,
                main,
                canvas: canvas(space.width - tree - GAP, map_height),
                map_height,
                legend: 0.0,
                details: main - map_height - GAP,
            }
        }
    }
}

/// The room a dashboard has on `window` when the rest of its page takes `used` DIPs of the height:
/// what is left of the window's client area after the pane, the title bar and the page's margins.
pub(super) fn room(window: &crate::ui::window::MainWindow, used: f64) -> Space {
    let size = window.size;
    Space {
        width: (size.width - PANE_WIDTH - PAGE_MARGIN.0 - SCROLL_BAR).max(MIN_WIDTH),
        height: (size.height - TITLE_BAR - PAGE_MARGIN.1 - used)
            .max(MIN_MAIN + CRUMBS + legend::STRIP + 2.0 * GAP),
    }
}

/// A card with one line in it: what a dashboard says while it has nothing else to show.
pub(super) fn empty_card(text: &str) -> Border {
    card(caption(text))
}

/// The way back up from the folder on show: every crumb but the last is a link.
fn crumb_bar(dash: &Dashboard, loaded: &Loaded, store: Store, context: Context<'_>) -> View {
    let trail = crumbs(&dash.at, &loaded.roots, top_label(store));
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
                    .on_click(context.message(Msg::Dash(store, Dash::Enter(crumb.target.clone()))))
                    .into(),
            );
        }
    }
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .height(CRUMBS)
        .children(steps)
        .into()
}

/// The bar of a row: as long as the row's share of its folder, in the colours of the types it
/// holds.
fn bar(row: &Row<'_>, kind: Option<EntityKind>) -> View {
    let full = (row.share * BAR).clamp(2.0, BAR);
    let parts = segments(&row.node.counts, kind, full);
    let mut columns: Vec<GridLength> = Vec::new();
    let mut cells: Vec<View> = Vec::new();
    for (i, (of, width)) in parts.iter().enumerate() {
        columns.push(GridLength::Pixel(*width));
        cells.push(
            Border::new()
                .background(of.map_or(palette::NEUTRAL, palette::kind_color))
                .grid_column(i32::try_from(i).unwrap_or(0))
                .into(),
        );
    }
    columns.push(GridLength::STAR);
    Grid::new()
        .width(BAR)
        .height(BAR_HEIGHT)
        .background(Color::argb(0x30, 0x80, 0x80, 0x80))
        .columns(columns)
        .vertical_alignment(VerticalAlignment::Center)
        .children(cells)
        .into()
}

/// What stands under a row's name: the files and the types for a folder, the types for a file.
fn row_caption(row: &Row<'_>, kind: Option<EntityKind>) -> String {
    let held: Vec<(EntityKind, u32)> = row
        .node
        .counts
        .iter()
        .copied()
        .filter(|&(of, _)| kind.is_none_or(|kind| kind == of))
        .collect();
    let names = types::names(&held, 2);
    if row.node.is_dir && kind.is_none() {
        format!(
            "{} \u{b7} {names}",
            counted(u64::from(row.node.files), "file", "files")
        )
    } else {
        names
    }
}

/// One row of the tree: how deep it is, a button to open it when it is a folder, its name over a
/// bar and the types it holds, and what it holds.
fn row_view(row: &Row<'_>, kind: Option<EntityKind>, store: Store, context: Context<'_>) -> View {
    let node = row.node;
    let chevron: View = if row.expandable() {
        Button::new()
            .style(ButtonStyle::Subtle)
            .grid_column(1)
            .vertical_alignment(VerticalAlignment::Center)
            .automation_name(format!(
                "{} {}",
                if row.open { "Close" } else { "Open" },
                node.name
            ))
            .on_click(context.message(Msg::Dash(store, Dash::Toggle(node.path.clone()))))
            .content(glyph(if row.open { "\u{E70D}" } else { "\u{E76C}" }, 10.0))
            .into()
    } else {
        Border::new().grid_column(1).into()
    };
    let name = Grid::new()
        .columns([GridLength::Auto, GridLength::STAR])
        .column_spacing(8.0)
        .children((
            glyph(if node.is_dir { "\u{E8B7}" } else { "\u{E7C3}" }, 14.0)
                .opacity(0.72)
                .vertical_alignment(VerticalAlignment::Center),
            TextBlock::new()
                .text(&node.name)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .grid_column(1),
        ));
    let under = Grid::new()
        .columns([GridLength::Pixel(BAR), GridLength::STAR])
        .column_spacing(8.0)
        .children((
            bar(row, kind),
            caption(row_caption(row, kind))
                .text_wrapping(TextWrapping::NoWrap)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .grid_column(1),
        ));
    let shown = if node.path.as_os_str().is_empty() {
        "Scans of files outside the folders piikey looks through".to_owned()
    } else {
        node.path.display().to_string()
    };
    Grid::new()
        .columns([
            GridLength::Pixel(INDENT * f64::from(u32::try_from(row.depth).unwrap_or(0))),
            GridLength::Auto,
            GridLength::STAR,
            GridLength::Auto,
        ])
        .children((
            Border::new().grid_column(0),
            chevron,
            StackPanel::new()
                .grid_column(2)
                .vertical_alignment(VerticalAlignment::Center)
                .children((name, under)),
            TextBlock::new()
                .text(thousands(row.found))
                .font_weight(FontWeight::SEMI_BOLD)
                .vertical_alignment(VerticalAlignment::Center)
                .margin(Thickness::new(10.0, 0.0, 0.0, 0.0))
                .grid_column(3),
        ))
        .tooltip(shown)
}

/// The line that stands for rows the tree leaves out.
fn leftover(line: &Line<'_>) -> Option<String> {
    match line {
        Line::Row(_) => None,
        Line::More { count, found, .. } => Some(format!(
            "And {} more that hold {} found. Open a folder, or pick a type, to see fewer.",
            thousands(u64::try_from(*count).unwrap_or(u64::MAX)),
            thousands(*found)
        )),
        Line::Cut => Some("The list stops here. Show a smaller folder to see the rest.".to_owned()),
    }
}

/// The tree in a card: a line over it that says how it is sorted, and the rows. A row picked is
/// the selection.
fn tree_card(dash: &Dashboard, loaded: &Loaded, store: Store, context: Context<'_>) -> Border {
    let pin = dash.selected.as_deref().filter(|_| dash.pinned);
    let all = lines(&loaded.levels, &dash.at, &dash.open, pin, dash.kind);
    let paths: Vec<Option<PathBuf>> = all
        .iter()
        .map(|line| line.path().map(Path::to_path_buf))
        .collect();
    let selected = dash
        .selected
        .as_deref()
        .and_then(|path| position(&all, path));
    // A row's key says how deep it is as well: a folder that is a location and also lies in another
    // location is two rows, and two rows must not share a key.
    let keys: Vec<String> = all
        .iter()
        .enumerate()
        .map(|(i, line)| match line {
            Line::Row(row) => format!("row:{}:{}", row.depth, row.node.path.display()),
            Line::More { .. } | Line::Cut => format!("more:{i}"),
        })
        .collect();
    // Rows that change places make a new list: moving the rows of a list with a selection makes
    // WinUI fail fast, as picking a second tile of the map did when it listed another folder first.
    let epoch = dash.tree_list(keys.clone());
    let items: Vec<DataItem> =
        all.iter()
            .zip(keys)
            .map(|(line, key)| match line {
                Line::Row(row) => DataItem::new(key, &row.node.name)
                    .content(row_view(row, dash.kind, store, context)),
                other => DataItem::new(key, "more").content(
                    caption(leftover(other).unwrap_or_default())
                        .margin(Thickness::new(INDENT, 8.0, 8.0, 8.0)),
                ),
            })
            .collect();
    let list = ListView::new()
        .selection_mode(ListViewSelectionMode::Single)
        .selected_index(selected)
        .items(items)
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            // The list reports nothing chosen while it is made again: that is not a choice.
            index
                .and_then(|i| paths.get(i).cloned().flatten())
                .map_or(Msg::Noop, |path| {
                    Msg::Dash(store, Dash::Select(path, Origin::Tree))
                })
        }));
    let list = Grid::new()
        .grid_row(1)
        .keyed_children([KeyedView::new(format!("tree-{epoch}"), list)]);
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .content(
            Grid::new()
                .rows([GridLength::Auto, GridLength::STAR])
                .children((
                    Grid::new()
                        .columns([GridLength::STAR, GridLength::Auto])
                        .margin(Thickness::new(14.0, 8.0, 16.0, 4.0))
                        .children((
                            caption("The most personal data first"),
                            caption("Found").grid_column(1),
                        )),
                    list,
                )),
        )
}

/// Whether the folder on show holds anything the dashboard could draw.
fn is_empty(dash: &Dashboard, loaded: &Loaded) -> bool {
    loaded.totals.is_empty()
        && loaded.tiles.tiles.is_empty()
        && loaded.levels.get(&dash.at).is_none_or(Vec::is_empty)
}

/// What a dashboard says while its first load has not come back.
pub(super) fn loading(space: Space) -> View {
    Grid::new()
        .height(space.height.min(240.0))
        .children((windows_reactor::ProgressRing::new()
            .is_active(true)
            .width(32.0)
            .height(32.0)
            .horizontal_alignment(windows_reactor::HorizontalAlignment::Center)
            .vertical_alignment(VerticalAlignment::Center),))
        .into()
}

/// The dashboard of `store`, laid out for `space`. When the folder on show holds nothing,
/// `nothing` says so under the way back up (it is told the folder is the top level or not).
pub(super) fn dashboard(
    window: &crate::ui::window::MainWindow,
    store: Store,
    space: Space,
    nothing: impl FnOnce(bool) -> View,
    context: Context<'_>,
) -> View {
    let dash = window.dash(store);
    let Some(loaded) = dash.loaded.as_ref() else {
        return loading(space);
    };
    let crumb_bar = crumb_bar(dash, loaded, store, context);
    if is_empty(dash, loaded) {
        return StackPanel::new()
            .spacing(GAP)
            .children((crumb_bar, nothing(dash.at.as_os_str().is_empty())))
            .into();
    }
    let plan = Plan::of(space, loaded.totals.len());
    let placed = map::place(
        &loaded.tiles,
        &dash.at,
        dash.kind,
        Rect {
            x: 0.0,
            y: 0.0,
            w: plan.canvas.0,
            h: plan.canvas.1,
        },
    );
    let selected = dash.selected.as_deref();
    let folder_selected = selected.is_some_and(|path| dash.is_folder(path));
    let map = map::map(
        &placed,
        plan.canvas,
        selected,
        folder_selected,
        store,
        context,
    );
    let tree = tree_card(dash, loaded, store, context);
    let details = details::details(dash, store, plan.details, context);
    if plan.wide {
        let side = Grid::new()
            .rows([GridLength::Pixel(plan.legend), GridLength::STAR])
            .row_spacing(GAP)
            .grid_column(2)
            .children((
                legend::list(&loaded.totals, dash.kind, plan.legend, store, context),
                details.grid_row(1),
            ));
        let main = Grid::new()
            .columns([
                GridLength::Pixel(plan.tree),
                GridLength::STAR,
                GridLength::Pixel(plan.side),
            ])
            .column_spacing(GAP)
            .height(plan.main)
            .children((tree, map.grid_column(1), side));
        return StackPanel::new()
            .spacing(GAP)
            .children((crumb_bar, main))
            .into();
    }
    let right = Grid::new()
        .rows([GridLength::Pixel(plan.map_height), GridLength::STAR])
        .row_spacing(GAP)
        .grid_column(1)
        .children((map, details.grid_row(1)));
    let main = Grid::new()
        .columns([GridLength::Pixel(plan.tree), GridLength::STAR])
        .column_spacing(GAP)
        .height(plan.main)
        .children((tree, right));
    StackPanel::new()
        .spacing(GAP)
        .children((
            crumb_bar,
            legend::strip(&loaded.totals, dash.kind, store, context),
            main,
        ))
        .into()
}

/// Whether the dashboard of `store` has been loaded and has something to show.
pub(super) fn has_data(window: &crate::ui::window::MainWindow, store: Store) -> Option<bool> {
    let dash = window.dash(store);
    let loaded = dash.loaded.as_ref()?;
    Some(!is_empty(dash, loaded))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_WINDOW: Space = Space {
        width: 772.0,
        height: 554.0,
    };
    const BIG_WINDOW: Space = Space {
        width: 1332.0,
        height: 890.0,
    };

    #[test]
    fn the_default_window_gets_the_narrow_plan_that_fits_it() {
        let plan = Plan::of(DEFAULT_WINDOW, 6);
        assert!(!plan.wide);
        // The tree and the map side by side fill the width, with a gap.
        assert!(plan.tree >= 300.0 && plan.tree <= 420.0);
        let right = DEFAULT_WINDOW.width - plan.tree - GAP;
        assert!((plan.canvas.0 - (right - MAP_CARD)).abs() < 1e-6);
        // The breadcrumb, the chips, the gaps and the main part add up to the height.
        let used = CRUMBS + legend::STRIP + 2.0 * GAP + plan.main;
        assert!((used - DEFAULT_WINDOW.height).abs() < 1e-6);
        // The map and the details share the right column.
        assert!(plan.map_height > 150.0 && plan.map_height < plan.main - 150.0);
    }

    #[test]
    fn a_wide_window_gets_three_columns_and_a_tall_map() {
        let plan = Plan::of(BIG_WINDOW, 6);
        assert!(plan.wide);
        let map_width = BIG_WINDOW.width - plan.tree - plan.side - 2.0 * GAP;
        assert!((plan.canvas.0 - (map_width - MAP_CARD)).abs() < 1e-6);
        assert!(
            plan.canvas.0 > 400.0 && plan.canvas.1 > 600.0,
            "{:?}",
            plan.canvas
        );
        assert!(plan.legend <= plan.main * 0.45 + 1e-6);
        assert!(plan.details > Plan::of(DEFAULT_WINDOW, 6).details);
    }

    #[test]
    fn the_default_window_leaves_the_dashboard_room_for_both_columns() {
        // The window opens 1040 by 760: the pane, the margins and the scroll bar come off the
        // width, the title bar, the margins and what the page keeps for itself off the height.
        let width = 1_040.0 - PANE_WIDTH - PAGE_MARGIN.0 - SCROLL_BAR;
        assert!((width - 756.0).abs() < 1e-9);
        assert!(width >= WIDE_FROM / 2.0);
    }

    #[test]
    fn a_tiny_room_still_gives_every_part_something() {
        let plan = Plan::of(
            Space {
                width: 100.0,
                height: 50.0,
            },
            3,
        );
        assert!(plan.main >= MIN_MAIN);
        assert!(plan.canvas.0 >= MIN_CANVAS.0 && plan.canvas.1 >= MIN_CANVAS.1);
    }
}
