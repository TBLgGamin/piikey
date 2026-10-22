//! The legend of a dashboard: the types of personal data found, each with its colour and its total.
//! Picking a type shows only that type in the map and the tree; picking it again, or "All types",
//! shows everything. The narrow dashboard has one row of chips, the wide one a list.

use piikey::{detect::EntityKind, inventory::TypeTotal};
use windows_reactor::{
    Border, Button, ButtonStyle, DataItem, Grid, GridLength, KeyedView, ListView,
    ListViewSelectionMode, Orientation, ScrollBarVisibility, ScrollViewer, StackPanel, TextBlock,
    TextTrimming, ThemeBrush, Thickness, VerticalAlignment, View,
};

use super::palette::swatch;
use crate::ui::{
    controller::Store,
    pages::kit::{Context, counted, thousands},
    window::{Dash, Msg},
};

/// The height of a row of chips, ring included.
pub(super) const STRIP: f64 = 40.0;

/// What every type adds up to.
fn all_hits(totals: &[TypeTotal]) -> u64 {
    totals.iter().map(|total| total.hits).sum()
}

/// A chip: the swatch of a type (none for "All types"), its name and its total. The chip of the
/// type on show has a ring; a click on it shows every type again.
fn chip(
    kind: Option<EntityKind>,
    name: &str,
    hits: u64,
    active: bool,
    store: Store,
    context: Context<'_>,
) -> View {
    let mut parts: Vec<View> = Vec::new();
    parts.extend(kind.map(|kind| View::from(swatch(kind))));
    parts.push(
        TextBlock::new()
            .text(name)
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
    );
    parts.push(
        TextBlock::new()
            .text(thousands(hits))
            .opacity(0.72)
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
    );
    // A chip of the type on show asks for every type; any other asks for its own.
    let asks = if active { None } else { kind };
    Border::new()
        .border_brush(if active {
            ThemeBrush::Accent
        } else {
            ThemeBrush::CardStroke
        })
        .border_thickness(if active { 2.0 } else { 1.0 })
        .corner_radius(6.0)
        .content(
            Button::new()
                .style(ButtonStyle::Subtle)
                .automation_name(format!("{name}, {}", thousands(hits)))
                .on_click(context.message(Msg::Dash(store, Dash::Type(asks))))
                .content(
                    StackPanel::new()
                        .orientation(Orientation::Horizontal)
                        .spacing(8.0)
                        .children(parts),
                ),
        )
        .into()
}

/// One row of chips, one chip for each type found and the one for all of them first; it scrolls
/// sideways when they do not fit.
pub(super) fn strip(
    totals: &[TypeTotal],
    shown: Option<EntityKind>,
    store: Store,
    context: Context<'_>,
) -> View {
    let mut chips: Vec<View> = vec![chip(
        None,
        "All types",
        all_hits(totals),
        shown.is_none(),
        store,
        context,
    )];
    chips.extend(totals.iter().map(|total| {
        chip(
            Some(total.kind),
            total.kind.label(),
            total.hits,
            shown == Some(total.kind),
            store,
            context,
        )
    }));
    ScrollViewer::new()
        .horizontal_scroll_bar_visibility(ScrollBarVisibility::Auto)
        .vertical_scroll_bar_visibility(ScrollBarVisibility::Disabled)
        .height(STRIP)
        .content(
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .spacing(6.0)
                .margin(Thickness::new(0.0, 2.0, 0.0, 2.0))
                .children(chips),
        )
        .into()
}

/// How tall the list is for `types` types: a row for each, the one for all of them, and the room
/// around, no more than `most`.
pub(super) fn list_height(types: usize, most: f64) -> f64 {
    // Row counts are tiny: the conversion is exact.
    let rows = f64::from(u32::try_from(types + 1).unwrap_or(u32::MAX));
    (rows * 40.0 + 8.0).min(most)
}

/// The row of one type, or of all of them: the swatch, the name, the total and the files.
fn row(kind: Option<EntityKind>, name: &str, hits: u64, files: Option<u32>) -> View {
    let mut cells: Vec<View> = Vec::new();
    cells.extend(kind.map(|kind| View::from(swatch(kind).grid_column(0))));
    cells.push(
        TextBlock::new()
            .text(name)
            .text_trimming(TextTrimming::CharacterEllipsis)
            .vertical_alignment(VerticalAlignment::Center)
            .grid_column(1)
            .into(),
    );
    cells.push(
        TextBlock::new()
            .text(thousands(hits))
            .font_weight(windows_reactor::FontWeight::SEMI_BOLD)
            .vertical_alignment(VerticalAlignment::Center)
            .grid_column(2)
            .into(),
    );
    cells.extend(files.map(|files| {
        View::from(
            TextBlock::new()
                .text(counted(u64::from(files), "file", "files"))
                .opacity(0.72)
                .vertical_alignment(VerticalAlignment::Center)
                .grid_column(3),
        )
    }));
    Grid::new()
        .columns([
            GridLength::Pixel(14.0),
            GridLength::STAR,
            GridLength::Auto,
            GridLength::Auto,
        ])
        .column_spacing(10.0)
        .children(cells)
        .into()
}

/// The wide dashboard's legend: "All types", then a row for each type found. The row picked is the
/// type on show.
pub(super) fn list(
    totals: &[TypeTotal],
    shown: Option<EntityKind>,
    height: f64,
    store: Store,
    context: Context<'_>,
) -> Border {
    let kinds: Vec<EntityKind> = totals.iter().map(|total| total.kind).collect();
    // Types that change places make a new list: moving the rows of a list with a selection makes
    // WinUI fail fast.
    let names: Vec<&str> = totals.iter().map(|total| total.kind.as_str()).collect();
    let selected = shown
        .and_then(|kind| kinds.iter().position(|&of| of == kind))
        .map_or(0, |i| i + 1);
    let mut items = vec![DataItem::new("all", "All types").content(row(
        None,
        "All types",
        all_hits(totals),
        None,
    ))];
    items.extend(totals.iter().map(|total| {
        DataItem::new(format!("type:{}", total.kind.as_str()), total.kind.label()).content(row(
            Some(total.kind),
            total.kind.label(),
            total.hits,
            Some(total.files),
        ))
    }));
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .height(height)
        .content(
            Grid::new().keyed_children([KeyedView::new(
                format!("types-{}", names.join(",")),
                ListView::new()
                    .selection_mode(ListViewSelectionMode::Single)
                    .selected_index(Some(selected))
                    .items(items)
                    .on_selection_changed(context.callback(move |index: Option<usize>| {
                        // A list that is made again reports nothing chosen for a moment: that is
                        // not a choice.
                        index.map_or(Msg::Noop, |i| {
                            Msg::Dash(
                                store,
                                Dash::Type(i.checked_sub(1).and_then(|k| kinds.get(k).copied())),
                            )
                        })
                    })),
            )]),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_as_tall_as_its_rows_up_to_the_most_it_may_take() {
        assert!((list_height(0, 500.0) - 48.0).abs() < 1e-9);
        assert!((list_height(3, 500.0) - 168.0).abs() < 1e-9);
        assert!((list_height(30, 300.0) - 300.0).abs() < 1e-9);
    }

    #[test]
    fn all_types_add_up_every_total() {
        let totals = [
            TypeTotal {
                kind: EntityKind::Email,
                hits: 5,
                files: 2,
            },
            TypeTotal {
                kind: EntityKind::Person,
                hits: 3,
                files: 1,
            },
        ];
        assert_eq!(all_hits(&totals), 8);
        assert_eq!(all_hits(&[]), 0);
    }
}
