//! The small widgets of the pages that edit a list: a list of check boxes, a row with a Remove
//! button, a box to add an entry. Protection (sites and apps), Inventory (its locations) and
//! Settings (the types of personal data) are built from them.

use std::{path::Path, rc::Rc};

use windows_reactor::{
    Button, ButtonStyle, CheckBox, DataItem, Grid, GridLength, ListView, ListViewSelectionMode,
    ScrollBarVisibility, ScrollViewer, StackPanel, TextBlock, TextBox, TextTrimming, Thickness,
    ToggleSwitch, VerticalAlignment, View,
};

use super::kit::{Context, caption, card, place_glyph, toned_glyph};
use crate::ui::{
    status::Tone,
    window::{Browse, Msg},
};

/// The height of the row of a place.
const PLACE_ROW: f64 = 44.0;
/// The most rows a list of places shows without scrolling.
const PLACE_ROWS: usize = 3;
/// What a list of places takes besides its rows: the card's padding and the gap under it.
const PLACE_CARD: f64 = 34.0;

/// Height of one list row in DIPs.
pub(super) const ROW: f64 = 40.0;

/// The height of a list of `rows` rows.
pub(super) fn list_height(rows: usize) -> f64 {
    // Row counts are tiny, so saturating at `u32::MAX` never happens and the conversion is exact.
    ROW * f64::from(u32::try_from(rows).unwrap_or(u32::MAX)) + 8.0
}

/// A list of `items` that cannot be selected, `height` DIPs high.
pub(super) fn plain_list(height: f64, items: impl IntoIterator<Item = DataItem>) -> ListView {
    ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(height)
        .items(items)
}

/// A check box row of a list; `key` names the row for as long as it lives.
pub(super) fn check_row(
    key: String,
    label: &str,
    checked: bool,
    on_change: impl Fn(bool) -> Msg + 'static,
    context: Context<'_>,
) -> DataItem {
    DataItem::new(key, label).content(
        CheckBox::new()
            .is_checked(checked)
            .content(label)
            .on_is_checked_changed(
                context.callback(move |value: Option<bool>| on_change(value.unwrap_or(false))),
            ),
    )
}

/// A row with a label and a Remove button on its right.
pub(super) fn remove_row(key: String, label: &str, action: Msg, context: Context<'_>) -> DataItem {
    DataItem::new(key, label).content(
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .column_spacing(12.0)
            .children((
                TextBlock::new()
                    .text(label)
                    .text_trimming(TextTrimming::CharacterEllipsis)
                    .margin(Thickness::new(0.0, 8.0, 0.0, 0.0)),
                Button::new()
                    .content("Remove")
                    .style(ButtonStyle::Subtle)
                    .grid_column(1)
                    .automation_name(format!("Remove {label}"))
                    .on_click(context.message(action)),
            )),
    )
}

/// A text box with its button on the right: the box that adds an entry to a list.
pub(super) fn add_row(
    placeholder: &str,
    draft: &str,
    button: &str,
    on_text: impl Fn(String) -> Msg + 'static,
    on_add: Msg,
    context: Context<'_>,
) -> View {
    add_row_with(placeholder, draft, button, on_text, on_add, &[], context)
}

/// [`add_row`] with Browse buttons after its button: each opens the Windows picker named by its
/// label, and what is picked goes where the box's text would.
pub(super) fn add_row_with(
    placeholder: &str,
    draft: &str,
    button: &str,
    on_text: impl Fn(String) -> Msg + 'static,
    on_add: Msg,
    browse: &[(&str, Browse)],
    context: Context<'_>,
) -> View {
    let mut columns = vec![GridLength::STAR, GridLength::Auto];
    let mut children: Vec<View> = vec![
        TextBox::new()
            .text(draft)
            .placeholder_text(placeholder)
            .automation_name(placeholder)
            .on_text_changed(context.callback(move |text: Rc<str>| on_text(text.to_string())))
            .into(),
        Button::new()
            .content(button)
            .grid_column(1)
            .is_enabled(!draft.trim().is_empty())
            .on_click(context.message(on_add))
            .into(),
    ];
    for (column, &(label, kind)) in (2..).zip(browse) {
        columns.push(GridLength::Auto);
        children.push(
            Button::new()
                .content(label)
                .grid_column(column)
                .on_click(context.message(Msg::Browse(kind)))
                .into(),
        );
    }
    Grid::new()
        .columns(columns)
        .column_spacing(8.0)
        .children(children)
        .into()
}

/// One place a page looks through (a location of the inventory): its folder icon in the brand
/// colour (in the caution colour when `tone` says something is wrong), its path, what it is doing,
/// its Monitor switch (`monitored` says where it stands, and `monitor` turns a toggle into the
/// message) and the button that takes it off.
#[expect(
    clippy::too_many_arguments,
    reason = "each part of the row is its own input: what it says, its switch and its button"
)]
pub(super) fn place_row(
    path: &Path,
    state: &str,
    tone: Tone,
    dark: bool,
    monitored: bool,
    monitor: impl Fn(bool) -> Msg + 'static,
    remove: Msg,
    context: Context<'_>,
) -> View {
    Grid::new()
        .columns([
            GridLength::Auto,
            GridLength::STAR,
            GridLength::Auto,
            GridLength::Auto,
        ])
        .column_spacing(12.0)
        .height(PLACE_ROW)
        .children((
            if tone == Tone::Caution {
                toned_glyph("\u{E8B7}", 18.0, tone, dark)
            } else {
                place_glyph(true, 18.0, dark)
            }
            .vertical_alignment(VerticalAlignment::Center),
            StackPanel::new()
                .grid_column(1)
                .vertical_alignment(VerticalAlignment::Center)
                .children((
                    TextBlock::new()
                        .text(path.display().to_string())
                        .text_trimming(TextTrimming::CharacterEllipsis)
                        .is_text_selection_enabled(true),
                    caption(state),
                )),
            ToggleSwitch::new()
                .is_on(monitored)
                .on_content("Monitoring")
                .off_content("Not monitored")
                .automation_name(format!("Monitor {}", path.display()))
                .grid_column(2)
                .vertical_alignment(VerticalAlignment::Center)
                .on_toggled(context.callback(monitor)),
            Button::new()
                .content("Remove")
                .style(ButtonStyle::Subtle)
                .automation_name(format!("Remove {}", path.display()))
                .grid_column(3)
                .vertical_alignment(VerticalAlignment::Center)
                .on_click(context.message(remove)),
        ))
        .into()
}

/// The rows of places in a card that scrolls past [`PLACE_ROWS`], so the card never grows past
/// them. With more rows, half of the next one shows under them, and the scroll bar is in view: the
/// list says it goes on (an idle scroll bar hides until the pointer comes near). Also how
/// much height the card and the gap under it take, for the page to leave room for.
pub(super) fn places_card(rows: Vec<View>) -> (View, f64) {
    let more = rows.len() > PLACE_ROWS;
    let bar = if more {
        ScrollBarVisibility::Visible
    } else {
        ScrollBarVisibility::Auto
    };
    // Row counts are tiny: the conversion is exact.
    let shown = f64::from(u32::try_from(rows.len().min(PLACE_ROWS)).unwrap_or(u32::MAX));
    let height = PLACE_ROW * if more { shown + 0.5 } else { shown };
    (
        card(
            ScrollViewer::new()
                .height(height)
                .vertical_scroll_bar_visibility(bar)
                .content(
                    StackPanel::new()
                        .margin(Thickness::new(0.0, 0.0, 16.0, 0.0))
                        .children(rows),
                ),
        )
        .into(),
        height + PLACE_CARD,
    )
}
