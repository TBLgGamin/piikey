//! The small widgets of the pages that edit a list: a list of check boxes, a row with a Remove
//! button, a box to add an entry. Protection (sites and apps), Inventory (its locations), Watch
//! (its folders) and Settings (the types of personal data) are built from them.

use std::rc::Rc;

use windows_reactor::{
    Button, ButtonStyle, CheckBox, DataItem, Grid, GridLength, ListView, ListViewSelectionMode,
    TextBlock, TextBox, TextTrimming, Thickness, View,
};

use super::kit::Context;
use crate::ui::window::Msg;

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
    Grid::new()
        .columns([GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((
            TextBox::new()
                .text(draft)
                .placeholder_text(placeholder)
                .automation_name(placeholder)
                .on_text_changed(context.callback(move |text: Rc<str>| on_text(text.to_string()))),
            Button::new()
                .content(button)
                .grid_column(1)
                .is_enabled(!draft.trim().is_empty())
                .on_click(context.message(on_add)),
        ))
        .into()
}
