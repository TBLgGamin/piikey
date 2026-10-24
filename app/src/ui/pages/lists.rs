//! The small widgets of the pages that edit a list: a list of check boxes, a row with a Remove
//! button, a box to add an entry. Protection (sites and apps), Inventory (its locations) and
//! Settings (the types of personal data) are built from them.

use std::{path::Path, rc::Rc};

use piikey::sources;
use windows_reactor::{
    Button, ButtonStyle, CheckBox, DataItem, Grid, GridLength, ListView, ListViewSelectionMode,
    Orientation, ScrollBarVisibility, ScrollViewer, StackPanel, TextBlock, TextBox, TextTrimming,
    Thickness, ToggleSwitch, VerticalAlignment, View,
};

use super::kit::{Context, caption, card, place_glyph, provider_icon, toned_glyph};
use crate::ui::{assets, controller::AccountView, status::Tone, window::Msg};

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

/// [`add_row`] with buttons after its button: each sends its message when pressed (a Browse button
/// opens the Windows picker named by its label, the cloud one the dialog of the accounts), and
/// what is picked goes where the box's text would.
pub(super) fn add_row_with(
    placeholder: &str,
    draft: &str,
    button: &str,
    on_text: impl Fn(String) -> Msg + 'static,
    on_add: Msg,
    browse: &[(&str, Msg)],
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
    for (column, (label, message)) in (2..).zip(browse) {
        columns.push(GridLength::Auto);
        children.push(
            Button::new()
                .content(*label)
                .grid_column(column)
                .on_click(context.message(message.clone()))
                .into(),
        );
    }
    Grid::new()
        .columns(columns)
        .column_spacing(8.0)
        .children(children)
        .into()
}

/// `path` as a person reads it: a path in a cloud account as the account's name and its folders
/// (`Example cloud › Shared › contacts.csv`: its provider is told by its logo), any other as
/// Windows writes it. The inventory's own address of a cloud item is never drawn.
pub(super) fn shown(path: &Path) -> String {
    sources::display_path(path).unwrap_or_else(|| path.display().to_string())
}

/// The name of the provider of the cloud item at `path`, as the window writes it: that of the
/// connected account the path names ([`assets::provider_name`], which keeps a pretend account from
/// passing for a real provider), else the provider's own name. `None` for a path on this PC.
pub(super) fn provider_label(accounts: &[AccountView], path: &Path) -> Option<&'static str> {
    let cloud = sources::parse_virtual(path)?;
    Some(
        accounts
            .iter()
            .find(|view| {
                view.account.provider == cloud.provider
                    && view.account.label.to_lowercase() == cloud.label.to_lowercase()
            })
            .map_or_else(
                || cloud.provider.name(),
                |view| assets::provider_name(&view.account),
            ),
    )
}

/// The icon of a place: a folder in the brand colour, in the caution colour when `tone` says
/// something is wrong. A folder of a cloud account has its provider's logo instead, which is never
/// recoloured: a caution is a small warning sign beside it.
fn place_icon(path: &Path, tone: Tone, dark: bool) -> View {
    let Some(cloud) = sources::parse_virtual(path) else {
        return if tone == Tone::Caution {
            toned_glyph("\u{E8B7}", 18.0, tone, dark)
        } else {
            place_glyph(true, 18.0, dark)
        }
        .vertical_alignment(VerticalAlignment::Center)
        .into();
    };
    let logo = provider_icon(cloud.provider, Some(&cloud.label), 18.0, dark);
    if tone != Tone::Caution {
        return logo;
    }
    let parts: Vec<View> = vec![logo, toned_glyph("\u{E7BA}", 14.0, tone, dark).into()];
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(6.0)
        .vertical_alignment(VerticalAlignment::Center)
        .children(parts)
        .into()
}

/// One place a page looks through (a location of the inventory): its icon (see [`place_icon`]),
/// its path, what it is doing, its Monitor switch (`monitored` says where it stands, and `monitor`
/// turns a toggle into the message) and the button that takes it off.
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
            place_icon(path, tone, dark),
            StackPanel::new()
                .grid_column(1)
                .vertical_alignment(VerticalAlignment::Center)
                .children((
                    TextBlock::new()
                        .text(shown(path))
                        .text_trimming(TextTrimming::CharacterEllipsis)
                        .is_text_selection_enabled(true),
                    caption(state),
                )),
            ToggleSwitch::new()
                .is_on(monitored)
                .on_content("Monitoring")
                .off_content("Not monitored")
                .automation_name(format!("Monitor {}", shown(path)))
                .grid_column(2)
                .vertical_alignment(VerticalAlignment::Center)
                .on_toggled(context.callback(monitor)),
            Button::new()
                .content("Remove")
                .style(ButtonStyle::Subtle)
                .automation_name(format!("Remove {}", shown(path)))
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
