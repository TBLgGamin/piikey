//! The Browse cloud dialog of Inventory: pick a folder of a connected account, which becomes a
//! location.
//!
//! The way around the account is the dialog's content (the account, the way up, the folders as
//! rows), because the dialog's own buttons close it: "Choose this folder" and Cancel.

use std::path::Path;

use windows_reactor::{
    Button, ButtonStyle, ComboBox, ContentDialog, ContentDialogButton, ContentDialogResult, Grid,
    GridLength, HorizontalAlignment, Orientation, ProgressRing, ScrollViewer, StackPanel,
    TextBlock, TextTrimming, TextWrapping, Thickness, TooltipExt, VerticalAlignment, View,
};

use super::{
    kit::{Context, body, caption, glyph, place_glyph, provider_icon},
    lists::shown,
};
use crate::ui::{
    assets,
    controller::AccountView,
    window::{CloudMsg, MainWindow, Msg},
};

/// How wide the content of the dialog is, in DIPs.
const WIDTH: f64 = 460.0;
/// How high the list of folders is, in DIPs: it scrolls past that.
const LIST_HEIGHT: f64 = 260.0;
/// The size of the icon of a folder, in DIPs.
const ICON: f64 = 18.0;

/// What the dialog says in a line for an account: its provider and its name.
fn account_line(view: &AccountView) -> String {
    format!(
        "{} \u{b7} {}",
        assets::provider_name(&view.account),
        view.account.label
    )
}

/// The name of a folder: its last component.
fn folder_name(folder: &Path) -> String {
    folder
        .file_name()
        .map_or_else(|| shown(folder), |name| name.to_string_lossy().into_owned())
}

/// The picker of the account, when there is more than one.
fn picker(accounts: &[AccountView], on: &str, context: Context<'_>) -> View {
    ComboBox::new()
        .items_source(accounts.iter().map(account_line))
        .selected_index(accounts.iter().position(|view| view.account.id == on))
        .horizontal_alignment(HorizontalAlignment::Stretch)
        .automation_name("Account")
        .on_selection_changed(context.callback(|index: Option<usize>| {
            index.map_or(Msg::Noop, |index| Msg::Cloud(CloudMsg::Account(index)))
        }))
        .into()
}

/// The way up and the place being looked at, as a path.
fn place(view: &AccountView, at: Option<&Path>, context: Context<'_>) -> View {
    let here = at.map_or_else(|| view.account.root(), Path::to_path_buf);
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR])
        .column_spacing(8.0)
        .children((
            Button::new()
                .style(ButtonStyle::Subtle)
                .is_enabled(at.is_some())
                .automation_name("Up")
                .vertical_alignment(VerticalAlignment::Center)
                .on_click(context.message(Msg::Cloud(CloudMsg::Up)))
                .content(glyph("\u{E74A}", 14.0))
                .tooltip("Up"),
            caption(shown(&here))
                .is_text_selection_enabled(true)
                .grid_column(1)
                .vertical_alignment(VerticalAlignment::Center)
                .text_wrapping(TextWrapping::NoWrap)
                .text_trimming(TextTrimming::CharacterEllipsis),
        ))
        .into()
}

/// One folder of the listing, a button that opens it. At the top of an account the folders are its
/// drives or sites, which carry its provider's logo; below that, they are folders.
fn folder_row(
    view: &AccountView,
    folder: &Path,
    top: bool,
    dark: bool,
    context: Context<'_>,
) -> View {
    let name = folder_name(folder);
    let icon: View = if top {
        provider_icon(view.account.provider, Some(&view.account.label), ICON, dark)
    } else {
        place_glyph(true, ICON, dark)
            .vertical_alignment(VerticalAlignment::Center)
            .into()
    };
    Button::new()
        .style(ButtonStyle::Subtle)
        .horizontal_alignment(HorizontalAlignment::Stretch)
        .horizontal_content_alignment(HorizontalAlignment::Left)
        .automation_name(format!("Open {name}"))
        .on_click(context.message(Msg::Cloud(CloudMsg::Enter(folder.to_path_buf()))))
        .content(
            Grid::new()
                .columns([GridLength::Auto, GridLength::STAR])
                .column_spacing(10.0)
                .children((
                    icon,
                    TextBlock::new()
                        .text(name)
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Center)
                        .text_trimming(TextTrimming::CharacterEllipsis),
                )),
        )
        .into()
}

/// What stands under the place: a ring while the folders come, why they did not, or the folders.
fn listing(window: &MainWindow, view: &AccountView, context: Context<'_>) -> View {
    let cloud = &window.cloud;
    match &cloud.listing {
        None => StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(10.0)
            .height(LIST_HEIGHT)
            .children((
                ProgressRing::new().is_active(true).width(16.0).height(16.0),
                caption("Loading folders\u{2026}").vertical_alignment(VerticalAlignment::Center),
            ))
            .into(),
        Some(Err(why)) => StackPanel::new()
            .spacing(10.0)
            .height(LIST_HEIGHT)
            .children((
                body(why).text_wrapping(TextWrapping::Wrap),
                Button::new()
                    .content("Try again")
                    .on_click(context.message(Msg::Cloud(CloudMsg::Retry))),
            ))
            .into(),
        Some(Ok(folders)) if folders.is_empty() => StackPanel::new()
            .height(LIST_HEIGHT)
            .children((caption("No folders here."),))
            .into(),
        Some(Ok(folders)) => {
            let top = cloud.at.is_none();
            ScrollViewer::new()
                .height(LIST_HEIGHT)
                .content(
                    StackPanel::new().spacing(2.0).children(
                        folders
                            .iter()
                            .map(|folder| folder_row(view, folder, top, window.dark, context))
                            .collect::<Vec<View>>(),
                    ),
                )
                .into()
        }
    }
}

/// The dialog on show, if the Browse cloud dialog is open: Choose this folder (off at the top of
/// the account, which is no folder) and Cancel, and the way around the account in its content. A
/// dialog closes on Escape, which counts as Cancel.
pub(super) fn dialog(window: &MainWindow, context: Context<'_>) -> Option<ContentDialog> {
    let cloud = &window.cloud;
    if !cloud.open {
        return None;
    }
    let accounts = &window.snap.accounts;
    let view = accounts
        .iter()
        .find(|view| view.account.id == cloud.account)?;
    let mut parts: Vec<View> = Vec::new();
    if accounts.len() > 1 {
        parts.push(picker(accounts, &cloud.account, context));
    } else {
        parts.push(caption(account_line(view)).into());
    }
    parts.push(place(view, cloud.at.as_deref(), context));
    parts.push(listing(window, view, context));
    Some(
        ContentDialog::new()
            .is_open(true)
            .title("Choose a cloud folder to scan")
            .content(
                StackPanel::new()
                    .width(WIDTH)
                    .spacing(10.0)
                    .margin(Thickness::new(0.0, 4.0, 0.0, 0.0))
                    .children(parts),
            )
            .primary_button_text("Choose this folder")
            .is_primary_button_enabled(cloud.at.is_some())
            .close_button_text("Cancel")
            .default_button(ContentDialogButton::Primary)
            .on_closed(
                context.callback(|result: ContentDialogResult| match result {
                    ContentDialogResult::Primary => Msg::Cloud(CloudMsg::Choose),
                    _ => Msg::Cloud(CloudMsg::Close),
                }),
            ),
    )
}
