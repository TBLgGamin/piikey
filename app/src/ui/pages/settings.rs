//! The Settings page: a tab bar, and under it the tab that was chosen. The cards that edit a list
//! (sites, programs, kinds, folders) are in [`super::lists`].

use std::rc::Rc;

use piikey::{api::http, policy::Highlight, service::default_pipe};
use windows_reactor::{
    Border, Button, ButtonStyle, ComboBox, FontIcon, FontWeight, Grid, GridLength, Image,
    InfoBarSeverity, KeyedView, Orientation, ScrollBarVisibility, ScrollViewer, SelectorBar,
    SelectorBarItem, StackPanel, Stretch, TextBlock, TextWrapping, Thickness, ToggleSwitch,
    VerticalAlignment, View,
};

use super::{
    Context, caption, card, certificate, column, counted, dismissible, heading,
    home::protection_switch,
    lists::{folders_card, kinds_card, left_out_card, programs_card, sites_card},
    thousands, title,
};
use crate::{
    proxy::PORT,
    ui::{
        assets,
        controller::Cert,
        window::{MainWindow, Msg, Page, SettingsTab},
    },
};

/// The Settings page: its title and tab bar stay where they are while the tab under them
/// scrolls.
pub(super) fn settings(window: &MainWindow, context: Context<'_>) -> View {
    let tab = window.settings_tab;
    let mut head: Vec<View> = vec![title(Page::Settings.title()).into(), tab_bar(tab, context)];
    if let Some(error) = &window.form_error {
        head.push(dismissible(
            "Not added",
            error,
            InfoBarSeverity::Warning,
            Msg::DismissForm,
            context,
        ));
    }
    let body = match tab {
        SettingsTab::General => general(window, context),
        SettingsTab::Masking => masking(window, context),
        SettingsTab::Detection => column(vec![kinds_card(window, context)]),
        SettingsTab::Inventory => inventory_tab(window, context),
        SettingsTab::Api => api_tab(window, context),
        SettingsTab::Vault => vault_tab(window, context),
        SettingsTab::About => column(vec![about_card(window)]),
    };
    Grid::new()
        .rows([GridLength::Auto, GridLength::STAR])
        .row_spacing(12.0)
        .children((
            StackPanel::new().spacing(12.0).children(head),
            // Keyed by the tab: each one opens at its top, with nothing left of the scroll
            // position or the open expanders of the last.
            Grid::new()
                .grid_row(1)
                .keyed_children([KeyedView::new(tab.label(), body)]),
        ))
        .into()
}

/// The tabs of Settings. The bar reports a pick by the text of the tab. In a window too narrow
/// for all of them it scrolls sideways, so no tab is cut off out of reach.
fn tab_bar(selected: SettingsTab, context: Context<'_>) -> View {
    let tabs = SelectorBar::new()
        .on_selected_text_changed(context.callback(|text: Option<Rc<str>>| {
            text.as_deref()
                .and_then(SettingsTab::from_label)
                .map_or(Msg::Noop, Msg::Tab)
        }))
        .keyed_items(SettingsTab::ALL.map(|tab| {
            KeyedView::new(
                tab.label(),
                SelectorBarItem::new()
                    .text(tab.label())
                    .is_selected(tab == selected),
            )
        }));
    ScrollViewer::new()
        .horizontal_scroll_bar_visibility(ScrollBarVisibility::Auto)
        .vertical_scroll_bar_visibility(ScrollBarVisibility::Disabled)
        .content(tabs)
        .into()
}

/// A card for every feature: its switch, and a link to the tab with the rest of its settings.
fn general(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    column(vec![
        setting_card(
            "\u{E72E}",
            "Mask what you send",
            "Replaces personal data in what you send to your protected sites and programs, and restores it in the answers.",
            Some(masking_link(window, context)),
            protection_switch(window, context).automation_name("Mask what you send"),
        ),
        setting_card(
            "\u{E7B3}",
            "Highlight personal data as you type",
            "Outlines the field you type in when it holds personal data, in any app. Nothing leaves your PC.",
            None,
            highlight_choice(window, context),
        ),
        setting_card(
            "\u{E8B7}",
            "Scan for PII in Explorer",
            "Adds Scan for PII to the right-click menu of files and folders (Show more options on Windows 11).",
            None,
            feature_switch(
                "Scan for PII in Explorer",
                policy.explorer_menu,
                Msg::ExplorerMenu,
                context,
            ),
        ),
        setting_card(
            "\u{E71D}",
            "PII inventory",
            "Keeps a map of which files in your folders hold personal data, scanning changed files in the background.",
            Some(flush(tab_link(
                "Inventory settings ›",
                SettingsTab::Inventory,
                context,
            ))),
            feature_switch("PII inventory", policy.inventory, Msg::Inventory, context),
        ),
        setting_card(
            "\u{E943}",
            "Local HTTP API",
            "Lets your scripts call piikey at 127.0.0.1 with a token. The CLI and the named pipe work without it.",
            Some(flush(tab_link("API settings ›", SettingsTab::Api, context))),
            feature_switch("Local HTTP API", policy.http_api, Msg::HttpApi, context),
        ),
    ])
}

/// The certificate masking needs, then the sites and programs it applies to.
fn masking(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![
        caption("Where piikey swaps your personal data for stand-ins.").into(),
        certificate(window, context),
        sites_card(window, context),
        programs_card(window, context),
    ])
}

/// What the Highlight setting offers, in the order of its list.
const HIGHLIGHTS: [(Highlight, &str); 3] = [
    (Highlight::Off, "Off"),
    (Highlight::Always, "Always"),
    (Highlight::Hotkey, "When I press Ctrl+Alt+P"),
];

/// One setting as a card: its icon, its name, what it does and, when more of it is on another
/// tab, the way there, with the control that sets it on the right.
fn setting_card(
    glyph: &str,
    name: &str,
    about: &str,
    more: Option<View>,
    control: impl Into<View>,
) -> View {
    let mut text: Vec<View> = vec![
        TextBlock::new()
            .text(name)
            .font_size(14.0)
            .font_weight(FontWeight::SEMI_BOLD)
            .text_wrapping(TextWrapping::Wrap)
            .into(),
        caption(about).into(),
    ];
    text.extend(more);
    card(
        Grid::new()
            .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
            .column_spacing(16.0)
            .children((
                FontIcon::new()
                    .glyph(glyph)
                    .font_size(20.0)
                    .vertical_alignment(VerticalAlignment::Center),
                StackPanel::new()
                    .spacing(2.0)
                    .grid_column(1)
                    .vertical_alignment(VerticalAlignment::Center)
                    .children(text),
                Border::new()
                    .grid_column(2)
                    .vertical_alignment(VerticalAlignment::Center)
                    .content(control),
            )),
    )
    .into()
}

/// How far `TextBlockButtonStyle` pads the text of a link button from its left edge, in DIPs.
const LINK_PAD: f64 = 11.0;

/// A link that opens `tab` of Settings.
fn tab_link(text: &str, tab: SettingsTab, context: Context<'_>) -> Button {
    Button::new()
        .content(text)
        .style(ButtonStyle::TextLink)
        .on_click(context.message(Msg::Tab(tab)))
}

/// `link` with its text in line with the text above it: the padding is pulled out to the left.
fn flush(link: Button) -> View {
    link.margin(Thickness::new(-LINK_PAD, 0.0, 0.0, 0.0)).into()
}

/// What goes under "Mask what you send": why its switch is off while the certificate is missing,
/// else the way to the tab with its sites and programs.
fn masking_link(window: &MainWindow, context: Context<'_>) -> View {
    if window.snap.cert == Cert::Missing {
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(6.0)
            .children((
                caption("Needs the piikey certificate first.")
                    .vertical_alignment(VerticalAlignment::Center),
                tab_link("Install it ›", SettingsTab::Masking, context),
            ))
            .into()
    } else {
        flush(tab_link(
            "Masking settings ›",
            SettingsTab::Masking,
            context,
        ))
    }
}

/// The switch of a feature of the policy; `to_message` turns the new state into the message.
fn feature_switch(
    name: &str,
    on: bool,
    to_message: impl Fn(bool) -> Msg + 'static,
    context: Context<'_>,
) -> ToggleSwitch {
    ToggleSwitch::new()
        .is_on(on)
        .on_content("On")
        .off_content("Off")
        .automation_name(name)
        .on_toggled(context.callback(to_message))
}

/// The choice of when the field in focus is outlined.
fn highlight_choice(window: &MainWindow, context: Context<'_>) -> ComboBox {
    ComboBox::new()
        .items_source(HIGHLIGHTS.iter().map(|&(_, label)| label))
        .selected_index(
            HIGHLIGHTS
                .iter()
                .position(|&(mode, _)| mode == window.snap.policy.highlight),
        )
        .width(210.0)
        .automation_name("Highlight personal data as you type")
        .on_selection_changed(context.callback(|index: Option<usize>| {
            index
                .and_then(|i| HIGHLIGHTS.get(i))
                .map_or(Msg::Noop, |&(mode, _)| Msg::Highlight(mode))
        }))
}

/// The state of the inventory with its rescan button, the folders it scans and what it leaves
/// out. Its switch is in General.
fn inventory_tab(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![
        inventory_status(window, context),
        folders_card(window, context),
        left_out_card(window, context),
    ])
}

/// Whether the inventory runs, with the button that scans its folders again now.
fn inventory_status(window: &MainWindow, context: Context<'_>) -> View {
    let on = window.snap.policy.inventory;
    let (name, about) = if on {
        (
            "PII inventory is on",
            "Looks through the folders below in the background. The files that hold personal data show up on Home.",
        )
    } else {
        (
            "PII inventory is off",
            "Switch it on in General to look through the folders below in the background.",
        )
    };
    setting_card(
        "\u{E71D}",
        name,
        about,
        (!on).then(|| flush(tab_link("General ›", SettingsTab::General, context))),
        Button::new()
            .content("Rescan now")
            .is_enabled(on)
            .on_click(context.message(Msg::RescanAll)),
    )
}

/// How scripts reach the app: the named pipe, and the HTTP address with its token. The switch of
/// the HTTP API is in General.
fn api_tab(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![pipe_card(), http_card(window, context)])
}

fn pipe_card() -> View {
    card(StackPanel::new().spacing(8.0).children((
        heading("Named pipe"),
        caption("The command line and Explorer's Scan for PII reach the app here while it runs."),
        caption(default_pipe()).is_text_selection_enabled(true),
    )))
    .into()
}

/// The HTTP address, whether it listens, and the token scripts send to it.
fn http_card(window: &MainWindow, context: Context<'_>) -> View {
    let status: View = if window.snap.http {
        caption("Listening.").into()
    } else {
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(6.0)
            .children((
                caption("Off.").vertical_alignment(VerticalAlignment::Center),
                tab_link(
                    "Switch on Local HTTP API in General ›",
                    SettingsTab::General,
                    context,
                ),
            ))
            .into()
    };
    let mut children: Vec<View> = vec![
        heading("HTTP").into(),
        caption("Scripts on this PC call this address and send the token below as an Authorization: Bearer header.").into(),
        caption(http::url(window.snap.policy.http_port))
        .is_text_selection_enabled(true)
        .into(),
        status,
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(8.0)
            .children((
                Button::new()
                    .content("Copy token")
                    .on_click(context.message(Msg::CopyToken)),
                Button::new()
                    .content("New token")
                    .on_click(context.message(Msg::RotateToken)),
            ))
            .into(),
        caption("Copy token puts the token on the clipboard. New token replaces it: scripts have to use the new one.").into(),
    ];
    if let Some(note) = window.token_note {
        children.push(caption(note).into());
    }
    card(StackPanel::new().spacing(8.0).children(children)).into()
}

/// What the armed Wipe vault button says it will do.
fn wipe_armed_text(records: u64) -> String {
    if records == 1 {
        "Click again to wipe the record".to_owned()
    } else {
        format!("Click again to wipe all {} records", thousands(records))
    }
}

/// The vault file, and what can be done with all of its records. Wiping takes two clicks: the
/// first one only changes the button.
fn vault_tab(window: &MainWindow, context: Context<'_>) -> View {
    let records = window.snap.issued;
    let (wipe, wipe_style) = if window.wipe_armed {
        (wipe_armed_text(records), ButtonStyle::Accent)
    } else {
        ("Wipe vault".to_owned(), ButtonStyle::Default)
    };
    column(vec![
        card(
            StackPanel::new().spacing(8.0).children((
                heading("Vault file"),
                caption("Every value piikey swapped for a stand-in, kept encrypted on this PC."),
                caption(window.input.controller.vault_path().display().to_string())
                    .is_text_selection_enabled(true),
                caption(counted(records, "record", "records")),
            )),
        )
        .into(),
        setting_card(
            "\u{E896}",
            "Export vault",
            "Writes every value with its stand-in to a CSV file in Downloads. The file holds the values themselves: keep it safe.",
            None,
            Button::new()
                .content("Export…")
                .is_enabled(records > 0)
                .on_click(context.message(Msg::ExportVault)),
        ),
        setting_card(
            "\u{E74D}",
            "Wipe the vault",
            "Removes every record, so stand-ins that were already sent can no longer be turned back into values.",
            None,
            Button::new()
                .content(wipe)
                .style(wipe_style)
                .is_enabled(records > 0)
                .on_click(context.message(Msg::WipeVault)),
        ),
    ])
}

fn about_card(window: &MainWindow) -> View {
    let proxy = format!(
        "127.0.0.1:{PORT}, {}",
        if window.snap.enabled {
            "listening"
        } else {
            "stopped"
        }
    );
    card(
        Grid::new()
            .columns([GridLength::Auto, GridLength::STAR])
            .column_spacing(16.0)
            .children((
                Image::new()
                    .source_svg(assets::symbol(window.dark))
                    .stretch(Stretch::Uniform)
                    .width(48.0)
                    .height(48.0)
                    .vertical_alignment(VerticalAlignment::Top),
                StackPanel::new().spacing(8.0).grid_column(1).children((
                    heading(&format!("piikey {}", env!("CARGO_PKG_VERSION"))),
                    caption(format!("Local proxy: {proxy}")),
                )),
            )),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::wipe_armed_text;

    #[test]
    fn the_armed_wipe_button_names_how_many_records_go() {
        assert!(
            !wipe_armed_text(1).contains('1'),
            "one record needs no number"
        );
        assert!(wipe_armed_text(12_345).contains("12,345"));
    }
}
