//! Vault: every value piikey has swapped for a stand-in, kept encrypted on this PC. The search and
//! its filters over the vault's records, a check box on each row, Select all, and Forget for the
//! rows that are ticked. The row of one swap is also what Overview lists as recent.

use std::rc::Rc;

use piikey::detect::{EntityKind, KIND_GROUPS};
use windows_reactor::{
    Border, Button, CheckBox, ComboBox, ContentDialog, ContentDialogButton, ContentDialogExt,
    ContentDialogResult, DataItem, FontIcon, FontWeight, Grid, GridLength, KeyedView, ListView,
    ListViewSelectionMode, ProgressRing, StackPanel, TextBlock, TextBox, TextTrimming, Thickness,
    TooltipExt, VerticalAlignment, View,
};

use super::kit::{
    Context, caption, card, counted, glyph, kind_glyph, measured, page_header, thousands,
};
use crate::ui::{
    controller::{Keyed, Period},
    window::{MainWindow, Msg, Page, VAULT_LIMIT},
};

/// Height of a swap row: the value over its stand-in.
const SWAP_ROW: f64 = 56.0;

/// What the page is, in a sentence.
const DEFINITION: &str = "Encrypted on this PC with Windows. It remembers which stand-in replaced which value, so replies can be turned back.";

/// What Export… writes, and why to keep it safe.
const EXPORT_NOTE: &str = "Writes every value with its stand-in to a CSV file in Downloads. The file holds the values themselves: keep it safe.";

/// What Forget does, as the question before it says.
const FORGET_NOTE: &str = "Their stand-ins will no longer be turned back.";

/// `site · app · time`, or the type of a value that was never sent.
fn detail(item: &Keyed) -> String {
    item.sent.as_ref().map_or_else(
        || item.kind.label().to_owned(),
        |sent| match &sent.exe {
            Some(exe) => format!("{} \u{b7} {exe} \u{b7} {}", sent.host, sent.at),
            None => format!("{} \u{b7} {}", sent.host, sent.at),
        },
    )
}

/// The icon of the type of a value.
fn icon(item: &Keyed) -> FontIcon {
    glyph(kind_glyph(item.kind), 20.0)
        .width(32.0)
        .vertical_alignment(VerticalAlignment::Center)
}

/// The value over the stand-in that replaced it.
fn names(item: &Keyed) -> StackPanel {
    StackPanel::new()
        .vertical_alignment(VerticalAlignment::Center)
        .children((
            TextBlock::new()
                .text(&item.original)
                .font_weight(FontWeight::SEMI_BOLD)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .is_text_selection_enabled(true),
            TextBlock::new()
                .text(format!("\u{2192} {}", item.proxy))
                .opacity(0.72)
                .text_trimming(TextTrimming::CharacterEllipsis)
                .is_text_selection_enabled(true),
        ))
}

/// Where and when a value went, on the right of its row.
fn whereabouts(item: &Keyed) -> TextBlock {
    caption(detail(item))
        .margin(Thickness::new(12.0, 0.0, 0.0, 0.0))
        .vertical_alignment(VerticalAlignment::Center)
}

/// One swap as Overview lists it: the icon of its type, the value over the stand-in that replaced
/// it, and where and when it went.
pub(super) fn swap_row(item: &Keyed) -> View {
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
        .children((
            icon(item),
            names(item).grid_column(1),
            whereabouts(item).grid_column(2),
        ))
        .into()
}

/// One swap on the Vault page: a check box ahead of what [`swap_row`] shows.
fn vault_row(item: &Keyed, picked: bool, context: Context<'_>) -> View {
    let original = item.original.clone();
    Grid::new()
        .columns([
            GridLength::Auto,
            GridLength::Auto,
            GridLength::STAR,
            GridLength::Auto,
        ])
        .children((
            CheckBox::new()
                .is_checked(picked)
                .min_width(0.0)
                .width(36.0)
                .vertical_alignment(VerticalAlignment::Center)
                .automation_name(format!("Select {}", item.original))
                .on_is_checked_changed(context.callback(move |value: Option<bool>| {
                    Msg::VaultPick(original.clone(), value.unwrap_or(false))
                })),
            icon(item).grid_column(1),
            names(item).grid_column(2),
            whereabouts(item).grid_column(3),
        ))
        .into()
}

// ---- The search ----

/// The type filter: "All types", then every type of [`KIND_GROUPS`] in their order.
fn type_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    let kinds: Vec<EntityKind> = KIND_GROUPS
        .iter()
        .flat_map(|&(_, kinds)| kinds.iter().copied())
        .collect();
    ComboBox::new()
        .items_source(std::iter::once("All types").chain(kinds.iter().map(|&kind| kind.label())))
        .selected_index(Some(
            window
                .vault
                .kind
                .and_then(|kind| kinds.iter().position(|&k| k == kind))
                .map_or(0, |i| i + 1),
        ))
        .width(170.0)
        .automation_name("Type")
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::VaultKind(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| kinds.get(i).copied()),
            )
        }))
}

/// The site filter: "All sites", then every site a value went to, most recent first. The chosen
/// site stays listed even when the last search no longer returned it.
fn site_filter(window: &MainWindow, context: Context<'_>) -> Grid {
    let mut sites: Vec<String> = window
        .vault_page
        .as_ref()
        .map(|page| page.sites.clone())
        .unwrap_or_default();
    if let Some(site) = &window.vault.site
        && !sites.contains(site)
    {
        sites.insert(0, site.clone());
    }
    let selected = window
        .vault
        .site
        .as_ref()
        .and_then(|site| sites.iter().position(|s| s == site))
        .map_or(0, |i| i + 1);
    // The list of sites arrives after the page is first drawn. A new list clears the choice of
    // the combo box that held the old one, and a `selected_index` that did not change is not
    // set again, so the box would stay empty: each list gets a combo box of its own.
    let key = sites.join("\n");
    let choice = ComboBox::new()
        .items_source(std::iter::once("All sites").chain(sites.iter().map(String::as_str)))
        .selected_index(Some(selected))
        .width(190.0)
        .automation_name("Site")
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::VaultSite(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| sites.get(i).cloned()),
            )
        }));
    Grid::new().keyed_children([KeyedView::new(key, choice)])
}

/// The time filter.
fn period_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    ComboBox::new()
        .items_source(Period::ALL.iter().map(|period| period.label()))
        .selected_index(Period::ALL.iter().position(|&p| p == window.vault.period))
        .width(150.0)
        .automation_name("Time")
        .on_selection_changed(context.callback(|index: Option<usize>| {
            Msg::VaultPeriod(
                index
                    .and_then(|i| Period::ALL.get(i).copied())
                    .unwrap_or_default(),
            )
        }))
}

/// The search box with the type, site and time filters.
fn search_bar(window: &MainWindow, context: Context<'_>) -> Grid {
    Grid::new()
        .columns([
            GridLength::STAR,
            GridLength::Auto,
            GridLength::Auto,
            GridLength::Auto,
        ])
        .column_spacing(8.0)
        .children((
            TextBox::new()
                .text(&window.vault.text)
                .placeholder_text("Search values, stand-ins, sites or apps")
                .automation_name("Search the vault")
                .on_text_changed(
                    context.callback(|text: Rc<str>| Msg::VaultQuery(text.to_string())),
                ),
            type_filter(window, context).grid_column(1),
            site_filter(window, context).grid_column(2),
            period_filter(window, context).grid_column(3),
        ))
}

/// What the list says about itself.
fn count_text(window: &MainWindow) -> String {
    match &window.vault_page {
        None => "Loading\u{2026}".to_owned(),
        Some(page) if page.items.is_empty() => {
            if window.snap.issued == 0 {
                "Nothing swapped yet. Every value piikey gives a stand-in is listed here."
                    .to_owned()
            } else {
                "No value matches.".to_owned()
            }
        }
        Some(page) => {
            if page.matched > page.items.len() {
                format!(
                    "Showing the {} most recent of {}. Search to narrow them down.",
                    thousands(u64::try_from(VAULT_LIMIT).unwrap_or(u64::MAX)),
                    thousands(u64::try_from(page.matched).unwrap_or(u64::MAX))
                )
            } else {
                format!(
                    "{}, most recent first",
                    counted(
                        u64::try_from(page.matched).unwrap_or(u64::MAX),
                        "value",
                        "values"
                    )
                )
            }
        }
    }
}

/// The row between the search and the list: Select all, what the list says about itself, and at
/// its right end the button that forgets the ticked rows.
fn commands(window: &MainWindow, context: Context<'_>) -> Grid {
    let listed = window
        .vault_page
        .as_ref()
        .map_or(0, |page| page.items.len());
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((
            CheckBox::new()
                .content("Select all")
                .is_checked(listed > 0 && window.vault_picked.len() == listed)
                .is_enabled(listed > 0)
                .on_is_checked_changed(
                    context
                        .callback(|value: Option<bool>| Msg::VaultPickAll(value.unwrap_or(false))),
                ),
            caption(count_text(window))
                .grid_column(1)
                .vertical_alignment(VerticalAlignment::Center),
            forget_button(window, context)
                .grid_column(2)
                .vertical_alignment(VerticalAlignment::Center),
        ))
}

/// The rows the last search found, or a ring while it runs.
fn list(window: &MainWindow, context: Context<'_>) -> View {
    match &window.vault_page {
        None => ProgressRing::new()
            .is_active(true)
            .width(32.0)
            .height(32.0)
            .into(),
        Some(page) if page.items.is_empty() => StackPanel::new().into(),
        Some(page) => ListView::new()
            .selection_mode(ListViewSelectionMode::None)
            .items(page.items.iter().map(|item| {
                let picked = window.vault_picked.contains(&item.original);
                DataItem::new(item.proxy.clone(), &item.original).content(
                    Border::new()
                        .height(SWAP_ROW)
                        .content(vault_row(item, picked, context)),
                )
            }))
            .into(),
    }
}

/// The button that forgets the selected values; it asks first.
fn forget_button(window: &MainWindow, context: Context<'_>) -> Button {
    let picked = window.vault_picked.len();
    Button::new()
        .content(format!("Forget {picked}"))
        .is_enabled(picked > 0)
        .on_click(context.message(Msg::VaultAskForget))
}

/// The question Forget asks before it forgets.
fn forget_dialog(window: &MainWindow, context: Context<'_>) -> ContentDialog {
    let picked = u64::try_from(window.vault_picked.len()).unwrap_or(u64::MAX);
    ContentDialog::new()
        .is_open(true)
        .title(format!("Forget {}?", counted(picked, "value", "values")))
        .content(TextBlock::new().text(FORGET_NOTE))
        .primary_button_text("Forget")
        .close_button_text("Cancel")
        .default_button(ContentDialogButton::Close)
        .on_closed(context.callback(|result: ContentDialogResult| {
            Msg::VaultForget(result == ContentDialogResult::Primary)
        }))
}

pub(super) fn vault(window: &MainWindow, context: Context<'_>) -> View {
    let export = Button::new()
        .content("Export\u{2026}")
        .is_enabled(window.snap.issued > 0)
        .on_click(context.message(Msg::ExportVault))
        .tooltip(EXPORT_NOTE);
    let page = measured(
        Grid::new()
            .rows([
                GridLength::Auto,
                GridLength::Auto,
                GridLength::Auto,
                GridLength::STAR,
            ])
            .row_spacing(12.0)
            .children((
                page_header(Page::Vault.title(), DEFINITION, [export]),
                search_bar(window, context).grid_row(1),
                commands(window, context).grid_row(2),
                card(list(window, context)).grid_row(3),
            )),
    );
    if window.forget_asked {
        page.content_dialog(forget_dialog(window, context))
    } else {
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_says_where_and_when_a_value_went() {
        let sent = crate::ui::controller::Sent {
            host: "chatgpt.com".to_owned(),
            exe: Some("chrome.exe".to_owned()),
            at: "14:05".to_owned(),
        };
        let mut item = Keyed {
            kind: EntityKind::Email,
            original: "jan@acme.nl".to_owned(),
            proxy: "lotte@mail.nl".to_owned(),
            sent: Some(sent),
        };
        assert_eq!(detail(&item), "chatgpt.com \u{b7} chrome.exe \u{b7} 14:05");
        item.sent = None;
        assert_eq!(detail(&item), EntityKind::Email.label());
    }
}
