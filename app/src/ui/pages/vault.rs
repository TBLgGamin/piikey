//! Vault: every value piikey has swapped for a stand-in, kept encrypted on this PC. The search and
//! its filters over the vault's records, Forget on each of them, and, one level down, the vault
//! file itself with its export and its wipe. The row of one swap is also what Overview lists as
//! recent.

use std::rc::Rc;

use piikey::detect::{EntityKind, KIND_GROUPS};
use windows_reactor::{
    Border, Button, ButtonStyle, Callback, ComboBox, DataItem, Expander, FontWeight, Grid,
    GridLength, HorizontalAlignment, KeyedView, ListView, ListViewSelectionMode, ProgressRing,
    StackPanel, TextBlock, TextBox, TextTrimming, Thickness, TooltipExt, VerticalAlignment, View,
};

use super::kit::{
    Context, Row, caption, counted, glyph, heading, measured, page_header, thousands,
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

/// What Forget does, as its tooltip says.
const FORGET_NOTE: &str = "Forget: its stand-in will no longer be turned back";

/// A Segoe Fluent Icons glyph for `kind`. Types of one group share a glyph.
const fn kind_glyph(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Email
        | EntityKind::PhoneNumber
        | EntityKind::ContactHandle
        | EntityKind::PostalAddress => "\u{E715}",
        EntityKind::Phone => "\u{E717}",
        EntityKind::Person
        | EntityKind::PersonAlias
        | EntityKind::PersonIdentifier
        | EntityKind::PersonAttribute
        | EntityKind::PersonRole
        | EntityKind::DateOfBirth => "\u{E77B}",
        EntityKind::Iban
        | EntityKind::CreditCard
        | EntityKind::BankAccount
        | EntityKind::PaymentCard
        | EntityKind::CardSecurity
        | EntityKind::FinancialAmount => "\u{E8C7}",
        EntityKind::NlBsn
        | EntityKind::UsSsn
        | EntityKind::DocumentId
        | EntityKind::DocumentReference
        | EntityKind::VehicleId => "\u{E779}",
        EntityKind::Ipv4
        | EntityKind::Ipv6
        | EntityKind::Mac
        | EntityKind::DeviceId
        | EntityKind::IdentifyingLink
        | EntityKind::AccountId => "\u{E968}",
        EntityKind::Secret | EntityKind::AuthSecret => "\u{E72E}",
        EntityKind::UrlCredential => "\u{E71B}",
        EntityKind::Location | EntityKind::GeoLocation => "\u{E707}",
        EntityKind::OrganizationName | EntityKind::OrganizationId | EntityKind::ProperName => {
            "\u{E821}"
        }
        EntityKind::HealthData
        | EntityKind::BiometricData
        | EntityKind::EthnicOrigin
        | EntityKind::PoliticalOpinion
        | EntityKind::ReligionOrBelief
        | EntityKind::SexualOrientation
        | EntityKind::TradeUnion
        | EntityKind::CriminalOffence => "\u{E8D7}",
    }
}

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

/// One swap: the icon of its type, the value over the stand-in that replaced it, and where and when
/// it went. With `on_forget` the row ends in a button that forgets the value.
pub(super) fn swap_row(item: &Keyed, on_forget: Option<Callback<()>>) -> View {
    let mut columns = vec![GridLength::Auto, GridLength::STAR, GridLength::Auto];
    let mut cells: Vec<View> = vec![
        glyph(kind_glyph(item.kind), 20.0)
            .width(32.0)
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
        StackPanel::new()
            .grid_column(1)
            .vertical_alignment(VerticalAlignment::Center)
            .children((
                TextBlock::new()
                    .text(&item.original)
                    .font_weight(FontWeight::SEMI_BOLD)
                    .text_trimming(TextTrimming::CharacterEllipsis),
                TextBlock::new()
                    .text(format!("\u{2192} {}", item.proxy))
                    .opacity(0.72)
                    .text_trimming(TextTrimming::CharacterEllipsis),
            ))
            .into(),
        caption(detail(item))
            .grid_column(2)
            .margin(Thickness::new(12.0, 0.0, 0.0, 0.0))
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
    ];
    if let Some(on_forget) = on_forget {
        columns.push(GridLength::Auto);
        cells.push(
            Button::new()
                .content(glyph("\u{E74D}", 14.0))
                .style(ButtonStyle::Subtle)
                .automation_name(format!("Forget {}", item.original))
                .grid_column(3)
                .vertical_alignment(VerticalAlignment::Center)
                .on_click(on_forget)
                .tooltip(FORGET_NOTE),
        );
    }
    Grid::new().columns(columns).children(cells).into()
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

/// What the list says about itself, and the list: the rows the last search found.
fn results(window: &MainWindow, context: Context<'_>) -> (String, View) {
    match &window.vault_page {
        None => (
            "Loading\u{2026}".to_owned(),
            ProgressRing::new()
                .is_active(true)
                .width(32.0)
                .height(32.0)
                .into(),
        ),
        Some(page) if page.items.is_empty() => (
            if window.snap.issued == 0 {
                "Nothing swapped yet. Every value piikey gives a stand-in is listed here."
                    .to_owned()
            } else {
                "No value matches.".to_owned()
            },
            StackPanel::new().into(),
        ),
        Some(page) => {
            let total = u64::try_from(page.matched).unwrap_or(u64::MAX);
            let count = if page.matched > page.items.len() {
                format!(
                    "Showing the {} most recent of {}. Search to narrow them down.",
                    thousands(u64::try_from(VAULT_LIMIT).unwrap_or(u64::MAX)),
                    thousands(total)
                )
            } else {
                format!("{}, most recent first", counted(total, "value", "values"))
            };
            let list = ListView::new()
                .selection_mode(ListViewSelectionMode::None)
                .items(page.items.iter().map(|item| {
                    let forget = context.message(Msg::Forget(item.original.clone()));
                    DataItem::new(item.proxy.clone(), &item.original).content(
                        Border::new()
                            .height(SWAP_ROW)
                            .content(swap_row(item, Some(forget))),
                    )
                }))
                .into();
            (count, list)
        }
    }
}

// ---- The vault file ----

/// What the armed Wipe vault button says it will do.
fn wipe_armed_text(records: u64) -> String {
    if records == 1 {
        "Click again to wipe the record".to_owned()
    } else {
        format!("Click again to wipe all {} records", thousands(records))
    }
}

/// The vault file, and what can be done with all of its records: one level down, closed until the
/// user asks. Wiping takes two clicks: the first one only changes the button.
fn manage(window: &MainWindow, context: Context<'_>) -> Expander {
    let records = window.snap.issued;
    let path = window.input.controller.vault_path().display().to_string();
    let wipe = if window.wipe_armed {
        wipe_armed_text(records)
    } else {
        "Wipe vault".to_owned()
    };
    Expander::new()
        .is_expanded(false)
        .horizontal_alignment(HorizontalAlignment::Stretch)
        .horizontal_content_alignment(HorizontalAlignment::Stretch)
        .header(
            StackPanel::new().spacing(2.0).children((
                heading("Manage"),
                caption(counted(records, "record", "records")),
            )),
        )
        .content(
            StackPanel::new().spacing(4.0).children((
                Row::new("Vault file")
                    .icon("\u{E8B7}")
                    .description(path)
                    .selectable()
                    .state(counted(records, "record", "records"))
                    .build(),
                Row::new("Export")
                    .icon("\u{E896}")
                    .description(EXPORT_NOTE)
                    .control(
                        Button::new()
                            .content("Export\u{2026}")
                            .is_enabled(records > 0)
                            .on_click(context.message(Msg::ExportVault)),
                    )
                    .build(),
                Row::new("Wipe the vault")
                    .icon("\u{E74D}")
                    .description(
                        "Removes every record, so stand-ins that were already sent can no longer be turned back into values.",
                    )
                    .control(
                        Button::new()
                            .content(wipe)
                            .style(if window.wipe_armed {
                                ButtonStyle::Accent
                            } else {
                                ButtonStyle::Default
                            })
                            .is_enabled(records > 0)
                            .on_click(context.message(Msg::WipeVault)),
                    )
                    .build(),
            )),
        )
}

pub(super) fn vault(window: &MainWindow, context: Context<'_>) -> View {
    let (count, list) = results(window, context);
    let export = Button::new()
        .content("Export\u{2026}")
        .is_enabled(window.snap.issued > 0)
        .on_click(context.message(Msg::ExportVault))
        .tooltip(EXPORT_NOTE);
    measured(
        Grid::new()
            .rows([
                GridLength::Auto,
                GridLength::Auto,
                GridLength::Auto,
                GridLength::STAR,
                GridLength::Auto,
            ])
            .row_spacing(12.0)
            .children((
                page_header(Page::Vault.title(), DEFINITION, [export]),
                search_bar(window, context).grid_row(1),
                caption(count).grid_row(2),
                Border::new().grid_row(3).content(list),
                manage(window, context).grid_row(4),
            )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_armed_wipe_button_names_how_many_records_go() {
        assert!(
            !wipe_armed_text(1).contains('1'),
            "one record needs no number"
        );
        assert!(wipe_armed_text(12_345).contains("12,345"));
    }

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
