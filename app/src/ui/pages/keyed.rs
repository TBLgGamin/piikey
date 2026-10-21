//! The Keyed values page: the search and its filters over the vault's records. The row of one
//! keyed value is also what Home lists as recent activity.

use std::rc::Rc;

use piikey::detect::{EntityKind, KIND_GROUPS};
use windows_reactor::{
    Border, Button, ButtonStyle, Callback, ComboBox, DataItem, FontIcon, FontWeight, Grid,
    GridLength, KeyedView, ListView, ListViewSelectionMode, ProgressRing, StackPanel, TextBlock,
    TextBox, TextTrimming, ThemeBrush, TooltipExt, VerticalAlignment, View,
};

use super::{Context, brand, caption, thousands, title};
use crate::ui::{
    controller::{Keyed, Period},
    window::{KEYED_LIMIT, MainWindow, Msg, Page},
};

/// Height of a keyed value row: value over proxy.
const KEYED_ROW: f64 = 56.0;

/// A Segoe Fluent Icons glyph for `kind`. Kinds of one group share a glyph.
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

/// One keyed value: kind icon, the value over its stand-in, and where it went. With `on_forget`
/// the row ends in a button that forgets the value.
pub(super) fn keyed_row(item: &Keyed, dark: bool, on_forget: Option<Callback<()>>) -> View {
    let detail = item.sent.as_ref().map_or_else(
        || item.kind.label().to_owned(),
        |sent| match &sent.exe {
            Some(exe) => format!("{} · {exe} · {}", sent.host, sent.at),
            None => format!("{} · {}", sent.host, sent.at),
        },
    );
    let mut columns = vec![GridLength::Auto, GridLength::STAR, GridLength::Auto];
    let mut cells: Vec<View> = vec![
        Border::new()
            .width(32.0)
            .height(32.0)
            .corner_radius(6.0)
            .background(ThemeBrush::CardBackground)
            .border_brush(ThemeBrush::CardStroke)
            .border_thickness(1.0)
            .vertical_alignment(VerticalAlignment::Center)
            .content(
                FontIcon::new()
                    .glyph(kind_glyph(item.kind))
                    .font_size(16.0)
                    .foreground(brand(dark)),
            )
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
                    .text(format!("→ {}", item.proxy))
                    .opacity(0.72)
                    .text_trimming(TextTrimming::CharacterEllipsis),
            ))
            .into(),
        caption(detail)
            .grid_column(2)
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
    ];
    if let Some(on_forget) = on_forget {
        columns.push(GridLength::Auto);
        cells.push(
            Button::new()
                .content(FontIcon::new().glyph("\u{E74D}").font_size(14.0))
                .style(ButtonStyle::Subtle)
                .automation_name("Forget")
                .grid_column(3)
                .vertical_alignment(VerticalAlignment::Center)
                .on_click(on_forget)
                .tooltip("Forget this value"),
        );
    }
    Grid::new()
        .columns(columns)
        .column_spacing(12.0)
        .children(cells)
        .into()
}

// ---- Keyed values ----

/// The Keyed values kind filter: "All kinds", then every kind of [`KIND_GROUPS`] in their order.
fn kind_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    let kinds: Vec<EntityKind> = KIND_GROUPS
        .iter()
        .flat_map(|&(_, kinds)| kinds.iter().copied())
        .collect();
    ComboBox::new()
        .items_source(std::iter::once("All kinds").chain(kinds.iter().map(|&kind| kind.label())))
        .selected_index(Some(
            window
                .keyed
                .kind
                .and_then(|kind| kinds.iter().position(|&k| k == kind))
                .map_or(0, |i| i + 1),
        ))
        .width(170.0)
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::KeyedKind(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| kinds.get(i).copied()),
            )
        }))
}

/// The Keyed values site filter: "All sites", then every site a value went to, most recent first.
/// The chosen site stays listed even when the last search no longer returned it.
fn site_filter(window: &MainWindow, context: Context<'_>) -> Grid {
    let mut sites: Vec<String> = window
        .keyed_page
        .as_ref()
        .map(|page| page.sites.clone())
        .unwrap_or_default();
    if let Some(site) = &window.keyed.site
        && !sites.contains(site)
    {
        sites.insert(0, site.clone());
    }
    let selected = window
        .keyed
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
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::KeyedSite(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| sites.get(i).cloned()),
            )
        }));
    Grid::new().keyed_children([KeyedView::new(key, choice)])
}

/// The Keyed values time filter.
fn period_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    ComboBox::new()
        .items_source(Period::ALL.iter().map(|period| period.label()))
        .selected_index(Period::ALL.iter().position(|&p| p == window.keyed.period))
        .width(150.0)
        .on_selection_changed(context.callback(|index: Option<usize>| {
            Msg::KeyedPeriod(
                index
                    .and_then(|i| Period::ALL.get(i).copied())
                    .unwrap_or_default(),
            )
        }))
}

/// The search box with the kind, site and period filters.
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
                .text(&window.keyed.text)
                .placeholder_text("Search values, stand-ins, sites or programs")
                .on_text_changed(
                    context.callback(|text: Rc<str>| Msg::KeyedQuery(text.to_string())),
                ),
            kind_filter(window, context).grid_column(1),
            site_filter(window, context).grid_column(2),
            period_filter(window, context).grid_column(3),
        ))
}

/// What the list says about itself, and the list: the rows the last search found.
fn results(window: &MainWindow, context: Context<'_>) -> (String, View) {
    match &window.keyed_page {
        None => (
            "Loading...".to_owned(),
            ProgressRing::new()
                .is_active(true)
                .width(32.0)
                .height(32.0)
                .into(),
        ),
        Some(page) if page.items.is_empty() => (
            if window.snap.issued == 0 {
                "Nothing keyed yet.".to_owned()
            } else {
                "No keyed value matches.".to_owned()
            },
            StackPanel::new().into(),
        ),
        Some(page) => {
            let total = u64::try_from(page.matched).unwrap_or(u64::MAX);
            let count = if page.matched > page.items.len() {
                format!(
                    "Showing the {} most recent of {}. Search to narrow them down.",
                    thousands(u64::try_from(KEYED_LIMIT).unwrap_or(u64::MAX)),
                    thousands(total)
                )
            } else if page.matched == 1 {
                "1 value".to_owned()
            } else {
                format!("{} values, most recently sent first", thousands(total))
            };
            let list = ListView::new()
                .selection_mode(ListViewSelectionMode::None)
                .items(page.items.iter().map(|item| {
                    let forget = context.message(Msg::Forget(item.original.clone()));
                    DataItem::new(item.proxy.clone(), &item.original).content(
                        Border::new().height(KEYED_ROW).content(keyed_row(
                            item,
                            window.dark,
                            Some(forget),
                        )),
                    )
                }))
                .into();
            (count, list)
        }
    }
}

pub(super) fn keyed(window: &MainWindow, context: Context<'_>) -> View {
    let (count, list) = results(window, context);
    Grid::new()
        .rows([
            GridLength::Auto,
            GridLength::Auto,
            GridLength::Auto,
            GridLength::STAR,
        ])
        .row_spacing(12.0)
        .children((
            Grid::new()
                .columns([GridLength::STAR, GridLength::Auto])
                .column_spacing(12.0)
                .children((
                    StackPanel::new().spacing(4.0).children((
                        title(Page::Keyed.title()),
                        caption("Every value piikey has given a stand-in, from the vault on this PC. The stand-in is what the site saw; piikey turns it back into the value in the answers."),
                    )),
                    Button::new()
                        .content("Export…")
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Top)
                        .is_enabled(window.snap.issued > 0)
                        .on_click(context.message(Msg::ExportVault)),
                )),
            search_bar(window, context).grid_row(1),
            caption(count).grid_row(2),
            Border::new().grid_row(3).content(list),
        ))
        .into()
}
