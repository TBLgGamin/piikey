//! The three pages of the window: Home, Keyed values and Settings.
//!
//! Text, cards, lists and controls take their colours from the theme, so they follow light or dark
//! mode and the accent colour. Only the brand parts use the piikey colours: the logo and the
//! charts, purple `#6f49b1` in light mode and lilac `#d6c9f9` in dark mode, as the logo kit
//! (`assets/brand/piikey-logo-kit`) prescribes.

use std::rc::Rc;

use piikey::detect::EntityKind;
use windows_reactor::{
    Border, Button, ButtonStyle, CheckBox, Color, ComboBox, DataItem, Expander, FontIcon,
    FontWeight, Grid, GridLength, HorizontalAlignment, HyperlinkButton, Image, InfoBar,
    InfoBarSeverity, ListView, ListViewSelectionMode, Orientation, ProgressBar, ProgressRing,
    RichText, RichTextBlock, RichTextInline, RichTextRun, ScrollViewer, StackPanel, Stretch,
    TextBlock, TextBox, TextTrimming, TextWrapping, ThemeBrush, Thickness, ToggleSwitch,
    VerticalAlignment, View, ViewContext,
};

use super::{
    assets,
    controller::{Busy, CHART_DAYS, Cert, Keyed, Model, Period, RECENT, Severity, Snapshot},
    stats::{self, Day},
    window::{KEYED_LIMIT, MainWindow, Msg, Page},
};
use crate::{policy::PRESETS, proxy::PORT};

/// Height of one list row in DIPs.
const ROW: f64 = 40.0;
/// Height of a keyed value row: value over proxy.
const KEYED_ROW: f64 = 56.0;
/// Height of the tallest bar of the day chart.
const CHART_HEIGHT: f64 = 120.0;

/// The entity kinds grouped for the UI, in display order. This is the single source of the Keyed
/// values filter and of the Settings toggles; every kind appears in exactly one group.
pub const KIND_GROUPS: [(&str, &[EntityKind]); 9] = [
    (
        "People",
        &[
            EntityKind::Person,
            EntityKind::PersonAlias,
            EntityKind::PersonIdentifier,
            EntityKind::PersonAttribute,
            EntityKind::PersonRole,
            EntityKind::DateOfBirth,
        ],
    ),
    (
        "Contact",
        &[
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::PhoneNumber,
            EntityKind::ContactHandle,
            EntityKind::PostalAddress,
        ],
    ),
    ("Places", &[EntityKind::Location, EntityKind::GeoLocation]),
    (
        "Money",
        &[
            EntityKind::Iban,
            EntityKind::BankAccount,
            EntityKind::CreditCard,
            EntityKind::PaymentCard,
            EntityKind::CardSecurity,
            EntityKind::FinancialAmount,
        ],
    ),
    (
        "IDs and documents",
        &[
            EntityKind::UsSsn,
            EntityKind::NlBsn,
            EntityKind::DocumentId,
            EntityKind::DocumentReference,
            EntityKind::VehicleId,
        ],
    ),
    (
        "Online and devices",
        &[
            EntityKind::Ipv4,
            EntityKind::Ipv6,
            EntityKind::Mac,
            EntityKind::DeviceId,
            EntityKind::IdentifyingLink,
            EntityKind::AccountId,
        ],
    ),
    (
        "Secrets",
        &[
            EntityKind::Secret,
            EntityKind::UrlCredential,
            EntityKind::AuthSecret,
        ],
    ),
    (
        "Organizations",
        &[
            EntityKind::OrganizationName,
            EntityKind::OrganizationId,
            EntityKind::ProperName,
        ],
    ),
    // The GDPR special categories of personal data.
    (
        "Sensitive",
        &[
            EntityKind::HealthData,
            EntityKind::BiometricData,
            EntityKind::EthnicOrigin,
            EntityKind::PoliticalOpinion,
            EntityKind::ReligionOrBelief,
            EntityKind::SexualOrientation,
            EntityKind::TradeUnion,
            EntityKind::CriminalOffence,
        ],
    ),
];

type Context<'a> = &'a ViewContext<'a, MainWindow>;

/// The page the navigation selected, under the notice the controller may have raised.
pub fn page(window: &MainWindow, context: Context<'_>) -> View {
    let body = match window.page {
        Page::Home => home(window, context),
        Page::Keyed => keyed(window, context),
        Page::Settings => settings(window, context),
    };
    let notices: Vec<View> = notice(&window.snap, context).into_iter().collect();
    Grid::new()
        .rows([GridLength::Auto, GridLength::STAR])
        .margin(Thickness::new(24.0, 8.0, 24.0, 16.0))
        .row_spacing(12.0)
        .children((
            StackPanel::new().grid_row(0).children(notices),
            Border::new().grid_row(1).content(body),
        ))
        .into()
}

/// The brand colour for the theme.
const fn brand(dark: bool) -> Color {
    if dark {
        Color::rgb(0xd6, 0xc9, 0xf9)
    } else {
        Color::rgb(0x6f, 0x49, 0xb1)
    }
}

fn title(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(28.0)
        .font_weight(FontWeight::SEMI_BOLD)
}

fn heading(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(18.0)
        .font_weight(FontWeight::SEMI_BOLD)
}

/// Secondary text: the theme's text color, dimmed.
fn caption(text: impl AsRef<str>) -> TextBlock {
    TextBlock::new()
        .text(text)
        .text_wrapping(TextWrapping::Wrap)
        .opacity(0.72)
}

fn card(content: impl Into<View>) -> Border {
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .padding(16.0)
        .content(content)
}

/// A scrolling column of sections, with room for the scroll bar.
fn column(children: Vec<View>) -> View {
    ScrollViewer::new()
        .content(
            StackPanel::new()
                .spacing(12.0)
                .margin(Thickness::new(0.0, 0.0, 16.0, 0.0))
                .children(children),
        )
        .into()
}

fn info(title: &str, message: impl AsRef<str>, severity: InfoBarSeverity) -> InfoBar {
    InfoBar::new()
        .title(title)
        .message(message)
        .severity(severity)
        .is_open(true)
        .is_closable(false)
}

/// What the controller wants the user to read: a warning or an error, until closed.
fn notice(snap: &Snapshot, context: Context<'_>) -> Option<View> {
    let notice = snap.notice.as_ref()?;
    let (title, severity) = match notice.severity {
        Severity::Warning => ("Heads up", InfoBarSeverity::Warning),
        Severity::Error => ("Something went wrong", InfoBarSeverity::Error),
    };
    Some(
        InfoBar::new()
            .title(title)
            .message(&notice.text)
            .severity(severity)
            .is_open(true)
            .is_closable(true)
            .on_closed(context.message(Msg::DismissNotice))
            .into(),
    )
}

fn busy_text(busy: Busy) -> &'static str {
    match busy {
        Busy::Starting => "Starting piikey...",
        Busy::Stopping => "Stopping piikey...",
        Busy::InstallingCertificate => "Waiting for Windows to add the certificate...",
    }
}

/// `12,345`.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `value / max` as a fraction of `length`; a value above zero gets at least a sliver.
fn scaled(value: u64, max: u64, length: f64) -> f64 {
    if value == 0 || max == 0 {
        return 0.0;
    }
    // Chart proportions: a few significant digits are all a bar can show.
    #[allow(clippy::cast_precision_loss)]
    let fraction = value as f64 / max as f64;
    (fraction * length).max(2.0)
}

fn grid_index(i: usize) -> i32 {
    i32::try_from(i).unwrap_or(i32::MAX)
}

pub fn kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Email => "Email",
        EntityKind::Phone => "Phone",
        EntityKind::Person => "Name",
        EntityKind::Iban => "IBAN",
        EntityKind::CreditCard => "Card number",
        EntityKind::NlBsn => "BSN",
        EntityKind::UsSsn => "SSN",
        EntityKind::Ipv4 => "IPv4 address",
        EntityKind::Ipv6 => "IPv6 address",
        EntityKind::Mac => "MAC address",
        EntityKind::Secret => "Secret",
        EntityKind::UrlCredential => "URL password",
        EntityKind::PersonAlias => "Alias or nickname",
        EntityKind::PersonIdentifier => "Personal ID number",
        EntityKind::PersonAttribute => "Personal trait",
        EntityKind::PersonRole => "Role or title",
        EntityKind::DateOfBirth => "Date of birth",
        EntityKind::PhoneNumber => "Other phone number",
        EntityKind::ContactHandle => "Social handle",
        EntityKind::PostalAddress => "Postal address",
        EntityKind::Location => "Place",
        EntityKind::GeoLocation => "Coordinates",
        EntityKind::DeviceId => "Device ID",
        EntityKind::IdentifyingLink => "Personal link",
        EntityKind::AccountId => "Account ID",
        EntityKind::AuthSecret => "Password",
        EntityKind::BankAccount => "Other bank account",
        EntityKind::PaymentCard => "Other card number",
        EntityKind::CardSecurity => "Card security code",
        EntityKind::FinancialAmount => "Amount of money",
        EntityKind::DocumentId => "Document number",
        EntityKind::DocumentReference => "Document reference",
        EntityKind::VehicleId => "Licence plate or VIN",
        EntityKind::OrganizationName => "Organization",
        EntityKind::OrganizationId => "Company number",
        EntityKind::ProperName => "Other proper name",
        EntityKind::HealthData => "Health",
        EntityKind::BiometricData => "Biometric data",
        EntityKind::EthnicOrigin => "Ethnic origin",
        EntityKind::PoliticalOpinion => "Political opinion",
        EntityKind::ReligionOrBelief => "Religion or belief",
        EntityKind::SexualOrientation => "Sexual orientation",
        EntityKind::TradeUnion => "Trade union",
        EntityKind::CriminalOffence => "Criminal record",
    }
}

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

// ---- Home ----

fn home(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut children: Vec<View> = vec![brand_header(window.dark), switch_card(window, context)];
    if snap.cert != Cert::Installed {
        children.push(certificate(window, context));
    }
    children.push(numbers(snap));
    children.push(charts(snap, window.dark));
    children.push(recent(window, context));
    column(children)
}

/// The logo lockup, which already reads "piikey".
fn brand_header(dark: bool) -> View {
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(12.0)
        .children((Image::new()
            .source_svg(assets::lockup(dark))
            .stretch(Stretch::Uniform)
            .height(36.0),))
        .into()
}

/// The on/off switch and what it means right now.
fn switch_card(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let on = window.desired.unwrap_or(snap.enabled);
    let working = snap.busy.is_some() || snap.pending > 0;
    let protected = snap.policy.sites.len() + snap.policy.programs.len();
    let (state, summary) = match snap.busy {
        Some(busy) => ("Working", busy_text(busy).to_owned()),
        None if on => (
            "Protection is on",
            format!(
                "Personal data sent to your {protected} protected sites and programs is replaced by stand-ins, and put back in the answers."
            ),
        ),
        None => (
            "Protection is off",
            "Nothing is read or changed, and your Windows proxy settings are your own.".to_owned(),
        ),
    };
    let last = snap.last_activity.as_ref().map_or_else(
        || "No traffic yet this session.".to_owned(),
        |activity| format!("Last activity: {} at {}", activity.host, activity.at),
    );
    card(
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .column_spacing(16.0)
            .children((
                StackPanel::new().spacing(4.0).children((
                    heading(state),
                    caption(summary),
                    caption(last),
                )),
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(12.0)
                    .grid_column(1)
                    .vertical_alignment(VerticalAlignment::Center)
                    .children((
                        ProgressRing::new()
                            .is_active(working)
                            .width(20.0)
                            .height(20.0),
                        ToggleSwitch::new()
                            .is_on(on)
                            .is_enabled(!working && snap.cert == Cert::Installed)
                            .on_content("On")
                            .off_content("Off")
                            .on_toggled(context.callback(Msg::Toggle)),
                    )),
            )),
    )
    .into()
}

/// One key number: big value over its label.
fn number(value: String, label: &str, column: usize) -> View {
    card(
        StackPanel::new().spacing(2.0).children((
            TextBlock::new()
                .text(value)
                .font_size(28.0)
                .font_weight(FontWeight::SEMI_BOLD),
            caption(label),
        )),
    )
    .grid_column(grid_index(column))
    .into()
}

fn numbers(snap: &Snapshot) -> View {
    let today = snap.days.last().copied().unwrap_or(Day {
        index: stats::today(),
        masked: 0,
        restored: 0,
    });
    let protected = snap.policy.sites.len() + snap.policy.programs.len();
    Grid::new()
        .columns([GridLength::STAR; 4])
        .column_spacing(12.0)
        .children(vec![
            number(thousands(snap.issued), "values keyed, all time", 0),
            number(thousands(today.masked), "masked today", 1),
            number(thousands(today.restored), "restored today", 2),
            number(
                thousands(u64::try_from(protected).unwrap_or(u64::MAX)),
                "sites and programs protected",
                3,
            ),
        ])
        .into()
}

fn charts(snap: &Snapshot, dark: bool) -> View {
    Grid::new()
        .columns([GridLength::Star(3.0), GridLength::Star(2.0)])
        .column_spacing(12.0)
        .children((
            card(day_chart(&snap.days, dark)),
            card(kind_chart(&snap.kinds, dark)).grid_column(1),
        ))
        .into()
}

/// A small legend swatch and its label.
fn legend(label: &str, dark: bool, opacity: f64) -> View {
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(6.0)
        .children((
            Border::new()
                .width(10.0)
                .height(10.0)
                .corner_radius(2.0)
                .background(brand(dark))
                .opacity(opacity)
                .vertical_alignment(VerticalAlignment::Center),
            caption(label),
        ))
        .into()
}

/// Masked and restored per day, side by side, oldest left.
fn day_chart(days: &[Day], dark: bool) -> View {
    const RESTORED_OPACITY: f64 = 0.4;
    let max = days
        .iter()
        .map(|day| day.masked.max(day.restored))
        .max()
        .unwrap_or(0);
    let bar = |value: u64, opacity: f64| -> View {
        Border::new()
            .width(7.0)
            .height(scaled(value, max, CHART_HEIGHT))
            .corner_radius(2.0)
            .background(brand(dark))
            .opacity(opacity)
            .vertical_alignment(VerticalAlignment::Bottom)
            .into()
    };
    let columns: Vec<View> = days
        .iter()
        .enumerate()
        .map(|(i, day)| {
            Grid::new()
                .rows([GridLength::Pixel(CHART_HEIGHT), GridLength::Auto])
                .row_spacing(4.0)
                .grid_column(grid_index(i))
                .children((
                    StackPanel::new()
                        .orientation(Orientation::Horizontal)
                        .spacing(2.0)
                        .horizontal_alignment(HorizontalAlignment::Center)
                        .vertical_alignment(VerticalAlignment::Bottom)
                        .children((bar(day.masked, 1.0), bar(day.restored, RESTORED_OPACITY))),
                    TextBlock::new()
                        .text(stats::day_of_month(day.index).to_string())
                        .font_size(11.0)
                        .opacity(0.6)
                        .horizontal_alignment(HorizontalAlignment::Center)
                        .grid_row(1),
                ))
                .into()
        })
        .collect();
    let peak = if max == 0 {
        "No traffic in this period yet.".to_owned()
    } else {
        format!("Busiest day: {}", thousands(max))
    };
    StackPanel::new()
        .spacing(12.0)
        .children((
            Grid::new()
                .columns([GridLength::STAR, GridLength::Auto])
                .children((
                    heading(&format!("Last {CHART_DAYS} days")),
                    StackPanel::new()
                        .orientation(Orientation::Horizontal)
                        .spacing(12.0)
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Center)
                        .children((
                            legend("Masked", dark, 1.0),
                            legend("Restored", dark, RESTORED_OPACITY),
                        )),
                )),
            Grid::new()
                .columns(days.iter().map(|_| GridLength::STAR))
                .children(columns),
            caption(peak),
        ))
        .into()
}

/// Keyed values per kind, as horizontal bars.
fn kind_chart(kinds: &[(EntityKind, usize)], dark: bool) -> View {
    const SHOWN: usize = 6;
    let max = kinds.first().map_or(0, |(_, count)| *count);
    let mut rows: Vec<View> = vec![heading("By kind").into()];
    if kinds.is_empty() {
        rows.push(caption("Nothing keyed yet.").into());
    }
    for &(kind, count) in kinds.iter().take(SHOWN) {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        let max = u64::try_from(max).unwrap_or(u64::MAX);
        // Star weights split the track: the filled part, then the rest.
        #[allow(clippy::cast_precision_loss)]
        let (filled, rest) = (count as f64, max.saturating_sub(count) as f64);
        rows.push(
            Grid::new()
                .columns([
                    GridLength::Pixel(96.0),
                    GridLength::STAR,
                    GridLength::Pixel(56.0),
                ])
                .column_spacing(8.0)
                .children((
                    TextBlock::new()
                        .text(kind_label(kind))
                        .text_trimming(TextTrimming::CharacterEllipsis),
                    Border::new()
                        .grid_column(1)
                        .height(10.0)
                        .corner_radius(5.0)
                        .background(ThemeBrush::CardStroke)
                        .vertical_alignment(VerticalAlignment::Center)
                        .content(
                            Grid::new()
                                .columns([GridLength::Star(filled), GridLength::Star(rest)])
                                .children((Border::new()
                                    .corner_radius(5.0)
                                    .background(brand(dark)),)),
                        ),
                    TextBlock::new()
                        .text(thousands(count))
                        .opacity(0.72)
                        .horizontal_alignment(HorizontalAlignment::Right)
                        .grid_column(2),
                ))
                .into(),
        );
    }
    if kinds.len() > SHOWN {
        let others: usize = kinds.iter().skip(SHOWN).map(|(_, count)| count).sum();
        rows.push(
            caption(format!(
                "and {} more of other kinds",
                thousands(u64::try_from(others).unwrap_or(u64::MAX))
            ))
            .into(),
        );
    }
    StackPanel::new().spacing(10.0).children(rows).into()
}

/// One keyed value: kind icon, the value over its stand-in, and where it went.
fn keyed_row(item: &Keyed, dark: bool) -> View {
    let detail = item.sent.as_ref().map_or_else(
        || kind_label(item.kind).to_owned(),
        |sent| match &sent.exe {
            Some(exe) => format!("{} · {exe} · {}", sent.host, sent.at),
            None => format!("{} · {}", sent.host, sent.at),
        },
    );
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
        .column_spacing(12.0)
        .children((
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
                ),
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
                )),
            caption(detail)
                .grid_column(2)
                .vertical_alignment(VerticalAlignment::Center),
        ))
        .into()
}

/// The most recently sent values, with the way to all of them.
fn recent(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut rows: Vec<View> = vec![
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .children((
                heading("Recent activity"),
                HyperlinkButton::new()
                    .content("View all")
                    .grid_column(1)
                    .is_enabled(snap.issued > 0)
                    .on_click(context.message(Msg::Nav(Page::Keyed))),
            ))
            .into(),
    ];
    if snap.recent.is_empty() {
        rows.push(
            caption("Nothing yet. Turn protection on and use one of your sites: every value that gets a stand-in shows up here.")
                .into(),
        );
    }
    rows.extend(
        snap.recent
            .iter()
            .take(RECENT)
            .map(|item| keyed_row(item, window.dark)),
    );
    card(StackPanel::new().spacing(10.0).children(rows)).into()
}

// ---- Keyed values ----

/// The Keyed values kind filter: "All kinds", then every kind of [`KIND_GROUPS`] in their order.
fn kind_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    let kinds: Vec<EntityKind> = KIND_GROUPS
        .iter()
        .flat_map(|&(_, kinds)| kinds.iter().copied())
        .collect();
    ComboBox::new()
        .items_source(
            std::iter::once("All kinds").chain(kinds.iter().map(|&kind| kind_label(kind))),
        )
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
fn site_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
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
    ComboBox::new()
        .items_source(std::iter::once("All sites").chain(sites.iter().map(String::as_str)))
        .selected_index(Some(selected))
        .width(190.0)
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::KeyedSite(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| sites.get(i).cloned()),
            )
        }))
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

fn keyed(window: &MainWindow, context: Context<'_>) -> View {
    let search = Grid::new()
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
        ));

    let (count, list): (String, View) = match &window.keyed_page {
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
                    DataItem::new(item.proxy.clone(), &item.original).content(
                        Border::new()
                            .height(KEYED_ROW)
                            .content(keyed_row(item, window.dark)),
                    )
                }))
                .into();
            (count, list)
        }
    };

    Grid::new()
        .rows([
            GridLength::Auto,
            GridLength::Auto,
            GridLength::Auto,
            GridLength::STAR,
        ])
        .row_spacing(12.0)
        .children((
            StackPanel::new().spacing(4.0).children((
                title(Page::Keyed.title()),
                caption("Every value piikey has given a stand-in, from the vault on this PC. The stand-in is what the site saw; piikey turns it back into the value in the answers."),
            )),
            search.grid_row(1),
            caption(count).grid_row(2),
            Border::new().grid_row(3).content(list),
        ))
        .into()
}

// ---- Settings ----

fn settings(window: &MainWindow, context: Context<'_>) -> View {
    let mut children: Vec<View> = vec![title(Page::Settings.title()).into()];
    if let Some(error) = &window.form_error {
        children.push(
            InfoBar::new()
                .title("Not added")
                .message(error)
                .severity(InfoBarSeverity::Warning)
                .is_open(true)
                .is_closable(true)
                .on_closed(context.message(Msg::DismissForm))
                .into(),
        );
    }
    children.extend([
        sites_card(window, context),
        programs_card(window, context),
        kinds_card(window, context),
        card(
            StackPanel::new()
                .spacing(8.0)
                .children((heading("Certificate"), certificate(window, context))),
        )
        .into(),
        about_card(window),
    ]);
    column(children)
}

fn certificate(window: &MainWindow, context: Context<'_>) -> View {
    let working = window.snap.busy.is_some() || window.snap.pending > 0;
    match window.snap.cert {
        Cert::Installed => info(
            "Certificate installed",
            "Windows trusts the piikey certificate, so piikey can read the HTTPS traffic of the sites and programs you select.",
            InfoBarSeverity::Success,
        )
        .into(),
        Cert::Missing => StackPanel::new()
            .spacing(8.0)
            .children((
                info(
                    "Certificate not installed",
                    "piikey needs it to read HTTPS traffic of the sites and programs you select. Windows asks you to confirm once.",
                    InfoBarSeverity::Warning,
                ),
                Button::new()
                    .content("Install certificate")
                    .style(ButtonStyle::Accent)
                    .is_enabled(!working)
                    .on_click(context.message(Msg::InstallCertificate)),
            ))
            .into(),
        Cert::Unknown => info(
            "Certificate",
            "Checking whether Windows trusts the piikey certificate...",
            InfoBarSeverity::Informational,
        )
        .into(),
    }
}

/// A check box row of a list.
fn check_row(
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

/// A row with a label and a button on its right.
fn remove_row(key: String, label: &str, action: Msg, context: Context<'_>) -> DataItem {
    DataItem::new(key, label).content(
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .column_spacing(12.0)
            .children((
                TextBlock::new()
                    .text(label)
                    .margin(Thickness::new(0.0, 8.0, 0.0, 0.0)),
                Button::new()
                    .content("Remove")
                    .style(ButtonStyle::Subtle)
                    .grid_column(1)
                    .on_click(context.message(action)),
            )),
    )
}

fn list_height(rows: usize) -> f64 {
    // Row counts are tiny, so the conversion is exact.
    #[allow(clippy::cast_precision_loss)]
    let rows = rows as f64;
    ROW * rows + 8.0
}

/// A text box with its button on the right.
fn add_row(
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
                .on_text_changed(context.callback(move |text: Rc<str>| on_text(text.to_string()))),
            Button::new()
                .content(button)
                .grid_column(1)
                .is_enabled(!draft.trim().is_empty())
                .on_click(context.message(on_add)),
        ))
        .into()
}

/// The preset sites with check boxes, then the sites the user added with a remove button each.
fn sites_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let presets = ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(list_height(PRESETS.len()))
        .items(PRESETS.iter().map(|&preset| {
            let site = preset.to_owned();
            check_row(
                format!("preset:{preset}"),
                preset,
                policy.sites.iter().any(|s| s == preset),
                move |on| Msg::Site(site.clone(), on),
                context,
            )
        }));
    let custom: Vec<&String> = policy
        .sites
        .iter()
        .filter(|site| !PRESETS.contains(&site.as_str()))
        .collect();
    let custom: View = if custom.is_empty() {
        caption("No other sites yet.").into()
    } else {
        ListView::new()
            .selection_mode(ListViewSelectionMode::None)
            .height(list_height(custom.len()))
            .items(custom.iter().map(|site| {
                remove_row(
                    format!("site:{site}"),
                    site,
                    Msg::Site((*site).clone(), false),
                    context,
                )
            }))
            .into()
    };
    card(
        StackPanel::new().spacing(8.0).children((
            heading("Sites"),
            caption("Only traffic to the sites you tick, and from the programs you tick below, is read and anonymized. Everything else passes through untouched."),
            presets,
            custom,
            add_row(
                "Another site, e.g. example.com or *.example.com",
                &window.site_draft,
                "Add site",
                Msg::SiteDraft,
                Msg::AddSite,
                context,
            ),
        )),
    )
    .into()
}

/// Running programs, plus any configured program that is not running now, with check boxes.
fn programs_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let mut programs: Vec<&str> = window
        .processes
        .iter()
        .chain(&policy.programs)
        .map(String::as_str)
        .collect();
    programs.sort_unstable();
    programs.dedup();
    let list = ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(ROW * 7.0)
        .items(programs.iter().map(|&exe| {
            let owned = exe.to_owned();
            check_row(
                format!("program:{exe}"),
                exe,
                policy.programs.iter().any(|p| p == exe),
                move |on| Msg::Program(owned.clone(), on),
                context,
            )
        }));
    card(
        StackPanel::new().spacing(8.0).children((
            heading("Programs"),
            caption("Every site a ticked program visits is protected. Works for programs that follow the Windows proxy settings: browsers, Electron apps, .NET apps, curl. The list refreshes every few seconds."),
            list,
            add_row(
                "Another program, e.g. chrome.exe",
                &window.program_draft,
                "Add program",
                Msg::ProgramDraft,
                Msg::AddProgram,
                context,
            ),
        )),
    )
    .into()
}

/// One collapsed expander per kind group, each listing its kinds as check boxes.
fn kinds_card(window: &MainWindow, context: Context<'_>) -> View {
    let disabled = &window.snap.policy.disabled_kinds;
    let mut children: Vec<View> = vec![
        heading("What piikey masks").into(),
        caption(
            "Everything is on by default. Turning a type off only affects new text; values piikey already replaced still come back.",
        )
        .into(),
    ];
    children.extend(KIND_GROUPS.iter().map(|&(group, kinds)| {
        let on = kinds.iter().filter(|kind| !disabled.contains(kind)).count();
        let list = ListView::new()
            .selection_mode(ListViewSelectionMode::None)
            .height(list_height(kinds.len()))
            .items(kinds.iter().map(|&kind| {
                check_row(
                    format!("kind:{}", kind.as_str()),
                    kind_label(kind),
                    !disabled.contains(&kind),
                    move |on| Msg::Kind(kind, on),
                    context,
                )
            }));
        Expander::new()
            .is_expanded(false)
            .horizontal_alignment(HorizontalAlignment::Stretch)
            .horizontal_content_alignment(HorizontalAlignment::Stretch)
            .header(TextBlock::new().text(format!("{group} ({on}/{})", kinds.len())))
            .content(list)
            .into()
    }));
    card(StackPanel::new().spacing(8.0).children(children)).into()
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
                    caption(format!(
                        "Vault: {}",
                        window.input.controller.vault_path().display()
                    )),
                )),
            )),
    )
    .into()
}

/// Lines the loading screen rotates through while the model downloads.
pub const FLAVOR: [&str; 12] = [
    "Teaching piikey that 'Jan Jansen' is a person and 'Jansen Bakery' is bread.",
    "Swapping your name for a nicer one. Don't worry, you get yours back.",
    "Your IBAN goes in, a perfectly fake IBAN comes out.",
    "Convincing the chatbot that you are Haley Marian from Westbrook.",
    "Learning 24 languages so your aunt's Polish address stays private too.",
    "Hiding your phone number from the robots. Politely.",
    "'Hi, I'm jan.jansen@acme.nl' becomes 'Hi, I'm lotte.peters@mail.nl'. Magic.",
    "Downloading a small brain. It only knows about privacy.",
    "Making sure your doctor's note stays between you and your doctor.",
    "Your secrets are safe. Your typos are still all yours.",
    "Calibrating the 'is this a name or a pizza topping' detector.",
    "Everything runs on this PC. Nothing about you leaves it in clear.",
];

/// The first-run screen: the model download's progress, or why it failed.
pub fn loading(window: &MainWindow, context: Context<'_>) -> StackPanel {
    let mut children: Vec<View> = vec![
        Image::new()
            .source_svg(assets::stacked(window.dark))
            .stretch(Stretch::Uniform)
            .height(120.0)
            .into(),
        TextBlock::new()
            .text("Getting piikey ready")
            .font_size(24.0)
            .font_weight(FontWeight::SEMI_BOLD)
            .horizontal_alignment(HorizontalAlignment::Center)
            .into(),
    ];
    match &window.snap.model {
        Model::Failed(message) => {
            children.push(info("Download failed", message, InfoBarSeverity::Error).into());
            children.push(
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(8.0)
                    .horizontal_alignment(HorizontalAlignment::Center)
                    .children((
                        Button::new()
                            .content("Try again")
                            .style(ButtonStyle::Accent)
                            .on_click(context.message(Msg::RetryModel)),
                        Button::new()
                            .content("Continue without it")
                            .on_click(context.message(Msg::SkipModel)),
                    ))
                    .into(),
            );
        }
        model => {
            let (done, total) = match *model {
                Model::Downloading { done, total } => (done, total),
                _ => (0, 0),
            };
            #[expect(
                clippy::cast_precision_loss,
                reason = "a progress bar needs no byte precision"
            )]
            let (done_f, total_f) = (done as f64, total.max(1) as f64);
            children.push(
                ProgressBar::new()
                    .minimum(0.0)
                    .maximum(total_f)
                    .value(done_f)
                    .width(360.0)
                    .horizontal_alignment(HorizontalAlignment::Center)
                    .into(),
            );
            children.push(
                caption(format!(
                    "{} MB of {} MB",
                    (done + 500_000) / 1_000_000,
                    (total + 500_000) / 1_000_000
                ))
                .horizontal_alignment(HorizontalAlignment::Center)
                .into(),
            );
        }
    }
    children.push(
        RichTextBlock::new()
            .paragraphs(RichText::single_paragraph([RichTextInline::Run(
                RichTextRun {
                    text: FLAVOR[window.flavor % FLAVOR.len()].to_owned(),
                    is_italic: true,
                    ..RichTextRun::default()
                },
            )]))
            .text_wrapping(TextWrapping::Wrap)
            .opacity(0.8)
            .horizontal_alignment(HorizontalAlignment::Center)
            .into(),
    );
    StackPanel::new()
        .spacing(16.0)
        .max_width(440.0)
        .horizontal_alignment(HorizontalAlignment::Center)
        .vertical_alignment(VerticalAlignment::Center)
        .children(children)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn bars_scale_to_the_largest_value_and_never_vanish() {
        assert!((scaled(50, 100, 120.0) - 60.0).abs() < f64::EPSILON);
        assert!((scaled(100, 100, 120.0) - 120.0).abs() < f64::EPSILON);
        assert!((scaled(1, 1_000_000, 120.0) - 2.0).abs() < f64::EPSILON);
        assert!(scaled(0, 100, 120.0).abs() < f64::EPSILON);
        assert!(scaled(0, 0, 120.0).abs() < f64::EPSILON);
    }

    #[test]
    fn the_groups_cover_every_kind_exactly_once() {
        let listed: Vec<EntityKind> = KIND_GROUPS
            .iter()
            .flat_map(|&(_, kinds)| kinds.iter().copied())
            .collect();
        assert_eq!(listed.len(), EntityKind::ALL.len());
        for kind in EntityKind::ALL {
            assert_eq!(listed.iter().filter(|&&k| k == kind).count(), 1, "{kind:?}");
        }
    }
}
