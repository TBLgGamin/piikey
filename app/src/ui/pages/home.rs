//! The Home page: the switch, the key numbers, the inventory map and the latest keyed values.

use windows_reactor::{
    FontWeight, Grid, GridLength, HyperlinkButton, Image, Orientation, ProgressRing, StackPanel,
    Stretch, TextBlock, ToggleSwitch, VerticalAlignment, View,
};

use super::{
    Context, caption, card, certificate, column, heading, inventory::inventory_card, is_working,
    keyed::keyed_row, protected, thousands,
};
use crate::ui::{
    assets,
    controller::{Busy, Cert, RECENT, Snapshot},
    window::{MainWindow, Msg, Page},
};

pub(super) fn home(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut children: Vec<View> = vec![brand_header(window.dark), switch_card(window, context)];
    if snap.cert != Cert::Installed {
        children.push(certificate(window, context));
    }
    children.push(numbers(snap));
    children.push(inventory_card(window, context));
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

/// The on/off switch of protection. It waits while the controller works, and stays off the
/// moment the certificate is missing.
pub(super) fn protection_switch(window: &MainWindow, context: Context<'_>) -> ToggleSwitch {
    let snap = &window.snap;
    ToggleSwitch::new()
        .is_on(window.desired.unwrap_or(snap.enabled))
        .is_enabled(!is_working(snap) && snap.cert == Cert::Installed)
        .on_content("On")
        .off_content("Off")
        .on_toggled(context.callback(Msg::Toggle))
}

fn busy_text(busy: Busy) -> &'static str {
    match busy {
        Busy::Starting => "Starting piikey...",
        Busy::Stopping => "Stopping piikey...",
        Busy::InstallingCertificate => "Waiting for Windows to add the certificate...",
    }
}

/// The on/off switch and what it means right now.
fn switch_card(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let on = window.desired.unwrap_or(snap.enabled);
    let protected = protected(snap);
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
                            .is_active(is_working(snap))
                            .width(20.0)
                            .height(20.0),
                        protection_switch(window, context),
                    )),
            )),
    )
    .into()
}

/// One key number: big value over its label, in grid column `column`.
fn number(value: u64, label: &str, column: i32) -> View {
    card(
        StackPanel::new().spacing(2.0).children((
            TextBlock::new()
                .text(thousands(value))
                .font_size(28.0)
                .font_weight(FontWeight::SEMI_BOLD),
            caption(label),
        )),
    )
    .grid_column(column)
    .into()
}

fn numbers(snap: &Snapshot) -> View {
    let (files, found) = snap.inventory_totals;
    Grid::new()
        .columns([GridLength::STAR; 4])
        .column_spacing(12.0)
        .children(vec![
            number(snap.issued, "values keyed, all time", 0),
            number(files, "files with personal data", 1),
            number(found, "personal data found in files", 2),
            number(protected(snap), "sites and programs protected", 3),
        ])
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
            .map(|item| keyed_row(item, window.dark, None)),
    );
    card(StackPanel::new().spacing(10.0).children(rows)).into()
}
