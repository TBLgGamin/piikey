//! The pages of the window: Overview, Protection, Inventory, Vault and Settings, and the first-run
//! screen.
//!
//! Text, cards, lists and controls take their colours from the theme, so they follow light or dark
//! mode and the accent colour the user chose in Windows. The brand purple, `#6f49b1` in light mode
//! and lilac `#d6c9f9` in dark mode, as the logo kit (`assets/brand/piikey-logo-kit`) prescribes,
//! appears in the logo and the icons of folders and files; the dashboard of Inventory colours by type of personal data. Status is
//! a glyph and words first, with Windows' own success and caution colours second.
//!
//! [`kit`] holds the page frame's parts and every widget the pages share (the type styles, the
//! card, the row, the section); each page has its own file, and [`dashboard`] is what Inventory
//! shows its files in.

mod accounts;
mod cloud;
mod dashboard;
mod inventory;
mod kit;
mod lists;
pub(super) mod loading;
mod overview;
mod protection;
mod settings;
mod vault;

use windows_reactor::{ContentDialog, Grid, GridLength, KeyedView, StackPanel, Thickness, View};

pub(super) use self::kit::status_chip;
use self::{
    dashboard::findings_panel,
    kit::{Context, measured, notice},
};
use super::{
    status::{Cause, Status},
    window::{MainWindow, Page},
};

/// The dialog over the page, if one is open: the Add account and Disconnect dialogs, the Browse
/// cloud dialog, or the result of a scan, in that order of priority.
pub(super) fn dialog(window: &MainWindow, context: Context<'_>) -> Option<ContentDialog> {
    accounts::dialog(window, context)
        .or_else(|| cloud::dialog(window, context))
        .or_else(|| dashboard::dialog(window, context))
}

/// The page the navigation selected, under the notice the controller may have raised; while the
/// findings view is open it takes the page's place, and the page comes back when it closes. Each
/// page is built anew when it comes back, from the top of its scroller.
pub fn page(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let (key, body) = match &window.findings {
        Some(view) => ("findings", findings_panel(view, context)),
        None => (
            window.page.tag(),
            match window.page {
                Page::Overview => overview::overview(window, status, context),
                Page::Protection => protection::protection(window, status, context),
                Page::Inventory => inventory::inventory(window, context),
                Page::Vault => vault::vault(window, context),
                Page::Settings => settings::settings(window, context),
            },
        ),
    };
    // Overview already shows an error as the cause it needs the user for: not twice.
    let shown_by_the_page = window.page == Page::Overview
        && window.findings.is_none()
        && matches!(
            status,
            Status::NeedsAttention {
                cause: Cause::Error(_),
                ..
            }
        );
    let notices: Vec<View> = if shown_by_the_page {
        Vec::new()
    } else {
        notice(&window.snap, context)
            .into_iter()
            .map(measured)
            .collect()
    };
    Grid::new()
        .rows([GridLength::Auto, GridLength::STAR])
        .margin(Thickness::new(24.0, 8.0, 24.0, 16.0))
        .row_spacing(12.0)
        .children((
            StackPanel::new().grid_row(0).children(notices),
            Grid::new()
                .grid_row(1)
                .keyed_children([KeyedView::new(key, body)]),
        ))
        .into()
}
