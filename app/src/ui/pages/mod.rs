//! The pages of the window: Overview, Protection, Inventory, Vault and Settings, and the first-run
//! screen.
//!
//! Text, cards, lists and controls take their colours from the theme, so they follow light or dark
//! mode and the accent colour the user chose in Windows. The brand purple, `#6f49b1` in light mode
//! and lilac `#d6c9f9` in dark mode, as the logo kit (`assets/brand/piikey-logo-kit`) prescribes,
//! appears in the logo and in the treemap of the inventory only. Status is a glyph and words first,
//! with Windows' own success and caution colours second.
//!
//! [`kit`] holds the page frame's parts and every widget the pages share (the type styles, the
//! card, the row, the section); each page has its own file.

mod inventory;
mod kit;
mod lists;
pub(super) mod loading;
mod overview;
mod protection;
mod settings;
mod vault;

use windows_reactor::{Grid, GridLength, KeyedView, StackPanel, Thickness, View};

pub(super) use self::kit::status_chip;
use self::kit::{Context, measured, notice};
use super::{
    status::{Cause, Status},
    window::{MainWindow, Page},
};

/// The page the navigation selected, under the notice the controller may have raised. Each page is
/// built anew when it comes back, from the top of its scroller.
pub fn page(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let body = match window.page {
        Page::Overview => overview::overview(window, status, context),
        Page::Protection => protection::protection(window, status, context),
        Page::Inventory => inventory::inventory(window, context),
        Page::Vault => vault::vault(window, context),
        Page::Settings => settings::settings(window, context),
    };
    // Overview already shows an error as the cause it needs the user for: not twice.
    let shown_by_the_page = window.page == Page::Overview
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
                .keyed_children([KeyedView::new(window.page.tag(), body)]),
        ))
        .into()
}
