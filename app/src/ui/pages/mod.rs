//! The three pages of the window: Home, Keyed values and Settings, and the first-run screen.
//!
//! Text, cards, lists and controls take their colours from the theme, so they follow light or dark
//! mode and the accent colour. Only the brand parts use the piikey colours: the logo and the kind
//! icons, purple `#6f49b1` in light mode and lilac `#d6c9f9` in dark mode, as the logo kit
//! (`assets/brand/piikey-logo-kit`) prescribes. The treemap of the inventory on Home colours its
//! tiles by the group of the kind found most, the same in both themes, under white text.
//!
//! This file holds the page frame and the widgets every page shares; each page has its own file.

mod home;
mod inventory;
mod keyed;
mod lists;
pub(super) mod loading;
mod settings;

use windows_reactor::{
    Border, Button, ButtonStyle, Color, FontWeight, Grid, GridLength, InfoBar, InfoBarSeverity,
    ScrollViewer, StackPanel, TextBlock, TextWrapping, ThemeBrush, Thickness, View, ViewContext,
};

use super::{
    controller::{Cert, Severity, Snapshot},
    window::{MainWindow, Msg, Page},
};

/// Height of one list row in DIPs.
const ROW: f64 = 40.0;

type Context<'a> = &'a ViewContext<'a, MainWindow>;

/// The page the navigation selected, under the notice the controller may have raised.
pub fn page(window: &MainWindow, context: Context<'_>) -> View {
    let body = match window.page {
        Page::Home => home::home(window, context),
        Page::Keyed => keyed::keyed(window, context),
        Page::Settings => settings::settings(window, context),
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

/// A message bar that stays open and has no close button.
fn info(title: &str, message: impl AsRef<str>, severity: InfoBarSeverity) -> InfoBar {
    InfoBar::new()
        .title(title)
        .message(message)
        .severity(severity)
        .is_open(true)
        .is_closable(false)
}

/// A message bar with a close button, which sends `closed`.
fn dismissible(
    title: &str,
    message: impl AsRef<str>,
    severity: InfoBarSeverity,
    closed: Msg,
    context: Context<'_>,
) -> View {
    info(title, message, severity)
        .is_closable(true)
        .on_closed(context.message(closed))
        .into()
}

/// What the controller wants the user to read: a warning or an error, until closed.
fn notice(snap: &Snapshot, context: Context<'_>) -> Option<View> {
    let notice = snap.notice.as_ref()?;
    let (title, severity) = match notice.severity {
        Severity::Warning => ("Heads up", InfoBarSeverity::Warning),
        Severity::Error => ("Something went wrong", InfoBarSeverity::Error),
    };
    Some(dismissible(
        title,
        &notice.text,
        severity,
        Msg::DismissNotice,
        context,
    ))
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

/// `1 file`, `2 files`.
fn counted(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", thousands(n), if n == 1 { one } else { many })
}

/// The controller is busy, or has commands it has not finished.
fn is_working(snap: &Snapshot) -> bool {
    snap.busy.is_some() || snap.pending > 0
}

/// How many sites and programs the policy protects.
fn protected(snap: &Snapshot) -> u64 {
    let count = snap.policy.sites.len() + snap.policy.programs.len();
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// The state of the piikey certificate, with the button that installs it while it is missing.
/// Home shows it until the certificate is in; the Masking tab always.
fn certificate(window: &MainWindow, context: Context<'_>) -> View {
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
                    .is_enabled(!is_working(&window.snap))
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

/// The height of a list of `rows` rows.
fn list_height(rows: usize) -> f64 {
    // Row counts are tiny, so saturating at `u32::MAX` never happens and the conversion is exact.
    ROW * f64::from(u32::try_from(rows).unwrap_or(u32::MAX)) + 8.0
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
    fn counts_take_the_plural_that_fits() {
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(0, "file", "files"), "0 files");
        assert_eq!(counted(1_500, "value", "values"), "1,500 values");
    }
}
