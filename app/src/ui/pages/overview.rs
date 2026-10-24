//! Overview: what piikey is doing. The status of protection as one hero card with the one button
//! that turns it on or off, the one thing that needs the user (when something does), a row for each
//! job with its own state and the way to its page, and the latest swaps.
//!
//! The hero is the only large element: no tiles, no map. Every number lives inside the row that
//! owns it.

use windows_reactor::{
    Button, ButtonStyle, Grid, GridLength, HorizontalAlignment, HyperlinkButton, Orientation,
    StackPanel, VerticalAlignment, View,
};

use super::{
    kit::{
        Context, Row, attention, body, caption, card, column, counted, section, section_with,
        status_glyph, subtitle, thousands, title,
    },
    vault::swap_row,
};
use crate::ui::{
    controller::Snapshot,
    status::{Action, Status, Work, protected, protected_text},
    window::{MainWindow, Msg, Page},
};
use piikey::policy::Highlight;

pub(super) fn overview(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let mut children: Vec<View> = vec![
        title(Page::Overview.title()).into(),
        hero(window, status, context),
    ];
    if let Some(cause) = status.problem() {
        children.push(attention(window, &cause, context));
    }
    children.push(doing(window, status, context));
    children.push(recent(window, status, context));
    column(children)
}

/// The status as one card: its glyph, what it is in a headline and one specific sentence, and the
/// button that turns protection on or off. While the button cannot be pressed the card says why.
fn hero(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let mut text: Vec<View> = vec![
        subtitle(status.title()).into(),
        body(status.sentence()).opacity(0.72).into(),
    ];
    let (label, accent, enabled, reason) = match status.action() {
        Action::TurnOn => ("Turn on", true, true, None),
        Action::TurnOff => ("Turn off", false, true, None),
        Action::Unavailable(reason) => ("Turn on", false, false, reason),
    };
    text.extend(reason.map(|reason| View::from(caption(reason))));
    let button = Button::new()
        .content(label)
        .style(if accent {
            ButtonStyle::Accent
        } else {
            ButtonStyle::Default
        })
        .is_enabled(enabled)
        .grid_column(2)
        .vertical_alignment(VerticalAlignment::Center)
        .automation_name(label)
        .on_click(context.message(Msg::Toggle(accent)));
    card(
        Grid::new()
            .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
            .column_spacing(20.0)
            .children((
                StackPanel::new()
                    .width(44.0)
                    .vertical_alignment(VerticalAlignment::Center)
                    .children((status_glyph(status, 40.0, window.dark),)),
                StackPanel::new()
                    .spacing(4.0)
                    .grid_column(1)
                    .vertical_alignment(VerticalAlignment::Center)
                    .children(text),
                button,
            )),
    )
    .into()
}

/// A row for each job, each on its way to the page that owns it, each saying how it is doing.
fn doing(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let snap = &window.snap;
    let go = |page: Page| context.message(Msg::Nav(page));
    section(
        "What piikey is doing",
        vec![
            Row::new("Masking")
                .icon("\u{E705}")
                .description("Swaps personal data for stand-ins in what you send.")
                .state(masking_state(status, protected(snap)))
                .on_click(go(Page::Protection))
                .build(),
            Row::new("Highlighting")
                .icon("\u{E7E6}")
                .description("Outlines the field you type in when it holds personal data.")
                .state(highlighting_state(
                    snap.policy.highlight,
                    snap.highlight_paused,
                ))
                .on_click(go(Page::Protection))
                .build(),
            Row::new("Inventory")
                .icon("\u{E8B7}")
                .description(
                    "Lists the files that hold personal data, and keeps the locations you monitor up to date.",
                )
                .state(inventory_state(snap))
                .on_click(go(Page::Inventory))
                .build(),
            Row::new("Vault")
                .icon("\u{E72E}")
                .description("Remembers which stand-in replaced which value.")
                .state(vault_state(snap.issued))
                .on_click(go(Page::Vault))
                .build(),
        ],
    )
}

/// `On · 4 sites and apps`, or `Off`, or what is on its way.
fn masking_state(status: &Status, protected: u64) -> String {
    match status {
        Status::Busy(Work::Starting) => "Starting\u{2026}".to_owned(),
        Status::Busy(Work::Stopping) => "Stopping\u{2026}".to_owned(),
        status if status.is_on() => format!("On \u{b7} {}", protected_text(protected)),
        _ => "Off".to_owned(),
    }
}

/// `Always`, `When you press Ctrl+Alt+P`, `Paused` (Always, paused by its shortcut) or `Off`.
fn highlighting_state(mode: Highlight, paused: bool) -> String {
    match mode {
        Highlight::Off => "Off",
        Highlight::Always if paused => "Paused",
        Highlight::Always => "Always",
        Highlight::Hotkey => "When you press Ctrl+Alt+P",
    }
    .to_owned()
}

/// `711 found in 51 files · monitoring 2 locations`, `Scanning… 3,412 of 20,100` or `Nothing
/// scanned yet`.
fn inventory_state(snap: &Snapshot) -> String {
    // A scan the user asked for, or the scan of what changed in a monitored location.
    if let Some((done, total)) = snap.scan.or(snap.watch.scanning) {
        return if total == 0 {
            "Scanning\u{2026}".to_owned()
        } else {
            format!(
                "Scanning\u{2026} {} of {}",
                thousands(done),
                thousands(total)
            )
        };
    }
    let (files, hits) = snap.inventory_totals;
    let base = if hits > 0 {
        format!(
            "{} found in {}",
            thousands(hits),
            counted(files, "file", "files")
        )
    } else {
        "Nothing scanned yet".to_owned()
    };
    match u64::try_from(snap.policy.monitored_roots.len()).unwrap_or(u64::MAX) {
        0 => base,
        n => format!(
            "{base} \u{b7} monitoring {}",
            counted(n, "location", "locations")
        ),
    }
}

/// `22 values remembered`.
fn vault_state(issued: u64) -> String {
    if issued == 0 {
        "Nothing remembered yet".to_owned()
    } else {
        format!("{} remembered", counted(issued, "value", "values"))
    }
}

/// The latest swaps, with the way to all of them, or an honest word about why there are none.
fn recent(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let snap = &window.snap;
    let all = HyperlinkButton::new()
        .content("View all")
        .is_enabled(snap.issued > 0)
        .on_click(context.message(Msg::Nav(Page::Vault)));
    let rows: Vec<View> = if snap.recent.is_empty() {
        let empty = if status.is_on() {
            "Nothing swapped yet. piikey is waiting for traffic from your protected sites and apps."
        } else {
            "Turn on protection to start masking."
        };
        vec![
            caption(empty)
                .horizontal_alignment(HorizontalAlignment::Left)
                .into(),
        ]
    } else {
        snap.recent.iter().map(swap_row).collect()
    };
    section_with(
        "Recent swaps",
        vec![all.into()],
        vec![
            card(
                StackPanel::new()
                    .orientation(Orientation::Vertical)
                    .spacing(10.0)
                    .children(rows),
            )
            .into(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ui::testing::{TempDir, stub_controller};

    #[test]
    fn the_masking_row_says_on_with_what_is_protected() {
        let on = Status::On {
            protected: 4,
            last: None,
        };
        assert_eq!(masking_state(&on, 4), "On \u{b7} 4 sites and apps");
        assert_eq!(
            masking_state(
                &Status::Off {
                    needs_certificate: false
                },
                4
            ),
            "Off"
        );
        assert_eq!(
            masking_state(&Status::Busy(Work::Starting), 4),
            "Starting\u{2026}"
        );
    }

    #[test]
    fn the_highlighting_row_tells_the_mode_and_a_pause() {
        assert_eq!(highlighting_state(Highlight::Off, false), "Off");
        assert_eq!(highlighting_state(Highlight::Always, false), "Always");
        assert_eq!(highlighting_state(Highlight::Always, true), "Paused");
        assert_eq!(
            highlighting_state(Highlight::Hotkey, false),
            "When you press Ctrl+Alt+P"
        );
    }

    #[test]
    fn the_inventory_row_says_how_many_locations_it_monitors() -> Result<(), String> {
        let dir = TempDir::new()?;
        let mut snap = stub_controller(&dir)?.snapshot();
        assert_eq!(inventory_state(&snap), "Nothing scanned yet");
        snap.inventory_totals = (5, 34);
        assert_eq!(inventory_state(&snap), "34 found in 5 files");
        snap.policy.monitored_roots = vec![
            PathBuf::from(r"C:\Users\me\Downloads"),
            PathBuf::from(r"C:\Users\me\Documents"),
        ];
        assert_eq!(
            inventory_state(&snap),
            "34 found in 5 files \u{b7} monitoring 2 locations"
        );
        snap.policy.monitored_roots.truncate(1);
        assert_eq!(
            inventory_state(&snap),
            "34 found in 5 files \u{b7} monitoring 1 location"
        );
        snap.watch.scanning = Some((12, 40));
        assert_eq!(inventory_state(&snap), "Scanning\u{2026} 12 of 40");
        snap.watch.scanning = Some((0, 0));
        assert_eq!(inventory_state(&snap), "Scanning\u{2026}");
        Ok(())
    }

    #[test]
    fn the_vault_row_counts_values() {
        assert_eq!(vault_state(0), "Nothing remembered yet");
        assert_eq!(vault_state(1), "1 value remembered");
        assert_eq!(vault_state(22), "22 values remembered");
    }
}
