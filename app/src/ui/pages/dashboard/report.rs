//! The dialog of the window that tells what a scan found: the result of a scan of files and
//! folders that was asked for (Explorer, the Inventory page, the API), a content dialog over the page
//! that is on show. It counts what was found by type; "Show what was found" opens the
//! [findings view](super::findings) with the values themselves.

use std::path::PathBuf;

use piikey::detect::EntityKind;
use windows_reactor::{
    ContentDialog, ContentDialogButton, ContentDialogResult, Grid, GridLength, ProgressBar,
    ProgressRing, StackPanel, TextBlock, TextTrimming, VerticalAlignment, View,
};

use super::palette::swatch;
use crate::ui::pages::kit::{Context, body, caption, counted, subtitle, thousands};
use crate::ui::{
    controller::{Reveal, RevealState, ScanSummary},
    window::{MainWindow, Msg},
};

/// The most types a result lists.
const TYPES: usize = 8;

/// The count of each type found, the types that hold most first.
fn type_rows(counts: &[(EntityKind, u32)]) -> Vec<View> {
    let mut rows: Vec<View> = counts
        .iter()
        .take(TYPES)
        .map(|&(kind, n)| {
            Grid::new()
                .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
                .column_spacing(10.0)
                .children((
                    swatch(kind).vertical_alignment(VerticalAlignment::Center),
                    TextBlock::new().text(kind.label()).grid_column(1),
                    TextBlock::new()
                        .text(thousands(u64::from(n)))
                        .opacity(0.72)
                        .grid_column(2),
                ))
                .into()
        })
        .collect();
    if counts.len() > TYPES {
        rows.push(
            caption(format!(
                "and {} more",
                counted(
                    u64::try_from(counts.len() - TYPES).unwrap_or(u64::MAX),
                    "type",
                    "types"
                )
            ))
            .into(),
        );
    }
    rows
}

/// What was asked to be scanned, in a line: the path, or how many.
pub(super) fn scanned_what(paths: &[PathBuf]) -> String {
    match paths {
        [] => String::new(),
        [one] => one.display().to_string(),
        [first, rest @ ..] => format!(
            "{} and {}",
            first.display(),
            counted(
                u64::try_from(rest.len()).unwrap_or(u64::MAX),
                "other item",
                "other items"
            )
        ),
    }
}

/// The headline of a result: what was found, or that nothing was.
pub(super) fn headline(summary: &ScanSummary) -> String {
    if summary.hits == 0 {
        "No personal data found".to_owned()
    } else {
        format!(
            "{} found in {}",
            thousands(summary.hits),
            counted(summary.files_with_data, "file", "files")
        )
    }
}

/// What the headline leaves out: how many files were looked at, and how many could not be read.
pub(super) fn tally(summary: &ScanSummary) -> String {
    let looked = counted(summary.files, "file", "files");
    if summary.unread == 0 {
        format!("{looked} scanned")
    } else {
        format!(
            "{looked} scanned \u{b7} {} could not be read, are too large or not in a format piikey reads",
            thousands(summary.unread)
        )
    }
}

/// How far a scan is, in one row: a ring while the files are still being looked for, a bar and
/// how many are scanned once they are counted.
fn progress(scan: Option<(u64, u64)>) -> View {
    match scan {
        Some((done, total)) if total > 0 => {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a progress bar needs no precision beyond 2^53 files"
            )]
            let (done_f, total_f) = (done as f64, total as f64);
            StackPanel::new()
                .spacing(6.0)
                .children((
                    ProgressBar::new()
                        .minimum(0.0)
                        .maximum(total_f)
                        .value(done_f),
                    caption(format!(
                        "Scanned {} of {} files\u{2026}",
                        thousands(done),
                        thousands(total)
                    )),
                ))
                .into()
        }
        _ => StackPanel::new()
            .orientation(windows_reactor::Orientation::Horizontal)
            .spacing(10.0)
            .children((
                ProgressRing::new().is_active(true).width(16.0).height(16.0),
                caption("Looking for files\u{2026}").vertical_alignment(VerticalAlignment::Center),
            ))
            .into(),
    }
}

/// The content of the result dialog for a scan that is `reveal`.
fn result_content(window: &MainWindow, reveal: &Reveal) -> View {
    let mut parts: Vec<View> = vec![
        caption(scanned_what(&reveal.paths))
            .is_text_selection_enabled(true)
            .max_lines(2)
            .text_trimming(TextTrimming::CharacterEllipsis)
            .into(),
    ];
    match &reveal.state {
        RevealState::Waiting => {
            parts.push(body("Waiting for the scan that is running to finish\u{2026}").into());
        }
        RevealState::Scanning => parts.push(progress(window.snap.scan)),
        RevealState::Failed(error) => parts.push(body(error).into()),
        RevealState::Done(summary) => {
            parts.push(subtitle(&headline(summary)).into());
            parts.push(caption(tally(summary)).into());
            parts.extend(type_rows(&summary.counts));
        }
    }
    StackPanel::new().spacing(8.0).children(parts).into()
}

/// The dialog of the scan whose result the user has not put away yet. A result that holds personal
/// data offers what was found itself (the default), and the Inventory with its map.
fn result(window: &MainWindow, reveal: &Reveal, context: Context<'_>) -> ContentDialog {
    let (title, found) = match &reveal.state {
        RevealState::Waiting | RevealState::Scanning => ("Scanning\u{2026}", false),
        RevealState::Failed(_) => ("The scan failed", false),
        RevealState::Done(summary) => ("Scan result", summary.hits > 0),
    };
    let dialog = ContentDialog::new()
        .is_open(true)
        .title(title)
        .content(result_content(window, reveal))
        .close_button_text("Close")
        .on_closed(
            context.callback(|result: ContentDialogResult| match result {
                ContentDialogResult::Primary => Msg::ReportFound,
                ContentDialogResult::Secondary => Msg::ReportShow,
                _ => Msg::ReportClose,
            }),
        );
    if found {
        dialog
            .primary_button_text("Show what was found")
            .secondary_button_text("Show in Inventory")
            .default_button(ContentDialogButton::Primary)
    } else {
        dialog.default_button(ContentDialogButton::Close)
    }
}

/// The dialog on show, if one is: the result of the newest scan that was asked to be shown and is
/// not put away.
pub(in crate::ui) fn dialog(window: &MainWindow, context: Context<'_>) -> Option<ContentDialog> {
    window
        .pending_reveal()
        .map(|reveal| result(window, reveal, context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(hits: u64, files_with_data: u64, files: u64, unread: u64) -> ScanSummary {
        ScanSummary {
            files,
            files_with_data,
            hits,
            counts: Vec::new(),
            unread,
        }
    }

    fn paths(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn the_headline_says_what_was_found_or_that_nothing_was() {
        assert_eq!(headline(&summary(711, 51, 60, 0)), "711 found in 51 files");
        assert_eq!(headline(&summary(1, 1, 1, 0)), "1 found in 1 file");
        assert_eq!(headline(&summary(0, 0, 12, 0)), "No personal data found");
    }

    #[test]
    fn the_tally_counts_the_files_and_the_ones_that_could_not_be_read() {
        assert_eq!(tally(&summary(5, 1, 1, 0)), "1 file scanned");
        assert!(tally(&summary(5, 1, 60, 3)).starts_with("60 files scanned \u{b7} 3 could not"));
    }

    #[test]
    fn what_was_scanned_is_the_path_or_how_many_items() {
        assert_eq!(scanned_what(&paths(&[r"C:\Docs\a.pdf"])), r"C:\Docs\a.pdf");
        assert_eq!(
            scanned_what(&paths(&[r"C:\Docs", r"C:\Mail", r"C:\Tax"])),
            r"C:\Docs and 2 other items"
        );
        assert_eq!(
            scanned_what(&paths(&[r"C:\Docs", r"C:\Mail"])),
            r"C:\Docs and 1 other item"
        );
        assert!(scanned_what(&[]).is_empty());
    }
}
