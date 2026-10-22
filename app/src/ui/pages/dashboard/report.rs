//! The dialogs of the window that tell what a scan found: the result of a scan of one file or
//! folder that was asked for (Explorer, the Inventory page), and the list of what was found in one
//! file. Both are content dialogs over the page that is on show.
//!
//! The values listed come from running the detection on the file at that moment and live in the
//! window only while the dialog is open: the inventory keeps counts, never the values.

use std::path::Path;

use piikey::{detect::EntityKind, inventory::Finding};
use windows_reactor::{
    ContentDialog, ContentDialogButton, ContentDialogResult, FontWeight, Grid, GridLength,
    ProgressBar, ProgressRing, ScrollViewer, StackPanel, TextBlock, TextTrimming, Thickness,
    TooltipExt, VerticalAlignment, View,
};

use super::{crumbs::name_of, palette::swatch};
use crate::ui::pages::kit::{Context, body, caption, counted, subtitle, thousands};
use crate::ui::{
    controller::{Reveal, RevealState, ScanSummary},
    window::{FindingsState, MainWindow, Msg, single_file},
};

/// The most findings a dialog lists; a file can hold thousands.
const MOST: usize = 200;
/// How tall the list of findings is at most, in DIPs.
const LIST_HEIGHT: f64 = 300.0;
/// The most types a result lists.
const TYPES: usize = 8;

/// One finding: the swatch of its type, the value over what stands around it in the file, and the
/// name of the type.
fn finding_row(finding: &Finding) -> View {
    Grid::new()
        .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
        .column_spacing(10.0)
        .children((
            swatch(finding.kind)
                .vertical_alignment(VerticalAlignment::Top)
                .margin(Thickness::new(0.0, 5.0, 0.0, 0.0)),
            StackPanel::new().grid_column(1).children((
                TextBlock::new()
                    .text(&*finding.value)
                    .font_weight(FontWeight::SEMI_BOLD)
                    .text_trimming(TextTrimming::CharacterEllipsis)
                    .tooltip(&*finding.value),
                caption(&*finding.snippet).max_lines(2),
            )),
            caption(finding.kind.label())
                .grid_column(2)
                .vertical_alignment(VerticalAlignment::Top)
                .margin(Thickness::new(0.0, 2.0, 0.0, 0.0)),
        ))
        .into()
}

/// The findings a dialog lists, and a line that says so when it lists only the first of them.
fn listed(list: &[Finding]) -> (&[Finding], Option<String>) {
    let shown = &list[..list.len().min(MOST)];
    let cut = (list.len() > MOST).then(|| {
        format!(
            "Showing the first {} of {}.",
            thousands(u64::try_from(MOST).unwrap_or(u64::MAX)),
            thousands(u64::try_from(list.len()).unwrap_or(u64::MAX))
        )
    });
    (shown, cut)
}

/// What was found in a file, as the state of the reading says: a ring while the detection runs,
/// the rows, or why there are none.
fn findings(state: &FindingsState) -> View {
    match state {
        FindingsState::Loading => StackPanel::new()
            .orientation(windows_reactor::Orientation::Horizontal)
            .spacing(10.0)
            .children((
                ProgressRing::new().is_active(true).width(16.0).height(16.0),
                caption("Reading the file\u{2026}").vertical_alignment(VerticalAlignment::Center),
            ))
            .into(),
        FindingsState::Failed(error) => caption(error).into(),
        FindingsState::Loaded(list) if list.is_empty() => {
            caption("Nothing to list: the detection finds no personal data in this file.").into()
        }
        FindingsState::Loaded(list) => {
            let (shown, cut) = listed(list);
            let mut rows: Vec<View> = shown.iter().map(finding_row).collect();
            rows.extend(cut.map(|text| View::from(caption(text))));
            ScrollViewer::new()
                .max_height(LIST_HEIGHT)
                .content(
                    StackPanel::new()
                        .spacing(10.0)
                        .margin(Thickness::new(0.0, 0.0, 12.0, 0.0))
                        .children(rows),
                )
                .into()
        }
    }
}

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
pub(super) fn scanned_what(reveal: &Reveal) -> String {
    match reveal.paths.as_slice() {
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
        caption(scanned_what(reveal))
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
            // One file: what was found in it, so the dialog answers "what exactly".
            if let (Some(file), true) = (single_file(reveal), summary.hits > 0)
                && let Some((path, state)) = &window.findings
                && path == file
            {
                parts.push(
                    TextBlock::new()
                        .text("Found in this file")
                        .font_weight(FontWeight::SEMI_BOLD)
                        .margin(Thickness::new(0.0, 8.0, 0.0, 0.0))
                        .into(),
                );
                parts.push(findings(state));
            }
        }
    }
    StackPanel::new().spacing(8.0).children(parts).into()
}

/// The dialog of the scan whose result the user has not put away yet.
fn result(window: &MainWindow, reveal: &Reveal, context: Context<'_>) -> ContentDialog {
    let (title, show) = match &reveal.state {
        RevealState::Waiting | RevealState::Scanning => ("Scanning\u{2026}", false),
        RevealState::Failed(_) => ("The scan failed", false),
        RevealState::Done(summary) => ("Scan result", summary.hits > 0),
    };
    let dialog = ContentDialog::new()
        .is_open(true)
        .title(title)
        .content(result_content(window, reveal))
        .close_button_text("Close")
        .on_closed(context.callback(|result: ContentDialogResult| {
            if result == ContentDialogResult::Primary {
                Msg::ReportShow
            } else {
                Msg::ReportClose
            }
        }));
    if show {
        dialog
            .primary_button_text("Show in Inventory")
            .default_button(ContentDialogButton::Primary)
    } else {
        dialog.default_button(ContentDialogButton::Close)
    }
}

/// The dialog of "Show what was found": the findings of one file.
fn found(path: &Path, state: &FindingsState, context: Context<'_>) -> ContentDialog {
    ContentDialog::new()
        .is_open(true)
        .title(name_of(path))
        .content(
            StackPanel::new().spacing(10.0).children((
                caption(path.display().to_string())
                    .is_text_selection_enabled(true)
                    .max_lines(2)
                    .text_trimming(TextTrimming::CharacterEllipsis),
                findings(state),
            )),
        )
        .close_button_text("Close")
        .default_button(ContentDialogButton::Close)
        .on_closed(context.callback(|_: ContentDialogResult| Msg::FindingsClosed))
}

/// The dialog on show, if one is: the findings of a file the user asked for, else the result of
/// the newest scan that was asked to be shown and is not put away.
pub(in crate::ui) fn dialog(window: &MainWindow, context: Context<'_>) -> Option<ContentDialog> {
    if window.findings_open
        && let Some((path, state)) = &window.findings
    {
        return Some(found(path, state, context));
    }
    window
        .pending_reveal()
        .map(|reveal| result(window, reveal, context))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

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

    fn reveal(paths: &[&str]) -> Reveal {
        Reveal {
            seq: 1,
            paths: paths.iter().map(PathBuf::from).collect(),
            at: PathBuf::new(),
            select: None,
            state: RevealState::Scanning,
        }
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
        assert_eq!(scanned_what(&reveal(&[r"C:\Docs\a.pdf"])), r"C:\Docs\a.pdf");
        assert_eq!(
            scanned_what(&reveal(&[r"C:\Docs", r"C:\Mail", r"C:\Tax"])),
            r"C:\Docs and 2 other items"
        );
        assert_eq!(
            scanned_what(&reveal(&[r"C:\Docs", r"C:\Mail"])),
            r"C:\Docs and 1 other item"
        );
        assert!(scanned_what(&reveal(&[])).is_empty());
    }

    #[test]
    fn only_so_many_findings_are_listed_and_the_cut_is_said() {
        let finding = |i: usize| Finding {
            kind: EntityKind::Email,
            value: format!("a{i}@acme.nl").into(),
            snippet: "mail a@acme.nl now".into(),
        };
        let few: Vec<Finding> = (0..3).map(finding).collect();
        let (shown, cut) = listed(&few);
        assert_eq!((shown.len(), cut), (3, None));

        let many: Vec<Finding> = (0..MOST + 5).map(finding).collect();
        let (shown, cut) = listed(&many);
        assert_eq!(shown.len(), MOST);
        assert_eq!(cut.as_deref(), Some("Showing the first 200 of 205."));
    }
}
