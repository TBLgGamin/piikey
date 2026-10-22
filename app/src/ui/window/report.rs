//! What the window keeps for its two dialogs about what a scan found: the result of a scan that was
//! asked for (Explorer's "Scan for personal data", the Inventory page's box and "Scan this", the
//! API), and the list of what was found in one file.
//!
//! The controller decides when a scan is asked for and how far it is ([`Reveal`]); the window only
//! remembers which of them the user has seen and put away. The values a list shows come from running
//! the detection on the file when the list is asked for, and are dropped when its dialog closes.

use std::path::{Path, PathBuf};

use piikey::inventory::Finding;
use windows_reactor::ComponentContext;

use super::{MainWindow, Msg};
use crate::ui::controller::{Reveal, RevealState};

/// How far the reading of a file's findings is.
#[derive(Clone)]
pub enum FindingsState {
    /// The detection runs.
    Loading,
    /// What it found, in the order it is in the file.
    Loaded(Vec<Finding>),
    /// Why it could not be read.
    Failed(String),
}

/// The one file a scan was asked for, if it was one: the path of a request for a single file.
#[must_use]
pub fn single_file(reveal: &Reveal) -> Option<&Path> {
    match (reveal.paths.as_slice(), reveal.select.as_deref()) {
        ([_], Some(file)) => Some(file),
        _ => None,
    }
}

impl MainWindow {
    /// The newest scan that was asked to be shown and whose result the user has not put away.
    pub(in crate::ui) fn pending_reveal(&self) -> Option<&Reveal> {
        self.snap
            .reveal
            .as_ref()
            .filter(|reveal| reveal.seq > self.dismissed)
    }

    /// Looks at the newest scan request: when its result is in and is about one file that holds
    /// personal data, the findings of that file are read for the dialog.
    pub(super) fn follow_reveal(&mut self, context: &ComponentContext<Self>) {
        // The list of "Show what was found" holds the findings now.
        if self.findings_open {
            return;
        }
        let Some(reveal) = self.pending_reveal() else {
            return;
        };
        let RevealState::Done(summary) = &reveal.state else {
            return;
        };
        let Some(file) = single_file(reveal).filter(|_| summary.hits > 0) else {
            return;
        };
        if self.findings.as_ref().is_some_and(|(path, _)| path == file) {
            return;
        }
        let file = file.to_path_buf();
        self.show_findings(file, false, context);
    }

    /// Puts the newest scan request away: its dialog is not shown again. The findings that were
    /// read for it go with it, unless the list of "Show what was found" is on show.
    fn put_away_reveal(&mut self) {
        if let Some(reveal) = &self.snap.reveal {
            self.dismissed = self.dismissed.max(reveal.seq);
        }
        if !self.findings_open {
            self.findings = None;
        }
    }

    /// The dialogs' own messages. [`Component::update`](windows_reactor::Component::update) routes
    /// them here.
    pub(super) fn update_report(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::ReportClose => self.put_away_reveal(),
            Msg::ReportShow => {
                let target: Option<(PathBuf, Option<PathBuf>)> = self
                    .pending_reveal()
                    .map(|reveal| (reveal.at.clone(), reveal.select.clone()));
                self.put_away_reveal();
                if let Some((at, select)) = target {
                    self.show_in_inventory(at, select, context);
                }
            }
            // The dialog may have closed, or asked for another file, while it was read.
            Msg::FindingsLoaded(path, result)
                if self
                    .findings
                    .as_ref()
                    .is_some_and(|(wanted, _)| *wanted == path) =>
            {
                let state = match result {
                    Ok(list) => FindingsState::Loaded(list),
                    Err(error) => FindingsState::Failed(error),
                };
                self.findings = Some((path, state));
            }
            Msg::FindingsClosed => {
                self.findings_open = false;
                self.findings = None;
            }
            _ => {}
        }
    }
}
