//! What the window keeps for the dialog of a scan that was asked for (Explorer's "Scan for
//! personal data", the Inventory page's box and "Scan this", the API).
//!
//! The controller decides when a scan is asked for and how far it is ([`Reveal`]); the window only
//! remembers which of them the user has seen and put away. What was found, value by value, is the
//! findings view's: see [`findings`](super::findings).

use std::path::PathBuf;

use windows_reactor::ComponentContext;

use super::{MainWindow, Msg};
use crate::ui::controller::{Command, Reveal, RevealState};

impl MainWindow {
    /// The newest scan that was asked to be shown and whose result the user has not put away.
    pub(in crate::ui) fn pending_reveal(&self) -> Option<&Reveal> {
        self.snap
            .reveal
            .as_ref()
            .filter(|reveal| reveal.seq > self.dismissed)
    }

    /// Puts the newest scan request away: its dialog is not shown again.
    fn put_away_reveal(&mut self) {
        if let Some(reveal) = &self.snap.reveal {
            self.dismissed = self.dismissed.max(reveal.seq);
        }
    }

    /// The dialog's own messages. [`Component::update`](windows_reactor::Component::update) routes
    /// them here.
    pub(super) fn update_report(&mut self, message: &Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::ReportClose => {
                // Closing the dialog of a scan that waits or runs stops it.
                if let Some(reveal) = self.pending_reveal()
                    && matches!(reveal.state, RevealState::Waiting | RevealState::Scanning)
                {
                    self.input.controller.submit(Command::StopScan(reveal.seq));
                }
                self.put_away_reveal();
            }
            Msg::ReportShow => {
                let target: Option<(PathBuf, Option<PathBuf>)> = self
                    .pending_reveal()
                    .map(|reveal| (reveal.at.clone(), reveal.select.clone()));
                self.put_away_reveal();
                if let Some((at, select)) = target {
                    self.show_in_inventory(at, select, context);
                }
            }
            Msg::ReportFound => {
                let roots: Option<Vec<PathBuf>> =
                    self.pending_reveal().map(|reveal| reveal.paths.clone());
                self.put_away_reveal();
                // A scan goes into the main inventory, which knows which files of a folder hold what.
                if let Some(roots) = roots {
                    self.open_findings(roots, context);
                }
            }
            _ => {}
        }
    }
}
