//! The detection model: its first-run download, and loading it into memory while something needs
//! it and freeing it when nothing does.

use std::{
    sync::{Arc, PoisonError, Weak},
    thread,
    time::Instant,
};

use piikey::{detect::ner::files::FILES, policy::Highlight};

use super::{Command, Controller, Notice, PROGRESS_EVERY};

/// The notice after the user goes on without the model.
pub(super) const SKIPPED_TEXT: &str = "The detection model is not downloaded, so names, addresses and other free-text details are not masked. piikey downloads it next time it starts.";

/// Bytes the model download fetches in all.
pub(super) fn model_size() -> u64 {
    FILES.iter().map(|file| file.size).sum()
}

/// The detection model's download state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Model {
    /// On disk; loads when piikey turns on.
    Ready,
    /// The first-run download is running.
    Downloading { done: u64, total: u64 },
    /// The download failed with this message.
    Failed(String),
    /// The user went on without it; only patterns are masked.
    Skipped,
}

impl Controller {
    /// Downloads the model again after a failure.
    pub(super) fn refetch(self: &Arc<Self>) {
        let idle = self.update(|state| {
            let idle = !state.fetch.running && state.model != Model::Ready;
            if idle {
                state.model = Model::Downloading {
                    done: 0,
                    total: model_size(),
                };
            }
            idle
        });
        if idle {
            self.spawn_fetch();
        }
    }

    /// Goes on without the model. A saved "on" is honoured now, with the patterns alone.
    pub(super) fn skip_model(&self) {
        let resume = self.update(|state| {
            if state.model == Model::Ready {
                return None;
            }
            state.model = Model::Skipped;
            Some(std::mem::take(&mut state.fetch.then_start))
        });
        let Some(resume) = resume else {
            return;
        };
        if resume {
            self.resume();
        }
        // After the start, which clears the notices it finds. One that it leaves says why it did
        // not go well, and is worth more than this.
        self.update(|state| {
            if !resume || state.notice.is_none() {
                state.notice = Some(Notice::warning(SKIPPED_TEXT));
            }
        });
    }

    /// Starts the model download on its own thread unless one is running.
    pub(super) fn spawn_fetch(self: &Arc<Self>) {
        let started = self.update(|state| !std::mem::replace(&mut state.fetch.running, true));
        if !started {
            return;
        }
        let controller = Arc::downgrade(self);
        let spawned = thread::Builder::new()
            .name("piikey-model".into())
            .spawn(move || fetch_model(&controller));
        if let Err(error) = spawned {
            self.update(|state| {
                state.fetch.running = false;
                state.model =
                    Model::Failed(format!("Could not start the download thread: {error}"));
            });
        }
    }

    /// Loads the detection model while something needs it, and frees its memory when nothing
    /// does: protection, the highlight, the watch, a scan, the findings of a file.
    pub(super) fn sync_model(&self) {
        self.sync_model_with(false);
    }

    /// As [`Controller::sync_model`]; `starting` counts protection as on.
    pub(super) fn sync_model_with(&self, starting: bool) {
        let _one = self
            .model_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Read only now: a call that waited for the lock must not act on what it saw before the
        // call ahead of it changed it.
        let policy = self.policy();
        let (want, ready) = {
            let state = self.lock();
            (
                starting
                    || state.enabled
                    || policy.highlight != Highlight::Off
                    || (policy.watch && !policy.watch_folders.is_empty())
                    || state.scan.is_some()
                    || state.watch.scan.is_some()
                    || state.findings > 0,
                state.model == Model::Ready,
            )
        };
        if !want {
            self.backend.release_model();
        } else if ready && let Err(error) = self.backend.load_model() {
            self.notify(Notice::warning(format!(
                "The detection model could not load ({error}); only emails, phone numbers, IBANs and other patterns are masked."
            )));
        }
    }
}

/// Downloads the model, reports progress, and turns the app on afterwards when that is waiting.
fn fetch_model(controller: &Weak<Controller>) {
    let Some(controller) = controller.upgrade() else {
        return;
    };
    let mut reported: Option<Instant> = None;
    let outcome = controller.backend.fetch_model(&mut |done, total| {
        if reported.is_none_or(|at| at.elapsed() >= PROGRESS_EVERY) {
            reported = Some(Instant::now());
            controller.update(|state| {
                if matches!(state.model, Model::Downloading { .. }) {
                    state.model = Model::Downloading { done, total };
                }
            });
        }
    });
    let start = controller.update(|state| {
        state.fetch.running = false;
        match outcome {
            Ok(()) => {
                state.model = Model::Ready;
                std::mem::take(&mut state.fetch.then_start)
            }
            Err(error) => {
                state.model = Model::Failed(error);
                false
            }
        }
    });
    if start {
        controller.submit(Command::SetEnabled(true));
    } else {
        // The highlight and the inventory may have been waiting for the model.
        controller.sync_model();
    }
}
