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

/// When a detection model that nothing needs may go (see [`Controller::sync_model_after_use`]),
/// and whether a thread is on its way to look at that time.
#[derive(Debug, Default)]
pub(super) struct Hold {
    until: Option<Instant>,
    timer: bool,
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
    /// does: protection, the highlight, monitoring, a scan, the findings of a file.
    pub(super) fn sync_model(&self) {
        self.sync_model_with(false);
    }

    /// As [`Controller::sync_model`]; `starting` counts protection as on. A model that nothing
    /// needs is freed now, whatever a scan that ended before asked it to wait for.
    pub(super) fn sync_model_with(&self, starting: bool) {
        let mut hold = self
            .model_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        hold.until = None;
        let (want, ready) = self.model_wanted(starting);
        if !want {
            self.backend.release_model();
        } else if ready {
            self.load_model_or_say_so();
        }
    }

    /// [`Controller::sync_model`] for the end of a scan or of a read of findings: a model that
    /// nothing needs any more stays in memory for [`Backend::model_idle`], with what it learned of
    /// the texts it read. What follows a scan is mostly a look at what it found, which reads the
    /// same texts again: with the model still there it costs no run of the model at all, and no
    /// seconds to load it.
    pub(super) fn sync_model_after_use(&self) {
        let mut hold = self
            .model_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (want, ready) = self.model_wanted(false);
        if want {
            hold.until = None;
            if ready {
                self.load_model_or_say_so();
            }
            return;
        }
        let now = Instant::now();
        let until = *hold.until.get_or_insert(now + self.backend.model_idle());
        if now >= until {
            hold.until = None;
            self.backend.release_model();
        } else if !hold.timer {
            hold.timer = true;
            let me = self.me.clone();
            let pause = until - now;
            let spawned = thread::Builder::new()
                .name("piikey-model-idle".into())
                .spawn(move || {
                    thread::sleep(pause);
                    if let Some(controller) = me.upgrade() {
                        controller.model_idle_elapsed();
                    }
                });
            if spawned.is_err() {
                hold.timer = false;
                hold.until = None;
                self.backend.release_model();
            }
        }
    }

    /// The time a model that nothing needed was kept is up, or may be: look again.
    fn model_idle_elapsed(&self) {
        self.model_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .timer = false;
        self.sync_model_after_use();
    }

    /// Whether something wants the model now, and whether it can be loaded (it is downloaded).
    /// Read only when the caller holds `model_sync`: a call that waited for the lock must not act
    /// on what it saw before the call ahead of it changed it.
    fn model_wanted(&self, starting: bool) -> (bool, bool) {
        let policy = self.policy();
        let state = self.lock();
        (
            starting
                || state.enabled
                || policy.highlight != Highlight::Off
                || !policy.monitored_roots.is_empty()
                || state.scan.is_some()
                || state.watch.scan.is_some()
                || state.findings > 0,
            state.model == Model::Ready,
        )
    }

    /// Loads the model; says so when that fails.
    fn load_model_or_say_so(&self) {
        if let Err(error) = self.backend.load_model() {
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
