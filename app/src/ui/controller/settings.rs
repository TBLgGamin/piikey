//! Following the settings: an edit or the API's patch is saved, becomes the live policy, and what
//! depends on it (the engine's kinds, the Explorer menu, the local API, the inventory, the
//! highlight and the detection model) is brought in line.

use std::sync::{Arc, PoisonError};

use piikey::policy::{Highlight, Policy, SettingsPatch};

use super::{Controller, Edit, Notice, apply_edit};

impl Controller {
    pub(super) fn edit(self: &Arc<Self>, edit: &Edit) {
        let mut policy = self.policy();
        match apply_edit(&mut policy, edit) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                self.notify(Notice::error(error));
                return;
            }
        }
        self.commit(&policy);
    }

    /// Applies the settings the API sent, as a whole: a patch with a bad value changes nothing.
    pub(super) fn settings(self: &Arc<Self>, patch: &SettingsPatch) {
        let mut policy = self.policy();
        let before = policy.clone();
        if let Err(error) = patch.apply(&mut policy) {
            self.notify(Notice::error(error.to_string()));
            return;
        }
        if policy != before {
            self.commit(&policy);
        }
    }

    /// Saves `policy` and makes it the live settings.
    fn commit(self: &Arc<Self>, policy: &Policy) {
        let old = self.policy();
        // Everything that can fail happens before the live state changes, so a failure leaves
        // the old settings fully in place.
        if let Err(error) = self.backend.save_policy(policy) {
            self.notify(Notice::error(format!("Could not save settings: {error}")));
            return;
        }
        self.adopt_policy(&old, policy);
    }

    /// Makes `new` the live settings and brings in line what depends on them, for what changed
    /// from `old`: the engine's kinds, the Explorer menu, the local API, the inventory, the
    /// highlight and the detection model.
    fn adopt_policy(self: &Arc<Self>, old: &Policy, new: &Policy) {
        self.engine().set_enabled(new.enabled_kinds());
        *self
            .shared
            .policy
            .write()
            .unwrap_or_else(PoisonError::into_inner) = new.clone();
        if new.explorer_menu != old.explorer_menu {
            self.sync_explorer_menu(new.explorer_menu);
        }
        if (new.http_api, new.http_port) != (old.http_api, old.http_port) {
            self.sync_http();
        }
        if new.inventory != old.inventory
            || new.inventory_roots != old.inventory_roots
            || new.inventory_exclude != old.inventory_exclude
        {
            self.sync_inventory(old, new);
        }
        if new.highlight != old.highlight {
            self.sync_highlight(new.highlight);
        }
        if new.highlight != old.highlight || new.inventory != old.inventory {
            self.sync_model();
        }
        self.update(|_| {});
    }

    /// Starts what the saved settings ask for, as if the user had just switched each on.
    pub(super) fn startup(self: &Arc<Self>) {
        let policy = self.policy();
        let off = Policy {
            highlight: Highlight::Off,
            explorer_menu: false,
            inventory: false,
            http_api: false,
            ..policy.clone()
        };
        self.adopt_policy(&off, &policy);
    }

    /// Adds or removes the Explorer menu. Registering again also points it at this exe, which a
    /// portable install that moved needs.
    fn sync_explorer_menu(&self, on: bool) {
        if let Err(error) = self.backend.set_explorer_menu(on) {
            self.notify(Notice::error(format!(
                "Could not update the Explorer menu: {error}"
            )));
        }
    }

    /// Starts, restarts or stops the local API to match the settings.
    fn sync_http(&self) {
        let policy = self.policy();
        if let Some(running) = self.update(|state| state.http.take()) {
            running.stop();
        }
        if !policy.http_api {
            return;
        }
        let started = self
            .token(false)
            .and_then(|token| self.backend.start_http(policy.http_port, token));
        match started {
            Ok(http) => self.update(|state| state.http = Some(http)),
            Err(error) => self.notify(Notice::error(format!(
                "Could not start the local API on 127.0.0.1:{}: {error}",
                policy.http_port
            ))),
        }
    }

    /// The token changed: the local API, when it runs, starts again to ask for the new one.
    pub(super) fn restart_http(&self) {
        if self.lock().http.is_some() {
            self.sync_http();
        }
    }

    /// Makes capture, the outline and its shortcut follow the highlight setting.
    fn sync_highlight(&self, mode: Highlight) {
        self.shared.purpose.set_highlight(mode);
        if let Some(error) = self.sync_capture(false) {
            self.highlight_failed(&error);
        }
        if let Err(error) = self
            .backend
            .set_hotkey(&self.shared, mode != Highlight::Off)
        {
            self.notify(Notice::warning(error));
        }
    }

    /// The focused field cannot be read, so the highlight shows nothing.
    pub(super) fn highlight_failed(&self, error: &str) {
        self.notify(Notice::warning(format!(
            "piikey could not read the focused field ({error}); highlighting is off."
        )));
    }

    /// Starts or stops capture so that it runs exactly while protection or the highlight needs
    /// it; `starting` counts protection as on. `Some(error)` when it could not start.
    pub(super) fn sync_capture(&self, starting: bool) -> Option<String> {
        let highlight = self.policy().highlight != Highlight::Off;
        let (want, running) = {
            let state = self.lock();
            (
                starting || state.enabled || highlight,
                state.capture.is_some(),
            )
        };
        if want == running {
            return None;
        }
        if want {
            return match self.backend.start_capture(Arc::clone(&self.shared)) {
                Ok(capture) => {
                    self.update(|state| state.capture = Some(capture));
                    None
                }
                Err(error) => Some(error),
            };
        }
        if let Some(capture) = self.update(|state| state.capture.take()) {
            capture.stop();
        }
        None
    }
}
