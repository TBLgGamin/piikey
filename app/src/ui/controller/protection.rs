//! Turning the app on and off, and the certificate: the commands that start and stop the proxy,
//! point Windows at it and give Windows its settings back.

use std::sync::Arc;

use super::{Busy, Controller, Model, Notice, Severity, cert_of, follow};
use crate::proxy::PORT;

impl Controller {
    pub(super) fn start(&self) {
        let (downloading, on) = self.update(|state| {
            let downloading = matches!(state.model, Model::Downloading { .. });
            if downloading {
                // The download turns the app on when it is done.
                state.fetch.then_start = true;
                state.notice = Some(Notice::warning(
                    "piikey turns on as soon as the model has downloaded.",
                ));
            }
            (downloading, state.enabled)
        });
        if downloading || on {
            return;
        }
        self.update(|state| {
            state.busy = Some(Busy::Starting);
            state.notice = None;
        });
        if let Err(notice) = self.try_start() {
            // Off again: the model must not hold memory, unless something else keeps it busy.
            self.sync_model();
            self.update(|state| state.notice = Some(notice));
        }
    }

    /// Starts the app the way the user left it. When that fails, Windows must not stay pointed
    /// at a proxy nobody serves (a session that was killed leaves exactly that), so it gets its
    /// settings back, and the saved settings change to off, which is what the app now is.
    pub(super) fn resume(&self) {
        self.start();
        if self.lock().enabled {
            return;
        }
        if let Err(error) = self.backend.disable_system_proxy() {
            self.add_error(&format!(
                "Windows may still point at piikey's proxy: {error}."
            ));
        }
        if let Err(error) = self.backend.save_policy(&self.policy()) {
            self.add_error(&format!("Could not save settings: {error}."));
        }
    }

    /// Shows `text` as an error after the notice that is showing, which is usually its cause.
    fn add_error(&self, text: &str) {
        self.update(|state| state.notice = Some(follow(state.notice.take(), text)));
    }

    fn try_start(&self) -> Result<(), Notice> {
        self.backend.ensure_ca().map_err(|error| {
            Notice::error(format!("Could not prepare the certificate: {error}"))
        })?;
        let installed = self.backend.ca_installed();
        self.update(|state| state.cert = cert_of(installed));
        if !installed {
            return Err(Notice::warning(
                "Install the piikey certificate first, then turn piikey on.",
            ));
        }
        self.sync_model_with(true);
        self.set_live(true);
        let proxy = match self
            .backend
            .start_proxy(Arc::clone(&self.shared), self.events.clone())
        {
            Ok(proxy) => proxy,
            Err(error) => {
                self.set_live(false);
                return Err(Notice::error(format!(
                    "Could not start the proxy on 127.0.0.1:{PORT}: {error}"
                )));
            }
        };
        if let Err(error) = self.backend.enable_system_proxy() {
            proxy.stop();
            self.set_live(false);
            return Err(Notice::error(format!(
                "Could not point Windows at the proxy: {error}"
            )));
        }
        if let Some(error) = self.sync_capture(true) {
            // The store stays inactive, so the proxy checks whole requests instead.
            let text = format!(
                "piikey could not read what you type ({error}), so it checks whole requests instead; some sites may not work fully."
            );
            self.update(|state| {
                let mut notice = follow(state.notice.take(), &text);
                notice.severity = Severity::Warning;
                state.notice = Some(notice);
            });
        }
        self.update(|state| {
            state.enabled = true;
            state.proxy = Some(proxy);
        });
        self.persist();
        Ok(())
    }

    /// `reason` is `Some` when the proxy died, `None` when the user asked.
    pub(super) fn stop(&self, reason: Option<String>) {
        // Turning off also cancels a start that waits for the model download.
        let enabled = self.update(|state| {
            state.fetch.then_start = false;
            state.enabled
        });
        if !enabled {
            return;
        }
        self.update(|state| state.busy = Some(Busy::Stopping));
        // Windows first: while it still routes through the proxy, stopping the proxy would cut
        // the connection.
        let restored = self.backend.disable_system_proxy();
        if let (Err(error), None) = (&restored, &reason) {
            self.update(|state| {
                state.notice = Some(Notice::error(format!(
                    "Could not restore the Windows proxy settings: {error}. piikey stays on."
                )));
            });
            return;
        }
        self.set_live(false);
        let proxy = self.update(|state| {
            state.enabled = false;
            state.proxy.take()
        });
        if let Some(proxy) = proxy {
            proxy.stop();
        }
        // After the proxy: the requests it still serves are masked as before. Capture goes on
        // while the highlight needs it.
        if let Some(error) = self.sync_capture(false) {
            self.highlight_failed(&error);
        }
        self.sync_model();
        self.persist();
        if let Some(reason) = reason {
            let text = match restored {
                Ok(()) => format!("piikey turned itself off: {reason}"),
                Err(error) => format!(
                    "piikey turned itself off: {reason}. Windows still points at the proxy: {error}"
                ),
            };
            self.update(|state| state.notice = Some(Notice::error(text)));
        }
    }

    pub(super) fn install(&self) {
        self.update(|state| {
            state.busy = Some(Busy::InstallingCertificate);
            state.notice = None;
        });
        let outcome = self
            .backend
            .ensure_ca()
            .and_then(|()| self.backend.install_ca());
        let installed = self.backend.ca_installed();
        self.update(|state| {
            state.cert = cert_of(installed);
            state.notice = match outcome {
                Err(error) => Some(Notice::error(format!(
                    "Could not install the certificate: {error}"
                ))),
                Ok(()) if !installed => Some(Notice::warning(
                    "Windows did not add the certificate to your trusted roots.",
                )),
                Ok(()) => None,
            };
        });
    }

    pub(super) fn refresh(&self) {
        let installed = self.backend.ca_installed();
        // Before the summary: it lists what the feed still knows.
        self.prune_activity();
        let summary = self.vault_summary();
        let totals = self.inventory.totals();
        self.update(|state| {
            state.cert = cert_of(installed);
            state.inventory_totals = totals;
            summary.apply(state);
        });
    }

    /// Writes the live settings to disk; a failure becomes a notice.
    fn persist(&self) {
        if let Err(error) = self.backend.save_policy(&self.policy()) {
            self.update(|state| {
                state.notice = Some(Notice::error(format!("Could not save settings: {error}")));
            });
        }
    }
}
