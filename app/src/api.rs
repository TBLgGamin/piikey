//! `AppApi`: the API as the app serves it, on the named pipe and over local HTTP.
//!
//! [`Local`] answers most of it from the engine and the inventory the app uses. What only the app
//! can do, or what must reach the rest of the app, goes through the controller: protection,
//! settings (so the features follow them), Explorer scans, the inventory's status and rescan (the
//! scans are the controller's), what removes values from the vault (so what was typed is forgotten
//! too) and the model's download (so its state is the app's).

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use piikey::{
    Error,
    api::{ApiError, Handler, Local, Request},
    detect::NerDetector,
    policy::{SettingsPatch, default_inventory_roots},
};
use serde_json::{Value, json};

use crate::ui::controller::{Command, Controller, Model, Snapshot};

/// How long a call waits for the controller to finish what it asked for.
const WAIT: Duration = Duration::from_mins(1);
/// How often a call that waits for a scan or a download looks again.
const LOOK: Duration = Duration::from_secs(2);

/// The API of the running app; see the module docs.
pub struct AppApi {
    local: Local,
    /// Weak: the controller owns the backend that serves this handler over HTTP.
    controller: Weak<Controller>,
}

impl AppApi {
    /// The handler over `controller`'s engine and inventory. `ner` is the detection model the
    /// engine detects with.
    pub fn new(controller: &Arc<Controller>, ner: NerDetector) -> Self {
        Self::with_local(
            controller,
            Local::new(
                controller.engine_source(),
                controller.inventory(),
                Some(ner),
            ),
        )
    }

    fn with_local(controller: &Arc<Controller>, local: Local) -> Self {
        Self {
            local,
            controller: Arc::downgrade(controller),
        }
    }

    fn controller(&self) -> Result<Arc<Controller>, ApiError> {
        self.controller
            .upgrade()
            .ok_or_else(|| ApiError::internal("piikey is shutting down"))
    }

    /// Switches protection and says how it stands. Turning it on can fail for a reason the user
    /// has to fix (the certificate, the port); the reason is the error.
    fn protection(&self, on: bool) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        controller.submit(Command::SetEnabled(on));
        if !controller.wait_idle(WAIT) {
            return Err(ApiError::busy("piikey is still switching protection"));
        }
        let snapshot = controller.snapshot();
        if snapshot.enabled != on {
            return Err(ApiError::internal(why_not(
                &snapshot,
                "protection could not be switched",
            )));
        }
        Ok(json!({ "protection": snapshot.enabled }))
    }

    fn status(&self) -> Result<Value, ApiError> {
        let mut status = self.local.handle(Request::Status)?;
        let protection = self.controller()?.snapshot().enabled;
        if let Value::Object(fields) = &mut status {
            fields.insert("app".to_owned(), Value::Bool(true));
            fields.insert("protection".to_owned(), Value::Bool(protection));
        }
        Ok(status)
    }

    fn settings_get(&self) -> Result<Value, ApiError> {
        serde_json::to_value(&self.controller()?.snapshot().policy)
            .map_err(|error| encode_error(&error))
    }

    /// Applies the patch through the controller, so the Explorer menu, the highlight, the
    /// inventory and the local API follow it, and answers with the settings as they are then.
    fn settings_set(&self, patch: &SettingsPatch) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        let mut expected = controller.snapshot().policy;
        patch.apply(&mut expected)?;
        controller.submit(Command::Settings(patch.clone()));
        // The listener of this very request may be the one that restarts: it waits for the request
        // to end, so the answer goes out first and the change follows.
        if patch.http_api.is_none() && patch.http_port.is_none() {
            if !controller.wait_idle(WAIT) {
                return Err(ApiError::busy("piikey is still applying the settings"));
            }
            let snapshot = controller.snapshot();
            // Protection may have been switched meanwhile; it is no setting of the patch.
            let mut live = snapshot.policy.clone();
            live.enabled = expected.enabled;
            if live != expected {
                return Err(ApiError::internal(why_not(
                    &snapshot,
                    "the settings could not be saved",
                )));
            }
        }
        serde_json::to_value(&expected).map_err(|error| encode_error(&error))
    }

    fn explorer_scan(&self, paths: Vec<PathBuf>) -> Result<Value, ApiError> {
        if paths.is_empty() {
            return Err(ApiError::bad_request("explorer_scan needs a path"));
        }
        for path in &paths {
            exists(path)?;
        }
        self.controller()?.submit(Command::ScanFiles {
            paths,
            reveal: true,
        });
        Ok(json!({}))
    }

    fn inventory_status(&self) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        let snapshot = controller.snapshot();
        let totals = controller.inventory().totals();
        let roots = if snapshot.policy.inventory_roots.is_empty() {
            default_inventory_roots()
        } else {
            snapshot.policy.inventory_roots.clone()
        };
        let roots: Vec<String> = roots
            .iter()
            .map(|root| root.to_string_lossy().into_owned())
            .collect();
        let scanning = snapshot
            .scan
            .map(|(done, total)| json!({ "done": done, "total": total }));
        Ok(json!({
            "enabled": snapshot.policy.inventory,
            "roots": roots,
            "files": totals.files,
            "files_with_pii": totals.files_with_pii,
            "hits": totals.hits,
            "scanning": scanning,
        }))
    }

    /// Scans the watched folders now and answers when the scan is over.
    fn inventory_rescan(&self) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        controller.submit(Command::Rescan);
        // The command has queued the scan once the controller is idle.
        if !controller.wait_idle(WAIT) {
            return Err(ApiError::busy("piikey is still starting the scan"));
        }
        // A scan of a big folder takes as long as it takes.
        while !controller.wait_scans(LOOK) {}
        serde_json::to_value(controller.inventory().totals()).map_err(|error| encode_error(&error))
    }

    /// Downloads the detection model, and answers when it is there. The controller does it, so
    /// the app's model state and its loading screen follow.
    fn model_download(&self) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        controller.submit(Command::FetchModel);
        // The command has started the download once the controller is idle.
        if !controller.wait_idle(WAIT) {
            return Err(ApiError::busy("piikey is still starting the download"));
        }
        let mut snapshot = controller.snapshot();
        loop {
            match &snapshot.model {
                Model::Ready => return Ok(json!({})),
                Model::Failed(message) => return Err(Error::Model(message.clone()).into()),
                Model::Skipped => {
                    return Err(
                        Error::Model("the detection model is not downloaded".to_owned()).into(),
                    );
                }
                Model::Downloading { .. } => {}
            }
            snapshot = controller
                .wait_changed(snapshot.version, LOOK)
                .unwrap_or_else(|| controller.snapshot());
        }
    }

    /// The model as [`Local`] sees it, with the download the controller runs, or that failed.
    fn model_status(&self) -> Result<Value, ApiError> {
        let mut status = self.local.handle(Request::ModelStatus)?;
        let Value::Object(fields) = &mut status else {
            return Ok(status);
        };
        match self.controller()?.snapshot().model {
            Model::Downloading { done, total } => {
                fields.insert("state".to_owned(), json!("missing"));
                fields.insert(
                    "downloading".to_owned(),
                    json!({ "done": done, "total": total }),
                );
            }
            Model::Failed(message) => {
                fields.insert("state".to_owned(), json!("failed"));
                fields.insert("error".to_owned(), json!(message));
            }
            Model::Ready | Model::Skipped => {}
        }
        Ok(status)
    }

    /// A new token also restarts the local API, which keeps the token it started with.
    fn rotate_token(&self) -> Result<Value, ApiError> {
        let token = self
            .controller()?
            .rotate_token()
            .map_err(ApiError::internal)?;
        Ok(json!({ "token": token }))
    }

    /// Asks `request` of [`Local`], then lets the app know the vault lost records.
    fn forget(&self, request: Request) -> Result<Value, ApiError> {
        let reply = self.local.handle(request)?;
        self.controller()?.vault_changed();
        Ok(reply)
    }

    /// Asks `request` of [`Local`], then lets the app know the inventory changed.
    fn scan_files(&self, paths: Vec<PathBuf>, record: bool) -> Result<Value, ApiError> {
        let reply = self.local.handle(Request::ScanFiles { paths, record })?;
        if record {
            self.controller()?.submit(Command::Refresh);
        }
        Ok(reply)
    }
}

impl Handler for AppApi {
    fn handle(&self, request: Request) -> Result<Value, ApiError> {
        match request {
            Request::Protection { on } => self.protection(on),
            Request::Status => self.status(),
            Request::SettingsGet => self.settings_get(),
            Request::SettingsSet { settings } => self.settings_set(&settings),
            Request::ExplorerScan { paths } => self.explorer_scan(paths),
            Request::InventoryStatus => self.inventory_status(),
            Request::InventoryRescan => self.inventory_rescan(),
            Request::ModelStatus => self.model_status(),
            Request::ModelDownload => self.model_download(),
            Request::ApiToken { rotate: true } => self.rotate_token(),
            Request::ScanFiles { paths, record } => self.scan_files(paths, record),
            Request::VaultForget { .. } | Request::VaultWipe { .. } => self.forget(request),
            other => self.local.handle(other),
        }
    }
}

/// Why the controller did not do what it was asked: the notice it raised, or `otherwise`.
fn why_not(snapshot: &Snapshot, otherwise: &str) -> String {
    snapshot
        .notice
        .as_ref()
        .map_or_else(|| otherwise.to_owned(), |notice| notice.text.clone())
}

/// `path` is a full path to something that exists.
fn exists(path: &Path) -> Result<(), ApiError> {
    if !path.is_absolute() {
        return Err(ApiError::bad_request(format!(
            "{} is not a full path: a path must start with a drive or a share",
            path.display()
        )));
    }
    match path.try_exists() {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::not_found(format!(
            "{} does not exist",
            path.display()
        ))),
        Err(error) => Err(Error::Io(error).into()),
    }
}

/// A value that cannot be turned into JSON, which is a bug.
fn encode_error(error: &serde_json::Error) -> ApiError {
    ApiError::internal(format!("cannot encode the result: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Instant};

    use super::*;
    use crate::ui::testing::{TempDir, stub_controller};

    type Test = Result<(), String>;

    /// The API over a controller that runs on a stub system, in `dir`.
    fn api(dir: &TempDir) -> Result<(AppApi, Arc<Controller>), String> {
        let controller = stub_controller(dir)?;
        let local = Local::new(controller.engine_source(), controller.inventory(), None)
            .with_model_dir(dir.0.join("model"));
        Ok((AppApi::with_local(&controller, local), controller))
    }

    fn ask(api: &AppApi, request: Request) -> Result<Value, String> {
        api.handle(request)
            .map_err(|error| format!("{}: {error}", error.code()))
    }

    fn refused(api: &AppApi, request: Request) -> Result<(String, String), String> {
        match api.handle(request) {
            Ok(value) => Err(format!("it should have been refused: {value}")),
            Err(error) => Ok((error.code().to_owned(), error.message().to_owned())),
        }
    }

    #[test]
    fn protection_is_switched_through_the_controller() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let on = ask(&api, Request::Protection { on: true })?;
        assert_eq!(on, json!({ "protection": true }));
        assert!(controller.snapshot().enabled);
        let off = ask(&api, Request::Protection { on: false })?;
        assert_eq!(off, json!({ "protection": false }));
        assert!(!controller.snapshot().enabled);
        Ok(())
    }

    #[test]
    fn settings_are_applied_validated_and_answered_as_saved() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let patch = SettingsPatch {
            sites: Some(vec!["Example.com".into()]),
            ..SettingsPatch::default()
        };
        let saved = ask(&api, Request::SettingsSet { settings: patch })?;
        assert_eq!(saved["sites"], json!(["example.com"]));
        assert_eq!(controller.snapshot().policy.sites, ["example.com"]);
        assert_eq!(ask(&api, Request::SettingsGet)?["sites"], saved["sites"]);

        let bad = SettingsPatch {
            sites: Some(vec!["not a site".into()]),
            ..SettingsPatch::default()
        };
        let (code, message) = refused(&api, Request::SettingsSet { settings: bad })?;
        assert_eq!(code, "bad_request");
        assert!(message.contains("not a site"), "{message}");
        assert_eq!(controller.snapshot().policy.sites, ["example.com"]);
        Ok(())
    }

    #[test]
    fn a_change_of_the_listener_answers_before_it_restarts() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let patch = SettingsPatch {
            http_port: Some(8123),
            ..SettingsPatch::default()
        };
        let saved = ask(&api, Request::SettingsSet { settings: patch })?;
        assert_eq!(saved["http_port"], 8123);
        assert!(controller.wait_idle(Duration::from_secs(20)));
        assert_eq!(controller.snapshot().policy.http_port, 8123);
        Ok(())
    }

    #[test]
    fn an_explorer_scan_needs_full_paths_that_exist() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let scan = |paths: Vec<PathBuf>| Request::ExplorerScan { paths };
        assert_eq!(refused(&api, scan(vec![]))?.0, "bad_request");
        assert_eq!(refused(&api, scan(vec!["a.txt".into()]))?.0, "bad_request");
        let (code, message) = refused(&api, scan(vec![dir.0.join("missing")]))?;
        assert_eq!(code, "not_found");
        assert!(message.contains("missing"), "{message}");

        let file = dir.0.join("a.txt");
        fs::write(&file, "mail jan.jansen@acme.nl").map_err(|e| e.to_string())?;
        assert_eq!(ask(&api, scan(vec![file.clone()]))?, json!({}));
        let deadline = Instant::now() + Duration::from_secs(20);
        let reveal = loop {
            if let Some(reveal) = controller.reveal() {
                break reveal;
            }
            if Instant::now() > deadline {
                return Err("the scan never asked to be shown".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(reveal.select, Some(file));
        Ok(())
    }

    #[test]
    fn the_inventory_status_comes_from_the_controller() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let docs = dir.0.join("docs");
        fs::create_dir(&docs).map_err(|e| e.to_string())?;
        fs::write(docs.join("a.txt"), "mail jan.jansen@acme.nl").map_err(|e| e.to_string())?;
        let patch = SettingsPatch {
            inventory_roots: Some(vec![docs]),
            ..SettingsPatch::default()
        };
        ask(&api, Request::SettingsSet { settings: patch })?;
        let status = ask(&api, Request::InventoryStatus)?;
        assert_eq!(status["enabled"], false);
        assert_eq!(status["files"], 0);
        assert_eq!(status["scanning"], Value::Null);
        // A rescan answers when it is over, with what the inventory holds.
        let totals = ask(&api, Request::InventoryRescan)?;
        assert_eq!(totals["files_with_pii"], 1);
        assert_eq!(totals["hits"], 1);
        let status = ask(&api, Request::InventoryStatus)?;
        assert_eq!(status["files"], 1);
        assert_eq!(status["hits"], 1);
        assert_eq!(controller.snapshot().inventory_totals, (1, 1));
        Ok(())
    }

    #[test]
    fn forgetting_through_the_api_refreshes_the_app() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        controller
            .engine()
            .run(
                piikey::detect::Mode::Anonymize,
                &["mail jan.jansen@acme.nl"],
            )
            .map_err(|e| e.to_string())?;
        controller.submit(Command::Refresh);
        assert!(controller.wait_idle(Duration::from_secs(20)));
        assert_eq!(controller.snapshot().issued, 1);
        let forgotten = ask(
            &api,
            Request::VaultForget {
                values: vec!["jan.jansen@acme.nl".to_owned()],
            },
        )?;
        assert_eq!(forgotten["forgotten"], 1);
        assert!(controller.wait_idle(Duration::from_secs(20)));
        assert_eq!(controller.snapshot().issued, 0);
        Ok(())
    }

    #[test]
    fn what_local_answers_alone_is_passed_on() -> Test {
        let dir = TempDir::new()?;
        let (api, _controller) = api(&dir)?;
        let reply = ask(
            &api,
            Request::ScanText {
                texts: vec!["mail jan.jansen@acme.nl".to_owned()],
            },
        )?;
        assert_eq!(reply["results"][0][0]["kind"], "email");
        Ok(())
    }
}
