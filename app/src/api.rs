//! `AppApi`: the API as the app serves it, on the named pipe and over local HTTP.
//!
//! [`Local`] answers most of it from the engine, the inventory and the settings the app uses. What
//! only the app can do, or what must reach the rest of the app, goes through the controller:
//! protection, settings (so the features follow them), Explorer scans, the inventory's rescan (the
//! scans are the controller's), what removes values from the vault (so what was typed is forgotten
//! too), the model's download (so its state is the app's) and the cloud accounts (so the window's
//! list, the locations and the notices follow them, and the app opens the browser to sign in).
//! File work runs in the pool of the app's own scans, so it leaves half the cores to the PC.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Weak, atomic::AtomicBool},
    time::Duration,
};

use piikey::{
    Error,
    api::{
        ApiError, Handler, Local, PolicySource, Request,
        reply::{self, ModelState},
        require_absolute, require_on_this_pc, to_json,
    },
    detect::NerDetector,
    policy::SettingsPatch,
    sources::{Account, Provider, SignIn},
    sys,
};
use serde_json::{Value, json};

use crate::ui::controller::{
    AccountStatus, AccountView, Command, Controller, Model, NewAccount, Snapshot,
};

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

    /// `local` answers from the settings the app holds, not from the file: they are the ones that
    /// apply while a change is still being saved.
    fn with_local(controller: &Arc<Controller>, local: Local) -> Self {
        let controller = Arc::downgrade(controller);
        let settings: PolicySource = Arc::new({
            let controller = Weak::clone(&controller);
            move || {
                controller
                    .upgrade()
                    .map(|controller| controller.policy())
                    .ok_or_else(|| Error::Busy("piikey is shutting down".to_owned()))
            }
        });
        Self {
            local: local.with_policy(settings),
            controller,
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
        to_json(&reply::Protection {
            protection: snapshot.enabled,
        })
    }

    /// What [`Local`] says, with what only the app knows: that it runs, whether protection is on
    /// and how the model's download stands.
    fn status(&self) -> Result<Value, ApiError> {
        let snapshot = self.controller()?.snapshot();
        let mut status = self.local.status()?;
        status.app = true;
        status.protection = Some(snapshot.enabled);
        follow_download(&mut status.model, snapshot.model);
        to_json(&status)
    }

    /// Applies the patch through the controller, so the Explorer menu, the highlight, the
    /// inventory and the local API follow it, and answers with the settings as they are then.
    fn settings_set(&self, patch: &SettingsPatch) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        let mut expected = controller.policy();
        controller.apply_patch(patch, &mut expected)?;
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
        to_json(&expected)
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

    /// Asks the app thread to bring the window forward.
    fn show_window(&self) -> Result<Value, ApiError> {
        self.controller()?.request_window();
        Ok(json!({}))
    }

    /// The accounts as the controller lists them, read again first: the command line, run on its
    /// own, may have added one since the app last looked.
    fn account_views(controller: &Controller) -> Result<Vec<AccountView>, ApiError> {
        controller.submit(Command::Refresh);
        if !controller.wait_idle(WAIT) {
            return Err(ApiError::busy("piikey is still reading the accounts"));
        }
        Ok(controller.accounts())
    }

    /// The account with this id, or `not_found`.
    fn account_view(controller: &Controller, id: &str) -> Result<AccountView, ApiError> {
        Self::account_views(controller)?
            .into_iter()
            .find(|view| view.account.id == id)
            .ok_or_else(|| ApiError::not_found(format!("no cloud account has the id {id}")))
    }

    /// `account` as the API shows it, with how the controller says it stands.
    fn account_info(controller: &Controller, account: &Account) -> reply::AccountInfo {
        let connected = controller
            .accounts()
            .iter()
            .any(|view| view.account.id == account.id && view.status == AccountStatus::Connected);
        reply::AccountInfo::new(account, connected)
    }

    fn accounts_list(&self) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        let accounts = Self::account_views(&controller)?
            .iter()
            .map(|view| {
                reply::AccountInfo::new(&view.account, view.status == AccountStatus::Connected)
            })
            .collect();
        to_json(&reply::Accounts { accounts })
    }

    fn account_add(
        &self,
        provider: Provider,
        label: String,
        sign_in: SignIn,
        client_secret: Option<String>,
    ) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        let account = controller.add_account(NewAccount {
            provider,
            label,
            sign_in,
            client_secret,
        })?;
        to_json(&Self::account_info(&controller, &account))
    }

    /// Signs the account in and answers when that is done: the person has up to five minutes in
    /// the browser the app opens.
    fn account_connect(&self, id: &str) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        Self::account_view(&controller, id)?;
        let account = controller.connect_account(id, &AtomicBool::new(false))?;
        to_json(&Self::account_info(&controller, &account))
    }

    fn account_remove(&self, id: &str) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        Self::account_view(&controller, id)?;
        let removed = controller.remove_account(id)?;
        to_json(&reply::AccountRemoved {
            id: removed.account.id,
            locations: removed
                .locations
                .iter()
                .map(|location| location.to_string_lossy().into_owned())
                .collect(),
            forgotten: u64::try_from(removed.forgotten).unwrap_or(u64::MAX),
        })
    }

    fn account_browse(&self, id: &str, under: Option<&Path>) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        let view = Self::account_view(&controller, id)?;
        if let Some(under) = under {
            require_absolute(under)?;
            if !sys::is_under(under, &view.account.root()) {
                return Err(ApiError::bad_request(format!(
                    "{} is not in the account {}",
                    under.display(),
                    view.account.label
                )));
            }
        }
        let folders = controller
            .browse_cloud(id, under)?
            .into_iter()
            .map(|path| reply::FolderInfo {
                name: path.file_name().map_or_else(
                    || path.to_string_lossy().into_owned(),
                    |name| name.to_string_lossy().into_owned(),
                ),
                path: path.to_string_lossy().into_owned(),
            })
            .collect();
        to_json(&reply::Folders { folders })
    }

    /// What [`Local`] says of the inventory, with the progress of the scan the controller runs (one
    /// somebody asked for, or one of what monitoring saw change): the app's scans are its own,
    /// not [`Local`]'s.
    fn inventory_status(&self) -> Result<Value, ApiError> {
        let mut status = self.local.inventory_status()?;
        let snapshot = self.controller()?.snapshot();
        status.scanning = snapshot
            .scan
            .or(snapshot.watch.scanning)
            .map(|(done, total)| reply::Progress { done, total });
        to_json(&status)
    }

    /// Scans the locations now and answers when the scan is over.
    fn inventory_rescan(&self) -> Result<Value, ApiError> {
        let controller = self.controller()?;
        controller.submit(Command::ScanAll);
        // The command has queued the scan once the controller is idle.
        if !controller.wait_idle(WAIT) {
            return Err(ApiError::busy("piikey is still starting the scan"));
        }
        // A scan of a big folder takes as long as it takes.
        while !controller.wait_scans(LOOK) {}
        to_json(&controller.inventory().totals())
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
        let mut model = self.local.model_status()?;
        follow_download(&mut model, self.controller()?.snapshot().model);
        to_json(&model)
    }

    /// A new token also restarts the local API, which keeps the token it started with.
    fn rotate_token(&self) -> Result<Value, ApiError> {
        let token = self.controller()?.token(true).map_err(ApiError::internal)?;
        to_json(&reply::Token { token })
    }

    /// Asks `request` of [`Local`], then lets the app know the vault lost records.
    fn forget(&self, request: Request) -> Result<Value, ApiError> {
        let reply = self.local.handle(request)?;
        self.controller()?.vault_changed();
        Ok(reply)
    }

    /// Asks `request` of [`Local`] in the pool the app's own scans use, so file work does not take
    /// every core of the PC.
    fn in_scan_pool(&self, request: Request) -> Result<Value, ApiError> {
        self.controller()?
            .in_scan_pool(|| self.local.handle(request))
    }

    /// Scans the files in that pool, then lets the app know the inventory changed.
    fn scan_files(&self, paths: Vec<PathBuf>, record: bool) -> Result<Value, ApiError> {
        let reply = self.in_scan_pool(Request::ScanFiles { paths, record })?;
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
            Request::SettingsSet { settings } => self.settings_set(&settings),
            Request::ExplorerScan { paths } => self.explorer_scan(paths),
            Request::AccountsList => self.accounts_list(),
            Request::AccountAdd {
                provider,
                label,
                sign_in,
                client_secret,
            } => self.account_add(provider, label, sign_in, client_secret),
            Request::AccountConnect { id } => self.account_connect(&id),
            Request::AccountRemove { id } => self.account_remove(&id),
            Request::AccountBrowse { id, under } => self.account_browse(&id, under.as_deref()),
            Request::ShowWindow => self.show_window(),
            Request::InventoryStatus => self.inventory_status(),
            Request::InventoryRescan => self.inventory_rescan(),
            Request::ModelStatus => self.model_status(),
            Request::ModelDownload => self.model_download(),
            Request::ApiToken { rotate: true } => self.rotate_token(),
            Request::ScanFiles { paths, record } => self.scan_files(paths, record),
            Request::AnonymizeFiles { .. }
            | Request::DeanonymizeFiles { .. }
            | Request::SubjectSearch { .. } => self.in_scan_pool(request),
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

/// Puts the download the controller runs, or the failure of one, into what [`Local`] says of the
/// model: the controller's download is the app's, [`Local`] knows only the files.
fn follow_download(model: &mut reply::Model, download: Model) {
    match download {
        Model::Downloading { done, total } => {
            model.state = ModelState::Missing;
            model.downloading = Some(reply::Progress { done, total });
        }
        Model::Failed(message) => {
            model.state = ModelState::Failed;
            model.error = Some(message);
        }
        Model::Ready | Model::Skipped => {}
    }
}

/// `path` is a full path to something that exists.
fn exists(path: &Path) -> Result<(), ApiError> {
    require_on_this_pc(path)?;
    match path.try_exists() {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::not_found(format!(
            "{} does not exist",
            path.display()
        ))),
        Err(error) => Err(Error::Io(error).into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Instant};

    use piikey::sources;

    use super::*;
    use crate::{
        Describe,
        ui::{
            controller::RevealState,
            testing::{TempDir, stub_controller},
        },
    };

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
        fs::write(&file, "mail jan.jansen@acme.nl").describe()?;
        assert_eq!(ask(&api, scan(vec![file.clone()]))?, json!({}));
        let deadline = Instant::now() + Duration::from_secs(20);
        let reveal = loop {
            if let Some(reveal) = controller.snapshot().reveal
                && matches!(reveal.state, RevealState::Done(_) | RevealState::Failed(_))
            {
                break reveal;
            }
            if Instant::now() > deadline {
                return Err("the scan never ended".to_owned());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(reveal.paths, [file]);
        let RevealState::Done(summary) = reveal.state else {
            return Err(format!("the scan failed: {:?}", reveal.state));
        };
        assert_eq!(
            (summary.files, summary.files_with_data, summary.hits),
            (1, 1, 1)
        );
        Ok(())
    }

    #[test]
    fn show_window_asks_the_application_thread_for_the_window() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        assert_eq!(controller.tray().show, 0);
        assert_eq!(ask(&api, Request::ShowWindow)?, json!({}));
        assert_eq!(ask(&api, Request::ShowWindow)?, json!({}));
        assert_eq!(controller.tray().show, 2);
        assert_eq!(controller.snapshot().show, 2);
        Ok(())
    }

    #[test]
    fn the_inventory_status_comes_from_the_controller() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let docs = dir.0.join("docs");
        fs::create_dir(&docs).describe()?;
        fs::write(docs.join("a.txt"), "mail jan.jansen@acme.nl").describe()?;
        let patch = SettingsPatch {
            inventory_roots: Some(vec![docs.clone()]),
            ..SettingsPatch::default()
        };
        ask(&api, Request::SettingsSet { settings: patch })?;
        // What the app holds, not what a file on this PC says: the stub saves nothing.
        let status = ask(&api, Request::InventoryStatus)?;
        assert!(status.get("enabled").is_none(), "no switch: {status}");
        assert_eq!(status["roots"], json!([docs.to_string_lossy()]));
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
            .describe()?;
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
    fn the_download_the_app_runs_is_what_the_model_status_says() {
        let local = || reply::Model {
            state: ModelState::Unloaded,
            device: None,
            error: None,
            downloading: None,
            dir: "model".to_owned(),
        };
        let mut model = local();
        follow_download(&mut model, Model::Downloading { done: 5, total: 20 });
        assert_eq!(model.state, ModelState::Missing);
        assert_eq!(
            model.downloading,
            Some(reply::Progress { done: 5, total: 20 })
        );

        let mut model = local();
        follow_download(&mut model, Model::Failed("no network".to_owned()));
        assert_eq!(model.state, ModelState::Failed);
        assert_eq!(model.error.as_deref(), Some("no network"));

        for idle in [Model::Ready, Model::Skipped] {
            let mut model = local();
            follow_download(&mut model, idle);
            assert_eq!(model, local(), "nothing to add");
        }
    }

    /// A Google Drive account that signs in with a key file, which is there: connected without a
    /// sign-in, and nothing of it is secret. It goes straight into the data folder, as another
    /// process would put it.
    fn add_google(dir: &TempDir, label: &str) -> Result<Account, String> {
        let key_file = dir.0.join("key.json");
        fs::write(&key_file, "{}").describe()?;
        sources::add_account(
            &dir.0,
            Provider::GoogleDrive,
            label,
            SignIn::GoogleServiceAccount {
                key_file,
                users: vec!["jan@acme.nl".to_owned()],
            },
            None,
        )
        .describe()
    }

    #[test]
    fn the_accounts_are_listed_as_the_controller_stands_and_added_through_it() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        assert_eq!(ask(&api, Request::AccountsList)?, json!({"accounts": []}));

        // One that another process added is found, and is connected.
        let work = add_google(&dir, "Work")?;
        let listed = ask(&api, Request::AccountsList)?;
        assert_eq!(
            listed["accounts"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
        assert_eq!(listed["accounts"][0]["id"], work.id.as_str());
        assert_eq!(listed["accounts"][0]["path"], r"\\Google Drive\Work");
        assert_eq!(listed["accounts"][0]["connected"], true);

        let added = ask(
            &api,
            Request::AccountAdd {
                provider: Provider::Dropbox,
                label: "Personal".to_owned(),
                sign_in: SignIn::DropboxDelegated {
                    app_key: "key-1".to_owned(),
                },
                client_secret: None,
            },
        )?;
        assert_eq!(added["label"], "Personal");
        assert_eq!(added["connected"], false, "nobody has signed in yet");
        assert_eq!(controller.accounts().len(), 2, "the app's own list follows");

        let duplicate = Request::AccountAdd {
            provider: Provider::Dropbox,
            label: "personal".to_owned(),
            sign_in: SignIn::DropboxDelegated {
                app_key: "key-2".to_owned(),
            },
            client_secret: None,
        };
        let (code, message) = refused(&api, duplicate)?;
        assert_eq!(code, "bad_request");
        assert!(message.contains("already"), "{message}");
        assert_eq!(controller.accounts().len(), 2);
        Ok(())
    }

    #[test]
    fn an_account_is_signed_in_through_the_controller_and_an_unknown_id_is_not_found() -> Test {
        let dir = TempDir::new()?;
        let (api, _controller) = api(&dir)?;
        let work = add_google(&dir, "Work")?;
        let connected = ask(
            &api,
            Request::AccountConnect {
                id: work.id.clone(),
            },
        )?;
        assert_eq!(connected["id"], work.id.as_str());
        assert_eq!(connected["connected"], true);
        for request in [
            Request::AccountConnect {
                id: "0000000000000000".to_owned(),
            },
            Request::AccountRemove {
                id: "0000000000000000".to_owned(),
            },
            Request::AccountBrowse {
                id: "0000000000000000".to_owned(),
                under: None,
            },
        ] {
            let op = request.op();
            assert_eq!(refused(&api, request)?.0, "not_found", "{op}");
        }
        Ok(())
    }

    #[test]
    fn removing_an_account_takes_its_locations_off_the_controllers_list() -> Test {
        let dir = TempDir::new()?;
        let (api, controller) = api(&dir)?;
        let work = add_google(&dir, "Work")?;
        let docs = PathBuf::from(r"\\Google Drive\Work\Docs");
        let set = |root: &Path| {
            ask(
                &api,
                Request::SettingsSet {
                    settings: SettingsPatch {
                        inventory_roots: Some(vec![root.to_path_buf()]),
                        ..SettingsPatch::default()
                    },
                },
            )
        };
        // A location of an account that is there is accepted, one of a stranger is not.
        set(&docs)?;
        assert_eq!(
            controller.snapshot().policy.inventory_roots,
            std::slice::from_ref(&docs)
        );
        let stranger = Request::SettingsSet {
            settings: SettingsPatch {
                inventory_roots: Some(vec![PathBuf::from(r"\\Google Drive\Nobody\Docs")]),
                ..SettingsPatch::default()
            },
        };
        let (code, message) = refused(&api, stranger)?;
        assert_eq!(code, "bad_request");
        assert!(message.contains("add the account first"), "{message}");
        assert_eq!(
            controller.snapshot().policy.inventory_roots,
            std::slice::from_ref(&docs)
        );

        let removed = ask(
            &api,
            Request::AccountRemove {
                id: work.id.clone(),
            },
        )?;
        assert_eq!(
            removed,
            json!({"id": work.id, "locations": [docs.to_string_lossy()], "forgotten": 0})
        );
        assert!(controller.snapshot().policy.inventory_roots.is_empty());
        assert!(controller.accounts().is_empty());
        assert_eq!(ask(&api, Request::AccountsList)?, json!({"accounts": []}));
        Ok(())
    }

    #[test]
    fn browsing_stays_in_the_account_and_tells_what_the_service_says() -> Test {
        let dir = TempDir::new()?;
        let (api, _controller) = api(&dir)?;
        let work = add_google(&dir, "Work")?;
        let browse = |under: Option<&str>| {
            refused(
                &api,
                Request::AccountBrowse {
                    id: work.id.clone(),
                    under: under.map(PathBuf::from),
                },
            )
        };
        // The stub has no cloud: what it says comes back as it is.
        let (code, message) = browse(None)?;
        assert_eq!(code, "bad_request");
        assert!(message.contains("no cloud"), "{message}");
        assert!(
            browse(Some(r"\\Google Drive\Work\Docs"))?
                .1
                .contains("no cloud")
        );
        // Before the service is asked: a path that is not in the account.
        for under in [r"\\Dropbox\Other\Docs", "Docs"] {
            let (code, message) = browse(Some(under))?;
            assert_eq!(code, "bad_request", "{under}");
            assert!(!message.contains("no cloud"), "{under}: {message}");
        }
        Ok(())
    }

    #[test]
    fn an_explorer_scan_refuses_a_path_in_a_cloud_account() -> Test {
        let dir = TempDir::new()?;
        let (api, _controller) = api(&dir)?;
        let (code, message) = refused(
            &api,
            Request::ExplorerScan {
                paths: vec![PathBuf::from(r"\\Google Drive\Work\Docs")],
            },
        )?;
        assert_eq!(code, "bad_request");
        assert!(message.contains("cloud account"), "{message}");
        Ok(())
    }
}
