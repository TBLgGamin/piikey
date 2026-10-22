//! App state behind the UI: start and stop, certificate, settings, the vault's values, the inventory
//! and the scans that fill it.
//!
//! Everything that can block (`certutil`, CA files, binding the proxy, `WinINET`, settings and vault
//! I/O) runs on one worker thread, in submission order. The window and the tray only submit
//! [`Command`]s and read [`Snapshot`]s, so they share one state and never wait on the system.
//! Scans of files take long, so they run on a thread of their own, see [`inventory`].
//!
//! This file holds the controller itself: its state, the worker that runs the commands and what
//! the window reads. The rest is `impl Controller` too, split by what it works on:
//!
//! - [`protection`]: turning the app on and off, and the certificate.
//! - [`settings`]: following the settings with what runs because of them.
//! - [`model`]: the detection model's download, load and release.
//! - [`keyed`]: the vault's values, where they went, and the activity feed.
//! - [`inventory`]: the inventory, its scans and the scan thread.
//! - [`edit`]: the edits of the settings, applied to a [`Policy`].
//!
//! Lock order: nothing else is locked while a `Shared` lock is held, and `Shared` is never locked
//! while the state mutex is held except to read the policy first in [`Controller::snapshot`].

mod edit;
mod inventory;
mod keyed;
mod model;
mod protection;
mod settings;
#[cfg(test)]
mod tests;

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, LazyLock, Mutex, MutexGuard, PoisonError, RwLock, Weak,
        atomic::Ordering,
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use piikey::{
    api::EngineSource,
    engine::Engine,
    inventory::{Inventory, Progress, Totals},
    policy::{Highlight, Policy, SettingsPatch},
};

use super::{activity::Activity, scanner::Scanner};
use crate::{
    Res,
    ledger::Ledger,
    proxy::{Event, Shared},
};

#[cfg(test)]
pub use self::keyed::RECENT;
pub use self::{
    edit::{Edit, apply_edit},
    inventory::{InventoryView, Reveal},
    keyed::{Keyed, KeyedPage, KeyedQuery, Period, Sent},
    model::Model,
};

/// How long a quitting app waits for a command that is still running.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// Progress of a download or a scan reaches the UI at most this often.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

/// Side effects the controller needs from the system. The real implementation is
/// [`System`](super::system::System); tests substitute a recording fake.
pub trait Backend: Send + Sync + 'static {
    /// Creates the local CA when it does not exist yet.
    fn ensure_ca(&self) -> Res<()>;
    /// Whether Windows trusts the CA.
    fn ca_installed(&self) -> bool;
    /// Adds the CA to the user's trusted roots (Windows asks the user once).
    fn install_ca(&self) -> Res<()>;
    /// Starts the proxy on [`PORT`](crate::proxy::PORT).
    fn start_proxy(&self, shared: Arc<Shared>, events: Sender<Event>) -> Res<Box<dyn Running>>;
    /// Points Windows at the proxy.
    fn enable_system_proxy(&self) -> Res<()>;
    /// Gives Windows its previous proxy settings back.
    fn disable_system_proxy(&self) -> Res<()>;
    /// Starts reading what the user types and pastes, so the proxy masks only that. While it is
    /// not running, the proxy checks whole requests.
    fn start_capture(&self, shared: Arc<Shared>) -> Res<Box<dyn Running>>;
    /// Persists the settings.
    fn save_policy(&self, policy: &Policy) -> Res<()>;
    /// Opens the engine over the vault.
    fn open_engine(&self) -> Res<Engine>;
    /// Opens the inventory: which files hold personal data, never the values.
    fn open_inventory(&self) -> Res<Inventory>;
    /// The saved activity feed; empty when there is none or it cannot be read.
    fn load_activity(&self) -> Activity;
    /// Persists the activity feed, as [`Activity::to_text`] wrote it.
    fn save_activity(&self, text: &str) -> Res<()>;
    /// Whether the detection model is downloaded and verified.
    fn model_installed(&self) -> bool;
    /// Downloads the detection model; `progress(done, total)` in bytes while it runs.
    fn fetch_model(&self, progress: &mut dyn FnMut(u64, u64)) -> Res<()>;
    /// Loads the detection model into memory (GPU or CPU).
    fn load_model(&self) -> Res<()>;
    /// Frees the detection model's memory.
    fn release_model(&self);
    /// The token the local HTTP API asks for, made on first use; with `rotate`, a new one that
    /// replaces it.
    fn token(&self, rotate: bool) -> Res<String>;
    /// Starts the local HTTP API on `127.0.0.1:port`, asking for `token`.
    fn start_http(&self, port: u16, token: String) -> Res<Box<dyn Running>>;
    /// Adds or removes "Scan for personal data" in Explorer's right-click menu.
    fn set_explorer_menu(&self, on: bool) -> Res<()>;
    /// Registers (`on`) or gives back the shortcut of the highlight, Ctrl+Alt+P. The error says
    /// why not, in words for the user: another program may have the shortcut.
    fn set_hotkey(&self, shared: &Shared, on: bool) -> Res<()>;
}

/// A started proxy or capture.
pub trait Running: Send {
    /// Stops it and waits for it to finish.
    fn stop(self: Box<Self>);
}

/// What the controller is working on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    Starting,
    Stopping,
    InstallingCertificate,
}

/// Whether Windows trusts the app's certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cert {
    Unknown,
    Installed,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

/// A message the user should read until they dismiss it or the next action replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub severity: Severity,
    pub text: String,
}

impl Notice {
    pub(super) fn warning(text: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            text: text.into(),
        }
    }

    pub(super) fn error(text: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            text: text.into(),
        }
    }
}

/// Everything the UI shows, copied out of the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Grows with every change; see [`Controller::wait_changed`].
    pub version: u64,
    /// The proxy runs and Windows routes through it.
    pub enabled: bool,
    pub busy: Option<Busy>,
    /// Commands submitted and not finished yet.
    pub pending: usize,
    pub cert: Cert,
    pub notice: Option<Notice>,
    /// Proxies issued so far: vault records.
    pub issued: u64,
    pub policy: Policy,
    /// The `RECENT` most recently sent values, filled up with the newest records.
    pub recent: Vec<Keyed>,
    /// The latest masking or restoring this session.
    pub last_activity: Option<Sent>,
    /// The detection model's download state.
    pub model: Model,
    /// Files scanned and files to scan, while a scan runs: the inventory's or Explorer's.
    pub scan: Option<(u64, u64)>,
    /// The latest request to show the result of a scan in the window.
    pub reveal: Option<Reveal>,
    /// Files in the inventory that hold personal data, and the values found in them.
    pub inventory_totals: (u64, u64),
    /// The local HTTP API is listening.
    pub http: bool,
    /// The highlight is paused: in Always mode its shortcut pauses and resumes it.
    pub highlight_paused: bool,
    /// How many times something asked for the window to come forward (a second start of the
    /// app, `piikey-cli open`), 0 before the first: see [`Controller::request_window`].
    pub show: u64,
}

/// What the application thread watches while no window is open: what the tray icon shows, and
/// the scan that asks to be shown. Small and copied under one short lock, because the thread asks
/// a few times a second (see `Ticker` in `ui/mod.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tray {
    /// The app runs or is starting: what the tray's menu and tooltip say.
    pub on: bool,
    /// See [`Snapshot::highlight_paused`].
    pub highlight_paused: bool,
    /// The number of the latest request to show a scan, 0 before the first: [`Reveal::seq`].
    pub reveal: u64,
    /// How many times something asked for the window to come forward: [`Snapshot::show`].
    pub show: u64,
}

/// Work for the worker thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    SetEnabled(bool),
    /// The saved settings say the app was on: start it again as the user left it. When that
    /// fails, Windows gets its proxy settings back, because a session that was killed leaves them
    /// pointing at a proxy nobody serves.
    Resume,
    InstallCertificate,
    Edit(Edit),
    /// The proxy reported that it cannot serve any more.
    Fatal(String),
    /// Re-check the certificate and the vault.
    Refresh,
    /// Download the detection model (again).
    FetchModel,
    /// Go on without the detection model.
    SkipModel,
    /// Bring everything in line with the saved settings: the Explorer menu, the local API, the
    /// inventory, the highlight and the detection model. Run once, after launch.
    Startup,
    /// Apply these settings together (the API's `settings_set`).
    Settings(SettingsPatch),
    /// Scan the watched folders again now.
    Rescan,
    /// Scan these files and folders into the inventory, as Explorer's "Scan for personal data" does. With
    /// `reveal` the window comes forward with the result.
    ScanFiles {
        paths: Vec<PathBuf>,
        reveal: bool,
    },
    /// Remove the vault records whose value or stand-in is one of these.
    Forget(Vec<String>),
    /// Remove every vault record; the key stays.
    WipeVault,
    /// Start the local API again: its token changed.
    RestartHttp,
}

struct State {
    version: u64,
    enabled: bool,
    busy: Option<Busy>,
    pending: usize,
    closing: bool,
    cert: Cert,
    notice: Option<Notice>,
    issued: u64,
    /// See [`Snapshot::recent`].
    recent: Vec<Keyed>,
    /// Which stand-ins went where and when. Readers of the vault hold a share of it while they
    /// walk, so recording copies it only when one does.
    activity: Arc<Activity>,
    last_activity: Option<Sent>,
    /// When `activity` was last written.
    feed_saved: Instant,
    /// `activity` changed since it was last written.
    feed_dirty: bool,
    proxy: Option<Box<dyn Running>>,
    /// Reads what the user types while the app is on. `None` when it could not start; the proxy
    /// then checks whole requests.
    capture: Option<Box<dyn Running>>,
    /// The local HTTP API while it is on.
    http: Option<Box<dyn Running>>,
    model: Model,
    fetch: Fetch,
    /// How far the scan that runs now has got.
    scan: Option<Arc<Progress>>,
    /// See [`Snapshot::reveal`].
    reveal: Option<Reveal>,
    /// See [`Snapshot::show`].
    show: u64,
    inventory_totals: Totals,
}

/// The model download's flags.
#[derive(Default)]
struct Fetch {
    /// A download thread is running.
    running: bool,
    /// Turn on as soon as the model has downloaded.
    then_start: bool,
}

/// Owns the proxy's lifetime and the state the UI renders.
pub struct Controller {
    shared: Arc<Shared>,
    backend: Box<dyn Backend>,
    vault_path: PathBuf,
    inventory: Arc<Inventory>,
    state: Mutex<State>,
    changed: Condvar,
    commands: Mutex<Option<Sender<Command>>>,
    events: Sender<Event>,
    /// What the scan thread works through.
    scanner: Arc<Scanner>,
    /// One load or release of the detection model at a time.
    model_sync: Mutex<()>,
    /// The pool the scans run in, made when first needed, see [`Controller::in_scan_pool`]; `None`
    /// when the system would not start its threads.
    pool: LazyLock<Option<rayon::ThreadPool>>,
}

impl Controller {
    /// Opens the engine and starts a controller the way the app does at launch. The caller holds
    /// the [`Instance`](super::instance::Instance) lock, so no other app is using the proxy or
    /// the Windows settings.
    ///
    /// Windows comes first. An app that was killed while it was on leaves the Windows proxy
    /// pointing at a port nobody serves, and the user without internet. If the saved settings say
    /// the app was off, nothing would give those settings back, so it happens here, before
    /// anything that can fail ([`Backend::disable_system_proxy`] does nothing when the proxy is
    /// not the app's). If they say it was on, [`Command::Resume`] starts it again, and gives the
    /// settings back when that fails.
    ///
    /// Without the detection model, the first-run download starts instead, Windows gets its proxy
    /// settings back (so the user keeps internet meanwhile) and a saved "on" waits for the
    /// download to finish.
    ///
    /// The other saved features (the Explorer menu, the local API, the inventory, the highlight)
    /// start with [`Command::Startup`], which the caller submits once what they serve exists.
    ///
    /// # Errors
    /// The vault or the inventory cannot be opened, or the operating system refused a thread.
    pub fn launch(
        backend: Box<dyn Backend>,
        vault_path: PathBuf,
        policy: Policy,
        mut notice: Option<Notice>,
    ) -> Res<Arc<Self>> {
        let resume = policy.enabled;
        let installed = backend.model_installed();
        if (!resume || !installed)
            && let Err(error) = backend.disable_system_proxy()
        {
            let text = format!(
                "Could not restore your Windows proxy settings after the last session: {error}."
            );
            notice = Some(follow(notice, &text));
        }
        let opened = backend
            .open_engine()
            .map_err(|error| format!("could not open the vault {}: {error}", vault_path.display()))
            .and_then(|engine| {
                backend
                    .open_inventory()
                    .map(|inventory| (engine, inventory))
                    .map_err(|error| format!("could not open the inventory: {error}"))
            });
        let (engine, inventory) = match opened {
            Ok(opened) => opened,
            Err(mut message) => {
                // No app will start, so nothing else would give Windows its settings back.
                if resume && let Err(error) = backend.disable_system_proxy() {
                    message =
                        format!("{message}. Windows may still point at piikey's proxy: {error}");
                }
                return Err(message);
            }
        };
        let controller = Self::new(backend, vault_path, policy, engine, inventory, notice)?;
        controller.submit(Command::Refresh);
        if !installed {
            controller.update(|state| {
                state.model = Model::Downloading {
                    done: 0,
                    total: model::model_size(),
                };
                state.fetch.then_start = resume;
            });
            controller.spawn_fetch();
        } else if resume {
            controller.submit(Command::Resume);
        }
        Ok(controller)
    }

    /// Builds a controller around `engine` and starts its worker and event threads.
    ///
    /// `policy.enabled` is the saved wish; the live flag the proxy reads stays off until the proxy
    /// actually runs, so the caller submits [`Command::Resume`] to honour it ([`Self::launch`]
    /// does).
    ///
    /// # Errors
    /// The operating system refused a thread.
    pub fn new(
        backend: Box<dyn Backend>,
        vault_path: PathBuf,
        mut policy: Policy,
        engine: Engine,
        inventory: Inventory,
        notice: Option<Notice>,
    ) -> Res<Arc<Self>> {
        policy.enabled = false;
        engine.set_enabled(policy.enabled_kinds());
        let highlight = policy.highlight;
        let shared = Arc::new(Shared {
            engine: RwLock::new(Arc::new(engine)),
            policy: RwLock::new(policy),
            ledger: Ledger::default(),
            typed: crate::proxy::Typed::new(),
            purpose: Arc::default(),
        });
        // Nothing is masked until the proxy runs; the highlight is as the settings say.
        shared.purpose.set_mask(false);
        shared.purpose.set_highlight(highlight);
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let activity = backend.load_activity();
        let inventory = Arc::new(inventory);
        let inventory_totals = inventory.totals();
        let controller = Arc::new(Self {
            shared,
            backend,
            vault_path,
            inventory,
            state: Mutex::new(State {
                version: 0,
                enabled: false,
                busy: None,
                pending: 0,
                closing: false,
                cert: Cert::Unknown,
                notice,
                issued: 0,
                recent: Vec::new(),
                activity: Arc::new(activity),
                last_activity: None,
                feed_saved: Instant::now(),
                feed_dirty: false,
                proxy: None,
                capture: None,
                http: None,
                model: Model::Ready,
                fetch: Fetch::default(),
                scan: None,
                reveal: None,
                show: 0,
                inventory_totals,
            }),
            changed: Condvar::new(),
            commands: Mutex::new(Some(command_tx)),
            events: event_tx,
            scanner: Arc::new(Scanner::default()),
            model_sync: Mutex::new(()),
            pool: LazyLock::new(inventory::scan_pool),
        });
        // A pause of the highlight is on the tray's tooltip: the window follows it like any change.
        let paused = Arc::downgrade(&controller);
        controller.shared.purpose.on_pause(move || {
            if let Some(controller) = paused.upgrade() {
                controller.update(|_| {});
            }
        });
        let worker = Arc::downgrade(&controller);
        thread::Builder::new()
            .name("piikey-worker".into())
            .spawn(move || work(&worker, &command_rx))
            .map_err(|error| format!("could not start the worker thread: {error}"))?;
        let pump = Arc::downgrade(&controller);
        thread::Builder::new()
            .name("piikey-events".into())
            .spawn(move || keyed::pump_events(&pump, &event_rx))
            .map_err(|error| format!("could not start the event thread: {error}"))?;
        Ok(controller)
    }

    /// Path of the vault the engine runs on.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Copies the state out for rendering.
    pub fn snapshot(&self) -> Snapshot {
        // The policy first: `Shared` locks are never taken while the state mutex is held.
        let policy = self.policy();
        let state = self.lock();
        Snapshot {
            version: state.version,
            enabled: state.enabled,
            busy: state.busy,
            pending: state.pending,
            cert: state.cert,
            notice: state.notice.clone(),
            issued: state.issued,
            policy,
            recent: state.recent.clone(),
            last_activity: state.last_activity.clone(),
            model: state.model.clone(),
            scan: state.scan.as_ref().map(|progress| {
                (
                    progress.done.load(Ordering::Relaxed),
                    progress.total.load(Ordering::Relaxed),
                )
            }),
            reveal: state.reveal.clone(),
            show: state.show,
            inventory_totals: (
                state.inventory_totals.files_with_pii,
                state.inventory_totals.hits,
            ),
            http: state.http.is_some(),
            highlight_paused: self.shared.purpose.paused(),
        }
    }

    /// Blocks until the state differs from `since` or `timeout` passes.
    pub fn wait_changed(&self, since: u64, timeout: Duration) -> Option<Snapshot> {
        let state = self.lock();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| state.version == since)
            .unwrap_or_else(PoisonError::into_inner);
        let changed = state.version != since;
        drop(state);
        changed.then(|| self.snapshot())
    }

    /// Blocks until every submitted command has finished; `false` on timeout.
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let (state, result) = self
            .changed
            .wait_timeout_while(state, timeout, |state| state.pending > 0)
            .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        !result.timed_out()
    }

    /// Queues `command` for the worker; never blocks.
    pub fn submit(&self, command: Command) {
        let commands = self.commands.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(sender) = commands.as_ref() else {
            return;
        };
        // Counted before the send so `wait_idle` cannot see a gap between queue and run.
        self.update(|state| state.pending += 1);
        if sender.send(command).is_err() {
            self.update(|state| state.pending = state.pending.saturating_sub(1));
        }
    }

    /// Whether the app runs or is starting: what a toggle should invert.
    pub fn is_on(&self) -> bool {
        self.tray().on
    }

    /// Whether something works in the background: protection, the highlight, the inventory or the
    /// local API. The app then stays in the tray when its window closes.
    pub fn runs_in_background(&self) -> bool {
        let policy = self.policy();
        policy.highlight != Highlight::Off || policy.inventory || policy.http_api || self.is_on()
    }

    /// Whether the last check found the certificate installed.
    pub fn cert_installed(&self) -> bool {
        self.lock().cert == Cert::Installed
    }

    /// Clears the notice the user closed.
    pub fn dismiss_notice(&self) {
        self.update(|state| state.notice = None);
    }

    /// Shows `notice` until the user closes it or the next action replaces it.
    pub(super) fn notify(&self, notice: Notice) {
        self.update(|state| state.notice = Some(notice));
    }

    /// Asks for the window to come forward, opening it if it is closed: what a second start of
    /// the app asks of the one that runs. The app thread sees [`Tray::show`] grow.
    pub fn request_window(&self) {
        self.update(|state| state.show += 1);
    }

    /// Whether the highlight is paused: in Always mode its shortcut pauses and resumes it.
    pub fn highlight_paused(&self) -> bool {
        self.shared.purpose.paused()
    }

    /// What the tray icon shows and whether a scan asks to be shown, see [`Tray`].
    pub fn tray(&self) -> Tray {
        let paused = self.highlight_paused();
        let state = self.lock();
        Tray {
            on: state.enabled || state.busy == Some(Busy::Starting),
            highlight_paused: paused,
            reveal: state.reveal.as_ref().map_or(0, |reveal| reveal.seq),
            show: state.show,
        }
    }

    /// The token the local HTTP API asks for, made on first use. With `rotate` a new one
    /// replaces it, and the local API starts again to ask for the new one.
    ///
    /// # Errors
    /// A message when the token cannot be read or written.
    pub fn token(&self, rotate: bool) -> Res<String> {
        let token = self.backend.token(rotate)?;
        if rotate {
            self.submit(Command::RestartHttp);
        }
        Ok(token)
    }

    /// Gives Windows its proxy settings back while the proxy keeps running; used right before
    /// the app quits so the machine is never left pointing at a closed port.
    pub fn restore_system_proxy(&self) {
        if self.lock().enabled {
            // Nothing to tell the user: the process is about to end, and `shutdown` retries.
            let _ = self.backend.disable_system_proxy();
        }
    }

    /// Stops accepting commands, waits for the running one, then turns the app off.
    pub fn shutdown(&self) {
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.update(|state| state.closing = true);
        self.wait_idle(SHUTDOWN_WAIT);
        self.stop_scans();
        let (enabled, proxy, capture, http) = self.update(|state| {
            let enabled = state.enabled;
            state.enabled = false;
            (
                enabled,
                state.proxy.take(),
                state.capture.take(),
                state.http.take(),
            )
        });
        if enabled {
            let _ = self.backend.disable_system_proxy();
        }
        self.set_live(false);
        if let Some(proxy) = proxy {
            proxy.stop();
        }
        if let Some(capture) = capture {
            capture.stop();
        }
        if let Some(http) = http {
            http.stop();
        }
        // After the proxy: its last events are counted too.
        self.save_feed(true);
    }

    /// The engine the proxy, the highlight and the scans use now.
    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(
            &self
                .shared
                .engine
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// The engine as the API handler asks for it: whichever is in use at the time of the call.
    pub fn engine_source(&self) -> EngineSource {
        let shared = Arc::clone(&self.shared);
        Arc::new(move || Arc::clone(&shared.engine.read().unwrap_or_else(PoisonError::into_inner)))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the state, bumps the version and wakes everyone waiting for a change.
    fn update<R>(&self, change: impl FnOnce(&mut State) -> R) -> R {
        let mut state = self.lock();
        let result = change(&mut state);
        state.version += 1;
        drop(state);
        self.changed.notify_all();
        result
    }

    /// The settings in force now, as the proxy and the features read them.
    pub fn policy(&self) -> Policy {
        self.shared
            .policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sets the flag the proxy reads: it only anonymizes while this is on. What is typed is kept
    /// for the proxy exactly then.
    fn set_live(&self, on: bool) {
        self.shared
            .policy
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .enabled = on;
        self.shared.purpose.set_mask(on);
    }

    fn run(self: &Arc<Self>, command: Command) {
        if !self.lock().closing {
            match command {
                Command::SetEnabled(true) => self.start(),
                Command::SetEnabled(false) => self.stop(None),
                Command::Resume => self.resume(),
                Command::InstallCertificate => self.install(),
                Command::Edit(edit) => self.edit(&edit),
                Command::Fatal(reason) => self.stop(Some(reason)),
                Command::Refresh => self.refresh(),
                Command::FetchModel => self.refetch(),
                Command::SkipModel => self.skip_model(),
                Command::Startup => self.startup(),
                Command::Settings(patch) => self.settings(&patch),
                Command::Rescan => self.rescan(),
                Command::ScanFiles { paths, reveal } => self.ask_scan(paths, reveal),
                Command::Forget(values) => self.forget(&values),
                Command::WipeVault => self.wipe(),
                Command::RestartHttp => self.restart_http(),
            }
        }
        self.update(|state| {
            state.pending = state.pending.saturating_sub(1);
            state.busy = None;
        });
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        // The scan thread waits for work: it ends.
        self.scanner.stop();
    }
}

fn cert_of(installed: bool) -> Cert {
    if installed {
        Cert::Installed
    } else {
        Cert::Missing
    }
}

/// `text` as an error that follows `first`, the notice that is showing, which is usually its cause.
fn follow(first: Option<Notice>, text: &str) -> Notice {
    Notice::error(match first {
        Some(first) if first.text.ends_with('.') => format!("{} {text}", first.text),
        Some(first) => format!("{}. {text}", first.text),
        None => text.to_owned(),
    })
}

/// Runs commands in order until the controller goes away.
fn work(controller: &Weak<Controller>, commands: &Receiver<Command>) {
    while let Ok(command) = commands.recv() {
        let Some(controller) = controller.upgrade() else {
            break;
        };
        controller.run(command);
    }
}
