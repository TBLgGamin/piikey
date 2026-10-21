//! App state behind the UI: start and stop, certificate, settings, keyed values, the PII inventory
//! and the scans that fill it.
//!
//! Everything that can block (`certutil`, CA files, binding the proxy, `WinINET`, settings and vault
//! I/O) runs on one worker thread, in submission order. The window and the tray only submit
//! [`Command`]s and read [`Snapshot`]s, so they share one state and never wait on the system.
//! Scans of files take long, so they run on a thread of their own, see [`scan_loop`].
//!
//! Lock order: nothing else is locked while a `Shared` lock is held, and `Shared` is never locked
//! while the state mutex is held except to read the policy first in [`Controller::snapshot`].

use std::{
    collections::HashSet,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use piikey::{
    api::EngineSource,
    detect::{EntityKind, ner::files::FILES},
    engine::Engine,
    inventory::{Entry, Inventory, Node, Progress, Totals},
    policy::{Highlight, Policy, SettingsPatch, default_inventory_roots},
};
use windows_reactor::DateTime;

use super::{
    activity::{self, Activity, Use},
    exports,
    scanner::{Job, Kind, Request, Scanner},
};
use crate::{
    Res,
    ledger::Ledger,
    proxy::{Event, PORT, Shared},
};

/// Keyed values the Home page lists.
pub const RECENT: usize = 8;
/// The activity feed is written at most this often while traffic flows, and at shutdown.
const FEED_SAVE_EVERY: Duration = Duration::from_secs(30);

/// How long a quitting app waits for a command that is still running.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);
/// How long a quitting app waits for the scan it cancelled to save what it did.
const SCAN_STOP_WAIT: Duration = Duration::from_secs(2);

/// Download progress reaches the UI at most this often.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

/// The notice after the user goes on without the model.
const SKIPPED_TEXT: &str = "The detection model is not downloaded, so names, addresses and other free-text details are not masked. piikey downloads it next time it starts.";

/// Bytes the model download fetches in all.
fn model_size() -> u64 {
    FILES.iter().map(|file| file.size).sum()
}

/// Side effects the controller needs from the system. The real implementation is
/// [`System`](super::system::System); tests substitute a recording fake.
pub trait Backend: Send + Sync + 'static {
    /// Creates the local CA when it does not exist yet.
    fn ensure_ca(&self) -> Res<()>;
    /// Whether Windows trusts the CA.
    fn ca_installed(&self) -> bool;
    /// Adds the CA to the user's trusted roots (Windows asks the user once).
    fn install_ca(&self) -> Res<()>;
    /// Starts the proxy on [`PORT`].
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
    /// Opens the PII inventory: which files hold personal data, never the values.
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
    /// Starts the local HTTP API on `127.0.0.1:port`.
    fn start_http(&self, port: u16) -> Res<Box<dyn Running>>;
    /// Adds or removes "Scan for PII" in Explorer's right-click menu.
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

/// Where and when traffic went: the last time a value was sent, or the latest masking/restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub host: String,
    /// The program that sent it, when known.
    pub exe: Option<String>,
    /// When, as a feed shows it: `14:05`, `yesterday 14:05`, `Mon 14:05` or `12 Oct`.
    pub at: String,
}

/// One vault record: a value and the proxy that stands in for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyed {
    pub kind: EntityKind,
    pub original: String,
    pub proxy: String,
    /// `None` when it was never sent.
    pub sent: Option<Sent>,
}

/// How far back the Keyed values page looks, by when a value was last sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Period {
    #[default]
    Any,
    Today,
    Week,
    Month,
}

impl Period {
    pub const ALL: [Self; 4] = [Self::Any, Self::Today, Self::Week, Self::Month];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Any => "Any time",
            Self::Today => "Today",
            Self::Week => "Last 7 days",
            Self::Month => "Last 30 days",
        }
    }

    /// Local days before today a value sent within this period may be; `None` is any.
    const fn days(self) -> Option<i64> {
        match self {
            Self::Any => None,
            Self::Today => Some(0),
            Self::Week => Some(6),
            Self::Month => Some(29),
        }
    }
}

/// What the Keyed values page asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyedQuery {
    /// Matched, ignoring case, against the value, its stand-in, the site and the program.
    pub text: String,
    pub kind: Option<EntityKind>,
    /// Values last sent to this site or one of its subdomains.
    pub site: Option<String>,
    pub period: Period,
}

/// One page of [`Controller::keyed`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyedPage {
    /// Most recently sent first, then the values never sent, newest first.
    pub items: Vec<Keyed>,
    /// Records that match, `items` included.
    pub matched: usize,
    /// Every site a value went to, most recently first: the site filter's choices.
    pub sites: Vec<String>,
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
    /// The [`RECENT`] most recently sent values, filled up with the newest records.
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
}

/// A request to show the result of a scan: the window comes forward, on Home, at `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    /// Grows with every request, so the window can tell a new one from one it handled.
    pub seq: u64,
    /// The folder to show: what was scanned, or the folder of the file that was.
    pub at: PathBuf,
    /// The file that was scanned, when it was one.
    pub select: Option<PathBuf>,
}

/// One level of the inventory's treemap, see [`Controller::inventory_view`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InventoryView {
    pub nodes: Vec<Node>,
    /// What the inventory knows of the selected file.
    pub entry: Option<Entry>,
    /// The folders the inventory watches, as the tiles were grouped by them: the breadcrumb
    /// names a folder below one of them by it, not by its whole path.
    pub roots: Vec<PathBuf>,
}

/// A change to the settings, one control of the Settings page at a time: the site and program
/// lists, the kinds that are masked and the features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    Site {
        site: String,
        on: bool,
    },
    Program {
        exe: String,
        on: bool,
    },
    /// Whether piikey masks `kind`.
    Kind {
        kind: EntityKind,
        on: bool,
    },
    /// When the field in focus is outlined if it holds personal data.
    Highlight(Highlight),
    /// Whether Explorer's right-click menu offers "Scan for PII".
    ExplorerMenu(bool),
    /// Whether the inventory scans the watched folders in the background. Switching it on with
    /// no folder chosen watches the usual ones.
    Inventory(bool),
    /// A folder the inventory watches; `on` adds it. A path that is no folder is refused.
    InventoryRoot {
        path: PathBuf,
        on: bool,
    },
    /// A folder or file the inventory leaves out, with everything below it; `on` adds it. What
    /// the inventory knows about it is forgotten.
    InventoryExclude {
        path: PathBuf,
        on: bool,
    },
    /// Whether the app serves the local HTTP API.
    HttpApi(bool),
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
    /// Scan these files and folders into the inventory, as Explorer's "Scan for PII" does. With
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
    /// Which stand-ins went where and when.
    activity: Activity,
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
                    .map_err(|error| format!("could not open the PII inventory: {error}"))
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
                    total: model_size(),
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
                activity,
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
                inventory_totals,
            }),
            changed: Condvar::new(),
            commands: Mutex::new(Some(command_tx)),
            events: event_tx,
            scanner: Arc::new(Scanner::default()),
            model_sync: Mutex::new(()),
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
            .spawn(move || pump_events(&pump, &event_rx))
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
            inventory_totals: (
                state.inventory_totals.files_with_pii,
                state.inventory_totals.hits,
            ),
            http: state.http.is_some(),
            highlight_paused: self.shared.purpose.paused(),
        }
    }

    /// The values `query` asks for, most recently sent first, then (when no site or period is
    /// asked for) the values never sent, newest first: at most `limit` of them, and how many
    /// match in all.
    pub fn keyed(&self, query: &KeyedQuery, limit: usize) -> KeyedPage {
        // The state first, then the vault: `Shared` is never locked while the state mutex is held.
        let activity = self.lock().activity.clone();
        let now = activity::now();
        let text = query.text.trim().to_lowercase();
        let has = |s: &str| s.to_lowercase().contains(&text);
        let mut page = KeyedPage {
            sites: activity.sites(),
            ..KeyedPage::default()
        };
        let engine = self.engine();
        let Ok(view) = engine.vault().read() else {
            return page;
        };
        let mut add = |kind: EntityKind, original: &str, proxy: &str, sent: Option<Sent>| {
            page.matched += 1;
            if page.items.len() < limit {
                page.items.push(Keyed {
                    kind,
                    original: original.to_owned(),
                    proxy: proxy.to_owned(),
                    sent,
                });
            }
        };
        for used in activity.iter() {
            let (Some(kind), Some(original)) =
                (view.kind_of(&used.proxy), view.original_for(&used.proxy))
            else {
                continue;
            };
            let wanted = query.kind.is_none_or(|k| k == kind)
                && query
                    .site
                    .as_deref()
                    .is_none_or(|site| on_site(&used.host, site))
                && query
                    .period
                    .days()
                    .is_none_or(|days| activity::day(now) - activity::day(used.ticks) <= days)
                && (text.is_empty()
                    || has(original)
                    || has(&used.proxy)
                    || has(&used.host)
                    || used.exe.as_deref().is_some_and(has));
            if wanted {
                add(kind, original, &used.proxy, Some(sent_of(used, now)));
            }
        }
        if query.site.is_none() && query.period == Period::Any {
            let sent: HashSet<&str> = activity.iter().map(|u| u.proxy.as_str()).collect();
            for (kind, original, proxy) in view.newest_first() {
                if !sent.contains(proxy)
                    && query.kind.is_none_or(|k| k == kind)
                    && (text.is_empty() || has(original) || has(proxy))
                {
                    add(kind, original, proxy, None);
                }
            }
        }
        drop(view);
        page
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

    /// The PII inventory: which files hold personal data.
    pub fn inventory(&self) -> Arc<Inventory> {
        Arc::clone(&self.inventory)
    }

    /// The latest request to show the result of a scan.
    pub fn reveal(&self) -> Option<Reveal> {
        self.lock().reveal.clone()
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
        }
    }

    /// The treemap's tiles at one level: what lies directly under `at`, or, for an empty `at`,
    /// one tile per watched folder that has findings, and one for the scans outside them (the
    /// node with an empty path). `selected` is a file whose entry is wanted.
    pub fn inventory_view(&self, at: &Path, selected: Option<&Path>) -> InventoryView {
        let roots = effective_roots(&self.policy());
        let under = (!at.as_os_str().is_empty()).then_some(at);
        let nodes = self.inventory.children(under, &roots);
        let entry = selected.and_then(|file| {
            self.inventory
                .entries(Some(file), 0)
                .into_iter()
                .find(|entry| entry.path == file)
        });
        InventoryView {
            nodes,
            entry,
            roots,
        }
    }

    /// Writes the vault as CSV to a new file in Downloads and returns where it is. The file holds
    /// the values themselves.
    ///
    /// # Errors
    /// A message when the file cannot be written.
    pub fn export_vault(&self) -> Res<PathBuf> {
        exports::vault_csv(&self.engine(), &exports::downloads()?, &exports::stamp())
    }

    /// Writes what the inventory found under `under` (everything for an empty path) as CSV to a
    /// new file in Downloads and returns where it is.
    ///
    /// # Errors
    /// A message when the file cannot be written.
    pub fn export_report(&self, under: &Path) -> Res<PathBuf> {
        exports::report_csv(
            &self.inventory,
            under,
            &exports::downloads()?,
            &exports::stamp(),
        )
    }

    /// Writes the masked copy of `file` beside it and returns where it is.
    ///
    /// # Errors
    /// A message when the file cannot be read, is not a format piikey reads, or the copy cannot
    /// be written.
    pub fn masked_copy(&self, file: &Path) -> Res<PathBuf> {
        exports::masked_copy(&self.engine(), file)
    }

    /// The token the local HTTP API asks for; made on first use.
    ///
    /// # Errors
    /// A message when the token cannot be read or written.
    pub fn api_token() -> Res<String> {
        piikey::api::read_or_create_token(false).map_err(|error| error.to_string())
    }

    /// Replaces the token. The local API starts again to ask for the new one.
    ///
    /// # Errors
    /// A message when the token cannot be written.
    pub fn rotate_token(&self) -> Res<String> {
        let token = piikey::api::read_or_create_token(true).map_err(|error| error.to_string())?;
        self.submit(Command::RestartHttp);
        Ok(token)
    }

    /// The vault lost records outside the controller (the API removed them): what was typed may
    /// hold their values, and the numbers of Home are old.
    pub fn vault_changed(&self) {
        self.shared.typed.clear();
        self.submit(Command::Refresh);
    }

    /// Blocks until every scan that was asked for is done and none runs; `false` on timeout.
    pub fn wait_scans(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let (state, result) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                state.scan.is_some() || !self.scanner.idle()
            })
            .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        !result.timed_out()
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

    /// Cancels the scan that runs and gives it a moment to save what it did.
    fn stop_scans(&self) {
        self.scanner.stop();
        let state = self.lock();
        let _ = self
            .changed
            .wait_timeout_while(state, SCAN_STOP_WAIT, |state| state.scan.is_some())
            .unwrap_or_else(PoisonError::into_inner);
    }

    /// Writes the activity feed when it changed and `now` is set or the last write is
    /// [`FEED_SAVE_EVERY`] ago. It is a convenience: a failed write is retried next time.
    fn save_feed(&self, now: bool) {
        let text = {
            let mut state = self.lock();
            if !state.feed_dirty || !(now || state.feed_saved.elapsed() >= FEED_SAVE_EVERY) {
                return;
            }
            state.feed_saved = Instant::now();
            state.feed_dirty = false;
            state.activity.to_text()
        };
        if self.backend.save_activity(&text).is_err() {
            self.lock().feed_dirty = true;
        }
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

    fn policy(&self) -> Policy {
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

    fn start(&self) {
        let waiting = self.update(|state| {
            let waiting = matches!(state.model, Model::Downloading { .. });
            if waiting {
                state.fetch.then_start = true;
                state.notice = Some(Notice::warning(
                    "piikey turns on as soon as the model has downloaded.",
                ));
            }
            waiting || state.enabled
        });
        if waiting {
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
    fn resume(&self) {
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

    /// Downloads the model again after a failure.
    fn refetch(self: &Arc<Self>) {
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
    fn skip_model(&self) {
        let resume = self.update(|state| {
            if state.model == Model::Ready {
                return false;
            }
            state.model = Model::Skipped;
            state.notice = Some(Notice::warning(SKIPPED_TEXT));
            std::mem::take(&mut state.fetch.then_start)
        });
        if resume {
            self.resume();
        }
    }

    /// Starts the model download on its own thread unless one is running.
    fn spawn_fetch(self: &Arc<Self>) {
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
    fn stop(&self, reason: Option<String>) {
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

    fn install(&self) {
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

    fn refresh(&self) {
        let installed = self.backend.ca_installed();
        let summary = self.vault_summary();
        let totals = self.inventory.totals();
        self.update(|state| {
            state.cert = cert_of(installed);
            state.inventory_totals = totals;
            summary.apply(state);
        });
    }

    fn edit(self: &Arc<Self>, edit: &Edit) {
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
    fn settings(self: &Arc<Self>, patch: &SettingsPatch) {
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
    fn startup(self: &Arc<Self>) {
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
        match self.backend.start_http(policy.http_port) {
            Ok(http) => self.update(|state| state.http = Some(http)),
            Err(error) => self.notify(Notice::error(format!(
                "Could not start the local API on 127.0.0.1:{}: {error}",
                policy.http_port
            ))),
        }
    }

    /// The token changed: the local API, when it runs, starts again to ask for the new one.
    fn restart_http(&self) {
        if self.lock().http.is_some() {
            self.sync_http();
        }
    }

    /// Follows the inventory switch and the folders it watches or leaves out: what is newly
    /// left out is forgotten, and the watched folders are scanned (again) or no longer.
    fn sync_inventory(self: &Arc<Self>, old: &Policy, new: &Policy) {
        for path in new
            .inventory_exclude
            .iter()
            .filter(|path| !old.inventory_exclude.contains(path))
        {
            if let Err(error) = self.inventory.forget_under(path) {
                self.notify(Notice::error(format!(
                    "Could not update the PII inventory: {error}"
                )));
            }
        }
        let totals = self.inventory.totals();
        self.update(|state| state.inventory_totals = totals);
        self.scanner.watch(new.inventory);
        if new.inventory {
            self.ensure_scanner();
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
    fn highlight_failed(&self, error: &str) {
        self.notify(Notice::warning(format!(
            "piikey could not read the focused field ({error}); highlighting is off."
        )));
    }

    /// Starts or stops capture so that it runs exactly while protection or the highlight needs
    /// it; `starting` counts protection as on. `Some(error)` when it could not start.
    fn sync_capture(&self, starting: bool) -> Option<String> {
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

    /// Loads the detection model while something needs it, and frees its memory when nothing
    /// does: protection, the highlight, the inventory, a scan.
    fn sync_model(&self) {
        self.sync_model_with(false);
    }

    /// As [`Controller::sync_model`]; `starting` counts protection as on.
    fn sync_model_with(&self, starting: bool) {
        let policy = self.policy();
        let _one = self
            .model_sync
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (want, ready) = {
            let state = self.lock();
            (
                starting
                    || state.enabled
                    || policy.highlight != Highlight::Off
                    || policy.inventory
                    || state.scan.is_some(),
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

    /// Starts the scan thread the first time something needs it.
    fn ensure_scanner(self: &Arc<Self>) {
        if !self.scanner.start_once() {
            return;
        }
        let controller = Arc::downgrade(self);
        let scanner = Arc::clone(&self.scanner);
        let spawned = thread::Builder::new()
            .name("piikey-scan".into())
            .spawn(move || scan_loop(&controller, &scanner));
        if let Err(error) = spawned {
            self.scanner.start_failed();
            self.notify(Notice::error(format!(
                "Could not start the scan thread: {error}"
            )));
        }
    }

    /// Queues a scan of `paths`: it runs before the scan of the watched folders.
    fn ask_scan(self: &Arc<Self>, paths: Vec<PathBuf>, reveal: bool) {
        self.scanner.ask(Request { paths, reveal });
        self.ensure_scanner();
    }

    /// Scans the watched folders now, whether or not the inventory is on.
    fn rescan(self: &Arc<Self>) {
        let roots = effective_roots(&self.policy());
        self.ask_scan(roots, false);
    }

    /// Runs one scan, on the scan thread. It leaves the window with the result when it was
    /// asked to, and the inventory saved.
    fn run_scan(&self, pool: Option<&rayon::ThreadPool>, job: &Job) {
        let policy = self.policy();
        let (paths, reveal) = match &job.kind {
            Kind::Asked(request) => (request.paths.clone(), request.reveal),
            Kind::Watched => (effective_roots(&policy), false),
        };
        // A `piikey-cli` run on its own may be scanning the same inventory. A scan nobody asked
        // for waits for the next turn.
        let _lock = match self.inventory.lock_scan() {
            Ok(lock) => lock,
            Err(error) => {
                if matches!(job.kind, Kind::Asked(_)) {
                    self.notify(Notice::error(format!("Could not scan: {error}")));
                }
                return;
            }
        };
        let progress = Arc::new(Progress::default());
        self.update(|state| state.scan = Some(Arc::clone(&progress)));
        self.sync_model();
        let engine = self.engine();
        let finished = AtomicBool::new(false);
        let result = thread::scope(|scope| {
            // Progress reaches the window a few times a second.
            let ticker = scope.spawn(|| {
                while !finished.load(Ordering::Acquire) {
                    thread::park_timeout(PROGRESS_EVERY);
                    self.update(|_| {});
                }
            });
            let scan = || {
                self.inventory.scan_paths(
                    &engine,
                    &paths,
                    &policy.inventory_exclude,
                    &progress,
                    &job.cancel,
                )
            };
            let result = match pool {
                Some(pool) => pool.install(scan),
                None => scan(),
            };
            finished.store(true, Ordering::Release);
            ticker.thread().unpark();
            result
        });
        let totals = self.inventory.totals();
        let target = paths
            .first()
            .filter(|_| reveal && !job.cancelled())
            .map(|first| reveal_target(first));
        self.update(|state| {
            state.scan = None;
            state.inventory_totals = totals;
            if let Some((at, select)) = target {
                let seq = state.reveal.as_ref().map_or(0, |reveal| reveal.seq) + 1;
                state.reveal = Some(Reveal { seq, at, select });
            }
        });
        if let Err(error) = result {
            self.notify(Notice::error(format!(
                "Could not save the inventory: {error}"
            )));
        }
        self.sync_model();
    }

    /// Removes the vault records whose value or stand-in is one of `values`.
    fn forget(&self, values: &[String]) {
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        if let Err(error) = self.engine().forget(&values) {
            self.notify(Notice::error(format!(
                "Could not forget the values: {error}"
            )));
        }
        self.vault_lost();
    }

    /// Removes every vault record.
    fn wipe(&self) {
        if let Err(error) = self.engine().wipe() {
            self.notify(Notice::error(format!("Could not wipe the vault: {error}")));
        }
        self.vault_lost();
    }

    /// What was typed may hold values the vault no longer knows, and the numbers of Home are old.
    fn vault_lost(&self) {
        self.shared.typed.clear();
        self.refresh();
    }

    /// Writes the live settings to disk; a failure becomes a notice.
    fn persist(&self) {
        if let Err(error) = self.backend.save_policy(&self.policy()) {
            self.update(|state| {
                state.notice = Some(Notice::error(format!("Could not save settings: {error}")));
            });
        }
    }

    /// The vault's numbers for the Home page, and its list: the most recently sent values, filled
    /// up with the newest records. Takes the state lock briefly, so never call it holding it.
    fn vault_summary(&self) -> VaultSummary {
        let recent = self.keyed(&KeyedQuery::default(), RECENT).items;
        let engine = self.engine();
        let Ok(view) = engine.vault().read() else {
            return VaultSummary::default();
        };
        VaultSummary {
            issued: view.record_count(),
            recent,
        }
    }

    /// Notes where the proxies of a proxy event went; a failure of the proxy itself also stops
    /// the app.
    fn record(&self, event: &Event) {
        match event {
            Event::Masked {
                host, exe, proxies, ..
            } => {
                let now = activity::now();
                self.update(|state| {
                    for proxy in proxies {
                        state.activity.record(proxy, host, exe.as_deref(), now);
                    }
                    state.feed_dirty = true;
                    state.last_activity = Some(Sent {
                        host: host.clone(),
                        exe: exe.clone(),
                        at: clock(),
                    });
                });
                // After recording: the Home list starts with what was just sent.
                let summary = self.vault_summary();
                self.update(|state| summary.apply(state));
            }
            Event::Restored { host, .. } => self.update(|state| {
                state.last_activity = Some(Sent {
                    host: host.clone(),
                    exe: None,
                    at: clock(),
                });
            }),
            Event::Error(reason) => self.submit(Command::Fatal(reason.clone())),
        }
        self.save_feed(false);
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        // The scan thread waits for work: it ends.
        self.scanner.stop();
    }
}

/// The vault's part of the Home page.
#[derive(Default)]
struct VaultSummary {
    issued: u64,
    recent: Vec<Keyed>,
}

impl VaultSummary {
    /// Moves the numbers into `state`.
    fn apply(self, state: &mut State) {
        state.issued = self.issued;
        state.recent = self.recent;
    }
}

/// Whether `host` is `site` or one of its subdomains.
fn on_site(host: &str, site: &str) -> bool {
    host == site
        || host
            .strip_suffix(site)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// `used` as a row shows it, seen from `now`.
fn sent_of(used: &Use, now: i64) -> Sent {
    Sent {
        host: used.host.clone(),
        exe: used.exe.clone(),
        at: activity::when(used.ticks, now),
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

/// Moves the proxy's events into the controller until the controller goes away.
fn pump_events(controller: &Weak<Controller>, events: &Receiver<Event>) {
    while let Ok(event) = events.recv() {
        let Some(controller) = controller.upgrade() else {
            break;
        };
        controller.record(&event);
    }
}

/// `hh:mm`, local time.
fn clock() -> String {
    let now = DateTime::now().to_local();
    format!("{:02}:{:02}", now.hour(), now.minute())
}

/// Applies `edit` to `policy`; `Ok(false)` when nothing changed.
///
/// # Errors
/// The text the user typed is not a site, a program or a folder, or the folder does not exist.
pub fn apply_edit(policy: &mut Policy, edit: &Edit) -> Res<bool> {
    match edit {
        Edit::Site { site, on: true } => {
            let parsed = Policy::parse_site(site).ok_or_else(|| {
                format!(
                    "\"{}\" is not a site. Use a host such as example.com or *.example.com.",
                    site.trim()
                )
            })?;
            Ok(add(&mut policy.sites, parsed))
        }
        Edit::Site { site, on: false } => Ok(remove(&mut policy.sites, site)),
        Edit::Program { exe, on: true } => {
            let parsed = normalize_program(exe).ok_or_else(|| {
                format!(
                    "\"{}\" is not a program name. Use a name such as chrome.exe.",
                    exe.trim()
                )
            })?;
            Ok(add(&mut policy.programs, parsed))
        }
        Edit::Program { exe, on: false } => Ok(remove(&mut policy.programs, exe)),
        Edit::Kind { kind, on: true } => {
            let before = policy.disabled_kinds.len();
            policy.disabled_kinds.retain(|disabled| disabled != kind);
            Ok(policy.disabled_kinds.len() != before)
        }
        Edit::Kind { kind, on: false } => {
            if policy.disabled_kinds.contains(kind) {
                return Ok(false);
            }
            policy.disabled_kinds.push(*kind);
            policy.disabled_kinds.sort_unstable();
            Ok(true)
        }
        Edit::Highlight(mode) => Ok(set(&mut policy.highlight, *mode)),
        Edit::ExplorerMenu(on) => Ok(set(&mut policy.explorer_menu, *on)),
        Edit::Inventory(on) => {
            let mut changed = set(&mut policy.inventory, *on);
            if *on && policy.inventory_roots.is_empty() {
                let usual = default_inventory_roots();
                changed |= !usual.is_empty();
                policy.inventory_roots = usual;
            }
            Ok(changed)
        }
        Edit::InventoryRoot { path, on } => {
            folder_edit(&mut policy.inventory_roots, path, *on, true)
        }
        Edit::InventoryExclude { path, on } => {
            folder_edit(&mut policy.inventory_exclude, path, *on, false)
        }
        Edit::HttpApi(on) => Ok(set(&mut policy.http_api, *on)),
    }
}

fn add(list: &mut Vec<String>, value: String) -> bool {
    if list.contains(&value) {
        false
    } else {
        list.push(value);
        true
    }
}

fn remove(list: &mut Vec<String>, value: &str) -> bool {
    let before = list.len();
    list.retain(|item| item != value);
    list.len() != before
}

/// `Chrome`, `"C:\Program Files\Google\Chrome\chrome.exe"` and `chrome.exe` all become
/// `chrome.exe`; `None` when nothing usable is left. A pasted path keeps only its file name,
/// everything else is the settings' own rule ([`Policy::parse_program`]).
pub fn normalize_program(input: &str) -> Option<String> {
    let name = input.trim().trim_matches('"');
    Policy::parse_program(name.rsplit(['\\', '/']).next()?)
}

/// Names of the programs running now: lowercase, unique, sorted.
pub fn running_programs() -> Vec<String> {
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    let mut names: Vec<String> = system
        .processes()
        .values()
        .map(|process| process.name().to_string_lossy().to_ascii_lowercase())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The folders the inventory scans: the chosen ones, or the usual ones when none were chosen.
fn effective_roots(policy: &Policy) -> Vec<PathBuf> {
    if policy.inventory_roots.is_empty() {
        default_inventory_roots()
    } else {
        policy.inventory_roots.clone()
    }
}

/// Where the window shows the result of scanning `first`: the folder, or for a file its folder
/// with the file selected.
fn reveal_target(first: &Path) -> (PathBuf, Option<PathBuf>) {
    match (first.is_file(), first.parent()) {
        (true, Some(folder)) => (folder.to_path_buf(), Some(first.to_path_buf())),
        _ => (first.to_path_buf(), None),
    }
}

/// Half the cores, so the PC stays responsive while it scans.
fn scan_pool() -> Option<rayon::ThreadPool> {
    let cores = thread::available_parallelism().map_or(1, NonZeroUsize::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads((cores / 2).max(1))
        .thread_name(|index| format!("piikey-scan-{index}"))
        .build()
        .ok()
}

/// The scan thread: runs what the [`Scanner`] hands it, one scan at a time, until the scanner is
/// stopped or the controller goes away.
fn scan_loop(controller: &Weak<Controller>, scanner: &Scanner) {
    let pool = scan_pool();
    while let Some(job) = scanner.next() {
        let Some(controller) = controller.upgrade() else {
            return;
        };
        controller.run_scan(pool.as_ref(), &job);
        scanner.done(&job);
        // Whoever waits for the scans to be over looks again.
        controller.update(|_| {});
    }
}

/// Sets `slot` to `value`; whether that changed it.
fn set<T: PartialEq>(slot: &mut T, value: T) -> bool {
    if *slot == value {
        false
    } else {
        *slot = value;
        true
    }
}

/// Adds `path` to a list of folders, or takes it off; whether the list changed. With `existing`
/// an added path must be a folder that exists.
fn folder_edit(list: &mut Vec<PathBuf>, path: &Path, on: bool, existing: bool) -> Res<bool> {
    if !on {
        let before = list.len();
        list.retain(|item| item != path);
        return Ok(list.len() != before);
    }
    if existing && !path.is_dir() {
        return Err(format!("Not a folder: {}", path.display()));
    }
    let folder = Policy::parse_folder(&path.to_string_lossy()).ok_or_else(|| {
        format!(
            "\"{}\" is not a full path. Use a path such as C:\\Users\\you\\Documents.",
            path.display()
        )
    })?;
    if list.iter().any(|item| same_folder(item, &folder)) {
        return Ok(false);
    }
    list.push(folder);
    Ok(true)
}

/// The same folder spelled alike: component by component, ignoring ASCII case, as Windows paths
/// are, and a trailing separator.
fn same_folder(a: &Path, b: &Path) -> bool {
    let mut b = b.components();
    a.components().all(|part| {
        b.next()
            .is_some_and(|other| part.as_os_str().eq_ignore_ascii_case(other.as_os_str()))
    }) && b.next().is_none()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicBool, Ordering},
    };

    use piikey::detect::KindSet;

    use super::*;
    use crate::ui::testing::TempDir;

    type Test = Result<(), String>;

    /// Calls the fake saw, in order.
    type Calls = Arc<Mutex<Vec<String>>>;

    /// Settings with the features that start on their own switched off: protection is then the
    /// only thing that runs capture and holds the model, as it was before the features existed.
    fn quiet() -> Policy {
        Policy {
            highlight: Highlight::Off,
            explorer_menu: false,
            ..Policy::default()
        }
    }

    #[derive(Default)]
    struct Fake {
        calls: Calls,
        installed: AtomicBool,
        fail_start: AtomicBool,
        fail_enable: AtomicBool,
        fail_capture: AtomicBool,
        /// The detection model cannot be loaded.
        fail_load: AtomicBool,
        fail_disable: AtomicBool,
        fail_save: AtomicBool,
        fail_engine: AtomicBool,
        /// The detection model is not downloaded yet.
        model_missing: AtomicBool,
        fetch_fails: AtomicBool,
        events: Mutex<Option<Sender<Event>>>,
        vault: PathBuf,
        /// The local API cannot start.
        fail_http: AtomicBool,
        /// The Explorer menu cannot be changed.
        fail_menu: AtomicBool,
        /// The shortcut of the highlight is taken.
        fail_hotkey: AtomicBool,
        /// What `load_activity` returns.
        loaded_activity: Activity,
        /// Every text `save_activity` got.
        saved_activity: Mutex<Vec<String>>,
        /// Every policy `save_policy` got, also the ones it refused.
        saved: Mutex<Vec<Policy>>,
    }

    impl Fake {
        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The policy `save_policy` got last.
        fn last_saved(&self) -> Result<Policy, String> {
            self.saved
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .last()
                .cloned()
                .ok_or_else(|| "nothing was saved".to_owned())
        }
    }

    struct FakeProxy(Calls);

    impl Running for FakeProxy {
        fn stop(self: Box<Self>) {
            log(&self.0, "stop_proxy");
        }
    }

    struct FakeCapture(Calls);

    impl Running for FakeCapture {
        fn stop(self: Box<Self>) {
            log(&self.0, "stop_capture");
        }
    }

    struct FakeHttp(Calls);

    impl Running for FakeHttp {
        fn stop(self: Box<Self>) {
            log(&self.0, "stop_http");
        }
    }

    fn log(calls: &Calls, call: &str) {
        calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call.to_owned());
    }

    fn fails(flag: &AtomicBool) -> bool {
        flag.load(Ordering::Relaxed)
    }

    impl Backend for Arc<Fake> {
        fn ensure_ca(&self) -> Res<()> {
            log(&self.calls, "ensure_ca");
            Ok(())
        }

        fn ca_installed(&self) -> bool {
            log(&self.calls, "ca_installed");
            self.installed.load(Ordering::Relaxed)
        }

        fn install_ca(&self) -> Res<()> {
            log(&self.calls, "install_ca");
            self.installed.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn start_proxy(
            &self,
            _shared: Arc<Shared>,
            events: Sender<Event>,
        ) -> Res<Box<dyn Running>> {
            log(&self.calls, "start_proxy");
            if fails(&self.fail_start) {
                return Err("port in use".into());
            }
            *self.events.lock().unwrap_or_else(PoisonError::into_inner) = Some(events);
            Ok(Box::new(FakeProxy(Arc::clone(&self.calls))))
        }

        fn enable_system_proxy(&self) -> Res<()> {
            log(&self.calls, "enable_system_proxy");
            if fails(&self.fail_enable) {
                return Err("registry".into());
            }
            Ok(())
        }

        fn disable_system_proxy(&self) -> Res<()> {
            log(&self.calls, "disable_system_proxy");
            if fails(&self.fail_disable) {
                return Err("registry".into());
            }
            Ok(())
        }

        fn start_capture(&self, _shared: Arc<Shared>) -> Res<Box<dyn Running>> {
            log(&self.calls, "start_capture");
            if fails(&self.fail_capture) {
                return Err("no uia".into());
            }
            Ok(Box::new(FakeCapture(Arc::clone(&self.calls))))
        }

        fn save_policy(&self, policy: &Policy) -> Res<()> {
            log(&self.calls, "save_policy");
            self.saved
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(policy.clone());
            if fails(&self.fail_save) {
                return Err("disk full".into());
            }
            Ok(())
        }

        fn open_engine(&self) -> Res<Engine> {
            log(&self.calls, "open_engine");
            if fails(&self.fail_engine) {
                return Err("vault locked".into());
            }
            Engine::open(&self.vault).map_err(|e| e.to_string())
        }

        fn open_inventory(&self) -> Res<Inventory> {
            Inventory::open(&self.vault.with_file_name("inventory.jsonl"))
                .map_err(|e| e.to_string())
        }

        fn start_http(&self, port: u16) -> Res<Box<dyn Running>> {
            log(&self.calls, &format!("start_http({port})"));
            if fails(&self.fail_http) {
                return Err("port in use".into());
            }
            Ok(Box::new(FakeHttp(Arc::clone(&self.calls))))
        }

        fn set_explorer_menu(&self, on: bool) -> Res<()> {
            log(&self.calls, &format!("set_explorer_menu({on})"));
            if fails(&self.fail_menu) {
                return Err("registry".into());
            }
            Ok(())
        }

        fn set_hotkey(&self, _shared: &Shared, on: bool) -> Res<()> {
            log(&self.calls, &format!("set_hotkey({on})"));
            if fails(&self.fail_hotkey) {
                return Err("Ctrl+Alt+P is used by another program".into());
            }
            Ok(())
        }

        fn model_installed(&self) -> bool {
            !fails(&self.model_missing)
        }

        fn fetch_model(&self, progress: &mut dyn FnMut(u64, u64)) -> Res<()> {
            log(&self.calls, "fetch_model");
            progress(50, 100);
            if fails(&self.fetch_fails) {
                return Err("offline".into());
            }
            self.model_missing.store(false, Ordering::Relaxed);
            Ok(())
        }

        fn load_model(&self) -> Res<()> {
            log(&self.calls, "load_model");
            if fails(&self.fail_load) {
                return Err("no gpu".into());
            }
            Ok(())
        }

        fn release_model(&self) {
            log(&self.calls, "release_model");
        }

        fn load_activity(&self) -> Activity {
            self.loaded_activity.clone()
        }

        fn save_activity(&self, text: &str) -> Res<()> {
            self.saved_activity
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(text.to_owned());
            Ok(())
        }
    }

    struct Rig {
        controller: Arc<Controller>,
        fake: Arc<Fake>,
        _dir: TempDir,
    }

    fn rig(installed: bool, policy: Policy) -> Result<Rig, String> {
        let dir = TempDir::new()?;
        let vault = dir.0.join("vault.pkv");
        let fake = Arc::new(Fake {
            installed: AtomicBool::new(installed),
            vault: vault.clone(),
            ..Fake::default()
        });
        let engine = Engine::open(&vault).map_err(|e| e.to_string())?;
        let inventory = fake.open_inventory()?;
        let controller = Controller::new(
            Box::new(Arc::clone(&fake)),
            vault,
            policy,
            engine,
            inventory,
            None,
        )?;
        Ok(Rig {
            controller,
            fake,
            _dir: dir,
        })
    }

    impl Rig {
        fn run(&self, command: Command) -> Test {
            self.controller.submit(command);
            if self.controller.wait_idle(Duration::from_secs(20)) {
                Ok(())
            } else {
                Err("command did not finish".into())
            }
        }

        fn calls(&self) -> Vec<String> {
            self.fake.calls()
        }

        fn forget_calls(&self) {
            self.fake
                .calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
        }

        fn live(&self) -> bool {
            self.controller.policy().enabled
        }

        fn notice(&self) -> Option<Notice> {
            self.controller.snapshot().notice
        }
    }

    fn masked(host: &str, proxies: &[&str]) -> Event {
        Event::Masked {
            host: host.into(),
            exe: Some("chrome.exe".into()),
            proxies: proxies.iter().map(|&p| p.to_owned()).collect(),
        }
    }

    /// A controller started the way the app starts it, and what the fake saw.
    struct Launched {
        fake: Arc<Fake>,
        outcome: Res<Arc<Controller>>,
        _dir: TempDir,
    }

    impl Launched {
        fn controller(&self) -> Result<&Arc<Controller>, String> {
            self.outcome.as_ref().map_err(Clone::clone)
        }

        fn failure(&self) -> Result<&str, String> {
            self.outcome
                .as_ref()
                .err()
                .map(String::as_str)
                .ok_or_else(|| "the launch should have failed".to_owned())
        }
    }

    /// Launches with the saved wish `saved_on`; `setup` sets the fake up first.
    fn launch(
        installed: bool,
        saved_on: bool,
        setup: impl FnOnce(&Fake),
    ) -> Result<Launched, String> {
        let policy = Policy {
            enabled: saved_on,
            ..quiet()
        };
        launch_with(installed, policy, setup)
    }

    /// Launches with the saved `policy`; `setup` sets the fake up first.
    fn launch_with(
        installed: bool,
        policy: Policy,
        setup: impl FnOnce(&Fake),
    ) -> Result<Launched, String> {
        let dir = TempDir::new()?;
        let vault = dir.0.join("vault.pkv");
        let fake = Arc::new(Fake {
            installed: AtomicBool::new(installed),
            vault: vault.clone(),
            ..Fake::default()
        });
        setup(&fake);
        let outcome = Controller::launch(Box::new(Arc::clone(&fake)), vault, policy, None);
        if let Ok(controller) = &outcome
            && !controller.wait_idle(Duration::from_secs(20))
        {
            return Err("the launch commands did not finish".into());
        }
        Ok(Launched {
            fake,
            outcome,
            _dir: dir,
        })
    }

    fn fail(flag: &AtomicBool) {
        flag.store(true, Ordering::Relaxed);
    }

    #[test]
    fn launching_with_the_app_saved_off_gives_windows_its_proxy_back() -> Test {
        let launched = launch(true, false, |_| {})?;
        // Windows first, before the vault is even opened; the app itself stays off.
        assert_eq!(
            launched.fake.calls(),
            ["disable_system_proxy", "open_engine", "ca_installed"]
        );
        let snapshot = launched.controller()?.snapshot();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.notice, None);
        Ok(())
    }

    #[test]
    fn a_failed_restore_at_launch_is_reported_and_the_app_still_starts() -> Test {
        let launched = launch(true, false, |fake| fail(&fake.fail_disable))?;
        let notice = launched
            .controller()?
            .snapshot()
            .notice
            .ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Error);
        assert!(
            notice.text.contains("Windows proxy settings") && notice.text.contains("registry"),
            "{}",
            notice.text
        );
        Ok(())
    }

    #[test]
    fn launching_with_the_app_saved_on_resumes_it_without_restoring_first() -> Test {
        let launched = launch(true, true, |_| {})?;
        assert_eq!(
            launched.fake.calls(),
            [
                "open_engine",
                "ca_installed",
                "ensure_ca",
                "ca_installed",
                "load_model",
                "start_proxy",
                "enable_system_proxy",
                "start_capture",
                "save_policy"
            ]
        );
        let controller = launched.controller()?;
        assert!(controller.snapshot().enabled && controller.policy().enabled);
        assert_eq!(controller.snapshot().notice, None);
        Ok(())
    }

    /// Waits until `done` holds for a snapshot and every queued command has finished.
    fn wait_for(
        controller: &Controller,
        done: impl Fn(&Snapshot) -> bool,
    ) -> Result<Snapshot, String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut snapshot = controller.snapshot();
        while !done(&snapshot) {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| format!("timed out at {snapshot:?}"))?;
            if let Some(next) = controller.wait_changed(snapshot.version, left) {
                snapshot = next;
            }
        }
        if !controller.wait_idle(Duration::from_secs(20)) {
            return Err("commands did not finish".into());
        }
        Ok(controller.snapshot())
    }

    #[test]
    fn a_launch_without_the_model_downloads_it_then_turns_on() -> Test {
        let launched = launch(true, true, |fake| fail(&fake.model_missing))?;
        let controller = launched.controller()?;
        let snapshot = wait_for(controller, |s| s.model == Model::Ready && s.enabled)?;
        assert_eq!(snapshot.notice, None);
        let calls = launched.fake.calls();
        // Windows gets its settings back for the download, which comes before the proxy.
        assert_eq!(
            calls.first().map(String::as_str),
            Some("disable_system_proxy")
        );
        let at = |call: &str| calls.iter().position(|c| c == call);
        let (fetch, load, start) = (at("fetch_model"), at("load_model"), at("start_proxy"));
        assert!(fetch.is_some() && fetch < load && load < start, "{calls:?}");
        Ok(())
    }

    #[test]
    fn a_failed_download_leaves_the_app_off() -> Test {
        let launched = launch(true, true, |fake| {
            fail(&fake.model_missing);
            fail(&fake.fetch_fails);
        })?;
        let controller = launched.controller()?;
        let snapshot = wait_for(controller, |s| matches!(s.model, Model::Failed(_)))?;
        assert_eq!(snapshot.model, Model::Failed("offline".into()));
        assert!(!snapshot.enabled);
        assert!(!launched.fake.calls().iter().any(|c| c == "start_proxy"));
        Ok(())
    }

    #[test]
    fn going_on_without_the_model_warns_and_masks_patterns_only() -> Test {
        let launched = launch(true, false, |fake| {
            fail(&fake.model_missing);
            fail(&fake.fetch_fails);
        })?;
        let controller = launched.controller()?;
        wait_for(controller, |s| matches!(s.model, Model::Failed(_)))?;
        controller.submit(Command::SkipModel);
        let snapshot = wait_for(controller, |s| s.model == Model::Skipped)?;
        let notice = snapshot.notice.ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Warning);
        assert!(notice.text.contains("not downloaded"), "{}", notice.text);
        // Turning on now starts without loading a model.
        controller.submit(Command::SetEnabled(true));
        let snapshot = wait_for(controller, |s| s.enabled)?;
        assert!(snapshot.enabled);
        assert!(!launched.fake.calls().iter().any(|c| c == "load_model"));
        Ok(())
    }

    #[test]
    fn a_resume_without_the_certificate_gives_windows_its_proxy_back() -> Test {
        let launched = launch(false, true, |_| {})?;
        assert_eq!(
            launched.fake.calls(),
            [
                "open_engine",
                "ca_installed",
                "ensure_ca",
                "ca_installed",
                "release_model",
                "disable_system_proxy",
                "save_policy"
            ]
        );
        let controller = launched.controller()?;
        let snapshot = controller.snapshot();
        assert!(!snapshot.enabled && !controller.policy().enabled);
        assert_eq!(snapshot.notice.map(|n| n.severity), Some(Severity::Warning));
        Ok(())
    }

    #[test]
    fn a_resume_whose_proxy_will_not_start_gives_windows_its_proxy_back() -> Test {
        let launched = launch(true, true, |fake| fail(&fake.fail_start))?;
        assert_eq!(
            launched.fake.calls(),
            [
                "open_engine",
                "ca_installed",
                "ensure_ca",
                "ca_installed",
                "load_model",
                "start_proxy",
                "release_model",
                "disable_system_proxy",
                "save_policy"
            ]
        );
        let controller = launched.controller()?;
        assert!(!controller.snapshot().enabled && !controller.policy().enabled);
        let notice = controller.snapshot().notice.ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Error);
        assert!(notice.text.contains("port in use"), "{}", notice.text);
        Ok(())
    }

    #[test]
    fn a_failed_restore_after_a_failed_resume_keeps_the_cause() -> Test {
        let launched = launch(true, true, |fake| {
            fail(&fake.fail_start);
            fail(&fake.fail_disable);
        })?;
        let notice = launched
            .controller()?
            .snapshot()
            .notice
            .ok_or("no notice")?;
        assert!(notice.text.contains("port in use"), "{}", notice.text);
        assert!(
            notice
                .text
                .contains("Windows may still point at piikey's proxy"),
            "{}",
            notice.text
        );
        Ok(())
    }

    #[test]
    fn a_vault_that_will_not_open_still_gives_windows_its_proxy_back() -> Test {
        // Saved off: restored once, up front.
        let off = launch(true, false, |fake| fail(&fake.fail_engine))?;
        assert_eq!(off.fake.calls(), ["disable_system_proxy", "open_engine"]);
        assert!(off.failure()?.contains("vault locked"));
        // Saved on: nothing will start the app, so it is restored after the failure.
        let on = launch(true, true, |fake| fail(&fake.fail_engine))?;
        assert_eq!(on.fake.calls(), ["open_engine", "disable_system_proxy"]);
        assert!(on.failure()?.contains("vault locked"));
        Ok(())
    }

    #[test]
    fn notices_follow_their_cause() {
        assert_eq!(follow(None, "B.").text, "B.");
        assert_eq!(follow(Some(Notice::warning("A")), "B.").text, "A. B.");
        assert_eq!(follow(Some(Notice::warning("A.")), "B.").text, "A. B.");
    }

    #[test]
    fn turning_on_starts_the_proxy_then_points_windows_at_it() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        assert_eq!(
            rig.calls(),
            [
                "ensure_ca",
                "ca_installed",
                "load_model",
                "start_proxy",
                "enable_system_proxy",
                "start_capture",
                "save_policy"
            ]
        );
        let snapshot = rig.controller.snapshot();
        assert!(snapshot.enabled && rig.live());
        assert_eq!(snapshot.cert, Cert::Installed);
        assert_eq!(snapshot.notice, None);
        assert_eq!(snapshot.busy, None);
        Ok(())
    }

    #[test]
    fn a_capture_that_cannot_start_leaves_protection_on_and_warns() -> Test {
        let rig = rig(true, quiet())?;
        fail(&rig.fake.fail_capture);
        rig.run(Command::SetEnabled(true))?;
        let snapshot = rig.controller.snapshot();
        assert!(snapshot.enabled && rig.live(), "protection stays on");
        let notice = snapshot.notice.ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Warning);
        assert!(
            notice.text.contains("no uia") && notice.text.contains("checks whole requests"),
            "{}",
            notice.text
        );
        // There is nothing to stop afterwards.
        rig.forget_calls();
        rig.run(Command::SetEnabled(false))?;
        assert_eq!(
            rig.calls(),
            [
                "disable_system_proxy",
                "stop_proxy",
                "release_model",
                "save_policy"
            ]
        );
        Ok(())
    }

    #[test]
    fn a_capture_warning_follows_the_model_warning() -> Test {
        let rig = rig(true, quiet())?;
        fail(&rig.fake.fail_load);
        fail(&rig.fake.fail_capture);
        rig.run(Command::SetEnabled(true))?;
        let snapshot = rig.controller.snapshot();
        assert!(snapshot.enabled);
        let notice = snapshot.notice.ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Warning);
        assert!(
            notice.text.contains("no gpu") && notice.text.contains("no uia"),
            "{}",
            notice.text
        );
        Ok(())
    }

    #[test]
    fn capture_runs_only_while_the_app_is_on() -> Test {
        let rig = rig(true, quiet())?;
        let count = |call: &str| rig.calls().iter().filter(|c| *c == call).count();
        rig.run(Command::SetEnabled(true))?;
        assert_eq!((count("start_capture"), count("stop_capture")), (1, 0));
        rig.run(Command::SetEnabled(false))?;
        assert_eq!((count("start_capture"), count("stop_capture")), (1, 1));
        rig.run(Command::SetEnabled(true))?;
        assert_eq!((count("start_capture"), count("stop_capture")), (2, 1));
        // Turning on again does not start a second one.
        rig.run(Command::SetEnabled(true))?;
        assert_eq!((count("start_capture"), count("stop_capture")), (2, 1));
        Ok(())
    }

    #[test]
    fn turning_on_without_the_certificate_only_warns() -> Test {
        let rig = rig(false, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        assert_eq!(rig.calls(), ["ensure_ca", "ca_installed", "release_model"]);
        let snapshot = rig.controller.snapshot();
        assert!(!snapshot.enabled && !rig.live());
        assert_eq!(snapshot.cert, Cert::Missing);
        assert_eq!(snapshot.notice.map(|n| n.severity), Some(Severity::Warning));
        Ok(())
    }

    #[test]
    fn a_proxy_that_will_not_start_leaves_everything_off() -> Test {
        let rig = rig(true, quiet())?;
        rig.fake.fail_start.store(true, Ordering::Relaxed);
        rig.run(Command::SetEnabled(true))?;
        assert!(!rig.controller.snapshot().enabled && !rig.live());
        assert!(!rig.calls().contains(&"enable_system_proxy".to_owned()));
        assert!(!rig.calls().contains(&"start_capture".to_owned()));
        let notice = rig.notice().ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Error);
        assert!(notice.text.contains("port in use"));
        Ok(())
    }

    #[test]
    fn a_windows_failure_stops_the_proxy_again() -> Test {
        let rig = rig(true, quiet())?;
        rig.fake.fail_enable.store(true, Ordering::Relaxed);
        rig.run(Command::SetEnabled(true))?;
        assert!(!rig.controller.snapshot().enabled && !rig.live());
        assert!(rig.calls().ends_with(&[
            "enable_system_proxy".to_owned(),
            "stop_proxy".to_owned(),
            "release_model".to_owned()
        ]));
        assert!(!rig.calls().contains(&"start_capture".to_owned()));
        Ok(())
    }

    #[test]
    fn turning_off_restores_windows_before_stopping_the_proxy() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        rig.forget_calls();
        rig.run(Command::SetEnabled(false))?;
        assert_eq!(
            rig.calls(),
            [
                "disable_system_proxy",
                "stop_proxy",
                "stop_capture",
                "release_model",
                "save_policy"
            ]
        );
        assert!(!rig.controller.snapshot().enabled && !rig.live());
        Ok(())
    }

    #[test]
    fn turning_off_keeps_the_app_when_windows_cannot_be_restored() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        rig.fake.fail_disable.store(true, Ordering::Relaxed);
        rig.forget_calls();
        rig.run(Command::SetEnabled(false))?;
        assert_eq!(rig.calls(), ["disable_system_proxy"]);
        assert!(rig.controller.snapshot().enabled && rig.live());
        assert_eq!(rig.notice().map(|n| n.severity), Some(Severity::Error));
        Ok(())
    }

    #[test]
    fn a_proxy_error_turns_the_app_off() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        rig.forget_calls();
        let events = rig
            .fake
            .events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or("proxy never started")?;
        events
            .send(Event::Error("runtime panicked".into()))
            .map_err(|e| e.to_string())?;
        // The event thread records the error, then queues the stop on the worker.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while rig.controller.snapshot().enabled {
            if std::time::Instant::now() > deadline {
                return Err("the app never turned off".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(rig.controller.wait_idle(Duration::from_secs(20)));
        assert_eq!(
            rig.calls(),
            [
                "disable_system_proxy",
                "stop_proxy",
                "stop_capture",
                "release_model",
                "save_policy"
            ]
        );
        assert!(!rig.live());
        let notice = rig.notice().ok_or("no notice")?;
        assert!(notice.text.contains("runtime panicked"));
        Ok(())
    }

    #[test]
    fn installing_the_certificate_updates_its_state() -> Test {
        let rig = rig(false, quiet())?;
        rig.run(Command::Refresh)?;
        assert_eq!(rig.controller.snapshot().cert, Cert::Missing);
        rig.run(Command::InstallCertificate)?;
        let snapshot = rig.controller.snapshot();
        assert_eq!(snapshot.cert, Cert::Installed);
        assert_eq!(snapshot.notice, None);
        Ok(())
    }

    #[test]
    fn a_kind_edit_persists_and_reaches_the_engine() -> Test {
        let rig = rig(true, quiet())?;
        let email = |on| {
            Command::Edit(Edit::Kind {
                kind: EntityKind::Email,
                on,
            })
        };
        rig.run(email(false))?;
        assert_eq!(rig.calls(), ["save_policy"]);
        assert_eq!(rig.fake.last_saved()?.disabled_kinds, [EntityKind::Email]);
        assert_eq!(
            rig.controller.engine().enabled(),
            KindSet::ALL.without(EntityKind::Email)
        );
        assert_eq!(
            rig.controller.snapshot().policy.disabled_kinds,
            [EntityKind::Email]
        );
        rig.run(email(true))?;
        assert_eq!(rig.calls(), ["save_policy", "save_policy"]);
        assert!(rig.fake.last_saved()?.disabled_kinds.is_empty());
        assert_eq!(rig.controller.engine().enabled(), KindSet::ALL);
        rig.run(email(true))?;
        assert_eq!(rig.calls().len(), 2, "repeating an edit saves nothing");
        Ok(())
    }

    #[test]
    fn a_failed_save_leaves_the_old_settings_and_engine() -> Test {
        let rig = rig(true, quiet())?;
        let before = rig.controller.engine();
        rig.fake.fail_save.store(true, Ordering::Relaxed);
        rig.run(Command::Edit(Edit::Site {
            site: "example.com".into(),
            on: true,
        }))?;
        assert!(Arc::ptr_eq(&before, &rig.controller.engine()));
        assert!(rig.controller.snapshot().policy.sites.is_empty());
        assert_eq!(rig.notice().map(|n| n.severity), Some(Severity::Error));
        Ok(())
    }

    #[test]
    fn a_failed_save_leaves_the_enabled_kinds_alone() -> Test {
        let rig = rig(true, quiet())?;
        rig.fake.fail_save.store(true, Ordering::Relaxed);
        rig.run(Command::Edit(Edit::Kind {
            kind: EntityKind::Email,
            on: false,
        }))?;
        assert_eq!(rig.controller.engine().enabled(), KindSet::ALL);
        assert!(rig.controller.snapshot().policy.disabled_kinds.is_empty());
        assert_eq!(rig.notice().map(|n| n.severity), Some(Severity::Error));
        Ok(())
    }

    #[test]
    fn saved_kinds_reach_the_engine_at_startup() -> Test {
        let policy = Policy {
            disabled_kinds: vec![EntityKind::Email],
            ..quiet()
        };
        let expected = KindSet::ALL.without(EntityKind::Email);
        assert_eq!(
            rig(true, policy.clone())?.controller.engine().enabled(),
            expected
        );
        let launched = launch_with(true, policy, |_| {})?;
        assert_eq!(launched.controller()?.engine().enabled(), expected);
        Ok(())
    }

    #[test]
    fn site_edits_reach_the_policy_the_proxy_reads() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::Edit(Edit::Site {
            site: "Example.COM".into(),
            on: true,
        }))?;
        rig.run(Command::Edit(Edit::Program {
            exe: "Chrome".into(),
            on: true,
        }))?;
        assert_eq!(rig.controller.policy().sites, ["example.com"]);
        assert_eq!(rig.controller.policy().programs, ["chrome.exe"]);
        rig.run(Command::Edit(Edit::Site {
            site: "example.com".into(),
            on: false,
        }))?;
        assert!(rig.controller.policy().sites.is_empty());
        // A repeated add changes nothing, so nothing is saved.
        rig.forget_calls();
        rig.run(Command::Edit(Edit::Program {
            exe: "chrome.exe".into(),
            on: true,
        }))?;
        assert!(rig.calls().is_empty());
        Ok(())
    }

    #[test]
    fn the_saved_wish_does_not_turn_the_live_flag_on() -> Test {
        let rig = rig(
            true,
            Policy {
                enabled: true,
                ..quiet()
            },
        )?;
        assert!(!rig.live() && !rig.controller.snapshot().enabled);
        Ok(())
    }

    /// Issues proxies for `texts` the way the proxy does, one text after the other (a batch
    /// is stored sorted, not in text order); returns them oldest first.
    fn issue(rig: &Rig, texts: &[&str]) -> Result<Vec<String>, String> {
        let engine = rig.controller.engine();
        for text in texts {
            engine
                .run(piikey::detect::Mode::Anonymize, &[text])
                .map_err(|e| e.to_string())?;
        }
        let view = engine.vault().read().map_err(|e| e.to_string())?;
        let mut proxies: Vec<String> = view.newest_first().map(|(_, _, p)| p.to_owned()).collect();
        proxies.reverse();
        Ok(proxies)
    }

    #[test]
    fn the_home_list_shows_where_values_went() -> Test {
        let rig = rig(true, quiet())?;
        let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
        rig.controller
            .record(&masked("chatgpt.com", &[proxies[0].as_str()]));
        rig.controller.record(&Event::Restored {
            host: "claude.ai".into(),
            count: 4,
        });
        let snap = rig.controller.snapshot();
        assert_eq!(snap.issued, 2);
        // The sent email first, though the phone is newer; then the phone, never sent.
        let email = snap.recent.first().ok_or("no recent")?;
        assert_eq!(email.original, "jan.jansen@acme.nl");
        let sent = email.sent.as_ref().ok_or("the email was sent")?;
        assert_eq!(
            (sent.host.as_str(), sent.exe.as_deref()),
            ("chatgpt.com", Some("chrome.exe"))
        );
        let phone = snap.recent.get(1).ok_or("no phone")?;
        assert_eq!(phone.kind, EntityKind::Phone);
        assert_eq!(phone.sent, None);
        assert_eq!(
            snap.last_activity.map(|a| a.host).as_deref(),
            Some("claude.ai")
        );
        Ok(())
    }

    /// A query for `text` alone.
    fn text(text: &str) -> KeyedQuery {
        KeyedQuery {
            text: text.to_owned(),
            ..KeyedQuery::default()
        }
    }

    #[test]
    fn keyed_values_filter_by_text_and_kind_newest_first() -> Test {
        let rig = rig(true, quiet())?;
        issue(
            &rig,
            &[
                "jan.jansen@acme.nl",
                "piet@acme.nl",
                "kees@example.org",
                "+31 6 12345678",
            ],
        )?;
        let acme = rig.controller.keyed(&text("ACME"), 1);
        assert_eq!(acme.matched, 2);
        assert_eq!(acme.items.len(), 1, "capped at the limit");
        assert!(acme.items[0].original.contains("acme"));
        let phone_query = KeyedQuery {
            kind: Some(EntityKind::Phone),
            ..KeyedQuery::default()
        };
        let phones = rig.controller.keyed(&phone_query, 10);
        assert_eq!(phones.matched, 1);
        assert_eq!(phones.items[0].kind, EntityKind::Phone);
        // The proxy is searchable too.
        let proxy = phones.items[0].proxy.clone();
        assert_eq!(rig.controller.keyed(&text(&proxy), 10).matched, 1);
        assert_eq!(rig.controller.keyed(&text("nobody"), 10).matched, 0);
        Ok(())
    }

    #[test]
    fn a_value_keyed_long_ago_comes_first_once_it_is_sent_again() -> Test {
        let rig = rig(true, quiet())?;
        let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
        // The email is the older record; sending it again puts it on top.
        rig.controller
            .record(&masked("chatgpt.com", &[proxies[0].as_str()]));
        let first = |items: &[Keyed]| items.first().map(|k| k.original.clone());
        let all = rig.controller.keyed(&KeyedQuery::default(), 10);
        assert_eq!(first(&all.items).as_deref(), Some("jan.jansen@acme.nl"));
        assert_eq!(all.matched, 2, "the never-sent phone is still listed");
        assert_eq!(
            first(&rig.controller.snapshot().recent).as_deref(),
            Some("jan.jansen@acme.nl")
        );
        assert_eq!(all.sites, ["chatgpt.com"]);
        Ok(())
    }

    #[test]
    fn keyed_values_filter_by_site_and_search_finds_sites() -> Test {
        let rig = rig(true, quiet())?;
        let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
        rig.controller
            .record(&masked("chat.openai.com", &[proxies[0].as_str()]));
        rig.controller
            .record(&masked("claude.ai", &[proxies[1].as_str()]));
        let site = |site: &str| KeyedQuery {
            site: Some(site.to_owned()),
            ..KeyedQuery::default()
        };
        // A subdomain counts for its site; never-sent values do not show under a site.
        let openai = rig.controller.keyed(&site("openai.com"), 10);
        assert_eq!(openai.matched, 1);
        assert_eq!(openai.items[0].original, "jan.jansen@acme.nl");
        assert_eq!(rig.controller.keyed(&site("penai.com"), 10).matched, 0);
        // The search box matches the site and the program.
        let claude = rig.controller.keyed(&text("CLAUDE"), 10);
        assert_eq!(claude.matched, 1);
        assert_eq!(claude.items[0].kind, EntityKind::Phone);
        assert_eq!(rig.controller.keyed(&text("chrome"), 10).matched, 2);
        assert_eq!(
            rig.controller.keyed(&KeyedQuery::default(), 10).sites,
            ["claude.ai", "chat.openai.com"]
        );
        Ok(())
    }

    #[test]
    fn the_feed_is_loaded_at_start_filtered_by_time_and_saved_at_shutdown() -> Test {
        let dir = TempDir::new()?;
        let vault = dir.0.join("vault.pkv");
        let engine = Engine::open(&vault).map_err(|e| e.to_string())?;
        engine
            .run(
                piikey::detect::Mode::Anonymize,
                &["mail jan.jansen@acme.nl"],
            )
            .map_err(|e| e.to_string())?;
        let proxy = {
            let view = engine.vault().read().map_err(|e| e.to_string())?;
            view.newest_first()
                .next()
                .map(|(_, _, p)| p.to_owned())
                .ok_or("nothing issued")?
        };
        let three_days_ago = activity::now() - 3 * 864_000_000_000;
        let mut loaded_activity = Activity::default();
        loaded_activity.record(&proxy, "claude.ai", None, three_days_ago);
        let fake = Arc::new(Fake {
            vault: vault.clone(),
            loaded_activity,
            ..Fake::default()
        });
        let inventory = fake.open_inventory()?;
        let controller = Controller::new(
            Box::new(Arc::clone(&fake)),
            vault,
            quiet(),
            engine,
            inventory,
            None,
        )?;
        let period = |period: Period| KeyedQuery {
            period,
            ..KeyedQuery::default()
        };
        let week = controller.keyed(&period(Period::Week), 10);
        assert_eq!(week.matched, 1);
        let sent = week.items[0].sent.as_ref().ok_or("not sent")?;
        assert_eq!(sent.host, "claude.ai");
        assert_eq!(controller.keyed(&period(Period::Today), 10).matched, 0);
        // Saved when anything changed.
        controller.record(&masked("chatgpt.com", &[proxy.as_str()]));
        controller.shutdown();
        let saved = fake
            .saved_activity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .cloned()
            .ok_or("nothing saved")?;
        let saved = Activity::parse(&saved);
        let latest = saved.iter().next().ok_or("empty")?;
        assert_eq!((latest.host.as_str(), latest.count), ("chatgpt.com", 2));
        Ok(())
    }

    #[test]
    fn shutdown_gives_windows_its_settings_back() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        rig.forget_calls();
        rig.controller.shutdown();
        assert_eq!(
            rig.calls(),
            ["disable_system_proxy", "stop_proxy", "stop_capture"]
        );
        // Commands after shutdown are ignored.
        rig.controller.submit(Command::SetEnabled(true));
        assert!(rig.calls().len() == 3 && rig.controller.wait_idle(Duration::from_secs(5)));
        Ok(())
    }

    #[test]
    fn programs_are_normalized() {
        assert_eq!(normalize_program("Chrome").as_deref(), Some("chrome.exe"));
        assert_eq!(
            normalize_program(" CHROME.EXE ").as_deref(),
            Some("chrome.exe")
        );
        assert_eq!(
            normalize_program(r#""C:\Program Files\Google\Chrome\chrome.exe""#).as_deref(),
            Some("chrome.exe")
        );
        assert_eq!(normalize_program("code - insiders"), None);
        assert_eq!(normalize_program("   "), None);
        assert_eq!(normalize_program("a|b"), None);
        assert_eq!(normalize_program(r"C:\folder\"), None);
    }

    #[test]
    fn edits_report_whether_they_changed_anything() -> Test {
        let mut policy = Policy::default();
        let add_site = Edit::Site {
            site: "claude.ai".into(),
            on: true,
        };
        assert!(apply_edit(&mut policy, &add_site)?);
        assert!(!apply_edit(&mut policy, &add_site)?);
        assert!(apply_edit(
            &mut policy,
            &Edit::Site {
                site: "claude.ai".into(),
                on: false
            }
        )?);
        let kind = |kind, on| Edit::Kind { kind, on };
        assert!(apply_edit(&mut policy, &kind(EntityKind::Phone, false))?);
        assert!(apply_edit(&mut policy, &kind(EntityKind::Email, false))?);
        assert_eq!(
            policy.disabled_kinds,
            [EntityKind::Email, EntityKind::Phone],
            "the list stays in kind order"
        );
        assert!(!apply_edit(&mut policy, &kind(EntityKind::Email, false))?);
        assert!(apply_edit(&mut policy, &kind(EntityKind::Email, true))?);
        assert!(!apply_edit(&mut policy, &kind(EntityKind::Email, true))?);
        assert_eq!(policy.disabled_kinds, [EntityKind::Phone]);
        Ok(())
    }

    /// Waits until `done` holds.
    fn eventually(what: &str, done: impl Fn() -> bool) -> Test {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            if Instant::now() > deadline {
                return Err(format!("timed out waiting for {what}"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn has_call(rig: &Rig, call: &str) -> bool {
        rig.calls().iter().any(|c| c == call)
    }

    /// A folder `docs` in `dir` with one file that holds an email address.
    fn docs(dir: &TempDir) -> Result<PathBuf, String> {
        let folder = dir.0.join("docs");
        fs::create_dir(&folder).map_err(|e| e.to_string())?;
        fs::write(folder.join("a.txt"), "mail jan.jansen@acme.nl").map_err(|e| e.to_string())?;
        Ok(folder)
    }

    #[test]
    fn feature_edits_report_whether_they_changed_anything() -> Test {
        let mut policy = quiet();
        assert!(apply_edit(
            &mut policy,
            &Edit::Highlight(Highlight::Always)
        )?);
        assert!(!apply_edit(
            &mut policy,
            &Edit::Highlight(Highlight::Always)
        )?);
        assert_eq!(policy.highlight, Highlight::Always);
        assert!(apply_edit(&mut policy, &Edit::ExplorerMenu(true))?);
        assert!(!apply_edit(&mut policy, &Edit::ExplorerMenu(true))?);
        assert!(apply_edit(&mut policy, &Edit::HttpApi(true))?);
        assert!(!apply_edit(&mut policy, &Edit::HttpApi(true))?);
        assert!(policy.explorer_menu && policy.http_api);
        assert!(apply_edit(&mut policy, &Edit::HttpApi(false))?);
        assert!(!policy.http_api);
        Ok(())
    }

    #[test]
    fn switching_the_inventory_on_watches_the_usual_folders_only_when_none_were_chosen() -> Test {
        let mut policy = quiet();
        assert!(apply_edit(&mut policy, &Edit::Inventory(true))?);
        assert!(policy.inventory);
        assert_eq!(policy.inventory_roots, default_inventory_roots());
        assert!(!apply_edit(&mut policy, &Edit::Inventory(true))?);

        let dir = TempDir::new()?;
        let mut chosen = Policy {
            inventory_roots: vec![dir.0.clone()],
            ..quiet()
        };
        assert!(apply_edit(&mut chosen, &Edit::Inventory(true))?);
        assert_eq!(
            chosen.inventory_roots,
            std::slice::from_ref(&dir.0),
            "the user's folders stay"
        );
        assert!(apply_edit(&mut chosen, &Edit::Inventory(false))?);
        assert_eq!(
            chosen.inventory_roots,
            std::slice::from_ref(&dir.0),
            "also while it is off"
        );
        Ok(())
    }

    #[test]
    fn watched_folders_must_be_folders_and_are_not_added_twice() -> Test {
        let dir = TempDir::new()?;
        let mut policy = quiet();
        let root = |path: &Path, on| Edit::InventoryRoot {
            path: path.to_path_buf(),
            on,
        };
        assert!(apply_edit(&mut policy, &root(&dir.0, true))?);
        assert!(
            !apply_edit(&mut policy, &root(&dir.0, true))?,
            "twice is once"
        );
        let shouted = PathBuf::from(dir.0.to_string_lossy().to_ascii_uppercase());
        assert!(
            !apply_edit(&mut policy, &root(&shouted, true))?,
            "Windows paths ignore case"
        );
        assert_eq!(policy.inventory_roots, std::slice::from_ref(&dir.0));
        let missing = apply_edit(&mut policy, &root(&dir.0.join("missing"), true))
            .err()
            .ok_or("a folder that is not there is refused")?;
        assert!(missing.starts_with("Not a folder:"), "{missing}");
        let file = dir.0.join("a.txt");
        fs::write(&file, "x").map_err(|e| e.to_string())?;
        assert!(
            apply_edit(&mut policy, &root(&file, true)).is_err(),
            "a file is no folder"
        );
        assert!(apply_edit(&mut policy, &root(&dir.0, false))?);
        assert!(!apply_edit(&mut policy, &root(&dir.0, false))?);
        assert!(policy.inventory_roots.is_empty());
        Ok(())
    }

    #[test]
    fn excluded_paths_need_not_exist_but_must_be_full_paths() -> Test {
        let mut policy = quiet();
        let exclude = |path: &str, on| Edit::InventoryExclude {
            path: PathBuf::from(path),
            on,
        };
        assert!(apply_edit(
            &mut policy,
            &exclude(r"C:\Users\you\Taxes\2024.pdf", true)
        )?);
        assert!(!apply_edit(
            &mut policy,
            &exclude(r"c:\users\YOU\taxes\2024.pdf", true)
        )?);
        assert_eq!(policy.inventory_exclude.len(), 1);
        assert!(apply_edit(&mut policy, &exclude(r"relative\path", true)).is_err());
        assert!(apply_edit(
            &mut policy,
            &exclude(r"C:\Users\you\Taxes\2024.pdf", false)
        )?);
        assert!(policy.inventory_exclude.is_empty());
        Ok(())
    }

    #[test]
    fn a_scanned_file_is_shown_in_its_folder() -> Test {
        let dir = TempDir::new()?;
        let file = dir.0.join("a.txt");
        fs::write(&file, "x").map_err(|e| e.to_string())?;
        assert_eq!(reveal_target(&file), (dir.0.clone(), Some(file.clone())));
        assert_eq!(reveal_target(&dir.0), (dir.0.clone(), None));
        let gone = dir.0.join("gone");
        assert_eq!(reveal_target(&gone), (gone.clone(), None));
        Ok(())
    }

    #[test]
    fn the_local_api_follows_its_switch() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::Edit(Edit::HttpApi(true)))?;
        assert_eq!(rig.calls(), ["save_policy", "start_http(7980)"]);
        assert!(rig.controller.snapshot().http);
        rig.forget_calls();
        rig.run(Command::Edit(Edit::HttpApi(false)))?;
        assert_eq!(rig.calls(), ["save_policy", "stop_http"]);
        assert!(!rig.controller.snapshot().http);
        Ok(())
    }

    #[test]
    fn a_new_port_restarts_the_local_api() -> Test {
        let rig = rig(
            true,
            Policy {
                http_api: true,
                ..quiet()
            },
        )?;
        rig.run(Command::Startup)?;
        rig.forget_calls();
        let patch = SettingsPatch {
            http_port: Some(8123),
            ..SettingsPatch::default()
        };
        rig.run(Command::Settings(patch))?;
        assert_eq!(
            rig.calls(),
            ["save_policy", "stop_http", "start_http(8123)"]
        );
        rig.forget_calls();
        // A new token is a restart too, but only while it runs.
        rig.run(Command::RestartHttp)?;
        assert_eq!(rig.calls(), ["stop_http", "start_http(8123)"]);
        Ok(())
    }

    #[test]
    fn a_local_api_that_will_not_start_says_why() -> Test {
        let rig = rig(true, quiet())?;
        fail(&rig.fake.fail_http);
        rig.run(Command::Edit(Edit::HttpApi(true)))?;
        let notice = rig.notice().ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Error);
        assert!(
            notice.text.contains("127.0.0.1:7980") && notice.text.contains("port in use"),
            "{}",
            notice.text
        );
        assert!(!rig.controller.snapshot().http);
        // Nothing runs, so nothing restarts.
        rig.forget_calls();
        rig.run(Command::RestartHttp)?;
        assert!(rig.calls().is_empty());
        Ok(())
    }

    #[test]
    fn the_explorer_menu_follows_its_switch() -> Test {
        let rig = rig(
            true,
            Policy {
                explorer_menu: true,
                ..quiet()
            },
        )?;
        rig.run(Command::Edit(Edit::ExplorerMenu(false)))?;
        assert_eq!(rig.calls(), ["save_policy", "set_explorer_menu(false)"]);
        rig.forget_calls();
        rig.run(Command::Edit(Edit::ExplorerMenu(true)))?;
        assert_eq!(rig.calls(), ["save_policy", "set_explorer_menu(true)"]);
        fail(&rig.fake.fail_menu);
        rig.run(Command::Edit(Edit::ExplorerMenu(false)))?;
        let notice = rig.notice().ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Error);
        assert!(
            notice.text.contains("Explorer menu") && notice.text.contains("registry"),
            "{}",
            notice.text
        );
        Ok(())
    }

    #[test]
    fn the_highlight_runs_capture_and_the_shortcut_and_the_model() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::Edit(Edit::Highlight(Highlight::Always)))?;
        assert_eq!(
            rig.calls(),
            [
                "save_policy",
                "start_capture",
                "set_hotkey(true)",
                "load_model"
            ]
        );
        let purpose = &rig.controller.shared.purpose;
        assert_eq!(purpose.highlight(), Highlight::Always);
        assert!(
            !purpose.mask(),
            "protection is off: nothing is kept for the proxy"
        );
        rig.forget_calls();
        rig.run(Command::Edit(Edit::Highlight(Highlight::Hotkey)))?;
        assert_eq!(
            rig.calls(),
            ["save_policy", "set_hotkey(true)", "load_model"]
        );
        rig.forget_calls();
        rig.run(Command::Edit(Edit::Highlight(Highlight::Off)))?;
        assert_eq!(
            rig.calls(),
            [
                "save_policy",
                "stop_capture",
                "set_hotkey(false)",
                "release_model"
            ]
        );
        assert_eq!(rig.controller.shared.purpose.highlight(), Highlight::Off);
        Ok(())
    }

    #[test]
    fn capture_serves_protection_and_the_highlight_together() -> Test {
        let rig = rig(
            true,
            Policy {
                highlight: Highlight::Always,
                ..quiet()
            },
        )?;
        rig.run(Command::Startup)?;
        let count = |call: &str| rig.calls().iter().filter(|c| *c == call).count();
        assert_eq!(count("start_capture"), 1);
        assert!(!rig.controller.shared.purpose.mask());
        rig.run(Command::SetEnabled(true))?;
        assert_eq!(count("start_capture"), 1, "capture runs already");
        assert!(rig.controller.shared.purpose.mask());
        rig.forget_calls();
        rig.run(Command::SetEnabled(false))?;
        // The proxy stops; capture and the model stay for the highlight.
        assert_eq!(
            rig.calls(),
            [
                "disable_system_proxy",
                "stop_proxy",
                "load_model",
                "save_policy"
            ]
        );
        assert!(!rig.controller.shared.purpose.mask());
        Ok(())
    }

    #[test]
    fn a_field_that_cannot_be_read_turns_the_highlight_into_a_notice() -> Test {
        let rig = rig(true, quiet())?;
        fail(&rig.fake.fail_capture);
        rig.run(Command::Edit(Edit::Highlight(Highlight::Always)))?;
        let notice = rig.notice().ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Warning);
        assert!(
            notice.text.contains("no uia") && notice.text.contains("highlighting is off"),
            "{}",
            notice.text
        );
        Ok(())
    }

    #[test]
    fn a_taken_shortcut_is_said_in_a_notice() -> Test {
        let rig = rig(true, quiet())?;
        fail(&rig.fake.fail_hotkey);
        rig.run(Command::Edit(Edit::Highlight(Highlight::Hotkey)))?;
        let notice = rig.notice().ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Warning);
        assert!(notice.text.contains("Ctrl+Alt+P"), "{}", notice.text);
        Ok(())
    }

    #[test]
    fn the_model_stays_loaded_while_the_highlight_needs_it() -> Test {
        let rig = rig(true, quiet())?;
        rig.run(Command::SetEnabled(true))?;
        rig.run(Command::Edit(Edit::Highlight(Highlight::Hotkey)))?;
        rig.forget_calls();
        rig.run(Command::SetEnabled(false))?;
        assert!(
            !has_call(&rig, "release_model"),
            "the highlight needs it: {:?}",
            rig.calls()
        );
        rig.run(Command::Edit(Edit::Highlight(Highlight::Off)))?;
        assert!(has_call(&rig, "release_model"));
        Ok(())
    }

    #[test]
    fn a_model_that_arrives_while_the_highlight_waits_is_loaded() -> Test {
        let launched = launch_with(
            true,
            Policy {
                highlight: Highlight::Always,
                ..quiet()
            },
            |fake| fail(&fake.model_missing),
        )?;
        let controller = launched.controller()?;
        wait_for(controller, |s| s.model == Model::Ready)?;
        eventually("the model to load", || {
            launched.fake.calls().iter().any(|c| c == "load_model")
        })
    }

    #[test]
    fn startup_brings_the_saved_features_up() -> Test {
        let rig = rig(
            true,
            Policy {
                highlight: Highlight::Hotkey,
                explorer_menu: true,
                http_api: true,
                ..quiet()
            },
        )?;
        rig.run(Command::Startup)?;
        assert_eq!(
            rig.calls(),
            [
                "set_explorer_menu(true)",
                "start_http(7980)",
                "start_capture",
                "set_hotkey(true)",
                "load_model"
            ]
        );
        assert!(rig.controller.snapshot().http);
        Ok(())
    }

    #[test]
    fn settings_from_the_api_apply_as_a_whole() -> Test {
        let rig = rig(true, quiet())?;
        let patch = SettingsPatch {
            sites: Some(vec!["Example.com".into()]),
            http_api: Some(true),
            ..SettingsPatch::default()
        };
        rig.run(Command::Settings(patch))?;
        assert_eq!(rig.controller.policy().sites, ["example.com"]);
        assert_eq!(rig.calls(), ["save_policy", "start_http(7980)"]);
        // One bad value and nothing changes.
        rig.forget_calls();
        let bad = SettingsPatch {
            sites: Some(vec!["not a site".into()]),
            http_api: Some(false),
            ..SettingsPatch::default()
        };
        rig.run(Command::Settings(bad))?;
        assert!(rig.calls().is_empty());
        assert!(rig.controller.policy().http_api);
        let notice = rig.notice().ok_or("no notice")?;
        assert_eq!(notice.severity, Severity::Error);
        assert!(notice.text.contains("not a site"), "{}", notice.text);
        // Nothing to change, nothing saved.
        rig.run(Command::Settings(SettingsPatch::default()))?;
        assert!(rig.calls().is_empty());
        Ok(())
    }

    #[test]
    fn an_explorer_scan_fills_the_inventory_and_asks_the_window_to_show_it() -> Test {
        let rig = rig(true, quiet())?;
        let dir = TempDir::new()?;
        let folder = docs(&dir)?;
        let file = folder.join("a.txt");
        rig.run(Command::ScanFiles {
            paths: vec![folder.clone()],
            reveal: true,
        })?;
        let snapshot = wait_for(&rig.controller, |s| s.reveal.is_some() && s.scan.is_none())?;
        assert_eq!(snapshot.inventory_totals, (1, 1));
        assert_eq!(
            snapshot.reveal,
            Some(Reveal {
                seq: 1,
                at: folder.clone(),
                select: None
            })
        );
        // The application thread's timer sees the request without a window: the tray state
        // carries its number, and nothing else of the rig's state has changed.
        assert_eq!(
            rig.controller.tray(),
            Tray {
                on: false,
                highlight_paused: false,
                reveal: 1
            }
        );
        // A scan writes nothing to the vault.
        let engine = rig.controller.engine();
        let records = engine
            .vault()
            .read()
            .map_err(|e| e.to_string())?
            .record_count();
        assert_eq!(records, 0);
        // Outside the watched folders: the tile for "Other scans", which has no path.
        let top = rig.controller.inventory_view(Path::new(""), None);
        assert_eq!(top.nodes.len(), 1);
        assert!(top.nodes[0].path.as_os_str().is_empty());
        // No folder chosen: the view groups by the usual ones, which is what the scans watch and
        // what the breadcrumb must collapse.
        assert_eq!(top.roots, default_inventory_roots());
        let level = rig.controller.inventory_view(&folder, Some(&file));
        assert_eq!(level.nodes.len(), 1);
        assert_eq!(level.nodes[0].name, "a.txt");
        assert_eq!(level.entry.map(|entry| entry.hits()), Some(1));
        // The scan of one file shows its folder with the file selected.
        rig.run(Command::ScanFiles {
            paths: vec![file.clone()],
            reveal: true,
        })?;
        let snapshot = wait_for(&rig.controller, |s| {
            s.reveal.as_ref().is_some_and(|reveal| reveal.seq == 2) && s.scan.is_none()
        })?;
        assert_eq!(
            snapshot.reveal,
            Some(Reveal {
                seq: 2,
                at: folder,
                select: Some(file)
            })
        );
        assert_eq!(rig.controller.tray().reveal, 2);
        // The model was loaded for the scans and given back.
        assert!(has_call(&rig, "load_model"));
        eventually("the model to be released", || {
            rig.calls()
                .last()
                .is_some_and(|call| call == "release_model")
        })
    }

    #[test]
    fn the_inventory_scans_the_watched_folders_until_it_is_switched_off() -> Test {
        let dir = TempDir::new()?;
        let folder = docs(&dir)?;
        let rig = rig(
            true,
            Policy {
                inventory_roots: vec![folder.clone()],
                ..quiet()
            },
        )?;
        rig.run(Command::Edit(Edit::Inventory(true)))?;
        let snapshot = wait_for(&rig.controller, |s| {
            s.inventory_totals == (1, 1) && s.scan.is_none()
        })?;
        assert_eq!(
            snapshot.reveal, None,
            "a scan nobody asked to see does not take the window"
        );
        let top = rig.controller.inventory_view(Path::new(""), None);
        assert_eq!(top.nodes.len(), 1);
        assert_eq!(top.nodes[0].path, folder);
        assert_eq!(top.roots, std::slice::from_ref(&folder));
        // What is left out is forgotten at once, and stays out of every scan.
        rig.run(Command::Edit(Edit::InventoryExclude {
            path: folder.join("a.txt"),
            on: true,
        }))?;
        assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
        rig.run(Command::Rescan)?;
        assert!(rig.controller.wait_scans(Duration::from_secs(20)));
        assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
        Ok(())
    }

    #[test]
    fn a_rescan_scans_the_watched_folders_even_with_the_inventory_off() -> Test {
        let dir = TempDir::new()?;
        let folder = docs(&dir)?;
        let rig = rig(
            true,
            Policy {
                inventory_roots: vec![folder],
                ..quiet()
            },
        )?;
        rig.run(Command::Rescan)?;
        assert!(rig.controller.wait_scans(Duration::from_secs(20)));
        assert_eq!(rig.controller.snapshot().inventory_totals, (1, 1));
        Ok(())
    }

    #[test]
    fn forgetting_and_wiping_remove_vault_records() -> Test {
        let rig = rig(true, quiet())?;
        issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
        rig.run(Command::Refresh)?;
        assert_eq!(rig.controller.snapshot().issued, 2);
        rig.run(Command::Forget(vec!["jan.jansen@acme.nl".to_owned()]))?;
        assert_eq!(rig.controller.snapshot().issued, 1);
        assert_eq!(rig.controller.keyed(&text("jan.jansen"), 10).matched, 0);
        assert_eq!(rig.controller.keyed(&text("6 12345678"), 10).matched, 1);
        rig.run(Command::WipeVault)?;
        let snapshot = rig.controller.snapshot();
        assert_eq!(snapshot.issued, 0);
        assert!(snapshot.recent.is_empty());
        Ok(())
    }

    #[test]
    fn a_pause_of_the_highlight_reaches_the_snapshot_and_wakes_the_window() -> Test {
        let rig = rig(true, quiet())?;
        let before = rig.controller.snapshot();
        assert!(!before.highlight_paused && !rig.controller.highlight_paused());
        rig.controller.shared.purpose.set_paused(true);
        let after = rig
            .controller
            .wait_changed(before.version, Duration::from_secs(20))
            .ok_or("the pause did not wake the window")?;
        assert!(after.highlight_paused && rig.controller.highlight_paused());
        rig.controller.shared.purpose.set_paused(false);
        assert!(!rig.controller.snapshot().highlight_paused);
        Ok(())
    }

    #[test]
    fn shutdown_stops_the_local_api() -> Test {
        let rig = rig(
            true,
            Policy {
                http_api: true,
                ..quiet()
            },
        )?;
        rig.run(Command::Startup)?;
        assert!(rig.controller.snapshot().http);
        rig.forget_calls();
        rig.controller.shutdown();
        assert!(has_call(&rig, "stop_http"));
        assert!(!rig.controller.snapshot().http);
        Ok(())
    }
}
