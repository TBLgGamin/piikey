//! App state behind the UI: start and stop, certificate, settings, keyed values and daily counts.
//!
//! Everything that can block (`certutil`, CA files, binding the proxy, `WinINET`, settings and vault
//! I/O) runs on one worker thread, in submission order. The window and the tray only submit
//! [`Command`]s and read [`Snapshot`]s, so they share one state and never wait on the system.
//!
//! Lock order: nothing else is locked while a `Shared` lock is held, and `Shared` is never locked
//! while the state mutex is held except to read the policy first in [`Controller::snapshot`].

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, Weak,
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use piikey::{
    detect::{EntityKind, ner::files::FILES},
    engine::Engine,
};
use windows_reactor::DateTime;

use super::{
    activity::{self, Activity, Use},
    stats::{self, Day, Stats},
};
use crate::{
    Res,
    ledger::Ledger,
    policy::Policy,
    proxy::{Event, PORT, Shared},
};

/// Keyed values the Home page lists.
pub const RECENT: usize = 8;
/// Days in the Home chart.
pub const CHART_DAYS: i64 = 14;
/// The daily counts are written at most this often while traffic flows, and at shutdown.
const STATS_SAVE_EVERY: Duration = Duration::from_secs(30);

/// How long a quitting app waits for a command that is still running.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

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
    /// The saved daily counts; none when there are none or they cannot be read.
    fn load_stats(&self) -> Stats;
    /// Persists the daily counts, as [`Stats::to_text`] wrote them.
    fn save_stats(&self, text: &str) -> Res<()>;
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
    /// Records per kind, the most common first; kinds without any are left out.
    pub kinds: Vec<(EntityKind, usize)>,
    /// The last [`CHART_DAYS`] days, oldest first; the last one is today.
    pub days: Vec<Day>,
    /// The latest masking or restoring this session.
    pub last_activity: Option<Sent>,
    /// The detection model's download state.
    pub model: Model,
}

/// A change to the site or program lists, or to which kinds are masked.
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
    kinds: Vec<(EntityKind, usize)>,
    stats: Stats,
    /// When `stats` was last written.
    stats_saved: Instant,
    /// `stats` changed since it was last written.
    stats_dirty: bool,
    /// Which stand-ins went where and when.
    activity: Activity,
    last_activity: Option<Sent>,
    proxy: Option<Box<dyn Running>>,
    /// Reads what the user types while the app is on. `None` when it could not start; the proxy
    /// then checks whole requests.
    capture: Option<Box<dyn Running>>,
    model: Model,
    fetch: Fetch,
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
    state: Mutex<State>,
    changed: Condvar,
    commands: Mutex<Option<Sender<Command>>>,
    events: Sender<Event>,
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
    /// # Errors
    /// The vault cannot be opened, or the operating system refused a thread.
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
        let engine = match backend.open_engine() {
            Ok(engine) => engine,
            Err(error) => {
                let mut message =
                    format!("could not open the vault {}: {error}", vault_path.display());
                // No app will start, so nothing else would give Windows its settings back.
                if resume && let Err(error) = backend.disable_system_proxy() {
                    message =
                        format!("{message}. Windows may still point at piikey's proxy: {error}");
                }
                return Err(message);
            }
        };
        let controller = Self::new(backend, vault_path, policy, engine, notice)?;
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
        notice: Option<Notice>,
    ) -> Res<Arc<Self>> {
        policy.enabled = false;
        engine.set_enabled(policy.enabled_kinds());
        let shared = Arc::new(Shared {
            engine: RwLock::new(Arc::new(engine)),
            policy: RwLock::new(policy),
            ledger: Ledger::default(),
            typed: crate::proxy::Typed::new(),
        });
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let stats = backend.load_stats();
        let activity = backend.load_activity();
        let controller = Arc::new(Self {
            shared,
            backend,
            vault_path,
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
                kinds: Vec::new(),
                stats,
                stats_saved: Instant::now(),
                stats_dirty: false,
                activity,
                last_activity: None,
                proxy: None,
                capture: None,
                model: Model::Ready,
                fetch: Fetch::default(),
            }),
            changed: Condvar::new(),
            commands: Mutex::new(Some(command_tx)),
            events: event_tx,
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
            kinds: state.kinds.clone(),
            days: state.stats.last(stats::today(), CHART_DAYS),
            last_activity: state.last_activity.clone(),
            model: state.model.clone(),
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
        let state = self.lock();
        state.enabled || state.busy == Some(Busy::Starting)
    }

    /// Whether the last check found the certificate installed.
    pub fn cert_installed(&self) -> bool {
        self.lock().cert == Cert::Installed
    }

    /// Clears the notice the user closed.
    pub fn dismiss_notice(&self) {
        self.update(|state| state.notice = None);
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
        let (enabled, proxy, capture) = self.update(|state| {
            let enabled = state.enabled;
            state.enabled = false;
            (enabled, state.proxy.take(), state.capture.take())
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
        // After the proxy: its last events are counted too.
        self.save_stats(true);
    }

    /// Writes the daily counts and the activity feed when they changed and `now` is set or the
    /// last write is [`STATS_SAVE_EVERY`] ago. Both are a convenience: a failed write is retried
    /// next time.
    fn save_stats(&self, now: bool) {
        let (stats, activity) = {
            let mut state = self.lock();
            if !state.stats_dirty || !(now || state.stats_saved.elapsed() >= STATS_SAVE_EVERY) {
                return;
            }
            state.stats_saved = Instant::now();
            state.stats_dirty = false;
            (
                state.stats.to_text(stats::today()),
                state.activity.to_text(),
            )
        };
        let saved = self.backend.save_stats(&stats);
        let logged = self.backend.save_activity(&activity);
        if saved.is_err() || logged.is_err() {
            self.lock().stats_dirty = true;
        }
    }

    fn engine(&self) -> Arc<Engine> {
        Arc::clone(
            &self
                .shared
                .engine
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
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

    /// Sets the flag the proxy reads: it only anonymizes while this is on.
    fn set_live(&self, on: bool) {
        self.shared
            .policy
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .enabled = on;
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
            // Off again: the model must not hold memory.
            self.backend.release_model();
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
        if self.lock().model == Model::Ready
            && let Err(error) = self.backend.load_model()
        {
            self.update(|state| {
                state.notice = Some(Notice::warning(format!(
                    "The detection model could not load ({error}); only emails, phone numbers, IBANs and other patterns are masked."
                )));
            });
        }
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
        let capture = match self.backend.start_capture(Arc::clone(&self.shared)) {
            Ok(capture) => Some(capture),
            Err(error) => {
                // The store stays inactive, so the proxy checks whole requests instead.
                let text = format!(
                    "piikey could not read what you type ({error}), so it checks whole requests instead; some sites may not work fully."
                );
                self.update(|state| {
                    let mut notice = follow(state.notice.take(), &text);
                    notice.severity = Severity::Warning;
                    state.notice = Some(notice);
                });
                None
            }
        };
        self.update(|state| {
            state.enabled = true;
            state.proxy = Some(proxy);
            state.capture = capture;
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
        let (proxy, capture) = self.update(|state| {
            state.enabled = false;
            (state.proxy.take(), state.capture.take())
        });
        if let Some(proxy) = proxy {
            proxy.stop();
        }
        // After the proxy: the requests it still serves are masked as before.
        if let Some(capture) = capture {
            capture.stop();
        }
        self.backend.release_model();
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
        self.update(|state| {
            state.cert = cert_of(installed);
            summary.apply(state);
        });
    }

    fn edit(&self, edit: &Edit) {
        let mut policy = self.policy();
        match apply_edit(&mut policy, edit) {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                self.update(|state| state.notice = Some(Notice::error(error)));
                return;
            }
        }
        // Everything that can fail happens before the live state changes, so a failure leaves
        // the old settings fully in place.
        if let Err(error) = self.backend.save_policy(&policy) {
            self.update(|state| {
                state.notice = Some(Notice::error(format!("Could not save settings: {error}")));
            });
            return;
        }
        self.engine().set_enabled(policy.enabled_kinds());
        *self
            .shared
            .policy
            .write()
            .unwrap_or_else(PoisonError::into_inner) = policy;
        self.update(|_| {});
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
        let mut kinds: Vec<(EntityKind, usize)> = EntityKind::ALL
            .into_iter()
            .map(|kind| (kind, view.count_of(kind)))
            .filter(|&(_, count)| count > 0)
            .collect();
        kinds.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
        VaultSummary {
            issued: view.record_count(),
            recent,
            kinds,
        }
    }

    /// Counts a proxy event and notes where its proxies went; a failure of the proxy itself also
    /// stops the app.
    fn record(&self, event: &Event) {
        let today = stats::today();
        match event {
            Event::Masked {
                host,
                exe,
                kinds,
                proxies,
            } => {
                // Files are counted apart from the values in them.
                let masked: usize = kinds
                    .iter()
                    .filter(|(kind, _)| *kind != ATTACHMENT)
                    .map(|(_, count)| count)
                    .sum();
                let now = activity::now();
                self.update(|state| {
                    state.stats.add(today, count(masked), 0);
                    state.stats_dirty = true;
                    for proxy in proxies {
                        state.activity.record(proxy, host, exe.as_deref(), now);
                    }
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
            Event::Restored { host, count: n } => self.update(|state| {
                state.stats.add(today, 0, count(*n));
                state.stats_dirty = true;
                state.last_activity = Some(Sent {
                    host: host.clone(),
                    exe: None,
                    at: clock(),
                });
            }),
            Event::Error(reason) => self.submit(Command::Fatal(reason.clone())),
        }
        self.save_stats(false);
    }
}

/// What the proxy calls an uploaded file it changed, in [`Event::Masked`] counts.
const ATTACHMENT: &str = "attachment";

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The vault's part of the Home page.
#[derive(Default)]
struct VaultSummary {
    issued: u64,
    recent: Vec<Keyed>,
    kinds: Vec<(EntityKind, usize)>,
}

impl VaultSummary {
    /// Moves the numbers into `state`.
    fn apply(self, state: &mut State) {
        state.issued = self.issued;
        state.kinds = self.kinds;
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
/// The text the user typed is not a site or a program name.
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use piikey::detect::KindSet;

    use super::*;
    use crate::ui::testing::TempDir;

    type Test = Result<(), String>;

    /// Calls the fake saw, in order.
    type Calls = Arc<Mutex<Vec<String>>>;

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
        /// What `load_stats` returns.
        loaded: Stats,
        /// Every text `save_stats` got; not in `calls`, which follow the system side effects.
        saved_stats: Mutex<Vec<String>>,
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

        fn load_stats(&self) -> Stats {
            self.loaded.clone()
        }

        fn save_stats(&self, text: &str) -> Res<()> {
            self.saved_stats
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(text.to_owned());
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
        let controller = Controller::new(Box::new(Arc::clone(&fake)), vault, policy, engine, None)?;
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
            kinds: vec![("email", 2), ("phone", 1), (ATTACHMENT, 1)],
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
            ..Policy::default()
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(false, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(false, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
            ..Policy::default()
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
        let rig = rig(true, Policy::default())?;
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
                ..Policy::default()
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
    fn traffic_counts_toward_today_and_the_home_list_shows_where_values_went() -> Test {
        let rig = rig(true, Policy::default())?;
        let proxies = issue(&rig, &["mail jan.jansen@acme.nl", "call +31 6 12345678"])?;
        rig.controller
            .record(&masked("chatgpt.com", &[proxies[0].as_str()]));
        rig.controller.record(&Event::Restored {
            host: "claude.ai".into(),
            count: 4,
        });
        let snap = rig.controller.snapshot();
        let today = snap.days.last().ok_or("no days")?;
        // email×2 + phone×1; the attachment is not a value.
        assert_eq!((today.masked, today.restored), (3, 4));
        assert_eq!(
            snap.days.len(),
            usize::try_from(CHART_DAYS).map_err(|e| e.to_string())?
        );
        assert_eq!(snap.issued, 2);
        assert_eq!(snap.kinds, [(EntityKind::Email, 1), (EntityKind::Phone, 1)]);
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

    #[test]
    fn daily_counts_are_loaded_at_start_and_saved_at_shutdown() -> Test {
        let dir = TempDir::new()?;
        let vault = dir.0.join("vault.pkv");
        let mut loaded = Stats::default();
        loaded.add(stats::today(), 5, 1);
        let fake = Arc::new(Fake {
            vault: vault.clone(),
            loaded,
            ..Fake::default()
        });
        let engine = Engine::open(&vault).map_err(|e| e.to_string())?;
        let controller = Controller::new(
            Box::new(Arc::clone(&fake)),
            vault,
            Policy::default(),
            engine,
            None,
        )?;
        let today = |days: &[Day]| days.last().map(|d| (d.masked, d.restored));
        assert_eq!(today(&controller.snapshot().days), Some((5, 1)));
        controller.record(&Event::Restored {
            host: "claude.ai".into(),
            count: 2,
        });
        controller.shutdown();
        let saved = fake
            .saved_stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .cloned()
            .ok_or("nothing saved")?;
        let saved = Stats::parse(&saved).last(stats::today(), 1);
        assert_eq!(today(&saved), Some((5, 3)));
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let rig = rig(true, Policy::default())?;
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
        let controller = Controller::new(
            Box::new(Arc::clone(&fake)),
            vault,
            Policy::default(),
            engine,
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
        // Saved together with the counts when anything changed.
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
        let rig = rig(true, Policy::default())?;
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
}
