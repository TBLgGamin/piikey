//! The Windows 11 app: one window, a tray icon and the controller behind both.
//!
//! The application outlives its window. Closing the window while protection is on, or while a
//! feature that works in the background is (the highlight, the PII inventory, the local API),
//! leaves the tray icon running; closing it with all of them off, or choosing Exit, ends the app
//! after Windows has its proxy settings back. However else the app ends, its watchdog gives them
//! back (see [`watchdog`]).

mod activity;
pub(crate) mod assets;
pub(crate) mod controller;
mod explorer;
mod exports;
mod instance;
mod pages;
mod scanner;
mod system;
#[cfg(test)]
pub(crate) mod testing;
mod ticker;
mod treemap;
mod watchdog;
mod window;

pub use self::watchdog::{RESTORE_FLAG, WATCH_FLAG, restore as restore_proxy, watch};

use std::{
    path::PathBuf,
    rc::Rc,
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};

use piikey::{
    Error,
    api::{self, Handler, Request},
    detect::NerDetector,
    policy::Policy,
    service::{self, Server},
};

use windows_reactor::{
    App, Application, ApplicationContext, ApplicationView, ApplicationViewContext, Key,
    LocalSender, Menu, MenuItem, NotifyIcon, ScreenPoint, StackPanel, TextBlock, TextWrapping,
    Thickness,
};

use self::{
    controller::{Command, Controller, Notice, Reveal},
    instance::Instance,
    system::System,
    ticker::Ticker,
    window::{Handle, MainWindow, WindowInput},
};
use crate::{Res, api::AppApi};

/// Why a second app does not start.
const ALREADY_RUNNING: &str = "piikey is already running for your Windows account. Open it from its key icon in the notification area.";
/// How long a starting app waits for one that is still ending, and for its watchdog.
const START_WAIT: Duration = Duration::from_secs(2);
/// How long a call to the app's pipe waits while the pipe is busy.
const CALL_WAIT: Duration = Duration::from_millis(300);
/// How long Explorer's scan waits for an app that is still starting to open its pipe, and how
/// often it asks again.
const EXPLORER_WAIT: Duration = Duration::from_secs(5);
const EXPLORER_RETRY: Duration = Duration::from_millis(250);
/// The notice when `piikey-cli serve` has the named pipe.
const PIPE_TAKEN: &str =
    "The piikey API pipe is taken by piikey-cli serve; stop it to use the CLI with the app.";
/// Removes the Explorer "Scan for PII" verb and exits (the uninstaller runs it).
pub const UNREGISTER_FLAG: &str = "--unregister-shell";
/// Scans the files and folders named after it: what Explorer's "Scan for PII" runs.
pub const SCAN_FLAG: &str = "--scan";

/// How an attempt to run the app ended.
enum Ran {
    /// The app ran, and has ended.
    Done,
    /// Another app holds the lock: this one did not start.
    AlreadyRunning,
}

/// Opens everything, runs the app until it ends, then turns the app off.
///
/// # Errors
/// Another copy of piikey is running, the vault or the settings folder cannot be opened, or the UI runtime
/// fails.
pub fn run() -> Res<()> {
    match run_with(None)? {
        Ran::Done => Ok(()),
        Ran::AlreadyRunning => Err(ALREADY_RUNNING.to_owned()),
    }
}

/// What Explorer's "Scan for PII" runs: gives `paths` to the app that runs, which scans them and
/// shows the result. With no app running this process becomes the app, and scans them first.
///
/// # Errors
/// As [`run`]; or the app that runs refuses the paths.
pub fn scan_from_explorer(paths: &[PathBuf]) -> Res<()> {
    let deadline = Instant::now() + EXPLORER_WAIT;
    loop {
        if hand_over(paths)? {
            return Ok(());
        }
        match run_with(Some(paths.to_vec()))? {
            Ran::Done => return Ok(()),
            // An app that is still starting has not opened its pipe yet: ask again.
            Ran::AlreadyRunning if Instant::now() < deadline => thread::sleep(EXPLORER_RETRY),
            Ran::AlreadyRunning => return Err(ALREADY_RUNNING.to_owned()),
        }
    }
}

/// Gives `paths` to the app that serves the API, as an Explorer scan; `false` when none does.
fn hand_over(paths: &[PathBuf]) -> Res<bool> {
    let request = Request::ExplorerScan {
        paths: paths.to_vec(),
    };
    let reply = service::call(&service::default_pipe(), &request, CALL_WAIT)
        .map_err(|error| error.to_string())?;
    let Some(envelope) = reply else {
        return Ok(false);
    };
    match api::open_envelope(envelope) {
        Ok(_) => Ok(true),
        // `piikey-cli serve` has the pipe, not the app: this process becomes the app.
        Err(error) if error.code() == "app_required" => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// [`run`] with the files and folders `scan` names scanned first, as Explorer's menu asks.
fn run_with(scan: Option<Vec<PathBuf>>) -> Res<Ran> {
    let vault = piikey::vault::default_path().map_err(|error| error.to_string())?;
    let folder = vault.parent().ok_or("the vault path has no folder")?;
    // First of all: a second copy would take the port and the Windows proxy from the first, and
    // its clean-up at launch (see `Controller::launch`) would undo the first one's work.
    let Some(_instance) = Instance::acquire(folder, START_WAIT)? else {
        return Ok(Ran::AlreadyRunning);
    };
    // Dropped before `_instance`: the watchdog then waits for the lock, and finds Windows already
    // restored by `shutdown` below. Without it the app still runs; only a crash would leave the
    // settings behind, until the next start or sign-in restores them.
    let _watchdog = watchdog::spawn()
        .inspect_err(|error| eprintln!("piikey: {error}"))
        .ok();
    let (controller, api) = open(vault)?;
    // The saved features start now: they serve the API, which exists.
    controller.submit(Command::Startup);
    if let Some(paths) = scan {
        controller.submit(Command::ScanFiles {
            paths,
            reveal: true,
        });
    }
    let pipe = serve(&controller, api);
    let icon = match assets::icon_file(controller.vault_path()) {
        Ok(path) => Some(path),
        Err(error) => {
            // The window still works; without a tray icon it just ends the app when it closes.
            eprintln!("piikey: no tray icon: {error}");
            None
        }
    };
    let result = App::run_application::<PiikeyApp>(AppInput {
        controller: Arc::clone(&controller),
        icon,
    })
    .map_err(|error| error.to_string());
    if let Some(pipe) = pipe {
        pipe.stop();
    }
    controller.shutdown();
    result.map(|()| Ran::Done)
}

/// Shows why the app could not start; the GUI build has no console to print to.
pub fn show_failure(message: &str) {
    let content = StackPanel::new()
        .spacing(8.0)
        .margin(Thickness::uniform(24.0))
        .children((
            TextBlock::new().text("piikey could not start"),
            TextBlock::new()
                .text(message)
                .text_wrapping(TextWrapping::Wrap),
        ));
    // Nothing more to do if even this window fails.
    let _ = App::run(content);
}

/// Loads the settings and starts the controller on `vault`, see [`Controller::launch`], with the
/// handler of the API that the controller's local HTTP API serves.
fn open(vault: PathBuf) -> Res<(Arc<Controller>, Arc<AppApi>)> {
    let (policy, notice) = match Policy::load() {
        Ok(policy) => (policy, None),
        Err(error) => (
            Policy::default(),
            Some(Notice::error(format!(
                "Could not read your settings, so defaults are in use: {error}"
            ))),
        ),
    };
    let model_dir = piikey::detect::ner::files::default_dir().map_err(|error| error.to_string())?;
    let ner = NerDetector::new(model_dir.clone());
    let slot: Arc<OnceLock<Arc<dyn Handler>>> = Arc::new(OnceLock::new());
    let controller = Controller::launch(
        Box::new(System {
            vault: vault.clone(),
            ner: ner.clone(),
            model_dir,
            api: Arc::clone(&slot),
        }),
        vault,
        policy,
        notice,
    )?;
    let api = Arc::new(AppApi::new(&controller, ner));
    // Nothing else fills the slot, and only the local API reads it, after `Command::Startup`.
    let handler: Arc<dyn Handler> = api.clone();
    let _ = slot.set(handler);
    Ok((controller, api))
}

/// Serves the API on the named pipe, which the CLI uses while the app runs. A pipe that is taken
/// is a notice, not a failure: the app works without it.
fn serve(controller: &Controller, api: Arc<AppApi>) -> Option<Server> {
    match service::spawn(api, &service::default_pipe()) {
        Ok(server) => Some(server),
        Err(Error::Busy(_)) => {
            controller.notify(Notice::warning(PIPE_TAKEN));
            None
        }
        Err(error) => {
            controller.notify(Notice::error(format!(
                "Could not serve the API on the named pipe: {error}"
            )));
            None
        }
    }
}

struct AppInput {
    controller: Arc<Controller>,
    /// The `.ico` of the tray icon and the window; `None` means no tray icon.
    icon: Option<PathBuf>,
}

enum AppMessage {
    /// Show the window.
    Open,
    Menu(Key),
    /// What the tray shows changed, or a scan asks to be shown. The window sends it when it sees
    /// the change, the [`Ticker`] when no window is open to see it.
    Sync,
    /// The window closed.
    WindowClosed,
}

struct PiikeyApp {
    controller: Arc<Controller>,
    /// What the tray menu shows right after a toggle from the tray, before the controller has
    /// caught up. The next message of any kind replaces it with the real state.
    wish: Option<bool>,
    /// The latest scan that asked to be shown, until the window that showed it closes: the window
    /// gets it with its input, so a window that opens for it knows where to go.
    reveal: Option<Reveal>,
    /// The number of the latest request to show a scan that was handled.
    revealed: u64,
    /// Wakes the application while no window is open; `None` if the runtime refused its timer.
    _ticker: Option<Ticker>,
}

impl PiikeyApp {
    fn on(&self) -> bool {
        self.wish.unwrap_or_else(|| self.controller.is_on())
    }

    /// Gives Windows its settings back first, then ends the app.
    fn quit(&self, context: &ApplicationContext<Self>) {
        self.controller.restore_system_proxy();
        context.exit();
    }

    /// A scan that has not been shown yet asks to be: the window comes forward at its result.
    fn show_scan(&mut self, context: &ApplicationContext<Self>) {
        let Some(reveal) = self.controller.reveal() else {
            return;
        };
        if reveal.seq > self.revealed {
            self.revealed = reveal.seq;
            self.reveal = Some(reveal);
            context.show_window("main");
        }
    }

    /// Brings the window forward, at the result of the latest scan that was not shown yet: one
    /// that finished while the window was closed and the ticker could not run is shown this way,
    /// when the user opens the window.
    fn open_window(&mut self, context: &ApplicationContext<Self>) {
        self.show_scan(context);
        context.show_window("main");
    }
}

/// What the tray icon says when the pointer rests on it.
fn tooltip(on: bool, highlight_paused: bool) -> String {
    let state = if on { "piikey: on" } else { "piikey: off" };
    if highlight_paused {
        format!("{state} \u{b7} highlighting paused")
    } else {
        state.to_owned()
    }
}

impl Application for PiikeyApp {
    type Input = AppInput;
    type Message = AppMessage;

    fn create(input: &AppInput, context: &ApplicationContext<Self>) -> Self {
        context.show_window("main");
        let sender: LocalSender<AppMessage> = context.sender();
        Self {
            controller: Arc::clone(&input.controller),
            wish: None,
            reveal: None,
            revealed: 0,
            _ticker: Ticker::start(Arc::clone(&input.controller), move || {
                // A refusal means the queue is full or the app is ending: nothing to do either way.
                let _ = sender.send(AppMessage::Sync);
            }),
        }
    }

    fn update(&mut self, message: AppMessage, context: &ApplicationContext<Self>) {
        self.wish = None;
        match message {
            AppMessage::Open => self.open_window(context),
            AppMessage::Menu(key) => match key.as_str() {
                Some("open") => self.open_window(context),
                Some("toggle") => {
                    let turn_on = !self.controller.is_on();
                    self.controller.submit(Command::SetEnabled(turn_on));
                    if turn_on && !self.controller.cert_installed() {
                        // The window explains what is missing and offers the install button.
                        context.show_window("main");
                    } else {
                        self.wish = Some(turn_on);
                    }
                }
                Some("exit") => self.quit(context),
                _ => {}
            },
            AppMessage::Sync => self.show_scan(context),
            AppMessage::WindowClosed => {
                self.reveal = None;
                if !self.controller.runs_in_background() {
                    self.quit(context);
                }
            }
        }
    }

    fn view(&self, input: &AppInput, context: &ApplicationViewContext<Self>) -> ApplicationView {
        let on = self.on();
        let view = ApplicationView::new().window::<MainWindow>(
            "main",
            WindowInput {
                controller: Handle(Arc::clone(&input.controller)),
                icon: input
                    .icon
                    .as_ref()
                    .map(|path| Rc::from(path.to_string_lossy().as_ref())),
                on_sync: context.callback(|()| AppMessage::Sync),
                on_closed: context.callback(|()| AppMessage::WindowClosed),
                reveal: self.reveal.clone(),
            },
        );
        let Some(icon) = &input.icon else {
            return view;
        };
        // Debug builds only, for the README screenshots: `PIIKEY_NO_TRAY` leaves the tray icon out,
        // so the app also starts on a desktop that has no notification area.
        #[cfg(debug_assertions)]
        if std::env::var_os("PIIKEY_NO_TRAY").is_some() {
            return view;
        }
        view.notify_icon(
            "tray",
            NotifyIcon::new(icon)
                .tooltip(tooltip(on, self.controller.highlight_paused()))
                .on_activate(context.callback(|_: ScreenPoint| AppMessage::Open))
                .menu(Menu::new(
                    [
                        MenuItem::item("open", "Open piikey"),
                        MenuItem::item(
                            "toggle",
                            if on {
                                "Turn piikey off"
                            } else {
                                "Turn piikey on"
                            },
                        ),
                        MenuItem::separator("separator"),
                        MenuItem::item("exit", "Exit"),
                    ],
                    context.callback(AppMessage::Menu),
                )),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::tooltip;

    #[test]
    fn the_tooltip_says_when_the_highlight_is_paused() {
        assert_eq!(tooltip(true, false), "piikey: on");
        assert_eq!(tooltip(false, false), "piikey: off");
        assert_eq!(tooltip(true, true), "piikey: on \u{b7} highlighting paused");
        assert_eq!(
            tooltip(false, true),
            "piikey: off \u{b7} highlighting paused"
        );
    }
}
