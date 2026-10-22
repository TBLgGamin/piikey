//! The Windows 11 app: one window, a tray icon and the controller behind both.
//!
//! The application outlives its window. Closing the window while protection is on, or while a
//! feature that works in the background is (the highlight, the inventory, the local API),
//! leaves the tray icon running; closing it with all of them off, or choosing Quit piikey, ends
//! the app after Windows has its proxy settings back. However else the app ends, its watchdog
//! gives them back (see [`watchdog`]).
//!
//! The tray says what the window's hero says: its tooltip, the header of its menu and its icon all
//! come from one [`Status`].

mod activity;
pub(crate) mod assets;
pub(crate) mod controller;
mod explorer;
mod exports;
mod goto;
mod instance;
mod pages;
mod scanner;
mod status;
mod system;
#[cfg(test)]
pub(crate) mod testing;
mod ticker;
mod treemap;
mod watchdog;
mod watcher;
mod window;

pub use self::watchdog::{RESTORE_FLAG, WATCH_FLAG, restore as restore_proxy, watch};

use std::{
    path::{Path, PathBuf},
    rc::Rc,
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};

use piikey::{
    Error,
    api::{Handler, Request},
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
    assets::TrayIcon,
    controller::{Command, Controller, Notice},
    instance::Instance,
    status::Status,
    system::System,
    ticker::Ticker,
    window::{Handle, MainWindow, WindowInput},
};
use crate::{Describe, Res, api::AppApi};

/// Why a second app does not start. `main` compares the error of [`run`] with it.
pub const ALREADY_RUNNING: &str = "piikey is already running for your Windows account. Open it from its key icon in the notification area.";
/// How long a starting app waits for one that is still ending, and for its watchdog.
const START_WAIT: Duration = Duration::from_secs(2);
/// How long Explorer's scan waits for an app that is still starting to open its pipe, and how
/// often it asks again.
const EXPLORER_WAIT: Duration = Duration::from_secs(5);
const EXPLORER_RETRY: Duration = Duration::from_millis(250);
/// The notice when `piikey-cli serve` has the named pipe.
const PIPE_TAKEN: &str =
    "The piikey API pipe is taken by piikey-cli serve; stop it to use the CLI with the app.";
/// Removes the Explorer "Scan for personal data" verb and exits (the uninstaller runs it).
pub const UNREGISTER_FLAG: &str = "--unregister-shell";
/// Scans the files and folders named after it: what Explorer's "Scan for personal data" runs.
pub const SCAN_FLAG: &str = "--scan";
/// Starts the app without its window, in the tray: what the sign-in entry runs.
pub const BACKGROUND_FLAG: &str = "--background";

/// How an attempt to run the app ended.
enum Ran {
    /// The app ran, and has ended.
    Done,
    /// Another app holds the lock: this one did not start.
    AlreadyRunning,
}

/// Opens everything, runs the app until it ends, then turns the app off. With `hidden` the app
/// starts in the tray without showing its window, as when it starts at sign-in; without a tray
/// icon there is nothing to open the window from, so it shows anyway.
///
/// # Errors
/// Another copy of piikey is running, the vault or the settings folder cannot be opened, or the UI runtime
/// fails.
pub fn run(hidden: bool) -> Res<()> {
    match run_with(None, hidden)? {
        Ran::Done => Ok(()),
        Ran::AlreadyRunning => Err(ALREADY_RUNNING.to_owned()),
    }
}

/// What Explorer's "Scan for personal data" runs: gives `paths` to the app that runs, which scans them and
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
        match run_with(Some(paths.to_vec()), false)? {
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
    match service::ask(&request) {
        Ok(reply) => Ok(reply.is_some()),
        // `piikey-cli serve` has the pipe, not the app: this process becomes the app.
        Err(error) if error.code() == "app_required" => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// [`run`] with the files and folders `scan` names scanned first, as Explorer's menu asks.
fn run_with(scan: Option<Vec<PathBuf>>, hidden: bool) -> Res<Ran> {
    let folder = piikey::sys::data_dir().describe()?;
    let vault = piikey::vault::default_path().describe()?;
    // First of all: a second copy would take the port and the Windows proxy from the first, and
    // its clean-up at launch (see `Controller::launch`) would undo the first one's work.
    let Some(_instance) = Instance::acquire(&folder, START_WAIT)? else {
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
    let icons = match assets::icon_file(controller.vault_path()) {
        Ok(app) => Some(Icons::load(app)),
        Err(error) => {
            // The window still works; without a tray icon it just ends the app when it closes.
            eprintln!("piikey: no tray icon: {error}");
            None
        }
    };
    let result = App::run_application::<PiikeyApp>(AppInput {
        controller: Arc::clone(&controller),
        icons,
        hidden,
    })
    .describe();
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
    let model_dir = piikey::detect::ner::files::default_dir().describe()?;
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

/// The icon files the window and the tray load, all in the data folder.
struct Icons {
    /// The app icon: the window's, and the tray's while protection runs.
    app: PathBuf,
    /// The tray's while protection is off.
    off: PathBuf,
    /// The tray's while the user is needed.
    attention: PathBuf,
}

impl Icons {
    /// Writes the tray's icons next to the app icon `app`. One that cannot be written is the app
    /// icon: the status then shows in the tray's tooltip and menu only.
    fn load(app: PathBuf) -> Self {
        let other = |icon: TrayIcon| {
            assets::tray_icon(icon).unwrap_or_else(|error| {
                eprintln!("piikey: no icon for the tray: {error}");
                app.clone()
            })
        };
        Self {
            off: other(TrayIcon::Off),
            attention: other(TrayIcon::Attention),
            app,
        }
    }

    /// The file that shows `icon`.
    fn of(&self, icon: TrayIcon) -> &Path {
        match icon {
            TrayIcon::Off => &self.off,
            TrayIcon::On => &self.app,
            TrayIcon::Attention => &self.attention,
        }
    }
}

struct AppInput {
    controller: Arc<Controller>,
    /// The icons of the window and the tray; `None` means no tray icon.
    icons: Option<Icons>,
    /// Start in the tray without showing the window.
    hidden: bool,
}

enum AppMessage {
    /// Show the window.
    Open,
    Menu(Key),
    /// What the tray shows changed, or a scan or a second start asks to be shown. The window
    /// sends it when it sees the change, the [`Ticker`] when no window is open to see it.
    Sync,
    /// The window closed.
    WindowClosed,
}

struct PiikeyApp {
    controller: Arc<Controller>,
    /// The tray icon is shown: the way back to the app once its window is closed.
    tray: bool,
    /// What the tray shows right after a toggle from the tray, before the controller has caught
    /// up. The next message of any kind replaces it with the real state.
    wish: Option<bool>,
    /// The number of the latest scan that asked to be shown, until the window that showed it
    /// closes: the window gets it with its input, so a window that opens for it shows its result.
    reveal: Option<u64>,
    /// The number of the latest request to show a scan that was handled.
    revealed: u64,
    /// The number of requests to bring the window forward that were handled: a second start of the
    /// app, `piikey-cli open`.
    shown: u64,
    /// Wakes the application while no window is open; `None` if the runtime refused its timer.
    _ticker: Option<Ticker>,
}

impl PiikeyApp {
    /// What piikey is doing, as the tray says it.
    fn status(&self) -> Status {
        Status::of(&self.controller.snapshot(), self.wish)
    }

    /// Gives Windows its settings back first, then ends the app.
    fn quit(&self, context: &ApplicationContext<Self>) {
        self.controller.restore_system_proxy();
        context.exit();
    }

    /// A scan that asks to be shown, and has not been yet: the window comes forward with its
    /// progress and its result in a dialog. The request is numbered when it is queued, so the window
    /// is there before the scan has found anything.
    fn show_scan(&mut self, context: &ApplicationContext<Self>) {
        let seq = self.controller.tray().reveal;
        if seq > self.revealed {
            self.revealed = seq;
            self.reveal = Some(seq);
            context.show_window("main");
        }
    }

    /// A request that arrived since the last look asks for the window: it opens, or comes forward
    /// if it is open already.
    fn show_requested(&mut self, context: &ApplicationContext<Self>) {
        let requests = self.controller.tray().show;
        if requests > self.shown {
            self.shown = requests;
            context.show_window("main");
        }
    }

    /// Brings the window forward, with the dialog of the latest scan that was not shown yet: one
    /// that was asked for while the ticker could not run is shown this way, when the user opens the
    /// window.
    fn open_window(&mut self, context: &ApplicationContext<Self>) {
        self.show_scan(context);
        context.show_window("main");
    }
}

/// The icons the tray shows, or `None` when the app has no tray icon.
fn tray_icons(input: &AppInput) -> Option<&Icons> {
    // Debug builds only, for the README screenshots: `PIIKEY_NO_TRAY` leaves the tray icon out,
    // so the app also starts on a desktop that has no notification area.
    #[cfg(debug_assertions)]
    if std::env::var_os("PIIKEY_NO_TRAY").is_some() {
        return None;
    }
    input.icons.as_ref()
}

/// Whether closing the window ends the app: it does when the user's setting says the app stays in
/// the tray only while its window is open (`keep_in_tray` off), and when no tray icon is left to
/// open the window again, whatever the setting says.
const fn closing_ends_app(tray: bool, keep_in_tray: bool) -> bool {
    !tray || !keep_in_tray
}

/// What the tray icon says when the pointer rests on it: the status, and a paused highlight.
/// Windows cuts the text at 127 characters, so the pause is only added where it fits.
fn tooltip(status: &Status, highlight_paused: bool) -> String {
    const PAUSED: &str = " \u{b7} highlighting paused";
    let text = status.tooltip();
    if highlight_paused && text.encode_utf16().count() + PAUSED.encode_utf16().count() <= 127 {
        format!("{text}{PAUSED}")
    } else {
        text
    }
}

/// The tray's menu: what piikey is doing as a header that cannot be chosen, then what the user can
/// do. The keys are what [`AppMessage::Menu`] carries.
fn menu_items(status: &Status) -> [MenuItem; 5] {
    [
        MenuItem::disabled("status", status.title()),
        MenuItem::item("open", "Open piikey"),
        MenuItem::item(
            "toggle",
            if status.is_on() {
                "Turn protection off"
            } else {
                "Turn protection on"
            },
        ),
        MenuItem::separator("separator"),
        MenuItem::item("exit", "Quit piikey"),
    ]
}

impl Application for PiikeyApp {
    type Input = AppInput;
    type Message = AppMessage;

    fn create(input: &AppInput, context: &ApplicationContext<Self>) -> Self {
        // Hidden is for the tray: with no tray icon the window is the only way in. A request for
        // the window that came before the app was up is honoured too.
        let tray = tray_icons(input).is_some();
        let asked = input.controller.tray().show;
        if !(input.hidden && tray) || asked > 0 {
            context.show_window("main");
        }
        let sender: LocalSender<AppMessage> = context.sender();
        Self {
            controller: Arc::clone(&input.controller),
            tray,
            wish: None,
            reveal: None,
            revealed: 0,
            shown: asked,
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
            AppMessage::Sync => {
                self.show_scan(context);
                self.show_requested(context);
            }
            AppMessage::WindowClosed => {
                self.reveal = None;
                if closing_ends_app(self.tray, self.controller.runs_in_background()) {
                    self.quit(context);
                }
            }
        }
    }

    fn view(&self, input: &AppInput, context: &ApplicationViewContext<Self>) -> ApplicationView {
        let view = ApplicationView::new().window::<MainWindow>(
            "main",
            WindowInput {
                controller: Handle(Arc::clone(&input.controller)),
                icon: input
                    .icons
                    .as_ref()
                    .map(|icons| Rc::from(icons.app.to_string_lossy().as_ref())),
                on_sync: context.callback(|()| AppMessage::Sync),
                on_closed: context.callback(|()| AppMessage::WindowClosed),
                reveal: self.reveal,
            },
        );
        let Some(icons) = tray_icons(input) else {
            return view;
        };
        let status = self.status();
        view.notify_icon(
            "tray",
            NotifyIcon::new(icons.of(status.icon()))
                .tooltip(tooltip(&status, self.controller.highlight_paused()))
                .on_activate(context.callback(|_: ScreenPoint| AppMessage::Open))
                .menu(Menu::new(
                    menu_items(&status),
                    context.callback(AppMessage::Menu),
                )),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Icons, MenuItem, Status, TrayIcon, closing_ends_app, menu_items,
        status::{Cause, Work},
        tooltip,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn closing_the_window_keeps_the_app_only_when_the_setting_says_so_and_a_tray_icon_is_there() {
        // With no tray icon nothing is left to open the window again: the app would run
        // unseen, holding the proxy and the API, whatever the setting says.
        assert!(closing_ends_app(false, true));
        assert!(closing_ends_app(false, false));
        // The setting off quits, with every feature stopped, as Quit piikey does.
        assert!(closing_ends_app(true, false));
        assert!(!closing_ends_app(true, true));
    }

    fn on() -> Status {
        Status::On {
            protected: 4,
            last: None,
        }
    }

    fn off() -> Status {
        Status::Off {
            needs_certificate: false,
        }
    }

    fn label(item: &MenuItem) -> Option<(&str, bool)> {
        match item {
            MenuItem::Item { label, enabled, .. } => Some((label, *enabled)),
            _ => None,
        }
    }

    #[test]
    fn the_menu_starts_with_what_piikey_is_doing_and_cannot_choose_it() {
        let menu = menu_items(&on());
        assert_eq!(label(&menu[0]), Some(("Protection is on", false)));
        assert_eq!(label(&menu[1]), Some(("Open piikey", true)));
        assert_eq!(label(&menu[2]), Some(("Turn protection off", true)));
        assert!(matches!(menu[3], MenuItem::Separator { .. }));
        assert_eq!(label(&menu[4]), Some(("Quit piikey", true)));
        // The header is the title of the status, whatever the status is.
        for status in [
            off(),
            Status::Busy(Work::Starting),
            Status::NeedsAttention {
                running: false,
                cause: Cause::CertificateMissing,
            },
        ] {
            assert_eq!(
                label(&menu_items(&status)[0]),
                Some((status.title(), false))
            );
        }
    }

    #[test]
    fn the_toggle_offers_the_opposite_of_what_runs_or_is_starting() {
        assert_eq!(
            label(&menu_items(&off())[2]),
            Some(("Turn protection on", true))
        );
        assert_eq!(
            label(&menu_items(&Status::Busy(Work::Starting))[2]),
            Some(("Turn protection off", true))
        );
    }

    #[test]
    fn the_tooltip_is_the_status_and_a_paused_highlight_where_it_fits() {
        assert_eq!(tooltip(&off(), false), "piikey: protection off");
        assert_eq!(
            tooltip(&off(), true),
            "piikey: protection off \u{b7} highlighting paused"
        );
        // Windows cuts the tooltip at 127 characters: a status that long keeps its own words.
        let long = Status::NeedsAttention {
            running: true,
            cause: Cause::Error("x".repeat(300)),
        };
        assert_eq!(tooltip(&long, true), long.tooltip());
    }

    #[test]
    fn each_look_of_the_tray_has_its_file() {
        let icons = Icons {
            app: PathBuf::from("piikey.ico"),
            off: PathBuf::from("tray-off.ico"),
            attention: PathBuf::from("tray-attention.ico"),
        };
        assert_eq!(icons.of(TrayIcon::On), Path::new("piikey.ico"));
        assert_eq!(icons.of(TrayIcon::Off), Path::new("tray-off.ico"));
        assert_eq!(
            icons.of(TrayIcon::Attention),
            Path::new("tray-attention.ico")
        );
        assert_eq!(on().icon(), TrayIcon::On);
        assert_eq!(off().icon(), TrayIcon::Off);
    }
}
