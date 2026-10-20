//! The Windows 11 app: one window, a tray icon and the controller behind both.
//!
//! The application outlives its window. Closing the window while the app is on leaves the tray
//! icon running; closing it with the app off, or choosing Exit, ends the app after Windows has
//! its proxy settings back. However else the app ends, its watchdog gives them back (see
//! [`watchdog`]).

mod activity;
mod assets;
mod controller;
mod instance;
mod pages;
mod stats;
mod system;
#[cfg(test)]
mod testing;
mod watchdog;
mod window;

pub use self::watchdog::{RESTORE_FLAG, WATCH_FLAG, restore as restore_proxy, watch};

use std::{path::PathBuf, rc::Rc, sync::Arc, time::Duration};

use piikey::detect::NerDetector;

use windows_reactor::{
    App, Application, ApplicationContext, ApplicationView, ApplicationViewContext, Key, Menu,
    MenuItem, NotifyIcon, ScreenPoint, StackPanel, TextBlock, TextWrapping, Thickness,
};

use self::{
    controller::{Command, Controller, Notice},
    instance::Instance,
    system::System,
    window::{Handle, MainWindow, WindowInput},
};
use crate::{Res, policy::Policy};

/// Why a second app does not start.
const ALREADY_RUNNING: &str = "piikey is already running for your Windows account. Open it from its key icon in the notification area.";
/// How long a starting app waits for one that is still ending, and for its watchdog.
const START_WAIT: Duration = Duration::from_secs(2);

/// Opens everything, runs the app until it ends, then turns the app off.
///
/// # Errors
/// Another copy of piikey is running, the vault or the settings folder cannot be opened, or the UI runtime
/// fails.
pub fn run() -> Res<()> {
    let vault = piikey::vault::default_path().map_err(|error| error.to_string())?;
    let folder = vault.parent().ok_or("the vault path has no folder")?;
    // First of all: a second copy would take the port and the Windows proxy from the first, and
    // its clean-up at launch (see `Controller::launch`) would undo the first one's work.
    let _instance = Instance::acquire(folder, START_WAIT)?.ok_or(ALREADY_RUNNING)?;
    // Dropped before `_instance`: the watchdog then waits for the lock, and finds Windows already
    // restored by `shutdown` below. Without it the app still runs; only a crash would leave the
    // settings behind, until the next start or sign-in restores them.
    let _watchdog = watchdog::spawn()
        .inspect_err(|error| eprintln!("piikey: {error}"))
        .ok();
    let controller = open(vault)?;
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
    controller.shutdown();
    result
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

/// Loads the settings and starts the controller on `vault`; see [`Controller::launch`].
fn open(vault: PathBuf) -> Res<Arc<Controller>> {
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
    Controller::launch(
        Box::new(System {
            vault: vault.clone(),
            ner: NerDetector::new(model_dir.clone()),
            model_dir,
        }),
        vault,
        policy,
        notice,
    )
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
    /// The window saw the app change.
    Sync,
    /// The window closed.
    WindowClosed,
}

struct PiikeyApp {
    controller: Arc<Controller>,
    /// What the tray menu shows right after a toggle from the tray, before the controller has
    /// caught up. The next message of any kind replaces it with the real state.
    wish: Option<bool>,
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
}

impl Application for PiikeyApp {
    type Input = AppInput;
    type Message = AppMessage;

    fn create(input: &AppInput, context: &ApplicationContext<Self>) -> Self {
        context.show_window("main");
        Self {
            controller: Arc::clone(&input.controller),
            wish: None,
        }
    }

    fn update(&mut self, message: AppMessage, context: &ApplicationContext<Self>) {
        self.wish = None;
        match message {
            AppMessage::Open => context.show_window("main"),
            AppMessage::Menu(key) => match key.as_str() {
                Some("open") => context.show_window("main"),
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
            AppMessage::Sync => {}
            AppMessage::WindowClosed => {
                if !self.controller.is_on() {
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
            },
        );
        let Some(icon) = &input.icon else {
            return view;
        };
        view.notify_icon(
            "tray",
            NotifyIcon::new(icon)
                .tooltip(if on { "piikey: on" } else { "piikey: off" })
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
