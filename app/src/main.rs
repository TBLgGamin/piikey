//! piikey: a local proxy that anonymizes what the sites and programs you select receive and
//! restores what they send back, with a Windows 11 app to control it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod ca;
mod capture;
mod highlight;
mod ledger;
mod process;
mod proxy;
mod shell;
mod startup;
mod sysproxy;
mod ui;

use std::{
    thread,
    time::{Duration, Instant},
};

/// App-level result; errors are user-facing messages.
pub type Res<T, E = String> = std::result::Result<T, E>;

/// Turns what went wrong into the message the user reads.
pub trait Describe<T> {
    /// The same result with its error as text.
    ///
    /// # Errors
    /// The error of the result, as it reads when displayed.
    fn describe(self) -> Res<T>;
}

impl<T, E: std::fmt::Display> Describe<T> for Result<T, E> {
    fn describe(self) -> Res<T> {
        self.map_err(|error| error.to_string())
    }
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let flag = args.next();
    let is = |name: &str| flag.as_ref().is_some_and(|flag| flag == name);
    // The watchdog and the sign-in clean-up have no window to show an error in.
    let headless = if is(ui::WATCH_FLAG) {
        Some(ui::watch())
    } else if is(ui::RESTORE_FLAG) {
        Some(ui::restore_proxy())
    } else if is(ui::UNREGISTER_FLAG) {
        Some(shell::unregister())
    } else {
        None
    };
    match headless {
        Some(Ok(())) => {}
        Some(Err(message)) => {
            eprintln!("piikey: {message}");
            std::process::exit(1);
        }
        None => {
            let result = if is(ui::SCAN_FLAG) {
                ui::scan_from_explorer(&shell::scan_paths(args))
            } else {
                launch(is(ui::BACKGROUND_FLAG) || startup::launched_at_sign_in())
            };
            if let Err(message) = result {
                eprintln!("piikey: {message}");
                ui::show_failure(&message);
                std::process::exit(1);
            }
        }
    }
}

/// How long a start waits for an app that is still opening its pipe, and how often it asks again.
const APP_WAIT: Duration = Duration::from_secs(5);
const APP_RETRY: Duration = Duration::from_millis(250);

/// Opens the app, or, when one runs for this Windows account, asks it to bring its window forward
/// (a start at sign-in leaves it alone) and ends quietly. `hidden`: no window at start, the tray
/// icon only.
fn launch(hidden: bool) -> Res<()> {
    let deadline = Instant::now() + APP_WAIT;
    loop {
        if startup::hand_over(hidden)? {
            return Ok(());
        }
        match ui::run(hidden) {
            // An app that is still starting has not opened its pipe yet: ask again.
            Err(message) if message == ui::ALREADY_RUNNING && Instant::now() < deadline => {
                thread::sleep(APP_RETRY);
            }
            result => return result,
        }
    }
}
