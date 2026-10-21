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
mod sysproxy;
mod ui;

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
                ui::run()
            };
            if let Err(message) = result {
                eprintln!("piikey: {message}");
                ui::show_failure(&message);
                std::process::exit(1);
            }
        }
    }
}
