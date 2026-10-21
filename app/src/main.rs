//! piikey: a local proxy that anonymizes what the sites and programs you select receive and
//! restores what they send back, with a Windows 11 app to control it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod ca;
mod capture;
mod highlight;
mod ledger;
mod proxy;
mod shell;
mod sysproxy;
mod ui;

use std::path::PathBuf;

/// App-level result; errors are user-facing messages.
pub type Res<T, E = String> = std::result::Result<T, E>;

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
                let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
                ui::scan_from_explorer(&paths)
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
