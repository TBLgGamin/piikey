//! piikey: a local proxy that anonymizes what the sites and programs you select receive and
//! restores what they send back, with a Windows 11 app to control it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ca;
mod capture;
mod ledger;
mod model;
mod policy;
mod proxy;
mod sysproxy;
mod ui;

/// App-level result; errors are user-facing messages.
pub type Res<T, E = String> = std::result::Result<T, E>;

fn main() {
    // The watchdog and the sign-in clean-up have no window to show an error in.
    let headless = match std::env::args_os().nth(1) {
        Some(flag) if flag == ui::WATCH_FLAG => Some(ui::watch()),
        Some(flag) if flag == ui::RESTORE_FLAG => Some(ui::restore_proxy()),
        _ => None,
    };
    match headless {
        Some(Ok(())) => {}
        Some(Err(message)) => {
            eprintln!("piikey: {message}");
            std::process::exit(1);
        }
        None => {
            if let Err(message) = ui::run() {
                eprintln!("piikey: {message}");
                ui::show_failure(&message);
                std::process::exit(1);
            }
        }
    }
}
