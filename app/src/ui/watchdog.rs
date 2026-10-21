//! Windows points at the app's proxy only while the app runs.
//!
//! A clean exit gives Windows its proxy settings back itself (see `Controller::shutdown`). For
//! every other end the app starts a watchdog: a second copy of the exe, run with [`WATCH_FLAG`],
//! that blocks on a pipe the app holds open for its whole life. Windows closes that pipe however
//! the app ends (crash, Task Manager, a debugger), and the watchdog then restores the settings.
//!
//! A shutdown or sign-out ends the watchdog too, so `sysproxy` also leaves a `RunOnce` entry
//! while the proxy is on: it runs the exe with [`RESTORE_FLAG`] at the next sign-in.

use std::{
    io,
    os::windows::process::CommandExt,
    process::{Child, Command, Stdio},
    time::Duration,
};

use piikey::sys::CREATE_NO_WINDOW;

use super::instance::Instance;
use crate::{Res, sysproxy};

/// Runs the exe as the watchdog of the app that started it.
pub const WATCH_FLAG: &str = "--watchdog";
/// Runs the exe to restore the proxy settings a session left behind, then exit.
pub const RESTORE_FLAG: &str = "--restore-proxy";

/// How long the restore waits for an ending app to let go of its lock. Longer than any clean
/// exit; an app that holds it past this is a new one, and owns the settings.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The running watchdog. Dropping it closes the pipe, which tells the watchdog the app ended.
#[derive(Debug)]
pub struct Watchdog {
    _child: Child,
}

/// Starts the watchdog of this process.
///
/// # Errors
/// The exe path is unknown or the process cannot be started.
pub fn spawn() -> Res<Watchdog> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate the piikey exe: {e}"))?;
    let child = Command::new(exe)
        .arg(WATCH_FLAG)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("cannot start the watchdog: {e}"))?;
    Ok(Watchdog { _child: child })
}

/// The watchdog process: waits for the app to end, then restores the proxy settings.
///
/// # Errors
/// See [`restore`].
pub fn watch() -> Res<()> {
    // Nothing is ever written: the read ends, with end-of-file or a broken pipe, when the app's
    // end of the pipe closes. Both mean the same, so the result is not looked at.
    let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
    restore()
}

/// Restores the Windows proxy settings unless an app is running. The app's lock decides: it is
/// held for an app's whole life, and the app waits for it at start, so no app can set the
/// proxy while this runs.
///
/// # Errors
/// The data folder, the lock or the registry cannot be used.
pub fn restore() -> Res<()> {
    let vault = piikey::vault::default_path().map_err(|error| error.to_string())?;
    let folder = vault.parent().ok_or("the vault path has no folder")?;
    match Instance::acquire(folder, LOCK_WAIT)? {
        Some(_instance) => sysproxy::disable(),
        None => Ok(()),
    }
}
