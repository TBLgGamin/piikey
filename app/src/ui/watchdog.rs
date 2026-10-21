//! Windows points at the app's proxy only while the app runs.
//!
//! A clean exit gives Windows its proxy settings back itself (see `Controller::shutdown`). For
//! every other end the app starts a watchdog: a second copy of the exe, run with [`WATCH_FLAG`],
//! that blocks on a pipe the app holds open for its whole life. Windows closes that pipe however
//! the app ends (crash, Task Manager, a debugger), and the watchdog then restores the settings.
//!
//! Ending a process tree (Task Manager's "End process tree", `taskkill /T`) ends every process
//! the app started, so the watchdog must not be one of them. The process the app starts only
//! starts the watchdog proper, run with [`DETACHED_FLAG`] and given the pipe, and exits: the
//! watchdog's parent is gone, so no tree of the app reaches it.
//!
//! A shutdown or sign-out ends the watchdog too, so `sysproxy` also leaves a `RunOnce` entry
//! while the proxy is on: it runs the exe with [`RESTORE_FLAG`] at the next sign-in.

use std::{
    io,
    os::windows::process::CommandExt,
    process::{Child, ChildStdin, Command, Stdio},
    time::Duration,
};

use piikey::sys::{CREATE_NO_WINDOW, data_dir};

use super::instance::Instance;
use crate::{Describe, Res, sysproxy};

/// Runs the exe as the watchdog of the app that started it.
pub const WATCH_FLAG: &str = "--watchdog";
/// The second argument of the watchdog proper, which the first one starts and then leaves.
const DETACHED_FLAG: &str = "--detached";
/// Runs the exe to restore the proxy settings a session left behind, then exit.
pub const RESTORE_FLAG: &str = "--restore-proxy";

/// How long the restore waits for an ending app to let go of its lock. Longer than any clean
/// exit; an app that holds it past this is a new one, and owns the settings.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The running watchdog. Dropping it closes the pipe, which tells the watchdog the app ended.
#[derive(Debug)]
pub struct Watchdog {
    _pipe: ChildStdin,
}

/// Starts the watchdog of this process.
///
/// # Errors
/// The exe path is unknown or the process cannot be started.
pub fn spawn() -> Res<Watchdog> {
    let mut starter = start(&[WATCH_FLAG], Stdio::piped())?;
    let pipe = starter.stdin.take().ok_or("the watchdog has no pipe")?;
    Ok(Watchdog { _pipe: pipe })
}

/// A copy of the exe with `args` and `stdin`, without a window or output.
fn start(args: &[&str], stdin: Stdio) -> Res<Child> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate the piikey exe: {e}"))?;
    Command::new(exe)
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("cannot start the watchdog: {e}"))
}

/// The watchdog process: the one the app started hands the pipe on to the watchdog proper and
/// ends; that one waits for the app to end, then restores the proxy settings.
///
/// # Errors
/// The watchdog proper cannot be started, or see [`restore`].
pub fn watch() -> Res<()> {
    let detached = std::env::args_os()
        .nth(2)
        .is_some_and(|flag| flag == DETACHED_FLAG);
    if !detached {
        return start(&[WATCH_FLAG, DETACHED_FLAG], Stdio::inherit()).map(|_| ());
    }
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
    let folder = data_dir().describe()?;
    match Instance::acquire(&folder, LOCK_WAIT)? {
        Some(_instance) => sysproxy::disable(),
        None => Ok(()),
    }
}
