//! How piikey is started other than by the user opening it: at sign-in, in the background, and by
//! a second start that finds the app running.
//!
//! Starting at sign-in is a setting of the user's ([`enabled`], [`set`]). The unpackaged exe (the
//! zip, the installer) keeps a `Run` value that starts it with [`BACKGROUND_FLAG`], so it comes up
//! as the tray icon and the proxy, without a window. The Microsoft Store build cannot: Windows
//! keeps the registry of a package apart from the user's, so it declares a startup task in its
//! manifest (`piikeyStartup`) and asks Windows to switch that on. A startup task starts the exe
//! without arguments; [`launched_at_sign_in`] reads the activation to tell it from the user.
//!
//! A start that finds the app running does not start a second one: [`hand_over`] asks the running
//! app, over its named pipe, to bring its window forward, and the start ends quietly.

use std::{io::ErrorKind, path::Path, time::Duration};

use piikey::{
    api::{self, Request},
    service,
    sys::{is_packaged, launch_path},
};
use windows::{
    ApplicationModel::{Activation::ActivationKind, AppInstance, StartupTask, StartupTaskState},
    core::HSTRING,
};
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, KEY_SET_VALUE},
};

use crate::{Describe, Res, ui::BACKGROUND_FLAG};

/// Where Windows keeps what it starts at sign-in.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Where Windows keeps whether the user switched such an entry off (in Settings > Apps > Startup,
/// or Task Manager's Startup tab). The entry stays in [`RUN_KEY`]; Windows just does not run it.
const APPROVED_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
/// The name of piikey's value in both keys.
const RUN_VALUE: &str = "piikey";
/// The startup task of the Store build, as `packaging/windows/msix/AppxManifest.xml` names it.
const TASK_ID: &str = "piikeyStartup";
/// How long a start waits for the running app to answer: it answers within moments, or is not there.
const ASK_WAIT: Duration = Duration::from_millis(300);

/// Whether piikey starts when the user signs in.
///
/// # Errors
/// The registry, or Windows' startup task, cannot be read.
pub fn enabled() -> Res<bool> {
    if is_packaged() {
        return Ok(task_is_on(task()?.State().describe()?));
    }
    run_enabled_in(
        RUN_KEY,
        APPROVED_KEY,
        &run_command(&launch_path().describe()?),
    )
}

/// Switches starting at sign-in on or off. Blocks on Windows (the Store build asks it to switch
/// its startup task), so it belongs on a background thread.
///
/// # Errors
/// The registry cannot be written; or, in the Store build, Windows refuses: the user switched
/// piikey off under Settings > Apps > Startup, or the organisation's policy forbids it.
pub fn set(on: bool) -> Res<()> {
    if is_packaged() {
        let task = task()?;
        return if on {
            enable_outcome(task.RequestEnableAsync().describe()?.join().describe()?)
        } else {
            task.Disable().describe()
        };
    }
    set_run_in(
        RUN_KEY,
        APPROVED_KEY,
        &run_command(&launch_path().describe()?),
        on,
    )
}

/// Whether Windows started this process at sign-in as the Store build's startup task. The
/// unpackaged exe is told by [`BACKGROUND_FLAG`] instead.
#[must_use]
pub fn launched_at_sign_in() -> bool {
    is_packaged()
        && AppInstance::GetActivatedEventArgs()
            .and_then(|args| args.Kind())
            .is_ok_and(|kind| kind == ActivationKind::StartupTask)
}

/// What a start of piikey asks of an app that is already running, so that it does not start a
/// second one: a plain start asks for the window; a background start (at sign-in) only checks
/// that there is one. `true` when an app answered, `false` when none did and this process is to
/// become the app.
///
/// # Errors
/// The app on the pipe refuses, or talking to it fails.
pub fn hand_over(hidden: bool) -> Res<bool> {
    hand_over_on(&service::default_pipe(), hidden)
}

fn hand_over_on(pipe: &str, hidden: bool) -> Res<bool> {
    let request = if hidden {
        Request::Status
    } else {
        Request::ShowWindow
    };
    let Some(envelope) = service::call(pipe, &request, ASK_WAIT).describe()? else {
        return Ok(false);
    };
    match api::open_envelope(envelope) {
        // `piikey-cli serve` answers a status too, saying it is not the app.
        Ok(result) => Ok(!hidden || result["app"] == true),
        // `piikey-cli serve` has the pipe, not the app: this process becomes the app.
        Err(error) if error.code() == "app_required" => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

/// The value of an exe that Windows starts at sign-in: quoted path, then the background flag.
fn run_command(exe: &Path) -> String {
    format!("\"{}\" {BACKGROUND_FLAG}", exe.display())
}

/// The startup task of the package.
fn task() -> Res<StartupTask> {
    StartupTask::GetAsync(&HSTRING::from(TASK_ID))
        .describe()?
        .join()
        .describe()
}

/// A startup task that Windows runs at sign-in.
fn task_is_on(state: StartupTaskState) -> bool {
    state == StartupTaskState::Enabled || state == StartupTaskState::EnabledByPolicy
}

/// What a request to switch the startup task on came to: Windows decides, and the user can have
/// switched it off where only they can switch it on again.
fn enable_outcome(state: StartupTaskState) -> Res<()> {
    if task_is_on(state) {
        Ok(())
    } else if state == StartupTaskState::DisabledByUser {
        Err("Windows has piikey switched off at sign-in: turn it on under Settings > Apps > Startup."
            .to_owned())
    } else if state == StartupTaskState::DisabledByPolicy {
        Err("Your organisation's policy keeps piikey from starting at sign-in.".to_owned())
    } else {
        Err("Windows did not switch piikey on at sign-in.".to_owned())
    }
}

/// [`enabled`] for the unpackaged exe: the `Run` value is there, runs this exe, and Windows has
/// not been told by the user to skip it.
fn run_enabled_in(run: &str, approved: &str, command: &str) -> Res<bool> {
    let Some(run) = open(run, "read the start at sign-in", false)? else {
        return Ok(false);
    };
    let current: Option<String> = match run.get_value(RUN_VALUE) {
        Ok(value) => Some(value),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot read the start at sign-in: {error}")),
    };
    // A value that runs another exe (this one was moved) does not start this one.
    if current.as_deref() != Some(command) {
        return Ok(false);
    }
    let Some(approved) = open(approved, "read the start at sign-in", false)? else {
        return Ok(true);
    };
    Ok(match approved.get_raw_value(RUN_VALUE) {
        // The first byte is even while the entry is on, odd once the user has switched it off.
        Ok(raw) => raw.bytes.first().is_none_or(|byte| byte % 2 == 0),
        Err(_) => true,
    })
}

/// [`set`] for the unpackaged exe. Switching on also clears the user's earlier "skip this
/// entry", which would else keep Windows from running the value just written.
fn set_run_in(run: &str, approved: &str, command: &str, on: bool) -> Res<()> {
    if on {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(run)
            .map_err(|error| format!("cannot start piikey at sign-in (HKCU\\{run}): {error}"))?;
        key.set_value(RUN_VALUE, &command)
            .map_err(|error| format!("cannot start piikey at sign-in: {error}"))?;
    } else {
        remove_value(run)?;
    }
    remove_value(approved)
}

/// Removes piikey's value from the key at `path`; one that is not there is already as wanted.
fn remove_value(path: &str) -> Res<()> {
    let Some(key) = open(path, "change the start at sign-in", true)? else {
        return Ok(());
    };
    match key.delete_value(RUN_VALUE) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            Err(format!("cannot change the start at sign-in: {error}"))
        }
        _ => Ok(()),
    }
}

/// Opens `path` under the user's hive; `None` when it is not there.
fn open(path: &str, what: &str, write: bool) -> Res<Option<RegKey>> {
    let hive = RegKey::predef(HKEY_CURRENT_USER);
    let key = if write {
        hive.open_subkey_with_flags(path, KEY_SET_VALUE)
    } else {
        hive.open_subkey(path)
    };
    match key {
        Ok(key) => Ok(Some(key)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot {what} (HKCU\\{path}): {error}")),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use piikey::api::{ApiError, Handler};
    use serde_json::{Value, json};
    use winreg::{RegValue, enums::REG_BINARY};

    use super::*;

    /// A private tree, so a test never touches the user's real start-up entries.
    struct Sandbox(String);

    impl Sandbox {
        fn new(name: &str) -> Self {
            Self(format!(
                r"Software\piikey-startup-test-{}-{name}",
                std::process::id()
            ))
        }

        fn run(&self) -> String {
            format!(r"{}\Run", self.0)
        }

        fn approved(&self) -> String {
            format!(r"{}\Approved", self.0)
        }

        fn value(key: &str) -> Option<String> {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey(key)
                .ok()?
                .get_value(RUN_VALUE)
                .ok()
        }

        /// What Windows writes when the user switches the entry off in Task Manager.
        fn user_switched_off(&self, first_byte: u8) -> Res<()> {
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(self.approved())
                .describe()?;
            let mut bytes = vec![0; 12];
            bytes[0] = first_byte;
            key.set_raw_value(
                RUN_VALUE,
                &RegValue {
                    bytes: bytes.into(),
                    vtype: REG_BINARY,
                },
            )
            .describe()
        }
    }

    impl Drop for Sandbox {
        /// Runs even when an assertion fails.
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }

    #[test]
    fn the_run_value_starts_the_quoted_exe_in_the_background() {
        assert_eq!(
            run_command(Path::new(r"C:\Program Files\piikey\piikey.exe")),
            r#""C:\Program Files\piikey\piikey.exe" --background"#
        );
        assert_eq!(BACKGROUND_FLAG, "--background");
        assert_eq!(
            run_command(&PathBuf::from(
                r"C:\Users\a\AppData\Local\Microsoft\WindowsApps\piikey.exe"
            )),
            r#""C:\Users\a\AppData\Local\Microsoft\WindowsApps\piikey.exe" --background"#
        );
    }

    #[test]
    fn switching_on_writes_the_value_and_off_removes_it() -> Res<()> {
        let sandbox = Sandbox::new("toggle");
        let command = run_command(Path::new(r"C:\piikey\piikey.exe"));
        let (run, approved) = (sandbox.run(), sandbox.approved());

        assert!(!run_enabled_in(&run, &approved, &command)?, "nothing yet");
        set_run_in(&run, &approved, &command, true)?;
        assert_eq!(Sandbox::value(&run).as_deref(), Some(command.as_str()));
        assert!(run_enabled_in(&run, &approved, &command)?);
        // Twice leaves the one value.
        set_run_in(&run, &approved, &command, true)?;
        assert!(run_enabled_in(&run, &approved, &command)?);

        set_run_in(&run, &approved, &command, false)?;
        assert_eq!(Sandbox::value(&run), None);
        assert!(!run_enabled_in(&run, &approved, &command)?);
        // Switching off what is not there is fine.
        set_run_in(&run, &approved, &command, false)
    }

    #[test]
    fn a_value_that_runs_another_exe_does_not_count() -> Res<()> {
        let sandbox = Sandbox::new("moved");
        let (run, approved) = (sandbox.run(), sandbox.approved());
        let old = run_command(Path::new(r"C:\old\piikey.exe"));
        let new = run_command(Path::new(r"C:\new\piikey.exe"));
        set_run_in(&run, &approved, &old, true)?;
        assert!(!run_enabled_in(&run, &approved, &new)?);
        // Switching on again points the value at the exe that runs now.
        set_run_in(&run, &approved, &new, true)?;
        assert!(run_enabled_in(&run, &approved, &new)?);
        Ok(())
    }

    #[test]
    fn what_the_user_switched_off_in_windows_reads_as_off_until_switched_on_here() -> Res<()> {
        let sandbox = Sandbox::new("approved");
        let (run, approved) = (sandbox.run(), sandbox.approved());
        let command = run_command(Path::new(r"C:\piikey\piikey.exe"));
        set_run_in(&run, &approved, &command, true)?;

        sandbox.user_switched_off(3)?;
        assert!(!run_enabled_in(&run, &approved, &command)?);
        set_run_in(&run, &approved, &command, true)?;
        assert!(run_enabled_in(&run, &approved, &command)?);

        // The even first bytes are Windows' "on".
        sandbox.user_switched_off(2)?;
        assert!(run_enabled_in(&run, &approved, &command)?);
        sandbox.user_switched_off(6)?;
        assert!(run_enabled_in(&run, &approved, &command)?);
        Ok(())
    }

    #[test]
    fn the_startup_task_says_why_it_will_not_switch_on() {
        assert!(enable_outcome(StartupTaskState::Enabled).is_ok());
        assert!(enable_outcome(StartupTaskState::EnabledByPolicy).is_ok());
        let by_user = enable_outcome(StartupTaskState::DisabledByUser).err();
        assert!(by_user.is_some_and(|text| text.contains("Settings > Apps > Startup")));
        let by_policy = enable_outcome(StartupTaskState::DisabledByPolicy).err();
        assert!(by_policy.is_some_and(|text| text.contains("policy")));
        assert!(enable_outcome(StartupTaskState::Disabled).is_err());
        assert!(task_is_on(StartupTaskState::Enabled));
        assert!(!task_is_on(StartupTaskState::DisabledByUser));
    }

    /// Counts the window requests it gets and answers like the app, or like `piikey-cli serve`.
    struct Stub {
        windows: AtomicUsize,
        is_app: bool,
    }

    impl Handler for Stub {
        fn handle(&self, request: Request) -> Result<Value, ApiError> {
            match request {
                Request::ShowWindow if self.is_app => {
                    self.windows.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({}))
                }
                Request::Status => Ok(json!({ "app": self.is_app })),
                _ => Err(ApiError::app_required("piikey.exe")),
            }
        }
    }

    fn test_pipe(what: &str) -> String {
        format!(
            r"\\.\pipe\piikey-startup-test-{}-{what}",
            std::process::id()
        )
    }

    #[test]
    fn a_second_start_asks_the_running_app_for_its_window_over_the_pipe() -> Res<()> {
        let pipe = test_pipe("show");
        assert!(!hand_over_on(&pipe, false)?, "nobody listens yet");
        let stub = Arc::new(Stub {
            windows: AtomicUsize::new(0),
            is_app: true,
        });
        let server = service::spawn(stub.clone(), &pipe).describe()?;
        assert!(hand_over_on(&pipe, false)?);
        assert_eq!(stub.windows.load(Ordering::SeqCst), 1);
        // A start at sign-in only checks that an app runs: no window.
        assert!(hand_over_on(&pipe, true)?);
        assert_eq!(stub.windows.load(Ordering::SeqCst), 1);
        server.stop();
        Ok(())
    }

    #[test]
    fn piikey_cli_serve_on_the_pipe_is_no_app_to_hand_over_to() -> Res<()> {
        let pipe = test_pipe("serve");
        let stub = Arc::new(Stub {
            windows: AtomicUsize::new(0),
            is_app: false,
        });
        let server = service::spawn(stub.clone(), &pipe).describe()?;
        assert!(!hand_over_on(&pipe, false)?);
        assert!(!hand_over_on(&pipe, true)?);
        assert_eq!(stub.windows.load(Ordering::SeqCst), 0);
        server.stop();
        Ok(())
    }
}
