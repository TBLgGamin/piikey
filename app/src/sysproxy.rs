//! Windows system proxy on/off.
//!
//! `WinINET`'s proxy settings are the only place most browsers and apps look.
//! The app overwrites them while it runs, so the previous values are kept in
//! `%LOCALAPPDATA%\piikey\proxy.prev` and put back afterwards.
//!
//! The file also marks a session that was not closed cleanly (crash, kill):
//! it exists exactly while the settings point at the app. That is why
//! [`disable`] can be called any time, and why it never touches a proxy the
//! app did not set: a user's own proxy is left alone.
//!
//! While the settings point at the app, a `RunOnce` entry also runs the
//! app with `--restore-proxy` at the next sign-in, for a session ended by
//! a shutdown or sign-out that the app could not clean up after.
//!
//! The previous values are read as raw registry values: the `sysproxy` crate
//! can only read a bare `ip:port`, so it would lose a proxy given by host
//! name or per protocol (`http=a:80;https=b:80`). `sysproxy` writes the
//! settings and tells `WinINET` to reload them; it also respells the server
//! and writes all three values, so a restore puts the saved ones back raw.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use ::sysproxy::Sysproxy;
use piikey::sys::{data_dir, write_atomic};
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_SZ, RegType},
    types::FromRegValue,
};

use crate::{Describe, Res};

const SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
// The file name is kept for existing installs.
const STATE_FILE: &str = "proxy.prev";
const RUN_ONCE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
const RUN_ONCE_VALUE: &str = "piikey proxy restore";
/// The `RunOnce` value name of the builds before the rename; removed so no stale entry stays behind.
const OLD_RUN_ONCE_VALUE: &str = "piikey Guard proxy restore";
/// Hosts that must never go through the app.
const BYPASS: &str = "<local>;localhost;127.*;10.*;172.16.*;192.168.*";
/// Proxy port written when the previous settings had no usable server.
const FALLBACK_PORT: u16 = 80;

/// `enable` and `disable` read, then write, the registry and `proxy.prev`.
static SERIALIZE: Mutex<()> = Mutex::new(());

/// The three `WinINET` values that decide the proxy, as the registry holds
/// them. `None` means the value does not exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Snapshot {
    /// `ProxyEnable`.
    enable: Option<bool>,
    /// `ProxyServer`: `host:port` or `http=h:p;https=h:p`.
    server: Option<String>,
    /// `ProxyOverride`.
    bypass: Option<String>,
}

/// What `proxy.prev` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Saved {
    /// The `ProxyServer` value the app wrote.
    ours: String,
    /// The settings to restore.
    prev: Snapshot,
}

/// What [`disable`] has to do.
#[derive(Debug, PartialEq, Eq)]
enum Undo {
    /// Not ours: leave the settings alone.
    Nothing,
    /// Put these settings back and drop `proxy.prev`.
    Restore(Snapshot),
    /// `proxy.prev` is stale (the user changed the proxy since): drop it only.
    Forget,
    /// Ours, but the previous settings are unknown: switch the proxy off.
    TurnOff,
}

/// Saves the current system proxy and points it at `127.0.0.1:port`.
///
/// Calling it again after a crash, while the settings still point at the
/// app, keeps the settings saved by the first call.
///
/// # Errors
/// Registry/`WinINET` failure.
pub fn enable(port: u16) -> Res<()> {
    let _serialized = SERIALIZE.lock().unwrap_or_else(PoisonError::into_inner);
    let ours = server_for(port);
    let current = read_settings()?;
    let state = state_path()?;
    let saved = plan_enable(&current, read_saved(&state).as_ref(), &ours);
    // Saved first: a crash between the two writes then leaves a record that
    // `disable` recognizes as stale instead of settings nobody can undo.
    write_atomic(&state, saved.to_text().as_bytes()).describe()?;
    arm_sign_in_restore()?;
    apply(true, &ours, BYPASS)
}

/// Restores the saved system proxy. A no-op when the app did not change it
/// (no `proxy.prev`, and the current proxy is not the app's).
///
/// # Errors
/// Registry/`WinINET` failure.
pub fn disable() -> Res<()> {
    let _serialized = SERIALIZE.lock().unwrap_or_else(PoisonError::into_inner);
    let state = state_path()?;
    let saved = read_saved(&state);
    let current = read_settings()?;
    let default_ours = server_for(crate::proxy::PORT);
    match plan_disable(&current, saved.as_ref(), &default_ours) {
        Undo::Nothing => Ok(()),
        Undo::Forget => {
            forget(&state)?;
            disarm_sign_in_restore()
        }
        Undo::Restore(prev) => {
            restore(&prev)?;
            forget(&state)?;
            disarm_sign_in_restore()
        }
        Undo::TurnOff => {
            let server = current.server.as_deref().unwrap_or(&default_ours);
            apply(false, server, current.bypass.as_deref().unwrap_or(""))?;
            disarm_sign_in_restore()
        }
    }
}

/// Has Windows run the app with [`crate::ui::RESTORE_FLAG`] at the next
/// sign-in. Windows deletes the entry before it runs it.
fn arm_sign_in_restore() -> Res<()> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate the piikey exe: {e}"))?;
    let command = format!("\"{}\" {}", exe.display(), crate::ui::RESTORE_FLAG);
    arm_in(RUN_ONCE_KEY, &command)
}

fn arm_in(path: &str, command: &str) -> Res<()> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(path)
        .map_err(|e| format!("cannot register the proxy restore at sign-in (HKCU\\{path}): {e}"))?;
    key.set_value(RUN_ONCE_VALUE, &command)
        .map_err(|e| format!("cannot register the proxy restore at sign-in: {e}"))
}

/// Removes the entry of [`arm_sign_in_restore`], and the one an earlier build
/// left under its old name. An entry that is already gone is fine (a restore
/// without a prior enable).
fn disarm_sign_in_restore() -> Res<()> {
    disarm_in(RUN_ONCE_KEY)
}

fn disarm_in(path: &str) -> Res<()> {
    let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(path, KEY_SET_VALUE) {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "cannot remove the proxy restore at sign-in (HKCU\\{path}): {e}"
            ));
        }
    };
    for value in [RUN_ONCE_VALUE, OLD_RUN_ONCE_VALUE] {
        delete_value(&key, value)
            .map_err(|e| format!("cannot remove the proxy restore at sign-in: {e}"))?;
    }
    Ok(())
}

/// `proxy.prev` of a session that ends with these `current` settings.
fn plan_enable(current: &Snapshot, saved: Option<&Saved>, ours: &str) -> Saved {
    let prev = match saved {
        // Still pointing at the app: the earlier session never restored,
        // so what it saved is still the user's.
        Some(saved) if is_ours(current, &saved.ours) => saved.prev.clone(),
        // Pointing at the app with nothing saved: there is nothing to go
        // back to but "off". Saving the app's own settings would make
        // `disable` re-enable them.
        None if is_ours(current, ours) => Snapshot::default(),
        // Stale record or none: the current settings are the user's.
        _ => current.clone(),
    };
    Saved {
        ours: ours.to_owned(),
        prev,
    }
}

fn plan_disable(current: &Snapshot, saved: Option<&Saved>, default_ours: &str) -> Undo {
    match saved {
        Some(saved) if is_ours(current, &saved.ours) => Undo::Restore(saved.prev.clone()),
        Some(_) => Undo::Forget,
        None if is_ours(current, default_ours) => Undo::TurnOff,
        None => Undo::Nothing,
    }
}

/// The proxy is on and set to `ours`.
fn is_ours(current: &Snapshot, ours: &str) -> bool {
    current.enable == Some(true) && current.server.as_deref() == Some(ours)
}

fn server_for(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Writes `prev` back exactly. `apply` goes through `sysproxy`, which respells
/// the server (`proxy.corp` becomes `proxy.corp:80`) and writes all three
/// values, so the saved ones are put back raw afterwards; values the user
/// never had are deleted again.
fn restore(prev: &Snapshot) -> Res<()> {
    let server = prev
        .server
        .clone()
        .unwrap_or_else(|| server_for(FALLBACK_PORT));
    apply(
        prev.enable.unwrap_or(false),
        &server,
        prev.bypass.as_deref().unwrap_or(""),
    )?;
    put_back_in(SETTINGS_KEY, prev)
}

/// Makes the values under `path` equal `prev`: text is written as it was
/// saved, `None` removes the value.
fn put_back_in(path: &str, prev: &Snapshot) -> Res<()> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(path, KEY_SET_VALUE)
        .map_err(|e| format!("cannot update the Windows proxy settings (HKCU\\{path}): {e}"))?;
    for (name, text) in [
        ("ProxyServer", prev.server.as_deref()),
        ("ProxyOverride", prev.bypass.as_deref()),
    ] {
        match text {
            Some(text) => key.set_value(name, &text),
            None => delete_value(&key, name),
        }
        .map_err(|e| format!("cannot restore the Windows proxy setting {name}: {e}"))?;
    }
    if prev.enable.is_none() {
        delete_value(&key, "ProxyEnable")
            .map_err(|e| format!("cannot restore the Windows proxy setting ProxyEnable: {e}"))?;
    }
    Ok(())
}

/// Deletes `name`; a value that is not there is already as wanted.
fn delete_value(key: &RegKey, name: &str) -> std::io::Result<()> {
    match key.delete_value(name) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Writes the settings and refreshes `WinINET`. `sysproxy` stores
/// `{host}:{port}`, so the raw `server` is split at its last colon, which
/// reproduces any server string that ends in a port.
fn apply(enable: bool, server: &str, bypass: &str) -> Res<()> {
    let (host, port) = split_server(server);
    Sysproxy {
        enable,
        host,
        port,
        bypass: bypass.to_owned(),
    }
    .set_system_proxy()
    .map_err(|e| format!("cannot update the Windows proxy settings: {e}"))
}

/// `("proxy.corp", 8080)` for `proxy.corp:8080`; `a:80;https=b` and
/// `b:81` pairs split at the last colon too. Without a port: port 80, the
/// default `WinINET` assumes.
fn split_server(server: &str) -> (String, u16) {
    match server.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => port.parse().map_or_else(
            |_| (server.to_owned(), FALLBACK_PORT),
            |p| (host.to_owned(), p),
        ),
        _ => (server.to_owned(), FALLBACK_PORT),
    }
}

fn read_settings() -> Res<Snapshot> {
    read_settings_in(SETTINGS_KEY)
}

/// Reads the values under `path` (relative to `HKEY_CURRENT_USER`). A value
/// that is absent, empty, or of another registry type than the settings use
/// reads as `None`.
fn read_settings_in(path: &str) -> Res<Snapshot> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(path)
        .map_err(|e| format!("cannot read the Windows proxy settings (HKCU\\{path}): {e}"))?;
    let text = |name: &str| -> Res<Option<String>> {
        Ok(raw_value::<String>(&key, name, &[REG_SZ, REG_EXPAND_SZ])?.filter(|s| !s.is_empty()))
    };
    Ok(Snapshot {
        enable: raw_value::<u32>(&key, "ProxyEnable", &[REG_DWORD])?.map(|value| value != 0),
        server: text("ProxyServer")?,
        bypass: text("ProxyOverride")?,
    })
}

/// The value `name` converted to `T`; `None` when it is absent, of a type not
/// in `kinds`, or not convertible.
fn raw_value<T: FromRegValue>(key: &RegKey, name: &str, kinds: &[RegType]) -> Res<Option<T>> {
    match key.get_raw_value(name) {
        Ok(raw) if kinds.contains(&raw.vtype) => Ok(T::from_reg_value(&raw).ok()),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read the Windows proxy setting {name}: {e}")),
    }
}

fn state_path() -> Res<PathBuf> {
    Ok(data_dir().describe()?.join(STATE_FILE))
}

/// The saved record; a missing or unreadable file means none.
fn read_saved(path: &Path) -> Option<Saved> {
    Saved::parse(&fs::read_to_string(path).ok()?)
}

fn forget(path: &Path) -> Res<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

impl Saved {
    fn to_text(&self) -> String {
        let mut lines = vec![format!("ours={}", self.ours)];
        if let Some(enable) = self.prev.enable {
            lines.push(format!("enable={}", u8::from(enable)));
        }
        if let Some(server) = &self.prev.server {
            lines.push(format!("server={server}"));
        }
        if let Some(bypass) = &self.prev.bypass {
            lines.push(format!("bypass={bypass}"));
        }
        lines.push(String::new());
        lines.join("\n")
    }

    /// `None` unless the file names the app's own server.
    fn parse(text: &str) -> Option<Self> {
        let mut ours = None;
        let mut prev = Snapshot::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "ours" => ours = Some(value.to_owned()),
                "enable" => prev.enable = Some(value == "1"),
                "server" => prev.server = Some(value.to_owned()),
                "bypass" => prev.bypass = Some(value.to_owned()),
                _ => {}
            }
        }
        Some(Self { ours: ours?, prev })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "127.0.0.1:7979";

    fn user(enable: bool, server: &str) -> Snapshot {
        Snapshot {
            enable: Some(enable),
            server: Some(server.to_owned()),
            bypass: Some("<local>".to_owned()),
        }
    }

    fn app_proxy() -> Snapshot {
        user(true, OURS)
    }

    fn saved(prev: Snapshot) -> Saved {
        Saved {
            ours: OURS.to_owned(),
            prev,
        }
    }

    /// A private tree, so a test never touches the user's real settings.
    struct Sandbox(String);

    impl Sandbox {
        fn new(name: &str) -> Self {
            Self(format!(
                r"Software\piikey-sysproxy-test-{}-{name}\key",
                std::process::id()
            ))
        }

        fn parent(&self) -> &str {
            self.0
                .rsplit_once('\\')
                .map_or(&self.0, |(parent, _)| parent)
        }

        fn key(&self) -> Res<RegKey> {
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&self.0)
                .describe()?;
            Ok(key)
        }
    }

    impl Drop for Sandbox {
        /// Runs even when an assertion fails.
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(self.parent());
        }
    }

    fn names(key: &RegKey) -> Vec<String> {
        // Stops at the first error: an iterator over a deleted key never ends.
        key.enum_values()
            .map_while(|v| v.ok().map(|v| v.0))
            .collect()
    }

    #[test]
    fn settings_are_read_from_the_registry() -> Res<()> {
        let sandbox = Sandbox::new("read");
        let key = sandbox.key()?;
        key.set_value("ProxyEnable", &1u32).describe()?;
        key.set_value("ProxyServer", &"http=a.corp:80;https=b.corp:81")
            .describe()?;
        key.set_value("ProxyOverride", &"<local>;*.corp.nl")
            .describe()?;
        assert_eq!(
            read_settings_in(&sandbox.0)?,
            Snapshot {
                enable: Some(true),
                server: Some("http=a.corp:80;https=b.corp:81".into()),
                bypass: Some("<local>;*.corp.nl".into()),
            }
        );
        key.set_value("ProxyEnable", &0u32).describe()?;
        assert_eq!(read_settings_in(&sandbox.0)?.enable, Some(false));
        Ok(())
    }

    #[test]
    fn missing_empty_and_mistyped_values_read_as_none() -> Res<()> {
        let sandbox = Sandbox::new("none");
        let key = sandbox.key()?;
        assert_eq!(read_settings_in(&sandbox.0)?, Snapshot::default());
        key.set_value("ProxyServer", &"").describe()?;
        key.set_value("ProxyOverride", &"").describe()?;
        key.set_value("ProxyEnable", &"1").describe()?;
        assert_eq!(read_settings_in(&sandbox.0)?, Snapshot::default());
        // A DWORD where a string belongs is not a server either.
        key.set_value("ProxyServer", &1u32).describe()?;
        assert_eq!(read_settings_in(&sandbox.0)?.server, None);
        Ok(())
    }

    #[test]
    fn an_unreadable_settings_key_is_an_error() {
        let sandbox = Sandbox::new("absent");
        assert!(read_settings_in(&sandbox.0).is_err());
    }

    #[test]
    fn put_back_restores_exact_text_and_deletes_absent_values() -> Res<()> {
        let sandbox = Sandbox::new("putback");
        let key = sandbox.key()?;
        // What `sysproxy` leaves behind after re-spelling the saved server.
        key.set_value("ProxyEnable", &1u32).describe()?;
        key.set_value("ProxyServer", &"proxy.corp:80").describe()?;
        key.set_value("ProxyOverride", &"<local>").describe()?;

        for server in ["proxy.corp", "http=a:80;https=b"] {
            let prev = Snapshot {
                enable: Some(false),
                server: Some(server.into()),
                bypass: Some("*.corp".into()),
            };
            put_back_in(&sandbox.0, &prev)?;
            let read = read_settings_in(&sandbox.0)?;
            assert_eq!(read.server.as_deref(), Some(server));
            assert_eq!(read.bypass.as_deref(), Some("*.corp"));
        }

        put_back_in(&sandbox.0, &Snapshot::default())?;
        assert!(names(&key).is_empty(), "left {:?}", names(&key));
        // Deleting what is already gone is fine.
        put_back_in(&sandbox.0, &Snapshot::default())?;
        Ok(())
    }

    #[test]
    fn arming_twice_leaves_one_entry_and_disarming_removes_both_names() -> Res<()> {
        let sandbox = Sandbox::new("runonce");
        arm_in(&sandbox.0, "\"a.exe\" --first")?;
        arm_in(&sandbox.0, "\"a.exe\" --second")?;
        let key = sandbox.key()?;
        assert_eq!(names(&key), [RUN_ONCE_VALUE]);
        assert_eq!(
            key.get_value::<String, _>(RUN_ONCE_VALUE).describe()?,
            "\"a.exe\" --second"
        );

        key.set_value(OLD_RUN_ONCE_VALUE, &"old").describe()?;
        key.set_value("unrelated", &"keep").describe()?;
        disarm_in(&sandbox.0)?;
        assert_eq!(names(&key), ["unrelated"]);
        // Nothing left to remove is fine, and so is no key at all.
        disarm_in(&sandbox.0)?;
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(sandbox.parent())
            .describe()?;
        disarm_in(&sandbox.0)?;
        Ok(())
    }

    #[test]
    fn saved_text_round_trips() {
        for prev in [
            user(true, "proxy.corp:8080"),
            user(false, "http=a:80;https=b:81"),
            Snapshot::default(),
            Snapshot {
                enable: Some(false),
                server: None,
                bypass: Some("<local>".into()),
            },
        ] {
            let record = saved(prev);
            assert_eq!(Saved::parse(&record.to_text()), Some(record));
        }
        assert_eq!(Saved::parse("garbage"), None, "no `ours` line");
        assert_eq!(Saved::parse(""), None);
    }

    #[test]
    fn split_server_reproduces_the_stored_string() {
        for raw in [
            "127.0.0.1:8080",
            "proxy.corp.nl:3128",
            "http=a.corp:80;https=b.corp:81",
            "[::1]:8888",
        ] {
            let (host, port) = split_server(raw);
            assert_eq!(format!("{host}:{port}"), raw);
        }
        assert_eq!(split_server("proxy.corp"), ("proxy.corp".into(), 80));
        assert_eq!(split_server(""), (String::new(), 80));
        assert_eq!(split_server(":80"), (":80".into(), 80), "no host");
    }

    #[test]
    fn enable_saves_the_users_proxy() {
        let current = user(true, "proxy.corp:8080");
        let record = plan_enable(&current, None, OURS);
        assert_eq!(record, saved(current));
    }

    #[test]
    fn enable_saves_a_leftover_disabled_proxy_too() {
        let current = user(false, "127.0.0.1:8080");
        assert_eq!(plan_enable(&current, None, OURS).prev, current);
    }

    #[test]
    fn enable_after_a_crash_keeps_the_first_saved_settings() {
        let users = user(true, "proxy.corp:8080");
        let earlier = saved(users.clone());
        // The proxy still points at the app: do not save that as "previous".
        let record = plan_enable(&app_proxy(), Some(&earlier), OURS);
        assert_eq!(record.prev, users);
        // The crashed session used another port; the new record follows the
        // new endpoint and still keeps the user's settings.
        let crashed = user(true, "127.0.0.1:9000");
        let earlier = Saved {
            ours: "127.0.0.1:9000".to_owned(),
            prev: users.clone(),
        };
        let record = plan_enable(&crashed, Some(&earlier), OURS);
        assert_eq!(record.ours, OURS, "ours is the new endpoint");
        assert_eq!(record.prev, users);
    }

    #[test]
    fn enable_with_a_stale_record_saves_the_current_settings() {
        let stale = saved(user(true, "old.proxy:1"));
        let current = user(true, "new.proxy:2");
        assert_eq!(plan_enable(&current, Some(&stale), OURS).prev, current);
    }

    #[test]
    fn enable_pointing_at_the_app_without_a_record_saves_off() {
        let record = plan_enable(&app_proxy(), None, OURS);
        assert_eq!(record.prev, Snapshot::default());
        assert!(
            !is_ours(&record.prev, OURS),
            "restoring it must not re-enable the app"
        );
    }

    #[test]
    fn disable_restores_what_enable_saved() {
        let users = user(true, "proxy.corp:8080");
        assert_eq!(
            plan_disable(&app_proxy(), Some(&saved(users.clone())), OURS),
            Undo::Restore(users)
        );
    }

    #[test]
    fn disable_never_touches_a_proxy_the_app_did_not_set() {
        // No record, user's own proxy (enabled or not): hands off.
        assert_eq!(
            plan_disable(&user(true, "proxy.corp:8080"), None, OURS),
            Undo::Nothing
        );
        assert_eq!(plan_disable(&user(false, OURS), None, OURS), Undo::Nothing);
        assert_eq!(
            plan_disable(&Snapshot::default(), None, OURS),
            Undo::Nothing
        );
        // A record, but the user changed the proxy since: keep theirs.
        let record = saved(user(false, "old"));
        assert_eq!(
            plan_disable(&user(true, "proxy.corp:8080"), Some(&record), OURS),
            Undo::Forget
        );
        assert_eq!(
            plan_disable(&user(false, OURS), Some(&record), OURS),
            Undo::Forget,
            "switched off by the user"
        );
    }

    #[test]
    fn disable_switches_off_a_app_proxy_with_no_record() {
        assert_eq!(plan_disable(&app_proxy(), None, OURS), Undo::TurnOff);
    }

    #[test]
    fn the_real_settings_can_be_read() -> Res<()> {
        // Read-only: never writes the registry.
        let settings = read_settings()?;
        if let Some(server) = &settings.server {
            assert!(!server.is_empty());
        }
        // What was read can be saved and reloaded as it is.
        let record = saved(settings);
        assert_eq!(Saved::parse(&record.to_text()), Some(record));
        Ok(())
    }
}
