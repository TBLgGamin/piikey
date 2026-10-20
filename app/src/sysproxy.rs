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
//! The previous values are read as raw registry strings with `reg.exe`: the
//! `sysproxy` crate can only read a bare `ip:port`, so it would lose a proxy
//! given by host name or per protocol (`http=a:80;https=b:80`). `sysproxy`
//! writes the settings and tells `WinINET` to reload them.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use ::sysproxy::Sysproxy;

use crate::{
    Res,
    policy::{data_dir, run_system_tool, write_atomic},
};

const SETTINGS_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
// The file name is kept for existing installs.
const STATE_FILE: &str = "proxy.prev";
const RUN_ONCE_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce";
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
    write_atomic(&state, saved.to_text().as_bytes())?;
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
    let out = run_system_tool(
        "reg.exe",
        &[
            "add",
            RUN_ONCE_KEY,
            "/v",
            RUN_ONCE_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            &command,
            "/f",
        ],
    )?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "cannot register the proxy restore at sign-in (reg.exe: {})",
            out.status
        ))
    }
}

/// Removes the entry of [`arm_sign_in_restore`], and the one an earlier build
/// left under its old name. The exit statuses are not checked: an entry is
/// usually gone already (a restore without a prior enable), and one left
/// behind only runs a restore that finds nothing to do.
fn disarm_sign_in_restore() -> Res<()> {
    for value in [RUN_ONCE_VALUE, OLD_RUN_ONCE_VALUE] {
        run_system_tool("reg.exe", &["delete", RUN_ONCE_KEY, "/v", value, "/f"])?;
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

/// Writes `prev` back. A missing server leaves the app's own value behind,
/// switched off, which is harmless.
fn restore(prev: &Snapshot) -> Res<()> {
    let enable = prev.enable.unwrap_or(false);
    let server = prev
        .server
        .clone()
        .unwrap_or_else(|| server_for(FALLBACK_PORT));
    apply(enable, &server, prev.bypass.as_deref().unwrap_or(""))
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
    let out = run_system_tool("reg.exe", &["query", SETTINGS_KEY])?;
    if !out.status.success() {
        return Err(format!(
            "cannot read the Windows proxy settings (reg.exe: {})",
            out.status
        ));
    }
    Ok(parse_reg_query(&String::from_utf8_lossy(&out.stdout)))
}

/// Picks the proxy values out of `reg query` output, whose value lines read
/// `    ProxyServer    REG_SZ    127.0.0.1:8080` (four spaces between fields;
/// the type names are not localized).
fn parse_reg_query(text: &str) -> Snapshot {
    let mut snapshot = Snapshot::default();
    for line in text.lines() {
        let mut fields = line.trim().splitn(3, "    ");
        let (Some(name), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        let data = fields.next().unwrap_or("").trim();
        let owned = || (!data.is_empty()).then(|| data.to_owned());
        match (name, kind) {
            ("ProxyEnable", "REG_DWORD") => {
                snapshot.enable = u32::from_str_radix(data.trim_start_matches("0x"), 16)
                    .ok()
                    .map(|value| value != 0);
            }
            ("ProxyServer", "REG_SZ" | "REG_EXPAND_SZ") => snapshot.server = owned(),
            ("ProxyOverride", "REG_SZ" | "REG_EXPAND_SZ") => snapshot.bypass = owned(),
            _ => {}
        }
    }
    snapshot
}

fn state_path() -> Res<PathBuf> {
    Ok(data_dir()?.join(STATE_FILE))
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

    #[test]
    fn parses_reg_query_output() {
        let text = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n\
                    \x20   ProxyEnable    REG_DWORD    0x1\r\n\
                    \x20   ProxyServer    REG_SZ    http=a.corp:80;https=b.corp:81\r\n\
                    \x20   ProxyOverride    REG_SZ    <local>;*.corp.nl;10.*\r\n\
                    \x20   AutoDetect    REG_DWORD    0x0\r\n\
                    \x20   MigrateProxy    REG_DWORD    0x1\r\n";
        assert_eq!(
            parse_reg_query(text),
            Snapshot {
                enable: Some(true),
                server: Some("http=a.corp:80;https=b.corp:81".into()),
                bypass: Some("<local>;*.corp.nl;10.*".into()),
            }
        );
    }

    #[test]
    fn missing_values_stay_none() {
        let text = "\r\nHKEY_CURRENT_USER\\x\r\n    ProxyEnable    REG_DWORD    0x0\r\n\
                    \x20   ProxyOverride    REG_SZ    \r\n";
        assert_eq!(
            parse_reg_query(text),
            Snapshot {
                enable: Some(false),
                server: None,
                bypass: None,
            }
        );
        assert_eq!(parse_reg_query(""), Snapshot::default());
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
