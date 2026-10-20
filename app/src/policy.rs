//! What the app intercepts, persisted at `%LOCALAPPDATA%\piikey\guard.cfg`.
//!
//! One `key=value` per line:
//!
//! ```text
//! enabled=true
//! site=chat.openai.com
//! site=*.anthropic.com
//! program=chrome.exe
//! disabled_kind=email
//! ```
//!
//! `disabled_kind=<kind>` lines (the `EntityKind::as_str` name) list the kinds
//! that are NOT masked; no line means every kind is masked, which is also what
//! an old file means. An unknown kind name is skipped like any unknown key.
//!
//! Blank lines and `#` comments are ignored, unknown keys are skipped, and
//! every value is normalized on load, so a hand-edited file cannot make the
//! matcher misbehave.
//!
//! This module also holds the few OS helpers the other app modules share:
//! the data folder, atomic file writes and running System32 tools.

use std::{
    fs::{self, File},
    io::Write,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use piikey::detect::{EntityKind, KindSet};

use crate::Res;

/// Site presets offered in the UI.
pub const PRESETS: &[&str] = &[
    "chatgpt.com",
    "*.openai.com",
    "claude.ai",
    "*.anthropic.com",
    "gemini.google.com",
    "copilot.microsoft.com",
    "chat.deepseek.com",
    "chat.mistral.ai",
    "*.perplexity.ai",
];

// The file name is kept for existing installs: renaming it would drop the saved settings.
const FILE_NAME: &str = "guard.cfg";

/// Persisted at `%LOCALAPPDATA%\piikey\guard.cfg`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub enabled: bool,
    /// Host patterns: `example.com` or `*.example.com`.
    pub sites: Vec<String>,
    /// Lowercase exe names, e.g. `chrome.exe`.
    pub programs: Vec<String>,
    /// Kinds piikey leaves alone in new text; empty means every kind is masked.
    pub disabled_kinds: Vec<EntityKind>,
}

impl Policy {
    /// Loads the saved policy; missing file -> default.
    ///
    /// # Errors
    /// Unreadable file.
    pub fn load() -> Res<Self> {
        Self::load_from(&data_dir()?.join(FILE_NAME))
    }

    /// Saves atomically.
    ///
    /// # Errors
    /// Write failure.
    pub fn save(&self) -> Res<()> {
        write_atomic(&data_dir()?.join(FILE_NAME), self.to_text().as_bytes())
    }

    /// Normalizes a user-typed site; `None` when invalid.
    ///
    /// Accepts a bare host (`Chat.OpenAI.com`), a wildcard (`*.openai.com`,
    /// any subdomain but not the apex) or a pasted URL, of which only the
    /// host is kept. IPv4 literals are valid hosts; IPv6 and non-ASCII names
    /// are not.
    #[must_use]
    pub fn parse_site(s: &str) -> Option<String> {
        let lower = s.trim().to_ascii_lowercase();
        let rest = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"))
            .unwrap_or(&lower);
        let authority = rest.split(['/', '?', '#']).next()?;
        let host_port = authority.rsplit('@').next()?;
        let host = match host_port.split_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                host
            }
            Some(_) => return None,
            None => host_port,
        };
        let host = host.trim_end_matches('.');
        match host.strip_prefix("*.") {
            Some(suffix) => valid_host(suffix).then(|| format!("*.{suffix}")),
            None => valid_host(host).then(|| host.to_owned()),
        }
    }

    /// Normalizes a user-typed program: lowercase, `.exe` appended when the
    /// name has no extension; `None` for paths, blanks and control characters.
    #[must_use]
    pub fn parse_program(s: &str) -> Option<String> {
        let name = s.trim().to_ascii_lowercase();
        let ok = !name.is_empty()
            && name.len() <= 255
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| !c.is_control() && !c.is_whitespace() && !"\\/:*?\"<>|=".contains(c));
        if !ok {
            return None;
        }
        Some(if name.contains('.') {
            name
        } else {
            format!("{name}.exe")
        })
    }

    /// Whether traffic to `host` from program `exe` is intercepted: the app
    /// is on and the host matches a site or the program is selected.
    #[must_use]
    pub fn intercepts(&self, host: &str, exe: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        let host = normalize_host(host);
        self.sites
            .iter()
            .any(|pattern| site_matches(pattern, &host))
            || exe.is_some_and(|exe| self.programs.iter().any(|p| p.eq_ignore_ascii_case(exe)))
    }

    fn load_from(path: &Path) -> Res<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    fn parse(text: &str) -> Self {
        let mut policy = Self::default();
        for line in text.strip_prefix('\u{feff}').unwrap_or(text).lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "enabled" => policy.enabled = value.eq_ignore_ascii_case("true"),
                "site" => push_unique(&mut policy.sites, Self::parse_site(value)),
                "program" => push_unique(&mut policy.programs, Self::parse_program(value)),
                "disabled_kind" => {
                    if let Some(kind) = EntityKind::parse(value)
                        && !policy.disabled_kinds.contains(&kind)
                    {
                        policy.disabled_kinds.push(kind);
                    }
                }
                _ => {}
            }
        }
        policy
    }

    /// The file contents; entries that would not survive a reload (invalid
    /// sites and programs) are left out.
    fn to_text(&self) -> String {
        let mut out = format!("enabled={}\n", self.enabled);
        let sites = self.sites.iter().filter_map(|s| Self::parse_site(s));
        let programs = self.programs.iter().filter_map(|p| Self::parse_program(p));
        for (key, values) in [
            ("site", sites.collect::<Vec<_>>()),
            ("program", programs.collect()),
            (
                "disabled_kind",
                EntityKind::ALL
                    .into_iter()
                    .filter(|kind| self.disabled_kinds.contains(kind))
                    .map(|kind| kind.as_str().to_owned())
                    .collect(),
            ),
        ] {
            for value in values {
                out.push_str(key);
                out.push('=');
                out.push_str(&value);
                out.push('\n');
            }
        }
        out
    }

    /// The kinds piikey masks in new text: every kind except the disabled ones.
    #[must_use]
    pub fn enabled_kinds(&self) -> KindSet {
        self.disabled_kinds
            .iter()
            .fold(KindSet::ALL, |set, &kind| set.without(kind))
    }
}

fn push_unique(list: &mut Vec<String>, value: Option<String>) {
    if let Some(value) = value
        && !list.contains(&value)
    {
        list.push(value);
    }
}

/// DNS-style host: 1-253 bytes of dot-separated labels of 1-63 letters,
/// digits and inner hyphens.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// `*.suffix` matches any subdomain of `suffix` (not `suffix` itself); any
/// other pattern matches exactly. Both sides are lowercase.
fn site_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|front| front.len() > 1 && front.ends_with('.')),
        None => pattern == host,
    }
}

/// Lowercase host without port, IPv6 brackets or trailing dot.
#[must_use]
pub(crate) fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        // `a.b:443` has one colon; a bare IPv6 address has several.
        None if host.matches(':').count() == 1 => host.split(':').next().unwrap_or(host),
        None => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// `%LOCALAPPDATA%\piikey` (created): config, CA and system-proxy state live
/// next to the vault.
///
/// # Errors
/// `%LOCALAPPDATA%` unset or the directory cannot be created.
pub(crate) fn data_dir() -> Res<PathBuf> {
    let vault = piikey::vault::default_path()
        .map_err(|e| format!("cannot locate the piikey data folder: {e}"))?;
    vault
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot locate the piikey data folder".to_owned())
}

/// Writes `bytes` to a temp file beside `path`, syncs it and renames it over
/// `path`, so readers see the old or the new file, never a torn one.
///
/// # Errors
/// I/O failure; the temp file is removed.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Res<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let written = File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot write {}: {e}", path.display())
    })
}

/// `CREATE_NO_WINDOW`: console tools run from the GUI must not flash a window.
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A command for `tool` (e.g. `curl.exe`) from `%SystemRoot%\System32` with
/// no console window and stdin closed; the caller adds arguments and pipes.
///
/// # Errors
/// The tool is not in System32.
pub(crate) fn system_command(tool: &str) -> Res<Command> {
    let root = std::env::var_os("SystemRoot")
        .filter(|root| !root.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let path = root.join("System32").join(tool);
    if !path.is_file() {
        return Err(format!("{tool} was not found in System32"));
    }
    let mut command = Command::new(path);
    command
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

/// Runs `tool` (e.g. `certutil.exe`) from `%SystemRoot%\System32` with no
/// console window and waits for it. A non-zero exit is not an error here;
/// callers read the status.
///
/// # Errors
/// The tool cannot be started.
pub(crate) fn run_system_tool(tool: &str, args: &[&str]) -> Res<Output> {
    system_command(tool)?
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {tool}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            enabled: true,
            sites: vec!["chatgpt.com".into(), "*.anthropic.com".into()],
            programs: vec!["chrome.exe".into()],
            disabled_kinds: vec![EntityKind::Email, EntityKind::Person],
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piikey-policy-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn text_round_trips() {
        let p = policy();
        assert_eq!(Policy::parse(&p.to_text()), p);
        assert_eq!(
            p.to_text(),
            "enabled=true\nsite=chatgpt.com\nsite=*.anthropic.com\nprogram=chrome.exe\n\
             disabled_kind=email\ndisabled_kind=person\n"
        );
    }

    #[test]
    fn disabled_empty_policy_round_trips() {
        let p = Policy::default();
        assert_eq!(Policy::parse(&p.to_text()), p);
    }

    #[test]
    fn save_and_load_round_trip_through_a_file() -> Res<()> {
        let path = temp_dir("file").join(FILE_NAME);
        assert_eq!(Policy::load_from(&path)?, Policy::default(), "missing file");
        write_atomic(&path, policy().to_text().as_bytes())?;
        assert_eq!(Policy::load_from(&path)?, policy());
        // Overwriting replaces the file and leaves no temp file behind.
        write_atomic(&path, Policy::default().to_text().as_bytes())?;
        assert_eq!(Policy::load_from(&path)?, Policy::default());
        let leftovers = fs::read_dir(path.parent().unwrap_or(Path::new(".")))
            .map_err(|e| e.to_string())?
            .count();
        assert_eq!(leftovers, 1);
        Ok(())
    }

    #[test]
    fn parse_is_forgiving() {
        let text = "\u{feff}# comment\n\nENABLED=true\nenabled = TRUE \nsite = Chat.OpenAI.com \n\
                    site=chat.openai.com\nsite=not a host\nprogram=Chrome\nprogram=chrome.exe\n\
                    disabled_kind = email \nunknown=1\nno equals sign\n";
        let p = Policy::parse(text);
        assert!(p.enabled);
        assert_eq!(p.sites, ["chat.openai.com"]);
        assert_eq!(p.programs, ["chrome.exe"]);
        assert_eq!(p.disabled_kinds, [EntityKind::Email]);
    }

    #[test]
    fn enabled_needs_the_word_true() {
        assert!(!Policy::parse("enabled=yes\n").enabled);
        assert!(!Policy::parse("").enabled);
        assert!(Policy::parse("enabled=true\n").enabled);
    }

    #[test]
    fn to_text_drops_entries_that_would_not_reload() {
        let p = Policy {
            enabled: false,
            sites: vec!["ok.com".into(), "bad host".into()],
            programs: vec!["a\\b.exe".into()],
            disabled_kinds: vec![EntityKind::Person, EntityKind::Email, EntityKind::Person],
        };
        assert_eq!(
            p.to_text(),
            "enabled=false\nsite=ok.com\ndisabled_kind=email\ndisabled_kind=person\n"
        );
    }

    #[test]
    fn disabled_kinds_parse_without_duplicates_or_unknown_kinds() {
        let p = Policy::parse(
            "disabled_kind=email\ndisabled_kind=bogus\ndisabled_kind=email\ndisabled_kind=\n",
        );
        assert_eq!(p.disabled_kinds, [EntityKind::Email]);
    }

    #[test]
    fn enabled_kinds_exclude_exactly_the_disabled_ones() {
        assert_eq!(Policy::default().enabled_kinds(), KindSet::ALL);
        let p = Policy {
            disabled_kinds: vec![EntityKind::Email, EntityKind::Person],
            ..Policy::default()
        };
        let enabled = p.enabled_kinds();
        for kind in EntityKind::ALL {
            let disabled = matches!(kind, EntityKind::Email | EntityKind::Person);
            assert_eq!(enabled.contains(kind), !disabled, "{kind:?}");
        }
    }

    #[test]
    fn disabled_kinds_are_written_in_kind_order() {
        let p = Policy {
            disabled_kinds: vec![EntityKind::Phone, EntityKind::Secret, EntityKind::Iban],
            ..Policy::default()
        };
        assert_eq!(
            p.to_text(),
            "enabled=false\ndisabled_kind=secret\ndisabled_kind=iban\ndisabled_kind=phone\n"
        );
        assert_eq!(
            Policy::parse(&p.to_text()).disabled_kinds,
            [EntityKind::Secret, EntityKind::Iban, EntityKind::Phone]
        );
    }

    #[test]
    fn an_old_file_with_name_lines_still_loads() {
        let p = Policy::parse("enabled=true\nsite=claude.ai\nname=Jeroen de Vries\n");
        assert!(p.enabled);
        assert_eq!(p.sites, ["claude.ai"]);
        assert!(p.disabled_kinds.is_empty());
        assert_eq!(p.enabled_kinds(), KindSet::ALL);
    }

    #[test]
    fn parse_site_normalizes_and_validates() {
        let ok = |s: &str| Policy::parse_site(s);
        assert_eq!(ok("Chat.OpenAI.com").as_deref(), Some("chat.openai.com"));
        assert_eq!(ok("  claude.ai  ").as_deref(), Some("claude.ai"));
        assert_eq!(ok("*.Anthropic.com").as_deref(), Some("*.anthropic.com"));
        assert_eq!(
            ok("https://chatgpt.com/c/123?x=1").as_deref(),
            Some("chatgpt.com")
        );
        assert_eq!(ok("http://user@host.nl:8080/").as_deref(), Some("host.nl"));
        assert_eq!(ok("example.com.").as_deref(), Some("example.com"));
        assert_eq!(ok("127.0.0.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(ok("localhost").as_deref(), Some("localhost"));
        for bad in [
            "",
            "   ",
            "*",
            "*.",
            "a b.com",
            "-a.com",
            "a-.com",
            "a..com",
            ".com",
            "exa$mple.com",
            "bücher.de",
            "[::1]",
            "host:port",
            "a.com:",
            "**.a.com",
        ] {
            assert_eq!(ok(bad), None, "{bad:?} must be rejected");
        }
        assert_eq!(
            ok(&format!("{}.com", "a".repeat(64))),
            None,
            "label too long"
        );
    }

    #[test]
    fn parse_program_normalizes_and_validates() {
        let ok = |s: &str| Policy::parse_program(s);
        assert_eq!(ok("Chrome.EXE").as_deref(), Some("chrome.exe"));
        assert_eq!(ok(" chrome ").as_deref(), Some("chrome.exe"));
        assert_eq!(ok("my.tool.exe").as_deref(), Some("my.tool.exe"));
        for bad in [
            "",
            " ",
            "C:\\a\\b.exe",
            "a/b.exe",
            "a b.exe",
            ".exe",
            "a=b.exe",
        ] {
            assert_eq!(ok(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn intercepts_exact_site() {
        let p = policy();
        assert!(p.intercepts("chatgpt.com", None));
        assert!(p.intercepts("ChatGPT.com", None), "case-insensitive");
        assert!(p.intercepts("chatgpt.com:443", None), "port ignored");
        assert!(p.intercepts("chatgpt.com.", None), "trailing dot ignored");
        assert!(
            !p.intercepts("www.chatgpt.com", None),
            "exact does not cover subdomains"
        );
        assert!(!p.intercepts("chatgpt.com.evil.net", None));
        assert!(!p.intercepts("notchatgpt.com", None));
    }

    #[test]
    fn intercepts_wildcard_site() {
        let p = policy();
        assert!(p.intercepts("api.anthropic.com", None));
        assert!(p.intercepts("a.b.anthropic.com", None));
        assert!(
            !p.intercepts("anthropic.com", None),
            "apex is not a subdomain"
        );
        assert!(
            !p.intercepts("evilanthropic.com", None),
            "needs a dot boundary"
        );
        assert!(!p.intercepts("anthropic.com.evil.net", None));
    }

    #[test]
    fn intercepts_selected_program_on_any_host() {
        let p = policy();
        assert!(p.intercepts("example.org", Some("chrome.exe")));
        assert!(p.intercepts("example.org", Some("Chrome.EXE")));
        assert!(!p.intercepts("example.org", Some("firefox.exe")));
        assert!(!p.intercepts("example.org", None));
    }

    #[test]
    fn disabled_policy_intercepts_nothing() {
        let p = Policy {
            enabled: false,
            ..policy()
        };
        assert!(!p.intercepts("chatgpt.com", None));
        assert!(!p.intercepts("example.org", Some("chrome.exe")));
    }

    #[test]
    fn normalize_host_strips_port_brackets_and_case() {
        assert_eq!(normalize_host("Example.COM:8443"), "example.com");
        assert_eq!(normalize_host("[::1]:443"), "::1");
        assert_eq!(normalize_host("::1"), "::1");
        assert_eq!(normalize_host("a.b."), "a.b");
        assert_eq!(normalize_host(" host "), "host");
    }

    #[test]
    fn presets_are_valid_sites() {
        for preset in PRESETS {
            assert_eq!(Policy::parse_site(preset).as_deref(), Some(*preset));
        }
    }
}
