//! The saved settings: what the app intercepts and which features are on, persisted at
//! `%LOCALAPPDATA%\piikey\guard.cfg`.
//!
//! One `key=value` per line:
//!
//! ```text
//! enabled=true
//! highlight=hotkey
//! explorer_menu=true
//! background=true
//! watch=false
//! http_api=false
//! http_port=7980
//! site=chat.openai.com
//! site=*.anthropic.com
//! program=chrome.exe
//! disabled_kind=email
//! inventory_root=C:\Users\jan\Documents
//! watch_folder=C:\Users\jan\Downloads
//! ```
//!
//! `disabled_kind=<kind>` lines (the `EntityKind::as_str` name) list the kinds
//! that are NOT masked; no line means every kind is masked, which is also what
//! an old file means. An unknown kind name is skipped like any unknown key.
//!
//! `highlight` is `off`, `always` or `hotkey`. `explorer_menu` and `background` are on unless
//! they say `false`; `watch`, `http_api` and `enabled` are off unless they say `true`.
//! `http_port` is a port from 1 to 65535. `program` is an exe name; a path stands for its file
//! name. `inventory_root` (the folders the inventory scans when asked) and `watch_folder` (the
//! folders the watch keeps an eye on) repeat, one absolute folder each. A file from an older
//! version lacks the newer keys and gets their defaults; the keys of features that are gone
//! (`inventory`, `inventory_exclude`) are skipped like any unknown key, and the next save leaves
//! them out.
//!
//! Blank lines and `#` comments are ignored, unknown keys are skipped, and
//! every value is normalized on load, so a hand-edited file cannot make the
//! matcher misbehave.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{
    Error, Result,
    detect::{EntityKind, KindSet},
    sys::{data_dir, io_context, same_path, write_atomic},
};

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

/// The keys of `guard.cfg`, in the order the file lists them. `settings set` takes all but
/// `enabled`: protection is switched on and off by itself.
pub const KEYS: [&str; 12] = [
    "enabled",
    "highlight",
    "explorer_menu",
    "background",
    "watch",
    "http_api",
    "http_port",
    "site",
    "program",
    "disabled_kind",
    "inventory_root",
    "watch_folder",
];

/// The port of the local HTTP API unless `http_port` says otherwise.
pub const DEFAULT_HTTP_PORT: u16 = 7980;

/// Whether `port` can be the HTTP API's: 1 to 65535 (a `u16` holds the upper bound).
#[must_use]
pub const fn valid_port(port: u16) -> bool {
    port != 0
}

/// When the field you type in is outlined because it holds personal data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Highlight {
    /// Never.
    Off,
    /// Whenever the field in focus holds personal data.
    Always,
    /// When the hotkey is pressed (Ctrl+Alt+P), for the field in focus.
    #[default]
    Hotkey,
}

impl Highlight {
    /// The `guard.cfg` value: `off`, `always` or `hotkey`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Always => "always",
            Self::Hotkey => "hotkey",
        }
    }

    /// Inverse of [`Self::as_str`], ignoring ASCII case.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Off, Self::Always, Self::Hotkey]
            .into_iter()
            .find(|mode| mode.as_str().eq_ignore_ascii_case(s))
    }
}

/// Persisted at `%LOCALAPPDATA%\piikey\guard.cfg`.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent feature switches of a settings file, not the states of one machine"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// A reply from another version lacks the keys it does not know: they get their defaults.
#[serde(default)]
pub struct Policy {
    /// Whether the proxy masks the sites and programs below.
    pub enabled: bool,
    /// Host patterns: `example.com` or `*.example.com`.
    pub sites: Vec<String>,
    /// Lowercase exe names, e.g. `chrome.exe`.
    pub programs: Vec<String>,
    /// Kinds piikey leaves alone in new text; empty means every kind is masked.
    #[serde(
        serialize_with = "serialize_kinds",
        deserialize_with = "deserialize_kinds"
    )]
    pub disabled_kinds: Vec<EntityKind>,
    /// When the field in focus is outlined if it holds personal data.
    pub highlight: Highlight,
    /// Whether Explorer's right-click menu offers "Scan for personal data".
    pub explorer_menu: bool,
    /// Whether closing the window leaves piikey running in the tray, with protection, the
    /// highlight, the watch and the API still working. Off: closing the window quits piikey.
    pub background: bool,
    /// Absolute folders the inventory scans when asked (its locations); empty means
    /// [`default_inventory_roots`].
    pub inventory_roots: Vec<PathBuf>,
    /// Whether the watch keeps an eye on [`Self::watch_folders`]: every change in them is
    /// scanned as it happens, into a store of its own.
    pub watch: bool,
    /// Absolute folders the watch keeps an eye on, below them too. Empty until the user picks
    /// some: nothing is watched by default.
    pub watch_folders: Vec<PathBuf>,
    /// Whether the app serves the local HTTP API on `127.0.0.1`.
    pub http_api: bool,
    /// The port of the local HTTP API, 1 to 65535.
    pub http_port: u16,
}

// Hand-written: a derived `Default` would switch the Explorer menu and the tray off and give the
// HTTP API port 0.
impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: false,
            sites: Vec::new(),
            programs: Vec::new(),
            disabled_kinds: Vec::new(),
            highlight: Highlight::default(),
            explorer_menu: true,
            background: true,
            inventory_roots: Vec::new(),
            watch: false,
            watch_folders: Vec::new(),
            http_api: false,
            http_port: DEFAULT_HTTP_PORT,
        }
    }
}

impl Policy {
    /// Loads the saved policy; missing file -> default.
    ///
    /// # Errors
    /// Unreadable file.
    pub fn load() -> Result<Self> {
        Self::load_from(&data_dir()?.join(FILE_NAME))
    }

    /// Saves atomically.
    ///
    /// # Errors
    /// Write failure.
    pub fn save(&self) -> Result<()> {
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

    /// Normalizes a user-typed program: the file name of a path (which may be quoted, as
    /// Explorer's "Copy as path" does), lowercase, `.exe` appended when the name has no
    /// extension; `None` for blanks, a folder and control characters.
    #[must_use]
    pub fn parse_program(s: &str) -> Option<String> {
        let name = s
            .trim()
            .trim_matches('"')
            .rsplit(['\\', '/'])
            .next()?
            .trim()
            .to_ascii_lowercase();
        let ok = !name.is_empty()
            && name.len() <= 255
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| !c.is_control() && !c.is_whitespace() && !":*?\"<>|=".contains(c));
        if !ok {
            return None;
        }
        Some(if name.contains('.') {
            name
        } else {
            format!("{name}.exe")
        })
    }

    /// Normalizes a user-typed folder for the inventory: surrounding spaces and the quotes
    /// Explorer's "Copy as path" adds are dropped; `None` for blanks, control characters and
    /// paths that are not absolute (a relative one would mean whatever folder the app was
    /// started in).
    #[must_use]
    pub fn parse_folder(s: &str) -> Option<PathBuf> {
        normalize_folder(s).map(PathBuf::from)
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

    fn load_from(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(io_context(&e, "read", path)),
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
                "highlight" => policy.highlight = Highlight::parse(value).unwrap_or_default(),
                "explorer_menu" => policy.explorer_menu = !value.eq_ignore_ascii_case("false"),
                "background" => policy.background = !value.eq_ignore_ascii_case("false"),
                "watch" => policy.watch = value.eq_ignore_ascii_case("true"),
                "http_api" => policy.http_api = value.eq_ignore_ascii_case("true"),
                "http_port" => {
                    policy.http_port = value
                        .parse()
                        .ok()
                        .filter(|&port| valid_port(port))
                        .unwrap_or(DEFAULT_HTTP_PORT);
                }
                "site" => push_unique(&mut policy.sites, Self::parse_site(value)),
                "program" => push_unique(&mut policy.programs, Self::parse_program(value)),
                "disabled_kind" => {
                    if let Some(kind) = EntityKind::parse(value)
                        && !policy.disabled_kinds.contains(&kind)
                    {
                        policy.disabled_kinds.push(kind);
                    }
                }
                "inventory_root" => {
                    push_unique_folder(&mut policy.inventory_roots, Self::parse_folder(value));
                }
                "watch_folder" => {
                    push_unique_folder(&mut policy.watch_folders, Self::parse_folder(value));
                }
                _ => {}
            }
        }
        policy
    }

    /// The file contents, one `key=value` per line in the order of [`KEYS`]; entries that would
    /// not survive a reload (invalid sites and programs, relative folders, folders that are not
    /// Unicode) are left out.
    fn to_text(&self) -> String {
        let sites = self.sites.iter().filter_map(|s| Self::parse_site(s));
        let programs = self.programs.iter().filter_map(|p| Self::parse_program(p));
        let folders = |list: &[PathBuf]| -> Vec<String> {
            list.iter()
                .filter_map(|path| path.to_str().and_then(normalize_folder))
                .map(str::to_owned)
                .collect()
        };
        let values: [Vec<String>; KEYS.len()] = [
            vec![self.enabled.to_string()],
            vec![self.highlight.as_str().to_owned()],
            vec![self.explorer_menu.to_string()],
            vec![self.background.to_string()],
            vec![self.watch.to_string()],
            vec![self.http_api.to_string()],
            vec![self.http_port.to_string()],
            sites.collect(),
            programs.collect(),
            EntityKind::ALL
                .into_iter()
                .filter(|kind| self.disabled_kinds.contains(kind))
                .map(|kind| kind.as_str().to_owned())
                .collect(),
            folders(&self.inventory_roots),
            folders(&self.watch_folders),
        ];
        let mut out = String::new();
        for (key, values) in KEYS.into_iter().zip(values) {
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

    /// The folders the inventory scans when asked: the saved ones, or
    /// [`default_inventory_roots`] when none were saved.
    #[must_use]
    pub fn inventory_roots_or_default(&self) -> Vec<PathBuf> {
        if self.inventory_roots.is_empty() {
            default_inventory_roots()
        } else {
            self.inventory_roots.clone()
        }
    }
}

/// A partial update of the [`Policy`], as the API's `settings_set` carries it: every field
/// that is present replaces the saved one, the others stay. Values are validated like typed
/// input, so a patch cannot leave the policy with something a reload would drop. A field that
/// is absent is not written, so a patch serialized and read back is the same patch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    /// Replaces [`Policy::sites`]; each entry goes through [`Policy::parse_site`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<String>>,
    /// Replaces [`Policy::programs`]; each entry goes through [`Policy::parse_program`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programs: Option<Vec<String>>,
    /// Replaces [`Policy::disabled_kinds`]; `EntityKind::as_str` names, empty clears the list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_kinds: Option<Vec<String>>,
    /// Replaces [`Policy::highlight`]: `off`, `always` or `hotkey`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight: Option<Highlight>,
    /// Replaces [`Policy::explorer_menu`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_menu: Option<bool>,
    /// Replaces [`Policy::background`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    /// Replaces [`Policy::inventory_roots`]; each entry goes through [`Policy::parse_folder`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_roots: Option<Vec<PathBuf>>,
    /// Replaces [`Policy::watch`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watch: Option<bool>,
    /// Replaces [`Policy::watch_folders`]; each entry goes through [`Policy::parse_folder`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watch_folders: Option<Vec<PathBuf>>,
    /// Replaces [`Policy::http_api`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_api: Option<bool>,
    /// Replaces [`Policy::http_port`]; 1 to 65535.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_port: Option<u16>,
}

impl SettingsPatch {
    /// Applies every present field to `policy`. Nothing is changed when any value is invalid.
    ///
    /// # Errors
    /// [`crate::Error::BadRequest`] naming the first invalid site, program, kind, folder or
    /// port.
    pub fn apply(&self, policy: &mut Policy) -> Result<()> {
        let mut next = policy.clone();
        if let Some(sites) = &self.sites {
            next.sites = checked(sites, "site", Policy::parse_site)?;
        }
        if let Some(programs) = &self.programs {
            next.programs = checked(programs, "program", Policy::parse_program)?;
        }
        if let Some(names) = &self.disabled_kinds {
            let mut kinds: Vec<EntityKind> = checked(names, "kind", EntityKind::parse)?;
            kinds.sort_by_key(|kind| *kind as u8);
            next.disabled_kinds = kinds;
        }
        if let Some(value) = self.highlight {
            next.highlight = value;
        }
        if let Some(value) = self.explorer_menu {
            next.explorer_menu = value;
        }
        if let Some(value) = self.background {
            next.background = value;
        }
        if let Some(folders) = &self.inventory_roots {
            next.inventory_roots = checked_folders(folders, "inventory folder")?;
        }
        if let Some(value) = self.watch {
            next.watch = value;
        }
        if let Some(folders) = &self.watch_folders {
            next.watch_folders = checked_folders(folders, "watch folder")?;
        }
        if let Some(value) = self.http_api {
            next.http_api = value;
        }
        if let Some(port) = self.http_port {
            if !valid_port(port) {
                return Err(Error::BadRequest(
                    "Not a valid port: 0 (use 1 to 65535)".to_owned(),
                ));
            }
            next.http_port = port;
        }
        *policy = next;
        Ok(())
    }
}

/// `values` normalized by `parse`, without duplicates.
fn checked<T: PartialEq>(
    values: &[String],
    what: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let parsed = parse(value)
            .ok_or_else(|| Error::BadRequest(format!("Not a valid {what}: {value}")))?;
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
    Ok(out)
}

fn checked_folders(folders: &[PathBuf], what: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::with_capacity(folders.len());
    for folder in folders {
        let parsed = folder
            .to_str()
            .and_then(Policy::parse_folder)
            .ok_or_else(|| {
                Error::BadRequest(format!(
                    "Not a valid {what}: {} (an absolute path is required)",
                    folder.display()
                ))
            })?;
        push_unique_folder(&mut out, Some(parsed));
    }
    Ok(out)
}

/// Serializes the kinds as their `EntityKind::as_str` names.
fn serialize_kinds<S: Serializer>(
    kinds: &[EntityKind],
    out: S,
) -> std::result::Result<S::Ok, S::Error> {
    out.collect_seq(kinds.iter().map(|kind| kind.as_str()))
}

/// Reads the kinds back from their `EntityKind::as_str` names; an unknown name is an error.
fn deserialize_kinds<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<EntityKind>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|name| {
            EntityKind::parse(name)
                .ok_or_else(|| D::Error::custom(format!("not a kind of personal data: {name}")))
        })
        .collect()
}

/// The folders the inventory scans when the user has picked none: the documents, the desktop
/// (both also where `OneDrive` keeps them) and the downloads that exist, without duplicates.
#[must_use]
pub fn default_inventory_roots() -> Vec<PathBuf> {
    default_roots_in(
        std::env::var_os("OneDrive").as_deref(),
        std::env::var_os("USERPROFILE").as_deref(),
    )
}

/// [`default_inventory_roots`] for the given `OneDrive` and user profile folders.
fn default_roots_in(onedrive: Option<&OsStr>, profile: Option<&OsStr>) -> Vec<PathBuf> {
    let candidates = [
        (onedrive, "Documents"),
        (onedrive, "Desktop"),
        (profile, "Documents"),
        (profile, "Desktop"),
        (profile, "Downloads"),
    ];
    let mut roots: Vec<PathBuf> = Vec::new();
    for (base, name) in candidates {
        let Some(base) = base.filter(|base| !base.is_empty()) else {
            continue;
        };
        let path = Path::new(base).join(name);
        if path.is_dir() && !roots.iter().any(|root| same_path(root, &path)) {
            roots.push(path);
        }
    }
    roots
}

fn push_unique(list: &mut Vec<String>, value: Option<String>) {
    if let Some(value) = value
        && !list.contains(&value)
    {
        list.push(value);
    }
}

fn push_unique_folder(list: &mut Vec<PathBuf>, value: Option<PathBuf>) {
    if let Some(value) = value
        && !list.iter().any(|folder| same_path(folder, &value))
    {
        list.push(value);
    }
}

/// `s` without surrounding spaces and quotes when it is an absolute path without control
/// characters.
fn normalize_folder(s: &str) -> Option<&str> {
    let s = s.trim().trim_matches('"').trim();
    (Path::new(s).is_absolute() && !s.chars().any(char::is_control)).then_some(s)
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
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        // `a.b:443` has one colon; a bare IPv6 address has several.
        None if host.matches(':').count() == 1 => host.split(':').next().unwrap_or(host),
        None => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    use super::*;

    /// The new switches at their defaults, as `to_text` writes them after `enabled`.
    const DEFAULT_SWITCHES: &str = "highlight=hotkey\nexplorer_menu=true\nbackground=true\nwatch=false\n\
                                    http_api=false\nhttp_port=7980\n";

    fn policy() -> Policy {
        Policy {
            enabled: true,
            sites: vec!["chatgpt.com".into(), "*.anthropic.com".into()],
            programs: vec!["chrome.exe".into()],
            disabled_kinds: vec![EntityKind::Email, EntityKind::Person],
            highlight: Highlight::Always,
            explorer_menu: false,
            background: false,
            inventory_roots: vec![
                PathBuf::from(r"C:\Users\jan\Documents"),
                PathBuf::from(r"D:\Archive"),
            ],
            watch: true,
            watch_folders: vec![PathBuf::from(r"C:\Users\jan\Downloads")],
            http_api: true,
            http_port: 8123,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        crate::testing::temp_dir(tag)
    }

    fn patch(json: &str) -> SettingsPatch {
        let Ok(patch) = serde_json::from_str(json) else {
            panic!("test patch is not valid: {json}");
        };
        patch
    }

    #[test]
    fn a_valid_patch_replaces_only_the_fields_it_carries() {
        let mut p = policy();
        let before = p.clone();
        assert!(
            patch(
                r#"{"sites":["HTTPS://Chat.OpenAI.com/x","*.example.org","chat.openai.com"],
                "programs":["Firefox"],
                "disabled_kinds":["phone","email","phone"],
                "highlight":"always","explorer_menu":false,"background":true,"watch":false,
                "inventory_roots":["\"C:\\Users\\jan\\Documents\"","C:\\Users\\jan\\documents\\"],
                "watch_folders":["C:\\Users\\jan\\Pictures"],
                "http_api":true,"http_port":8123}"#,
            )
            .apply(&mut p)
            .is_ok()
        );
        assert_eq!(p.sites, ["chat.openai.com", "*.example.org"]);
        assert_eq!(p.programs, ["firefox.exe"]);
        assert_eq!(p.disabled_kinds, [EntityKind::Email, EntityKind::Phone]);
        assert_eq!(p.highlight, Highlight::Always);
        assert!(!p.explorer_menu && p.background && !p.watch && p.http_api);
        assert_eq!(
            p.inventory_roots,
            [PathBuf::from(r"C:\Users\jan\Documents")]
        );
        assert_eq!(p.watch_folders, [PathBuf::from(r"C:\Users\jan\Pictures")]);
        assert_eq!(p.http_port, 8123);
        assert_eq!(p.enabled, before.enabled);

        let mut q = before.clone();
        assert!(SettingsPatch::default().apply(&mut q).is_ok());
        assert_eq!(q, before);
    }

    #[test]
    fn an_invalid_value_is_rejected_and_changes_nothing() {
        for json in [
            r#"{"background":true,"sites":["chatgpt.com","not a host"]}"#,
            r#"{"background":true,"programs":["a|b.exe"]}"#,
            r#"{"background":true,"disabled_kinds":["nonsense"]}"#,
            r#"{"background":true,"inventory_roots":["relative\\folder"]}"#,
            r#"{"background":true,"watch_folders":[""]}"#,
            r#"{"background":true,"http_port":0}"#,
        ] {
            let mut p = policy();
            let before = p.clone();
            let Err(error) = patch(json).apply(&mut p) else {
                panic!("{json} must be rejected");
            };
            assert!(matches!(error, Error::BadRequest(_)), "{json}: {error:?}");
            assert_eq!(p, before, "{json}");
        }
        let Err(error) = patch(r#"{"sites":["not a host"]}"#).apply(&mut policy()) else {
            panic!("an invalid site must be rejected");
        };
        assert!(error.to_string().contains("not a host"));
    }

    #[test]
    fn unknown_fields_and_values_do_not_deserialize() {
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"enabled":true}"#).is_err());
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"highlight":"loud"}"#).is_err());
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"http_port":70000}"#).is_err());
        // The inventory's switch and its exclusions are gone: a patch that still names them is
        // refused, not silently half applied.
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"inventory":true}"#).is_err());
        assert!(serde_json::from_str::<SettingsPatch>(r#"{"inventory_exclude":[]}"#).is_err());
    }

    #[test]
    fn an_empty_kind_list_clears_the_disabled_kinds() {
        let mut p = policy();
        p.disabled_kinds = vec![EntityKind::Email];
        assert!(patch(r#"{"disabled_kinds":[]}"#).apply(&mut p).is_ok());
        assert!(p.disabled_kinds.is_empty());
        assert_eq!(p.enabled_kinds(), KindSet::ALL);
    }

    #[test]
    fn the_policy_serializes_with_its_field_names() {
        let p = Policy {
            sites: vec!["chatgpt.com".into()],
            disabled_kinds: vec![EntityKind::CreditCard, EntityKind::Email],
            inventory_roots: vec![PathBuf::from(r"C:\Docs")],
            watch_folders: vec![PathBuf::from(r"D:\Inbox")],
            ..Policy::default()
        };
        let Ok(json) = serde_json::to_value(&p) else {
            panic!("the policy must serialize");
        };
        assert_eq!(
            json,
            serde_json::json!({
                "enabled": false,
                "sites": ["chatgpt.com"],
                "programs": [],
                "disabled_kinds": ["credit_card", "email"],
                "highlight": "hotkey",
                "explorer_menu": true,
                "background": true,
                "inventory_roots": ["C:\\Docs"],
                "watch": false,
                "watch_folders": ["D:\\Inbox"],
                "http_api": false,
                "http_port": 7980,
            })
        );
    }

    #[test]
    fn text_round_trips() {
        let p = policy();
        assert_eq!(Policy::parse(&p.to_text()), p);
        assert_eq!(
            p.to_text(),
            "enabled=true\nhighlight=always\nexplorer_menu=false\nbackground=false\nwatch=true\n\
             http_api=true\nhttp_port=8123\nsite=chatgpt.com\nsite=*.anthropic.com\n\
             program=chrome.exe\ndisabled_kind=email\ndisabled_kind=person\n\
             inventory_root=C:\\Users\\jan\\Documents\ninventory_root=D:\\Archive\n\
             watch_folder=C:\\Users\\jan\\Downloads\n"
        );
    }

    #[test]
    fn disabled_empty_policy_round_trips() {
        let p = Policy::default();
        assert_eq!(Policy::parse(&p.to_text()), p);
        assert_eq!(p.to_text(), format!("enabled=false\n{DEFAULT_SWITCHES}"));
    }

    #[test]
    fn save_and_load_round_trip_through_a_file() -> Result<()> {
        let path = temp_dir("file").join(FILE_NAME);
        assert_eq!(Policy::load_from(&path)?, Policy::default(), "missing file");
        write_atomic(&path, policy().to_text().as_bytes())?;
        assert_eq!(Policy::load_from(&path)?, policy());
        // Overwriting replaces the file and leaves no temp file behind.
        write_atomic(&path, Policy::default().to_text().as_bytes())?;
        assert_eq!(Policy::load_from(&path)?, Policy::default());
        let leftovers = fs::read_dir(path.parent().unwrap_or(Path::new(".")))?.count();
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
            programs: vec!["a|b.exe".into()],
            disabled_kinds: vec![EntityKind::Person, EntityKind::Email, EntityKind::Person],
            ..Policy::default()
        };
        assert_eq!(
            p.to_text(),
            format!(
                "enabled=false\n{DEFAULT_SWITCHES}site=ok.com\ndisabled_kind=email\ndisabled_kind=person\n"
            )
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
            format!(
                "enabled=false\n{DEFAULT_SWITCHES}\
                 disabled_kind=secret\ndisabled_kind=iban\ndisabled_kind=phone\n"
            )
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
    fn an_old_file_without_the_feature_keys_gets_their_defaults() {
        let p = Policy::parse("enabled=true\nsite=claude.ai\ndisabled_kind=email\n");
        let expected = Policy {
            enabled: true,
            sites: vec!["claude.ai".into()],
            disabled_kinds: vec![EntityKind::Email],
            ..Policy::default()
        };
        assert_eq!(p, expected);
        assert_eq!(p.highlight, Highlight::Hotkey);
        assert!(p.explorer_menu);
        assert!(p.background, "closing the window keeps piikey in the tray");
        assert!(!p.watch && !p.http_api);
        assert_eq!(p.http_port, 7980);
        assert!(p.inventory_roots.is_empty() && p.watch_folders.is_empty());
    }

    #[test]
    fn the_keys_of_the_features_that_are_gone_load_and_are_dropped() {
        // A file of the version that had the inventory's switch, its exclusions and no watch.
        let old = "enabled=true\nhighlight=always\nexplorer_menu=false\ninventory=true\n\
                   http_api=true\nhttp_port=8123\nsite=claude.ai\n\
                   inventory_root=C:\\Users\\jan\\Documents\n\
                   inventory_exclude=C:\\Users\\jan\\Documents\\Private\n";
        let p = Policy::parse(old);
        assert!(p.enabled && p.http_api && !p.explorer_menu);
        assert_eq!(p.highlight, Highlight::Always);
        assert_eq!(p.http_port, 8123);
        assert_eq!(p.sites, ["claude.ai"]);
        assert_eq!(
            p.inventory_roots,
            [PathBuf::from(r"C:\Users\jan\Documents")]
        );
        assert!(p.background && !p.watch && p.watch_folders.is_empty());
        // The next save leaves them out.
        let saved = p.to_text();
        assert!(!saved.contains("inventory=") && !saved.contains("inventory_exclude"));
        assert_eq!(Policy::parse(&saved), p);

        // The same through the file, and through an API reply of that version.
        let path = temp_dir("old").join(FILE_NAME);
        assert!(write_atomic(&path, old.as_bytes()).is_ok());
        assert_eq!(Policy::load_from(&path).ok().as_ref(), Some(&p));
        let reply = r#"{"enabled":true,"inventory":true,"inventory_roots":["C:\\a"],"inventory_exclude":["C:\\a\\b"]}"#;
        let from_reply = serde_json::from_str::<Policy>(reply);
        assert_eq!(
            from_reply.ok().map(|policy| policy.inventory_roots),
            Some(vec![PathBuf::from(r"C:\a")])
        );
    }

    #[test]
    fn the_highlight_mode_reads_its_three_words() {
        let mode = |text: &str| Policy::parse(text).highlight;
        assert_eq!(mode("highlight=off\n"), Highlight::Off);
        assert_eq!(mode("highlight = ALWAYS \n"), Highlight::Always);
        assert_eq!(mode("highlight=hotkey\n"), Highlight::Hotkey);
        assert_eq!(mode("highlight=bogus\n"), Highlight::Hotkey, "the default");
        assert_eq!(mode("highlight=\n"), Highlight::Hotkey, "the default");
        for highlight in [Highlight::Off, Highlight::Always, Highlight::Hotkey] {
            assert_eq!(Highlight::parse(highlight.as_str()), Some(highlight));
        }
        assert_eq!(Highlight::parse("sometimes"), None);
        assert_eq!(Highlight::default(), Highlight::Hotkey);
    }

    #[test]
    fn the_switches_follow_their_own_defaults() {
        let read = |text: &str| Policy::parse(text);
        // On by default: only the word `false` turns them off.
        assert!(!read("explorer_menu=false\n").explorer_menu);
        assert!(!read("explorer_menu=FALSE\n").explorer_menu);
        assert!(read("explorer_menu=true\n").explorer_menu);
        assert!(read("explorer_menu=no\n").explorer_menu);
        assert!(read("explorer_menu=\n").explorer_menu);
        assert!(!read("background=false\n").background);
        assert!(!read("background = FALSE\n").background);
        assert!(read("background=true\n").background);
        assert!(read("background=0\n").background);
        assert!(read("background=\n").background);
        assert!(read("").background);
        // Off by default: only the word `true` turns them on.
        assert!(read("watch=true\n").watch);
        assert!(read("http_api=TRUE\n").http_api);
        assert!(!read("watch=yes\n").watch);
        assert!(!read("http_api=1\n").http_api);
    }

    #[test]
    fn the_http_port_falls_back_to_the_default_when_it_is_not_a_port() {
        let port = |value: &str| Policy::parse(&format!("http_port={value}\n")).http_port;
        assert_eq!(port("8080"), 8080);
        assert_eq!(port(" 65535 "), 65535);
        assert_eq!(port("1"), 1);
        for bad in ["0", "65536", "70000", "-1", "abc", "80 80", ""] {
            assert_eq!(port(bad), 7980, "{bad:?}");
        }
    }

    #[test]
    fn parse_reads_every_key() {
        for key in KEYS {
            let sample = match key {
                "enabled" | "watch" | "http_api" => "true",
                "highlight" => "off",
                "explorer_menu" | "background" => "false",
                "http_port" => "1",
                "site" => "a.com",
                "program" => "a.exe",
                "disabled_kind" => "email",
                "inventory_root" | "watch_folder" => r"C:\a",
                other => panic!("{other} needs a sample"),
            };
            assert_ne!(
                Policy::parse(&format!("{key}={sample}\n")),
                Policy::default(),
                "{key} is not read"
            );
        }
    }

    #[test]
    fn the_policy_deserializes_what_it_serializes() -> std::result::Result<(), serde_json::Error> {
        let saved = policy();
        let back: Policy = serde_json::from_value(serde_json::to_value(&saved)?)?;
        assert_eq!(back, saved);
        // A reply from another version: what it lacks is the default, what is new is ignored.
        let partial: Policy = serde_json::from_str(r#"{"enabled":true,"from_the_future":1}"#)?;
        assert_eq!(
            partial,
            Policy {
                enabled: true,
                ..Policy::default()
            }
        );
        assert!(serde_json::from_str::<Policy>(r#"{"disabled_kinds":["nonsense"]}"#).is_err());
        Ok(())
    }

    #[test]
    fn saved_folders_win_and_none_saved_means_the_usual_ones() {
        assert_eq!(
            Policy::default().inventory_roots_or_default(),
            default_inventory_roots()
        );
        assert_eq!(
            policy().inventory_roots_or_default(),
            policy().inventory_roots
        );
    }

    #[test]
    fn inventory_and_watch_folders_are_normalized_and_deduplicated() {
        let p = Policy::parse(
            "inventory_root=C:\\Users\\jan\\Documents\n\
             inventory_root=\"C:\\Users\\jan\\Desktop\"\n\
             inventory_root = c:\\users\\JAN\\documents\\ \n\
             inventory_root=Documents\n\
             inventory_root=\\Users\\jan\n\
             inventory_root=C:relative\n\
             inventory_root=\n\
             inventory_root=\"\"\n\
             inventory_root=C:\\a\u{1}b\n\
             watch_folder=D:\\Inbox\n\
             watch_folder = d:\\inbox\\\n\
             watch_folder=Inbox\n",
        );
        assert_eq!(
            p.inventory_roots,
            [
                PathBuf::from(r"C:\Users\jan\Documents"),
                PathBuf::from(r"C:\Users\jan\Desktop"),
            ]
        );
        assert_eq!(p.watch_folders, [PathBuf::from(r"D:\Inbox")]);
    }

    #[test]
    fn parse_folder_keeps_only_absolute_paths() {
        let ok = |s: &str| Policy::parse_folder(s);
        assert_eq!(
            ok(r#"  "C:\Users\jan\My Documents"  "#),
            Some(PathBuf::from(r"C:\Users\jan\My Documents"))
        );
        assert_eq!(
            ok(r"\\server\share\files"),
            Some(PathBuf::from(r"\\server\share\files"))
        );
        for bad in [
            "",
            "   ",
            "\"\"",
            "Documents",
            r"..\up",
            r"\rooted",
            "C:drive-relative",
        ] {
            assert_eq!(ok(bad), None, "{bad:?} must be rejected");
        }
        assert_eq!(ok("C:\\a\nb"), None, "control character");
    }

    #[test]
    fn to_text_drops_folders_that_would_not_reload() {
        let not_unicode = PathBuf::from(OsString::from_wide(
            &r"C:\".encode_utf16().chain([0xD800]).collect::<Vec<u16>>(),
        ));
        let p = Policy {
            inventory_roots: vec![
                PathBuf::from(r"C:\ok"),
                PathBuf::from("relative"),
                not_unicode,
            ],
            watch_folders: vec![PathBuf::from(r"C:\ok\watched")],
            ..Policy::default()
        };
        assert_eq!(
            p.to_text(),
            format!(
                "enabled=false\n{DEFAULT_SWITCHES}\
                 inventory_root=C:\\ok\nwatch_folder=C:\\ok\\watched\n"
            )
        );
    }

    #[test]
    fn default_roots_are_the_existing_folders_without_duplicates() -> Result<()> {
        let dir = temp_dir("roots");
        let onedrive = dir.join("OneDrive");
        let profile = dir.join("profile");
        for folder in [
            onedrive.join("Documents"),
            onedrive.join("Desktop"),
            profile.join("Documents"),
            profile.join("Downloads"),
        ] {
            fs::create_dir_all(folder)?;
        }
        // A file is not a folder.
        fs::write(profile.join("Desktop"), b"")?;
        assert_eq!(
            default_roots_in(Some(onedrive.as_os_str()), Some(profile.as_os_str())),
            [
                onedrive.join("Documents"),
                onedrive.join("Desktop"),
                profile.join("Documents"),
                profile.join("Downloads"),
            ]
        );
        // The same folder under another spelling is listed once, in the spelling it was met in.
        let shouted = PathBuf::from(profile.to_string_lossy().to_uppercase());
        assert_eq!(
            default_roots_in(Some(shouted.as_os_str()), Some(profile.as_os_str())),
            [shouted.join("Documents"), profile.join("Downloads")]
        );
        assert!(default_roots_in(None, None).is_empty());
        assert!(default_roots_in(Some(OsStr::new("")), Some(OsStr::new(""))).is_empty());
        fs::remove_dir_all(&dir)?;
        Ok(())
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
            "a b.exe",
            ".exe",
            "a=b.exe",
            "a|b",
            "code - insiders",
            r"C:\folder\",
            "\"\"",
        ] {
            assert_eq!(ok(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn a_pasted_path_stands_for_its_file_name() {
        let ok = |s: &str| Policy::parse_program(s);
        assert_eq!(
            ok(r"C:\Windows\System32\Notepad.EXE").as_deref(),
            Some("notepad.exe")
        );
        assert_eq!(ok("C:/tools/mytool").as_deref(), Some("mytool.exe"));
        // Explorer's "Copy as path" quotes it.
        assert_eq!(
            ok(r#" "C:\Program Files\Google\Chrome\chrome.exe" "#).as_deref(),
            Some("chrome.exe")
        );
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
