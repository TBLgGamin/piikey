//! The edits of the settings, one control of the Settings page at a time, applied to a [`Policy`].
//! The window applies them to its own copy too, so the page answers at once.

use std::path::{Path, PathBuf};

use piikey::{
    detect::EntityKind,
    policy::{Highlight, Policy},
};

use crate::Res;

/// A change to the settings, one control of the Settings page at a time: the site and program
/// lists, the kinds that are masked, the folders and the features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    Site {
        site: String,
        on: bool,
    },
    Program {
        exe: String,
        on: bool,
    },
    /// Whether piikey masks `kind`.
    Kind {
        kind: EntityKind,
        on: bool,
    },
    /// When the field in focus is outlined if it holds personal data.
    Highlight(Highlight),
    /// Whether Explorer's right-click menu offers "Scan for personal data".
    ExplorerMenu(bool),
    /// Whether closing the window leaves piikey running in the tray. Without, closing the window
    /// quits piikey.
    Background(bool),
    /// A folder the inventory scans when asked (one of its locations); `on` adds it, `off`
    /// takes it off. A path that is no folder is refused. There is no location until the user
    /// adds one.
    InventoryRoot {
        path: PathBuf,
        on: bool,
    },
    /// Whether the watch keeps an eye on its folders.
    Watch(bool),
    /// A folder the watch keeps an eye on; `on` adds it, `off` takes it off. A path that is no
    /// folder is refused.
    WatchFolder {
        path: PathBuf,
        on: bool,
    },
    /// Whether the app serves the local HTTP API.
    HttpApi(bool),
}

/// Applies `edit` to `policy`; `Ok(false)` when nothing changed.
///
/// # Errors
/// The text the user typed is not a site, a program or a folder, or the folder does not exist.
pub fn apply_edit(policy: &mut Policy, edit: &Edit) -> Res<bool> {
    match edit {
        Edit::Site { site, on: true } => {
            let parsed = Policy::parse_site(site).ok_or_else(|| {
                format!(
                    "\"{}\" is not a site. Use a host such as example.com or *.example.com.",
                    site.trim()
                )
            })?;
            Ok(add(&mut policy.sites, parsed))
        }
        Edit::Site { site, on: false } => Ok(remove(&mut policy.sites, site.as_str())),
        Edit::Program { exe, on: true } => {
            let parsed = Policy::parse_program(exe).ok_or_else(|| {
                format!(
                    "\"{}\" is not an app name. Use a name such as chrome.exe.",
                    exe.trim()
                )
            })?;
            Ok(add(&mut policy.programs, parsed))
        }
        Edit::Program { exe, on: false } => Ok(remove(&mut policy.programs, exe.as_str())),
        Edit::Kind { kind, on: true } => Ok(remove(&mut policy.disabled_kinds, kind)),
        Edit::Kind { kind, on: false } => {
            let changed = add(&mut policy.disabled_kinds, *kind);
            if changed {
                policy.disabled_kinds.sort_unstable();
            }
            Ok(changed)
        }
        Edit::Highlight(mode) => Ok(set(&mut policy.highlight, *mode)),
        Edit::ExplorerMenu(on) => Ok(set(&mut policy.explorer_menu, *on)),
        Edit::Background(on) => Ok(set(&mut policy.background, *on)),
        Edit::InventoryRoot { path, on } => folder_edit(&mut policy.inventory_roots, path, *on),
        Edit::Watch(on) => Ok(set(&mut policy.watch, *on)),
        Edit::WatchFolder { path, on } => folder_edit(&mut policy.watch_folders, path, *on),
        Edit::HttpApi(on) => Ok(set(&mut policy.http_api, *on)),
    }
}

/// Adds `value` to `list` unless it is in it; whether the list changed.
fn add<T: PartialEq>(list: &mut Vec<T>, value: T) -> bool {
    if list.contains(&value) {
        return false;
    }
    list.push(value);
    true
}

/// Takes `value` off `list`; whether the list changed.
fn remove<T: PartialEq<U>, U: ?Sized>(list: &mut Vec<T>, value: &U) -> bool {
    let before = list.len();
    list.retain(|item| item != value);
    list.len() != before
}

/// Sets `slot` to `value`; whether that changed it.
fn set<T: PartialEq>(slot: &mut T, value: T) -> bool {
    if *slot == value {
        false
    } else {
        *slot = value;
        true
    }
}

/// Adds `path` to a list of folders, or takes it off; whether the list changed. An added path
/// must be a folder that exists.
fn folder_edit(list: &mut Vec<PathBuf>, path: &Path, on: bool) -> Res<bool> {
    if !on {
        let before = list.len();
        list.retain(|item| !same_folder(item, path));
        return Ok(list.len() != before);
    }
    if !path.is_dir() {
        return Err(format!("Not a folder: {}", path.display()));
    }
    let folder = Policy::parse_folder(&path.to_string_lossy()).ok_or_else(|| {
        format!(
            "\"{}\" is not a full path. Use a path such as C:\\Users\\you\\Documents.",
            path.display()
        )
    })?;
    if list.iter().any(|item| same_folder(item, &folder)) {
        return Ok(false);
    }
    list.push(folder);
    Ok(true)
}

/// The same folder spelled alike: component by component, ignoring ASCII case, as Windows paths
/// are, and a trailing separator.
fn same_folder(a: &Path, b: &Path) -> bool {
    let mut b = b.components();
    a.components().all(|part| {
        b.next()
            .is_some_and(|other| part.as_os_str().eq_ignore_ascii_case(other.as_os_str()))
    }) && b.next().is_none()
}
