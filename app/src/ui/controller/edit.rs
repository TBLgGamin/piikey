//! The edits of the settings, one control of the Settings page at a time, applied to a [`Policy`].
//! The window applies them to its own copy too, so the page answers at once.

use std::path::{Path, PathBuf};

use piikey::{
    detect::EntityKind,
    policy::{Highlight, Policy},
};

use crate::Res;

/// A change to the settings, one control of the Settings page at a time: the site and program
/// lists, the kinds that are masked and the features.
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
    /// Whether the inventory scans the watched folders in the background. Switching it on with
    /// no folder chosen watches the usual ones.
    Inventory(bool),
    /// A folder the inventory watches; `on` adds it. A path that is no folder is refused.
    InventoryRoot {
        path: PathBuf,
        on: bool,
    },
    /// A folder or file the inventory leaves out, with everything below it; `on` adds it. What
    /// the inventory knows about it is forgotten.
    InventoryExclude {
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
        Edit::Inventory(on) => {
            let mut changed = set(&mut policy.inventory, *on);
            if *on && policy.inventory_roots.is_empty() {
                // From now on the usual folders are a choice, kept while the inventory is off.
                let usual = policy.inventory_roots_or_default();
                changed |= !usual.is_empty();
                policy.inventory_roots = usual;
            }
            Ok(changed)
        }
        Edit::InventoryRoot { path, on } => {
            folder_edit(&mut policy.inventory_roots, path, *on, true)
        }
        Edit::InventoryExclude { path, on } => {
            folder_edit(&mut policy.inventory_exclude, path, *on, false)
        }
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

/// Adds `path` to a list of folders, or takes it off; whether the list changed. With `existing`
/// an added path must be a folder that exists.
fn folder_edit(list: &mut Vec<PathBuf>, path: &Path, on: bool, existing: bool) -> Res<bool> {
    if !on {
        return Ok(remove(list, path));
    }
    if existing && !path.is_dir() {
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
