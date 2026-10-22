//! Watch: folders piikey keeps an eye on. While it is on, a change to a file in one of them (the
//! file system tells) is picked up a moment later and the file is scanned again; a file that did
//! not change is not read. What it finds lives in a store of its own, apart from the inventory, and
//! is shown by the same dashboard as the inventory.

use piikey::policy::default_inventory_roots;
use windows_reactor::{Button, StackPanel, View};

use super::{
    dashboard::{self, dashboard, room},
    kit::{
        Context, caption, card, counted, feature_switch, form_error, page_header, thousands, when,
        wide_column,
    },
    lists::{add_row, place_row, places_card},
};
use crate::ui::{
    controller::{FolderStatus, Store, WatchedFolder},
    status::Tone,
    window::{MainWindow, Msg, Page},
};

/// What the page is, in a sentence.
const DEFINITION: &str = "Keeps an eye on folders and checks a file again when it changes.";

/// What the dashboard has to leave room for on this page besides the folders: the header, the box
/// that adds a folder, the line under it, and the gaps between them.
const CHROME: f64 = 150.0;

/// What a folder is doing: watched, being scanned (`scanning` is how far the watch has got), or
/// why it is not, and when a change was last seen.
pub(super) fn folder_status(folder: &WatchedFolder, scanning: Option<(u64, u64)>) -> String {
    match &folder.status {
        FolderStatus::Off => "Not watched: Watch is off".to_owned(),
        FolderStatus::Unavailable(why) => format!("Not available: {why}"),
        FolderStatus::Watching => {
            let state = match scanning {
                Some((done, total)) if total > 0 => {
                    format!("Scanning {} of {}", thousands(done), thousands(total))
                }
                Some(_) => "Scanning\u{2026}".to_owned(),
                None => "Watching".to_owned(),
            };
            match folder.last_change {
                Some(at) => format!("{state} \u{b7} last change {}", when(at)),
                None => state,
            }
        }
    }
}

/// The colour of what a folder is doing.
const fn tone(status: &FolderStatus) -> Tone {
    match status {
        FolderStatus::Watching => Tone::Good,
        FolderStatus::Unavailable(_) => Tone::Caution,
        FolderStatus::Off => Tone::Neutral,
    }
}

/// The folders, in a card that scrolls past a few rows, or what to do when there are none; with the
/// room the card takes.
fn folders(window: &MainWindow, context: Context<'_>) -> (View, f64) {
    let watch = &window.snap.watch;
    if watch.folders.is_empty() {
        let usual = Button::new()
            .content(format!("Watch {}", usual_names(&default_inventory_roots())))
            .on_click(context.message(Msg::WatchUsual));
        return (
            card(StackPanel::new().spacing(10.0).children((
                caption("No folders yet. Add one below, or start with the usual ones."),
                usual,
            )))
            .into(),
            90.0,
        );
    }
    places_card(
        watch
            .folders
            .iter()
            .map(|folder| {
                place_row(
                    &folder.path,
                    &folder_status(folder, watch.scanning),
                    tone(&folder.status),
                    window.dark,
                    Msg::RemoveWatch(folder.path.clone()),
                    context,
                )
            })
            .collect(),
    )
}

/// `Documents, Desktop and Downloads`: the folders' names.
fn usual_names(paths: &[std::path::PathBuf]) -> String {
    let names: Vec<String> = paths
        .iter()
        .filter_map(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    match names.as_slice() {
        [] => "the usual folders".to_owned(),
        [only] => only.clone(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// What stands under the box that adds a folder: how far the watch is, or what it holds.
fn status_line(window: &MainWindow) -> View {
    let watch = &window.snap.watch;
    if let Some((done, total)) = watch.scanning {
        return caption(if total > 0 {
            format!(
                "Looking at {} of {} files\u{2026}",
                thousands(done),
                thousands(total)
            )
        } else {
            "Looking for files\u{2026}".to_owned()
        })
        .into();
    }
    let (files, hits) = watch.totals;
    caption(if hits > 0 {
        format!(
            "{} found in {}",
            thousands(hits),
            counted(files, "file", "files")
        )
    } else if window.snap.policy.watch {
        "Nothing found yet.".to_owned()
    } else {
        "Watch is off.".to_owned()
    })
    .into()
}

/// What the dashboard says when nothing was found.
fn nothing(window: &MainWindow, top: bool) -> View {
    if !top {
        return dashboard::empty_card("No personal data found in this folder.").into();
    }
    let policy = &window.snap.policy;
    dashboard::empty_card(if policy.watch_folders.is_empty() {
        "Add a folder above to start watching it."
    } else if !policy.watch {
        "Watch is off. Turn it on to look through the folders above and keep an eye on their files."
    } else {
        "No personal data found in the watched folders yet. Files are looked at again when they change."
    })
    .into()
}

pub(super) fn watch(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let (list, listed) = folders(window, context);
    let mut children: Vec<View> = vec![page_header(
        Page::Watch.title(),
        DEFINITION,
        [feature_switch("Watch", policy.watch, Msg::Watch, context).into()],
    )];
    children.extend(form_error(window, context));
    children.push(list);
    children.push(add_row(
        "A folder to watch, e.g. C:\\Users\\you\\Downloads",
        &window.watch_draft,
        "Add folder",
        Msg::WatchDraft,
        Msg::AddWatch,
        context,
    ));
    children.push(status_line(window));
    children.push(dashboard(
        window,
        Store::Watch,
        room(window, CHROME + listed),
        |top| nothing(window, top),
        context,
    ));
    wide_column(children)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn folder(status: FolderStatus, last_change: Option<u64>) -> WatchedFolder {
        WatchedFolder {
            path: PathBuf::from(r"C:\Users\me\Downloads"),
            status,
            last_change,
        }
    }

    #[test]
    fn a_watched_folder_says_watching_scanning_and_when_it_last_changed() {
        let watching = folder(FolderStatus::Watching, None);
        assert_eq!(folder_status(&watching, None), "Watching");
        assert_eq!(
            folder_status(&watching, Some((12, 40))),
            "Scanning 12 of 40"
        );
        assert_eq!(folder_status(&watching, Some((0, 0))), "Scanning\u{2026}");
        let changed = folder(FolderStatus::Watching, Some(1_700_000_000));
        let text = folder_status(&changed, None);
        assert!(text.starts_with("Watching \u{b7} last change "), "{text}");
    }

    #[test]
    fn a_folder_that_is_not_watched_says_why() {
        assert_eq!(
            folder_status(&folder(FolderStatus::Off, None), None),
            "Not watched: Watch is off"
        );
        assert_eq!(
            folder_status(
                &folder(
                    FolderStatus::Unavailable("the drive is gone".to_owned()),
                    None
                ),
                None
            ),
            "Not available: the drive is gone"
        );
    }

    #[test]
    fn the_usual_folders_are_named_in_a_list() {
        let paths: Vec<PathBuf> = [r"C:\u\Documents", r"C:\u\Desktop", r"C:\u\Downloads"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(usual_names(&paths), "Documents, Desktop and Downloads");
        assert_eq!(usual_names(&paths[..1]), "Documents");
        assert_eq!(usual_names(&[]), "the usual folders");
    }
}
