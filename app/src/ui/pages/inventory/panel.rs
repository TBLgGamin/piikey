//! What the side panel of the treemap says and offers, and the way back up from the folder on
//! show. No widgets: the card in [`super`] draws a [`Panel`].

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use piikey::{
    detect::EntityKind,
    inventory::{Entry, MAX_FILE, Node, Status},
};
use windows_reactor::DateTime;

use super::map::MAX_TILES;
use crate::ui::{
    activity,
    controller::InventoryView,
    pages::kit::{counted, thousands},
    window::Selection,
};

/// Kinds the side panel lists.
const SIDE_KINDS: usize = 8;

/// `+12 more`: the name of the tile, and of the panel, for the nodes beyond the tiles.
pub(super) fn more_title(count: usize) -> String {
    format!(
        "+{} more",
        thousands(u64::try_from(count).unwrap_or(u64::MAX))
    )
}

/// One step of the way from the top level to the folder on show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Crumb {
    pub(super) label: String,
    /// The folder it leads to; empty is the top level.
    pub(super) target: PathBuf,
}

/// The buttons of the side panel, by what they act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Buttons {
    /// Nothing to act on.
    None,
    /// The top level: scan every watched folder again.
    All,
    /// A folder: show it, scan it again, leave it out.
    Folder,
    /// A file: open it, show it, scan it again, make a masked copy, leave it out.
    File,
}

/// What the side panel says and offers, apart from how it looks.
#[derive(Debug, PartialEq)]
pub(super) struct Panel<'a> {
    /// The name of the folder or file, or "+N more".
    pub(super) title: String,
    /// The full path, or where the numbers come from.
    pub(super) detail: String,
    /// "12 values in 3 files", or why a file has none.
    pub(super) summary: String,
    /// The kinds found most, at most [`SIDE_KINDS`], with how many of each.
    pub(super) kinds: Vec<(EntityKind, u32)>,
    /// When the file was scanned, in seconds since the Unix epoch.
    pub(super) scanned: Option<u64>,
    /// The file or folder the buttons act on.
    pub(super) target: Option<&'a Path>,
    pub(super) buttons: Buttons,
    /// The nodes of the "+N more" tile, listed in the panel.
    pub(super) rest: &'a [Node],
}

/// `12 values in 3 files`.
pub(super) fn found_text(hits: u64, files: u64) -> String {
    format!(
        "{} in {}",
        counted(hits, "value", "values"),
        counted(files, "file", "files")
    )
}

/// The values and the files of `nodes`, added up.
pub(super) fn totals(nodes: &[Node]) -> (u64, u64) {
    nodes.iter().fold((0, 0), |(hits, files), node| {
        (hits + node.hits, files + u64::from(node.files))
    })
}

/// The kinds found most, at most [`SIDE_KINDS`], with how many of each; the counts of one kind
/// are added up.
pub(super) fn top_kinds(
    counts: impl IntoIterator<Item = (EntityKind, u32)>,
) -> Vec<(EntityKind, u32)> {
    let mut per_kind: BTreeMap<EntityKind, u32> = BTreeMap::new();
    for (kind, n) in counts {
        let total = per_kind.entry(kind).or_default();
        *total = total.saturating_add(n);
    }
    let mut kinds: Vec<(EntityKind, u32)> = per_kind.into_iter().collect();
    // Stable: kinds with as many findings stay in the order of the kinds.
    kinds.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    kinds.truncate(SIDE_KINDS);
    kinds
}

/// The last component of `path`: the name of a folder or a file; a drive keeps its whole path.
fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Whether two path components are the same name. Windows paths are not case sensitive, and
/// neither is this, for letters beyond ASCII too (`Ünal` and `ÜNAL`).
fn same_name(a: &OsStr, b: &OsStr) -> bool {
    a.eq_ignore_ascii_case(b)
        || a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}

/// Whether `path` is `prefix` or lies below it, by [`same_name`] of every component.
fn is_under(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix.components().all(|want| {
        path.next()
            .is_some_and(|have| same_name(have.as_os_str(), want.as_os_str()))
    })
}

/// The crumbs from "This PC" to `at`. Everything up to the deepest of the watched `roots` that
/// holds `at` is one crumb, named after that folder. Without such a folder every component is a
/// crumb, except that the drive and its root (`C:` and `\`) are one: `C:\`.
pub(super) fn crumbs(at: &Path, roots: &[PathBuf]) -> Vec<Crumb> {
    let mut trail = vec![Crumb {
        label: "This PC".to_owned(),
        target: PathBuf::new(),
    }];
    let deepest = roots
        .iter()
        .filter(|root| is_under(at, root))
        .max_by_key(|root| root.components().count());
    let (mut path, skip) = if let Some(root) = deepest {
        (root.clone(), root.components().count())
    } else {
        let lead = at
            .components()
            .take_while(|part| matches!(part, Component::Prefix(_) | Component::RootDir));
        (lead.clone().collect::<PathBuf>(), lead.count())
    };
    if skip > 0 {
        trail.push(Crumb {
            label: name_of(&path),
            target: path.clone(),
        });
    }
    for part in at.components().skip(skip) {
        path.push(part.as_os_str());
        trail.push(Crumb {
            label: part.as_os_str().to_string_lossy().into_owned(),
            target: path.clone(),
        });
    }
    trail
}

/// What the scan of a file came to, as the side panel puts it.
fn entry_summary(entry: &Entry) -> String {
    match &entry.status {
        Status::Ok if entry.hits() == 0 => "No personal data found.".to_owned(),
        Status::Ok => found_text(entry.hits(), 1),
        Status::Unsupported => "piikey cannot read this type of file.".to_owned(),
        Status::TooLarge => format!(
            "Too large to scan: piikey skips files over {} MB.",
            MAX_FILE >> 20
        ),
        Status::Failed(error) => format!("Could not be scanned: {error}"),
    }
}

/// The panel for the folder `at` itself (the top level when it is empty), when nothing is
/// selected. `watching` is whether the inventory keeps the watched folders scanned.
fn folder_panel<'a>(view: &InventoryView, at: &'a Path, watching: bool) -> Panel<'a> {
    let top = at.as_os_str().is_empty();
    let (hits, files) = totals(&view.nodes);
    let buttons = match (top, watching) {
        (false, _) => Buttons::Folder,
        (true, true) => Buttons::All,
        (true, false) => Buttons::None,
    };
    Panel {
        title: if top {
            "This PC".to_owned()
        } else {
            name_of(at)
        },
        detail: if top {
            "Every folder piikey watches, and what you scanned from Explorer.".to_owned()
        } else {
            at.display().to_string()
        },
        summary: found_text(hits, files),
        kinds: top_kinds(
            view.nodes
                .iter()
                .flat_map(|node| node.counts.iter().copied()),
        ),
        scanned: None,
        target: (!top).then_some(at),
        buttons,
        rest: &[],
    }
}

/// The panel for the nodes beyond the tiles: their numbers, and the nodes as a list.
fn rest_panel(rest: &[Node]) -> Panel<'_> {
    let (hits, files) = totals(rest);
    Panel {
        title: more_title(rest.len()),
        detail: "The smaller ones, the biggest first. Pick one to look at it.".to_owned(),
        summary: found_text(hits, files),
        kinds: top_kinds(rest.iter().flat_map(|node| node.counts.iter().copied())),
        scanned: None,
        target: None,
        buttons: Buttons::None,
        rest,
    }
}

/// The panel for the file or folder `chosen`: a tile of the view, or a file the scan found
/// nothing in, which has no tile but may have an entry.
fn chosen_panel<'a>(view: &'a InventoryView, chosen: &'a Path) -> Panel<'a> {
    let entry = view.entry.as_ref().filter(|entry| entry.path == chosen);
    let Some(node) = view.nodes.iter().find(|node| node.path == chosen) else {
        return Panel {
            title: name_of(chosen),
            detail: chosen.display().to_string(),
            summary: entry.map_or_else(|| "No scan of this file yet.".to_owned(), entry_summary),
            kinds: entry.map_or_else(Vec::new, |entry| top_kinds(entry.counts.iter().copied())),
            scanned: entry.map(|entry| entry.scanned),
            target: Some(chosen),
            buttons: Buttons::File,
            rest: &[],
        };
    };
    // The "Other scans" node gathers files from everywhere: its path is empty, and there is
    // nothing to open, show or scan.
    let other = node.path.as_os_str().is_empty();
    let buttons = match (other, node.is_dir) {
        (true, _) => Buttons::None,
        (false, true) => Buttons::Folder,
        (false, false) => Buttons::File,
    };
    Panel {
        title: node.name.clone(),
        detail: if other {
            "Scans of files outside the folders piikey watches.".to_owned()
        } else {
            node.path.display().to_string()
        },
        summary: found_text(node.hits, u64::from(node.files)),
        kinds: top_kinds(node.counts.iter().copied()),
        scanned: entry.map(|entry| entry.scanned),
        target: (!other).then_some(node.path.as_path()),
        buttons,
        rest: &[],
    }
}

/// What the side panel describes: what is `selected` among the tiles of `view`, or the folder
/// `at` itself.
pub(super) fn panel<'a>(
    view: &'a InventoryView,
    at: &'a Path,
    selected: Option<&'a Selection>,
    watching: bool,
) -> Panel<'a> {
    match selected {
        Some(Selection::Node(chosen)) => chosen_panel(view, chosen),
        Some(Selection::More) => view
            .nodes
            .get(MAX_TILES..)
            .filter(|rest| !rest.is_empty())
            .map_or_else(|| folder_panel(view, at, watching), rest_panel),
        None => folder_panel(view, at, watching),
    }
}

/// "Last scanned 14:05": when a scan looked at the file, told the way the vault's list
/// tells times.
pub(super) fn scanned_text(scanned: u64) -> String {
    let secs = i64::try_from(scanned).unwrap_or(i64::MAX);
    let local = DateTime::from_unix_secs(secs).to_local().ticks();
    format!("Last scanned {}", activity::when(local, activity::now()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::pages::inventory::fixtures::{node, nodes};

    fn view_of(nodes: Vec<Node>) -> InventoryView {
        InventoryView {
            nodes,
            ..InventoryView::default()
        }
    }

    fn entry(path: &str, status: Status, counts: Vec<(EntityKind, u32)>) -> Entry {
        Entry {
            path: PathBuf::from(path),
            size: 10,
            modified: 0,
            scanned: 1_700_000_000,
            status,
            counts,
        }
    }

    fn roots(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn labels(trail: &[Crumb]) -> Vec<&str> {
        trail.iter().map(|crumb| crumb.label.as_str()).collect()
    }

    fn targets(trail: &[Crumb]) -> Vec<&Path> {
        trail.iter().map(|crumb| crumb.target.as_path()).collect()
    }

    #[test]
    fn the_side_panel_lists_the_eight_kinds_found_most() {
        let counts: Vec<(EntityKind, u32)> =
            EntityKind::ALL.into_iter().take(12).zip(1..).collect();
        let top = top_kinds(counts.iter().copied());
        assert_eq!(top.len(), SIDE_KINDS);
        assert!(top.windows(2).all(|pair| pair[0].1 >= pair[1].1));
        assert_eq!(top[0].1, 12);
        // The counts of one kind, from several nodes, are added up.
        let merged = top_kinds([
            (EntityKind::Email, 2),
            (EntityKind::Iban, 3),
            (EntityKind::Email, 4),
        ]);
        assert_eq!(merged, [(EntityKind::Email, 6), (EntityKind::Iban, 3)]);
    }

    #[test]
    fn the_way_up_starts_at_this_pc_and_folds_the_watched_folder_into_one_crumb() {
        let roots = roots(&[r"C:\Users\me\Documents"]);
        let top = crumbs(Path::new(""), &roots);
        assert_eq!(labels(&top), ["This PC"]);
        assert_eq!(targets(&top), [Path::new("")]);

        let deep = crumbs(Path::new(r"C:\Users\me\Documents\Taxes\2024"), &roots);
        assert_eq!(labels(&deep), ["This PC", "Documents", "Taxes", "2024"]);
        assert_eq!(
            targets(&deep),
            [
                Path::new(""),
                Path::new(r"C:\Users\me\Documents"),
                Path::new(r"C:\Users\me\Documents\Taxes"),
                Path::new(r"C:\Users\me\Documents\Taxes\2024"),
            ]
        );

        let at_root = crumbs(Path::new(r"C:\Users\me\Documents"), &roots);
        assert_eq!(labels(&at_root), ["This PC", "Documents"]);
    }

    #[test]
    fn the_deepest_watched_folder_names_the_first_crumb() {
        let roots = roots(&[r"C:\Users\me", r"C:\Users\me\Documents"]);
        let trail = crumbs(Path::new(r"C:\Users\me\Documents\Taxes"), &roots);
        assert_eq!(labels(&trail), ["This PC", "Documents", "Taxes"]);
        let trail = crumbs(Path::new(r"C:\Users\me\Pictures"), &roots);
        assert_eq!(labels(&trail), ["This PC", "me", "Pictures"]);
    }

    #[test]
    fn watched_folders_match_without_regard_to_case() {
        let roots = roots(&[r"C:\Users\Me\Documents"]);
        let trail = crumbs(Path::new(r"c:\users\me\documents\x"), &roots);
        assert_eq!(labels(&trail), ["This PC", "Documents", "x"]);
        assert_eq!(trail[1].target, Path::new(r"C:\Users\Me\Documents"));
    }

    #[test]
    fn watched_folders_match_without_regard_to_case_beyond_ascii() {
        let roots = roots(&[r"C:\Users\ÜNAL\Documents"]);
        let trail = crumbs(Path::new(r"c:\users\ünal\documents\x"), &roots);
        assert_eq!(labels(&trail), ["This PC", "Documents", "x"]);
        assert_eq!(trail[1].target, Path::new(r"C:\Users\ÜNAL\Documents"));
    }

    #[test]
    fn without_a_watched_folder_every_component_is_a_crumb_and_the_drive_is_one() {
        let trail = crumbs(
            Path::new(r"C:\Temp\pk"),
            &roots(&[r"C:\Users\me\Documents"]),
        );
        assert_eq!(labels(&trail), ["This PC", r"C:\", "Temp", "pk"]);
        assert_eq!(
            targets(&trail),
            [
                Path::new(""),
                Path::new(r"C:\"),
                Path::new(r"C:\Temp"),
                Path::new(r"C:\Temp\pk"),
            ]
        );
    }

    #[test]
    fn with_nothing_selected_the_panel_describes_the_folder_on_show() {
        let view = view_of(vec![
            node("a.txt", 10, EntityKind::Email),
            node("b.txt", 5, EntityKind::Iban),
        ]);
        let top = panel(&view, Path::new(""), None, true);
        assert_eq!(top.title, "This PC");
        assert_eq!(top.summary, "15 values in 2 files");
        assert_eq!(top.kinds, [(EntityKind::Email, 10), (EntityKind::Iban, 5)]);
        assert_eq!(top.target, None);
        assert_eq!(top.buttons, Buttons::All);
        assert_eq!(
            panel(&view, Path::new(""), None, false).buttons,
            Buttons::None
        );

        let folder = panel(&view, Path::new(r"C:\Data"), None, false);
        assert_eq!(folder.title, "Data");
        assert_eq!(folder.detail, r"C:\Data");
        assert_eq!(folder.target, Some(Path::new(r"C:\Data")));
        assert_eq!(folder.buttons, Buttons::Folder);
    }

    #[test]
    fn a_selected_file_gets_the_file_buttons_and_its_scan_time() {
        let mut view = view_of(vec![node("id.pdf", 4, EntityKind::Iban)]);
        view.entry = Some(entry(
            r"C:\Data\id.pdf",
            Status::Ok,
            vec![(EntityKind::Iban, 4)],
        ));
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\id.pdf"));
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.title, "id.pdf");
        assert_eq!(panel.summary, "4 values in 1 file");
        assert_eq!(panel.kinds, [(EntityKind::Iban, 4)]);
        assert_eq!(panel.scanned, Some(1_700_000_000));
        assert_eq!(panel.target, Some(Path::new(r"C:\Data\id.pdf")));
        assert_eq!(panel.buttons, Buttons::File);
    }

    #[test]
    fn a_selected_folder_tile_gets_no_file_buttons() {
        let mut folder = node("Taxes", 9, EntityKind::Iban);
        folder.is_dir = true;
        folder.files = 3;
        let view = view_of(vec![folder]);
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\Taxes"));
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.summary, "9 values in 3 files");
        assert_eq!(panel.buttons, Buttons::Folder);
        assert_eq!(panel.scanned, None);
    }

    #[test]
    fn the_other_scans_node_shows_its_numbers_without_buttons() {
        let other = Node {
            path: PathBuf::new(),
            name: "Other scans".to_owned(),
            is_dir: true,
            hits: 7,
            files: 2,
            counts: vec![(EntityKind::Email, 7)],
        };
        let view = view_of(vec![other]);
        let chosen = Selection::Node(PathBuf::new());
        let panel = panel(&view, Path::new(""), Some(&chosen), true);
        assert_eq!(panel.title, "Other scans");
        assert_eq!(panel.summary, "7 values in 2 files");
        assert_eq!(panel.target, None);
        assert_eq!(panel.buttons, Buttons::None);
    }

    #[test]
    fn a_selected_file_without_findings_says_so() {
        let mut view = view_of(vec![node("other.txt", 2, EntityKind::Email)]);
        view.entry = Some(entry(r"C:\Data\clean.txt", Status::Ok, Vec::new()));
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\clean.txt"));
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.title, "clean.txt");
        assert_eq!(panel.summary, "No personal data found.");
        assert_eq!(panel.buttons, Buttons::File);
        assert_eq!(panel.target, Some(Path::new(r"C:\Data\clean.txt")));

        // The entry of another file is not this file's.
        view.entry = Some(entry(r"C:\Data\other.txt", Status::Ok, Vec::new()));
        let panel = super::panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.summary, "No scan of this file yet.");
    }

    #[test]
    fn a_file_that_could_not_be_scanned_says_why() {
        // The limit named is the one the scan applies.
        let too_large = entry(r"C:\Data\disk.img", Status::TooLarge, Vec::new());
        assert!(entry_summary(&too_large).contains(&format!("{} MB", MAX_FILE >> 20)));
        let failed = entry(
            r"C:\Data\a.docx",
            Status::Failed("bad zip".to_owned()),
            Vec::new(),
        );
        assert!(entry_summary(&failed).contains("bad zip"));
    }

    #[test]
    fn the_more_tile_selects_the_nodes_without_a_tile() {
        let more = Selection::More;
        let all = nodes(MAX_TILES + 2);
        let view = view_of(all.clone());
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&more), true);
        assert_eq!(panel.title, "+2 more");
        assert_eq!(panel.rest, &all[MAX_TILES..]);
        assert_eq!(panel.buttons, Buttons::None);
        assert_eq!(panel.target, None);

        // With no node beyond the tiles there is nothing for it to select.
        let view = view_of(nodes(MAX_TILES));
        let panel = super::panel(&view, Path::new(r"C:\Data"), Some(&more), true);
        assert_eq!(panel.title, "Data");
        assert!(panel.rest.is_empty());
    }
}
