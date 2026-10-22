//! The state of the two dashboards, Inventory and Watch, and what their controls do. Both show
//! one store of the controller the same way, so they share one set of messages ([`Dash`]) and one
//! state ([`Dashboard`]) of their own each.
//!
//! What a dashboard shows comes from the controller's views, which wait on the inventory and run in
//! the background: a load brings the tree levels the user has open, the map's tiles, the types for
//! the legend and the entry of the selected file in one message ([`Loaded`]). What the user chose
//! (folder, selection, open folders, type) lives in [`Dashboard`] and survives a load.

use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use piikey::{
    detect::EntityKind,
    inventory::{Entry, Finding, Node, Tiles, TypeTotal},
    sys::is_under,
};
use windows_reactor::ComponentContext;

use super::{FindingsState, MainWindow, Msg, Page};
use crate::ui::{
    controller::{Command, Controller, Store},
    explorer,
};

/// Files the map gives a tile of their own; the others are one tile together.
pub const TILES: usize = 400;

/// Where a selection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A row of the tree: it is where the user looks, so the tree stays as it is.
    Tree,
    /// A tile of the map: the tree opens the way to it and lists that way first.
    Map,
}

/// What a dashboard's controls ask of the window. The message that carries it says which
/// dashboard.
#[derive(Clone)]
pub enum Dash {
    /// Show this folder: the tree starts in it, the map and the legend cover it. Empty is
    /// everything.
    Enter(PathBuf),
    /// Select a folder or a file.
    Select(PathBuf, Origin),
    /// Open the folder in the tree, or close it.
    Toggle(PathBuf),
    /// Show only this type in the map and the tree, or with `None` every type.
    Type(Option<EntityKind>),
    /// What a load brought; the number says which load it answers, so a slow old one cannot
    /// replace a newer one.
    Loaded(u64, Box<Loaded>),
    /// Open the file in the app Windows chooses for it.
    Open(PathBuf),
    /// Show the file or folder in Explorer.
    Show(PathBuf),
    /// Write a masked copy of the file beside it and show it.
    Mask(PathBuf),
    /// Scan the file or folder again, into the main inventory, and show the result.
    Scan(PathBuf),
    /// Run the detection over the file and show what it finds.
    Found(PathBuf),
    /// Write a report of everything under the folder on show to Downloads and show it.
    Report,
}

/// What one load brought.
#[derive(Clone)]
pub struct Loaded {
    /// The folder on show when it was read: a load that comes back for another one is old.
    pub at: PathBuf,
    /// The nodes of each folder the tree lists: the one of the folder on show is the top level.
    pub levels: HashMap<PathBuf, Vec<Node>>,
    /// The top level of the store, whatever folder is on show: one node for each of its locations
    /// that holds something.
    pub top: Vec<Node>,
    /// The folders the store looks through, which the top level is grouped by.
    pub roots: Vec<PathBuf>,
    /// The map's files.
    pub tiles: Tiles,
    /// The types found under the folder on show, for the legend.
    pub totals: Vec<TypeTotal>,
    /// What the store knows of the selected file.
    pub entry: Option<Entry>,
}

/// What a dashboard shows and what the user chose in it.
pub struct Dashboard {
    /// The folder the map and the legend cover and the tree starts in; empty is everything.
    pub(in crate::ui) at: PathBuf,
    /// The folder or file the details describe.
    pub(in crate::ui) selected: Option<PathBuf>,
    /// The way to the selection is listed first in the tree: it was picked in the map.
    pub(in crate::ui) pinned: bool,
    /// The folders opened in the tree.
    pub(in crate::ui) open: HashSet<PathBuf>,
    /// The only type on show, or all.
    pub(in crate::ui) kind: Option<EntityKind>,
    /// What the last load brought; `None` until the first one.
    pub(in crate::ui) loaded: Option<Loaded>,
    /// The number of the latest load asked for.
    seq: u64,
    /// The number of the load that `loaded` came from: one that is older than that, or was made
    /// for another folder, is not shown.
    shown: u64,
    /// The keys of the tree's rows as they were last drawn, and the number of the list they were
    /// drawn in: see [`Dashboard::tree_list`].
    tree_keys: RefCell<Vec<String>>,
    tree_epoch: Cell<u64>,
}

impl Dashboard {
    /// A dashboard that shows everything and has nothing selected.
    pub fn new() -> Self {
        Self {
            at: PathBuf::new(),
            selected: None,
            pinned: false,
            open: HashSet::new(),
            kind: None,
            loaded: None,
            seq: 0,
            shown: 0,
            tree_keys: RefCell::new(Vec::new()),
            tree_epoch: Cell::new(0),
        }
    }

    /// Tells the dashboard the tree is about to be drawn with rows keyed `keys`, and returns the
    /// number of the list to draw it in. Rows that come or go keep the list; rows that change places
    /// make it a new one, because moving the rows of a list that has a selection makes `WinUI` fail
    /// fast (`0xC000027B`): the old list is dropped and the new one made, which also starts it at the
    /// top, where the way to the selection is listed first.
    pub(in crate::ui) fn tree_list(&self, keys: Vec<String>) -> u64 {
        let mut last = self.tree_keys.borrow_mut();
        if !keeps_order(&last, &keys) {
            self.tree_epoch.set(self.tree_epoch.get() + 1);
        }
        *last = keys;
        self.tree_epoch.get()
    }

    /// The folders the store looks through, as the last load knew them.
    fn roots(&self) -> &[PathBuf] {
        self.loaded.as_ref().map_or(&[], |loaded| &loaded.roots)
    }

    /// Whether `path` is a folder, as far as the last load knows: the folder on show, a folder of
    /// the tree, or a location. Anything else is taken for a file.
    pub(in crate::ui) fn is_folder(&self, path: &Path) -> bool {
        if path.as_os_str().is_empty() {
            return false;
        }
        if path == self.at || self.roots().iter().any(|root| root == path) {
            return true;
        }
        self.loaded.as_ref().is_some_and(|loaded| {
            loaded
                .levels
                .values()
                .flatten()
                .any(|node| node.is_dir && node.path == path)
        })
    }

    /// The selected file, if the selection is one.
    fn selected_file(&self) -> Option<&Path> {
        self.selected
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty() && !self.is_folder(path))
    }

    /// Selects `path`; `false` when it was selected already, which a row the user clicked says
    /// again once the tree has moved the selection there.
    fn select(&mut self, path: PathBuf, origin: Origin) -> bool {
        if self.selected.as_deref() == Some(path.as_path()) {
            return false;
        }
        self.pinned = origin == Origin::Map;
        if self.pinned {
            let way = ancestors(&path, &self.at, self.roots());
            self.open.extend(way);
        }
        self.selected = Some(path);
        true
    }

    /// Opens the folder, or closes it; `true` when it opened and its contents have to be loaded.
    fn toggle(&mut self, folder: PathBuf) -> bool {
        if self.open.remove(&folder) {
            return false;
        }
        self.open.insert(folder);
        true
    }

    /// Shows the folder `at`: what was open below it stays open.
    fn enter(&mut self, at: PathBuf) {
        self.open.retain(|folder| is_under(folder, &at));
        self.at = at;
        self.selected = None;
        self.pinned = false;
    }

    /// Shows the folder `at` with `select` chosen in it, the way to it open and listed first.
    pub(in crate::ui) fn reveal(&mut self, at: PathBuf, select: Option<PathBuf>) {
        self.enter(at);
        if let Some(file) = select {
            self.select(file, Origin::Map);
        }
    }

    /// Takes what load number `load` brought, unless it is older than what is shown or was read for
    /// a folder that is not on show any more; `true` when it was taken.
    fn take(&mut self, load: u64, loaded: Loaded) -> bool {
        if load <= self.shown || loaded.at != self.at {
            return false;
        }
        self.shown = load;
        self.loaded = Some(loaded);
        true
    }

    /// Shows only `kind`, or every type.
    fn show_type(&mut self, kind: Option<EntityKind>) {
        self.kind = kind;
    }
}

/// Whether the rows that are in both lists come in the same order in both: nothing has to move.
fn keeps_order(old: &[String], new: &[String]) -> bool {
    let in_new: HashSet<&str> = new.iter().map(String::as_str).collect();
    let in_old: HashSet<&str> = old.iter().map(String::as_str).collect();
    old.iter()
        .filter(|key| in_new.contains(key.as_str()))
        .eq(new.iter().filter(|key| in_old.contains(key.as_str())))
}

/// The folders that have to be open for the row of `path` to show, from the outermost in: the ones
/// between `at` and `path`. At the top level the rows start at the `roots`, the folders the store
/// looks through, so the folders above those are not rows.
fn ancestors(path: &Path, at: &Path, roots: &[PathBuf]) -> Vec<PathBuf> {
    let top = at.as_os_str().is_empty();
    let mut found: Vec<PathBuf> = path
        .ancestors()
        .skip(1)
        .take_while(|folder| is_under(folder, at) && !folder.as_os_str().is_empty())
        .filter(|folder| !top || roots.iter().any(|root| is_under(folder, root)))
        .map(Path::to_path_buf)
        .collect();
    // `at` itself is the top of the tree, not a row.
    found.retain(|folder| folder != at);
    found.reverse();
    found
}

impl Loaded {
    /// Reads what a dashboard shows from the controller: the level of `at`, the levels of the
    /// `open` folders below it, the map's files and the types, and the entry of `file`.
    pub(in crate::ui) fn read(
        controller: &Controller,
        store: Store,
        at: &Path,
        open: &[PathBuf],
        file: Option<&Path>,
    ) -> Self {
        let top = controller.inventory_view(store, at, file);
        let places = if at.as_os_str().is_empty() {
            top.nodes.clone()
        } else {
            controller.inventory_view(store, Path::new(""), None).nodes
        };
        let mut levels = HashMap::new();
        for folder in open
            .iter()
            .filter(|folder| is_under(folder, at) && *folder != at)
        {
            let level = controller.inventory_view(store, folder, None);
            levels.insert(folder.clone(), level.nodes);
        }
        levels.insert(at.to_path_buf(), top.nodes);
        Self {
            at: at.to_path_buf(),
            levels,
            top: places,
            roots: top.roots,
            tiles: controller.tiles(store, at, TILES),
            totals: controller.type_totals(store, at),
            entry: top.entry,
        }
    }
}

impl MainWindow {
    /// The dashboard of `store`.
    pub(in crate::ui) const fn dash(&self, store: Store) -> &Dashboard {
        match store {
            Store::Inventory => &self.inventory,
            Store::Watch => &self.watch,
        }
    }

    fn dash_mut(&mut self, store: Store) -> &mut Dashboard {
        match store {
            Store::Inventory => &mut self.inventory,
            Store::Watch => &mut self.watch,
        }
    }

    /// Loads what the dashboard of `store` shows, in the background.
    pub(super) fn load_dashboard(&mut self, store: Store, context: &ComponentContext<Self>) {
        let dash = self.dash_mut(store);
        dash.seq += 1;
        let load = dash.seq;
        let at = dash.at.clone();
        let open: Vec<PathBuf> = dash.open.iter().cloned().collect();
        let file = dash.selected_file().map(Path::to_path_buf);
        let controller = Arc::clone(&self.input.controller.0);
        context.spawn_background(move |_| {
            let loaded = Loaded::read(&controller, store, &at, &open, file.as_deref());
            Msg::Dash(store, Dash::Loaded(load, Box::new(loaded)))
        });
    }

    /// Runs what a control of the dashboard of `store` asks for.
    pub(super) fn update_dashboard(
        &mut self,
        store: Store,
        message: Dash,
        context: &ComponentContext<Self>,
    ) {
        match message {
            Dash::Enter(path) => {
                self.dash_mut(store).enter(path);
                self.load_dashboard(store, context);
            }
            Dash::Select(path, origin) => {
                if self.dash_mut(store).select(path, origin) {
                    self.load_dashboard(store, context);
                }
            }
            Dash::Toggle(folder) => {
                if self.dash_mut(store).toggle(folder) {
                    self.load_dashboard(store, context);
                }
            }
            Dash::Type(kind) => self.dash_mut(store).show_type(kind),
            Dash::Loaded(load, loaded) => {
                self.dash_mut(store).take(load, *loaded);
            }
            Dash::Open(path) => self.background(context, move |_| {
                explorer::open(&path)?;
                Ok(Msg::Noop)
            }),
            Dash::Show(path) => self.background(context, move |_| {
                explorer::show(&path)?;
                Ok(Msg::Noop)
            }),
            Dash::Mask(path) => self.background(context, move |controller| {
                explorer::show(&controller.masked_copy(&path)?)?;
                Ok(Msg::Noop)
            }),
            Dash::Scan(path) => self.input.controller.submit(Command::ScanFiles {
                paths: vec![path],
                reveal: true,
            }),
            Dash::Found(path) => self.show_findings(path, true, context),
            Dash::Report => {
                let under = self.dash(store).at.clone();
                self.background(context, move |controller| {
                    explorer::show(&controller.export_report(&under)?)?;
                    Ok(Msg::Noop)
                });
            }
        }
    }

    /// Reads what the detection finds in `path`, in the background, and keeps it for the dialog
    /// that lists it. `ask` says whether that dialog is the one of "Show what was found"; the
    /// findings of a scan that shows its result belong to that result's dialog instead.
    pub(super) fn show_findings(
        &mut self,
        path: PathBuf,
        ask: bool,
        context: &ComponentContext<Self>,
    ) {
        self.findings = Some((path.clone(), FindingsState::Loading));
        self.findings_open = ask;
        context.spawn_background({
            let controller = Arc::clone(&self.input.controller.0);
            move |_| {
                let found: Result<Vec<Finding>, String> = controller.findings(&path);
                Msg::FindingsLoaded(path, found)
            }
        });
    }

    /// Goes to Inventory, at `at`, with `select` chosen: where "Show in Inventory" leads.
    pub(super) fn show_in_inventory(
        &mut self,
        at: PathBuf,
        select: Option<PathBuf>,
        context: &ComponentContext<Self>,
    ) {
        self.inventory.reveal(at, select);
        self.navigate(Page::Inventory, context);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(path: &str, is_dir: bool) -> Node {
        Node {
            path: PathBuf::from(path),
            name: path.rsplit('\\').next().unwrap_or_default().to_owned(),
            is_dir,
            hits: 3,
            files: 1,
            counts: vec![(EntityKind::Email, 3)],
        }
    }

    fn loaded(roots: &[&str], nodes: &[Node]) -> Loaded {
        let mut levels = HashMap::new();
        levels.insert(PathBuf::new(), nodes.to_vec());
        Loaded {
            at: PathBuf::new(),
            levels,
            top: Vec::new(),
            roots: roots.iter().map(PathBuf::from).collect(),
            tiles: Tiles {
                tiles: Vec::new(),
                rest: piikey::inventory::Rest::default(),
            },
            totals: Vec::new(),
            entry: None,
        }
    }

    fn dashboard() -> Dashboard {
        let mut dash = Dashboard::new();
        dash.loaded = Some(loaded(
            &[r"C:\Docs"],
            &[node(r"C:\Docs", true), node(r"C:\Docs\a.pdf", false)],
        ));
        dash
    }

    #[test]
    fn rows_that_come_or_go_keep_the_list_and_rows_that_move_make_a_new_one() {
        let keys = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        let dash = Dashboard::new();
        let first = dash.tree_list(keys(&["a", "b", "c"]));
        // A folder opened: rows come in between.
        assert_eq!(dash.tree_list(keys(&["a", "a1", "a2", "b", "c"])), first);
        // A folder closed, and the same drawn again.
        assert_eq!(dash.tree_list(keys(&["a", "b", "c"])), first);
        assert_eq!(dash.tree_list(keys(&["a", "b", "c"])), first);
        // The way to a tile's file listed first: rows move.
        let moved = dash.tree_list(keys(&["c", "a", "b"]));
        assert_ne!(moved, first);
        assert_eq!(dash.tree_list(keys(&["c", "a", "b", "d"])), moved);
        // Rows that are all new need no move either, but a new order of the old ones does.
        assert_eq!(dash.tree_list(keys(&["x", "y"])), moved);
        assert_ne!(dash.tree_list(keys(&["y", "x"])), moved);
    }

    #[test]
    fn a_new_dashboard_shows_everything_and_has_chosen_nothing() {
        let dash = Dashboard::new();
        assert!(dash.at.as_os_str().is_empty());
        assert!(dash.selected.is_none() && dash.kind.is_none());
        assert!(dash.loaded.is_none() && dash.open.is_empty());
    }

    #[test]
    fn a_tile_opens_the_way_to_its_file_and_a_row_does_not() {
        let mut dash = dashboard();
        assert!(dash.select(PathBuf::from(r"C:\Docs\Taxes\2023.pdf"), Origin::Map));
        assert!(dash.pinned);
        assert!(dash.open.contains(Path::new(r"C:\Docs")));
        assert!(dash.open.contains(Path::new(r"C:\Docs\Taxes")));

        let mut dash = dashboard();
        assert!(dash.select(PathBuf::from(r"C:\Docs\Taxes\2023.pdf"), Origin::Tree));
        assert!(!dash.pinned);
        assert!(
            dash.open.is_empty(),
            "a row is where the user already looks"
        );
    }

    #[test]
    fn the_row_the_tree_reports_after_a_tile_was_picked_changes_nothing() {
        let mut dash = dashboard();
        let file = PathBuf::from(r"C:\Docs\a.pdf");
        assert!(dash.select(file.clone(), Origin::Map));
        assert!(
            !dash.select(file, Origin::Tree),
            "the echo of the selection must not unpin it"
        );
        assert!(dash.pinned);
    }

    #[test]
    fn a_folder_opens_and_closes_and_only_opening_needs_a_load() {
        let mut dash = dashboard();
        let folder = PathBuf::from(r"C:\Docs");
        assert!(dash.toggle(folder.clone()));
        assert!(dash.open.contains(&folder));
        assert!(!dash.toggle(folder.clone()));
        assert!(dash.open.is_empty());
    }

    #[test]
    fn entering_a_folder_keeps_what_is_open_below_it_and_forgets_the_selection() {
        let mut dash = dashboard();
        dash.open.insert(PathBuf::from(r"C:\Docs\Taxes"));
        dash.open.insert(PathBuf::from(r"C:\Mail"));
        dash.selected = Some(PathBuf::from(r"C:\Mail\jan.eml"));
        dash.enter(PathBuf::from(r"C:\Docs"));
        assert_eq!(dash.at, PathBuf::from(r"C:\Docs"));
        assert!(dash.selected.is_none());
        assert!(dash.open.contains(Path::new(r"C:\Docs\Taxes")));
        assert!(!dash.open.contains(Path::new(r"C:\Mail")));
    }

    #[test]
    fn revealing_a_file_shows_its_folder_with_the_file_chosen() {
        let mut dash = dashboard();
        dash.reveal(
            PathBuf::from(r"C:\Docs\Taxes"),
            Some(PathBuf::from(r"C:\Docs\Taxes\2023.pdf")),
        );
        assert_eq!(dash.at, PathBuf::from(r"C:\Docs\Taxes"));
        assert_eq!(
            dash.selected,
            Some(PathBuf::from(r"C:\Docs\Taxes\2023.pdf"))
        );
        assert!(dash.pinned);
        // A folder is shown without a choice.
        dash.reveal(PathBuf::from(r"C:\Docs"), None);
        assert!(dash.selected.is_none());
    }

    #[test]
    fn a_load_is_taken_unless_it_is_old_or_was_read_for_another_folder() {
        let mut dash = Dashboard::new();
        let read = |at: &str| Loaded {
            at: PathBuf::from(at),
            ..loaded(&[], &[])
        };
        assert!(dash.take(2, read("")));
        // An older load that comes back late.
        assert!(!dash.take(1, read("")));
        assert!(!dash.take(2, read("")));
        assert!(dash.take(3, read("")));
        // A load made before the folder on show changed.
        dash.enter(PathBuf::from(r"C:\Docs"));
        assert!(!dash.take(4, read("")));
        assert!(dash.take(5, read(r"C:\Docs")));
    }

    #[test]
    fn a_type_shows_only_that_type_and_none_shows_every_type() {
        let mut dash = Dashboard::new();
        dash.show_type(Some(EntityKind::Email));
        assert_eq!(dash.kind, Some(EntityKind::Email));
        dash.show_type(Some(EntityKind::Person));
        assert_eq!(dash.kind, Some(EntityKind::Person));
        // The same type said twice (a list that reports the row it already shows) stays.
        dash.show_type(Some(EntityKind::Person));
        assert_eq!(dash.kind, Some(EntityKind::Person));
        dash.show_type(None);
        assert_eq!(dash.kind, None);
    }

    #[test]
    fn folders_are_told_from_files_by_what_the_load_knows() {
        let dash = dashboard();
        assert!(dash.is_folder(Path::new(r"C:\Docs")));
        assert!(!dash.is_folder(Path::new(r"C:\Docs\a.pdf")));
        assert!(
            !dash.is_folder(Path::new("")),
            "the empty path is the top, not a folder"
        );
        // What is not known is taken for a file: the map only has files.
        assert!(!dash.is_folder(Path::new(r"C:\Else\b.pdf")));
    }

    #[test]
    fn the_folders_to_open_for_a_file_are_the_ones_between_it_and_the_top() {
        let roots = [PathBuf::from(r"C:\Docs")];
        assert_eq!(
            ancestors(Path::new(r"C:\Docs\Taxes\2023.pdf"), Path::new(""), &roots),
            [PathBuf::from(r"C:\Docs"), PathBuf::from(r"C:\Docs\Taxes")],
            "the folders above a location are not rows"
        );
        assert_eq!(
            ancestors(
                Path::new(r"C:\Docs\Taxes\2023.pdf"),
                Path::new(r"C:\Docs"),
                &roots
            ),
            [PathBuf::from(r"C:\Docs\Taxes")]
        );
        assert!(ancestors(Path::new(r"C:\Docs\a.pdf"), Path::new(r"C:\Docs"), &roots).is_empty());
        // A file outside every location is in no folder of the tree.
        assert!(ancestors(Path::new(r"D:\Other\a.pdf"), Path::new(""), &roots).is_empty());
    }
}
