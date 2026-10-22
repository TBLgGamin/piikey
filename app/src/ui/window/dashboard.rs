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
    inventory::{Entry, Node, Tiles, TypeTotal},
    sys::is_under,
};
use windows_reactor::ComponentContext;

use super::{MainWindow, Msg, Page};
use crate::ui::{
    controller::{Controller, Store},
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
    /// Run the detection over the file, or over the files of the folder that hold personal data,
    /// and show every value it finds in the findings view.
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
    /// For the top of the store (an empty `at`) that is its drives.
    pub levels: HashMap<PathBuf, Vec<Node>>,
    /// What the store found in each of its locations, whatever folder is on show: one node for
    /// each that holds something. Only the Inventory's rows say that; the Watch page's have no use
    /// for it, so a load for the watch leaves it empty.
    pub places: Vec<Node>,
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
    /// The keys of the tree's rows as they were last drawn, and the revision of the tree's list:
    /// see [`Dashboard::tree_revision`].
    tree_keys: RefCell<Vec<String>>,
    tree_revision: Cell<u64>,
}

impl Dashboard {
    /// A dashboard that shows everything and has nothing selected.
    pub fn new() -> Self {
        Self {
            at: PathBuf::new(),
            selected: None,
            open: HashSet::new(),
            kind: None,
            loaded: None,
            seq: 0,
            shown: 0,
            tree_keys: RefCell::new(Vec::new()),
            tree_revision: Cell::new(0),
        }
    }

    /// Tells the dashboard the tree is about to be drawn with rows keyed `keys`, and returns the
    /// revision of its rows: a new one whenever rows came, went or the folder on show changed, so
    /// the list takes the new keys; the same while only what the rows say changed.
    pub(in crate::ui) fn tree_revision(&self, keys: &[String]) -> u64 {
        let mut last = self.tree_keys.borrow_mut();
        if last.as_slice() != keys {
            self.tree_revision.set(self.tree_revision.get() + 1);
            *last = keys.to_vec();
        }
        self.tree_revision.get()
    }

    /// Whether `path` is a folder, as far as the last load knows: the folder on show, or a folder
    /// of the tree. Anything else is taken for a file.
    pub(in crate::ui) fn is_folder(&self, path: &Path) -> bool {
        path == self.at
            || self.loaded.as_ref().is_some_and(|loaded| {
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
            .filter(|path| !self.is_folder(path))
    }

    /// Selects `path`; `false` when it was selected already, which a row the user clicked says
    /// again once the tree has moved the selection there.
    fn select(&mut self, path: PathBuf, origin: Origin) -> bool {
        if self.selected.as_deref() == Some(path.as_path()) {
            return false;
        }
        if origin == Origin::Map {
            let way = ancestors(&path, &self.at);
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
    }

    /// Shows the folder `at` with `select` chosen in it and the way to it open.
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

/// The folders that have to be open for the row of `path` to show, from the outermost in: the ones
/// between `at` and `path`. At the top level the rows start at the drives, so the way to a file
/// starts with its drive.
fn ancestors(path: &Path, at: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = path
        .ancestors()
        .skip(1)
        .take_while(|folder| is_under(folder, at) && !folder.as_os_str().is_empty())
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
            places: if store == Store::Inventory {
                controller.places(store)
            } else {
                Vec::new()
            },
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
            Dash::Found(path) => self.open_findings(vec![path], store, context),
            Dash::Report => {
                let under = self.dash(store).at.clone();
                self.background(context, move |controller| {
                    explorer::show(&controller.export_report(&under)?)?;
                    Ok(Msg::Noop)
                });
            }
        }
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

    fn loaded(levels: &[(&str, &[Node])]) -> Loaded {
        Loaded {
            at: PathBuf::new(),
            levels: levels
                .iter()
                .map(|(at, nodes)| (PathBuf::from(at), nodes.to_vec()))
                .collect(),
            places: Vec::new(),
            tiles: Tiles {
                tiles: Vec::new(),
                rest: piikey::inventory::Rest::default(),
            },
            totals: Vec::new(),
            entry: None,
        }
    }

    /// A dashboard whose store holds one drive, with `Docs` in it and a file in that.
    fn dashboard() -> Dashboard {
        let mut dash = Dashboard::new();
        dash.loaded = Some(loaded(&[
            ("", &[node(r"C:\", true)]),
            (r"C:\", &[node(r"C:\Docs", true)]),
            (r"C:\Docs", &[node(r"C:\Docs\a.pdf", false)]),
        ]));
        dash
    }

    #[test]
    fn the_tree_revision_moves_only_when_its_rows_do() {
        let keys = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        let dash = Dashboard::new();
        let first = dash.tree_revision(&keys(&["a", "b"]));
        assert_eq!(dash.tree_revision(&keys(&["a", "b"])), first);
        let opened = dash.tree_revision(&keys(&["a", "a1", "b"]));
        assert_ne!(opened, first);
        assert_eq!(dash.tree_revision(&keys(&["a", "a1", "b"])), opened);
        assert_ne!(dash.tree_revision(&keys(&["a", "b"])), opened);
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
        assert!(
            dash.open.contains(Path::new(r"C:\")),
            "the way starts at the drive"
        );
        assert!(dash.open.contains(Path::new(r"C:\Docs")));
        assert!(dash.open.contains(Path::new(r"C:\Docs\Taxes")));

        let mut dash = dashboard();
        assert!(dash.select(PathBuf::from(r"C:\Docs\Taxes\2023.pdf"), Origin::Tree));
        assert!(
            dash.open.is_empty(),
            "a row is where the user already looks"
        );
    }

    #[test]
    fn a_row_picked_again_changes_nothing() {
        let mut dash = dashboard();
        let file = PathBuf::from(r"C:\Docs\a.pdf");
        assert!(dash.select(file.clone(), Origin::Map));
        assert!(!dash.select(file, Origin::Tree));
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
        // A folder is shown without a choice.
        dash.reveal(PathBuf::from(r"C:\Docs"), None);
        assert!(dash.selected.is_none());
    }

    #[test]
    fn a_load_is_taken_unless_it_is_old_or_was_read_for_another_folder() {
        let mut dash = Dashboard::new();
        let read = |at: &str| Loaded {
            at: PathBuf::from(at),
            ..loaded(&[])
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
        assert!(dash.is_folder(Path::new(r"C:\")), "a drive is a folder");
        assert!(dash.is_folder(Path::new(r"C:\Docs")));
        assert!(!dash.is_folder(Path::new(r"C:\Docs\a.pdf")));
        // What is not known is taken for a file: the map only has files.
        assert!(!dash.is_folder(Path::new(r"C:\Else\b.pdf")));
    }

    #[test]
    fn the_folders_to_open_for_a_file_are_the_ones_between_it_and_the_top() {
        let way = |path: &str, at: &str| ancestors(Path::new(path), Path::new(at));
        let paths = |list: &[&str]| list.iter().map(PathBuf::from).collect::<Vec<_>>();
        // At the top the tree starts at the drives: the way to a file starts at its drive.
        assert_eq!(
            way(r"C:\Docs\Taxes\2023.pdf", ""),
            paths(&[r"C:\", r"C:\Docs", r"C:\Docs\Taxes"])
        );
        assert_eq!(
            way(r"C:\Docs\Taxes\2023.pdf", r"C:\Docs"),
            paths(&[r"C:\Docs\Taxes"])
        );
        // The folder on show is the top of the tree, not a row.
        assert_eq!(way(r"C:\Docs\a.pdf", r"C:\"), paths(&[r"C:\Docs"]));
        assert!(way(r"C:\Docs\a.pdf", r"C:\Docs").is_empty());
        assert!(way(r"C:\a.pdf", r"C:\").is_empty());
        // A file on another drive is not in the folder on show.
        assert!(way(r"D:\Other\a.pdf", r"C:\").is_empty());
        // A network share is a drive.
        assert_eq!(
            way(r"\\nas\share\docs\a.pdf", ""),
            paths(&[r"\\nas\share\", r"\\nas\share\docs"])
        );
    }
}
