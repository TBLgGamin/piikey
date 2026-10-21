//! The main window: navigation and state. The pages are drawn by [`pages`](super::pages).
//!
//! The window holds a copy of the controller's [`Snapshot`] and refreshes it from a background
//! poll; every user action becomes a message, then a [`Command`] for the controller. Edits to the
//! lists and the feature switches are applied to the copy at once so the controls follow the
//! click; the next snapshot is the truth and puts a rejected edit back. Work that waits on the
//! disk or the clipboard (exports, the API token, masked copies, the inventory view) runs in the
//! background, and its errors reach the user as the controller's notice.

use std::{
    ops::Deref,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use piikey::{detect::EntityKind, inventory::Node, policy::Highlight};
use windows_reactor::{
    Callback, Component, ComponentContext, ComponentTimer, Grid, GridLength, Icon, KeyedView,
    NavigationView, NavigationViewBackButtonVisible, NavigationViewItem,
    NavigationViewPaneDisplayMode, TitleBar, View, ViewContext, WindowBackdrop, WindowConstraints,
    WindowVisuals,
};

use super::{
    assets,
    controller::{
        Command, Controller, Edit, InventoryView, KeyedPage, KeyedQuery, Model, Notice, Period,
        Reveal, Snapshot, apply_edit,
    },
    explorer, pages,
};
use crate::Res;

/// How long one background poll waits for a change before it checks for cancellation.
const POLL: Duration = Duration::from_secs(2);

/// How often the list of running programs refreshes while the Masking tab of Settings is open.
const PROCESS_REFRESH: Duration = Duration::from_secs(5);

/// How long each joke line stays on the loading screen.
const FLAVOR_EVERY: Duration = Duration::from_secs(4);

/// Width of the navigation pane in DIPs.
const PANE_WIDTH: f64 = 220.0;

/// Rows the Keyed values page lists at most; the search narrows the rest down.
pub const KEYED_LIMIT: usize = 500;

/// The pages of the navigation pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home,
    Keyed,
    Settings,
}

impl Page {
    const ALL: [Self; 3] = [Self::Home, Self::Keyed, Self::Settings];

    const fn tag(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Keyed => "keyed",
            Self::Settings => "settings",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|page| page.tag() == tag)
    }

    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Keyed => "Keyed values",
            Self::Settings => "Settings",
        }
    }

    /// A Segoe Fluent Icons glyph: home, key, settings.
    const fn glyph(self) -> &'static str {
        match self {
            Self::Home => "\u{E80F}",
            Self::Keyed => "\u{E8D7}",
            Self::Settings => "\u{E713}",
        }
    }
}

/// The tabs of the Settings page, in the order of its tab bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SettingsTab {
    /// A card for every feature, with a link to the tab that holds the rest of its settings.
    #[default]
    General,
    /// The certificate, and the sites and programs whose traffic is masked.
    Masking,
    /// The kinds of personal data piikey looks for.
    Detection,
    /// The folders the inventory scans, and what it leaves out.
    Inventory,
    /// How scripts reach the app: the pipe, the HTTP address and the token.
    Api,
    /// The vault file: where it is, and exporting or wiping it.
    Vault,
    About,
}

impl SettingsTab {
    pub const ALL: [Self; 7] = [
        Self::General,
        Self::Masking,
        Self::Detection,
        Self::Inventory,
        Self::Api,
        Self::Vault,
        Self::About,
    ];

    /// The text of the tab. The tab bar reports a pick by this text, so each tab has its own.
    pub const fn label(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Masking => "Masking",
            Self::Detection => "Detection",
            Self::Inventory => "Inventory",
            Self::Api => "API",
            Self::Vault => "Vault",
            Self::About => "About",
        }
    }

    /// The tab whose text the tab bar reported.
    pub(super) fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tab| tab.label() == label)
    }
}

/// The controller as a window input: equal while it is the same controller.
#[derive(Clone)]
pub struct Handle(pub Arc<Controller>);

impl PartialEq for Handle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for Handle {
    type Target = Controller;

    fn deref(&self) -> &Controller {
        &self.0
    }
}

/// What the application gives the window.
#[derive(Clone, PartialEq)]
pub struct WindowInput {
    pub controller: Handle,
    /// Path of the `.ico` for the title bar; `None` when it could not be written.
    pub icon: Option<Rc<str>>,
    /// Tells the application that what the tray shows may have changed.
    pub on_sync: Callback<()>,
    /// Tells the application that the window went away.
    pub on_closed: Callback<()>,
    /// The latest "show this in the treemap" request the application handled (an Explorer scan
    /// that finished); `None` once the window has closed. The window follows each request once.
    pub reveal: Option<Reveal>,
}

/// What the Home treemap's side panel describes instead of the folder on show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// A tile of the folder: a file, or the node with an empty path that stands for the scans
    /// outside the watched folders.
    Node(PathBuf),
    /// The "+N more" tile: the nodes that did not get a tile of their own.
    More,
}

/// Messages of the window; all `Send` so background work can return them.
#[derive(Clone)]
pub enum Msg {
    Nav(Page),
    /// A tab of Settings, from its tab bar or from a link to it.
    Tab(SettingsTab),
    /// A snapshot newer than the last one, or `None` when the poll was cancelled or the Windows
    /// theme changed.
    Polled(Option<Box<Snapshot>>),
    Toggle(bool),
    InstallCertificate,
    DismissNotice,
    DismissForm,
    SiteDraft(String),
    AddSite,
    Site(String, bool),
    ProgramDraft(String),
    AddProgram,
    Program(String, bool),
    Processes(Vec<String>),
    RefreshProcesses,
    /// A Settings toggle: whether piikey masks that kind.
    Kind(EntityKind, bool),
    /// The Settings highlight choice.
    Highlight(Highlight),
    /// The Settings switch of the Explorer "Scan for PII" menu entry.
    ExplorerMenu(bool),
    /// The Settings switch of the PII inventory.
    Inventory(bool),
    /// The Settings switch of the local HTTP API.
    HttpApi(bool),
    /// The "add a folder" box of the inventory settings.
    RootDraft(String),
    AddRoot,
    /// A folder the inventory scans: added (`true`) or removed.
    Root(PathBuf, bool),
    /// A folder or file the inventory leaves out: added (`true`) or taken back.
    Exclude(PathBuf, bool),
    /// "Rescan now": the inventory scans all its folders again.
    RescanAll,
    CopyToken,
    RotateToken,
    /// What the Local API card says after a token action.
    TokenNote(&'static str),
    /// Write the vault to a CSV file in Downloads and show it in Explorer.
    ExportVault,
    /// The Wipe vault button: the first click arms it, the second one wipes.
    WipeVault,
    /// Forget the vault records of this value.
    Forget(String),
    /// The Keyed values search box.
    KeyedQuery(String),
    /// The Keyed values kind filter; `None` is every kind.
    KeyedKind(Option<EntityKind>),
    /// The Keyed values site filter; `None` is every site.
    KeyedSite(Option<String>),
    /// The Keyed values time filter.
    KeyedPeriod(Period),
    /// A Keyed values search finished; the number is the search it answers.
    KeyedLoaded(u64, KeyedPage),
    /// A breadcrumb of the treemap: show this folder (empty is the top level).
    InvNav(PathBuf),
    /// A tile of the treemap: a folder opens, a file is selected.
    InvOpen(PathBuf),
    /// The "+N more" tile.
    InvMore,
    /// A treemap level finished loading; the number is the load it answers.
    InvLoaded(u64, InventoryView),
    /// Open the file in the program Windows chooses for it.
    InvLaunch(PathBuf),
    /// Show the file or folder in Explorer.
    InvShow(PathBuf),
    /// Scan this file or folder again.
    InvRescan(PathBuf),
    /// Write a masked copy of this file beside it and show it in Explorer.
    InvMask(PathBuf),
    /// Leave this file or folder out of the inventory.
    InvExclude(PathBuf),
    /// Write a report of everything under the folder on show to Downloads and show it.
    InvReport,
    /// Show the next line of the loading screen.
    Flavor,
    /// Download the detection model again.
    RetryModel,
    /// Go on without the detection model.
    SkipModel,
    Noop,
}

/// What a click on a treemap tile does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Click {
    /// Show that folder in the treemap.
    Enter,
    /// Describe it in the side panel.
    Select,
    /// The tile is not in the view any more.
    Stale,
}

/// What a click on the tile of `path` does among `nodes`: folders open; files and the "Other
/// scans" node, whose empty path has no folder to open, are selected.
fn click_on(nodes: &[Node], path: &Path) -> Click {
    match nodes.iter().find(|node| node.path == path) {
        None => Click::Stale,
        Some(node) if node.is_dir && !path.as_os_str().is_empty() => Click::Enter,
        Some(_) => Click::Select,
    }
}

pub struct MainWindow {
    pub(super) input: WindowInput,
    pub(super) snap: Snapshot,
    pub(super) page: Page,
    /// The tab Settings shows: the one last chosen, while the window is open.
    pub(super) settings_tab: SettingsTab,
    /// Windows apps use the dark theme: picks the logo colour.
    pub(super) dark: bool,
    /// What the on/off switch shows while the controller is still getting there.
    pub(super) desired: Option<bool>,
    /// Programs running now, for the picker.
    pub(super) processes: Vec<String>,
    pub(super) site_draft: String,
    pub(super) program_draft: String,
    /// The inventory folder being typed in Settings.
    pub(super) root_draft: String,
    /// Why the last "Add" was refused.
    pub(super) form_error: Option<String>,
    /// The first click on Wipe vault came; the next one wipes. Changing the tab or the page puts
    /// it back.
    pub(super) wipe_armed: bool,
    /// What the API tab says about the last token action; changing the tab or the page clears it.
    pub(super) token_note: Option<&'static str>,
    /// What the Keyed values page asks for.
    pub(super) keyed: KeyedQuery,
    /// The latest search result; `None` until the first one arrives.
    pub(super) keyed_page: Option<KeyedPage>,
    /// Numbers the searches, so a slow old one cannot replace a newer result.
    keyed_search: u64,
    /// The folder the Home treemap shows; empty is the top level.
    pub(super) inv_at: PathBuf,
    /// What the treemap's side panel describes; `None` is the folder on show.
    pub(super) inv_selected: Option<Selection>,
    /// The tiles of `inv_at`, and the entry of the selected file.
    pub(super) inv_view: InventoryView,
    /// `inv_view` has been loaded at least once: until then the card does not claim it is empty.
    pub(super) inv_loaded: bool,
    /// Numbers the loads of `inv_view`, so a slow old one cannot replace a newer one.
    inv_seq: u64,
    /// The newest reveal request this window has followed.
    revealed: u64,
    timer: Option<ComponentTimer>,
    /// Which [`pages::loading::FLAVOR`] line the loading screen shows.
    pub(super) flavor: usize,
    flavor_timer: Option<ComponentTimer>,
}

impl MainWindow {
    /// The window as it opens: on Home, with Settings on its General tab.
    fn new(input: &WindowInput) -> Self {
        Self {
            input: input.clone(),
            snap: input.controller.snapshot(),
            page: Page::Home,
            settings_tab: SettingsTab::default(),
            dark: assets::system_dark(),
            desired: None,
            processes: Vec::new(),
            site_draft: String::new(),
            program_draft: String::new(),
            root_draft: String::new(),
            form_error: None,
            wipe_armed: false,
            token_note: None,
            keyed: KeyedQuery::default(),
            keyed_page: None,
            keyed_search: 0,
            inv_at: PathBuf::new(),
            inv_selected: None,
            inv_view: InventoryView::default(),
            inv_loaded: false,
            inv_seq: 0,
            revealed: 0,
            timer: None,
            flavor: 0,
            flavor_timer: None,
        }
    }

    /// Starts waiting for the next change of the controller, or of the Windows theme, which the
    /// controller knows nothing of: the logo and the colours of the pages follow it.
    fn poll(&self, context: &ComponentContext<Self>) {
        let controller = Arc::clone(&self.input.controller.0);
        let since = self.snap.version;
        let dark = self.dark;
        context.spawn_background(move |token| {
            loop {
                if token.is_cancelled() {
                    return Msg::Polled(None);
                }
                if let Some(snapshot) = controller.wait_changed(since, POLL) {
                    return Msg::Polled(Some(Box::new(snapshot)));
                }
                // A quiet controller says nothing about the theme; look at it each time the
                // wait runs out.
                if assets::system_dark() != dark {
                    return Msg::Polled(None);
                }
            }
        });
    }

    fn refresh_processes(context: &ComponentContext<Self>) {
        context.spawn_background(|_| Msg::Processes(crate::process::running_names()));
    }

    /// Runs `work` off the UI thread, where it may wait on the disk or the clipboard. The message
    /// it returns goes to the window; an error becomes the controller's notice instead.
    fn background(
        &self,
        context: &ComponentContext<Self>,
        work: impl FnOnce(&Controller) -> Res<Msg> + Send + 'static,
    ) {
        let controller = Arc::clone(&self.input.controller.0);
        context.spawn_background(move |_| match work(&controller) {
            Ok(message) => message,
            Err(error) => {
                controller.notify(Notice::error(error));
                Msg::Noop
            }
        });
    }

    fn adopt(&mut self, snapshot: Snapshot, context: &ComponentContext<Self>) {
        // What the tray shows, or a scan that asks to be shown: the application looks again.
        let tray_changed = self.snap.enabled != snapshot.enabled
            || self.snap.busy != snapshot.busy
            || self.snap.highlight_paused != snapshot.highlight_paused
            || self.snap.reveal != snapshot.reveal;
        let vault_changed = self.snap.issued != snapshot.issued;
        // The treemap follows what the scans find, while they run and once one has ended.
        let inventory_changed = self.snap.inventory_totals != snapshot.inventory_totals
            || (self.snap.scan.is_some() && snapshot.scan.is_none());
        self.snap = snapshot;
        if self.snap.busy.is_none() && self.snap.pending == 0 {
            self.desired = None;
        }
        if tray_changed {
            self.input.on_sync.call(());
        }
        if vault_changed && self.page == Page::Keyed {
            self.search(context);
        }
        if inventory_changed && self.page == Page::Home {
            self.load_inventory(context);
        }
    }

    /// Shows `page`. What the page before it left half done does not follow.
    fn open_page(&mut self, page: Page) {
        self.page = page;
        self.reset_transients();
    }

    /// Shows `tab` of Settings, on the same clean slate as a new page.
    fn open_tab(&mut self, tab: SettingsTab) {
        self.settings_tab = tab;
        self.reset_transients();
    }

    /// Puts back what a page or a tab leaves half done: a refused entry, a first click on Wipe
    /// vault, a note about the token.
    fn reset_transients(&mut self) {
        self.form_error = None;
        self.wipe_armed = false;
        self.token_note = None;
    }

    fn navigate(&mut self, page: Page, context: &ComponentContext<Self>) {
        self.open_page(page);
        match page {
            Page::Home => {
                self.input.controller.submit(Command::Refresh);
                self.load_inventory(context);
            }
            Page::Keyed => self.search(context),
            Page::Settings => self.watch_programs(context),
        }
    }

    /// Shows `tab` of Settings, from its tab bar or from a link to it.
    fn select_tab(&mut self, tab: SettingsTab, context: &ComponentContext<Self>) {
        if self.settings_tab != tab {
            self.open_tab(tab);
            self.watch_programs(context);
        }
    }

    /// Whether the Masking tab is on show: the only place that lists the programs running now.
    fn watching_programs(&self) -> bool {
        self.page == Page::Settings && self.settings_tab == SettingsTab::Masking
    }

    /// Asks for the running programs while the Masking tab is on show. The answer schedules the
    /// next ask.
    fn watch_programs(&self, context: &ComponentContext<Self>) {
        if self.watching_programs() {
            Self::refresh_processes(context);
        }
    }

    /// Follows the request to show an Explorer scan, once per request: Home, at the scanned
    /// folder, with the scanned file selected. `false` when there is nothing new to show.
    fn follow(&mut self, reveal: Option<&Reveal>, context: &ComponentContext<Self>) -> bool {
        let Some(reveal) = reveal.filter(|reveal| reveal.seq > self.revealed) else {
            return false;
        };
        self.revealed = reveal.seq;
        self.inv_at.clone_from(&reveal.at);
        self.inv_selected = reveal.select.clone().map(Selection::Node);
        self.navigate(Page::Home, context);
        true
    }

    /// Runs the Keyed values search in the background.
    fn search(&mut self, context: &ComponentContext<Self>) {
        self.keyed_search += 1;
        let search = self.keyed_search;
        let controller = Arc::clone(&self.input.controller.0);
        let query = self.keyed.clone();
        context.spawn_background(move |_| {
            Msg::KeyedLoaded(search, controller.keyed(&query, KEYED_LIMIT))
        });
    }

    /// The selected file, whose entry (size, scan time, what was found) the side panel wants.
    fn selected_file(&self) -> Option<PathBuf> {
        match &self.inv_selected {
            Some(Selection::Node(path)) if !path.as_os_str().is_empty() => Some(path.clone()),
            _ => None,
        }
    }

    /// Loads the tiles of `inv_at` in the background, with the entry of the selected file.
    fn load_inventory(&mut self, context: &ComponentContext<Self>) {
        self.inv_seq += 1;
        let load = self.inv_seq;
        let controller = Arc::clone(&self.input.controller.0);
        let at = self.inv_at.clone();
        let selected = self.selected_file();
        context.spawn_background(move |_| {
            Msg::InvLoaded(load, controller.inventory_view(&at, selected.as_deref()))
        });
    }

    /// Applies `edit` to the local copy of the policy and hands it to the controller.
    fn edit(&mut self, edit: Edit) -> Result<(), String> {
        apply_edit(&mut self.snap.policy, &edit)?;
        self.input.controller.submit(Command::Edit(edit));
        Ok(())
    }

    /// Whether the first-run loading screen replaces the pages.
    fn loading(&self) -> bool {
        matches!(
            self.snap.model,
            Model::Downloading { .. } | Model::Failed(_)
        )
    }

    /// The Settings lists: sites, programs, kinds, and the inventory's folders and exclusions.
    /// [`Component::update`] routes the messages of these lists here.
    fn update_lists(&mut self, message: Msg) {
        match message {
            Msg::SiteDraft(text) => {
                self.site_draft = text;
                self.form_error = None;
            }
            Msg::AddSite => {
                let site = self.site_draft.clone();
                match self.edit(Edit::Site { site, on: true }) {
                    Ok(()) => {
                        self.site_draft.clear();
                        self.form_error = None;
                    }
                    Err(error) => self.form_error = Some(error),
                }
            }
            Msg::Site(site, on) => {
                // Only removals of listed sites and presets reach here: nothing to validate.
                let _ = self.edit(Edit::Site { site, on });
            }
            Msg::ProgramDraft(text) => {
                self.program_draft = text;
                self.form_error = None;
            }
            Msg::AddProgram => {
                let exe = self.program_draft.clone();
                match self.edit(Edit::Program { exe, on: true }) {
                    Ok(()) => {
                        self.program_draft.clear();
                        self.form_error = None;
                    }
                    Err(error) => self.form_error = Some(error),
                }
            }
            Msg::Program(exe, on) => {
                let _ = self.edit(Edit::Program { exe, on });
            }
            Msg::Kind(kind, on) => {
                let _ = self.edit(Edit::Kind { kind, on });
            }
            Msg::RootDraft(text) => {
                self.root_draft = text;
                self.form_error = None;
            }
            Msg::AddRoot => {
                let path = PathBuf::from(self.root_draft.trim());
                match self.edit(Edit::InventoryRoot { path, on: true }) {
                    Ok(()) => {
                        self.root_draft.clear();
                        self.form_error = None;
                    }
                    Err(error) => self.form_error = Some(error),
                }
            }
            Msg::Root(path, on) => {
                let _ = self.edit(Edit::InventoryRoot { path, on });
            }
            Msg::Exclude(path, on) => {
                let _ = self.edit(Edit::InventoryExclude { path, on });
            }
            _ => {}
        }
    }

    /// The Settings feature switches, the Local API and the vault. [`Component::update`] routes
    /// their messages here.
    fn update_features(&mut self, message: &Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::Highlight(mode) => {
                let _ = self.edit(Edit::Highlight(*mode));
            }
            Msg::ExplorerMenu(on) => {
                let _ = self.edit(Edit::ExplorerMenu(*on));
            }
            Msg::Inventory(on) => {
                let _ = self.edit(Edit::Inventory(*on));
            }
            Msg::HttpApi(on) => {
                let _ = self.edit(Edit::HttpApi(*on));
            }
            Msg::RescanAll => self.input.controller.submit(Command::Rescan),
            Msg::CopyToken => self.background(context, |controller| {
                let token = controller.token(false)?;
                clipboard_win::set_clipboard_string(&token)
                    .map_err(|error| format!("Could not copy the token: {error}"))?;
                Ok(Msg::TokenNote("Token copied to the clipboard."))
            }),
            Msg::RotateToken => self.background(context, |controller| {
                controller.token(true)?;
                Ok(Msg::TokenNote(
                    "New token made. Scripts have to use it from now on: copy it with Copy token.",
                ))
            }),
            Msg::TokenNote(note) => self.token_note = Some(*note),
            Msg::ExportVault => self.background(context, |controller| {
                explorer::show(&controller.export_vault()?)?;
                Ok(Msg::Noop)
            }),
            Msg::WipeVault => self.click_wipe(),
            _ => {}
        }
    }

    /// Wipe vault takes two clicks: the first one only arms the button, the second one wipes.
    fn click_wipe(&mut self) {
        if self.wipe_armed {
            self.wipe_armed = false;
            self.input.controller.submit(Command::WipeVault);
        } else {
            self.wipe_armed = true;
        }
    }

    /// The Keyed values page: its search and Forget. [`Component::update`] routes its messages
    /// here.
    fn update_keyed(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::KeyedQuery(text) => {
                self.keyed.text = text;
                self.search(context);
            }
            Msg::KeyedKind(kind) => {
                self.keyed.kind = kind;
                self.search(context);
            }
            Msg::KeyedSite(site) => {
                self.keyed.site = site;
                self.search(context);
            }
            Msg::KeyedPeriod(period) => {
                self.keyed.period = period;
                self.search(context);
            }
            Msg::KeyedLoaded(search, page) if search == self.keyed_search => {
                self.keyed_page = Some(page);
            }
            Msg::Forget(original) => self
                .input
                .controller
                .submit(Command::Forget(vec![original])),
            _ => {}
        }
    }

    /// The Home treemap: navigation, selection and the actions of its side panel.
    /// [`Component::update`] routes its messages here.
    fn update_inventory(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::InvNav(path) => {
                self.inv_at = path;
                self.inv_selected = None;
                self.load_inventory(context);
            }
            Msg::InvOpen(path) => match click_on(&self.inv_view.nodes, &path) {
                Click::Enter => {
                    self.inv_at = path;
                    self.inv_selected = None;
                    self.load_inventory(context);
                }
                Click::Select => {
                    // The "Other scans" node has no file whose entry could be looked up.
                    let is_file = !path.as_os_str().is_empty();
                    self.inv_selected = Some(Selection::Node(path));
                    if is_file {
                        self.load_inventory(context);
                    }
                }
                Click::Stale => {}
            },
            Msg::InvMore => self.inv_selected = Some(Selection::More),
            Msg::InvLoaded(load, view) if load == self.inv_seq => {
                self.inv_view = view;
                self.inv_loaded = true;
            }
            Msg::InvLaunch(path) => self.background(context, move |_| {
                explorer::open(&path)?;
                Ok(Msg::Noop)
            }),
            Msg::InvShow(path) => self.background(context, move |_| {
                explorer::show(&path)?;
                Ok(Msg::Noop)
            }),
            Msg::InvRescan(path) => self.input.controller.submit(Command::ScanFiles {
                paths: vec![path],
                reveal: false,
            }),
            Msg::InvMask(path) => self.background(context, move |controller| {
                explorer::show(&controller.masked_copy(&path)?)?;
                Ok(Msg::Noop)
            }),
            Msg::InvExclude(path) => {
                // Gone from the side panel at once; the controller forgets what lies under it, and
                // the totals that change then load the view again.
                self.inv_selected = None;
                if let Err(error) = self.edit(Edit::InventoryExclude { path, on: true }) {
                    self.input.controller.notify(Notice::error(error));
                }
                self.load_inventory(context);
            }
            Msg::InvReport => {
                let under = self.inv_at.clone();
                self.background(context, move |controller| {
                    explorer::show(&controller.export_report(&under)?)?;
                    Ok(Msg::Noop)
                });
            }
            _ => {}
        }
    }
}

impl Component for MainWindow {
    type Input = WindowInput;
    type Message = Msg;

    fn create(input: &WindowInput, context: &ComponentContext<Self>) -> Self {
        let mut window = Self::new(input);
        window.flavor_timer = Some(context.set_timeout(FLAVOR_EVERY, Msg::Flavor));
        window.poll(context);
        // Home is the first page: it needs its treemap, unless a reveal has just loaded it.
        if !window.follow(input.reveal.as_ref(), context) {
            window.load_inventory(context);
        }
        window
    }

    fn input_changed(&mut self, input: &WindowInput, context: &ComponentContext<Self>) {
        self.input = input.clone();
        self.follow(input.reveal.as_ref(), context);
    }

    fn update(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::Nav(page) => self.navigate(page, context),
            Msg::Tab(tab) => self.select_tab(tab, context),
            Msg::Polled(snapshot) => {
                // Whatever ended the poll, the theme may have changed.
                self.dark = assets::system_dark();
                if let Some(snapshot) = snapshot {
                    self.adopt(*snapshot, context);
                }
                self.poll(context);
            }
            Msg::Toggle(on) => {
                self.desired = Some(on);
                self.input.controller.submit(Command::SetEnabled(on));
            }
            Msg::InstallCertificate => self.input.controller.submit(Command::InstallCertificate),
            Msg::DismissNotice => self.input.controller.dismiss_notice(),
            Msg::DismissForm => self.form_error = None,
            Msg::Processes(processes) => {
                self.processes = processes;
                if self.watching_programs() {
                    self.timer = Some(context.set_timeout(PROCESS_REFRESH, Msg::RefreshProcesses));
                }
            }
            Msg::RefreshProcesses => self.watch_programs(context),
            Msg::Flavor => {
                if self.loading() {
                    self.flavor = (self.flavor + 1) % pages::loading::FLAVOR.len();
                    self.flavor_timer = Some(context.set_timeout(FLAVOR_EVERY, Msg::Flavor));
                } else {
                    self.flavor_timer = None;
                }
            }
            Msg::RetryModel => self.input.controller.submit(Command::FetchModel),
            Msg::SkipModel => self.input.controller.submit(Command::SkipModel),
            Msg::Noop => {}
            Msg::SiteDraft(_)
            | Msg::AddSite
            | Msg::Site(..)
            | Msg::ProgramDraft(_)
            | Msg::AddProgram
            | Msg::Program(..)
            | Msg::Kind(..)
            | Msg::RootDraft(_)
            | Msg::AddRoot
            | Msg::Root(..)
            | Msg::Exclude(..) => self.update_lists(message),
            Msg::Highlight(_)
            | Msg::ExplorerMenu(_)
            | Msg::Inventory(_)
            | Msg::HttpApi(_)
            | Msg::RescanAll
            | Msg::CopyToken
            | Msg::RotateToken
            | Msg::TokenNote(_)
            | Msg::ExportVault
            | Msg::WipeVault => self.update_features(&message, context),
            Msg::KeyedQuery(_)
            | Msg::KeyedKind(_)
            | Msg::KeyedSite(_)
            | Msg::KeyedPeriod(_)
            | Msg::KeyedLoaded(..)
            | Msg::Forget(_) => self.update_keyed(message, context),
            Msg::InvNav(_)
            | Msg::InvOpen(_)
            | Msg::InvMore
            | Msg::InvLoaded(..)
            | Msg::InvLaunch(_)
            | Msg::InvShow(_)
            | Msg::InvRescan(_)
            | Msg::InvMask(_)
            | Msg::InvExclude(_)
            | Msg::InvReport => self.update_inventory(message, context),
        }
    }

    fn view(&self, input: &WindowInput, context: &mut ViewContext<Self>) -> View {
        let mut visuals = WindowVisuals::new()
            .backdrop(WindowBackdrop::Mica)
            .theme(assets::window_theme())
            .client_size(1040.0, 760.0)
            .constraints(WindowConstraints {
                min_width: Some(760.0),
                min_height: Some(560.0),
                ..WindowConstraints::default()
            });
        if let Some(icon) = &input.icon {
            visuals = visuals.icon(Rc::clone(icon));
        }
        context.window_visuals(visuals);
        context.window_title("piikey");
        context.use_effect("ready", (), || {
            println!("piikey: window ready");
            None
        });
        let closed = input.on_closed.clone();
        context.use_effect_guard("closed", (), move || Closed(closed));

        let context = &*context;
        let items = Page::ALL.map(|page| {
            KeyedView::new(
                page.tag(),
                NavigationViewItem::new()
                    .tag(page.tag())
                    .is_selected(self.page == page)
                    .content(page.title())
                    .icon(Icon::font(page.glyph())),
            )
        });
        let navigation = NavigationView::new()
            .pane_display_mode(NavigationViewPaneDisplayMode::Left)
            .open_pane_length(PANE_WIDTH)
            .is_pane_toggle_button_visible(false)
            .is_back_button_visible(NavigationViewBackButtonVisible::Collapsed)
            .is_settings_visible(false)
            .always_show_header(false)
            .on_selected_tag_changed(context.callback(|tag: Option<Rc<str>>| {
                tag.as_deref()
                    .and_then(Page::from_tag)
                    .map_or(Msg::Noop, Msg::Nav)
            }))
            .keyed_menu_items(items)
            .content(pages::page(self, context))
            .grid_row(1);
        // The title bar takes the icon from the `.ico` file: `TitleBar` with path data as its
        // icon source makes WinUI fail fast at startup (stowed exception 0xC000027B).
        let title_bar = TitleBar::new().title("piikey").grid_row(0);
        let title_bar = match input
            .icon
            .as_ref()
            .and_then(|path| Icon::image_file(path.as_ref()).ok())
        {
            Some(icon) => title_bar.icon(icon),
            None => title_bar,
        };
        let body: View = if self.loading() {
            pages::loading::screen(self, context).grid_row(1).into()
        } else {
            navigation.into()
        };
        Grid::new()
            .rows([GridLength::Auto, GridLength::STAR])
            .children((title_bar, body))
            .into()
    }
}

/// Tells the application when the window component is dropped, which is when the window closes.
struct Closed(Callback<()>);

impl Drop for Closed {
    fn drop(&mut self) {
        self.0.call(());
    }
}

#[cfg(test)]
mod tests {
    use piikey::{
        detect::{KIND_GROUPS, Mode},
        service::default_pipe,
    };
    use windows_reactor::{
        ComponentHost, ComponentSender, ComponentServices, ComponentTimerRegistration, Key,
        Mutation, PropertyId, PropertyValue, RecordingAdapter, component,
    };

    use super::{
        super::testing::{TempDir, stub_controller, stub_controller_with},
        *,
    };
    use crate::{Describe, proxy::PORT};

    fn node(path: &str, is_dir: bool) -> Node {
        Node {
            path: PathBuf::from(path),
            name: path.rsplit('\\').next().unwrap_or_default().to_owned(),
            is_dir,
            hits: 3,
            files: 1,
            counts: Vec::new(),
        }
    }

    #[test]
    fn a_folder_tile_opens_and_a_file_tile_is_selected() {
        let nodes = [node(r"C:\Docs\Taxes", true), node(r"C:\Docs\id.pdf", false)];
        assert_eq!(click_on(&nodes, Path::new(r"C:\Docs\Taxes")), Click::Enter);
        assert_eq!(
            click_on(&nodes, Path::new(r"C:\Docs\id.pdf")),
            Click::Select
        );
    }

    #[test]
    fn the_other_scans_tile_has_no_folder_to_open() {
        // Its path is empty and the inventory calls it a folder.
        let nodes = [node("", true)];
        assert_eq!(click_on(&nodes, Path::new("")), Click::Select);
    }

    #[test]
    fn a_tile_that_left_the_view_does_nothing() {
        let nodes = [node(r"C:\Docs\Taxes", true)];
        assert_eq!(click_on(&nodes, Path::new(r"C:\Docs\Gone")), Click::Stale);
        assert_eq!(click_on(&[], Path::new(r"C:\Docs\Taxes")), Click::Stale);
    }

    type Test = Result<(), String>;

    /// How long a test waits for the controller's worker.
    const WAIT: Duration = Duration::from_secs(20);

    /// A window on a stub controller; its files go away with the folder.
    fn window() -> Result<(MainWindow, TempDir), String> {
        let dir = TempDir::new()?;
        let input = WindowInput {
            controller: Handle(stub_controller(&dir)?),
            icon: None,
            on_sync: Callback::new(|()| {}),
            on_closed: Callback::new(|()| {}),
            reveal: None,
        };
        Ok((MainWindow::new(&input), dir))
    }

    /// Leaves something half done on every control that a new page or tab must put back.
    fn leave_half_done(window: &mut MainWindow) {
        window.wipe_armed = true;
        window.token_note = Some("Token copied to the clipboard.");
        window.form_error = Some("Not a folder".to_owned());
    }

    fn is_clean(window: &MainWindow) -> bool {
        !window.wipe_armed && window.token_note.is_none() && window.form_error.is_none()
    }

    #[test]
    fn a_tab_is_found_again_by_the_text_the_tab_bar_reports() {
        for tab in SettingsTab::ALL {
            assert_eq!(SettingsTab::from_label(tab.label()), Some(tab));
        }
        let mut labels: Vec<&str> = SettingsTab::ALL.iter().map(|tab| tab.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            SettingsTab::ALL.len(),
            "two tabs share a text"
        );
        assert_eq!(SettingsTab::from_label("Keyed values"), None);
        assert_eq!(SettingsTab::from_label(""), None);
        assert_eq!(SettingsTab::ALL[0], SettingsTab::default());
    }

    #[test]
    fn settings_open_on_general_and_keep_the_tab_chosen_last() -> Test {
        let (mut window, _dir) = window()?;
        assert_eq!(window.settings_tab, SettingsTab::General);
        window.open_page(Page::Settings);
        window.open_tab(SettingsTab::Vault);
        window.open_page(Page::Keyed);
        window.open_page(Page::Settings);
        assert_eq!(window.settings_tab, SettingsTab::Vault);
        Ok(())
    }

    #[test]
    fn only_the_masking_tab_asks_for_the_running_programs() -> Test {
        let (mut window, _dir) = window()?;
        assert!(!window.watching_programs());
        window.open_page(Page::Settings);
        assert!(!window.watching_programs());
        window.open_tab(SettingsTab::Masking);
        assert!(window.watching_programs());
        window.open_tab(SettingsTab::Detection);
        assert!(!window.watching_programs());
        window.open_tab(SettingsTab::Masking);
        window.open_page(Page::Home);
        assert!(!window.watching_programs());
        Ok(())
    }

    #[test]
    fn a_new_tab_or_page_starts_without_what_the_last_one_left_half_done() -> Test {
        let (mut window, _dir) = window()?;
        window.open_page(Page::Settings);
        leave_half_done(&mut window);
        window.open_tab(SettingsTab::Masking);
        assert!(is_clean(&window));
        leave_half_done(&mut window);
        window.open_page(Page::Home);
        assert!(is_clean(&window));
        Ok(())
    }

    #[test]
    fn wiping_the_vault_takes_two_clicks_and_another_tab_in_between_starts_over() -> Test {
        let (mut window, _dir) = window()?;
        let controller = Arc::clone(&window.input.controller.0);
        controller
            .engine()
            .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
            .describe()?;
        controller.submit(Command::Refresh);
        assert!(controller.wait_idle(WAIT));
        assert_eq!(controller.snapshot().issued, 1);

        window.open_page(Page::Settings);
        window.open_tab(SettingsTab::Vault);
        window.click_wipe();
        assert!(window.wipe_armed);
        assert!(controller.wait_idle(WAIT));
        assert_eq!(controller.snapshot().issued, 1, "one click must not wipe");

        // Looking at another tab disarms the button: the next click only arms it again.
        window.open_tab(SettingsTab::General);
        window.open_tab(SettingsTab::Vault);
        window.click_wipe();
        assert!(window.wipe_armed);
        assert!(controller.wait_idle(WAIT));
        assert_eq!(controller.snapshot().issued, 1, "the armed click was lost");

        window.click_wipe();
        assert!(!window.wipe_armed);
        assert!(controller.wait_idle(WAIT));
        assert_eq!(controller.snapshot().issued, 0);
        Ok(())
    }

    // ---- The real window on the reactor's headless host ----

    /// Background work and timers that never run: the window's poll, its loads and its joke
    /// timer stay quiet, and a test sends the messages they would have brought.
    struct Idle;

    struct NeverFires;

    impl ComponentTimerRegistration for NeverFires {
        fn cancel(&self) {}
    }

    impl ComponentServices for Idle {
        fn spawn_background(&self, _work: Box<dyn FnOnce() + Send>) {}

        fn set_timeout(
            &self,
            _delay: Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> Arc<dyn ComponentTimerRegistration> {
            Arc::new(NeverFires)
        }
    }

    /// The window as the application mounts it, on a recording adapter instead of `WinUI`:
    /// nothing is shown. Every view the window builds is reconciled and checked against the
    /// contracts of the controls, and the recorded mutations say which text was drawn.
    struct Headless {
        host: ComponentHost<RecordingAdapter>,
        window: ComponentSender<Msg>,
        controller: Arc<Controller>,
        _dir: TempDir,
    }

    impl Headless {
        /// Mounts the window on the controller that `controller` makes in a fresh folder, once the
        /// controller has looked at the certificate and the vault.
        fn open(
            controller: impl FnOnce(&TempDir) -> Result<Arc<Controller>, String>,
        ) -> Result<Self, String> {
            let dir = TempDir::new()?;
            let controller = controller(&dir)?;
            controller.submit(Command::Refresh);
            if !controller.wait_idle(WAIT) {
                return Err("the controller did not settle".to_owned());
            }
            let input = WindowInput {
                controller: Handle(Arc::clone(&controller)),
                icon: None,
                on_sync: Callback::new(|()| {}),
                on_closed: Callback::new(|()| {}),
                reveal: None,
            };
            let mut adapter = RecordingAdapter::new();
            adapter.record_batches(true);
            let key = Key::from("window");
            let host = ComponentHost::mount_with_services(
                adapter,
                Arc::new(Idle),
                [component::<MainWindow>(key.clone(), input)],
            )
            .map_err(|error| format!("{error:?}"))?;
            let window = host
                .sender::<MainWindow>(&key)
                .ok_or("the window has no mailbox")?;
            Ok(Self {
                host,
                window,
                controller,
                _dir: dir,
            })
        }

        /// Gives the window `message`, lets it handle it, and returns the text of everything it
        /// drew for it.
        fn send(&mut self, message: Msg) -> Result<Vec<String>, String> {
            let before = self.host.adapter().batches().len();
            if !self.window.send(message) {
                return Err("the window took no message".to_owned());
            }
            self.host.drain(64).map_err(|error| format!("{error:?}"))?;
            Ok(texts(&self.host.adapter().batches()[before..]))
        }

        /// Brings the controller's state to the window, as the poll does.
        fn poll(&mut self) -> Result<Vec<String>, String> {
            let snapshot = self.controller.snapshot();
            self.send(Msg::Polled(Some(Box::new(snapshot))))
        }
    }

    /// The text that `batches` set on labels, buttons, titles and messages: what was drawn.
    fn texts(batches: &[Vec<Mutation>]) -> Vec<String> {
        batches
            .iter()
            .flatten()
            .filter_map(|mutation| match mutation {
                Mutation::SetProperties { set, .. } => Some(set.iter()),
                _ => None,
            })
            .flatten()
            .filter(|property| {
                matches!(
                    property.id,
                    PropertyId::Text | PropertyId::Title | PropertyId::Message
                )
            })
            .filter_map(|property| match &property.value {
                PropertyValue::String(text) => Some(text.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Fails unless `drawn` holds every one of `wanted`, naming the step that missed them.
    fn expect_drawn(step: &str, drawn: &[String], wanted: &[&str]) -> Test {
        for text in wanted {
            if !drawn.iter().any(|drawn| drawn == text) {
                return Err(format!("{step}: {text:?} was not drawn, only {drawn:?}"));
            }
        }
        Ok(())
    }

    /// Fails if `drawn` holds one of `unwanted`.
    fn expect_not_drawn(step: &str, drawn: &[String], unwanted: &[&str]) -> Test {
        for text in unwanted {
            if drawn.iter().any(|drawn| drawn == text) {
                return Err(format!("{step}: {text:?} was drawn"));
            }
        }
        Ok(())
    }

    #[test]
    fn every_tab_of_settings_draws_its_own_content_and_opens_again_from_scratch() -> Test {
        let mut ui = Headless::open(stub_controller)?;
        let first = ui.send(Msg::Nav(Page::Settings))?;
        let labels = SettingsTab::ALL.map(SettingsTab::label);
        expect_drawn("the tab bar", &first, &labels)?;

        let general = [
            "Mask what you send",
            "Highlight personal data as you type",
            "Scan for PII in Explorer",
            "PII inventory",
            "Local HTTP API",
            "Masking settings ›",
            "Inventory settings ›",
            "API settings ›",
        ];
        expect_drawn("General", &first, &general)?;

        let about_title = format!("piikey {}", env!("CARGO_PKG_VERSION"));
        let pipe = default_pipe();
        let proxy = format!("Local proxy: 127.0.0.1:{PORT}, stopped");
        let http = piikey::api::http::url(piikey::policy::DEFAULT_HTTP_PORT);
        let tabs: [(SettingsTab, Vec<&str>); 6] = [
            (
                SettingsTab::Masking,
                vec![
                    "Certificate installed",
                    "Sites",
                    "Programs",
                    "Add site",
                    "Add program",
                ],
            ),
            (SettingsTab::Detection, vec!["What piikey looks for"]),
            (
                SettingsTab::Inventory,
                vec![
                    "PII inventory is off",
                    "General ›",
                    "Rescan now",
                    "Folders to scan",
                    "Add folder",
                    "Left out",
                    "Nothing is left out.",
                ],
            ),
            (
                SettingsTab::Api,
                vec![
                    "Named pipe",
                    pipe.as_str(),
                    "HTTP",
                    http.as_str(),
                    "Off.",
                    "Switch on Local HTTP API in General ›",
                    "Copy token",
                    "New token",
                ],
            ),
            (
                SettingsTab::Vault,
                vec![
                    "Vault file",
                    "0 records",
                    "Export vault",
                    "Export…",
                    "Wipe the vault",
                    "Wipe vault",
                ],
            ),
            (
                SettingsTab::About,
                vec![about_title.as_str(), proxy.as_str()],
            ),
        ];
        for (tab, wanted) in &tabs {
            let drawn = ui.send(Msg::Tab(*tab))?;
            expect_drawn(tab.label(), &drawn, wanted)?;
            // The tab before it is gone: nothing of General is drawn again, nor kept.
            expect_not_drawn(tab.label(), &drawn, &general)?;
        }
        // The kinds sit in one collapsed expander per group.
        let detection = ui.send(Msg::Tab(SettingsTab::Detection))?;
        let group = KIND_GROUPS[0].0;
        assert!(
            detection.iter().any(|text| text.starts_with(group)),
            "no expander of {group}: {detection:?}"
        );

        // A tab that was left is built anew when it comes back.
        let again = ui.send(Msg::Tab(SettingsTab::General))?;
        expect_drawn("General again", &again, &general)?;
        Ok(())
    }

    #[test]
    fn the_other_pages_still_draw_next_to_settings() -> Test {
        let mut ui = Headless::open(stub_controller)?;
        let keyed = ui.send(Msg::Nav(Page::Keyed))?;
        expect_drawn("Keyed values", &keyed, &["Keyed values"])?;
        let settings = ui.send(Msg::Nav(Page::Settings))?;
        expect_drawn("Settings", &settings, &["Settings", "Mask what you send"])?;
        let home = ui.send(Msg::Nav(Page::Home))?;
        expect_drawn("Home", &home, &["values keyed, all time"])?;
        // The tab chosen last is the one Settings opens on again.
        ui.send(Msg::Tab(SettingsTab::Vault))?;
        let back = ui.send(Msg::Nav(Page::Settings))?;
        expect_drawn("Settings again", &back, &["Vault file"])?;
        Ok(())
    }

    #[test]
    fn without_the_certificate_general_says_why_masking_is_off_and_where_to_fix_it() -> Test {
        let mut ui = Headless::open(|dir| stub_controller_with(dir, false))?;
        let general = ui.send(Msg::Nav(Page::Settings))?;
        expect_drawn(
            "General",
            &general,
            &["Needs the piikey certificate first.", "Install it ›"],
        )?;
        expect_not_drawn("General", &general, &["Masking settings ›"])?;
        let masking = ui.send(Msg::Tab(SettingsTab::Masking))?;
        expect_drawn(
            "Masking",
            &masking,
            &["Certificate not installed", "Install certificate"],
        )?;
        Ok(())
    }

    #[test]
    fn the_vault_tab_shows_the_second_click_and_another_tab_takes_it_back() -> Test {
        let mut ui = Headless::open(|dir| {
            let controller = stub_controller(dir)?;
            controller
                .engine()
                .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
                .describe()?;
            Ok(controller)
        })?;
        ui.send(Msg::Nav(Page::Settings))?;
        let vault = ui.send(Msg::Tab(SettingsTab::Vault))?;
        expect_drawn("Vault", &vault, &["1 record", "Wipe vault"])?;

        let armed = ui.send(Msg::WipeVault)?;
        expect_drawn("first click", &armed, &["Click again to wipe the record"])?;

        // Another tab in between puts the button back.
        ui.send(Msg::Tab(SettingsTab::General))?;
        let vault = ui.send(Msg::Tab(SettingsTab::Vault))?;
        expect_drawn("Vault again", &vault, &["Wipe vault"])?;
        expect_not_drawn("Vault again", &vault, &["Click again to wipe the record"])?;

        // Two clicks in a row wipe, and the count follows.
        ui.send(Msg::WipeVault)?;
        ui.send(Msg::WipeVault)?;
        assert!(ui.controller.wait_idle(WAIT));
        let wiped = ui.poll()?;
        expect_drawn("after the wipe", &wiped, &["0 records"])?;
        Ok(())
    }
}
