//! The main window: navigation and state. The pages are drawn by [`pages`](super::pages).
//!
//! The window holds a copy of the controller's [`Snapshot`] and refreshes it from a background
//! poll; every user action becomes a message, then a [`Command`] for the controller. Edits to the
//! lists and the feature switches are applied to the copy at once so the controls follow the
//! click; the next snapshot is the truth and puts a rejected edit back. Work that waits on the
//! disk, the registry or the clipboard (exports, the API token, masked copies, the inventory view,
//! starting at sign-in) runs in the background, and its errors reach the user as the controller's
//! notice.

use std::{
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use piikey::{api::reply::Device, detect::EntityKind, inventory::Node, policy::Highlight};
use windows_reactor::{
    Callback, Component, ComponentContext, ComponentTimer, Grid, GridLength, HorizontalAlignment,
    Icon, Image, KeyedView, NavigationView, NavigationViewBackButtonVisible, NavigationViewItem,
    NavigationViewPaneDisplayMode, Stretch, Thickness, TitleBar, View, ViewContext, WindowBackdrop,
    WindowConstraints, WindowVisuals,
};

use super::{
    assets,
    controller::{
        Command, Controller, Edit, InventoryView, KeyedPage, KeyedQuery, Model, Notice, Period,
        Reveal, Snapshot, apply_edit,
    },
    explorer, pages,
    status::Status,
};
use crate::{Res, startup};

/// How long one background poll waits for a change before it checks for cancellation.
const POLL: Duration = Duration::from_secs(2);

/// How often the list of running apps refreshes while Protection is open.
const APP_REFRESH: Duration = Duration::from_secs(5);

/// How long each joke line stays on the loading screen.
const FLAVOR_EVERY: Duration = Duration::from_secs(4);

/// Width of the navigation pane in DIPs.
const PANE_WIDTH: f64 = 220.0;

/// Rows the Vault page lists at most; the search narrows the rest down.
pub const VAULT_LIMIT: usize = 500;

/// The pages of the navigation pane: four in its menu, and Settings at its foot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Protection,
    Inventory,
    Vault,
    Settings,
}

impl Page {
    /// The pages of the pane's menu, in order. Settings is the pane's footer item.
    const MENU: [Self; 4] = [
        Self::Overview,
        Self::Protection,
        Self::Inventory,
        Self::Vault,
    ];

    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Protection,
        Self::Inventory,
        Self::Vault,
        Self::Settings,
    ];

    pub(super) const fn tag(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Protection => "protection",
            Self::Inventory => "inventory",
            Self::Vault => "vault",
            Self::Settings => "settings",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|page| page.tag() == tag)
    }

    /// The pane's label and the page's own title.
    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Protection => "Protection",
            Self::Inventory => "Inventory",
            Self::Vault => "Vault",
            Self::Settings => "Settings",
        }
    }

    /// A Segoe Fluent Icons glyph: home, shield, folder, lock, gear.
    const fn glyph(self) -> &'static str {
        match self {
            Self::Overview => "\u{E80F}",
            Self::Protection => "\u{EA18}",
            Self::Inventory => "\u{E8B7}",
            Self::Vault => "\u{E72E}",
            Self::Settings => "\u{E713}",
        }
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

/// What the Inventory treemap's side panel describes instead of the folder on show.
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
    /// A snapshot newer than the last one, or `None` when the poll was cancelled or the Windows
    /// theme changed.
    Polled(Option<Box<Snapshot>>),
    /// The master switch: protection on (`true`) or off.
    Toggle(bool),
    InstallCertificate,
    DismissNotice,
    DismissForm,
    /// The "add a site" box of Protection.
    SiteDraft(String),
    AddSite,
    /// A site protected (`true`) or not.
    Site(String, bool),
    /// The "add an app" box of Protection.
    AppDraft(String),
    AddApp,
    /// An app protected (`true`) or not.
    App(String, bool),
    /// The apps running now.
    Apps(Vec<String>),
    RefreshApps,
    /// The Protection choice of when the field in focus is outlined.
    Highlight(Highlight),
    /// A Settings checkbox: whether piikey looks for that type of personal data.
    Kind(EntityKind, bool),
    /// The Inventory switch of the Explorer "Scan for personal data" menu entry.
    ExplorerMenu(bool),
    /// The Inventory switch of the inventory.
    Inventory(bool),
    /// The Settings switch of the local HTTP API.
    HttpApi(bool),
    /// The "add a folder" box of Inventory.
    RootDraft(String),
    AddRoot,
    /// A folder the inventory scans: added (`true`) or removed.
    Root(PathBuf, bool),
    /// A folder or file the inventory leaves out: added (`true`) or taken back.
    Exclude(PathBuf, bool),
    /// "Rescan": the inventory scans all its folders again.
    RescanAll,
    CopyToken,
    RotateToken,
    /// What Developer access says after a token action.
    TokenNote(&'static str),
    /// Whether piikey starts when the user signs in, as the system says; `None` when it could not
    /// be read.
    StartupLoaded(Option<bool>),
    /// The Settings switch of starting piikey at sign-in.
    SetStartup(bool),
    /// Where the detection model runs, as the model folder says; `None` before its first load.
    DeviceLoaded(Option<Device>),
    /// Show the data folder in Explorer.
    OpenDataFolder,
    /// Write the vault to a CSV file in Downloads and show it in Explorer.
    ExportVault,
    /// The Wipe vault button: the first click arms it, the second one wipes.
    WipeVault,
    /// Forget the vault records of this value.
    Forget(String),
    /// The Vault search box.
    VaultQuery(String),
    /// The Vault type filter; `None` is every type.
    VaultKind(Option<EntityKind>),
    /// The Vault site filter; `None` is every site.
    VaultSite(Option<String>),
    /// The Vault time filter.
    VaultPeriod(Period),
    /// A Vault search finished; the number is the search it answers.
    VaultLoaded(u64, KeyedPage),
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

/// What the model folder's `device.cfg` names, if it names a device. The app writes it plain;
/// people write it by hand, and what `echo cpu > device.cfg` leaves in Windows `PowerShell` is
/// UTF-16 with a byte-order mark, so that is read too. `gpu`, as an older version wrote it, is the
/// CPU and the GPU together.
fn parse_device(bytes: &[u8]) -> Option<Device> {
    let text = match bytes {
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    };
    match text.trim() {
        "hybrid" | "gpu" => Some(Device::Hybrid),
        "cpu" => Some(Device::Cpu),
        _ => None,
    }
}

/// `bytes` as UTF-16 text of the given byte order.
fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| unit([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Where the detection model runs, as its folder says; `None` when nothing says yet.
fn read_device() -> Option<Device> {
    let dir = piikey::detect::ner::files::default_dir().ok()?;
    let bytes = fs::read(dir.join(piikey::detect::ner::files::DEVICE_FILE)).ok()?;
    parse_device(&bytes)
}

/// What the user asked of the controller, and it has not yet finished: the switches show it at
/// once, and the fix button holds still, so nothing is asked twice. Everything else on the pages
/// stays as it is, however long the controller is at work.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Asked {
    /// What the on/off switches show while the controller is still getting there.
    pub(super) protection: Option<bool>,
    /// "Install certificate" was pressed.
    pub(super) certificate: bool,
}

pub struct MainWindow {
    pub(super) input: WindowInput,
    pub(super) snap: Snapshot,
    pub(super) page: Page,
    /// Windows apps use the dark theme: picks the logo and the status colours.
    pub(super) dark: bool,
    /// What the user asked of the controller that it has not finished.
    pub(super) asked: Asked,
    /// Apps running now, for the picker of Protection.
    pub(super) apps: Vec<String>,
    pub(super) site_draft: String,
    pub(super) app_draft: String,
    /// The inventory folder being typed in Inventory.
    pub(super) root_draft: String,
    /// Why the last "Add" was refused.
    pub(super) form_error: Option<String>,
    /// The first click on Wipe vault came; the next one wipes. Changing the page puts it back.
    pub(super) wipe_armed: bool,
    /// What Developer access says about the last token action; changing the page clears it.
    pub(super) token_note: Option<&'static str>,
    /// Whether piikey starts at sign-in; `None` until the system has answered.
    pub(super) startup: Option<bool>,
    /// Where the detection model runs; `None` until it has loaded once, or until read.
    pub(super) device: Option<Device>,
    /// What the Vault page asks for.
    pub(super) vault: KeyedQuery,
    /// The latest search result; `None` until the first one arrives.
    pub(super) vault_page: Option<KeyedPage>,
    /// Numbers the searches, so a slow old one cannot replace a newer result.
    vault_search: u64,
    /// The folder the Inventory treemap shows; empty is the top level.
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
    /// The window as it opens: on Overview.
    fn new(input: &WindowInput) -> Self {
        Self {
            input: input.clone(),
            snap: input.controller.snapshot(),
            page: Page::Overview,
            dark: assets::system_dark(),
            asked: Asked::default(),
            apps: Vec::new(),
            site_draft: String::new(),
            app_draft: String::new(),
            root_draft: String::new(),
            form_error: None,
            wipe_armed: false,
            token_note: None,
            startup: None,
            device: None,
            vault: KeyedQuery::default(),
            vault_page: None,
            vault_search: 0,
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

    /// What piikey is doing now: the one status the hero, the chip and the switches show.
    pub(super) fn status(&self) -> Status {
        Status::of(&self.snap, self.asked.protection)
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

    fn refresh_apps(context: &ComponentContext<Self>) {
        context.spawn_background(|_| Msg::Apps(crate::process::running_names()));
    }

    /// Runs `work` off the UI thread, where it may wait on the disk, the registry or the
    /// clipboard. The message it returns goes to the window; an error becomes the controller's
    /// notice instead.
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
        // What the tray shows, or a scan or a second start that asks to be shown: the
        // application looks again. The status is all of what the tray shows.
        let tray_changed = Status::of(&self.snap, None) != Status::of(&snapshot, None)
            || self.snap.highlight_paused != snapshot.highlight_paused
            || self.snap.reveal != snapshot.reveal
            || self.snap.show != snapshot.show;
        let vault_changed = self.snap.issued != snapshot.issued;
        // The treemap follows what the scans find, while they run and once one has ended.
        let inventory_changed = self.snap.inventory_totals != snapshot.inventory_totals
            || (self.snap.scan.is_some() && snapshot.scan.is_none());
        self.snap = snapshot;
        if self.snap.busy.is_none() && self.snap.pending == 0 {
            self.asked = Asked::default();
        }
        if tray_changed {
            self.input.on_sync.call(());
        }
        if vault_changed && self.page == Page::Vault {
            self.search(context);
        }
        if inventory_changed && self.page == Page::Inventory {
            self.load_inventory(context);
        }
    }

    /// Shows `page`. What the page before it left half done does not follow.
    fn open_page(&mut self, page: Page) {
        self.page = page;
        self.reset_transients();
    }

    /// Puts back what a page leaves half done: a refused entry, a first click on Wipe vault, a
    /// note about the token.
    fn reset_transients(&mut self) {
        self.form_error = None;
        self.wipe_armed = false;
        self.token_note = None;
    }

    fn navigate(&mut self, page: Page, context: &ComponentContext<Self>) {
        self.open_page(page);
        match page {
            Page::Overview => self.input.controller.submit(Command::Refresh),
            Page::Protection => {
                // The certificate may have been installed another way since the last look.
                self.input.controller.submit(Command::Refresh);
                self.watch_apps(context);
            }
            Page::Inventory => self.load_inventory(context),
            Page::Vault => self.search(context),
            Page::Settings => self.load_settings(context),
        }
    }

    /// Whether Protection is on show: the only place that lists the apps running now.
    fn watching_apps(&self) -> bool {
        self.page == Page::Protection
    }

    /// Asks for the running apps while Protection is on show. The answer schedules the next ask.
    fn watch_apps(&self, context: &ComponentContext<Self>) {
        if self.watching_apps() {
            Self::refresh_apps(context);
        }
    }

    /// What Settings shows that the controller does not know: whether piikey starts at sign-in,
    /// and where the model runs.
    fn load_settings(&self, context: &ComponentContext<Self>) {
        // A setting that cannot be read is a notice, and its switch stays off limits.
        self.background(context, |_| {
            startup::enabled().map(|on| Msg::StartupLoaded(Some(on)))
        });
        self.background(context, |_| Ok(Msg::DeviceLoaded(read_device())));
    }

    /// Follows the request to show an Explorer scan, once per request: Inventory, at the scanned
    /// folder, with the scanned file selected. `false` when there is nothing new to show.
    fn follow(&mut self, reveal: Option<&Reveal>, context: &ComponentContext<Self>) -> bool {
        let Some(reveal) = reveal.filter(|reveal| reveal.seq > self.revealed) else {
            return false;
        };
        self.revealed = reveal.seq;
        self.inv_at.clone_from(&reveal.at);
        self.inv_selected = reveal.select.clone().map(Selection::Node);
        self.navigate(Page::Inventory, context);
        true
    }

    /// Runs the Vault search in the background.
    fn search(&mut self, context: &ComponentContext<Self>) {
        self.vault_search += 1;
        let search = self.vault_search;
        let controller = Arc::clone(&self.input.controller.0);
        let query = self.vault.clone();
        context.spawn_background(move |_| {
            Msg::VaultLoaded(search, controller.keyed(&query, VAULT_LIMIT))
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

    /// The lists of Protection and Inventory: sites, apps, and the inventory's folders and
    /// exclusions. [`Component::update`] routes the messages of these lists here.
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
            Msg::AppDraft(text) => {
                self.app_draft = text;
                self.form_error = None;
            }
            Msg::AddApp => {
                let exe = self.app_draft.clone();
                match self.edit(Edit::Program { exe, on: true }) {
                    Ok(()) => {
                        self.app_draft.clear();
                        self.form_error = None;
                    }
                    Err(error) => self.form_error = Some(error),
                }
            }
            Msg::App(exe, on) => {
                let _ = self.edit(Edit::Program { exe, on });
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

    /// The feature switches, the types of personal data, and Developer access.
    /// [`Component::update`] routes their messages here.
    fn update_features(&mut self, message: &Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::Highlight(mode) => {
                let _ = self.edit(Edit::Highlight(*mode));
            }
            Msg::Kind(kind, on) => {
                let _ = self.edit(Edit::Kind {
                    kind: *kind,
                    on: *on,
                });
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
            Msg::StartupLoaded(on) => self.startup = *on,
            Msg::SetStartup(on) => {
                let on = *on;
                self.startup = Some(on);
                self.background(context, move |controller| {
                    // Windows may refuse (the user switched it off under Settings > Apps >
                    // Startup, or a policy holds it): say so, and let what the system says
                    // now decide what the switch shows.
                    if let Err(error) = startup::set(on) {
                        controller.notify(Notice::error(error));
                    }
                    Ok(Msg::StartupLoaded(startup::enabled().ok()))
                });
            }
            Msg::DeviceLoaded(device) => self.device = *device,
            Msg::OpenDataFolder => {
                let folder = self
                    .input
                    .controller
                    .vault_path()
                    .parent()
                    .map(Path::to_path_buf);
                self.background(context, move |_| {
                    if let Some(folder) = &folder {
                        explorer::open(folder)?;
                    }
                    Ok(Msg::Noop)
                });
            }
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

    /// The Vault page: its search, its export, Forget and Wipe. [`Component::update`] routes its
    /// messages here.
    fn update_vault(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::VaultQuery(text) => {
                self.vault.text = text;
                self.search(context);
            }
            Msg::VaultKind(kind) => {
                self.vault.kind = kind;
                self.search(context);
            }
            Msg::VaultSite(site) => {
                self.vault.site = site;
                self.search(context);
            }
            Msg::VaultPeriod(period) => {
                self.vault.period = period;
                self.search(context);
            }
            Msg::VaultLoaded(search, page) if search == self.vault_search => {
                self.vault_page = Some(page);
            }
            Msg::Forget(original) => self
                .input
                .controller
                .submit(Command::Forget(vec![original])),
            Msg::ExportVault => self.background(context, |controller| {
                explorer::show(&controller.export_vault()?)?;
                Ok(Msg::Noop)
            }),
            Msg::WipeVault => self.click_wipe(),
            _ => {}
        }
    }

    /// The Inventory treemap: navigation, selection and the actions of its side panel.
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

/// One item of the pane: its icon and name, selected while its page is on show.
fn nav_item(page: Page, current: Page) -> KeyedView {
    KeyedView::new(
        page.tag(),
        NavigationViewItem::new()
            .tag(page.tag())
            .is_selected(current == page)
            .content(page.title())
            .icon(Icon::font(page.glyph())),
    )
}

/// The brand at the top of the pane: the horizontal lockup, which already reads "piikey".
fn pane_header(dark: bool) -> View {
    Image::new()
        .source_svg(assets::lockup(dark))
        .stretch(Stretch::Uniform)
        .height(28.0)
        .horizontal_alignment(HorizontalAlignment::Left)
        .margin(Thickness::new(16.0, 12.0, 16.0, 12.0))
        .into()
}

impl Component for MainWindow {
    type Input = WindowInput;
    type Message = Msg;

    fn create(input: &WindowInput, context: &ComponentContext<Self>) -> Self {
        let mut window = Self::new(input);
        window.flavor_timer = Some(context.set_timeout(FLAVOR_EVERY, Msg::Flavor));
        window.poll(context);
        // Overview is the first page, unless a reveal has just taken the window to the map.
        window.follow(input.reveal.as_ref(), context);
        window
    }

    fn input_changed(&mut self, input: &WindowInput, context: &ComponentContext<Self>) {
        self.input = input.clone();
        self.follow(input.reveal.as_ref(), context);
    }

    fn update(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::Nav(page) => self.navigate(page, context),
            Msg::Polled(snapshot) => {
                // Whatever ended the poll, the theme may have changed.
                self.dark = assets::system_dark();
                if let Some(snapshot) = snapshot {
                    self.adopt(*snapshot, context);
                }
                self.poll(context);
            }
            Msg::Toggle(on) => {
                self.asked.protection = Some(on);
                self.input.controller.submit(Command::SetEnabled(on));
            }
            Msg::InstallCertificate => {
                self.asked.certificate = true;
                self.input.controller.submit(Command::InstallCertificate);
            }
            Msg::DismissNotice => self.input.controller.dismiss_notice(),
            Msg::DismissForm => self.form_error = None,
            Msg::Apps(apps) => {
                self.apps = apps;
                if self.watching_apps() {
                    self.timer = Some(context.set_timeout(APP_REFRESH, Msg::RefreshApps));
                }
            }
            Msg::RefreshApps => self.watch_apps(context),
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
            | Msg::AppDraft(_)
            | Msg::AddApp
            | Msg::App(..)
            | Msg::RootDraft(_)
            | Msg::AddRoot
            | Msg::Root(..)
            | Msg::Exclude(..) => self.update_lists(message),
            Msg::Highlight(_)
            | Msg::Kind(..)
            | Msg::ExplorerMenu(_)
            | Msg::Inventory(_)
            | Msg::HttpApi(_)
            | Msg::RescanAll
            | Msg::CopyToken
            | Msg::RotateToken
            | Msg::TokenNote(_)
            | Msg::StartupLoaded(_)
            | Msg::SetStartup(_)
            | Msg::DeviceLoaded(_)
            | Msg::OpenDataFolder => self.update_features(&message, context),
            Msg::ExportVault
            | Msg::WipeVault
            | Msg::Forget(_)
            | Msg::VaultQuery(_)
            | Msg::VaultKind(_)
            | Msg::VaultSite(_)
            | Msg::VaultPeriod(_)
            | Msg::VaultLoaded(..) => self.update_vault(message, context),
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
        let status = self.status();
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
            .pane_header(pane_header(self.dark))
            .keyed_menu_items(Page::MENU.map(|page| nav_item(page, self.page)))
            .keyed_footer_menu_items([nav_item(Page::Settings, self.page)])
            .pane_footer(pages::status_chip(self, &status, context))
            .content(pages::page(self, &status, context))
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
mod tests;
