//! The main window: navigation and state. The pages are drawn by [`pages`](super::pages).
//!
//! The window holds a copy of the controller's [`Snapshot`] and refreshes it from a background
//! poll; every user action becomes a message, then a [`Command`] for the controller. Edits to the
//! lists and the feature switches are applied to the copy at once so the controls follow the
//! click; the next snapshot is the truth and puts a rejected edit back. Work that waits on the
//! disk, the registry or the clipboard (exports, the API token, masked copies, the dashboard's
//! view, starting at sign-in) runs in the background, and its errors reach the user as the
//! controller's notice.

use std::{
    collections::HashSet,
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use piikey::{detect::EntityKind, inventory::Finding, policy::Highlight};
use windows_reactor::{
    Callback, Component, ComponentContext, ComponentTimer, ContentDialogExt, Grid, GridLength,
    HorizontalAlignment, Icon, Image, KeyedView, NavigationView, NavigationViewBackButtonVisible,
    NavigationViewItem, NavigationViewPaneDisplayMode, Stretch, Thickness, TitleBar, View,
    ViewContext, WindowBackdrop, WindowConstraints, WindowSize, WindowVisuals,
};

use super::{
    assets,
    controller::{
        Command, Controller, Edit, FindingFiles, KeyedPage, KeyedQuery, Model, Notice, Period,
        Snapshot, apply_edit,
    },
    explorer, goto, pages,
    status::Status,
};
use crate::{Res, startup};

mod dashboard;
mod findings;
mod report;

pub use self::{
    dashboard::{Dash, Dashboard, Loaded, Origin},
    findings::{FindingsView, Reading, Row, Working},
};

/// How long one background poll waits for a change before it checks for cancellation.
const POLL: Duration = Duration::from_secs(2);

/// How often the list of running apps refreshes while Protection is open.
const APP_REFRESH: Duration = Duration::from_secs(5);

/// How long each joke line stays on the loading screen.
const FLAVOR_EVERY: Duration = Duration::from_secs(4);

/// Width of the navigation pane in DIPs.
pub const PANE_WIDTH: f64 = 220.0;

/// The size the window opens with, in DIPs: until it says otherwise, this is the room the pages
/// have.
const OPENS_AT: WindowSize = WindowSize {
    width: 1_040.0,
    height: 760.0,
};

/// How coarsely the window's size is followed, in DIPs: a smaller change leaves the layout of the
/// dashboard alone, so dragging an edge builds it anew once in a while, not at every pixel.
const SIZE_STEP: f64 = 8.0;

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
    /// The number of the scan request that opened the window, `None` when the user did: a window
    /// that opens for a scan shows its result, one that opens for the user does not show the
    /// results of scans it never saw.
    pub reveal: Option<u64>,
}

/// What a Browse button picks, and for which box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browse {
    /// A folder for the inventory: it becomes a location and is scanned.
    Location,
    /// A file for the inventory: it is scanned.
    File,
}

impl Browse {
    /// The picker's title.
    const fn title(self) -> &'static str {
        match self {
            Self::Location => "Choose a folder to scan",
            Self::File => "Choose a file to scan",
        }
    }
}

/// Messages of the window; all `Send` so background work can return them.
#[derive(Clone)]
pub enum Msg {
    Nav(Page),
    /// A snapshot newer than the last one, or `None` when the poll was cancelled or the Windows
    /// theme changed.
    Polled(Option<Box<Snapshot>>),
    /// The window has this size now.
    Resized(WindowSize),
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
    /// The Settings switch of the Explorer "Scan for personal data" menu entry.
    ExplorerMenu(bool),
    /// The Settings switch of keeping piikey in the tray when the window closes.
    Background(bool),
    /// The Settings switch of the local HTTP API.
    HttpApi(bool),
    /// The "scan a folder or file" box of Inventory.
    RootDraft(String),
    AddRoot,
    /// The box's text names a folder or file that is there: it is being scanned.
    RootAdded,
    /// The box's text names nothing that can be scanned; the text says why.
    RootRefused(String),
    /// A location the Scan button looks through, taken off the list.
    RemoveLocation(PathBuf),
    /// The Scan button: the inventory scans all its locations now.
    ScanAll,
    /// A location's Monitor switch: its file changes are scanned as they happen, or not.
    Monitor(PathBuf, bool),
    /// A Browse button: open the Windows picker for it.
    Browse(Browse),
    /// The picker of a Browse button gave this path: it goes where the box's text would.
    Browsed(Browse, PathBuf),
    /// Something was dropped on the window: the paths of the files and folders.
    Dropped(Vec<String>),
    /// Something the dashboard's controls ask for.
    Dash(Dash),
    /// The files the findings view will read.
    FindingsListed(u64, FindingFiles),
    /// What a batch of those files held, or why one could not be read; the number says which
    /// reading it belongs to.
    FindingsRead(u64, Vec<(PathBuf, Result<Vec<Finding>, String>)>),
    /// More values of a file that is still being read, in the order they were found.
    FindingsMore(u64, PathBuf, Vec<Finding>),
    /// What the reading with this number is doing now, for the line of progress.
    FindingsBusy(u64, Working),
    /// The reading that has this number is over.
    FindingsDone(u64),
    /// The findings view's search box.
    FindingsSearch(String),
    /// A type chosen in the findings view; `None` is every type.
    FindingsType(Option<EntityKind>),
    /// A file chosen in the findings view, by its place in the list; `None` is every file.
    FindingsFile(Option<usize>),
    /// The findings view was left.
    FindingsClose,
    /// "Open at this place" on the row with this number.
    FindingsOpen(u32),
    /// What "Open at this place" did for that row.
    FindingsOpened(u32, goto::Outcome),
    /// The result of a scan was closed.
    ReportClose,
    /// "Show in Inventory" on the result of a scan.
    ReportShow,
    /// "Show what was found" on the result of a scan.
    ReportFound,
    CopyToken,
    RotateToken,
    /// What Developer access says after a token action.
    TokenNote(&'static str),
    /// Whether piikey starts when the user signs in, as the system says; `None` when it could not
    /// be read.
    StartupLoaded(Option<bool>),
    /// The Settings switch of starting piikey at sign-in.
    SetStartup(bool),
    /// Show the data folder in Explorer.
    OpenDataFolder,
    /// Write the vault to a CSV file in Downloads and show it in Explorer.
    ExportVault,
    /// The Vault check box of this value was set or cleared.
    VaultPick(String, bool),
    /// Select all: every listed value, or none.
    VaultPickAll(bool),
    /// The Forget N button: ask before forgetting the selected values.
    VaultAskForget,
    /// The answer to that question: `true` forgets the selected values.
    VaultForget(bool),
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
    /// Show the next line of the loading screen.
    Flavor,
    /// Download the detection model again.
    RetryModel,
    /// Go on without the detection model.
    SkipModel,
    Noop,
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
    /// The window's client size, as far as the layout follows it.
    pub(super) size: WindowSize,
    /// Windows apps use the dark theme: picks the logo and the status colours.
    pub(super) dark: bool,
    /// What the user asked of the controller that it has not finished.
    pub(super) asked: Asked,
    /// Apps running now, for the picker of Protection.
    pub(super) apps: Vec<String>,
    pub(super) site_draft: String,
    pub(super) app_draft: String,
    /// The folder or file being typed in Inventory.
    pub(super) root_draft: String,
    /// Why the last "Add" was refused.
    pub(super) form_error: Option<String>,
    /// What Developer access says about the last token action; changing the page clears it.
    pub(super) token_note: Option<&'static str>,
    /// Whether piikey starts at sign-in; `None` until the system has answered.
    pub(super) startup: Option<bool>,
    /// What the Vault page asks for.
    pub(super) vault: KeyedQuery,
    /// The latest search result; `None` until the first one arrives.
    pub(super) vault_page: Option<KeyedPage>,
    /// The values ticked on the Vault page: only ever values of `vault_page`.
    pub(super) vault_picked: HashSet<String>,
    /// Forget was pressed and its question is on show.
    pub(super) forget_asked: bool,
    /// Numbers the searches, so a slow old one cannot replace a newer result.
    vault_search: u64,
    /// What the Inventory page shows and what the user chose in it.
    pub(super) inventory: Dashboard,
    /// The findings view while it is open: the values of the files of a result and how the list is
    /// narrowed down. Never kept past the view.
    pub(super) findings: Option<FindingsView>,
    /// Numbers the findings views, so what an older reading brings is dropped.
    findings_seq: u64,
    /// The newest scan request whose result the user has seen and put away.
    pub(super) dismissed: u64,
    timer: Option<ComponentTimer>,
    /// Which [`pages::loading::FLAVOR`] line the loading screen shows.
    pub(super) flavor: usize,
    flavor_timer: Option<ComponentTimer>,
}

impl MainWindow {
    /// The window as it opens: on Overview.
    fn new(input: &WindowInput) -> Self {
        let snap = input.controller.snapshot();
        // A window that opens for a scan shows its result; any other shows only what comes after.
        let dismissed = match input.reveal {
            Some(seq) => seq.saturating_sub(1),
            None => snap.reveal.as_ref().map_or(0, |reveal| reveal.seq),
        };
        Self {
            input: input.clone(),
            snap,
            page: Page::Overview,
            size: OPENS_AT,
            dark: assets::system_dark(),
            asked: Asked::default(),
            apps: Vec::new(),
            site_draft: String::new(),
            app_draft: String::new(),
            root_draft: String::new(),
            form_error: None,
            token_note: None,
            startup: None,
            vault: KeyedQuery::default(),
            vault_page: None,
            vault_picked: HashSet::new(),
            forget_asked: false,
            vault_search: 0,
            inventory: Dashboard::new(),
            findings: None,
            findings_seq: 0,
            dismissed,
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
        // The dashboard follows what the scans find, while they run and once one has ended: the
        // ones that were asked for and the ones of what monitoring saw change.
        let inventory_changed = self.snap.inventory_totals != snapshot.inventory_totals
            || (self.snap.scan.is_some() && snapshot.scan.is_none())
            || (self.snap.watch.scanning.is_some() && snapshot.watch.scanning.is_none());
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
            self.load_dashboard(context);
        }
    }

    /// Shows `page`. What the page before it left half done does not follow.
    fn open_page(&mut self, page: Page) {
        self.page = page;
        self.reset_transients();
    }

    /// Puts back what a page leaves half done: a refused entry, an unanswered question about
    /// forgetting, a note about the token.
    fn reset_transients(&mut self) {
        self.form_error = None;
        self.forget_asked = false;
        self.token_note = None;
    }

    fn navigate(&mut self, page: Page, context: &ComponentContext<Self>) {
        self.close_findings();
        self.open_page(page);
        match page {
            Page::Overview => self.input.controller.submit(Command::Refresh),
            Page::Protection => {
                // The certificate may have been installed another way since the last look.
                self.input.controller.submit(Command::Refresh);
                self.watch_apps(context);
            }
            Page::Inventory => self.load_dashboard(context),
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

    /// What Settings shows that the controller does not know: whether piikey starts at sign-in.
    fn load_settings(&self, context: &ComponentContext<Self>) {
        // A setting that cannot be read is a notice, and its switch stays off limits.
        self.background(context, |_| {
            startup::enabled().map(|on| Msg::StartupLoaded(Some(on)))
        });
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

    /// The window has this size now; a change smaller than a step is not followed.
    fn resize(&mut self, size: WindowSize) {
        let snap = |value: f64| (value / SIZE_STEP).round() * SIZE_STEP;
        let size = WindowSize {
            width: snap(size.width),
            height: snap(size.height),
        };
        if size != self.size {
            self.size = size;
        }
    }

    /// The lists of Protection and Inventory: sites, apps, and the locations the inventory scans
    /// and monitors. [`Component::update`] routes the messages of these here.
    fn update_lists(&mut self, message: Msg, context: &ComponentContext<Self>) {
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
            Msg::AddRoot => self.add_root(context),
            Msg::Browse(browse) => Self::browse(browse, context),
            Msg::Browsed(Browse::Location | Browse::File, path) => {
                self.root_draft = path.display().to_string();
                self.add_root(context);
            }
            Msg::RootAdded => {
                self.root_draft.clear();
                self.form_error = None;
            }
            Msg::RootRefused(error) => self.form_error = Some(error),
            Msg::RemoveLocation(path) => {
                let _ = self.edit(Edit::InventoryRoot { path, on: false });
            }
            Msg::Monitor(path, on) => match self.edit(Edit::Monitor { path, on }) {
                Ok(()) => self.form_error = None,
                Err(error) => self.form_error = Some(error),
            },
            _ => {}
        }
    }

    /// Opens the Windows picker of `browse` off the UI thread: it waits for the user. Nothing
    /// happens when the picker is closed without a choice.
    fn browse(browse: Browse, context: &ComponentContext<Self>) {
        context.spawn_background(move |_| {
            let dialog = rfd::FileDialog::new().set_title(browse.title());
            let picked = match browse {
                Browse::File => dialog.pick_file(),
                Browse::Location => dialog.pick_folder(),
            };
            picked.map_or(Msg::Noop, |path| Msg::Browsed(browse, path))
        });
    }

    /// The Inventory box: a folder is added to the locations and scanned, a file is scanned, both
    /// with the result on show. Which it is, is for the disk to say, so that is asked in the
    /// background.
    fn add_root(&self, context: &ComponentContext<Self>) {
        let path = PathBuf::from(self.root_draft.trim());
        self.background(context, move |controller| match fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => {
                controller.submit(Command::AddLocation(path));
                Ok(Msg::RootAdded)
            }
            Ok(_) => {
                controller.submit(Command::ScanFiles {
                    paths: vec![path],
                    reveal: true,
                });
                Ok(Msg::RootAdded)
            }
            Err(error) => Ok(Msg::RootRefused(format!(
                "Cannot scan {}: {error}",
                path.display()
            ))),
        });
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
            Msg::Background(on) => {
                let _ = self.edit(Edit::Background(*on));
            }
            Msg::HttpApi(on) => {
                let _ = self.edit(Edit::HttpApi(*on));
            }
            Msg::ScanAll => self.input.controller.submit(Command::ScanAll),
            Msg::Dropped(paths) => {
                let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
                if !paths.is_empty() {
                    self.input.controller.submit(Command::ScanFiles {
                        paths,
                        reveal: true,
                    });
                }
            }
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

    /// The Vault page: its search, its export, its selection and Forget. [`Component::update`]
    /// routes its messages here.
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
                // Only what the list shows stays selected.
                let listed: HashSet<&str> = page
                    .items
                    .iter()
                    .map(|item| item.original.as_str())
                    .collect();
                self.vault_picked
                    .retain(|value| listed.contains(value.as_str()));
                self.vault_page = Some(page);
            }
            Msg::VaultPick(original, on) => {
                if on {
                    self.vault_picked.insert(original);
                } else {
                    self.vault_picked.remove(&original);
                }
            }
            Msg::VaultPickAll(on) => {
                self.vault_picked.clear();
                if on && let Some(page) = &self.vault_page {
                    self.vault_picked
                        .extend(page.items.iter().map(|item| item.original.clone()));
                }
            }
            Msg::VaultAskForget => self.forget_asked = !self.vault_picked.is_empty(),
            Msg::VaultForget(confirmed) => {
                self.forget_asked = false;
                if confirmed {
                    let values: Vec<String> = self
                        .vault_page
                        .iter()
                        .flat_map(|page| &page.items)
                        .filter(|item| self.vault_picked.contains(&item.original))
                        .map(|item| item.original.clone())
                        .collect();
                    self.vault_picked.clear();
                    if !values.is_empty() {
                        self.input.controller.submit(Command::Forget(values));
                    }
                }
            }
            Msg::ExportVault => self.background(context, |controller| {
                explorer::show(&controller.export_vault()?)?;
                Ok(Msg::Noop)
            }),
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
        window
    }

    fn input_changed(&mut self, input: &WindowInput, _context: &ComponentContext<Self>) {
        self.input = input.clone();
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
            Msg::Resized(size) => self.resize(size),
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
            Msg::Dash(message) => self.update_dashboard(message, context),
            Msg::SiteDraft(_)
            | Msg::AddSite
            | Msg::Site(..)
            | Msg::AppDraft(_)
            | Msg::AddApp
            | Msg::App(..)
            | Msg::RootDraft(_)
            | Msg::AddRoot
            | Msg::RootAdded
            | Msg::RootRefused(_)
            | Msg::RemoveLocation(_)
            | Msg::Monitor(..)
            | Msg::Browse(_)
            | Msg::Browsed(..) => self.update_lists(message, context),
            Msg::Highlight(_)
            | Msg::Kind(..)
            | Msg::ExplorerMenu(_)
            | Msg::Background(_)
            | Msg::HttpApi(_)
            | Msg::ScanAll
            | Msg::Dropped(_)
            | Msg::CopyToken
            | Msg::RotateToken
            | Msg::TokenNote(_)
            | Msg::StartupLoaded(_)
            | Msg::SetStartup(_)
            | Msg::OpenDataFolder => self.update_features(&message, context),
            Msg::ExportVault
            | Msg::VaultPick(..)
            | Msg::VaultPickAll(_)
            | Msg::VaultAskForget
            | Msg::VaultForget(_)
            | Msg::VaultQuery(_)
            | Msg::VaultKind(_)
            | Msg::VaultSite(_)
            | Msg::VaultPeriod(_)
            | Msg::VaultLoaded(..) => self.update_vault(message, context),
            Msg::ReportClose | Msg::ReportShow | Msg::ReportFound => {
                self.update_report(&message, context);
            }
            Msg::FindingsListed(..)
            | Msg::FindingsRead(..)
            | Msg::FindingsMore(..)
            | Msg::FindingsBusy(..)
            | Msg::FindingsDone(_)
            | Msg::FindingsSearch(_)
            | Msg::FindingsType(_)
            | Msg::FindingsFile(_)
            | Msg::FindingsClose
            | Msg::FindingsOpen(_)
            | Msg::FindingsOpened(..) => self.update_findings(message, context),
        }
    }

    fn view(&self, input: &WindowInput, context: &mut ViewContext<Self>) -> View {
        let mut visuals = WindowVisuals::new()
            .backdrop(WindowBackdrop::Mica)
            .theme(assets::window_theme())
            .client_size(OPENS_AT.width, OPENS_AT.height)
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
        let resized = context.callback(Msg::Resized);
        context.on_window_size(resized);
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
        let frame: View = Grid::new()
            .rows([GridLength::Auto, GridLength::STAR])
            .children((title_bar, body))
            .into();
        // What a scan found, or what was found in a file, over whatever page is on show.
        match pages::dialog(self, context) {
            Some(dialog) => frame.content_dialog(dialog),
            None => frame,
        }
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
