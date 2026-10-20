//! The main window: navigation and state. The pages are drawn by [`pages`](super::pages).
//!
//! The window holds a copy of the controller's [`Snapshot`] and refreshes it from a background
//! poll; every user action becomes a message, then a [`Command`] for the controller. Edits to the
//! lists are applied to the copy at once so the controls follow the click; the next snapshot is
//! the truth and puts a rejected edit back.

use std::{ops::Deref, rc::Rc, sync::Arc, time::Duration};

use piikey::detect::EntityKind;
use windows_reactor::{
    Callback, Component, ComponentContext, ComponentTimer, Grid, GridLength, Icon, KeyedView,
    NavigationView, NavigationViewBackButtonVisible, NavigationViewItem,
    NavigationViewPaneDisplayMode, TitleBar, View, ViewContext, WindowBackdrop, WindowConstraints,
    WindowTheme, WindowVisuals,
};

use super::{
    assets,
    controller::{
        Command, Controller, Edit, KeyedPage, KeyedQuery, Model, Period, Snapshot, apply_edit,
        running_programs,
    },
    pages,
};

/// How long one background poll waits for a change before it checks for cancellation.
const POLL: Duration = Duration::from_secs(2);

/// How often the list of running programs refreshes while Settings is open.
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
}

/// Messages of the window; all `Send` so background work can return them.
#[derive(Clone)]
pub enum Msg {
    Nav(Page),
    /// A snapshot newer than the last one, or `None` when the poll timed out.
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
    /// Show the next line of the loading screen.
    Flavor,
    /// Download the detection model again.
    RetryModel,
    /// Go on without the detection model.
    SkipModel,
    Noop,
}

pub struct MainWindow {
    pub(super) input: WindowInput,
    pub(super) snap: Snapshot,
    pub(super) page: Page,
    /// Windows apps use the dark theme: picks the logo colour.
    pub(super) dark: bool,
    /// What the on/off switch shows while the controller is still getting there.
    pub(super) desired: Option<bool>,
    /// Programs running now, for the picker.
    pub(super) processes: Vec<String>,
    pub(super) site_draft: String,
    pub(super) program_draft: String,
    /// Why the last "Add" was refused.
    pub(super) form_error: Option<String>,
    /// What the Keyed values page asks for.
    pub(super) keyed: KeyedQuery,
    /// The latest search result; `None` until the first one arrives.
    pub(super) keyed_page: Option<KeyedPage>,
    /// Numbers the searches, so a slow old one cannot replace a newer result.
    keyed_search: u64,
    timer: Option<ComponentTimer>,
    /// Which [`pages::FLAVOR`] line the loading screen shows.
    pub(super) flavor: usize,
    flavor_timer: Option<ComponentTimer>,
}

impl MainWindow {
    /// Starts waiting for the next change of the controller.
    fn poll(&self, context: &ComponentContext<Self>) {
        let controller = Arc::clone(&self.input.controller.0);
        let since = self.snap.version;
        context.spawn_background(move |token| {
            loop {
                if token.is_cancelled() {
                    return Msg::Polled(None);
                }
                if let Some(snapshot) = controller.wait_changed(since, POLL) {
                    return Msg::Polled(Some(Box::new(snapshot)));
                }
            }
        });
    }

    fn refresh_processes(context: &ComponentContext<Self>) {
        context.spawn_background(|_| Msg::Processes(running_programs()));
    }

    fn adopt(&mut self, snapshot: Snapshot, context: &ComponentContext<Self>) {
        let tray_changed = self.snap.enabled != snapshot.enabled || self.snap.busy != snapshot.busy;
        let vault_changed = self.snap.issued != snapshot.issued;
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
    }

    fn navigate(&mut self, page: Page, context: &ComponentContext<Self>) {
        self.page = page;
        self.form_error = None;
        match page {
            Page::Home => self.input.controller.submit(Command::Refresh),
            Page::Keyed => self.search(context),
            Page::Settings => Self::refresh_processes(context),
        }
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
}

impl Component for MainWindow {
    type Input = WindowInput;
    type Message = Msg;

    fn create(input: &WindowInput, context: &ComponentContext<Self>) -> Self {
        let snap = input.controller.snapshot();
        let mut window = Self {
            input: input.clone(),
            snap,
            page: Page::Home,
            dark: assets::system_dark(),
            desired: None,
            processes: Vec::new(),
            site_draft: String::new(),
            program_draft: String::new(),
            form_error: None,
            keyed: KeyedQuery::default(),
            keyed_page: None,
            keyed_search: 0,
            timer: None,
            flavor: 0,
            flavor_timer: None,
        };
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
                // The theme can change any time; the poll comes back every few seconds.
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
            Msg::Processes(processes) => {
                self.processes = processes;
                if self.page == Page::Settings {
                    self.timer = Some(context.set_timeout(PROCESS_REFRESH, Msg::RefreshProcesses));
                }
            }
            Msg::RefreshProcesses => {
                if self.page == Page::Settings {
                    Self::refresh_processes(context);
                }
            }
            Msg::Kind(kind, on) => {
                let _ = self.edit(Edit::Kind { kind, on });
            }
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
            Msg::KeyedLoaded(search, page) => {
                if search == self.keyed_search {
                    self.keyed_page = Some(page);
                }
            }
            Msg::Flavor => {
                if self.loading() {
                    self.flavor = (self.flavor + 1) % pages::FLAVOR.len();
                    self.flavor_timer = Some(context.set_timeout(FLAVOR_EVERY, Msg::Flavor));
                } else {
                    self.flavor_timer = None;
                }
            }
            Msg::RetryModel => self.input.controller.submit(Command::FetchModel),
            Msg::SkipModel => self.input.controller.submit(Command::SkipModel),
            Msg::Noop => {}
        }
    }

    fn view(&self, input: &WindowInput, context: &mut ViewContext<Self>) -> View {
        let mut visuals = WindowVisuals::new()
            .backdrop(WindowBackdrop::Mica)
            .theme(WindowTheme::System)
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
            pages::loading(self, context).grid_row(1).into()
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
