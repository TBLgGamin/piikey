use piikey::{
    detect::{KIND_GROUPS, Mode},
    inventory::Finding,
};
use windows_reactor::{
    ComponentHost, ComponentSender, ComponentServices, ComponentTimerRegistration, Key, Mutation,
    ObjectId, ObjectType, PropertyId, PropertyValue, RecordingAdapter, component,
};

use super::{
    super::testing::{TempDir, stub_controller, stub_controller_with},
    *,
};
use crate::ui::controller::{FolderStatus, Reveal, RevealState, ScanSummary, Watch, WatchedFolder};
use crate::{Describe, proxy::PORT};

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

/// Leaves something half done on every control that a new page must put back.
fn leave_half_done(window: &mut MainWindow) {
    window.forget_asked = true;
    window.token_note = Some("Token copied to the clipboard.");
    window.form_error = Some("Not a folder".to_owned());
}

fn is_clean(window: &MainWindow) -> bool {
    !window.forget_asked && window.token_note.is_none() && window.form_error.is_none()
}

#[test]
fn a_page_is_found_again_by_the_tag_the_pane_reports() {
    for page in Page::ALL {
        assert_eq!(Page::from_tag(page.tag()), Some(page));
    }
    let mut tags: Vec<&str> = Page::ALL.iter().map(|page| page.tag()).collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), Page::ALL.len(), "two pages share a tag");
    assert_eq!(Page::from_tag("keyed"), None);
    assert_eq!(Page::from_tag(""), None);
    // The pane lists the five feature pages; Settings is its footer.
    assert!(!Page::MENU.contains(&Page::Settings));
    assert_eq!(Page::MENU.len() + 1, Page::ALL.len());
}

#[test]
fn the_window_opens_on_overview() -> Test {
    let (window, _dir) = window()?;
    assert_eq!(window.page, Page::Overview);
    Ok(())
}

#[test]
fn only_protection_asks_for_the_running_apps() -> Test {
    let (mut window, _dir) = window()?;
    assert!(!window.watching_apps());
    window.open_page(Page::Protection);
    assert!(window.watching_apps());
    window.open_page(Page::Settings);
    assert!(!window.watching_apps());
    Ok(())
}

#[test]
fn a_new_page_starts_without_what_the_last_one_left_half_done() -> Test {
    let (mut window, _dir) = window()?;
    window.open_page(Page::Settings);
    leave_half_done(&mut window);
    window.open_page(Page::Vault);
    assert!(is_clean(&window));
    leave_half_done(&mut window);
    window.open_page(Page::Overview);
    assert!(is_clean(&window));
    Ok(())
}

// ---- The real window on the reactor's headless host ----

/// Background work and timers that never run: the window's poll, its loads and its joke timer
/// stay quiet, and a test sends the messages they would have brought.
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

/// The window as the application mounts it, on a recording adapter instead of `WinUI`: nothing is
/// shown. Every view the window builds is reconciled and checked against the contracts of the
/// controls, and the recorded mutations say which text was drawn.
struct Headless {
    host: ComponentHost<RecordingAdapter>,
    window: ComponentSender<Msg>,
    controller: Arc<Controller>,
    /// The number of the last load a dashboard was given, which only has to grow.
    loads: u64,
    dir: TempDir,
}

impl Headless {
    /// Mounts the window on the controller that `controller` makes in a fresh folder, once the
    /// controller has looked at the certificate and the vault.
    fn open(
        controller: impl FnOnce(&TempDir) -> Result<Arc<Controller>, String>,
    ) -> Result<Self, String> {
        Self::open_for(controller, None)
    }

    /// As [`Headless::open`], for a window that the application opens for the scan request
    /// number `reveal`, or for the user when it is `None`.
    fn open_for(
        controller: impl FnOnce(&TempDir) -> Result<Arc<Controller>, String>,
        reveal: Option<u64>,
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
            reveal,
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
            loads: 0,
            dir,
        })
    }

    /// Gives the window `message`, lets it handle it, and returns the text of everything it drew
    /// for it.
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

    /// As [`Headless::poll`], for a controller whose snapshot `change` has altered: what a state
    /// the stub cannot reach would bring (a model that downloads, a scan that runs).
    fn poll_with(&mut self, change: impl FnOnce(&mut Snapshot)) -> Result<Vec<String>, String> {
        let mut snapshot = self.controller.snapshot();
        change(&mut snapshot);
        self.send(Msg::Polled(Some(Box::new(snapshot))))
    }

    /// Everything the window has drawn since it opened: its first page, and what came after.
    fn everything(&self) -> Vec<String> {
        texts(self.host.adapter().batches())
    }

    /// Gives the dashboard of `store` what its load would bring for the folder `at`, read from the
    /// controller as the window reads it, and returns what that drew.
    fn loaded(&mut self, store: Store, at: &Path) -> Result<Vec<String>, String> {
        self.loads += 1;
        let loaded = Loaded::read(&self.controller, store, at, &[], None);
        self.send(Msg::Dash(store, Dash::Loaded(self.loads, Box::new(loaded))))
    }

    /// As [`Headless::loaded`], with the folders `open` read as well and the entry of `file`.
    fn loaded_with(
        &mut self,
        store: Store,
        at: &Path,
        open: &[PathBuf],
        file: Option<&Path>,
    ) -> Result<Vec<String>, String> {
        self.loads += 1;
        let loaded = Loaded::read(&self.controller, store, at, open, file);
        self.send(Msg::Dash(store, Dash::Loaded(self.loads, Box::new(loaded))))
    }

    /// Opens `page` and gives it what the background work would bring: the dashboards' views and
    /// the vault's rows. Returns what was drawn.
    fn go(&mut self, page: Page) -> Result<Vec<String>, String> {
        let mut drawn = self.send(Msg::Nav(page))?;
        match page {
            Page::Inventory => drawn.extend(self.loaded(Store::Inventory, Path::new(""))?),
            Page::Watch => drawn.extend(self.loaded(Store::Watch, Path::new(""))?),
            Page::Vault => drawn.extend(self.send(Msg::VaultLoaded(1, KeyedPage::default()))?),
            Page::Overview | Page::Protection | Page::Settings => {}
        }
        Ok(drawn)
    }

    /// Writes `files` (name and text) to a folder of the test's own, has the controller scan it
    /// into the main inventory, and returns the folder.
    fn scanned(&self, files: &[(&str, &str)]) -> Result<PathBuf, String> {
        let folder = self.dir.0.join("scanned");
        fs::create_dir_all(&folder).describe()?;
        for (name, text) in files {
            fs::write(folder.join(name), text).describe()?;
        }
        // A location, so its files are a folder of the tree and not "Other scans".
        self.controller.submit(Command::Edit(Edit::InventoryRoot {
            path: folder.clone(),
            on: true,
        }));
        self.controller.submit(Command::ScanFiles {
            paths: vec![folder.clone()],
            reveal: false,
        });
        if !self.controller.wait_idle(WAIT) || !self.controller.wait_scans(WAIT) {
            return Err("the scan did not finish".to_owned());
        }
        Ok(folder)
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
                PropertyId::Text
                    | PropertyId::Title
                    | PropertyId::Message
                    | PropertyId::PrimaryButtonText
                    | PropertyId::CloseButtonText
            )
        })
        .filter_map(|property| match &property.value {
            PropertyValue::String(text) => Some(text.to_string()),
            _ => None,
        })
        .collect()
}

/// How many controls of `kind` the batches made.
fn created(batches: &[Vec<Mutation>], kind: ObjectType) -> usize {
    batches
        .iter()
        .flatten()
        .filter(|mutation| matches!(mutation, Mutation::Create { kind: made, .. } if *made == kind))
        .count()
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

/// How many of `drawn` are exactly `text`.
fn times(drawn: &[String], text: &str) -> usize {
    drawn.iter().filter(|drawn| *drawn == text).count()
}

/// Whether the control that shows `text` was last drawn enabled, or `None` when nothing shows it.
/// The text of a button is a label inside it, so the state is the one the label has with all its
/// parents: a control is enabled unless it or a control around it was told otherwise. Of several
/// controls with the same text (a page that was left and came back), the last one drawn counts.
fn enabled(batches: &[Vec<Mutation>], text: &str) -> Option<bool> {
    let mut showing: Vec<ObjectId> = Vec::new();
    let mut told = std::collections::HashMap::new();
    let mut parents = std::collections::HashMap::new();
    for mutation in batches.iter().flatten() {
        match mutation {
            Mutation::SetProperties { object, set, clear } => {
                for property in set.iter() {
                    match (property.id, &property.value) {
                        (PropertyId::Text, PropertyValue::String(shown)) => {
                            showing.retain(|other| other != object);
                            if &**shown == text {
                                showing.push(*object);
                            }
                        }
                        (PropertyId::IsEnabled, PropertyValue::Bool(on)) => {
                            told.insert(*object, *on);
                        }
                        _ => {}
                    }
                }
                if clear.contains(&PropertyId::IsEnabled) {
                    told.remove(object);
                }
            }
            Mutation::Attach { parent, child, .. } | Mutation::Insert { parent, child, .. } => {
                parents.insert(*child, *parent);
            }
            _ => {}
        }
    }
    let mut at = *showing.last()?;
    // A tree is not deeper than the controls it has.
    for _ in 0..=parents.len() {
        if told.get(&at) == Some(&false) {
            return Some(false);
        }
        match parents.get(&at) {
            Some(parent) => at = *parent,
            None => break,
        }
    }
    Some(true)
}

/// What Off says.
const OFF: &str = "Nothing is read or changed, and your Windows proxy settings are your own.";

/// What the Inventory dashboard says while nothing was scanned.
const INVENTORY_EMPTY: &str = "Scan your locations to see which files hold personal data, or right-click a file or folder in Explorer and choose Scan for personal data.";

/// What each page other than Overview must say, with the controller of a fresh install.
fn pages() -> [(Page, &'static [&'static str]); 5] {
    [
        (
            Page::Protection,
            &[
                "Protection",
                "Highlighting",
                "Highlight personal data as you type",
                "Try highlighting before you turn masking on.",
                "Protected sites",
                "Add site",
                "Protected apps",
                "Add app",
            ],
        ),
        (
            Page::Inventory,
            &[
                "Inventory",
                "Where personal data is stored on this PC. Only what you scan is listed.",
                "Scan",
                "Export report",
                "Add and scan",
                "Nothing found yet.",
                "This PC",
                INVENTORY_EMPTY,
            ],
        ),
        (
            Page::Watch,
            &[
                "Watch",
                "Keeps an eye on folders and checks a file again when it changes.",
                "No folders yet. Add one below, or start with the usual ones.",
                "Add folder",
                "Watch is off.",
                "Watched folders",
                "Add a folder above to start watching it.",
            ],
        ),
        (
            Page::Vault,
            &[
                "Vault",
                "Encrypted on this PC with Windows. It remembers which stand-in replaced which value, so replies can be turned back.",
                "Export\u{2026}",
                "Select all",
                "Forget 0",
            ],
        ),
        (
            Page::Settings,
            &[
                "Settings",
                "General",
                "Start piikey when I sign in",
                "Scan for personal data in Explorer",
                "Keep piikey running in the tray when I close the window",
                "Types of personal data",
                "Developer access",
                "Local HTTP API",
                "Copy token",
                "New token",
                "Privacy & data",
                "Data folder",
                "Open folder",
                "About",
                "Source",
                "Report an issue",
                "License",
            ],
        ),
    ]
}

#[test]
fn overview_says_what_piikey_is_doing_in_one_hero_and_a_row_for_each_job() -> Test {
    let ui = Headless::open(stub_controller)?;
    let drawn = ui.everything();
    expect_drawn(
        "Overview",
        &drawn,
        &[
            "Overview",
            "Protection is off",
            OFF,
            "Turn on",
            "What piikey is doing",
            "Masking",
            "Highlighting",
            "Inventory",
            "Watch",
            "Vault",
            "Detection",
            "Model ready",
            "Recent swaps",
            "View all",
            "Turn on protection to start masking.",
            // The pane around it: Settings in its foot, the status in its chip.
            "Settings",
            "Protection off",
        ],
    )?;
    // No tiles, no tabs, nothing of the old window.
    expect_not_drawn(
        "Overview",
        &drawn,
        &["values keyed, all time", "General", "Home", "Keyed values"],
    )
}

#[test]
fn every_page_draws_its_own_content_and_opens_again_from_scratch() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let mut before: &[&str] = &[];
    for (page, wanted) in pages() {
        let drawn = ui.go(page)?;
        expect_drawn(page.title(), &drawn, wanted)?;
        // The page before it is gone: nothing of it is drawn again, nor kept.
        let unique: Vec<&str> = before
            .iter()
            .copied()
            .filter(|text| !wanted.contains(text) && *text != "Protection")
            .collect();
        expect_not_drawn(page.title(), &drawn, &unique)?;
        before = wanted;
    }
    // A page that was left is built anew when it comes back.
    let again = ui.send(Msg::Nav(Page::Protection))?;
    expect_drawn("Protection again", &again, &["Protected sites", "Add site"])
}

#[test]
fn protection_has_no_master_switch_of_its_own() -> Test {
    // The hero of Overview is the one place in the window that turns protection on and off.
    let mut ui = Headless::open(stub_controller)?;
    let overview = created(ui.host.adapter().batches(), ObjectType::ToggleSwitch);
    assert_eq!(overview, 0, "Overview has a button, not a switch");
    let before = ui.host.adapter().batches().len();
    ui.send(Msg::Nav(Page::Protection))?;
    let made = created(
        &ui.host.adapter().batches()[before..],
        ObjectType::ToggleSwitch,
    );
    assert_eq!(made, 0, "Protection made {made} switches");
    Ok(())
}

#[test]
fn settings_shows_what_the_system_answers() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let drawn = ui.send(Msg::Nav(Page::Settings))?;
    let version = format!("piikey {}", env!("CARGO_PKG_VERSION"));
    let proxy = format!("Local proxy: 127.0.0.1:{PORT}, stopped");
    let http = piikey::api::http::url(piikey::policy::DEFAULT_HTTP_PORT);
    expect_drawn(
        "Settings",
        &drawn,
        &[version.as_str(), proxy.as_str(), http.as_str()],
    )?;
    // The types of personal data sit in one collapsed expander per group.
    let group = KIND_GROUPS[0].0;
    assert!(
        drawn.iter().any(|text| text.starts_with(group)),
        "no expander of {group}: {drawn:?}"
    );
    // A section that is only text, and rows that told how to reach what works without the API, are
    // gone; so is the old row that only described closing the window.
    expect_not_drawn(
        "Settings",
        &drawn,
        &[
            "Detection",
            "Detection model",
            "Used by Masking, Highlighting and Inventory.",
            "Model ready",
            "Named pipe",
            "Command line",
            "Closing the window",
        ],
    )?;
    // Nothing is said about a model that is there.
    assert!(
        !drawn.iter().any(|text| text.starts_with("Detection model")),
        "the model is ready and has no row: {drawn:?}"
    );

    // The answer the poll of the window would bring: starting at sign-in.
    ui.send(Msg::StartupLoaded(Some(true)))?;
    Ok(())
}

#[test]
fn the_window_says_everything_in_the_words_of_the_glossary() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    for (page, _) in pages() {
        ui.go(page)?;
    }
    for text in ui.everything() {
        for banned in [
            "PII", "Keyed", "keyed", "program", "Program", "kind", "Kind",
        ] {
            assert!(!text.contains(banned), "{text:?} says {banned:?}");
        }
    }
    Ok(())
}

#[test]
fn without_the_certificate_overview_names_the_one_fix_and_protection_leaves_it_there() -> Test {
    let mut ui = Headless::open(|dir| stub_controller_with(dir, false))?;
    let overview = ui.everything();
    // Nobody asked for protection: it is off, and what stands in its way has one button.
    expect_drawn(
        "Overview",
        &overview,
        &[
            "Protection is off",
            "Protection off",
            "Certificate not installed",
            "Install certificate",
            "Install the certificate first.",
        ],
    )?;
    expect_not_drawn("Overview", &overview, &["Needs attention"])?;

    // Protection does not repeat it: the fix lives on Overview, in one place.
    let protection = ui.send(Msg::Nav(Page::Protection))?;
    expect_drawn(
        "Protection",
        &protection,
        &["Highlighting", "Protected sites"],
    )?;
    expect_not_drawn(
        "Protection",
        &protection,
        &[
            "Certificate",
            "Certificate installed",
            "Certificate not installed",
            "Install certificate",
        ],
    )?;
    Ok(())
}

#[test]
fn the_hero_the_chip_and_the_rows_follow_protection_being_turned_on_and_off() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    ui.controller.submit(Command::SetEnabled(true));
    assert!(ui.controller.wait_idle(WAIT));
    let sentence = Status::of(&ui.controller.snapshot(), None).sentence();
    let on = ui.poll()?;
    expect_drawn(
        "on",
        &on,
        &[
            "Protection is on",
            sentence.as_str(),
            "Turn off",
            "Protection on",
        ],
    )?;
    expect_not_drawn("on", &on, &[OFF])?;

    ui.send(Msg::Toggle(false))?;
    assert!(ui.controller.wait_idle(WAIT));
    let off = ui.poll()?;
    expect_drawn(
        "off again",
        &off,
        &["Protection is off", OFF, "Turn on", "Protection off"],
    )?;
    Ok(())
}

#[test]
fn an_error_shows_once_on_overview_and_once_on_every_other_page() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    ui.controller.notify(Notice::error(
        "Could not start the proxy on 127.0.0.1:8080: port in use",
    ));
    let overview = ui.poll()?;
    expect_drawn(
        "Overview",
        &overview,
        &[
            "Protection needs attention",
            "Needs attention",
            "Could not start the proxy on 127.0.0.1:8080: port in use",
        ],
    )?;
    // The cause is a message bar of the page; the frame's own bar does not say it again.
    assert_eq!(times(&overview, "Something went wrong"), 1, "{overview:?}");

    let vault = ui.send(Msg::Nav(Page::Vault))?;
    assert_eq!(times(&vault, "Something went wrong"), 1, "{vault:?}");
    Ok(())
}

/// The Vault page on a vault of two swapped values, loaded as the search would bring it, and the
/// two values in the order of its rows.
fn two_swaps() -> Result<(Headless, [String; 2]), String> {
    let mut ui = Headless::open(|dir| {
        let controller = stub_controller(dir)?;
        controller
            .engine()
            .run(
                Mode::Anonymize,
                &["mail jan.jansen@acme.nl", "mail piet.pieters@acme.nl"],
            )
            .describe()?;
        Ok(controller)
    })?;
    ui.send(Msg::Nav(Page::Vault))?;
    let page = ui.controller.keyed(&KeyedQuery::default(), VAULT_LIMIT);
    let values: Vec<String> = page
        .items
        .iter()
        .map(|item| item.original.clone())
        .collect();
    let values: [String; 2] = values
        .try_into()
        .map_err(|values: Vec<String>| format!("two values expected, found {values:?}"))?;
    ui.send(Msg::VaultLoaded(1, page))?;
    Ok((ui, values))
}

#[test]
fn the_vault_page_has_select_all_and_a_forget_that_waits_for_a_selection() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let vault = ui.send(Msg::Nav(Page::Vault))?;
    expect_drawn("Vault", &vault, &["Select all", "Forget 0"])?;
    expect_not_drawn("Vault", &vault, &["Manage", "Wipe vault", "Vault file"])?;
    assert_eq!(
        enabled(ui.host.adapter().batches(), "Forget 0"),
        Some(false)
    );
    Ok(())
}

#[test]
fn ticking_rows_and_select_all_count_what_forget_would_forget() -> Test {
    let (mut ui, [first, _]) = two_swaps()?;
    let one = ui.send(Msg::VaultPick(first.clone(), true))?;
    expect_drawn("one row", &one, &["Forget 1"])?;
    assert_eq!(enabled(ui.host.adapter().batches(), "Forget 1"), Some(true));

    let all = ui.send(Msg::VaultPickAll(true))?;
    expect_drawn("select all", &all, &["Forget 2"])?;

    let one = ui.send(Msg::VaultPick(first, false))?;
    expect_drawn("one cleared", &one, &["Forget 1"])?;

    let none = ui.send(Msg::VaultPickAll(false))?;
    expect_drawn("cleared", &none, &["Forget 0"])?;
    assert_eq!(
        enabled(ui.host.adapter().batches(), "Forget 0"),
        Some(false)
    );
    Ok(())
}

/// What the question before forgetting says, for two values.
const ASKED: [&str; 3] = [
    "Forget 2 values?",
    "Their stand-ins will no longer be turned back.",
    "Cancel",
];

#[test]
fn forget_asks_first_and_cancel_keeps_the_vault_and_the_selection() -> Test {
    let (mut ui, _) = two_swaps()?;
    let picked = ui.send(Msg::VaultPickAll(true))?;
    expect_not_drawn("before asking", &picked, &ASKED)?;
    let asked = ui.send(Msg::VaultAskForget)?;
    expect_drawn("asked", &asked, &ASKED)?;

    let cancelled = ui.send(Msg::VaultForget(false))?;
    expect_not_drawn("cancelled", &cancelled, &["Forget 0"])?;
    assert!(ui.controller.wait_idle(WAIT));
    assert_eq!(ui.controller.snapshot().issued, 2);
    // Still selected: asking again is about both values.
    let again = ui.send(Msg::VaultAskForget)?;
    expect_drawn("asked again", &again, &["Forget 2 values?"])?;
    Ok(())
}

#[test]
fn confirming_forget_forgets_the_selected_values_and_empties_the_selection() -> Test {
    let (mut ui, [first, _]) = two_swaps()?;
    ui.send(Msg::VaultPick(first, true))?;
    let asked = ui.send(Msg::VaultAskForget)?;
    expect_drawn("asked", &asked, &["Forget 1 value?"])?;
    let confirmed = ui.send(Msg::VaultForget(true))?;
    expect_drawn("confirmed", &confirmed, &["Forget 0"])?;
    assert!(ui.controller.wait_idle(WAIT));
    assert_eq!(ui.controller.snapshot().issued, 1);
    Ok(())
}

#[test]
fn a_new_result_drops_the_selected_values_it_no_longer_lists() -> Test {
    let (mut ui, [first, _]) = two_swaps()?;
    ui.send(Msg::VaultPickAll(true))?;
    let query = KeyedQuery {
        text: first.clone(),
        ..KeyedQuery::default()
    };
    let page = ui.controller.keyed(&query, VAULT_LIMIT);
    // The search that opening the page started is number 1; the query starts number 2.
    ui.send(Msg::VaultQuery(first))?;
    let drawn = ui.send(Msg::VaultLoaded(2, page))?;
    expect_drawn("narrowed", &drawn, &["Forget 1"])?;
    Ok(())
}

#[test]
fn the_vault_page_lists_what_was_swapped_and_what_forget_does() -> Test {
    let mut ui = Headless::open(|dir| {
        let controller = stub_controller(dir)?;
        controller
            .engine()
            .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
            .describe()?;
        Ok(controller)
    })?;
    ui.send(Msg::Nav(Page::Vault))?;
    let page = ui.controller.keyed(&KeyedQuery::default(), VAULT_LIMIT);
    let drawn = ui.send(Msg::VaultLoaded(1, page))?;
    expect_drawn(
        "the list",
        &drawn,
        &["jan.jansen@acme.nl", "1 value, most recent first"],
    )?;
    Ok(())
}

#[test]
fn the_rows_of_overview_each_tell_their_own_state() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let drawn = ui.poll_with(|snap| {
        snap.inventory_totals = (51, 711);
        snap.issued = 22;
        snap.policy.highlight = Highlight::Always;
        snap.highlight_paused = true;
        snap.model = Model::Skipped;
        snap.policy.watch = true;
        snap.policy.watch_folders = vec![PathBuf::from(r"C:\Users\me\Downloads")];
        snap.watch.totals = (5, 34);
    })?;
    expect_drawn(
        "rows",
        &drawn,
        &[
            "711 found in 51 files",
            "34 found in 5 files",
            "22 values remembered",
            "Paused",
            "Patterns only (model skipped)",
        ],
    )?;
    let scanning = ui.poll_with(|snap| snap.scan = Some((3_412, 20_100)))?;
    expect_drawn("scan", &scanning, &["Scanning\u{2026} 3,412 of 20,100"])
}

#[test]
fn the_first_run_screen_replaces_the_pages_and_follows_the_download() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let downloading = ui.poll_with(|snap| {
        snap.model = Model::Downloading {
            done: 159_600_000,
            total: 380_000_000,
        };
    })?;
    expect_drawn(
        "downloading",
        &downloading,
        &["Getting piikey ready", "160 MB of 380 MB"],
    )?;
    // The joke on the screen changes with the timer; it is rich text, which the recording of
    // plain texts does not hold, so all that can be told is that the window takes it.
    ui.send(Msg::Flavor)?;

    // A download that failed says why, with the two ways on.
    let failed = ui.poll_with(|snap| snap.model = Model::Failed("no network".to_owned()))?;
    expect_drawn(
        "failed",
        &failed,
        &[
            "Download failed",
            "no network",
            "Try again",
            "Continue without it",
        ],
    )?;

    // Once the model is there the pages come back, on the page the window was on.
    let back = ui.poll()?;
    expect_drawn("back", &back, &["Overview", "What piikey is doing"])
}

#[test]
fn settings_offers_to_download_a_model_that_was_skipped() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    ui.send(Msg::Nav(Page::Settings))?;
    let skipped = ui.poll_with(|snap| snap.model = Model::Skipped)?;
    expect_drawn(
        "skipped",
        &skipped,
        &[
            "Detection model not installed",
            "Names and addresses are found only by patterns.",
            "Download model",
        ],
    )?;
    expect_not_drawn("skipped", &skipped, &["Model ready", "Detection"])?;
    // Once it is there again, the row goes.
    ui.send(Msg::RetryModel)?;
    Ok(())
}

#[test]
fn the_certificate_button_waits_for_nothing_but_its_own_install() -> Test {
    let mut ui = Headless::open(|dir| stub_controller_with(dir, false))?;
    let button = "Install certificate";
    assert_eq!(enabled(ui.host.adapter().batches(), button), Some(true));
    // The controller is far behind: commands queued, a scan that waits for the model to load. None
    // of it is the fix's business, and the fix is what lets protection start.
    ui.poll_with(|snap| {
        snap.pending = 3;
        snap.scan = Some((0, 0));
    })?;
    assert_eq!(enabled(ui.host.adapter().batches(), button), Some(true));
    // Pressed, it holds still until the controller has finished: the install is asked once.
    ui.send(Msg::InstallCertificate)?;
    assert!(ui.controller.wait_idle(WAIT));
    assert_eq!(enabled(ui.host.adapter().batches(), button), Some(false));
    ui.poll_with(|snap| snap.pending = 1)?;
    assert_eq!(enabled(ui.host.adapter().batches(), button), Some(false));
    // The stub still does not trust the certificate once it is done, so the button is back.
    ui.poll()?;
    assert_eq!(enabled(ui.host.adapter().batches(), button), Some(true));
    Ok(())
}

#[test]
fn a_scan_that_waits_for_the_model_leaves_the_rest_of_the_page_alone() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    ui.send(Msg::Nav(Page::Inventory))?;
    // What is on screen while the model loads for the first time: a scan that has found no files
    // yet, and a controller with commands to go.
    let drawn = ui.poll_with(|snap| {
        snap.pending = 4;
        snap.scan = Some((0, 0));
        snap.policy.inventory_roots = vec![PathBuf::from(r"C:\Docs"), PathBuf::from(r"C:\Mail")];
    })?;
    expect_drawn(
        "scan",
        &drawn,
        &["Looking for files\u{2026}", r"C:\Docs", r"C:\Mail"],
    )?;
    // The buttons of the locations are not the scan's business.
    assert_eq!(enabled(ui.host.adapter().batches(), "Remove"), Some(true));
    Ok(())
}

#[test]
fn a_poll_that_brings_nothing_new_builds_nothing() -> Test {
    let mut ui = Headless::open(|dir| {
        let controller = stub_controller(dir)?;
        controller
            .engine()
            .run(
                Mode::Anonymize,
                &["mail jan.jansen@acme.nl and piet@acme.nl"],
            )
            .describe()?;
        Ok(controller)
    })?;
    for page in Page::ALL {
        if page == Page::Vault {
            ui.send(Msg::Nav(page))?;
            let found = ui.controller.keyed(&KeyedQuery::default(), VAULT_LIMIT);
            ui.send(Msg::VaultLoaded(1, found))?;
        } else {
            ui.go(page)?;
        }
        // A scan without files yet, and folders to watch: the busiest the pages get.
        let mut snapshot = ui.controller.snapshot();
        snapshot.scan = Some((0, 0));
        snapshot.policy.inventory_roots =
            vec![PathBuf::from(r"C:\Docs"), PathBuf::from(r"C:\Mail")];
        ui.send(Msg::Polled(Some(Box::new(snapshot.clone()))))?;
        let before = ui.host.adapter().batches().len();
        snapshot.version += 1;
        ui.send(Msg::Polled(Some(Box::new(snapshot))))?;
        // Only the handlers of the controls are new, they are made again with each look. A control
        // that was made or replaced would play its entrance again: the fade of a list's rows,
        // the slide of a switch.
        let rebuilt: Vec<String> = ui.host.adapter().batches()[before..]
            .iter()
            .flatten()
            .filter(|mutation| !matches!(mutation, Mutation::SetEvents { .. }))
            .map(|mutation| format!("{mutation:?}"))
            .collect();
        if !rebuilt.is_empty() {
            return Err(format!("{page:?}: an unchanged poll rebuilt {rebuilt:?}"));
        }
    }
    Ok(())
}

/// What `batches` made, replaced, moved or removed: the mutations that are neither a change of a
/// control's properties nor of its handlers.
fn rebuilt(batches: &[Vec<Mutation>]) -> Vec<String> {
    batches
        .iter()
        .flatten()
        .filter(|mutation| {
            !matches!(
                mutation,
                Mutation::SetEvents { .. } | Mutation::SetProperties { .. }
            )
        })
        .map(|mutation| format!("{mutation:?}"))
        .collect()
}

/// Shows the window a scan at `scan` over two watched folders; what that rebuilt.
fn scan_look(ui: &mut Headless, scan: (u64, u64)) -> Result<Vec<String>, String> {
    let before = ui.host.adapter().batches().len();
    ui.poll_with(|snap| {
        snap.scan = Some(scan);
        snap.policy.inventory_roots = vec![PathBuf::from(r"C:\Docs"), PathBuf::from(r"C:\Mail")];
    })?;
    Ok(rebuilt(&ui.host.adapter().batches()[before..]))
}

#[test]
fn a_scan_that_counts_files_rebuilds_nothing_but_its_own_progress() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    ui.send(Msg::Nav(Page::Inventory))?;
    scan_look(&mut ui, (0, 0))?;
    // The ring makes way for the bar: its controls are made and the ring's are retired, and no
    // more. The lists keep their rows: rows that were made again would play their entrance again
    // with every tick, and look washed out for as long as the scan lasts.
    let counted = scan_look(&mut ui, (10, 100))?;
    assert!(
        counted.len() <= 4,
        "the ring made way for the bar: {counted:?}"
    );
    for done in [20, 60, 100] {
        let ticked = scan_look(&mut ui, (done, 100))?;
        assert!(ticked.is_empty(), "{done} of 100 files: {ticked:?}");
    }
    Ok(())
}

/// A window on a controller whose inventory holds what `files` hold, in a folder that is one of
/// its locations.
fn scanned_window(files: &[(&str, &str)]) -> Result<(Headless, PathBuf), String> {
    let ui = Headless::open(stub_controller)?;
    let folder = ui.scanned(files)?;
    Ok((ui, folder))
}

#[test]
fn the_inventory_dashboard_lists_what_was_scanned_in_the_tree_the_legend_the_map_and_the_details()
-> Test {
    let (mut ui, folder) = scanned_window(&[
        ("a.txt", "mail jan.jansen@acme.nl and piet@acme.nl"),
        ("b.txt", "call jan.jansen@acme.nl"),
    ])?;
    ui.send(Msg::Nav(Page::Inventory))?;
    let drawn = ui.loaded(Store::Inventory, Path::new(""))?;
    expect_drawn(
        "the dashboard",
        &drawn,
        &[
            "This PC",
            "All types",
            "Email",
            "The most personal data first",
            "Found",
            "scanned",
            "a.txt",
            "3 found in 2 files",
        ],
    )?;
    // A folder row selected: the details offer what applies to a folder.
    let folder_row = ui.send(Msg::Dash(
        Store::Inventory,
        Dash::Select(folder.clone(), Origin::Tree),
    ))?;
    expect_drawn(
        "a folder",
        &folder_row,
        &["Show only this folder", "Show in Explorer", "Scan this"],
    )?;
    // A tile of the map selected: the details offer what applies to a file.
    let file = folder.join("a.txt");
    let picked = ui.send(Msg::Dash(
        Store::Inventory,
        Dash::Select(file.clone(), Origin::Map),
    ))?;
    expect_drawn(
        "a file",
        &picked,
        &[
            "Open",
            "Show what was found",
            "Make masked copy",
            "Scan this",
        ],
    )?;
    // The load that follows brings the entry of the file: when it was scanned, and how big.
    let entry = ui.loaded_with(Store::Inventory, Path::new(""), &[folder], Some(&file))?;
    assert!(
        entry.iter().any(|text| text.starts_with("Last scanned ")),
        "{entry:?}"
    );
    // One type shown: its chip is the one that stays lit and the tree counts only it.
    let email = ui.send(Msg::Dash(
        Store::Inventory,
        Dash::Type(Some(piikey::detect::EntityKind::Email)),
    ))?;
    expect_not_drawn("a type", &email, &["Show what was found"])
}

#[test]
fn a_wide_window_lists_the_types_in_a_column_next_to_the_map() -> Test {
    let (mut ui, _folder) = scanned_window(&[("a.txt", "mail jan.jansen@acme.nl")])?;
    ui.send(Msg::Resized(WindowSize {
        width: 1_920.0,
        height: 1_080.0,
    }))?;
    ui.send(Msg::Nav(Page::Inventory))?;
    let drawn = ui.loaded(Store::Inventory, Path::new(""))?;
    expect_drawn(
        "the wide dashboard",
        &drawn,
        &[
            "All types",
            "Email",
            "1 file",
            "The most personal data first",
        ],
    )
}

#[test]
fn the_watch_page_shows_its_folders_what_they_are_doing_and_what_was_found_there() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    ui.go(Page::Watch)?;
    let folder = PathBuf::from(r"C:\Users\me\Downloads");
    let drawn = ui.poll_with(|snap| {
        snap.policy.watch = true;
        snap.policy.watch_folders = vec![folder.clone()];
        snap.watch = Watch {
            folders: vec![WatchedFolder {
                path: folder.clone(),
                status: FolderStatus::Watching,
                last_change: None,
            }],
            scanning: Some((3, 10)),
            totals: (0, 0),
        };
    })?;
    expect_drawn(
        "watching",
        &drawn,
        &[
            r"C:\Users\me\Downloads",
            "Scanning 3 of 10",
            "Remove",
            "Looking at 3 of 10 files\u{2026}",
        ],
    )?;
    // Switching it on asks the controller, which saves it.
    ui.send(Msg::Watch(true))?;
    assert!(ui.controller.wait_idle(WAIT));
    assert!(ui.controller.snapshot().policy.watch);
    Ok(())
}

#[test]
fn a_scan_that_was_asked_for_shows_its_progress_and_its_result_in_a_dialog() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let folder = ui.dir.0.join("docs");
    let reveal = |state: RevealState| Reveal {
        seq: 1,
        paths: vec![folder.clone()],
        at: folder.clone(),
        select: None,
        state,
    };
    let scanning = ui.poll_with(|snap| snap.reveal = Some(reveal(RevealState::Scanning)))?;
    expect_drawn(
        "scanning",
        &scanning,
        &["Scanning\u{2026}", "Looking for files\u{2026}", "Close"],
    )?;
    let summary = ScanSummary {
        files: 3,
        files_with_data: 2,
        hits: 7,
        counts: vec![(piikey::detect::EntityKind::Email, 7)],
        unread: 0,
    };
    let done =
        ui.poll_with(|snap| snap.reveal = Some(reveal(RevealState::Done(summary.clone()))))?;
    expect_drawn(
        "done",
        &done,
        &[
            "Scan result",
            "7 found in 2 files",
            "3 files scanned",
            "Email",
            "Show in Inventory",
        ],
    )?;
    // "Show in Inventory" goes to the page and puts the result away: it is not shown again.
    let shown = ui.send(Msg::ReportShow)?;
    expect_drawn("show", &shown, &["Add and scan"])?;
    let again =
        ui.poll_with(|snap| snap.reveal = Some(reveal(RevealState::Done(summary.clone()))))?;
    expect_not_drawn("put away", &again, &["Scan result"])?;
    // A scan that found nothing has nothing to show in the inventory.
    let nothing = ScanSummary {
        hits: 0,
        files_with_data: 0,
        counts: Vec::new(),
        ..summary
    };
    let none = ui.poll_with(|snap| {
        snap.reveal = Some(Reveal {
            seq: 2,
            ..reveal(RevealState::Done(nothing.clone()))
        });
    })?;
    expect_drawn("nothing", &none, &["No personal data found", "Close"])?;
    expect_not_drawn("nothing", &none, &["Show in Inventory"])
}

#[test]
fn a_window_that_opens_for_a_scan_shows_its_result_and_one_that_opens_for_the_user_does_not() -> Test
{
    let scan = |dir: &TempDir| -> Result<Arc<Controller>, String> {
        let controller = stub_controller(dir)?;
        let folder = dir.0.join("docs");
        fs::create_dir_all(&folder).describe()?;
        fs::write(folder.join("a.txt"), "mail jan.jansen@acme.nl").describe()?;
        controller.submit(Command::ScanFiles {
            paths: vec![folder],
            reveal: true,
        });
        if !controller.wait_idle(WAIT) || !controller.wait_scans(WAIT) {
            return Err("the scan did not finish".to_owned());
        }
        Ok(controller)
    };
    let ui = Headless::open_for(scan, Some(1))?;
    expect_drawn(
        "opened for the scan",
        &ui.everything(),
        &["Scan result", "1 found in 1 file", "Show in Inventory"],
    )?;
    let ui = Headless::open_for(scan, None)?;
    expect_not_drawn("opened by the user", &ui.everything(), &["Scan result"])
}

#[test]
fn what_was_found_in_a_file_is_listed_on_request_and_dropped_when_the_list_closes() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let file = PathBuf::from(r"C:\Docs\a.pdf");
    let asked = ui.send(Msg::Dash(Store::Inventory, Dash::Found(file.clone())))?;
    expect_drawn(
        "asked",
        &asked,
        &["a.pdf", "Reading the file\u{2026}", "Close"],
    )?;
    let finding = Finding {
        kind: piikey::detect::EntityKind::Email,
        value: "jan.jansen@acme.nl".into(),
        snippet: "write to jan.jansen@acme.nl today".into(),
    };
    let listed = ui.send(Msg::FindingsLoaded(file, Ok(vec![finding])))?;
    expect_drawn(
        "listed",
        &listed,
        &[
            "jan.jansen@acme.nl",
            "write to jan.jansen@acme.nl today",
            "Email",
        ],
    )?;
    // Closed, the values are gone from the window: asking again reads them again.
    ui.send(Msg::FindingsClosed)?;
    let again = ui.send(Msg::Dash(
        Store::Inventory,
        Dash::Found(PathBuf::from(r"C:\Docs\a.pdf")),
    ))?;
    expect_drawn("again", &again, &["Reading the file\u{2026}"])?;
    expect_not_drawn("again", &again, &["jan.jansen@acme.nl"])
}

#[test]
fn keeping_piikey_in_the_tray_when_the_window_closes_is_a_setting() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    assert!(ui.controller.snapshot().policy.background, "on by default");
    ui.send(Msg::Nav(Page::Settings))?;
    ui.send(Msg::Background(false))?;
    assert!(ui.controller.wait_idle(WAIT));
    assert!(!ui.controller.snapshot().policy.background);
    assert!(!ui.controller.runs_in_background());
    Ok(())
}

#[test]
fn protection_starts_with_highlighting_then_the_sites_and_the_apps() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let drawn = ui.send(Msg::Nav(Page::Protection))?;
    let at = |text: &str| drawn.iter().position(|drawn| drawn == text);
    let order: Vec<Option<usize>> = ["Highlighting", "Protected sites", "Protected apps"]
        .iter()
        .map(|text| at(text))
        .collect();
    assert!(
        order.iter().all(Option::is_some) && order.windows(2).all(|pair| pair[0] < pair[1]),
        "{order:?} in {drawn:?}"
    );
    Ok(())
}

#[test]
fn inventory_lists_its_locations_like_watch_lists_its_folders() -> Test {
    let (mut ui, folder) = scanned_window(&[
        ("a.txt", "mail jan.jansen@acme.nl and piet@acme.nl"),
        ("b.txt", "call jan.jansen@acme.nl"),
    ])?;
    let before = ui.send(Msg::Nav(Page::Inventory))?;
    // A row for each location, with what the inventory holds of it before the load says more.
    expect_drawn("locations", &before, &["Remove", "Nothing found yet"])?;
    expect_not_drawn("no flyout", &before, &["Locations (3)"])?;
    let drawn = ui.loaded(Store::Inventory, Path::new(""))?;
    let path = folder.display().to_string();
    expect_drawn(
        "the scanned location",
        &drawn,
        &[path.as_str(), "3 found in 2 files"],
    )?;
    // Taking a location off the list asks the controller, which saves it.
    ui.send(Msg::RemoveLocation(folder))?;
    assert!(ui.controller.wait_idle(WAIT));
    assert!(
        !ui.controller
            .snapshot()
            .policy
            .inventory_roots
            .iter()
            .any(|root| root.display().to_string() == path)
    );
    Ok(())
}

#[test]
fn picking_a_tile_of_another_folder_makes_a_new_tree_and_never_moves_the_rows_of_one() -> Test {
    // WinUI fails fast (0xC000027B) when the rows of a list that has a selection change places,
    // which is what listing the way to the second tile's folder first did.
    let mut ui = Headless::open(stub_controller)?;
    let docs = ui.dir.0.join("docs");
    let mail = ui.dir.0.join("mail");
    for (folder, text) in [
        (&docs, "mail jan.jansen@acme.nl"),
        (&mail, "mail a@acme.nl b@acme.nl c@acme.nl"),
    ] {
        fs::create_dir_all(folder).describe()?;
        fs::write(folder.join("a.txt"), text).describe()?;
        ui.controller.submit(Command::Edit(Edit::InventoryRoot {
            path: folder.clone(),
            on: true,
        }));
    }
    ui.controller.submit(Command::ScanFiles {
        paths: vec![docs.clone(), mail.clone()],
        reveal: false,
    });
    if !ui.controller.wait_idle(WAIT) || !ui.controller.wait_scans(WAIT) {
        return Err("the scan did not finish".to_owned());
    }
    ui.send(Msg::Nav(Page::Inventory))?;
    ui.loaded(Store::Inventory, Path::new(""))?;
    // The folder that holds more is listed first; a tile of the other one is picked, so its way
    // comes first: the rows would have to change places.
    let first = mail.join("a.txt");
    let second = docs.join("a.txt");
    ui.send(Msg::Dash(
        Store::Inventory,
        Dash::Select(first, Origin::Map),
    ))?;
    ui.loaded_with(
        Store::Inventory,
        Path::new(""),
        std::slice::from_ref(&mail),
        None,
    )?;
    let before = ui.host.adapter().batches().len();
    ui.send(Msg::Dash(
        Store::Inventory,
        Dash::Select(second, Origin::Map),
    ))?;
    let made = created(&ui.host.adapter().batches()[before..], ObjectType::ListView);
    assert_eq!(made, 1, "the rows changed places in a list that stayed");
    // The same rows again keep their list.
    let before = ui.host.adapter().batches().len();
    ui.loaded_with(Store::Inventory, Path::new(""), &[mail, docs], None)?;
    let made = created(&ui.host.adapter().batches()[before..], ObjectType::ListView);
    assert_eq!(made, 0, "rows that only came made a new list");
    Ok(())
}
