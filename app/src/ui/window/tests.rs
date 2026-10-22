use piikey::{
    api::reply::Device,
    detect::{KIND_GROUPS, Mode},
    service::default_pipe,
};
use windows_reactor::{
    ComponentHost, ComponentSender, ComponentServices, ComponentTimerRegistration, Key, Mutation,
    ObjectId, PropertyId, PropertyValue, RecordingAdapter, component,
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

/// Leaves something half done on every control that a new page must put back.
fn leave_half_done(window: &mut MainWindow) {
    window.wipe_armed = true;
    window.token_note = Some("Token copied to the clipboard.");
    window.form_error = Some("Not a folder".to_owned());
}

fn is_clean(window: &MainWindow) -> bool {
    !window.wipe_armed && window.token_note.is_none() && window.form_error.is_none()
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
    // The pane lists the four feature pages; Settings is its footer.
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

#[test]
fn wiping_the_vault_takes_two_clicks_and_another_page_in_between_starts_over() -> Test {
    let (mut window, _dir) = window()?;
    let controller = Arc::clone(&window.input.controller.0);
    controller
        .engine()
        .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
        .describe()?;
    controller.submit(Command::Refresh);
    assert!(controller.wait_idle(WAIT));
    assert_eq!(controller.snapshot().issued, 1);

    window.open_page(Page::Vault);
    window.click_wipe();
    assert!(window.wipe_armed);
    assert!(controller.wait_idle(WAIT));
    assert_eq!(controller.snapshot().issued, 1, "one click must not wipe");

    // Looking at another page disarms the button: the next click only arms it again.
    window.open_page(Page::Overview);
    window.open_page(Page::Vault);
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

#[test]
fn the_device_file_is_read_as_the_app_and_a_person_write_it() {
    assert_eq!(parse_device(b"cpu"), Some(Device::Cpu));
    assert_eq!(parse_device(b"hybrid\r\n"), Some(Device::Hybrid));
    // What an older version wrote for a GPU that won.
    assert_eq!(parse_device(b" gpu "), Some(Device::Hybrid));
    assert_eq!(parse_device(b"\xEF\xBB\xBFcpu\r\n"), Some(Device::Cpu));
    // `echo cpu > device.cfg` in Windows PowerShell 5.1: UTF-16 with a byte-order mark.
    let powershell = [
        0xFF, 0xFE, 0x63, 0x00, 0x70, 0x00, 0x75, 0x00, 0x0D, 0x00, 0x0A, 0x00,
    ];
    assert_eq!(parse_device(&powershell), Some(Device::Cpu));
    let big_endian = [0xFE, 0xFF, 0x00, 0x63, 0x00, 0x70, 0x00, 0x75];
    assert_eq!(parse_device(&big_endian), Some(Device::Cpu));
    assert_eq!(parse_device(b""), None);
    assert_eq!(parse_device(b"tpu"), None);
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

/// What each page other than Overview must say, with the controller of a fresh install.
fn pages() -> [(Page, &'static [&'static str]); 4] {
    [
        (
            Page::Protection,
            &[
                "Protection",
                "Certificate",
                "Certificate installed",
                "Protected sites",
                "Add site",
                "Protected apps",
                "Add app",
                "Highlighting",
                "Highlight personal data as you type",
                "Try highlighting before you turn masking on.",
            ],
        ),
        (
            Page::Inventory,
            &[
                "Inventory",
                "Where personal data is stored on this PC",
                "Turn on inventory",
                "Map",
                "Export report",
                "Rescan",
                "Watched folders",
                "Add folder",
                "Left out",
                "Nothing is left out.",
                "Explorer menu",
                "Scan for personal data",
            ],
        ),
        (
            Page::Vault,
            &[
                "Vault",
                "Encrypted on this PC with Windows. It remembers which stand-in replaced which value, so replies can be turned back.",
                "Export\u{2026}",
                "Manage",
                "0 records",
                "Wipe vault",
            ],
        ),
        (
            Page::Settings,
            &[
                "Settings",
                "General",
                "Start piikey when I sign in",
                "Closing the window",
                "Detection",
                "Detection model",
                "Model ready",
                "Used by Masking, Highlighting and Inventory.",
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
        let mut drawn = ui.send(Msg::Nav(page))?;
        // What the background work would bring: the treemap's level and the vault's rows.
        match page {
            Page::Inventory => drawn.extend(ui.send(Msg::InvLoaded(1, InventoryView::default()))?),
            Page::Vault => drawn.extend(ui.send(Msg::VaultLoaded(1, KeyedPage::default()))?),
            _ => {}
        }
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
fn settings_shows_what_the_system_answers() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let drawn = ui.send(Msg::Nav(Page::Settings))?;
    let version = format!("piikey {}", env!("CARGO_PKG_VERSION"));
    let proxy = format!("Local proxy: 127.0.0.1:{PORT}, stopped");
    let pipe = default_pipe();
    let http = piikey::api::http::url(piikey::policy::DEFAULT_HTTP_PORT);
    expect_drawn(
        "Settings",
        &drawn,
        &[
            version.as_str(),
            proxy.as_str(),
            pipe.as_str(),
            http.as_str(),
        ],
    )?;
    // The types of personal data sit in one collapsed expander per group.
    let group = KIND_GROUPS[0].0;
    assert!(
        drawn.iter().any(|text| text.starts_with(group)),
        "no expander of {group}: {drawn:?}"
    );

    // The answers the poll of the window would bring: starting at sign-in, and where the model runs.
    ui.send(Msg::StartupLoaded(Some(true)))?;
    let device = ui.send(Msg::DeviceLoaded(Some(Device::Hybrid)))?;
    expect_drawn("the device", &device, &["Runs on CPU and GPU"])
}

#[test]
fn the_window_says_everything_in_the_words_of_the_glossary() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    for (page, _) in pages() {
        ui.send(Msg::Nav(page))?;
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
fn without_the_certificate_overview_and_protection_name_the_one_fix() -> Test {
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

    let protection = ui.send(Msg::Nav(Page::Protection))?;
    expect_drawn(
        "Protection",
        &protection,
        &["Certificate not installed", "Install certificate"],
    )?;
    expect_not_drawn("Protection", &protection, &["Certificate installed"])?;
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

#[test]
fn the_vault_page_shows_the_second_click_and_another_page_takes_it_back() -> Test {
    let mut ui = Headless::open(|dir| {
        let controller = stub_controller(dir)?;
        controller
            .engine()
            .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
            .describe()?;
        Ok(controller)
    })?;
    let vault = ui.send(Msg::Nav(Page::Vault))?;
    expect_drawn("Vault", &vault, &["1 record", "Wipe vault"])?;

    let armed = ui.send(Msg::WipeVault)?;
    expect_drawn("first click", &armed, &["Click again to wipe the record"])?;

    // Another page in between puts the button back.
    ui.send(Msg::Nav(Page::Settings))?;
    let vault = ui.send(Msg::Nav(Page::Vault))?;
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
    })?;
    expect_drawn(
        "rows",
        &drawn,
        &[
            "711 found in 51 files",
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
        &["Patterns only (model skipped)", "Download model"],
    )?;
    expect_not_drawn("skipped", &skipped, &["Model ready"])
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
        snap.policy.inventory = true;
        snap.policy.inventory_roots = vec![PathBuf::from(r"C:\Docs"), PathBuf::from(r"C:\Mail")];
    })?;
    expect_drawn(
        "scan",
        &drawn,
        &["Looking for files\u{2026}", r"C:\Docs", r"C:\Mail"],
    )?;
    // The buttons of the folders are not the scan's business.
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
        ui.send(Msg::Nav(page))?;
        if page == Page::Vault {
            let found = ui.controller.keyed(&KeyedQuery::default(), VAULT_LIMIT);
            ui.send(Msg::VaultLoaded(1, found))?;
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
        snap.policy.inventory = true;
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
