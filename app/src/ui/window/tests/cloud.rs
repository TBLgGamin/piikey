//! Cloud locations in the window: their rows, their node in the tree, the Browse cloud dialog and
//! the findings of a cloud file.
//!
//! The window runs on the reactor's headless host, where background work never runs: what a
//! listing, a load or a reading would bring is sent by the test, as the messages the window would
//! have got.

use std::collections::HashMap;

use piikey::{
    detect::EntityKind,
    inventory::{Entry, Node, Rest, Status, Tile, Tiles, TypeTotal},
    sources::{Provider, SignIn},
};
use windows_reactor::ImageSource;

use super::*;
use crate::ui::{assets, goto};

/// The top of a Microsoft 365 account.
const ACCOUNT: &str = r"\\Microsoft 365\jan@acme.com";
/// A folder of that account.
const DOCS: &str = r"\\Microsoft 365\jan@acme.com\Documents";
/// A file in that folder.
const FILE: &str = r"\\Microsoft 365\jan@acme.com\Documents\clients.docx";
/// The button beside the Browse buttons that opens the dialog.
const BROWSE_CLOUD: &str = "Browse cloud\u{2026}";
/// The title of that dialog.
const TITLE: &str = "Choose a cloud folder to scan";
/// What the dialog says while a listing is on its way.
const LOADING: &str = "Loading folders\u{2026}";
/// What the button of a cloud row says before it was pressed.
const CLOUD_HINT: &str =
    "Open in your browser. piikey cannot jump to the value there: search for it.";
/// What it says once the browser has opened the file.
const CLOUD_OPENED_ONLY: &str =
    "Opened in your browser. piikey cannot jump to the value there: search for it.";
/// What a service that cannot be reached says.
const UNREACHABLE: &str =
    "piikey cannot reach Microsoft 365. Check the internet connection and try again.";

/// A controller whose data folder holds two accounts: Microsoft 365 for `jan@acme.com` and
/// Dropbox for `jan@home.nl`.
fn with_accounts(dir: &TempDir) -> Result<Arc<Controller>, String> {
    let microsoft = SignIn::MicrosoftDelegated {
        tenant: "organizations".to_owned(),
        client_id: "client".to_owned(),
    };
    sources::add_account(
        &dir.0,
        Provider::Microsoft365,
        "jan@acme.com",
        microsoft,
        None,
    )
    .describe()?;
    let dropbox = SignIn::DropboxDelegated {
        app_key: "key".to_owned(),
    };
    sources::add_account(&dir.0, Provider::Dropbox, "jan@home.nl", dropbox, None).describe()?;
    stub_controller(dir)
}

/// A window on [`with_accounts`], on the Inventory page.
fn inventory_with_accounts() -> Result<Headless, String> {
    let mut ui = Headless::open(with_accounts)?;
    let accounts = ui.controller.snapshot().accounts.len();
    if accounts != 2 {
        return Err(format!("the controller knows {accounts} accounts, not 2"));
    }
    ui.go(Page::Inventory)?;
    Ok(ui)
}

/// How many batches the window has drawn so far: where what comes next starts.
fn mark(ui: &Headless) -> usize {
    ui.host.adapter().batches().len()
}

/// What the window drew since `mark`.
fn since(ui: &Headless, mark: usize) -> &[Vec<Mutation>] {
    ui.host.adapter().batches().get(mark..).unwrap_or_default()
}

/// The properties `batches` set, as `(object, property)`.
fn properties(
    batches: &[Vec<Mutation>],
) -> impl Iterator<Item = (ObjectId, &windows_reactor::Property)> {
    batches
        .iter()
        .flatten()
        .filter_map(|mutation| match mutation {
            Mutation::SetProperties { object, set, .. } => Some((*object, set.iter())),
            _ => None,
        })
        .flat_map(|(object, set)| set.map(move |property| (object, property)))
}

/// How many images of the logo of `provider` the batches made, in either theme's variant.
fn logos(batches: &[Vec<Mutation>], provider: Provider) -> usize {
    let wanted = [false, true].map(|dark| ImageSource::svg(assets::provider_logo(provider, dark)));
    properties(batches)
        .filter(|(_, property)| {
            property.id == PropertyId::Source
                && matches!(&property.value, PropertyValue::ImageSource(source) if wanted.contains(source))
        })
        .count()
}

/// The glyphs of the icons the batches made.
fn glyphs(batches: &[Vec<Mutation>]) -> Vec<String> {
    strings(batches, &[PropertyId::Glyph])
}

/// Whether a dialog is open, as the batches leave it.
fn dialog_open(batches: &[Vec<Mutation>]) -> bool {
    let (mut shown, mut open) = (false, false);
    for mutation in batches.iter().flatten() {
        match mutation {
            Mutation::SetContentDialog { dialog, .. } => {
                shown = dialog.is_some();
                if !shown {
                    open = false;
                }
            }
            Mutation::SetContentDialogOpen { open: now, .. } => open = *now,
            _ => {}
        }
    }
    shown && open
}

/// What each control was last told about its boolean property `id`; a control whose property was
/// cleared is not in it.
fn told(batches: &[Vec<Mutation>], id: PropertyId) -> HashMap<ObjectId, bool> {
    let mut told = HashMap::new();
    for mutation in batches.iter().flatten() {
        if let Mutation::SetProperties { object, set, clear } = mutation {
            for property in set.iter() {
                if let (true, PropertyValue::Bool(on)) = (property.id == id, &property.value) {
                    told.insert(*object, *on);
                }
            }
            if clear.contains(&id) {
                told.remove(object);
            }
        }
    }
    told
}

/// Whether the primary button of the newest dialog is enabled: it is, unless it was told
/// otherwise. `None` when no dialog was made.
fn primary_enabled(batches: &[Vec<Mutation>]) -> Option<bool> {
    let dialog = batches
        .iter()
        .flatten()
        .filter_map(|mutation| match mutation {
            Mutation::Create {
                object,
                kind: ObjectType::ContentDialog,
            } => Some(*object),
            _ => None,
        })
        .next_back()?;
    Some(
        told(batches, PropertyId::IsPrimaryButtonEnabled)
            .get(&dialog)
            .copied()
            .unwrap_or(true),
    )
}

/// Whether the control that was last given the screen reader name `name` is enabled (it is,
/// unless it was told otherwise), or `None` when no control has that name.
fn enabled_by_name(batches: &[Vec<Mutation>], name: &str) -> Option<bool> {
    let named = properties(batches)
        .filter(|(_, property)| {
            property.id == PropertyId::AutomationName
                && matches!(&property.value, PropertyValue::String(text) if &**text == name)
        })
        .map(|(object, _)| object)
        .last()?;
    Some(
        told(batches, PropertyId::IsEnabled)
            .get(&named)
            .copied()
            .unwrap_or(true),
    )
}

/// Gives the dashboard `loaded`, as a load would, and returns what that drew.
fn bring(ui: &mut Headless, loaded: Loaded) -> Result<Vec<String>, String> {
    ui.loads += 1;
    let load = ui.loads;
    ui.send(Msg::Dash(Dash::Loaded(load, Box::new(loaded))))
}

/// A folder (`is_dir`) or a file of the tree that holds `hits` email addresses.
fn node(path: &str, name: &str, is_dir: bool, hits: u32) -> Node {
    Node {
        path: PathBuf::from(path),
        name: name.to_owned(),
        is_dir,
        hits: u64::from(hits),
        files: 1,
        counts: vec![(EntityKind::Email, hits)],
    }
}

/// What a load brings when the inventory holds, besides a drive and a network share, the account
/// `jan@acme.com`, its folder `Documents` and the file `clients.docx` in it, which was scanned.
fn tree() -> Loaded {
    let entry = Entry {
        path: PathBuf::from(FILE),
        size: 2048,
        modified: 1,
        scanned: 1_700_000_000,
        status: Status::Ok,
        counts: vec![(EntityKind::Email, 3)],
        hash: None,
    };
    Loaded {
        at: PathBuf::new(),
        map_at: PathBuf::new(),
        levels: HashMap::from([
            (
                PathBuf::new(),
                vec![
                    // Not in Explorer's order: the tree puts them there.
                    node(r"\\nas\share", r"\\nas\share", true, 2),
                    node(ACCOUNT, ACCOUNT, true, 3),
                    node(r"C:\", "C:", true, 4),
                ],
            ),
            (
                PathBuf::from(ACCOUNT),
                vec![node(DOCS, "Documents", true, 3)],
            ),
            (
                PathBuf::from(DOCS),
                vec![node(FILE, "clients.docx", false, 3)],
            ),
        ]),
        places: Vec::new(),
        tiles: Tiles {
            tiles: vec![Tile {
                path: PathBuf::from(FILE),
                size: 2048,
                hits: 3,
                counts: vec![(EntityKind::Email, 3)],
            }],
            rest: Rest::default(),
        },
        totals: vec![TypeTotal {
            kind: EntityKind::Email,
            hits: 9,
            files: 3,
        }],
        entry: Some(entry),
    }
}

/// A window with the tree of [`tree`] on its dashboard and `path` selected: what that drew, and
/// where in the window's batches it starts.
fn selected(path: &str) -> Result<(Headless, Vec<String>, usize), String> {
    let mut ui = inventory_with_accounts()?;
    bring(&mut ui, tree())?;
    let from = mark(&ui);
    let drawn = ui.send(Msg::Dash(Dash::Select(PathBuf::from(path), Origin::Tree)))?;
    Ok((ui, drawn, from))
}

#[test]
fn browse_cloud_is_offered_only_when_an_account_is_connected() -> Test {
    let mut none = Headless::open(stub_controller)?;
    let drawn = none.go(Page::Inventory)?;
    expect_drawn(
        "no account",
        &drawn,
        &["Browse folder\u{2026}", "Browse file\u{2026}"],
    )?;
    expect_not_drawn("no account", &drawn, &[BROWSE_CLOUD])?;

    let mut ui = Headless::open(with_accounts)?;
    let drawn = ui.go(Page::Inventory)?;
    expect_drawn(
        "an account",
        &drawn,
        &["Browse folder\u{2026}", "Browse file\u{2026}", BROWSE_CLOUD],
    )?;
    Ok(())
}

#[test]
fn a_cloud_location_shows_its_logo_its_path_and_how_it_stands() -> Test {
    let mut ui = inventory_with_accounts()?;
    let cloud = PathBuf::from(DOCS);
    let local = PathBuf::from(r"C:\Users\me\Downloads");
    let from = mark(&ui);
    let drawn = ui.poll_with(|snap| {
        snap.policy.inventory_roots = vec![cloud.clone(), local.clone()];
        snap.policy.monitored_roots = vec![cloud.clone()];
        snap.watch = Watch {
            folders: vec![WatchedFolder {
                path: cloud.clone(),
                status: FolderStatus::Unavailable("Sign in to Microsoft 365 again.".to_owned()),
                last_change: None,
            }],
            scanning: None,
        };
    })?;
    // The path as the row of a folder on this PC has it, and what is wrong in plain words.
    expect_drawn(
        "the rows",
        &drawn,
        &[
            DOCS_SHOWN,
            r"C:\Users\me\Downloads",
            "Nothing found yet \u{b7} Cannot monitor: Sign in to Microsoft 365 again.",
            "Nothing found yet",
            "Monitoring",
            "Not monitored",
        ],
    )?;
    assert_eq!(times(&drawn, "Remove"), 2, "{drawn:?}");
    // The provider's logo stands where the folder icon of the local row does; a problem is a
    // caution sign beside the logo, which is never recoloured.
    let batches = since(&ui, from);
    assert_eq!(logos(batches, Provider::Microsoft365), 1);
    assert_eq!(logos(batches, Provider::Dropbox), 0);
    let icons = glyphs(batches);
    assert_eq!(times(&icons, "\u{E7BA}"), 1, "{icons:?}");
    assert_eq!(times(&icons, "\u{E8B7}"), 1, "{icons:?}");
    Ok(())
}

#[test]
fn a_cloud_row_and_a_local_row_are_the_same_widgets_but_for_the_icon() -> Test {
    let made = |root: PathBuf| -> Result<(Vec<usize>, usize, usize), String> {
        let mut ui = inventory_with_accounts()?;
        let from = mark(&ui);
        ui.poll_with(|snap| snap.policy.inventory_roots = vec![root.clone()])?;
        let batches = since(&ui, from);
        let counts = [
            ObjectType::Grid,
            ObjectType::StackPanel,
            ObjectType::TextBlock,
            ObjectType::ToggleSwitch,
            ObjectType::Button,
        ]
        .map(|kind| created(batches, kind))
        .to_vec();
        Ok((
            counts,
            created(batches, ObjectType::Image),
            created(batches, ObjectType::FontIcon),
        ))
    };
    let (cloud, cloud_images, cloud_icons) = made(PathBuf::from(DOCS))?;
    let (local, local_images, local_icons) = made(PathBuf::from(r"C:\Users\me\Downloads"))?;
    assert_eq!(cloud, local);
    assert_eq!(cloud_images, local_images + 1);
    assert_eq!(cloud_icons + 1, local_icons);
    Ok(())
}

#[test]
fn an_account_is_a_node_of_the_tree_with_its_logo_and_name_after_the_drives() -> Test {
    let mut ui = inventory_with_accounts()?;
    let from = mark(&ui);
    let drawn = bring(&mut ui, tree())?;
    // The readable name, the provider in the tooltip: not the path of the account.
    expect_drawn(
        "the top of the tree",
        &drawn,
        &[
            "C:",
            "jan@acme.com",
            r"\\nas\share",
            "Microsoft 365: jan@acme.com",
        ],
    )?;
    expect_not_drawn("no path for a name", &drawn, &[ACCOUNT])?;
    // Explorer's order: the drives first, then shares and accounts by name.
    let at = |name: &str| drawn.iter().position(|text| text == name);
    assert!(at("C:") < at("jan@acme.com"), "{drawn:?}");
    assert!(at("jan@acme.com") < at(r"\\nas\share"), "{drawn:?}");
    assert_eq!(logos(since(&ui, from), Provider::Microsoft365), 1);
    // What is below the account is an ordinary folder and file.
    let from = mark(&ui);
    let folders = ui.send(Msg::Dash(Dash::Toggle(PathBuf::from(ACCOUNT))))?;
    expect_drawn("a folder of the account", &folders, &["Documents"])?;
    let files = ui.send(Msg::Dash(Dash::Toggle(PathBuf::from(DOCS))))?;
    expect_drawn("a file of the folder", &files, &["clients.docx"])?;
    assert_eq!(logos(since(&ui, from), Provider::Microsoft365), 0);
    Ok(())
}

#[test]
fn the_details_of_a_cloud_file_open_its_web_page_and_have_no_explorer_and_no_masked_copy() -> Test {
    let (ui, drawn, from) = selected(FILE)?;
    expect_drawn(
        "a cloud file",
        &drawn,
        &[
            "clients.docx",
            FILE_SHOWN,
            "3 found",
            "Open",
            "Show what was found",
        ],
    )?;
    expect_not_drawn(
        "a cloud file",
        &drawn,
        &[
            "Show in Explorer",
            "Make masked copy",
            "Show only this folder",
        ],
    )?;
    // What a scan knows of a local file, the details say of this one.
    assert!(
        drawn
            .iter()
            .any(|text| text.starts_with("Last scanned ") && text.ends_with("2.0 KB")),
        "{drawn:?}"
    );
    // The path line starts with the logo of the provider.
    assert_eq!(logos(since(&ui, from), Provider::Microsoft365), 1);
    Ok(())
}

#[test]
fn the_details_of_a_cloud_folder_offer_what_was_found_and_no_explorer() -> Test {
    for (path, title) in [(DOCS, "Documents"), (ACCOUNT, "jan@acme.com")] {
        let (_ui, drawn, _) = selected(path)?;
        expect_drawn(
            path,
            &drawn,
            &[title, "Show only this folder", "Show what was found"],
        )?;
        expect_not_drawn(
            path,
            &drawn,
            &["Show in Explorer", "Make masked copy", "Open"],
        )?;
    }
    Ok(())
}

#[test]
fn a_cloud_item_cannot_be_shown_in_explorer_or_copied_masked_even_when_asked() -> Test {
    let mut ui = inventory_with_accounts()?;
    for ask in [
        Msg::Dash(Dash::Show(PathBuf::from(FILE))),
        Msg::Dash(Dash::Mask(PathBuf::from(FILE))),
    ] {
        ui.send(ask)?;
        let said = ui.poll()?;
        expect_drawn(
            "refused",
            &said,
            &[
                "A file in the cloud is not on this PC: it cannot be shown in Explorer or copied masked.",
            ],
        )?;
        ui.send(Msg::DismissNotice)?;
        ui.poll()?;
    }
    Ok(())
}

/// The Browse cloud dialog, driven by hand. A listing waits on the service, so it runs in the
/// background and never here: the test says what each one brought, under the number the window
/// gave it (every listing it asks for takes the next one).
struct Dialog {
    ui: Headless,
    seq: u64,
}

impl Dialog {
    fn new() -> Result<Self, String> {
        Ok(Self {
            ui: inventory_with_accounts()?,
            seq: 0,
        })
    }

    /// The top of the first account.
    fn root(&self) -> Result<PathBuf, String> {
        self.ui
            .controller
            .snapshot()
            .accounts
            .first()
            .map(|view| view.account.root())
            .ok_or_else(|| "no account".to_owned())
    }

    /// A message of the dialog that asks for a listing.
    fn ask(&mut self, message: CloudMsg) -> Result<Vec<String>, String> {
        self.seq += 1;
        self.ui.send(Msg::Cloud(message))
    }

    /// What the latest listing brought.
    fn listed(&mut self, folders: &[PathBuf]) -> Result<Vec<String>, String> {
        self.arrived(self.seq, Ok(folders.to_vec()))
    }

    /// What the listing number `seq` brought.
    fn arrived(
        &mut self,
        seq: u64,
        listed: Result<Vec<PathBuf>, String>,
    ) -> Result<Vec<String>, String> {
        self.ui.send(Msg::Cloud(CloudMsg::Listed(seq, listed)))
    }

    fn open(&self) -> bool {
        dialog_open(self.ui.host.adapter().batches())
    }

    fn primary(&self) -> Option<bool> {
        primary_enabled(self.ui.host.adapter().batches())
    }

    fn up(&self) -> Option<bool> {
        enabled_by_name(self.ui.host.adapter().batches(), "Up")
    }

    /// The locations of the inventory, once the controller is done with what it was asked.
    fn locations(&self) -> Result<Vec<PathBuf>, String> {
        if !self.ui.controller.wait_idle(WAIT) || !self.ui.controller.wait_scans(WAIT) {
            return Err("the controller did not settle".to_owned());
        }
        Ok(self.ui.controller.snapshot().policy.inventory_roots)
    }
}

#[test]
fn the_dialog_opens_at_the_top_of_the_first_account_and_lists_its_folders_by_name() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    let from = mark(&dialog.ui);
    let opened = dialog.ask(CloudMsg::Open)?;
    expect_drawn(
        "opened",
        &opened,
        &[TITLE, "Choose this folder", "Cancel", LOADING, &read(&root)],
    )?;
    assert!(dialog.open());
    // Two accounts: a list to pick one from. At the top of an account there is no folder to
    // choose and no way up.
    let named = names(since(&dialog.ui, from));
    assert!(named.iter().any(|name| name == "Account"), "{named:?}");
    assert_eq!(dialog.primary(), Some(false));
    assert_eq!(dialog.up(), Some(false));

    let from = mark(&dialog.ui);
    let listed = dialog.listed(&[root.join("Documents"), root.join("archive")])?;
    expect_drawn("the folders", &listed, &["archive", "Documents"])?;
    expect_not_drawn("no longer waiting", &listed, &[LOADING])?;
    let at = |name: &str| listed.iter().position(|text| text == name);
    assert!(at("archive") < at("Documents"), "{listed:?}");
    // The drives or sites of an account carry its logo.
    assert_eq!(logos(since(&dialog.ui, from), Provider::Microsoft365), 2);
    Ok(())
}

#[test]
fn a_folder_opens_into_its_folders_and_up_goes_back_one_step_at_a_time() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    let (docs, clients) = (
        root.join("Documents"),
        root.join("Documents").join("Clients"),
    );
    dialog.ask(CloudMsg::Open)?;
    dialog.listed(std::slice::from_ref(&docs))?;

    let entered = dialog.ask(CloudMsg::Enter(docs.clone()))?;
    expect_drawn("entered", &entered, &[&read(&docs), LOADING])?;
    assert_eq!(dialog.primary(), Some(true));
    assert_eq!(dialog.up(), Some(true));
    // Below the top the rows are folders, not the logo.
    let from = mark(&dialog.ui);
    let inside = dialog.listed(std::slice::from_ref(&clients))?;
    expect_drawn("a folder", &inside, &["Clients"])?;
    assert_eq!(logos(since(&dialog.ui, from), Provider::Microsoft365), 0);

    dialog.ask(CloudMsg::Enter(clients.clone()))?;
    let empty = dialog.listed(&[])?;
    expect_drawn("nothing there", &empty, &["No folders here."])?;
    assert_eq!(dialog.primary(), Some(true));

    // Up: the folder above, and at the first level the top of the account.
    let up = dialog.ask(CloudMsg::Up)?;
    expect_drawn("up", &up, &[&read(&docs)])?;
    assert_eq!(dialog.up(), Some(true));
    let top = dialog.ask(CloudMsg::Up)?;
    expect_drawn("the top", &top, &[&read(&root)])?;
    assert_eq!(dialog.up(), Some(false));
    assert_eq!(dialog.primary(), Some(false));
    Ok(())
}

#[test]
fn a_listing_that_comes_late_for_a_folder_that_was_left_is_ignored() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    dialog.ask(CloudMsg::Open)?;
    dialog.listed(&[root.join("Documents"), root.join("Archive")])?;
    dialog.ask(CloudMsg::Enter(root.join("Documents")))?;
    let old = dialog.seq;
    dialog.ask(CloudMsg::Enter(root.join("Archive")))?;
    let late = dialog.arrived(old, Ok(vec![root.join("Documents").join("Stale")]))?;
    expect_not_drawn("a late listing", &late, &["Stale"])?;
    let fresh = dialog.listed(&[root.join("Archive").join("Fresh")])?;
    expect_drawn("the listing asked for last", &fresh, &["Fresh"])?;
    // A listing for a dialog that is shut is not wanted either.
    dialog.ui.send(Msg::Cloud(CloudMsg::Close))?;
    let shut = dialog.listed(&[root.join("Archive").join("Later")])?;
    expect_not_drawn("a shut dialog", &shut, &["Later"])
}

#[test]
fn a_listing_that_fails_says_why_and_try_again_asks_for_it_once_more() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    dialog.ask(CloudMsg::Open)?;
    let failed = dialog.arrived(dialog.seq, Err(UNREACHABLE.to_owned()))?;
    expect_drawn("failed", &failed, &[UNREACHABLE, "Try again"])?;
    expect_not_drawn("failed", &failed, &[LOADING])?;
    assert_eq!(dialog.primary(), Some(false));
    let retry = dialog.ask(CloudMsg::Retry)?;
    expect_drawn("asked again", &retry, &[LOADING])?;
    let listed = dialog.listed(&[root.join("Documents")])?;
    expect_drawn("it worked", &listed, &["Documents"])?;
    expect_not_drawn("it worked", &listed, &["Try again"])
}

#[test]
fn another_account_is_picked_from_the_list_and_starts_at_its_top() -> Test {
    let mut dialog = Dialog::new()?;
    dialog.ask(CloudMsg::Open)?;
    let microsoft = dialog.root()?;
    dialog.listed(&[microsoft.join("Documents")])?;
    // The one that is on show again, and one that is not there, ask for nothing.
    let same = dialog.ui.send(Msg::Cloud(CloudMsg::Account(0)))?;
    assert!(same.is_empty(), "{same:?}");
    let none = dialog.ui.send(Msg::Cloud(CloudMsg::Account(9)))?;
    assert!(none.is_empty(), "{none:?}");

    let from = mark(&dialog.ui);
    let dropbox = PathBuf::from(r"\\Dropbox\jan@home.nl");
    let picked = dialog.ask(CloudMsg::Account(1))?;
    expect_drawn("the second account", &picked, &[&read(&dropbox), LOADING])?;
    assert_eq!(dialog.primary(), Some(false));
    let listed = dialog.listed(&[dropbox.join("Apps"), dropbox.join("Work")])?;
    expect_drawn("its folders", &listed, &["Apps", "Work"])?;
    let batches = since(&dialog.ui, from);
    assert_eq!(logos(batches, Provider::Dropbox), 2);
    assert_eq!(logos(batches, Provider::Microsoft365), 0);
    Ok(())
}

#[test]
fn choosing_a_folder_adds_it_as_a_location_and_shuts_the_dialog() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    let docs = root.join("Documents");
    dialog.ask(CloudMsg::Open)?;
    dialog.listed(std::slice::from_ref(&docs))?;
    dialog.ask(CloudMsg::Enter(docs.clone()))?;
    dialog.listed(&[])?;
    assert!(dialog.locations()?.is_empty());
    dialog.ui.send(Msg::Cloud(CloudMsg::Choose))?;
    assert!(!dialog.open());
    assert_eq!(dialog.locations()?, [docs]);
    Ok(())
}

#[test]
fn cancelling_adds_nothing_and_neither_does_choosing_at_the_top_of_an_account() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    dialog.ask(CloudMsg::Open)?;
    dialog.listed(&[root.join("Documents")])?;
    assert!(dialog.open());
    dialog.ui.send(Msg::Cloud(CloudMsg::Close))?;
    assert!(!dialog.open());
    assert!(dialog.locations()?.is_empty());
    // The top of an account is no folder: the button is off, and a message that comes anyway
    // only shuts the dialog.
    dialog.ask(CloudMsg::Open)?;
    assert!(dialog.open());
    dialog.ui.send(Msg::Cloud(CloudMsg::Choose))?;
    assert!(!dialog.open());
    assert!(dialog.locations()?.is_empty());
    Ok(())
}

#[test]
fn the_dialog_shuts_when_the_account_it_looks_at_is_disconnected() -> Test {
    let mut dialog = Dialog::new()?;
    dialog.ask(CloudMsg::Open)?;
    assert!(dialog.open());
    dialog.ui.poll_with(|snap| snap.accounts.clear())?;
    assert!(!dialog.open());
    // Nothing is left to browse.
    let drawn = dialog.ui.send(Msg::Cloud(CloudMsg::Open))?;
    expect_not_drawn("no account", &drawn, &[TITLE])?;
    assert!(!dialog.open());
    Ok(())
}

/// A window whose findings view holds one value of the cloud file [`FILE`], its rows made.
fn cloud_findings() -> Result<Headless, String> {
    let mut ui = inventory_with_accounts()?;
    ui.send(Msg::Dash(Dash::Found(PathBuf::from(FILE))))?;
    let listed = FindingFiles {
        files: vec![FindingFile {
            path: PathBuf::from(FILE),
            label: "clients.docx".to_owned(),
        }],
        left_out: 0,
    };
    ui.send(Msg::FindingsListed(1, listed))?;
    let read = vec![(
        PathBuf::from(FILE),
        Ok(vec![found(
            EntityKind::Email,
            "jan.jansen@acme.nl",
            "write to jan.jansen@acme.nl today",
            Location::Line {
                line: 3,
                column: 10,
            },
        )]),
    )];
    ui.send(Msg::FindingsRead(1, read))?;
    Ok(ui)
}

#[test]
fn a_cloud_findings_row_says_it_opens_in_the_browser_and_that_is_as_far_as_it_goes() -> Test {
    let mut ui = cloud_findings()?;
    let rows = ui.realize(1)?;
    expect_drawn(
        "the row",
        &rows,
        &["jan.jansen@acme.nl", "line 3", CLOUD_HINT],
    )?;
    expect_not_drawn("the row", &rows, &[OPEN_AT_THIS_PLACE, OPENED_ONLY])?;
    // While it opens the row shows a ring; the page opened, the tooltip says what was done.
    let from = mark(&ui);
    ui.send(Msg::FindingsOpen(0))?;
    assert!(created(since(&ui, from), ObjectType::ProgressRing) >= 1);
    let opened = ui.send(Msg::FindingsOpened(0, goto::Outcome::Opened))?;
    expect_drawn("opened", &opened, &[CLOUD_OPENED_ONLY])?;
    expect_not_drawn("opened", &opened, &[OPENED_ONLY])
}

#[test]
fn a_row_of_a_file_on_this_pc_keeps_its_own_tooltip() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    findings_view(&mut ui)?;
    let rows = ui.realize(3)?;
    expect_drawn("a local row", &rows, &[OPEN_AT_THIS_PLACE])?;
    expect_not_drawn("a local row", &rows, &[CLOUD_HINT])
}

#[test]
fn opening_a_cloud_row_asks_for_its_web_page_and_never_for_a_file_on_this_pc() -> Test {
    let dir = TempDir::new()?;
    let controller = with_accounts(&dir)?;
    let target = goto::Target {
        file: PathBuf::from(FILE),
        value: "jan.jansen@acme.nl".to_owned(),
        place: None,
    };
    // The stub has no cloud to ask for the page: the answer is the reason it gives. A file on
    // this PC would have been handed to Windows, which says something else.
    let refused = super::super::findings::open_row(&controller, &target)
        .err()
        .ok_or("the row opened without a web page")?;
    assert!(refused.contains("the stub has no cloud"), "{refused}");
    Ok(())
}

#[test]
fn the_cloud_screens_say_everything_in_the_words_of_the_glossary() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    // The dialog: its steps and a failure.
    dialog.ask(CloudMsg::Open)?;
    dialog.listed(&[root.join("Documents")])?;
    dialog.ask(CloudMsg::Enter(root.join("Documents")))?;
    dialog.arrived(dialog.seq, Err(UNREACHABLE.to_owned()))?;
    dialog.ask(CloudMsg::Retry)?;
    dialog.listed(&[])?;
    dialog.ui.send(Msg::Cloud(CloudMsg::Close))?;
    // The rows of locations, the tree and the details of an account, a folder and a file.
    let mut ui = dialog.ui;
    let cloud = PathBuf::from(DOCS);
    ui.poll_with(|snap| {
        snap.policy.inventory_roots = vec![cloud.clone()];
        snap.policy.monitored_roots = vec![cloud.clone()];
        snap.watch = Watch {
            folders: vec![WatchedFolder {
                path: cloud.clone(),
                status: FolderStatus::Unavailable("Sign in to Microsoft 365 again.".to_owned()),
                last_change: None,
            }],
            scanning: None,
        };
    })?;
    bring(&mut ui, tree())?;
    ui.send(Msg::Dash(Dash::Toggle(PathBuf::from(ACCOUNT))))?;
    for path in [ACCOUNT, DOCS, FILE] {
        ui.send(Msg::Dash(Dash::Select(PathBuf::from(path), Origin::Tree)))?;
    }
    // The findings of the file, and the tooltip of its row.
    ui.send(Msg::Dash(Dash::Found(PathBuf::from(FILE))))?;
    let listed = FindingFiles {
        files: vec![FindingFile {
            path: PathBuf::from(FILE),
            label: "clients.docx".to_owned(),
        }],
        left_out: 0,
    };
    ui.send(Msg::FindingsListed(1, listed))?;
    let read = vec![(
        PathBuf::from(FILE),
        Ok(vec![found(
            EntityKind::Email,
            "jan.jansen@acme.nl",
            "write to jan.jansen@acme.nl today",
            Location::Line { line: 1, column: 1 },
        )]),
    )];
    ui.send(Msg::FindingsRead(1, read))?;
    ui.realize(1)?;
    ui.send(Msg::FindingsOpen(0))?;
    ui.send(Msg::FindingsOpened(0, goto::Outcome::Opened))?;
    let drawn = ui.everything();
    clean("the cloud screens", &drawn)?;
    expect_drawn(
        "the cloud screens",
        &drawn,
        &[TITLE, LOADING, "Try again", CLOUD_HINT, CLOUD_OPENED_ONLY],
    )?;
    for text in drawn {
        for banned in [
            "PII",
            "Keyed",
            "keyed",
            "program",
            "Program",
            "kind",
            "Kind",
            "Watch",
            "watch",
            "OAuth",
            "token",
            "Token",
            "authenticate",
            "HTTP",
        ] {
            assert!(!text.contains(banned), "{text:?} says {banned:?}");
        }
    }
    Ok(())
}

/// Another file in the same folder as [`FILE`].
const OTHER: &str = r"\\Microsoft 365\jan@acme.com\Documents\other.docx";
/// [`DOCS`] as a person reads it.
const DOCS_SHOWN: &str = "jan@acme.com \u{203a} Documents";
/// [`FILE`] as a person reads it.
const FILE_SHOWN: &str = "jan@acme.com \u{203a} Documents \u{203a} clients.docx";

/// Fails when a text still holds the inventory's own address of a cloud item (`\\Provider\...`):
/// a person is never shown that.
fn clean(step: &str, drawn: &[String]) -> Test {
    // A network share of this PC (`\\nas\share`, in the fixtures) is no cloud item.
    let found = drawn
        .iter()
        .find(|text| text.replace(r"\\nas\share", "").contains(r"\\"));
    match found {
        Some(text) => Err(format!(
            "{step}: {text:?} shows the address of a cloud item"
        )),
        None => Ok(()),
    }
}

/// [`clean`] for everything the window drew so far, and every name it gave a control for a screen
/// reader.
fn clean_all(step: &str, ui: &Headless) -> Test {
    clean(step, &ui.everything())?;
    clean(step, &names(ui.host.adapter().batches()))
}

/// A cloud path as a person reads it.
fn read(path: &Path) -> String {
    sources::display_path(path).unwrap_or_default()
}

#[test]
fn a_cloud_location_row_reads_as_the_account_and_its_folders() -> Test {
    let mut ui = inventory_with_accounts()?;
    let cloud = PathBuf::from(DOCS);
    let drawn = ui.poll_with(|snap| {
        snap.policy.inventory_roots = vec![cloud.clone()];
        snap.policy.monitored_roots = vec![cloud.clone()];
    })?;
    expect_drawn("the row", &drawn, &[DOCS_SHOWN])?;
    clean("the row", &drawn)?;
    let named = names(ui.host.adapter().batches());
    for name in [
        format!("Monitor {DOCS_SHOWN}"),
        format!("Remove {DOCS_SHOWN}"),
    ] {
        assert!(named.contains(&name), "{name:?} is not in {named:?}");
    }
    clean_all("the row", &ui)
}

#[test]
fn the_details_of_cloud_items_read_as_the_account_and_name_its_provider() -> Test {
    for path in [FILE, DOCS, ACCOUNT] {
        let (ui, drawn, _) = selected(path)?;
        expect_drawn(
            path,
            &drawn,
            &[read(Path::new(path)).as_str(), "Microsoft 365"],
        )?;
        clean(path, &drawn)?;
        clean_all(path, &ui)?;
    }
    Ok(())
}

#[test]
fn the_breadcrumb_of_a_cloud_folder_reads_as_the_account_and_its_folders() -> Test {
    let mut ui = inventory_with_accounts()?;
    bring(&mut ui, tree())?;
    let top = ui.send(Msg::Dash(Dash::Enter(PathBuf::from(ACCOUNT))))?;
    expect_drawn("an account", &top, &["This PC", "jan@acme.com"])?;
    clean("an account", &top)?;
    let inside = ui.send(Msg::Dash(Dash::Enter(PathBuf::from(DOCS))))?;
    expect_drawn("a folder", &inside, &["jan@acme.com", "Documents"])?;
    clean("a folder", &inside)?;
    clean_all("the breadcrumb", &ui)
}

#[test]
fn the_tree_and_the_map_never_show_the_address_of_a_cloud_item() -> Test {
    let mut ui = inventory_with_accounts()?;
    bring(&mut ui, tree())?;
    ui.send(Msg::Dash(Dash::Toggle(PathBuf::from(ACCOUNT))))?;
    ui.send(Msg::Dash(Dash::Toggle(PathBuf::from(DOCS))))?;
    let drawn = ui.everything();
    // The tooltip of a folder of the tree says where it is as a person reads it.
    expect_drawn("tooltips", &drawn, &[DOCS_SHOWN, FILE_SHOWN])?;
    clean_all("the tree", &ui)
}

#[test]
fn the_findings_of_cloud_files_name_them_as_the_account_and_their_folders() -> Test {
    let mut ui = inventory_with_accounts()?;
    let header = ui.send(Msg::Dash(Dash::Found(PathBuf::from(FILE))))?;
    expect_drawn("the header", &header, &[FILE_SHOWN])?;
    clean("the header", &header)?;
    let listed = FindingFiles {
        files: vec![
            FindingFile {
                path: PathBuf::from(FILE),
                label: "clients.docx".to_owned(),
            },
            FindingFile {
                path: PathBuf::from(OTHER),
                label: "other.docx".to_owned(),
            },
        ],
        left_out: 0,
    };
    ui.send(Msg::FindingsListed(1, listed))?;
    let value = |file: &str, text: &str| {
        (
            PathBuf::from(file),
            Ok(vec![found(
                EntityKind::Email,
                text,
                text,
                Location::Line { line: 1, column: 1 },
            )]),
        )
    };
    ui.send(Msg::FindingsRead(
        1,
        vec![
            value(FILE, "jan.jansen@acme.nl"),
            value(OTHER, "piet@acme.nl"),
        ],
    ))?;
    let rows = ui.realize(2)?;
    expect_drawn("rows", &rows, &["clients.docx", "other.docx"])?;
    // The tooltip of a file's name is its place as a person reads it.
    expect_drawn("tooltips", &ui.everything(), &[FILE_SHOWN])?;
    clean("rows", &rows)?;
    clean_all("the findings", &ui)
}

#[test]
fn the_result_dialog_of_a_cloud_scan_names_what_was_scanned_as_a_person_reads_it() -> Test {
    let mut ui = inventory_with_accounts()?;
    let paths = vec![PathBuf::from(FILE), PathBuf::from(OTHER)];
    let scanning = ui.poll_with(|snap| {
        snap.reveal = Some(Reveal {
            seq: 1,
            paths: paths.clone(),
            state: RevealState::Scanning,
        });
        snap.scan = Some((0, 2));
        snap.scan_reading = vec![piikey::inventory::Reading {
            path: PathBuf::from(FILE),
            busy: None,
        }];
    })?;
    expect_drawn(
        "scanning",
        &scanning,
        &[
            &format!("{FILE_SHOWN} and 1 other item"),
            "clients.docx",
            FILE_SHOWN,
        ],
    )?;
    clean("scanning", &scanning)?;
    clean_all("the result", &ui)
}

#[test]
fn the_browse_cloud_dialog_reads_paths_as_the_account_and_its_folders() -> Test {
    let mut dialog = Dialog::new()?;
    let root = dialog.root()?;
    let docs = root.join("Documents");
    let opened = dialog.ask(CloudMsg::Open)?;
    expect_drawn("the top", &opened, &["jan@acme.com"])?;
    clean("the top", &opened)?;
    dialog.listed(std::slice::from_ref(&docs))?;
    let inside = dialog.ask(CloudMsg::Enter(docs))?;
    expect_drawn("a folder", &inside, &[DOCS_SHOWN])?;
    clean("a folder", &inside)?;
    clean_all("the dialog", &dialog.ui)
}

/// A controller whose data folder holds the pretend account of a debug build: a Box account
/// called `Example cloud`.
#[cfg(debug_assertions)]
fn with_fake(dir: &TempDir) -> Result<Arc<Controller>, String> {
    let sign_in = SignIn::BoxApp {
        client_id: "example".to_owned(),
        subject: piikey::sources::BoxSubject::Enterprise("0".to_owned()),
    };
    sources::add_account(
        &dir.0,
        Provider::Box,
        "Example cloud",
        sign_in,
        Some("example"),
    )
    .describe()?;
    stub_controller(dir)
}

#[cfg(debug_assertions)]
#[test]
fn the_pretend_account_never_shows_the_word_box_or_the_address_of_its_items() -> Test {
    const TOP: &str = r"\\Box\Example cloud";
    const FOLDER: &str = r"\\Box\Example cloud\Shared\Clients";
    const CSV: &str = r"\\Box\Example cloud\Shared\Clients\contacts.csv";
    let mut ui = Headless::open(with_fake)?;
    ui.go(Page::Inventory)?;
    let folder = PathBuf::from(FOLDER);
    ui.poll_with(|snap| {
        snap.policy.inventory_roots = vec![folder.clone()];
        snap.policy.monitored_roots = vec![folder.clone()];
    })?;
    let level = |path: &str, name: &str, is_dir: bool| node(path, name, is_dir, 2);
    let loaded = Loaded {
        at: PathBuf::new(),
        map_at: PathBuf::new(),
        levels: HashMap::from([
            (PathBuf::new(), vec![level(TOP, TOP, true)]),
            (PathBuf::from(TOP), vec![level(FOLDER, "Clients", true)]),
            (
                PathBuf::from(FOLDER),
                vec![level(CSV, "contacts.csv", false)],
            ),
        ]),
        ..tree()
    };
    bring(&mut ui, loaded)?;
    ui.send(Msg::Dash(Dash::Toggle(PathBuf::from(TOP))))?;
    ui.send(Msg::Dash(Dash::Toggle(folder)))?;
    for path in [TOP, FOLDER, CSV] {
        ui.send(Msg::Dash(Dash::Select(PathBuf::from(path), Origin::Tree)))?;
    }
    ui.send(Msg::Dash(Dash::Enter(PathBuf::from(FOLDER))))?;
    // The dialog: the account's top and a folder.
    ui.send(Msg::Cloud(CloudMsg::Open))?;
    ui.send(Msg::Cloud(CloudMsg::Listed(
        1,
        Ok(vec![PathBuf::from(FOLDER)]),
    )))?;
    ui.send(Msg::Cloud(CloudMsg::Enter(PathBuf::from(FOLDER))))?;
    ui.send(Msg::Cloud(CloudMsg::Close))?;
    let drawn = ui.everything();
    expect_drawn(
        "the pretend account",
        &drawn,
        &[
            "Example cloud \u{203a} Shared \u{203a} Clients",
            "Example cloud \u{203a} Shared \u{203a} Clients \u{203a} contacts.csv",
            "Example provider: Example cloud",
            "Example provider",
        ],
    )?;
    for text in drawn.iter().chain(&names(ui.host.adapter().batches())) {
        assert!(!text.contains("Box"), "{text:?} says Box");
    }
    clean_all("the pretend account", &ui)
}
