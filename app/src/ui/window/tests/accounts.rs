//! The Connected accounts section of Settings and the Add account dialog, in the window.

use std::{fs, path::PathBuf, sync::Arc, thread::sleep, time::Duration};

use piikey::sources::{Accounts, Provider, SignIn, add_account};
use windows_reactor::{Mutation, ObjectType, PropertyId, PropertyValue};

use super::*;
use crate::ui::{
    assets::CLOUD_GLYPH,
    controller::{
        ConnectState, Connecting, Controller, NewAccount, Notice, NoticeAction, Severity, Snapshot,
    },
};

/// A controller whose data folder holds three accounts: a Dropbox account that was never signed
/// in, a Google service account whose key file is there (so it stands as connected), and a Box
/// account that was never signed in.
fn with_accounts(dir: &TempDir) -> Result<Arc<Controller>, String> {
    let key = dir.0.join("key.json");
    fs::write(&key, "{}").map_err(|error| error.to_string())?;
    let add = |provider, label, sign_in, secret| {
        add_account(&dir.0, provider, label, sign_in, secret)
            .map(|_account| ())
            .map_err(|error| error.to_string())
    };
    add(
        Provider::Dropbox,
        "Me",
        SignIn::DropboxDelegated {
            app_key: "key".to_owned(),
        },
        None,
    )?;
    add(
        Provider::GoogleDrive,
        "Work",
        SignIn::GoogleServiceAccount {
            key_file: key,
            users: vec!["jan@acme.com".to_owned()],
        },
        None,
    )?;
    add(
        Provider::Box,
        "Files",
        SignIn::BoxDelegated {
            client_id: "cid".to_owned(),
        },
        Some("secret"),
    )?;
    stub_controller(dir)
}

/// A controller whose data folder holds the one Dropbox account that was never signed in.
fn with_one_account(dir: &TempDir) -> Result<Arc<Controller>, String> {
    add_account(
        &dir.0,
        Provider::Dropbox,
        "Me",
        SignIn::DropboxDelegated {
            app_key: "key".to_owned(),
        },
        None,
    )
    .map_err(|error| error.to_string())?;
    stub_controller(dir)
}

/// The id of the account called `label`, as the controller lists it.
fn id_of(ui: &Headless, label: &str) -> Result<String, String> {
    ui.controller
        .accounts()
        .into_iter()
        .find(|view| view.account.label == label)
        .map(|view| view.account.id)
        .ok_or_else(|| format!("no account called {label}"))
}

/// Waits for the controller's snapshot to be one `done` is content with.
fn wait_for(controller: &Controller, done: impl Fn(&Snapshot) -> bool) -> Test {
    for _ in 0..2000 {
        if done(&controller.snapshot()) {
            return Ok(());
        }
        sleep(Duration::from_millis(10));
    }
    Err("the controller did not get there".to_owned())
}

/// The lists that `batches` gave to a control that offers a choice (a combo box, radio buttons).
fn lists(batches: &[Vec<Mutation>]) -> Vec<Vec<String>> {
    batches
        .iter()
        .flatten()
        .filter_map(|mutation| match mutation {
            Mutation::SetProperties { set, .. } => Some(set.iter()),
            _ => None,
        })
        .flatten()
        .filter(|property| property.id == PropertyId::ItemsSource)
        .filter_map(|property| match &property.value {
            PropertyValue::StringList(items) => {
                Some(items.iter().map(ToString::to_string).collect())
            }
            _ => None,
        })
        .collect()
}

/// Whether the button that says `text` is enabled, as the window last drew it.
fn button(ui: &Headless, text: &str) -> Option<bool> {
    enabled(ui.host.adapter().batches(), text)
}

/// A drawn text that holds `part`.
fn has(drawn: &[String], part: &str) -> bool {
    drawn.iter().any(|text| text.contains(part))
}

/// What the Settings page says of its accounts, for a window that has the three of
/// [`with_accounts`].
fn settings_with_accounts() -> Result<(Headless, Vec<String>), String> {
    let mut ui = Headless::open(with_accounts)?;
    let drawn = ui.send(Msg::Nav(Page::Settings))?;
    Ok((ui, drawn))
}

/// The dialog's first step, then the service `provider` and the step after it.
fn open_for(ui: &mut Headless, provider: Provider) -> Result<Vec<String>, String> {
    let mut drawn = ui.send(Msg::Account(AccountMsg::Add))?;
    drawn.extend(ui.send(Msg::Account(AccountMsg::Provider(provider)))?);
    Ok(drawn)
}

/// A Dropbox account as the dialog would hand it over.
fn dropbox(label: &str) -> NewAccount {
    NewAccount {
        provider: Provider::Dropbox,
        label: label.to_owned(),
        sign_in: SignIn::DropboxDelegated {
            app_key: "abc".to_owned(),
        },
        client_secret: None,
    }
}

/// The sign-in numbered 1 of `label`, in the state `state`.
fn signing(label: &str, provider: Provider, state: ConnectState) -> Connecting {
    Connecting {
        seq: 1,
        provider,
        label: label.to_owned(),
        state,
    }
}

#[test]
fn without_an_account_the_section_says_so_and_offers_to_add_one() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let drawn = ui.send(Msg::Nav(Page::Settings))?;
    expect_drawn(
        "no account",
        &drawn,
        &[
            "Connected accounts",
            "Scan the files in your cloud storage. piikey only reads them, and nothing leaves this PC.",
            "No account connected yet.",
            "Add account",
        ],
    )?;
    // The setup guide is in the Add account dialog, at each service, not here.
    expect_not_drawn(
        "no account",
        &drawn,
        &["Sign in again", "Disconnect", "Set up an account"],
    )?;
    // The section sits between General and the types of personal data.
    let at = |text: &str| drawn.iter().position(|drawn| drawn == text);
    assert!(
        at("General") < at("Connected accounts")
            && at("Connected accounts") < at("Developer access"),
        "the section is out of place: {drawn:?}"
    );
    Ok(())
}

#[test]
fn each_account_has_a_row_with_its_logo_its_way_to_sign_in_and_how_it_stands() -> Test {
    let (ui, drawn) = settings_with_accounts()?;
    expect_drawn(
        "rows",
        &drawn,
        &[
            "Me",
            "Dropbox \u{b7} Sign in with a browser",
            "Work",
            "Google Drive \u{b7} Service account (Google Workspace)",
            "Files",
            "Box \u{b7} Sign in with a browser",
        ],
    )?;
    // Two have to be signed in; the one that has what it needs says Connected.
    assert_eq!(times(&drawn, "Needs sign-in"), 2, "{drawn:?}");
    assert_eq!(times(&drawn, "Connected"), 1, "{drawn:?}");
    // Signing in again is offered to those two only; every account can be disconnected.
    assert_eq!(times(&drawn, "Sign in again"), 2, "{drawn:?}");
    assert_eq!(times(&drawn, "Disconnect"), 3, "{drawn:?}");
    assert_eq!(button(&ui, "Sign in again"), Some(true));
    Ok(())
}

#[test]
fn every_provider_shows_its_logo_and_only_a_pretend_account_the_cloud_glyph() -> Test {
    let mut bare = Headless::open(stub_controller)?;
    bare.send(Msg::Nav(Page::Settings))?;
    let (with, _) = settings_with_accounts()?;
    let glyphs = |ui: &Headless| strings(ui.host.adapter().batches(), &[PropertyId::Glyph]);
    let images = |ui: &Headless| created(ui.host.adapter().batches(), ObjectType::Image);
    // The rows of Dropbox, Google Drive and Box each have the logo of their provider, Box too...
    assert_eq!(images(&with), images(&bare) + 3);
    // ...and none of them the cloud glyph, which only the pretend account of a debug build has.
    assert!(!glyphs(&with).iter().any(|glyph| glyph == CLOUD_GLYPH));
    Ok(())
}

#[test]
fn sign_in_again_starts_the_sign_in_of_that_account() -> Test {
    let mut ui = Headless::open(with_one_account)?;
    ui.send(Msg::Nav(Page::Settings))?;
    let id = id_of(&ui, "Me")?;
    ui.send(Msg::Account(AccountMsg::SignIn(id)))?;
    wait_for(&ui.controller, |snap| {
        snap.connecting.as_ref().is_some_and(|connecting| {
            connecting.label == "Me"
                && connecting.provider == Provider::Dropbox
                && connecting.state == ConnectState::Done
        })
    })?;
    // The row follows what the sign-in is doing.
    let drawn = ui.poll_with(|snap| {
        snap.connecting = Some(signing("Me", Provider::Dropbox, ConnectState::Working));
    })?;
    expect_drawn("working", &drawn, &["Waiting for you to sign in\u{2026}"])?;
    assert_eq!(button(&ui, "Sign in again"), Some(false));
    let drawn = ui.poll_with(|snap| {
        snap.connecting = Some(signing(
            "Me",
            Provider::Dropbox,
            ConnectState::Failed("Dropbox did not accept the sign-in.".to_owned()),
        ));
    })?;
    expect_drawn("failed", &drawn, &["Dropbox did not accept the sign-in."])?;
    assert_eq!(button(&ui, "Sign in again"), Some(true));
    Ok(())
}

#[test]
fn disconnect_asks_first_and_cancel_keeps_the_account() -> Test {
    let (mut ui, _) = settings_with_accounts()?;
    let id = id_of(&ui, "Me")?;
    let asked = ui.send(Msg::Account(AccountMsg::Disconnect(id)))?;
    expect_drawn(
        "question",
        &asked,
        &[
            "Disconnect Me?",
            "piikey stops scanning its locations, removes them from Inventory and forgets what was found in them. Nothing is deleted from Dropbox.",
            "Disconnect",
            "Cancel",
        ],
    )?;
    ui.send(Msg::Account(AccountMsg::Disconnected(false)))?;
    assert!(ui.controller.wait_idle(WAIT));
    let accounts = Accounts::open(&ui.dir.0).map_err(|error| error.to_string())?;
    assert_eq!(accounts.list().len(), 3, "cancel keeps every account");
    // The question is gone: a later answer does nothing.
    ui.send(Msg::Account(AccountMsg::Disconnected(true)))?;
    assert!(ui.controller.wait_idle(WAIT));
    let accounts = Accounts::open(&ui.dir.0).map_err(|error| error.to_string())?;
    assert_eq!(accounts.list().len(), 3, "nothing was asked");
    Ok(())
}

#[test]
fn confirming_disconnect_takes_the_account_away() -> Test {
    let (mut ui, _) = settings_with_accounts()?;
    let id = id_of(&ui, "Me")?;
    ui.send(Msg::Account(AccountMsg::Disconnect(id)))?;
    ui.send(Msg::Account(AccountMsg::Disconnected(true)))?;
    assert!(ui.controller.wait_idle(WAIT));
    let accounts = Accounts::open(&ui.dir.0).map_err(|error| error.to_string())?;
    let labels: Vec<&str> = accounts
        .list()
        .iter()
        .map(|account| account.label.as_str())
        .collect();
    assert_eq!(labels, ["Work", "Files"]);
    // The window's next snapshot lists what is left.
    ui.poll()?;
    assert_eq!(ui.controller.accounts().len(), 2);
    Ok(())
}

#[test]
fn an_account_that_vanishes_closes_the_question_about_it() -> Test {
    let (mut ui, _) = settings_with_accounts()?;
    let id = id_of(&ui, "Me")?;
    ui.send(Msg::Account(AccountMsg::Disconnect(id)))?;
    // The command line took it away.
    let accounts = ui.controller.accounts();
    let drawn = ui.poll_with(|snap| {
        snap.accounts = accounts
            .iter()
            .filter(|view| view.account.label != "Me")
            .cloned()
            .collect();
    })?;
    // A late "Disconnect" of the dialog finds nothing to disconnect.
    ui.send(Msg::Account(AccountMsg::Disconnected(true)))?;
    assert!(ui.controller.wait_idle(WAIT));
    let accounts = Accounts::open(&ui.dir.0).map_err(|error| error.to_string())?;
    assert_eq!(
        accounts.list().len(),
        3,
        "the answer had no account to act on"
    );
    expect_not_drawn("vanished", &drawn, &["Me"])
}

#[test]
fn the_dialog_starts_with_the_services_and_next_waits_for_one() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let drawn = ui.send(Msg::Account(AccountMsg::Add))?;
    expect_drawn(
        "services",
        &drawn,
        &[
            "Add account",
            "Which service do you want piikey to read?",
            "Microsoft 365",
            "OneDrive",
            "Google Drive",
            "Dropbox",
            "Box",
            "Next",
            "Cancel",
        ],
    )?;
    assert_eq!(button(&ui, "Next"), Some(false));
    ui.send(Msg::Account(AccountMsg::Provider(Provider::Dropbox)))?;
    assert_eq!(button(&ui, "Next"), Some(true));
    // Every service has its logo beside its name, Box too: no cloud glyph stands in for one.
    assert!(
        !strings(ui.host.adapter().batches(), &[PropertyId::Glyph])
            .iter()
            .any(|glyph| glyph == CLOUD_GLYPH)
    );
    Ok(())
}

#[test]
fn a_service_with_several_ways_asks_which_and_the_others_go_straight_on() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Microsoft365)?;
    let before = ui.host.adapter().batches().len();
    let drawn = ui.send(Msg::Account(AccountMsg::Go(Step::Way)))?;
    expect_drawn(
        "ways",
        &drawn,
        &["How do you sign in to Microsoft 365?", "Back", "Next"],
    )?;
    let offered = lists(&ui.host.adapter().batches()[before..]);
    assert_eq!(
        offered,
        [[
            "Sign in with a browser",
            "App registration, whole tenant",
            "App registration, selected sites"
        ]]
    );
    // Back returns to the services; a service with one way is asked for its fields at once.
    let back = ui.send(Msg::Account(AccountMsg::Go(Step::Provider)))?;
    expect_drawn(
        "back",
        &back,
        &["Which service do you want piikey to read?"],
    )?;
    ui.send(Msg::Account(AccountMsg::Provider(Provider::OneDrive)))?;
    let fields = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_drawn(
        "onedrive",
        &fields,
        &[
            "OneDrive \u{b7} Sign in with a browser",
            "Account name",
            "Application (client) ID",
            "Back",
            "Connect",
        ],
    )?;
    // Personal accounts have one tenant, so none is asked.
    expect_not_drawn("onedrive", &fields, &["Tenant"])
}

#[test]
fn connect_waits_until_the_name_and_everything_the_way_needs_are_filled_in() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Dropbox)?;
    let fields = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_drawn(
        "fields",
        &fields,
        &[
            "Dropbox \u{b7} Sign in with a browser",
            "Account name",
            "App key",
            "Setup guide",
            "Fill in the account name.",
            "Connect",
        ],
    )?;
    // The help says what to register and the exact redirect address.
    assert!(has(&fields, "http://127.0.0.1:53123/"), "{fields:?}");
    assert_eq!(button(&ui, "Connect"), Some(false));
    let named = ui.send(Msg::Account(AccountMsg::Field("name", "Me".to_owned())))?;
    expect_drawn("named", &named, &["Fill in the app key."])?;
    assert_eq!(button(&ui, "Connect"), Some(false));
    ui.send(Msg::Account(AccountMsg::Field("app_key", "abc".to_owned())))?;
    assert_eq!(button(&ui, "Connect"), Some(true));
    // Back goes to the services, as Dropbox has one way.
    let back = ui.send(Msg::Account(AccountMsg::Go(Step::Provider)))?;
    expect_drawn(
        "back",
        &back,
        &["Which service do you want piikey to read?"],
    )
}

#[test]
fn an_app_registration_asks_for_a_secret_or_a_certificate_and_the_sites_it_may_read() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Microsoft365)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Way)))?;
    ui.send(Msg::Account(AccountMsg::Way(1)))?;
    let app = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_drawn(
        "whole tenant",
        &app,
        &[
            "Microsoft 365 \u{b7} App registration, whole tenant",
            "Tenant",
            "Application (client) ID",
            "Credential",
            "Client secret",
        ],
    )?;
    expect_not_drawn("whole tenant", &app, &["Sites", "Private key file (PEM)"])?;
    let certificate = ui.send(Msg::Account(AccountMsg::Field(
        "credential",
        "certificate".to_owned(),
    )))?;
    expect_drawn(
        "certificate",
        &certificate,
        &[
            "Private key file (PEM)",
            "Certificate file (PEM)",
            "Browse\u{2026}",
        ],
    )?;
    expect_not_drawn("certificate", &certificate, &["Client secret"])?;
    let picked = ui.send(Msg::Account(AccountMsg::Picked(
        "key_file",
        PathBuf::from(r"C:\keys\app.key"),
    )))?;
    expect_drawn("picked", &picked, &[r"C:\keys\app.key"])?;
    // Selected sites also ask which.
    ui.send(Msg::Account(AccountMsg::Go(Step::Way)))?;
    ui.send(Msg::Account(AccountMsg::Way(2)))?;
    let selected = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_drawn(
        "selected sites",
        &selected,
        &[
            "Microsoft 365 \u{b7} App registration, selected sites",
            "Sites",
        ],
    )?;
    assert!(has(&selected, "Sites.Selected"), "{selected:?}");
    Ok(())
}

#[test]
fn a_box_app_says_whom_it_acts_as() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Box)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Way)))?;
    ui.send(Msg::Account(AccountMsg::Way(1)))?;
    let app = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_drawn(
        "box app",
        &app,
        &[
            "Box \u{b7} App (client credentials)",
            "Client ID",
            "Client secret",
            "Act as",
            "Enterprise ID",
        ],
    )?;
    assert!(has(&app, "Client Credentials Grant"), "{app:?}");
    let user = ui.send(Msg::Account(AccountMsg::Field("act_as", "user".to_owned())))?;
    expect_drawn("user", &user, &["User ID"])
}

#[test]
fn connect_shows_what_it_waits_for_and_a_finished_sign_in_closes_the_dialog() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Dropbox)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    let working = ui.send(Msg::Account(AccountMsg::Connect(Box::new(dropbox("Me")))))?;
    expect_drawn(
        "working",
        &working,
        &["Waiting for you to sign in in your browser\u{2026}"],
    )?;
    // The sign-in has no end yet: the dialog stays as it is.
    let waiting = ui.poll_with(|snap| {
        snap.connecting = Some(signing("Me", Provider::Dropbox, ConnectState::Working));
    })?;
    expect_not_drawn("waiting", &waiting, &["Connect", "Back"])?;
    // It is done: the dialog goes, and nothing of its steps is reachable any more.
    ui.poll_with(|snap| {
        snap.connecting = Some(signing("Me", Provider::Dropbox, ConnectState::Done));
    })?;
    let after = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_not_drawn("closed", &after, &["Connect", "Back", "Next"])
}

#[test]
fn a_sign_in_of_another_account_does_not_end_the_dialogs_wait() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Dropbox)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    ui.send(Msg::Account(AccountMsg::Connect(Box::new(dropbox("Me")))))?;
    // An older sign-in of the same name, and one of another account, are not its answer.
    ui.poll_with(|snap| {
        snap.connecting = Some(signing(
            "Other",
            Provider::Dropbox,
            ConnectState::Failed("No.".to_owned()),
        ));
    })?;
    let drawn = ui.poll_with(|snap| {
        snap.connecting = Some(Connecting {
            seq: 0,
            ..signing("Me", Provider::Dropbox, ConnectState::Done)
        });
    })?;
    expect_not_drawn("still waiting", &drawn, &["Connect", "Could not connect"])
}

#[test]
fn a_sign_in_that_fails_returns_to_the_fields_with_what_was_typed_and_why() -> Test {
    let secret = "hunter2-secret";
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::GoogleDrive)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Way)))?;
    ui.send(Msg::Account(AccountMsg::Way(0)))?;
    let fields = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_drawn(
        "google",
        &fields,
        &[
            "Google Drive \u{b7} Sign in with a browser",
            "Client ID",
            "Client secret",
        ],
    )?;
    ui.send(Msg::Account(AccountMsg::Field("name", "Jan".to_owned())))?;
    let missing = ui.send(Msg::Account(AccountMsg::Field(
        "client_id",
        "my-client".to_owned(),
    )))?;
    expect_drawn("no secret", &missing, &["Fill in the client secret."])?;
    assert_eq!(button(&ui, "Connect"), Some(false));
    ui.send(Msg::Account(AccountMsg::Secret(secret.to_owned())))?;
    assert_eq!(button(&ui, "Connect"), Some(true));
    let new = NewAccount {
        provider: Provider::GoogleDrive,
        label: "Jan".to_owned(),
        sign_in: SignIn::GoogleDelegated {
            client_id: "my-client".to_owned(),
        },
        client_secret: Some(secret.to_owned()),
    };
    ui.send(Msg::Account(AccountMsg::Connect(Box::new(new))))?;
    let before = ui.host.adapter().batches().len();
    let failed = ui.poll_with(|snap| {
        snap.connecting = Some(signing(
            "Jan",
            Provider::GoogleDrive,
            ConnectState::Failed("Google did not accept the sign-in.".to_owned()),
        ));
    })?;
    expect_drawn(
        "failed",
        &failed,
        &[
            "Could not connect",
            "Google did not accept the sign-in.",
            "Jan",
            "my-client",
            "Connect",
        ],
    )?;
    // What was typed is back; the secret is not: it went with Connect.
    let batches = ui.host.adapter().batches();
    let passwords = strings(&batches[before..], &[PropertyId::Password]);
    assert!(
        !passwords.iter().any(|password| password.contains(secret)),
        "the secret is still in the window"
    );
    expect_drawn("secret gone", &failed, &["Fill in the client secret."])?;
    assert_eq!(button(&ui, "Connect"), Some(false));
    Ok(())
}

#[test]
fn closing_the_dialog_while_it_waits_puts_it_away() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Dropbox)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    ui.send(Msg::Account(AccountMsg::Connect(Box::new(dropbox("Me")))))?;
    ui.poll_with(|snap| {
        snap.connecting = Some(signing("Me", Provider::Dropbox, ConnectState::Working));
    })?;
    ui.send(Msg::Account(AccountMsg::Close))?;
    assert!(ui.controller.wait_idle(WAIT));
    let after = ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    expect_not_drawn("closed", &after, &["Connect", "Back"])?;
    // Opening it again starts from the services, with nothing of the last time.
    let again = ui.send(Msg::Account(AccountMsg::Add))?;
    expect_drawn(
        "again",
        &again,
        &["Which service do you want piikey to read?"],
    )?;
    assert_eq!(button(&ui, "Next"), Some(false));
    Ok(())
}

#[test]
fn another_sign_in_that_is_open_holds_connect_back_with_a_word() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    open_for(&mut ui, Provider::Dropbox)?;
    ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?;
    ui.poll_with(|snap| {
        snap.connecting = Some(signing("Other", Provider::Dropbox, ConnectState::Working));
    })?;
    let drawn = ui.send(Msg::Account(AccountMsg::Connect(Box::new(dropbox("Me")))))?;
    expect_drawn(
        "busy",
        &drawn,
        &[
            "Could not connect",
            "Finish the sign-in that is open first, or stop it.",
        ],
    )?;
    expect_not_drawn(
        "busy",
        &drawn,
        &["Waiting for you to sign in in your browser\u{2026}"],
    )
}

#[test]
fn a_notice_that_asks_for_a_sign_in_has_the_button_that_does_it() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    let action = NoticeAction::SignIn {
        account: "0123456789abcdef".to_owned(),
        provider: Provider::Dropbox,
    };
    let drawn = ui.poll_with(|snap| {
        snap.notice = Some(Notice {
            severity: Severity::Warning,
            text: "Me needs you to sign in again.".to_owned(),
            action: Some(action.clone()),
        });
    })?;
    expect_drawn(
        "notice",
        &drawn,
        &[
            "Heads up",
            "Me needs you to sign in again.",
            "Sign in to Dropbox",
        ],
    )?;
    // The button asks the controller to sign that account in: it has none of that id, and says so.
    ui.send(Msg::NoticeButton(action))?;
    assert!(ui.controller.wait_idle(WAIT));
    let notice = ui
        .controller
        .snapshot()
        .notice
        .ok_or("the controller said nothing")?;
    assert!(notice.text.contains("0123456789abcdef"), "{}", notice.text);
    Ok(())
}

#[test]
fn a_notice_without_an_action_has_no_button() -> Test {
    let mut ui = Headless::open(stub_controller)?;
    // Overview shows an error as its own cause; any other page shows the notice.
    ui.send(Msg::Nav(Page::Protection))?;
    let drawn = ui.poll_with(|snap| {
        snap.notice = Some(Notice {
            severity: Severity::Error,
            text: "Something is wrong.".to_owned(),
            action: None,
        });
    })?;
    expect_drawn(
        "notice",
        &drawn,
        &["Something went wrong", "Something is wrong."],
    )?;
    assert!(!has(&drawn, "Sign in to"), "{drawn:?}");
    Ok(())
}

/// Every step of the dialog for every service and way, the way a person would go through it.
fn walk_the_dialog(ui: &mut Headless) -> Result<Vec<String>, String> {
    let mut drawn = Vec::new();
    for (provider, ways) in Provider::ALL.into_iter().zip([3_usize, 1, 2, 1, 2]) {
        drawn.extend(open_for(ui, provider)?);
        for way in 0..ways {
            if ways > 1 {
                drawn.extend(ui.send(Msg::Account(AccountMsg::Go(Step::Way)))?);
                drawn.extend(ui.send(Msg::Account(AccountMsg::Way(way)))?);
            }
            drawn.extend(ui.send(Msg::Account(AccountMsg::Go(Step::Fields)))?);
            for (key, choice) in [("credential", "certificate"), ("act_as", "user")] {
                drawn.extend(ui.send(Msg::Account(AccountMsg::Field(key, choice.to_owned())))?);
            }
        }
        drawn.extend(ui.send(Msg::Account(AccountMsg::Connect(Box::new(dropbox("Me")))))?);
        drawn.extend(ui.poll_with(|snap| {
            snap.connecting = Some(signing(
                "Me",
                Provider::Dropbox,
                ConnectState::Failed("The sign-in was stopped.".to_owned()),
            ));
        })?);
        drawn.extend(ui.send(Msg::Account(AccountMsg::Close))?);
    }
    Ok(drawn)
}

#[test]
fn the_accounts_say_everything_in_the_words_of_the_glossary() -> Test {
    let (mut ui, mut drawn) = settings_with_accounts()?;
    let id = id_of(&ui, "Me")?;
    drawn.extend(ui.send(Msg::Account(AccountMsg::Disconnect(id)))?);
    drawn.extend(ui.send(Msg::Account(AccountMsg::Disconnected(false)))?);
    let section = drawn.len();
    drawn.extend(walk_the_dialog(&mut ui)?);
    drawn.extend(ui.poll_with(|snap| {
        snap.notice = Some(Notice {
            severity: Severity::Warning,
            text: "Me needs you to sign in again.".to_owned(),
            action: Some(NoticeAction::SignIn {
                account: "0123456789abcdef".to_owned(),
                provider: Provider::Box,
            }),
        });
    })?);
    for text in &drawn {
        for banned in [
            "PII", "Keyed", "keyed", "program", "Program", "kind", "Kind", "Watch", "watch",
        ] {
            assert!(!text.contains(banned), "{text:?} says {banned:?}");
        }
    }
    // What the dialog says has no jargon of the services' protocols and no codes of their answers.
    for text in &drawn[section..] {
        for banned in [
            "OAuth", "oauth", "token", "Token", "HTTP", "401", "403", "404",
        ] {
            assert!(!text.contains(banned), "{text:?} says {banned:?}");
        }
    }
    Ok(())
}

/// A controller whose data folder holds the debug fake account (a Box account called "Example
/// cloud") and a real Box account of another name.
fn with_the_fake_account(dir: &TempDir) -> Result<Arc<Controller>, String> {
    for label in ["Example cloud", "Real box"] {
        add_account(
            &dir.0,
            Provider::Box,
            label,
            SignIn::BoxApp {
                client_id: "cid".to_owned(),
                subject: piikey::sources::BoxSubject::Enterprise("1".to_owned()),
            },
            Some("x"),
        )
        .map_err(|error| error.to_string())?;
    }
    stub_controller(dir)
}

#[test]
fn the_fake_account_is_never_called_box_but_a_real_box_account_is() -> Test {
    let mut ui = Headless::open(with_the_fake_account)?;
    let row = ui.send(Msg::Nav(Page::Settings))?;
    expect_drawn(
        "rows",
        &row,
        &[
            "Example provider \u{b7} App (client credentials)",
            "Box \u{b7} App (client credentials)",
        ],
    )?;
    // The only text with "Box" in it is the real account's line and the section's own words.
    let boxes: Vec<&String> = row.iter().filter(|text| text.contains("Box")).collect();
    assert!(
        boxes
            .iter()
            .all(|text| text.starts_with("Box \u{b7}") || text.starts_with("Microsoft 365,")),
        "{boxes:?}"
    );
    let fake = id_of(&ui, "Example cloud")?;
    let asked = ui.send(Msg::Account(AccountMsg::Disconnect(fake.clone())))?;
    assert!(
        has(&asked, "Nothing is deleted from Example provider."),
        "{asked:?}"
    );
    assert!(!has(&asked, "from Box"), "{asked:?}");
    ui.send(Msg::Account(AccountMsg::Disconnected(false)))?;
    let real = id_of(&ui, "Real box")?;
    let asked = ui.send(Msg::Account(AccountMsg::Disconnect(real.clone())))?;
    assert!(has(&asked, "Nothing is deleted from Box."), "{asked:?}");
    ui.send(Msg::Account(AccountMsg::Disconnected(false)))?;
    for (id, name) in [(fake, "Example provider"), (real, "Box")] {
        let provider = Provider::Box;
        let button = format!("Sign in to {name}");
        let drawn = ui.poll_with(|snap| {
            snap.notice = Some(Notice {
                severity: Severity::Warning,
                text: "Sign in again.".to_owned(),
                action: Some(NoticeAction::SignIn {
                    account: id.clone(),
                    provider,
                }),
            });
        })?;
        expect_drawn("notice", &drawn, &[button.as_str()])?;
    }
    Ok(())
}
