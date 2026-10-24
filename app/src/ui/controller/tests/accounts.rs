//! The cloud accounts in the controller: signing in on a thread of its own, signing in again when
//! a scan says so, disconnecting, and what the folder picker and "Open" ask of an account.

use piikey::sources::{Accounts, Cursors, Error, Provider, Secrets, SignIn, TokenStore};

use super::{
    cloud::{LABEL, cloud_rig, connect_account, connected, drive, drive_policy},
    inventory::docs,
    watch::statuses,
    *,
};

const MAIL: &str = "mail jan.jansen@acme.nl";

/// What the Add account dialog collects for `jan@acme.com`; the key file it names is made.
fn new_account(rig: &Rig) -> Result<NewAccount, String> {
    let key = rig.controller.data_dir().join("key.json");
    fs::write(&key, "the key of a service account").describe()?;
    Ok(NewAccount {
        provider: Provider::GoogleDrive,
        label: LABEL.to_owned(),
        sign_in: SignIn::GoogleServiceAccount {
            key_file: key,
            users: vec![LABEL.to_owned()],
        },
        client_secret: None,
    })
}

/// Waits until the sign-in that was started last is in a state `done` says yes to.
fn signing_in(rig: &Rig, done: impl Fn(&ConnectState) -> bool) -> Result<Snapshot, String> {
    wait_for(&rig.controller, |s| {
        s.connecting
            .as_ref()
            .is_some_and(|connecting| done(&connecting.state))
    })
}

/// A sign-in that waits for the person in the browser: it says so on the returned receiver, and
/// goes on once the flag is set.
fn browser(rig: &Rig) -> (Receiver<()>, Arc<AtomicBool>) {
    let (waiting, in_browser) = mpsc::channel();
    let done = Arc::new(AtomicBool::new(false));
    rig.fake.script_sign_in(SignInScript::Waits {
        url: "https://accounts.example.test/sign-in",
        waiting,
        done: Arc::clone(&done),
    });
    (in_browser, done)
}

#[test]
fn adding_an_account_signs_it_in_on_a_thread_of_its_own() -> Test {
    let rig = rig(true, quiet())?;
    let (in_browser, done) = browser(&rig);
    // The command returns at once: the person takes the time they need.
    rig.run(Command::AddAccount(new_account(&rig)?))?;
    in_browser
        .recv_timeout(Duration::from_secs(20))
        .map_err(|error| error.to_string())?;
    let snapshot = rig.controller.snapshot();
    let connecting = snapshot.connecting.ok_or("no sign-in")?;
    assert_eq!(
        (connecting.provider, connecting.label.as_str()),
        (Provider::GoogleDrive, LABEL)
    );
    assert_eq!(connecting.state, ConnectState::Working);
    assert!(has_call(
        &rig,
        "open_url(https://accounts.example.test/sign-in)"
    ));

    // One at a time: a second one is told to wait, and the first goes on.
    rig.run(Command::AddAccount(new_account(&rig)?))?;
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(
        notice.text,
        "Finish the sign-in that is open first, or stop it."
    );
    let same = rig.controller.snapshot().connecting.ok_or("no sign-in")?;
    assert_eq!(
        (same.seq, same.state),
        (connecting.seq, ConnectState::Working)
    );

    // The person is done: the account is there, and signed in.
    done.store(true, Ordering::SeqCst);
    let snapshot = signing_in(&rig, |state| *state == ConnectState::Done)?;
    let view = snapshot.accounts.first().ok_or("no account")?;
    assert_eq!(snapshot.accounts.len(), 1);
    assert_eq!(view.account.label, LABEL);
    assert_eq!(view.status, AccountStatus::Connected);
    assert!(has_call(&rig, "connect(jan@acme.com)"));
    Ok(())
}

#[test]
fn a_sign_in_that_fails_leaves_no_account_behind_and_the_next_one_can_work() -> Test {
    let rig = rig(true, quiet())?;
    rig.fake.script_sign_in(SignInScript::Fails(|| {
        Error::forbidden(Provider::GoogleDrive, "access denied")
    }));
    rig.run(Command::AddAccount(new_account(&rig)?))?;
    let snapshot = signing_in(&rig, |state| matches!(state, ConnectState::Failed(_)))?;
    let words =
        "Google Drive does not allow piikey to read this. Check what piikey may read there.";
    assert_eq!(
        snapshot.connecting.map(|connecting| connecting.state),
        Some(ConnectState::Failed(words.to_owned()))
    );
    assert!(snapshot.accounts.is_empty());
    assert!(
        Accounts::open(rig.controller.data_dir())
            .describe()?
            .list()
            .is_empty()
    );

    // The same account can be tried again, and works.
    rig.run(Command::AddAccount(new_account(&rig)?))?;
    let snapshot = signing_in(&rig, |state| *state == ConnectState::Done)?;
    assert_eq!(snapshot.accounts.len(), 1);
    Ok(())
}

#[test]
fn a_sign_in_an_administrator_must_approve_says_so_with_the_approval_link() -> Test {
    let rig = rig(true, quiet())?;
    rig.fake
        .script_sign_in(SignInScript::Fails(|| Error::AdminApproval {
            provider: Provider::Microsoft365,
            detail: "AADSTS90094".to_owned(),
        }));
    rig.run(Command::AddAccount(NewAccount {
        provider: Provider::Microsoft365,
        label: "Work".to_owned(),
        sign_in: SignIn::MicrosoftDelegated {
            tenant: "organizations".to_owned(),
            client_id: "app-id".to_owned(),
        },
        client_secret: None,
    }))?;
    let snapshot = signing_in(&rig, |state| {
        matches!(state, ConnectState::NeedsApproval { .. })
    })?;
    assert_eq!(
        snapshot.connecting.map(|connecting| connecting.state),
        Some(ConnectState::NeedsApproval {
            why: "Your organization's administrator has to approve piikey before it can read Microsoft 365. Send them the approval link.".to_owned(),
            link: "https://login.microsoftonline.com/organizations/adminconsent?client_id=app-id"
                .to_owned(),
        })
    );
    // Nothing of it stays until it can sign in.
    assert!(snapshot.accounts.is_empty());
    Ok(())
}

#[test]
fn stopping_a_sign_in_that_waits_for_the_browser_leaves_nothing_of_the_account() -> Test {
    let rig = rig(true, quiet())?;
    let (in_browser, _) = browser(&rig);
    rig.run(Command::AddAccount(new_account(&rig)?))?;
    in_browser
        .recv_timeout(Duration::from_secs(20))
        .map_err(|error| error.to_string())?;
    let seq = rig
        .controller
        .snapshot()
        .connecting
        .ok_or("no sign-in")?
        .seq;

    // The number of another sign-in stops nothing.
    rig.run(Command::CancelConnect(seq + 1))?;
    let still = rig.controller.snapshot().connecting.ok_or("no sign-in")?;
    assert_eq!(still.state, ConnectState::Working);

    rig.run(Command::CancelConnect(seq))?;
    let snapshot = signing_in(&rig, |state| matches!(state, ConnectState::Failed(_)))?;
    assert_eq!(
        snapshot.connecting.map(|connecting| connecting.state),
        Some(ConnectState::Failed("The sign-in was stopped.".to_owned()))
    );
    assert!(snapshot.accounts.is_empty());
    assert!(
        Accounts::open(rig.controller.data_dir())
            .describe()?
            .list()
            .is_empty()
    );
    Ok(())
}

#[test]
fn disconnecting_an_account_removes_its_locations_entries_cursor_and_secrets() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let (rig, cloud, account) = connected(Policy {
        inventory_roots: vec![folder.clone(), drive()],
        monitored_roots: vec![drive()],
        ..quiet()
    })?;
    cloud.put("Docs/a.txt", MAIL);
    rig.fake.poll_every(Duration::from_millis(50));
    let data = rig.controller.data_dir().to_path_buf();
    // What piikey keeps of an account besides its settings: a token file.
    let token = data.join("sources").join(format!("{}.token", account.id));
    TokenStore::new(&data)
        .save(
            &account.id,
            &Secrets::default().with_access_token("token", 0),
        )
        .describe()?;
    assert!(token.is_file());
    rig.run(Command::Startup)?;
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (2, 2));
    assert!(Cursors::new(&data).get(&drive()).describe()?.is_some());

    rig.run(Command::RemoveAccount(account.id.clone()))?;
    let snapshot = rig.controller.snapshot();
    // Its locations and their monitoring are gone, and what the inventory held of it; the
    // folder on this PC stays.
    assert_eq!(snapshot.policy.inventory_roots, [folder]);
    assert!(snapshot.policy.monitored_roots.is_empty());
    assert!(snapshot.watch.folders.is_empty());
    assert_eq!(snapshot.inventory_totals, (1, 1));
    assert!(
        rig.controller
            .inventory()
            .entries(Some(&account.root()), 0)
            .is_empty()
    );
    // What piikey kept of it is gone: where its scans left off, its secrets, its settings, its row.
    assert_eq!(Cursors::new(&data).get(&drive()).describe()?, None);
    assert!(!token.exists());
    assert!(Accounts::open(&data).describe()?.list().is_empty());
    let settings = fs::read_to_string(data.join("sources.json")).describe()?;
    assert!(!settings.contains(&account.id), "{settings}");
    assert!(snapshot.accounts.is_empty());
    // Nobody asks the account any more.
    let listings = cloud.listings();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(cloud.listings(), listings);
    Ok(())
}

#[test]
fn an_account_that_has_to_sign_in_again_gives_one_notice_with_the_button_that_does_it() -> Test {
    let (rig, cloud, account) = connected(drive_policy(true))?;
    cloud.put("Docs/a.txt", MAIL);
    cloud.fail_with(|| Error::sign_in_needed(Provider::GoogleDrive, "the refresh token expired"));
    rig.fake.poll_every(Duration::from_millis(50));
    rig.run(Command::Startup)?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.notice.is_some()
            && s.watch.scanning.is_none()
            && matches!(statuses(s).first(), Some(FolderStatus::Unavailable(_)))
    })?;

    // A warning with the button that signs in again, the account's row and the location's row.
    let notice = snapshot.notice.clone().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert_eq!(notice.text, "Sign in to Google Drive again.");
    assert_eq!(
        notice.action,
        Some(NoticeAction::SignIn {
            account: account.id.clone(),
            provider: Provider::GoogleDrive
        })
    );
    let view = snapshot.accounts.first().ok_or("no account")?;
    assert_eq!(view.status, AccountStatus::SignInNeeded);
    assert_eq!(view.status_text(), "Needs sign-in");
    assert_eq!(
        statuses(&snapshot),
        [FolderStatus::Unavailable(
            "Sign in to Google Drive again.".to_owned()
        )]
    );
    assert_eq!(snapshot.inventory_totals, (0, 0));

    // The same failure again is no news: the notice that was closed does not come back.
    rig.controller.dismiss_notice();
    let listings = cloud.listings();
    eventually("more polls", || cloud.listings() >= listings + 3)?;
    assert_eq!(rig.notice(), None);
    Ok(())
}

#[test]
fn signing_in_again_clears_the_notice_and_the_status_of_the_account_and_its_location() -> Test {
    let (rig, cloud, account) = connected(drive_policy(true))?;
    cloud.put("Docs/a.txt", MAIL);
    cloud.fail_with(|| Error::sign_in_needed(Provider::GoogleDrive, "the refresh token expired"));
    rig.run(Command::Startup)?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.notice.is_some() && s.watch.scanning.is_none()
    })?;
    let asked = snapshot.notice.and_then(|notice| notice.action);
    assert_eq!(
        asked,
        Some(NoticeAction::SignIn {
            account: account.id.clone(),
            provider: Provider::GoogleDrive
        })
    );

    // The button signs in (the fake works at once), and the service takes the account again.
    cloud.heal();
    rig.run(Command::ConnectAccount(account.id.clone()))?;
    let snapshot = signing_in(&rig, |state| *state == ConnectState::Done)?;
    assert!(has_call(&rig, "connect(jan@acme.com)"));
    assert_eq!(
        snapshot.notice, None,
        "the notice that asked for it is done"
    );
    let view = snapshot.accounts.first().ok_or("no account")?;
    assert_eq!(view.status, AccountStatus::Connected);

    // The next scan finds the location as it is: read, and watched again.
    rig.run(Command::ScanAll)?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.inventory_totals == (1, 1) && s.scan.is_none()
    })?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert_eq!(snapshot.notice, None);
    Ok(())
}

#[test]
fn the_folders_of_an_account_and_the_page_of_an_item_come_from_its_connector() -> Test {
    let (rig, cloud, account) = connected(quiet())?;
    cloud.put("Docs/a.txt", MAIL);
    cloud.put("Mail/b.txt", MAIL);
    // The top of the account is what a person picks a location from, and a folder lists its folders.
    let top = rig.controller.browse_cloud(&account.id, None).describe()?;
    assert_eq!(top, [drive()]);
    let inside = rig
        .controller
        .browse_cloud(&account.id, Some(&drive()))
        .describe()?;
    assert_eq!(inside, [drive().join("Docs"), drive().join("Mail")]);
    let nothing = rig
        .controller
        .browse_cloud(&account.id, Some(&drive().join("Docs")))
        .describe()?;
    assert!(nothing.is_empty());

    // A file and a folder have a page, a path in no connected account has none.
    let file = drive().join("Docs").join("a.txt");
    assert_eq!(
        rig.controller.web_url(&file).describe()?,
        "https://drive.example.test/Docs/a.txt"
    );
    assert_eq!(
        rig.controller.web_url(&drive()).describe()?,
        "https://drive.example.test/"
    );
    let elsewhere = rig
        .controller
        .web_url(Path::new(r"\\Dropbox\someone\Docs"))
        .err()
        .ok_or("no account has that path")?;
    assert!(
        elsewhere
            .to_string()
            .contains("is not in a connected account"),
        "{elsewhere}"
    );
    let gone = rig
        .controller
        .web_url(&drive().join("Docs").join("gone.txt"))
        .err()
        .ok_or("nothing is there")?;
    assert!(
        gone.to_string().contains("no longer in Google Drive"),
        "{gone}"
    );
    Ok(())
}

#[test]
fn an_account_that_cannot_be_reached_shows_it_on_its_row_until_a_call_works() -> Test {
    let (rig, cloud, account) = connected(quiet())?;
    cloud.fail_with(|| Error::network(Provider::GoogleDrive, "timed out"));
    let error = rig
        .controller
        .browse_cloud(&account.id, None)
        .err()
        .ok_or("the account cannot be reached")?;
    let words = "piikey cannot reach Google Drive. Check the internet connection and try again.";
    assert_eq!(error.to_string(), words);
    let snapshot = rig.controller.snapshot();
    let view = snapshot.accounts.first().ok_or("no account")?;
    assert_eq!(view.status, AccountStatus::Problem(words.to_owned()));
    assert_eq!(view.status_text(), words);
    assert_eq!(snapshot.notice, None, "the folder picker says it itself");

    // The next call that works takes it away.
    cloud.heal();
    rig.controller.browse_cloud(&account.id, None).describe()?;
    let view = rig.controller.accounts();
    assert_eq!(
        view.first().map(|view| view.status.clone()),
        Some(AccountStatus::Connected)
    );
    Ok(())
}

#[test]
fn the_api_adds_a_cloud_location_only_for_a_connected_account() -> Test {
    let (rig, _) = cloud_rig(quiet())?;
    let patch = SettingsPatch {
        inventory_roots: Some(vec![drive()]),
        ..SettingsPatch::default()
    };
    // No connected account has the name: nothing changes, and the notice says why.
    rig.run(Command::Settings(patch.clone()))?;
    assert!(rig.controller.policy().inventory_roots.is_empty());
    assert!(rig.calls().is_empty());
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(
        notice.text.contains("no connected account has that name"),
        "{}",
        notice.text
    );

    connect_account(&rig)?;
    rig.run(Command::Settings(patch))?;
    assert_eq!(rig.controller.policy().inventory_roots, [drive()]);
    assert_eq!(rig.fake.last_saved()?.inventory_roots, [drive()]);
    Ok(())
}
