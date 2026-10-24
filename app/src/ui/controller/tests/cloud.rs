//! Locations in a cloud account, in the controller: scanned in one run with the folders on this
//! PC, monitored by asking, forgotten, read for their findings. The cloud is a fake that lives in
//! memory, an account whose change feed has generations for cursors.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::AtomicUsize,
    time::{SystemTime, UNIX_EPOCH},
};

use piikey::{
    sources::{
        self, Account, Changes, Connector, Cursors, Error, Provider, RemoteFolder, RemoteItem,
        Resolved, SignIn,
    },
    sys,
};

use super::{
    inventory::{docs, entry_of, of_file, read_events, shown, summary_of},
    watch::{statuses, watch_holds},
    *,
};

/// The name of the account every test of the cloud signs in as.
pub(super) const LABEL: &str = "jan@acme.com";
/// Its Drive, the folder of the account that is a location.
pub(super) const DRIVE: &str = r"\\Google Drive\jan@acme.com\My Drive";
const MAIL: &str = "mail jan.jansen@acme.nl";
const CALL: &str = "call +31 6 12345678";
const IBAN: &str = "iban NL91ABNA0417164300";

/// The Drive as a path.
pub(super) fn drive() -> PathBuf {
    PathBuf::from(DRIVE)
}

/// Where a browser opens `path`, as the fake cloud says.
fn page(path: &Path) -> String {
    let below = path.strip_prefix(DRIVE).unwrap_or(path);
    format!(
        "https://drive.example.test/{}",
        below.display().to_string().replace('\\', "/")
    )
}

/// A file of the fake cloud.
struct Held {
    bytes: Vec<u8>,
    modified: SystemTime,
    version: String,
}

/// What the fake Drive holds, and what changed in it.
#[derive(Default)]
struct Feed {
    files: BTreeMap<PathBuf, Held>,
    /// Grows with every change: it is what a cursor says.
    generation: u64,
    changed: Vec<(u64, PathBuf)>,
    removed: Vec<(u64, PathBuf)>,
}

/// A call of the cloud that a test makes wait: the call says that it has begun, and goes on once
/// it is let go or the scan it belongs to is stopped.
struct Gate {
    began: Sender<()>,
    go: Arc<AtomicBool>,
}

/// What a test holds of a call it made wait.
pub(super) struct Hold {
    began: Receiver<()>,
    go: Arc<AtomicBool>,
}

impl Hold {
    /// Waits until the call has begun.
    pub(super) fn began(&self) -> Test {
        self.began
            .recv_timeout(Duration::from_secs(20))
            .map_err(|error| format!("the call did not begin: {error}"))
    }

    /// Lets the call go on.
    pub(super) fn release(&self) {
        self.go.store(true, Ordering::SeqCst);
    }
}

/// An account that lives in memory: a Drive with a change feed.
#[derive(Default)]
pub(super) struct Cloud {
    feed: Mutex<Feed>,
    listings: AtomicUsize,
    downloads: AtomicUsize,
    /// How many listings gave way to a scan that was asked for.
    stopped: AtomicUsize,
    /// The cursor each listing was asked with, in order.
    asked: Mutex<Vec<Option<String>>>,
    /// What asks the account (a listing, a download, the folder picker) fails with this.
    failure: Mutex<Option<fn() -> Error>>,
    hold_listing: Mutex<Option<Gate>>,
    hold_download: Mutex<Option<Gate>>,
}

impl Cloud {
    fn feed(&self) -> MutexGuard<'_, Feed> {
        self.feed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The path of `name`, written as `Docs/a.txt`, in the Drive.
    fn path_of(name: &str) -> PathBuf {
        name.split('/')
            .fold(drive(), |path, part| sources::child(&path, part))
    }

    /// Puts a file in the Drive, or replaces it: the service says it changed.
    pub(super) fn put(&self, name: &str, text: &str) {
        let path = Self::path_of(name);
        let mut feed = self.feed();
        feed.generation += 1;
        let generation = feed.generation;
        feed.changed.push((generation, path.clone()));
        feed.files.insert(
            path,
            Held {
                bytes: text.as_bytes().to_vec(),
                modified: UNIX_EPOCH + Duration::from_secs(1_000 + generation),
                version: format!("v{generation}"),
            },
        );
    }

    /// Deletes a file from the Drive.
    pub(super) fn remove(&self, name: &str) {
        let path = Self::path_of(name);
        let mut feed = self.feed();
        feed.generation += 1;
        let generation = feed.generation;
        feed.removed.push((generation, path.clone()));
        feed.files.remove(&path);
    }

    /// How many times the change feed was asked.
    pub(super) fn listings(&self) -> usize {
        self.listings.load(Ordering::SeqCst)
    }

    /// How many files were downloaded.
    pub(super) fn downloads(&self) -> usize {
        self.downloads.load(Ordering::SeqCst)
    }

    /// How many times the change feed was asked and gave way to a scan that was asked for.
    pub(super) fn stopped(&self) -> usize {
        self.stopped.load(Ordering::SeqCst)
    }

    /// The cursor each ask of the change feed came with, in order: `None` for a full listing.
    pub(super) fn asked(&self) -> Vec<Option<String>> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The cursor a listing now ends with.
    pub(super) fn cursor(&self) -> String {
        format!("g{}", self.feed().generation)
    }

    /// From now on what asks the account fails with `error`.
    pub(super) fn fail_with(&self, error: fn() -> Error) {
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = Some(error);
    }

    /// The account works again.
    pub(super) fn heal(&self) {
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Makes the next ask of the change feed wait.
    pub(super) fn hold_listing(&self) -> Hold {
        Self::arm(&self.hold_listing)
    }

    /// Makes the next download wait.
    pub(super) fn hold_download(&self) -> Hold {
        Self::arm(&self.hold_download)
    }

    fn arm(slot: &Mutex<Option<Gate>>) -> Hold {
        let (began, waiting) = mpsc::channel();
        let go = Arc::new(AtomicBool::new(false));
        *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(Gate {
            began,
            go: Arc::clone(&go),
        });
        Hold { began: waiting, go }
    }

    /// The failure a test set, if it did.
    fn failure(&self) -> sources::Result<()> {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map_or(Ok(()), |error| Err(error()))
    }

    /// A listing was stopped.
    fn gave_way(&self) -> Error {
        self.stopped.fetch_add(1, Ordering::SeqCst);
        Error::Cancelled
    }

    fn item(path: &Path, held: &Held) -> RemoteItem {
        RemoteItem {
            id: path.to_string_lossy().into_owned(),
            path: path.to_path_buf(),
            size: u64::try_from(held.bytes.len()).unwrap_or(u64::MAX),
            modified: held.modified,
            version: held.version.clone(),
            web_url: page(path),
            export: None,
        }
    }
}

/// Waits at the gate a test armed in `slot`, if it did: until the test lets the call go or
/// `cancel` is set. The gate is used up.
fn wait_at(slot: &Mutex<Option<Gate>>, cancel: &AtomicBool) {
    let gate = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
    let Some(gate) = gate else {
        return;
    };
    let _ = gate.began.send(());
    while !gate.go.load(Ordering::SeqCst) && !cancel.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(5));
    }
}

/// What `Fake::connector` hands out: the cloud its account was registered with.
pub(super) struct Handle(pub(super) Arc<Cloud>);

impl Connector for Handle {
    fn provider(&self) -> Provider {
        Provider::GoogleDrive
    }

    fn browse(&self, under: Option<&RemoteFolder>) -> sources::Result<Vec<RemoteFolder>> {
        self.0.failure()?;
        let folder = |path: PathBuf| RemoteFolder {
            id: path.to_string_lossy().into_owned(),
            web_url: page(&path),
            path,
        };
        let Some(under) = under else {
            return Ok(vec![folder(drive())]);
        };
        let feed = self.0.feed();
        let mut children: Vec<PathBuf> = Vec::new();
        for path in feed.files.keys() {
            // The folder right below `under` that the file is in, when it lies deeper than that.
            if let Ok(rest) = path.strip_prefix(&under.path) {
                let mut parts = rest.components();
                if let (Some(first), Some(_)) = (parts.next(), parts.next()) {
                    let child = under.path.join(first.as_os_str());
                    if !children.contains(&child) {
                        children.push(child);
                    }
                }
            }
        }
        Ok(children.into_iter().map(folder).collect())
    }

    fn resolve(&self, path: &Path) -> sources::Result<Resolved> {
        let feed = self.0.feed();
        if let Some(held) = feed.files.get(path) {
            return Ok(Resolved::File(Cloud::item(path, held)));
        }
        let folder = sys::same_path(path, &drive())
            || feed.files.keys().any(|file| sys::is_under(file, path));
        if folder {
            return Ok(Resolved::Folder(RemoteFolder {
                id: path.to_string_lossy().into_owned(),
                path: path.to_path_buf(),
                web_url: page(path),
            }));
        }
        Err(Error::not_found(
            Provider::GoogleDrive,
            "no such file or folder",
        ))
    }

    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> sources::Result<Changes> {
        self.0.listings.fetch_add(1, Ordering::SeqCst);
        self.0
            .asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cursor.map(str::to_owned));
        wait_at(&self.0.hold_listing, cancel);
        if cancel.load(Ordering::Relaxed) {
            return Err(self.0.gave_way());
        }
        self.0.failure()?;
        let feed = self.0.feed();
        let next = format!("g{}", feed.generation);
        let under = |path: &Path| sys::is_under(path, &root.path);
        let since = cursor.and_then(|cursor| cursor.strip_prefix('g')?.parse::<u64>().ok());
        // Without a cursor the fake knows, everything is listed.
        let Some(since) = since else {
            return Ok(Changes {
                items: feed
                    .files
                    .iter()
                    .filter(|(path, _)| under(path))
                    .map(|(path, held)| Cloud::item(path, held))
                    .collect(),
                removed: Vec::new(),
                cursor: next,
                full: true,
            });
        };
        let touched: BTreeSet<&PathBuf> = feed
            .changed
            .iter()
            .filter(|(generation, path)| *generation > since && under(path))
            .map(|(_, path)| path)
            .collect();
        Ok(Changes {
            items: touched
                .into_iter()
                .filter_map(|path| feed.files.get(path).map(|held| Cloud::item(path, held)))
                .collect(),
            removed: feed
                .removed
                .iter()
                .filter(|(generation, path)| *generation > since && under(path))
                .map(|(_, path)| path.clone())
                .collect(),
            cursor: next,
            full: false,
        })
    }

    fn download(
        &self,
        item: &RemoteItem,
        max: u64,
        cancel: &AtomicBool,
    ) -> sources::Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        self.0.downloads.fetch_add(1, Ordering::SeqCst);
        wait_at(&self.0.hold_download, cancel);
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        self.0.failure()?;
        let feed = self.0.feed();
        let held = feed
            .files
            .get(&item.path)
            .ok_or_else(|| Error::not_found(Provider::GoogleDrive, "no such file"))?;
        if u64::try_from(held.bytes.len()).is_ok_and(|len| len > max) {
            return Err(Error::TooLarge);
        }
        Ok(held.bytes.clone())
    }
}

/// A rig whose settings are `policy`, with a fake cloud registered as the account
/// `jan@acme.com`. The account is not connected yet.
pub(super) fn cloud_rig(policy: Policy) -> Result<(Rig, Arc<Cloud>), String> {
    let rig = rig(true, policy)?;
    let cloud = Arc::new(Cloud::default());
    rig.fake.add_cloud(LABEL, &cloud);
    Ok((rig, cloud))
}

/// Connects the account `jan@acme.com` as the Settings page does: its settings are in the data
/// folder, and so is the key file it names.
pub(super) fn connect_account(rig: &Rig) -> Result<Account, String> {
    let key = rig.controller.data_dir().join("key.json");
    fs::write(&key, "the key of a service account").describe()?;
    let account = sources::add_account(
        rig.controller.data_dir(),
        Provider::GoogleDrive,
        LABEL,
        SignIn::GoogleServiceAccount {
            key_file: key,
            users: vec![LABEL.to_owned()],
        },
        None,
    )
    .describe()?;
    rig.controller.refresh_accounts();
    Ok(account)
}

/// A rig with the account connected and a fake cloud behind it.
pub(super) fn connected(policy: Policy) -> Result<(Rig, Arc<Cloud>, Account), String> {
    let (rig, cloud) = cloud_rig(policy)?;
    let account = connect_account(&rig)?;
    Ok((rig, cloud, account))
}

/// Settings whose one location is the Drive, monitored when `monitored`.
pub(super) fn drive_policy(monitored: bool) -> Policy {
    Policy {
        inventory_roots: vec![drive()],
        monitored_roots: if monitored { vec![drive()] } else { Vec::new() },
        ..quiet()
    }
}

/// How many times the detection model was loaded.
fn loads(rig: &Rig) -> usize {
    rig.calls()
        .iter()
        .filter(|call| *call == "load_model")
        .count()
}

/// How many times the fake was asked for the connector of an account.
fn connections(rig: &Rig) -> usize {
    rig.calls()
        .iter()
        .filter(|call| call.starts_with("connector("))
        .count()
}

#[test]
fn one_scan_runs_over_the_folders_on_this_pc_and_the_cloud_with_one_count_and_one_result() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let (rig, cloud, _) = connected(Policy {
        inventory_roots: vec![folder.clone(), drive()],
        ..quiet()
    })?;
    cloud.put("Docs/a.txt", IBAN);
    cloud.put("Docs/b.txt", "mail piet.pietersen@acme.nl");
    cloud.put("Docs/c.txt", "nothing here");
    let download = cloud.hold_download();
    rig.run(Command::ScanFiles {
        paths: vec![folder.clone(), drive()],
        reveal: true,
    })?;
    download.began()?;

    // One line of progress for both: the file on this PC and the three files of the cloud, and
    // the bars of the files being read show a cloud file like any other.
    let snapshot = rig.controller.snapshot();
    assert_eq!(snapshot.scan.map(|(_, total)| total), Some(4));
    assert!(
        snapshot
            .scan_reading
            .iter()
            .any(|reading| sources::is_virtual(&reading.path)),
        "{:?}",
        snapshot.scan_reading
    );
    download.release();

    // One result for both, from one run that loaded the model once and read the account once.
    let snapshot = shown(&rig.controller)?;
    assert_eq!(
        summary_of(&snapshot)?,
        ScanSummary {
            files: 4,
            files_with_data: 3,
            hits: 3,
            counts: vec![(EntityKind::Email, 2), (EntityKind::Iban, 1)],
            unread: 0,
            cloud_only: 0
        }
    );
    assert_eq!(snapshot.inventory_totals, (3, 3));
    assert_eq!(loads(&rig), 1);
    assert_eq!(connections(&rig), 1);
    assert_eq!(cloud.downloads(), 3);

    // The account is a place of the Inventory like a drive, and what it holds is counted.
    let places: Vec<(PathBuf, u64, u32)> = rig
        .controller
        .places()
        .into_iter()
        .map(|node| (node.path, node.hits, node.files))
        .collect();
    assert_eq!(places, [(folder, 1, 1), (drive(), 2, 2)]);
    let top = rig.controller.inventory_view(Path::new(""), None).nodes;
    assert!(
        top.iter()
            .any(|node| node.name == format!(r"\\Google Drive\{LABEL}")),
        "{top:?}"
    );
    Ok(())
}

#[test]
fn a_scan_keeps_where_the_cloud_location_was_left_and_the_next_one_reads_only_what_changed() -> Test
{
    let (rig, cloud, _) = connected(drive_policy(false))?;
    cloud.put("Docs/a.txt", MAIL);
    cloud.put("Docs/b.txt", CALL);
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (2, 2));
    assert_eq!(cloud.downloads(), 2);
    let cursors = Cursors::new(rig.controller.data_dir());
    assert_eq!(cursors.get(&drive()).describe()?, Some(cloud.cursor()));

    // Nothing changed: the scan asks from where the last one left off, and reads nothing.
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(cloud.downloads(), 2);
    assert_eq!(cloud.asked(), [None, Some("g2".to_owned())]);

    // One file changed: only that one is read.
    cloud.put(
        "Docs/b.txt",
        "call +31 6 87654321 or mail piet.pietersen@acme.nl",
    );
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(cloud.downloads(), 3);
    assert_eq!(rig.controller.snapshot().inventory_totals, (2, 3));
    assert_eq!(cursors.get(&drive()).describe()?, Some(cloud.cursor()));
    Ok(())
}

#[test]
fn an_account_is_read_once_for_all_its_locations_in_a_run() -> Test {
    let docs_folder = drive().join("Docs");
    let mail_folder = drive().join("Mail");
    let (rig, cloud, _) = connected(Policy {
        inventory_roots: vec![docs_folder.clone(), mail_folder.clone()],
        ..quiet()
    })?;
    cloud.put("Docs/a.txt", MAIL);
    cloud.put("Mail/b.txt", CALL);
    cloud.put("Elsewhere/c.txt", MAIL);
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (2, 2));
    assert_eq!(cloud.listings(), 2, "each location is listed");
    assert_eq!(connections(&rig), 1);
    let cursors = Cursors::new(rig.controller.data_dir());
    assert!(cursors.get(&docs_folder).describe()?.is_some());
    assert!(cursors.get(&mail_folder).describe()?.is_some());
    Ok(())
}

#[test]
fn monitoring_a_cloud_location_needs_no_watcher_and_reads_it_at_once() -> Test {
    let (rig, cloud, _) = connected(drive_policy(true))?;
    cloud.put("Docs/a.txt", MAIL);
    rig.run(Command::Startup)?;
    // The system has no files of it to report on: nothing is asked to watch it.
    assert!(
        !rig.calls()
            .iter()
            .any(|call| call.starts_with("start_watch")),
        "{:?}",
        rig.calls()
    );
    // What catching up does is the first poll: it reads the location, and that was a change.
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert_eq!(
        snapshot.watch.folders.first().map(|f| &f.path),
        Some(&drive())
    );
    assert!(
        snapshot
            .watch
            .folders
            .first()
            .is_some_and(|f| f.last_change.is_some())
    );
    assert_eq!(cloud.listings(), 1);
    assert_eq!(snapshot.reveal, None, "the dialog is not asked for");
    // The model is kept for as long as the location is monitored.
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert!(has_call(&rig, "load_model"));
    rig.controller.shutdown();
    Ok(())
}

#[test]
fn the_next_poll_finds_a_new_file_and_a_removed_one_and_monitor_off_ends_the_polls() -> Test {
    let (rig, cloud, _) = connected(drive_policy(true))?;
    rig.fake.poll_every(Duration::from_millis(50));
    rig.run(Command::Startup)?;
    // The cloud is empty: the polls come and read nothing, and nothing has changed.
    eventually("the first polls", || cloud.listings() >= 3)?;
    let snapshot = watch_holds(&rig, (0, 0))?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert_eq!(
        snapshot
            .watch
            .folders
            .first()
            .map(|folder| folder.last_change),
        Some(None)
    );

    // A file is added: the next poll reads it, and the location has a change to show.
    cloud.put("Docs/a.txt", MAIL);
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert!(
        snapshot
            .watch
            .folders
            .first()
            .is_some_and(|f| f.last_change.is_some())
    );

    // A file goes: the next poll forgets it.
    cloud.remove("Docs/a.txt");
    watch_holds(&rig, (0, 0))?;
    assert_eq!(rig.controller.inventory().totals().files, 0);

    // Monitor off: nothing asks the account any more, and the location stays.
    rig.run(Command::Edit(Edit::Monitor {
        path: drive(),
        on: false,
    }))?;
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.watch.folders.is_empty());
    assert_eq!(snapshot.policy.inventory_roots, [drive()]);
    let listings = cloud.listings();
    thread::sleep(Duration::from_millis(400));
    assert_eq!(cloud.listings(), listings, "the polls ended");
    Ok(())
}

#[test]
fn removing_a_monitored_cloud_location_ends_its_polls_and_forgets_what_it_held_and_its_cursor()
-> Test {
    let (rig, cloud, _) = connected(drive_policy(true))?;
    cloud.put("Docs/a.txt", MAIL);
    rig.fake.poll_every(Duration::from_millis(50));
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    let cursors = Cursors::new(rig.controller.data_dir());
    assert_eq!(cursors.get(&drive()).describe()?, Some(cloud.cursor()));

    rig.run(Command::Edit(Edit::InventoryRoot {
        path: drive(),
        on: false,
    }))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.policy.inventory_roots.is_empty());
    assert!(snapshot.policy.monitored_roots.is_empty());
    assert!(snapshot.watch.folders.is_empty());
    assert_eq!(snapshot.inventory_totals, (0, 0));
    assert_eq!(rig.controller.inventory().totals().files, 0);
    assert_eq!(
        cursors.get(&drive()).describe()?,
        None,
        "where its scan left off goes too"
    );
    let listings = cloud.listings();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        cloud.listings(),
        listings,
        "nobody asks the account any more"
    );

    // Added again, it is listed in full: no old cursor is left to skip the files it had.
    rig.run(Command::AddLocation(drive()))?;
    let snapshot = shown(&rig.controller)?;
    assert_eq!(summary_of(&snapshot)?.hits, 1);
    assert_eq!(snapshot.inventory_totals, (1, 1));
    assert_eq!(cloud.asked().last(), Some(&None));
    Ok(())
}

#[test]
fn a_cloud_folder_scanned_outside_the_locations_is_shown_and_not_kept_and_listed_in_full_again()
-> Test {
    let (rig, cloud, _) = connected(quiet())?;
    cloud.put("Docs/a.txt", MAIL);
    let folder = drive().join("Docs");
    let scan = || Command::ScanFiles {
        paths: vec![folder.clone()],
        reveal: true,
    };
    rig.run(scan())?;
    let snapshot = shown(&rig.controller)?;
    assert_eq!(summary_of(&snapshot)?.hits, 1);
    // No location holds it: the Inventory keeps nothing of it, nor where its scan left off, but
    // the findings view of the result still reads its file.
    assert_eq!(snapshot.inventory_totals, (0, 0));
    assert_eq!(rig.controller.inventory().totals().files, 0);
    assert_eq!(
        Cursors::new(rig.controller.data_dir())
            .get(&folder)
            .describe()?,
        None
    );
    let listed = rig.controller.finding_files(std::slice::from_ref(&folder));
    assert_eq!(
        listed
            .files
            .iter()
            .map(|file| &file.path)
            .collect::<Vec<_>>(),
        [&folder.join("a.txt")]
    );

    // So the next scan of it lists it in full, and shows the same.
    rig.run(scan())?;
    let again = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| reveal.seq == 2 && matches!(reveal.state, RevealState::Done(_)))
            && s.scan.is_none()
    })?;
    assert_eq!(summary_of(&again)?, summary_of(&snapshot)?);
    assert_eq!(cloud.asked(), [None, None]);
    Ok(())
}

#[test]
fn a_cloud_location_is_added_only_for_a_connected_account_and_scanned_with_the_dialog() -> Test {
    let (rig, cloud) = cloud_rig(quiet())?;
    cloud.put("Docs/a.txt", MAIL);
    // No connected account has that name: it is refused, and nothing is scanned.
    rig.run(Command::AddLocation(drive()))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.policy.inventory_roots.is_empty());
    assert_eq!(snapshot.reveal, None, "nothing was scanned for the dialog");
    let notice = snapshot.notice.ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Error);
    assert!(
        notice.text.starts_with("Not added: no connected account"),
        "{}",
        notice.text
    );
    assert!(!has_call(&rig, "save_policy"));
    assert_eq!(cloud.listings(), 0);

    // With the account connected the same path is a location, scanned with the dialog.
    connect_account(&rig)?;
    rig.run(Command::AddLocation(drive()))?;
    let snapshot = shown(&rig.controller)?;
    assert_eq!(snapshot.policy.inventory_roots, [drive()]);
    assert_eq!(rig.fake.last_saved()?.inventory_roots, [drive()]);
    assert_eq!(summary_of(&snapshot)?.hits, 1);
    assert_eq!(snapshot.inventory_totals, (1, 1));
    Ok(())
}

#[test]
fn a_scan_that_could_not_read_any_root_says_why_and_one_that_read_some_shows_its_result() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let ghost = PathBuf::from(r"\\Dropbox\ghost@acme.com\Files");
    let (rig, cloud, _) = connected(quiet())?;

    // The one root has no account any more: the dialog says why, and so does a notice.
    rig.run(Command::ScanFiles {
        paths: vec![ghost.clone()],
        reveal: true,
    })?;
    let snapshot = shown(&rig.controller)?;
    let why = format!(
        "The account of {} is not connected any more. Connect it again in Settings, or remove the location.",
        piikey::sources::shown(&ghost)
    );
    assert_eq!(
        snapshot.reveal.map(|reveal| reveal.state),
        Some(RevealState::Failed(why.clone()))
    );
    assert_eq!(snapshot.notice.map(|notice| notice.text), Some(why));

    // Another root worked: the dialog shows what was found there, and the notice is for the rest.
    rig.run(Command::ScanFiles {
        paths: vec![folder, ghost],
        reveal: true,
    })?;
    let snapshot = shown(&rig.controller)?;
    assert_eq!(summary_of(&snapshot)?.hits, 1);
    assert!(
        snapshot
            .notice
            .is_some_and(|notice| notice.text.contains("is not connected any more"))
    );

    // An account that cannot be reached is no sign-in to do again: a plain notice, once.
    cloud.fail_with(|| Error::network(Provider::GoogleDrive, "timed out"));
    rig.run(Command::ScanFiles {
        paths: vec![drive()],
        reveal: true,
    })?;
    let snapshot = shown(&rig.controller)?;
    let unreachable =
        "piikey cannot reach Google Drive. Check the internet connection and try again.";
    assert_eq!(
        snapshot.reveal.map(|reveal| reveal.state),
        Some(RevealState::Failed(unreachable.to_owned()))
    );
    let notice = snapshot.notice.ok_or("no notice")?;
    assert_eq!(notice.severity, Severity::Warning);
    assert_eq!(notice.text, format!("{LABEL}: {unreachable}"));
    assert_eq!(notice.action, None);
    assert_eq!(
        snapshot.accounts.first().map(|view| view.status.clone()),
        Some(AccountStatus::Problem(unreachable.to_owned()))
    );
    Ok(())
}

#[test]
fn the_findings_of_cloud_files_are_listed_from_the_inventory_and_read_through_the_account() -> Test
{
    let (rig, cloud, account) = connected(drive_policy(false))?;
    cloud.put("Docs/a.txt", MAIL);
    cloud.put(
        "Docs/sub/b.txt",
        "jan.jansen@acme.nl and piet.pietersen@acme.nl",
    );
    cloud.put("Docs/c.txt", "nothing to see here");
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    // A folder lists the files with personal data, the most first, as a folder on this PC does.
    let folder = drive().join("Docs");
    let listed = rig.controller.finding_files(std::slice::from_ref(&folder));
    let labels: Vec<&str> = listed
        .files
        .iter()
        .map(|file| file.label.as_str())
        .collect();
    assert_eq!(labels, ["sub \u{203a} b.txt", "a.txt"]);
    assert_eq!(
        listed.files.first().map(|file| &file.path),
        Some(&folder.join("sub").join("b.txt"))
    );
    assert_eq!(listed.left_out, 0);
    // A path that has an entry of its own is a file, whether or not it holds anything; one that
    // the inventory knows nothing of is taken for a folder with nothing in it.
    let file = folder.join("a.txt");
    let clean = folder.join("c.txt");
    let named = rig.controller.finding_files(&[file.clone(), clean.clone()]);
    let paths: Vec<&PathBuf> = named.files.iter().map(|listed| &listed.path).collect();
    assert_eq!(paths, [&file, &clean]);
    assert_eq!(named.files.first().map(|f| f.label.as_str()), Some("a.txt"));
    let unknown = rig.controller.finding_files(&[folder.join("unknown.txt")]);
    assert!(unknown.files.is_empty());

    // The values are read through the account into memory, and kept nowhere.
    let gone = folder.join("gone.txt");
    let events = read_events(
        &rig.controller,
        &[file.clone(), gone.clone()],
        1_000,
        |_| true,
    );
    assert!(
        matches!(events.first(), Some(FindingsEvent::Loading)),
        "{events:?}"
    );
    let (found, ended) = of_file(&events, &file);
    assert_eq!(ended, Some(Ok(())));
    assert_eq!(found.len(), 1);
    assert_eq!(found.first().map(|f| f.kind), Some(EntityKind::Email));
    assert_eq!(found.first().map(|f| &*f.value), Some("jan.jansen@acme.nl"));
    assert_eq!(found.first().map(|f| &*f.snippet), Some(MAIL));
    let (nothing, ended) = of_file(&events, &gone);
    assert!(nothing.is_empty());
    assert!(ended.is_some_and(|result| {
        result.is_err_and(|error| error.contains("no longer in Google Drive"))
    }));
    assert_eq!(
        rig.controller.inventory().totals().files,
        3,
        "reading is no scanning"
    );

    // An account that has to sign in again: that is what the file says, and a notice has the button.
    cloud.fail_with(|| Error::sign_in_needed(Provider::GoogleDrive, "expired"));
    let events = read_events(&rig.controller, std::slice::from_ref(&file), 1_000, |_| {
        true
    });
    let (_, ended) = of_file(&events, &file);
    assert_eq!(
        ended,
        Some(Err("Sign in to Google Drive again.".to_owned()))
    );
    let notice = rig.notice().ok_or("no notice")?;
    assert_eq!(
        notice.action,
        Some(NoticeAction::SignIn {
            account: account.id,
            provider: Provider::GoogleDrive
        })
    );

    // A masked copy is written beside a file on this PC, and a cloud file is not on it.
    let refused = rig
        .controller
        .masked_copy(&file)
        .err()
        .ok_or("no copy of a cloud file")?;
    assert_eq!(
        refused,
        "A masked copy can only be made of a file on this PC."
    );
    Ok(())
}

#[test]
fn a_requested_scan_stops_a_poll_which_starts_again_once_the_scan_is_done() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let (rig, cloud, _) = connected(Policy {
        inventory_roots: vec![folder.clone(), drive()],
        monitored_roots: vec![drive()],
        ..quiet()
    })?;
    cloud.put("Docs/a.txt", CALL);
    // The poll that catching up makes waits in the cloud ...
    let first = cloud.hold_listing();
    rig.run(Command::Startup)?;
    first.began()?;

    // ... and gives way to the scan somebody asks for, which does not wait for it.
    let second = cloud.hold_listing();
    rig.run(Command::ScanFiles {
        paths: vec![folder],
        reveal: false,
    })?;
    // The poll starts again after the scan: the file on this PC is in by then.
    second.began()?;
    assert_eq!(cloud.stopped(), 1, "the poll was told to give way");
    assert_eq!(rig.controller.inventory().totals().files, 1);
    assert_eq!(rig.controller.snapshot().scan, None);
    assert_eq!(cloud.downloads(), 0, "the poll that gave way read nothing");
    assert_eq!(
        cloud.asked(),
        [None, None],
        "it starts over with no cursor to keep"
    );
    second.release();
    let snapshot = watch_holds(&rig, (2, 2))?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert_eq!((cloud.listings(), cloud.downloads()), (2, 1));
    Ok(())
}

#[test]
fn the_inventory_keeps_what_a_cloud_location_holds_and_tidies_the_rest_at_start() -> Test {
    let (rig, cloud, _) = connected(drive_policy(false))?;
    cloud.put("Docs/a.txt", MAIL);
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    // An older piikey left an entry of the account's other Drive, which no location holds.
    let other = Path::new(r"\\Google Drive\jan@acme.com\Shared with me\old.txt");
    rig.controller
        .inventory()
        .record(vec![entry_of(other, &[(EntityKind::Email, 1)])])
        .describe()?;
    assert_eq!(rig.controller.inventory().totals().files, 2);

    // Starting tidies the inventory to its locations: what the Drive holds stays.
    rig.run(Command::Startup)?;
    assert_eq!(rig.controller.inventory().totals().files, 1);
    assert!(rig.controller.inventory().entry(other).is_none());
    assert_eq!(rig.controller.snapshot().inventory_totals, (1, 1));
    let places: Vec<PathBuf> = rig
        .controller
        .places()
        .into_iter()
        .map(|node| node.path)
        .collect();
    assert_eq!(places, [drive()]);
    Ok(())
}

#[test]
fn lost_reports_of_the_system_have_the_cloud_locations_asked_too_but_show_no_change_there() -> Test
{
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let (rig, cloud, _) = connected(Policy {
        inventory_roots: vec![folder.clone(), drive()],
        monitored_roots: vec![folder.clone(), drive()],
        ..quiet()
    })?;
    rig.run(Command::Startup)?;
    // The system watches the folder on this PC, and only that one.
    assert!(has_call(&rig, "start_watch(1)"));
    watch_holds(&rig, (1, 1))?;
    assert_eq!(cloud.listings(), 1);

    // The system says it lost track: everything is looked at, the Drive is asked too.
    rig.fake.report(Change::Everything)?;
    let snapshot = wait_for(&rig.controller, |s| {
        cloud.listings() >= 2 && s.watch.scanning.is_none()
    })?;
    assert_eq!(
        statuses(&snapshot),
        [FolderStatus::Watching, FolderStatus::Watching]
    );
    // A change somewhere on this PC, and nothing of the kind in the empty Drive.
    let changes: Vec<Option<u64>> = snapshot
        .watch
        .folders
        .iter()
        .map(|folder| folder.last_change)
        .collect();
    assert!(matches!(changes.as_slice(), [Some(_), None]), "{changes:?}");
    Ok(())
}
