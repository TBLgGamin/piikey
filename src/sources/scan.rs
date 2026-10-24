//! Scanning a cloud location into the inventory, and reading one cloud file for the findings view.
//!
//! A scan of a location asks the account's [`Connector`] what changed since the cursor of the last
//! scan (everything, the first time), reads the files that are new or changed, and forgets what is
//! gone. It reports through the same [`Progress`] a scan of folders on this PC reports to, adding
//! to its count, so one run can scan both: scan the folders on this PC first (that starts the
//! count), then each cloud location with the same `progress` and `cancel`.
//!
//! A file is read again when its size, its time or its version (a content hash, a revision: what
//! [`RemoteItem::version`] says) differs from what the inventory has seen. The inventory has no
//! field for a version, so [`filetime`] folds it into the digits of the stored time below a
//! millisecond, which no service reports.

use std::{
    collections::{BTreeMap, HashMap},
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{Connector, Error, RemoteItem, Result};
use crate::{
    engine::Engine,
    formats::{self, Report},
    inventory::{
        Inventory, MAX_FILE, Progress,
        remote::{Fetched, Listed},
    },
    sys,
};

/// How long saving the cursors waits for another piikey process that is saving them.
const SAVE_WAIT: Duration = Duration::from_secs(5);
/// Windows `FILETIME` ticks (100 ns) in a millisecond.
const TICKS_PER_MS: u64 = 10_000;
/// Milliseconds from 1601-01-01, where a `FILETIME` starts, to 1970-01-01.
const UNIX_AS_FILETIME_MS: u64 = 11_644_473_600_000;
/// How long a cursor is trusted (see [`Cursors::get`]).
const CURSOR_AGE: Duration = Duration::from_hours(7 * 24);

/// The seconds since the Unix epoch.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// How a scan of one cloud location ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    /// Where to go on from next time (see [`Cursors`]). `None` when the scan did not get to the
    /// end because it was cancelled: the cursor of the last scan stays, and what was not read is
    /// found again.
    pub cursor: Option<String>,
    /// The listing was complete, not only what changed: a first scan, or a cursor the service no
    /// longer knew.
    pub full: bool,
    /// How many files the account named.
    pub listed: usize,
    /// How many entries were recorded or replaced.
    pub read: usize,
    /// How many entries were forgotten: what the account says is gone, and after a complete
    /// listing what it does not name.
    pub forgotten: usize,
}

impl Scanned {
    fn stopped() -> Self {
        Self {
            cursor: None,
            full: false,
            listed: 0,
            read: 0,
            forgotten: 0,
        }
    }

    /// Whether the scan got to the end (so its cursor is to be kept).
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.cursor.is_some()
    }
}

/// Brings the inventory up to date with the location `root` (a virtual path of the connector's
/// account): what changed since `cursor` (everything for `None`) is read and recorded, what is
/// gone is forgotten. Keep the cursor of the result for the next scan (see [`Cursors`]).
///
/// What is gone is forgotten before the changes are read, and what a complete listing does not
/// name after: so a file that went and came back is read again, not lost. The work goes on the
/// rayon pool the caller runs in, as a scan of folders does, and `progress` and `cancel` are
/// the ones of a scan of folders: the files to read are added to [`Progress::total`] and each one
/// done to [`Progress::done`], the files being read are in [`Progress::reading`], and a set
/// `cancel` ends the scan within the file it is in. A file the account does not let piikey read
/// is recorded as one that failed, with a sentence that says what to do; a file that went in the
/// meantime is skipped; a failure of the account itself (it has to sign in again, the service is
/// out of reach or busy) ends the scan with that error, keeping what was done and the old cursor.
///
/// For one run over folders on this PC and cloud locations, scan the folders first with
/// [`Inventory::scan_paths`] (it starts the count), then each cloud location with the same
/// `progress` and `cancel`: the counts add up. Hold [`Inventory::lock_scan`] for the whole run,
/// as for a scan of folders.
///
/// # Errors
/// `NotFound` when the location is no longer in the account (nothing is forgotten), `SignInNeeded`,
/// `Forbidden`, `Throttled`, `Network` and `Unexpected` from the account, and `Local` when the
/// inventory cannot be read or saved.
pub fn scan_remote(
    connector: &dyn Connector,
    inventory: &Inventory,
    engine: &Engine,
    root: &Path,
    cursor: Option<&str>,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<Scanned> {
    if cancel.load(Ordering::Relaxed) {
        return Ok(Scanned::stopped());
    }
    let folder = connector.folder(root)?;
    let changes = match connector.changes(&folder, cursor, cancel) {
        Ok(changes) => changes,
        Err(Error::Cancelled) => return Ok(Scanned::stopped()),
        Err(error) => return Err(error),
    };
    let items = distinct(changes.items, root);
    let listed: Vec<Listed> = items
        .iter()
        .map(|item| Listed {
            path: item.path.clone(),
            size: item.export.is_none().then_some(item.size),
            modified: filetime(item.modified, &item.version),
        })
        .collect();

    let mut forgotten = inventory.forget_removed(root, &changes.removed)?;
    let fatal: Mutex<Option<Error>> = Mutex::new(None);
    let fetch = |index: usize| match items.get(index) {
        None => Fetched::Gone,
        Some(item) => match connector.download(item, MAX_FILE, cancel) {
            Ok(bytes) => Fetched::Bytes(bytes),
            Err(Error::TooLarge) => Fetched::TooLarge,
            Err(Error::NotFound { .. }) => Fetched::Gone,
            Err(Error::Cancelled) => Fetched::Stop,
            Err(error @ (Error::Forbidden { .. } | Error::Unexpected { .. })) => {
                Fetched::Failed(error.to_string())
            }
            Err(error) => {
                fatal
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get_or_insert(error);
                Fetched::Stop
            }
        },
    };
    let outcome = inventory.scan_listed(engine, &listed, &fetch, progress, cancel)?;
    if let Some(error) = fatal.into_inner().unwrap_or_else(PoisonError::into_inner) {
        return Err(error);
    }
    if !outcome.finished {
        return Ok(Scanned {
            read: outcome.recorded,
            forgotten,
            ..Scanned::stopped()
        });
    }
    if changes.full {
        forgotten += inventory.forget_unlisted(root, &listed)?;
    }
    Ok(Scanned {
        cursor: Some(changes.cursor),
        full: changes.full,
        listed: listed.len(),
        read: outcome.recorded,
        forgotten,
    })
}

/// The items under `root`, each path once (the last of two wins), in the order they came.
fn distinct(items: Vec<RemoteItem>, root: &Path) -> Vec<RemoteItem> {
    let mut at: HashMap<String, usize> = HashMap::with_capacity(items.len());
    let mut kept: Vec<Option<RemoteItem>> = Vec::with_capacity(items.len());
    for item in items {
        if !sys::is_under(&item.path, root) {
            continue;
        }
        let key = sys::path_key(&item.path);
        if let Some(&index) = at.get(&key) {
            kept[index] = Some(item);
        } else {
            at.insert(key, kept.len());
            kept.push(Some(item));
        }
    }
    kept.into_iter().flatten().collect()
}

/// A time as the inventory keeps it (a Windows `FILETIME`, 100 ns ticks since 1601) with a
/// fingerprint of `version` in the ticks below a millisecond: the same time and version always
/// give the same number, another version gives another number (all but 1 time in 10,000), and
/// the time is not changed by more than a millisecond. Never 0: that means the time is not known.
#[must_use]
pub(crate) fn filetime(time: SystemTime, version: &str) -> u64 {
    let ms = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0));
    let digest = blake3::hash(version.as_bytes());
    let mut head = [0; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    let fingerprint = u64::from_le_bytes(head) % TICKS_PER_MS;
    ms.saturating_add(UNIX_AS_FILETIME_MS)
        .saturating_mul(TICKS_PER_MS)
        .saturating_add(fingerprint)
}

/// Reads the cloud file at the virtual path `path` now and reports what the detector finds in it
/// to `report`, as [`crate::inventory::findings`] does for a file on this PC (same passes over
/// the same formats, same places, same `report` contract): it is downloaded into memory, read and
/// dropped, and nothing is kept. A set `cancel` ends the download within a moment.
///
/// # Errors
/// `NotFound` when nothing (or a folder) is at `path`; `Cancelled`; the errors of the account;
/// `Local` with `UnsupportedFormat` when the file is over [`MAX_FILE`] or in a format piikey does
/// not read, and the other errors of reading the format.
pub fn findings(
    connector: &dyn Connector,
    engine: &Engine,
    path: &Path,
    cancel: &AtomicBool,
    report: &(dyn Fn(Report) -> bool + Sync),
) -> Result<()> {
    let item = connector.file(path)?;
    let bytes = match connector.download(&item, MAX_FILE, cancel) {
        Ok(bytes) => bytes,
        Err(Error::TooLarge) => {
            return Err(crate::Error::UnsupportedFormat("the file is too large to be read").into());
        }
        Err(error) => return Err(error),
    };
    Ok(formats::findings(engine, &bytes, report)?)
}

/// Where each cloud location's scan left off: `<data folder>\sources\cursors.json`. A cursor is
/// opaque (the connector made it); it only makes the next scan cheap, so a missing or damaged
/// file just means a full listing.
#[derive(Debug, Clone)]
pub struct Cursors {
    path: PathBuf,
}

/// One cursor as the file keeps it.
#[derive(Serialize, Deserialize)]
struct Kept {
    /// The location as it was named (the key is its lower-case form).
    location: String,
    cursor: String,
    /// When the cursor was kept: seconds since the Unix epoch.
    #[serde(default)]
    at: u64,
}

impl Cursors {
    /// The cursors kept in the data folder `data`.
    #[must_use]
    pub fn new(data: &Path) -> Self {
        Self {
            path: data.join("sources").join("cursors.json"),
        }
    }

    /// The cursor of the scan that last ended at the location `location`, if there is one that
    /// is not older than a week: a change feed cannot always say where a file that was moved or
    /// renamed used to be, so after a week the next scan lists the whole location again, which
    /// reads nothing that did not change, and forgets what such a move left behind.
    ///
    /// # Errors
    /// `Io` when the file exists but cannot be read.
    pub fn get(&self, location: &Path) -> crate::Result<Option<String>> {
        let now = unix_now();
        Ok(self
            .read()?
            .remove(&sys::path_key(location))
            .filter(|kept| now.saturating_sub(kept.at) <= CURSOR_AGE.as_secs())
            .map(|kept| kept.cursor))
    }

    /// Keeps `cursor` for `location`, replacing the last.
    ///
    /// # Errors
    /// `Io` when the file cannot be written; `Busy` when another piikey process holds it for
    /// longer than a save takes.
    pub fn set(&self, location: &Path, cursor: &str) -> crate::Result<()> {
        self.put(location, cursor, unix_now())
    }

    /// [`Cursors::set`], with the time it was kept.
    fn put(&self, location: &Path, cursor: &str, at: u64) -> crate::Result<()> {
        self.edit(|kept| {
            kept.insert(
                sys::path_key(location),
                Kept {
                    location: location.to_string_lossy().into_owned(),
                    cursor: cursor.to_owned(),
                    at,
                },
            );
        })
    }

    /// Forgets the cursors of the locations at and under `prefix` (a location that is removed, or
    /// every location of an account that is disconnected): the next scan of one starts over.
    ///
    /// # Errors
    /// As [`Cursors::set`].
    pub fn forget_under(&self, prefix: &Path) -> crate::Result<()> {
        self.edit(|kept| kept.retain(|_, one| !sys::is_under(Path::new(&one.location), prefix)))
    }

    /// The file's cursors by lower-case location; none when it is missing or damaged.
    fn read(&self) -> crate::Result<BTreeMap<String, Kept>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(sys::io_context(&error, "read", &self.path)),
        }
    }

    /// Changes the file under its lock.
    fn edit(&self, change: impl FnOnce(&mut BTreeMap<String, Kept>)) -> crate::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|error| sys::io_context(&error, "create", dir))?;
        }
        let _lock =
            sys::lock_within(&self.path.with_extension("lock"), SAVE_WAIT)?.ok_or_else(|| {
                crate::Error::Busy("another piikey process is saving the cursors".to_owned())
            })?;
        let mut kept = self.read()?;
        change(&mut kept);
        let bytes = serde_json::to_vec(&kept).map_err(io::Error::from)?;
        sys::write_atomic(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::AtomicUsize, time::Duration};

    use super::*;
    use crate::{
        detect::EntityKind::{Email, Iban},
        inventory::Status,
        sources::{Changes, Export, Provider, RemoteFolder, Resolved, testing::Res},
        testing::temp_dir,
    };

    const EMAIL: &str = "jan.jansen@acme.nl";
    const IBAN: &str = "NL91ABNA0417164300";
    const ROOT: &str = r"\\Dropbox\work";

    /// A file of the fake account.
    struct Held {
        bytes: Vec<u8>,
        modified: SystemTime,
        version: String,
        /// A file with no bytes of its own, which the service converts when it is downloaded.
        export: Option<Export>,
    }

    #[derive(Default)]
    struct State {
        files: BTreeMap<PathBuf, Held>,
        generation: u64,
        changed: Vec<(u64, PathBuf)>,
        removed: Vec<(u64, PathBuf)>,
        /// A cursor older than this is one the service no longer knows.
        expired_before: u64,
        /// Downloads of these paths fail with this.
        refuse: BTreeMap<PathBuf, fn() -> Error>,
    }

    /// An account that lives in memory: a change feed with generations for cursors.
    #[derive(Default)]
    struct Cloud {
        state: Mutex<State>,
        downloads: AtomicUsize,
        listings: AtomicUsize,
        /// What `changes` was asked with, the cursors it was given.
        asked: Mutex<Vec<Option<String>>>,
    }

    impl Cloud {
        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Puts (or replaces) a file; `version` says what its contents are called by the service.
        fn put(&self, name: &str, text: &str, version: &str, seconds: u64) {
            self.put_as(name, text, version, seconds, None);
        }

        /// A Google-Docs-like file: no size of its own, downloaded as a Word file.
        fn put_doc(&self, name: &str, text: &str, version: &str, seconds: u64) {
            self.put_as(name, text, version, seconds, Some(Export::Docx));
        }

        fn put_as(
            &self,
            name: &str,
            text: &str,
            version: &str,
            seconds: u64,
            export: Option<Export>,
        ) {
            let path = Path::new(ROOT).join(name);
            let mut state = self.state();
            state.generation += 1;
            let generation = state.generation;
            state.changed.push((generation, path.clone()));
            state.files.insert(
                path,
                Held {
                    bytes: text.as_bytes().to_vec(),
                    modified: UNIX_EPOCH + Duration::from_secs(seconds),
                    version: version.to_owned(),
                    export,
                },
            );
        }

        fn remove(&self, name: &str) {
            let path = Path::new(ROOT).join(name);
            let mut state = self.state();
            state.generation += 1;
            let generation = state.generation;
            state.removed.push((generation, path.clone()));
            state.files.remove(&path);
        }

        fn item(path: &Path, held: &Held) -> RemoteItem {
            RemoteItem {
                id: path.to_string_lossy().into_owned(),
                path: path.to_path_buf(),
                size: if held.export.is_some() {
                    0
                } else {
                    u64::try_from(held.bytes.len()).unwrap_or(u64::MAX)
                },
                modified: held.modified,
                version: held.version.clone(),
                web_url: String::new(),
                export: held.export,
            }
        }

        fn downloads(&self) -> usize {
            self.downloads.load(Ordering::SeqCst)
        }
    }

    impl Connector for Cloud {
        fn provider(&self) -> Provider {
            Provider::Dropbox
        }

        fn browse(&self, _: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>> {
            Ok(Vec::new())
        }

        fn resolve(&self, path: &Path) -> Result<Resolved> {
            let state = self.state();
            if sys::same_path(path, Path::new(ROOT)) {
                return Ok(Resolved::Folder(RemoteFolder {
                    id: "root".to_owned(),
                    path: path.to_path_buf(),
                    web_url: String::new(),
                }));
            }
            state
                .files
                .get(path)
                .map(|held| Resolved::File(Self::item(path, held)))
                .ok_or_else(|| Error::not_found(Provider::Dropbox, "no such file"))
        }

        fn changes(
            &self,
            _: &RemoteFolder,
            cursor: Option<&str>,
            cancel: &AtomicBool,
        ) -> Result<Changes> {
            self.listings.fetch_add(1, Ordering::SeqCst);
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(cursor.map(str::to_owned));
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let state = self.state();
            let next = format!("g{}", state.generation);
            let since = cursor
                .and_then(|cursor| cursor.strip_prefix('g')?.parse::<u64>().ok())
                .filter(|since| *since >= state.expired_before);
            Ok(match since {
                None => Changes {
                    items: state
                        .files
                        .iter()
                        .map(|(path, held)| Self::item(path, held))
                        .collect(),
                    removed: Vec::new(),
                    cursor: next,
                    full: true,
                },
                Some(since) => {
                    let mut paths: Vec<&PathBuf> = state
                        .changed
                        .iter()
                        .filter(|(generation, _)| *generation > since)
                        .map(|(_, path)| path)
                        .collect();
                    paths.dedup();
                    Changes {
                        items: paths
                            .into_iter()
                            .filter_map(|path| {
                                state.files.get(path).map(|held| Self::item(path, held))
                            })
                            .collect(),
                        removed: state
                            .removed
                            .iter()
                            .filter(|(generation, _)| *generation > since)
                            .map(|(_, path)| path.clone())
                            .collect(),
                        cursor: next,
                        full: false,
                    }
                }
            })
        }

        fn download(&self, item: &RemoteItem, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>> {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            self.downloads.fetch_add(1, Ordering::SeqCst);
            let state = self.state();
            if let Some(refuse) = state.refuse.get(&item.path) {
                return Err(refuse());
            }
            let held = state
                .files
                .get(&item.path)
                .ok_or_else(|| Error::not_found(Provider::Dropbox, "no such file"))?;
            if u64::try_from(held.bytes.len()).is_ok_and(|len| len > max) {
                return Err(Error::TooLarge);
            }
            Ok(held.bytes.clone())
        }
    }

    struct World {
        engine: Engine,
        inventory: Inventory,
        cursors: Cursors,
        cloud: Cloud,
        dir: PathBuf,
    }

    impl World {
        fn new(tag: &str) -> Res<Self> {
            let dir = temp_dir(tag);
            Ok(Self {
                engine: Engine::open(&dir.join("vault.pkv"))?,
                inventory: Inventory::open(&dir.join("inventory.jsonl"))?,
                cursors: Cursors::new(&dir),
                cloud: Cloud::default(),
                dir,
            })
        }

        /// One scan of the location with what `cursors` has, keeping the cursor as a caller does.
        fn scan(&self) -> Res<Scanned> {
            self.scan_with(&Progress::default(), &AtomicBool::new(false))
        }

        fn scan_with(&self, progress: &Progress, cancel: &AtomicBool) -> Res<Scanned> {
            let root = Path::new(ROOT);
            let cursor = self.cursors.get(root)?;
            let scanned = scan_remote(
                &self.cloud,
                &self.inventory,
                &self.engine,
                root,
                cursor.as_deref(),
                progress,
                cancel,
            )?;
            if let Some(next) = &scanned.cursor {
                self.cursors.set(root, next)?;
            }
            Ok(scanned)
        }

        fn counts(&self, name: &str) -> Option<Vec<(crate::detect::EntityKind, u32)>> {
            self.inventory
                .entry(&Path::new(ROOT).join(name))
                .map(|entry| entry.counts)
        }

        fn names(&self) -> Vec<String> {
            self.inventory
                .entries(Some(Path::new(ROOT)), 0)
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                })
                .collect()
        }
    }

    #[test]
    fn the_first_scan_records_every_item_and_the_next_one_with_the_cursor_reads_nothing() -> Res {
        let world = World::new("scan-first")?;
        world
            .cloud
            .put("a.txt", &format!("mail {EMAIL}"), "v1", 1_000);
        world
            .cloud
            .put("b.txt", &format!("iban {IBAN}"), "v1", 1_001);
        world.cloud.put("c.txt", "nothing here", "v1", 1_002);

        let progress = Progress::default();
        let first = world.scan_with(&progress, &AtomicBool::new(false))?;
        assert_eq!(
            first,
            Scanned {
                cursor: Some("g3".to_owned()),
                full: true,
                listed: 3,
                read: 3,
                forgotten: 0
            }
        );
        assert!(first.finished());
        assert_eq!(world.cloud.downloads(), 3);
        assert_eq!(progress.total.load(Ordering::Relaxed), 3);
        assert_eq!(progress.done.load(Ordering::Relaxed), 3);
        assert_eq!(world.counts("a.txt"), Some(vec![(Email, 1)]));
        assert_eq!(world.counts("b.txt"), Some(vec![(Iban, 1)]));
        assert_eq!(world.counts("c.txt"), Some(vec![]));
        let entry = world
            .inventory
            .entry(&Path::new(ROOT).join("a.txt"))
            .ok_or("no entry")?;
        assert_eq!(entry.size, u64::try_from(format!("mail {EMAIL}").len())?);
        assert_eq!(entry.status, Status::Ok);

        let second = world.scan()?;
        assert_eq!(
            second,
            Scanned {
                cursor: Some("g3".to_owned()),
                full: false,
                listed: 0,
                read: 0,
                forgotten: 0
            }
        );
        assert_eq!(
            world.cloud.downloads(),
            3,
            "nothing changed, nothing is read"
        );
        let asked = world.cloud.asked.lock().map_err(|_| "poisoned")?.clone();
        assert_eq!(asked, [None, Some("g3".to_owned())]);
        Ok(())
    }

    #[test]
    fn a_full_listing_of_files_that_did_not_change_reads_nothing_but_a_new_version_is_read() -> Res
    {
        let world = World::new("scan-version")?;
        world
            .cloud
            .put("a.txt", &format!("mail {EMAIL}"), "v1", 1_000);
        world.cloud.put("b.txt", "plain", "v1", 1_000);
        world.scan()?;
        assert_eq!(world.cloud.downloads(), 2);

        // No cursor: the whole account is listed again, and every file still matches.
        let progress = Progress::default();
        let again = scan_remote(
            &world.cloud,
            &world.inventory,
            &world.engine,
            Path::new(ROOT),
            None,
            &progress,
            &AtomicBool::new(false),
        )?;
        assert!(again.full);
        assert_eq!((again.listed, again.read, again.forgotten), (2, 0, 0));
        assert_eq!(world.cloud.downloads(), 2);
        assert_eq!(progress.total.load(Ordering::Relaxed), 0);

        // Same size, same time, another version: the service says the contents changed.
        world
            .cloud
            .put("a.txt", &format!("mail {EMAIL}"), "v2", 1_000);
        let after = world.scan()?;
        assert_eq!(after.read, 1);
        assert_eq!(world.cloud.downloads(), 3);
        Ok(())
    }

    #[test]
    fn a_file_with_no_size_of_its_own_is_read_once_and_again_when_its_version_changes() -> Res {
        let world = World::new("scan-export")?;
        let text = format!("mail {EMAIL}");
        world.cloud.put_doc("notes", &text, "7", 1_000);
        let first = world.scan()?;
        assert_eq!((first.listed, first.read), (1, 1));
        let path = Path::new(ROOT).join("notes");
        let entry = world.inventory.entry(&path).ok_or("no entry")?;
        assert_eq!(
            entry.size,
            u64::try_from(text.len())?,
            "the size of what was downloaded"
        );
        assert_eq!(entry.counts, vec![(Email, 1)]);

        // Listed again with no size: nothing is compared but the time and the version.
        let again = scan_remote(
            &world.cloud,
            &world.inventory,
            &world.engine,
            Path::new(ROOT),
            None,
            &Progress::default(),
            &AtomicBool::new(false),
        )?;
        assert_eq!((again.listed, again.read), (1, 0));
        assert_eq!(world.cloud.downloads(), 1);

        world
            .cloud
            .put_doc("notes", &format!("{text} and {IBAN}"), "8", 1_000);
        assert_eq!(world.scan()?.read, 1);
        let counts = world.counts("notes").ok_or("no entry")?;
        assert!(
            counts.contains(&(Email, 1)) && counts.contains(&(Iban, 1)),
            "{counts:?}"
        );
        Ok(())
    }

    #[test]
    fn a_changed_item_is_detected_again_and_a_removed_one_is_forgotten() -> Res {
        let world = World::new("scan-change")?;
        world
            .cloud
            .put("a.txt", &format!("mail {EMAIL}"), "v1", 1_000);
        world
            .cloud
            .put("b.txt", &format!("iban {IBAN}"), "v1", 1_000);
        world.cloud.put("keep.txt", "plain", "v1", 1_000);
        world.scan()?;

        world
            .cloud
            .put("a.txt", &format!("mail {EMAIL} and {IBAN}"), "v2", 2_000);
        world.cloud.remove("b.txt");
        let progress = Progress::default();
        let scanned = world.scan_with(&progress, &AtomicBool::new(false))?;
        assert_eq!(
            (
                scanned.full,
                scanned.listed,
                scanned.read,
                scanned.forgotten
            ),
            (false, 1, 1, 1)
        );
        assert_eq!(world.cloud.downloads(), 4);
        assert_eq!(progress.total.load(Ordering::Relaxed), 1);
        let counts = world.counts("a.txt").ok_or("no entry")?;
        assert!(
            counts.contains(&(Email, 1)) && counts.contains(&(Iban, 1)),
            "{counts:?}"
        );
        assert_eq!(world.counts("b.txt"), None);
        assert_eq!(world.names(), ["a.txt", "keep.txt"]);

        // A file that went and came back in one feed is read again, not lost.
        world.cloud.remove("keep.txt");
        world.cloud.put("keep.txt", "plain again", "v9", 3_000);
        world.scan()?;
        assert_eq!(world.names(), ["a.txt", "keep.txt"]);
        Ok(())
    }

    #[test]
    fn a_cursor_the_service_forgot_gives_a_full_listing_that_forgets_what_it_does_not_name() -> Res
    {
        let world = World::new("scan-expired")?;
        world.cloud.put("a.txt", "plain", "v1", 1_000);
        world.scan()?;
        // Something the inventory knows that the account does not, and things of other trees.
        let stray = |path: &str| crate::inventory::Entry {
            path: PathBuf::from(path),
            size: 1,
            modified: 1,
            scanned: 1,
            status: Status::Ok,
            counts: vec![(Email, 1)],
            hash: None,
        };
        world.inventory.record(vec![
            stray(r"\\Dropbox\work\ghost.txt"),
            stray(r"\\Dropbox\other\x.txt"),
            stray(r"C:\local\y.txt"),
        ])?;
        world.cloud.state().expired_before = 99;

        let scanned = world.scan()?;
        assert!(scanned.full);
        assert_eq!((scanned.listed, scanned.read, scanned.forgotten), (1, 0, 1));
        assert_eq!(world.names(), ["a.txt"]);
        assert!(
            world
                .inventory
                .entry(Path::new(r"\\Dropbox\other\x.txt"))
                .is_some()
        );
        assert!(
            world
                .inventory
                .entry(Path::new(r"C:\local\y.txt"))
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn a_scan_that_is_cancelled_gives_no_cursor_and_the_rest_is_found_next_time() -> Res {
        let world = World::new("scan-cancel")?;
        for n in 0..4 {
            world
                .cloud
                .put(&format!("{n}.txt"), "plain", "v1", 1_000 + n);
        }
        let cancelled = AtomicBool::new(true);
        let scanned = world.scan_with(&Progress::default(), &cancelled)?;
        assert_eq!(scanned, Scanned::stopped());
        assert!(!scanned.finished());
        assert_eq!(world.cursors.get(Path::new(ROOT))?, None);
        assert_eq!(world.cloud.listings.load(Ordering::SeqCst), 0);

        let done = world.scan()?;
        assert_eq!((done.full, done.read), (true, 4));
        Ok(())
    }

    #[test]
    fn an_account_that_must_sign_in_again_ends_the_scan_and_keeps_the_old_cursor() -> Res {
        let world = World::new("scan-signin")?;
        world.cloud.put("a.txt", "plain", "v1", 1_000);
        world.scan()?;
        let kept = world.cursors.get(Path::new(ROOT))?;
        world.cloud.put("b.txt", "plain", "v1", 1_000);
        world
            .cloud
            .state()
            .refuse
            .insert(Path::new(ROOT).join("b.txt"), || {
                Error::sign_in_needed(Provider::Dropbox, "401")
            });
        let error = world.scan().err().ok_or("the scan should fail")?;
        let error = error.to_string();
        assert_eq!(error, "Sign in to Dropbox again.");
        assert_eq!(
            world.cursors.get(Path::new(ROOT))?,
            kept,
            "the cursor did not move"
        );

        // Signed in again: the same change is found again and read.
        world.cloud.state().refuse.clear();
        let scanned = world.scan()?;
        assert_eq!((scanned.read, scanned.finished()), (1, true));
        assert_eq!(world.names(), ["a.txt", "b.txt"]);
        Ok(())
    }

    #[test]
    fn a_file_that_may_not_be_read_is_recorded_as_failed_and_the_scan_goes_on() -> Res {
        let world = World::new("scan-forbidden")?;
        world.cloud.put("locked.txt", "plain", "v1", 1_000);
        world
            .cloud
            .put("open.txt", &format!("mail {EMAIL}"), "v1", 1_000);
        world.cloud.put("vanished.txt", "plain", "v1", 1_000);
        world
            .cloud
            .state()
            .refuse
            .insert(Path::new(ROOT).join("locked.txt"), || {
                Error::forbidden(Provider::Dropbox, "403")
            });
        world
            .cloud
            .state()
            .refuse
            .insert(Path::new(ROOT).join("vanished.txt"), || {
                Error::not_found(Provider::Dropbox, "404")
            });
        let scanned = world.scan()?;
        assert!(scanned.finished());
        let locked = world
            .inventory
            .entry(&Path::new(ROOT).join("locked.txt"))
            .ok_or("no entry")?;
        assert_eq!(
            locked.status,
            Status::Failed(
                "Dropbox does not allow piikey to read this. Check what piikey may read there."
                    .to_owned()
            )
        );
        assert_eq!(locked.modified, 0, "the next listing reads it again");
        assert_eq!(world.counts("open.txt"), Some(vec![(Email, 1)]));
        assert_eq!(world.counts("vanished.txt"), None);
        Ok(())
    }

    #[test]
    fn a_location_that_is_not_in_the_account_any_more_forgets_nothing() -> Res {
        let world = World::new("scan-gone")?;
        world.cloud.put("a.txt", "plain", "v1", 1_000);
        world.scan()?;
        let moved = Path::new(r"\\Dropbox\work\folder-that-is-gone");
        let error = scan_remote(
            &world.cloud,
            &world.inventory,
            &world.engine,
            moved,
            None,
            &Progress::default(),
            &AtomicBool::new(false),
        )
        .err()
        .ok_or("the scan should fail")?;
        assert!(matches!(error, Error::NotFound { .. }), "{error:?}");
        assert_eq!(world.names(), ["a.txt"]);
        Ok(())
    }

    #[test]
    fn folders_on_this_pc_and_a_cloud_location_are_one_run_with_one_count() -> Res {
        let world = World::new("scan-mixed")?;
        let local = world.dir.join("docs");
        fs::create_dir_all(&local)?;
        fs::write(local.join("one.txt"), format!("mail {EMAIL}"))?;
        fs::write(local.join("two.txt"), "plain")?;
        world
            .cloud
            .put("a.txt", &format!("iban {IBAN}"), "v1", 1_000);
        world.cloud.put("b.txt", "plain", "v1", 1_000);
        world.cloud.put("c.txt", "plain", "v1", 1_000);

        let progress = Progress::default();
        let cancel = AtomicBool::new(false);
        world.inventory.scan_paths(
            &world.engine,
            std::slice::from_ref(&local),
            &progress,
            &cancel,
        )?;
        assert_eq!(
            (
                progress.done.load(Ordering::Relaxed),
                progress.total.load(Ordering::Relaxed)
            ),
            (2, 2)
        );
        world.scan_with(&progress, &cancel)?;
        assert_eq!(
            (
                progress.done.load(Ordering::Relaxed),
                progress.total.load(Ordering::Relaxed)
            ),
            (5, 5),
            "the cloud files add to the count of the folders"
        );

        let summary = world.inventory.summary(&[local, PathBuf::from(ROOT)]);
        assert_eq!(summary.files, 5);
        assert_eq!(
            summary
                .counts
                .iter()
                .map(|&(_, n)| u64::from(n))
                .sum::<u64>(),
            2
        );
        Ok(())
    }

    #[test]
    fn the_findings_of_a_cloud_file_come_from_the_same_pass_as_a_local_one() -> Res {
        let world = World::new("scan-findings")?;
        world.cloud.put(
            "a.txt",
            &format!("write to {EMAIL} about {IBAN}"),
            "v1",
            1_000,
        );
        let found = Mutex::new(Vec::new());
        findings(
            &world.cloud,
            &world.engine,
            &Path::new(ROOT).join("a.txt"),
            &AtomicBool::new(false),
            &|report| {
                if let Report::Found(more) = report {
                    found
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend(more.into_iter().map(|f| (f.kind, f.value.to_string())));
                }
                true
            },
        )?;
        let mut found = found.into_inner().map_err(|_| "poisoned")?;
        found.sort();
        assert_eq!(found, [(Email, EMAIL.to_owned()), (Iban, IBAN.to_owned())]);

        let no = Path::new(ROOT).join("no.txt");
        let never = AtomicBool::new(false);
        let missing = findings(&world.cloud, &world.engine, &no, &never, &|_| true);
        assert!(matches!(missing, Err(Error::NotFound { .. })));
        let folder = findings(
            &world.cloud,
            &world.engine,
            Path::new(ROOT),
            &never,
            &|_| true,
        );
        assert!(matches!(folder, Err(Error::NotFound { .. })));
        let stopped = AtomicBool::new(true);
        let a = Path::new(ROOT).join("a.txt");
        let cancelled = findings(&world.cloud, &world.engine, &a, &stopped, &|_| true);
        assert!(matches!(cancelled, Err(Error::Cancelled)));
        Ok(())
    }

    #[test]
    fn a_file_over_the_size_limit_has_no_findings_to_read() -> Res {
        struct Huge;
        impl Connector for Huge {
            fn provider(&self) -> Provider {
                Provider::Box
            }
            fn browse(&self, _: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>> {
                Ok(Vec::new())
            }
            fn resolve(&self, path: &Path) -> Result<Resolved> {
                Ok(Resolved::File(RemoteItem {
                    id: "1".to_owned(),
                    path: path.to_path_buf(),
                    size: MAX_FILE + 1,
                    modified: UNIX_EPOCH,
                    version: String::new(),
                    web_url: String::new(),
                    export: None,
                }))
            }
            fn changes(
                &self,
                _: &RemoteFolder,
                _: Option<&str>,
                _: &AtomicBool,
            ) -> Result<Changes> {
                Err(Error::Cancelled)
            }
            fn download(&self, _: &RemoteItem, _: u64, _: &AtomicBool) -> Result<Vec<u8>> {
                Err(Error::TooLarge)
            }
        }
        let world = World::new("scan-huge")?;
        let path = Path::new(r"\\Box\work\big.iso");
        let error = findings(&Huge, &world.engine, path, &AtomicBool::new(false), &|_| {
            true
        })
        .err()
        .ok_or("it should fail")?;
        assert!(
            matches!(&error, Error::Local(crate::Error::UnsupportedFormat(_))),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn cursors_are_kept_per_location_and_forgotten_with_it() -> Res {
        let dir = temp_dir("cursors");
        let cursors = Cursors::new(&dir);
        let (a, b) = (Path::new(r"\\Dropbox\work\Docs"), Path::new(r"\\Box\team"));
        assert_eq!(cursors.get(a)?, None);
        cursors.set(a, "one")?;
        cursors.set(b, "two")?;
        cursors.set(a, "three")?;
        assert_eq!(
            cursors.get(Path::new(r"\\dropbox\WORK\docs"))?.as_deref(),
            Some("three")
        );
        assert_eq!(Cursors::new(&dir).get(b)?.as_deref(), Some("two"));
        cursors.forget_under(Path::new(r"\\Dropbox\work"))?;
        assert_eq!(cursors.get(a)?, None);
        assert_eq!(cursors.get(b)?.as_deref(), Some("two"));

        // A file that is not the cursors' is no reason to fail: the next scan lists everything.
        fs::write(dir.join("sources").join("cursors.json"), b"not json")?;
        assert_eq!(cursors.get(b)?, None);
        cursors.set(b, "again")?;
        assert_eq!(cursors.get(b)?.as_deref(), Some("again"));
        Ok(())
    }

    #[test]
    fn a_cursor_older_than_a_week_is_not_used_so_the_location_is_listed_again() -> Res {
        let cursors = Cursors::new(&temp_dir("cursors-age"));
        let location = Path::new(r"\\Dropbox\work");
        let week = CURSOR_AGE.as_secs();
        cursors.put(location, "old", unix_now() - week - 60)?;
        assert_eq!(cursors.get(location)?, None);
        cursors.put(location, "fresh", unix_now() - week + 3_600)?;
        assert_eq!(cursors.get(location)?.as_deref(), Some("fresh"));
        // The first time there was (nothing is that old) is far too old.
        cursors.put(location, "ancient", 0)?;
        assert_eq!(cursors.get(location)?, None);
        Ok(())
    }

    #[test]
    fn a_stored_time_says_the_version_too_without_moving_by_a_millisecond() {
        let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_millis(250);
        let first = filetime(at, "rev-1");
        assert_eq!(
            first,
            filetime(at, "rev-1"),
            "the same inputs, the same number"
        );
        assert_ne!(first, filetime(at, "rev-2"));
        assert_eq!(first / TICKS_PER_MS, filetime(at, "rev-2") / TICKS_PER_MS);
        // Unix 1_700_000_000.250 s in FILETIME ticks, less the fingerprint.
        assert_eq!(
            first / TICKS_PER_MS,
            (1_700_000_000 * 1_000 + 250) + UNIX_AS_FILETIME_MS
        );
        assert_ne!(
            filetime(at, "rev-1"),
            filetime(at + Duration::from_millis(1), "rev-1")
        );
        assert_ne!(filetime(UNIX_EPOCH, ""), 0);
        assert_ne!(filetime(UNIX_EPOCH - Duration::from_secs(1), ""), 0);
    }
}
