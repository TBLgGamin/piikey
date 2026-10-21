//! The PII inventory: which files in the folders the user watches hold personal data, and how
//! much of it. A scan keeps, for each file, how many values of each kind the detector found,
//! never the values: the inventory is no more sensitive than a list of file names and numbers.
//!
//! It is stored beside the vault as `inventory.jsonl`, one JSON object per file:
//! `{"path","size","modified","scanned","status","error"?,"counts":{"email":3,..}}`. `size`
//! and `modified` (the write time as a Windows `FILETIME`) say whether a file changed since it
//! was scanned, so a rescan reads only what is new or different.
//!
//! The detector reads what [`Engine::enabled`] says, and the inventory keeps what it found at the
//! time: changing the kinds does not rescan files that did not change.
//!
//! The app and the CLI can both write the file. A scan holds `inventory.lock` for as long as it
//! runs, so one runs at a time. A save is short and holds `inventory.save.lock`: under it the
//! save first takes over what another process wrote to the file since this one last read or
//! wrote it, puts the changes this process has not saved yet on top (where both changed the
//! same file, this process's entry stays), and replaces the file. Forgetting does the same, so
//! it also forgets what another process added since. A scan takes over the file when its walk
//! is over, so it does not read again what another process just scanned.

use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::OsStr,
    fmt,
    fs::{self, File, Metadata},
    hash::{DefaultHasher, Hasher},
    io::{self, BufWriter, Read, Write},
    mem,
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{
        Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rayon::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    Error, Result,
    detect::EntityKind,
    engine::Engine,
    files, formats,
    sys::{self, FileLock, io_context},
    vault::{ExportFormat, csv_row},
};

/// Files bigger than this are not read: they are recorded as [`Status::TooLarge`]. Reading a
/// file whole and running the detector over it costs time and memory in proportion, which a
/// background scan must not spend on a disk image.
pub const MAX_FILE: u64 = 64 << 20;

/// The inventory's file name in the data folder.
const FILE_NAME: &str = "inventory.jsonl";
/// Files a scan hands to the thread pool at once; the scan can be stopped between two chunks.
const CHUNK: usize = 64;
/// A scan saves the inventory when this many entries are unsaved, but not more often than
/// `SAVE_GAP`: a save writes every entry again.
const SAVE_EVERY: usize = 2_000;
const SAVE_GAP: Duration = Duration::from_secs(15);
/// How long a save waits for another process's save to end. A save takes well under a second;
/// a process that holds the lock for longer is stuck, and is not waited for.
const SAVE_WAIT: Duration = Duration::from_secs(5);
/// Folders nothing of the user's lives in: caches, dependencies, build output, the recycle bin.
const SKIPPED_DIRS: [&str; 6] = [
    "AppData",
    "node_modules",
    ".git",
    "target",
    "$RECYCLE.BIN",
    "System Volume Information",
];
/// `FILE_ATTRIBUTE_HIDDEN` and `_SYSTEM`: not the user's files.
const HIDDEN_OR_SYSTEM: u32 = 0x2 | 0x4;
/// What a node that stands for entries under no watched folder is called.
const OTHER: &str = "Other scans";

/// What a scan found out about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    pub size: u64,
    /// The file's write time as Windows keeps it, a `FILETIME`: 100 ns ticks since 1601. With
    /// `size` it says whether the file changed since the scan. 0 when it is not known, which no
    /// write time is: the file could not be read, so the next scan looks at it again.
    pub modified: u64,
    /// When the scan ran: seconds since the Unix epoch.
    pub scanned: u64,
    pub status: Status,
    /// What was found, by kind, the most first. Empty unless `status` is [`Status::Ok`], and
    /// for a file with nothing in it.
    pub counts: Vec<(EntityKind, u32)>,
}

/// How far a file got in a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Read and scanned.
    Ok,
    /// Not a format piikey reads: binary data, a zip that is no document.
    Unsupported,
    /// Over [`MAX_FILE`]: not read.
    TooLarge,
    /// Could not be read or parsed; the message says why. A file that could not be read has no
    /// known write time (see [`Entry::modified`]), so the next scan tries it again: whatever
    /// held it may be over. A file that was read but not understood is not read again until it
    /// changes: it would cost the same every time.
    Failed(String),
}

impl Status {
    /// The name the file and the API use.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unsupported => "unsupported",
            Self::TooLarge => "too_large",
            Self::Failed(_) => "failed",
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Self::Failed(message) => Some(message),
            _ => None,
        }
    }
}

impl Entry {
    /// Scans the file at `path` now, whether or not the inventory knows it: its size and write
    /// time from the file system, then its contents (not when it is over [`MAX_FILE`]). A file
    /// that cannot be read is an entry with a [`Status::Failed`], not an error.
    #[must_use]
    pub fn scan(engine: &Engine, path: &Path) -> Self {
        match fs::metadata(path) {
            Ok(meta) => scan_file(engine, path, &meta),
            Err(err) => Self {
                path: path.to_path_buf(),
                size: 0,
                modified: 0,
                scanned: unix_now(),
                status: Status::Failed(err.to_string()),
                counts: Vec::new(),
            },
        }
    }

    /// How many values were found, of every kind.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.counts.iter().map(|&(_, n)| u64::from(n)).sum()
    }
}

/// A folder or a file of the treemap: what lies under it, added up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Empty for the node that stands for the scans outside every watched folder.
    pub path: PathBuf,
    /// The last component of `path`, for display.
    pub name: String,
    pub is_dir: bool,
    /// Values found in the files under it.
    pub hits: u64,
    /// Files under it that hold any.
    pub files: u32,
    /// By kind, the most first.
    pub counts: Vec<(EntityKind, u32)>,
}

/// What a running scan has done; read it from another thread to show progress.
#[derive(Debug, Default)]
pub struct Progress {
    /// Files scanned so far.
    pub done: AtomicU64,
    /// Files this scan has to scan: the new and the changed ones. Known once the folders were
    /// walked, 0 before.
    pub total: AtomicU64,
}

/// The inventory in numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Files the inventory knows.
    pub files: u64,
    /// Of those, the ones that hold personal data.
    pub files_with_pii: u64,
    /// Values found, of every kind.
    pub hits: u64,
}

/// The inventory in memory, and the file it is saved to.
pub struct Inventory {
    path: PathBuf,
    state: RwLock<State>,
    /// Orders this process's own saves and takeovers: threads queue here instead of polling the
    /// save lock file against each other, and the state changes of a save and the digest below
    /// are never interleaved with another thread's. Ordering against other processes is the
    /// save lock file's job, so this is taken first, and no state lock is held while it is
    /// waited for. Holds the digest of the file as this process last read or wrote it: another
    /// one on disk means that another process wrote the file since.
    saving: Mutex<u64>,
}

/// What an [`Inventory`] holds in memory.
struct State {
    entries: BTreeMap<PathBuf, Entry>,
    /// The paths this process added, replaced or removed since its last save: what it puts on
    /// top of the file when another process wrote it in the meantime.
    changed: HashSet<PathBuf>,
}

impl State {
    /// Puts this process's unsaved changes on top of `theirs`, the file as another process left
    /// it, and takes the result as the entries. What this process removed is removed from
    /// `theirs` too, and what only the file has stays.
    fn rebase(&mut self, mut theirs: BTreeMap<PathBuf, Entry>) {
        for path in &self.changed {
            match self.entries.remove(path) {
                Some(entry) => {
                    theirs.insert(path.clone(), entry);
                }
                None => {
                    theirs.remove(path);
                }
            }
        }
        self.entries = theirs;
    }
}

// No entries: they are a map of the user's files.
impl fmt::Debug for Inventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inventory")
            .field("path", &self.path)
            .field("entries", &self.read().entries.len())
            .finish_non_exhaustive()
    }
}

impl Inventory {
    /// `%LOCALAPPDATA%\piikey\inventory.jsonl`.
    ///
    /// # Errors
    /// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` when the folder cannot be made.
    pub fn default_path() -> Result<PathBuf> {
        Ok(sys::data_dir()?.join(FILE_NAME))
    }

    /// The inventory saved at `path`. A missing file is an empty inventory; a line that is not
    /// an entry (a torn write, a newer version's status) is skipped.
    ///
    /// # Errors
    /// `Io` when the file exists but cannot be read.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = read_file(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            state: RwLock::new(State {
                entries: parse(&bytes),
                changed: HashSet::new(),
            }),
            saving: Mutex::new(digest(&bytes)),
        })
    }

    // The state is plain data and every change to it is a few inserts and removes, so whatever
    // a panicking thread left behind is a usable state.
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes the inventory to its file, replacing it as a whole. What another process wrote to
    /// the file since this one last read or wrote it stays: this process's unsaved changes go
    /// on top of it.
    ///
    /// # Errors
    /// `Io`; `Busy` when another process holds the save lock for longer than a save takes. The
    /// changes that were not saved stay in memory for the next save.
    pub fn save(&self) -> Result<()> {
        self.save_within(SAVE_WAIT)
    }

    /// [`Inventory::save`], waiting for the save lock `wait` at most.
    fn save_within(&self, wait: Duration) -> Result<()> {
        self.update(wait, |_| ((), true))
    }

    /// Takes over what another process wrote to the file, lets `edit` change the entries, and
    /// writes the file when `edit` says so (its second value), all under one hold of the save
    /// lock: nothing another process writes between the takeover and the write is missed by
    /// `edit`. Gives what `edit` gave. When the write fails, the changes stay unsaved.
    fn update<R>(&self, wait: Duration, edit: impl FnOnce(&mut State) -> (R, bool)) -> Result<R> {
        let mut synced = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let _lock = self.lock_save(wait)?;
        self.take_over(&mut synced)?;
        let (result, write) = edit(&mut self.write());
        if !write {
            return Ok(result);
        }
        // Every save writes under the lock, so no temp file of the inventory is in use now: the
        // ones there are what a save that crashed left.
        sys::remove_temps(&self.path);
        // Taken before the snapshot: what changes meanwhile is in this save or the next, never
        // in neither.
        let saved = mem::take(&mut self.write().changed);
        let written = self.snapshot().and_then(|bytes| {
            sys::write_atomic(&self.path, &bytes)?;
            Ok(digest(&bytes))
        });
        match written {
            Ok(now) => {
                *synced = now;
                Ok(result)
            }
            Err(error) => {
                self.write().changed.extend(saved);
                Err(error)
            }
        }
    }

    /// Takes the right to scan: one scan at a time over this inventory file, across processes
    /// (the CLI and the app). Hold the lock for as long as the scan runs.
    ///
    /// # Errors
    /// `Busy` when another scan holds it; `Io`.
    pub fn lock_scan(&self) -> Result<FileLock> {
        sys::try_lock(&self.path.with_extension("lock"))?
            .ok_or_else(|| Error::Busy("another inventory scan is running".into()))
    }

    /// Takes the right to save: one process at a time reads the file, puts its changes on top
    /// and replaces it. It is not the scan lock, which is held for minutes.
    fn lock_save(&self, wait: Duration) -> Result<FileLock> {
        sys::lock_within(&self.path.with_extension("save.lock"), wait)?
            .ok_or_else(|| Error::Busy("another piikey process is saving the inventory".into()))
    }

    /// Takes over what another process wrote to the file since this one last read or wrote it,
    /// with this process's unsaved changes on top. `synced` is the digest of the file as this
    /// process last saw it. The save lock must be held.
    fn take_over(&self, synced: &mut u64) -> Result<()> {
        let bytes = read_file(&self.path)?;
        let now = digest(&bytes);
        if now != *synced {
            self.write().rebase(parse(&bytes));
            *synced = now;
        }
        Ok(())
    }

    /// [`Inventory::take_over`] on its own, for a scan to start from what is saved.
    fn sync(&self) -> Result<()> {
        let mut synced = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let _lock = self.lock_save(SAVE_WAIT)?;
        self.take_over(&mut synced)
    }

    /// The file as it would be written: one line per entry, in path order.
    fn snapshot(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for entry in self.read().entries.values() {
            serde_json::to_writer(&mut bytes, &Row::of(entry, false)).map_err(io::Error::from)?;
            bytes.push(b'\n');
        }
        Ok(bytes)
    }

    /// Scans the files under `paths` and updates the inventory: new and changed files are read,
    /// the others are left as they are (a file whose size and write time equal what was stored,
    /// whatever came of it, but for a file that could not be read: that is read again). Entries
    /// under `paths` whose files are gone, or that lie under `exclude`, are dropped.
    ///
    /// The walk leaves out `exclude`, `AppData`, `node_modules`, `.git`, `target`, the recycle
    /// bin, hidden and system files, and files that are online only (reading them would
    /// download them), so what a folder of the user's holds is what is scanned. Files over
    /// [`MAX_FILE`] are recorded as too large. Work goes in chunks on the rayon pool the caller
    /// runs in, which is how the app keeps a scan to half the cores; `progress` is updated as
    /// files finish, and `cancel` is looked at between files, so a scan stops within the file
    /// it is in. A cancelled scan saves what it did and drops nothing.
    ///
    /// The scan starts from the saved file, so what another process (the CLI, when this is the
    /// app) scanned since this one last looked is not read again. Hold [`Inventory::lock_scan`]
    /// for as long as it runs.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be read or saved; `Busy` when another process holds the
    /// save lock for longer than a save takes.
    pub fn scan_paths(
        &self,
        engine: &Engine,
        paths: &[PathBuf],
        exclude: &[PathBuf],
        progress: &Progress,
        cancel: &AtomicBool,
    ) -> Result<()> {
        progress.done.store(0, Ordering::Relaxed);
        progress.total.store(0, Ordering::Relaxed);
        let walked = files::walk(paths, &|path, meta| {
            cancel.load(Ordering::Relaxed) || unwanted(path, meta, exclude)
        });
        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        // After the walk, which can take minutes: the file may have changed in the meantime.
        self.sync()?;
        let pending: Vec<&(PathBuf, Metadata)> = {
            let state = self.read();
            walked
                .iter()
                .filter(|(path, meta)| {
                    !state.entries.get(path).is_some_and(|known| {
                        known.size == meta.len() && known.modified == meta.last_write_time()
                    })
                })
                .collect()
        };
        progress.total.store(
            u64::try_from(pending.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let mut last_save = Instant::now();
        for chunk in pending.chunks(CHUNK) {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let scanned: Vec<Entry> = chunk
                .par_iter()
                .filter_map(|(path, meta)| {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    let entry = scan_file(engine, path, meta);
                    progress.done.fetch_add(1, Ordering::Relaxed);
                    Some(entry)
                })
                .collect();
            self.insert(scanned);
            if self.unsaved() >= SAVE_EVERY && last_save.elapsed() >= SAVE_GAP {
                self.save()?;
                last_save = Instant::now();
            }
        }
        if !cancel.load(Ordering::Relaxed) {
            self.drop_stale(paths, exclude, &walked);
        }
        if self.unsaved() > 0 {
            self.save()?;
        }
        Ok(())
    }

    fn insert(&self, entries: Vec<Entry>) {
        let mut state = self.write();
        for entry in entries {
            state.changed.insert(entry.path.clone());
            state.entries.insert(entry.path.clone(), entry);
        }
    }

    /// How many entries were added, replaced or removed since the last save.
    fn unsaved(&self) -> usize {
        self.read().changed.len()
    }

    /// Adds `entries`, replacing what is stored for the same files, and saves.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be saved; `Busy` as for [`Inventory::save`].
    pub fn record(&self, entries: Vec<Entry>) -> Result<()> {
        self.insert(entries);
        self.save()
    }

    /// Drops the entries under `roots` that a complete walk of them did not find and that are
    /// gone from disk, and the ones under `exclude`. An entry that the walk found spelled in
    /// another letter case (the folder was chosen again in that case, or a file was renamed in
    /// case) is the same file: the scan has just recorded it as the walk spelled it, and the
    /// old spelling goes.
    ///
    /// A root that does not exist (a disk that is unplugged) drops nothing, and neither does a
    /// file that exists but was not walked (a folder that could not be listed this time).
    fn drop_stale(&self, roots: &[PathBuf], exclude: &[PathBuf], walked: &[(PathBuf, Metadata)]) {
        let present: HashSet<&Path> = walked.iter().map(|(path, _)| path.as_path()).collect();
        let roots: Vec<&PathBuf> = roots
            .iter()
            .filter(|root| fs::metadata(root).is_ok())
            .collect();
        let candidates: Vec<PathBuf> = self
            .read()
            .entries
            .keys()
            .filter(|path| {
                roots.iter().any(|root| sys::is_under(path, root))
                    && !present.contains(path.as_path())
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return;
        }
        let respelled: HashSet<String> =
            walked.iter().map(|(path, _)| sys::path_key(path)).collect();
        // The file system is asked outside the lock.
        let stale: Vec<PathBuf> = candidates
            .into_iter()
            .filter(|path| {
                is_excluded(path, exclude)
                    || respelled.contains(&sys::path_key(path))
                    || is_gone(path)
            })
            .collect();
        let mut held = self.write();
        for path in stale {
            if held.entries.remove(&path).is_some() {
                held.changed.insert(path);
            }
        }
    }

    /// Forgets the entries at and under `prefix` and saves; returns how many there were.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be read or saved; `Busy` as for [`Inventory::save`].
    pub fn forget_under(&self, prefix: &Path) -> Result<usize> {
        // Under the save lock, after the takeover: what another process scanned under `prefix`
        // since this one last looked is forgotten too, and cannot come back with the save.
        self.update(SAVE_WAIT, |state| {
            let State { entries, changed } = state;
            let before = entries.len();
            entries.retain(|path, _| {
                let forgotten = sys::is_under(path, prefix);
                if forgotten {
                    changed.insert(path.clone());
                }
                !forgotten
            });
            let removed = before - entries.len();
            (removed, removed > 0)
        })
    }

    /// The entries at and under `under` (all of them for `None`) that hold at least `min_hits`
    /// values, in path order. `min_hits` 0 gives every entry, the clean ones and the files that
    /// were not scanned too.
    #[must_use]
    pub fn entries(&self, under: Option<&Path>, min_hits: u64) -> Vec<Entry> {
        self.select(under, |entry| entry.hits() >= min_hits)
    }

    /// The entries at and under `under` that `keep` says yes to, cloned, in path order.
    fn select(&self, under: Option<&Path>, keep: impl Fn(&Entry) -> bool) -> Vec<Entry> {
        self.read()
            .entries
            .values()
            .filter(|entry| {
                under.is_none_or(|under| sys::is_under(&entry.path, under)) && keep(entry)
            })
            .cloned()
            .collect()
    }

    /// The inventory in numbers.
    #[must_use]
    pub fn totals(&self) -> Totals {
        let state = self.read();
        let mut totals = Totals {
            files: u64::try_from(state.entries.len()).unwrap_or(u64::MAX),
            ..Totals::default()
        };
        for hits in state
            .entries
            .values()
            .map(Entry::hits)
            .filter(|&hits| hits > 0)
        {
            totals.files_with_pii += 1;
            totals.hits += hits;
        }
        totals
    }

    /// The tiles of the treemap at one level, the one with the most values first. Only files
    /// that hold personal data count.
    ///
    /// With `under`, the entries below it, grouped by the next component of their path: a
    /// folder node for what lies deeper, a file node for a file in `under` itself. Without,
    /// one folder node per watched folder in `roots` that has entries; entries under none of
    /// them make one more node, with an empty `path` and the name "Other scans". Of nested
    /// roots the deepest one takes an entry.
    #[must_use]
    pub fn children(&self, under: Option<&Path>, roots: &[PathBuf]) -> Vec<Node> {
        let state = self.read();
        let held = state.entries.values().filter(|entry| entry.hits() > 0);
        let mut nodes = match under {
            Some(under) => below(held, under),
            None => top_level(held, roots),
        };
        nodes.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.name.cmp(&b.name)));
        nodes
    }

    /// Writes the entries at and under `under` (all for `None`) that hold personal data, or
    /// that could not be checked (failed, too large), in path order; returns how many.
    ///
    /// CSV has one row per file: `path`, `status`, `hits`, a column for each kind that occurs
    /// (its name, `iban`), and `scanned` as a UTC time. JSON is an array of objects with the
    /// same fields, and `counts` as an object. To keep from overwriting a file, open it with
    /// `OpenOptions::create_new`.
    ///
    /// # Errors
    /// `Io`.
    pub fn report(
        &self,
        under: Option<&Path>,
        format: ExportFormat,
        out: &mut dyn Write,
    ) -> Result<usize> {
        let rows = self.select(under, |entry| {
            entry.hits() > 0 || matches!(entry.status, Status::Failed(_) | Status::TooLarge)
        });
        // Callers hand over a bare file: unbuffered, every field would be a system call.
        let mut out = BufWriter::new(out);
        match format {
            ExportFormat::Json => {
                out.write_all(b"[")?;
                for (i, entry) in rows.iter().enumerate() {
                    out.write_all(if i == 0 { b"\n" } else { b",\n" })?;
                    serde_json::to_writer(&mut out, &Row::of(entry, true))
                        .map_err(io::Error::from)?;
                }
                out.write_all(b"\n]\n")?;
            }
            ExportFormat::Csv => {
                let present: BTreeSet<EntityKind> = rows
                    .iter()
                    .flat_map(|row| row.counts.iter().map(|&(kind, _)| kind))
                    .collect();
                let kinds: Vec<EntityKind> = EntityKind::ALL
                    .into_iter()
                    .filter(|kind| present.contains(kind))
                    .collect();
                let mut header = vec!["path", "status", "hits"];
                header.extend(kinds.iter().map(|kind| kind.as_str()));
                header.push("scanned");
                csv_row(&mut out, &header)?;
                for entry in &rows {
                    let path = entry.path.to_string_lossy();
                    let hits = entry.hits().to_string();
                    let counts: Vec<String> = kinds
                        .iter()
                        .map(|kind| {
                            let n = entry
                                .counts
                                .iter()
                                .find(|(k, _)| k == kind)
                                .map_or(0, |&(_, n)| n);
                            n.to_string()
                        })
                        .collect();
                    let scanned = iso_utc(entry.scanned);
                    let mut row = vec![&*path, entry.status.as_str(), hits.as_str()];
                    row.extend(counts.iter().map(String::as_str));
                    row.push(&scanned);
                    csv_row(&mut out, &row)?;
                }
            }
        }
        out.flush()?;
        Ok(rows.len())
    }
}

/// Reads and scans one file, or says why not.
fn scan_file(engine: &Engine, path: &Path, meta: &Metadata) -> Entry {
    let mut modified = meta.last_write_time();
    let (status, counts) = if meta.len() > MAX_FILE {
        (Status::TooLarge, Vec::new())
    } else {
        match read_capped(path) {
            Ok(None) => (Status::TooLarge, Vec::new()),
            // Whatever stopped the read (a sync client or a virus scanner holding the file, a
            // permission that was fixed since) may be over by the next scan, and trying costs
            // nothing. With no write time on record the file looks changed by then.
            Err(err) => {
                modified = 0;
                (Status::Failed(err.to_string()), Vec::new())
            }
            Ok(Some(bytes)) => match formats::scan(engine, &bytes, false) {
                Ok(scanned) => (Status::Ok, tally(&scanned.found)),
                Err(Error::UnsupportedFormat(_)) => (Status::Unsupported, Vec::new()),
                Err(err) => {
                    // A damaged file fails the same way again, so it waits for a change. The
                    // vault, the model or a lock failing says nothing about the file: the
                    // next scan tries it again, as for a file that could not be read.
                    if !err.is_unreadable() {
                        modified = 0;
                    }
                    (Status::Failed(err.to_string()), Vec::new())
                }
            },
        }
    };
    Entry {
        path: path.to_path_buf(),
        size: meta.len(),
        modified,
        scanned: unix_now(),
        status,
        counts,
    }
}

/// The contents of the file at `path`, or `None` when it is bigger than [`MAX_FILE`]. The size
/// in a folder listing can be out of date for a file that is being written, so the open file is
/// asked for its size, and the read stops at the limit.
///
/// # Errors
/// Whatever opening or reading the file fails with.
pub(crate) fn read_capped(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size > MAX_FILE {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    Ok(u64::try_from(bytes.len())
        .is_ok_and(|len| len <= MAX_FILE)
        .then_some(bytes))
}

/// The contents of the file at `path`; none for a file that is not there.
fn read_file(path: &Path) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(io_context(&err, "read", path)),
    }
}

/// The entries of an inventory file. A line that is not an entry (a torn write, a newer
/// version's status) is skipped.
fn parse(bytes: &[u8]) -> BTreeMap<PathBuf, Entry> {
    bytes
        .split(|&byte| byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Entry>(line.trim_ascii()).ok())
        .map(|entry| (entry.path.clone(), entry))
        .collect()
}

/// A fingerprint of `bytes`: the same contents always give the same digest.
fn digest(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

/// How many of each kind, the most first, then by kind.
fn tally(found: &[(EntityKind, Box<str>)]) -> Vec<(EntityKind, u32)> {
    let mut per_kind: BTreeMap<EntityKind, u32> = BTreeMap::new();
    for (kind, _) in found {
        let n = per_kind.entry(*kind).or_insert(0);
        *n = n.saturating_add(1);
    }
    ranked(per_kind)
}

fn ranked(per_kind: BTreeMap<EntityKind, u32>) -> Vec<(EntityKind, u32)> {
    let mut counts: Vec<(EntityKind, u32)> = per_kind.into_iter().collect();
    counts.sort_by_key(|&(kind, n)| (Reverse(n), kind));
    counts
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Whether a walk leaves `path` out: hidden, system or online-only things, the folders nothing
/// of the user's lives in, and what the user excluded.
fn unwanted(path: &Path, meta: &Metadata, exclude: &[PathBuf]) -> bool {
    meta.file_attributes() & HIDDEN_OR_SYSTEM != 0
        || files::is_online_only(meta)
        || (meta.is_dir()
            && path.file_name().is_some_and(|name| {
                SKIPPED_DIRS
                    .iter()
                    .any(|skipped| name.eq_ignore_ascii_case(skipped))
            }))
        || is_excluded(path, exclude)
}

fn is_excluded(path: &Path, exclude: &[PathBuf]) -> bool {
    exclude.iter().any(|excluded| sys::is_under(path, excluded))
}

/// Whether `path` is gone from the disk: no such file, or no such folder above it.
fn is_gone(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|err| {
        matches!(
            err.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        )
    })
}

/// `name` in lowercase, in `into`.
fn lowercase_into(name: &OsStr, into: &mut String) {
    into.clear();
    into.extend(name.to_string_lossy().chars().flat_map(char::to_lowercase));
}

/// What a watched folder is called: its last component, or all of it for a drive.
fn folder_name(root: &Path) -> String {
    root.file_name().map_or_else(
        || root.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// The component of `path` right below `base`, and whether something lies below that (it is a
/// folder), or `None` when `path` is not below `base`.
fn child_of<'a>(path: &'a Path, base: &[Component<'_>]) -> Option<(Component<'a>, bool)> {
    let mut components = path.components();
    for want in base {
        if !components
            .next()
            .is_some_and(|have| sys::same_component(have, *want))
        {
            return None;
        }
    }
    let next = components.next()?;
    Some((next, components.next().is_some()))
}

/// The nodes one level below `under`, one for each next component of the paths of `entries`: a
/// folder node for what lies deeper, a file node for a file in `under` itself. A node is spelled
/// as the first entry under it spells it.
fn below<'a>(entries: impl Iterator<Item = &'a Entry>, under: &Path) -> Vec<Node> {
    let base: Vec<Component<'_>> = under.components().collect();
    let mut tallies: HashMap<String, Tally> = HashMap::new();
    let mut key = String::new();
    for entry in entries {
        let Some((next, deeper)) = child_of(&entry.path, &base) else {
            continue;
        };
        lowercase_into(next.as_os_str(), &mut key);
        if let Some(tally) = tallies.get_mut(&key) {
            tally.add(entry, deeper);
            continue;
        }
        let path: PathBuf = entry.path.components().take(base.len() + 1).collect();
        let name = next.as_os_str().to_string_lossy().into_owned();
        let mut tally = Tally::new(path, name);
        tally.add(entry, deeper);
        tallies.insert(key.clone(), tally);
    }
    tallies.into_values().map(Tally::finish).collect()
}

/// The top nodes: one for each watched folder in `roots` that holds any of `entries`, and one
/// with an empty path for the entries under none of them. Of nested roots the deepest one
/// takes an entry.
fn top_level<'a>(entries: impl Iterator<Item = &'a Entry>, roots: &[PathBuf]) -> Vec<Node> {
    let mut tops: Vec<(&PathBuf, usize, Option<Tally>)> = roots
        .iter()
        .map(|root| (root, root.components().count(), None))
        .collect();
    let mut other: Option<Tally> = None;
    for entry in entries {
        let deepest = tops
            .iter_mut()
            .filter(|(root, ..)| sys::is_under(&entry.path, root))
            .max_by_key(|(_, depth, _)| *depth);
        let tally = match deepest {
            Some((root, _, held)) => {
                let root = *root;
                held.get_or_insert_with(|| Tally::new(root.clone(), folder_name(root)))
            }
            None => other.get_or_insert_with(|| Tally::new(PathBuf::new(), OTHER.to_owned())),
        };
        tally.add(entry, true);
    }
    tops.into_iter()
        .filter_map(|(_, _, held)| held)
        .chain(other)
        .map(Tally::finish)
        .collect()
}

/// A node being added up.
struct Tally {
    node: Node,
    per_kind: BTreeMap<EntityKind, u32>,
}

impl Tally {
    fn new(path: PathBuf, name: String) -> Self {
        Self {
            node: Node {
                path,
                name,
                is_dir: false,
                hits: 0,
                files: 0,
                counts: Vec::new(),
            },
            per_kind: BTreeMap::new(),
        }
    }

    /// Adds `entry`, which lies deeper than the node when `deeper`: the node is a folder then.
    fn add(&mut self, entry: &Entry, deeper: bool) {
        self.node.is_dir |= deeper;
        self.node.hits += entry.hits();
        self.node.files = self.node.files.saturating_add(1);
        for &(kind, n) in &entry.counts {
            let total = self.per_kind.entry(kind).or_insert(0);
            *total = total.saturating_add(n);
        }
    }

    fn finish(mut self) -> Node {
        self.node.counts = ranked(self.per_kind);
        self.node
    }
}

/// An entry as it is written and read: to the file (without `hits`, which the counts give), and
/// to the API and the report (with `hits`, which is ignored when read back).
#[derive(Serialize, Deserialize)]
struct Row<'a> {
    path: Cow<'a, str>,
    size: u64,
    modified: u64,
    scanned: u64,
    status: Cow<'a, str>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<Cow<'a, str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hits: Option<u64>,
    #[serde(default)]
    counts: Counts<'a>,
}

impl<'a> Row<'a> {
    fn of(entry: &'a Entry, with_hits: bool) -> Self {
        Self {
            path: entry.path.to_string_lossy(),
            size: entry.size,
            modified: entry.modified,
            scanned: entry.scanned,
            status: Cow::Borrowed(entry.status.as_str()),
            error: entry.status.error().map(Cow::Borrowed),
            hits: with_hits.then(|| entry.hits()),
            counts: Counts(Cow::Borrowed(&entry.counts)),
        }
    }

    /// The entry, or the name of the status when this version does not know it.
    fn into_entry(self) -> Result<Entry, String> {
        let status = match &*self.status {
            "ok" => Status::Ok,
            "unsupported" => Status::Unsupported,
            "too_large" => Status::TooLarge,
            "failed" => Status::Failed(self.error.map(Cow::into_owned).unwrap_or_default()),
            unknown => return Err(unknown.to_owned()),
        };
        Ok(Entry {
            path: PathBuf::from(self.path.into_owned()),
            size: self.size,
            modified: self.modified,
            scanned: self.scanned,
            status,
            counts: self.counts.0.into_owned(),
        })
    }
}

/// Counts as a JSON object, `{"email":3}`, the most first. Read back, a kind this version does
/// not know and a count of 0 are dropped, and what is left is ranked again.
#[derive(Default)]
struct Counts<'a>(Cow<'a, [(EntityKind, u32)]>);

impl Serialize for Counts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(kind, n)| (kind.as_str(), n)))
    }
}

impl<'de> Deserialize<'de> for Counts<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let named = BTreeMap::<String, u32>::deserialize(deserializer)?;
        let per_kind: BTreeMap<EntityKind, u32> = named
            .into_iter()
            .filter(|&(_, n)| n > 0)
            .filter_map(|(name, n)| EntityKind::parse(&name).map(|kind| (kind, n)))
            .collect();
        Ok(Self(Cow::Owned(ranked(per_kind))))
    }
}

impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        Row::of(self, true).serialize(serializer)
    }
}

/// Reads what [`Serialize`] writes, and a line of the inventory file, which has no `hits`. A
/// status this version does not know is an error.
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Row::deserialize(deserializer)?
            .into_entry()
            .map_err(|status| de::Error::custom(format_args!("unknown status {status:?}")))
    }
}

/// A node as it is written and read.
#[derive(Serialize, Deserialize)]
struct NodeRow<'a> {
    path: Cow<'a, str>,
    name: Cow<'a, str>,
    is_dir: bool,
    hits: u64,
    files: u32,
    counts: Counts<'a>,
}

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        NodeRow {
            path: self.path.to_string_lossy(),
            name: Cow::Borrowed(&self.name),
            is_dir: self.is_dir,
            hits: self.hits,
            files: self.files,
            counts: Counts(Cow::Borrowed(&self.counts)),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let row = NodeRow::deserialize(deserializer)?;
        Ok(Self {
            path: PathBuf::from(row.path.into_owned()),
            name: row.name.into_owned(),
            is_dir: row.is_dir,
            hits: row.hits,
            files: row.files,
            counts: row.counts.0.into_owned(),
        })
    }
}

/// `secs` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
fn iso_utc(secs: u64) -> String {
    // Days since 1970 to a civil date: Howard Hinnant's algorithm, for the proleptic Gregorian
    // calendar, with the year starting in March so the leap day comes last.
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let time = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3_600,
        time % 3_600 / 60,
        time % 60
    )
}

#[cfg(test)]
mod tests {
    use std::{os::windows::fs::OpenOptionsExt, sync::atomic::AtomicUsize};

    use super::*;
    use crate::detect::EntityKind::{Email, Iban, Phone};

    type Res<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    const EMAIL: &str = "jan.jansen@acme.nl";
    const IBAN: &str = "NL91ABNA0417164300";

    /// Temp directory removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> io::Result<Self> {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "piikey-inventory-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn engine(&self) -> Result<Engine> {
            Engine::open(&self.0.join("vault.pkv"))
        }

        fn inventory(&self) -> Result<Inventory> {
            Inventory::open(&self.0.join("inventory.jsonl"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn put(path: &Path, text: &str) -> io::Result<()> {
        put_bytes(path, text.as_bytes())
    }

    fn put_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)
    }

    /// A scan with nothing excluded and no cancel; the progress it made.
    fn scan(
        inv: &Inventory,
        engine: &Engine,
        paths: &[PathBuf],
        exclude: &[PathBuf],
    ) -> Result<Progress> {
        let progress = Progress::default();
        inv.scan_paths(engine, paths, exclude, &progress, &AtomicBool::new(false))?;
        Ok(progress)
    }

    fn counts_of(inv: &Inventory, path: &Path) -> Option<BTreeMap<EntityKind, u32>> {
        inv.read()
            .entries
            .get(path)
            .map(|entry| entry.counts.iter().copied().collect())
    }

    fn stored(inv: &Inventory) -> Vec<PathBuf> {
        inv.entries(None, 0).into_iter().map(|e| e.path).collect()
    }

    fn entry(path: &str, counts: &[(EntityKind, u32)]) -> Entry {
        Entry {
            path: PathBuf::from(path),
            size: 1,
            modified: 1,
            scanned: 1_700_000_000,
            status: Status::Ok,
            counts: counts.to_vec(),
        }
    }

    #[test]
    fn a_rescan_reads_only_new_and_changed_files() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        let a = root.join("a.txt");
        let b = root.join("sub").join("b.txt");
        put(&a, &format!("mail {EMAIL} and {IBAN}"))?;
        put(&b, "nothing to see")?;

        let first = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(first.total.load(Ordering::Relaxed), 2);
        assert_eq!(first.done.load(Ordering::Relaxed), 2);
        assert_eq!(
            counts_of(&inv, &a),
            Some(BTreeMap::from([(Email, 1), (Iban, 1)]))
        );
        assert_eq!(counts_of(&inv, &b), Some(BTreeMap::new()));
        assert_eq!(
            engine.vault().read()?.record_count(),
            0,
            "a scan issues nothing"
        );

        // Unchanged: nothing is read again.
        let second = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(second.total.load(Ordering::Relaxed), 0);

        // Another content of the same size and write time still counts as unchanged: the
        // stored counts stay, which shows the file was not read.
        let written = fs::metadata(&a)?.modified()?;
        fs::write(&a, "x".repeat(fs::read(&a)?.len()))?;
        fs::OpenOptions::new()
            .write(true)
            .open(&a)?
            .set_modified(written)?;
        let third = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(third.total.load(Ordering::Relaxed), 0);
        assert_eq!(counts_of(&inv, &a).map(|c| c.len()), Some(2));

        // A different size is a change.
        put(&a, &format!("{EMAIL} {EMAIL}"))?;
        let fourth = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(fourth.total.load(Ordering::Relaxed), 1);
        assert_eq!(counts_of(&inv, &a), Some(BTreeMap::from([(Email, 2)])));

        // A file that is gone is dropped, and the inventory survives a restart.
        fs::remove_file(&b)?;
        scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(stored(&inv), std::slice::from_ref(&a));
        assert_eq!(stored(&tmp.inventory()?), std::slice::from_ref(&a));
        Ok(())
    }

    #[test]
    fn what_cannot_be_scanned_is_recorded_and_not_read_again_until_it_changes() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        put_bytes(&root.join("binary.bin"), &[0x90, 0, 1, 2, 0, 0, 7])?;
        put_bytes(&root.join("broken.zip"), b"PK\x03\x04 not really a zip")?;
        put(&root.join("clean.txt"), "just words")?;
        let big = File::create(root.join("big.dat"))?;
        big.set_len(MAX_FILE + 1)?;
        drop(big);

        let progress = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(progress.done.load(Ordering::Relaxed), 4);
        let status = |name: &str| {
            inv.read()
                .entries
                .get(&root.join(name))
                .map(|e| e.status.clone())
        };
        assert_eq!(status("binary.bin"), Some(Status::Unsupported));
        assert_eq!(status("clean.txt"), Some(Status::Ok));
        assert_eq!(status("big.dat"), Some(Status::TooLarge));
        assert!(matches!(status("broken.zip"), Some(Status::Failed(_))));

        // Nothing changed, so nothing is read again, the failure included.
        let again = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(again.total.load(Ordering::Relaxed), 0);
        // A file that changed is read again.
        put(
            &root.join("broken.zip"),
            "now it is text with jan.jansen@acme.nl",
        )?;
        let changed = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(changed.total.load(Ordering::Relaxed), 1);
        assert_eq!(status("broken.zip"), Some(Status::Ok));
        Ok(())
    }

    #[test]
    fn caches_hidden_files_and_the_excluded_are_left_out_and_dropped() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        for file in [
            "keep/a.txt",
            "skipme/z.txt",
            "node_modules/x.txt",
            ".git/y.txt",
            "Target/t.txt",
            "hidden.txt",
        ] {
            put(&root.join(file), EMAIL)?;
        }
        let hidden = root.join("hidden.txt");
        let hidden_path = hidden.to_string_lossy();
        let attrib = sys::run_system_tool("attrib.exe", &["+h", hidden_path.as_ref()])?;
        assert!(attrib.status.success(), "attrib failed");

        scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        let names = |inv: &Inventory| -> Vec<PathBuf> {
            stored(inv)
                .into_iter()
                .filter_map(|p| p.strip_prefix(&root).ok().map(Path::to_path_buf))
                .collect()
        };
        assert_eq!(
            names(&inv),
            [
                Path::new("keep").join("a.txt"),
                Path::new("skipme").join("z.txt")
            ]
        );

        // Excluding a folder drops what is stored under it, in any letter case.
        let excluded = root.join("KEEP");
        scan(&inv, &engine, std::slice::from_ref(&root), &[excluded])?;
        assert_eq!(names(&inv), [Path::new("skipme").join("z.txt")]);
        Ok(())
    }

    #[test]
    fn cancelling_drops_nothing_and_a_missing_root_keeps_its_entries() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        put(&root.join("a.txt"), EMAIL)?;
        let gone = tmp.0.join("unplugged").join("old.txt");
        inv.record(vec![entry(&gone.to_string_lossy(), &[(Email, 1)])])?;

        let progress = Progress::default();
        inv.scan_paths(
            &engine,
            std::slice::from_ref(&root),
            &[],
            &progress,
            &AtomicBool::new(true),
        )?;
        assert_eq!(
            stored(&inv),
            std::slice::from_ref(&gone),
            "a cancelled scan adds nothing"
        );

        // The root of `old.txt` does not exist: its entries stay for when the disk is back.
        scan(&inv, &engine, &[root.clone(), tmp.0.join("unplugged")], &[])?;
        assert_eq!(stored(&inv), [root.join("a.txt"), gone]);
        // A root that exists says what is gone from it.
        put(&tmp.0.join("unplugged").join("new.txt"), "x")?;
        scan(&inv, &engine, &[tmp.0.join("unplugged")], &[])?;
        assert_eq!(
            stored(&inv),
            [root.join("a.txt"), tmp.0.join("unplugged").join("new.txt")]
        );
        Ok(())
    }

    #[test]
    fn a_file_given_by_name_is_scanned_even_when_a_crawl_would_skip_it() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let file = tmp.0.join("node_modules").join("x.txt");
        put(&file, EMAIL)?;
        scan(&inv, &engine, std::slice::from_ref(&file), &[])?;
        assert_eq!(counts_of(&inv, &file), Some(BTreeMap::from([(Email, 1)])));
        let entry = Entry::scan(&engine, &file);
        assert_eq!(entry.hits(), 1);
        assert_eq!(entry.status, Status::Ok);
        let missing = Entry::scan(&engine, &tmp.0.join("nope.txt"));
        assert!(matches!(missing.status, Status::Failed(_)));
        Ok(())
    }

    #[test]
    fn children_group_by_the_next_component_most_values_first() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        inv.record(vec![
            entry(r"C:\Users\jan\Documents\a.docx", &[(Email, 3), (Iban, 1)]),
            entry(r"C:\Users\jan\Documents\work\b.xlsx", &[(Phone, 5)]),
            entry(r"C:\Users\jan\Documents\work\deep\c.txt", &[(Email, 1)]),
            entry(r"C:\Users\jan\Documents\clean.txt", &[]),
            entry(r"C:\Users\jan\Desktop\d.txt", &[(Email, 2)]),
            entry(r"D:\elsewhere\e.txt", &[(Email, 1)]),
        ])?;
        let roots = [
            PathBuf::from(r"C:\Users\jan\Documents"),
            PathBuf::from(r"C:\Users\jan\Desktop"),
            PathBuf::from(r"C:\Users\jan\Pictures"),
        ];
        let summary = |nodes: Vec<Node>| -> Vec<(String, bool, u64, u32)> {
            nodes
                .into_iter()
                .map(|n| (n.name, n.is_dir, n.hits, n.files))
                .collect()
        };

        let top = inv.children(None, &roots);
        assert_eq!(
            summary(top.clone()),
            [
                ("Documents".to_owned(), true, 10, 3),
                ("Desktop".to_owned(), true, 2, 1),
                (OTHER.to_owned(), true, 1, 1),
            ]
        );
        assert_eq!(top[0].path, roots[0], "a folder node carries its root");
        assert!(
            top[2].path.as_os_str().is_empty(),
            "the virtual node has no path"
        );
        assert_eq!(top[0].counts, [(Phone, 5), (Email, 4), (Iban, 1)]);

        let documents = inv.children(Some(&roots[0]), &roots);
        assert_eq!(
            summary(documents),
            [
                ("work".to_owned(), true, 6, 2),
                ("a.docx".to_owned(), false, 4, 1)
            ]
        );
        let work = inv.children(Some(&roots[0].join("work")), &roots);
        assert_eq!(
            summary(work),
            [
                ("b.xlsx".to_owned(), false, 5, 1),
                ("deep".to_owned(), true, 1, 1)
            ]
        );
        // Letter case does not matter, and the nodes keep the stored spelling.
        let shouted = inv.children(Some(Path::new(r"c:\USERS\jan\documents")), &roots);
        assert_eq!(shouted.len(), 2);
        assert_eq!(shouted[0].path, Path::new(r"C:\Users\jan\Documents\work"));
        // A file has nothing below it.
        assert!(
            inv.children(Some(Path::new(r"C:\Users\jan\Desktop\d.txt")), &roots)
                .is_empty()
        );

        // Of nested roots the deepest takes the entry.
        let nested = [roots[0].clone(), roots[0].join("work")];
        assert_eq!(
            summary(inv.children(None, &nested)),
            [
                ("work".to_owned(), true, 6, 2),
                ("Documents".to_owned(), true, 4, 1),
                (OTHER.to_owned(), true, 3, 2),
            ]
        );
        Ok(())
    }

    #[test]
    fn entries_totals_and_forgetting() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        inv.record(vec![
            entry(r"C:\r\a.txt", &[(Email, 2)]),
            entry(r"C:\r\sub\b.txt", &[(Phone, 1)]),
            entry(r"C:\r\sub\clean.txt", &[]),
            // `sub` starts its name, but it is not in the folder.
            entry(r"C:\r\subway\d.txt", &[(Email, 1)]),
            entry(r"C:\other\c.txt", &[(Iban, 4)]),
        ])?;
        assert_eq!(
            inv.totals(),
            Totals {
                files: 5,
                files_with_pii: 4,
                hits: 8
            }
        );
        let under = |min| -> Vec<PathBuf> {
            inv.entries(Some(Path::new(r"C:\R")), min)
                .into_iter()
                .map(|e| e.path)
                .collect()
        };
        assert_eq!(under(0).len(), 4);
        assert_eq!(under(2), [PathBuf::from(r"C:\r\a.txt")]);

        assert_eq!(inv.forget_under(Path::new(r"C:\r\sub"))?, 2);
        assert_eq!(inv.forget_under(Path::new(r"C:\r\sub"))?, 0);
        let reopened = tmp.inventory()?;
        assert_eq!(
            stored(&reopened),
            [
                PathBuf::from(r"C:\other\c.txt"),
                PathBuf::from(r"C:\r\a.txt"),
                PathBuf::from(r"C:\r\subway\d.txt"),
            ]
        );
        Ok(())
    }

    #[test]
    fn open_skips_what_is_not_an_entry_and_saving_round_trips() -> Res {
        let tmp = TempDir::new()?;
        let path = tmp.0.join("inventory.jsonl");
        let lines = [
            r#"{"path":"C:\\a.txt","size":1,"modified":2,"scanned":3,"status":"ok","counts":{"email":2,"martian":4,"iban":0}}"#,
            "this is not json",
            r#"{"path":"C:\\b.txt","size":1,"modified":2,"scanned":3,"status":"from_the_future","counts":{}}"#,
            r#"{"path":"C:\\c.txt","size":9,"modified":8,"scanned":7,"status":"failed","error":"boom"}"#,
            "",
        ];
        fs::write(&path, lines.join("\n"))?;
        let inv = Inventory::open(&path)?;
        let entries = inv.entries(None, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].counts, [(Email, 2)]);
        assert_eq!(entries[1].status, Status::Failed("boom".to_owned()));
        assert_eq!(
            (entries[1].size, entries[1].modified, entries[1].scanned),
            (9, 8, 7)
        );

        inv.save()?;
        assert_eq!(Inventory::open(&path)?.entries(None, 0), entries);
        let saved = fs::read_to_string(&path)?;
        assert!(saved.contains(r#""counts":{"email":2}"#), "{saved}");
        assert!(!saved.contains("hits"), "the file has no totals: {saved}");
        assert!(
            Inventory::open(&tmp.0.join("nope.jsonl"))?
                .entries(None, 0)
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn only_one_scan_may_hold_the_lock() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        let held = inv.lock_scan()?;
        assert!(matches!(tmp.inventory()?.lock_scan(), Err(Error::Busy(_))));
        drop(held);
        assert!(tmp.inventory()?.lock_scan().is_ok());
        Ok(())
    }

    #[test]
    fn the_report_lists_what_holds_data_or_could_not_be_checked() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        let mut failed = entry(r"C:\r\c.txt", &[]);
        failed.status = Status::Failed("a, \"quoted\" reason".to_owned());
        let mut large = entry(r"C:\r\d.txt", &[]);
        large.status = Status::TooLarge;
        inv.record(vec![
            entry(r"C:\r\a.txt", &[(Email, 2), (Iban, 1)]),
            entry(r"C:\r\b.txt", &[]),
            failed,
            large,
            entry(r"C:\other\e.txt", &[(Phone, 1)]),
        ])?;

        let mut csv = Vec::new();
        let rows = inv.report(Some(Path::new(r"C:\r")), ExportFormat::Csv, &mut csv)?;
        assert_eq!(rows, 3);
        let csv = String::from_utf8(csv)?;
        let lines: Vec<&str> = csv.lines().collect();
        let header: Vec<&str> = lines[0].split(',').collect();
        assert_eq!(header.first(), Some(&"path"));
        assert_eq!(header.last(), Some(&"scanned"));
        assert!(!header.contains(&"phone_number") && !header.contains(&"phone"));
        let column = |name: &str| header.iter().position(|h| *h == name);
        let a: Vec<&str> = lines[1].split(',').collect();
        assert_eq!(a[0], r"C:\r\a.txt");
        assert_eq!(column("hits").map(|i| a[i]), Some("3"));
        assert_eq!(column("email").map(|i| a[i]), Some("2"));
        assert_eq!(column("iban").map(|i| a[i]), Some("1"));
        assert_eq!(a.last(), Some(&"2023-11-14T22:13:20Z"));
        assert!(lines[2].starts_with(r"C:\r\c.txt,failed,0,"), "{csv}");
        assert!(lines[3].starts_with(r"C:\r\d.txt,too_large,0,"), "{csv}");
        assert_eq!(lines.len(), 4, "{csv}");

        let mut json = Vec::new();
        assert_eq!(inv.report(None, ExportFormat::Json, &mut json)?, 4);
        let json: serde_json::Value = serde_json::from_slice(&json)?;
        let rows = json.as_array().map_or(0, Vec::len);
        assert_eq!(rows, 4);
        assert_eq!(json[0]["path"], r"C:\other\e.txt");
        assert_eq!(json[0]["hits"], 1);
        assert_eq!(json[1]["counts"]["email"], 2);
        assert_eq!(json[2]["status"], "failed");
        assert_eq!(json[2]["error"], "a, \"quoted\" reason");
        Ok(())
    }

    #[test]
    fn entries_nodes_and_totals_go_through_json_and_come_back_equal() -> Res {
        let mut failed = entry(r"C:\r\f.txt", &[]);
        failed.status = Status::Failed("a \"quoted\" reason".to_owned());
        let mut large = entry(r"C:\r\l.txt", &[]);
        large.status = Status::TooLarge;
        let mut binary = entry(r"C:\r\b.bin", &[]);
        binary.status = Status::Unsupported;
        let ranked = entry(r"C:\r\a.txt", &[(Phone, 3), (Email, 2)]);
        for one in [ranked, failed, large, binary] {
            let json = serde_json::to_value(&one)?;
            assert_eq!(serde_json::from_value::<Entry>(json)?, one);
        }
        // The shape the API documents.
        assert_eq!(
            serde_json::to_value(entry(r"C:\r\a.txt", &[(Email, 2)]))?,
            serde_json::json!({
                "path": r"C:\r\a.txt", "size": 1, "modified": 1, "scanned": 1_700_000_000,
                "status": "ok", "hits": 2, "counts": {"email": 2}
            })
        );

        let node = Node {
            path: PathBuf::from(r"C:\r"),
            name: "r".to_owned(),
            is_dir: true,
            hits: 5,
            files: 2,
            counts: vec![(Phone, 3), (Email, 2)],
        };
        let json = serde_json::to_value(&node)?;
        assert_eq!(json["counts"][Phone.as_str()], 3);
        assert_eq!(json["files"], 2);
        assert_eq!(serde_json::from_value::<Node>(json)?, node);

        let totals = Totals {
            files: 4,
            files_with_pii: 3,
            hits: 7,
        };
        let json = serde_json::to_value(totals)?;
        assert_eq!(
            json,
            serde_json::json!({"files": 4, "files_with_pii": 3, "hits": 7})
        );
        assert_eq!(serde_json::from_value::<Totals>(json)?, totals);
        Ok(())
    }

    #[test]
    fn reading_an_entry_drops_what_this_version_does_not_know() -> Res {
        let line = r#"{"path":"C:\\a.txt","size":1,"modified":2,"scanned":3,"status":"ok","hits":99,"counts":{"email":2,"martian":4,"iban":0}}"#;
        let one: Entry = serde_json::from_str(line)?;
        assert_eq!(one.counts, [(Email, 2)]);
        assert_eq!(one.hits(), 2, "the hits come from the counts");
        let future = line.replace(r#""ok""#, r#""from_the_future""#);
        assert!(serde_json::from_str::<Entry>(&future).is_err());
        Ok(())
    }

    #[test]
    fn times_are_written_as_utc_dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn a_file_that_could_not_be_read_is_read_again_by_the_next_scan() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        let file = root.join("held.txt");
        put(&file, EMAIL)?;

        // Another program has the file open and shares it with nobody, as a sync client or a
        // virus scanner can for a moment.
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&file)?;
        scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        let failed = inv.entries(Some(&file), 0);
        assert!(matches!(failed[0].status, Status::Failed(_)), "{failed:?}");

        drop(held);
        let again = scan(&inv, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(again.total.load(Ordering::Relaxed), 1);
        assert_eq!(counts_of(&inv, &file), Some(BTreeMap::from([(Email, 1)])));
        Ok(())
    }

    #[test]
    fn a_folder_chosen_in_another_letter_case_does_not_double_its_entries() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        put(&root.join("a.txt"), EMAIL)?;
        put(&root.join("sub").join("b.txt"), IBAN)?;
        scan(&inv, &engine, std::slice::from_ref(&root), &[])?;

        // The same folder spelled otherwise holds the same files, with one entry each.
        let shouted = tmp.0.join("DOCS");
        scan(&inv, &engine, std::slice::from_ref(&shouted), &[])?;
        let kept = stored(&inv);
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(
            kept.iter().all(|path| path.starts_with(&shouted)),
            "{kept:?}"
        );

        // So does a file renamed in letter case only.
        fs::rename(shouted.join("a.txt"), shouted.join("A.TXT"))?;
        scan(&inv, &engine, std::slice::from_ref(&shouted), &[])?;
        let kept = stored(&inv);
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept.contains(&shouted.join("A.TXT")), "{kept:?}");
        Ok(())
    }

    #[test]
    fn a_file_bigger_than_the_walk_said_is_too_large() -> Res {
        let tmp = TempDir::new()?;
        let engine = tmp.engine()?;
        let small = tmp.0.join("small.txt");
        put(&small, "tiny")?;
        let big = tmp.0.join("big.dat");
        let file = File::create(&big)?;
        file.set_len(MAX_FILE + 1)?;
        drop(file);

        // A folder listing gives the size a file had when it was last closed: one that is
        // being written can be far bigger by the time it is read.
        let listed = fs::metadata(&small)?;
        assert_eq!(scan_file(&engine, &big, &listed).status, Status::TooLarge);
        assert_eq!(read_capped(&small)?.as_deref(), Some(&b"tiny"[..]));
        assert_eq!(read_capped(&big)?, None);
        Ok(())
    }

    #[test]
    fn a_save_keeps_what_another_process_saved_since_this_one_last_looked() -> Res {
        let tmp = TempDir::new()?;
        // The app, which has run for a while, and the CLI: two processes on one file.
        let (app, cli) = (tmp.inventory()?, tmp.inventory()?);
        cli.record(vec![entry(r"C:\r\cli.txt", &[(Email, 1)])])?;
        app.record(vec![entry(r"C:\r\app.txt", &[(Phone, 2)])])?;

        let both = [r"C:\r\app.txt", r"C:\r\cli.txt"].map(PathBuf::from);
        assert_eq!(stored(&tmp.inventory()?), both, "the file has both");
        assert_eq!(stored(&app), both, "the app took the CLI's over");

        // Now the CLI is the one behind, and catches up the same way.
        cli.record(vec![entry(r"C:\r\more.txt", &[])])?;
        assert_eq!(stored(&tmp.inventory()?).len(), 3);
        Ok(())
    }

    #[test]
    fn what_another_process_forgot_stays_forgotten() -> Res {
        let tmp = TempDir::new()?;
        tmp.inventory()?.record(vec![
            entry(r"C:\r\a.txt", &[(Email, 1)]),
            entry(r"C:\r\sub\b.txt", &[(Email, 1)]),
        ])?;
        let (app, cli) = (tmp.inventory()?, tmp.inventory()?);
        assert_eq!(cli.forget_under(Path::new(r"C:\r\sub"))?, 1);
        // The app still has `b.txt`; saving something else must not bring it back.
        app.record(vec![entry(r"C:\r\c.txt", &[])])?;
        let kept = [r"C:\r\a.txt", r"C:\r\c.txt"].map(PathBuf::from);
        assert_eq!(stored(&tmp.inventory()?), kept);
        assert_eq!(stored(&app), kept);

        // What the app forgets is gone from the file too, whatever the CLI wrote since.
        cli.record(vec![entry(r"C:\r\d.txt", &[])])?;
        assert_eq!(app.forget_under(Path::new(r"C:\r\a.txt"))?, 1);
        let kept = [r"C:\r\c.txt", r"C:\r\d.txt"].map(PathBuf::from);
        assert_eq!(stored(&tmp.inventory()?), kept);
        Ok(())
    }

    #[test]
    fn a_scan_starts_from_what_another_process_scanned() -> Res {
        let tmp = TempDir::new()?;
        let engine = tmp.engine()?;
        let root = tmp.0.join("docs");
        put(&root.join("a.txt"), EMAIL)?;
        put(&root.join("b.txt"), IBAN)?;
        let (app, cli) = (tmp.inventory()?, tmp.inventory()?);

        let first = scan(&cli, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(first.total.load(Ordering::Relaxed), 2);
        // The app opened the inventory before that, and has not seen it.
        let second = scan(&app, &engine, std::slice::from_ref(&root), &[])?;
        assert_eq!(second.total.load(Ordering::Relaxed), 0);
        assert_eq!(stored(&app).len(), 2);
        Ok(())
    }

    #[test]
    fn processes_saving_at_the_same_time_lose_nothing() -> Res {
        let tmp = TempDir::new()?;
        let inventories = [tmp.inventory()?, tmp.inventory()?, tmp.inventory()?];
        let results: Vec<Result<()>> = std::thread::scope(|scope| {
            let workers: Vec<_> = inventories
                .iter()
                .enumerate()
                .map(|(n, inv)| {
                    scope.spawn(move || {
                        (0..6).try_for_each(|i| {
                            let path = format!(r"C:\r\p{n}\f{i}.txt");
                            inv.record(vec![entry(&path, &[(Email, 1)])])
                        })
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap_or(Err(Error::Poisoned)))
                .collect()
        });
        for result in results {
            result?;
        }
        assert_eq!(stored(&tmp.inventory()?).len(), 18);
        Ok(())
    }

    #[test]
    fn a_save_that_cannot_take_the_lock_keeps_its_changes_for_the_next() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        let held = sys::try_lock(&tmp.0.join("inventory.save.lock"))?.ok_or("the lock is taken")?;
        inv.insert(vec![entry(r"C:\r\a.txt", &[(Email, 1)])]);
        assert!(matches!(
            inv.save_within(Duration::ZERO),
            Err(Error::Busy(_))
        ));
        assert_eq!(inv.unsaved(), 1);
        assert!(stored(&tmp.inventory()?).is_empty());

        drop(held);
        inv.save()?;
        assert_eq!(inv.unsaved(), 0);
        assert_eq!(stored(&tmp.inventory()?), [PathBuf::from(r"C:\r\a.txt")]);
        Ok(())
    }

    #[test]
    fn a_save_removes_the_temp_files_a_crashed_save_left() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        let left = tmp.0.join("inventory.jsonl.4242-7.tmp");
        fs::write(&left, "half a file")?;
        inv.record(vec![entry(r"C:\r\a.txt", &[])])?;
        assert!(!left.exists());
        Ok(())
    }

    #[test]
    fn forgetting_also_forgets_what_another_process_added_since() -> Res {
        let tmp = TempDir::new()?;
        let (app, cli) = (tmp.inventory()?, tmp.inventory()?);
        cli.record(vec![
            entry(r"C:\r\sub\new.txt", &[(Email, 1)]),
            entry(r"C:\r\keep.txt", &[]),
        ])?;
        // The app has not seen `new.txt`, and still has to forget it.
        assert_eq!(app.forget_under(Path::new(r"C:\r\sub"))?, 1);
        let kept = [PathBuf::from(r"C:\r\keep.txt")];
        assert_eq!(stored(&tmp.inventory()?), kept);
        assert_eq!(stored(&app), kept);
        Ok(())
    }

    #[test]
    fn what_this_process_has_not_saved_wins_over_another_process_for_the_same_file() -> Res {
        let tmp = TempDir::new()?;
        let (app, cli) = (tmp.inventory()?, tmp.inventory()?);
        cli.record(vec![entry(r"C:\r\a.txt", &[(Email, 1)])])?;
        app.insert(vec![entry(r"C:\r\a.txt", &[(Phone, 5)])]);
        app.save()?;
        let saved = tmp.inventory()?.entries(None, 0);
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].counts, [(Phone, 5)]);
        Ok(())
    }

    #[test]
    fn a_save_that_cannot_write_keeps_its_changes_for_the_next() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        inv.record(vec![entry(r"C:\r\a.txt", &[])])?;
        inv.insert(vec![entry(r"C:\r\b.txt", &[])]);

        // A reader that does not share the file for deletion keeps the rename from replacing it.
        let reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(tmp.0.join("inventory.jsonl"))?;
        assert!(matches!(inv.save(), Err(Error::Io(_))));
        assert_eq!(inv.unsaved(), 1);
        assert_eq!(stored(&tmp.inventory()?).len(), 1);

        drop(reader);
        inv.save()?;
        assert_eq!(inv.unsaved(), 0);
        assert_eq!(stored(&tmp.inventory()?).len(), 2);
        Ok(())
    }

    #[test]
    fn a_folder_watched_twice_in_two_letter_cases_has_one_entry_per_file() -> Res {
        let tmp = TempDir::new()?;
        let (engine, inv) = (tmp.engine()?, tmp.inventory()?);
        let root = tmp.0.join("docs");
        put(&root.join("a.txt"), EMAIL)?;
        put(&root.join("sub").join("b.txt"), IBAN)?;

        let progress = scan(&inv, &engine, &[root, tmp.0.join("DOCS")], &[])?;
        assert_eq!(progress.total.load(Ordering::Relaxed), 2);
        assert_eq!(stored(&inv).len(), 2, "{:?}", stored(&inv));
        assert_eq!(inv.totals().hits, 2);
        Ok(())
    }

    /// A writer that counts how often it is written to.
    #[derive(Default)]
    struct Counting {
        bytes: Vec<u8>,
        writes: usize,
    }

    impl Write for Counting {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer with no room left.
    struct Full;

    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_report_is_written_in_big_pieces_and_a_write_error_is_an_error() -> Res {
        let tmp = TempDir::new()?;
        let inv = tmp.inventory()?;
        let rows: Vec<Entry> = (0..400)
            .map(|i| entry(&format!(r"C:\r\f{i}.txt"), &[(Email, 2), (Iban, 1)]))
            .collect();
        inv.record(rows)?;
        for format in [ExportFormat::Csv, ExportFormat::Json] {
            let mut out = Counting::default();
            assert_eq!(inv.report(None, format, &mut out)?, 400);
            // Every write to a file is a system call: one for each field would be thousands.
            let (writes, bytes) = (out.writes, out.bytes.len());
            assert!(writes * 2048 < bytes, "{writes} writes for {bytes} bytes");
        }
        assert!(matches!(
            inv.report(None, ExportFormat::Csv, &mut Full),
            Err(Error::Io(_))
        ));
        Ok(())
    }
}
