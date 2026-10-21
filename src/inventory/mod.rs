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

use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fs::{self, File, Metadata, OpenOptions, TryLockError},
    io::{self, Write},
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{
        Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    Error, Result,
    detect::EntityKind,
    engine::Engine,
    files, formats,
    sys::{self, io_context},
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
/// A scan saves the inventory after this many scanned files, but not more often than
/// `SAVE_GAP`: a save writes every entry again.
const SAVE_EVERY: usize = 2_000;
const SAVE_GAP: Duration = Duration::from_secs(15);
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
    /// `size` it says whether the file changed since the scan.
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
    /// Could not be read or parsed; the message says why. Like any other file it is not read
    /// again until it changes: a file that cannot be understood would cost the same every time.
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
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
    entries: RwLock<BTreeMap<PathBuf, Entry>>,
    /// Two saves at once would write the same temporary file.
    saving: Mutex<()>,
}

// No entries: they are a map of the user's files.
impl fmt::Debug for Inventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inventory")
            .field("path", &self.path)
            .field("entries", &self.read().len())
            .finish_non_exhaustive()
    }
}

/// Held while an inventory scan runs, see [`Inventory::lock_scan`].
#[derive(Debug)]
pub struct ScanLock(File);

impl Drop for ScanLock {
    fn drop(&mut self) {
        // Closing the handle releases the lock as well, so a failure is harmless.
        let _ = self.0.unlock();
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
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(io_context(&err, "read", path)),
        };
        let entries = bytes
            .split(|&byte| byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<Stored>(line.trim_ascii()).ok())
            .filter_map(Stored::entry)
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        Ok(Self {
            path: path.to_path_buf(),
            entries: RwLock::new(entries),
            saving: Mutex::new(()),
        })
    }

    // The map is plain data and every change to it is one insert or remove, so whatever a
    // panicking thread left behind is a valid map.
    fn read(&self) -> RwLockReadGuard<'_, BTreeMap<PathBuf, Entry>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, BTreeMap<PathBuf, Entry>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes the inventory to its file, replacing it as a whole.
    ///
    /// # Errors
    /// `Io`.
    pub fn save(&self) -> Result<()> {
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let mut bytes = Vec::new();
        for entry in self.read().values() {
            serde_json::to_writer(&mut bytes, &Shown::of(entry, false)).map_err(io::Error::from)?;
            bytes.push(b'\n');
        }
        sys::write_atomic(&self.path, &bytes)
    }

    /// Takes the right to scan: one scan at a time over this inventory file, across processes
    /// (the CLI and the app). Hold the lock for as long as the scan runs.
    ///
    /// # Errors
    /// `Busy` when another scan holds it; `Io`.
    pub fn lock_scan(&self) -> Result<ScanLock> {
        let path = self.path.with_extension("lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| io_context(&e, "open", &path))?;
        match file.try_lock() {
            Ok(()) => Ok(ScanLock(file)),
            Err(TryLockError::WouldBlock) => {
                Err(Error::Busy("another inventory scan is running".into()))
            }
            Err(TryLockError::Error(err)) => Err(io_context(&err, "lock", &path)),
        }
    }

    /// Scans the files under `paths` and updates the inventory: new and changed files are read,
    /// the others are left as they are (a file whose size and write time equal what was stored,
    /// whatever came of it). Entries under `paths` whose files are gone, or that lie
    /// under `exclude`, are dropped.
    ///
    /// The walk leaves out `exclude`, `AppData`, `node_modules`, `.git`, `target`, the recycle
    /// bin, hidden and system files, and files that are online only (reading them would
    /// download them), so what a folder of the user's holds is what is scanned. Files over
    /// [`MAX_FILE`] are recorded as too large. Work goes in chunks on the rayon pool the caller
    /// runs in, which is how the app keeps a scan to half the cores; `progress` is updated as
    /// files finish, and `cancel` is looked at between files, so a scan stops within the file
    /// it is in. A cancelled scan saves what it did and drops nothing.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be saved.
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
        let pending: Vec<&(PathBuf, Metadata)> = {
            let stored = self.read();
            walked
                .iter()
                .filter(|(path, meta)| {
                    !stored.get(path).is_some_and(|known| {
                        known.size == meta.len() && known.modified == meta.last_write_time()
                    })
                })
                .collect()
        };
        progress.total.store(
            u64::try_from(pending.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let mut unsaved = false;
        let mut since_save = 0;
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
            since_save += scanned.len();
            unsaved |= !scanned.is_empty();
            self.insert(scanned);
            if since_save >= SAVE_EVERY && last_save.elapsed() >= SAVE_GAP {
                self.save()?;
                (since_save, unsaved, last_save) = (0, false, Instant::now());
            }
        }
        if !cancel.load(Ordering::Relaxed) {
            unsaved |= self.drop_stale(paths, exclude, &walked) > 0;
        }
        if unsaved {
            self.save()?;
        }
        Ok(())
    }

    fn insert(&self, entries: Vec<Entry>) {
        let mut map = self.write();
        for entry in entries {
            map.insert(entry.path.clone(), entry);
        }
    }

    /// Adds `entries`, replacing what is stored for the same files, and saves.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be saved.
    pub fn record(&self, entries: Vec<Entry>) -> Result<()> {
        self.insert(entries);
        self.save()
    }

    /// Drops the entries under `roots` that a complete walk of them did not find and that are
    /// gone from disk, and the ones under `exclude`; returns how many.
    ///
    /// A root that does not exist (a disk that is unplugged) drops nothing, and neither does a
    /// file that exists but was not walked (a folder that could not be listed this time).
    fn drop_stale(
        &self,
        roots: &[PathBuf],
        exclude: &[PathBuf],
        walked: &[(PathBuf, Metadata)],
    ) -> usize {
        let present: HashSet<&Path> = walked.iter().map(|(path, _)| path.as_path()).collect();
        let roots: Vec<&PathBuf> = roots
            .iter()
            .filter(|root| fs::metadata(root).is_ok())
            .collect();
        let candidates: Vec<PathBuf> = self
            .read()
            .keys()
            .filter(|path| {
                roots.iter().any(|root| is_under(path, root)) && !present.contains(path.as_path())
            })
            .cloned()
            .collect();
        // The file system is asked outside the lock.
        let stale: Vec<PathBuf> = candidates
            .into_iter()
            .filter(|path| is_excluded(path, exclude) || is_gone(path))
            .collect();
        let mut map = self.write();
        for path in &stale {
            map.remove(path);
        }
        stale.len()
    }

    /// Forgets the entries at and under `prefix` and saves; returns how many there were.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be saved.
    pub fn forget_under(&self, prefix: &Path) -> Result<usize> {
        let removed = {
            let mut map = self.write();
            let before = map.len();
            map.retain(|path, _| !is_under(path, prefix));
            before - map.len()
        };
        if removed > 0 {
            self.save()?;
        }
        Ok(removed)
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
            .values()
            .filter(|entry| under.is_none_or(|under| is_under(&entry.path, under)) && keep(entry))
            .cloned()
            .collect()
    }

    /// The inventory in numbers.
    #[must_use]
    pub fn totals(&self) -> Totals {
        let map = self.read();
        let mut totals = Totals {
            files: u64::try_from(map.len()).unwrap_or(u64::MAX),
            ..Totals::default()
        };
        for hits in map.values().map(Entry::hits).filter(|&hits| hits > 0) {
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
        let base: Vec<Component<'_>> = under
            .map(|under| under.components().collect())
            .unwrap_or_default();
        let mut nodes: HashMap<String, Tally> = HashMap::new();
        for entry in self.read().values().filter(|entry| entry.hits() > 0) {
            let node = match under {
                Some(_) => child_of(&entry.path, &base),
                None => Some(top_of(&entry.path, roots)),
            };
            if let Some((path, name, is_dir)) = node {
                let key = path.to_string_lossy().to_lowercase();
                nodes
                    .entry(key)
                    .or_insert_with(|| Tally::new(path, name, is_dir))
                    .add(entry);
            }
        }
        let mut nodes: Vec<Node> = nodes.into_values().map(Tally::finish).collect();
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
        match format {
            ExportFormat::Json => {
                out.write_all(b"[")?;
                for (i, entry) in rows.iter().enumerate() {
                    out.write_all(if i == 0 { b"\n" } else { b",\n" })?;
                    serde_json::to_writer(&mut *out, &Shown::of(entry, true))
                        .map_err(io::Error::from)?;
                }
                out.write_all(b"\n]\n")?;
            }
            ExportFormat::Csv => {
                let kinds: Vec<EntityKind> = EntityKind::ALL
                    .into_iter()
                    .filter(|kind| {
                        rows.iter()
                            .any(|row| row.counts.iter().any(|(k, _)| k == kind))
                    })
                    .collect();
                let mut header = vec!["path", "status", "hits"];
                header.extend(kinds.iter().map(|kind| kind.as_str()));
                header.push("scanned");
                csv_row(out, &header)?;
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
                    csv_row(out, &row)?;
                }
            }
        }
        out.flush()?;
        Ok(rows.len())
    }
}

/// Reads and scans one file, or says why not.
fn scan_file(engine: &Engine, path: &Path, meta: &Metadata) -> Entry {
    let size = meta.len();
    let (status, counts) = if size > MAX_FILE {
        (Status::TooLarge, Vec::new())
    } else {
        match fs::read(path) {
            Err(err) => (Status::Failed(err.to_string()), Vec::new()),
            Ok(bytes) => match formats::scan(engine, &bytes, false) {
                Ok(scanned) => (Status::Ok, tally(&scanned.found)),
                Err(Error::UnsupportedFormat(_)) => (Status::Unsupported, Vec::new()),
                Err(err) => (Status::Failed(err.to_string()), Vec::new()),
            },
        }
    };
    Entry {
        path: path.to_path_buf(),
        size,
        modified: meta.last_write_time(),
        scanned: unix_now(),
        status,
        counts,
    }
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
    exclude.iter().any(|excluded| is_under(path, excluded))
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

/// Whether `path` is `prefix` or lies below it. Windows paths are not case sensitive, and
/// neither is this.
fn is_under(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix
        .components()
        .all(|want| path.next().is_some_and(|have| same_component(have, want)))
}

fn same_component(a: Component<'_>, b: Component<'_>) -> bool {
    a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
}

/// The node of `path` one level below `base`: its path, its name and whether it is a folder
/// (something lies below it), or `None` when `path` is not below `base`.
fn child_of(path: &Path, base: &[Component<'_>]) -> Option<(PathBuf, String, bool)> {
    let mut components = path.components();
    for want in base {
        if !components
            .next()
            .is_some_and(|have| same_component(have, *want))
        {
            return None;
        }
    }
    let next = components.next()?;
    let is_dir = components.next().is_some();
    let child: PathBuf = path.components().take(base.len() + 1).collect();
    Some((
        child,
        next.as_os_str().to_string_lossy().into_owned(),
        is_dir,
    ))
}

/// The top-level node `path` belongs to: the deepest of `roots` it is under, else the node for
/// the scans outside them.
fn top_of(path: &Path, roots: &[PathBuf]) -> (PathBuf, String, bool) {
    roots
        .iter()
        .filter(|root| is_under(path, root))
        .max_by_key(|root| root.components().count())
        .map_or_else(
            || (PathBuf::new(), OTHER.to_owned(), true),
            |root| {
                let name = root.file_name().map_or_else(
                    || root.display().to_string(),
                    |name| name.to_string_lossy().into_owned(),
                );
                (root.clone(), name, true)
            },
        )
}

/// A node being added up.
struct Tally {
    node: Node,
    per_kind: BTreeMap<EntityKind, u32>,
}

impl Tally {
    fn new(path: PathBuf, name: String, is_dir: bool) -> Self {
        Self {
            node: Node {
                path,
                name,
                is_dir,
                hits: 0,
                files: 0,
                counts: Vec::new(),
            },
            per_kind: BTreeMap::new(),
        }
    }

    fn add(&mut self, entry: &Entry) {
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

/// An entry as it is read from the file.
#[derive(Deserialize)]
struct Stored {
    path: String,
    size: u64,
    modified: u64,
    scanned: u64,
    status: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    counts: BTreeMap<String, u32>,
}

impl Stored {
    /// `None` for a status this version does not know.
    fn entry(self) -> Option<Entry> {
        let status = match self.status.as_str() {
            "ok" => Status::Ok,
            "unsupported" => Status::Unsupported,
            "too_large" => Status::TooLarge,
            "failed" => Status::Failed(self.error.unwrap_or_default()),
            _ => return None,
        };
        let counts = self
            .counts
            .into_iter()
            .filter(|&(_, n)| n > 0)
            .filter_map(|(name, n)| EntityKind::parse(&name).map(|kind| (kind, n)))
            .collect();
        Some(Entry {
            path: PathBuf::from(self.path),
            size: self.size,
            modified: self.modified,
            scanned: self.scanned,
            status,
            counts: ranked(counts),
        })
    }
}

/// An entry as it is written: to the file (without `hits`, which the counts give) and to the
/// API and the report (with).
#[derive(Serialize)]
struct Shown<'a> {
    path: Cow<'a, str>,
    size: u64,
    modified: u64,
    scanned: u64,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hits: Option<u64>,
    counts: Counts<'a>,
}

impl<'a> Shown<'a> {
    fn of(entry: &'a Entry, with_hits: bool) -> Self {
        Self {
            path: entry.path.to_string_lossy(),
            size: entry.size,
            modified: entry.modified,
            scanned: entry.scanned,
            status: entry.status.as_str(),
            error: entry.status.error(),
            hits: with_hits.then(|| entry.hits()),
            counts: Counts(&entry.counts),
        }
    }
}

/// Counts as a JSON object, `{"email":3}`.
struct Counts<'a>(&'a [(EntityKind, u32)]);

impl Serialize for Counts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(kind, n)| (kind.as_str(), n)))
    }
}

impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        Shown::of(self, true).serialize(serializer)
    }
}

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Shape<'a> {
            path: Cow<'a, str>,
            name: &'a str,
            is_dir: bool,
            hits: u64,
            files: u32,
            counts: Counts<'a>,
        }
        Shape {
            path: self.path.to_string_lossy(),
            name: &self.name,
            is_dir: self.is_dir,
            hits: self.hits,
            files: self.files,
            counts: Counts(&self.counts),
        }
        .serialize(serializer)
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
    use std::sync::atomic::AtomicUsize;

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
        let status = |name: &str| inv.read().get(&root.join(name)).map(|e| e.status.clone());
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
            entry(r"C:\other\c.txt", &[(Iban, 4)]),
        ])?;
        assert_eq!(
            inv.totals(),
            Totals {
                files: 4,
                files_with_pii: 3,
                hits: 7
            }
        );
        let under = |min| -> Vec<PathBuf> {
            inv.entries(Some(Path::new(r"C:\R")), min)
                .into_iter()
                .map(|e| e.path)
                .collect()
        };
        assert_eq!(under(0).len(), 3);
        assert_eq!(under(2), [PathBuf::from(r"C:\r\a.txt")]);

        assert_eq!(inv.forget_under(Path::new(r"C:\r\sub"))?, 2);
        assert_eq!(inv.forget_under(Path::new(r"C:\r\sub"))?, 0);
        let reopened = tmp.inventory()?;
        assert_eq!(
            stored(&reopened),
            [
                PathBuf::from(r"C:\other\c.txt"),
                PathBuf::from(r"C:\r\a.txt")
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
    fn entries_and_nodes_serialize_for_the_api() -> Res {
        let one = entry(r"C:\r\a.txt", &[(Email, 2)]);
        let json = serde_json::to_value(&one).map_err(io::Error::from)?;
        assert_eq!(
            json,
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
        let json = serde_json::to_value(&node).map_err(io::Error::from)?;
        assert_eq!(json["counts"][Phone.as_str()], 3);
        assert_eq!(json["files"], 2);
        Ok(())
    }

    #[test]
    fn the_inventory_and_its_progress_can_be_shared_between_threads() {
        fn check<T: Send + Sync>() {}
        check::<Inventory>();
        check::<Progress>();
        check::<Entry>();
    }

    #[test]
    fn times_are_written_as_utc_dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn paths_are_compared_by_component_and_without_case() {
        assert!(is_under(
            Path::new(r"C:\Users\Jan\a.txt"),
            Path::new(r"c:\users\jan")
        ));
        assert!(is_under(
            Path::new(r"C:\Users\Jan"),
            Path::new(r"C:\Users\Jan")
        ));
        assert!(!is_under(
            Path::new(r"C:\Users\Jansen\a.txt"),
            Path::new(r"C:\Users\Jan")
        ));
        assert!(!is_under(
            Path::new(r"C:\Users"),
            Path::new(r"C:\Users\Jan")
        ));
        assert!(!is_under(
            Path::new(r"D:\Users\Jan"),
            Path::new(r"C:\Users\Jan")
        ));
    }
}
