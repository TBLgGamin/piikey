//! DPAPI-wrapped, encrypted original↔proxy vault: append-only, but for [`Vault::forget`].
//!
//! The file is the source of truth and the in-memory `State` a cache of it.
//! [`Vault::resolve`] appends records and [`Vault::forget`] removes them; those two are the
//! only writers. Under the in-process mutex and the cross-process file lock each first finishes
//! a forget that stopped halfway and merges what other processes did. `resolve` then picks
//! proxies that collide with nothing (and that the caller does not turn down, see `resolve`),
//! appends them in one write and syncs. `forget` rewrites the file: see there.
//!
//! No lock is ever held across a rayon call. A rayon worker that waits for its
//! own parallel work runs other queued jobs meanwhile, and one of those may
//! call back into the vault on the same thread; against a lock this thread
//! already holds, that deadlocks. So the parallel work (candidate generation)
//! happens before any lock is taken, and everything under a lock is sequential.

mod file;
mod keys;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard},
};

use rayon::prelude::*;
use serde::Serialize;

use self::{
    file::{Entry, FileLock, Id, VAULT_ID_LEN},
    keys::VaultKeys,
};
use crate::{
    Error, Result,
    detect::EntityKind,
    proxy::{ProxyKeys, generate, watermark_ok},
    sys,
};

/// Candidates tried per original before giving up.
const MAX_ATTEMPTS: u32 = 4096;
const KINDS: usize = EntityKind::ALL.len();

/// `%LOCALAPPDATA%\piikey\vault.pkv` (parent dir created).
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` on mkdir failure.
pub fn default_path() -> Result<PathBuf> {
    Ok(sys::data_dir()?.join("vault.pkv"))
}

/// How [`export`] writes the records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// A JSON array of `{"kind","original","proxy"}` objects.
    Json,
    /// RFC 4180 CSV with the header `kind,original,proxy`.
    Csv,
}

/// Index of `kind` in `State::by_original`.
fn slot(kind: EntityKind) -> usize {
    usize::from(kind as u8) - 1
}

/// Everything the file holds, indexed for lookup.
struct State {
    /// original → proxy, per kind, so lookups by `&str` allocate nothing.
    by_original: [HashMap<Arc<str>, Arc<str>>; KINDS],
    /// proxy → (kind, original). Keyed without the kind so a proxy is unique
    /// across kinds and deanonymizing needs no kind.
    by_proxy: HashMap<Arc<str>, (EntityKind, Arc<str>)>,
    /// Every original of every kind: no proxy may equal one of them.
    originals: HashSet<Arc<str>>,
    /// Every record in file order, which is the order they were issued in. Their number is also
    /// the next record's index.
    records: Vec<Entry>,
    /// Byte length of the longest proxy of any record, see [`VaultView::longest_proxy`].
    longest_proxy: usize,
    /// How often the records were replaced wholesale since the vault was opened, see
    /// [`VaultView::generation`].
    generation: u64,
}

// Hand-written: `Default` is only derived for arrays of up to 32 elements, and there is one map
// per kind.
impl Default for State {
    fn default() -> Self {
        Self {
            by_original: std::array::from_fn(|_| HashMap::new()),
            by_proxy: HashMap::new(),
            originals: HashSet::new(),
            records: Vec::new(),
            longest_proxy: 0,
            generation: 0,
        }
    }
}

impl State {
    /// Records in the file: the index of the next one.
    fn count(&self) -> u64 {
        self.records.len() as u64
    }

    fn insert_all(&mut self, entries: Vec<Entry>) {
        let mut per_kind = [0usize; KINDS];
        for entry in &entries {
            per_kind[slot(entry.kind)] += 1;
        }
        for (map, extra) in self.by_original.iter_mut().zip(per_kind) {
            map.reserve(extra);
        }
        self.by_proxy.reserve(entries.len());
        self.originals.reserve(entries.len());
        self.records.reserve(entries.len());
        for entry in entries {
            self.longest_proxy = self.longest_proxy.max(entry.proxy.len());
            self.by_original[slot(entry.kind)]
                .insert(Arc::clone(&entry.original), Arc::clone(&entry.proxy));
            self.by_proxy.insert(
                Arc::clone(&entry.proxy),
                (entry.kind, Arc::clone(&entry.original)),
            );
            self.originals.insert(Arc::clone(&entry.original));
            self.records.push(entry);
        }
    }
}

/// The vault. All methods take `&self`; it is `Send + Sync`.
pub struct Vault {
    file: File,
    path: PathBuf,
    keys: VaultKeys,
    /// The DPAPI-wrapped master key as the header holds it: a forget writes it back as it is.
    wrapped: Vec<u8>,
    /// Size of the header in bytes; the records start there. It depends on the wrapped key
    /// alone, so it outlives a forget.
    header_len: u64,
    /// The id the file's records are sealed under. Another process's forget replaces it, and
    /// `merge_appended` is where this process finds out. Only touched with `known_len` held.
    id: RwLock<Id>,
    state: RwLock<State>,
    /// File offset just past the last record this process has read or
    /// written. Also the in-process writer lock: it is held for a whole write.
    known_len: Mutex<u64>,
}

/// A consistent read snapshot (holds the read lock while alive).
///
/// Drop it before calling [`Vault::resolve`] or [`Vault::forget`] on the same thread, and never
/// hold one across a rayon `par_iter`/`join`: a worker waiting inside one
/// runs other jobs, and any of them may need the write lock or a second read
/// lock, which deadlocks against the one held here.
pub struct VaultView<'a> {
    state: RwLockReadGuard<'a, State>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither keys nor mappings: this ends up in logs.
        f.debug_struct("Vault")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VaultView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultView")
            .field("records", &self.state.count())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Opens the vault at `path`. A missing or empty file becomes a new vault
    /// with a fresh DPAPI-wrapped key; concurrent first opens are safe. A
    /// record cut short by a crash at the end of the file is truncated, and a
    /// [`Vault::forget`] that a crash interrupted is finished.
    ///
    /// # Errors
    /// `Io`, `Dpapi`, `VaultCorrupt`.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        // One exclusive lock covers finishing an interrupted forget, creating the header,
        // reading the file and cutting a torn tail. Whoever gets it first on an empty file
        // creates the vault; everyone else waits and then loads it.
        let lock = FileLock::exclusive(&file)?;
        finish_compaction(&file, path)?;
        let len = file.metadata()?.len();
        let (head, body) = if len == 0 {
            (create_header(&file)?, Vec::new())
        } else {
            let head = load_header(&file, len)?;
            let body = file::read_range(&file, head.len, len)?;
            (head, body)
        };
        let framed = file::frame(&head.keys.records, &head.id, &body, 0)?;
        let known_len = head.len + framed.good_len as u64;
        if framed.good_len < body.len() {
            file.set_len(known_len)?;
        }
        // Decrypting everything is the slow part; it needs only the bytes in
        // memory, so it runs after the lock is released and in parallel.
        drop(lock);
        let entries = file::decrypt(&head.keys.records, &head.id, &body, &framed.frames, 0, true)?;
        let mut state = State::default();
        state.insert_all(entries);
        Ok(Self {
            file,
            path: path.to_owned(),
            keys: head.keys,
            wrapped: head.wrapped,
            header_len: head.len,
            id: RwLock::new(head.id),
            state: RwLock::new(state),
            known_len: Mutex::new(known_len),
        })
    }

    /// Proxy derivation/watermark keys.
    #[must_use]
    pub fn proxy_keys(&self) -> &ProxyKeys {
        &self.keys.proxy
    }

    /// Read snapshot for many lookups under one lock.
    ///
    /// # Errors
    /// `Poisoned`.
    pub fn read(&self) -> Result<VaultView<'_>> {
        Ok(VaultView {
            state: self.state.read()?,
        })
    }

    /// Issues proxies for every `(kind, original)` not yet mapped, merging
    /// records appended by other processes first. The only call that adds records.
    ///
    /// A proxy equals no issued proxy, no known original, no original in `new`
    /// and no proxy issued by this call, and none for which `avoid(kind,
    /// proxy)` holds: that is how a caller keeps a proxy from reading like
    /// text it is about to leave as it is. `avoid` is asked about each
    /// candidate in turn while the vault's write lock is held, so it must be
    /// cheap and must not call back into the vault.
    ///
    /// # Errors
    /// `Io`, `VaultCorrupt`, `ProxyExhausted`, `Poisoned`.
    pub fn resolve(
        &self,
        mut new: Vec<(EntityKind, Box<str>)>,
        avoid: &dyn Fn(EntityKind, &str) -> bool,
    ) -> Result<()> {
        new.par_sort_unstable();
        new.dedup();
        let mut pending = self.unresolved(new)?;
        if pending.is_empty() {
            return Ok(());
        }
        // The expensive part of choosing a proxy does not depend on the
        // vault's contents, so it runs now, in parallel, with no lock held.
        let keys = self.proxy_keys();
        pending
            .par_iter_mut()
            .for_each(|p| p.first = watermarked(keys, p.kind, &p.original, 0));
        self.locked_append(|state| choose(keys, state, pending, avoid))
    }

    /// Removes every record `gone(kind, original, proxy)` says yes to and returns how many there
    /// were. The file is rewritten without them: they are not in it afterwards, and a proxy that
    /// was issued for one is ordinary text again. A call that finds nothing to remove writes
    /// nothing.
    ///
    /// Every record is sealed under the vault id and its own index, so the rewrite seals all the
    /// records that stay again, under a new random id. It is done in place, in the same file,
    /// because other processes hold it open. They find out from the id: the next time one of them
    /// writes it reloads the vault, while a process that only reads keeps the records it has until
    /// it is restarted. The order of the steps makes a crash at any point recoverable:
    ///
    /// 1. the new file is written to a temporary file, synced and renamed to
    ///    `<vault>.compact`, which is the point of no return;
    /// 2. the vault file is cut to the new length and the new contents are written over it;
    /// 3. `.compact` is deleted.
    ///
    /// A forget that stopped after step 1, by a crash or an `Io` error, is finished by the next
    /// [`Vault::open`] and by the next write of any process that has the vault open, so nothing
    /// is appended to the old contents it is about to replace.
    ///
    /// `gone` is asked about each record in turn while the vault's locks are held, so it must be
    /// cheap and must not call back into the vault.
    ///
    /// # Errors
    /// `Io`, `VaultCorrupt`, `Poisoned`. An `Io` after step 1 may leave the file half rewritten:
    /// the next open or write repairs it.
    pub fn forget(&self, gone: &dyn Fn(EntityKind, &str, &str) -> bool) -> Result<usize> {
        let (mut known_len, _lock) = self.lock_current()?;
        let (kept, removed) = {
            let state = self.state.read()?;
            let mut kept = Vec::with_capacity(state.records.len());
            for record in &state.records {
                if !gone(record.kind, &record.original, &record.proxy) {
                    kept.push(record.clone());
                }
            }
            let removed = state.records.len() - kept.len();
            (kept, removed)
        };
        if removed == 0 {
            return Ok(0);
        }
        let mut id = [0u8; VAULT_ID_LEN];
        sys::fill_random(&mut id)?;
        let mut image = file::encode_header(&self.wrapped, &id)?;
        image.extend_from_slice(&file::seal(&self.keys.records, &id, 0, &kept)?);

        let compact = suffixed(&self.path, COMPACT_SUFFIX);
        sys::write_atomic(&compact, &image)?;
        overwrite(&self.file, &image)?;
        // Best effort: a copy that stays is recognized for what it is, and removed, by the next
        // open or write, see `finish_compaction`.
        let _ = fs::remove_file(&compact);

        self.replace_state(kept)?;
        *self.id.write()? = id;
        *known_len = image.len() as u64;
        Ok(removed)
    }

    /// Removes every record, see [`Vault::forget`]. The key stays, so the vault is as usable as
    /// a new one.
    ///
    /// # Errors
    /// As [`Vault::forget`].
    pub fn wipe(&self) -> Result<usize> {
        self.forget(&|_, _, _| true)
    }

    /// The requests that have no proxy yet, with their originals shared.
    fn unresolved(&self, new: Vec<(EntityKind, Box<str>)>) -> Result<Vec<Pending>> {
        let state = self.state.read()?;
        Ok(new
            .into_iter()
            .filter(|(kind, original)| !state.by_original[slot(*kind)].contains_key(&**original))
            .map(|(kind, original)| Pending {
                kind,
                original: Arc::from(original),
                first: None,
            })
            .collect())
    }

    /// Runs `choose` against the up-to-date contents of the vault, then
    /// appends the entries it returns to the file.
    ///
    /// Takes the locks and brings the vault up to date first, see
    /// [`Self::lock_current`], and only then calls `choose`. Everything here is sequential: see
    /// the module docs.
    fn locked_append<F>(&self, choose: F) -> Result<()>
    where
        F: FnOnce(&State) -> Result<Vec<Entry>>,
    {
        let (mut known_len, _lock) = self.lock_current()?;
        let entries = {
            let state = self.state.read()?;
            choose(&state)?
        };
        if entries.is_empty() {
            return Ok(());
        }
        self.append(&mut known_len, entries)
    }

    /// Takes the in-process mutex, then the file lock, and brings this process up to date with
    /// the file: first a forget that was interrupted is finished, then the records other
    /// processes appended are merged. The locks are released when the guards drop, the file
    /// lock first.
    ///
    /// A forget holds both locks from its first step to its last, so a `.compact` file that is
    /// there once the lock is ours belongs to one that stopped. Left alone, the vault would be
    /// appended to or cut as a torn tail in a state that the finishing then overwrites.
    fn lock_current(&self) -> Result<(MutexGuard<'_, u64>, FileLock<'_>)> {
        let mut known_len = self.known_len.lock()?;
        let lock = FileLock::exclusive(&self.file)?;
        if suffixed(&self.path, COMPACT_SUFFIX).try_exists()? {
            finish_compaction(&self.file, &self.path)?;
        }
        self.merge_appended(&mut known_len)?;
        Ok((known_len, lock))
    }

    /// Brings the in-memory state up to date with the file: with the records other processes
    /// appended past `known_len` (cutting a torn tail they left behind) or, when one of them
    /// forgot records and so gave the vault a new id, with the whole file. The file lock must
    /// be held.
    fn merge_appended(&self, known_len: &mut u64) -> Result<()> {
        let len = self.file.metadata()?.len();
        // After a forget the file can be shorter or longer than this process expects, or the
        // same length: the id is what tells.
        let id = *self.id.read()?;
        if len >= self.header_len && self.file_id()? != id {
            return self.reload(known_len, len);
        }
        if len == *known_len {
            return Ok(());
        }
        let first_index = self.state.read()?.count();
        if len < *known_len {
            // Records this process already read are gone.
            return Err(Error::VaultCorrupt {
                record: first_index,
            });
        }
        let body = file::read_range(&self.file, *known_len, len)?;
        let cipher = &self.keys.records;
        let framed = file::frame(cipher, &id, &body, first_index)?;
        let good_end = *known_len + framed.good_len as u64;
        if framed.good_len < body.len() {
            self.file.set_len(good_end)?;
        }
        let entries = file::decrypt(cipher, &id, &body, &framed.frames, first_index, false)?;
        self.state.write()?.insert_all(entries);
        *known_len = good_end;
        Ok(())
    }

    /// The vault id the file's header carries now. The file lock must be held.
    fn file_id(&self) -> Result<Id> {
        let mut id = [0u8; VAULT_ID_LEN];
        file::read_exact_at(&self.file, &mut id, self.header_len - VAULT_ID_LEN as u64)?;
        Ok(id)
    }

    /// Replaces everything this process knows with the file's contents, which a forget rewrote
    /// under a new id: another process's, or one that stopped after its point of no return and
    /// was finished by [`Vault::lock_current`]. The file lock must be held.
    fn reload(&self, known_len: &mut u64, len: u64) -> Result<()> {
        let header = file::read_header(&self.file, len)?;
        // A forget keeps the key. Another one means another vault, and its records would not
        // open with ours.
        if header.wrapped_key != self.wrapped {
            return Err(file::invalid(
                "the vault file was replaced by another vault",
            ));
        }
        let body = file::read_range(&self.file, header.len, len)?;
        let cipher = &self.keys.records;
        let framed = file::frame(cipher, &header.vault_id, &body, 0)?;
        let good_end = header.len + framed.good_len as u64;
        if framed.good_len < body.len() {
            self.file.set_len(good_end)?;
        }
        let entries = file::decrypt(cipher, &header.vault_id, &body, &framed.frames, 0, false)?;
        self.replace_state(entries)?;
        *self.id.write()? = header.vault_id;
        *known_len = good_end;
        Ok(())
    }

    /// Swaps the records in memory for `entries`, which are all the file holds now.
    fn replace_state(&self, entries: Vec<Entry>) -> Result<()> {
        let mut fresh = State::default();
        fresh.insert_all(entries);
        let mut state = self.state.write()?;
        fresh.generation = state.generation + 1;
        *state = fresh;
        Ok(())
    }

    /// Encrypts `entries`, appends them at `known_len`, syncs, and adds them
    /// to the in-memory state. The file lock must be held and `known_len`
    /// must be the file's length.
    fn append(&self, known_len: &mut u64, entries: Vec<Entry>) -> Result<()> {
        let first_index = self.state.read()?.count();
        let id = *self.id.read()?;
        let bytes = file::seal(&self.keys.records, &id, first_index, &entries)?;
        let written =
            file::write_all_at(&self.file, &bytes, *known_len).and_then(|()| self.file.sync_data());
        if let Err(e) = written {
            // Best effort: a partial append left behind would be cut by the
            // next merge anyway.
            let _ = self.file.set_len(*known_len);
            return Err(e.into());
        }
        *known_len += bytes.len() as u64;
        self.state.write()?.insert_all(entries);
        Ok(())
    }
}

/// What the header of a vault file holds.
struct Head {
    id: Id,
    /// The header's size in bytes: the records start there.
    len: u64,
    /// The DPAPI-wrapped master key.
    wrapped: Vec<u8>,
    keys: VaultKeys,
}

/// Creates the header of an empty vault file.
fn create_header(file: &File) -> Result<Head> {
    let master = keys::generate_master()?;
    let wrapped = keys::wrap(&master)?;
    let mut id = [0u8; VAULT_ID_LEN];
    sys::fill_random(&mut id)?;
    let header = file::encode_header(&wrapped, &id)?;
    file::write_all_at(file, &header, 0)
        .and_then(|()| file.sync_data())
        .inspect_err(|_| {
            // Leave an empty file so the next open starts over.
            let _ = file.set_len(0);
        })?;
    Ok(Head {
        id,
        len: header.len() as u64,
        wrapped,
        keys: VaultKeys::derive(&master),
    })
}

/// Reads the header of an existing vault file of `len` bytes.
fn load_header(file: &File, len: u64) -> Result<Head> {
    let header = file::read_header(file, len)?;
    let master = keys::unwrap(&header.wrapped_key)?;
    Ok(Head {
        id: header.vault_id,
        len: header.len,
        wrapped: header.wrapped_key,
        keys: VaultKeys::derive(&master),
    })
}

/// `<vault>.compact`: what [`Vault::forget`] leaves while it replaces the vault's contents.
const COMPACT_SUFFIX: &str = ".compact";

/// `path` with `suffix` appended to its file name.
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Makes `file` hold exactly `image`. It is cut to the new length first, and that is on disk
/// before the new contents are written, so that a crash never leaves the new contents followed
/// by what is left of the old ones.
fn overwrite(file: &File, image: &[u8]) -> io::Result<()> {
    file.set_len(image.len() as u64)?;
    file.sync_data()?;
    file::write_all_at(file, image, 0)?;
    file.sync_data()
}

/// Finishes a [`Vault::forget`] that stopped, and sweeps what it left: [`Vault::open`] does it
/// first thing, and every write after it when it finds the `.compact` file. The file lock must
/// be held.
///
/// `<vault>.compact` is the complete file the forget was about to put in place, and it only
/// exists once that was decided. The vault file is then in one of these states:
///
/// - the old file, cut short or written over in part: the forget goes through;
/// - the new file, with or without records appended since: nothing to do. That is also what a
///   forget that merely failed to delete `.compact` leaves, and the check is what keeps the
///   leftover from cutting off the records appended afterwards;
/// - shorter than the new file, which none of the above ever is, or with another key: the vault
///   was deleted or swapped for another since, and `.compact` is not for it, so it must not
///   bring back records or write over what is there.
fn finish_compaction(file: &File, path: &Path) -> Result<()> {
    let compact = suffixed(path, COMPACT_SUFFIX);
    // A forget that died while writing `.compact` left only temporary files of it.
    sys::remove_temps(&compact);
    let image = match File::open(&compact) {
        Ok(image) => image,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let image_len = image.metadata()?.len();
    let header = file::read_header(&image, image_len).map_err(|e| match e {
        Error::Io(e) => sys::io_context(&e, "use", &compact),
        other => other,
    })?;
    let bytes = file::read_range(&image, 0, image_len)?;
    drop(image);
    if is_unfinished(file, &bytes, header.len)? {
        overwrite(file, &bytes)?;
    } else {
        // The image may be in the cache only, if the forget was killed or failed before its own
        // sync: the copy must not go before the vault is on disk.
        file.sync_data()?;
    }
    let _ = fs::remove_file(&compact);
    Ok(())
}

/// Whether `file` is the vault that `image` (whose header is `header_len` bytes) was made from,
/// still short of it. A vault keeps its key for good and a forget changes nothing in the
/// header but the id at its end, so a file that is at least as long as `image`, starts like it
/// up to that id and then differs is the old file or a new one written in part.
fn is_unfinished(file: &File, image: &[u8], header_len: u64) -> Result<bool> {
    let len = image.len() as u64;
    if file.metadata()?.len() < len {
        return Ok(false);
    }
    let current = file::read_range(file, 0, len)?;
    let key_len =
        usize::try_from(header_len).map_or(image.len(), |n| n.saturating_sub(VAULT_ID_LEN));
    Ok(current[..key_len] == image[..key_len] && current != image)
}

/// A value waiting for a proxy.
struct Pending {
    kind: EntityKind,
    original: Arc<str>,
    /// The first candidate that is not the original and carries the
    /// watermark, with its attempt number. `None` if there is none.
    first: Option<(String, u32)>,
}

/// The first attempt at or after `from` whose candidate differs from
/// `original` and, for kinds that are found by watermark, carries it. Kinds
/// found by exact vault match need none (and short values would run out of
/// candidates). Depends on the keys only.
fn watermarked(
    keys: &ProxyKeys,
    kind: EntityKind,
    original: &str,
    from: u32,
) -> Option<(String, u32)> {
    (from..MAX_ATTEMPTS).find_map(|attempt| {
        let candidate = generate(keys, kind, original, attempt);
        (candidate != original && (!kind.is_watermarked() || watermark_ok(keys, kind, &candidate)))
            .then_some((candidate, attempt))
    })
}

/// Picks a proxy for every pending value that is still unresolved in
/// `state`: the first watermarked candidate that equals no issued proxy, no
/// known original, no original in this batch and no proxy chosen earlier in
/// it, and that `avoid` does not turn down. Values are taken in their sorted
/// order, so the outcome does not depend on how the caller ordered them.
fn choose(
    keys: &ProxyKeys,
    state: &State,
    pending: Vec<Pending>,
    avoid: &dyn Fn(EntityKind, &str) -> bool,
) -> Result<Vec<Entry>> {
    // Another process may have issued some since they were queued.
    let pending: Vec<Pending> = pending
        .into_iter()
        .filter(|p| !state.by_original[slot(p.kind)].contains_key(&*p.original))
        .collect();
    // Strings no proxy may equal besides what the vault already holds: every
    // original in this batch, then each proxy chosen for it.
    let mut reserved: HashSet<Arc<str>> = HashSet::with_capacity(2 * pending.len());
    reserved.extend(pending.iter().map(|p| Arc::clone(&p.original)));
    let mut entries = Vec::with_capacity(pending.len());
    for p in pending {
        let free = |candidate: &str| {
            !state.by_proxy.contains_key(candidate)
                && !state.originals.contains(candidate)
                && !reserved.contains(candidate)
                && !avoid(p.kind, candidate)
        };
        let proxy = first_free(keys, p.kind, &p.original, p.first, free)?;
        let proxy: Arc<str> = Arc::from(proxy);
        reserved.insert(Arc::clone(&proxy));
        entries.push(Entry {
            kind: p.kind,
            original: p.original,
            proxy,
        });
    }
    Ok(entries)
}

/// Starting from the candidate `found`, the first that satisfies `free`.
fn first_free(
    keys: &ProxyKeys,
    kind: EntityKind,
    original: &str,
    mut found: Option<(String, u32)>,
    free: impl Fn(&str) -> bool,
) -> Result<String> {
    while let Some((candidate, attempt)) = found {
        if free(&candidate) {
            return Ok(candidate);
        }
        found = watermarked(keys, kind, original, attempt + 1);
    }
    Err(Error::ProxyExhausted { kind })
}

impl VaultView<'_> {
    /// Proxy previously issued for `original` of `kind`.
    #[must_use]
    pub fn proxy_for(&self, kind: EntityKind, original: &str) -> Option<&str> {
        self.state.by_original[slot(kind)]
            .get(original)
            .map(|proxy| &**proxy)
    }

    /// Original behind an issued proxy.
    #[must_use]
    pub fn original_for(&self, proxy: &str) -> Option<&str> {
        self.state
            .by_proxy
            .get(proxy)
            .map(|(_, original)| &**original)
    }

    /// Kind of an issued proxy.
    #[must_use]
    pub fn kind_of(&self, proxy: &str) -> Option<EntityKind> {
        self.state.by_proxy.get(proxy).map(|(kind, _)| *kind)
    }

    /// Every issued proxy of `kind`.
    pub fn proxies_of(&self, kind: EntityKind) -> impl Iterator<Item = &str> {
        self.state.by_original[slot(kind)].values().map(|p| &**p)
    }

    /// Every record as `(kind, original, proxy)`, the newest first.
    pub fn newest_first(&self) -> impl Iterator<Item = (EntityKind, &str, &str)> {
        records(&self.state).rev()
    }

    /// The records whose original or proxy contains `query`, as `(kind, original, proxy)`, the
    /// newest first. Case does not matter, and an empty `query` matches every record. With a
    /// `kind`, only records of that kind are looked at.
    pub fn search<'v>(
        &'v self,
        query: &str,
        kind: Option<EntityKind>,
    ) -> impl Iterator<Item = (EntityKind, &'v str, &'v str)> + use<'v> {
        let mut needle = String::new();
        fold_into(query, &mut needle);
        let mut scratch = String::new();
        records(&self.state)
            .rev()
            .filter(move |&(found_kind, original, proxy)| {
                kind.is_none_or(|wanted| wanted == found_kind)
                    && (needle.is_empty()
                        || [original, proxy].into_iter().any(|text| {
                            fold_into(text, &mut scratch);
                            scratch.contains(needle.as_str())
                        }))
            })
    }

    /// Every proxy issued as the `from`-th record or after, with its kind, in the order they
    /// were issued: the vault's growth since it had `from` records, see
    /// [`VaultView::record_count`].
    pub fn issued_since(&self, from: u64) -> impl Iterator<Item = (EntityKind, &str)> {
        let from = usize::try_from(from).unwrap_or(usize::MAX);
        let issued = self.state.records.get(from..).unwrap_or_default();
        issued.iter().map(|record| (record.kind, &*record.proxy))
    }

    /// Records in the vault; changes whenever a proxy is issued.
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.state.count()
    }

    /// Byte length of the longest proxy in the vault, of any kind; 0 when it has none. Kept as
    /// records come and go, so it costs nothing however large the vault is: a text that is cut
    /// further than this from where a proxy starts cannot have cut that proxy in two.
    #[must_use]
    pub fn longest_proxy(&self) -> usize {
        self.state.longest_proxy
    }

    /// How often the vault's records were replaced wholesale (by a [`Vault::forget`], here or in
    /// another process) since it was opened. [`VaultView::record_count`] only says how many
    /// records there are; this says whether the ones an earlier view saw are still the first
    /// ones: they are, as long as it is the same.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.state.generation
    }
}

/// The records of `state` as `(kind, original, proxy)`, in the order they were issued in.
fn records(state: &State) -> impl DoubleEndedIterator<Item = (EntityKind, &str, &str)> {
    state
        .records
        .iter()
        .map(|record| (record.kind, &*record.original, &*record.proxy))
}

/// Lower-cases `text` into `out`, replacing what it held. Per character, so the same text folds
/// the same wherever it stands: `str::to_lowercase` reads a Greek final sigma by its position.
/// The final sigma is folded to the small sigma, as the capital sigma is, so that a word in
/// capitals and the same word in lower case agree. Nearly every record is ASCII, which is folded
/// a byte at a time.
fn fold_into(text: &str, out: &mut String) {
    const FINAL_SIGMA: char = '\u{3C2}';
    const SIGMA: char = '\u{3C3}';
    out.clear();
    if text.is_ascii() {
        out.push_str(text);
        out.make_ascii_lowercase();
    } else {
        out.extend(
            text.chars()
                .flat_map(char::to_lowercase)
                .map(|c| if c == FINAL_SIGMA { SIGMA } else { c }),
        );
    }
}

/// One record as [`export`] writes it in JSON.
#[derive(Serialize)]
struct Exported<'a> {
    kind: &'a str,
    original: &'a str,
    proxy: &'a str,
}

/// Writes every record of `view`, in the order they were issued in, as `format` and returns how
/// many there were. JSON is an array of `{"kind","original","proxy"}` objects with the kind as
/// its name (`email`), CSV has the header `kind,original,proxy`.
///
/// The originals are in the output in the clear: where it goes is the caller's to protect. To
/// keep from overwriting a file, open it with `OpenOptions::create_new`.
///
/// # Errors
/// `Io`.
pub fn export(view: &VaultView<'_>, format: ExportFormat, out: &mut dyn Write) -> Result<usize> {
    let mut out = BufWriter::new(out);
    let mut count = 0;
    match format {
        ExportFormat::Json => {
            out.write_all(b"[")?;
            for (kind, original, proxy) in records(&view.state) {
                out.write_all(if count == 0 { b"\n" } else { b",\n" })?;
                let record = Exported {
                    kind: kind.as_str(),
                    original,
                    proxy,
                };
                serde_json::to_writer(&mut out, &record).map_err(io::Error::from)?;
                count += 1;
            }
            out.write_all(b"\n]\n")?;
        }
        ExportFormat::Csv => {
            csv_row(&mut out, &["kind", "original", "proxy"])?;
            for (kind, original, proxy) in records(&view.state) {
                csv_row(&mut out, &[kind.as_str(), original, proxy])?;
                count += 1;
            }
        }
    }
    out.flush()?;
    Ok(count)
}

/// One CSV record: the fields, quoted where RFC 4180 asks for it (when they hold a comma, a
/// quote or a line break; a quote inside is doubled), separated by commas and ended by CRLF.
pub(crate) fn csv_row(out: &mut dyn Write, fields: &[&str]) -> io::Result<()> {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.write_all(b",")?;
        }
        if field.contains([',', '"', '\r', '\n']) {
            out.write_all(b"\"")?;
            out.write_all(field.replace('"', "\"\"").as_bytes())?;
            out.write_all(b"\"")?;
        } else {
            out.write_all(field.as_bytes())?;
        }
    }
    out.write_all(b"\r\n")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A scratch directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> std::io::Result<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("piikey-test-{}-vault-{n}", std::process::id()));
            std::fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }

        fn vault_path(&self) -> PathBuf {
            self.0.join("vault.pkv")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    type Row = (EntityKind, String, String);

    /// Nothing for a proxy to stay away from.
    const FREE: &dyn Fn(EntityKind, &str) -> bool = &|_, _| false;

    /// Appends records with the given proxies, bypassing proxy generation.
    fn append(vault: &Vault, rows: &[(EntityKind, &str, &str)]) -> Result<()> {
        vault.locked_append(|_| {
            Ok(rows
                .iter()
                .map(|&(kind, original, proxy)| Entry {
                    kind,
                    original: original.into(),
                    proxy: proxy.into(),
                })
                .collect())
        })
    }

    /// Every mapping of the vault, sorted.
    fn dump(vault: &Vault) -> Result<Vec<Row>> {
        let view = vault.read()?;
        let mut rows: Vec<Row> = EntityKind::ALL
            .into_iter()
            .flat_map(|kind| {
                view.state.by_original[slot(kind)]
                    .iter()
                    .map(move |(o, p)| (kind, o.to_string(), p.to_string()))
            })
            .collect();
        rows.sort();
        Ok(rows)
    }

    fn proxy_of(vault: &Vault, kind: EntityKind, original: &str) -> Result<Option<String>> {
        Ok(vault.read()?.proxy_for(kind, original).map(str::to_owned))
    }

    /// One value of every kind.
    fn corpus() -> Vec<(EntityKind, Box<str>)> {
        use EntityKind::{
            CreditCard, Email, Iban, Ipv4, Ipv6, Mac, NlBsn, Phone, Secret, UrlCredential, UsSsn,
        };
        [
            (Email, "jan.jansen@example.org"),
            (Iban, "NL91ABNA0417164300"),
            (CreditCard, "4111 1111 1111 1111"),
            (Phone, "+31 6 12345678"),
            (Ipv4, "203.0.113.7"),
            (Ipv6, "2001:db8::1"),
            (Mac, "00:1a:2b:3c:4d:5e"),
            (UsSsn, "123-45-6789"),
            (NlBsn, "111222333"),
            (Secret, "AKIAIOSFODNN7EXAMPLE"),
            (UrlCredential, "admin:hunter2"),
        ]
        .into_iter()
        .map(|(kind, original)| (kind, original.into()))
        .collect()
    }

    /// Byte offset of every record in a vault file, found with the
    /// documented layout rather than the code under test.
    fn record_starts(bytes: &[u8]) -> Vec<usize> {
        let dpapi_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut at = 8 + usize::try_from(dpapi_len).unwrap_or(usize::MAX) + 16;
        let mut starts = Vec::new();
        while at < bytes.len() {
            starts.push(at);
            let len = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            at += 4 + 24 + usize::try_from(len).unwrap_or(usize::MAX);
        }
        assert_eq!(at, bytes.len(), "records do not end at the end of the file");
        starts
    }

    /// Byte offset where record `index`'s ciphertext starts.
    fn ciphertext_start(bytes: &[u8], index: usize) -> usize {
        record_starts(bytes)[index] + 4 + 24
    }

    fn flip(path: &Path, offset: usize) -> Result<()> {
        let mut bytes = std::fs::read(path)?;
        bytes[offset] ^= 0x01;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn three(vault: &Vault) -> Result<()> {
        append(
            vault,
            &[
                (EntityKind::Email, "a@example.org", "x1@example.net"),
                (EntityKind::Email, "b@example.org", "x2@example.net"),
                (EntityKind::Email, "c@example.org", "x3@example.net"),
            ],
        )
    }

    #[test]
    fn vault_is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<Vault>();
    }

    #[test]
    fn kind_slots_are_distinct_and_in_range() {
        let mut seen = HashSet::new();
        for kind in EntityKind::ALL {
            assert!(slot(kind) < KINDS);
            assert!(seen.insert(slot(kind)), "{kind:?} shares a slot");
        }
    }

    /// The vault's place is part of the on-disk contract: another name would start an empty
    /// vault beside the one the user already has.
    #[test]
    fn default_path_is_under_localappdata() -> Result<()> {
        match default_path() {
            Ok(path) => {
                assert!(path.ends_with(r"piikey\vault.pkv"), "{path:?}");
                assert!(path.parent().is_some_and(Path::is_dir));
            }
            Err(Error::VaultPathUnavailable) => {
                assert!(std::env::var_os("LOCALAPPDATA").is_none_or(|v| v.is_empty()));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    #[test]
    fn a_new_vault_gets_a_header_and_reopens_empty() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        drop(vault);
        let bytes = std::fs::read(dir.vault_path())?;
        assert_eq!(&bytes[..4], b"PKV1");
        assert!(record_starts(&bytes).is_empty());
        let vault = Vault::open(&dir.vault_path())?;
        assert!(dump(&vault)?.is_empty());
        assert_eq!(
            vault.read()?.proxy_for(EntityKind::Email, "x@example.org"),
            None
        );
        Ok(())
    }

    #[test]
    fn mappings_survive_reopen() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        three(&vault)?;
        let before = dump(&vault)?;
        assert_eq!(before.len(), 3);
        drop(vault);

        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?, before);
        let view = vault.read()?;
        assert_eq!(
            view.proxy_for(EntityKind::Email, "b@example.org"),
            Some("x2@example.net")
        );
        assert_eq!(view.original_for("x3@example.net"), Some("c@example.org"));
        assert_eq!(view.original_for("c@example.org"), None);
        Ok(())
    }

    #[test]
    fn records_come_newest_first_and_keep_their_order_across_reopen() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        three(&vault)?;
        append(
            &vault,
            &[(EntityKind::Phone, "+31612345678", "+31687654321")],
        )?;
        let newest = |vault: &Vault| -> Result<Vec<String>> {
            Ok(vault
                .read()?
                .newest_first()
                .map(|(_, original, _)| original.to_owned())
                .collect())
        };
        let expected = [
            "+31612345678",
            "c@example.org",
            "b@example.org",
            "a@example.org",
        ];
        assert_eq!(newest(&vault)?, expected);
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(newest(&vault)?, expected);
        let view = vault.read()?;
        assert_eq!(view.proxies_of(EntityKind::Email).count(), 3);
        assert_eq!(view.proxies_of(EntityKind::Phone).count(), 1);
        assert_eq!(view.proxies_of(EntityKind::Iban).count(), 0);
        Ok(())
    }

    #[test]
    fn lookups_are_exact_and_per_kind() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[
                (EntityKind::NlBsn, "111222333", "100000008"),
                (EntityKind::UsSsn, "111222333", "100000009"),
            ],
        )?;
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        let view = vault.read()?;
        assert_eq!(
            view.proxy_for(EntityKind::NlBsn, "111222333"),
            Some("100000008")
        );
        assert_eq!(
            view.proxy_for(EntityKind::UsSsn, "111222333"),
            Some("100000009")
        );
        assert_eq!(view.proxy_for(EntityKind::Phone, "111222333"), None);
        assert_eq!(view.original_for("100000008"), Some("111222333"));
        assert_eq!(view.original_for("100000009"), Some("111222333"));
        assert_eq!(view.original_for("111222333"), None);
        Ok(())
    }

    #[test]
    fn the_file_holds_no_plaintext() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[(
                EntityKind::Email,
                "jan.jansen@example.org",
                "piet.bakker@orchardgate.org",
            )],
        )?;
        drop(vault);
        let bytes = std::fs::read(dir.vault_path())?;
        let has = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(!has("jan.jansen"));
        assert!(!has("example.org"));
        assert!(!has("piet.bakker"));
        assert!(!has("orchardgate"));
        Ok(())
    }

    #[test]
    fn flipping_a_middle_record_is_corruption() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        let bytes = std::fs::read(dir.vault_path())?;
        flip(&dir.vault_path(), ciphertext_start(&bytes, 1) + 5)?;
        assert!(matches!(
            Vault::open(&dir.vault_path()),
            Err(Error::VaultCorrupt { record: 1 })
        ));
        // The file is left alone: nothing was truncated.
        assert_eq!(std::fs::read(dir.vault_path())?.len(), bytes.len());
        Ok(())
    }

    #[test]
    fn garbage_tail_is_truncated_on_open() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        let good = std::fs::read(dir.vault_path())?;
        let mut dirty = good.clone();
        dirty.extend_from_slice(&[0xA5, 0x5A, 0xFF, 0x00, 0x13, 0x37, 0xC0, 0xDE, 0x01, 0x80]);
        std::fs::write(dir.vault_path(), dirty)?;

        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 3);
        drop(vault);
        assert_eq!(std::fs::read(dir.vault_path())?, good);
        Ok(())
    }

    #[test]
    fn a_cut_record_is_truncated_on_open_and_the_vault_keeps_working() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        let bytes = std::fs::read(dir.vault_path())?;
        let starts = record_starts(&bytes);
        std::fs::write(dir.vault_path(), &bytes[..bytes.len() - 7])?;

        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 2);
        assert_eq!(std::fs::metadata(dir.vault_path())?.len(), starts[2] as u64);
        // The next record takes the place (and index) of the cut one.
        append(
            &vault,
            &[(EntityKind::Email, "d@example.org", "x4@example.net")],
        )?;
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 3);
        assert_eq!(
            proxy_of(&vault, EntityKind::Email, "d@example.org")?.as_deref(),
            Some("x4@example.net")
        );
        Ok(())
    }

    #[test]
    fn a_failing_last_record_is_dropped_on_open() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        let bytes = std::fs::read(dir.vault_path())?;
        let starts = record_starts(&bytes);
        flip(&dir.vault_path(), ciphertext_start(&bytes, 2) + 5)?;

        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 2);
        assert_eq!(proxy_of(&vault, EntityKind::Email, "c@example.org")?, None);
        drop(vault);
        assert_eq!(std::fs::metadata(dir.vault_path())?.len(), starts[2] as u64);
        Ok(())
    }

    #[test]
    fn a_zero_filled_tail_is_truncated_on_open() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        let good = std::fs::read(dir.vault_path())?;
        let mut dirty = good.clone();
        dirty.resize(good.len() + 8192, 0);
        std::fs::write(dir.vault_path(), dirty)?;
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 3);
        drop(vault);
        assert_eq!(std::fs::read(dir.vault_path())?, good);
        Ok(())
    }

    #[test]
    fn damaged_headers_are_rejected_and_left_alone() -> Result<()> {
        let dir = TempDir::new()?;
        drop(Vault::open(&dir.vault_path())?);
        let good = std::fs::read(dir.vault_path())?;

        // Not a vault at all.
        std::fs::write(dir.vault_path(), b"this is not a vault file")?;
        assert!(matches!(Vault::open(&dir.vault_path()), Err(Error::Io(_))));
        assert_eq!(
            std::fs::read(dir.vault_path())?,
            b"this is not a vault file"
        );

        // Cut inside the header.
        std::fs::write(dir.vault_path(), &good[..good.len() - 3])?;
        assert!(matches!(Vault::open(&dir.vault_path()), Err(Error::Io(_))));
        assert_eq!(std::fs::read(dir.vault_path())?.len(), good.len() - 3);

        // A flipped byte in the DPAPI blob: DPAPI refuses to unwrap it.
        std::fs::write(dir.vault_path(), &good)?;
        flip(&dir.vault_path(), 8 + 60)?;
        assert!(matches!(
            Vault::open(&dir.vault_path()),
            Err(Error::Dpapi(_))
        ));
        Ok(())
    }

    #[test]
    fn a_vault_file_that_shrinks_under_an_open_vault_is_corruption() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        three(&vault)?;
        let bytes = std::fs::read(dir.vault_path())?;
        let starts = record_starts(&bytes);
        OpenOptions::new()
            .write(true)
            .open(dir.vault_path())?
            .set_len(starts[1] as u64)?;
        let result = append(
            &vault,
            &[(EntityKind::Email, "d@example.org", "x4@example.net")],
        );
        assert!(matches!(result, Err(Error::VaultCorrupt { .. })));
        Ok(())
    }

    #[test]
    fn a_second_instance_merges_what_the_first_appended() -> Result<()> {
        let dir = TempDir::new()?;
        let a = Vault::open(&dir.vault_path())?;
        let b = Vault::open(&dir.vault_path())?;
        append(
            &a,
            &[(EntityKind::Email, "a@example.org", "pa@example.net")],
        )?;
        // `b` has not seen `a`'s record; it must merge it before appending, or
        // its record would carry the wrong index.
        append(
            &b,
            &[(EntityKind::Email, "b@example.org", "pb@example.net")],
        )?;
        assert_eq!(dump(&b)?.len(), 2);
        append(
            &a,
            &[(EntityKind::Email, "c@example.org", "pc@example.net")],
        )?;
        assert_eq!(dump(&a)?.len(), 3, "a merges b's record when it appends");
        drop((a, b));

        let vault = Vault::open(&dir.vault_path())?;
        let rows = dump(&vault)?;
        let originals: Vec<&str> = rows.iter().map(|(_, o, _)| o.as_str()).collect();
        assert_eq!(
            originals,
            ["a@example.org", "b@example.org", "c@example.org"]
        );
        Ok(())
    }

    #[test]
    fn a_torn_tail_left_by_another_process_is_cut_when_merging() -> Result<()> {
        use std::io::Write;

        let dir = TempDir::new()?;
        let a = Vault::open(&dir.vault_path())?;
        let b = Vault::open(&dir.vault_path())?;
        append(
            &a,
            &[(EntityKind::Email, "a@example.org", "pa@example.net")],
        )?;
        // A process that crashed mid-append leaves junk after the last record.
        OpenOptions::new()
            .append(true)
            .open(dir.vault_path())?
            .write_all(&[0xAB; 10])?;
        append(
            &b,
            &[(EntityKind::Email, "b@example.org", "pb@example.net")],
        )?;
        append(
            &a,
            &[(EntityKind::Email, "c@example.org", "pc@example.net")],
        )?;
        drop((a, b));

        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 3);
        let bytes = std::fs::read(dir.vault_path())?;
        assert_eq!(
            record_starts(&bytes).len(),
            3,
            "no junk left between records"
        );
        Ok(())
    }

    /// Appends fixed, unique rows for writer `t`: no proxy generation involved.
    fn append_fixed(vault: &Vault, t: usize, rounds: usize, per_round: usize) -> Result<()> {
        for round in 0..rounds {
            let rows: Vec<(String, String)> = (0..per_round)
                .map(|i| {
                    (
                        format!("t{t}.r{round}.i{i}@example.org"),
                        format!("p{t}.r{round}.i{i}@example.net"),
                    )
                })
                .collect();
            let rows: Vec<(EntityKind, &str, &str)> = rows
                .iter()
                .map(|(o, p)| (EntityKind::Email, o.as_str(), p.as_str()))
                .collect();
            append(vault, &rows)?;
        }
        Ok(())
    }

    fn join_all(handles: Vec<std::thread::ScopedJoinHandle<'_, Result<()>>>) -> Result<()> {
        let results: Vec<Result<()>> = handles
            .into_iter()
            .map(|h| h.join().unwrap_or(Err(Error::Poisoned)))
            .collect();
        results.into_iter().collect()
    }

    #[test]
    fn racing_instances_create_one_vault_and_append_without_losing_records() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.vault_path();
        // The file does not exist yet: the first opens race to create it.
        std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|t| {
                    let path = &path;
                    scope.spawn(move || -> Result<()> {
                        let vault = Vault::open(path)?;
                        append_fixed(&vault, t, 6, 5)
                    })
                })
                .collect();
            join_all(handles)
        })?;
        let vault = Vault::open(&path)?;
        assert_eq!(dump(&vault)?.len(), 8 * 6 * 5);
        Ok(())
    }

    #[test]
    fn one_instance_shared_by_threads_appends_without_losing_records() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        std::thread::scope(|scope| {
            let vault = &vault;
            let handles = (0..8)
                .map(|t| scope.spawn(move || append_fixed(vault, t, 6, 5)))
                .collect();
            join_all(handles)
        })?;
        assert_eq!(dump(&vault)?.len(), 8 * 6 * 5);
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 8 * 6 * 5);
        Ok(())
    }

    #[test]
    fn resolve_issues_distinct_watermarked_proxies_that_differ_from_originals() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        vault.resolve(corpus(), FREE)?;
        let view = vault.read()?;
        let mut seen = HashSet::new();
        for (kind, original) in corpus() {
            let proxy = view
                .proxy_for(kind, &original)
                .ok_or(Error::ProxyExhausted { kind })?;
            assert_ne!(proxy, &*original, "{kind:?}");
            assert!(watermark_ok(vault.proxy_keys(), kind, proxy), "{kind:?}");
            assert_eq!(view.original_for(proxy), Some(&*original), "{kind:?}");
            assert!(seen.insert(proxy.to_owned()), "duplicate proxy {proxy}");
        }
        Ok(())
    }

    #[test]
    fn listed_model_kinds_get_proxies_without_a_watermark() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        let values: Vec<(EntityKind, Box<str>)> = [
            (
                EntityKind::PostalAddress,
                "Keizersgracht 123, 1015 CJ Amsterdam",
            ),
            (EntityKind::HealthData, "diabetes"),
            (EntityKind::OrganizationName, "Acme B.V."),
            (EntityKind::PersonRole, "CEO"),
        ]
        .into_iter()
        .map(|(kind, original)| (kind, original.into()))
        .collect();
        vault.resolve(values.clone(), FREE)?;
        let view = vault.read()?;
        for (kind, original) in values {
            let proxy = view
                .proxy_for(kind, &original)
                .ok_or(Error::ProxyExhausted { kind })?;
            assert_ne!(proxy, &*original, "{kind:?}");
            assert!(
                crate::detect::validate::accepts(kind, proxy),
                "{kind:?}: {proxy}"
            );
            assert_eq!(view.original_for(proxy), Some(&*original), "{kind:?}");
        }
        Ok(())
    }

    #[test]
    fn the_same_original_gets_the_same_proxy_across_reopen() -> Result<()> {
        let dir = TempDir::new()?;
        let first = {
            let vault = Vault::open(&dir.vault_path())?;
            vault.resolve(corpus(), FREE)?;
            dump(&vault)?
        };
        assert_eq!(first.len(), corpus().len());
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?, first);
        let len = std::fs::metadata(dir.vault_path())?.len();
        vault.resolve(corpus(), FREE)?;
        assert_eq!(dump(&vault)?, first, "resolving again changed a proxy");
        assert_eq!(
            std::fs::metadata(dir.vault_path())?.len(),
            len,
            "resolving again wrote"
        );
        Ok(())
    }

    #[test]
    fn issued_proxies_round_trip_through_reopen() -> Result<()> {
        let dir = TempDir::new()?;
        let proxies: Vec<(EntityKind, Box<str>, String)> = {
            let vault = Vault::open(&dir.vault_path())?;
            vault.resolve(corpus(), FREE)?;
            let view = vault.read()?;
            corpus()
                .into_iter()
                .filter_map(|(kind, original)| {
                    let proxy = view.proxy_for(kind, &original)?.to_owned();
                    Some((kind, original, proxy))
                })
                .collect()
        };
        assert_eq!(proxies.len(), corpus().len());
        let vault = Vault::open(&dir.vault_path())?;
        let view = vault.read()?;
        for (kind, original, proxy) in &proxies {
            assert_eq!(view.proxy_for(*kind, original), Some(proxy.as_str()));
            assert_eq!(view.original_for(proxy), Some(&**original));
        }
        Ok(())
    }

    #[test]
    fn duplicate_requests_are_issued_once() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        let mut batch = corpus();
        batch.extend(corpus());
        batch.push((EntityKind::Email, "jan.jansen@example.org".into()));
        vault.resolve(batch, FREE)?;
        assert_eq!(dump(&vault)?.len(), corpus().len());
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), corpus().len());
        Ok(())
    }

    #[test]
    fn the_same_text_under_two_kinds_gets_two_proxies() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        vault.resolve(
            vec![
                (EntityKind::NlBsn, "111222333".into()),
                (EntityKind::UsSsn, "111222333".into()),
            ],
            FREE,
        )?;
        let bsn = proxy_of(&vault, EntityKind::NlBsn, "111222333")?;
        let ssn = proxy_of(&vault, EntityKind::UsSsn, "111222333")?;
        assert!(bsn.is_some() && ssn.is_some());
        assert_ne!(bsn, ssn);
        Ok(())
    }

    #[test]
    fn two_instances_resolving_overlapping_originals_agree_after_reopen() -> Result<()> {
        let dir = TempDir::new()?;
        let a = Vault::open(&dir.vault_path())?;
        let b = Vault::open(&dir.vault_path())?;
        let all = corpus();
        a.resolve(all[..7].to_vec(), FREE)?;
        b.resolve(all[4..].to_vec(), FREE)?;
        // `a` learns what `b` added the next time it writes, or reopens.
        a.resolve(all.clone(), FREE)?;
        b.resolve(all.clone(), FREE)?;
        assert_eq!(dump(&a)?, dump(&b)?);
        assert_eq!(dump(&a)?.len(), all.len());
        let live = dump(&a)?;
        drop((a, b));
        let reopened = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&reopened)?, live);
        Ok(())
    }

    /// Distinct, realistic-looking values for stress tests.
    fn emails(prefix: &str, n: usize) -> Vec<(EntityKind, Box<str>)> {
        (0..n)
            .map(|i| {
                (
                    EntityKind::Email,
                    format!("{prefix}.user{i}@example.org").into(),
                )
            })
            .collect()
    }

    fn assert_consistent(vault: &Vault, expected: usize) -> Result<()> {
        let rows = dump(vault)?;
        assert_eq!(rows.len(), expected);
        let view = vault.read()?;
        let proxies: HashSet<&str> = rows.iter().map(|(_, _, p)| p.as_str()).collect();
        assert_eq!(proxies.len(), expected, "two originals share a proxy");
        for (_, original, proxy) in &rows {
            assert_eq!(view.original_for(proxy), Some(original.as_str()));
        }
        Ok(())
    }

    /// One writer's workload: `rounds` batches of a shared set plus its own values.
    fn resolve_rounds(vault: &Vault, t: usize, rounds: usize) -> Result<()> {
        for round in 0..rounds {
            let mut batch = emails("shared", 20);
            batch.extend(emails(&format!("t{t}r{round}"), 10));
            vault.resolve(batch, FREE)?;
            // Readers run alongside the writers.
            let _ = vault
                .read()?
                .proxy_for(EntityKind::Email, "shared.user0@example.org");
        }
        Ok(())
    }

    #[test]
    fn instances_in_many_threads_end_consistent() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.vault_path();
        std::thread::scope(|scope| {
            let handles = (0..4)
                .map(|t| {
                    let path = &path;
                    scope.spawn(move || -> Result<()> { resolve_rounds(&Vault::open(path)?, t, 5) })
                })
                .collect();
            join_all(handles)
        })?;
        assert_consistent(&Vault::open(&path)?, 20 + 4 * 5 * 10)
    }

    #[test]
    fn one_instance_shared_by_many_threads_ends_consistent() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        std::thread::scope(|scope| {
            let vault = &vault;
            let handles = (0..6)
                .map(|t| scope.spawn(move || resolve_rounds(vault, t, 5)))
                .collect();
            join_all(handles)
        })?;
        assert_consistent(&vault, 20 + 6 * 5 * 10)?;
        drop(vault);
        assert_consistent(&Vault::open(&dir.vault_path())?, 20 + 6 * 5 * 10)
    }

    #[test]
    fn rayon_workers_can_resolve_concurrently() -> Result<()> {
        // The CLI processes files from a rayon `par_iter` and each calls
        // `resolve`, which itself uses rayon. Holding a lock across that
        // inner call would deadlock when a worker steals a sibling file.
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        (0..96).into_par_iter().try_for_each(|i| {
            let mut batch = emails("shared", 30);
            batch.extend(emails(&format!("file{i}"), 30));
            vault.resolve(batch, FREE)
        })?;
        assert_consistent(&vault, 30 + 96 * 30)
    }

    /// The candidates the vault tries for `original`, in order: those that differ from it and
    /// carry the watermark.
    fn watermarked_candidates(vault: &Vault, kind: EntityKind, original: &str) -> Vec<String> {
        let keys = vault.proxy_keys();
        (0..MAX_ATTEMPTS)
            .map(|attempt| generate(keys, kind, original, attempt))
            .filter(|c| c != original && watermark_ok(keys, kind, c))
            .collect()
    }

    #[test]
    fn resolve_skips_the_candidates_the_caller_avoids() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        let email = "jan.jansen@example.org";
        let phone = "+31 6 12345678";
        let emails = watermarked_candidates(&vault, EntityKind::Email, email);
        let phones = watermarked_candidates(&vault, EntityKind::Phone, phone);
        assert!(emails.len() > 2 && !phones.is_empty());
        // The first two email candidates are turned down. The phone number is not affected:
        // `avoid` is asked with the kind.
        let avoid = |kind: EntityKind, candidate: &str| {
            kind == EntityKind::Email && (candidate == emails[0] || candidate == emails[1])
        };
        vault.resolve(
            vec![
                (EntityKind::Email, email.into()),
                (EntityKind::Phone, phone.into()),
            ],
            &avoid,
        )?;
        assert_eq!(
            proxy_of(&vault, EntityKind::Email, email)?.as_deref(),
            Some(emails[2].as_str())
        );
        assert_eq!(
            proxy_of(&vault, EntityKind::Phone, phone)?.as_deref(),
            Some(phones[0].as_str())
        );
        Ok(())
    }

    #[test]
    fn resolve_gives_up_when_every_candidate_is_avoided() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        let refused = vault.resolve(
            vec![(EntityKind::Email, "jan.jansen@example.org".into())],
            &|_, _| true,
        );
        assert!(
            matches!(
                refused,
                Err(Error::ProxyExhausted {
                    kind: EntityKind::Email
                })
            ),
            "{refused:?}"
        );
        // Nothing was written, and a later call without the constraint succeeds.
        assert_eq!(vault.read()?.record_count(), 0);
        vault.resolve(
            vec![(EntityKind::Email, "jan.jansen@example.org".into())],
            FREE,
        )?;
        assert_eq!(vault.read()?.record_count(), 1);
        Ok(())
    }

    #[test]
    fn issued_since_lists_the_records_added_after_a_count_in_issue_order() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[
                (EntityKind::Email, "a@example.org", "x1@example.net"),
                (EntityKind::Person, "Jan", "Haley"),
            ],
        )?;
        append(
            &vault,
            &[(EntityKind::HealthData, "diabetes", "Health-7KQX")],
        )?;
        let view = vault.read()?;
        assert_eq!(view.record_count(), 3);
        let since = |n: u64| -> Vec<(EntityKind, String)> {
            view.issued_since(n)
                .map(|(kind, proxy)| (kind, proxy.to_owned()))
                .collect()
        };
        assert_eq!(
            since(0),
            [
                (EntityKind::Email, "x1@example.net".to_owned()),
                (EntityKind::Person, "Haley".to_owned()),
                (EntityKind::HealthData, "Health-7KQX".to_owned()),
            ]
        );
        assert_eq!(
            since(2),
            [(EntityKind::HealthData, "Health-7KQX".to_owned())]
        );
        assert!(since(3).is_empty());
        assert!(since(u64::MAX).is_empty());
        Ok(())
    }

    #[test]
    fn the_longest_proxy_follows_the_records() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        let longest = |vault: &Vault| -> Result<usize> { Ok(vault.read()?.longest_proxy()) };
        // What it has to be, found the slow way.
        let by_hand = |vault: &Vault| -> Result<usize> {
            Ok(vault
                .read()?
                .newest_first()
                .map(|(_, _, proxy)| proxy.len())
                .max()
                .unwrap_or(0))
        };
        let email = "a.much.longer.proxy@example.net";
        let name = "A Name That Is Longer Than The Email Proxy";
        assert_eq!(longest(&vault)?, 0);

        append(
            &vault,
            &[
                (EntityKind::Email, "a@example.org", "x1@example.net"),
                (EntityKind::Email, "b@example.org", email),
            ],
        )?;
        assert_eq!(longest(&vault)?, email.len());

        // A record another instance appended is found when this one writes next.
        let other = Vault::open(&dir.vault_path())?;
        append(&other, &[(EntityKind::Person, "Jan", name)])?;
        append(
            &vault,
            &[(EntityKind::Email, "c@example.org", "x3@example.net")],
        )?;
        assert_eq!(longest(&vault)?, name.len());
        assert_eq!(longest(&vault)?, by_hand(&vault)?);

        // Forgetting the longest brings it down, and an instance that opens later knows it.
        assert_eq!(vault.forget(&|_, original, _| original == "Jan")?, 1);
        assert_eq!(longest(&vault)?, email.len());
        drop((vault, other));
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(longest(&vault)?, email.len());
        assert_eq!(longest(&vault)?, by_hand(&vault)?);
        assert_eq!(vault.wipe()?, 3);
        assert_eq!(longest(&vault)?, 0);
        Ok(())
    }

    /// The vault id in the header of a vault file, found with the documented layout rather
    /// than the code under test.
    fn id_of(bytes: &[u8]) -> Vec<u8> {
        let dpapi_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let at = 8 + usize::try_from(dpapi_len).unwrap_or(usize::MAX);
        bytes[at..at + 16].to_vec()
    }

    fn contains_bytes(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    fn compact_of(dir: &TempDir) -> PathBuf {
        suffixed(&dir.vault_path(), COMPACT_SUFFIX)
    }

    /// The originals of every record, the newest first.
    fn originals_newest_first(vault: &Vault) -> Result<Vec<String>> {
        Ok(vault
            .read()?
            .newest_first()
            .map(|(_, original, _)| original.to_owned())
            .collect())
    }

    /// Everything `export` writes for the vault, and how many records it says it wrote.
    fn exported(vault: &Vault, format: ExportFormat) -> Result<(usize, String)> {
        let mut out = Vec::new();
        let count = export(&vault.read()?, format, &mut out)?;
        let text = String::from_utf8(out)
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        Ok((count, text))
    }

    fn parse_json(text: &str) -> Result<serde_json::Value> {
        serde_json::from_str(text).map_err(|e| Error::Io(io::Error::from(e)))
    }

    #[test]
    fn forget_removes_the_records_and_rewrites_the_file() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[
                (
                    EntityKind::Email,
                    "jan.jansen@example.org",
                    "piet.bakker@orchardgate.org",
                ),
                (EntityKind::Email, "b@example.org", "x2@example.net"),
                (EntityKind::Phone, "+31612345678", "+31687654321"),
            ],
        )?;
        let before = std::fs::read(dir.vault_path())?;
        let starts = record_starts(&before);
        assert_eq!(vault.read()?.generation(), 0);

        let removed = vault.forget(&|_, original, _| original == "jan.jansen@example.org")?;
        assert_eq!(removed, 1);
        {
            let view = vault.read()?;
            assert_eq!(view.record_count(), 2);
            assert_eq!(view.generation(), 1);
            assert_eq!(
                view.proxy_for(EntityKind::Email, "jan.jansen@example.org"),
                None
            );
            assert_eq!(view.original_for("piet.bakker@orchardgate.org"), None);
            assert_eq!(view.proxies_of(EntityKind::Email).count(), 1);
            assert_eq!(
                view.proxy_for(EntityKind::Email, "b@example.org"),
                Some("x2@example.net")
            );
            assert_eq!(view.issued_since(0).count(), 2);
        }

        // On disk: a well-formed file of two records under a new id, in which nothing of the
        // old file is left: every record that stays was sealed again.
        let after = std::fs::read(dir.vault_path())?;
        assert_eq!(record_starts(&after).len(), 2);
        assert_ne!(id_of(&after), id_of(&before), "the vault got a new id");
        assert!(after.len() < before.len());
        for needle in ["jan.jansen", "example.org", "piet.bakker", "orchardgate"] {
            assert!(!contains_bytes(&after, needle.as_bytes()), "{needle}");
        }
        let mut ends = starts[1..].to_vec();
        ends.push(before.len());
        for (&start, &end) in starts.iter().zip(&ends) {
            assert!(!contains_bytes(&after, &before[start..end]));
        }
        let files: Vec<_> = std::fs::read_dir(&dir.0)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<_>>()?;
        assert_eq!(
            files,
            ["vault.pkv"],
            "no .compact or temporary file is left"
        );

        // The vault goes on under its new id.
        append(
            &vault,
            &[(EntityKind::Email, "c@example.org", "x3@example.net")],
        )?;
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(
            vault.read()?.generation(),
            0,
            "a generation counts from open"
        );
        assert_eq!(
            originals_newest_first(&vault)?,
            ["c@example.org", "+31612345678", "b@example.org"]
        );
        let (count, json) = exported(&vault, ExportFormat::Json)?;
        assert_eq!(count, 3);
        assert!(!json.contains("jan.jansen"), "{json}");
        assert!(json.contains("b@example.org"), "{json}");
        Ok(())
    }

    #[test]
    fn forgetting_nothing_writes_nothing() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        three(&vault)?;
        let before = std::fs::read(dir.vault_path())?;
        assert_eq!(vault.forget(&|_, _, _| false)?, 0);
        assert_eq!(
            vault.forget(&|_, original, _| original == "nobody@example.org")?,
            0
        );
        assert_eq!(std::fs::read(dir.vault_path())?, before);
        assert_eq!(vault.read()?.generation(), 0);
        assert!(!compact_of(&dir).exists());
        Ok(())
    }

    #[test]
    fn forget_offers_the_kind_the_original_and_the_proxy() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        three(&vault)?;
        append(
            &vault,
            &[(EntityKind::Phone, "+31612345678", "+31687654321")],
        )?;
        assert_eq!(vault.forget(&|kind, _, _| kind == EntityKind::Phone)?, 1);
        assert_eq!(
            vault.forget(&|_, _, proxy| proxy == "x2@example.net")?,
            1,
            "by proxy"
        );
        assert_eq!(
            originals_newest_first(&vault)?,
            ["c@example.org", "a@example.org"]
        );
        Ok(())
    }

    #[test]
    fn forgetting_one_kind_keeps_the_same_text_of_another() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[
                (EntityKind::NlBsn, "111222333", "100000008"),
                (EntityKind::UsSsn, "111222333", "100000009"),
            ],
        )?;
        assert_eq!(vault.forget(&|kind, _, _| kind == EntityKind::NlBsn)?, 1);
        let view = vault.read()?;
        assert_eq!(view.proxy_for(EntityKind::NlBsn, "111222333"), None);
        assert_eq!(
            view.proxy_for(EntityKind::UsSsn, "111222333"),
            Some("100000009")
        );
        assert_eq!(view.original_for("100000008"), None);
        assert_eq!(view.original_for("100000009"), Some("111222333"));
        // What the kept record holds still keeps a new proxy from being equal to it.
        assert!(view.state.originals.contains("111222333"));
        Ok(())
    }

    #[test]
    fn wipe_empties_the_vault_and_keeps_its_key() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(vault.wipe()?, 0, "nothing to wipe");
        three(&vault)?;
        let before = std::fs::read(dir.vault_path())?;
        assert_eq!(vault.wipe()?, 3);
        assert_eq!(vault.read()?.record_count(), 0);

        let after = std::fs::read(dir.vault_path())?;
        assert!(record_starts(&after).is_empty());
        let wrapped = after.len() - 16;
        assert_eq!(
            after[..wrapped],
            before[..wrapped],
            "the wrapped key is kept"
        );
        assert_ne!(id_of(&after), id_of(&before));

        // The same key opens it, and it takes records again.
        vault.resolve(corpus(), FREE)?;
        let issued = dump(&vault)?;
        assert_eq!(issued.len(), corpus().len());
        drop(vault);
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?, issued);
        Ok(())
    }

    /// The vault file as a crash between the rename of `.compact` and the end of the rewrite can
    /// leave it, given the file before the forget and after (two records of the three left).
    fn crash_states(before: &[u8], after: &[u8]) -> [(&'static str, Vec<u8>); 5] {
        let starts = record_starts(after);
        // The new bytes up to `upto`, the old ones after.
        let mixed = |upto: usize| [&after[..upto], &before[upto..after.len()]].concat();
        [
            ("untouched", before.to_vec()),
            ("cut to the new length", before[..after.len()].to_vec()),
            ("new header, old records", mixed(starts[0])),
            ("new header and first record", mixed(starts[1])),
            ("complete", after.to_vec()),
        ]
    }

    #[test]
    fn a_forget_stopped_after_its_point_of_no_return_is_finished_on_open() -> Result<()> {
        let dir = TempDir::new()?;
        let (before, after) = forget_b(&dir)?;
        for (what, state) in crash_states(&before, &after) {
            std::fs::write(dir.vault_path(), &state)?;
            std::fs::write(compact_of(&dir), &after)?;
            let vault = Vault::open(&dir.vault_path())?;
            assert_eq!(
                originals_newest_first(&vault)?,
                ["c@example.org", "a@example.org"],
                "{what}"
            );
            drop(vault);
            assert!(!compact_of(&dir).exists(), "{what}: .compact was left");
            assert_eq!(std::fs::read(dir.vault_path())?, after, "{what}");
        }
        Ok(())
    }

    #[test]
    fn a_forget_stopped_after_its_point_of_no_return_is_finished_by_a_write_of_an_open_vault()
    -> Result<()> {
        let dir = TempDir::new()?;
        let (before, after) = forget_b(&dir)?;
        let expected = ["d@example.org", "c@example.org", "a@example.org"];
        for (what, state) in crash_states(&before, &after) {
            // An instance that is open when the forget stops: it knows the three records.
            std::fs::write(dir.vault_path(), &before)?;
            let live = Vault::open(&dir.vault_path())?;
            assert_eq!(dump(&live)?.len(), 3, "{what}");
            std::fs::write(dir.vault_path(), &state)?;
            std::fs::write(compact_of(&dir), &after)?;

            // Its record belongs after the ones that stay. Appended to the old contents, it would
            // be written over by the finishing at the next open; cut as a torn tail of the new
            // ones, the records that stay would be lost.
            append(
                &live,
                &[(EntityKind::Email, "d@example.org", "x4@example.net")],
            )?;
            assert_eq!(originals_newest_first(&live)?, expected, "{what}");
            drop(live);
            assert!(!compact_of(&dir).exists(), "{what}: .compact was left");
            let vault = Vault::open(&dir.vault_path())?;
            assert_eq!(originals_newest_first(&vault)?, expected, "{what}");
        }
        Ok(())
    }

    /// Three records, one of them forgotten: the vault file before and after.
    fn forget_b(dir: &TempDir) -> Result<(Vec<u8>, Vec<u8>)> {
        let vault = Vault::open(&dir.vault_path())?;
        three(&vault)?;
        let before = std::fs::read(dir.vault_path())?;
        assert_eq!(
            vault.forget(&|_, original, _| original == "b@example.org")?,
            1
        );
        let after = std::fs::read(dir.vault_path())?;
        Ok((before, after))
    }

    #[test]
    fn a_compact_file_left_behind_does_not_cost_the_records_appended_after_it() -> Result<()> {
        let dir = TempDir::new()?;
        let (_, after) = forget_b(&dir)?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[(EntityKind::Email, "d@example.org", "x4@example.net")],
        )?;
        drop(vault);
        let grown = std::fs::read(dir.vault_path())?;
        assert!(grown.len() > after.len());

        // The forget could not delete its `.compact`.
        std::fs::write(compact_of(&dir), &after)?;
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(
            originals_newest_first(&vault)?,
            ["d@example.org", "c@example.org", "a@example.org"]
        );
        drop(vault);
        assert!(!compact_of(&dir).exists());
        assert_eq!(std::fs::read(dir.vault_path())?, grown);
        Ok(())
    }

    #[test]
    fn a_compact_file_does_not_bring_back_a_vault_that_was_deleted() -> Result<()> {
        let dir = TempDir::new()?;
        let (_, after) = forget_b(&dir)?;
        std::fs::remove_file(dir.vault_path())?;
        std::fs::write(compact_of(&dir), &after)?;
        let vault = Vault::open(&dir.vault_path())?;
        assert!(dump(&vault)?.is_empty());
        drop(vault);
        assert!(!compact_of(&dir).exists());
        Ok(())
    }

    #[test]
    fn a_compact_file_does_not_overwrite_another_vault_that_took_the_place() -> Result<()> {
        let dir = TempDir::new()?;
        let (_, after) = forget_b(&dir)?;
        // Another vault, with a key of its own and records enough to be longer than the file
        // `.compact` holds, put there while the app was closed.
        let elsewhere = TempDir::new()?;
        three(&Vault::open(&elsewhere.vault_path())?)?;
        let theirs = std::fs::read(elsewhere.vault_path())?;
        assert!(theirs.len() > after.len());
        std::fs::write(dir.vault_path(), &theirs)?;
        std::fs::write(compact_of(&dir), &after)?;

        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(
            originals_newest_first(&vault)?,
            ["c@example.org", "b@example.org", "a@example.org"]
        );
        drop(vault);
        assert!(!compact_of(&dir).exists());
        assert_eq!(std::fs::read(dir.vault_path())?, theirs);
        Ok(())
    }

    #[test]
    fn a_compact_file_that_is_not_a_vault_is_refused_and_overwrites_nothing() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        let good = std::fs::read(dir.vault_path())?;
        std::fs::write(compact_of(&dir), b"this is not a vault file")?;
        assert!(matches!(Vault::open(&dir.vault_path()), Err(Error::Io(_))));
        assert_eq!(std::fs::read(dir.vault_path())?, good);
        Ok(())
    }

    #[test]
    fn temporary_files_of_an_interrupted_forget_are_swept_on_open() -> Result<()> {
        let dir = TempDir::new()?;
        three(&Vault::open(&dir.vault_path())?)?;
        // The name a temporary file of `.compact` has now, and the one older versions used.
        let temps = [
            suffixed(&compact_of(&dir), ".4242-1.tmp"),
            suffixed(&compact_of(&dir), ".tmp"),
        ];
        for tmp in &temps {
            std::fs::write(tmp, b"PKV1 cut short")?;
        }
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 3);
        for tmp in &temps {
            assert!(!tmp.exists(), "{tmp:?} was left");
        }
        Ok(())
    }

    #[test]
    fn a_second_instance_reloads_after_a_forget_on_its_next_write() -> Result<()> {
        let dir = TempDir::new()?;
        let a = Vault::open(&dir.vault_path())?;
        let b = Vault::open(&dir.vault_path())?;
        three(&a)?;
        // `b` merges the three by writing a record of its own.
        append(
            &b,
            &[(EntityKind::Email, "d@example.org", "x4@example.net")],
        )?;
        assert_eq!(dump(&b)?.len(), 4);

        assert_eq!(a.forget(&|_, original, _| original == "b@example.org")?, 1);
        assert_eq!(dump(&a)?.len(), 3, "a merged d before it rewrote the file");
        assert_eq!(dump(&b)?.len(), 4, "b cannot know yet");
        let generation = b.read()?.generation();

        b.resolve(vec![(EntityKind::Email, "new@example.org".into())], FREE)?;
        assert!(b.read()?.generation() > generation);
        assert_eq!(proxy_of(&b, EntityKind::Email, "b@example.org")?, None);
        let originals: Vec<String> = dump(&b)?.into_iter().map(|(_, o, _)| o).collect();
        assert_eq!(
            originals,
            [
                "a@example.org",
                "c@example.org",
                "d@example.org",
                "new@example.org"
            ]
        );

        // `a` takes `b`'s record when it next writes: they share the new id now.
        append(
            &a,
            &[(EntityKind::Email, "e@example.org", "x5@example.net")],
        )?;
        assert_eq!(dump(&a)?.len(), 5);
        drop((a, b));
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?.len(), 5);
        assert_eq!(proxy_of(&vault, EntityKind::Email, "b@example.org")?, None);
        Ok(())
    }

    #[test]
    fn a_forget_that_leaves_the_file_exactly_as_long_is_noticed_by_its_id() -> Result<()> {
        let dir = TempDir::new()?;
        let a = Vault::open(&dir.vault_path())?;
        let b = Vault::open(&dir.vault_path())?;
        three(&a)?;
        append(
            &b,
            &[(EntityKind::Email, "d@example.org", "x4@example.net")],
        )?;
        let len = std::fs::metadata(dir.vault_path())?.len();

        // One record out, one of the same size in: `b`'s idea of the length is still right.
        assert_eq!(a.forget(&|_, original, _| original == "b@example.org")?, 1);
        append(
            &a,
            &[(EntityKind::Email, "z@example.org", "x9@example.net")],
        )?;
        assert_eq!(std::fs::metadata(dir.vault_path())?.len(), len);

        append(
            &b,
            &[(EntityKind::Email, "f@example.org", "x6@example.net")],
        )?;
        let originals: Vec<String> = dump(&b)?.into_iter().map(|(_, o, _)| o).collect();
        assert_eq!(
            originals,
            [
                "a@example.org",
                "c@example.org",
                "d@example.org",
                "f@example.org",
                "z@example.org"
            ]
        );
        drop((a, b));
        assert_eq!(dump(&Vault::open(&dir.vault_path())?)?.len(), 5);
        Ok(())
    }

    #[test]
    fn instances_forgetting_while_others_append_end_consistent() -> Result<()> {
        const WRITERS: usize = 3;
        const ROUNDS: usize = 6;
        const KEPT_PER_ROUND: usize = 4;
        let dir = TempDir::new()?;
        let path = dir.vault_path();
        let dropped = |_: EntityKind, original: &str, _: &str| original.starts_with("drop.");
        let finished = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for t in 0..WRITERS {
                let (path, finished) = (&path, &finished);
                handles.push(scope.spawn(move || -> Result<()> {
                    let written = Vault::open(path).and_then(|vault| {
                        for round in 0..ROUNDS {
                            let mut batch = emails(&format!("keep.t{t}r{round}"), KEPT_PER_ROUND);
                            batch.extend(emails(&format!("drop.t{t}r{round}"), 3));
                            vault.resolve(batch, FREE)?;
                        }
                        Ok(())
                    });
                    finished.fetch_add(1, Ordering::SeqCst);
                    written
                }));
            }
            let (path, dropped, finished) = (&path, &dropped, &finished);
            handles.push(scope.spawn(move || -> Result<()> {
                let vault = Vault::open(path)?;
                while finished.load(Ordering::SeqCst) < WRITERS {
                    vault.forget(dropped)?;
                    std::thread::yield_now();
                }
                Ok(())
            }));
            join_all(handles)
        })?;

        // Nothing that stays was lost, whatever the forgets did meanwhile; one more clears the
        // records the writers added after the forgetter's last turn.
        let kept = WRITERS * ROUNDS * KEPT_PER_ROUND;
        let vault = Vault::open(&path)?;
        vault.forget(&dropped)?;
        assert_consistent(&vault, kept)?;
        assert!(
            dump(&vault)?
                .iter()
                .all(|(_, original, _)| original.starts_with("keep."))
        );
        drop(vault);
        assert_consistent(&Vault::open(&path)?, kept)
    }

    #[test]
    fn search_matches_original_or_proxy_ignoring_case_newest_first() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        append(
            &vault,
            &[
                (
                    EntityKind::Email,
                    "Jan.Jansen@Example.org",
                    "px1@example.net",
                ),
                (EntityKind::Person, "\u{C9}mile M\u{FC}ller", "Haley Quinn"),
                (EntityKind::Phone, "+31612345678", "+31687654321"),
                (
                    EntityKind::Email,
                    "other@example.org",
                    "jan-proxy@example.net",
                ),
            ],
        )?;
        let view = vault.read()?;
        let found = |query: &str, kind: Option<EntityKind>| -> Vec<String> {
            view.search(query, kind)
                .map(|(_, original, _)| original.to_owned())
                .collect()
        };
        assert_eq!(
            found("", None),
            [
                "other@example.org",
                "+31612345678",
                "\u{C9}mile M\u{FC}ller",
                "Jan.Jansen@Example.org"
            ],
            "an empty query matches everything"
        );
        assert_eq!(
            found("jan", None),
            ["other@example.org", "Jan.Jansen@Example.org"],
            "the original of one, the proxy of the other"
        );
        assert_eq!(found("JAN.JANSEN", None), ["Jan.Jansen@Example.org"]);
        assert_eq!(found("EXAMPLE.ORG", None).len(), 2);
        assert_eq!(
            found("\u{E9}MILE m\u{DC}LLER", None),
            ["\u{C9}mile M\u{FC}ller"]
        );
        assert_eq!(
            found("QUINN", Some(EntityKind::Person)),
            ["\u{C9}mile M\u{FC}ller"],
            "the proxy matches too"
        );
        assert!(found("quinn", Some(EntityKind::Email)).is_empty());
        assert_eq!(found("+316", Some(EntityKind::Phone)), ["+31612345678"]);
        assert!(found("nobody", None).is_empty());
        Ok(())
    }

    #[test]
    fn search_treats_the_greek_final_sigma_as_a_sigma() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        // `\u{3A3}` is the capital sigma and `\u{3C2}` the final one: the same word as capitals
        // and as lower case, which spells its last letter differently.
        let capitals =
            "\u{393}\u{399}\u{3A9}\u{3A1}\u{393}\u{39F}\u{3A3} \u{3A3}\u{399}\u{3A9}\u{3A3}";
        let small = "\u{3B3}\u{3B9}\u{3C9}\u{3C1}\u{3B3}\u{3BF}\u{3C2}";
        append(
            &vault,
            &[
                (EntityKind::Person, capitals, "Haley Quinn"),
                (EntityKind::Person, small, "Jan Brooks"),
            ],
        )?;
        let view = vault.read()?;
        let found = |query: &str| -> Vec<String> {
            view.search(query, None)
                .map(|(_, original, _)| original.to_owned())
                .collect()
        };
        for query in [
            small,
            "\u{393}\u{399}\u{3A9}\u{3A1}\u{393}\u{39F}\u{3A3}",
            "\u{3B3}\u{3B9}\u{3C9}\u{3C1}\u{3B3}\u{3BF}\u{3C3}",
        ] {
            assert_eq!(found(query), [small, capitals], "{query}");
        }
        // A part of a word is found wherever it stands in the other.
        assert_eq!(found("\u{3A3}\u{399}\u{3A9}\u{3A3}"), [capitals]);
        assert_eq!(found("\u{3C3}\u{3B9}\u{3C9}\u{3C2}"), [capitals]);
        Ok(())
    }

    #[test]
    fn export_json_is_an_array_of_records_in_file_order() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        let (count, empty) = exported(&vault, ExportFormat::Json)?;
        assert_eq!(count, 0);
        assert_eq!(parse_json(&empty)?, serde_json::json!([]));

        // Quotes, backslashes, line breaks, control characters and characters outside ASCII.
        let tricky = "Zo\u{EB} \"Z\" O'Neil\\ \u{1F600} \u{1}";
        append(
            &vault,
            &[
                (
                    EntityKind::Email,
                    "jan.jansen@example.org",
                    "x1@example.net",
                ),
                (EntityKind::Person, tricky, "Haley\ttab\r\nbreak"),
                (EntityKind::Phone, "+31 6 12345678", "+31 6 87654321"),
            ],
        )?;
        let (count, json) = exported(&vault, ExportFormat::Json)?;
        assert_eq!(count, 3);
        assert_eq!(
            parse_json(&json)?,
            serde_json::json!([
                {"kind": "email", "original": "jan.jansen@example.org", "proxy": "x1@example.net"},
                {"kind": "person", "original": tricky, "proxy": "Haley\ttab\r\nbreak"},
                {"kind": "phone", "original": "+31 6 12345678", "proxy": "+31 6 87654321"},
            ])
        );
        Ok(())
    }

    #[test]
    fn export_csv_quotes_what_rfc_4180_says_to_quote() -> Result<()> {
        let dir = TempDir::new()?;
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(
            exported(&vault, ExportFormat::Csv)?,
            (0, "kind,original,proxy\r\n".to_owned())
        );
        append(
            &vault,
            &[
                (EntityKind::Email, "plain@example.org", "p1@example.net"),
                (EntityKind::Email, "a,b@example.org", "p2@example.net"),
                (EntityKind::Person, "say \"hi\"", "p3"),
                (EntityKind::Person, "line one\nline two", "p4"),
                (EntityKind::Person, "carriage\rreturn", "p5, \"quoted\""),
                (EntityKind::Person, "Zo\u{EB}", "p6"),
            ],
        )?;
        let (count, csv) = exported(&vault, ExportFormat::Csv)?;
        assert_eq!(count, 6);
        assert_eq!(
            csv,
            "kind,original,proxy\r\n\
             email,plain@example.org,p1@example.net\r\n\
             email,\"a,b@example.org\",p2@example.net\r\n\
             person,\"say \"\"hi\"\"\",p3\r\n\
             person,\"line one\nline two\",p4\r\n\
             person,\"carriage\rreturn\",\"p5, \"\"quoted\"\"\"\r\n\
             person,Zo\u{EB},p6\r\n"
        );
        Ok(())
    }

    #[test]
    fn csv_rows_quote_only_where_needed() -> io::Result<()> {
        let mut out = Vec::new();
        csv_row(&mut out, &["a", "", "b c", "d,e", "f\"g", "h\ni"])?;
        csv_row(&mut out, &[])?;
        assert_eq!(
            String::from_utf8_lossy(&out),
            "a,,b c,\"d,e\",\"f\"\"g\",\"h\ni\"\r\n\r\n"
        );
        Ok(())
    }
}
