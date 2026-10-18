//! DPAPI-wrapped, encrypted, append-only original↔proxy vault.
//!
//! The file is the source of truth and the in-memory `State` a cache of it.
//! [`Vault::resolve`] is the only writer: under the in-process mutex and the
//! cross-process file lock it merges the records other processes appended,
//! picks proxies that collide with nothing, appends them in one write and
//! syncs.
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
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, RwLockReadGuard},
};

use rayon::prelude::*;

use self::{
    file::{Entry, FileLock, VAULT_ID_LEN},
    keys::VaultKeys,
};
use crate::{
    Error, Result,
    detect::EntityKind,
    proxy::{ProxyKeys, generate, watermark_ok},
};

/// Candidates tried per original before giving up.
const MAX_ATTEMPTS: u32 = 4096;
const KINDS: usize = EntityKind::ALL.len();

/// `%LOCALAPPDATA%\piikey\vault.pkv` (parent dir created).
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` on mkdir failure.
pub fn default_path() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|base| !base.is_empty())
        .ok_or(Error::VaultPathUnavailable)?;
    let dir = PathBuf::from(base).join("piikey");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("vault.pkv"))
}

/// Index of `kind` in `State::by_original`.
fn slot(kind: EntityKind) -> usize {
    usize::from(kind as u8) - 1
}

/// Everything the file holds, indexed for lookup.
#[derive(Default)]
struct State {
    /// original → proxy, per kind, so lookups by `&str` allocate nothing.
    by_original: [HashMap<Arc<str>, Arc<str>>; KINDS],
    /// proxy → original. Keyed without the kind so a proxy is unique across
    /// kinds and deanonymizing needs no kind.
    by_proxy: HashMap<Arc<str>, Arc<str>>,
    /// Every original of every kind: no proxy may equal one of them.
    originals: HashSet<Arc<str>>,
    /// Records in the file, which is also the next record's index.
    count: u64,
}

impl State {
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
        for Entry {
            kind,
            original,
            proxy,
        } in entries
        {
            self.by_original[slot(kind)].insert(Arc::clone(&original), Arc::clone(&proxy));
            self.by_proxy.insert(proxy, Arc::clone(&original));
            self.originals.insert(original);
            self.count += 1;
        }
    }
}

/// The vault. All methods take `&self`; it is `Send + Sync`.
pub struct Vault {
    file: File,
    path: PathBuf,
    keys: VaultKeys,
    id: [u8; VAULT_ID_LEN],
    state: RwLock<State>,
    /// File offset just past the last record this process has read or
    /// written. Also the in-process writer lock: it is held for a whole write.
    known_len: Mutex<u64>,
}

/// A consistent read snapshot (holds the read lock while alive).
///
/// Drop it before calling [`Vault::resolve`] on the same thread, and never
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
            .field("records", &self.state.count)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Opens the vault at `path`. A missing or empty file becomes a new vault
    /// with a fresh DPAPI-wrapped key; concurrent first opens are safe. A
    /// record cut short by a crash at the end of the file is truncated.
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
        // One exclusive lock covers creating the header, reading the file and
        // cutting a torn tail. Whoever gets it first on an empty file creates
        // the vault; everyone else waits and then loads it.
        let lock = FileLock::exclusive(&file)?;
        let len = file.metadata()?.len();
        let (vault_id, header_len, keys, body) = if len == 0 {
            let (vault_id, header_len, keys) = create_header(&file)?;
            (vault_id, header_len, keys, Vec::new())
        } else {
            let (vault_id, header_len, keys) = load_header(&file, len)?;
            let body = file::read_range(&file, header_len, len)?;
            (vault_id, header_len, keys, body)
        };
        let framed = file::frame(&keys.records, &vault_id, &body, 0)?;
        let known_len = header_len + framed.good_len as u64;
        if framed.good_len < body.len() {
            file.set_len(known_len)?;
        }
        // Decrypting everything is the slow part; it needs only the bytes in
        // memory, so it runs after the lock is released and in parallel.
        drop(lock);
        let entries = file::decrypt(&keys.records, &vault_id, &body, &framed.frames, 0, true)?;
        let mut state = State::default();
        state.insert_all(entries);
        Ok(Self {
            file,
            path: path.to_owned(),
            keys,
            id: vault_id,
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
    /// records appended by other processes first. The only writer.
    ///
    /// # Errors
    /// `Io`, `VaultCorrupt`, `ProxyExhausted`, `Poisoned`.
    pub fn resolve(&self, mut new: Vec<(EntityKind, Box<str>)>) -> Result<()> {
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
        self.locked_append(|state| choose(keys, state, pending))
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
    /// Takes the in-process mutex, then the file lock, merges records other
    /// processes appended since this one last looked, and only then calls
    /// `choose`. Everything here is sequential: see the module docs.
    fn locked_append<F>(&self, choose: F) -> Result<()>
    where
        F: FnOnce(&State) -> Result<Vec<Entry>>,
    {
        let mut known_len = self.known_len.lock()?;
        let _lock = FileLock::exclusive(&self.file)?;
        self.merge_appended(&mut known_len)?;
        let entries = {
            let state = self.state.read()?;
            choose(&state)?
        };
        if entries.is_empty() {
            return Ok(());
        }
        self.append(&mut known_len, entries)
    }

    /// Adds the records other processes appended past `known_len`, cutting a
    /// torn tail they left behind. The file lock must be held.
    fn merge_appended(&self, known_len: &mut u64) -> Result<()> {
        let len = self.file.metadata()?.len();
        if len == *known_len {
            return Ok(());
        }
        let first_index = self.state.read()?.count;
        if len < *known_len {
            // Records this process already read are gone.
            return Err(Error::VaultCorrupt {
                record: first_index,
            });
        }
        let body = file::read_range(&self.file, *known_len, len)?;
        let cipher = &self.keys.records;
        let framed = file::frame(cipher, &self.id, &body, first_index)?;
        let good_end = *known_len + framed.good_len as u64;
        if framed.good_len < body.len() {
            self.file.set_len(good_end)?;
        }
        let entries = file::decrypt(cipher, &self.id, &body, &framed.frames, first_index, false)?;
        self.state.write()?.insert_all(entries);
        *known_len = good_end;
        Ok(())
    }

    /// Encrypts `entries`, appends them at `known_len`, syncs, and adds them
    /// to the in-memory state. The file lock must be held and `known_len`
    /// must be the file's length.
    fn append(&self, known_len: &mut u64, entries: Vec<Entry>) -> Result<()> {
        let first_index = self.state.read()?.count;
        let bytes = file::seal(&self.keys.records, &self.id, first_index, &entries)?;
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

/// Creates the header of an empty vault file and returns
/// `(vault_id, header_len, keys)`.
fn create_header(file: &File) -> Result<([u8; VAULT_ID_LEN], u64, VaultKeys)> {
    let master = keys::generate_master()?;
    let wrapped_key = keys::wrap(&master)?;
    let mut vault_id = [0u8; VAULT_ID_LEN];
    keys::fill_random(&mut vault_id)?;
    let header = file::encode_header(&wrapped_key, &vault_id)?;
    file::write_all_at(file, &header, 0)
        .and_then(|()| file.sync_data())
        .inspect_err(|_| {
            // Leave an empty file so the next open starts over.
            let _ = file.set_len(0);
        })?;
    Ok((vault_id, header.len() as u64, VaultKeys::derive(&master)))
}

/// Reads the header of an existing vault file of `len` bytes and returns
/// `(vault_id, header_len, keys)`.
fn load_header(file: &File, len: u64) -> Result<([u8; VAULT_ID_LEN], u64, VaultKeys)> {
    let header = file::read_header(file, len)?;
    let master = keys::unwrap(&header.wrapped_key)?;
    Ok((header.vault_id, header.len, VaultKeys::derive(&master)))
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
/// `original` and carries the watermark. Depends on the keys only.
fn watermarked(
    keys: &ProxyKeys,
    kind: EntityKind,
    original: &str,
    from: u32,
) -> Option<(String, u32)> {
    (from..MAX_ATTEMPTS).find_map(|attempt| {
        let candidate = generate(keys, kind, original, attempt);
        (candidate != original && watermark_ok(keys, kind, &candidate))
            .then_some((candidate, attempt))
    })
}

/// Picks a proxy for every pending value that is still unresolved in
/// `state`: the first watermarked candidate that equals no issued proxy, no
/// known original, no original in this batch and no proxy chosen earlier in
/// it. Values are taken in their sorted order, so the outcome does not depend
/// on how the caller ordered them.
fn choose(keys: &ProxyKeys, state: &State, pending: Vec<Pending>) -> Result<Vec<Entry>> {
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
        self.state.by_proxy.get(proxy).map(|original| &**original)
    }
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
        vault.resolve(corpus())?;
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
    fn the_same_original_gets_the_same_proxy_across_reopen() -> Result<()> {
        let dir = TempDir::new()?;
        let first = {
            let vault = Vault::open(&dir.vault_path())?;
            vault.resolve(corpus())?;
            dump(&vault)?
        };
        assert_eq!(first.len(), corpus().len());
        let vault = Vault::open(&dir.vault_path())?;
        assert_eq!(dump(&vault)?, first);
        let len = std::fs::metadata(dir.vault_path())?.len();
        vault.resolve(corpus())?;
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
            vault.resolve(corpus())?;
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
        vault.resolve(batch)?;
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
        vault.resolve(vec![
            (EntityKind::NlBsn, "111222333".into()),
            (EntityKind::UsSsn, "111222333".into()),
        ])?;
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
        a.resolve(all[..7].to_vec())?;
        b.resolve(all[4..].to_vec())?;
        // `a` learns what `b` added the next time it writes, or reopens.
        a.resolve(all.clone())?;
        b.resolve(all.clone())?;
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
            vault.resolve(batch)?;
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
            vault.resolve(batch)
        })?;
        assert_consistent(&vault, 30 + 96 * 30)
    }
}
