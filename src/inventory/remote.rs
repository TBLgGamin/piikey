//! What the inventory does for the files of a cloud account (see [`crate::sources`]).
//!
//! Such a file is not on this PC's file system: the account's listing says what it is (path, size,
//! time) and a connector fetches its bytes. Everything after the bytes is the scan of a file on
//! this PC: the same fingerprint, the same detection, the same entry, the same saves, and the
//! same [`Progress`], so a scan of local folders and of cloud folders can be one run with one
//! count (run the local part first: it starts the count, and this adds to it).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use rayon::prelude::*;

use super::{
    Busy, CHUNK, Entry, Inventory, MAX_FILE, Prior, Progress, SAVE_EVERY, SAVE_GAP, SAVE_WAIT,
    State, Status, judge, unix_now,
};
use crate::{Result, engine::Engine, sys};

/// A file of a cloud account as the account's listing describes it: what says whether the scan
/// has to read it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listed {
    /// Its virtual path.
    pub path: PathBuf,
    /// Its size as the listing says. `None` when the service does not say, as for a file that has
    /// no bytes of its own (a Google Doc is downloaded as a Word file): the entry then keeps the
    /// size of what was downloaded, and the size is not compared to tell whether it changed.
    pub size: Option<u64>,
    /// What goes in [`Entry::modified`]: a Windows `FILETIME`, never 0.
    pub modified: u64,
}

/// What fetching the contents of a listed file came to.
#[derive(Debug)]
pub(crate) enum Fetched {
    /// The contents.
    Bytes(Vec<u8>),
    /// More than [`MAX_FILE`].
    TooLarge,
    /// They could not be fetched; the sentence says why. The next scan tries again.
    Failed(String),
    /// The file is not there any more: nothing is recorded.
    Gone,
    /// The scan cannot go on (the account needs to sign in again, the service is out of
    /// reach): the caller has the reason. What was scanned so far is kept.
    Stop,
}

/// How a scan of listed files ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Entries recorded or replaced.
    pub recorded: usize,
    /// Every file that had to be read was dealt with: it was not cancelled or stopped.
    pub finished: bool,
}

impl Inventory {
    /// Reads the files of `listed` that are new or changed (no entry, or another size or time, or
    /// an entry of a read that failed: its time is 0) and records what the detector finds, as a
    /// scan of folders on this PC does. `fetch` gets the contents of the file at an index of
    /// `listed`, on a thread of the rayon pool the caller runs in. A file whose contents turn out
    /// to be what the entry says (the service touched it, nothing changed) is not detected again.
    ///
    /// The number of files to read is added to [`Progress::total`] and each one done to
    /// [`Progress::done`]: nothing is reset, so this can follow a scan of folders on this PC with
    /// the same `progress`. `cancel` is looked at between files; a cancelled or stopped scan
    /// saves what it did.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be read or saved; `Busy` as for [`Inventory::save`].
    pub(crate) fn scan_listed(
        &self,
        engine: &Engine,
        listed: &[Listed],
        fetch: &(dyn Fn(usize) -> Fetched + Sync),
        progress: &Progress,
        cancel: &AtomicBool,
    ) -> Result<Outcome> {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Outcome {
                recorded: 0,
                finished: false,
            });
        }
        // The listing can have taken minutes: what another process scanned since is not read
        // again.
        self.sync()?;
        let pending: Vec<(usize, Option<Prior>)> = {
            let state = self.read();
            listed
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    let known = state.entries.get(&item.path);
                    let unchanged = known.is_some_and(|known| {
                        item.size.is_none_or(|size| known.size == size)
                            && known.modified == item.modified
                    });
                    (!unchanged).then(|| (index, known.and_then(Prior::of)))
                })
                .collect()
        };
        progress.total.fetch_add(
            u64::try_from(pending.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let stopped = AtomicBool::new(false);
        let going = || !cancel.load(Ordering::Relaxed) && !stopped.load(Ordering::Relaxed);
        let mut recorded = 0;
        let mut last_save = Instant::now();
        for chunk in pending.chunks(CHUNK) {
            if !going() {
                break;
            }
            let scanned: Vec<Entry> = chunk
                .par_iter()
                .filter_map(|(index, prior)| {
                    if !going() {
                        return None;
                    }
                    let item = listed.get(*index)?;
                    progress.begin(&item.path);
                    let follow = |busy: Busy| {
                        progress.busy(&item.path, busy);
                        going()
                    };
                    let entry = read_listed(
                        engine,
                        item,
                        prior.as_ref(),
                        || fetch(*index),
                        &follow,
                        &stopped,
                    );
                    progress.end(&item.path);
                    entry
                })
                .collect();
            recorded += scanned.len();
            self.insert(scanned);
            if self.unsaved() >= SAVE_EVERY && last_save.elapsed() >= SAVE_GAP {
                self.save()?;
                last_save = Instant::now();
            }
        }
        if self.unsaved() > 0 {
            self.save()?;
        }
        Ok(Outcome {
            recorded,
            finished: going(),
        })
    }

    /// Forgets the entries at and under each of `gone`, virtual paths below `root` that a cloud
    /// account says are gone (letter case ignored), and saves; returns how many entries went.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be read or saved; `Busy` as for [`Inventory::save`].
    pub(crate) fn forget_removed(&self, root: &Path, gone: &[PathBuf]) -> Result<usize> {
        if gone.is_empty() {
            return Ok(0);
        }
        let gone: HashSet<String> = gone.iter().map(|path| sys::path_key(path)).collect();
        self.update(SAVE_WAIT, |state| {
            let State { entries, changed } = state;
            let before = entries.len();
            entries.retain(|path, _| {
                let forgotten = sys::is_under(path, root)
                    && path
                        .ancestors()
                        .any(|above| gone.contains(&sys::path_key(above)));
                if forgotten {
                    changed.insert(path.clone());
                }
                !forgotten
            });
            let removed = before - entries.len();
            (removed, removed > 0)
        })
    }

    /// Forgets the entries under `root` that `listed`, a complete listing of everything under
    /// it, does not name (a path spelled in another letter case is another path: the listing
    /// spells it as the service does now), and saves; returns how many went.
    ///
    /// # Errors
    /// `Io` when the inventory cannot be read or saved; `Busy` as for [`Inventory::save`].
    pub(crate) fn forget_unlisted(&self, root: &Path, listed: &[Listed]) -> Result<usize> {
        let present: HashSet<&Path> = listed.iter().map(|item| item.path.as_path()).collect();
        self.update(SAVE_WAIT, |state| {
            let State { entries, changed } = state;
            let before = entries.len();
            entries.retain(|path, _| {
                let forgotten = sys::is_under(path, root) && !present.contains(path.as_path());
                if forgotten {
                    changed.insert(path.clone());
                }
                !forgotten
            });
            let removed = before - entries.len();
            (removed, removed > 0)
        })
    }
}

/// Fetches and judges one listed file, or says why not: the entry it makes, or `None` when the
/// file is gone, the scan is to stop (`stopped` is set) or `follow` stopped the read.
fn read_listed(
    engine: &Engine,
    item: &Listed,
    prior: Option<&Prior>,
    fetch: impl FnOnce() -> Fetched,
    follow: &(dyn Fn(Busy) -> bool + Sync),
    stopped: &AtomicBool,
) -> Option<Entry> {
    let mut modified = item.modified;
    let mut size = item.size;
    let mut hash = None;
    let fetched = if size.is_some_and(|size| size > MAX_FILE) {
        Fetched::TooLarge
    } else {
        fetch()
    };
    let (status, counts) = match fetched {
        Fetched::TooLarge => (Status::TooLarge, Vec::new()),
        Fetched::Bytes(bytes) => {
            let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            size.get_or_insert(len);
            if len > MAX_FILE {
                (Status::TooLarge, Vec::new())
            } else {
                let (seen, status, counts) = judge(engine, &bytes, prior, &mut modified, follow)?;
                hash = Some(seen);
                (status, counts)
            }
        }
        // Whatever stopped the fetch may be over by the next scan: with no time on record the
        // file looks changed by then.
        Fetched::Failed(why) => {
            modified = 0;
            (Status::Failed(why), Vec::new())
        }
        Fetched::Gone => return None,
        Fetched::Stop => {
            stopped.store(true, Ordering::Relaxed);
            return None;
        }
    };
    Some(Entry {
        path: item.path.clone(),
        size: size.unwrap_or(0),
        modified,
        scanned: unix_now(),
        status,
        counts,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::{
        detect::EntityKind::{Email, Iban},
        inventory::ContentHash,
        testing::temp_dir,
    };

    type Res<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    const EMAIL: &str = "jan.jansen@acme.nl";
    const IBAN: &str = "NL91ABNA0417164300";

    fn listed(path: &str, size: u64, modified: u64) -> Listed {
        Listed {
            path: PathBuf::from(path),
            size: Some(size),
            modified,
        }
    }

    fn setup(tag: &str) -> Res<(Engine, Inventory)> {
        let dir = temp_dir(tag);
        Ok((
            Engine::open(&dir.join("vault.pkv"))?,
            Inventory::open(&dir.join("inventory.jsonl"))?,
        ))
    }

    /// Fetches `contents[index]`, counting the fetches.
    fn fetching<'a>(
        contents: &'a [&'a str],
        count: &'a AtomicUsize,
    ) -> impl Fn(usize) -> Fetched + Sync + 'a {
        move |index| {
            count.fetch_add(1, Ordering::SeqCst);
            Fetched::Bytes(contents[index].as_bytes().to_vec())
        }
    }

    fn run(
        inv: &Inventory,
        engine: &Engine,
        items: &[Listed],
        fetch: &(dyn Fn(usize) -> Fetched + Sync),
        progress: &Progress,
    ) -> Res<Outcome> {
        Ok(inv.scan_listed(engine, items, fetch, progress, &AtomicBool::new(false))?)
    }

    #[test]
    fn listed_files_are_read_once_and_counted_into_the_progress_they_are_given() -> Res {
        let (engine, inv) = setup("remote-scan")?;
        let items = [
            listed(r"\\Box\work\a.txt", 20, 1_000),
            listed(r"\\Box\work\b.txt", 5, 2_000),
        ];
        let contents = [format!("mail {EMAIL} iban {IBAN}"), "nothing".to_owned()];
        let contents: Vec<&str> = contents.iter().map(String::as_str).collect();
        let count = AtomicUsize::new(0);
        let fetch = fetching(&contents, &count);

        // The part of the run that came first: the count goes on from it.
        let progress = Progress::default();
        progress.done.store(3, Ordering::Relaxed);
        progress.total.store(10, Ordering::Relaxed);
        let outcome = run(&inv, &engine, &items, &fetch, &progress)?;
        assert_eq!(
            outcome,
            Outcome {
                recorded: 2,
                finished: true
            }
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(progress.done.load(Ordering::Relaxed), 5);
        assert_eq!(progress.total.load(Ordering::Relaxed), 12);
        assert!(progress.reading().is_empty());

        let first = inv.entry(&items[0].path).ok_or("no entry")?;
        assert_eq!(
            (first.size, first.modified, first.status.as_str()),
            (20, 1_000, "ok")
        );
        assert_eq!(
            first
                .counts
                .iter()
                .map(|&(kind, _)| kind)
                .collect::<Vec<_>>()
                .len(),
            2
        );
        assert!(first.counts.contains(&(Email, 1)) && first.counts.contains(&(Iban, 1)));
        assert!(first.hash.is_some());
        assert_eq!(inv.entry(&items[1].path).ok_or("no entry")?.hits(), 0);

        // Nothing changed: nothing is read, nothing is added to the count.
        let again = Progress::default();
        let outcome = run(&inv, &engine, &items, &fetch, &again)?;
        assert_eq!(
            outcome,
            Outcome {
                recorded: 0,
                finished: true
            }
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(again.total.load(Ordering::Relaxed), 0);

        // The entries are on disk for the next process.
        let reopened = Inventory::open(&inv.path)?;
        assert_eq!(reopened.entries(None, 0).len(), 2);
        Ok(())
    }

    #[test]
    fn a_file_that_changed_in_time_but_not_in_contents_is_not_detected_again() -> Res {
        let (engine, inv) = setup("remote-same")?;
        let text = format!("mail {EMAIL}");
        let path = PathBuf::from(r"\\Dropbox\work\a.txt");
        // What the entry says (99 emails) is not what the detector would find: if it is still
        // there after the file is read again, the detector did not run.
        inv.record(vec![Entry {
            path: path.clone(),
            size: 5,
            modified: 1_000,
            scanned: 1,
            status: Status::Ok,
            counts: vec![(Email, 99)],
            hash: Some(ContentHash::of(text.as_bytes())),
        }])?;
        let count = AtomicUsize::new(0);
        let contents = [text.as_str()];
        let fetch = fetching(&contents, &count);
        let items = [listed(r"\\Dropbox\work\a.txt", 5, 2_000)];
        run(&inv, &engine, &items, &fetch, &Progress::default())?;
        assert_eq!(count.load(Ordering::SeqCst), 1, "the file is read");
        let entry = inv.entry(&path).ok_or("no entry")?;
        assert_eq!(
            (entry.modified, entry.counts.clone()),
            (2_000, vec![(Email, 99)])
        );

        // Other contents are detected.
        let other = format!("{text} and {IBAN}");
        let contents = [other.as_str()];
        let fetch = fetching(&contents, &count);
        let items = [listed(r"\\Dropbox\work\a.txt", 9, 3_000)];
        run(&inv, &engine, &items, &fetch, &Progress::default())?;
        let entry = inv.entry(&path).ok_or("no entry")?;
        assert!(entry.counts.contains(&(Email, 1)) && entry.counts.contains(&(Iban, 1)));
        Ok(())
    }

    #[test]
    fn a_file_with_no_size_of_its_own_keeps_the_size_of_what_was_downloaded() -> Res {
        let (engine, inv) = setup("remote-nosize")?;
        let path = PathBuf::from(r"\\Google Drive\jan\My Drive\notes");
        let text = format!("mail {EMAIL}");
        let items = [Listed {
            path: path.clone(),
            size: None,
            modified: 1_000,
        }];
        let count = AtomicUsize::new(0);
        let contents = [text.as_str()];
        let fetch = fetching(&contents, &count);
        run(&inv, &engine, &items, &fetch, &Progress::default())?;
        let entry = inv.entry(&path).ok_or("no entry")?;
        assert_eq!(entry.size, u64::try_from(text.len())?);
        assert_eq!(entry.counts, vec![(Email, 1)]);

        // The listing still says nothing of the size: it is the time that says nothing changed.
        let progress = Progress::default();
        run(&inv, &engine, &items, &fetch, &progress)?;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(progress.total.load(Ordering::Relaxed), 0);
        let changed = [Listed {
            modified: 2_000,
            ..items[0].clone()
        }];
        run(&inv, &engine, &changed, &fetch, &Progress::default())?;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn a_failed_fetch_is_tried_again_and_a_big_file_is_not_fetched() -> Res {
        let (engine, inv) = setup("remote-failed")?;
        let items = [
            listed(r"\\Box\work\locked.txt", 5, 1_000),
            listed(r"\\Box\work\huge.iso", MAX_FILE + 1, 2_000),
            listed(r"\\Box\work\gone.txt", 5, 3_000),
            listed(r"\\Box\work\lying.bin", 5, 4_000),
        ];
        let fetch = |index: usize| match index {
            0 => Fetched::Failed("Box does not allow piikey to read this.".to_owned()),
            1 => Fetched::Bytes(b"must not be asked for".to_vec()),
            2 => Fetched::Gone,
            _ => Fetched::Bytes(vec![0; usize::try_from(MAX_FILE).unwrap_or(0) + 1]),
        };
        let outcome = run(&inv, &engine, &items, &fetch, &Progress::default())?;
        assert!(outcome.finished);
        let locked = inv.entry(&items[0].path).ok_or("no entry")?;
        assert_eq!(
            locked.status,
            Status::Failed("Box does not allow piikey to read this.".to_owned())
        );
        assert_eq!(locked.modified, 0, "so that the next scan tries again");
        assert_eq!(
            inv.entry(&items[1].path).ok_or("no entry")?.status,
            Status::TooLarge
        );
        assert!(
            inv.entry(&items[2].path).is_none(),
            "a file that is gone leaves nothing"
        );
        let lying = inv.entry(&items[3].path).ok_or("no entry")?;
        assert_eq!((lying.status, lying.size), (Status::TooLarge, 5));

        let count = AtomicUsize::new(0);
        let contents = ["fine now"];
        let fetch_ok = fetching(&contents, &count);
        let retry = [items[0].clone()];
        run(&inv, &engine, &retry, &fetch_ok, &Progress::default())?;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(
            inv.entry(&items[0].path).ok_or("no entry")?.status,
            Status::Ok
        );
        Ok(())
    }

    #[test]
    fn a_scan_that_is_cancelled_or_stopped_keeps_what_it_did_and_says_it_did_not_finish() -> Res {
        let (engine, inv) = setup("remote-stop")?;
        let items: Vec<Listed> = (0..5)
            .map(|n| listed(&format!(r"\\Box\work\{n}.txt"), 1, 1_000 + n))
            .collect();
        let started = Progress::default();
        let cancelled = AtomicBool::new(true);
        let outcome = inv.scan_listed(&engine, &items, &|_| Fetched::Gone, &started, &cancelled)?;
        assert_eq!(
            outcome,
            Outcome {
                recorded: 0,
                finished: false
            }
        );
        assert_eq!(started.total.load(Ordering::Relaxed), 0);

        // Stopped by the fetcher in the middle: one pool thread makes the order certain.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
        let outcome = pool.install(|| {
            inv.scan_listed(
                &engine,
                &items,
                &|index| {
                    if index == 2 {
                        Fetched::Stop
                    } else {
                        Fetched::Bytes(b"x".to_vec())
                    }
                },
                &Progress::default(),
                &AtomicBool::new(false),
            )
        })?;
        assert!(!outcome.finished);
        assert_eq!(outcome.recorded, 2);
        assert_eq!(inv.entries(None, 0).len(), 2, "what was done is saved");
        assert_eq!(Inventory::open(&inv.path)?.entries(None, 0).len(), 2);

        // Cancelled from inside the fetch of the first file.
        let cancel = AtomicBool::new(false);
        let other = Inventory::open(&temp_dir("remote-cancel").join("inventory.jsonl"))?;
        let outcome = pool.install(|| {
            other.scan_listed(
                &engine,
                &items,
                &|_| {
                    cancel.store(true, Ordering::Relaxed);
                    Fetched::Bytes(b"x".to_vec())
                },
                &Progress::default(),
                &cancel,
            )
        })?;
        assert!(!outcome.finished);
        Ok(())
    }

    #[test]
    fn what_a_service_says_is_gone_or_does_not_list_any_more_is_forgotten() -> Res {
        let (_, inv) = setup("remote-forget")?;
        let entry = |path: &str| Entry {
            path: PathBuf::from(path),
            size: 1,
            modified: 1,
            scanned: 1,
            status: Status::Ok,
            counts: vec![(Email, 1)],
            hash: None,
        };
        let root = Path::new(r"\\Dropbox\work");
        inv.record(vec![
            entry(r"\\Dropbox\work\a\1.txt"),
            entry(r"\\Dropbox\work\a\sub\2.txt"),
            entry(r"\\Dropbox\work\b\3.txt"),
            entry(r"\\Dropbox\work\c.txt"),
            entry(r"\\Dropbox\other\a\4.txt"),
            entry(r"C:\a\5.txt"),
        ])?;
        // A folder and a file; the spelling's letter case does not matter; other trees are
        // not touched.
        let gone = [
            PathBuf::from(r"\\dropbox\WORK\A"),
            PathBuf::from(r"\\Dropbox\work\c.txt"),
        ];
        assert_eq!(inv.forget_removed(root, &gone)?, 3);
        assert_eq!(inv.forget_removed(root, &[])?, 0);
        let kept = |inv: &Inventory| {
            let mut paths: Vec<PathBuf> =
                inv.entries(None, 0).into_iter().map(|e| e.path).collect();
            paths.sort();
            paths
        };
        let mut want = vec![
            PathBuf::from(r"C:\a\5.txt"),
            PathBuf::from(r"\\Dropbox\other\a\4.txt"),
            PathBuf::from(r"\\Dropbox\work\b\3.txt"),
        ];
        want.sort();
        assert_eq!(kept(&inv), want);

        // A complete listing: what it does not name goes, a respelled path too.
        inv.record(vec![
            entry(r"\\Dropbox\work\b\old.txt"),
            entry(r"\\Dropbox\work\B\3.txt"),
        ])?;
        let full = [listed(r"\\Dropbox\work\b\3.txt", 1, 1)];
        assert_eq!(inv.forget_unlisted(root, &full)?, 2);
        assert_eq!(kept(&inv), want);
        assert_eq!(Inventory::open(&inv.path)?.entries(None, 0).len(), 3);
        Ok(())
    }
}
