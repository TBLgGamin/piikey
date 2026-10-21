//! Windows plumbing the CLI, the API and the app share: the data folder, atomic and exclusive
//! file writes, file locks, DPAPI, random bytes, path comparison and the tools that ship in
//! System32.

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Write},
    os::windows::process::CommandExt,
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{Duration, Instant},
};

use windows_dpapi::{Scope, decrypt_data, encrypt_data};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// `CREATE_NO_WINDOW`: console tools run from the GUI must not flash a window.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `%LOCALAPPDATA%\piikey` (created): the vault, the settings, the certificate, the model and the
/// inventory live here.
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` when the folder cannot be created.
pub fn data_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|base| !base.is_empty())
        .ok_or(Error::VaultPathUnavailable)?;
    let dir = PathBuf::from(base).join("piikey");
    fs::create_dir_all(&dir).map_err(|e| io_context(&e, "create", &dir))?;
    Ok(dir)
}

/// Writes `bytes` to a temp file beside `path`, syncs it and renames it over `path`, so readers
/// see the old or the new file, never a torn one. Every call has a temp file of its own, so
/// writers of one file (threads, or the CLI and the app) cannot tear each other's: the last
/// rename wins.
///
/// # Errors
/// `Io` on any I/O failure, naming `path`; the temp file is removed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_path(path);
    let written = File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_context(&e, "write", path)
    })
}

/// What a temp file of [`write_atomic`] ends in.
const TEMP_SUFFIX: &str = ".tmp";

/// A name beside `path` that no other write uses: the process id and a count make
/// `<file>.<pid>-<n>.tmp`.
fn temp_path(path: &Path) -> PathBuf {
    static WRITES: AtomicU32 = AtomicU32::new(0);
    let mut name = path.as_os_str().to_owned();
    name.push(format!(
        ".{}-{}{TEMP_SUFFIX}",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(name)
}

/// Removes the temp files an interrupted [`write_atomic`] of `path` left beside it, and the
/// `<file>.tmp` that older versions left. For the owner of `path` to call when nothing is
/// writing it: the temp file of a write that is still running would go too.
pub fn remove_temps(path: &Path) {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return;
    };
    let Ok(entries) = fs::read_dir(folder_of(path)) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|candidate| is_temp_of(candidate, name))
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// The folder `path` is in: `.` for a bare file name, whose `parent()` is the empty path, which
/// no file system call takes.
fn folder_of(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Whether `candidate` is `<name>.<pid>-<n>.tmp` or the older `<name>.tmp`.
fn is_temp_of(candidate: &str, name: &str) -> bool {
    let Some(rest) = candidate
        .strip_prefix(name)
        .and_then(|rest| rest.strip_suffix(TEMP_SUFFIX))
    else {
        return false;
    };
    let number = |digits: &str| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    rest.is_empty()
        || rest
            .strip_prefix('.')
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(pid, count)| number(pid) && number(count))
}

/// Creates the file `path`, which must not exist (an existing file is somebody's and is never
/// replaced), and its folder when missing, lets `write` fill it, syncs it to disk and returns
/// what `write` returns. A file that was not written whole is removed again.
///
/// # Errors
/// `Io` naming the path when the file or folder cannot be created or synced; whatever `write`
/// fails with.
pub fn write_new<T>(path: &Path, write: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
    let dir = folder_of(path);
    fs::create_dir_all(dir).map_err(|e| io_context(&e, "create", dir))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io_context(&e, "create", path))?;
    let written = write(&mut file).and_then(|value| {
        file.sync_all().map_err(|e| io_context(&e, "write", path))?;
        Ok(value)
    });
    if written.is_err() {
        drop(file);
        // Best effort: the file is ours, and half of it is of no use to anyone.
        let _ = fs::remove_file(path);
    }
    written
}

/// A lock on a file, taken with [`try_lock`] and released when dropped.
#[derive(Debug)]
pub struct FileLock(File);

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing the handle releases the lock as well, but Windows may take its time over that;
        // a failure here is harmless.
        let _ = self.0.unlock();
    }
}

/// Takes an exclusive lock on the file `path` (made when missing, its contents untouched)
/// without waiting: one holder at a time, across processes and across handles in this one.
/// Windows drops the lock when the process ends, however it ends, so a crash never keeps the
/// next holder out.
///
/// # Errors
/// `Io` when the file cannot be opened or locked; `Ok(None)` when somebody else holds the lock.
pub fn try_lock(path: &Path) -> Result<Option<FileLock>> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| io_context(&e, "open", path))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(FileLock(file))),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(io_context(&e, "lock", path)),
    }
}

/// How often [`lock_within`] tries again.
const LOCK_RETRY: Duration = Duration::from_millis(50);

/// [`try_lock`], tried again every 50 ms for up to `wait` while somebody else holds the lock:
/// for a lock that is held only for a short while, or by a process that is still ending.
///
/// # Errors
/// `Io` when the file cannot be opened or locked; `Ok(None)` when somebody still holds the lock
/// after `wait`.
pub fn lock_within(path: &Path, wait: Duration) -> Result<Option<FileLock>> {
    let deadline = Instant::now() + wait;
    loop {
        if let Some(lock) = try_lock(path)? {
            return Ok(Some(lock));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(LOCK_RETRY);
    }
}

/// Fills `buf` from the operating system's random number generator.
///
/// # Errors
/// `Io` when the system has no random bytes to give.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Io(io::Error::other(e)))
}

/// Wraps `plain` so only the current Windows user on this machine can unwrap it. `entropy` binds
/// the blob to one purpose: it unwraps only with the same.
///
/// # Errors
/// `Dpapi` when Windows refuses.
pub fn dpapi_protect(plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    encrypt_data(plain, Scope::User, Some(entropy)).map_err(|e| Error::Dpapi(format!("{e:#}")))
}

/// Inverse of [`dpapi_protect`]; the plain bytes are wiped when dropped.
///
/// # Errors
/// `Dpapi` when the blob is damaged, was wrapped for another user or machine, or with other
/// `entropy`.
pub fn dpapi_unprotect(blob: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_data(blob, Scope::User, Some(entropy))
        .map(Zeroizing::new)
        .map_err(|e| Error::Dpapi(format!("{e:#}")))
}

/// `error` as an [`Error::Io`] that says what was being done to which file ("cannot read
/// C:\...\guard.cfg: Access is denied."). The kind is kept, so callers can still match on it.
pub(crate) fn io_context(error: &io::Error, doing: &str, path: &Path) -> Error {
    Error::Io(io::Error::new(
        error.kind(),
        format!("cannot {doing} {}: {error}", path.display()),
    ))
}

/// Whether `path` is `prefix` or lies below it, component by component. Windows ignores letter
/// case in names, and so does this: see [`same_component`].
#[must_use]
pub fn is_under(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix
        .components()
        .all(|want| path.next().is_some_and(|have| same_component(have, want)))
}

/// Whether `a` and `b` are one path spelled alike: the same components, whatever their letter
/// case, and with or without a trailing separator.
#[must_use]
pub fn same_path(a: &Path, b: &Path) -> bool {
    let mut b = b.components();
    a.components()
        .all(|part| b.next().is_some_and(|other| same_component(part, other)))
        && b.next().is_none()
}

/// `path` as a key that every spelling of it shares, for a hash set: each component in
/// lowercase (see [`same_component`]), whatever the separators and a trailing one. Paths have
/// one key exactly when [`same_path`] says they are the same.
#[must_use]
pub(crate) fn path_key(path: &Path) -> String {
    let mut key = String::new();
    for component in path.components() {
        if !key.is_empty() {
            key.push('\\');
        }
        key.push_str(&component.as_os_str().to_string_lossy().to_lowercase());
    }
    key
}

/// Whether two path components name the same file or folder. Windows ignores letter case in
/// names in every script, not only in ASCII.
#[must_use]
pub fn same_component(a: Component<'_>, b: Component<'_>) -> bool {
    let (a, b) = (a.as_os_str(), b.as_os_str());
    // The cheap check settles nearly every comparison; lowercasing costs an allocation.
    a.eq_ignore_ascii_case(b)
        || a.to_str().zip(b.to_str()).is_some_and(|(a, b)| {
            !(a.is_ascii() && b.is_ascii()) && a.to_lowercase() == b.to_lowercase()
        })
}

/// A command for `tool` (e.g. `curl.exe`) from `%SystemRoot%\System32` with no console window
/// and stdin closed; the caller adds arguments and pipes.
///
/// # Errors
/// `Tool` when the tool is not in System32.
pub fn system_command(tool: &str) -> Result<Command> {
    let root = std::env::var_os("SystemRoot")
        .filter(|root| !root.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let path = root.join("System32").join(tool);
    if !path.is_file() {
        return Err(Error::Tool(format!("{tool} was not found in System32")));
    }
    let mut command = Command::new(path);
    command
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

/// Runs `tool` (e.g. `certutil.exe`) from `%SystemRoot%\System32` with no console window and
/// waits for it. A non-zero exit is not an error here; callers read the status.
///
/// # Errors
/// `Tool` when the tool is missing or cannot be started.
pub fn run_system_tool(tool: &str, args: &[&str]) -> Result<Output> {
    system_command(tool)?
        .args(args)
        .output()
        .map_err(|e| Error::Tool(format!("cannot run {tool}: {e}")))
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::testing::temp_dir;

    #[test]
    fn the_data_dir_is_the_piikey_folder_under_localappdata() -> Result<()> {
        match data_dir() {
            Ok(dir) => {
                assert!(dir.ends_with("piikey"), "{dir:?}");
                assert!(dir.is_dir());
            }
            Err(Error::VaultPathUnavailable) => {
                assert!(std::env::var_os("LOCALAPPDATA").is_none_or(|v| v.is_empty()));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    #[test]
    fn writing_replaces_the_file_and_leaves_no_temp_file() -> Result<()> {
        let dir = temp_dir("atomic");
        let path = dir.join("a.cfg");
        write_atomic(&path, b"one")?;
        write_atomic(&path, b"two")?;
        assert_eq!(fs::read(&path)?, b"two");
        assert_eq!(fs::read_dir(&dir)?.count(), 1, "no temp file stays behind");
        Ok(())
    }

    #[test]
    fn writers_of_one_file_never_share_a_temp_file() -> Result<()> {
        let dir = temp_dir("racing");
        let path = dir.join("a.cfg");
        // Different lengths, so a mix of the two would show.
        let (one, two) = ("1".repeat(8192), "2".repeat(512));
        let results: Vec<Result<()>> = thread::scope(|scope| {
            let writers: Vec<_> = [&one, &two]
                .into_iter()
                .map(|text| {
                    scope.spawn(|| (0..200).try_for_each(|_| write_atomic(&path, text.as_bytes())))
                })
                .collect();
            writers
                .into_iter()
                .map(|writer| writer.join().unwrap_or(Err(Error::Poisoned)))
                .collect()
        });
        for result in results {
            result?;
        }
        let written = fs::read(&path)?;
        assert!(
            written == one.as_bytes() || written == two.as_bytes(),
            "a torn file of {} bytes",
            written.len()
        );
        assert_eq!(fs::read_dir(&dir)?.count(), 1, "no temp file stays behind");
        Ok(())
    }

    #[test]
    fn a_failed_write_names_the_file_and_keeps_the_error_kind() {
        let dir = temp_dir("failed");
        let path = dir.join("missing-folder").join("a.cfg");
        let message = match write_atomic(&path, b"x") {
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => e.to_string(),
            other => panic!("expected a NotFound I/O error, got {other:?}"),
        };
        assert!(message.contains("cannot write"), "{message}");
        assert!(message.contains("a.cfg"), "{message}");
    }

    #[test]
    fn a_bare_file_name_is_in_the_current_folder() {
        // `Path::parent` says the empty path, and `read_dir("")` fails: temps beside a relative
        // path would never be swept.
        assert_eq!(folder_of(Path::new("a.cfg")), Path::new("."));
        assert_eq!(folder_of(Path::new(r"C:\x\a.cfg")), Path::new(r"C:\x"));
    }

    #[test]
    fn only_the_temp_files_of_that_file_are_removed() -> Result<()> {
        let dir = temp_dir("temps");
        let target = dir.join("a.cfg");
        let leftovers = ["a.cfg.4242-7.tmp", "a.cfg.tmp"];
        let keep = [
            "a.cfg",
            "a.cfg.bak",
            "a.cfg.x-7.tmp",
            "a.cfg.4242-.tmp",
            "b.cfg.1-1.tmp",
        ];
        for name in leftovers.into_iter().chain(keep) {
            fs::write(dir.join(name), b"x")?;
        }
        remove_temps(&target);
        for name in leftovers {
            assert!(!dir.join(name).exists(), "{name} stays");
        }
        for name in keep {
            assert!(dir.join(name).exists(), "{name} is gone");
        }
        // What `write_atomic` itself would name.
        let own = temp_path(&target);
        fs::write(&own, b"x")?;
        remove_temps(&target);
        assert!(!own.exists());
        Ok(())
    }

    #[test]
    fn a_new_file_is_made_with_its_folder_and_an_existing_one_is_never_replaced() -> Result<()> {
        let dir = temp_dir("new");
        let path = dir.join("deeper").join("report.csv");
        let rows = write_new(&path, |file| {
            file.write_all(b"a,b\n")?;
            Ok(1)
        })?;
        assert_eq!(rows, 1);
        assert_eq!(fs::read(&path)?, b"a,b\n");
        match write_new(&path, |_| Ok(())) {
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                assert!(e.to_string().contains("report.csv"), "{e}");
            }
            other => panic!("expected an AlreadyExists error, got {other:?}"),
        }
        assert_eq!(fs::read(&path)?, b"a,b\n", "the first file is untouched");
        Ok(())
    }

    #[test]
    fn a_file_that_was_not_written_whole_is_removed_again() {
        let dir = temp_dir("half");
        let path = dir.join("half.csv");
        let result: Result<()> = write_new(&path, |file| {
            file.write_all(b"half of it")?;
            Err(Error::BadRequest("stopped".into()))
        });
        assert!(matches!(result, Err(Error::BadRequest(_))), "{result:?}");
        assert!(!path.exists());
    }

    #[test]
    fn a_lock_has_one_holder_until_it_is_dropped() -> Result<()> {
        let dir = temp_dir("lock");
        let path = dir.join("some.lock");
        let held = try_lock(&path)?;
        assert!(held.is_some());
        assert!(try_lock(&path)?.is_none(), "a second holder is refused");
        drop(held);
        assert!(try_lock(&path)?.is_some(), "free again once dropped");
        Ok(())
    }

    #[test]
    fn a_lock_let_go_while_waiting_is_taken() -> Result<()> {
        let path = temp_dir("lock-wait").join("some.lock");
        let held = try_lock(&path)?;
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(held);
        });
        let taken = lock_within(&path, Duration::from_secs(5))?;
        releaser.join().map_err(|_| Error::Poisoned)?;
        assert!(taken.is_some());
        Ok(())
    }

    #[test]
    fn a_lock_still_held_after_the_wait_is_not_taken() -> Result<()> {
        let path = temp_dir("lock-held").join("some.lock");
        let _held = try_lock(&path)?;
        assert!(lock_within(&path, Duration::from_millis(120))?.is_none());
        Ok(())
    }

    #[test]
    fn a_lock_in_a_missing_folder_is_an_error_that_names_the_file() {
        let path = temp_dir("lock-missing").join("nope").join("some.lock");
        match try_lock(&path) {
            Err(Error::Io(e)) => assert!(e.to_string().contains("some.lock"), "{e}"),
            other => panic!("expected an I/O error, got {other:?}"),
        }
    }

    #[test]
    fn wrapped_bytes_unwrap_only_with_their_entropy() -> Result<()> {
        let blob = dpapi_protect(b"secret key", b"purpose one")?;
        assert_ne!(blob, b"secret key");
        assert_eq!(&**dpapi_unprotect(&blob, b"purpose one")?, b"secret key");
        assert!(matches!(
            dpapi_unprotect(&blob, b"purpose two"),
            Err(Error::Dpapi(_))
        ));
        assert!(matches!(
            dpapi_unprotect(b"not a blob", b"purpose one"),
            Err(Error::Dpapi(_))
        ));
        Ok(())
    }

    #[test]
    fn paths_are_compared_by_component_and_without_case() {
        let under = |path: &str, prefix: &str| is_under(Path::new(path), Path::new(prefix));
        assert!(under(r"C:\Users\Jan\a.txt", r"c:\users\jan"));
        assert!(under(r"C:\Users\Jan", r"C:\Users\Jan"));
        assert!(under(r"C:\Users\Jan\", r"C:\Users\Jan"));
        assert!(!under(r"C:\Users\Jansen\a.txt", r"C:\Users\Jan"));
        assert!(!under(r"C:\Users", r"C:\Users\Jan"));
        assert!(!under(r"D:\Users\Jan", r"C:\Users\Jan"));
    }

    #[test]
    fn letter_case_is_ignored_in_every_script() {
        let under = |path: &str, prefix: &str| is_under(Path::new(path), Path::new(prefix));
        assert!(under(r"C:\Users\JÜRGEN\Ärzte\a.txt", r"c:\users\jürgen"));
        assert!(under(r"C:\Données\Élodie", r"C:\DONNÉES\élodie"));
        assert!(under(r"C:\Ελλάδα\a", r"C:\ΕΛΛΆΔΑ"));
        assert!(!under(r"C:\Jürgen", r"C:\Jurgen"));
    }

    #[test]
    fn paths_are_the_same_ignoring_case_and_a_trailing_separator() {
        let same = |a: &str, b: &str| same_path(Path::new(a), Path::new(b));
        assert!(same(r"C:\Users\jan", r"c:\users\JAN"));
        assert!(same(r"C:\Users\jan\", r"C:\Users\jan"));
        assert!(same(r"C:\Users\jan", r"C:\Users\jan\"));
        assert!(same(r"C:\Users\Jürgen", r"C:\USERS\JÜRGEN"));
        assert!(!same(r"C:\Users\jan", r"C:\Users\jan\Documents"));
        assert!(!same(r"C:\Users\jan\Documents", r"C:\Users\jan"));
        assert!(!same(r"C:\Users\jan", r"D:\Users\jan"));
    }

    #[test]
    fn the_spellings_of_one_path_share_a_key_and_no_other_path_does() {
        let pairs = [
            (r"C:\Users\jan", r"c:\users\JAN"),
            (r"C:\Users\jan\", r"C:\Users\jan"),
            ("C:/Users/jan", r"C:\Users\jan"),
            (r"C:\Users\Jürgen\a.txt", r"C:\USERS\JÜRGEN\A.TXT"),
            (r"C:\Users\jan", r"D:\Users\jan"),
            (r"C:\Users\jan", r"C:\Users\jan\Documents"),
            (r"C:\Jürgen", r"C:\Jurgen"),
        ];
        for (a, b) in pairs {
            let (a, b) = (Path::new(a), Path::new(b));
            assert_eq!(path_key(a) == path_key(b), same_path(a, b), "{a:?} {b:?}");
        }
    }

    #[test]
    fn a_missing_tool_is_a_tool_error() {
        assert!(matches!(
            system_command("piikey-no-such-tool.exe"),
            Err(Error::Tool(message)) if message.contains("piikey-no-such-tool.exe")
        ));
    }

    #[test]
    fn a_system_tool_runs_and_its_output_is_captured() -> Result<()> {
        let out = run_system_tool("cmd.exe", &["/C", "echo", "piikey"])?;
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("piikey"));
        Ok(())
    }
}
