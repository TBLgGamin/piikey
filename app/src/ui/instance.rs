//! One app per Windows user. A second one would take the proxy port, the tray icon and the
//! Windows proxy settings from the first, and its clean-up at launch would undo the first one's
//! work.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
    thread,
    time::{Duration, Instant},
};

use crate::Res;

// The file name is kept for existing installs, so an old and a new build still lock each other out.
const FILE_NAME: &str = "guard.lock";

/// Proof that this is the only app of the user. Windows drops the lock when the process ends,
/// however it ends, so an app that crashed never keeps the next one out.
#[derive(Debug)]
pub struct Instance {
    _lock: File,
}

/// How often [`Instance::acquire`] tries again while it waits.
const RETRY: Duration = Duration::from_millis(50);

impl Instance {
    /// Takes the lock in `folder`, trying for up to `wait`; `Ok(None)` when another process still
    /// holds it then. Waiting covers an app that is still ending, and its watchdog's clean-up.
    ///
    /// # Errors
    /// The lock file cannot be created or locked.
    pub fn acquire(folder: &Path, wait: Duration) -> Res<Option<Self>> {
        let path = folder.join(FILE_NAME);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|error| format!("could not open {}: {error}", path.display()))?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Some(Self { _lock: file })),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(RETRY),
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Error(error)) => {
                    return Err(format!("could not lock {}: {error}", path.display()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::testing::TempDir;

    #[test]
    fn a_second_app_is_refused_until_the_first_is_gone() -> Result<(), String> {
        let dir = TempDir::new()?;
        let first = Instance::acquire(&dir.0, Duration::ZERO)?;
        assert!(first.is_some());
        assert!(Instance::acquire(&dir.0, Duration::from_millis(120))?.is_none());
        drop(first);
        assert!(Instance::acquire(&dir.0, Duration::ZERO)?.is_some());
        Ok(())
    }

    #[test]
    fn a_lock_let_go_while_waiting_is_taken() -> Result<(), String> {
        let dir = TempDir::new()?;
        let first = Instance::acquire(&dir.0, Duration::ZERO)?;
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(first);
        });
        let second = Instance::acquire(&dir.0, Duration::from_secs(5))?;
        releaser.join().map_err(|_| "releaser panicked")?;
        assert!(second.is_some());
        Ok(())
    }

    #[test]
    fn a_folder_that_does_not_exist_is_an_error() -> Result<(), String> {
        let dir = TempDir::new()?;
        let error = Instance::acquire(&dir.0.join("missing"), Duration::ZERO)
            .err()
            .ok_or("expected an error")?;
        assert!(error.contains("guard.lock"), "{error}");
        Ok(())
    }
}
