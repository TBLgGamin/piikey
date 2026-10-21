//! Helpers shared by the unit tests.

use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

/// The folders [`temp_dir`] made on this thread, removed when the thread ends. The test harness
/// runs every test on a thread of its own, so that is when the test is done, after its locals
/// (an engine holding the vault open) are dropped, and also when it failed.
struct Made(RefCell<Vec<PathBuf>>);

impl Drop for Made {
    fn drop(&mut self) {
        for dir in self.0.get_mut().drain(..) {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

thread_local! {
    static MADE: Made = const { Made(RefCell::new(Vec::new())) };
}

/// A fresh, empty folder under the system temp folder, removed when the calling test ends.
pub fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "piikey-test-{}-{}-{tag}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::create_dir_all(&dir);
    MADE.with(|made| made.0.borrow_mut().push(dir.clone()));
    dir
}
