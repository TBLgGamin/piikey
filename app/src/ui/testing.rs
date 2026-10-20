//! Helpers shared by the tests of this module.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};

/// A fresh folder under the system temp folder, removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Result<Self, String> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "piikey-app-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
