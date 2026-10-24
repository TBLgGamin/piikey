//! Helpers shared by the tests of this module and of the API handler.

use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
        mpsc::Sender,
    },
};

use piikey::{
    engine::Engine,
    inventory::Inventory,
    policy::{Highlight, Policy},
};

use super::{
    activity::Activity,
    controller::{Backend, Change, Controller, Running, Started},
};
use crate::{
    Describe, Res,
    proxy::{Event, Shared},
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
        fs::create_dir_all(&dir).describe()?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

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
        "piikey-app-test-{}-{}-{tag}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::create_dir_all(&dir);
    MADE.with(|made| made.0.borrow_mut().push(dir.clone()));
    dir
}

/// A system that does nothing and succeeds, for tests that need a controller but do not look at
/// the machine: the certificate is trusted (unless a test asks for it missing), the model is
/// there, the proxy "starts".
pub struct Stub {
    vault: PathBuf,
    certificate: bool,
}

struct Nothing;

impl Running for Nothing {
    fn stop(self: Box<Self>) {}
}

impl Backend for Stub {
    fn ensure_ca(&self) -> Res<()> {
        Ok(())
    }

    fn ca_installed(&self) -> bool {
        self.certificate
    }

    fn install_ca(&self) -> Res<()> {
        Ok(())
    }

    fn start_proxy(&self, _shared: Arc<Shared>, _events: Sender<Event>) -> Res<Box<dyn Running>> {
        Ok(Box::new(Nothing))
    }

    fn enable_system_proxy(&self) -> Res<()> {
        Ok(())
    }

    fn disable_system_proxy(&self) -> Res<()> {
        Ok(())
    }

    fn start_capture(&self, _shared: Arc<Shared>) -> Res<Box<dyn Running>> {
        Ok(Box::new(Nothing))
    }

    fn save_policy(&self, _policy: &Policy) -> Res<()> {
        Ok(())
    }

    fn open_engine(&self) -> Res<Engine> {
        Engine::open(&self.vault).describe()
    }

    fn open_inventory(&self) -> Res<Inventory> {
        Inventory::open(&self.vault.with_file_name("inventory.jsonl")).describe()
    }

    fn open_watch(&self) -> Res<Inventory> {
        Inventory::open(&self.vault.with_file_name("watch.jsonl")).describe()
    }

    fn load_activity(&self) -> Activity {
        Activity::default()
    }

    fn save_activity(&self, _text: &str) -> Res<()> {
        Ok(())
    }

    fn model_installed(&self) -> bool {
        true
    }

    fn fetch_model(&self, _progress: &mut dyn FnMut(u64, u64)) -> Res<()> {
        Ok(())
    }

    fn load_model(&self) -> Res<()> {
        Ok(())
    }

    fn release_model(&self) {}

    fn token(&self, _rotate: bool) -> Res<String> {
        Ok("test-token".to_owned())
    }

    fn start_http(&self, _port: u16, _token: String) -> Res<Box<dyn Running>> {
        Ok(Box::new(Nothing))
    }

    fn set_explorer_menu(&self, _on: bool) -> Res<()> {
        Ok(())
    }

    fn set_hotkey(&self, _shared: &Shared, _on: bool) -> Res<()> {
        Ok(())
    }

    fn start_watch(&self, _folders: &[PathBuf], _changes: Sender<Change>) -> Res<Started> {
        Ok(Started {
            running: Box::new(Nothing),
            failed: Vec::new(),
        })
    }
}

/// A controller on a [`Stub`], its vault and inventory in `dir`, with the features that start on
/// their own switched off.
pub fn stub_controller(dir: &TempDir) -> Result<Arc<Controller>, String> {
    stub_controller_with(dir, true)
}

/// Like [`stub_controller`], with the certificate trusted or, with `certificate` false, missing.
pub fn stub_controller_with(dir: &TempDir, certificate: bool) -> Result<Arc<Controller>, String> {
    let vault = dir.0.join("vault.pkv");
    let engine = Engine::open(&vault).describe()?;
    let stub = Stub {
        vault: vault.clone(),
        certificate,
    };
    let inventory = stub.open_inventory()?;
    let watch = stub.open_watch()?;
    let policy = Policy {
        highlight: Highlight::Off,
        explorer_menu: false,
        ..Policy::default()
    };
    Controller::new(
        Box::new(stub),
        vault,
        policy,
        engine,
        inventory,
        watch,
        None,
    )
}
