//! The controller against a recording fake of the system.

mod edit;
mod inventory;
mod keyed;
mod model;
mod protection;
mod settings;

use std::{
    fs,
    sync::atomic::{AtomicBool, Ordering},
};

use piikey::detect::EntityKind;

use super::*;
use crate::{Describe, ui::testing::TempDir};

type Test = Result<(), String>;

/// Calls the fake saw, in order.
type Calls = Arc<Mutex<Vec<String>>>;

/// Settings with the features that start on their own switched off: protection is then the
/// only thing that runs capture and holds the model, as it was before the features existed.
fn quiet() -> Policy {
    Policy {
        highlight: Highlight::Off,
        explorer_menu: false,
        ..Policy::default()
    }
}

#[derive(Default)]
struct Fake {
    calls: Calls,
    installed: AtomicBool,
    fail_start: AtomicBool,
    fail_enable: AtomicBool,
    fail_capture: AtomicBool,
    /// The detection model cannot be loaded.
    fail_load: AtomicBool,
    fail_disable: AtomicBool,
    fail_save: AtomicBool,
    fail_engine: AtomicBool,
    /// The detection model is not downloaded yet.
    model_missing: AtomicBool,
    fetch_fails: AtomicBool,
    events: Mutex<Option<Sender<Event>>>,
    vault: PathBuf,
    /// The local API cannot start.
    fail_http: AtomicBool,
    /// The Explorer menu cannot be changed.
    fail_menu: AtomicBool,
    /// The shortcut of the highlight is taken.
    fail_hotkey: AtomicBool,
    /// What `load_activity` returns.
    loaded_activity: Activity,
    /// Every text `save_activity` got.
    saved_activity: Mutex<Vec<String>>,
    /// Every policy `save_policy` got, also the ones it refused.
    saved: Mutex<Vec<Policy>>,
    /// Runs once, at the next `load_model`: what happens meanwhile, to a scan that has just read
    /// the settings.
    on_load: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Fake {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The policy `save_policy` got last.
    fn last_saved(&self) -> Result<Policy, String> {
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .cloned()
            .ok_or_else(|| "nothing was saved".to_owned())
    }
}

struct FakeProxy(Calls);

impl Running for FakeProxy {
    fn stop(self: Box<Self>) {
        log(&self.0, "stop_proxy");
    }
}

struct FakeCapture(Calls);

impl Running for FakeCapture {
    fn stop(self: Box<Self>) {
        log(&self.0, "stop_capture");
    }
}

struct FakeHttp(Calls);

impl Running for FakeHttp {
    fn stop(self: Box<Self>) {
        log(&self.0, "stop_http");
    }
}

fn log(calls: &Calls, call: &str) {
    calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(call.to_owned());
}

fn fails(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}

impl Backend for Arc<Fake> {
    fn ensure_ca(&self) -> Res<()> {
        log(&self.calls, "ensure_ca");
        Ok(())
    }

    fn ca_installed(&self) -> bool {
        log(&self.calls, "ca_installed");
        self.installed.load(Ordering::Relaxed)
    }

    fn install_ca(&self) -> Res<()> {
        log(&self.calls, "install_ca");
        self.installed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn start_proxy(&self, _shared: Arc<Shared>, events: Sender<Event>) -> Res<Box<dyn Running>> {
        log(&self.calls, "start_proxy");
        if fails(&self.fail_start) {
            return Err("port in use".into());
        }
        *self.events.lock().unwrap_or_else(PoisonError::into_inner) = Some(events);
        Ok(Box::new(FakeProxy(Arc::clone(&self.calls))))
    }

    fn enable_system_proxy(&self) -> Res<()> {
        log(&self.calls, "enable_system_proxy");
        if fails(&self.fail_enable) {
            return Err("registry".into());
        }
        Ok(())
    }

    fn disable_system_proxy(&self) -> Res<()> {
        log(&self.calls, "disable_system_proxy");
        if fails(&self.fail_disable) {
            return Err("registry".into());
        }
        Ok(())
    }

    fn start_capture(&self, _shared: Arc<Shared>) -> Res<Box<dyn Running>> {
        log(&self.calls, "start_capture");
        if fails(&self.fail_capture) {
            return Err("no uia".into());
        }
        Ok(Box::new(FakeCapture(Arc::clone(&self.calls))))
    }

    fn save_policy(&self, policy: &Policy) -> Res<()> {
        log(&self.calls, "save_policy");
        self.saved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(policy.clone());
        if fails(&self.fail_save) {
            return Err("disk full".into());
        }
        Ok(())
    }

    fn open_engine(&self) -> Res<Engine> {
        log(&self.calls, "open_engine");
        if fails(&self.fail_engine) {
            return Err("vault locked".into());
        }
        Engine::open(&self.vault).describe()
    }

    fn open_inventory(&self) -> Res<Inventory> {
        Inventory::open(&self.vault.with_file_name("inventory.jsonl")).describe()
    }

    fn token(&self, _rotate: bool) -> Res<String> {
        Ok("test-token".to_owned())
    }

    fn start_http(&self, port: u16, _token: String) -> Res<Box<dyn Running>> {
        log(&self.calls, &format!("start_http({port})"));
        if fails(&self.fail_http) {
            return Err("port in use".into());
        }
        Ok(Box::new(FakeHttp(Arc::clone(&self.calls))))
    }

    fn set_explorer_menu(&self, on: bool) -> Res<()> {
        log(&self.calls, &format!("set_explorer_menu({on})"));
        if fails(&self.fail_menu) {
            return Err("registry".into());
        }
        Ok(())
    }

    fn set_hotkey(&self, _shared: &Shared, on: bool) -> Res<()> {
        log(&self.calls, &format!("set_hotkey({on})"));
        if fails(&self.fail_hotkey) {
            return Err("Ctrl+Alt+P is used by another program".into());
        }
        Ok(())
    }

    fn model_installed(&self) -> bool {
        !fails(&self.model_missing)
    }

    fn fetch_model(&self, progress: &mut dyn FnMut(u64, u64)) -> Res<()> {
        log(&self.calls, "fetch_model");
        progress(50, 100);
        if fails(&self.fetch_fails) {
            return Err("offline".into());
        }
        self.model_missing.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn load_model(&self) -> Res<()> {
        log(&self.calls, "load_model");
        let hook = self
            .on_load
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(hook) = hook {
            hook();
        }
        if fails(&self.fail_load) {
            return Err("no gpu".into());
        }
        Ok(())
    }

    fn release_model(&self) {
        log(&self.calls, "release_model");
    }

    fn load_activity(&self) -> Activity {
        self.loaded_activity.clone()
    }

    fn save_activity(&self, text: &str) -> Res<()> {
        self.saved_activity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(text.to_owned());
        Ok(())
    }
}

struct Rig {
    controller: Arc<Controller>,
    fake: Arc<Fake>,
    _dir: TempDir,
}

fn rig(installed: bool, policy: Policy) -> Result<Rig, String> {
    let dir = TempDir::new()?;
    let vault = dir.0.join("vault.pkv");
    let fake = Arc::new(Fake {
        installed: AtomicBool::new(installed),
        vault: vault.clone(),
        ..Fake::default()
    });
    let engine = Engine::open(&vault).describe()?;
    let inventory = fake.open_inventory()?;
    let controller = Controller::new(
        Box::new(Arc::clone(&fake)),
        vault,
        policy,
        engine,
        inventory,
        None,
    )?;
    Ok(Rig {
        controller,
        fake,
        _dir: dir,
    })
}

impl Rig {
    fn run(&self, command: Command) -> Test {
        self.controller.submit(command);
        if self.controller.wait_idle(Duration::from_secs(20)) {
            Ok(())
        } else {
            Err("command did not finish".into())
        }
    }

    fn calls(&self) -> Vec<String> {
        self.fake.calls()
    }

    fn forget_calls(&self) {
        self.fake
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn live(&self) -> bool {
        self.controller.policy().enabled
    }

    fn notice(&self) -> Option<Notice> {
        self.controller.snapshot().notice
    }
}

/// A controller started the way the app starts it, and what the fake saw.
struct Launched {
    fake: Arc<Fake>,
    outcome: Res<Arc<Controller>>,
    _dir: TempDir,
}

impl Launched {
    fn controller(&self) -> Result<&Arc<Controller>, String> {
        self.outcome.as_ref().map_err(Clone::clone)
    }

    fn failure(&self) -> Result<&str, String> {
        self.outcome
            .as_ref()
            .err()
            .map(String::as_str)
            .ok_or_else(|| "the launch should have failed".to_owned())
    }
}

/// Launches with the saved wish `saved_on`; `setup` sets the fake up first.
fn launch(installed: bool, saved_on: bool, setup: impl FnOnce(&Fake)) -> Result<Launched, String> {
    let policy = Policy {
        enabled: saved_on,
        ..quiet()
    };
    launch_with(installed, policy, setup)
}

/// Launches with the saved `policy`; `setup` sets the fake up first.
fn launch_with(
    installed: bool,
    policy: Policy,
    setup: impl FnOnce(&Fake),
) -> Result<Launched, String> {
    let dir = TempDir::new()?;
    let vault = dir.0.join("vault.pkv");
    let fake = Arc::new(Fake {
        installed: AtomicBool::new(installed),
        vault: vault.clone(),
        ..Fake::default()
    });
    setup(&fake);
    let outcome = Controller::launch(Box::new(Arc::clone(&fake)), vault, policy, None);
    if let Ok(controller) = &outcome
        && !controller.wait_idle(Duration::from_secs(20))
    {
        return Err("the launch commands did not finish".into());
    }
    Ok(Launched {
        fake,
        outcome,
        _dir: dir,
    })
}

fn fail(flag: &AtomicBool) {
    flag.store(true, Ordering::Relaxed);
}

/// Waits until `done` holds for a snapshot and every queued command has finished.
fn wait_for(controller: &Controller, done: impl Fn(&Snapshot) -> bool) -> Result<Snapshot, String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut snapshot = controller.snapshot();
    while !done(&snapshot) {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| format!("timed out at {snapshot:?}"))?;
        if let Some(next) = controller.wait_changed(snapshot.version, left) {
            snapshot = next;
        }
    }
    if !controller.wait_idle(Duration::from_secs(20)) {
        return Err("commands did not finish".into());
    }
    Ok(controller.snapshot())
}

/// Waits until `done` holds.
fn eventually(what: &str, done: impl Fn() -> bool) -> Test {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for {what}"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn has_call(rig: &Rig, call: &str) -> bool {
    rig.calls().iter().any(|c| c == call)
}
