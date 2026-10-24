//! The real side effects behind the controller: certificate, proxy, Windows proxy, settings, vault,
//! the Explorer menu, the shortcut of the highlight and the local API.

use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{Arc, OnceLock, mpsc::Sender},
    time::Duration,
};

use piikey::{
    api::{self, Handler},
    detect::{
        NerDetector,
        ner::{self, files},
    },
    engine::Engine,
    inventory::Inventory,
    policy::Policy,
    service::Server,
    sys::{data_dir, is_packaged, launch_path, write_atomic},
};

use super::{
    activity::Activity,
    assets,
    controller::{Backend, Change, Running, Started},
    watcher,
};
use crate::{
    Describe, Res, ca,
    capture::{self, Capture},
    highlight::Overlay,
    proxy::{self, Event, ProxyHandle, Shared},
    shell, sysproxy,
};

/// The activity feed, next to the settings; see [`super::activity`].
const ACTIVITY_FILE: &str = "activity.cfg";

/// How long the detection model stays in memory after a scan or a read of findings, when nothing
/// else needs it: long enough to look at what a scan found, which reads the same texts again
/// (the model remembers its answers for them), and to read the findings of another file.
const MODEL_IDLE: Duration = Duration::from_mins(2);

/// Talks to the machine.
pub struct System {
    /// The vault the engine opens.
    pub vault: PathBuf,
    /// The detection model; loaded while protection, the highlight, the watch or a scan needs it.
    pub ner: NerDetector,
    /// Where the model files live.
    pub model_dir: PathBuf,
    /// What the local HTTP API serves. It needs the controller, which needs this backend, so
    /// [`ui::open`](super::open) fills it once the controller exists, before anything starts the API.
    pub api: Arc<OnceLock<Arc<dyn Handler>>>,
}

impl Backend for System {
    fn ensure_ca(&self) -> Res<()> {
        ca::ensure().map(drop)
    }

    fn ca_installed(&self) -> bool {
        ca::is_installed()
    }

    fn install_ca(&self) -> Res<()> {
        ca::install()
    }

    fn start_proxy(&self, shared: Arc<Shared>, events: Sender<Event>) -> Res<Box<dyn Running>> {
        let handle = proxy::start(shared, events, proxy::PORT)?;
        Ok(Box::new(handle))
    }

    fn start_capture(&self, shared: Arc<Shared>) -> Res<Box<dyn Running>> {
        let capture = capture::start(&shared)?;
        Ok(Box::new(capture))
    }

    fn enable_system_proxy(&self) -> Res<()> {
        sysproxy::enable(proxy::PORT)
    }

    fn disable_system_proxy(&self) -> Res<()> {
        sysproxy::disable()
    }

    fn save_policy(&self, policy: &Policy) -> Res<()> {
        policy.save().describe()
    }

    fn open_engine(&self) -> Res<Engine> {
        Engine::open_with_model(&self.vault, self.ner.clone()).describe()
    }

    fn open_inventory(&self) -> Res<Inventory> {
        let path = Inventory::default_path().describe()?;
        Inventory::open(&path).map_err(|error| format!("{}: {error}", path.display()))
    }

    fn open_watch(&self) -> Res<Inventory> {
        let path = Inventory::watch_path().describe()?;
        Inventory::open(&path).map_err(|error| format!("{}: {error}", path.display()))
    }

    fn start_watch(&self, folders: &[PathBuf], changes: Sender<Change>) -> Res<Started> {
        watcher::start(folders, changes)
    }

    fn model_installed(&self) -> bool {
        files::is_installed(&self.model_dir)
    }

    fn fetch_model(&self, progress: &mut dyn FnMut(u64, u64)) -> Res<()> {
        // The library reports through a shared `Fn`; this runs on one thread and never re-enters.
        let progress = RefCell::new(progress);
        ner::fetch(&self.model_dir, &|done, total| {
            (progress.borrow_mut())(done, total);
        })
        .describe()
    }

    fn load_model(&self) -> Res<()> {
        self.ner.load().map(drop).describe()
    }

    fn release_model(&self) {
        self.ner.release();
    }

    fn model_idle(&self) -> Duration {
        MODEL_IDLE
    }

    fn token(&self, rotate: bool) -> Res<String> {
        api::read_or_create_token(rotate).describe()
    }

    fn start_http(&self, port: u16, token: String) -> Res<Box<dyn Running>> {
        let handler = self.api.get().cloned().ok_or("the API is not ready yet")?;
        let server = api::http::spawn(handler, port, token).describe()?;
        Ok(Box::new(server))
    }

    fn set_explorer_menu(&self, on: bool) -> Res<()> {
        if !on {
            return shell::unregister();
        }
        let launcher =
            launch_path().map_err(|error| format!("could not find piikey.exe: {error}"))?;
        // Explorer cannot read an icon out of the execution alias of a packaged app: the icon
        // file that the tray icon uses stands in for it.
        let icon = if is_packaged() {
            assets::icon_file(&self.vault)?
        } else {
            launcher.clone()
        };
        shell::register(&launcher, &icon)
    }

    fn set_hotkey(&self, shared: &Shared, on: bool) -> Res<()> {
        if on {
            return Overlay::get_or_start(&shared.purpose)?.set_hotkey(true);
        }
        // Nothing to give back when the overlay never started.
        Overlay::get().map_or(Ok(()), |overlay| overlay.set_hotkey(false))
    }

    fn load_activity(&self) -> Activity {
        data_dir()
            .ok()
            .and_then(|dir| std::fs::read_to_string(dir.join(ACTIVITY_FILE)).ok())
            .map(|text| Activity::parse(&text))
            .unwrap_or_default()
    }

    fn save_activity(&self, text: &str) -> Res<()> {
        write_data(ACTIVITY_FILE, text)
    }
}

/// Writes `text` to the file `name` in the data folder, so a reader sees the old or the new file.
fn write_data(name: &str, text: &str) -> Res<()> {
    let path = data_dir().describe()?.join(name);
    write_atomic(&path, text.as_bytes()).describe()
}

impl Running for ProxyHandle {
    fn stop(self: Box<Self>) {
        Self::stop(*self);
    }
}

impl Running for Capture {
    fn stop(self: Box<Self>) {
        Self::stop(*self);
    }
}

impl Running for Server {
    fn stop(self: Box<Self>) {
        Self::stop(*self);
    }
}
