//! The real side effects behind the controller: certificate, proxy, Windows proxy, settings, vault,
//! the Explorer menu, the shortcut of the highlight and the local API.

use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{Arc, OnceLock, mpsc::Sender},
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
    sys::{data_dir, write_atomic},
};

use super::{
    activity::Activity,
    controller::{Backend, Running},
};
use crate::{
    Res, ca,
    capture::{self, Capture},
    highlight::Overlay,
    proxy::{self, Event, ProxyHandle, Shared},
    shell, sysproxy,
};

/// The activity feed, next to the settings; see [`super::activity`].
const ACTIVITY_FILE: &str = "activity.cfg";

/// Talks to the machine.
pub struct System {
    /// The vault the engine opens.
    pub vault: PathBuf,
    /// The detection model; loaded while protection, the highlight, the inventory or a scan needs it.
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
        policy.save().map_err(|error| error.to_string())
    }

    fn open_engine(&self) -> Res<Engine> {
        Engine::open_with_model(&self.vault, self.ner.clone()).map_err(|error| error.to_string())
    }

    fn open_inventory(&self) -> Res<Inventory> {
        let path = Inventory::default_path().map_err(|error| error.to_string())?;
        Inventory::open(&path).map_err(|error| format!("{}: {error}", path.display()))
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
        .map_err(|error| error.to_string())
    }

    fn load_model(&self) -> Res<()> {
        self.ner.load().map(drop).map_err(|error| error.to_string())
    }

    fn release_model(&self) {
        self.ner.release();
    }

    fn start_http(&self, port: u16) -> Res<Box<dyn Running>> {
        let handler = self.api.get().cloned().ok_or("the API is not ready yet")?;
        let token = api::read_or_create_token(false).map_err(|error| error.to_string())?;
        let server = api::http::spawn(handler, port, token).map_err(|error| error.to_string())?;
        Ok(Box::new(server))
    }

    fn set_explorer_menu(&self, on: bool) -> Res<()> {
        if on {
            let exe = std::env::current_exe()
                .map_err(|error| format!("could not find piikey.exe: {error}"))?;
            shell::register(&exe)
        } else {
            shell::unregister()
        }
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
    let path = data_dir().map_err(|error| error.to_string())?.join(name);
    write_atomic(&path, text.as_bytes()).map_err(|error| error.to_string())
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
