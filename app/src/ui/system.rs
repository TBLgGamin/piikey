//! The real side effects behind the controller: certificate, proxy, Windows proxy, settings, vault.

use std::{
    path::PathBuf,
    sync::{Arc, mpsc::Sender},
};

use piikey::{
    detect::{NerDetector, ner::files},
    engine::Engine,
};

use super::{
    activity::Activity,
    controller::{Backend, Running},
    stats::Stats,
};
use crate::{
    Res, ca,
    capture::{self, Capture},
    model,
    policy::{Policy, data_dir, write_atomic},
    proxy::{self, Event, ProxyHandle, Shared},
    sysproxy,
};

/// Daily counts, next to the settings; see [`super::stats`].
// The file name is kept for existing installs.
const STATS_FILE: &str = "stats.cfg";
/// The activity feed, next to the settings; see [`super::activity`].
const ACTIVITY_FILE: &str = "activity.cfg";

/// Talks to the machine.
pub struct System {
    /// The vault the engine opens.
    pub vault: PathBuf,
    /// The detection model; loaded while protection is on.
    pub ner: NerDetector,
    /// Where the model files live.
    pub model_dir: PathBuf,
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
        policy.save()
    }

    fn open_engine(&self) -> Res<Engine> {
        Engine::open_with_model(&self.vault, self.ner.clone()).map_err(|error| error.to_string())
    }

    fn model_installed(&self) -> bool {
        files::is_installed(&self.model_dir)
    }

    fn fetch_model(&self, progress: &mut dyn FnMut(u64, u64)) -> Res<()> {
        model::fetch(&self.model_dir, progress)
    }

    fn load_model(&self) -> Res<()> {
        self.ner.load().map(drop).map_err(|error| error.to_string())
    }

    fn release_model(&self) {
        self.ner.release();
    }

    fn load_stats(&self) -> Stats {
        data_dir()
            .ok()
            .and_then(|dir| std::fs::read_to_string(dir.join(STATS_FILE)).ok())
            .map(|text| Stats::parse(&text))
            .unwrap_or_default()
    }

    fn save_stats(&self, text: &str) -> Res<()> {
        write_atomic(&data_dir()?.join(STATS_FILE), text.as_bytes())
    }

    fn load_activity(&self) -> Activity {
        data_dir()
            .ok()
            .and_then(|dir| std::fs::read_to_string(dir.join(ACTIVITY_FILE)).ok())
            .map(|text| Activity::parse(&text))
            .unwrap_or_default()
    }

    fn save_activity(&self, text: &str) -> Res<()> {
        write_atomic(&data_dir()?.join(ACTIVITY_FILE), text.as_bytes())
    }
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
