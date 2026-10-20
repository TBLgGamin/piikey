//! The MITM proxy: HTTPS (and WebSocket) traffic of the selected sites and
//! programs is decrypted with the local CA, its personal data replaced by
//! proxies on the way out and restored on the way back. Everything else is
//! tunneled untouched.
//!
//! While the user's input is captured ([`Typed`]), an outgoing request is searched for what they
//! typed or pasted and nothing else; without capture, for every personal value it carries.
//!
//! The proxy runs on its own thread with its own tokio runtime;
//! [`ProxyHandle::stop`] ends both.

mod body;
mod events;
mod handler;
mod origin;
mod response;
mod transform;
pub mod typed;

#[cfg(test)]
mod test_names;
#[cfg(test)]
mod tests;

use std::{
    any::Any,
    net::{Ipv4Addr, TcpListener},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::pin,
    sync::{Arc, RwLock, mpsc::Sender},
    thread::JoinHandle,
    time::Duration,
};

use hudsucker::{
    Proxy,
    certificate_authority::RcgenAuthority,
    hyper_util::{
        client::legacy::{Builder as ClientBuilder, Client},
        rt::TokioExecutor,
        server::conn::auto::Builder as ServerBuilder,
    },
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};
use piikey::engine::Engine;
use tokio::{runtime::Runtime, sync::watch};

pub use self::typed::Typed;
use self::{
    handler::{Env, Interceptor, WsInterceptor},
    origin::Origin,
};
use crate::{Res, ca, ledger::Ledger, policy::Policy};

/// Default proxy port.
pub const PORT: u16 = 7979;

/// How long open connections get to finish after a stop before they are cut.
const GRACE: Duration = Duration::from_secs(3);
/// How long the runtime waits for its blocking work after that.
const RUNTIME_EXIT: Duration = Duration::from_secs(2);
/// Server certificates the proxy keeps ready.
const CERT_CACHE: u64 = 1_000;
/// Header bytes accepted per request or response over HTTP/2. hyper's default, 16 KiB, is less
/// than what sites like chatgpt.com send (cookies and tokens), and the browser then got a 431
/// from the proxy. Servers accept far more; 256 KiB covers any real site.
const MAX_HEADER_BYTES: u32 = 256 << 10;
/// Header lines accepted per request or response over HTTP/1.1 (hyper's default: 100).
const MAX_HEADER_LINES: usize = 512;

/// State shared by the proxy and the UI. `engine` can be swapped under a running proxy: the next
/// request uses the new one.
#[derive(Debug)]
pub struct Shared {
    pub engine: RwLock<Arc<Engine>>,
    pub policy: RwLock<Policy>,
    pub ledger: Ledger,
    /// What the user typed or pasted. While its capture runs, requests are masked by it alone.
    pub typed: Typed,
}

/// Something the UI counts and shows.
#[derive(Debug, Clone)]
pub enum Event {
    /// An outgoing request was anonymized. `kinds`: (kind name, count).
    Masked {
        host: String,
        exe: Option<String>,
        kinds: Vec<(&'static str, usize)>,
        /// Every issued proxy the request carried.
        proxies: Vec<String>,
    },
    /// A response had proxies restored.
    Restored { host: String, count: usize },
    /// The proxy can no longer serve (fatal: the thread or runtime failed).
    /// Problems with one request never use this; they show up in the answer
    /// that request gets.
    Error(String),
}

/// A running proxy; dropping it does not stop it, call [`ProxyHandle::stop`].
#[derive(Debug)]
pub struct ProxyHandle {
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl ProxyHandle {
    /// Stops the proxy and waits for its thread. Open connections get a few
    /// seconds to finish; the rest are cut.
    pub fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts the proxy on `127.0.0.1:port` on a background thread.
///
/// # Errors
/// CA or bind failure.
pub fn start(shared: Arc<Shared>, events: Sender<Event>, port: u16) -> Res<ProxyHandle> {
    let ca = ca::ensure()?;
    start_on(&ca, shared, events, bind(port)?, GRACE)
}

/// The listening socket on `127.0.0.1:port` (`0`: any free port). Loopback
/// only: the proxy must never be reachable from the network.
fn bind(port: u16) -> Res<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .map_err(|e| format!("cannot listen on 127.0.0.1:{port}: {e}"))
}

/// [`start`] on an already bound listener, with the CA given and the grace
/// period of [`ProxyHandle::stop`] chosen.
fn start_on(
    ca: &ca::Ca,
    shared: Arc<Shared>,
    events: Sender<Event>,
    listener: TcpListener,
    grace: Duration,
) -> Res<ProxyHandle> {
    let key = KeyPair::from_pem(&ca.key_pem).map_err(|e| format!("the CA key is unusable: {e}"))?;
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, key)
        .map_err(|e| format!("the CA certificate is unusable: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot use the proxy socket: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("cannot use the proxy socket: {e}"))?
        .port();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("piikey-proxy-worker")
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the proxy runtime: {e}"))?;

    let env = Env {
        shared,
        events: events.clone(),
        origin: Arc::new(Origin::new(port)),
    };
    let (stop, stopped) = watch::channel(false);
    let thread = std::thread::Builder::new()
        .name("piikey-proxy".to_owned())
        .spawn(move || serve(runtime, listener, issuer, env, &stopped, &events, grace))
        .map_err(|e| format!("cannot start the proxy thread: {e}"))?;
    Ok(ProxyHandle {
        stop,
        thread: Some(thread),
    })
}

/// The proxy thread: runs the proxy to its end, then reports an end nobody
/// asked for.
fn serve(
    runtime: Runtime,
    listener: TcpListener,
    issuer: Issuer<'static, KeyPair>,
    env: Env,
    stopped: &watch::Receiver<bool>,
    events: &Sender<Event>,
    grace: Duration,
) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(run(listener, issuer, env, stopped.clone(), grace))
    }));
    let asked = *stopped.borrow();
    let failure = match outcome {
        Ok(Ok(())) if asked => None,
        Ok(Ok(())) => Some("the proxy stopped unexpectedly".to_owned()),
        Ok(Err(e)) => Some(e),
        Err(panic) => Some(format!("the proxy crashed: {}", panic_message(&*panic))),
    };
    if let Some(failure) = failure {
        let _ = events.send(Event::Error(failure));
    }
    // Connections still open after the grace period are dropped with the
    // runtime; blocking work gets a moment to finish.
    runtime.shutdown_timeout(RUNTIME_EXIT);
}

/// Serves until stopped, then waits `grace` for open connections.
async fn run(
    listener: TcpListener,
    issuer: Issuer<'static, KeyPair>,
    env: Env,
    stopped: watch::Receiver<bool>,
    grace: Duration,
) -> Result<(), String> {
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| format!("cannot use the proxy socket: {e}"))?;
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(RcgenAuthority::new(
            issuer,
            CERT_CACHE,
            aws_lc_rs::default_provider(),
        ))
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_client(client_builder())
        .with_server(server_builder())
        .with_http_handler(Interceptor::new(env.clone()))
        .with_websocket_handler(WsInterceptor::new(env))
        .with_graceful_shutdown(stop_signal(stopped.clone()))
        .build()
        .map_err(|e| format!("cannot start the proxy: {e}"))?;
    // hudsucker's graceful shutdown waits for every open connection with no
    // limit, and a streaming reply or an idle tunnel can stay open forever.
    let mut serving = pin!(proxy.start());
    tokio::select! {
        done = &mut serving => done.map_err(|e| e.to_string()),
        () = cut_off(stopped, grace) => Ok(()),
    }
}

/// The side that talks to the browser: hudsucker's defaults, with room for big headers.
fn server_builder() -> ServerBuilder<TokioExecutor> {
    let mut server = ServerBuilder::new(TokioExecutor::new());
    server
        .http1()
        .title_case_headers(true)
        .preserve_header_case(true)
        .max_headers(MAX_HEADER_LINES);
    server.http2().max_header_list_size(MAX_HEADER_BYTES);
    server
}

/// The side that talks to the sites: hudsucker's defaults, with room for big headers.
fn client_builder() -> ClientBuilder {
    let mut client = Client::builder(TokioExecutor::new());
    client
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .http1_max_headers(MAX_HEADER_LINES)
        .http2_max_header_list_size(MAX_HEADER_BYTES);
    client
}

/// Completes when [`ProxyHandle::stop`] is called. A handle that is merely
/// dropped does not stop the proxy.
async fn stop_signal(mut stopped: watch::Receiver<bool>) {
    if stopped.wait_for(|&stop| stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Completes `grace` after the stop signal.
async fn cut_off(stopped: watch::Receiver<bool>, grace: Duration) {
    stop_signal(stopped).await;
    tokio::time::sleep(grace).await;
}

fn panic_message(panic: &(dyn Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_owned())
}
