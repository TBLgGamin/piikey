//! The named pipe the app and `piikey-cli serve` answer API requests on, and the client that
//! calls it.
//!
//! Request: `b'P', 2, 0, 0, u32 len`, then `len` bytes of JSON, an [`api::Request`].
//! Response: `status (0 ok, 1 error), 0, 0, 0, u32 len`, then `len` bytes of JSON, the
//! [envelope](api::envelope) of the reply. All integers are little-endian.
//!
//! A connection serves one request after the other until the client leaves. A request that is
//! no valid JSON request is answered with an error and the connection goes on. One that breaks
//! the framing (a bad magic, a payload that is too long) is answered with an error and the
//! connection is closed, and so is the old binary protocol, version 1, which is no longer
//! served.
//!
//! The pipe is `\\.\pipe\piikey-<user>`, see [`default_pipe`]: only the app (or one
//! `piikey-cli serve`) owns it at a time.

use std::{
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions},
    sync::Notify,
};

use crate::{
    Error, Result,
    api::{self, ApiError, Handler, Request},
    sys::io_context,
};

const MAGIC: u8 = b'P';
const VERSION: u8 = 2;
const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;
/// Largest accepted request payload.
const MAX_PAYLOAD: usize = 512 * 1024 * 1024;
/// What a client of the removed binary protocol is told.
const V1_REMOVED: &str = "pipe protocol version 1 was removed; send version 2 (JSON)";
/// `ERROR_PIPE_BUSY`: every instance of the pipe has a client; one will be free in a moment.
const ERROR_PIPE_BUSY: i32 = 231;
/// How long a client waits between two tries to connect to a busy pipe.
const RETRY: Duration = Duration::from_millis(10);
/// How long stopping a server waits for requests that are still running before it lets go of
/// them: their threads end when the work does, or with the process.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
/// What a reply that cannot be encoded is replaced with.
const UNENCODABLE: &[u8] =
    br#"{"ok":false,"error":{"code":"internal","message":"the reply could not be encoded"}}"#;

/// The pipe of this user: `\\.\pipe\piikey-<USERNAME>`, so that two users of one machine do not
/// share one. Characters of the name other than letters, digits, `.`, `_` and `-` become `_`;
/// without a name it is `user`.
#[must_use]
pub fn default_pipe() -> String {
    let user = std::env::var_os("USERNAME").map(|name| name.to_string_lossy().into_owned());
    pipe_for(user.as_deref())
}

fn pipe_for(user: Option<&str>) -> String {
    let user = user.filter(|name| !name.is_empty()).unwrap_or("user");
    let safe: String = user
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(r"\\.\pipe\piikey-{safe}")
}

/// A response ready to be written: 8-byte header, then payload.
#[derive(Debug)]
struct Frame {
    header: [u8; 8],
    payload: Vec<u8>,
}

/// Validates a request header and returns the payload length.
fn parse_request_header(h: [u8; 8]) -> Result<usize> {
    if h[0] != MAGIC {
        return Err(Error::Protocol("bad magic"));
    }
    match h[1] {
        VERSION => {}
        1 => return Err(Error::BadRequest(V1_REMOVED.to_owned())),
        _ => return Err(Error::Protocol("unsupported protocol version")),
    }
    let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Protocol("payload too large"));
    }
    Ok(len)
}

/// Builds a response frame around a JSON body. A body that does not fit a `u32` length becomes
/// an error frame instead.
fn frame(status: u8, body: Vec<u8>) -> Frame {
    let Ok(len) = u32::try_from(body.len()) else {
        return reply_frame(Err(ApiError::internal("the reply is too large")));
    };
    let len = len.to_le_bytes();
    Frame {
        header: [status, 0, 0, 0, len[0], len[1], len[2], len[3]],
        payload: body,
    }
}

/// The frame that carries `reply`, as its envelope.
fn reply_frame(reply: Result<Value, ApiError>) -> Frame {
    let status = if reply.is_ok() { STATUS_OK } else { STATUS_ERR };
    match serde_json::to_vec(&api::envelope(reply)) {
        Ok(body) => frame(status, body),
        Err(_) => frame(STATUS_ERR, UNENCODABLE.to_vec()),
    }
}

/// Reads a request and has `handler` answer it. Runs on a blocking thread: parsing a big
/// request and answering it is work.
fn dispatch(handler: &dyn Handler, payload: &[u8]) -> Result<Value, ApiError> {
    let request: Request = serde_json::from_slice(payload)
        .map_err(|e| ApiError::bad_request(format!("not a request: {e}")))?;
    handler.handle(request)
}

async fn write_frame(pipe: &mut NamedPipeServer, f: &Frame) -> io::Result<()> {
    pipe.write_all(&f.header).await?;
    pipe.write_all(&f.payload).await?;
    pipe.flush().await
}

/// Serves requests on one connection until the client leaves or breaks the framing.
async fn handle_connection(mut pipe: NamedPipeServer, handler: Arc<dyn Handler>) -> io::Result<()> {
    loop {
        let mut header = [0_u8; 8];
        pipe.read_exact(&mut header).await?;
        let len = match parse_request_header(header) {
            Ok(len) => len,
            Err(e) => return write_frame(&mut pipe, &reply_frame(Err(e.into()))).await,
        };
        // `take` + `read_to_end` grows with the bytes that actually arrive, so a client
        // announcing 512 MiB and sending nothing costs nothing.
        let mut payload = Vec::new();
        let got = AsyncReadExt::take(&mut pipe, len as u64)
            .read_to_end(&mut payload)
            .await?;
        if got < len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let handler = Arc::clone(&handler);
        let reply = tokio::task::spawn_blocking(move || dispatch(handler.as_ref(), &payload))
            .await
            // The handler panicked: that request fails, the connection and the server live on.
            .unwrap_or_else(|_| Err(ApiError::internal("the request failed unexpectedly")));
        write_frame(&mut pipe, &reply_frame(reply)).await?;
    }
}

fn server_options() -> ServerOptions {
    let mut options = ServerOptions::new();
    options
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte);
    options
}

/// Creates the first instance of `pipe`, which fails when another server owns the name.
fn first_instance(pipe: &str) -> Result<NamedPipeServer> {
    server_options()
        .first_pipe_instance(true)
        .create(pipe)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied
                || e.raw_os_error() == Some(ERROR_PIPE_BUSY)
            {
                Error::Busy(
                    "the piikey app (or another piikey-cli serve) already serves the API"
                        .to_owned(),
                )
            } else {
                io_context(&e, "create", Path::new(pipe))
            }
        })
}

/// Accepts connections until `stop` is notified.
async fn serve_pipe(
    first: NamedPipeServer,
    pipe: String,
    handler: Arc<dyn Handler>,
    stop: Arc<Notify>,
) -> Result<()> {
    let stopped = stop.notified();
    tokio::pin!(stopped);
    let mut server = first;
    loop {
        tokio::select! {
            () = &mut stopped => return Ok(()),
            connected = server.connect() => connected?,
        }
        let client = server;
        // The next instance must exist before this client is handed off, or a second client
        // would find no pipe to connect to.
        server = server_options().create(&pipe)?;
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            // A broken connection only ends that connection.
            let _ = handle_connection(client, handler).await;
        });
    }
}

/// A server on a thread of its own: the pipe's, see [`spawn`], or the HTTP API's, see
/// [`api::http::spawn`]. Dropping it stops it, like [`Server::stop`].
#[derive(Debug)]
#[must_use = "dropping a server stops it"]
pub struct Server {
    stop: Arc<Notify>,
    thread: Option<JoinHandle<Result<()>>>,
}

impl Server {
    /// Runs the server `serve` makes on a thread of its own, on a runtime of its own with that
    /// one thread. `bind` makes what the server listens on, inside that runtime, and the
    /// caller gets its error here and now rather than from the thread.
    pub(crate) fn start<L, Fut>(
        name: &str,
        bind: impl FnOnce() -> Result<L>,
        serve: impl FnOnce(L, Arc<Notify>) -> Fut + Send + 'static,
    ) -> Result<Self>
    where
        L: Send + 'static,
        Fut: Future<Output = Result<()>>,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let bound = {
            let _inside = runtime.enter();
            bind()
        };
        let listener = match bound {
            Ok(listener) => listener,
            Err(error) => {
                // Dropping a runtime waits; in an async caller that would panic.
                runtime.shutdown_background();
                return Err(error);
            }
        };
        let stop = Arc::new(Notify::new());
        let signal = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let result = runtime.block_on(serve(listener, signal));
                runtime.shutdown_timeout(SHUTDOWN_WAIT);
                result
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Stops the server and waits until it has stopped: connections are closed, and a request
    /// that is still being answered is given a moment to finish.
    pub fn stop(mut self) {
        self.shut_down();
    }

    /// Waits until the server ends by itself, which it does only when it fails.
    ///
    /// # Errors
    /// The error that ended the server, or `Io` when its thread panicked.
    pub fn wait(mut self) -> Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread.join().unwrap_or_else(|_| {
            Err(Error::Io(io::Error::other(
                "the API server stopped unexpectedly",
            )))
        })
    }

    fn shut_down(&mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            // A server that failed has nobody to tell: whoever cared called `wait`.
            let _ = thread.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// Serves `handler` on the named pipe `pipe`, on a thread of its own, until the [`Server`] is
/// stopped or dropped.
///
/// # Errors
/// `Busy` when the pipe already has a server (the app, or another `piikey-cli serve`); `Io`
/// when it cannot be created.
pub fn spawn(handler: Arc<dyn Handler>, pipe: &str) -> Result<Server> {
    let name = pipe.to_owned();
    Server::start(
        "piikey-api-pipe",
        || first_instance(pipe),
        move |first, stop| serve_pipe(first, name, handler, stop),
    )
}

/// Opens `pipe` for a call: `None` when there is no such pipe, and after `timeout` an error
/// when it exists and stays busy.
fn connect(pipe: &str, timeout: Duration) -> Result<Option<File>> {
    let deadline = Instant::now() + timeout;
    loop {
        match OpenOptions::new().read(true).write(true).open(pipe) {
            Ok(file) => return Ok(Some(file)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if Instant::now() >= deadline {
                    return Err(Error::Busy(format!(
                        "the piikey service at {pipe} is busy; try again in a moment"
                    )));
                }
                thread::sleep(RETRY);
            }
            Err(e) => return Err(io_context(&e, "connect to", Path::new(pipe))),
        }
    }
}

/// Sends `request` to the server on `pipe` and returns its reply, the whole
/// [envelope](api::envelope) (read it with [`api::open_envelope`]). `Ok(None)` means nobody is
/// listening on `pipe`. A pipe that is busy is tried again for up to `connect_timeout`; there is
/// no limit on how long the answer may take, since a scan of a big folder does.
///
/// # Errors
/// `BadRequest` when the request cannot be sent (a path that is no text, a payload over 512
/// MiB); `Busy` when the pipe stays busy; `Io` when talking to the server fails; `Protocol`
/// when what it answers is no reply.
pub fn call(pipe: &str, request: &Request, connect_timeout: Duration) -> Result<Option<Value>> {
    let body = serde_json::to_vec(request)
        .map_err(|e| Error::BadRequest(format!("cannot encode the request: {e}")))?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&len| len as usize <= MAX_PAYLOAD)
        .ok_or_else(|| Error::BadRequest("the request is too large".to_owned()))?
        .to_le_bytes();
    let Some(mut file) = connect(pipe, connect_timeout)? else {
        return Ok(None);
    };
    let talk = |e: io::Error| io_context(&e, "talk to", Path::new(pipe));
    file.write_all(&[MAGIC, VERSION, 0, 0, len[0], len[1], len[2], len[3]])
        .map_err(talk)?;
    file.write_all(&body).map_err(talk)?;
    let mut header = [0_u8; 8];
    file.read_exact(&mut header).map_err(talk)?;
    if header[0] > STATUS_ERR {
        return Err(Error::Protocol("bad reply"));
    }
    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let mut payload = Vec::new();
    let got = Read::take(&mut file, len as u64)
        .read_to_end(&mut payload)
        .map_err(talk)?;
    if got < len {
        return Err(Error::Protocol("reply truncated"));
    }
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|_| Error::Protocol("the reply is not JSON"))
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as StdError,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
    };

    use serde_json::json;

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    fn header(magic: u8, version: u8, len: u32) -> [u8; 8] {
        let l = len.to_le_bytes();
        [magic, version, 0, 0, l[0], l[1], l[2], l[3]]
    }

    /// A pipe name no other test uses.
    fn test_pipe(what: &str) -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!(
            r"\\.\pipe\piikey-test-{}-{what}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Answers what the tests ask: echoes texts, refuses a wipe, panics on a status.
    struct Stub;

    impl Handler for Stub {
        fn handle(&self, request: Request) -> Result<Value, ApiError> {
            match request {
                Request::ScanText { texts } => Ok(json!({ "echo": texts })),
                Request::VaultWipe { .. } => Err(ApiError::busy("not now")),
                Request::Status => panic!("the stub was told to panic"),
                other => Ok(json!({ "op": other.op() })),
            }
        }
    }

    fn serve_stub(pipe: &str) -> Result<Server> {
        spawn(Arc::new(Stub), pipe)
    }

    fn ask(pipe: &str, request: &Request) -> std::result::Result<Value, Box<dyn StdError>> {
        let reply = call(pipe, request, Duration::from_secs(5))?.ok_or("nobody listening")?;
        Ok(reply)
    }

    #[test]
    fn header_accepts_version_2() -> TestResult {
        assert_eq!(parse_request_header(header(b'P', 2, 7))?, 7);
        assert_eq!(parse_request_header(header(b'P', 2, 0))?, 0);
        Ok(())
    }

    #[test]
    fn header_rejects_bad_magic_and_versions() {
        for h in [header(b'X', 2, 0), header(b'P', 0, 0), header(b'P', 3, 0)] {
            assert!(matches!(parse_request_header(h), Err(Error::Protocol(_))));
        }
        match parse_request_header(header(b'P', 1, 12)) {
            Err(Error::BadRequest(message)) => assert_eq!(message, V1_REMOVED),
            other => panic!("version 1 was not refused as removed: {other:?}"),
        }
    }

    #[test]
    fn header_enforces_length_limit() -> TestResult {
        let max = u32::try_from(MAX_PAYLOAD)?;
        assert_eq!(parse_request_header(header(b'P', 2, max))?, MAX_PAYLOAD);
        assert!(matches!(
            parse_request_header(header(b'P', 2, max + 1)),
            Err(Error::Protocol("payload too large"))
        ));
        Ok(())
    }

    #[test]
    fn frame_layout() -> TestResult {
        let f = frame(STATUS_ERR, b"{}".to_vec());
        assert_eq!(f.header, [1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(f.payload, b"{}");

        let ok = reply_frame(Ok(json!({"a": 1})));
        assert_eq!(ok.header[0], STATUS_OK);
        let body: Value = serde_json::from_slice(&ok.payload)?;
        assert_eq!(body, json!({"ok": true, "result": {"a": 1}}));
        assert_eq!(
            usize::try_from(u32::from_le_bytes([
                ok.header[4],
                ok.header[5],
                ok.header[6],
                ok.header[7]
            ]))?,
            ok.payload.len()
        );

        let failed = reply_frame(Err(Error::Protocol("bad magic").into()));
        assert_eq!(failed.header[0], STATUS_ERR);
        let body: Value = serde_json::from_slice(&failed.payload)?;
        assert_eq!(
            body,
            json!({"ok": false, "error": {"code": "bad_request", "message": "protocol: bad magic"}})
        );
        Ok(())
    }

    #[test]
    fn the_default_pipe_names_the_user() {
        assert_eq!(pipe_for(Some("jan")), r"\\.\pipe\piikey-jan");
        assert_eq!(pipe_for(Some("Jan Jansen")), r"\\.\pipe\piikey-Jan_Jansen");
        assert_eq!(pipe_for(Some("a.b_c-d")), r"\\.\pipe\piikey-a.b_c-d");
        assert_eq!(pipe_for(Some(r"DOM\jan")), r"\\.\pipe\piikey-DOM_jan");
        assert_eq!(pipe_for(Some("zoë")), r"\\.\pipe\piikey-zo_");
        assert_eq!(pipe_for(Some("")), r"\\.\pipe\piikey-user");
        assert_eq!(pipe_for(None), r"\\.\pipe\piikey-user");
        assert!(default_pipe().starts_with(r"\\.\pipe\piikey-"));
    }

    #[test]
    fn nobody_listening_is_none() -> TestResult {
        let pipe = test_pipe("nobody");
        assert!(call(&pipe, &Request::Kinds, Duration::from_millis(50))?.is_none());
        Ok(())
    }

    #[test]
    fn requests_round_trip_through_the_pipe() -> TestResult {
        let pipe = test_pipe("roundtrip");
        let server = serve_stub(&pipe)?;

        let reply = ask(
            &pipe,
            &Request::ScanText {
                texts: vec!["héllo".into(), "wörld".into()],
            },
        )?;
        assert_eq!(
            reply,
            json!({"ok": true, "result": {"echo": ["héllo", "wörld"]}})
        );
        assert_eq!(
            api::open_envelope(reply)?,
            json!({"echo": ["héllo", "wörld"]})
        );

        // Errors are envelopes too, and the server goes on.
        let reply = ask(&pipe, &Request::VaultWipe { confirm: true })?;
        let error = api::open_envelope(reply).err().ok_or("expected an error")?;
        assert_eq!((error.code(), error.message()), ("busy", "not now"));
        assert_eq!(ask(&pipe, &Request::Kinds)?["result"]["op"], "kinds");

        // A big request: the payload is read in pieces.
        let big = "x".repeat(3 * 1024 * 1024);
        let reply = ask(
            &pipe,
            &Request::ScanText {
                texts: vec![big.clone()],
            },
        )?;
        assert_eq!(
            reply["result"]["echo"][0].as_str().map(str::len),
            Some(big.len())
        );

        // A handler that panics fails that request only.
        let reply = ask(&pipe, &Request::Status)?;
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "internal");
        assert_eq!(ask(&pipe, &Request::Kinds)?["result"]["op"], "kinds");

        // The name is owned: a second server on it is told so.
        let second = serve_stub(&pipe)
            .err()
            .ok_or("a second server was started")?;
        assert!(matches!(second, Error::Busy(_)), "{second}");

        server.stop();
        assert!(call(&pipe, &Request::Kinds, Duration::from_millis(50))?.is_none());
        Ok(())
    }

    /// A client that writes the bytes itself.
    struct Raw(File);

    impl Raw {
        fn connect(pipe: &str) -> std::result::Result<Self, Box<dyn StdError>> {
            let file = connect(pipe, Duration::from_secs(5))?.ok_or("nobody listening")?;
            Ok(Self(file))
        }

        fn send(&mut self, header: [u8; 8], payload: &[u8]) -> TestResult {
            self.0.write_all(&header)?;
            self.0.write_all(payload)?;
            Ok(())
        }

        fn reply(&mut self) -> std::result::Result<(u8, Value), Box<dyn StdError>> {
            let mut h = [0_u8; 8];
            self.0.read_exact(&mut h)?;
            let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
            let mut payload = vec![0_u8; len];
            self.0.read_exact(&mut payload)?;
            Ok((h[0], serde_json::from_slice(&payload)?))
        }

        fn closed(&mut self) -> bool {
            let mut rest = [0_u8; 1];
            matches!(self.0.read(&mut rest), Ok(0) | Err(_))
        }
    }

    #[test]
    fn version_1_is_refused_and_the_connection_closed() -> TestResult {
        let pipe = test_pipe("v1");
        let server = serve_stub(&pipe)?;
        let mut old = Raw::connect(&pipe)?;
        // A version 1 ping: op 5, no payload.
        old.send([b'P', 1, 5, 0, 0, 0, 0, 0], b"")?;
        let (status, body) = old.reply()?;
        assert_eq!(status, STATUS_ERR);
        assert_eq!(
            body,
            json!({"ok": false, "error": {"code": "bad_request", "message": V1_REMOVED}})
        );
        assert!(old.closed());
        server.stop();
        Ok(())
    }

    #[test]
    fn broken_framing_is_answered_and_closes_the_connection() -> TestResult {
        let pipe = test_pipe("framing");
        let server = serve_stub(&pipe)?;
        for bad in [
            [b'X', 2, 0, 0, 0, 0, 0, 0],
            [b'P', 9, 0, 0, 0, 0, 0, 0],
            header(b'P', 2, u32::MAX),
        ] {
            let mut client = Raw::connect(&pipe)?;
            client.send(bad, b"")?;
            let (status, body) = client.reply()?;
            assert_eq!(status, STATUS_ERR);
            assert_eq!(body["error"]["code"], "bad_request");
            assert!(client.closed());
        }
        server.stop();
        Ok(())
    }

    #[test]
    fn a_bad_request_is_answered_and_the_connection_survives() -> TestResult {
        let pipe = test_pipe("badjson");
        let server = serve_stub(&pipe)?;
        let mut client = Raw::connect(&pipe)?;
        for bad in [
            &b"not json"[..],
            br#"{"op":"no_such_op"}"#,
            br#"{"op":"scan_text","texts":[],"surprise":1}"#,
            &[0xFF, 0xFE],
        ] {
            client.send(header(b'P', 2, u32::try_from(bad.len())?), bad)?;
            let (status, body) = client.reply()?;
            assert_eq!(status, STATUS_ERR, "{}", String::from_utf8_lossy(bad));
            assert_eq!(body["error"]["code"], "bad_request");
        }
        let good = br#"{"op":"kinds"}"#;
        client.send(header(b'P', 2, u32::try_from(good.len())?), good)?;
        let (status, body) = client.reply()?;
        assert_eq!(
            (status, &body["result"]["op"]),
            (STATUS_OK, &json!("kinds"))
        );
        server.stop();
        Ok(())
    }

    #[test]
    fn many_clients_at_once_are_all_answered() -> TestResult {
        let pipe = test_pipe("many");
        let server = serve_stub(&pipe)?;
        let clients: Vec<_> = (0..8)
            .map(|n| {
                let pipe = pipe.clone();
                thread::spawn(move || -> std::result::Result<(), String> {
                    for i in 0..25 {
                        let text = format!("{n}-{i}");
                        let request = Request::ScanText {
                            texts: vec![text.clone()],
                        };
                        let reply = call(&pipe, &request, Duration::from_secs(5))
                            .map_err(|e| e.to_string())?
                            .ok_or("nobody listening")?;
                        if reply["result"]["echo"][0] != text.as_str() {
                            return Err(format!("wrong answer: {reply}"));
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        for client in clients {
            client.join().map_err(|_| "a client panicked")??;
        }
        server.stop();
        Ok(())
    }

    /// Holds a request until the test lets it go.
    struct Gated {
        started: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Handler for Gated {
        fn handle(&self, request: Request) -> Result<Value, ApiError> {
            if matches!(request, Request::ModelDownload) {
                let _ = self.started.lock().map(|started| started.send(()));
                let released = self
                    .release
                    .lock()
                    .map(|release| release.recv_timeout(Duration::from_secs(20)));
                if !matches!(released, Ok(Ok(()))) {
                    return Err(ApiError::internal("never released"));
                }
            }
            Ok(json!({ "op": request.op() }))
        }
    }

    #[test]
    fn a_slow_request_does_not_hold_up_the_others() -> TestResult {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gated = Gated {
            started: Mutex::new(started_tx),
            release: Mutex::new(release_rx),
        };
        let pipe = test_pipe("gated");
        let server = spawn(Arc::new(gated), &pipe)?;
        let slow = {
            let pipe = pipe.clone();
            thread::spawn(move || {
                call(&pipe, &Request::ModelDownload, Duration::from_secs(5))
                    .map_err(|e| e.to_string())
            })
        };
        started_rx.recv_timeout(Duration::from_secs(20))?;
        // The slow request is being answered; another client is served meanwhile.
        assert_eq!(ask(&pipe, &Request::Kinds)?["result"]["op"], "kinds");
        assert!(!slow.is_finished());
        release_tx.send(())?;
        let reply = slow.join().map_err(|_| "the slow client panicked")??;
        assert_eq!(
            reply.ok_or("nobody listening")?["result"]["op"],
            "model_download"
        );
        server.stop();
        Ok(())
    }

    #[test]
    fn a_dropped_server_gives_the_pipe_back() -> TestResult {
        let pipe = test_pipe("drop");
        drop(serve_stub(&pipe)?);
        let again = serve_stub(&pipe)?;
        assert_eq!(ask(&pipe, &Request::Kinds)?["result"]["op"], "kinds");
        again.stop();
        Ok(())
    }

    #[test]
    fn a_pipe_name_that_is_no_pipe_is_not_busy() {
        let error = serve_stub("not-a-pipe-name").err();
        assert!(matches!(error, Some(Error::Io(_))), "{error:?}");
    }
}
