//! The proxy end to end: a real proxy on a loopback port between a client
//! and a small HTTP server, over plain HTTP. (The TLS path needs a trusted CA
//! and a real certificate chain upstream; it is exercised by hand.)

use std::{
    net::{SocketAddr, TcpListener as StdListener},
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError, RwLock, mpsc},
    time::{Duration, Instant},
};

use hudsucker::{
    futures::{SinkExt, StreamExt},
    rcgen::{CertifiedKey, generate_simple_self_signed},
    rustls::{
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    },
    tokio_tungstenite::{
        WebSocketStream, accept_async,
        tungstenite::{Message as WsMessage, protocol::Role},
    },
};
use piikey::{detect::Mode, engine::Engine};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::events::{
    Framing,
    fixtures::{anthropic, ndjson, openai, sse_events, texts},
};
use super::*;
use crate::{Res, ca};

fn io<T>(result: std::io::Result<T>) -> Res<T> {
    result.map_err(|e| e.to_string())
}

fn core<T>(result: piikey::Result<T>) -> Res<T> {
    result.map_err(|e| e.to_string())
}

fn utf8(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or("<not utf-8>")
}

/// A request as the server saw it.
#[derive(Debug, Clone)]
struct Received {
    /// Request line and headers.
    head: String,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }
}

/// How the server answers.
#[derive(Debug, Clone)]
enum Reply {
    /// The request body back, as JSON.
    Echo,
    /// The body back with a letter doubled in its first email-like token.
    Typo,
    /// Server-sent events carrying the email-like token of the request, cut
    /// in two chunks in the middle of it.
    SplitStream,
    /// These bytes with this content type.
    Fixed(&'static str, Vec<u8>),
}

struct Server {
    seen: Mutex<Vec<Received>>,
    reply: Mutex<Reply>,
}

impl Server {
    fn seen(&self) -> Vec<Received> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    fn reply_with(&self, reply: Reply) {
        if let Ok(mut current) = self.reply.lock() {
            *current = reply;
        }
    }

    async fn serve(&self, socket: &mut TcpStream) -> std::io::Result<()> {
        let request = read_request(socket).await?;
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(request.clone());
        }
        let reply = self.reply.lock().map_or(Reply::Echo, |reply| reply.clone());
        let body = String::from_utf8_lossy(&request.body).into_owned();
        let (content_type, answer) = match reply {
            Reply::SplitStream => return stream_split_email(socket, &body).await,
            Reply::Echo => ("application/json", request.body.clone()),
            Reply::Typo => ("application/json", with_typo(&body).into_bytes()),
            Reply::Fixed(content_type, bytes) => (content_type, bytes),
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            answer.len()
        );
        socket.write_all(head.as_bytes()).await?;
        socket.write_all(&answer).await?;
        socket.shutdown().await
    }
}

/// A chunked event stream whose first chunk ends inside the email-like token
/// of `body`.
async fn stream_split_email(socket: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let token = email_span(body).map_or("none", |span| &body[span]);
    let (head, tail) = token.split_at(token.len() / 2);
    socket
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
              Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .await?;
    for piece in [
        format!("data: write to {head}"),
        format!("{tail} please\n\n"),
    ] {
        socket
            .write_all(format!("{:x}\r\n{piece}\r\n", piece.len()).as_bytes())
            .await?;
        socket.flush().await?;
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    socket.write_all(b"0\r\n\r\n").await?;
    socket.shutdown().await
}

/// Where the first email-like token of `text` is.
fn email_span(text: &str) -> Option<Range<usize>> {
    let at = text.find('@')?;
    let word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    let start = text[..at].rfind(|c| !word(c)).map_or(0, |i| i + 1);
    let end = text[at + 1..]
        .find(|c| !word(c))
        .map_or(text.len(), |i| at + 1 + i);
    Some(start..end)
}

/// `text` with the third letter of its first email-like token doubled: a typo.
fn with_typo(text: &str) -> String {
    let Some(span) = email_span(text) else {
        return text.to_owned();
    };
    let third = text[span.clone()].chars().nth(2).unwrap_or('x');
    let mut out = text.to_owned();
    out.insert(span.start + 2, third);
    out
}

async fn read_request(socket: &mut TcpStream) -> std::io::Result<Received> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&buffer[..n]);
    };
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    while data.len() < head_end + length {
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
    }
    Ok(Received {
        head,
        body: data[head_end..].to_vec(),
    })
}

/// Decodes a `Transfer-Encoding: chunked` body.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = raw.windows(2).position(|w| w == b"\r\n") {
        let size = std::str::from_utf8(&raw[..line_end])
            .ok()
            .and_then(|hex| usize::from_str_radix(hex.trim(), 16).ok())
            .unwrap_or(0);
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        let end = (start + size).min(raw.len());
        out.extend_from_slice(&raw[start..end]);
        raw = raw.get(end + 2..).unwrap_or(&[]);
    }
    out
}

/// Sends `request` to the proxy and reads the whole answer: `(head, body)`.
async fn through_proxy(proxy: SocketAddr, request: &[u8]) -> Res<(String, Vec<u8>)> {
    let mut socket = io(TcpStream::connect(proxy).await)?;
    io(socket.write_all(request).await)?;
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(20), socket.read_to_end(&mut answer)).await;
    io(read
        .map_err(|_| std::io::ErrorKind::TimedOut.into())
        .and_then(|read| read))?;
    let split = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("no response head in {:?}", String::from_utf8_lossy(&answer)))?;
    let head = String::from_utf8_lossy(&answer[..split]).into_owned();
    let body = &answer[split + 4..];
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    Ok((
        head,
        if chunked {
            dechunk(body)
        } else {
            body.to_vec()
        },
    ))
}

/// A proxy, a server behind it and a client to talk to it.
struct Rig {
    handle: Option<ProxyHandle>,
    proxy: SocketAddr,
    server_addr: SocketAddr,
    server: Arc<Server>,
    shared: Arc<Shared>,
    vault: PathBuf,
    /// The proxy's CA certificate, for clients that must trust it.
    ca_pem: String,
    events: mpsc::Receiver<Event>,
    runtime: tokio::runtime::Runtime,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }
}

fn temp_vault(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("piikey-proxy-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir.join("vault.pkv")
}

fn own_exe() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

/// Intercepts traffic to the loopback host the server listens on.
fn local_sites() -> Policy {
    Policy {
        enabled: true,
        sites: vec!["127.0.0.1".to_owned()],
        ..Policy::default()
    }
}

fn rig(tag: &str, policy: Policy) -> Res<Rig> {
    let vault = temp_vault(tag);
    let engine = core(test_names::engine(&vault, &["Jeroen de Vries"]))?;
    let shared = Arc::new(Shared {
        engine: RwLock::new(Arc::new(engine)),
        policy: RwLock::new(policy),
        ledger: Ledger::default(),
        typed: Typed::new(),
    });
    let (tx, events) = mpsc::channel();
    let listener = io(StdListener::bind("127.0.0.1:0"))?;
    let proxy = io(listener.local_addr())?;
    let ca = ca::generate()?;
    let handle = start_on(
        &ca,
        Arc::clone(&shared),
        tx,
        listener,
        Duration::from_millis(300),
    )?;

    let runtime = io(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build())?;
    let server = Arc::new(Server {
        seen: Mutex::new(Vec::new()),
        reply: Mutex::new(Reply::Echo),
    });
    let listener = io(runtime.block_on(TcpListener::bind("127.0.0.1:0")))?;
    let server_addr = io(listener.local_addr())?;
    let serving = Arc::clone(&server);
    runtime.spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let server = Arc::clone(&serving);
            tokio::spawn(async move {
                let _ = server.serve(&mut socket).await;
            });
        }
    });
    Ok(Rig {
        handle: Some(handle),
        proxy,
        server_addr,
        server,
        shared,
        vault,
        ca_pem: ca.cert_pem,
        events,
        runtime,
    })
}

impl Rig {
    fn engine(&self) -> Arc<Engine> {
        let engine = self
            .shared
            .engine
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&engine)
    }

    /// An absolute-form `POST` through the proxy, as a client configured with
    /// an HTTP proxy sends it.
    fn post(&self, content_type: &str, body: &[u8]) -> Res<(String, Vec<u8>)> {
        self.post_with(content_type, &[], body)
    }

    fn post_with(&self, content_type: &str, extra: &[&str], body: &[u8]) -> Res<(String, Vec<u8>)> {
        let mut request = format!(
            "POST http://{addr}/echo HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\n\
             Accept-Encoding: gzip\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len(),
            addr = self.server_addr
        );
        for header in extra {
            request.push_str(header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body);
        self.runtime.block_on(through_proxy(self.proxy, &bytes))
    }

    fn event(&self) -> Option<Event> {
        self.events.recv_timeout(Duration::from_secs(5)).ok()
    }

    /// The issued proxies in `text`.
    fn proxies_in(&self, text: &str) -> Res<Vec<String>> {
        let plans = core(self.engine().plan(Mode::Deanonymize, &[text]))?;
        Ok(plans
            .into_iter()
            .flatten()
            .map(|rep| text[rep.start..rep.end].to_owned())
            .collect())
    }

    fn original_of(&self, proxy: &str) -> Res<Option<String>> {
        let engine = self.engine();
        let view = core(engine.vault().read())?;
        Ok(view.original_for(proxy).map(str::to_owned))
    }

    /// What the server received in its `n`th request.
    fn received(&self, n: usize) -> Res<Received> {
        self.server
            .seen()
            .get(n)
            .cloned()
            .ok_or_else(|| format!("the server received no request #{n}"))
    }
}

const JSON: &str = r#"{"m":"mail jan.jansen@acme.nl"}"#;

#[test]
fn outgoing_data_is_anonymized_and_the_reply_restored() -> Res<()> {
    let rig = rig("basic", local_sites())?;
    let (head, body) = rig.post("application/json", JSON.as_bytes())?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    // The server never saw the address: it got a proxy the vault knows.
    assert_eq!(rig.server.seen().len(), 1);
    let received = rig.received(0)?;
    let sent = utf8(&received.body);
    assert!(!sent.contains("jan.jansen@acme.nl"), "{sent}");
    let proxies = rig.proxies_in(sent)?;
    assert_eq!(proxies.len(), 1, "{sent}");
    assert_eq!(
        rig.original_of(&proxies[0])?.as_deref(),
        Some("jan.jansen@acme.nl")
    );
    assert_eq!(
        received.header("content-length").as_deref(),
        Some(received.body.len().to_string().as_str()),
        "the length follows the rewritten body"
    );
    assert_eq!(
        received.header("accept-encoding").as_deref(),
        Some("identity"),
        "compressed replies could not be restored"
    );

    // The client got its address back.
    assert_eq!(utf8(&body), JSON);

    let Some(Event::Masked {
        host, exe, kinds, ..
    }) = rig.event()
    else {
        return Err("expected a Masked event".into());
    };
    assert_eq!(host, "127.0.0.1");
    assert_eq!(
        exe.as_deref(),
        Some(own_exe().as_str()),
        "the sending program is named"
    );
    assert_eq!(kinds, [("email", 1)]);
    let Some(Event::Restored { host, count }) = rig.event() else {
        return Err("expected a Restored event".into());
    };
    assert_eq!((host.as_str(), count), ("127.0.0.1", 1));
    Ok(())
}

/// While the user's input is captured, only what the user typed is anonymized: the address the
/// page sends on its own goes out as it is.
#[test]
fn only_what_the_user_typed_is_anonymized_while_capturing() -> Res<()> {
    let rig = rig("typed", local_sites())?;
    rig.shared.typed.set_active(true);
    rig.shared.typed.push("mail jan.jansen@acme.nl".to_owned());

    let body = r#"{"m":"mail jan.jansen@acme.nl","telemetry":"piet@acme.nl"}"#;
    let (head, reply) = rig.post("application/json", body.as_bytes())?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let received = rig.received(0)?;
    let sent = utf8(&received.body);
    assert!(!sent.contains("jan.jansen@acme.nl"), "{sent}");
    assert!(
        sent.contains(r#""telemetry":"piet@acme.nl""#),
        "not typed, so not touched: {sent}"
    );
    assert_eq!(rig.proxies_in(sent)?.len(), 1, "{sent}");
    assert_eq!(utf8(&reply), body, "the typed address comes back");

    let Some(Event::Masked { kinds, proxies, .. }) = rig.event() else {
        return Err("expected a Masked event".into());
    };
    assert_eq!(kinds, [("email", 1)]);
    assert_eq!(proxies.len(), 1);
    Ok(())
}

/// A chat client resends its history with every message. The stand-ins in it were sent to this
/// site before: they go out as they are, or the next reply would restore to a stand-in.
#[test]
fn stand_ins_in_a_resent_history_go_out_as_they_are() -> Res<()> {
    let rig = rig("resent", local_sites())?;
    rig.post("application/json", br#"{"m":"Ik ben Jeroen de Vries"}"#)?;
    let first = utf8(&rig.received(0)?.body).to_owned();
    let proxies = rig.proxies_in(&first)?;
    let [stand_in] = proxies.as_slice() else {
        return Err(format!("expected one stand-in in {first}"));
    };
    let records = core(rig.engine().vault().read())?.record_count();

    let history = format!(r#"{{"m":["Ik ben {stand_in}","Met welke letter start mijn naam?"]}}"#);
    rig.post("application/json", history.as_bytes())?;
    assert_eq!(
        utf8(&rig.received(1)?.body),
        history,
        "the history went out unchanged"
    );
    assert_eq!(
        core(rig.engine().vault().read())?.record_count(),
        records,
        "no stand-in for a stand-in"
    );
    Ok(())
}

#[test]
fn a_typo_in_the_reply_is_repaired_for_proxies_sent_to_that_host() -> Res<()> {
    // Needs the tolerant restorer: the exact pass alone cannot match it.
    let rig = rig("typo", local_sites())?;
    rig.server.reply_with(Reply::Typo);
    let (_, body) = rig.post("application/json", JSON.as_bytes())?;
    assert_eq!(
        utf8(&body),
        JSON,
        "the doubled letter did not stop the restore"
    );
    Ok(())
}

#[test]
fn proxies_split_across_stream_chunks_are_restored() -> Res<()> {
    let rig = rig("stream", local_sites())?;
    rig.server.reply_with(Reply::SplitStream);
    let (head, body) = rig.post("application/json", JSON.as_bytes())?;
    let head = head.to_ascii_lowercase();
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
    assert!(
        !head.contains("content-length"),
        "restoring changes the length: {head}"
    );
    assert_eq!(utf8(&body), "data: write to jan.jansen@acme.nl please\n\n");
    Ok(())
}

#[test]
fn replies_that_are_not_text_are_left_alone() -> Res<()> {
    let rig = rig("binary", local_sites())?;
    rig.post("application/json", JSON.as_bytes())?;
    let proxy = rig.proxies_in(utf8(&rig.received(0)?.body))?.remove(0);
    // A binary reply that happens to contain a proxy keeps it.
    let payload = format!("\x00\x01{proxy}\x02").into_bytes();
    rig.server
        .reply_with(Reply::Fixed("application/octet-stream", payload.clone()));
    let (head, body) = rig.post("application/json", JSON.as_bytes())?;
    assert!(
        head.to_ascii_lowercase().contains("content-length"),
        "{head}"
    );
    assert_eq!(body, payload);
    Ok(())
}

#[test]
fn other_hosts_are_not_touched() -> Res<()> {
    let policy = Policy {
        sites: vec!["example.org".to_owned()],
        ..local_sites()
    };
    let rig = rig("other", policy)?;
    let (_, body) = rig.post("application/json", JSON.as_bytes())?;
    let received = rig.received(0)?;
    assert_eq!(utf8(&received.body), JSON, "forwarded as it is");
    assert_eq!(received.header("accept-encoding").as_deref(), Some("gzip"));
    assert_eq!(utf8(&body), JSON);
    assert!(rig.events.try_recv().is_err(), "nothing to report");
    Ok(())
}

/// chatgpt.com sends tens of KiB of cookies and tokens and well over 100 header lines; hyper's
/// defaults (16 KiB over HTTP/2, 100 lines over HTTP/1.1) answered such requests with a 431.
#[test]
fn browser_sized_headers_get_through() -> Res<()> {
    let rig = rig("big-headers", local_sites())?;
    let cookie = format!("Cookie: session={}", "c".repeat(40 << 10));
    let mut extra: Vec<String> = (0..150).map(|n| format!("X-Extra-{n}: {n}")).collect();
    extra.push(cookie.clone());
    let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
    let (head, body) = rig.post_with("application/json", &extra, JSON.as_bytes())?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(utf8(&body), JSON);
    let received = rig.received(0)?;
    assert_eq!(
        received.header("cookie").map(|c| c.len()),
        Some(cookie.len() - "Cookie: ".len())
    );
    assert_eq!(received.header("x-extra-149").as_deref(), Some("149"));
    Ok(())
}

#[test]
fn a_disabled_app_touches_nothing() -> Res<()> {
    let policy = Policy {
        enabled: false,
        ..local_sites()
    };
    let rig = rig("disabled", policy)?;
    let (_, body) = rig.post("application/json", JSON.as_bytes())?;
    assert_eq!(utf8(&rig.received(0)?.body), JSON);
    assert_eq!(utf8(&body), JSON);
    assert!(rig.events.try_recv().is_err());
    Ok(())
}

#[test]
fn a_selected_program_is_intercepted_on_any_host() -> Res<()> {
    let policy = Policy {
        enabled: true,
        programs: vec![own_exe()],
        ..Policy::default()
    };
    {
        let rig = rig("program", policy)?;
        rig.post("application/json", JSON.as_bytes())?;
        assert!(!utf8(&rig.received(0)?.body).contains("jan.jansen"));
    }
    let elsewhere = Policy {
        enabled: true,
        programs: vec!["some-other-program.exe".to_owned()],
        ..Policy::default()
    };
    let rig = rig("program-other", elsewhere)?;
    rig.post("application/json", JSON.as_bytes())?;
    assert_eq!(utf8(&rig.received(0)?.body), JSON);
    Ok(())
}

#[test]
fn policy_changes_apply_to_the_next_request() -> Res<()> {
    let rig = rig("live-policy", Policy::default())?;
    rig.post("application/json", JSON.as_bytes())?;
    assert_eq!(utf8(&rig.received(0)?.body), JSON, "off at first");

    if let Ok(mut policy) = rig.shared.policy.write() {
        *policy = local_sites();
    }
    rig.post("application/json", JSON.as_bytes())?;
    assert!(
        !utf8(&rig.received(1)?.body).contains("jan.jansen"),
        "now on"
    );

    if let Ok(mut policy) = rig.shared.policy.write() {
        policy.enabled = false;
    }
    rig.post("application/json", JSON.as_bytes())?;
    assert_eq!(utf8(&rig.received(2)?.body), JSON, "off again");
    Ok(())
}

#[test]
fn swapping_the_engine_applies_its_detector_to_the_next_request() -> Res<()> {
    let rig = rig("swap", local_sites())?;
    let text = r#"{"m":"hello Haley Brooks"}"#;
    rig.post("application/json", text.as_bytes())?;
    assert_eq!(
        utf8(&rig.received(0)?.body),
        text,
        "the first engine does not find this name"
    );

    let engine = core(test_names::engine(&temp_vault("swap-2"), &["Haley Brooks"]))?;
    if let Ok(mut slot) = rig.shared.engine.write() {
        *slot = Arc::new(engine);
    }
    let (_, body) = rig.post("application/json", text.as_bytes())?;
    let proxies = rig.proxies_in(utf8(&rig.received(1)?.body))?;
    assert_eq!(proxies.len(), 1, "the name went out as a proxy");
    assert_eq!(
        rig.original_of(&proxies[0])?.as_deref(),
        Some("Haley Brooks")
    );
    assert_eq!(utf8(&body), text, "and it is restored");
    Ok(())
}

#[test]
fn form_bodies_are_anonymized_value_by_value() -> Res<()> {
    let rig = rig("form", local_sites())?;
    let form = "mail=jan.jansen%40acme.nl&x=1&note=a+b";
    rig.post("application/x-www-form-urlencoded", form.as_bytes())?;
    let received = rig.received(0)?;
    let sent = utf8(&received.body);
    assert!(!sent.contains("jansen"), "{sent}");
    assert!(
        sent.ends_with("&x=1&note=a+b"),
        "untouched fields keep their spelling: {sent}"
    );
    let encoded = sent
        .strip_prefix("mail=")
        .and_then(|rest| rest.split('&').next())
        .unwrap_or_default();
    assert!(encoded.contains("%40"), "the proxy is re-encoded: {sent}");

    // A reply that quotes the proxy as plain text gets the original back.
    let proxy = encoded.replace("%40", "@");
    assert_eq!(
        rig.original_of(&proxy)?.as_deref(),
        Some("jan.jansen@acme.nl")
    );
    rig.server.reply_with(Reply::Fixed(
        "text/plain",
        format!("sent to {proxy}").into_bytes(),
    ));
    let (_, body) = rig.post("application/x-www-form-urlencoded", form.as_bytes())?;
    assert_eq!(utf8(&body), "sent to jan.jansen@acme.nl");
    Ok(())
}

#[test]
fn text_without_personal_data_passes_unchanged_and_quietly() -> Res<()> {
    let rig = rig("clean", local_sites())?;
    let clean = r#"{"m":"hello world"}"#;
    let (_, body) = rig.post("application/json", clean.as_bytes())?;
    assert_eq!(utf8(&rig.received(0)?.body), clean);
    assert_eq!(utf8(&body), clean);
    assert!(
        rig.events.try_recv().is_err(),
        "no Masked or Restored event"
    );
    Ok(())
}

#[test]
fn binary_requests_are_forwarded_as_they_are() -> Res<()> {
    let rig = rig("octets", local_sites())?;
    let blob = b"\x00\x01 jan.jansen@acme.nl \xFF";
    rig.server
        .reply_with(Reply::Fixed("application/octet-stream", b"ok".to_vec()));
    rig.post("application/octet-stream", blob)?;
    assert_eq!(rig.received(0)?.body, blob);
    Ok(())
}

#[test]
fn a_declared_body_over_the_limit_is_refused_before_it_is_read() -> Res<()> {
    let rig = rig("huge", local_sites())?;
    let request = format!(
        "POST http://{addr}/ HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: 100000000\r\nConnection: close\r\n\r\n",
        addr = rig.server_addr
    );
    let (head, body) = rig
        .runtime
        .block_on(through_proxy(rig.proxy, request.as_bytes()))?;
    assert!(head.starts_with("HTTP/1.1 413"), "{head}");
    assert!(utf8(&body).contains("64 MiB"), "{}", utf8(&body));
    assert!(rig.server.seen().is_empty(), "nothing was forwarded");
    Ok(())
}

#[test]
fn a_body_that_cannot_be_inspected_is_forwarded_untouched() -> Res<()> {
    let rig = rig("encoding", local_sites())?;
    rig.post_with(
        "application/json",
        &["Content-Encoding: snappy"],
        JSON.as_bytes(),
    )?;
    let received = rig.received(0)?;
    assert_eq!(utf8(&received.body), JSON);
    assert_eq!(
        received.header("content-encoding").as_deref(),
        Some("snappy")
    );
    Ok(())
}

/// `JSON`, gzip-compressed.
const JSON_GZIP: [u8; 49] = [
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0xab, 0x56, 0xca, 0x55, 0xb2, 0x52,
    0xca, 0x4d, 0xcc, 0xcc, 0x51, 0xc8, 0x4a, 0xcc, 0xd3, 0x03, 0xe2, 0xe2, 0xd4, 0x3c, 0x87, 0xc4,
    0xe4, 0xdc, 0x54, 0xbd, 0xbc, 0x1c, 0xa5, 0x5a, 0x00, 0x69, 0x36, 0x15, 0x53, 0x1f, 0x00, 0x00,
    0x00,
];

#[test]
fn compressed_request_bodies_are_decoded_anonymized_and_sent_plain() -> Res<()> {
    let rig = rig("gzip", local_sites())?;
    let (_, body) = rig.post_with("application/json", &["Content-Encoding: gzip"], &JSON_GZIP)?;
    let received = rig.received(0)?;
    assert_eq!(
        received.header("content-encoding"),
        None,
        "forwarded uncompressed"
    );
    let sent = utf8(&received.body);
    assert!(sent.starts_with(r#"{"m":"mail "#), "{sent}");
    assert!(!sent.contains("jan.jansen"), "{sent}");
    assert_eq!(
        received.header("content-length").as_deref(),
        Some(received.body.len().to_string().as_str())
    );
    assert_eq!(utf8(&body), JSON);
    Ok(())
}

#[test]
fn a_vault_failure_stops_the_request_instead_of_leaking_it() -> Res<()> {
    let rig = rig("failing", local_sites())?;
    // The vault file is cut behind the engine's back: the next record it has
    // to write finds the file shorter than what it already read.
    let file = io(std::fs::OpenOptions::new().write(true).open(&rig.vault))?;
    io(file.set_len(0))?;
    drop(file);

    let (head, body) = rig.post("application/json", JSON.as_bytes())?;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(utf8(&body).contains("not sent"), "{}", utf8(&body));
    assert!(
        rig.server.seen().is_empty(),
        "the original must not reach the server"
    );
    Ok(())
}

/// A WebSocket server that records every message and sends it back.
async fn websocket_echo(listener: TcpListener, seen: Arc<Mutex<Vec<WsMessage>>>) {
    while let Ok((socket, _)) = listener.accept().await {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let Ok(mut ws) = accept_async(socket).await else {
                return;
            };
            while let Some(Ok(message)) = ws.next().await {
                if let Ok(mut seen) = seen.lock() {
                    seen.push(message.clone());
                }
                if ws.send(message).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[test]
fn websocket_text_frames_are_anonymized_out_and_restored_back() -> Res<()> {
    let rig = rig("websocket", local_sites())?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ws_listener = io(rig.runtime.block_on(TcpListener::bind("127.0.0.1:0")))?;
    let ws_addr = io(ws_listener.local_addr())?;
    rig.runtime
        .spawn(websocket_echo(ws_listener, Arc::clone(&seen)));

    let proxy = rig.proxy;
    let received = rig.runtime.block_on(async move {
        let mut socket = TcpStream::connect(proxy).await?;
        let upgrade = format!(
            "GET http://{ws_addr}/chat HTTP/1.1\r\nHost: {ws_addr}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        socket.write_all(upgrade.as_bytes()).await?;
        // The handshake answer, byte by byte: whatever follows is WebSocket.
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await?);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&head)
        );

        let mut ws = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
        let mut answers = Vec::new();
        for message in [
            WsMessage::text(JSON),
            WsMessage::binary(b"\x00 jan.jansen@acme.nl".to_vec()),
        ] {
            ws.send(message).await.map_err(std::io::Error::other)?;
            answers.push(
                tokio::time::timeout(Duration::from_secs(10), ws.next())
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?,
            );
        }
        Ok::<_, std::io::Error>(answers)
    });
    let answers = io(received)?;

    let seen = seen.lock().map(|seen| seen.clone()).unwrap_or_default();
    assert_eq!(seen.len(), 2, "{seen:?}");
    // Text: the server saw a proxy, the client got its address back.
    let WsMessage::Text(sent) = &seen[0] else {
        return Err(format!("the server saw {:?} first", seen[0]));
    };
    assert!(!sent.as_str().contains("jan.jansen@acme.nl"), "{sent}");
    let proxies = rig.proxies_in(sent.as_str())?;
    assert_eq!(proxies.len(), 1, "{sent}");
    assert_eq!(
        rig.original_of(&proxies[0])?.as_deref(),
        Some("jan.jansen@acme.nl")
    );
    let Some(Some(Ok(WsMessage::Text(back)))) = answers.first() else {
        return Err(format!("the client got {answers:?} first"));
    };
    assert_eq!(back.as_str(), JSON);
    // Binary frames are not text: untouched both ways.
    assert_eq!(
        seen[1],
        WsMessage::binary(b"\x00 jan.jansen@acme.nl".to_vec())
    );
    assert!(matches!(
        answers.get(1),
        Some(Some(Ok(WsMessage::Binary(bytes)))) if bytes.as_ref() == b"\x00 jan.jansen@acme.nl"
    ));

    let Some(Event::Masked { host, kinds, .. }) = rig.event() else {
        return Err("expected a Masked event".into());
    };
    assert_eq!(
        (host.as_str(), kinds.as_slice()),
        ("127.0.0.1", [("email", 1)].as_slice())
    );
    let Some(Event::Restored { count, .. }) = rig.event() else {
        return Err("expected a Restored event".into());
    };
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn stopping_ends_every_thread_even_with_a_tunnel_left_open() -> Res<()> {
    let mut rig = rig("stop", local_sites())?;
    // A CONNECT tunnel that nobody closes: not TLS, so a plain byte tunnel.
    let held = rig.runtime.block_on(async {
        let mut socket = TcpStream::connect(rig.proxy).await?;
        let connect = format!(
            "CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n",
            addr = rig.server_addr
        );
        socket.write_all(connect.as_bytes()).await?;
        let mut answer = [0u8; 9];
        socket.read_exact(&mut answer).await?;
        socket.write_all(b"XXXX not a protocol").await?;
        Ok::<_, std::io::Error>((socket, answer))
    });
    let (mut held, answer) = io(held)?;
    assert_eq!(&answer, b"HTTP/1.1 ");

    let started = Instant::now();
    if let Some(handle) = rig.handle.take() {
        handle.stop();
    }
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "stop took {:?}",
        started.elapsed()
    );
    // The tunnel was cut and nobody listens any more.
    let mut buffer = [0u8; 64];
    let cut = rig.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), held.read(&mut buffer)).await
    });
    assert!(matches!(cut, Ok(Ok(0) | Err(_))), "{cut:?}");
    assert!(
        StdListener::bind(rig.proxy).is_ok(),
        "the port is free again"
    );
    assert!(
        rig.events.try_recv().is_err(),
        "a requested stop is not an error"
    );
    Ok(())
}

#[test]
fn stopping_an_idle_proxy_is_prompt() -> Res<()> {
    let mut rig = rig("stop-idle", local_sites())?;
    let started = Instant::now();
    if let Some(handle) = rig.handle.take() {
        handle.stop();
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

#[test]
fn a_busy_port_is_reported_when_starting() -> Res<()> {
    let taken = io(StdListener::bind("127.0.0.1:0"))?;
    let port = io(taken.local_addr())?.port();
    let err = bind(port).err().unwrap_or_default();
    assert!(err.contains(&format!("127.0.0.1:{port}")), "{err}");
    Ok(())
}

#[test]
fn unusable_ca_material_is_reported_when_starting() -> Res<()> {
    let (tx, _rx) = mpsc::channel();
    let listener = io(StdListener::bind("127.0.0.1:0"))?;
    let broken = ca::Ca {
        cert_pem: "not a certificate".to_owned(),
        key_pem: "not a key".to_owned(),
    };
    let engine = core(Engine::open(&temp_vault("bad-ca")))?;
    let shared = Arc::new(Shared {
        engine: RwLock::new(Arc::new(engine)),
        policy: RwLock::new(Policy::default()),
        ledger: Ledger::default(),
        typed: Typed::new(),
    });
    let err = start_on(&broken, shared, tx, listener, GRACE)
        .err()
        .unwrap_or_default();
    assert!(err.contains("CA"), "{err}");
    Ok(())
}

/// The service answers an event stream whose text is `Write to <proxy> today.`,
/// the proxy of an email address sent to it before, cut into five pieces.
/// Returns the head and body the client reads.
fn event_stream_reply(
    tag: &str,
    content_type: &'static str,
    build: fn(&[&str]) -> Vec<u8>,
) -> Res<(String, Vec<u8>)> {
    let rig = rig(tag, local_sites())?;
    rig.post("application/json", JSON.as_bytes())?;
    let proxy = rig.proxies_in(utf8(&rig.received(0)?.body))?.remove(0);
    // The proxy cut into pieces inside the stream.
    let (a, rest) = proxy.split_at(4);
    let (b, c) = rest.split_at(rest.len() / 2);
    let (c, d) = c.split_at(c.len() - 1);
    let stream = build(&["Write to ", a, b, c, d, " today."]);
    rig.server.reply_with(Reply::Fixed(content_type, stream));
    rig.post("application/json", JSON.as_bytes())
}

#[test]
fn event_streams_are_restored_across_the_events_a_proxy_is_cut_into() -> Res<()> {
    let read = "Write to jan.jansen@acme.nl today.";

    let (head, body) = event_stream_reply("sse-openai", "text/event-stream", openai)?;
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("transfer-encoding: chunked") && !lower.contains("content-length"),
        "{head}"
    );
    assert_eq!(texts(&body, Framing::Sse, "/choices/0/delta/content"), read);
    assert_eq!(
        sse_events(&body).last().map(|(_, data)| data.as_str()),
        Some("[DONE]")
    );

    let (_, body) = event_stream_reply(
        "sse-anthropic",
        "text/event-stream; charset=utf-8",
        anthropic,
    )?;
    assert_eq!(texts(&body, Framing::Sse, "/delta/text"), read);
    let last = sse_events(&body).pop().and_then(|(name, _)| name);
    assert_eq!(last.as_deref(), Some("message_stop"));

    let (_, body) = event_stream_reply("sse-ndjson", "application/x-ndjson", ndjson)?;
    assert_eq!(texts(&body, Framing::Ndjson, "/message/content"), read);
    Ok(())
}

// ---- TLS: which connections are decrypted, and with what certificate ----
//
// The proxy cannot forward decrypted traffic to a server here (its upstream
// checks certificates against the public web roots), but the client-facing
// half is fully testable: which certificate a client is shown, and what the
// proxy does with a request it was able to read.

/// The DER inside a PEM certificate.
fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut der = Vec::new();
    let (mut accumulated, mut bits) = (0u32, 0u32);
    for byte in body.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        accumulated = (accumulated << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            der.push(u8::try_from((accumulated >> bits) & 0xFF).unwrap_or(0));
        }
    }
    der
}

fn tls_error(e: impl std::fmt::Display) -> String {
    e.to_string()
}

type Tls = StreamOwned<ClientConnection, std::net::TcpStream>;

/// `CONNECT localhost:port` through the proxy, then a TLS handshake for
/// `localhost` trusting only the `trusted` certificates. Returns the secured
/// stream and the certificate the other side presented.
fn tls_through_proxy(proxy: SocketAddr, port: u16, trusted: &[&[u8]]) -> Res<(Tls, Vec<u8>)> {
    tls_to(proxy, "localhost", port, trusted)
}

/// `CONNECT host:port` through the proxy, then a TLS handshake for `host`
/// trusting only the `trusted` certificates.
fn tls_to(proxy: SocketAddr, host: &str, port: u16, trusted: &[&[u8]]) -> Res<(Tls, Vec<u8>)> {
    let mut tcp = io(std::net::TcpStream::connect(proxy))?;
    io(tcp.set_read_timeout(Some(Duration::from_secs(20))))?;
    let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    io(std::io::Write::write_all(&mut tcp, connect.as_bytes()))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        io(std::io::Read::read_exact(&mut tcp, &mut byte))?;
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );

    let mut roots = RootCertStore::empty();
    for der in trusted {
        roots
            .add(CertificateDer::from(der.to_vec()))
            .map_err(tls_error)?;
    }
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(tls_error)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned()).map_err(tls_error)?;
    let mut connection = ClientConnection::new(Arc::new(config), name).map_err(tls_error)?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut tcp)
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
    }
    let presented = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or("the server presented no certificate")?;
    Ok((StreamOwned::new(connection, tcp), presented))
}

/// A TLS server of its own for `localhost` (one connection, handshake only):
/// `(port, its certificate)`.
fn tls_server() -> Res<(u16, Vec<u8>)> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).map_err(tls_error)?;
    let der = cert.der().as_ref().to_vec();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(tls_error)?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der.clone())], key)
        .map_err(tls_error)?;
    let listener = io(StdListener::bind("127.0.0.1:0"))?;
    let port = io(listener.local_addr())?.port();
    std::thread::spawn(move || {
        let Ok((mut tcp, _)) = listener.accept() else {
            return;
        };
        let Ok(mut connection) = ServerConnection::new(Arc::new(config)) else {
            return;
        };
        while connection.is_handshaking() {
            if connection.complete_io(&mut tcp).is_err() {
                return;
            }
        }
        // Hold the connection until the client has looked at the certificate.
        let mut sink = [0u8; 16];
        let _ = std::io::Read::read(&mut tcp, &mut sink);
    });
    Ok((port, der))
}
/// A server that hangs up on everyone: an upstream the proxy fails to reach
/// quickly, so its error comes back at once.
fn hang_up_server() -> Res<u16> {
    let listener = io(StdListener::bind("127.0.0.1:0"))?;
    let port = io(listener.local_addr())?.port();
    std::thread::spawn(move || while listener.accept().is_ok() {});
    Ok(port)
}

#[test]
fn selected_sites_are_decrypted_with_a_certificate_of_the_proxys_ca() -> Res<()> {
    let rig = rig(
        "tls-site",
        Policy {
            sites: vec!["localhost".to_owned()],
            ..local_sites()
        },
    )?;
    let upstream = hang_up_server()?;
    let ca = pem_to_der(&rig.ca_pem);
    let (mut tls, presented) = tls_through_proxy(rig.proxy, upstream, &[&ca])?;
    assert_ne!(presented, ca, "a server certificate, not the CA itself");

    // The proxy reads what the client sends inside the tunnel: the address
    // is replaced before anything is forwarded (the forwarding itself fails
    // here, as the upstream is not a server the proxy could talk to).
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost:{upstream}\r\nContent-Type: application/json\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n{JSON}",
        JSON.len()
    );
    io(std::io::Write::write_all(&mut tls, request.as_bytes()))?;
    let mut answer = Vec::new();
    // The connection may be cut right after the answer; what arrived counts.
    let _ = std::io::Read::read_to_end(&mut tls, &mut answer);
    assert!(
        answer.starts_with(b"HTTP/1.1 502"),
        "the upstream failure comes back through the tunnel: {:?}",
        String::from_utf8_lossy(&answer)
    );
    let Some(Event::Masked {
        host, exe, kinds, ..
    }) = rig.event()
    else {
        return Err("the decrypted request was not anonymized".into());
    };
    assert_eq!(host, "localhost");
    assert_eq!(exe.as_deref(), Some(own_exe().as_str()));
    assert_eq!(kinds, [("email", 1)]);
    Ok(())
}

/// Live: real TLS through the app to a public echo service. Run with
/// `cargo test -p piikey-app live_ -- --ignored`. httpbin echoes what it
/// received, so a restored original in the reply proves the upstream got a
/// proxy and the app swapped it back.
#[test]
#[ignore = "needs internet (httpbin.org)"]
fn live_tls_round_trip_through_a_public_site() -> Res<()> {
    let rig = rig(
        "live",
        Policy {
            sites: vec!["httpbin.org".to_owned()],
            ..local_sites()
        },
    )?;
    let ca = pem_to_der(&rig.ca_pem);
    let (mut tls, _) = tls_to(rig.proxy, "httpbin.org", 443, &[&ca])?;
    let request = format!(
        "POST /anything HTTP/1.1\r\nHost: httpbin.org\r\nContent-Type: application/json\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n{JSON}",
        JSON.len()
    );
    io(std::io::Write::write_all(&mut tls, request.as_bytes()))?;
    let mut answer = Vec::new();
    let _ = std::io::Read::read_to_end(&mut tls, &mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(
        answer.contains("jan.jansen@acme.nl"),
        "restored in the reply: {answer}"
    );
    let mut masked = false;
    let mut restored = 0;
    while let Some(event) = rig.event() {
        match event {
            Event::Masked { .. } => masked = true,
            Event::Restored { count, .. } => restored += count,
            Event::Error(e) => return Err(e),
        }
        if masked && restored > 0 {
            break;
        }
    }
    assert!(masked, "the request was anonymized");
    assert!(restored > 0, "the echoed proxy was restored");
    eprintln!("{answer}");
    Ok(())
}

#[test]
fn other_sites_are_tunneled_with_their_own_certificate() -> Res<()> {
    let rig = rig(
        "tls-tunnel",
        Policy {
            sites: vec!["example.org".to_owned()],
            ..local_sites()
        },
    )?;
    let (port, upstream) = tls_server()?;
    // The client trusts only the real server's certificate: the handshake
    // can only succeed when the proxy passes it through untouched.
    let (_tls, presented) = tls_through_proxy(rig.proxy, port, &[&upstream])?;
    assert_eq!(presented, upstream);
    assert!(rig.events.try_recv().is_err());
    Ok(())
}

#[test]
fn program_rules_decide_which_tls_connections_are_decrypted() -> Res<()> {
    let selected = Policy {
        enabled: true,
        programs: vec![own_exe()],
        ..Policy::default()
    };
    {
        let rig = rig("tls-program", selected)?;
        let ca = pem_to_der(&rig.ca_pem);
        // Any host: the sending program is what matches.
        let (_tls, presented) = tls_through_proxy(rig.proxy, rig.server_addr.port(), &[&ca])?;
        assert_ne!(presented, ca);
    }
    let other = Policy {
        enabled: true,
        programs: vec!["some-other-program.exe".to_owned()],
        ..Policy::default()
    };
    let rig = rig("tls-program-other", other)?;
    let (port, upstream) = tls_server()?;
    let (_tls, presented) = tls_through_proxy(rig.proxy, port, &[&upstream])?;
    assert_eq!(presented, upstream);
    Ok(())
}

#[test]
fn a_disabled_app_decrypts_nothing_over_tls() -> Res<()> {
    let rig = rig(
        "tls-off",
        Policy {
            enabled: false,
            sites: vec!["localhost".to_owned()],
            ..Policy::default()
        },
    )?;
    let (port, upstream) = tls_server()?;
    let (_tls, presented) = tls_through_proxy(rig.proxy, port, &[&upstream])?;
    assert_eq!(presented, upstream);
    Ok(())
}
