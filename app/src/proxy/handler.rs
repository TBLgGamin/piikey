//! The traffic decisions: what is decrypted, what is anonymized on the way
//! out and what is restored on the way back.
//!
//! One [`Interceptor`] serves each request of a connection; hudsucker hands the same
//! instance the request and its response, which is how the response learns
//! which host it came from.

use std::{
    net::SocketAddr,
    sync::{Arc, PoisonError, RwLockReadGuard, mpsc::Sender},
};

use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    decode_request, decode_response,
    hyper::{
        Method, Request, Response, StatusCode,
        header::{
            ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap,
            HeaderValue, TRANSFER_ENCODING,
        },
    },
    rustls::server::ClientHello,
    tokio_tungstenite::tungstenite::Message,
};
use piikey::{
    detect::Mode,
    engine::{Engine, Resent},
    policy::{Policy, normalize_host},
    restore::Restorer,
};

use super::{
    Event, Shared,
    body::{CollectError, collect},
    origin::Origin,
    response::{Pipeline, restoring_body},
    transform::{BodyKind, ContentType, mask},
};

/// The largest request body that is read and anonymized.
const MAX_BODY: usize = 64 << 20;

/// Everything the handlers share. Cheap to clone.
#[derive(Clone)]
pub(super) struct Env {
    pub(super) shared: Arc<Shared>,
    pub(super) events: Sender<Event>,
    pub(super) origin: Arc<Origin>,
}

/// Traffic that is being intercepted: where it goes and who sends it.
#[derive(Debug, Clone)]
struct Target {
    /// Lowercase host without port.
    host: Arc<str>,
    /// Lowercase exe name of the program, when it could be told.
    exe: Option<Arc<str>>,
}

/// A connection's program, looked up at most once.
#[derive(Debug, Clone, Default)]
struct Owner {
    looked_up: bool,
    exe: Option<Arc<str>>,
}

impl Env {
    fn engine(&self) -> Arc<Engine> {
        let engine = self
            .shared
            .engine
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&engine)
    }

    fn policy(&self) -> RwLockReadGuard<'_, Policy> {
        self.shared
            .policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn emit(&self, event: Event) {
        // The receiver is the UI; without one there is nobody to tell.
        let _ = self.events.send(event);
    }

    /// The program behind `owner`, found on first use (a blocking lookup).
    async fn exe_of(&self, client: SocketAddr, owner: &mut Owner) -> Option<Arc<str>> {
        if !owner.looked_up {
            let origin = Arc::clone(&self.origin);
            owner.exe = tokio::task::spawn_blocking(move || origin.exe_for_client(client))
                .await
                .ok()
                .flatten();
            owner.looked_up = true;
        }
        owner.exe.clone()
    }

    /// Whether traffic from `client` to `host` is intercepted: the app is
    /// on, and the host matches a site or the program a selected one. The
    /// program is only looked up when the policy has program rules or the
    /// request is intercepted anyway (for the Activity log).
    async fn target_for(
        &self,
        client: SocketAddr,
        host: &str,
        owner: &mut Owner,
    ) -> Option<Target> {
        let (enabled, by_site, by_program_possible) = {
            let policy = self.policy();
            (
                policy.enabled,
                policy.intercepts(host, None),
                !policy.programs.is_empty(),
            )
        };
        if !enabled || !(by_site || by_program_possible) {
            return None;
        }
        let exe = self.exe_of(client, owner).await;
        let hit = by_site || self.policy().intercepts(host, exe.as_deref());
        hit.then(|| Target {
            host: Arc::from(host),
            exe,
        })
    }

    /// Anonymizes the request body. `Err` is the response to send instead:
    /// the request must not go out when it cannot be made safe.
    async fn rewrite_request(
        &self,
        target: &Target,
        mut req: Request<Body>,
    ) -> Result<Request<Body>, Response<Body>> {
        // Compressed replies could not be restored.
        req.headers_mut()
            .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        let Some(kind) = ContentType::of(req.headers()).and_then(|ct| ct.body_kind()) else {
            return Ok(req);
        };
        if declared_length(req.headers()).is_some_and(|len| len > MAX_BODY as u64) {
            return Err(too_large());
        }
        let req = if req.headers().contains_key(CONTENT_ENCODING) {
            // A compression the proxy cannot undo: the body cannot be read,
            // so it goes out as it is.
            if !decodable(req.headers()) {
                return Ok(req);
            }
            decode_request(req)
                .map_err(|_| refuse(StatusCode::BAD_REQUEST, "cannot decode the request body"))?
        } else {
            req
        };

        let (mut parts, body) = req.into_parts();
        let bytes = match collect(body, MAX_BODY).await {
            Ok(bytes) => bytes,
            Err(CollectError::TooLarge) => return Err(too_large()),
            Err(CollectError::Read(e)) => {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    &format!("cannot read the request body: {e}"),
                ));
            }
        };

        let engine = self.engine();
        let shared = Arc::clone(&self.shared);
        let host = Arc::clone(&target.host);
        let masked = tokio::task::spawn_blocking(move || {
            let sent = shared.ledger.sent_to(&host);
            let resent = |proxy: &str| sent.contains(proxy);
            let masked = mask(
                &engine,
                &shared.typed,
                Resent::These(&resent),
                &kind,
                &bytes,
            )?;
            // Before the request leaves: its answer may come back at once.
            for proxy in &masked.proxies {
                shared.ledger.touch(&host, proxy);
            }
            Ok::<_, piikey::Error>(masked)
        })
        .await;
        let masked = match masked {
            Ok(Ok(masked)) => masked,
            Ok(Err(e)) => return Err(unsafe_to_send(&e.to_string())),
            Err(e) => return Err(unsafe_to_send(&e.to_string())),
        };
        if !masked.counts.is_empty() {
            self.emit(Event::Masked {
                host: target.host.to_string(),
                exe: target.exe.as_deref().map(str::to_owned),
                proxies: masked.proxies,
            });
        }

        parts.headers.remove(TRANSFER_ENCODING);
        parts.headers.remove(CONTENT_ENCODING);
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(masked.body.len()));
        Ok(Request::from_parts(parts, Body::from(masked.body)))
    }

    /// Wraps a text response so that proxies in it are restored while it
    /// streams. Anything else (binary, bodiless, partial) passes untouched.
    async fn restore_response(&self, pending: &Pending, res: Response<Body>) -> Response<Body> {
        let status = res.status();
        let bodiless = pending.head
            || matches!(
                status,
                StatusCode::NO_CONTENT
                    | StatusCode::RESET_CONTENT
                    | StatusCode::NOT_MODIFIED
                    | StatusCode::PARTIAL_CONTENT
            );
        let content = ContentType::of(res.headers());
        if bodiless || !content.as_ref().is_some_and(ContentType::is_restorable) {
            return res;
        }
        // Event streams are restored delta by delta, everything else as bytes.
        let framing = content.and_then(|content| content.framing());
        let res = if res.headers().contains_key(CONTENT_ENCODING) {
            if !decodable(res.headers()) {
                return res;
            }
            match decode_response(res) {
                Ok(res) => res,
                Err(_) => {
                    return refuse(StatusCode::BAD_GATEWAY, "cannot decode the response body");
                }
            }
        } else {
            res
        };

        let engine = self.engine();
        let shared = Arc::clone(&self.shared);
        let host = Arc::clone(&pending.target.host);
        let built = tokio::task::spawn_blocking(move || {
            Pipeline::new(engine, &shared.ledger, &host, framing)
        })
        .await;
        // Without a pipeline the response is forwarded as it is.
        let Ok(Ok(pipeline)) = built else {
            return res;
        };
        let (mut parts, body) = res.into_parts();
        // The length changes with every restored value.
        parts.headers.remove(CONTENT_LENGTH);
        let body = restoring_body(
            body,
            pipeline,
            self.events.clone(),
            Arc::clone(&pending.target.host),
        );
        Response::from_parts(parts, body)
    }
}

/// What `handle_request` decided about the request in flight.
#[derive(Debug, Clone)]
struct Pending {
    target: Target,
    /// A `HEAD` response has headers describing a body it does not carry.
    head: bool,
}

/// HTTP traffic: decides per connection and per request.
#[derive(Clone)]
pub(super) struct Interceptor {
    env: Env,
    /// Host named by the `CONNECT` that opened this connection; the fallback
    /// when the TLS hello carries no server name.
    connect_host: Option<String>,
    /// Set when the TLS connection was chosen for interception.
    conn: Option<Target>,
    pending: Option<Pending>,
}

impl Interceptor {
    pub(super) fn new(env: Env) -> Self {
        Self {
            env,
            connect_host: None,
            conn: None,
            pending: None,
        }
    }

    /// Whether to decrypt a TLS connection from `client` that asked for
    /// `server_name` (or, without one, the host its `CONNECT` named).
    async fn decide_tls(&mut self, client: SocketAddr, server_name: Option<String>) -> bool {
        let host = server_name
            .or_else(|| self.connect_host.clone())
            .unwrap_or_default();
        self.conn = self
            .env
            .target_for(client, &host, &mut Owner::default())
            .await;
        self.conn.is_some()
    }

    /// One request from `client`: anonymized when it is intercepted.
    async fn request(&mut self, client: SocketAddr, req: Request<Body>) -> RequestOrResponse {
        self.pending = None;
        // The tunnel itself: nothing to anonymize, hudsucker sets it up.
        if req.method() == Method::CONNECT {
            return req.into();
        }
        let target = match self.conn.clone() {
            // Inside a decrypted connection; the policy may have changed
            // since it was opened.
            Some(conn) => self
                .env
                .policy()
                .intercepts(&conn.host, conn.exe.as_deref())
                .then_some(conn),
            None => match request_host(&req) {
                Some(host) => {
                    self.env
                        .target_for(client, &host, &mut Owner::default())
                        .await
                }
                None => None,
            },
        };
        let Some(target) = target else {
            return req.into();
        };
        self.pending = Some(Pending {
            target: target.clone(),
            head: req.method() == Method::HEAD,
        });
        match self.env.rewrite_request(&target, req).await {
            Ok(req) => req.into(),
            Err(refusal) => {
                self.pending = None;
                refusal.into()
            }
        }
    }

    /// The response to the request in flight: restored when that request was
    /// intercepted.
    async fn response(&mut self, res: Response<Body>) -> Response<Body> {
        match self.pending.take() {
            Some(pending) => self.env.restore_response(&pending, res).await,
            None => res,
        }
    }
}

impl HttpHandler for Interceptor {
    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        self.connect_host = req.uri().host().map(normalize_host);
        true
    }

    /// The decision to decrypt: everything else is tunneled untouched, so the
    /// real certificate reaches the client.
    async fn should_intercept_tls(
        &mut self,
        ctx: &HttpContext,
        client_hello: ClientHello<'_>,
    ) -> bool {
        let sni = server_name(&client_hello);
        self.decide_tls(ctx.client_addr, sni).await
    }

    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        self.request(ctx.client_addr, req).await
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        self.response(res).await
    }
}

/// WebSocket traffic: whole text frames, both ways. One instance serves one
/// direction of one connection.
pub(super) struct WsInterceptor {
    env: Env,
    owner: Owner,
    /// The tolerant matcher for server frames, with the ledger generation it
    /// was built for.
    restorer: Option<(u64, Restorer)>,
}

impl Clone for WsInterceptor {
    /// A clone serves another connection: it starts without state.
    fn clone(&self) -> Self {
        Self::new(self.env.clone())
    }
}

impl WsInterceptor {
    pub(super) fn new(env: Env) -> Self {
        Self {
            env,
            owner: Owner::default(),
            restorer: None,
        }
    }

    /// The frame anonymized; `None` when it must not be sent.
    async fn mask_frame(&self, target: &Target, text: String) -> Option<String> {
        let engine = self.env.engine();
        let shared = Arc::clone(&self.env.shared);
        let host = Arc::clone(&target.host);
        let masked = tokio::task::spawn_blocking(move || {
            let sent = shared.ledger.sent_to(&host);
            let resent = |proxy: &str| sent.contains(proxy);
            let masked = mask(
                &engine,
                &shared.typed,
                Resent::These(&resent),
                &BodyKind::Text,
                text.as_bytes(),
            )?;
            for proxy in &masked.proxies {
                shared.ledger.touch(&host, proxy);
            }
            Ok::<_, piikey::Error>(masked)
        })
        .await
        .ok()?
        .ok()?;
        if !masked.counts.is_empty() {
            self.env.emit(Event::Masked {
                host: target.host.to_string(),
                exe: target.exe.as_deref().map(str::to_owned),
                proxies: masked.proxies,
            });
        }
        String::from_utf8(masked.body).ok()
    }

    /// The frame with its proxies restored; `None` when that fails.
    async fn restore_frame(&mut self, target: &Target, text: String) -> Option<String> {
        let engine = self.env.engine();
        let shared = Arc::clone(&self.env.shared);
        let host = Arc::clone(&target.host);
        let cached = self.restorer.take();
        let done = tokio::task::spawn_blocking(move || {
            restore_text(&engine, &shared, &host, cached, &text)
        })
        .await
        .ok()??;
        self.restorer = Some((done.generation, done.matcher));
        if done.count > 0 {
            self.env.emit(Event::Restored {
                host: target.host.to_string(),
                count: done.count,
            });
        }
        Some(done.text)
    }
}

/// One restored server frame, and the tolerant matcher to reuse for the next.
struct FrameRestore {
    generation: u64,
    matcher: Restorer,
    text: String,
    count: usize,
}

/// Restores `text` with the proxies sent to `host`, then with every proxy
/// the vault knows. `cached` is reused when the ledger has not changed since
/// it was built, so a chatty socket does not rebuild the matcher per frame.
fn restore_text(
    engine: &Engine,
    shared: &Shared,
    host: &str,
    cached: Option<(u64, Restorer)>,
    text: &str,
) -> Option<FrameRestore> {
    let generation = shared.ledger.generation();
    let mut matcher = match cached {
        Some((built_for, matcher)) if built_for == generation => matcher,
        _ => Restorer::new(shared.ledger.scope_for(host, engine.vault())).ok()?,
    };
    let before = matcher.restored_count();
    let mut out = matcher.feed(text.as_bytes());
    out.extend(matcher.flush());
    let mut count = matcher.restored_count() - before;
    let mut text = String::from_utf8(out).ok()?;
    // Whatever the ledger no longer knows, the vault still does.
    let plans = engine.plan(Mode::Deanonymize, &[text.as_str()]).ok();
    if let Some(reps) = plans.as_ref().and_then(|plans| plans.first())
        && !reps.is_empty()
    {
        count += reps.len();
        text = Engine::apply(&text, reps);
    }
    Some(FrameRestore {
        generation,
        matcher,
        text,
        count,
    })
}

/// The server name a TLS client asked for, lowercase.
fn server_name(hello: &ClientHello<'_>) -> Option<String> {
    hello.server_name().map(normalize_host)
}

impl WebSocketHandler for WsInterceptor {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        // Only text carries chat; binary, pings and closes go through.
        let Message::Text(text) = &message else {
            return Some(message);
        };
        let (client, host, outbound) = match ctx {
            WebSocketContext::ClientToServer { src, dst, .. } => (*src, dst.host(), true),
            WebSocketContext::ServerToClient { src, dst, .. } => (*dst, src.host(), false),
        };
        let Some(host) = host.map(normalize_host) else {
            return Some(message);
        };
        let Some(target) = self.env.target_for(client, &host, &mut self.owner).await else {
            return Some(message);
        };
        let text = text.as_str().to_owned();
        if outbound {
            // A frame that cannot be anonymized is not forwarded.
            self.mask_frame(&target, text).await.map(Message::text)
        } else {
            // A frame that cannot be restored is forwarded as it is.
            let restored = self.restore_frame(&target, text.clone()).await;
            Some(Message::text(restored.unwrap_or(text)))
        }
    }
}

/// `host` of the request: the absolute URI's, else the `Host` header's.
fn request_host(req: &Request<Body>) -> Option<String> {
    req.uri().host().map(normalize_host).or_else(|| {
        req.headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(normalize_host)
    })
}

/// `Content-Length`, when it is there and a number.
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Whether every `Content-Encoding` is one hudsucker can undo. Its decoder
/// compares the names exactly, so this does too: a request that passes this
/// check cannot fail to decode up front.
fn decodable(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .flat_map(|value| value.as_bytes().split(|&b| b == b','))
        .map(<[u8]>::trim_ascii)
        .all(|name| {
            matches!(
                name,
                b"identity" | b"gzip" | b"x-gzip" | b"deflate" | b"br" | b"zstd"
            )
        })
}

/// A plain-text answer from the app itself.
fn refuse(status: StatusCode, message: &str) -> Response<Body> {
    let mut res = Response::new(Body::from(format!("piikey: {message}\n")));
    *res.status_mut() = status;
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

fn too_large() -> Response<Body> {
    refuse(
        StatusCode::PAYLOAD_TOO_LARGE,
        "the request body is larger than 64 MiB and cannot be checked for personal data",
    )
}

/// The request could not be anonymized, so it is not sent.
fn unsafe_to_send(why: &str) -> Response<Body> {
    refuse(
        StatusCode::BAD_GATEWAY,
        &format!("the request was not sent because it could not be anonymized ({why})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for &(name, value) in pairs {
            map.append(name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn declared_length_reads_numbers_only() {
        assert_eq!(
            declared_length(&headers(&[("content-length", "42")])),
            Some(42)
        );
        assert_eq!(
            declared_length(&headers(&[("content-length", " 7 ")])),
            Some(7)
        );
        assert_eq!(declared_length(&headers(&[("content-length", "x")])), None);
        assert_eq!(declared_length(&HeaderMap::new()), None);
    }

    #[test]
    fn only_encodings_hudsucker_can_undo_are_decodable() {
        let ok = |value| decodable(&headers(&[("content-encoding", value)]));
        assert!(ok("gzip") && ok("br") && ok("zstd") && ok("deflate") && ok("identity"));
        assert!(ok("gzip, br") && ok(" gzip ,identity"));
        assert!(!ok("compress") && !ok("gzip, snappy") && !ok("GZIP"));
        let two = headers(&[("content-encoding", "gzip"), ("content-encoding", "weird")]);
        assert!(!decodable(&two), "every header value counts");
    }

    #[test]
    fn refusals_are_plain_text_with_the_status() {
        let res = unsafe_to_send("vault locked");
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(too_large().status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ---- decisions and frames, without a network ----

    use std::{
        net::TcpListener as StdListener,
        path::PathBuf,
        sync::{RwLock, mpsc},
    };

    use piikey::detect::EntityKind;

    use crate::{ledger::Ledger, proxy::Typed};

    const CLIENT: &str = "127.0.0.1:1";

    fn client() -> SocketAddr {
        CLIENT
            .parse()
            .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 1)))
    }

    fn temp_vault(tag: &str) -> PathBuf {
        crate::ui::testing::temp_dir(tag).join("vault.pkv")
    }

    fn policy(sites: &[&str], programs: &[&str]) -> Policy {
        Policy {
            enabled: true,
            sites: sites.iter().map(|s| (*s).to_owned()).collect(),
            programs: programs.iter().map(|p| (*p).to_owned()).collect(),
            ..Policy::default()
        }
    }

    /// A handler environment with a fresh vault; `origin_port` is the port
    /// the program lookup treats as the proxy's.
    fn make_env(
        tag: &str,
        policy: Policy,
        origin_port: u16,
    ) -> piikey::Result<(Env, mpsc::Receiver<Event>)> {
        let engine = Engine::open(&temp_vault(tag))?;
        let shared = Arc::new(Shared {
            engine: RwLock::new(Arc::new(engine)),
            policy: RwLock::new(policy),
            ledger: Ledger::default(),
            typed: Typed::new(),
            purpose: Arc::default(),
        });
        let (events, receiver) = mpsc::channel();
        let env = Env {
            shared,
            events,
            origin: Arc::new(Origin::new(origin_port)),
        };
        Ok((env, receiver))
    }

    fn request(method: Method, uri: &str, content_type: &'static str, body: &str) -> Request<Body> {
        let mut req = Request::new(Body::from(body.to_owned()));
        *req.method_mut() = method;
        *req.uri_mut() = uri.parse().unwrap_or_default();
        req.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        req
    }

    fn json_response(body: &str) -> Response<Body> {
        let mut res = Response::new(Body::from(body.to_owned()));
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        res.headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        res
    }

    async fn text_of(body: Body) -> String {
        collect(body, 1 << 20)
            .await
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default()
    }

    /// The request that went on, or the answer that replaced it.
    async fn forwarded(
        outcome: RequestOrResponse,
    ) -> Result<(Request<Body>, String), (StatusCode, String)> {
        match outcome {
            RequestOrResponse::Request(req) => {
                let (parts, body) = req.into_parts();
                let text = text_of(body).await;
                Ok((Request::from_parts(parts, Body::empty()), text))
            }
            RequestOrResponse::Response(res) => {
                let status = res.status();
                Err((status, text_of(res.into_body()).await))
            }
        }
    }

    const EMAIL: &str = "jan.jansen@acme.nl";

    #[tokio::test]
    async fn the_tls_decision_follows_site_rules_and_falls_back_to_the_connect_host()
    -> piikey::Result<()> {
        let (env, _events) = make_env(
            "tls-sites",
            policy(&["chat.example.com", "*.ai.example"], &[]),
            1,
        )?;
        let mut interceptor = Interceptor::new(env);
        assert!(
            interceptor
                .decide_tls(client(), Some("chat.example.com".into()))
                .await
        );
        assert!(
            interceptor
                .decide_tls(client(), Some("api.ai.example".into()))
                .await
        );
        assert!(
            !interceptor
                .decide_tls(client(), Some("example.org".into()))
                .await
        );
        assert!(
            interceptor.conn.is_none(),
            "a refused connection keeps no decision"
        );

        // No server name in the hello: the host the CONNECT named decides.
        interceptor.connect_host = Some("chat.example.com".into());
        assert!(interceptor.decide_tls(client(), None).await);
        interceptor.connect_host = Some("other.example".into());
        assert!(!interceptor.decide_tls(client(), None).await);
        interceptor.connect_host = None;
        assert!(!interceptor.decide_tls(client(), None).await);
        Ok(())
    }

    #[tokio::test]
    async fn a_disabled_app_decrypts_nothing() -> piikey::Result<()> {
        let mut off = policy(&["chat.example.com"], &["chrome.exe"]);
        off.enabled = false;
        let (env, _events) = make_env("tls-off", off, 1)?;
        let mut interceptor = Interceptor::new(env);
        assert!(
            !interceptor
                .decide_tls(client(), Some("chat.example.com".into()))
                .await
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_tls_decision_names_the_program_for_program_rules() -> piikey::Result<()> {
        // A real connection from this process to a listener standing in for the proxy.
        let io = piikey::Error::Io;
        let listener = StdListener::bind("127.0.0.1:0").map_err(io)?;
        let proxy_port = listener.local_addr().map_err(io)?.port();
        let socket = std::net::TcpStream::connect(("127.0.0.1", proxy_port)).map_err(io)?;
        let client = socket.local_addr().map_err(io)?;
        let (_accepted, _) = listener.accept().map_err(io)?;
        let own = std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().to_lowercase()))
            .unwrap_or_default();

        let (env, _events) = make_env("tls-program", policy(&[], &[own.as_str()]), proxy_port)?;
        let mut interceptor = Interceptor::new(env);
        assert!(
            interceptor
                .decide_tls(client, Some("any.host.example".into()))
                .await
        );
        assert_eq!(
            interceptor.conn.as_ref().and_then(|c| c.exe.as_deref()),
            Some(own.as_str())
        );

        let (env, _events) =
            make_env("tls-other", policy(&[], &["other-program.exe"]), proxy_port)?;
        let mut interceptor = Interceptor::new(env);
        assert!(
            !interceptor
                .decide_tls(client, Some("any.host.example".into()))
                .await
        );
        Ok(())
    }

    #[tokio::test]
    async fn requests_in_a_decrypted_connection_are_anonymized_and_their_replies_restored()
    -> piikey::Result<()> {
        let (env, events) = make_env("conn", policy(&["chat.example.com"], &[]), 1)?;
        let shared = Arc::clone(&env.shared);
        let mut interceptor = Interceptor::new(env);
        assert!(
            interceptor
                .decide_tls(client(), Some("chat.example.com".into()))
                .await
        );

        // As hudsucker hands it over inside the tunnel: https + the CONNECT authority.
        let json = format!(r#"{{"m":"mail {EMAIL}"}}"#);
        let req = request(
            Method::POST,
            "https://chat.example.com/backend-api/conversation",
            "application/json",
            &json,
        );
        let Ok((sent, body)) = forwarded(interceptor.request(client(), req).await).await else {
            panic!("the request was refused");
        };
        assert!(!body.contains(EMAIL), "{body}");
        assert_eq!(
            sent.headers()
                .get(ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("identity")
        );
        assert_eq!(
            sent.headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(body.len().to_string().as_str())
        );
        assert!(sent.headers().get(TRANSFER_ENCODING).is_none());
        assert!(
            matches!(&events.try_recv(), Ok(Event::Masked { host, .. }) if host == "chat.example.com")
        );

        // The reply quotes the proxy: it comes back as the original, streamed
        // (no length) and reported.
        let res = interceptor.response(json_response(&body)).await;
        assert!(res.headers().get(CONTENT_LENGTH).is_none());
        assert_eq!(text_of(res.into_body()).await, json);
        assert!(matches!(
            events.try_recv(),
            Ok(Event::Restored { count: 1, .. })
        ));
        assert!(
            shared.ledger.generation() > 0,
            "the proxy was recorded as sent"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_policy_change_applies_inside_an_open_connection() -> piikey::Result<()> {
        let (env, _events) = make_env("conn-policy", policy(&["chat.example.com"], &[]), 1)?;
        let shared = Arc::clone(&env.shared);
        let mut interceptor = Interceptor::new(env);
        assert!(
            interceptor
                .decide_tls(client(), Some("chat.example.com".into()))
                .await
        );

        if let Ok(mut policy) = shared.policy.write() {
            policy.sites.clear();
        }
        let json = format!(r#"{{"m":"mail {EMAIL}"}}"#);
        let req = request(
            Method::POST,
            "https://chat.example.com/api",
            "application/json",
            &json,
        );
        let Ok((sent, body)) = forwarded(interceptor.request(client(), req).await).await else {
            panic!("the request was refused");
        };
        assert_eq!(body, json, "no longer intercepted: untouched");
        assert!(sent.headers().get(ACCEPT_ENCODING).is_none());
        assert!(interceptor.pending.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn connect_requests_and_other_hosts_pass_untouched() -> piikey::Result<()> {
        let (env, events) = make_env("passes", policy(&["chat.example.com"], &[]), 1)?;
        let mut interceptor = Interceptor::new(env);
        let connect = request(
            Method::CONNECT,
            "chat.example.com:443",
            "application/json",
            "x",
        );
        assert!(matches!(
            interceptor.request(client(), connect).await,
            RequestOrResponse::Request(_)
        ));
        assert!(interceptor.pending.is_none());

        let json = format!(r#"{{"m":"mail {EMAIL}"}}"#);
        let req = request(
            Method::POST,
            "http://elsewhere.example/api",
            "application/json",
            &json,
        );
        let Ok((_, body)) = forwarded(interceptor.request(client(), req).await).await else {
            panic!("the request was refused");
        };
        assert_eq!(body, json);
        assert!(events.try_recv().is_err());
        // The reply of an untouched request is untouched too.
        let res = interceptor.response(json_response(&json)).await;
        assert!(res.headers().get(CONTENT_LENGTH).is_some());
        Ok(())
    }

    #[tokio::test]
    async fn replies_without_a_text_body_are_not_wrapped() -> piikey::Result<()> {
        let (env, _events) = make_env("no-wrap", policy(&["chat.example.com"], &[]), 1)?;
        let mut interceptor = Interceptor::new(env);
        assert!(
            interceptor
                .decide_tls(client(), Some("chat.example.com".into()))
                .await
        );
        let mut cases = Vec::new();
        for (method, status, content_type) in [
            (Method::HEAD, StatusCode::OK, "application/json"),
            (Method::GET, StatusCode::NO_CONTENT, "application/json"),
            (Method::GET, StatusCode::NOT_MODIFIED, "application/json"),
            (Method::GET, StatusCode::PARTIAL_CONTENT, "application/json"),
            (Method::GET, StatusCode::OK, "image/png"),
            (Method::GET, StatusCode::OK, "text/css"),
            (Method::GET, StatusCode::OK, "text/javascript"),
        ] {
            let req = request(
                method.clone(),
                "https://chat.example.com/x",
                "text/plain",
                "",
            );
            let _ = interceptor.request(client(), req).await;
            let mut res = json_response("{}");
            *res.status_mut() = status;
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
            let res = interceptor.response(res).await;
            cases.push((method, status, res.headers().contains_key(CONTENT_LENGTH)));
        }
        assert!(cases.iter().all(|&(_, _, kept)| kept), "{cases:?}");
        Ok(())
    }

    #[tokio::test]
    async fn a_request_that_cannot_be_anonymized_is_not_sent() -> piikey::Result<()> {
        let path = temp_vault("refused");
        let (env, _events) = make_env("refused-x", policy(&["chat.example.com"], &[]), 1)?;
        // Swap in an engine whose vault file is cut behind its back.
        let engine = Engine::open(&path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.set_len(0)?;
        drop(file);
        if let Ok(mut slot) = env.shared.engine.write() {
            *slot = Arc::new(engine);
        }
        let mut interceptor = Interceptor::new(env);
        assert!(
            interceptor
                .decide_tls(client(), Some("chat.example.com".into()))
                .await
        );
        let json = format!(r#"{{"m":"mail {EMAIL}"}}"#);
        let req = request(
            Method::POST,
            "https://chat.example.com/api",
            "application/json",
            &json,
        );
        let Err((status, body)) = forwarded(interceptor.request(client(), req).await).await else {
            panic!("the request must not be forwarded");
        };
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("not sent"), "{body}");
        assert!(interceptor.pending.is_none(), "no reply to restore");
        Ok(())
    }

    // ---- WebSocket frames ----

    #[tokio::test]
    async fn outgoing_frames_are_anonymized_recorded_and_reported() -> piikey::Result<()> {
        let (env, events) = make_env("ws-out", policy(&["chat.example.com"], &[]), 1)?;
        let shared = Arc::clone(&env.shared);
        let ws = WsInterceptor::new(env);
        let target = Target {
            host: Arc::from("chat.example.com"),
            exe: Some(Arc::from("chrome.exe")),
        };
        let frame = ws
            .mask_frame(&target, format!(r#"{{"text":"hi {EMAIL}"}}"#))
            .await
            .unwrap_or_default();
        assert!(!frame.contains(EMAIL), "{frame}");
        assert!(frame.starts_with(r#"{"text":"hi "#) && frame.ends_with(r#""}"#));
        let Ok(Event::Masked { host, exe, .. }) = events.try_recv() else {
            panic!("expected a Masked event");
        };
        assert_eq!(host, "chat.example.com");
        assert_eq!(exe.as_deref(), Some("chrome.exe"));
        let engine = shared
            .engine
            .read()
            .map(|e| Arc::clone(&e))
            .map_err(|_| piikey::Error::Poisoned)?;
        let scope = shared.ledger.scope_for("chat.example.com", engine.vault());
        assert_eq!(scope.entries().len(), 1);
        assert_eq!(scope.entries()[0].kind, EntityKind::Email);
        assert_eq!(&*scope.entries()[0].original, EMAIL);
        Ok(())
    }

    #[tokio::test]
    async fn incoming_frames_get_their_proxies_back_and_the_matcher_is_reused() -> piikey::Result<()>
    {
        let (env, events) = make_env("ws-in", policy(&["chat.example.com"], &[]), 1)?;
        let shared = Arc::clone(&env.shared);
        let mut ws = WsInterceptor::new(env.clone());
        let target = Target {
            host: Arc::from("chat.example.com"),
            exe: None,
        };
        let sent = ws
            .mask_frame(&target, format!("write to {EMAIL}"))
            .await
            .unwrap_or_default();
        let proxy = sent
            .strip_prefix("write to ")
            .unwrap_or_default()
            .to_owned();
        assert!(events.try_recv().is_ok(), "the Masked event");

        let restored = ws.restore_frame(&target, format!("done: {proxy}!")).await;
        assert_eq!(
            restored.as_deref(),
            Some(format!("done: {EMAIL}!").as_str())
        );
        assert!(matches!(
            events.try_recv(),
            Ok(Event::Restored { count: 1, .. })
        ));
        let built_for = ws.restorer.as_ref().map(|(generation, _)| *generation);
        assert_eq!(built_for, Some(shared.ledger.generation()));

        // Nothing new was sent: the matcher is kept; a frame without proxies reports nothing.
        let plain = ws.restore_frame(&target, "no proxies here".into()).await;
        assert_eq!(plain.as_deref(), Some("no proxies here"));
        assert!(events.try_recv().is_err());
        assert_eq!(
            ws.restorer.as_ref().map(|(generation, _)| *generation),
            built_for
        );

        // Something new was sent: the next frame rebuilds it.
        shared.ledger.touch("chat.example.com", "another-proxy");
        ws.restore_frame(&target, "x".into()).await;
        assert_eq!(
            ws.restorer.as_ref().map(|(generation, _)| *generation),
            Some(shared.ledger.generation())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_frame_that_cannot_be_anonymized_is_dropped() -> piikey::Result<()> {
        let path = temp_vault("ws-drop");
        let (env, _events) = make_env("ws-drop-x", policy(&["chat.example.com"], &[]), 1)?;
        let engine = Engine::open(&path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.set_len(0)?;
        drop(file);
        if let Ok(mut slot) = env.shared.engine.write() {
            *slot = Arc::new(engine);
        }
        let ws = WsInterceptor::new(env);
        let target = Target {
            host: Arc::from("chat.example.com"),
            exe: None,
        };
        assert_eq!(ws.mask_frame(&target, format!("mail {EMAIL}")).await, None);
        Ok(())
    }
}
