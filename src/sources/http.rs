//! The one blocking HTTPS client every connector uses: Windows' own TLS (so the certificate store,
//! and a company's TLS-inspection root, is trusted), timeouts, retries that honour `Retry-After`,
//! form and JSON bodies, and a cap on what a download may hold.
//!
//! A reply of any status comes back as a [`Reply`]: the caller decides what its status means
//! ([`Reply::error`] says what a plain status stands for). The services' base addresses are not
//! here: each connector holds its own, so a test points it at a [`super::testing::Mock`].
//! Windows' system proxy is not used (piikey turns it to its own while protection is on); the
//! `HTTPS_PROXY` and `ALL_PROXY` environment variables are.

use std::{
    fmt::{self, Write as _},
    io::{self, Read as _},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::de::DeserializeOwned;
use ureq::{
    Agent,
    tls::{RootCerts, TlsConfig, TlsProvider},
};

use super::{Error, Provider, Result};

/// Tries for one request: the first, and the ones after a throttled or busy answer or a
/// connection that failed.
const TRIES: u32 = 5;
/// The longest piikey waits, inside one call, because a service asked it to. A service that asks
/// for more is answered with what it said, and left to the caller (the next scan).
const MAX_WAIT: Duration = Duration::from_mins(1);
/// The wait before the second try when the service named none; each later one doubles it.
const FIRST_WAIT: Duration = Duration::from_secs(1);
/// How long making a connection takes at most, TLS included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one call takes at most, from the first byte sent to the last received.
const CALL_TIMEOUT: Duration = Duration::from_mins(2);
/// The same for a call that downloads a file.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_mins(10);
/// The biggest answer to a call that is not a download: a page of a listing, a token.
const JSON_LIMIT: u64 = 32 << 20;
/// The most pages [`pages`] follows: more means the service never says it is done.
const MAX_PAGES: usize = 100_000;
/// How much of an answer's text goes into the detail of an error.
const DETAIL_LEN: usize = 300;
/// How much of a failure's own message is read even when the cap for a file is smaller.
const ERROR_LIMIT: u64 = 1 << 20;
/// How much of a download is read at a time, between two looks at the cancel flag.
const READ_CHUNK: usize = 64 << 10;
/// How often a wait looks at the cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// Never set: for calls nobody can stop.
static NEVER: AtomicBool = AtomicBool::new(false);

/// What to do while waiting for a service, `cancel` being the stop flag of the scan the wait is
/// in: sleeps, or in a test notes how long.
type Pause = Arc<dyn Fn(Duration, &AtomicBool) + Send + Sync>;

/// Sleeps for `wait`, or until `cancel` is set.
fn sleep_unless_cancelled(wait: Duration, cancel: &AtomicBool) {
    let end = Instant::now() + wait;
    while !cancel.load(Ordering::Relaxed) {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        thread::sleep(left.min(CANCEL_POLL));
    }
}

/// The client of one provider. It is cheap to clone: the connections are shared.
#[derive(Clone)]
pub(crate) struct Http {
    agent: Agent,
    provider: Provider,
    pause: Pause,
}

impl fmt::Debug for Http {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl Http {
    /// A client for `provider`; the errors it makes are about that provider.
    pub(crate) fn new(provider: Provider) -> Self {
        Self::build(provider, Arc::new(sleep_unless_cancelled))
    }

    /// A client that calls `pause` where it would sleep, so a test neither waits nor loses track
    /// of how long it was asked to.
    #[cfg(test)]
    pub(crate) fn with_pause(
        provider: Provider,
        pause: impl Fn(Duration) + Send + Sync + 'static,
    ) -> Self {
        Self::build(provider, Arc::new(move |wait, _| pause(wait)))
    }

    fn build(provider: Provider, pause: Pause) -> Self {
        // `PlatformVerifier` with the native TLS is the Windows certificate store.
        let tls = TlsConfig::builder()
            .provider(TlsProvider::NativeTls)
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("piikey/", env!("CARGO_PKG_VERSION")))
            .tls_config(tls)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(CALL_TIMEOUT))
            .build();
        Self {
            agent: Agent::new_with_config(config),
            provider,
            pause,
        }
    }

    /// The provider whose service this talks to.
    pub(crate) const fn provider(&self) -> Provider {
        self.provider
    }

    /// Sends `request` and reads the whole answer, whatever its status. A throttled or busy
    /// answer (429, 502, 503, 504) is waited out as the service asks and tried again, up to five
    /// tries, but never for longer than a minute at a time.
    ///
    /// # Errors
    /// `Network` when the service cannot be reached; `Unexpected` for an answer over 32 MiB or
    /// a request that cannot be made.
    pub(crate) fn send(&self, request: &Request) -> Result<Reply> {
        self.call(request, JSON_LIMIT, CALL_TIMEOUT, &NEVER)
            .map_err(|error| match error {
                Error::TooLarge => Error::unexpected(self.provider, "the answer is too large"),
                other => other,
            })
    }

    /// [`Http::send`] for a request that answers with a file: the body is at most `max` bytes.
    /// A reply that is not a success has the service's own (small) message as its body. The
    /// download is read in pieces, and a set `cancel` ends it (and a wait for a busy service)
    /// within a moment.
    ///
    /// # Errors
    /// `TooLarge` when the body has more than `max` bytes, whether or not the service says so
    /// first; `Cancelled` when `cancel` was set; otherwise as [`Http::send`].
    pub(crate) fn download(
        &self,
        request: &Request,
        max: u64,
        cancel: &AtomicBool,
    ) -> Result<Reply> {
        self.call(request, max, DOWNLOAD_TIMEOUT, cancel)
    }

    fn call(
        &self,
        request: &Request,
        limit: u64,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<Reply> {
        let mut tries = 0;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            tries += 1;
            let last = tries >= TRIES;
            match self.once(request, limit, timeout, cancel) {
                Ok(reply) => {
                    if !last && is_busy(reply.status) {
                        let wait = reply.retry_after().unwrap_or_else(|| backoff(tries));
                        if wait <= MAX_WAIT {
                            (self.pause)(wait, cancel);
                            continue;
                        }
                    }
                    return Ok(reply);
                }
                Err(Attempt::Transport { retry: true, .. }) if !last => {
                    (self.pause)(backoff(tries), cancel);
                }
                Err(Attempt::Transport {
                    retry: true,
                    detail,
                }) => {
                    return Err(Error::network(self.provider, detail));
                }
                Err(Attempt::Transport { detail, .. }) => {
                    return Err(Error::unexpected(self.provider, detail));
                }
                Err(Attempt::TooLarge) => return Err(Error::TooLarge),
                Err(Attempt::Cancelled) => return Err(Error::Cancelled),
            }
        }
    }

    /// One try.
    fn once(
        &self,
        request: &Request,
        limit: u64,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> std::result::Result<Reply, Attempt> {
        let response = self.dispatch(request, timeout)?;
        let status = response.status().as_u16();
        // The cap is for a file. What a service says about a failure is small whatever the cap,
        // and must not read as a file that is too large.
        let limit = if (200..300).contains(&status) {
            limit
        } else {
            limit.max(ERROR_LIMIT)
        };
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response.into_body();
        let declared = body.content_length();
        if declared.is_some_and(|len| len > limit) {
            return Err(Attempt::TooLarge);
        }
        let mut bytes =
            Vec::with_capacity(declared.map_or(0, |len| usize::try_from(len).unwrap_or_default()));
        let mut reader = body
            .into_with_config()
            .limit(u64::MAX)
            .reader()
            .take(limit.saturating_add(1));
        let mut chunk = vec![0; READ_CHUNK];
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(Attempt::Cancelled);
            }
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => bytes.extend_from_slice(chunk.get(..read).unwrap_or_default()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(Attempt::Transport {
                        detail: error.to_string(),
                        retry: true,
                    });
                }
            }
        }
        if u64::try_from(bytes.len()).is_ok_and(|len| len > limit) {
            return Err(Attempt::TooLarge);
        }
        Ok(Reply {
            provider: self.provider,
            status,
            headers,
            body: bytes,
        })
    }

    fn dispatch(
        &self,
        request: &Request,
        timeout: Duration,
    ) -> std::result::Result<ureq::http::Response<ureq::Body>, Attempt> {
        let result = match request.method {
            Method::Get => {
                let mut call = self
                    .agent
                    .get(&request.url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build();
                for (name, value) in &request.headers {
                    call = call.header(name, value);
                }
                call.query_pairs(request.query.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    .call()
            }
            Method::Post => {
                let mut call = self
                    .agent
                    .post(&request.url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build();
                for (name, value) in &request.headers {
                    call = call.header(name, value);
                }
                let call =
                    call.query_pairs(request.query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
                match &request.body {
                    Body::None => call.send_empty(),
                    Body::Form(fields) => {
                        call.send_form(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    }
                    Body::Json(bytes) => {
                        call.content_type("application/json").send(bytes.as_slice())
                    }
                }
            }
        };
        result.map_err(Attempt::from)
    }
}

/// Why one try did not give an answer.
enum Attempt {
    /// The request could not be made or the answer not read; `retry` says whether another try
    /// can help (a connection that fails does; an address that cannot be parsed does not).
    Transport { detail: String, retry: bool },
    /// The body has more bytes than allowed.
    TooLarge,
    /// The caller stopped it.
    Cancelled,
}

impl From<ureq::Error> for Attempt {
    fn from(error: ureq::Error) -> Self {
        let retry = !matches!(
            error,
            ureq::Error::BadUri(_)
                | ureq::Error::Http(_)
                | ureq::Error::RequireHttpsOnly(_)
                | ureq::Error::InvalidProxyUrl
        );
        Self::Transport {
            detail: error.to_string(),
            retry,
        }
    }
}

/// Whether a status says the service is busy and a later try may do.
const fn is_busy(status: u16) -> bool {
    matches!(status, 429 | 502 | 503 | 504)
}

/// The wait before the try after number `tries` when the service named none: 1, 2, 4 seconds...
fn backoff(tries: u32) -> Duration {
    FIRST_WAIT * 2_u32.saturating_pow(tries.saturating_sub(1))
}

/// The two methods the services need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
}

#[derive(Clone)]
enum Body {
    None,
    /// The fields of a form, to be encoded as one.
    Form(Vec<(String, String)>),
    Json(Vec<u8>),
}

/// A request, built before it is sent so it can be sent again.
#[derive(Clone)]
pub(crate) struct Request {
    method: Method,
    url: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Body,
}

// No headers, no fields: they hold tokens, codes and secrets.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url.split('?').next().unwrap_or_default())
            .finish_non_exhaustive()
    }
}

impl Request {
    /// A GET of `url`, which may have a query already.
    pub(crate) fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url.into())
    }

    /// A POST to `url`.
    pub(crate) fn post(url: impl Into<String>) -> Self {
        Self::new(Method::Post, url.into())
    }

    fn new(method: Method, url: String) -> Self {
        Self {
            method,
            url,
            query: Vec::new(),
            headers: Vec::new(),
            body: Body::None,
        }
    }

    /// Adds a field to the query; both parts are encoded.
    #[must_use]
    pub(crate) fn query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Sets a header, replacing one of the same name.
    #[must_use]
    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .retain(|(have, _)| !have.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Sets `Authorization: Bearer <token>`.
    #[must_use]
    pub(crate) fn bearer(self, token: &str) -> Self {
        self.header("Authorization", &format!("Bearer {token}"))
    }

    /// Adds a field to the body, which is sent as a form (`application/x-www-form-urlencoded`).
    #[must_use]
    pub(crate) fn form(mut self, name: &str, value: &str) -> Self {
        let field = (name.to_owned(), value.to_owned());
        match &mut self.body {
            Body::Form(fields) => fields.push(field),
            body => *body = Body::Form(vec![field]),
        }
        self
    }

    /// Sets the body to `value`, sent as JSON.
    #[must_use]
    pub(crate) fn json(mut self, value: &serde_json::Value) -> Self {
        self.body = Body::Json(value.to_string().into_bytes());
        self
    }
}

/// What a service answered.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    provider: Provider,
    pub(crate) status: u16,
    headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// The value of the header `name`, in any letter case.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(have, value)| have.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }

    /// Whether the status is a success (2xx).
    pub(crate) const fn is_success(&self) -> bool {
        matches!(self.status, 200..=299)
    }

    /// How long the service asked to wait (`Retry-After` in seconds); a date is not read.
    pub(crate) fn retry_after(&self) -> Option<Duration> {
        self.header("retry-after")?
            .trim()
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    }

    /// The body as JSON.
    ///
    /// # Errors
    /// `Unexpected` when it is not the `T` that was asked for.
    pub(crate) fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|error| {
            Error::unexpected(
                self.provider,
                format!("the answer is not what was expected: {error}"),
            )
        })
    }

    /// The body as text, for what a service says about an error.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// This reply when it is a success, and otherwise [`Reply::error`].
    ///
    /// # Errors
    /// What the status stands for.
    pub(crate) fn ok(self) -> Result<Self> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(self.error())
        }
    }

    /// What a status that is not a success stands for, by itself: 401 is a sign-in that is no
    /// longer good, 403 a permission that is missing, 404 and 410 something that is not there,
    /// 429 (and a 503 that says when to come back) throttling, other 5xx a service that is not
    /// reachable, and the rest an answer piikey does not understand. A connector that knows
    /// more (Google's 403 for too many calls, Dropbox's 409 for a path that is not there) looks
    /// at the body first.
    pub(crate) fn error(&self) -> Error {
        let provider = self.provider;
        let mut detail = format!("HTTP {}", self.status);
        let text = self.text();
        let text = text.trim();
        if !text.is_empty() {
            detail.push_str(": ");
            detail.extend(text.chars().take(DETAIL_LEN));
        }
        match self.status {
            401 => Error::sign_in_needed(provider, detail),
            403 => Error::forbidden(provider, detail),
            404 | 410 => Error::not_found(provider, detail),
            429 => Error::throttled(provider, self.retry_after(), detail),
            503 if self.retry_after().is_some() => {
                Error::throttled(provider, self.retry_after(), detail)
            }
            408 | 500..=599 => Error::network(provider, detail),
            _ => Error::unexpected(provider, detail),
        }
    }
}

/// Sends `first` with `send`, hands each answer to `page`, and sends the request `page` gives
/// back, until it gives `None`: the last page. It stops with `Cancelled` between two pages when
/// `cancel` is set.
///
/// # Errors
/// What `send` or `page` fails with; `Cancelled`; `Unexpected` when there are over 100,000 pages.
pub(crate) fn pages(
    provider: Provider,
    cancel: &AtomicBool,
    first: Request,
    send: &dyn Fn(&Request) -> Result<Reply>,
    mut page: impl FnMut(Reply) -> Result<Option<Request>>,
) -> Result<()> {
    let mut next = Some(first);
    let mut count = 0_usize;
    while let Some(request) = next {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        count += 1;
        if count > MAX_PAGES {
            return Err(Error::unexpected(provider, "the listing does not end"));
        }
        next = page(send(&request)?)?;
    }
    Ok(())
}

/// `text` as one segment of a URL's path, or one value of its query: everything but letters,
/// digits and `-._~` is percent-encoded.
pub(crate) fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `path` with each of its `/`-separated segments encoded by [`encode`].
pub(crate) fn encode_path(path: &str) -> String {
    path.split('/').map(encode).collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use std::{
        net::TcpListener,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use serde_json::json;

    use super::*;
    use crate::sources::testing::{Answer, Mock, Res};

    /// A client that never sleeps and notes how long it was asked to.
    fn quick() -> (Http, Arc<Mutex<Vec<Duration>>>) {
        let waits = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&waits);
        let http = Http::with_pause(Provider::Dropbox, move |wait| {
            if let Ok(mut waits) = seen.lock() {
                waits.push(wait);
            }
        });
        (http, waits)
    }

    fn waited(waits: &Mutex<Vec<Duration>>) -> Vec<Duration> {
        waits.lock().map(|waits| waits.clone()).unwrap_or_default()
    }

    #[test]
    fn a_throttled_call_waits_as_long_as_the_service_asked_and_tries_again() -> Res {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let mock = Mock::start(move |_| {
            if counted.fetch_add(1, Ordering::SeqCst) < 2 {
                Answer::empty(429).header("Retry-After", "7")
            } else {
                Answer::json(200, &json!({"ok": true}))
            }
        })?;
        let (http, waits) = quick();
        let reply = http.send(&Request::get(format!("{}/x", mock.url())))?;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.json::<serde_json::Value>()?["ok"], true);
        assert_eq!(waited(&waits), [Duration::from_secs(7); 2]);
        assert_eq!(mock.seen().len(), 3);
        Ok(())
    }

    #[test]
    fn a_wait_longer_than_a_minute_is_left_to_the_caller() -> Res {
        let mock = Mock::start(|_| Answer::text(429, "slow down").header("Retry-After", "900"))?;
        let (http, waits) = quick();
        let reply = http.send(&Request::get(format!("{}/x", mock.url())))?;
        assert_eq!(reply.status, 429);
        assert!(waited(&waits).is_empty());
        assert_eq!(mock.seen().len(), 1);
        let error = reply.error();
        assert!(
            matches!(&error, Error::Throttled { retry_after: Some(wait), .. } if *wait == Duration::from_mins(15)),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn a_busy_service_is_tried_again_with_growing_waits_and_then_given_up_on() -> Res {
        let mock = Mock::start(|_| Answer::empty(503))?;
        let (http, waits) = quick();
        let reply = http.send(&Request::post(format!("{}/x", mock.url())).form("a", "1"))?;
        assert_eq!(reply.status, 503);
        assert_eq!(mock.seen().len(), 5, "five tries");
        assert_eq!(
            waited(&waits),
            [1, 2, 4, 8].map(Duration::from_secs),
            "doubling from a second"
        );
        assert!(matches!(reply.error(), Error::Network { .. }));
        Ok(())
    }

    #[test]
    fn an_unreachable_service_is_a_network_failure_after_a_few_tries() -> Res {
        let closed = TcpListener::bind(("127.0.0.1", 0))?;
        let port = closed.local_addr()?.port();
        drop(closed);
        let (http, waits) = quick();
        let error = http.send(&Request::get(format!("http://127.0.0.1:{port}/x")));
        assert!(
            matches!(
                &error,
                Err(Error::Network {
                    provider: Provider::Dropbox,
                    ..
                })
            ),
            "{error:?}"
        );
        assert_eq!(waited(&waits).len(), 4);
        let shown = error
            .map(|_| ())
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            shown.contains("Dropbox") && !shown.contains("127.0.0.1"),
            "{shown}"
        );
        Ok(())
    }

    #[test]
    fn a_download_over_the_limit_is_too_large_whether_or_not_its_length_is_said() -> Res {
        let mock = Mock::start(|seen| {
            let body = vec![b'x'; 10];
            if seen.path() == "/sized" {
                Answer::bytes(200, body)
            } else {
                Answer::bytes(200, body).streamed()
            }
        })?;
        let (http, _) = quick();
        let never = AtomicBool::new(false);
        for path in ["/sized", "/unsized"] {
            let request = Request::get(format!("{}{path}", mock.url()));
            assert!(
                matches!(http.download(&request, 9, &never), Err(Error::TooLarge)),
                "{path}"
            );
            assert_eq!(
                http.download(&request, 10, &never)?.body.len(),
                10,
                "{path}"
            );
        }
        Ok(())
    }

    #[test]
    fn what_a_service_says_of_a_failure_is_never_taken_for_a_file_that_is_too_large() -> Res {
        let note = "x".repeat(2_000);
        let mock = Mock::start(move |_| Answer::text(404, &note))?;
        let (http, _) = quick();
        let request = Request::get(format!("{}/gone", mock.url()));
        let reply = http.download(&request, 5, &AtomicBool::new(false))?;
        assert_eq!((reply.status, reply.body.len()), (404, 2_000));
        assert!(matches!(reply.error(), Error::NotFound { .. }));
        Ok(())
    }

    #[test]
    fn a_download_that_is_cancelled_ends_and_so_does_a_wait_for_a_busy_service() -> Res {
        let mock = Mock::start(|seen| {
            if seen.path() == "/busy" {
                Answer::empty(503).header("Retry-After", "30")
            } else {
                Answer::bytes(200, vec![b'x'; 200_000])
            }
        })?;
        let http = Http::new(Provider::Box);
        let cancel = AtomicBool::new(true);
        let started = Instant::now();
        let busy = Request::get(format!("{}/busy", mock.url()));
        assert!(matches!(
            http.download(&busy, 1 << 20, &cancel),
            Err(Error::Cancelled)
        ));
        assert!(
            mock.seen().is_empty(),
            "a scan that is stopped asks for nothing"
        );

        // Cancelled while waiting 30 s for a busy service: the wait ends within moments.
        let cancel = Arc::new(AtomicBool::new(false));
        let stopper = {
            let cancel = Arc::clone(&cancel);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                cancel.store(true, Ordering::Relaxed);
            })
        };
        assert!(matches!(
            http.download(&busy, 1 << 20, &cancel),
            Err(Error::Cancelled)
        ));
        let _ = stopper.join();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(mock.seen().len(), 1);
        Ok(())
    }

    #[test]
    fn the_bearer_the_query_and_the_body_reach_the_service() -> Res {
        let mock = Mock::start(|_| Answer::empty(204))?;
        let (http, _) = quick();
        let base = mock.url();
        http.send(
            &Request::get(format!("{base}/list?alt=json"))
                .query("q", "name = 'a b'")
                .bearer("t0k3n")
                .header("Accept", "application/json"),
        )?;
        http.send(
            &Request::post(format!("{base}/token"))
                .form("grant_type", "refresh_token")
                .form("refresh_token", "a b&c"),
        )?;
        http.send(
            &Request::post(format!("{base}/api"))
                .json(&json!({"path": "/Ä"}))
                .bearer("x"),
        )?;
        let seen = mock.seen();
        assert_eq!(seen[0].param("alt").as_deref(), Some("json"));
        assert_eq!(seen[0].param("q").as_deref(), Some("name = 'a b'"));
        assert_eq!(seen[0].header("authorization"), Some("Bearer t0k3n"));
        assert_eq!(seen[0].header("accept"), Some("application/json"));
        assert!(
            seen[0]
                .header("user-agent")
                .is_some_and(|agent| agent.starts_with("piikey/"))
        );
        assert_eq!(seen[1].method, "POST");
        assert_eq!(seen[1].field("refresh_token").as_deref(), Some("a b&c"));
        assert_eq!(seen[1].header("authorization"), None);
        assert_eq!(seen[2].json(), json!({"path": "/Ä"}));
        assert_eq!(seen[2].header("content-type"), Some("application/json"));
        Ok(())
    }

    #[test]
    fn a_status_stands_for_what_a_person_can_act_on() {
        let reply = |status, retry: Option<&str>| Reply {
            provider: Provider::GoogleDrive,
            status,
            headers: retry
                .map(|seconds| vec![("Retry-After".to_owned(), seconds.to_owned())])
                .unwrap_or_default(),
            body: b"{\"error\":\"secret detail\"}".to_vec(),
        };
        assert!(matches!(
            reply(401, None).error(),
            Error::SignInNeeded { .. }
        ));
        assert!(matches!(reply(403, None).error(), Error::Forbidden { .. }));
        assert!(matches!(reply(404, None).error(), Error::NotFound { .. }));
        assert!(matches!(reply(410, None).error(), Error::NotFound { .. }));
        assert!(matches!(
            reply(429, Some("3")).error(),
            Error::Throttled {
                retry_after: Some(_),
                ..
            }
        ));
        assert!(matches!(
            reply(503, Some("3")).error(),
            Error::Throttled { .. }
        ));
        assert!(matches!(reply(503, None).error(), Error::Network { .. }));
        assert!(matches!(reply(500, None).error(), Error::Network { .. }));
        assert!(matches!(reply(400, None).error(), Error::Unexpected { .. }));
        assert!(reply(200, None).ok().is_ok());
        let shown = reply(403, None).error().to_string();
        assert!(
            !shown.contains("403") && !shown.contains("secret"),
            "{shown}"
        );
        assert!(format!("{:?}", reply(403, None).error()).contains("secret detail"));
    }

    #[test]
    fn a_redirect_is_followed_without_the_bearer() -> Res {
        let target = Mock::start(|_| Answer::text(200, "the file"))?;
        let there = format!("{}/file", target.url());
        let source = Mock::start(move |_| Answer::redirect(&there))?;
        let (http, _) = quick();
        let request = Request::get(format!("{}/content", source.url())).bearer("t0k3n");
        let reply = http.download(&request, 100, &AtomicBool::new(false))?;
        assert_eq!(reply.text(), "the file");
        assert_eq!(
            source.seen()[0].header("authorization"),
            Some("Bearer t0k3n")
        );
        assert_eq!(target.seen()[0].header("authorization"), None);
        Ok(())
    }

    #[test]
    fn pages_are_followed_to_the_last_and_stop_when_asked() -> Res {
        let mock = Mock::start(|seen| {
            let page: u32 = seen
                .param("page")
                .and_then(|page| page.parse().ok())
                .unwrap_or(1);
            Answer::json(200, &json!({"page": page, "more": page < 3}))
        })?;
        let (http, _) = quick();
        let base = format!("{}/list", mock.url());
        let send = |request: &Request| http.send(request);
        let mut got = Vec::new();
        let cancel = AtomicBool::new(false);
        pages(
            Provider::Dropbox,
            &cancel,
            Request::get(&base),
            &send,
            |reply| {
                let body: serde_json::Value = reply.json()?;
                let page = body["page"].as_u64().unwrap_or_default();
                got.push(page);
                Ok((body["more"] == true)
                    .then(|| Request::get(&base).query("page", &(page + 1).to_string())))
            },
        )?;
        assert_eq!(got, [1, 2, 3]);

        let mut seen = 0;
        let stopped = pages(
            Provider::Dropbox,
            &cancel,
            Request::get(&base),
            &send,
            |_| {
                seen += 1;
                cancel.store(true, Ordering::Relaxed);
                Ok(Some(Request::get(&base)))
            },
        );
        assert!(matches!(stopped, Err(Error::Cancelled)));
        assert_eq!(seen, 1);
        Ok(())
    }

    #[test]
    fn a_path_is_encoded_segment_by_segment() {
        assert_eq!(encode("a b/c"), "a%20b%2Fc");
        assert_eq!(
            encode_path("My Drive/Ä&b/x.docx"),
            "My%20Drive/%C3%84%26b/x.docx"
        );
        assert_eq!(encode("safe-._~09azAZ"), "safe-._~09azAZ");
    }
}
