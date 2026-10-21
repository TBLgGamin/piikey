//! The local HTTP API: [`spawn`] serves a [`Handler`] on `127.0.0.1`, behind a bearer token.
//!
//! `POST /v1/<op>` with the request's fields as a JSON body (the `op` is the path's; an `op` in
//! the body is ignored), and `GET /v1/status`. The reply is the [`envelope`],
//! with status 200, or 400, 404, 409 or 500 by its error code:
//!
//! - every request needs `Authorization: Bearer <token>`, else 401;
//! - a request with an `Origin` header comes from a web page and is refused with 403, token or
//!   not: no page may talk to piikey;
//! - a body over 64 MiB is refused with 413;
//! - an operation that does not exist is 404.
//!
//! It listens on the loopback address and nowhere else.

use std::{convert::Infallible, io, net::Ipv4Addr, sync::Arc, time::Duration};

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{
    HeaderMap, Method, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{
        ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, ORIGIN,
        WWW_AUTHENTICATE,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Map, Value};
use tokio::{net::TcpListener, sync::Notify};

use super::{ApiError, Handler, Request, envelope};
use crate::{Error, Result, service::Server};

/// Largest accepted request body.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// How long a client may take to send the request line and the headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait after a connection could not be accepted (the client was gone already).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// What a reply that cannot be encoded is replaced with.
const UNENCODABLE: &[u8] =
    br#"{"ok":false,"error":{"code":"internal","message":"the reply could not be encoded"}}"#;

/// Everything a connection needs to answer.
struct Gate {
    handler: Arc<dyn Handler>,
    token: String,
}

impl Gate {
    /// Whether `headers` carry `Authorization: Bearer <token>` with this server's token. The
    /// scheme is not case sensitive, the token is, and it is compared in constant time.
    fn authorized(&self, headers: &HeaderMap) -> bool {
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .is_some_and(|(scheme, token)| {
                scheme.eq_ignore_ascii_case("bearer")
                    && same(token.trim().as_bytes(), self.token.as_bytes())
            })
    }

    async fn respond(&self, request: hyper::Request<Incoming>) -> Response<Full<Bytes>> {
        let (parts, body) = request.into_parts();
        // A page in a browser says where it comes from (always on a POST); a program does not.
        if parts.headers.contains_key(ORIGIN) {
            return refuse(StatusCode::FORBIDDEN, "requests from web pages are refused");
        }
        if !self.authorized(&parts.headers) {
            let mut response = refuse(
                StatusCode::UNAUTHORIZED,
                "a token is required: send Authorization: Bearer <token>",
            );
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return response;
        }
        let path = parts.uri.path();
        let Some(op) = path
            .strip_prefix("/v1/")
            .filter(|op| Request::OPS.contains(op))
        else {
            return reply(
                StatusCode::NOT_FOUND,
                Err(ApiError::not_found(format!("no such operation: {path}"))),
            );
        };
        let allowed = if op == "status" { "GET, POST" } else { "POST" };
        let get = parts.method == Method::GET && op == "status";
        if !get && parts.method != Method::POST {
            let mut response = refuse(StatusCode::METHOD_NOT_ALLOWED, "use POST");
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static(allowed));
            return response;
        }
        let bytes = if get {
            Bytes::new()
        } else {
            match read_body(&parts.headers, body).await {
                Ok(bytes) => bytes,
                Err(response) => return response,
            }
        };
        let (status, result) = run(Arc::clone(&self.handler), op.to_owned(), bytes).await;
        reply(status, result)
    }
}

/// [`answer`] on a blocking thread.
async fn run(
    handler: Arc<dyn Handler>,
    op: String,
    body: Bytes,
) -> (StatusCode, std::result::Result<Value, ApiError>) {
    tokio::task::spawn_blocking(move || answer(handler.as_ref(), &op, &body))
        .await
        // The handler panicked: that request fails, the server lives on.
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Err(ApiError::internal("the request failed unexpectedly")),
            )
        })
}

/// Reads a request body of at most [`MAX_BODY`] bytes.
async fn read_body(
    headers: &HeaderMap,
    body: Incoming,
) -> std::result::Result<Bytes, Response<Full<Bytes>>> {
    let too_large = || refuse(StatusCode::PAYLOAD_TOO_LARGE, "the body is over 64 MiB");
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if declared.is_some_and(|len| len > MAX_BODY as u64) {
        return Err(too_large());
    }
    match Limited::new(body, MAX_BODY).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => Err(too_large()),
        Err(_) => Err(refuse(
            StatusCode::BAD_REQUEST,
            "the body could not be read",
        )),
    }
}

/// Reads the request `op` and `body` make and has `handler` answer it, with the HTTP status the
/// answer gets. Runs on a blocking thread: parsing a big body and answering is work.
fn answer(
    handler: &dyn Handler,
    op: &str,
    body: &[u8],
) -> (StatusCode, std::result::Result<Value, ApiError>) {
    match parse(op, body) {
        Ok(request) => {
            let result = handler.handle(request);
            let status = result.as_ref().map_or_else(status_of, |_| StatusCode::OK);
            (status, result)
        }
        Err(error) => (StatusCode::BAD_REQUEST, Err(error)),
    }
}

/// The request whose op is `op` and whose other fields are the JSON object `body` (nothing at
/// all is an empty object).
fn parse(op: &str, body: &[u8]) -> std::result::Result<Request, ApiError> {
    let mut fields = if body.trim_ascii().is_empty() {
        Map::new()
    } else {
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(fields)) => fields,
            Ok(_) => return Err(ApiError::bad_request("the body must be a JSON object")),
            Err(e) => return Err(ApiError::bad_request(format!("the body is not JSON: {e}"))),
        }
    };
    // Whatever `op` the body brought, the one that was asked for in the path is the one that
    // runs.
    fields.insert("op".to_owned(), Value::String(op.to_owned()));
    serde_json::from_value(Value::Object(fields)).map_err(|e| ApiError::bad_request(e.to_string()))
}

/// The status an error is answered with.
fn status_of(error: &ApiError) -> StatusCode {
    match error.code() {
        "bad_request" => StatusCode::BAD_REQUEST,
        "not_found" => StatusCode::NOT_FOUND,
        "app_required" | "busy" => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// A response with the envelope of `result` as its body.
fn reply(
    status: StatusCode,
    result: std::result::Result<Value, ApiError>,
) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&envelope(result)).unwrap_or_else(|_| UNENCODABLE.to_vec());
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A request that is refused before it gets to the handler. The code is `bad_request`; the
/// status says why.
fn refuse(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    reply(status, Err(ApiError::bad_request(message)))
}

/// Whether two secrets are equal, in a time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// Accepts connections until `stop` is notified.
async fn serve(listener: TcpListener, gate: Arc<Gate>, stop: Arc<Notify>) -> Result<()> {
    let stopped = stop.notified();
    tokio::pin!(stopped);
    loop {
        let accepted = tokio::select! {
            () = &mut stopped => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            tokio::time::sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        // Replies are small and the other end is on this machine: do not wait to fill packets.
        let _ = stream.set_nodelay(true);
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let gate = Arc::clone(&gate);
                async move { Ok::<_, Infallible>(gate.respond(request).await) }
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service);
            // A broken connection only ends that connection.
            let _ = connection.await;
        });
    }
}

fn bind(port: u16) -> Result<TcpListener> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| {
        if e.kind() == io::ErrorKind::AddrInUse {
            Error::Busy(format!("port {port} on 127.0.0.1 is in use"))
        } else {
            Error::Io(e)
        }
    })?;
    listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(listener)?)
}

/// Serves `handler` over HTTP on `127.0.0.1:port`, on a thread of its own, for requests that
/// carry `token` as a bearer token, until the [`Server`] is stopped or dropped.
///
/// # Errors
/// `Busy` when the port is in use; `BadRequest` for an empty token; `Io` when the server cannot
/// be started.
pub fn spawn(handler: Arc<dyn Handler>, port: u16, token: String) -> Result<Server> {
    if token.is_empty() {
        return Err(Error::BadRequest("the API token is empty".to_owned()));
    }
    let gate = Arc::new(Gate { handler, token });
    Server::start(
        "piikey-api-http",
        || bind(port),
        move |listener, stop| serve(listener, gate, stop),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as StdError,
        fmt::Write as _,
        io::{Read, Write},
        net::TcpStream,
    };

    use serde_json::json;

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    /// Answers what the tests ask: echoes texts, and fails in the ways the statuses are for.
    struct Stub;

    impl Handler for Stub {
        fn handle(&self, request: Request) -> std::result::Result<Value, ApiError> {
            match request {
                Request::ScanText { texts } => Ok(json!({ "echo": texts })),
                Request::VaultWipe { .. } => Err(ApiError::busy("not now")),
                Request::ExplorerScan { .. } => Err(ApiError::app_required("start the app")),
                Request::ModelStatus => Err(ApiError::not_found("no model")),
                Request::ApiToken { .. } => Err(ApiError::internal("broken")),
                Request::ModelDownload => panic!("the stub was told to panic"),
                other => Ok(json!({ "op": other.op() })),
            }
        }
    }

    /// What came back over the wire.
    struct Wire {
        status: u16,
        headers: String,
        body: String,
    }

    impl Wire {
        fn json(&self) -> std::result::Result<Value, Box<dyn StdError>> {
            Ok(serde_json::from_str(&self.body)?)
        }

        fn code(&self) -> std::result::Result<String, Box<dyn StdError>> {
            Ok(self.json()?["error"]["code"]
                .as_str()
                .ok_or("no error code")?
                .to_owned())
        }
    }

    /// One request on a connection of its own, written by hand.
    fn send(
        port: u16,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> std::result::Result<Wire, Box<dyn StdError>> {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
        stream.set_read_timeout(Some(Duration::from_secs(20)))?;
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
        for (name, value) in headers {
            write!(request, "{name}: {value}\r\n")?;
        }
        if let Some(body) = body {
            write!(request, "Content-Length: {}\r\n", body.len())?;
        }
        request.push_str("\r\n");
        if let Some(body) = body {
            request.push_str(body);
        }
        stream.write_all(request.as_bytes())?;
        let mut raw = Vec::new();
        // The server closes the connection after the answer; a reset after a refusal that left
        // the body unread still leaves the answer in `raw`.
        let _ = stream.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").ok_or("no response")?;
        let (status_line, headers) = head.split_once("\r\n").unwrap_or((head, ""));
        let status = status_line
            .split(' ')
            .nth(1)
            .ok_or("no status")?
            .parse::<u16>()?;
        Ok(Wire {
            status,
            headers: headers.to_ascii_lowercase(),
            body: body.to_owned(),
        })
    }

    fn authed(
        port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> std::result::Result<Wire, Box<dyn StdError>> {
        send(
            port,
            method,
            path,
            &[("Authorization", &format!("Bearer {TOKEN}"))],
            body,
        )
    }

    /// A port nobody listens on.
    fn free_port() -> std::result::Result<u16, Box<dyn StdError>> {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        Ok(probe.local_addr()?.port())
    }

    fn serve_stub() -> std::result::Result<(Server, u16), Box<dyn StdError>> {
        let port = free_port()?;
        Ok((spawn(Arc::new(Stub), port, TOKEN.to_owned())?, port))
    }

    #[test]
    fn a_request_needs_the_token() -> TestResult {
        let (server, port) = serve_stub()?;
        let body = Some(r#"{"texts":["a"]}"#);

        let none = send(port, "POST", "/v1/scan_text", &[], body)?;
        assert_eq!(none.status, 401);
        assert!(
            none.headers.contains("www-authenticate: bearer"),
            "{}",
            none.headers
        );
        assert_eq!(none.code()?, "bad_request");
        assert_eq!(none.json()?["ok"], false);

        for header in [
            "Bearer nope",
            "Bearer ",
            "Bearer",
            "Basic 0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
            "Bearer 0123456789abcdef0123456789abcde",
            "Bearer 0123456789abcdef0123456789abcdef0",
        ] {
            let wrong = send(
                port,
                "POST",
                "/v1/scan_text",
                &[("Authorization", header)],
                body,
            )?;
            assert_eq!(wrong.status, 401, "{header}");
        }

        let ok = authed(port, "POST", "/v1/scan_text", body)?;
        assert_eq!(ok.status, 200, "{}", ok.body);
        assert_eq!(ok.json()?, json!({"ok": true, "result": {"echo": ["a"]}}));
        assert!(ok.headers.contains("content-type: application/json"));

        // The scheme is not case sensitive.
        let lower = send(
            port,
            "POST",
            "/v1/scan_text",
            &[("authorization", &format!("bearer {TOKEN}"))],
            body,
        )?;
        assert_eq!(lower.status, 200);
        server.stop();
        Ok(())
    }

    #[test]
    fn a_web_page_is_refused_whatever_it_sends() -> TestResult {
        let (server, port) = serve_stub()?;
        let with_token = send(
            port,
            "POST",
            "/v1/scan_text",
            &[
                ("Authorization", &format!("Bearer {TOKEN}")),
                ("Origin", "https://evil.example"),
            ],
            Some(r#"{"texts":[]}"#),
        )?;
        assert_eq!(with_token.status, 403);
        assert_eq!(with_token.code()?, "bad_request");
        let without = send(
            port,
            "POST",
            "/v1/scan_text",
            &[("Origin", "null")],
            Some(r#"{"texts":[]}"#),
        )?;
        assert_eq!(without.status, 403);
        let get = send(
            port,
            "GET",
            "/v1/status",
            &[
                ("Authorization", &format!("Bearer {TOKEN}")),
                ("Origin", "http://127.0.0.1:1"),
            ],
            None,
        )?;
        assert_eq!(get.status, 403);
        server.stop();
        Ok(())
    }

    #[test]
    fn unknown_operations_and_wrong_methods() -> TestResult {
        let (server, port) = serve_stub()?;
        for path in [
            "/v1/nope",
            "/v1/",
            "/v1",
            "/",
            "/v2/scan_text",
            "/v1/scan_text/",
        ] {
            let wire = authed(port, "POST", path, Some("{}"))?;
            assert_eq!(wire.status, 404, "{path}");
            assert_eq!(wire.code()?, "not_found", "{path}");
        }
        // Without a token the answer does not say which operations exist.
        assert_eq!(send(port, "POST", "/v1/nope", &[], Some("{}"))?.status, 401);

        let get = authed(port, "GET", "/v1/scan_text", None)?;
        assert_eq!(get.status, 405);
        assert!(get.headers.contains("allow: post"), "{}", get.headers);
        let put = authed(port, "PUT", "/v1/status", Some("{}"))?;
        assert_eq!(put.status, 405);
        assert!(put.headers.contains("allow: get, post"));

        let status = authed(port, "GET", "/v1/status", None)?;
        assert_eq!(status.status, 200);
        assert_eq!(status.json()?["result"]["op"], "status");
        server.stop();
        Ok(())
    }

    #[test]
    fn the_body_is_the_requests_fields() -> TestResult {
        let (server, port) = serve_stub()?;
        // No body is no fields.
        let kinds = authed(port, "POST", "/v1/kinds", None)?;
        assert_eq!(kinds.status, 200, "{}", kinds.body);
        assert_eq!(kinds.json()?["result"]["op"], "kinds");
        let spaces = authed(port, "POST", "/v1/kinds", Some("  \r\n "))?;
        assert_eq!(spaces.status, 200);

        // An `op` in the body does not change what runs.
        let sneaky = authed(
            port,
            "POST",
            "/v1/kinds",
            Some(r#"{"op":"vault_wipe","confirm":true}"#),
        )?;
        assert_eq!(sneaky.status, 200, "{}", sneaky.body);
        assert_eq!(sneaky.json()?["result"]["op"], "kinds");

        for body in [
            "not json",
            "[1,2]",
            "\"texts\"",
            r#"{"texts":"a"}"#,
            r#"{"texts":[],"surprise":true}"#,
            "{}",
        ] {
            let wire = authed(port, "POST", "/v1/scan_text", Some(body))?;
            assert_eq!(wire.status, 400, "{body}: {}", wire.body);
            assert_eq!(wire.code()?, "bad_request");
        }
        server.stop();
        Ok(())
    }

    #[test]
    fn errors_get_the_status_of_their_code() -> TestResult {
        let (server, port) = serve_stub()?;
        let cases = [
            ("/v1/vault_wipe", r#"{"confirm":true}"#, 409, "busy"),
            ("/v1/explorer_scan", r#"{"paths":[]}"#, 409, "app_required"),
            ("/v1/model_status", "{}", 404, "not_found"),
            ("/v1/api_token", "{}", 500, "internal"),
            // A handler that panics fails its request, and the server answers the next.
            ("/v1/model_download", "{}", 500, "internal"),
            ("/v1/vault_forget", "{}", 400, "bad_request"),
        ];
        for (path, body, status, code) in cases {
            let wire = authed(port, "POST", path, Some(body))?;
            assert_eq!(
                (wire.status, wire.code()?.as_str()),
                (status, code),
                "{path}"
            );
        }
        assert_eq!(authed(port, "POST", "/v1/kinds", None)?.status, 200);
        server.stop();
        Ok(())
    }

    #[test]
    fn a_body_over_the_limit_is_refused() -> TestResult {
        let (server, port) = serve_stub()?;
        // The length is announced; the server answers without waiting for the body.
        let wire = send(
            port,
            "POST",
            "/v1/scan_text",
            &[
                ("Authorization", &format!("Bearer {TOKEN}")),
                ("Content-Length", &(MAX_BODY + 1).to_string()),
            ],
            None,
        )?;
        assert_eq!(wire.status, 413);
        assert_eq!(wire.code()?, "bad_request");
        server.stop();
        Ok(())
    }

    #[test]
    fn a_big_body_within_the_limit_is_read() -> TestResult {
        let (server, port) = serve_stub()?;
        let text = "y".repeat(5 * 1024 * 1024);
        let body = format!(r#"{{"texts":["{text}"]}}"#);
        let wire = authed(port, "POST", "/v1/scan_text", Some(&body))?;
        assert_eq!(wire.status, 200);
        assert_eq!(
            wire.json()?["result"]["echo"][0].as_str().map(str::len),
            Some(text.len())
        );
        server.stop();
        Ok(())
    }

    /// The client the README documents. A body over a megabyte makes curl ask `Expect:
    /// 100-continue` first, which the server has to answer for the body to be sent.
    #[test]
    fn curl_can_call_it() -> TestResult {
        let Ok(mut curl) = crate::sys::system_command("curl.exe") else {
            // No curl in System32: there is no real client to try.
            return Ok(());
        };
        let (server, port) = serve_stub()?;
        let text = "z".repeat(2 * 1024 * 1024);
        let file =
            std::env::temp_dir().join(format!("piikey-test-{}-curl.json", std::process::id()));
        std::fs::write(&file, format!(r#"{{"texts":["{text}"]}}"#))?;
        let output = curl
            .args(["--silent", "--show-error", "--max-time", "30", "--header"])
            .arg(format!("Authorization: Bearer {TOKEN}"))
            .arg("--data-binary")
            .arg(format!("@{}", file.display()))
            .arg(format!("http://127.0.0.1:{port}/v1/scan_text"))
            .output();
        let _ = std::fs::remove_file(&file);
        let output = output?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reply: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(reply["ok"], true);
        assert_eq!(
            reply["result"]["echo"][0].as_str().map(str::len),
            Some(text.len())
        );

        // Without the token curl is told so, and the exit code is still 0: it is an answer.
        let refused = crate::sys::system_command("curl.exe")?
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                "--write-out",
                "%{http_code}",
            ])
            .args(["--output", "NUL"])
            .arg(format!("http://127.0.0.1:{port}/v1/status"))
            .output()?;
        assert_eq!(String::from_utf8_lossy(&refused.stdout), "401");
        server.stop();
        Ok(())
    }

    #[test]
    fn the_server_owns_its_port_until_stopped() -> TestResult {
        let (server, port) = serve_stub()?;
        let second = spawn(Arc::new(Stub), port, TOKEN.to_owned()).err();
        assert!(matches!(second, Some(Error::Busy(_))), "{second:?}");
        server.stop();
        let again = spawn(Arc::new(Stub), port, TOKEN.to_owned())?;
        assert_eq!(authed(port, "POST", "/v1/kinds", None)?.status, 200);
        drop(again);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
        Ok(())
    }

    #[test]
    fn an_empty_token_is_refused() -> TestResult {
        let port = free_port()?;
        let error = spawn(Arc::new(Stub), port, String::new()).err();
        assert!(matches!(error, Some(Error::BadRequest(_))), "{error:?}");
        Ok(())
    }

    #[test]
    fn secrets_compare_by_content_and_length() {
        assert!(same(b"abc", b"abc"));
        assert!(same(b"", b""));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"abcd"));
        assert!(!same(b"abc", b""));
    }

    #[test]
    fn every_error_code_has_a_status() {
        let cases = [
            (ApiError::bad_request("x"), StatusCode::BAD_REQUEST),
            (ApiError::not_found("x"), StatusCode::NOT_FOUND),
            (ApiError::app_required("x"), StatusCode::CONFLICT),
            (ApiError::busy("x"), StatusCode::CONFLICT),
            (ApiError::internal("x"), StatusCode::INTERNAL_SERVER_ERROR),
            (
                Error::Io(io::ErrorKind::Other.into()).into(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                Error::Model("x".into()).into(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                Error::UnsupportedFormat("x").into(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (error, status) in cases {
            assert_eq!(status_of(&error), status, "{}", error.code());
        }
    }
}
