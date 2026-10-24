//! A tiny HTTP/1.1 server on the loopback for the tests of this module: it answers from a closure
//! and remembers what it was asked, so a test never reaches a real service.

use std::{
    fmt::Write as _,
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::Value;

/// The result type of a test.
pub(crate) type Res<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One request the server got.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub method: String,
    /// The path and the query, as sent (`/v1.0/drives?select=id`).
    pub target: String,
    /// The headers, with the names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    /// The target without its query.
    pub(crate) fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }

    /// The query's fields, decoded.
    pub(crate) fn query(&self) -> Vec<(String, String)> {
        self.target
            .split_once('?')
            .map_or_else(Vec::new, |(_, query)| fields(query))
    }

    /// The value of the query field `name`.
    pub(crate) fn param(&self, name: &str) -> Option<String> {
        self.query()
            .into_iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }

    /// The value of the header `name` (any letter case).
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }

    /// The fields of a form body, decoded.
    pub(crate) fn form(&self) -> Vec<(String, String)> {
        fields(&String::from_utf8_lossy(&self.body))
    }

    /// The value of the form field `name`.
    pub(crate) fn field(&self, name: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }

    /// The body as JSON; `null` when it is none.
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// `a=1&b=two%20words` as pairs.
fn fields(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect()
}

/// Percent-decodes `text`; a `+` is a space.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let digits = bytes.get(at + 1..at + 3).and_then(|pair| {
                    let hex = |digit: u8| char::from(digit).to_digit(16);
                    Some(hex(pair[0])? * 16 + hex(pair[1])?)
                });
                if let Some(value) = digits.and_then(|value| u8::try_from(value).ok()) {
                    out.push(value);
                    at += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What the server says back.
#[derive(Debug, Clone)]
pub(crate) struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Whether to say how long the body is. Without it the body ends where the connection does.
    sized: bool,
}

impl Answer {
    /// A JSON body.
    pub(crate) fn json(status: u16, value: &Value) -> Self {
        Self::bytes(status, value.to_string().into_bytes())
            .header("Content-Type", "application/json")
    }

    /// A plain text body.
    pub(crate) fn text(status: u16, text: &str) -> Self {
        Self::bytes(status, text.as_bytes().to_vec()).header("Content-Type", "text/plain")
    }

    /// Any body.
    pub(crate) fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
            sized: true,
        }
    }

    /// No body.
    pub(crate) fn empty(status: u16) -> Self {
        Self::bytes(status, Vec::new())
    }

    /// A redirect to `location`.
    pub(crate) fn redirect(location: &str) -> Self {
        Self::empty(302).header("Location", location)
    }

    /// Adds a header.
    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Leaves out the `Content-Length`: the body ends where the connection does.
    pub(crate) fn streamed(mut self) -> Self {
        self.sized = false;
        self
    }
}

/// The server. It stops when dropped.
pub(crate) struct Mock {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

type Handler = dyn Fn(&Seen) -> Answer + Send + Sync;

impl Mock {
    /// Starts a server on a free port of the loopback; `handler` answers each request, from
    /// whichever thread asked.
    pub(crate) fn start(
        handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let thread = {
            let (seen, stop) = (Arc::clone(&seen), Arc::clone(&stop));
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let (seen, handler) = (Arc::clone(&seen), Arc::clone(&handler));
                    thread::spawn(move || serve(stream, &seen, &*handler));
                }
            })
        };
        Ok(Self {
            port,
            seen,
            stop,
            thread: Some(thread),
        })
    }

    /// The server's address: `http://127.0.0.1:<port>`, without a slash at the end.
    pub(crate) fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Every request so far, the first first.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    /// The requests so far for `path`.
    pub(crate) fn seen_at(&self, path: &str) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|request| request.path() == path)
            .collect()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accept loop, which looks at the flag once a connection comes.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Reads one request, remembers it, answers it and closes the connection.
fn serve(stream: TcpStream, seen: &Mutex<Vec<Seen>>, handler: &Handler) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let request = Seen {
        method,
        target,
        headers,
        body,
    };
    if let Ok(mut all) = seen.lock() {
        all.push(request.clone());
    }
    let answer = handler(&request);
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\n",
        answer.status,
        reason(answer.status)
    );
    if answer.sized {
        let _ = write!(head, "Content-Length: {}\r\n", answer.body.len());
    }
    for (name, value) in &answer.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("\r\n");
    let _ = writer
        .write_all(head.as_bytes())
        .and_then(|()| writer.write_all(&answer.body))
        .and_then(|()| writer.flush());
    let _ = writer.shutdown(Shutdown::Both);
}

/// The reason phrase of a status.
const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}
