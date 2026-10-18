//! Named-pipe service and its length-prefixed wire protocol.
//!
//! Request: `b'P', 1, op, 0, u32 len`, then `len` payload bytes.
//! Response: `status (0 ok, 1 error), 0, 0, 0, u32 len`, then `len` payload
//! bytes (the error text on failure). All integers are little-endian.
//!
//! Ops: 1 anonymize, 2 deanonymize (UTF-8 text); 3 anonymize batch,
//! 4 deanonymize batch (`u32 count`, then `count × (u32 len, bytes)`);
//! 5 ping (empty payload, empty reply).

use std::{io, str, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions},
};

use crate::{Error, Result, detect::Mode, engine::Engine};

/// Default pipe name.
pub const DEFAULT_PIPE: &str = r"\\.\pipe\piikey";

const MAGIC: u8 = b'P';
const VERSION: u8 = 1;
const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;
/// Largest accepted request payload.
const MAX_PAYLOAD: usize = 512 * 1024 * 1024;

/// What a request asks the service to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Anonymize,
    Deanonymize,
    AnonymizeBatch,
    DeanonymizeBatch,
    Ping,
}

impl Op {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Anonymize),
            2 => Some(Self::Deanonymize),
            3 => Some(Self::AnonymizeBatch),
            4 => Some(Self::DeanonymizeBatch),
            5 => Some(Self::Ping),
            _ => None,
        }
    }

    fn mode(self) -> Mode {
        match self {
            Self::Anonymize | Self::AnonymizeBatch | Self::Ping => Mode::Anonymize,
            Self::Deanonymize | Self::DeanonymizeBatch => Mode::Deanonymize,
        }
    }
}

/// A response ready to be written: 8-byte header, then payload.
#[derive(Debug)]
struct Frame {
    header: [u8; 8],
    payload: Vec<u8>,
}

/// Validates a request header and returns the op and payload length.
fn parse_request_header(h: [u8; 8]) -> Result<(Op, usize)> {
    if h[0] != MAGIC {
        return Err(Error::Protocol("bad magic"));
    }
    if h[1] != VERSION {
        return Err(Error::Protocol("unsupported protocol version"));
    }
    let op = Op::from_u8(h[2]).ok_or(Error::Protocol("unknown op"))?;
    let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Protocol("payload too large"));
    }
    Ok((op, len))
}

/// Builds a response frame. A payload that does not fit a `u32` length
/// becomes an error frame instead.
fn frame(status: u8, payload: Vec<u8>) -> Frame {
    let Ok(len) = u32::try_from(payload.len()) else {
        return frame(STATUS_ERR, b"protocol: response too large".to_vec());
    };
    let len = len.to_le_bytes();
    Frame {
        header: [status, 0, 0, 0, len[0], len[1], len[2], len[3]],
        payload,
    }
}

fn frame_for(result: Result<Vec<u8>>) -> Frame {
    match result {
        Ok(payload) => frame(STATUS_OK, payload),
        Err(e) => frame(STATUS_ERR, e.to_string().into_bytes()),
    }
}

fn take_u32(buf: &[u8]) -> Result<(usize, &[u8])> {
    let (head, rest) = buf
        .split_first_chunk::<4>()
        .ok_or(Error::Protocol("batch truncated"))?;
    Ok((u32::from_le_bytes(*head) as usize, rest))
}

/// Splits a batch payload into its items.
fn decode_batch(payload: &[u8]) -> Result<Vec<&[u8]>> {
    let (count, mut rest) = take_u32(payload)?;
    // Every item needs at least 4 bytes, so a lying count cannot over-allocate.
    let mut items = Vec::with_capacity(count.min(rest.len() / 4));
    for _ in 0..count {
        let (len, tail) = take_u32(rest)?;
        if len > tail.len() {
            return Err(Error::Protocol("batch item overruns payload"));
        }
        let (item, tail) = tail.split_at(len);
        items.push(item);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::Protocol("trailing bytes after batch"));
    }
    Ok(items)
}

/// Joins items into a batch payload.
fn encode_batch(items: &[String]) -> Result<Vec<u8>> {
    const TOO_LARGE: Error = Error::Protocol("response too large");
    let total = items
        .iter()
        .try_fold(4_usize, |acc, s| acc.checked_add(4)?.checked_add(s.len()));
    let mut out = Vec::with_capacity(total.ok_or(TOO_LARGE)?);
    out.extend_from_slice(
        &u32::try_from(items.len())
            .map_err(|_| TOO_LARGE)?
            .to_le_bytes(),
    );
    for s in items {
        out.extend_from_slice(&u32::try_from(s.len()).map_err(|_| TOO_LARGE)?.to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    Ok(out)
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    str::from_utf8(bytes).map_err(|_| Error::Protocol("invalid UTF-8"))
}

/// Executes one request. Runs on a blocking thread; rayon does the heavy work.
fn respond(engine: &Engine, op: Op, payload: &[u8]) -> Result<Vec<u8>> {
    match op {
        Op::Ping if payload.is_empty() => Ok(Vec::new()),
        Op::Ping => Err(Error::Protocol("ping takes no payload")),
        Op::Anonymize | Op::Deanonymize => {
            let mut out = engine.run(op.mode(), &[utf8(payload)?])?;
            Ok(out.pop().unwrap_or_default().into_bytes())
        }
        Op::AnonymizeBatch | Op::DeanonymizeBatch => {
            let texts = decode_batch(payload)?
                .into_iter()
                .map(utf8)
                .collect::<Result<Vec<_>>>()?;
            encode_batch(&engine.run(op.mode(), &texts)?)
        }
    }
}

async fn write_frame(pipe: &mut NamedPipeServer, f: &Frame) -> io::Result<()> {
    pipe.write_all(&f.header).await?;
    pipe.write_all(&f.payload).await?;
    pipe.flush().await
}

/// Serves requests on one connection until the client leaves or breaks the
/// protocol.
async fn handle_connection(pipe: &mut NamedPipeServer, engine: &Arc<Engine>) -> io::Result<()> {
    loop {
        let mut header = [0_u8; 8];
        pipe.read_exact(&mut header).await?;
        let (op, len) = match parse_request_header(header) {
            Ok(parsed) => parsed,
            Err(e) => return write_frame(pipe, &frame_for(Err(e))).await,
        };
        // `take` + `read_to_end` grows with the bytes that actually arrive, so
        // a client announcing 512 MiB and sending nothing costs nothing.
        let mut payload = Vec::new();
        let got = AsyncReadExt::take(&mut *pipe, len as u64)
            .read_to_end(&mut payload)
            .await?;
        if got < len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let engine = Arc::clone(engine);
        let result = tokio::task::spawn_blocking(move || respond(&engine, op, &payload)).await;
        let reply = result.unwrap_or(Err(Error::Protocol("internal error")));
        write_frame(pipe, &frame_for(reply)).await?;
    }
}

fn server_options() -> ServerOptions {
    let mut options = ServerOptions::new();
    options
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte);
    options
}

/// Serves requests on `pipe` until the process exits.
///
/// # Errors
/// `Io` when the pipe cannot be created ("pipe already in use") or accepting
/// a connection fails.
pub fn serve(engine: Arc<Engine>, pipe: &str) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async move {
        let mut server = server_options()
            .first_pipe_instance(true)
            .create(pipe)
            .map_err(|e| {
                Error::Io(io::Error::new(
                    e.kind(),
                    format!("pipe already in use: {pipe} ({e})"),
                ))
            })?;
        loop {
            server.connect().await?;
            let mut client = server;
            // The next instance must exist before this client is handed off,
            // or a second client would find no pipe to connect to.
            server = server_options().create(pipe)?;
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                // A broken connection only ends that connection.
                let _ = handle_connection(&mut client, &engine).await;
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as StdError,
        fs::{File, OpenOptions},
        io::{Read, Write},
        path::PathBuf,
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    fn header(magic: u8, version: u8, op: u8, len: u32) -> [u8; 8] {
        let l = len.to_le_bytes();
        [magic, version, op, 0, l[0], l[1], l[2], l[3]]
    }

    #[test]
    fn header_accepts_every_op() -> TestResult {
        let expected = [
            (1, Op::Anonymize),
            (2, Op::Deanonymize),
            (3, Op::AnonymizeBatch),
            (4, Op::DeanonymizeBatch),
            (5, Op::Ping),
        ];
        for (byte, op) in expected {
            assert_eq!(parse_request_header(header(b'P', 1, byte, 7))?, (op, 7));
        }
        Ok(())
    }

    #[test]
    fn header_rejects_bad_magic_version_op() {
        for h in [
            header(b'X', 1, 1, 0),
            header(b'P', 2, 1, 0),
            header(b'P', 1, 0, 0),
            header(b'P', 1, 6, 0),
        ] {
            assert!(matches!(parse_request_header(h), Err(Error::Protocol(_))));
        }
    }

    #[test]
    fn header_enforces_length_limit() -> TestResult {
        let max = u32::try_from(MAX_PAYLOAD)?;
        assert_eq!(
            parse_request_header(header(b'P', 1, 1, max))?.1,
            MAX_PAYLOAD
        );
        assert!(matches!(
            parse_request_header(header(b'P', 1, 1, max + 1)),
            Err(Error::Protocol("payload too large"))
        ));
        Ok(())
    }

    #[test]
    fn frame_layout() {
        let f = frame(STATUS_ERR, b"abc".to_vec());
        assert_eq!(f.header, [1, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(f.payload, b"abc");
        let f = frame_for(Ok(Vec::new()));
        assert_eq!(f.header, [0; 8]);
        let f = frame_for(Err(Error::Protocol("bad magic")));
        assert_eq!(f.header[0], STATUS_ERR);
        assert_eq!(f.payload, b"protocol: bad magic");
    }

    #[test]
    fn batch_round_trip() -> TestResult {
        let items = vec![String::from("a"), String::new(), String::from("héllo 世界")];
        let wire = encode_batch(&items)?;
        let decoded = decode_batch(&wire)?;
        assert_eq!(decoded.len(), 3);
        for (d, i) in decoded.iter().zip(&items) {
            assert_eq!(*d, i.as_bytes());
        }
        assert!(decode_batch(&encode_batch(&[])?)?.is_empty());
        Ok(())
    }

    #[test]
    fn batch_decode_rejects_malformed() {
        let cases: [&[u8]; 6] = [
            &[],
            &[1, 0, 0],
            &[1, 0, 0, 0],
            &[1, 0, 0, 0, 5, 0, 0, 0, b'a'],
            &[0, 0, 0, 0, 9],
            // Count far larger than the payload can hold.
            &[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0],
        ];
        for c in cases {
            assert!(matches!(decode_batch(c), Err(Error::Protocol(_))), "{c:?}");
        }
    }

    #[test]
    fn utf8_rejects_invalid() {
        assert!(matches!(
            utf8(&[0xFF, 0xFE]),
            Err(Error::Protocol("invalid UTF-8"))
        ));
        assert!(matches!(utf8(b"ok"), Ok("ok")));
    }

    struct Client(File);

    impl Client {
        fn connect(
            pipe: &str,
            serving: &thread::JoinHandle<()>,
        ) -> std::result::Result<Self, Box<dyn StdError>> {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                match OpenOptions::new().read(true).write(true).open(pipe) {
                    Ok(f) => return Ok(Self(f)),
                    Err(_) if Instant::now() < deadline && !serving.is_finished() => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(e) => return Err(format!("cannot open {pipe}: {e}").into()),
                }
            }
        }

        fn send_raw(&mut self, header: [u8; 8], payload: &[u8]) -> TestResult {
            self.0.write_all(&header)?;
            self.0.write_all(payload)?;
            Ok(())
        }

        fn read_reply(&mut self) -> std::result::Result<(u8, Vec<u8>), Box<dyn StdError>> {
            let mut h = [0_u8; 8];
            self.0.read_exact(&mut h)?;
            let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
            let mut payload = vec![0_u8; len];
            self.0.read_exact(&mut payload)?;
            Ok((h[0], payload))
        }

        fn call(
            &mut self,
            op: u8,
            payload: &[u8],
        ) -> std::result::Result<(u8, Vec<u8>), Box<dyn StdError>> {
            self.send_raw(header(b'P', 1, op, u32::try_from(payload.len())?), payload)?;
            self.read_reply()
        }

        fn ok(
            &mut self,
            op: u8,
            payload: &[u8],
        ) -> std::result::Result<Vec<u8>, Box<dyn StdError>> {
            let (status, body) = self.call(op, payload)?;
            if status != STATUS_OK {
                return Err(format!("server error: {}", String::from_utf8_lossy(&body)).into());
            }
            Ok(body)
        }
    }

    fn batch(items: &[&str]) -> std::result::Result<Vec<u8>, Box<dyn StdError>> {
        let owned: Vec<String> = items.iter().map(|s| (*s).to_owned()).collect();
        Ok(encode_batch(&owned)?)
    }

    fn unbatch(wire: &[u8]) -> std::result::Result<Vec<String>, Box<dyn StdError>> {
        decode_batch(wire)?
            .into_iter()
            .map(|b| Ok(utf8(b)?.to_owned()))
            .collect()
    }

    fn temp_vault() -> PathBuf {
        std::env::temp_dir().join(format!("piikey-test-{}-service.pkv", std::process::id()))
    }

    #[test]
    fn end_to_end() -> TestResult {
        let pipe = format!(r"\\.\pipe\piikey-test-{}", std::process::id());
        let vault = temp_vault();
        let _ = std::fs::remove_file(&vault);
        let engine = Arc::new(Engine::open(&vault)?);
        let name = pipe.clone();
        let serving = thread::spawn(move || {
            let _ = serve(engine, &name);
        });

        let mut c = Client::connect(&pipe, &serving)?;
        assert!(c.ok(5, b"")?.is_empty());
        assert_eq!(c.call(5, b"x")?.0, STATUS_ERR);

        let original = "mail jan@example.org";
        let anon = c.ok(1, original.as_bytes())?;
        let anon = String::from_utf8(anon)?;
        assert!(!anon.contains("jan@example.org"), "{anon}");
        let back = c.ok(2, anon.as_bytes())?;
        assert_eq!(String::from_utf8(back)?, original);

        // Invalid UTF-8 is an error response and the connection survives.
        assert_eq!(c.call(1, &[0xFF, 0xFE])?.0, STATUS_ERR);
        assert!(c.ok(5, b"")?.is_empty());

        let texts = [
            "mail a.b@example.org",
            "nothing to hide",
            "ip 8.8.4.4 and mail c@example.net",
        ];
        let anon = unbatch(&c.ok(3, &batch(&texts)?)?)?;
        assert_eq!(anon.len(), 3);
        assert_eq!(anon[1], texts[1]);
        let anon_refs: Vec<&str> = anon.iter().map(String::as_str).collect();
        let back = unbatch(&c.ok(4, &batch(&anon_refs)?)?)?;
        assert_eq!(back, texts);

        // A bad magic gets an error response, then the connection is closed.
        let mut bad = Client::connect(&pipe, &serving)?;
        bad.send_raw(header(b'X', 1, 5, 0), b"")?;
        let (status, body) = bad.read_reply()?;
        assert_eq!(status, STATUS_ERR);
        assert!(String::from_utf8_lossy(&body).contains("bad magic"));
        let mut rest = [0_u8; 1];
        assert!(matches!(bad.0.read(&mut rest), Ok(0) | Err(_)));

        // The name is owned: a second server on it fails with the context.
        let second = Arc::new(Engine::open(&temp_vault().with_extension("two"))?);
        let err = serve(second, &pipe).err().map(|e| e.to_string());
        assert!(err.is_some_and(|m| m.contains("pipe already in use")));
        let _ = std::fs::remove_file(vault);
        let _ = std::fs::remove_file(temp_vault().with_extension("two"));
        Ok(())
    }
}
