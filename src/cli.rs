//! `piikey-cli`: a client of the piikey API, one command per operation.
//!
//! Every command becomes one [`Request`]. It goes to the app over the named pipe when the app
//! answers there, and is answered in this process, by [`Local`], when nobody does (or with
//! `--local` or `--vault`). Either way the result is the same JSON, printed as it is with
//! `--json` and as lines and tables without.
//!
//! Exit codes: 0 done; 1 `scan --fail-on` found personal data; 2 the command line is wrong;
//! 3 the API answered with an error, or this process could not read or write.

mod parse;
mod show;
#[cfg(test)]
mod tests;

use std::{
    io::{self, Read, Write},
    path::{self, Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use parse::{Call, Cli, Command, Input, ParseError, Serve};
use piikey::{
    api::{self, ApiError, DownloadProgress, EngineSource, Handler, Local, Request},
    detect::{NerDetector, ner},
    engine::Engine,
    inventory::Inventory,
    policy::Policy,
    service,
    vault::default_path,
};
use serde_json::Value;
use show::View;

const USAGE: &str = "\
usage:
  piikey-cli scan [--fail-on KINDS|any] [--no-record] [PATH...]        no PATH: stdin text
  piikey-cli anonymize [--out DIR] [PATH...]                            no PATH: stdin -> stdout
  piikey-cli deanonymize [--tolerant] [--out DIR] [PATH...]
  piikey-cli subject --value V [--value V ...] [PATH...]
  piikey-cli vault list [--query Q] [--kind KIND] [--limit N] [--offset N]
  piikey-cli vault forget VALUE...
  piikey-cli vault export --out FILE [--format json|csv]
  piikey-cli vault wipe --yes
  piikey-cli inventory status | list [--under PATH] [--limit N] [--offset N] | tree [--under PATH] | rescan | report --out FILE [--format json|csv]
  piikey-cli settings get | settings set KEY=VALUE...      keys = guard.cfg keys; list keys repeat (site=a site=b)
  piikey-cli kinds | model status | model download | token [--rotate] | status | protection on|off
  piikey-cli serve [--http [--port N]] [--pipe NAME]
global: --json  --local  --vault PATH  -h/--help  -V/--version

With no PATH, scan, anonymize and deanonymize read UTF-8 text from stdin, and anonymize and
deanonymize write the result to stdout. With PATHs, anonymize and deanonymize need --out DIR;
folders are walked recursively.

--fail-on      the kinds (see `piikey-cli kinds`) whose presence makes scan exit 1
--tolerant     also restores stand-ins that came back with a typo, and first or last names
               that came back alone
--local        work in this process even when the app is running; --vault PATH implies it
--pipe         serve on \\\\.\\pipe\\NAME instead of \\\\.\\pipe\\piikey-<USERNAME>

exit codes: 0 done; 1 personal data found under --fail-on; 2 usage error; 3 any API error";

/// The prefix of a named pipe's path.
const PIPE_PREFIX: &str = r"\\.\pipe\";

/// How the command ended, which is the process's exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Ok,
    /// `scan --fail-on` found personal data.
    Found,
    Usage,
    Failed,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(match exit {
            Exit::Ok => 0,
            Exit::Found => 1,
            Exit::Usage => 2,
            Exit::Failed => 3,
        })
    }
}

/// Why a command stopped: the API said no, or this process could not read or write.
#[derive(Debug)]
pub enum Fail {
    Api(ApiError),
    Io(io::Error),
}

impl From<ApiError> for Fail {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<piikey::Error> for Fail {
    fn from(error: piikey::Error) -> Self {
        Self::Api(error.into())
    }
}

impl From<io::Error> for Fail {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Fail {
    fn into_api(self) -> ApiError {
        match self {
            Self::Api(error) => error,
            Self::Io(error) => piikey::Error::Io(error).into(),
        }
    }
}

/// Where a request is answered.
trait Caller {
    fn call(&mut self, request: Request) -> Result<Value, Fail>;
}

/// The app if it answers on the pipe, else this process.
struct Router {
    /// `--local` or `--vault`: do not ask the app.
    in_process: bool,
    vault: Option<PathBuf>,
}

impl Caller for Router {
    fn call(&mut self, request: Request) -> Result<Value, Fail> {
        let download = matches!(request, Request::ModelDownload);
        // What the download shares with the app is nothing, so it never asks.
        if !self.in_process
            && !download
            && let Some(value) = service::ask(&request)?
        {
            return Ok(value);
        }
        let progress = download.then(|| -> DownloadProgress { Arc::new(show_download) });
        let local = open_local(self.vault.as_deref(), detects(&request), progress)?;
        let reply = local.handle(request);
        if download {
            // The progress line stays on one line; end it.
            eprintln!();
        }
        Ok(reply?)
    }
}

/// `\r<done>/<total> MB`, over the same line each time.
fn show_download(done: u64, total: u64) {
    const MB: u64 = 1024 * 1024;
    eprint!("\r{}/{} MB", done / MB, total / MB);
}

/// Whether the operation finds personal data, which the detection model helps with.
fn detects(request: &Request) -> bool {
    matches!(
        request,
        Request::ScanText { .. }
            | Request::Anonymize { .. }
            | Request::ScanFiles { .. }
            | Request::AnonymizeFiles { .. }
            | Request::SubjectSearch { .. }
            | Request::InventoryRescan
    )
}

/// The handler that answers in this process, on the vault at `vault` (the default vault when
/// `None`), the user's inventory and settings, and the detection model when it is downloaded.
fn open_local(
    vault: Option<&Path>,
    detecting: bool,
    progress: Option<DownloadProgress>,
) -> piikey::Result<Local> {
    let vault = match vault {
        Some(path) => path.to_path_buf(),
        None => default_path()?,
    };
    let model_dir = ner::files::default_dir().ok();
    let installed = model_dir.as_deref().is_some_and(ner::files::is_installed);
    let detector = model_dir.map(NerDetector::new);
    let engine = match &detector {
        Some(detector) if installed => Engine::open_with_model(&vault, detector.clone())?,
        _ => {
            if detecting {
                eprintln!(
                    "note: the detection model is not downloaded (piikey-cli model download); \
                     only emails, phone numbers, IBANs and other patterns are found"
                );
            }
            Engine::open(&vault)?
        }
    };
    // What the user switched off in Settings is off here too, as it is in the app.
    engine.set_enabled(Policy::load()?.enabled_kinds());
    let engine = Arc::new(engine);
    let source: EngineSource = Arc::new(move || Arc::clone(&engine));
    let inventory = Arc::new(Inventory::open(&Inventory::default_path()?)?);
    let local = Local::new(source, inventory, detector);
    Ok(match progress {
        Some(progress) => local.with_progress(progress),
        None => local,
    })
}

/// What a command reads and writes.
struct Streams<'a> {
    stdin: &'a mut dyn Read,
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

/// Runs `call` against `caller`, printing the result (as JSON with `json`) and the failures.
fn run(json: bool, call: Call, caller: &mut dyn Caller, streams: &mut Streams<'_>) -> Exit {
    match execute(json, call, caller, streams) {
        Ok(exit) => exit,
        Err(fail) => {
            report(json, &fail.into_api(), streams);
            Exit::Failed
        }
    }
}

fn execute(
    json: bool,
    call: Call,
    caller: &mut dyn Caller,
    streams: &mut Streams<'_>,
) -> Result<Exit, Fail> {
    let Call { input, fail_on } = call;
    let mut request = match input {
        Input::Request(request) => request,
        Input::Stdin(text) => text.request(read_text(streams.stdin)?),
    };
    make_absolute(&mut request)?;
    let view = View::of(&request);
    let value = caller.call(request)?;
    // A reader that leaves early (`| head`) is no failure, and the verdict below still counts.
    match print_result(json, &view, &value, streams) {
        Err(Fail::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe => {}
        printed => printed?,
    }
    let verdict = show::verdict(&view, &value, fail_on.as_ref())?;
    Ok(if verdict.found {
        Exit::Found
    } else if verdict.failed > 0 {
        Exit::Failed
    } else {
        Exit::Ok
    })
}

/// The result as JSON, or as lines and tables.
fn print_result(
    json: bool,
    view: &View,
    value: &Value,
    streams: &mut Streams<'_>,
) -> Result<(), Fail> {
    if json {
        writeln!(streams.out, "{}", show::pretty(value))?;
    } else {
        show::print(view, value, streams.out, streams.err)?;
    }
    streams.out.flush()?;
    Ok(())
}

/// The text on stdin. It travels as JSON, so it has to be UTF-8.
fn read_text(stdin: &mut dyn Read) -> Result<String, Fail> {
    let mut bytes = Vec::new();
    stdin.read_to_end(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| {
        ApiError::bad_request(
            "stdin is not UTF-8 text; give other encodings and documents as PATH arguments",
        )
        .into()
    })
}

/// Makes every path in `request` absolute. The app that answers has another working folder than
/// this process, and the API wants absolute paths whoever answers.
fn make_absolute(request: &mut Request) -> io::Result<()> {
    match request {
        Request::ScanFiles { paths, .. }
        | Request::SubjectSearch { paths, .. }
        | Request::ExplorerScan { paths } => absolute_all(paths),
        Request::AnonymizeFiles { paths, out } | Request::DeanonymizeFiles { paths, out, .. } => {
            absolute_all(paths)?;
            absolute(out)
        }
        Request::VaultExport { path, .. } | Request::InventoryReport { path, .. } => absolute(path),
        Request::InventoryList { under, .. } | Request::InventoryTree { under } => {
            under.as_mut().map_or(Ok(()), absolute)
        }
        Request::ScanText { .. }
        | Request::Anonymize { .. }
        | Request::Deanonymize { .. }
        | Request::VaultList { .. }
        | Request::VaultForget { .. }
        | Request::VaultWipe { .. }
        | Request::InventoryStatus
        | Request::InventoryRescan
        | Request::SettingsGet
        | Request::SettingsSet { .. }
        | Request::Kinds
        | Request::ModelStatus
        | Request::ModelDownload
        | Request::ApiToken { .. }
        | Request::Status
        | Request::Protection { .. } => Ok(()),
    }
}

fn absolute(target: &mut PathBuf) -> io::Result<()> {
    *target = path::absolute(&*target)?;
    Ok(())
}

fn absolute_all(paths: &mut [PathBuf]) -> io::Result<()> {
    paths.iter_mut().try_for_each(absolute)
}

/// Says why a command failed: on stderr, or with `--json` as the error object on stdout.
fn report(json: bool, error: &ApiError, streams: &mut Streams<'_>) {
    // The command already failed, and there is nowhere else to say so.
    let _ = if json {
        let body = serde_json::json!({ "code": error.code(), "message": error.message() });
        writeln!(streams.out, "{}", show::pretty(&body)).and_then(|()| streams.out.flush())
    } else {
        writeln!(streams.err, "piikey-cli: {}", error.message())
    };
}

/// `serve`: answers the API on the pipe (and HTTP) from this process until Ctrl+C.
fn serve(vault: Option<&Path>, args: &Serve) -> Result<(), Fail> {
    let handler: Arc<dyn Handler> = Arc::new(open_local(vault, true, None)?);
    let pipe = args
        .pipe
        .as_deref()
        .map_or_else(service::default_pipe, pipe_name);
    let pipe_server = service::spawn(Arc::clone(&handler), &pipe)?;
    let http_server = if args.http {
        match serve_http(handler, args.port) {
            Ok(started) => Some(started),
            Err(fail) => {
                pipe_server.stop();
                return Err(fail);
            }
        }
    } else {
        None
    };
    // Said now, so that a server that could not start does not claim to serve.
    eprintln!("piikey-cli: serving the API on {pipe}; stop with Ctrl+C");
    if let Some((_, port)) = &http_server {
        eprintln!(
            "piikey-cli: serving HTTP on {}; the token is what piikey-cli token prints",
            api::http::url(*port)
        );
    }
    // Ctrl+C ends the process, which closes the pipe: nothing here needs a clean stop.
    let ended = pipe_server.wait();
    if let Some((http_server, _)) = http_server {
        http_server.stop();
    }
    Ok(ended?)
}

/// The HTTP server, and the port it listens on.
fn serve_http(
    handler: Arc<dyn Handler>,
    port: Option<u16>,
) -> Result<(service::Server, u16), Fail> {
    let port = match port {
        Some(port) => port,
        None => Policy::load()?.http_port,
    };
    let token = api::read_or_create_token(false)?;
    Ok((api::http::spawn(handler, port, token)?, port))
}

/// A pipe name as given: `NAME` or the whole `\\.\pipe\NAME`.
fn pipe_name(name: &str) -> String {
    let full = name
        .get(..PIPE_PREFIX.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(PIPE_PREFIX));
    if full {
        name.to_owned()
    } else {
        format!("{PIPE_PREFIX}{name}")
    }
}

/// Entry point called by `main`.
pub fn main() -> ExitCode {
    let cli = match parse::parse(std::env::args_os().skip(1)) {
        Ok(cli) => cli,
        Err(ParseError::Usage(message)) => {
            eprintln!("piikey-cli: {message}\n{USAGE}");
            return Exit::Usage.into();
        }
        Err(ParseError::Invalid(message)) => {
            eprintln!("piikey-cli: {message}");
            return Exit::Usage.into();
        }
    };
    let in_process = cli.in_process();
    let Cli {
        json,
        vault,
        command,
        ..
    } = cli;
    let exit = match command {
        Command::Help => print_line(USAGE),
        Command::Version => print_line(&format!("piikey-cli {}", env!("CARGO_PKG_VERSION"))),
        Command::Serve(args) => match serve(vault.as_deref(), &args) {
            Ok(()) => Exit::Ok,
            Err(fail) => {
                eprintln!("piikey-cli: {}", fail.into_api().message());
                Exit::Failed
            }
        },
        Command::Call(call) => {
            let mut router = Router { in_process, vault };
            let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
            let mut streams = Streams {
                stdin: &mut stdin.lock(),
                out: &mut stdout.lock(),
                err: &mut stderr.lock(),
            };
            run(json, call, &mut router, &mut streams)
        }
    };
    exit.into()
}

/// A line on stdout, for `--help` and `--version`. A reader that left (`| head`) is no failure;
/// any other write error is, and no panic.
fn print_line(line: &str) -> Exit {
    match writeln!(io::stdout().lock(), "{line}") {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Exit::Failed,
        _ => Exit::Ok,
    }
}
