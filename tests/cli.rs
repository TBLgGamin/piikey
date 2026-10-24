//! `piikey-cli` as a process: arguments, stdin, stdout and exit codes.
//!
//! Every test gets a data folder of its own (`LOCALAPPDATA`) and a pipe name of its own
//! (`USERNAME`), so nothing of the user's is read or written, no app that happens to run answers,
//! and no detection model is found: the patterns do the work, as on CI.

use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// How long a run may take before the test gives up on it.
const LIMIT: Duration = Duration::from_mins(2);

/// A data folder and a user name (so a pipe) that belong to one test.
struct Sandbox {
    dir: PathBuf,
    user: String,
}

/// What a run printed and how it ended.
struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

impl Sandbox {
    fn new() -> TestResult<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let id = format!(
            "piikey-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(&id);
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, user: id })
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_piikey-cli"));
        command
            .env("LOCALAPPDATA", &self.dir)
            .env("USERNAME", &self.user);
        command
    }

    /// `piikey-cli args`, with `stdin` as its input.
    fn run(&self, args: &[&str], stdin: &str) -> TestResult<Ran> {
        let mut child = self
            .cli()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Each pipe has a thread: a command that fills a pipe nobody reads, or waits for input
        // while the test waits for its output, would never finish.
        let feeding = child.stdin.take().map(|mut input| {
            let text = stdin.to_owned();
            thread::spawn(move || {
                // A command that fails before it reads has no use for it.
                let _ = input.write_all(text.as_bytes());
            })
        });
        let out = drain(child.stdout.take());
        let err = drain(child.stderr.take());
        let deadline = Instant::now() + LIMIT;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                return Err(format!("{args:?} did not finish").into());
            }
            thread::sleep(Duration::from_millis(20));
        };
        if let Some(feeding) = feeding {
            feeding
                .join()
                .map_err(|_| "the thread feeding stdin panicked")?;
        }
        let (out, err) = (out.join(), err.join());
        let (Ok(out), Ok(err)) = (out, err) else {
            return Err("a thread reading the output panicked".into());
        };
        Ok(Ran {
            code: status.code(),
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
        })
    }

    /// The result of `--json --local args`.
    fn json(&self, args: &[&str], stdin: &str) -> TestResult<Value> {
        let mut line = vec!["--json", "--local"];
        line.extend_from_slice(args);
        let got = self.run(&line, stdin)?;
        assert_eq!(got.code, Some(0), "{args:?}: {}", got.err);
        Ok(serde_json::from_str(&got.out)?)
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A `piikey-cli serve` that runs until the test ends.
struct Server {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Server {
    fn start(sandbox: &Sandbox) -> TestResult<Self> {
        let mut child = sandbox
            .cli()
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("the server has no stderr")?;
        let (send, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Self { child, lines };
        server.wait_for("serving the API")?;
        Ok(server)
    }

    /// Waits until the server has said a line that holds `text`.
    fn wait_for(&mut self, text: &str) -> TestResult {
        let deadline = Instant::now() + LIMIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(text) => return Ok(()),
                Ok(_) => {}
                Err(_) => return Err(format!("the server never said '{text}'").into()),
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `pipe` to its end on a thread of its own.
fn drain(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

const MAIL: &str = "mail jan.jansen@acme.nl about it\n";

#[test]
fn version_and_help_are_printed_and_exit_zero() -> TestResult {
    let sandbox = Sandbox::new()?;
    let got = sandbox.run(&["--version"], "")?;
    assert_eq!(got.code, Some(0));
    assert_eq!(
        got.out,
        format!("piikey-cli {}\n", env!("CARGO_PKG_VERSION"))
    );
    let got = sandbox.run(&["--help"], "")?;
    assert_eq!(got.code, Some(0));
    assert!(got.out.starts_with("usage:\n"), "{}", got.out);
    Ok(())
}

#[test]
fn a_wrong_command_line_exits_two() -> TestResult {
    let sandbox = Sandbox::new()?;
    let lines: [&[&str]; 6] = [
        &[],
        &["frobnicate"],
        &["scan", "--bogus"],
        &["anonymize", "a.txt"],
        &["vault", "wipe"],
        &["scan", "--fail-on", "nope"],
    ];
    for args in lines {
        let got = sandbox.run(args, "")?;
        assert_eq!(got.code, Some(2), "{args:?}: {}", got.err);
        assert_eq!(got.out, "");
        assert!(got.err.starts_with("piikey-cli: "), "{}", got.err);
    }
    Ok(())
}

#[test]
fn scan_reads_stdin_and_gates_with_exit_one() -> TestResult {
    let sandbox = Sandbox::new()?;
    let found = sandbox.json(&["scan"], MAIL)?;
    assert_eq!(found["results"][0][0]["kind"], "email");
    assert_eq!(found["results"][0][0]["value"], "jan.jansen@acme.nl");

    let scan = |gate: &str, text: &str| -> TestResult<Option<i32>> {
        Ok(sandbox
            .run(&["scan", "--local", "--fail-on", gate], text)?
            .code)
    };
    assert_eq!(scan("email", MAIL)?, Some(1));
    assert_eq!(scan("any", MAIL)?, Some(1));
    assert_eq!(scan("iban,phone", MAIL)?, Some(0));
    assert_eq!(scan("any", "hello\n")?, Some(0));
    // A scan changes nothing in the vault.
    assert_eq!(sandbox.json(&["vault", "list"], "")?["total"], 0);
    Ok(())
}

#[test]
fn text_goes_through_the_vault_and_back() -> TestResult {
    let sandbox = Sandbox::new()?;
    let masked = sandbox.run(&["anonymize", "--local"], MAIL)?;
    assert_eq!(masked.code, Some(0), "{}", masked.err);
    assert!(!masked.out.contains("jan.jansen@acme.nl"), "{}", masked.out);
    assert!(masked.out.starts_with("mail "), "{}", masked.out);
    assert!(masked.out.ends_with(" about it\n"), "{}", masked.out);
    let restored = sandbox.run(&["deanonymize", "--local"], &masked.out)?;
    assert_eq!(restored.code, Some(0), "{}", restored.err);
    assert_eq!(restored.out, MAIL);
    // The stand-in is in the vault, with the original.
    let list = sandbox.json(&["vault", "list", "--query", "jansen"], "")?;
    assert_eq!(list["total"], 1);
    assert_eq!(list["records"][0]["original"], "jan.jansen@acme.nl");
    Ok(())
}

/// What a command prints does not wait for the test to finish reading: output that fills a pipe
/// blocks the command until somebody reads it.
#[test]
fn a_command_that_prints_more_than_a_pipe_holds_still_finishes() -> TestResult {
    let sandbox = Sandbox::new()?;
    let lines = 2000;
    let text = "mail jan.jansen@acme.nl about it\n".repeat(lines);
    let masked = sandbox.run(&["anonymize", "--local"], &text)?;
    assert_eq!(masked.code, Some(0), "{}", masked.err);
    assert_eq!(masked.out.lines().count(), lines);
    assert!(masked.out.len() > 64 * 1024, "{} bytes", masked.out.len());
    Ok(())
}

#[test]
fn forgetting_a_value_removes_it_from_what_is_exported() -> TestResult {
    let sandbox = Sandbox::new()?;
    let masked = sandbox.run(&["anonymize", "--local"], MAIL)?;
    assert_eq!(masked.code, Some(0), "{}", masked.err);
    let forgot = sandbox.run(&["vault", "forget", "--local", "jan.jansen@acme.nl"], "")?;
    assert_eq!(forgot.code, Some(0), "{}", forgot.err);
    assert_eq!(forgot.out, "forgot 1 record\n");
    assert_eq!(sandbox.json(&["vault", "list"], "")?["total"], 0);
    let file = sandbox.path("vault.csv");
    let exported = sandbox.run(
        &[
            "vault", "export", "--local", "--format", "csv", "--out", &file,
        ],
        "",
    )?;
    assert_eq!(exported.code, Some(0), "{}", exported.err);
    let csv = fs::read_to_string(&file)?;
    assert_eq!(csv.trim_end(), "kind,original,proxy");
    // An export never overwrites.
    let again = sandbox.run(&["vault", "export", "--local", "--out", &file], "")?;
    assert_eq!(again.code, Some(3), "{}", again.err);
    // Wiping needs the word yes, and keeps its promise.
    sandbox.run(&["anonymize", "--local"], MAIL)?;
    assert_eq!(
        sandbox.run(&["vault", "wipe", "--local"], "")?.code,
        Some(2)
    );
    let wiped = sandbox.run(&["vault", "wipe", "--local", "--yes"], "")?;
    assert_eq!(wiped.code, Some(0), "{}", wiped.err);
    assert_eq!(sandbox.json(&["vault", "list"], "")?["total"], 0);
    Ok(())
}

#[test]
fn files_are_scanned_recorded_masked_and_searched() -> TestResult {
    let sandbox = Sandbox::new()?;
    let tree = sandbox.dir.join("tree");
    fs::create_dir_all(&tree)?;
    fs::write(
        tree.join("a.txt"),
        "Rekening NL91ABNA0417164300 en nog iets\n",
    )?;
    fs::write(tree.join("b.txt"), "bel +31 6 1234 5678 vandaag\n")?;
    fs::write(tree.join("c.txt"), "niets bijzonders\n")?;
    let tree = tree.to_string_lossy().into_owned();

    let scan = sandbox.json(&["scan", &tree], "")?;
    let files = scan["files"].as_array().ok_or("no files")?;
    assert_eq!(files.len(), 3);
    assert_eq!(scan["hits"], 2);
    let a = files
        .iter()
        .find(|file| file["path"].as_str().is_some_and(|p| p.ends_with("a.txt")))
        .ok_or("a.txt is not listed")?;
    assert_eq!(a["counts"]["iban"], 1);

    // Recorded in the inventory, which is why it can be listed.
    let listed = sandbox.json(&["inventory", "list"], "")?;
    assert_eq!(listed["total"], 2);
    // `--no-record` keeps a scan out of it; without it a new file is added.
    let extra = sandbox.dir.join("tree").join("d.txt");
    fs::write(&extra, "mail jan.jansen@acme.nl\n")?;
    let extra = extra.to_string_lossy().into_owned();
    assert_eq!(sandbox.json(&["inventory", "status"], "")?["files"], 3);
    sandbox.json(&["scan", "--no-record", &extra], "")?;
    assert_eq!(sandbox.json(&["inventory", "status"], "")?["files"], 3);
    sandbox.json(&["scan", &extra], "")?;
    assert_eq!(sandbox.json(&["inventory", "status"], "")?["files"], 4);

    let gate = sandbox.run(
        &["scan", "--local", "--fail-on", "iban", "--no-record", &tree],
        "",
    )?;
    assert_eq!(gate.code, Some(1), "{}", gate.err);
    assert!(gate.out.contains("a.txt"), "{}", gate.out);

    // Masked into another folder, whose files then scan clean.
    let out = sandbox.path("masked");
    let masked = sandbox.run(&["anonymize", "--local", "--out", &out, &tree], "")?;
    assert_eq!(masked.code, Some(0), "{}", masked.err);
    let text = fs::read_to_string(sandbox.dir.join("masked").join("a.txt"))?;
    assert!(!text.contains("NL91ABNA0417164300"), "{text}");
    let clean = sandbox.run(
        &["scan", "--local", "--no-record", "--fail-on", "any", &out],
        "",
    )?;
    assert_eq!(clean.code, Some(0), "{}{}", clean.out, clean.err);

    // Who is named where.
    let subject = sandbox.json(&["subject", "--value", "+31612345678", &tree], "")?;
    let matches = subject["matches"].as_array().ok_or("no matches")?;
    assert_eq!(matches.len(), 1);
    assert!(
        matches[0]["path"]
            .as_str()
            .is_some_and(|p| p.ends_with("b.txt"))
    );
    let none = sandbox.json(&["subject", "--value", "0612345678", &tree], "")?;
    assert_eq!(none["matches"].as_array().map(Vec::len), Some(0));
    Ok(())
}

#[test]
fn a_command_that_cannot_be_done_exits_three_with_the_reason() -> TestResult {
    let sandbox = Sandbox::new()?;
    let missing = sandbox.path("nope.txt");
    let got = sandbox.run(&["scan", "--local", "--no-record", &missing], "")?;
    assert_eq!(got.code, Some(3), "{}", got.err);
    // The reason is the last line; a note about the model may come before it.
    let reason = got.err.lines().last().unwrap_or_default();
    assert!(reason.starts_with("piikey-cli: "), "{}", got.err);
    assert!(reason.contains("nope.txt"), "{}", got.err);
    // With --json the error is the output, with the API's code.
    let got = sandbox.run(&["--json", "--local", "scan", "--no-record", &missing], "")?;
    assert_eq!(got.code, Some(3));
    let error: Value = serde_json::from_str(&got.out)?;
    assert_eq!(error["code"], "not_found");
    // What needs the app says so when the app is not there.
    let got = sandbox.run(&["--json", "protection", "on"], "")?;
    assert_eq!(got.code, Some(3), "{}", got.err);
    let error: Value = serde_json::from_str(&got.out)?;
    assert_eq!(error["code"], "app_required");
    let got = sandbox.run(&["--json", "open"], "")?;
    assert_eq!(got.code, Some(3), "{}", got.err);
    let error: Value = serde_json::from_str(&got.out)?;
    assert_eq!(error["code"], "app_required");
    // Text that is no text.
    let mut child = sandbox
        .cli()
        .args(["anonymize", "--local"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(&[0xff, 0xfe, 0xfd])?;
    }
    let got = child.wait_with_output()?;
    assert_eq!(got.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&got.stderr).contains("UTF-8"));
    Ok(())
}

#[test]
fn the_settings_are_kept_and_decide_what_is_looked_for() -> TestResult {
    let sandbox = Sandbox::new()?;
    let inbox = sandbox.dir.join("inbox");
    let inbox = inbox.to_string_lossy().into_owned();
    let set = sandbox.json(
        &[
            "settings",
            "set",
            "highlight=always",
            "background=false",
            &format!("inventory_root={inbox}"),
            &format!("monitor_root={inbox}"),
            "site=chatgpt.com",
            "site=*.openai.com",
            "http_port=7999",
        ],
        "",
    )?;
    assert_eq!(set["highlight"], "always");
    let got = sandbox.json(&["settings", "get"], "")?;
    assert!(got.get("watch").is_none() && got.get("watch_folders").is_none());
    assert_eq!(got["background"], false);
    assert_eq!(got["monitored_roots"][0], inbox);
    assert!(got.get("inventory").is_none(), "{got}");
    assert!(got.get("inventory_exclude").is_none(), "{got}");
    assert_eq!(got["http_port"], 7999);
    assert_eq!(got["sites"][1], "*.openai.com");
    // The inventory's switch and its exclusions are gone, and so is the watch.
    for gone in [
        "inventory=true",
        r"inventory_exclude=C:\Private",
        "watch=true",
        r"watch_folder=C:\Inbox",
    ] {
        let refused = sandbox.run(&["settings", "set", "--local", gone], "")?;
        assert_eq!(refused.code, Some(2), "{gone}: {}", refused.err);
    }
    // A value the settings refuse changes nothing.
    let refused = sandbox.run(&["settings", "set", "--local", "site=not a site"], "")?;
    assert_eq!(refused.code, Some(3), "{}", refused.err);
    assert_eq!(
        sandbox.json(&["settings", "get"], "")?["sites"][0],
        "chatgpt.com"
    );

    // A kind that is switched off is not looked for.
    let kinds = sandbox.json(&["kinds"], "")?;
    let email = kinds
        .as_array()
        .and_then(|all| all.iter().find(|k| k["kind"] == "email"))
        .ok_or("no email kind")?;
    assert_eq!(email["enabled"], true);
    sandbox.json(&["settings", "set", "disabled_kind=email"], "")?;
    let found = sandbox.json(&["scan"], MAIL)?;
    assert_eq!(found["results"][0].as_array().map(Vec::len), Some(0));
    sandbox.json(&["settings", "set", "disabled_kind="], "")?;
    let found = sandbox.json(&["scan"], MAIL)?;
    assert_eq!(found["results"][0][0]["kind"], "email");
    Ok(())
}

#[test]
fn the_token_is_kept_until_it_is_rotated() -> TestResult {
    let sandbox = Sandbox::new()?;
    let token = |args: &[&str]| -> TestResult<String> {
        let mut line = vec!["token", "--local"];
        line.extend_from_slice(args);
        let got = sandbox.run(&line, "")?;
        assert_eq!(got.code, Some(0), "{}", got.err);
        Ok(got.out.trim_end().to_owned())
    };
    let first = token(&[])?;
    assert!(first.len() >= 32 && first.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(token(&[])?, first);
    assert_ne!(token(&["--rotate"])?, first);
    Ok(())
}

#[test]
fn a_server_answers_before_this_process_does() -> TestResult {
    let sandbox = Sandbox::new()?;
    let _server = Server::start(&sandbox)?;
    // Through the pipe: the engine is the server's, so there is nothing to say about the model.
    let got = sandbox.run(&["--json", "scan"], MAIL)?;
    assert_eq!(got.code, Some(0), "{}", got.err);
    assert!(!got.err.contains("note:"), "{}", got.err);
    let found: Value = serde_json::from_str(&got.out)?;
    assert_eq!(found["results"][0][0]["kind"], "email");
    // What a server answers for itself is the in-process answer: the app is not there.
    let status = sandbox.run(&["--json", "status"], "")?;
    let status: Value = serde_json::from_str(&status.out)?;
    assert_eq!(status["app"], false);
    // A second server finds the pipe taken.
    let second = sandbox.run(&["serve"], "")?;
    assert_eq!(second.code, Some(3), "{}", second.err);
    assert!(
        second.err.contains("already serves the API"),
        "{}",
        second.err
    );
    // `--local` goes around the server.
    let local = sandbox.run(&["--local", "scan"], MAIL)?;
    assert_eq!(local.code, Some(0), "{}", local.err);
    assert!(local.err.contains("note:"), "{}", local.err);
    Ok(())
}

/// The settings file of the account list in the sandbox's data folder.
fn accounts_file(sandbox: &Sandbox) -> PathBuf {
    sandbox.dir.join("piikey").join("sources.json")
}

#[test]
fn the_help_lists_the_account_commands() -> TestResult {
    let sandbox = Sandbox::new()?;
    let got = sandbox.run(&["--help"], "")?;
    assert_eq!(got.code, Some(0));
    for line in [
        "piikey-cli account list | connect ID | remove ID --yes | browse ID [--under PATH]",
        "piikey-cli account add PROVIDER --label NAME",
        "--client-secret-stdin",
    ] {
        assert!(
            got.out.contains(line),
            "{line} is not in the help: {}",
            got.out
        );
    }
    Ok(())
}

#[test]
fn a_wrong_account_command_exits_two_and_adds_nothing() -> TestResult {
    let sandbox = Sandbox::new()?;
    let lines: [&[&str]; 8] = [
        &["account"],
        &["account", "sign"],
        &["account", "connect"],
        &["account", "remove", "ab"],
        &["account", "browse"],
        &["account", "add", "dropbox", "--label", "W"],
        &["account", "add", "icloud", "--label", "W"],
        // The client secret has to come on stdin.
        &[
            "account",
            "add",
            "box",
            "--label",
            "T",
            "--mode",
            "box_delegated",
            "--client-id",
            "c",
        ],
    ];
    for args in lines {
        let mut line = vec!["--local"];
        line.extend_from_slice(args);
        let got = sandbox.run(&line, "")?;
        assert_eq!(got.code, Some(2), "{args:?}: {}", got.err);
        assert_eq!(got.out, "", "{args:?}");
    }
    assert!(!accounts_file(&sandbox).exists());
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario over a data folder: add, list, scan a location, remove, list again"
)]
fn accounts_are_added_listed_and_removed_with_their_locations() -> TestResult {
    let sandbox = Sandbox::new()?;
    fs::write(sandbox.dir.join("key.json"), "{}")?;
    let key = sandbox.path("key.json");
    let none = sandbox.run(&["--local", "account", "list"], "")?;
    assert_eq!(none.code, Some(0), "{}", none.err);
    assert!(none.out.starts_with("no cloud accounts"), "{}", none.out);

    let added = sandbox.json(
        &[
            "account",
            "add",
            "google_drive",
            "--mode",
            "google_service_account",
            "--label",
            "Workspace",
            "--key-file",
            &key,
            "--user",
            "a@acme.nl",
        ],
        "",
    )?;
    assert_eq!(added["provider"], "google_drive");
    assert_eq!(added["label"], "Workspace");
    assert_eq!(added["path"], r"\\Google Drive\Workspace");
    assert_eq!(added["sign_in"]["mode"], "google_service_account");
    assert_eq!(added["sign_in"]["key_file"], key.as_str());
    assert_eq!(added["connected"], true);
    let id = added["id"].as_str().ok_or("no id")?.to_owned();

    // Dropbox has one way to sign in, so the mode can be left out; nobody has signed in yet.
    let dropbox = sandbox.json(
        &[
            "account",
            "add",
            "dropbox",
            "--label",
            "Personal",
            "--app-key",
            "key-1",
        ],
        "",
    )?;
    assert_eq!(dropbox["connected"], false);
    let dropbox_id = dropbox["id"].as_str().ok_or("no id")?.to_owned();

    let listed = sandbox.json(&["account", "list"], "")?;
    assert_eq!(listed["accounts"].as_array().map(Vec::len), Some(2));
    assert_eq!(listed["accounts"][0]["id"], id.as_str());
    assert_eq!(listed["accounts"][1]["id"], dropbox_id.as_str());
    let table = sandbox.run(&["--local", "account", "list"], "")?;
    assert_eq!(table.code, Some(0), "{}", table.err);
    assert!(table.out.starts_with("ID "), "{}", table.out);
    for text in [
        id.as_str(),
        "Google Drive",
        "Workspace",
        "google_service_account",
        "connected",
        dropbox_id.as_str(),
        "not connected",
        r"\\Dropbox\Personal",
    ] {
        assert!(table.out.contains(text), "{text} is not in {}", table.out);
    }

    // The same label is refused, and so is a location of an account that is not there.
    let again = sandbox.run(
        &[
            "--local",
            "account",
            "add",
            "dropbox",
            "--label",
            "personal",
            "--app-key",
            "k",
        ],
        "",
    )?;
    assert_eq!(again.code, Some(3), "{}", again.out);
    assert!(again.err.contains("already"), "{}", again.err);
    let stranger = sandbox.run(
        &[
            "--local",
            "settings",
            "set",
            r"inventory_root=\\Google Drive\Nobody\Docs",
        ],
        "",
    )?;
    assert_eq!(stranger.code, Some(3), "{}", stranger.out);
    assert!(
        stranger.err.contains("add the account first"),
        "{}",
        stranger.err
    );

    // A location of the account goes with it.
    let location = r"inventory_root=\\Google Drive\Workspace\Docs";
    sandbox.json(&["settings", "set", location], "")?;
    let status = sandbox.json(&["inventory", "status"], "")?;
    assert_eq!(
        status["roots"],
        serde_json::json!([r"\\Google Drive\Workspace\Docs"])
    );
    let refused = sandbox.run(&["--local", "account", "remove", &id], "")?;
    assert_eq!(refused.code, Some(2), "{}", refused.err);
    let removed = sandbox.json(&["account", "remove", &id, "--yes"], "")?;
    assert_eq!(
        removed,
        serde_json::json!({"id": id, "locations": [r"\\Google Drive\Workspace\Docs"], "forgotten": 0})
    );
    let status = sandbox.json(&["inventory", "status"], "")?;
    assert_eq!(status["roots"], serde_json::json!([]));
    let left = sandbox.json(&["account", "list"], "")?;
    assert_eq!(left["accounts"].as_array().map(Vec::len), Some(1));
    let text = sandbox.run(&["--local", "account", "remove", &dropbox_id, "--yes"], "")?;
    assert_eq!(text.code, Some(0), "{}", text.err);
    assert!(
        text.out
            .starts_with(&format!("removed the account {dropbox_id}\n")),
        "{}",
        text.out
    );
    Ok(())
}

#[test]
fn an_account_that_is_not_there_is_an_api_error() -> TestResult {
    let sandbox = Sandbox::new()?;
    for args in [
        &["account", "connect", "0123456789abcdef"][..],
        &["account", "browse", "0123456789abcdef"],
        &["account", "remove", "0123456789abcdef", "--yes"],
    ] {
        let mut line = vec!["--local"];
        line.extend_from_slice(args);
        let got = sandbox.run(&line, "")?;
        assert_eq!(got.code, Some(3), "{args:?}: {}", got.out);
        assert!(
            got.err.contains("no cloud account has the id"),
            "{}",
            got.err
        );
    }
    Ok(())
}

#[test]
fn the_client_secret_comes_on_stdin_and_is_kept_in_neither_the_output_nor_the_settings()
-> TestResult {
    let sandbox = Sandbox::new()?;
    let added = sandbox.json(
        &[
            "account",
            "add",
            "box",
            "--label",
            "Team",
            "--mode",
            "box_delegated",
            "--client-id",
            "id-1",
            "--client-secret-stdin",
        ],
        "s3cret-xyz\n",
    )?;
    assert_eq!(added["connected"], false, "a person still has to sign in");
    assert!(!added.to_string().contains("s3cret"), "{added}");
    let settings = fs::read_to_string(accounts_file(&sandbox))?;
    assert!(!settings.contains("s3cret"), "{settings}");
    assert!(settings.contains("Team"));
    let id = added["id"].as_str().ok_or("no id")?;

    // Without a secret nothing is added.
    let empty = sandbox.run(
        &[
            "--local",
            "account",
            "add",
            "box",
            "--label",
            "Other",
            "--mode",
            "box_delegated",
            "--client-id",
            "id-2",
            "--client-secret-stdin",
        ],
        "\n",
    )?;
    assert_eq!(empty.code, Some(3), "{}", empty.out);
    assert!(empty.err.contains("no client secret"), "{}", empty.err);
    let listed = sandbox.json(&["account", "list"], "")?;
    assert_eq!(listed["accounts"].as_array().map(Vec::len), Some(1));
    sandbox.json(&["account", "remove", id, "--yes"], "")?;
    Ok(())
}

#[test]
fn a_path_in_a_cloud_account_is_no_path_to_scan() -> TestResult {
    let sandbox = Sandbox::new()?;
    let got = sandbox.run(&["--local", "scan", r"\\Google Drive\Work\Docs"], "")?;
    assert_eq!(got.code, Some(3), "{}", got.out);
    assert!(got.err.contains("cloud account"), "{}", got.err);
    Ok(())
}
