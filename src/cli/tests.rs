use std::ffi::OsString;

use serde_json::json;

use super::*;

/// A caller that answers from a script and remembers what it was asked.
struct Script {
    replies: Vec<Result<Value, Fail>>,
    asked: Vec<Request>,
}

impl Caller for Script {
    fn call(&mut self, request: Request) -> Result<Value, Fail> {
        self.asked.push(request);
        if self.replies.is_empty() {
            return Err(Fail::Api(ApiError::internal(
                "the script has no reply left",
            )));
        }
        self.replies.remove(0)
    }
}

/// What a command did.
struct Ran {
    exit: Exit,
    out: String,
    err: String,
    asked: Vec<Request>,
}

fn ran(args: &[&str], stdin: &[u8], replies: Vec<Result<Value, Fail>>) -> Ran {
    let mut out = Vec::new();
    let mut got = ran_into(args, stdin, replies, &mut out);
    got.out = String::from_utf8_lossy(&out).into_owned();
    got
}

/// Like [`ran`], with stdout going to `out`; the result's `out` is empty.
fn ran_into(
    args: &[&str],
    stdin: &[u8],
    replies: Vec<Result<Value, Fail>>,
    out: &mut dyn Write,
) -> Ran {
    let cli = match parse::parse(args.iter().map(OsString::from)) {
        Ok(cli) => cli,
        Err(error) => panic!("{args:?} was rejected: {error:?}"),
    };
    let Command::Call(call) = cli.command else {
        panic!("{args:?} is not a call");
    };
    let mut script = Script {
        replies,
        asked: Vec::new(),
    };
    let mut err = Vec::new();
    let mut input = stdin;
    let exit = run(
        cli.json,
        call,
        &mut script,
        &mut Streams {
            stdin: &mut input,
            out,
            err: &mut err,
        },
    );
    Ran {
        exit,
        out: String::new(),
        err: String::from_utf8_lossy(&err).into_owned(),
        asked: script.asked,
    }
}

/// A reader that has gone away, as `head` has after its last line.
struct Gone;

impl Write for Gone {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

fn one_email() -> Value {
    json!({"results": [[{"start": 5, "end": 16, "kind": "email", "value": "jan@acme.nl"}]]})
}

/// A scanned file as the API writes it.
fn scanned(path: &str, status: &str, counts: Value) -> Value {
    let mut file = json!({"path": path, "size": 0, "modified": 0, "scanned": 0, "status": status});
    file["counts"] = counts;
    file
}

fn one_file_with(kind: &str) -> Value {
    json!({"hits": 1, "files": [scanned(r"C:\x\a.txt", "ok", json!({kind: 1}))]})
}

fn failed_file(path: &str, error: &str) -> Value {
    let mut failed = scanned(path, "failed", json!({}));
    failed["error"] = json!(error);
    failed
}

#[test]
fn a_scan_of_stdin_sends_the_text_and_prints_what_it_found() {
    let got = ran(&["scan"], b"mail jan@acme.nl", vec![Ok(one_email())]);
    assert_eq!(got.exit, Exit::Ok);
    assert_eq!(
        got.out,
        "KIND   BYTES  VALUE\nemail  5-16   jan@acme.nl\n1 value found\n"
    );
    assert_eq!(got.err, "");
    assert!(got.asked.len() == 1);
    assert!(
        got.asked[0]
            == Request::ScanText {
                texts: vec!["mail jan@acme.nl".to_owned()]
            }
    );
}

#[test]
fn fail_on_turns_a_find_of_that_kind_into_exit_one() {
    let found = ran(&["scan", "--fail-on", "email"], b"x", vec![Ok(one_email())]);
    assert_eq!(found.exit, Exit::Found);
    // The result is printed all the same.
    assert!(found.out.contains("jan@acme.nl"));
    let other_kind = ran(&["scan", "--fail-on", "iban"], b"x", vec![Ok(one_email())]);
    assert_eq!(other_kind.exit, Exit::Ok);
    let any = ran(&["scan", "--fail-on", "any"], b"x", vec![Ok(one_email())]);
    assert_eq!(any.exit, Exit::Found);
    let clean = ran(
        &["scan", "--fail-on", "any"],
        b"hello",
        vec![Ok(json!({"results": [[]]}))],
    );
    assert_eq!(clean.exit, Exit::Ok);
    assert_eq!(clean.out, "no personal data found\n");
    // Without a gate a find is no failure.
    assert_eq!(ran(&["scan"], b"x", vec![Ok(one_email())]).exit, Exit::Ok);
}

#[test]
fn fail_on_gates_a_scan_of_files_too() {
    let iban = one_file_with("iban");
    let args = ["scan", "--no-record", "--fail-on", "iban", "a.txt"];
    let got = ran(&args, b"", vec![Ok(iban.clone())]);
    assert_eq!(got.exit, Exit::Found);
    assert!(got.out.contains(r"C:\x\a.txt"));
    let other = ran(
        &["scan", "--fail-on", "email", "a.txt"],
        b"",
        vec![Ok(iban)],
    );
    assert_eq!(other.exit, Exit::Ok);
    // `--no-record` is carried to the API, so the scan stays out of the inventory.
    match &got.asked[..] {
        [Request::ScanFiles { record, .. }] => assert!(!record),
        _ => panic!("not one scan_files"),
    }
}

#[test]
fn a_file_that_could_not_be_scanned_fails_the_command_unless_data_was_found() {
    let value = json!({"hits": 0, "files": [failed_file("a", "bad zip")]});
    let got = ran(&["scan", "a"], b"", vec![Ok(value.clone())]);
    assert_eq!(got.exit, Exit::Failed);
    assert_eq!(got.err, "piikey-cli: a: bad zip\n");
    // A file that is not a supported format is no failure.
    let skipped = json!({"hits": 0, "files": [scanned("b.bin", "unsupported", json!({}))]});
    assert_eq!(
        ran(&["scan", "b.bin"], b"", vec![Ok(skipped)]).exit,
        Exit::Ok
    );
    // What was found is the more important news.
    let mixed = json!({"hits": 1, "files": [
        failed_file("a", "bad zip"),
        scanned("b", "ok", json!({"email": 1}))
    ]});
    let got = ran(
        &["scan", "--fail-on", "any", "a", "b"],
        b"",
        vec![Ok(mixed)],
    );
    assert_eq!(got.exit, Exit::Found);
}

#[test]
fn files_that_were_not_written_fail_the_command() {
    let value = json!({
        "written": [{"input": "a.txt", "output": "o\\a.txt"}],
        "failed": [{"input": "b.docx", "error": "not a document"}]
    });
    let got = ran(
        &["anonymize", "--out", "o", "a.txt", "b.docx"],
        b"",
        vec![Ok(value)],
    );
    assert_eq!(got.exit, Exit::Failed);
    assert_eq!(got.out, "a.txt -> o\\a.txt\n1 file written, 1 failed\n");
    assert_eq!(got.err, "piikey-cli: b.docx: not a document\n");
}

#[test]
fn anonymized_text_goes_back_out_byte_for_byte() {
    let masked = "Mail kim@example.org\r\n  ";
    let got = ran(
        &["anonymize"],
        b"Mail jan@acme.nl\r\n  ",
        vec![Ok(json!({"texts": [masked]}))],
    );
    assert_eq!(got.exit, Exit::Ok);
    assert_eq!(got.out, masked);
    assert!(
        got.asked[0]
            == Request::Anonymize {
                texts: vec!["Mail jan@acme.nl\r\n  ".to_owned()]
            }
    );
    let back = ran(
        &["deanonymize", "--tolerant"],
        b"x",
        vec![Ok(json!({"texts": ["y"]}))],
    );
    assert!(
        back.asked[0]
            == Request::Deanonymize {
                texts: vec!["x".to_owned()],
                tolerant: true
            }
    );
}

#[test]
fn json_prints_the_result_as_it_is() {
    let reply = one_email();
    let got = ran(&["--json", "scan"], b"x", vec![Ok(reply.clone())]);
    assert_eq!(got.exit, Exit::Ok);
    assert_eq!(got.out, format!("{}\n", show::pretty(&reply)));
    let value: Value = serde_json::from_str(&got.out).unwrap_or_default();
    assert_eq!(value, reply);
    // The text of a stdin command is a result like any other with `--json`.
    let masked = ran(
        &["anonymize", "--json"],
        b"x",
        vec![Ok(json!({"texts": ["y"]}))],
    );
    assert_eq!(masked.out, "{\n  \"texts\": [\n    \"y\"\n  ]\n}\n");
}

#[test]
fn an_api_error_is_exit_three_with_its_message() {
    let error = || {
        vec![Err(Fail::Api(ApiError::busy(
            "another inventory scan is running",
        )))]
    };
    let got = ran(&["inventory", "rescan"], b"", error());
    assert_eq!(got.exit, Exit::Failed);
    assert_eq!(got.out, "");
    assert_eq!(got.err, "piikey-cli: another inventory scan is running\n");
    // With `--json` the error is the output, and stderr stays quiet.
    let got = ran(&["--json", "inventory", "rescan"], b"", error());
    assert_eq!(got.exit, Exit::Failed);
    assert_eq!(got.err, "");
    let value: Value = serde_json::from_str(&got.out).unwrap_or_default();
    assert_eq!(
        value,
        json!({"code": "busy", "message": "another inventory scan is running"})
    );
}

#[test]
fn a_failed_write_or_read_is_exit_three_too() {
    let got = ran(
        &["status"],
        b"",
        vec![Err(Fail::Io(io::Error::other("disk on fire")))],
    );
    assert_eq!(got.exit, Exit::Failed);
    assert!(got.err.starts_with("piikey-cli: ") && got.err.contains("disk on fire"));
}

#[test]
fn a_reply_that_is_not_what_the_operation_promises_is_exit_three() {
    let got = ran(&["status"], b"", vec![Ok(json!({"surprise": true}))]);
    assert_eq!(got.exit, Exit::Failed);
    assert!(got.err.contains("unexpected reply"), "{}", got.err);
}

#[test]
fn stdin_that_is_not_utf8_is_refused_before_anything_is_sent() {
    let got = ran(
        &["anonymize"],
        &[0xff, 0xfe, b'a'],
        vec![Ok(json!({"texts": [""]}))],
    );
    assert_eq!(got.exit, Exit::Failed);
    assert!(got.asked.is_empty());
    assert!(got.err.contains("UTF-8"), "{}", got.err);
    assert_eq!(got.out, "");
}

#[test]
fn paths_are_made_absolute_before_they_are_sent() {
    let got = ran(
        &["anonymize", "--out", "out", "in.txt", r"C:\abs\b.txt"],
        b"",
        vec![Ok(json!({"written": [], "failed": []}))],
    );
    match &got.asked[..] {
        [Request::AnonymizeFiles { paths, out }] => {
            assert!(out.is_absolute(), "{out:?}");
            assert_eq!(paths.len(), 2);
            assert!(paths.iter().all(|p| p.is_absolute()), "{paths:?}");
            assert!(paths[0].ends_with("in.txt"));
            assert_eq!(paths[1], PathBuf::from(r"C:\abs\b.txt"));
        }
        _ => panic!("not one anonymize_files"),
    }
    let got = ran(
        &["vault", "export", "--out", "v.csv"],
        b"",
        vec![Ok(json!({"records": 0, "path": "v.csv"}))],
    );
    match &got.asked[..] {
        [Request::VaultExport { path, .. }] => assert!(path.is_absolute()),
        _ => panic!("not one vault_export"),
    }
    let got = ran(
        &["inventory", "list", "--under", "sub"],
        b"",
        vec![Ok(json!({"entries": [], "total": 0}))],
    );
    match &got.asked[..] {
        [
            Request::InventoryList {
                under: Some(under), ..
            },
        ] => assert!(under.is_absolute()),
        _ => panic!("not one inventory_list"),
    }
    // Nothing to make absolute: no path, no change.
    let got = ran(
        &["subject", "--value", "a@b.nl"],
        b"",
        vec![Ok(json!({"matches": []}))],
    );
    assert!(matches!(&got.asked[..], [Request::SubjectSearch { paths, .. }] if paths.is_empty()));
}

#[test]
fn a_subject_search_shows_the_values_it_was_given() {
    let got = ran(
        &["subject", "--value", "Jan Jansen", r"C:\x"],
        b"",
        vec![Ok(
            json!({"matches": [{"path": r"C:\x\a.txt", "values": [0], "count": 2}]}),
        )],
    );
    assert_eq!(got.exit, Exit::Ok);
    assert!(got.out.contains("Jan Jansen"), "{}", got.out);
}

#[test]
fn a_pipe_is_named_by_its_whole_path_or_its_name() {
    assert_eq!(pipe_name("test"), r"\\.\pipe\test");
    assert_eq!(pipe_name(r"\\.\pipe\test"), r"\\.\pipe\test");
    assert_eq!(pipe_name(r"\\.\PIPE\Test"), r"\\.\PIPE\Test");
    assert_eq!(pipe_name("é"), "\\\\.\\pipe\\é");
}

#[test]
fn only_what_finds_personal_data_is_told_about_the_model() {
    assert!(detects(&Request::ScanText { texts: vec![] }));
    assert!(detects(&Request::InventoryRescan));
    assert!(!detects(&Request::Deanonymize {
        texts: vec![],
        tolerant: false
    }));
    assert!(!detects(&Request::Kinds));
}

/// The commands the README shows are the ones `--help` shows: a command line that is in one and
/// not the other is a documentation bug.
#[test]
fn the_readme_documents_the_usage_text() {
    let readme = include_str!("../../README.md");
    let block = readme
        .split("## Command line")
        .nth(1)
        .and_then(|rest| rest.split("```").nth(1))
        .unwrap_or_default();
    let lines: Vec<&str> = block
        .lines()
        .filter(|line| line.starts_with("piikey-cli ") || line.starts_with("global:"))
        .collect();
    assert!(lines.len() >= 10, "no command lines in the README: {block}");
    for line in lines {
        assert!(
            USAGE.lines().any(|usage| usage.trim_start() == line),
            "the README documents `{line}`, which --help does not say"
        );
    }
}

#[test]
fn a_reader_that_left_is_no_failure_and_the_gate_still_counts() {
    let quiet = ran_into(&["scan"], b"x", vec![Ok(one_email())], &mut Gone);
    assert_eq!(quiet.exit, Exit::Ok);
    assert_eq!(quiet.err, "");
    let gated = ran_into(
        &["scan", "--fail-on", "email"],
        b"x",
        vec![Ok(one_email())],
        &mut Gone,
    );
    assert_eq!(gated.exit, Exit::Found);
    assert_eq!(gated.err, "");
    // The same for JSON, and for text that goes out as it is.
    let json = ran_into(&["--json", "kinds"], b"", vec![Ok(json!([]))], &mut Gone);
    assert_eq!(json.exit, Exit::Ok);
    let text = ran_into(
        &["anonymize"],
        b"x",
        vec![Ok(json!({"texts": ["y"]}))],
        &mut Gone,
    );
    assert_eq!(text.exit, Exit::Ok);
}

#[test]
fn any_other_write_error_is_exit_three() {
    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let got = ran_into(&["scan"], b"x", vec![Ok(one_email())], &mut Full);
    assert_eq!(got.exit, Exit::Failed);
    assert!(got.err.contains("disk full"), "{}", got.err);
}

fn added_account() -> Value {
    json!({
        "id": "3f9c2a7d41b8e605",
        "provider": "box",
        "label": "Team",
        "sign_in": {"mode": "box_delegated", "client_id": "c"},
        "path": r"\\Box\Team",
        "connected": false,
    })
}

const ADD_BOX: [&str; 10] = [
    "account",
    "add",
    "box",
    "--label",
    "Team",
    "--mode",
    "box_delegated",
    "--client-id",
    "c",
    "--client-secret-stdin",
];

#[test]
fn the_client_secret_is_the_first_line_of_stdin_and_goes_only_into_the_request() {
    let got = ran(
        &ADD_BOX,
        b"  s3cret value \r\nsecond line",
        vec![Ok(added_account())],
    );
    assert_eq!(got.exit, Exit::Ok);
    assert_eq!(
        got.asked,
        [Request::AccountAdd {
            provider: piikey::sources::Provider::Box,
            label: "Team".to_owned(),
            sign_in: SignIn::BoxDelegated {
                client_id: "c".to_owned()
            },
            client_secret: Some("s3cret value".to_owned()),
        }]
    );
    assert!(!got.out.contains("s3cret") && !got.err.contains("s3cret"));
    assert!(
        got.out
            .contains("not connected yet: piikey-cli account connect 3f9c2a7d41b8e605 signs in"),
        "{}",
        got.out
    );
    // A secret with no line break after it is read to the end of stdin.
    let bare = ran(&ADD_BOX, b"abc", vec![Ok(added_account())]);
    assert!(matches!(
        bare.asked.as_slice(),
        [Request::AccountAdd { client_secret: Some(secret), .. }] if secret == "abc"
    ));
}

#[test]
fn a_client_secret_that_is_not_there_stops_the_command_before_it_asks() {
    for stdin in [&b""[..], b"\n", b"   \r\nsecret", &[0xff, 0xfe, b'\n']] {
        let got = ran(&ADD_BOX, stdin, vec![]);
        assert_eq!(got.exit, Exit::Failed, "{stdin:?}");
        assert!(got.asked.is_empty(), "{stdin:?}");
        assert!(got.err.contains("client secret"), "{}", got.err);
    }
    let long = vec![b'x'; 5000];
    let got = ran(&ADD_BOX, &long, vec![]);
    assert_eq!(got.exit, Exit::Failed);
    assert!(got.err.contains("too long"), "{}", got.err);
}

#[test]
fn the_files_of_an_account_are_made_absolute_but_a_path_of_an_account_is_left_alone()
-> io::Result<()> {
    let mut add = Request::AccountAdd {
        provider: piikey::sources::Provider::GoogleDrive,
        label: "Workspace".to_owned(),
        sign_in: SignIn::GoogleServiceAccount {
            key_file: PathBuf::from("key.json"),
            users: vec!["a@acme.nl".to_owned()],
        },
        client_secret: None,
    };
    make_absolute(&mut add)?;
    let Request::AccountAdd {
        sign_in: SignIn::GoogleServiceAccount { key_file, .. },
        ..
    } = &add
    else {
        return Err(io::Error::other("the request changed its kind"));
    };
    assert!(key_file.is_absolute(), "{key_file:?}");
    assert!(key_file.ends_with("key.json"));

    let mut certificate = Request::AccountAdd {
        provider: piikey::sources::Provider::Microsoft365,
        label: "App".to_owned(),
        sign_in: SignIn::MicrosoftApp {
            tenant: "t".to_owned(),
            client_id: "c".to_owned(),
            credential: Credential::Certificate {
                key_file: PathBuf::from("k.pem"),
                cert_file: PathBuf::from("c.pem"),
            },
        },
        client_secret: None,
    };
    make_absolute(&mut certificate)?;
    let Request::AccountAdd {
        sign_in:
            SignIn::MicrosoftApp {
                credential:
                    Credential::Certificate {
                        key_file,
                        cert_file,
                    },
                ..
            },
        ..
    } = &certificate
    else {
        return Err(io::Error::other("the request changed its kind"));
    };
    assert!(key_file.is_absolute() && cert_file.is_absolute());

    // `\\Dropbox\Work\Docs` is not a folder of this PC: it is the same however it is written.
    let virtual_path = PathBuf::from(r"\\Dropbox\Work\Docs");
    let mut browse = Request::AccountBrowse {
        id: "ab".to_owned(),
        under: Some(virtual_path.clone()),
    };
    make_absolute(&mut browse)?;
    assert_eq!(
        browse,
        Request::AccountBrowse {
            id: "ab".to_owned(),
            under: Some(virtual_path)
        }
    );
    Ok(())
}

#[test]
fn the_help_lists_the_account_commands() {
    for line in [
        "piikey-cli account list | connect ID | remove ID --yes | browse ID [--under PATH]",
        "piikey-cli account add PROVIDER --label NAME",
    ] {
        assert!(
            USAGE
                .lines()
                .any(|usage| usage.trim_start().starts_with(line)),
            "{line}"
        );
    }
}
