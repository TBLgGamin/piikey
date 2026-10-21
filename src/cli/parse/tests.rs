use std::collections::BTreeSet;

use super::*;

fn try_parse(list: &[&str]) -> Result<Cli, ParseError> {
    parse(list.iter().map(OsString::from))
}

fn parsed(list: &[&str]) -> Cli {
    match try_parse(list) {
        Ok(cli) => cli,
        Err(error) => panic!("{list:?} was rejected: {error:?}"),
    }
}

fn rejected(list: &[&str]) -> ParseError {
    match try_parse(list) {
        Ok(cli) => panic!("{list:?} was accepted as {:?}", cli.command),
        Err(error) => error,
    }
}

fn usage_error(list: &[&str]) -> bool {
    matches!(rejected(list), ParseError::Usage(_))
}

fn invalid_value(list: &[&str]) -> bool {
    matches!(rejected(list), ParseError::Invalid(_))
}

/// The one request the command line builds.
fn request(list: &[&str]) -> Request {
    match parsed(list).command {
        Command::Call(Call {
            input: Input::Request(request),
            ..
        }) => request,
        other => panic!("{list:?} is not one request: {other:?}"),
    }
}

fn json(request: &Request) -> String {
    serde_json::to_string(request).unwrap_or_default()
}

fn same(actual: &Request, expected: &Request) {
    assert!(
        actual == expected,
        "got      {}\nexpected {}",
        json(actual),
        json(expected)
    );
}

fn paths(list: &[&str]) -> Vec<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn patch(list: &[&str]) -> SettingsPatch {
    let mut line = vec!["settings", "set"];
    line.extend_from_slice(list);
    match request(&line) {
        Request::SettingsSet { settings } => settings,
        other => panic!("not settings_set: {}", json(&other)),
    }
}

fn stdin_command(list: &[&str]) -> (Text, Option<FailOn>) {
    match parsed(list).command {
        Command::Call(Call {
            input: Input::Stdin(text),
            fail_on,
        }) => (text, fail_on),
        other => panic!("{list:?} does not read stdin: {other:?}"),
    }
}

#[test]
fn text_commands_without_paths_read_stdin() {
    assert_eq!(stdin_command(&["scan"]), (Text::Scan, None));
    assert_eq!(stdin_command(&["anonymize"]), (Text::Anonymize, None));
    assert_eq!(
        stdin_command(&["deanonymize"]),
        (Text::Deanonymize { tolerant: false }, None)
    );
    assert_eq!(
        stdin_command(&["deanonymize", "--tolerant"]),
        (Text::Deanonymize { tolerant: true }, None)
    );
}

#[test]
fn stdin_text_becomes_the_matching_request() {
    same(
        &Text::Scan.request("a".to_owned()),
        &Request::ScanText {
            texts: strings(&["a"]),
        },
    );
    same(
        &Text::Anonymize.request("a".to_owned()),
        &Request::Anonymize {
            texts: strings(&["a"]),
        },
    );
    same(
        &Text::Deanonymize { tolerant: true }.request("a".to_owned()),
        &Request::Deanonymize {
            texts: strings(&["a"]),
            tolerant: true,
        },
    );
}

#[test]
fn scan_of_paths_records_unless_told_not_to() {
    same(
        &request(&["scan", "a.txt", "dir"]),
        &Request::ScanFiles {
            paths: paths(&["a.txt", "dir"]),
            record: true,
        },
    );
    same(
        &request(&["scan", "--no-record", "a.txt"]),
        &Request::ScanFiles {
            paths: paths(&["a.txt"]),
            record: false,
        },
    );
}

#[test]
fn scan_takes_the_kinds_it_fails_on() {
    let (_, fail_on) = stdin_command(&["scan", "--fail-on", "email,iban"]);
    assert_eq!(
        fail_on,
        Some(FailOn::Kinds(vec![EntityKind::Email, EntityKind::Iban]))
    );
    let (_, fail_on) = stdin_command(&["scan", "--fail-on=any"]);
    assert_eq!(fail_on, Some(FailOn::Any));
    // Repeated, in any letter case, with spaces and a trailing comma.
    let (_, fail_on) = stdin_command(&["scan", "--fail-on", "Email, ", "--fail-on", "iban,email,"]);
    assert_eq!(
        fail_on,
        Some(FailOn::Kinds(vec![EntityKind::Email, EntityKind::Iban]))
    );
    // `any` swallows the kinds, whichever comes first.
    let (_, fail_on) = stdin_command(&["scan", "--fail-on", "email", "--fail-on", "any"]);
    assert_eq!(fail_on, Some(FailOn::Any));
    let (_, fail_on) = stdin_command(&["scan", "--fail-on", "any,email"]);
    assert_eq!(fail_on, Some(FailOn::Any));
    match parsed(&["scan", "--fail-on", "any", "a.txt"]).command {
        Command::Call(Call { fail_on, .. }) => assert_eq!(fail_on, Some(FailOn::Any)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn fail_on_matches_the_kind_names_the_api_reports() {
    assert!(FailOn::Any.matches("anything"));
    let some = FailOn::Kinds(vec![EntityKind::Email]);
    assert!(some.matches("email"));
    assert!(!some.matches("iban"));
}

#[test]
fn fail_on_needs_known_kinds() {
    assert!(invalid_value(&["scan", "--fail-on", "emial"]));
    assert!(invalid_value(&["scan", "--fail-on", ""]));
    assert!(invalid_value(&["scan", "--fail-on", ","]));
    assert!(usage_error(&["scan", "--fail-on"]));
    assert!(usage_error(&["anonymize", "--fail-on", "any"]));
}

#[test]
fn rewrite_commands_with_paths_need_out() {
    same(
        &request(&["anonymize", "--out", "o", "a.txt", "dir"]),
        &Request::AnonymizeFiles {
            paths: paths(&["a.txt", "dir"]),
            out: PathBuf::from("o"),
        },
    );
    same(
        &request(&["deanonymize", "a.txt", "--out=o"]),
        &Request::DeanonymizeFiles {
            paths: paths(&["a.txt"]),
            out: PathBuf::from("o"),
            tolerant: false,
        },
    );
    same(
        &request(&["deanonymize", "--tolerant", "--out", "o", "a.txt"]),
        &Request::DeanonymizeFiles {
            paths: paths(&["a.txt"]),
            out: PathBuf::from("o"),
            tolerant: true,
        },
    );
    assert!(invalid_value(&["anonymize", "a.txt"]));
    assert!(invalid_value(&["deanonymize", "a.txt"]));
    // `--out` is for files; stdin goes to stdout.
    assert!(invalid_value(&["anonymize", "--out", "o"]));
    // Only deanonymize restores, tolerantly or not.
    assert!(usage_error(&["anonymize", "--tolerant"]));
    assert!(usage_error(&[
        "anonymize",
        "--tolerant",
        "--out",
        "o",
        "a.txt"
    ]));
}

#[test]
fn subject_needs_values() {
    same(
        &request(&[
            "subject",
            "--value",
            "Jan Jansen",
            "--value=+31612345678",
            "dir",
        ]),
        &Request::SubjectSearch {
            values: strings(&["Jan Jansen", "+31612345678"]),
            paths: paths(&["dir"]),
        },
    );
    // No path: the inventory's folders, which the answering side picks.
    same(
        &request(&["subject", "--value", "a@b.nl"]),
        &Request::SubjectSearch {
            values: strings(&["a@b.nl"]),
            paths: Vec::new(),
        },
    );
    assert!(invalid_value(&["subject", "dir"]));
    assert!(usage_error(&["subject", "--value"]));
    assert!(usage_error(&["scan", "--value", "x"]));
}

#[test]
fn vault_commands() {
    same(
        &request(&["vault", "list"]),
        &Request::VaultList {
            query: None,
            kind: None,
            limit: None,
            offset: 0,
        },
    );
    same(
        &request(&[
            "vault", "list", "--query", "jan", "--kind", "email", "--limit", "5", "--offset", "10",
        ]),
        &Request::VaultList {
            query: Some("jan".to_owned()),
            kind: Some("email".to_owned()),
            limit: Some(5),
            offset: 10,
        },
    );
    same(
        &request(&["vault", "forget", "a@b.nl", "+31 6 1"]),
        &Request::VaultForget {
            values: strings(&["a@b.nl", "+31 6 1"]),
        },
    );
    same(
        &request(&["vault", "export", "--out", "v.csv", "--format", "csv"]),
        &Request::VaultExport {
            path: PathBuf::from("v.csv"),
            format: Format::Csv,
        },
    );
    same(
        &request(&["vault", "export", "--out", "v.json"]),
        &Request::VaultExport {
            path: PathBuf::from("v.json"),
            format: Format::Json,
        },
    );
    same(
        &request(&["vault", "wipe", "--yes"]),
        &Request::VaultWipe { confirm: true },
    );
}

#[test]
fn vault_commands_check_their_arguments() {
    assert!(invalid_value(&["vault", "forget"]));
    assert!(invalid_value(&["vault", "export"]));
    assert!(invalid_value(&[
        "vault", "export", "--out", "v", "--format", "xml"
    ]));
    assert!(invalid_value(&["vault", "wipe"]));
    assert!(invalid_value(&["vault", "list", "--limit", "many"]));
    assert!(invalid_value(&["vault", "list", "--offset", "-1"]));
    assert!(usage_error(&["vault"]));
    assert!(usage_error(&["vault", "burn"]));
    assert!(usage_error(&["vault", "list", "extra"]));
    assert!(usage_error(&["vault", "wipe", "--yes", "--out", "x"]));
    assert!(usage_error(&["vault", "forget", "--yes", "x"]));
}

#[test]
fn a_value_that_looks_like_an_option_follows_two_dashes() {
    same(
        &request(&["vault", "forget", "--", "-12"]),
        &Request::VaultForget {
            values: strings(&["-12"]),
        },
    );
    // A value of an option is taken as it comes.
    same(
        &request(&["vault", "list", "--query", "-x"]),
        &Request::VaultList {
            query: Some("-x".to_owned()),
            kind: None,
            limit: None,
            offset: 0,
        },
    );
}

#[test]
fn inventory_commands() {
    same(
        &request(&["inventory", "status"]),
        &Request::InventoryStatus,
    );
    same(
        &request(&["inventory", "list"]),
        &Request::InventoryList {
            under: None,
            limit: None,
            offset: 0,
        },
    );
    same(
        &request(&[
            "inventory",
            "list",
            "--under",
            "d",
            "--limit",
            "20",
            "--offset",
            "40",
        ]),
        &Request::InventoryList {
            under: Some(PathBuf::from("d")),
            limit: Some(20),
            offset: 40,
        },
    );
    same(
        &request(&["inventory", "tree", "--under", "d"]),
        &Request::InventoryTree {
            under: Some(PathBuf::from("d")),
        },
    );
    same(
        &request(&["inventory", "tree"]),
        &Request::InventoryTree { under: None },
    );
    same(
        &request(&["inventory", "rescan"]),
        &Request::InventoryRescan,
    );
    same(
        &request(&["inventory", "report", "--out", "r.csv", "--format", "csv"]),
        &Request::InventoryReport {
            path: PathBuf::from("r.csv"),
            format: Format::Csv,
        },
    );
    assert!(invalid_value(&["inventory", "report"]));
    assert!(usage_error(&["inventory"]));
    assert!(usage_error(&["inventory", "status", "--under", "d"]));
    assert!(usage_error(&["inventory", "tree", "--limit", "3"]));
}

#[test]
fn settings_get_and_set() {
    same(&request(&["settings", "get"]), &Request::SettingsGet);
    assert!(usage_error(&["settings"]));
    assert!(usage_error(&["settings", "reset"]));
    assert!(usage_error(&["settings", "get", "site=a.nl"]));
    assert!(usage_error(&[
        "settings",
        "set",
        "--out",
        "x",
        "inventory=true"
    ]));
    assert!(invalid_value(&["settings", "set"]));
}

#[test]
fn settings_set_reads_scalars() {
    let got = patch(&[
        "highlight=always",
        "explorer_menu=false",
        "inventory=TRUE",
        "http_api=true",
        "http_port=8080",
    ]);
    assert_eq!(
        got,
        SettingsPatch {
            highlight: Some(Highlight::Always),
            explorer_menu: Some(false),
            inventory: Some(true),
            http_api: Some(true),
            http_port: Some(8080),
            ..SettingsPatch::default()
        }
    );
    // What is not named stays as it is.
    assert_eq!(patch(&["inventory=false"]).http_port, None);
    // The last one wins.
    assert_eq!(patch(&["http_port=1", "http_port=2"]).http_port, Some(2));
}

#[test]
fn settings_set_collects_list_keys() {
    let got = patch(&[
        "site=chatgpt.com",
        "site=*.openai.com",
        "program=chrome.exe",
        "disabled_kind=email",
        "disabled_kind=iban",
        r"inventory_root=C:\Users\jan\Documents",
        r"inventory_exclude=C:\Users\jan\Documents\Private",
    ]);
    assert_eq!(
        got,
        SettingsPatch {
            sites: Some(strings(&["chatgpt.com", "*.openai.com"])),
            programs: Some(strings(&["chrome.exe"])),
            disabled_kinds: Some(strings(&["email", "iban"])),
            inventory_roots: Some(paths(&[r"C:\Users\jan\Documents"])),
            inventory_exclude: Some(paths(&[r"C:\Users\jan\Documents\Private"])),
            ..SettingsPatch::default()
        }
    );
}

#[test]
fn an_empty_list_value_empties_the_list() {
    assert_eq!(patch(&["disabled_kind="]).disabled_kinds, Some(Vec::new()));
    assert_eq!(patch(&["site="]).sites, Some(Vec::new()));
    // It only makes the list present: what else is given still goes in.
    assert_eq!(
        patch(&["site=", "site=a.nl"]).sites,
        Some(strings(&["a.nl"]))
    );
    // A list that is not mentioned is not touched.
    assert_eq!(patch(&["inventory=true"]).sites, None);
}

#[test]
fn settings_set_rejects_what_is_not_a_setting() {
    assert!(invalid_value(&["settings", "set", "highlight=loud"]));
    assert!(invalid_value(&["settings", "set", "inventory=maybe"]));
    assert!(invalid_value(&["settings", "set", "http_port=70000"]));
    assert!(invalid_value(&["settings", "set", "http_port=0"]));
    assert!(invalid_value(&["settings", "set", "http_port=x"]));
    assert!(invalid_value(&["settings", "set", "colour=red"]));
    assert!(invalid_value(&["settings", "set", "site"]));
    // Protection is switched with its own command.
    assert!(invalid_value(&["settings", "set", "enabled=true"]));
}

#[test]
fn settings_set_takes_every_key_of_the_settings_file_but_protection() {
    for key in piikey::policy::KEYS
        .into_iter()
        .filter(|key| *key != "enabled")
    {
        let value = match key {
            "highlight" => "off",
            "http_port" => "8080",
            "explorer_menu" | "inventory" | "http_api" => "true",
            // The list keys: an empty value empties the list.
            _ => "",
        };
        let line = format!("{key}={value}");
        assert!(
            try_parse(&["settings", "set", &line]).is_ok(),
            "settings set refuses {key}"
        );
    }
}

#[test]
fn small_commands() {
    same(&request(&["kinds"]), &Request::Kinds);
    same(&request(&["status"]), &Request::Status);
    same(&request(&["model", "status"]), &Request::ModelStatus);
    same(&request(&["model", "download"]), &Request::ModelDownload);
    same(&request(&["token"]), &Request::ApiToken { rotate: false });
    same(
        &request(&["token", "--rotate"]),
        &Request::ApiToken { rotate: true },
    );
    same(
        &request(&["protection", "on"]),
        &Request::Protection { on: true },
    );
    same(
        &request(&["protection", "off"]),
        &Request::Protection { on: false },
    );
    assert!(usage_error(&["protection"]));
    assert!(usage_error(&["protection", "maybe"]));
    assert!(usage_error(&["protection", "on", "off"]));
    assert!(usage_error(&["model"]));
    assert!(usage_error(&["model", "remove"]));
    assert!(usage_error(&["kinds", "email"]));
    assert!(usage_error(&["status", "--rotate"]));
    assert!(usage_error(&["token", "--yes"]));
}

#[test]
fn serve_takes_http_and_a_pipe() {
    assert_eq!(
        parsed(&["serve"]).command,
        Command::Serve(Serve {
            http: false,
            port: None,
            pipe: None
        })
    );
    assert_eq!(
        parsed(&["serve", "--http", "--port", "8080", "--pipe", r"\\.\pipe\x"]).command,
        Command::Serve(Serve {
            http: true,
            port: Some(8080),
            pipe: Some(r"\\.\pipe\x".to_owned())
        })
    );
    assert_eq!(
        parsed(&["serve", "--http"]).command,
        Command::Serve(Serve {
            http: true,
            port: None,
            pipe: None
        })
    );
    assert!(invalid_value(&["serve", "--port", "8080"]));
    assert!(invalid_value(&["serve", "--http", "--port", "0"]));
    assert!(invalid_value(&["serve", "--http", "--port", "99999"]));
    assert!(usage_error(&["serve", "a.txt"]));
    assert!(usage_error(&["serve", "--out", "o"]));
}

#[test]
fn global_options_go_anywhere() {
    let cli = parsed(&["--json", "status"]);
    assert!(cli.json && !cli.local && cli.vault.is_none());
    assert!(!cli.in_process());
    let cli = parsed(&["status", "--json"]);
    assert!(cli.json);
    let cli = parsed(&["scan", "a.txt", "--local", "--no-record"]);
    assert!(cli.local && cli.in_process());
    // A vault of its own means this process.
    let cli = parsed(&["--vault", "v.pkv", "anonymize"]);
    assert_eq!(cli.vault, Some(PathBuf::from("v.pkv")));
    assert!(!cli.local && cli.in_process());
    let cli = parsed(&["anonymize", "--vault=v"]);
    assert_eq!(cli.vault, Some(PathBuf::from("v")));
    // They fit every command.
    let cli = parsed(&["serve", "--vault", "v", "--json"]);
    assert!(cli.json && cli.in_process());
}

#[test]
fn help_and_version_win() {
    assert_eq!(parsed(&["--help"]).command, Command::Help);
    assert_eq!(parsed(&["-h"]).command, Command::Help);
    assert_eq!(parsed(&["anonymize", "-h"]).command, Command::Help);
    assert_eq!(parsed(&["--version"]).command, Command::Version);
    assert_eq!(parsed(&["-V"]).command, Command::Version);
    // It wins over what follows it, however wrong.
    assert_eq!(
        parsed(&["scan", "-V", "--fail-on", "x"]).command,
        Command::Version
    );
    assert_eq!(
        parsed(&["frobnicate", "--help", "--bogus"]).command,
        Command::Help
    );
}

#[test]
fn bad_command_lines_are_usage_errors() {
    assert!(usage_error(&[]));
    assert!(usage_error(&["--json"]));
    assert!(usage_error(&["frobnicate"]));
    assert!(usage_error(&["scan", "--bogus"]));
    assert!(usage_error(&["scan", "-x"]));
    assert!(usage_error(&["--vault"]));
    assert!(usage_error(&["status", "--json=yes"]));
}

#[test]
fn an_empty_path_is_a_mistake() {
    assert!(invalid_value(&["scan", ""]));
    assert!(invalid_value(&["anonymize", "--out", "", "a.txt"]));
    assert!(invalid_value(&["--vault", "", "status"]));
    assert!(invalid_value(&["inventory", "list", "--under", ""]));
}

#[test]
fn every_operation_but_the_explorer_one_has_a_command() {
    let lines: [&[&str]; 25] = [
        &["scan"],
        &["anonymize"],
        &["deanonymize"],
        &["scan", "a"],
        &["anonymize", "--out", "o", "a"],
        &["deanonymize", "--out", "o", "a"],
        &["subject", "--value", "v"],
        &["vault", "list"],
        &["vault", "forget", "v"],
        &["vault", "export", "--out", "f"],
        &["vault", "wipe", "--yes"],
        &["inventory", "status"],
        &["inventory", "list"],
        &["inventory", "tree"],
        &["inventory", "rescan"],
        &["inventory", "report", "--out", "f"],
        &["settings", "get"],
        &["settings", "set", "inventory=true"],
        &["kinds"],
        &["model", "status"],
        &["model", "download"],
        &["token"],
        &["status"],
        &["protection", "on"],
        &["serve"],
    ];
    let mut ops = BTreeSet::new();
    for line in lines {
        match parsed(line).command {
            Command::Call(Call {
                input: Input::Request(request),
                ..
            }) => {
                ops.insert(request.op());
            }
            Command::Call(Call {
                input: Input::Stdin(text),
                ..
            }) => {
                ops.insert(text.request(String::new()).op());
            }
            _ => {}
        }
    }
    for op in Request::OPS {
        // Only the Explorer menu scans a path for the app to show.
        if op != "explorer_scan" {
            assert!(ops.contains(op), "{op} has no command");
        }
    }
    assert_eq!(ops.len(), Request::OPS.len() - 1);
}
