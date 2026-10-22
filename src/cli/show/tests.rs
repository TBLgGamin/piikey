use serde_json::json;

use super::*;

fn shown(view: &View, value: &Value) -> (String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    if let Err(fail) = print(view, value, &mut out, &mut err) {
        panic!("printing failed: {fail:?}");
    }
    (
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

fn out_of(view: &View, value: &Value) -> String {
    shown(view, value).0
}

fn cells(row: &[&str]) -> Vec<String> {
    row.iter().map(|cell| (*cell).to_owned()).collect()
}

/// A file of a scan or of the inventory, as the API writes it.
fn file(path: &str, status: &str, counts: Value) -> Value {
    let mut file = json!({"path": path, "size": 0, "modified": 0, "scanned": 0, "status": status});
    file["counts"] = counts;
    file
}

/// A file that could not be read, with the message the scan ran into.
fn failed_file(path: &str, error: &str) -> Value {
    let mut failed = file(path, "failed", json!({}));
    failed["error"] = json!(error);
    failed
}

#[test]
fn a_table_pads_its_columns_but_not_the_last() {
    let mut out = Vec::new();
    let rows = [
        cells(&["12", "email: 12", "a.txt"]),
        cells(&["3", "iban: 3", r"C:\long\b.txt"]),
    ];
    assert!(table(&mut out, &["HITS", "FOUND", "FILE"], &[0], &rows).is_ok());
    assert_eq!(
        String::from_utf8_lossy(&out),
        "HITS  FOUND      FILE\n  12  email: 12  a.txt\n   3  iban: 3    C:\\long\\b.txt\n"
    );
}

#[test]
fn a_wide_cell_widens_its_column_and_counts_characters() {
    let mut out = Vec::new();
    let rows = [cells(&["é", "x"]), cells(&["abcd", "y"])];
    assert!(table(&mut out, &["A", "B"], &[], &rows).is_ok());
    assert_eq!(String::from_utf8_lossy(&out), "A     B\né     x\nabcd  y\n");
}

#[test]
fn counts_keep_their_order_and_skip_zeros() {
    let counts = [
        (EntityKind::Iban, 3),
        (EntityKind::Phone, 3),
        (EntityKind::Email, 1),
        (EntityKind::Secret, 0),
    ];
    assert_eq!(super::counts(&counts), "iban: 3, phone: 3, email: 1");
    assert_eq!(super::counts(&[]), "");
}

#[test]
fn control_characters_are_written_out() {
    assert_eq!(one_line("a\nb\r\tc\u{7}d"), "a\\nb\\r\\tc\\u{7}d");
    assert_eq!(one_line("Jürgen Ä"), "Jürgen Ä");
}

#[test]
fn plurals() {
    assert_eq!(plural(0, "file"), "0 files");
    assert_eq!(plural(1, "file"), "1 file");
    assert_eq!(plural(2, "file"), "2 files");
}

#[test]
fn every_request_has_a_view() {
    assert_eq!(View::of(&Request::Status), View::Status);
    assert_eq!(View::of(&Request::Anonymize { texts: vec![] }), View::Text);
    assert_eq!(
        View::of(&Request::Deanonymize {
            texts: vec![],
            tolerant: true
        }),
        View::Text
    );
    assert_eq!(View::of(&Request::ScanText { texts: vec![] }), View::Spans);
    assert_eq!(
        View::of(&Request::SubjectSearch {
            values: vec!["a".to_owned()],
            paths: vec![]
        }),
        View::Subject(vec!["a".to_owned()])
    );
    assert_eq!(
        View::of(&Request::VaultList {
            query: None,
            kind: None,
            limit: None,
            offset: 7
        }),
        View::Records { offset: 7 }
    );
    assert_eq!(
        View::of(&Request::Protection { on: true }),
        View::Protection
    );
    assert_eq!(
        View::of(&Request::VaultWipe { confirm: true }),
        View::Forgotten
    );
    // The ones for which a view is chosen are all the operations: `of` is a match without a
    // catch-all, so a new operation does not compile until it has one.
    for op in Request::OPS {
        assert!(!op.is_empty());
    }
}

#[test]
fn stdin_text_is_written_as_it_is() {
    let value = json!({"texts": ["a\r\nb  "]});
    assert_eq!(out_of(&View::Text, &value), "a\r\nb  ");
    // One text in, one text out: anything else is not a reply to this request.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert!(print(&View::Text, &json!({"texts": []}), &mut out, &mut err).is_err());
    assert!(
        print(
            &View::Text,
            &json!({"texts": ["a", "b"]}),
            &mut out,
            &mut err
        )
        .is_err()
    );
    assert!(out.is_empty());
}

#[test]
fn a_reply_of_the_wrong_shape_is_an_error() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = print(&View::Files, &json!({"nope": 1}), &mut out, &mut err);
    assert!(matches!(result, Err(Fail::Api(e)) if e.code() == "internal"));
}

#[test]
fn spans_are_listed_with_where_they_are() {
    let value = json!({"results": [[
        {"start": 5, "end": 23, "kind": "email", "value": "jan.jansen@acme.nl"},
        {"start": 30, "end": 36, "kind": "iban", "value": "NL91\nABNA"}
    ]]});
    assert_eq!(
        out_of(&View::Spans, &value),
        "KIND   BYTES  VALUE\n\
         email  5-23   jan.jansen@acme.nl\n\
         iban   30-36  NL91\\nABNA\n\
         2 values found\n"
    );
    assert_eq!(
        out_of(&View::Spans, &json!({"results": [[]]})),
        "no personal data found\n"
    );
}

#[test]
fn scanned_files_are_listed_when_they_hold_something() {
    let value = json!({"hits": 5, "files": [
        file(r"C:\x\a.txt", "ok", json!({"iban": 1, "phone": 1})),
        file(r"C:\x\b.bin", "unsupported", json!({})),
        failed_file(r"C:\x\c.docx", "bad zip"),
        file(r"C:\x\d.txt", "ok", json!({})),
        file(r"C:\x\e.txt", "ok", json!({"email": 3})),
        file(r"C:\x\f.iso", "too_large", json!({}))
    ]});
    let (out, err) = shown(&View::Files, &value);
    assert_eq!(
        out,
        "HITS  FOUND              FILE\n\
         \x20  3  email: 3           C:\\x\\e.txt\n\
         \x20  2  iban: 1, phone: 1  C:\\x\\a.txt\n\
         6 files scanned, 2 with personal data, 5 values found, \
         2 not read (unsupported format or too big), 1 failed\n"
    );
    assert_eq!(err, "piikey-cli: C:\\x\\c.docx: bad zip\n");
}

#[test]
fn scanned_files_without_findings_say_so() {
    let value = json!({"hits": 0, "files": [file("a.txt", "ok", json!({}))]});
    assert_eq!(
        shown(&View::Files, &value),
        (
            "1 file scanned, no personal data found\n".to_owned(),
            String::new()
        )
    );
}

#[test]
fn written_files_are_listed_and_the_failed_ones_go_to_stderr() {
    let value = json!({
        "written": [{"input": "a.txt", "output": "o\\a.txt"}],
        "failed": [{"input": "b.docx", "error": "not a document"}]
    });
    let (out, err) = shown(&View::Written, &value);
    assert_eq!(out, "a.txt -> o\\a.txt\n1 file written, 1 failed\n");
    assert_eq!(err, "piikey-cli: b.docx: not a document\n");
    let clean = json!({"written": [], "failed": []});
    assert_eq!(out_of(&View::Written, &clean), "0 files written\n");
}

#[test]
fn a_subject_search_names_the_values_it_found() {
    let values = vec!["Jan Jansen".to_owned(), "+31612345678".to_owned()];
    let value = json!({"matches": [
        {"path": r"C:\x\a.txt", "values": [0, 1], "count": 12},
        {"path": r"C:\x\b.txt", "values": [1], "count": 2}
    ]});
    assert_eq!(
        out_of(&View::Subject(values.clone()), &value),
        "COUNT  VALUES                    FILE\n\
         \x20  12  Jan Jansen, +31612345678  C:\\x\\a.txt\n\
         \x20   2  +31612345678              C:\\x\\b.txt\n\
         2 files mention them\n"
    );
    assert_eq!(
        out_of(&View::Subject(values), &json!({"matches": []})),
        "no file mentions these values\n"
    );
}

#[test]
fn vault_records_say_how_to_page() {
    let record = |kind: &str, original: &str, proxy: &str| json!({"kind": kind, "original": original, "proxy": proxy});
    let page = json!({"total": 5, "records": [
        record("email", "jan@acme.nl", "kim@example.org"),
        record("iban", "NL91ABNA0417164300", "NL02ABNA0123456789"),
    ]});
    assert_eq!(
        out_of(&View::Records { offset: 0 }, &page),
        "KIND   VALUE               STAND-IN\n\
         email  jan@acme.nl         kim@example.org\n\
         iban   NL91ABNA0417164300  NL02ABNA0123456789\n\
         records 1-2 of 5; the next ones follow with --offset 2\n"
    );
    assert!(
        out_of(&View::Records { offset: 2 }, &page)
            .ends_with("records 3-4 of 5; the next ones follow with --offset 4\n")
    );
    assert!(out_of(&View::Records { offset: 3 }, &page).ends_with("records 4-5 of 5\n"));
    let all = json!({"total": 1, "records": [record("email", "a@b.nl", "c@d.nl")]});
    assert!(out_of(&View::Records { offset: 0 }, &all).ends_with("1 record\n"));
    // One that is alone says so in the singular, and a count of many in the plural.
    let two = json!({"total": 2, "records": [record("email", "a@b.nl", "c@d.nl"), record("email", "e@f.nl", "g@h.nl")]});
    assert!(out_of(&View::Records { offset: 0 }, &two).ends_with("2 records\n"));
    assert_eq!(
        out_of(
            &View::Records { offset: 0 },
            &json!({"total": 0, "records": []})
        ),
        "no records\n"
    );
}

#[test]
fn forgetting_and_exporting_report_counts() {
    assert_eq!(
        out_of(&View::Forgotten, &json!({"forgotten": 1})),
        "forgot 1 record\n"
    );
    assert_eq!(
        out_of(&View::Forgotten, &json!({"forgotten": 7})),
        "forgot 7 records\n"
    );
    assert_eq!(
        out_of(&View::Forgotten, &json!({"forgotten": 0})),
        "no records removed\n"
    );
    assert_eq!(
        out_of(&View::Exported, &json!({"records": 2, "path": r"C:\v.csv"})),
        "wrote 2 records to C:\\v.csv\n"
    );
    assert_eq!(
        out_of(&View::Report, &json!({"rows": 1, "path": r"C:\r.csv"})),
        "wrote 1 row to C:\\r.csv\n"
    );
}

#[test]
fn the_inventory_status_is_a_list_of_facts() {
    let value = json!({
        "roots": [r"C:\Docs", r"C:\Desk"], "files": 120,
        "files_with_pii": 4, "hits": 17, "scanning": {"done": 10, "total": 50}
    });
    assert_eq!(
        out_of(&View::InventoryStatus, &value),
        "folders             C:\\Docs, C:\\Desk\n\
         files               120\n\
         with personal data  4\n\
         values found        17\n\
         scan                running, 10 of 50 files\n"
    );
    let idle = json!({
        "roots": [], "files": 0, "files_with_pii": 0, "hits": 0, "scanning": null
    });
    let text = out_of(&View::InventoryStatus, &idle);
    assert!(text.contains("folders             none\n"), "{text}");
    assert!(
        text.ends_with("scan                not running\n"),
        "{text}"
    );
    // A reply of a version that still had the switch is read all the same.
    let old = json!({
        "enabled": true, "roots": [], "files": 0, "files_with_pii": 0, "hits": 0, "scanning": null
    });
    assert!(out_of(&View::InventoryStatus, &old).starts_with("folders"));
}

#[test]
fn inventory_entries_and_nodes_are_tables() {
    let entries = json!({"total": 2, "entries": [
        file(r"C:\x\a.txt", "ok", json!({"email": 3})),
        file(r"C:\x\b.txt", "ok", json!({"iban": 1, "phone": 1}))
    ]});
    assert_eq!(
        out_of(&View::Entries { offset: 0 }, &entries),
        "HITS  FOUND              FILE\n\
         \x20  3  email: 3           C:\\x\\a.txt\n\
         \x20  2  iban: 1, phone: 1  C:\\x\\b.txt\n\
         2 files\n"
    );
    assert_eq!(
        out_of(
            &View::Entries { offset: 0 },
            &json!({"total": 0, "entries": []})
        ),
        "no files with personal data in the inventory\n"
    );
    let nodes = json!({"nodes": [
        {"path": r"C:\", "name": "C:", "is_dir": true, "hits": 32, "files": 5, "counts": {"email": 30, "iban": 2}},
        {"path": r"C:\Docs\a.txt", "name": "a.txt", "is_dir": false, "hits": 2, "files": 1, "counts": {"iban": 2}},
        {"path": r"\\nas\share\", "name": r"\\nas\share", "is_dir": true, "hits": 1, "files": 1, "counts": {"phone": 1}}
    ]});
    assert_eq!(
        out_of(&View::Nodes, &nodes),
        "HITS  FILES  FOUND               PATH\n\
         \x20 32      5  email: 30, iban: 2  C:\\\n\
         \x20  2      1  iban: 2             C:\\Docs\\a.txt\n\
         \x20  1      1  phone: 1            \\\\nas\\share\\\n"
    );
    assert_eq!(
        out_of(&View::Nodes, &json!({"nodes": []})),
        "nothing with personal data here\n"
    );
}

#[test]
fn settings_are_shown_as_the_keys_that_set_them() {
    let value = json!({
        "enabled": true, "highlight": "hotkey", "explorer_menu": true, "background": false,
        "watch": true, "http_api": false, "http_port": 7980, "sites": ["chatgpt.com", "claude.ai"],
        "programs": ["chrome.exe"], "disabled_kinds": ["email"],
        "inventory_roots": [r"C:\Docs"], "watch_folders": [r"C:\Inbox"]
    });
    assert_eq!(
        out_of(&View::Settings, &value),
        "highlight=hotkey\n\
         explorer_menu=true\n\
         background=false\n\
         watch=true\n\
         http_api=false\n\
         http_port=7980\n\
         site=chatgpt.com\n\
         site=claude.ai\n\
         program=chrome.exe\n\
         disabled_kind=email\n\
         inventory_root=C:\\Docs\n\
         watch_folder=C:\\Inbox\n"
    );
}

#[test]
fn kinds_are_a_table() {
    let value = json!([
        {"kind": "email", "label": "Email", "group": "Contact", "enabled": true},
        {"kind": "person", "label": "Person", "group": "People", "enabled": false}
    ]);
    assert_eq!(
        out_of(&View::Kinds, &value),
        "KIND    LABEL   GROUP    ON\n\
         email   Email   Contact  yes\n\
         person  Person  People   no\n"
    );
}

#[test]
fn the_model_and_the_status() {
    let missing = json!({"state": "missing", "device": null, "dir": r"C:\m"});
    assert_eq!(
        out_of(&View::Model, &missing),
        "model   not downloaded (piikey-cli model download)\nfolder  C:\\m\n"
    );
    let ready = json!({"state": "ready", "device": "hybrid", "dir": r"C:\m"});
    assert!(out_of(&View::Model, &ready).starts_with("model   ready (hybrid)\n"));
    let failed = json!({"state": "failed", "device": null, "error": "no DirectML", "dir": r"C:\m"});
    assert!(out_of(&View::Model, &failed).starts_with("model   failed: no DirectML\n"));
    // The app says so while it is downloading the model itself.
    let downloading = json!({
        "state": "missing", "device": null, "dir": r"C:\m",
        "downloading": {"done": 52_428_800, "total": 359_000_000}
    });
    assert!(out_of(&View::Model, &downloading).starts_with("model   downloading, 50 of 342 MB\n"));

    let status = json!({
        "app": false, "protection": null, "version": "0.1.0", "vault_records": 1,
        "model": ready, "highlight": "always", "explorer_menu": true, "watch": false,
        "http_api": true
    });
    assert_eq!(
        out_of(&View::Status, &status),
        "version        0.1.0\n\
         app            not running\n\
         protection     unknown (it is the app's)\n\
         vault          1 record\n\
         model          ready (hybrid)\n\
         highlight      always\n\
         explorer menu  on\n\
         watch          off\n\
         HTTP API       on\n"
    );
    let running = json!({
        "app": true, "protection": true, "version": "0.1.0", "vault_records": 0,
        "model": missing, "highlight": "off", "explorer_menu": false, "watch": true,
        "http_api": false
    });
    let text = out_of(&View::Status, &running);
    assert!(
        text.contains("app            running\nprotection     on\nvault          0 records\n"),
        "{text}"
    );
}

#[test]
fn the_token_is_alone_on_its_line() {
    assert_eq!(
        out_of(&View::Token, &json!({"token": "abc123"})),
        "abc123\n"
    );
}

#[test]
fn small_results() {
    assert_eq!(
        out_of(&View::Downloaded, &json!({})),
        "the detection model is downloaded\n"
    );
    assert_eq!(
        out_of(&View::Protection, &json!({"protection": true})),
        "protection is on\n"
    );
    assert_eq!(
        out_of(&View::Protection, &json!({"protection": false})),
        "protection is off\n"
    );
    assert_eq!(
        out_of(
            &View::Rescanned,
            &json!({"files": 10, "files_with_pii": 2, "hits": 5})
        ),
        "scanned: the inventory holds 10 files, 2 with personal data, 5 values found\n"
    );
    assert_eq!(out_of(&View::Json, &json!({"a": 1})), "{\n  \"a\": 1\n}\n");
}

#[test]
fn the_gate_looks_at_the_kinds_of_what_was_found() {
    let spans = json!({"results": [[{"start": 0, "end": 1, "kind": "iban", "value": "x"}]]});
    let email = FailOn::Kinds(vec![EntityKind::Email]);
    let iban = FailOn::Kinds(vec![EntityKind::Iban]);
    let found = |fail_on: Option<&FailOn>, view: &View, value: &Value| {
        verdict(view, value, fail_on).map(|verdict| verdict.found)
    };
    assert!(matches!(
        found(Some(&email), &View::Spans, &spans),
        Ok(false)
    ));
    assert!(matches!(found(Some(&iban), &View::Spans, &spans), Ok(true)));
    assert!(matches!(
        found(Some(&FailOn::Any), &View::Spans, &spans),
        Ok(true)
    ));
    // Without `--fail-on` nothing is held against what was found.
    assert!(matches!(found(None, &View::Spans, &spans), Ok(false)));
    let nothing = json!({"results": [[]]});
    assert!(matches!(
        found(Some(&FailOn::Any), &View::Spans, &nothing),
        Ok(false)
    ));

    let files = json!({"hits": 1, "files": [
        file("a", "ok", json!({"iban": 1})),
        file("b", "ok", json!({"email": 0}))
    ]});
    assert!(matches!(found(Some(&iban), &View::Files, &files), Ok(true)));
    assert!(matches!(
        found(Some(&email), &View::Files, &files),
        Ok(false)
    ));
    assert!(matches!(
        found(Some(&FailOn::Any), &View::Files, &files),
        Ok(true)
    ));
    // Only scans are gated, and any other reply is not even read.
    assert!(matches!(
        verdict(&View::Status, &json!("not a status"), Some(&FailOn::Any)),
        Ok(v) if v == Verdict::default()
    ));
}

#[test]
fn failures_are_the_files_that_could_not_be_done() {
    let files = json!({"hits": 0, "files": [
        failed_file("a", "x"),
        file("b", "unsupported", json!({})),
        file("c", "ok", json!({}))
    ]});
    assert!(matches!(verdict(&View::Files, &files, None), Ok(v) if v.failed == 1));
    let written = json!({"written": [], "failed": [{"input": "a", "error": "x"}]});
    assert!(matches!(verdict(&View::Written, &written, None), Ok(v) if v.failed == 1));
    assert!(verdict(&View::Files, &json!({"nope": 1}), None).is_err());
}

#[test]
fn a_failure_without_a_message_is_still_reported_and_a_skipped_file_is_no_failure() {
    let value = json!({"hits": 0, "files": [
        failed_file(r"C:\x\a.docx", ""),
        file(r"C:\x\b.iso", "too_large", json!({}))
    ]});
    let (out, err) = shown(&View::Files, &value);
    assert_eq!(
        out,
        "2 files scanned, no personal data found, \
         1 not read (unsupported format or too big), 1 failed\n"
    );
    assert_eq!(err, "piikey-cli: C:\\x\\a.docx: could not be read\n");
    assert!(matches!(verdict(&View::Files, &value, None), Ok(v) if v.failed == 1));
}

#[test]
fn one_file_that_holds_the_values_is_named_in_the_singular() {
    let values = vec!["a@b.nl".to_owned()];
    let value = json!({"matches": [{"path": "a.txt", "values": [0], "count": 1}]});
    assert!(out_of(&View::Subject(values), &value).ends_with("1 file mentions them\n"));
}
