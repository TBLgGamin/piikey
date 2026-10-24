use std::{collections::BTreeSet, error::Error as StdError, path::PathBuf};

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::*;
use crate::{
    api::Code,
    detect::EntityKind,
    inventory::{ContentHash, Entry, Node, Status},
    policy::{Highlight, SettingsPatch},
    subject::SubjectMatch,
    vault::ExportFormat,
};

type TestResult = Result<(), Box<dyn StdError>>;

const PROSE: &str = include_str!("../../../docs/api/prose.toml");
const OPENAPI: &str = include_str!("../../../docs/api/openapi.json");
const MARKDOWN: &str = include_str!("../../../docs/api/README.md");

/// The statuses every operation can end with besides 200.
const FAILURES: [&str; 8] = ["400", "401", "403", "404", "405", "409", "413", "500"];

/// The line (counted from 1) where `a` and `b` first differ.
fn first_difference(a: &str, b: &str) -> usize {
    a.lines()
        .zip(b.lines())
        .position(|(x, y)| x != y)
        .map_or_else(|| a.lines().count().min(b.lines().count()) + 1, |at| at + 1)
}

/// Fails with how to regenerate when the committed `text` of `path` is not `generated`.
fn assert_committed(path: &str, text: &str, generated: &str) {
    let text = text.replace("\r\n", "\n");
    assert!(
        text == generated,
        "{path} is not what the code generates (first difference at line {}): run `cargo api-docs` and commit the result",
        first_difference(&text, generated)
    );
}

#[test]
fn the_committed_reference_is_what_the_code_generates() -> TestResult {
    let made = generate(PROSE)?;
    // The version of the package changes with each release, and the pull request that makes the
    // release does not run `cargo api-docs`: the version is not compared.
    let mut committed: Value = serde_json::from_str(OPENAPI)
        .map_err(|error| format!("{SPEC_PATH} is not JSON ({error}): run `cargo api-docs`"))?;
    if let Some(version) = committed.pointer_mut("/info/version") {
        *version = Value::from(env!("CARGO_PKG_VERSION"));
    }
    assert_committed(SPEC_PATH, &pretty(&committed)?, &made.openapi);
    assert_committed(MARKDOWN_PATH, MARKDOWN, &made.markdown);
    Ok(())
}

#[test]
fn what_the_app_serves_is_the_generated_file() -> TestResult {
    assert_eq!(spec_json()?, generate(PROSE)?.openapi);
    assert_eq!(markdown()?, generate(PROSE)?.markdown);
    Ok(())
}

#[test]
fn api_prose_is_reviewed() -> TestResult {
    let review = review(PROSE)?;
    if !review.missing.is_empty() {
        eprintln!(
            "note: no prose for {} (allowed): {}",
            review.missing.len(),
            review.missing.join(", ")
        );
    }
    assert!(
        review.problems.is_empty(),
        "\n{}\n",
        review.problems.join("\n")
    );
    Ok(())
}

/// Every `$ref` in `value`, with where it stands.
fn refs(value: &Value, at: &str, found: &mut Vec<(String, String)>) {
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                match field {
                    Value::String(target) if key == "$ref" => {
                        found.push((at.to_owned(), target.clone()));
                    }
                    other => refs(other, &format!("{at}/{key}"), found),
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                refs(item, &format!("{at}/{index}"), found);
            }
        }
        _ => {}
    }
}

#[test]
fn every_reference_resolves_and_every_schema_is_used() -> TestResult {
    let spec = spec()?;
    let mut found = Vec::new();
    refs(&spec, "", &mut found);
    let mut used = BTreeSet::new();
    for (at, target) in &found {
        let resolved = target
            .strip_prefix('#')
            .and_then(|pointer| spec.pointer(pointer));
        assert!(resolved.is_some(), "{at}: {target} does not resolve");
        if let Some(name) = target.strip_prefix("#/components/schemas/") {
            used.insert(name.to_owned());
        }
    }
    let schemas = spec["components"]["schemas"]
        .as_object()
        .ok_or("no schemas")?;
    let unused: Vec<&String> = schemas
        .keys()
        .filter(|name| !used.contains(*name))
        .collect();
    assert!(unused.is_empty(), "schemas nobody refers to: {unused:?}");
    Ok(())
}

#[test]
fn every_op_is_in_paths_with_a_body_the_serde_takes_and_every_status() -> TestResult {
    let spec = spec()?;
    let paths = spec["paths"].as_object().ok_or("no paths")?;
    let wanted: BTreeSet<String> = Request::OPS
        .iter()
        .map(|op| format!("/v1/{op}"))
        .chain([http::SPEC_ROUTE.to_owned()])
        .collect();
    assert_eq!(paths.keys().cloned().collect::<BTreeSet<_>>(), wanted);
    for op in Request::OPS {
        let item = &paths[&format!("/v1/{op}")];
        assert_eq!(item.get("get").is_some(), http::allows_get(op), "{op}");
        let post = &item["post"];
        assert_eq!(post["operationId"], op);
        assert!(
            post["summary"]
                .as_str()
                .is_some_and(|title| !title.is_empty())
        );
        assert!(
            post["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
        let ok = &post["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(ok["properties"]["ok"]["const"], true, "{op}");
        assert!(ok["properties"]["result"].is_object(), "{op}");
        for status in FAILURES {
            assert!(post["responses"][status].is_object(), "{op} {status}");
        }
        // The example the reference shows is a request the serde takes.
        let example = &post["requestBody"]["content"]["application/json"]["example"];
        let mut body = example.as_object().cloned().unwrap_or_default();
        body.insert("op".to_owned(), Value::from(op));
        let request: Request = serde_json::from_value(Value::Object(body))?;
        assert_eq!(request.op(), op);
    }
    Ok(())
}

#[test]
fn the_spec_lists_itself_without_a_token() -> TestResult {
    let spec = spec()?;
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["info"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(spec["security"], json!([{"bearerAuth": []}]));
    assert_eq!(
        spec["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        "bearer"
    );
    let server = &spec["servers"][0];
    assert_eq!(server["url"], "http://127.0.0.1:{port}");
    assert_eq!(
        server["variables"]["port"]["default"],
        DEFAULT_HTTP_PORT.to_string()
    );
    let own = &spec["paths"][http::SPEC_ROUTE]["get"];
    assert_eq!(own["security"], json!([]));
    assert_eq!(
        own["description"],
        "This spec. The only call that needs no token: it holds nothing that is not public."
    );
    // It is a path of its own, not an operation.
    assert!(
        Request::OPS
            .iter()
            .all(|op| format!("/v1/{op}") != http::SPEC_ROUTE)
    );
    assert!(spec["paths"][http::SPEC_ROUTE]["post"].is_null());
    Ok(())
}

#[test]
fn the_pipe_is_spelled_as_the_service_names_it() {
    assert!(crate::service::default_pipe().starts_with(r"\\.\pipe\piikey-"));
    assert!(PIPE.starts_with(r"\\.\pipe\piikey-"));
}

#[test]
fn the_error_codes_are_the_ones_the_api_names() -> TestResult {
    let model = Model::build()?;
    let code = &model.components["ErrorCode"];
    let names: Vec<&str> = code["enum"]
        .as_array()
        .ok_or("no enum")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(names, Code::ALL.map(Code::as_str));
    for name in names {
        let meaning = code["x-enumDescriptions"][name]
            .as_str()
            .unwrap_or_default();
        assert!(!meaning.is_empty(), "{name} has no description");
    }
    // Every code is answered with the status of the HTTP API, and every refusal is listed.
    for ending in &model.endings {
        assert!(!ending.meaning.is_empty());
    }
    for code in Code::ALL {
        let status = http::status_of(&ApiError::new(code, "")).as_u16();
        let listed = model
            .endings
            .iter()
            .any(|ending| ending.code == code.as_str() && ending.status == status);
        assert!(listed, "{}", code.as_str());
    }
    for (status, name) in intro::RESPONSES {
        assert!(
            model.endings.iter().any(|ending| ending.status == status),
            "{name}"
        );
    }
    Ok(())
}

// ---- The schemas are what the serde reads and writes ----

/// A small check of a JSON `value` against a `schema` of the keywords the generator makes.
fn conforms(
    value: &Value,
    schema: &Value,
    components: &Map<String, Value>,
    at: &str,
) -> Result<(), String> {
    let Some(fields) = schema.as_object() else {
        return Ok(());
    };
    if let Some(target) = fields.get("$ref").and_then(Value::as_str) {
        let found = schema::resolve(components, target)
            .ok_or_else(|| format!("{at}: {target} does not resolve"))?;
        conforms(value, found, components, at)?;
    }
    if let Some(constant) = fields.get("const")
        && value != constant
    {
        return Err(format!("{at}: {value} is not {constant}"));
    }
    if let Some(all) = fields.get("enum").and_then(Value::as_array)
        && !all.contains(value)
    {
        return Err(format!("{at}: {value} is none of {all:?}"));
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(all) = fields.get(key).and_then(Value::as_array)
            && !all
                .iter()
                .any(|one| conforms(value, one, components, at).is_ok())
        {
            return Err(format!("{at}: {value} fits none of the {key}"));
        }
    }
    if let Some(types) = fields.get("type") {
        let names: Vec<&str> = match types {
            Value::String(one) => vec![one],
            Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let fits = names.iter().any(|name| match *name {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            _ => false,
        });
        if !fits {
            return Err(format!("{at}: {value} is not of the type {names:?}"));
        }
    }
    if let Some(number) = value.as_f64() {
        let below = fields.get("minimum").and_then(Value::as_f64);
        let above = fields.get("maximum").and_then(Value::as_f64);
        if below.is_some_and(|low| number < low) || above.is_some_and(|high| number > high) {
            return Err(format!("{at}: {number} is out of bounds"));
        }
    }
    match value {
        Value::Object(map) => conform_object(map, fields, components, at)?,
        Value::Array(items) => {
            if let Some(each) = fields.get("items") {
                for (index, item) in items.iter().enumerate() {
                    conforms(item, each, components, &format!("{at}/{index}"))?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn conform_object(
    map: &Map<String, Value>,
    fields: &Map<String, Value>,
    components: &Map<String, Value>,
    at: &str,
) -> Result<(), String> {
    let properties = fields.get("properties").and_then(Value::as_object);
    for name in fields
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !map.contains_key(name) {
            return Err(format!("{at}: `{name}` is required and missing"));
        }
    }
    for (key, field) in map {
        let here = format!("{at}/{key}");
        if let Some(property) = properties.and_then(|all| all.get(key)) {
            conforms(field, property, components, &here)?;
        } else {
            match fields.get("additionalProperties") {
                Some(Value::Bool(false)) => return Err(format!("{here}: not a property")),
                Some(rest @ Value::Object(_)) => conforms(field, rest, components, &here)?,
                _ => {}
            }
        }
        if let Some(names) = fields.get("propertyNames") {
            conforms(&Value::from(key.as_str()), names, components, &here)?;
        }
    }
    Ok(())
}

/// A request of each op with every field given, as the serde writes it.
fn full_requests() -> Vec<Request> {
    let path = || PathBuf::from(r"C:\data");
    vec![
        Request::ScanText {
            texts: vec!["a".into()],
        },
        Request::Anonymize {
            texts: vec!["a".into()],
        },
        Request::Deanonymize {
            texts: vec!["a".into()],
            tolerant: true,
        },
        Request::ScanFiles {
            paths: vec![path()],
            record: false,
        },
        Request::AnonymizeFiles {
            paths: vec![path()],
            out: path(),
        },
        Request::DeanonymizeFiles {
            paths: vec![path()],
            out: path(),
            tolerant: true,
        },
        Request::SubjectSearch {
            values: vec!["Jan".into()],
            paths: vec![path()],
        },
        Request::VaultList {
            query: Some("a".into()),
            kind: Some("email".into()),
            limit: Some(5),
            offset: 1,
        },
        Request::VaultForget {
            values: vec!["a".into()],
        },
        Request::VaultExport {
            path: path(),
            format: crate::api::Format::Csv,
        },
        Request::VaultWipe { confirm: true },
        Request::InventoryStatus,
        Request::InventoryList {
            under: Some(path()),
            limit: Some(5),
            offset: 1,
        },
        Request::InventoryTree {
            under: Some(path()),
        },
        Request::InventoryRescan,
        Request::InventoryReport {
            path: path(),
            format: crate::api::Format::Csv,
        },
        Request::SettingsGet,
        Request::SettingsSet {
            settings: SettingsPatch {
                sites: Some(vec!["example.com".into()]),
                programs: Some(vec!["chrome.exe".into()]),
                disabled_kinds: Some(vec!["email".into()]),
                highlight: Some(Highlight::Always),
                explorer_menu: Some(false),
                background: Some(false),
                inventory_roots: Some(vec![path()]),
                monitored_roots: Some(vec![path()]),
                http_api: Some(true),
                http_port: Some(8000),
            },
        },
        Request::Kinds,
        Request::ModelStatus,
        Request::ModelDownload,
        Request::ApiToken { rotate: true },
        Request::Status,
        Request::Protection { on: false },
        Request::ExplorerScan {
            paths: vec![path()],
        },
        Request::ShowWindow,
    ]
}

#[test]
fn a_request_is_what_the_schema_of_its_op_describes() -> TestResult {
    let spec = spec()?;
    let components = spec["components"]["schemas"]
        .as_object()
        .ok_or("no schemas")?;
    let requests = full_requests();
    assert_eq!(requests.len(), Request::OPS.len());
    for request in requests {
        let op = request.op();
        let Value::Object(mut body) = serde_json::to_value(&request)? else {
            return Err("a request is no object".into());
        };
        assert_eq!(body.remove("op"), Some(Value::from(op)));
        let post = &spec["paths"][&format!("/v1/{op}")]["post"];
        let Some(schema) = post["requestBody"]["content"]["application/json"].get("schema") else {
            // An operation without fields: the body of a request of it is empty.
            assert!(body.is_empty(), "{op}");
            continue;
        };
        conforms(&Value::Object(body.clone()), schema, components, op)?;
        // The fields that are required are the ones the serde cannot do without, and the schema
        // refuses what the serde refuses.
        let required: Vec<&str> = schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for field in body.keys() {
            let mut without = body.clone();
            without.remove(field);
            without.insert("op".to_owned(), Value::from(op));
            let taken = serde_json::from_value::<Request>(Value::Object(without)).is_ok();
            assert_eq!(taken, !required.contains(&field.as_str()), "{op}: {field}");
        }
        let mut more = body.clone();
        more.insert("extra".to_owned(), Value::from(1));
        assert!(conforms(&Value::Object(more.clone()), schema, components, op).is_err());
        more.insert("op".to_owned(), Value::from(op));
        assert!(serde_json::from_value::<Request>(Value::Object(more)).is_err());
    }
    Ok(())
}

fn written<T: Serialize>(value: &T) -> Result<Value, serde_json::Error> {
    serde_json::to_value(value)
}

fn entry(status: Status, counts: Vec<(EntityKind, u32)>) -> Entry {
    Entry {
        path: PathBuf::from(r"C:\data\a.txt"),
        size: 12,
        modified: 133_000_000_000_000_000,
        scanned: 1_700_000_000,
        status,
        counts,
        hash: Some(ContentHash::of(b"a")),
    }
}

type Samples = Result<Vec<(&'static str, Value)>, serde_json::Error>;

fn entries() -> Vec<Entry> {
    vec![
        entry(Status::Ok, vec![(EntityKind::Email, 2)]),
        entry(Status::Failed("busy".into()), vec![]),
        entry(Status::TooLarge, vec![]),
        entry(Status::Unsupported, vec![]),
    ]
}

/// The model as it is when it works (`failed` false) and when it did not.
fn a_model(failed: bool) -> reply::Model {
    use reply::{Device, ModelState, Progress};
    if failed {
        return reply::Model {
            state: ModelState::Failed,
            device: None,
            error: Some("no".into()),
            downloading: None,
            dir: r"C:\models".into(),
        };
    }
    reply::Model {
        state: ModelState::Ready,
        device: Some(Device::Hybrid),
        error: None,
        downloading: Some(Progress { done: 1, total: 2 }),
        dir: r"C:\models".into(),
    }
}

fn a_status(model: &reply::Model, protection: Option<bool>) -> reply::Status {
    reply::Status {
        app: true,
        protection,
        version: "1.0.0".into(),
        vault_records: 4,
        model: model.clone(),
        highlight: Highlight::Hotkey,
        explorer_menu: true,
        monitoring: false,
        http_api: true,
    }
}

/// What the ops on texts and files answer, written by the types that write it.
fn text_replies() -> Samples {
    let span = reply::Span {
        start: 5,
        end: 16,
        kind: "email".into(),
        value: "jan@acme.nl".into(),
    };
    let texts = reply::Texts {
        texts: vec!["x".into()],
    };
    let found = SubjectMatch {
        path: PathBuf::from(r"C:\data\a.txt"),
        values: vec![0, 1],
        count: 3,
    };
    Ok(vec![
        (
            "scan_text",
            written(&reply::Spans {
                results: vec![vec![span], vec![]],
            })?,
        ),
        ("anonymize", written(&texts)?),
        ("deanonymize", written(&texts)?),
        (
            "scan_files",
            written(&reply::Scanned {
                files: entries(),
                hits: 2,
            })?,
        ),
        (
            "anonymize_files",
            written(&reply::Written {
                written: vec![reply::Moved {
                    input: "a".into(),
                    output: "b".into(),
                }],
                failed: vec![reply::Failed {
                    input: "c".into(),
                    error: "no".into(),
                }],
            })?,
        ),
        (
            "deanonymize_files",
            written(&reply::Written {
                written: vec![],
                failed: vec![],
            })?,
        ),
        (
            "subject_search",
            written(&reply::Found {
                matches: vec![found],
            })?,
        ),
    ])
}

/// What the ops on the vault and the inventory answer.
fn vault_and_inventory_replies() -> Samples {
    use reply::Progress;
    let node = Node {
        path: PathBuf::from(r"C:\data"),
        name: "data".into(),
        is_dir: true,
        hits: 3,
        files: 1,
        counts: vec![(EntityKind::Email, 2), (EntityKind::Phone, 1)],
    };
    Ok(vec![
        (
            "vault_list",
            written(&reply::Records {
                records: vec![reply::Record {
                    kind: "email".into(),
                    original: "a".into(),
                    proxy: "b".into(),
                }],
                total: 1,
            })?,
        ),
        ("vault_forget", written(&reply::Forgotten { forgotten: 1 })?),
        (
            "vault_export",
            written(&reply::Exported {
                records: 1,
                path: r"C:\v.json".into(),
            })?,
        ),
        ("vault_wipe", written(&reply::Forgotten { forgotten: 0 })?),
        (
            "inventory_status",
            written(&reply::InventoryStatus {
                roots: vec![r"C:\data".into()],
                monitored: vec![],
                files: 4,
                files_with_pii: 2,
                hits: 9,
                scanning: Some(Progress { done: 1, total: 4 }),
            })?,
        ),
        (
            "inventory_list",
            written(&reply::Entries {
                entries: entries(),
                total: 4,
            })?,
        ),
        (
            "inventory_tree",
            written(&reply::Nodes { nodes: vec![node] })?,
        ),
        (
            "inventory_rescan",
            written(&crate::inventory::Totals {
                files: 1,
                files_with_pii: 1,
                hits: 1,
            })?,
        ),
        (
            "inventory_report",
            written(&reply::Reported {
                rows: 2,
                path: r"C:\r.csv".into(),
            })?,
        ),
    ])
}

/// What the ops on the settings, the model and the app answer.
fn app_replies() -> Samples {
    let model = a_model(false);
    let set = Policy {
        disabled_kinds: vec![EntityKind::Email, EntityKind::Iban],
        sites: vec!["example.com".into()],
        programs: vec!["chrome.exe".into()],
        inventory_roots: vec![PathBuf::from(r"C:\data")],
        monitored_roots: vec![PathBuf::from(r"C:\data")],
        http_api: true,
        ..Policy::default()
    };
    Ok(vec![
        ("settings_get", written(&Policy::default())?),
        ("settings_set", written(&set)?),
        (
            "kinds",
            written(&vec![reply::Kind {
                kind: "email".into(),
                label: "Email address".into(),
                group: "Contact".into(),
                enabled: true,
            }])?,
        ),
        ("model_status", written(&model)?),
        ("model_download", json!({})),
        ("api_token", written(&reply::Token { token: "t".into() })?),
        ("status", written(&a_status(&model, Some(true)))?),
        (
            "protection",
            written(&reply::Protection { protection: true })?,
        ),
        ("explorer_scan", json!({})),
        ("show_window", json!({})),
        // A reply from the other side of every `null` and every absent field.
        ("status", written(&a_status(&a_model(true), None))?),
    ])
}

/// What each op answers, written by the types that write it.
fn replies() -> Samples {
    let mut all = text_replies()?;
    all.extend(vault_and_inventory_replies()?);
    all.extend(app_replies()?);
    Ok(all)
}

#[test]
fn a_result_is_what_the_schema_of_its_op_describes() -> TestResult {
    let spec = spec()?;
    let components = spec["components"]["schemas"]
        .as_object()
        .ok_or("no schemas")?;
    let replies = replies()?;
    let named: BTreeSet<&str> = replies.iter().map(|(op, _)| *op).collect();
    assert_eq!(named.len(), Request::OPS.len(), "an op without a sample");
    for (op, result) in replies {
        let post = &spec["paths"][&format!("/v1/{op}")]["post"];
        let envelope = &post["responses"]["200"]["content"]["application/json"]["schema"];
        let reply = crate::api::envelope(Ok(result));
        conforms(&reply, envelope, components, op)?;
    }
    // A failed reply is described by the schema of a failure.
    let failure = &spec["components"]["schemas"]["Failure"];
    for code in Code::ALL {
        let reply = crate::api::envelope(Err(ApiError::new(code, "no")));
        conforms(&reply, failure, components, code.as_str())?;
    }
    // And a reply that says `ok` and has no `result` is not a reply that worked.
    let ok = &spec["paths"]["/v1/kinds"]["post"]["responses"]["200"]["content"]["application/json"]
        ["schema"];
    assert!(conforms(&json!({"ok": true}), ok, components, "kinds").is_err());
    Ok(())
}

// ---- What the reference says, and how it says it ----

/// The words that the glossary of the project does not allow in what the reader reads. What is
/// between backticks is code, and keeps the names of the fields; the target of a link is no text.
fn glossary(text: &str) -> Vec<String> {
    let mut plain = String::new();
    let mut code = false;
    for part in text.split('`') {
        if !code {
            plain.push_str(part);
            plain.push(' ');
        }
        code = !code;
    }
    let mut read = String::new();
    let mut rest = plain.as_str();
    while let Some(at) = rest.find("](") {
        read.push_str(&rest[..at]);
        read.push(' ');
        rest = rest[at + 2..]
            .split_once(')')
            .map_or("", |(_, after)| after);
    }
    read.push_str(rest);
    read.split(|c: char| !c.is_alphanumeric())
        .filter(|word| {
            *word == "PII"
                || matches!(
                    word.to_ascii_lowercase().as_str(),
                    "kind" | "kinds" | "program" | "programs" | "proxy" | "proxies"
                )
        })
        .map(str::to_owned)
        .collect()
}

/// Every text of the spec that a reader sees.
fn texts(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                match field {
                    Value::String(text)
                        if matches!(key.as_str(), "description" | "summary" | "title") =>
                    {
                        found.push(text.clone());
                    }
                    Value::Object(meanings) if key == "x-enumDescriptions" => {
                        found.extend(
                            meanings
                                .values()
                                .filter_map(Value::as_str)
                                .map(str::to_owned),
                        );
                    }
                    other => texts(other, found),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| texts(item, found)),
        _ => {}
    }
}

#[test]
fn the_reference_speaks_the_words_of_the_glossary() -> TestResult {
    let mut found = Vec::new();
    texts(&spec()?, &mut found);
    for text in found {
        let wrong = glossary(&text);
        assert!(wrong.is_empty(), "{wrong:?} in {text:?}");
    }
    let page = markdown()?;
    let without_examples: String = page.split("```").step_by(2).collect::<Vec<_>>().join(" ");
    for line in without_examples.lines() {
        let wrong = glossary(line);
        assert!(wrong.is_empty(), "{wrong:?} in {line:?}");
    }
    Ok(())
}

#[test]
fn the_page_has_every_operation_once_with_its_example() -> TestResult {
    let page = markdown()?;
    for op in Request::OPS {
        assert_eq!(page.matches(&format!("\n#### `{op}`\n")).count(), 1, "{op}");
        let url = format!("http://127.0.0.1:{DEFAULT_HTTP_PORT}/v1/{op}");
        assert!(page.contains(&url), "{op} has no example");
    }
    assert!(page.contains("`GET /v1/status` or `POST /v1/status`"));
    assert!(page.starts_with("# piikey API\n"));
    assert!(page.ends_with("|\n") || page.ends_with('\n'));
    // Every link to a section of the page goes to a heading that is there.
    for part in page.split("](#").skip(1) {
        let anchor = part.split(')').next().unwrap_or_default();
        let op = Request::OPS.contains(&anchor);
        let schema = anchor.strip_suffix("-schema").is_some_and(|name| {
            page.contains(&format!("### `{}` schema", schema_named(&page, name)))
        });
        assert!(op || schema, "#{anchor} goes nowhere");
    }
    Ok(())
}

/// The name of the schema whose anchor is `lowercase`, as the page spells it.
fn schema_named(page: &str, lowercase: &str) -> String {
    page.lines()
        .filter_map(|line| line.strip_prefix("### `"))
        .filter_map(|line| line.strip_suffix("` schema"))
        .find(|name| name.to_lowercase() == lowercase)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn the_page_is_the_same_every_time() -> TestResult {
    assert_eq!(markdown()?, markdown()?);
    assert_eq!(spec_json()?, spec_json()?);
    Ok(())
}

// ---- Fingerprints, and what the prose is reviewed against ----

#[test]
fn an_op_changes_its_fingerprint_when_its_contract_changes_and_no_other_does() -> TestResult {
    let before = Model::build()?;
    let was = before.fingerprints();
    assert_eq!(was.len(), Request::OPS.len() + 1);

    // The doc comment of one operation.
    let mut doc = Model::build()?;
    let at = doc
        .operations
        .iter()
        .position(|op| op.name == "scan_text")
        .ok_or("no scan_text")?;
    doc.operations[at].doc.push_str(" More.");
    let now = doc.fingerprints();
    let changed: Vec<&String> = now.keys().filter(|name| now[*name] != was[*name]).collect();
    assert_eq!(changed, ["scan_text"]);

    // A type that some results contain: the operations that answer with it change.
    let mut nested = Model::build()?;
    if let Some(Value::Object(progress)) = nested.components.get_mut("Progress") {
        progress.insert("description".to_owned(), Value::from("Changed."));
    }
    let now = nested.fingerprints();
    let changed: BTreeSet<&str> = now
        .keys()
        .filter(|name| now[*name] != was[*name])
        .map(String::as_str)
        .collect();
    assert_eq!(
        changed,
        BTreeSet::from(["inventory_status", "model_status", "status"])
    );

    // The intro.
    let mut intro = Model::build()?;
    if let Some(Value::Object(failure)) = intro.components.get_mut("Failure") {
        failure.insert("description".to_owned(), Value::from("Changed."));
    }
    let now = intro.fingerprints();
    let changed: Vec<&String> = now.keys().filter(|name| now[*name] != was[*name]).collect();
    assert_eq!(changed, ["intro"]);
    Ok(())
}

/// A prose of two tables with a comment and a text of several lines, accepted: reviewed against
/// the code as it is now, whatever the committed `prose.toml` says.
fn reviewed_sample() -> Result<String, DocsError> {
    let sample = "# A comment that stays.\n[intro]\nreviewed = \"0000000000000000\"\ntext = '''\nOne.\n\nTwo \"quoted\".\n'''\n\n[scan_text]   # so does this one\nreviewed = \"0000000000000000\"\ntext = \"CLI: `piikey-cli scan`\"\n";
    accept(sample, "all")
}

#[test]
fn a_stale_orphan_and_missing_prose_are_told_apart() -> TestResult {
    let sample = reviewed_sample()?;
    let parsed = Prose::parse(&sample)?;
    // Reviewed against the code as it is: nothing to say, and the other operations have none.
    let clean = review(&sample)?;
    assert_eq!(clean.problems, Vec::<String>::new());
    assert_eq!(clean.missing.len(), Request::OPS.len() - 1);
    assert!(!clean.missing.contains(&"scan_text".to_owned()));

    let stale = parsed.restamp(&sample, &[("scan_text", "ffffffffffffffff")])?;
    assert_eq!(
        review(&stale)?.problems,
        [format!(
            "op `scan_text` changed since its prose was reviewed: read {PROSE_PATH} [scan_text], then run `cargo api-docs --accept scan_text`"
        )]
    );
    let stale = parsed.restamp(&sample, &[("intro", "ffffffffffffffff")])?;
    let problems = review(&stale)?.problems;
    assert_eq!(problems.len(), 1);
    assert!(problems[0].starts_with("the intro changed since its prose was reviewed"));
    assert!(problems[0].ends_with("run `cargo api-docs --accept intro`"));

    let orphan =
        format!("{sample}\n[foo]\nreviewed = \"0000000000000000\"\ntext = \"for nothing\"\n");
    assert_eq!(
        review(&orphan)?.problems,
        [format!(
            "prose for `foo`, which is no operation: remove [foo] from {PROSE_PATH}"
        )]
    );

    // Without the table of an operation there is no problem, only a note; and no prose at all is
    // allowed.
    let report = review("")?;
    assert!(report.problems.is_empty());
    assert_eq!(report.missing, Request::OPS);
    Ok(())
}

/// `text` with the fingerprint of every table blanked, to see what else changed.
fn without_fingerprints(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.starts_with("reviewed = ") {
                "reviewed"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn accepting_rewrites_the_fingerprints_and_nothing_else() -> TestResult {
    let sample = reviewed_sample()?;
    let parsed = Prose::parse(&sample)?;
    let stale = parsed.restamp(
        &sample,
        &[
            ("scan_text", "ffffffffffffffff"),
            ("intro", "eeeeeeeeeeeeeeee"),
        ],
    )?;
    assert_eq!(review(&stale)?.problems.len(), 2);

    // One table.
    let one = accept(&stale, "scan_text")?;
    assert_eq!(review(&one)?.problems.len(), 1);
    assert_eq!(without_fingerprints(&one), without_fingerprints(&sample));
    // The intro.
    let intro = accept(&stale, "intro")?;
    assert_eq!(review(&intro)?.problems.len(), 1);
    // All of them: the text as it was reviewed, byte for byte.
    let all = accept(&stale, "all")?;
    assert_eq!(all, sample);
    assert!(review(&all)?.problems.is_empty());

    // What cannot be accepted is said.
    assert!(accept(&sample, "nothing").is_err());
    let short = "[intro]\nreviewed = \"0000000000000000\"\ntext = \"x\"\n";
    assert!(accept(short, "scan_text").is_err());
    Ok(())
}

#[test]
fn the_prose_names_nothing_but_operations_and_the_intro() -> TestResult {
    for name in Prose::parse(PROSE)?.names() {
        assert!(
            name == "intro" || Request::OPS.contains(&name),
            "{name} is no operation"
        );
    }
    Ok(())
}

#[test]
fn the_prose_is_part_of_the_descriptions() -> TestResult {
    let spec = spec()?;
    let prose = Prose::parse(PROSE)?;
    let description = spec["info"]["description"]
        .as_str()
        .ok_or("no description")?;
    if let Some(text) = prose.text("intro") {
        assert!(description.contains(text));
    }
    for op in Request::OPS {
        let described = spec["paths"][&format!("/v1/{op}")]["post"]["description"]
            .as_str()
            .ok_or("no description")?;
        if let Some(text) = prose.text(op) {
            assert!(described.contains(text), "{op}");
        }
    }
    // The format: a plain one, `json`, comes with the words of the doc comment.
    assert_eq!(
        spec["components"]["schemas"]["Format"]["enum"],
        json!(["json", "csv"])
    );
    assert_eq!(
        ExportFormat::from(crate::api::Format::Json),
        ExportFormat::Json
    );
    Ok(())
}
