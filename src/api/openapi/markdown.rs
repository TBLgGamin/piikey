//! The reference as a Markdown page, from the same model as the `OpenAPI` document.

use std::{collections::BTreeSet, fmt::Write as _};

use serde_json::{Map, Value};

use super::{Model, Operation, Prose, REFERENCE_URL, Tag, describe, http, intro, schema};
use crate::policy::DEFAULT_HTTP_PORT;

/// The longest list of values that a type cell spells out instead of naming the schema.
const SPELLED_OUT: usize = 4;

/// The schemas that tables point at: from the fields of requests, and from results.
#[derive(Default)]
struct Shown {
    request: BTreeSet<String>,
    result: BTreeSet<String>,
}

/// The whole page: the intro, every operation by group, then the schemas the tables point at.
pub(super) fn render(model: &Model, prose: &Prose) -> String {
    let mut out = String::new();
    out.push_str("# piikey API\n\n");
    out.push_str("> Generated from the code by `cargo api-docs`: never edit this file by hand. Change a doc comment in the code, or the notes in [`prose.toml`](prose.toml).\n\n");
    let _ = write!(
        out,
        "[OpenAPI 3.1 file](openapi.json) · [Interactive reference]({REFERENCE_URL})\n\n"
    );
    out.push_str(&intro::text(&model.endings, prose.text("intro")));
    out.push_str("\n\n");
    let mut shown = Shown::default();
    operations(&mut out, model, prose, &mut shown);
    schemas(&mut out, model, &shown);
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

/// The index of the operations, then each group and each operation of it.
fn operations(out: &mut String, model: &Model, prose: &Prose, shown: &mut Shown) {
    out.push_str("## Operations\n\n| Operation | What it does |\n|---|---|\n");
    for tag in Tag::ALL {
        for op in model.operations.iter().filter(|op| op.route.tag == tag) {
            let _ = writeln!(
                out,
                "| [`{name}`](#{name}) | {} |",
                cell(schema::first_sentence(&op.description)),
                name = op.name,
            );
        }
    }
    out.push('\n');
    for tag in Tag::ALL {
        let _ = write!(out, "### {}\n\n{}\n\n", tag.name(), tag.about());
        for op in model.operations.iter().filter(|op| op.route.tag == tag) {
            operation(out, model, prose, op, shown);
        }
    }
}

/// One operation: what it does, how to call it, its fields, its result and an example.
fn operation(out: &mut String, model: &Model, prose: &Prose, op: &Operation, shown: &mut Shown) {
    let _ = write!(out, "#### `{}`\n\n", op.name);
    out.push_str(&describe(&op.description, prose.text(op.name)));
    out.push_str("\n\n");
    let calls = if http::allows_get(op.name) {
        format!("`GET /v1/{0}` or `POST /v1/{0}`", op.name)
    } else {
        format!("`POST /v1/{}`", op.name)
    };
    let _ = write!(out, "{calls}\n\n");

    match &op.body {
        Some(body) => {
            out.push_str("**Request fields**\n\n");
            fields(out, body, &model.components, &mut shown.request, true);
        }
        None => out.push_str("This operation takes no fields: any that are sent are ignored.\n\n"),
    }

    out.push_str("**Result**\n\n");
    result(out, &op.result, &model.components, &mut shown.result);

    let _ = write!(out, "**Example**\n\n```powershell\n{}\n```\n\n", curl(op));
}

/// What the result is: the fields of the object (of each item of a list), or `{}`.
fn result(
    out: &mut String,
    result: &Value,
    components: &Map<String, Value>,
    shown: &mut BTreeSet<String>,
) {
    let items = result
        .get("items")
        .filter(|_| type_name(result) == Some("array"));
    let item = items.unwrap_or(result);
    let object = resolved(item, components);
    if object.get("properties").is_some() {
        if items.is_some() {
            let name = item
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(schema::ref_name)
                .unwrap_or("object");
            let _ = write!(out, "A list of `{name}`, each with these fields:\n\n");
        }
        fields(out, object, components, shown, false);
    } else if type_name(object) == Some("object") {
        out.push_str("An empty object, `{}`.\n\n");
    } else {
        let text = kinds(result, shown, true);
        let _ = write!(out, "{text}\n\n");
    }
}

/// The `type` of a schema.
fn type_name(schema: &Value) -> Option<&str> {
    schema.as_object().and_then(schema::type_of)
}

/// `schema` with a `$ref` followed to what it points at.
fn resolved<'a>(schema: &'a Value, components: &'a Map<String, Value>) -> &'a Value {
    schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|target| schema::resolve(components, target))
        .unwrap_or(schema)
}

/// The table of the fields of an object schema. `request` leaves `null` out of the types: in a
/// request a field is left out, in a result it can be `null`.
fn fields(
    out: &mut String,
    object: &Value,
    components: &Map<String, Value>,
    shown: &mut BTreeSet<String>,
    request: bool,
) {
    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        return;
    };
    let required: Vec<&str> = object
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    out.push_str("| Field | Type | Required | Description |\n|---|---|---|---|\n");
    for (name, property) in properties {
        let mut about: Vec<String> = Vec::new();
        if let Some(text) = described(property, components) {
            about.push(text.to_owned());
        }
        if request && let Some(default) = property.get("default") {
            about.push(format!("Default: `{default}`."));
        }
        let _ = writeln!(
            out,
            "| `{name}` | {} | {} | {} |",
            kinds(property, shown, !request),
            if required.contains(&name.as_str()) {
                "yes"
            } else {
                "no"
            },
            cell(&about.join("\n\n")),
        );
    }
    out.push('\n');
}

/// The description of a property: its own, else the first sentence of that of the schema it
/// points at.
fn described<'a>(property: &'a Value, components: &'a Map<String, Value>) -> Option<&'a str> {
    property
        .get("description")
        .and_then(Value::as_str)
        .or_else(|| {
            resolved(property, components)
                .get("description")
                .and_then(Value::as_str)
                .map(schema::first_sentence)
        })
}

/// A type as a cell shows it, in Markdown. `nulls` says whether `null` is spelled out.
fn kinds(schema: &Value, shown: &mut BTreeSet<String>, nulls: bool) -> String {
    let found = alternatives(schema, shown, nulls);
    if found.is_empty() {
        return "any".to_owned();
    }
    found
        .iter()
        .map(Alternative::markdown)
        .collect::<Vec<_>>()
        .join(" or ")
}

/// One thing a value can be: a label, and the schema it names when it names one.
struct Alternative {
    label: String,
    link: Option<String>,
}

impl Alternative {
    fn plain(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            link: None,
        }
    }

    fn markdown(&self) -> String {
        match &self.link {
            Some(name) => format!("[`{}`](#{})", self.label, anchor(name)),
            None => format!("`{}`", self.label),
        }
    }
}

/// The anchor of the section of a schema.
fn anchor(name: &str) -> String {
    format!("{}-schema", name.to_lowercase())
}

fn alternatives(schema: &Value, shown: &mut BTreeSet<String>, nulls: bool) -> Vec<Alternative> {
    let Some(fields) = schema.as_object() else {
        return Vec::new();
    };
    if let Some(name) = fields
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(schema::ref_name)
    {
        shown.insert(name.to_owned());
        return vec![Alternative {
            label: name.to_owned(),
            link: Some(name.to_owned()),
        }];
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(all) = fields.get(key).and_then(Value::as_array) {
            return all
                .iter()
                .filter(|one| nulls || !schema::is_null(one))
                .flat_map(|one| alternatives(one, shown, nulls))
                .collect();
        }
    }
    if let Some(constant) = fields.get("const") {
        return vec![Alternative::plain(constant.to_string())];
    }
    if let Some(values) = fields.get("enum").and_then(Value::as_array)
        && values.len() <= SPELLED_OUT
    {
        return values
            .iter()
            .map(|value| Alternative::plain(value.to_string()))
            .collect();
    }
    let mut found = typed(fields, shown, nulls);
    let null_too = fields
        .get("type")
        .and_then(Value::as_array)
        .is_some_and(|names| names.iter().any(|name| name == "null"));
    if nulls && null_too {
        found.push(Alternative::plain("null"));
    }
    found
}

/// The alternatives that the `type` of a schema names.
fn typed(
    fields: &Map<String, Value>,
    shown: &mut BTreeSet<String>,
    nulls: bool,
) -> Vec<Alternative> {
    match schema::type_of(fields) {
        Some("array") => {
            let inner = fields
                .get("items")
                .map(|items| alternatives(items, shown, nulls))
                .unwrap_or_default();
            match inner.into_iter().next() {
                Some(item) => vec![Alternative {
                    label: format!("{}[]", item.label),
                    link: item.link,
                }],
                None => vec![Alternative::plain("array")],
            }
        }
        Some("object") => {
            // An object keyed by a type of personal data: the keys are named, so the schema that
            // lists the names is shown below.
            if let Some(keys) = fields.get("propertyNames") {
                alternatives(keys, shown, false);
            }
            match fields
                .get("additionalProperties")
                .filter(|rest| rest.is_object())
            {
                Some(values) => {
                    let value = alternatives(values, shown, false)
                        .first()
                        .map_or_else(|| "any".to_owned(), |one| one.label.clone());
                    vec![Alternative::plain(format!("object of {value}"))]
                }
                None => vec![Alternative::plain("object")],
            }
        }
        Some(name) => vec![Alternative::plain(with_range(name, fields))],
        None => Vec::new(),
    }
}

/// A number type with the bounds that matter: `integer (1 to 65535)`. A lower bound of 0 alone is
/// the unsigned numbers' and says nothing.
fn with_range(name: &str, fields: &Map<String, Value>) -> String {
    let lowest = fields.get("minimum").and_then(Value::as_i64);
    let highest = fields.get("maximum").and_then(Value::as_i64);
    match (lowest, highest) {
        (Some(low), Some(high)) if low > 0 || high < i64::from(u32::MAX) => {
            format!("{name} ({low} to {high})")
        }
        (Some(low), None) if low > 0 => format!("{name} (at least {low})"),
        _ => name.to_owned(),
    }
}

/// A table cell: no pipes, no line breaks.
fn cell(text: &str) -> String {
    text.replace('|', r"\|")
        .replace("\n\n", "<br><br>")
        .replace('\n', " ")
}

/// The call of `op` as PowerShell types it: the token from the command line, the JSON body through
/// the pipe (quoting JSON in the arguments of a program is what PowerShell 5.1 gets wrong), and
/// `curl.exe`, because `curl` alone is `Invoke-WebRequest` there.
fn curl(op: &Operation) -> String {
    let url = format!("http://127.0.0.1:{DEFAULT_HTTP_PORT}/v1/{}", op.name);
    let header = r#"-H "Authorization: Bearer $token""#;
    let call = if http::allows_get(op.name) {
        format!("curl.exe -s {header} {url}")
    } else {
        let body = op.example.to_string().replace('\'', "''");
        format!("'{body}' | curl.exe -s {header} --data-binary '@-' {url}")
    };
    format!("$token = piikey-cli token\n{call}")
}

/// The sections of the schemas that the tables name, and of the schemas those name, by name. A
/// schema that only requests have is shown as the fields of a request.
fn schemas(out: &mut String, model: &Model, shown: &Shown) {
    let by_result = closure(model, &shown.result);
    let by_request = closure(model, &shown.request);
    let wanted: BTreeSet<&String> = by_result.union(&by_request).collect();
    if wanted.is_empty() {
        return;
    }
    out.push_str("## Schemas\n\nThe objects and values that the tables above point at.\n\n");
    for name in wanted {
        let Some(found) = model.components.get(name) else {
            continue;
        };
        let _ = write!(out, "### `{name}` schema\n\n");
        if let Some(about) = found.get("description").and_then(Value::as_str) {
            let _ = write!(out, "{about}\n\n");
        }
        if let Some(meanings) = found.get("x-enumDescriptions").and_then(Value::as_object) {
            out.push_str("| Value | Meaning |\n|---|---|\n");
            for (value, meaning) in meanings {
                let meaning = meaning.as_str().unwrap_or_default();
                let _ = writeln!(out, "| `{value}` | {} |", cell(meaning));
            }
            out.push('\n');
        } else {
            let request = by_request.contains(name) && !by_result.contains(name);
            fields(out, found, &model.components, &mut BTreeSet::new(), request);
        }
    }
}

/// The schemas in `start`, and every schema that those point at, and so on.
fn closure(model: &Model, start: &BTreeSet<String>) -> BTreeSet<String> {
    let mut all = start.clone();
    let mut queue: Vec<String> = all.iter().cloned().collect();
    while let Some(name) = queue.pop() {
        let Some(found) = model.components.get(&name) else {
            continue;
        };
        for inner in schema::references(found) {
            if all.insert(inner.clone()) {
                queue.push(inner);
            }
        }
    }
    all
}
