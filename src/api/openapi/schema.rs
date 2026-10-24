//! Shaping the JSON Schemas of the API for the reference: references, doc comments, examples and
//! the fingerprint of a contract.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

/// The start of every `$ref` to a schema of the document.
const SCHEMAS: &str = "#/components/schemas/";

/// How deep an example or an inlined schema goes before it stops: no type of the API is
/// recursive, so this only keeps a mistake from running away.
const DEEPEST: usize = 16;

/// The name of the schema a `$ref` points at.
pub(super) fn ref_name(reference: &str) -> Option<&str> {
    reference.strip_prefix(SCHEMAS)
}

/// A `$ref` to the schema `name` of the document.
pub(super) fn reference(name: &str) -> Value {
    json!({ "$ref": format!("{SCHEMAS}{name}") })
}

/// The names of the schemas that `value` points at, each once, in order.
pub(super) fn references(value: &Value) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    collect(value, &mut found);
    found
}

fn collect(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                match field {
                    Value::String(target) if key == "$ref" => {
                        if let Some(name) = ref_name(target) {
                            found.insert(name.to_owned());
                        }
                    }
                    other => collect(other, found),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect(item, found)),
        _ => {}
    }
}

/// The schema `reference` points at.
pub(super) fn resolve<'a>(
    components: &'a Map<String, Value>,
    reference: &str,
) -> Option<&'a Value> {
    ref_name(reference).and_then(|name| components.get(name))
}

/// `schema` with every `$ref` replaced by the schema it points at, so that a change anywhere
/// under it is a change of it.
pub(super) fn inline(schema: &Value, components: &Map<String, Value>) -> Value {
    inline_under(schema, components, &mut Vec::new())
}

fn inline_under<'a>(
    schema: &Value,
    components: &'a Map<String, Value>,
    open: &mut Vec<&'a str>,
) -> Value {
    match schema {
        Value::Object(fields) => {
            let mut merged = Map::new();
            for (key, field) in fields {
                if key != "$ref" {
                    merged.insert(key.clone(), inline_under(field, components, open));
                }
            }
            let Some(target) = fields.get("$ref").and_then(Value::as_str) else {
                return Value::Object(merged);
            };
            let found = ref_name(target)
                .filter(|name| open.len() < DEEPEST && !open.contains(name))
                .and_then(|name| components.get_key_value(name));
            let Some((name, found)) = found else {
                merged.insert("$ref".to_owned(), Value::String(target.to_owned()));
                return Value::Object(merged);
            };
            open.push(name);
            let inlined = inline_under(found, components, open);
            open.pop();
            match inlined {
                // The schema pointed at, with what stands next to the `$ref` on top of it.
                Value::Object(mut base) => {
                    base.extend(merged);
                    Value::Object(base)
                }
                other => other,
            }
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| inline_under(item, components, open))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `value` as one line of JSON whose objects are in key order: the same text for the same
/// contract, whatever order the schemas were built in.
pub(super) fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            out.push('{');
            for (at, key) in keys.into_iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                if let Some(field) = fields.get(key) {
                    write_canonical(field, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// A short, stable name of `contract`: the first 16 hexadecimal digits of the BLAKE3 hash of its
/// canonical JSON. Prose carries it as the contract it was reviewed against.
pub(super) fn fingerprint(contract: &Value) -> String {
    blake3::hash(canonical(contract).as_bytes())
        .to_hex()
        .chars()
        .take(16)
        .collect()
}

/// A doc comment as the reference prints it: the lines of a paragraph joined (the comment is
/// wrapped for the source, not for the reader) and links in the syntax of the Rust docs reduced
/// to code spans, since their targets mean nothing here.
pub(super) fn tidy(doc: &str) -> String {
    let mut paragraphs: Vec<String> = Vec::new();
    let mut open = false;
    for line in doc.lines().map(str::trim) {
        if line.is_empty() {
            open = false;
        } else if let Some(last) = paragraphs.last_mut().filter(|_| open && !is_item(line)) {
            last.push(' ');
            last.push_str(line);
        } else {
            paragraphs.push(line.to_owned());
            open = true;
        }
    }
    unlink(&paragraphs.join("\n\n"))
}

/// Whether `line` starts an item of a list.
fn is_item(line: &str) -> bool {
    line.starts_with("- ") || line.starts_with("* ")
}

/// ``[`Name`]`` and ``[`Name`](target)`` as `` `Name` ``.
fn unlink(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("[`") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("`]") else {
            out.push_str("[`");
            rest = after;
            continue;
        };
        out.push('`');
        out.push_str(&after[..end]);
        out.push('`');
        rest = &after[end + 2..];
        if let Some(target) = rest.strip_prefix('(')
            && let Some(close) = target.find(')')
        {
            rest = &target[close + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// The doc without its closing `Result: ...` sentence: the reference shows the result as a schema.
pub(super) fn without_result(doc: &str) -> &str {
    doc.rfind("Result:").map_or(doc, |at| doc[..at].trim_end())
}

/// The first sentence of `text`: up to the first full stop outside parentheses and code.
pub(super) fn first_sentence(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut depth = 0_u32;
    let mut code = false;
    for (at, byte) in bytes.iter().enumerate() {
        match byte {
            b'`' => code = !code,
            b'(' if !code => depth += 1,
            b')' if !code => depth = depth.saturating_sub(1),
            b'.' if !code
                && depth == 0
                && bytes.get(at + 1).is_none_or(u8::is_ascii_whitespace) =>
            {
                return &text[..=at];
            }
            _ => {}
        }
    }
    text
}

/// The first type of a schema's `type` that is not `null`.
pub(super) fn type_of(schema: &Map<String, Value>) -> Option<&str> {
    match schema.get("type")? {
        Value::String(one) => Some(one),
        Value::Array(many) => many
            .iter()
            .filter_map(Value::as_str)
            .find(|name| *name != "null"),
        _ => None,
    }
}

/// Whether `schema` is the schema of `null` and nothing else.
pub(super) fn is_null(schema: &Value) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("null")
}

/// An example of what `schema` describes, for a request body: the first of its `examples`, else
/// what its type needs. A field is in the example when it is required or has examples of its own.
pub(super) fn example(schema: &Value, components: &Map<String, Value>) -> Value {
    example_under(schema, components, 0)
}

fn example_under(schema: &Value, components: &Map<String, Value>, depth: usize) -> Value {
    let Some(fields) = schema.as_object() else {
        return Value::Null;
    };
    if let Some(first) = fields
        .get("examples")
        .and_then(Value::as_array)
        .and_then(|all| all.first())
    {
        return first.clone();
    }
    if let Some(value) = fields.get("const") {
        return value.clone();
    }
    if depth >= DEEPEST {
        return Value::Null;
    }
    if let Some(target) = fields
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| resolve(components, reference))
    {
        return example_under(target, components, depth + 1);
    }
    if let Some(first) = fields
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|all| all.first())
    {
        return first.clone();
    }
    if let Some(value) = fields.get("default") {
        return value.clone();
    }
    for key in ["oneOf", "anyOf"] {
        let first = fields
            .get(key)
            .and_then(Value::as_array)
            .and_then(|all| all.iter().find(|one| !is_null(one)));
        if let Some(first) = first {
            return example_under(first, components, depth + 1);
        }
    }
    match type_of(fields) {
        Some("string") => Value::from("string"),
        Some("integer" | "number") => fields.get("minimum").cloned().unwrap_or(Value::from(0)),
        Some("boolean") => Value::Bool(false),
        Some("array") => Value::Array(
            fields
                .get("items")
                .map(|items| example_under(items, components, depth + 1))
                .into_iter()
                .collect(),
        ),
        Some("object") => example_object(fields, components, depth),
        _ => Value::Null,
    }
}

fn example_object(
    fields: &Map<String, Value>,
    components: &Map<String, Value>,
    depth: usize,
) -> Value {
    let required: Vec<&str> = fields
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut object = Map::new();
    if let Some(properties) = fields.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            if required.contains(&name.as_str()) || property.get("examples").is_some() {
                object.insert(name.clone(), example_under(property, components, depth + 1));
            }
        }
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_comment_is_unwrapped_and_its_links_become_code() {
        let doc = "Restores the masked values in each\ntext. Result: [`reply::Texts`].\n\nAnd\nthen [`Totals`](crate::inventory::Totals) too.";
        assert_eq!(
            tidy(doc),
            "Restores the masked values in each text. Result: `reply::Texts`.\n\nAnd then `Totals` too."
        );
        assert_eq!(tidy("- one\n  more\n- two"), "- one more\n\n- two");
        assert_eq!(tidy("a [`b"), "a [`b");
    }

    #[test]
    fn the_result_sentence_and_the_summary_are_cut_out() {
        let doc = "Scans files (recursively). With `record`, the inventory keeps it. Result: `{}`.";
        assert_eq!(
            without_result(doc),
            "Scans files (recursively). With `record`, the inventory keeps it."
        );
        assert_eq!(without_result("No result."), "No result.");
        assert_eq!(
            first_sentence(without_result(doc)),
            "Scans files (recursively)."
        );
        // A full stop inside parentheses or a code span does not end the sentence.
        assert_eq!(
            first_sentence("Which files (a name, ...). Then more."),
            "Which files (a name, ...)."
        );
        assert_eq!(
            first_sentence("Use `C:\\.` here. More."),
            "Use `C:\\.` here."
        );
        assert_eq!(first_sentence("No full stop"), "No full stop");
    }

    #[test]
    fn a_reference_is_replaced_by_what_it_points_at() {
        let Value::Object(components) = json!({
            "A": {"type": "object", "properties": {"b": {"$ref": "#/components/schemas/B"}}},
            "B": {"type": "string", "description": "b"},
            "Loop": {"properties": {"again": {"$ref": "#/components/schemas/Loop"}}},
        }) else {
            panic!("not an object");
        };
        let top = json!({"$ref": "#/components/schemas/A", "description": "own"});
        assert_eq!(
            inline(&top, &components),
            json!({
                "type": "object",
                "properties": {"b": {"type": "string", "description": "b"}},
                "description": "own",
            })
        );
        // A schema that contains itself is cut where it meets itself.
        let looped = inline(&json!({"$ref": "#/components/schemas/Loop"}), &components);
        assert_eq!(
            looped,
            json!({"properties": {"again": {"$ref": "#/components/schemas/Loop"}}})
        );
        assert_eq!(
            references(&top).into_iter().collect::<Vec<_>>(),
            ["A".to_owned()]
        );
    }

    #[test]
    fn the_same_contract_has_the_same_name_in_any_key_order() {
        let a = json!({"x": [1, {"b": 2, "a": 1}], "y": null});
        let b = json!({"y": null, "x": [1, {"a": 1, "b": 2}]});
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(canonical(&a), r#"{"x":[1,{"a":1,"b":2}],"y":null}"#);
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&a).len(), 16);
        assert!(fingerprint(&a).chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(fingerprint(&a), fingerprint(&json!({"x": []})));
    }

    #[test]
    fn an_example_has_what_is_required_and_what_brings_its_own() {
        let Value::Object(components) = json!({
            "Mode": {"type": "string", "enum": ["json", "csv"]},
        }) else {
            panic!("not an object");
        };
        let body = json!({
            "type": "object",
            "properties": {
                "texts": {"type": "array", "items": {"type": "string"}, "examples": [["a"]]},
                "paths": {"type": "array", "items": {"type": "string"}},
                "port": {"type": "integer", "minimum": 1},
                "mode": {"$ref": "#/components/schemas/Mode"},
                "on": {"type": ["boolean", "null"]},
                "confirm": {"type": "boolean", "default": false, "examples": [true]},
                "optional": {"type": "string"},
            },
            "required": ["texts", "paths", "port", "mode", "on"],
        });
        assert_eq!(
            example(&body, &components),
            json!({
                "texts": ["a"],
                "paths": ["string"],
                "port": 1,
                "mode": "json",
                "on": false,
                "confirm": true,
            })
        );
    }
}
