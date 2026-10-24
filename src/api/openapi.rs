//! The reference of the API, generated from the code: [`spec`] is an `OpenAPI` 3.1 document and
//! [`markdown`] the same facts as a page for GitHub. `docs/api` holds both, and the page of
//! Scalar that the project site publishes.
//!
//! No operation is described by hand. The fields of each request and each result come from the
//! `JsonSchema` derives on [`Request`] and the types of [`reply`] (which follow their serde
//! attributes), the descriptions from their doc comments, the examples from the `examples` of
//! their fields, and the statuses from [`http`]. Which type each operation answers with is the
//! match in `route`, which the compiler keeps complete.
//!
//! What a person wrote on top lives in `docs/api/prose.toml`: a text per operation and one for the
//! introduction, merged into the descriptions. Each text carries the fingerprint of the generated
//! contract it was reviewed against (the request, the result and the doc comment of its
//! operation), so a change of that contract flags the text until it is read and accepted again:
//! see [`review`] and [`accept`].
//!
//! `cargo api-docs` (`examples/api_docs.rs`) writes the two generated files; a test fails when
//! they differ from what [`generate`] makes of the code.

mod intro;
mod markdown;
mod prose;
mod schema;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, fmt};

use schemars::{
    JsonSchema, Schema, SchemaGenerator,
    generate::{Contract, SchemaSettings},
    json_schema,
};
use serde_json::{Map, Value, json};

pub use self::prose::{PROSE_PATH, Prose};
use super::{ApiError, Request, http, reply};
use crate::{
    inventory::Totals,
    policy::{DEFAULT_HTTP_PORT, Policy},
};

/// Where the project site publishes the reference.
pub const REFERENCE_URL: &str = "https://tblggamin.github.io/piikey/";
/// The `OpenAPI` document in the repository.
pub const SPEC_PATH: &str = "docs/api/openapi.json";
/// The page for GitHub in the repository.
pub const MARKDOWN_PATH: &str = "docs/api/README.md";

/// The named pipe, as the reference spells it: `service::default_pipe` for the Windows user.
const PIPE: &str = r"\\.\pipe\piikey-<USERNAME>";

/// Why the reference could not be made, or the prose could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocsError(String);

impl DocsError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for DocsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DocsError {}

/// The `OpenAPI` document, with the prose of `docs/api/prose.toml` merged into its descriptions.
///
/// # Errors
/// An operation whose example is no request (a new field without `examples` that the type needs),
/// which a test of this module catches.
pub fn spec() -> Result<Value, DocsError> {
    Ok(assemble(&Model::build()?, &embedded()?))
}

/// [`spec`] as the text of `docs/api/openapi.json`: pretty-printed, with a final line break.
///
/// # Errors
/// As [`spec`].
pub fn spec_json() -> Result<String, DocsError> {
    pretty(&spec()?)
}

/// The Markdown page of `docs/api/README.md`, with the prose merged in.
///
/// # Errors
/// As [`spec`].
pub fn markdown() -> Result<String, DocsError> {
    Ok(markdown::render(&Model::build()?, &embedded()?))
}

/// Both generated files, as the text they are written as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// `docs/api/openapi.json`.
    pub openapi: String,
    /// `docs/api/README.md`.
    pub markdown: String,
}

/// The two generated files for the code, with the prose of `prose` (the text of `prose.toml`)
/// merged in. `cargo api-docs` reads the file from disk, so a change of it counts at once.
///
/// # Errors
/// The prose is not valid, or as [`spec`].
pub fn generate(prose: &str) -> Result<Reference, DocsError> {
    let prose = Prose::parse(prose)?;
    let model = Model::build()?;
    Ok(Reference {
        openapi: pretty(&assemble(&model, &prose))?,
        markdown: markdown::render(&model, &prose),
    })
}

/// What [`review`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// One line per problem: prose whose contract changed since it was reviewed, and prose for
    /// something that is no operation.
    pub problems: Vec<String>,
    /// The operations that have no prose. Allowed: not a problem.
    pub missing: Vec<String>,
}

/// Compares the prose (the text of `prose.toml`) with the contracts of the code.
///
/// # Errors
/// The prose is not valid, or as [`spec`].
pub fn review(prose: &str) -> Result<Review, DocsError> {
    let prose = Prose::parse(prose)?;
    let current = Model::build()?.fingerprints();
    let mut problems = Vec::new();
    let mut missing = Vec::new();
    for name in std::iter::once("intro").chain(Request::OPS) {
        let Some(now) = current.get(name) else {
            continue;
        };
        match prose.reviewed(name) {
            Some(reviewed) if reviewed != now.as_str() && name == "intro" => problems.push(format!(
                "the intro changed since its prose was reviewed (the envelope, the error codes, the auth rules or the server): read {PROSE_PATH} [intro], then run `cargo api-docs --accept intro`"
            )),
            Some(reviewed) if reviewed != now.as_str() => problems.push(format!(
                "op `{name}` changed since its prose was reviewed: read {PROSE_PATH} [{name}], then run `cargo api-docs --accept {name}`"
            )),
            None if name != "intro" => missing.push(name.to_owned()),
            _ => {}
        }
    }
    for name in prose.names().filter(|name| !current.contains_key(*name)) {
        problems.push(format!(
            "prose for `{name}`, which is no operation: remove [{name}] from {PROSE_PATH}"
        ));
    }
    Ok(Review { problems, missing })
}

/// The text of `prose.toml` with the fingerprint of `which` (an operation, `intro` or `all`)
/// brought up to date: what the prose was reviewed against is now the current contract. The text
/// of the prose and everything else in the file stay as they are.
///
/// # Errors
/// The prose is not valid, `which` names no operation and has no table, or as [`spec`].
pub fn accept(prose: &str, which: &str) -> Result<String, DocsError> {
    let parsed = Prose::parse(prose)?;
    let current = Model::build()?.fingerprints();
    let names: Vec<&str> = if which == "all" {
        parsed
            .names()
            .filter(|name| current.contains_key(*name))
            .collect()
    } else if !current.contains_key(which) {
        return Err(DocsError::new(format!(
            "`{which}` is no operation (use an operation, `intro` or `all`)"
        )));
    } else if parsed.reviewed(which).is_none() {
        return Err(DocsError::new(format!(
            "{PROSE_PATH} has no table [{which}] to accept"
        )));
    } else {
        vec![which]
    };
    let stamps: Vec<(&str, &str)> = names
        .into_iter()
        .filter_map(|name| current.get(name).map(|now| (name, now.as_str())))
        .collect();
    parsed.restamp(prose, &stamps)
}

/// The prose that the library carries, for the document the app serves.
fn embedded() -> Result<Prose, DocsError> {
    Prose::parse(include_str!("../../docs/api/prose.toml"))
}

/// `value` as pretty JSON with a final line break.
fn pretty(value: &Value) -> Result<String, DocsError> {
    let mut text = serde_json::to_string_pretty(value)
        .map_err(|error| DocsError::new(format!("the document cannot be written: {error}")))?;
    text.push('\n');
    Ok(text)
}

/// `text` followed by the prose that goes with it, if there is any.
fn describe(text: &str, prose: Option<&str>) -> String {
    match prose {
        Some(prose) => format!("{text}\n\n{prose}"),
        None => text.to_owned(),
    }
}

/// The groups the operations are listed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Text,
    Files,
    Subject,
    Vault,
    Inventory,
    Accounts,
    Settings,
    Model,
    App,
}

impl Tag {
    const ALL: [Self; 9] = [
        Self::Text,
        Self::Files,
        Self::Subject,
        Self::Vault,
        Self::Inventory,
        Self::Accounts,
        Self::Settings,
        Self::Model,
        Self::App,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Files => "Files",
            Self::Subject => "Subject search",
            Self::Vault => "Vault",
            Self::Inventory => "Inventory",
            Self::Accounts => "Accounts",
            Self::Settings => "Settings",
            Self::Model => "Model",
            Self::App => "App",
        }
    }

    const fn about(self) -> &'static str {
        match self {
            Self::Text => "Find, mask and restore personal data in texts.",
            Self::Files => "The same for files and folders.",
            Self::Subject => "Find the files that mention a person, for access requests.",
            Self::Vault => "The values piikey swapped, and the stand-ins it issued for them.",
            Self::Inventory => {
                "What the scans found in your locations: counts and paths, never the values."
            }
            Self::Accounts => "The cloud accounts piikey may read.",
            Self::Settings => {
                "What piikey is set to, the types of personal data, and the API token."
            }
            Self::Model => "The detection model.",
            Self::App => "How piikey is doing, and what only the running app can do.",
        }
    }
}

/// What the reference knows of an operation besides its fields: where it is listed, what it is
/// called, and what its `result` is.
struct Route {
    tag: Tag,
    title: &'static str,
    result: fn(&mut SchemaGenerator) -> Schema,
}

impl Route {
    /// An operation whose `result` is a `T`.
    fn of<T: JsonSchema>(tag: Tag, title: &'static str) -> Self {
        Self {
            tag,
            title,
            result: |generator| generator.subschema_for::<T>(),
        }
    }

    /// An operation with nothing to report: its `result` is `{}`.
    fn nothing(tag: Tag, title: &'static str) -> Self {
        fn empty(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "object",
                "description": "Nothing to report: an empty object, `{}`.",
                "additionalProperties": false
            })
        }
        Self {
            tag,
            title,
            result: empty,
        }
    }
}

/// Where each operation is listed, and what it answers with. The match has no catch-all arm, so
/// an operation added to [`Request`] does not compile until it is here.
fn route(request: &Request) -> Route {
    match request {
        Request::ScanText { .. } => Route::of::<reply::Spans>(Tag::Text, "Scan text"),
        Request::Anonymize { .. } => Route::of::<reply::Texts>(Tag::Text, "Mask text"),
        Request::Deanonymize { .. } => Route::of::<reply::Texts>(Tag::Text, "Restore text"),
        Request::ScanFiles { .. } => Route::of::<reply::Scanned>(Tag::Files, "Scan files"),
        Request::AnonymizeFiles { .. } => Route::of::<reply::Written>(Tag::Files, "Mask files"),
        Request::DeanonymizeFiles { .. } => {
            Route::of::<reply::Written>(Tag::Files, "Restore files")
        }
        Request::SubjectSearch { .. } => {
            Route::of::<reply::Found>(Tag::Subject, "Search for a person")
        }
        Request::VaultList { .. } => Route::of::<reply::Records>(Tag::Vault, "List the vault"),
        Request::VaultForget { .. } => Route::of::<reply::Forgotten>(Tag::Vault, "Forget values"),
        Request::VaultExport { .. } => Route::of::<reply::Exported>(Tag::Vault, "Export the vault"),
        Request::VaultWipe { .. } => Route::of::<reply::Forgotten>(Tag::Vault, "Wipe the vault"),
        Request::InventoryStatus => {
            Route::of::<reply::InventoryStatus>(Tag::Inventory, "Inventory status")
        }
        Request::InventoryList { .. } => {
            Route::of::<reply::Entries>(Tag::Inventory, "List files with personal data")
        }
        Request::InventoryTree { .. } => {
            Route::of::<reply::Nodes>(Tag::Inventory, "Browse the tree")
        }
        Request::InventoryRescan => Route::of::<Totals>(Tag::Inventory, "Scan the locations"),
        Request::InventoryReport { .. } => {
            Route::of::<reply::Reported>(Tag::Inventory, "Write a report")
        }
        Request::SettingsGet => Route::of::<Policy>(Tag::Settings, "Read the settings"),
        Request::SettingsSet { .. } => Route::of::<Policy>(Tag::Settings, "Change the settings"),
        Request::AccountsList => {
            Route::of::<reply::Accounts>(Tag::Accounts, "List the cloud accounts")
        }
        Request::AccountAdd { .. } => {
            Route::of::<reply::AccountInfo>(Tag::Accounts, "Add a cloud account")
        }
        Request::AccountConnect { .. } => {
            Route::of::<reply::AccountInfo>(Tag::Accounts, "Sign in to a cloud account")
        }
        Request::AccountRemove { .. } => {
            Route::of::<reply::AccountRemoved>(Tag::Accounts, "Remove a cloud account")
        }
        Request::AccountBrowse { .. } => {
            Route::of::<reply::Folders>(Tag::Accounts, "Browse a cloud account")
        }
        Request::Kinds => {
            Route::of::<Vec<reply::Kind>>(Tag::Settings, "List the types of personal data")
        }
        Request::ModelStatus => Route::of::<reply::Model>(Tag::Model, "Detection model status"),
        Request::ModelDownload => Route::nothing(Tag::Model, "Download the detection model"),
        Request::ApiToken { .. } => Route::of::<reply::Token>(Tag::Settings, "Get the API token"),
        Request::Status => Route::of::<reply::Status>(Tag::App, "Status"),
        Request::Protection { .. } => Route::of::<reply::Protection>(Tag::App, "Switch protection"),
        Request::ExplorerScan { .. } => Route::nothing(Tag::App, "Scan from Explorer"),
        Request::ShowWindow => Route::nothing(Tag::App, "Show the window"),
    }
}

/// What the reference says of one operation.
struct Operation {
    name: &'static str,
    route: Route,
    /// The doc comment of the variant of [`Request`], whole.
    doc: String,
    /// The doc comment without its closing `Result:` sentence.
    description: String,
    /// The fields of the request as an object schema; `None` for an operation that takes none.
    body: Option<Value>,
    /// A request body that the operation takes.
    example: Value,
    /// The schema of the `result` of the reply.
    result: Value,
}

/// Everything the generated files say, made from the code.
struct Model {
    /// The schemas of `components/schemas`, by name.
    components: Map<String, Value>,
    /// The operations, in the order of `Request::OPS`.
    operations: Vec<Operation>,
    /// How a call can end badly.
    endings: Vec<intro::Ending>,
}

impl Model {
    fn build() -> Result<Self, DocsError> {
        let mut requests = generator(Contract::Deserialize);
        requests.subschema_for::<Request>();
        let mut components = requests.take_definitions(false);
        let request = components
            .shift_remove("Request")
            .ok_or_else(|| DocsError::new("the schemas have no `Request`"))?;
        let variants = variants(&request)?;

        let mut replies = generator(Contract::Serialize);
        let mut operations = Vec::with_capacity(Request::OPS.len());
        for name in Request::OPS {
            let variant = variants.get(name).ok_or_else(|| {
                DocsError::new(format!("the schema of `Request` has no variant `{name}`"))
            })?;
            operations.push(operation(name, variant, &components, &mut replies)?);
        }

        let error = replies.subschema_for::<ApiError>().to_value();
        for (name, schema) in replies.take_definitions(false) {
            match components.get(&name) {
                Some(taken) if *taken != schema => {
                    return Err(DocsError::new(format!(
                        "`{name}` is a different schema in a request than in a reply: give one of them another name"
                    )));
                }
                _ => {
                    components.insert(name, schema);
                }
            }
        }
        components.insert("Failure".to_owned(), failure(&error));

        for schema in components.values_mut() {
            tidy_descriptions(schema);
            name_values(schema);
        }
        let mut sorted: Vec<(String, Value)> = components.into_iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let components: Map<String, Value> = sorted.into_iter().collect();

        let endings = intro::endings(&components);
        Ok(Self {
            components,
            operations,
            endings,
        })
    }

    /// The fingerprint of the contract of each operation, and of the intro, by name.
    fn fingerprints(&self) -> BTreeMap<String, String> {
        let mut found = BTreeMap::new();
        let failure = self
            .components
            .get("Failure")
            .map_or(Value::Null, |failure| {
                schema::inline(failure, &self.components)
            });
        found.insert(
            "intro".to_owned(),
            schema::fingerprint(&intro::contract(&self.endings, &failure)),
        );
        for op in &self.operations {
            let methods: &[&str] = if http::allows_get(op.name) {
                &["GET", "POST"]
            } else {
                &["POST"]
            };
            let contract = json!({
                "doc": op.doc,
                "methods": methods,
                "request": op.body.as_ref().map(|body| schema::inline(body, &self.components)),
                "result": schema::inline(&op.result, &self.components),
            });
            found.insert(op.name.to_owned(), schema::fingerprint(&contract));
        }
        found
    }
}

/// A generator of schemas that refer to each other as `components/schemas` entries do, for a
/// request (what is deserialized) or a reply (what is serialized).
fn generator(contract: Contract) -> SchemaGenerator {
    SchemaSettings::draft2020_12()
        .with(|settings| {
            settings.definitions_path = "/components/schemas".into();
            settings.meta_schema = None;
            settings.contract = contract;
        })
        .into_generator()
}

/// The schema of each variant of `Request` by the name of its operation.
fn variants(request: &Value) -> Result<BTreeMap<String, Value>, DocsError> {
    let list = request
        .get("oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| DocsError::new("the schema of `Request` is not a list of variants"))?;
    list.iter()
        .map(|variant| {
            let name = variant
                .pointer("/properties/op/const")
                .and_then(Value::as_str)
                .ok_or_else(|| DocsError::new("a variant of `Request` has no `op`"))?;
            Ok((name.to_owned(), variant.clone()))
        })
        .collect()
}

/// The fields of a request without its `op`, as an object schema; `None` when it has none.
fn body_of(variant: &Value) -> Option<Value> {
    let mut fields = variant.as_object()?.clone();
    fields.shift_remove("description");
    let properties = fields.get_mut("properties")?.as_object_mut()?;
    properties.shift_remove("op");
    if properties.is_empty() {
        return None;
    }
    let none_required = match fields.get_mut("required") {
        Some(Value::Array(required)) => {
            required.retain(|name| name != "op");
            required.is_empty()
        }
        _ => false,
    };
    if none_required {
        fields.shift_remove("required");
    }
    Some(Value::Object(fields))
}

/// What the reference says of the operation `name`, whose variant of `Request` is `variant`.
/// The `result` is made by `replies`. The example must be a request: a field the type needs and
/// that has no `examples` is spotted here.
fn operation(
    name: &'static str,
    variant: &Value,
    components: &Map<String, Value>,
    replies: &mut SchemaGenerator,
) -> Result<Operation, DocsError> {
    let doc = schema::tidy(
        variant
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let mut body = body_of(variant);
    let example = body
        .as_ref()
        .map_or_else(|| json!({}), |body| schema::example(body, components));
    let mut request = Map::new();
    request.insert("op".to_owned(), Value::from(name));
    if let Value::Object(fields) = &example {
        request.extend(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    let request: Request = serde_json::from_value(Value::Object(request)).map_err(|error| {
        DocsError::new(format!(
            "the example of `{name}` is no request ({error}): give the fields it needs `examples`"
        ))
    })?;
    let route = route(&request);
    let mut result = (route.result)(replies).to_value();
    if let Some(body) = &mut body {
        tidy_descriptions(body);
        name_values(body);
    }
    tidy_descriptions(&mut result);
    name_values(&mut result);
    Ok(Operation {
        name,
        route,
        description: schema::without_result(&doc).to_owned(),
        doc,
        body,
        example,
        result,
    })
}

/// The schema of a failed reply: `ok` is `false` and `error` says what failed.
fn failure(error: &Value) -> Value {
    json!({
        "type": "object",
        "description": "The reply of a call that failed.",
        "properties": {
            "ok": {"type": "boolean", "const": false, "description": "Always `false`."},
            "error": error,
        },
        "required": ["ok", "error"],
        "additionalProperties": false,
    })
}

/// The schema of a reply that worked: `ok` is `true` and `result` is `result`.
fn success(result: &Value) -> Value {
    json!({
        "type": "object",
        "description": "The reply of a call that worked.",
        "properties": {
            "ok": {"type": "boolean", "const": true, "description": "Always `true`."},
            "result": result,
        },
        "required": ["ok", "result"],
        "additionalProperties": false,
    })
}

/// Every `description` in `schema` as [`schema::tidy`] makes it.
fn tidy_descriptions(schema: &mut Value) {
    match schema {
        Value::Object(fields) => {
            for (key, field) in fields.iter_mut() {
                match field {
                    Value::String(text) if key == "description" => *text = schema::tidy(text),
                    other => tidy_descriptions(other),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(tidy_descriptions),
        _ => {}
    }
}

/// Every list of named values that schemars made a `oneOf` of constants, as the list of what the
/// values are and one description of each (`enum` and `x-enumDescriptions`): the form that
/// Scalar, Postman and the code generators know.
fn name_values(schema: &mut Value) {
    match schema {
        Value::Object(fields) => {
            if let Some(named) = values_of(fields) {
                fields.shift_remove("oneOf");
                fields.insert("type".to_owned(), Value::from("string"));
                fields.insert("enum".to_owned(), Value::Array(named.0));
                fields.insert("x-enumDescriptions".to_owned(), Value::Object(named.1));
            }
            fields.values_mut().for_each(name_values);
        }
        Value::Array(items) => items.iter_mut().for_each(name_values),
        _ => {}
    }
}

/// The values and what each means, when `fields` is a `oneOf` of constants and nothing else.
fn values_of(fields: &Map<String, Value>) -> Option<(Vec<Value>, Map<String, Value>)> {
    let all = fields.get("oneOf")?.as_array()?;
    let mut values = Vec::with_capacity(all.len());
    let mut meanings = Map::new();
    for one in all {
        let one = one.as_object()?;
        let value = one.get("const")?.as_str()?;
        if one
            .keys()
            .any(|key| !matches!(key.as_str(), "const" | "type" | "description" | "title"))
        {
            return None;
        }
        values.push(Value::from(value));
        let meaning = one.get("description").or_else(|| one.get("title"))?;
        meanings.insert(value.to_owned(), meaning.clone());
    }
    Some((values, meanings))
}

/// The whole `OpenAPI` document.
fn assemble(model: &Model, prose: &Prose) -> Value {
    let port = DEFAULT_HTTP_PORT.to_string();
    let tags: Vec<Value> = Tag::ALL
        .iter()
        .map(|tag| json!({"name": tag.name(), "description": tag.about()}))
        .collect();
    let responses: Map<String, Value> = intro::RESPONSES
        .iter()
        .map(|&(status, name)| (name.to_owned(), intro::response(status, &model.endings)))
        .collect();
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "piikey API",
            "version": env!("CARGO_PKG_VERSION"),
            "summary": "One local JSON API for the piikey app, scripts and the command line.",
            "description": intro::text(&model.endings, prose.text("intro")),
            "license": {"name": env!("CARGO_PKG_LICENSE"), "identifier": env!("CARGO_PKG_LICENSE")},
        },
        "servers": [{
            "url": "http://127.0.0.1:{port}",
            "description": "The local HTTP API of the app, on this PC only. Settings > Developer access switches it on.",
            "variables": {"port": {
                "default": port,
                "description": "The port set in Settings > Developer access.",
            }},
        }],
        "tags": tags,
        "security": [{"bearerAuth": []}],
        "paths": paths(model, prose),
        "components": {
            "securitySchemes": {"bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "The token that `piikey-cli token` prints, and that Settings > Developer access copies.",
            }},
            "responses": responses,
            "schemas": model.components,
        },
    })
}

/// The path of each operation, and that of this document.
fn paths(model: &Model, prose: &Prose) -> Value {
    let mut paths = Map::new();
    for op in &model.operations {
        let mut item = Map::new();
        if http::allows_get(op.name) {
            item.insert("get".to_owned(), call(prose, op, true));
        }
        item.insert("post".to_owned(), call(prose, op, false));
        paths.insert(format!("/v1/{}", op.name), Value::Object(item));
    }
    paths.insert(
        intro::SPEC_ROUTE.to_owned(),
        json!({"get": {
            "tags": [Tag::App.name()],
            "summary": "This reference",
            "description": "This spec. The only call that needs no token: it holds nothing that is not public.",
            "operationId": "openapi",
            "security": [],
            "responses": {
                "200": {
                    "description": "The OpenAPI 3.1 document, as JSON.",
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                "403": {"$ref": "#/components/responses/Forbidden"},
                "405": {"$ref": "#/components/responses/MethodNotAllowed"},
            },
        }}),
    );
    Value::Object(paths)
}

/// One way to call `op`: `GET` (which has no body) or `POST`.
fn call(prose: &Prose, op: &Operation, get: bool) -> Value {
    let mut call = Map::new();
    call.insert("tags".to_owned(), json!([op.route.tag.name()]));
    call.insert("summary".to_owned(), Value::from(op.route.title));
    call.insert(
        "description".to_owned(),
        Value::from(describe(&op.description, prose.text(op.name))),
    );
    call.insert(
        "operationId".to_owned(),
        Value::from(if get {
            format!("{}_get", op.name)
        } else {
            op.name.to_owned()
        }),
    );
    if let (Some(body), false) = (&op.body, get) {
        let required = body.get("required").is_some();
        call.insert(
            "requestBody".to_owned(),
            json!({
                "required": required,
                "content": {"application/json": {"schema": body, "example": op.example}},
            }),
        );
    }
    let mut responses = Map::new();
    responses.insert(
        "200".to_owned(),
        json!({
            "description": "The call worked: `result` is what the operation answers with.",
            "content": {"application/json": {"schema": success(&op.result)}},
        }),
    );
    for (status, name) in intro::RESPONSES {
        responses.insert(
            status.to_string(),
            json!({"$ref": format!("#/components/responses/{name}")}),
        );
    }
    call.insert("responses".to_owned(), Value::Object(responses));
    Value::Object(call)
}
