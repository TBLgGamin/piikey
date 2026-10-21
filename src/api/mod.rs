//! The API: one request type, one reply envelope, three ways in.
//!
//! Everything piikey does for a program or a script is a [`Request`]. The answer is a JSON value,
//! or an [`ApiError`]. The same requests reach a [`Handler`] three ways:
//!
//! - in process, through [`Local`] (the command line when the app is not running, and
//!   `piikey-cli serve`);
//! - over the named pipe `\\.\pipe\piikey-<user>` ([`crate::service`]), which the app and
//!   `piikey-cli serve` listen on and the command line tries first;
//! - over HTTP on `127.0.0.1` ([`http`]), when the user turns the local API on.
//!
//! A request is a JSON object whose `op` names the operation, `{"op":"scan_text","texts":["a"]}`.
//! Over HTTP the op is the last part of the path (`POST /v1/scan_text`) and the body holds the
//! other fields. An op refuses fields it does not know (the ops that take no fields at all
//! ignore any).
//!
//! The reply is an envelope, `{"ok":true,"result":<value>}` or
//! `{"ok":false,"error":{"code":"<code>","message":"..."}}`; see [`envelope`]. The codes are
//! `bad_request`, `app_required`, `not_found`, `busy`, `io`, `vault`, `unsupported`, `model` and
//! `internal`.
//!
//! Paths in a request are absolute: the answering process may not be the one the request came
//! from, and a relative path would mean its working folder. Offsets of text spans are UTF-8
//! byte offsets.

pub mod http;
mod local;

use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::local::{EngineSource, Local, read_or_create_token, token_path};
use crate::{Error, policy::SettingsPatch, vault::ExportFormat};

/// How an export or a report is written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// A JSON array with one object per row.
    #[default]
    Json,
    /// RFC 4180 CSV with a header row.
    Csv,
}

impl From<Format> for ExportFormat {
    fn from(format: Format) -> Self {
        match format {
            Format::Json => Self::Json,
            Format::Csv => Self::Csv,
        }
    }
}

fn yes() -> bool {
    true
}

/// One operation and what it needs. The doc of each variant says what the reply's `result`
/// holds.
///
/// `Debug` shows the op and nothing else: texts, values and queries are personal data and must
/// not end up in a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// What the detector finds in each text, without changing anything (the vault is left as it
    /// is, and stand-ins piikey issued are not counted). Result:
    /// `{"results":[[{"start","end","kind","value"}]]}`, one list per text; `start` and `end`
    /// are UTF-8 byte offsets.
    ScanText { texts: Vec<String> },
    /// Masks the personal data in each text. Result: `{"texts":[..]}`.
    Anonymize { texts: Vec<String> },
    /// Restores the masked values in each text. With `tolerant`, also stand-ins that came back
    /// with a typo and names that came back alone. Result: `{"texts":[..]}`.
    Deanonymize {
        texts: Vec<String>,
        #[serde(default)]
        tolerant: bool,
    },
    /// Scans files and folders (recursively). With `record`, what was found is also kept in
    /// the inventory. Result: `{"files":[{"path","size","modified","scanned","status","error"?,
    /// "hits","counts":{kind:n}}],"hits":n}`.
    ScanFiles {
        paths: Vec<PathBuf>,
        #[serde(default = "yes")]
        record: bool,
    },
    /// Masks files and folders into the folder `out`. Result:
    /// `{"written":[{"input","output"}],"failed":[{"input","error"}]}`.
    AnonymizeFiles { paths: Vec<PathBuf>, out: PathBuf },
    /// Restores files and folders into the folder `out`. Result as for `anonymize_files`.
    DeanonymizeFiles {
        paths: Vec<PathBuf>,
        out: PathBuf,
        #[serde(default)]
        tolerant: bool,
    },
    /// Which files hold the given values (a name, a phone number, an email address, ...); an
    /// empty `paths` means the inventory's folders. Result:
    /// `{"matches":[{"path","values":[index],"count"}]}`.
    SubjectSearch {
        values: Vec<String>,
        #[serde(default)]
        paths: Vec<PathBuf>,
    },
    /// The vault's records, the newest first, whose original or stand-in holds `query` (any
    /// letter case; all of them without a query), of one kind if `kind` says. `limit` is 100
    /// unless given, at most 10,000. Result: `{"records":[{"kind","original","proxy"}],"total":n}`,
    /// where `total` counts every match, not only the page.
    VaultList {
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        #[serde(default)]
        offset: usize,
    },
    /// Removes the records whose original or stand-in is one of `values`; the vault file is
    /// rewritten without them. Result: `{"forgotten":n}`.
    VaultForget { values: Vec<String> },
    /// Writes every record of the vault to a new file `path` (an existing file is an error).
    /// Result: `{"records":n,"path"}`.
    VaultExport {
        path: PathBuf,
        #[serde(default)]
        format: Format,
    },
    /// Removes every record of the vault; the key stays. Needs `confirm: true`. Result:
    /// `{"forgotten":n}`.
    VaultWipe {
        #[serde(default)]
        confirm: bool,
    },
    /// The inventory in numbers. Result:
    /// `{"enabled","roots":[..],"files","files_with_pii","hits","scanning":{"done","total"}|null}`.
    InventoryStatus,
    /// The inventory's files that hold personal data, the one with the most first, at and
    /// under `under`. Result: `{"entries":[..],"total":n}`, entries shaped as in `scan_files`.
    InventoryList {
        #[serde(skip_serializing_if = "Option::is_none")]
        under: Option<PathBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        #[serde(default)]
        offset: usize,
    },
    /// The treemap's tiles at one level: what lies directly under `under`, or the watched
    /// folders without it. Result: `{"nodes":[{"path","name","is_dir","hits","files","counts"}]}`.
    InventoryTree {
        #[serde(skip_serializing_if = "Option::is_none")]
        under: Option<PathBuf>,
    },
    /// Scans the inventory's folders now. Result: `{"files","files_with_pii","hits"}`.
    InventoryRescan,
    /// Writes the inventory's findings to a new file `path`. Result: `{"rows":n,"path"}`.
    InventoryReport {
        path: PathBuf,
        #[serde(default)]
        format: Format,
    },
    /// The saved settings. Result: the settings as an object, see `Policy`.
    SettingsGet,
    /// Changes the given settings, validated as a whole. Result: the settings as saved.
    SettingsSet { settings: SettingsPatch },
    /// Every kind of personal data. Result: `[{"kind","label","group","enabled"}]`.
    Kinds,
    /// Where the detection model stands. Result:
    /// `{"state":"missing"|"unloaded"|"ready"|"failed","device":"cpu"|"hybrid"|null,"error"?,"dir"}`.
    ModelStatus,
    /// Downloads the detection model. Result: `{}`.
    ModelDownload,
    /// The token the HTTP API wants as `Authorization: Bearer <token>`; `rotate` makes a new
    /// one first. Result: `{"token"}`.
    ApiToken {
        #[serde(default)]
        rotate: bool,
    },
    /// How piikey is doing. Result:
    /// `{"app","protection","version","vault_records","model","highlight","explorer_menu",
    /// "inventory","http_api"}`; `protection` is `null` when the app is not running.
    Status,
    /// Switches protection (masking what goes to the protected sites and programs) on or off.
    /// Needs the app.
    Protection { on: bool },
    /// Scans files and folders as Explorer's "Scan for PII" does and shows the result in the
    /// app. Needs the app.
    ExplorerScan { paths: Vec<PathBuf> },
}

impl Request {
    /// The names of all ops, as they are spelled in `op` and in HTTP paths.
    pub const OPS: [&'static str; 25] = [
        "scan_text",
        "anonymize",
        "deanonymize",
        "scan_files",
        "anonymize_files",
        "deanonymize_files",
        "subject_search",
        "vault_list",
        "vault_forget",
        "vault_export",
        "vault_wipe",
        "inventory_status",
        "inventory_list",
        "inventory_tree",
        "inventory_rescan",
        "inventory_report",
        "settings_get",
        "settings_set",
        "kinds",
        "model_status",
        "model_download",
        "api_token",
        "status",
        "protection",
        "explorer_scan",
    ];

    /// This request's op, one of [`Request::OPS`].
    #[must_use]
    pub const fn op(&self) -> &'static str {
        match self {
            Self::ScanText { .. } => "scan_text",
            Self::Anonymize { .. } => "anonymize",
            Self::Deanonymize { .. } => "deanonymize",
            Self::ScanFiles { .. } => "scan_files",
            Self::AnonymizeFiles { .. } => "anonymize_files",
            Self::DeanonymizeFiles { .. } => "deanonymize_files",
            Self::SubjectSearch { .. } => "subject_search",
            Self::VaultList { .. } => "vault_list",
            Self::VaultForget { .. } => "vault_forget",
            Self::VaultExport { .. } => "vault_export",
            Self::VaultWipe { .. } => "vault_wipe",
            Self::InventoryStatus => "inventory_status",
            Self::InventoryList { .. } => "inventory_list",
            Self::InventoryTree { .. } => "inventory_tree",
            Self::InventoryRescan => "inventory_rescan",
            Self::InventoryReport { .. } => "inventory_report",
            Self::SettingsGet => "settings_get",
            Self::SettingsSet { .. } => "settings_set",
            Self::Kinds => "kinds",
            Self::ModelStatus => "model_status",
            Self::ModelDownload => "model_download",
            Self::ApiToken { .. } => "api_token",
            Self::Status => "status",
            Self::Protection { .. } => "protection",
            Self::ExplorerScan { .. } => "explorer_scan",
        }
    }
}

// Only the op: the fields are the user's texts, values and file names.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("op", &self.op())
            .finish_non_exhaustive()
    }
}

/// Every code of an [`ApiError`].
const CODES: [&str; 9] = [
    "bad_request",
    "app_required",
    "not_found",
    "busy",
    "io",
    "vault",
    "unsupported",
    "model",
    "internal",
];

/// Why a request failed: a code a program can act on, and a message for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The request is wrong: a bad value, a missing confirmation, a path that is not absolute.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }

    /// The request needs the piikey app to be running.
    #[must_use]
    pub fn app_required(message: impl Into<String>) -> Self {
        Self::new("app_required", message)
    }

    /// There is no such op, file or record.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    /// What the request needs is in use: a scan that is already running.
    #[must_use]
    pub fn busy(message: impl Into<String>) -> Self {
        Self::new("busy", message)
    }

    /// Something went wrong that the request did not cause.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }

    /// One of `bad_request`, `app_required`, `not_found`, `busy`, `io`, `vault`, `unsupported`,
    /// `model` and `internal`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// What went wrong, for a person.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        let code = match &error {
            Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => "not_found",
            Error::Io(_) => "io",
            Error::Dpapi(_)
            | Error::VaultCorrupt { .. }
            | Error::VaultPathUnavailable
            | Error::ProxyExhausted { .. } => "vault",
            Error::UnsupportedFormat(_)
            | Error::Zip(_)
            | Error::Xml(_)
            | Error::Pdf(_)
            | Error::Ocr(_)
            | Error::Mail(_) => "unsupported",
            Error::Protocol(_) | Error::BadRequest(_) => "bad_request",
            Error::Model(_) => "model",
            Error::Busy(_) => "busy",
            Error::Tool(_) | Error::Poisoned => "internal",
        };
        Self::new(code, error.to_string())
    }
}

/// What answering a request gives.
///
/// Implemented by [`Local`] and by the app, which adds what only it can do (protection, Explorer
/// scans); the pipe ([`crate::service::spawn`]) and the HTTP API ([`http::spawn`]) serve any
/// handler. A call may take long (a scan of a big folder) and runs on a thread of its own.
pub trait Handler: Send + Sync {
    /// Answers `request`.
    ///
    /// # Errors
    /// An [`ApiError`] saying why not.
    fn handle(&self, request: Request) -> Result<Value, ApiError>;
}

/// A JSON object of `fields`, in the order given.
pub(crate) fn object<const N: usize>(fields: [(&'static str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// The envelope of a reply: `{"ok":true,"result":<value>}`, or
/// `{"ok":false,"error":{"code":"<code>","message":"..."}}`. This is what goes over the pipe
/// and what an HTTP reply carries as its body.
#[must_use]
pub fn envelope(reply: Result<Value, ApiError>) -> Value {
    match reply {
        Ok(result) => object([("ok", true.into()), ("result", result)]),
        Err(error) => object([
            ("ok", false.into()),
            (
                "error",
                object([
                    ("code", error.code.into()),
                    ("message", error.message.into()),
                ]),
            ),
        ]),
    }
}

/// The reply inside an [`envelope`]: the `result`, or the error. A value that is no envelope, or
/// an error with a code this version does not know, becomes an `internal` error.
///
/// # Errors
/// The envelope's error.
pub fn open_envelope(envelope: Value) -> Result<Value, ApiError> {
    let Value::Object(mut fields) = envelope else {
        return Err(ApiError::internal("the reply is not a piikey reply"));
    };
    match fields.get("ok") {
        Some(Value::Bool(true)) => Ok(fields.remove("result").unwrap_or(Value::Null)),
        Some(Value::Bool(false)) => {
            let error = fields.remove("error").unwrap_or(Value::Null);
            let code = error
                .get("code")
                .and_then(Value::as_str)
                .and_then(|code| CODES.iter().find(|known| **known == code))
                .copied()
                .unwrap_or("internal");
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Err(ApiError::new(code, message))
        }
        _ => Err(ApiError::internal("the reply is not a piikey reply")),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use serde_json::json;

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    /// One request of every op, each with only what it must have.
    fn samples() -> Vec<Request> {
        let path = || PathBuf::from(r"C:\data");
        vec![
            Request::ScanText { texts: vec![] },
            Request::Anonymize { texts: vec![] },
            Request::Deanonymize {
                texts: vec![],
                tolerant: false,
            },
            Request::ScanFiles {
                paths: vec![path()],
                record: true,
            },
            Request::AnonymizeFiles {
                paths: vec![path()],
                out: path(),
            },
            Request::DeanonymizeFiles {
                paths: vec![path()],
                out: path(),
                tolerant: false,
            },
            Request::SubjectSearch {
                values: vec!["Jan".into()],
                paths: vec![],
            },
            Request::VaultList {
                query: None,
                kind: None,
                limit: None,
                offset: 0,
            },
            Request::VaultForget { values: vec![] },
            Request::VaultExport {
                path: path(),
                format: Format::Json,
            },
            Request::VaultWipe { confirm: false },
            Request::InventoryStatus,
            Request::InventoryList {
                under: None,
                limit: None,
                offset: 0,
            },
            Request::InventoryTree { under: None },
            Request::InventoryRescan,
            Request::InventoryReport {
                path: path(),
                format: Format::Json,
            },
            Request::SettingsGet,
            Request::SettingsSet {
                settings: SettingsPatch::default(),
            },
            Request::Kinds,
            Request::ModelStatus,
            Request::ModelDownload,
            Request::ApiToken { rotate: false },
            Request::Status,
            Request::Protection { on: true },
            Request::ExplorerScan {
                paths: vec![path()],
            },
        ]
    }

    #[test]
    fn every_op_is_listed_once_and_named_as_it_serializes() -> TestResult {
        let samples = samples();
        assert_eq!(samples.len(), Request::OPS.len());
        for (sample, listed) in samples.iter().zip(Request::OPS) {
            assert_eq!(sample.op(), listed);
            let json = serde_json::to_value(sample)?;
            assert_eq!(json["op"], listed, "{listed}");
        }
        let mut sorted = Request::OPS;
        sorted.sort_unstable();
        assert!(sorted.windows(2).all(|pair| pair[0] != pair[1]));
        Ok(())
    }

    #[test]
    fn every_request_round_trips_through_json() -> TestResult {
        for sample in samples() {
            let wire = serde_json::to_vec(&sample)?;
            let back: Request = serde_json::from_slice(&wire)?;
            assert_eq!(back, sample, "{}", sample.op());
        }
        Ok(())
    }

    #[test]
    fn a_minimal_body_is_enough_and_defaults_apply() -> TestResult {
        let scan: Request = serde_json::from_str(r#"{"op":"scan_files","paths":["C:\\a"]}"#)?;
        assert_eq!(
            scan,
            Request::ScanFiles {
                paths: vec![PathBuf::from(r"C:\a")],
                record: true
            }
        );
        let wipe: Request = serde_json::from_str(r#"{"op":"vault_wipe"}"#)?;
        assert_eq!(wipe, Request::VaultWipe { confirm: false });
        let list: Request = serde_json::from_str(r#"{"op":"vault_list"}"#)?;
        assert_eq!(
            list,
            Request::VaultList {
                query: None,
                kind: None,
                limit: None,
                offset: 0
            }
        );
        let export: Request =
            serde_json::from_str(r#"{"op":"inventory_report","path":"C:\\r.csv","format":"csv"}"#)?;
        assert_eq!(
            export,
            Request::InventoryReport {
                path: PathBuf::from(r"C:\r.csv"),
                format: Format::Csv
            }
        );
        Ok(())
    }

    #[test]
    fn unknown_ops_fields_and_values_are_refused() {
        for bad in [
            r#"{"op":"nope"}"#,
            r#"{"texts":[]}"#,
            r#"{"op":"scan_text"}"#,
            r#"{"op":"scan_text","texts":[],"extra":1}"#,
            r#"{"op":"scan_text","texts":"a"}"#,
            r#"{"op":"protection"}"#,
            r#"{"op":"vault_export","path":"C:\\a","format":"xml"}"#,
            r#"{"op":"settings_set","settings":{"enabled":true}}"#,
            r#"{"op":"settings_set"}"#,
        ] {
            assert!(
                serde_json::from_str::<Request>(bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn a_settings_patch_keeps_only_what_it_sets() -> TestResult {
        let request = Request::SettingsSet {
            settings: SettingsPatch {
                http_port: Some(8000),
                inventory_roots: Some(vec![PathBuf::from(r"C:\Docs")]),
                ..SettingsPatch::default()
            },
        };
        let json = serde_json::to_value(&request)?;
        assert_eq!(
            json,
            json!({"op":"settings_set","settings":{"http_port":8000,"inventory_roots":[r"C:\Docs"]}})
        );
        Ok(())
    }

    #[test]
    fn debug_never_shows_the_personal_data_of_a_request() {
        let request = Request::ScanText {
            texts: vec!["jan.jansen@acme.nl".into()],
        };
        let shown = format!("{request:?}");
        assert!(shown.contains("scan_text"));
        assert!(!shown.contains("jan.jansen"), "{shown}");
    }

    #[test]
    fn errors_map_to_their_codes() {
        let cases = [
            (Error::Io(std::io::ErrorKind::NotFound.into()), "not_found"),
            (Error::Io(std::io::ErrorKind::PermissionDenied.into()), "io"),
            (Error::Dpapi("x".into()), "vault"),
            (Error::VaultCorrupt { record: 3 }, "vault"),
            (Error::VaultPathUnavailable, "vault"),
            (Error::UnsupportedFormat("zip"), "unsupported"),
            (Error::Pdf("x".into()), "unsupported"),
            (Error::Protocol("bad magic"), "bad_request"),
            (Error::BadRequest("x".into()), "bad_request"),
            (Error::Model("x".into()), "model"),
            (Error::Busy("x".into()), "busy"),
            (Error::Tool("x".into()), "internal"),
            (Error::Poisoned, "internal"),
        ];
        for (error, code) in cases {
            let shown = error.to_string();
            let api = ApiError::from(error);
            assert_eq!(api.code(), code, "{shown}");
            assert_eq!(api.message(), shown);
            assert!(CODES.contains(&api.code()));
        }
    }

    #[test]
    fn the_envelope_round_trips() -> TestResult {
        let ok = envelope(Ok(json!({"forgotten": 2})));
        assert_eq!(ok, json!({"ok": true, "result": {"forgotten": 2}}));
        assert_eq!(open_envelope(ok)?, json!({"forgotten": 2}));

        let failed = envelope(Err(ApiError::busy("a scan is running")));
        assert_eq!(
            failed,
            json!({"ok": false, "error": {"code": "busy", "message": "a scan is running"}})
        );
        let error = open_envelope(failed).err().ok_or("expected an error")?;
        assert_eq!(
            (error.code(), error.message()),
            ("busy", "a scan is running")
        );
        Ok(())
    }

    #[test]
    fn a_reply_that_is_no_envelope_is_an_internal_error() {
        for odd in [
            json!(1),
            json!([]),
            json!({}),
            json!({"ok": "yes"}),
            json!({"ok": false, "error": {"code": "made_up", "message": "m"}}),
        ] {
            let error = open_envelope(odd).err();
            assert_eq!(error.map(|e| e.code()), Some("internal"));
        }
        // A success without a result is a null result, not a failure.
        assert_eq!(open_envelope(json!({"ok": true})).ok(), Some(Value::Null));
    }

    #[test]
    fn format_converts_to_the_vault_export_format() {
        assert_eq!(ExportFormat::from(Format::Json), ExportFormat::Json);
        assert_eq!(ExportFormat::from(Format::Csv), ExportFormat::Csv);
        assert_eq!(Format::default(), Format::Json);
    }
}
