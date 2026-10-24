//! What each request answers: the `result` of the reply's envelope, as types.
//!
//! The handlers ([`Local`](super::Local) and the app) build these and the command line reads
//! them, so a field is named in one place and a rename is a compile error on both sides. A type
//! says which requests it answers. Optional fields that are absent are left out of the JSON,
//! except where a type says it is `null`.

use serde::{Deserialize, Serialize};

use crate::{
    inventory::{Entry, Node},
    policy::Highlight,
    subject::SubjectMatch,
};

/// `scan_text`: what the detector finds in each text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spans {
    /// One list per text, in the order the texts were given.
    pub results: Vec<Vec<Span>>,
}

/// A value found in a text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// UTF-8 byte offset of its first byte.
    pub start: usize,
    /// UTF-8 byte offset after its last byte.
    pub end: usize,
    /// The kind of personal data, as `EntityKind::as_str` names it.
    pub kind: String,
    pub value: String,
}

/// `anonymize` and `deanonymize`: the texts that came out, in the order they were given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Texts {
    pub texts: Vec<String>,
}

/// `scan_files`: what was found in the files and folders named, each file once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scanned {
    pub files: Vec<Entry>,
    /// Values found in all of them.
    pub hits: u64,
}

/// `anonymize_files` and `deanonymize_files`: what became of each file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Written {
    pub written: Vec<Moved>,
    pub failed: Vec<Failed>,
}

/// A file that was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moved {
    pub input: String,
    pub output: String,
}

/// A file that could not be written, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failed {
    pub input: String,
    pub error: String,
}

/// `subject_search`: the files that hold some of the values, the one with the most first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub matches: Vec<SubjectMatch>,
}

/// `vault_list`: one page of the vault's records, the newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Records {
    pub records: Vec<Record>,
    /// Every record that matched, not only the page.
    pub total: usize,
}

/// A value and the stand-in piikey issued for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The kind of personal data, as `EntityKind::as_str` names it.
    pub kind: String,
    pub original: String,
    pub proxy: String,
}

/// `vault_forget` and `vault_wipe`: how many records were removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forgotten {
    pub forgotten: usize,
}

/// `vault_export`: the file that was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exported {
    pub records: usize,
    pub path: String,
}

/// `inventory_report`: the file that was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reported {
    pub rows: usize,
    pub path: String,
}

/// How far a scan or a download is: `done` of `total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
}

/// `inventory_status`: the inventory in numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryStatus {
    /// The folders it scans when asked: the user's locations, none until one is added.
    pub roots: Vec<String>,
    /// The locations whose changes are scanned as they happen.
    pub monitored: Vec<String>,
    pub files: u64,
    pub files_with_pii: u64,
    pub hits: u64,
    /// Files scanned so far, while a scan runs; `null` otherwise.
    pub scanning: Option<Progress>,
}

/// `inventory_list`: one page of the files that hold personal data, the one with the most first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entries {
    pub entries: Vec<Entry>,
    /// Every file that matched, not only the page.
    pub total: usize,
}

/// `inventory_tree`: what lies directly under a folder, or the drives and shares that hold files
/// with personal data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nodes {
    pub nodes: Vec<Node>,
}

/// One kind of personal data, in the reply to `kinds`: the reply is a list of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kind {
    /// The name the API uses (`EntityKind::as_str`).
    pub kind: String,
    /// What a person calls it.
    pub label: String,
    /// The group it is listed under.
    pub group: String,
    /// Whether scans and masking look for it.
    pub enabled: bool,
}

/// Where the detection model stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelState {
    /// Not downloaded.
    Missing,
    /// Downloaded, loaded when it is needed.
    Unloaded,
    /// Loaded and detecting.
    Ready,
    /// Loading or running failed.
    Failed,
}

/// What the loaded model runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    Cpu,
    /// The CPU and the GPU together.
    Hybrid,
}

impl Device {
    /// The name the API uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Hybrid => "hybrid",
        }
    }
}

/// `model_status`: the detection model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub state: ModelState,
    /// Present while the model is loaded; `null` otherwise.
    pub device: Option<Device>,
    /// Why it failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Only the app says it: the download it is running, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloading: Option<Progress>,
    /// The folder the model lives in.
    pub dir: String,
}

/// `api_token`: what the HTTP API wants as `Authorization: Bearer <token>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
}

/// `status`: how piikey is doing.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of one report, not the states of one machine"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Whether the app is running (it answers for itself, and says `true`).
    pub app: bool,
    /// Whether protection is on; `null` when the app is not running, as it is the app's.
    pub protection: Option<bool>,
    pub version: String,
    pub vault_records: u64,
    pub model: Model,
    pub highlight: Highlight,
    pub explorer_menu: bool,
    /// Whether any location is monitored.
    pub monitoring: bool,
    pub http_api: bool,
}

/// `protection`: how protection stands after the switch. Only the app answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protection {
    pub protection: bool,
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use serde_json::json;

    use super::*;
    use crate::api::to_json;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    #[test]
    fn what_is_absent_is_left_out_and_what_is_null_says_so() -> TestResult {
        let model = Model {
            state: ModelState::Missing,
            device: None,
            error: None,
            downloading: None,
            dir: r"C:\models".to_owned(),
        };
        assert_eq!(
            to_json(&model)?,
            json!({"state": "missing", "device": null, "dir": r"C:\models"})
        );
        let failed = Model {
            state: ModelState::Failed,
            error: Some("out of memory".to_owned()),
            downloading: Some(Progress { done: 1, total: 2 }),
            ..model
        };
        let shown = to_json(&failed)?;
        assert_eq!(shown["state"], "failed");
        assert_eq!(shown["error"], "out of memory");
        assert_eq!(shown["downloading"], json!({"done": 1, "total": 2}));

        let status = to_json(&InventoryStatus {
            roots: vec![],
            monitored: vec![],
            files: 0,
            files_with_pii: 0,
            hits: 0,
            scanning: None,
        })?;
        assert_eq!(status["scanning"], serde_json::Value::Null);
        Ok(())
    }

    #[test]
    fn a_reply_reads_back_as_it_was_written() -> TestResult {
        let status = Status {
            app: false,
            protection: None,
            version: "1.2.3".to_owned(),
            vault_records: 7,
            model: Model {
                state: ModelState::Ready,
                device: Some(Device::Hybrid),
                error: None,
                downloading: None,
                dir: r"C:\models".to_owned(),
            },
            highlight: Highlight::Hotkey,
            explorer_menu: true,
            monitoring: false,
            http_api: false,
        };
        let wire = to_json(&status)?;
        assert_eq!(wire["highlight"], "hotkey");
        assert_eq!(wire["protection"], serde_json::Value::Null);
        assert_eq!(serde_json::from_value::<Status>(wire)?, status);

        let spans = Spans {
            results: vec![
                vec![Span {
                    start: 5,
                    end: 23,
                    kind: "email".to_owned(),
                    value: "jan.jansen@acme.nl".to_owned(),
                }],
                vec![],
            ],
        };
        let wire = to_json(&spans)?;
        // The fields come in the order the README lists them.
        assert_eq!(
            wire["results"][0][0].to_string(),
            r#"{"start":5,"end":23,"kind":"email","value":"jan.jansen@acme.nl"}"#
        );
        assert_eq!(serde_json::from_value::<Spans>(wire)?, spans);
        Ok(())
    }
}
