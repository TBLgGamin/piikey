//! What each request answers: the `result` of the reply's envelope, as types.
//!
//! The handlers (`Local` and the app) build these and the command line reads
//! them, so a field is named in one place and a rename is a compile error on both sides. A type
//! says which requests it answers. Optional fields that are absent are left out of the JSON,
//! except where a type says it is `null`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    detect::EntityKind,
    inventory::{Entry, Node},
    policy::Highlight,
    sources::{Account, Provider, SignIn},
    subject::SubjectMatch,
};

/// `scan_text`: what the detector finds in each text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Spans {
    /// One list per text, in the order the texts were given.
    pub results: Vec<Vec<Span>>,
}

/// A value found in a text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Span {
    /// UTF-8 byte offset of its first byte.
    pub start: usize,
    /// UTF-8 byte offset after its last byte.
    pub end: usize,
    /// The type of personal data, by the name `kinds` lists it.
    #[schemars(with = "EntityKind")]
    pub kind: String,
    /// The value that was found, as it stands in the text.
    pub value: String,
}

/// `anonymize` and `deanonymize`: the texts that came out, in the order they were given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Texts {
    /// The texts that came out, in the order they were given.
    pub texts: Vec<String>,
}

/// `scan_files`: what was found in the files and folders named, each file once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Scanned {
    /// One entry per file that was read, each file once.
    pub files: Vec<Entry>,
    /// Values found in all of them.
    pub hits: u64,
}

/// `anonymize_files` and `deanonymize_files`: what became of each file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Written {
    /// The files that were written.
    pub written: Vec<Moved>,
    /// The files that could not be written.
    pub failed: Vec<Failed>,
}

/// A file that was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Moved {
    /// The file that was read.
    pub input: String,
    /// The file that was written.
    pub output: String,
}

/// A file that could not be written, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Failed {
    /// The file that could not be written.
    pub input: String,
    /// Why it could not be.
    pub error: String,
}

/// `subject_search`: the files that hold some of the values, the one with the most first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Found {
    /// The files that hold some of the values, the one with the most first.
    pub matches: Vec<SubjectMatch>,
}

/// `vault_list`: one page of the vault's records, the newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Records {
    /// The records on this page, the newest first.
    pub records: Vec<Record>,
    /// Every record that matched, not only the page.
    pub total: usize,
}

/// A value and the stand-in piikey issued for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Record {
    /// The type of personal data, by the name `kinds` lists it.
    #[schemars(with = "EntityKind")]
    pub kind: String,
    /// The value.
    pub original: String,
    /// The stand-in piikey issued for it.
    pub proxy: String,
}

/// `vault_forget` and `vault_wipe`: how many records were removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Forgotten {
    /// How many records were removed.
    pub forgotten: usize,
}

/// `vault_export`: the file that was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Exported {
    /// How many records were written.
    pub records: usize,
    /// The file that was written.
    pub path: String,
}

/// `inventory_report`: the file that was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reported {
    /// How many rows were written.
    pub rows: usize,
    /// The file that was written.
    pub path: String,
}

/// How far a scan or a download is: `done` of `total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Progress {
    /// How many are done.
    pub done: u64,
    /// How many there are in all (files for a scan, bytes for a download).
    pub total: u64,
}

/// `inventory_status`: the inventory in numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InventoryStatus {
    /// The folders it scans when asked: the user's locations, none until one is added.
    pub roots: Vec<String>,
    /// The locations whose changes are scanned as they happen.
    pub monitored: Vec<String>,
    /// Files the inventory knows.
    pub files: u64,
    /// Of those, the files that hold personal data.
    pub files_with_pii: u64,
    /// Values found in all of them.
    pub hits: u64,
    /// Files scanned so far, while a scan runs; `null` otherwise.
    pub scanning: Option<Progress>,
}

/// `inventory_list`: one page of the files that hold personal data, the one with the most first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Entries {
    /// The files on this page, the one with the most values first.
    pub entries: Vec<Entry>,
    /// Every file that matched, not only the page.
    pub total: usize,
}

/// `inventory_tree`: what lies directly under a folder, or the drives and shares that hold files
/// with personal data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Nodes {
    /// The tiles at this level of the tree.
    pub nodes: Vec<Node>,
}

/// One type of personal data, in the reply to `kinds`: the reply is a list of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "TypeInfo")]
pub struct Kind {
    /// The name the API uses for the type.
    #[schemars(with = "EntityKind")]
    pub kind: String,
    /// What a person calls it.
    pub label: String,
    /// The group it is listed under.
    pub group: String,
    /// Whether scans and masking look for it.
    pub enabled: bool,
}

/// Where the detection model stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    /// The CPU alone.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Model {
    /// Where the model stands.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Token {
    /// The bearer token.
    pub token: String,
}

/// `status`: how piikey is doing.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts of one report, not the states of one machine"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Status {
    /// Whether the app is running (it answers for itself, and says `true`).
    pub app: bool,
    /// Whether protection is on; `null` when the app is not running, as it is the app's.
    pub protection: Option<bool>,
    /// piikey's version.
    pub version: String,
    /// How many records the vault holds.
    pub vault_records: u64,
    /// Where the detection model stands.
    pub model: Model,
    /// When the field in focus is outlined if it holds personal data.
    pub highlight: Highlight,
    /// Whether Explorer's right-click menu offers "Scan for personal data".
    pub explorer_menu: bool,
    /// Whether any location is monitored.
    pub monitoring: bool,
    /// Whether the local HTTP API is switched on.
    pub http_api: bool,
}

/// `protection`: how protection stands after the switch. Only the app answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Protection {
    /// Whether protection is on.
    pub protection: bool,
}

/// One cloud account, in the reply to `account_add` and `account_connect` and in the list
/// `accounts_list` answers. It holds no secret: a client secret is kept DPAPI-protected in the
/// data folder, a key stays in its file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AccountInfo {
    /// The account's id (16 hexadecimal digits), which never changes: the other account
    /// operations take it.
    pub id: String,
    /// The cloud service.
    pub provider: Provider,
    /// The name the account goes by, unique among the accounts of its service. It is the second
    /// part of the paths of the account's folders.
    pub label: String,
    /// How the account signs in, with what that way needs (no secret).
    pub sign_in: SignIn,
    /// The path of the account's top, `\\<service>\<name>`: the start of the path of every
    /// folder and file in it, and what a location of the inventory is picked below.
    pub path: String,
    /// Whether piikey has what it needs to read the account: a person has signed in, or the app
    /// has its secret or its key files. It says nothing about whether the service still accepts
    /// it.
    pub connected: bool,
}

impl AccountInfo {
    /// `account` as the API shows it.
    #[must_use]
    pub fn new(account: &Account, connected: bool) -> Self {
        Self {
            id: account.id.clone(),
            provider: account.provider,
            label: account.label.clone(),
            sign_in: account.sign_in.clone(),
            path: account.root().to_string_lossy().into_owned(),
            connected,
        }
    }
}

/// `accounts_list`: the cloud accounts piikey may read, in the order they were added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Accounts {
    /// The accounts, in the order they were added.
    pub accounts: Vec<AccountInfo>,
}

/// `account_remove`: what went with the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AccountRemoved {
    /// The id of the account that was removed.
    pub id: String,
    /// The locations of the inventory that were taken off the list, because they were in the
    /// account.
    pub locations: Vec<String>,
    /// How many files of the account the inventory forgot.
    pub forgotten: u64,
}

/// A folder of a cloud account, in the reply to `account_browse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FolderInfo {
    /// The folder's path, which a location of the inventory can be and the next
    /// `account_browse` can look under.
    pub path: String,
    /// The folder's name: the last part of its path.
    pub name: String,
}

/// `account_browse`: the folders directly in one folder of an account, or the top of the
/// account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Folders {
    /// The folders, in the order the service lists them.
    pub folders: Vec<FolderInfo>,
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

    #[test]
    fn an_account_is_shown_with_its_path_and_never_with_a_secret() -> TestResult {
        let account = Account {
            id: "3f9c2a7d41b8e605".to_owned(),
            provider: Provider::Box,
            label: "Team".to_owned(),
            sign_in: SignIn::BoxApp {
                client_id: "client-1".to_owned(),
                subject: crate::sources::BoxSubject::Enterprise("77".to_owned()),
            },
        };
        let info = AccountInfo::new(&account, true);
        let wire = to_json(&info)?;
        assert_eq!(
            wire,
            json!({
                "id": "3f9c2a7d41b8e605",
                "provider": "box",
                "label": "Team",
                "sign_in": {
                    "mode": "box_app",
                    "client_id": "client-1",
                    "subject": {"type": "enterprise", "id": "77"},
                },
                "path": r"\\Box\Team",
                "connected": true,
            })
        );
        assert!(!wire.to_string().contains("secret"), "{wire}");
        assert_eq!(serde_json::from_value::<AccountInfo>(wire)?, info);
        let list = Accounts {
            accounts: vec![info, AccountInfo::new(&account, false)],
        };
        assert_eq!(serde_json::from_value::<Accounts>(to_json(&list)?)?, list);
        Ok(())
    }

    #[test]
    fn what_went_with_an_account_and_its_folders_read_back() -> TestResult {
        let removed = AccountRemoved {
            id: "ab".to_owned(),
            locations: vec![r"\\Box\Team\Docs".to_owned()],
            forgotten: 12,
        };
        let wire = to_json(&removed)?;
        assert_eq!(
            wire,
            json!({"id": "ab", "locations": [r"\\Box\Team\Docs"], "forgotten": 12})
        );
        assert_eq!(serde_json::from_value::<AccountRemoved>(wire)?, removed);
        let folders = Folders {
            folders: vec![FolderInfo {
                path: r"\\Box\Team\Docs".to_owned(),
                name: "Docs".to_owned(),
            }],
        };
        let wire = to_json(&folders)?;
        assert_eq!(
            wire,
            json!({"folders": [{"path": r"\\Box\Team\Docs", "name": "Docs"}]})
        );
        assert_eq!(serde_json::from_value::<Folders>(wire)?, folders);
        Ok(())
    }
}
