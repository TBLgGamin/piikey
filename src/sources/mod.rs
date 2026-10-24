//! Cloud storage as inventory locations: Microsoft 365 (`SharePoint` and `OneDrive` for Business),
//! `OneDrive`, Google Drive, Dropbox and Box, through their official REST APIs.
//!
//! A cloud folder is a location like a folder on this PC: the inventory scans it into the same
//! file, keeping counts and paths only. A file's contents are downloaded into memory, scanned and
//! dropped; values never leave this PC. Only read-only scopes are asked for.
//!
//! An item of an account is stored under a virtual path that looks like a network share,
//! `\\<provider>\<account label>\<drive or site>\<folder>\...\<file>`, so the tree, the crumbs and
//! [`crate::sys::is_under`] work on it unchanged (see [`parse_virtual`]). Every part of such a path
//! is a legal Windows file name ([`component`]).
//!
//! The pieces:
//! - [`Account`] and [`Accounts`]: the connected accounts, as non-secret settings in
//!   `<data folder>\sources.json`. Secrets and tokens never go there: they are kept DPAPI-protected,
//!   one file per account, by the `TokenStore`.
//! - [`Connector`]: what a provider offers (browse folders, follow a change feed, download a file),
//!   made by [`connector`]. One module per provider implements it.
//! - `scan_remote`: brings the inventory up to date with one cloud location, through the same
//!   [`crate::inventory::Progress`] a scan of this PC reports to.
//! - [`Error`]: why a call failed, in the words of the person at the screen (never an HTTP code).

mod auth;
mod boxcom;
mod dropbox;
mod google;
mod graph;
mod http;
mod scan;
#[cfg(test)]
mod testing;

pub use auth::{SIGN_IN_TIMEOUT, Secrets, TokenStore};
pub use scan::{Cursors, Scanned, findings, scan_remote};

use std::{
    fmt::{self, Write as _},
    fs, io,
    path::{Component, Path, PathBuf, Prefix},
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::sys;

/// The account list's file name in the data folder.
const ACCOUNTS_FILE: &str = "sources.json";
/// How long saving the account list waits for another piikey process that is saving it.
const SAVE_WAIT: Duration = Duration::from_secs(5);
/// The longest account name.
const MAX_LABEL: usize = 100;

/// A cloud service whose folders piikey can scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Provider {
    /// `SharePoint` and `OneDrive` for Business, through Microsoft Graph.
    #[serde(rename = "microsoft365")]
    Microsoft365,
    /// A personal Microsoft account's `OneDrive`, through Microsoft Graph.
    #[serde(rename = "onedrive")]
    OneDrive,
    /// Google Drive, through the Drive API.
    #[serde(rename = "google_drive")]
    GoogleDrive,
    /// Dropbox.
    #[serde(rename = "dropbox")]
    Dropbox,
    /// Box.
    #[serde(rename = "box")]
    Box,
}

impl Provider {
    /// Every provider, in the order a picker lists them.
    pub const ALL: [Self; 5] = [
        Self::Microsoft365,
        Self::OneDrive,
        Self::GoogleDrive,
        Self::Dropbox,
        Self::Box,
    ];

    /// The name the person at the screen knows it by. It is also the server part of the virtual
    /// paths of its accounts.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Microsoft365 => "Microsoft 365",
            Self::OneDrive => "OneDrive",
            Self::GoogleDrive => "Google Drive",
            Self::Dropbox => "Dropbox",
            Self::Box => "Box",
        }
    }

    /// The name settings and the API use: `microsoft365`, `onedrive`, `google_drive`, `dropbox`
    /// or `box`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Microsoft365 => "microsoft365",
            Self::OneDrive => "onedrive",
            Self::GoogleDrive => "google_drive",
            Self::Dropbox => "dropbox",
            Self::Box => "box",
        }
    }

    /// The provider [`Provider::id`] spells.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|provider| provider.id() == id)
    }

    /// The provider whose [`Provider::name`] is `name`, in any letter case.
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.name().eq_ignore_ascii_case(name))
    }
}

/// How an app registration proves who it is when no user signs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credential {
    /// A client secret. The secret itself is kept by the token store, not in the settings.
    Secret,
    /// A certificate: the app signs a short-lived assertion with its private key (RS256). The
    /// files are PEM files that stay where the user keeps them.
    Certificate {
        /// The private key, PEM (`BEGIN PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`, not encrypted).
        key_file: PathBuf,
        /// The certificate that was uploaded to the app registration, PEM.
        cert_file: PathBuf,
    },
}

/// Whom a Box app acts as when it signs in with its client credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum BoxSubject {
    /// The whole enterprise, by its enterprise id.
    Enterprise(String),
    /// One user, by user id.
    User(String),
}

/// How an account signs in, with what that way needs. The settings hold no secret: a client
/// secret is given to the token store, a key stays in its file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SignIn {
    /// A person signs in with a browser (authorization code with PKCE; a public client).
    /// `tenant` is a tenant id, a domain, `organizations` (any work or school account) or
    /// `consumers` (personal accounts, for `OneDrive`).
    MicrosoftDelegated { tenant: String, client_id: String },
    /// An app registration reads for the whole tenant (client credentials; the application
    /// permissions `Sites.Read.All` and `Files.Read.All`, with administrator consent).
    MicrosoftApp {
        tenant: String,
        client_id: String,
        credential: Credential,
    },
    /// An app registration that may read only the sites an administrator granted it (the
    /// application permission `Sites.Selected`). `sites` lists them, by URL such as
    /// `https://contoso.sharepoint.com/sites/Finance`: the service cannot list them for the app.
    MicrosoftAppSelected {
        tenant: String,
        client_id: String,
        credential: Credential,
        sites: Vec<String>,
    },
    /// A person signs in with a browser, with the user's own OAuth client (an installed-app
    /// client; its secret is kept by the token store).
    GoogleDelegated { client_id: String },
    /// A Google Workspace service account with domain-wide delegation: it reads the Drive of each
    /// of `users` (email addresses) as that user. `key_file` is the JSON key file Google issued.
    GoogleServiceAccount {
        key_file: PathBuf,
        users: Vec<String>,
    },
    /// A person signs in with a browser (authorization code with PKCE and refresh tokens).
    /// `app_key` is the Dropbox app's key.
    DropboxDelegated { app_key: String },
    /// A person signs in with a browser (authorization code; Box requires a client secret, kept by
    /// the token store).
    BoxDelegated { client_id: String },
    /// A Box app reads as `subject` (client credentials grant; its secret is kept by the token
    /// store).
    BoxApp {
        client_id: String,
        subject: BoxSubject,
    },
}

impl SignIn {
    /// Whether `provider` has this way to sign in.
    #[must_use]
    pub const fn fits(&self, provider: Provider) -> bool {
        match self {
            Self::MicrosoftDelegated { .. } => {
                matches!(provider, Provider::Microsoft365 | Provider::OneDrive)
            }
            Self::MicrosoftApp { .. } | Self::MicrosoftAppSelected { .. } => {
                matches!(provider, Provider::Microsoft365)
            }
            Self::GoogleDelegated { .. } | Self::GoogleServiceAccount { .. } => {
                matches!(provider, Provider::GoogleDrive)
            }
            Self::DropboxDelegated { .. } => matches!(provider, Provider::Dropbox),
            Self::BoxDelegated { .. } | Self::BoxApp { .. } => matches!(provider, Provider::Box),
        }
    }

    /// Whether a person signs in with a browser (the account has to be connected before it can
    /// be read) rather than an app that holds its own credentials.
    #[must_use]
    pub const fn needs_browser(&self) -> bool {
        matches!(
            self,
            Self::MicrosoftDelegated { .. }
                | Self::GoogleDelegated { .. }
                | Self::DropboxDelegated { .. }
                | Self::BoxDelegated { .. }
        )
    }

    /// Whether this way to sign in needs a client secret, which is given to the token store and
    /// never kept in the settings.
    #[must_use]
    pub const fn needs_secret(&self) -> bool {
        matches!(
            self,
            Self::GoogleDelegated { .. }
                | Self::BoxDelegated { .. }
                | Self::BoxApp { .. }
                | Self::MicrosoftApp {
                    credential: Credential::Secret,
                    ..
                }
                | Self::MicrosoftAppSelected {
                    credential: Credential::Secret,
                    ..
                }
        )
    }

    /// What is still to be filled in: the first value this way needs that is empty, in the words
    /// a form uses ("the tenant"); `None` when there is nothing missing.
    #[must_use]
    pub fn missing(&self) -> Option<&'static str> {
        let blank = |text: &str| text.trim().is_empty();
        let no_credential = |credential: &Credential| match credential {
            Credential::Secret => None,
            Credential::Certificate {
                key_file,
                cert_file,
            } => key_file
                .as_os_str()
                .is_empty()
                .then_some("the private key file")
                .or_else(|| {
                    cert_file
                        .as_os_str()
                        .is_empty()
                        .then_some("the certificate file")
                }),
        };
        match self {
            Self::MicrosoftDelegated { tenant, client_id } => blank(tenant)
                .then_some("the tenant")
                .or_else(|| blank(client_id).then_some("the application (client) ID")),
            Self::MicrosoftApp {
                tenant,
                client_id,
                credential,
            } => blank(tenant)
                .then_some("the tenant")
                .or_else(|| blank(client_id).then_some("the application (client) ID"))
                .or_else(|| no_credential(credential)),
            Self::MicrosoftAppSelected {
                tenant,
                client_id,
                credential,
                sites,
            } => blank(tenant)
                .then_some("the tenant")
                .or_else(|| blank(client_id).then_some("the application (client) ID"))
                .or_else(|| no_credential(credential))
                .or_else(|| {
                    sites
                        .iter()
                        .all(|site| blank(site))
                        .then_some("at least one site")
                }),
            Self::GoogleDelegated { client_id } | Self::BoxDelegated { client_id } => {
                blank(client_id).then_some("the client ID")
            }
            Self::GoogleServiceAccount { key_file, users } => key_file
                .as_os_str()
                .is_empty()
                .then_some("the key file")
                .or_else(|| {
                    users
                        .iter()
                        .all(|user| blank(user))
                        .then_some("at least one user")
                }),
            Self::DropboxDelegated { app_key } => blank(app_key).then_some("the app key"),
            Self::BoxApp { client_id, subject } => blank(client_id)
                .then_some("the client ID")
                .or_else(|| match subject {
                    BoxSubject::Enterprise(id) => blank(id).then_some("the enterprise ID"),
                    BoxSubject::User(id) => blank(id).then_some("the user ID"),
                }),
        }
    }
}

/// A connected cloud account: what the settings keep of it. No secret, no token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Account {
    /// A short name that never changes, for the files and the API (16 hexadecimal digits).
    pub id: String,
    pub provider: Provider,
    /// What the person calls it; unique among the accounts of its provider. It is the share part
    /// of the virtual paths of the account.
    pub label: String,
    pub sign_in: SignIn,
}

impl Account {
    /// The virtual path of the account's top: `\\<provider>\<label>`.
    #[must_use]
    pub fn root(&self) -> PathBuf {
        PathBuf::from(format!(r"\\{}\{}", self.provider.name(), self.label))
    }

    /// Whether the account has what it needs to be read: a person has signed in with the browser
    /// (the token store keeps a refresh token), or an app has its client secret in the token
    /// store, or its key and certificate files, or its key file. That is what is kept, not
    /// whether the service still accepts it: only a call finds that out, and says `SignInNeeded`.
    ///
    /// # Errors
    /// What [`TokenStore::load`] fails with.
    pub fn is_connected(&self, tokens: &TokenStore) -> crate::Result<bool> {
        let has_secret = || Ok::<_, crate::Error>(tokens.load(&self.id)?.client_secret.is_some());
        Ok(match &self.sign_in {
            SignIn::MicrosoftApp { credential, .. }
            | SignIn::MicrosoftAppSelected { credential, .. } => match credential {
                Credential::Secret => has_secret()?,
                Credential::Certificate {
                    key_file,
                    cert_file,
                } => key_file.is_file() && cert_file.is_file(),
            },
            SignIn::GoogleServiceAccount { key_file, .. } => key_file.is_file(),
            SignIn::BoxApp { .. } => has_secret()?,
            SignIn::MicrosoftDelegated { .. }
            | SignIn::GoogleDelegated { .. }
            | SignIn::DropboxDelegated { .. }
            | SignIn::BoxDelegated { .. } => tokens.load(&self.id)?.refresh_token.is_some(),
        })
    }
}

/// The connected accounts, as `<data folder>\sources.json` keeps them.
#[derive(Debug, Clone, Default)]
pub struct Accounts {
    list: Vec<Account>,
}

/// The shape of `sources.json`.
#[derive(Serialize, Deserialize, Default)]
struct AccountsFile {
    accounts: Vec<Account>,
}

/// The accounts in the file `path`; none when there is no file.
fn read_accounts(path: &Path) -> crate::Result<Vec<Account>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<AccountsFile>(&bytes)
            .map(|file| file.accounts)
            .map_err(|e| {
                sys::io_context(&io::Error::new(io::ErrorKind::InvalidData, e), "read", path)
            }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(sys::io_context(&e, "read", path)),
    }
}

impl Accounts {
    /// The accounts saved in the data folder `data`; none when there is no file yet.
    ///
    /// # Errors
    /// `Io` when the file exists but cannot be read or is damaged.
    pub fn open(data: &Path) -> crate::Result<Self> {
        Ok(Self {
            list: read_accounts(&data.join(ACCOUNTS_FILE))?,
        })
    }

    /// Changes the saved accounts. One process at a time: the file is read as it is now, `change`
    /// edits the list ([`Accounts::add`], [`Accounts::remove`]) and, when it succeeds, the list is
    /// saved. What another process (the app, the command line) saved before is not lost.
    ///
    /// # Errors
    /// What `change` fails with, nothing being saved then; `Io` when the file cannot be read or
    /// written; `Busy` when another piikey process holds it for longer than a save takes.
    pub fn edit<R>(
        data: &Path,
        change: impl FnOnce(&mut Self) -> crate::Result<R>,
    ) -> crate::Result<R> {
        fs::create_dir_all(data).map_err(|e| sys::io_context(&e, "create", data))?;
        let path = data.join(ACCOUNTS_FILE);
        let _lock =
            sys::lock_within(&path.with_extension("lock"), SAVE_WAIT)?.ok_or_else(|| {
                crate::Error::Busy("another piikey process is saving the accounts".to_owned())
            })?;
        let mut accounts = Self {
            list: read_accounts(&path)?,
        };
        let result = change(&mut accounts)?;
        let bytes = serde_json::to_vec_pretty(&AccountsFile {
            accounts: accounts.list,
        })
        .map_err(io::Error::from)?;
        sys::write_atomic(&path, &bytes)?;
        Ok(result)
    }

    /// The accounts, in the order they were added.
    #[must_use]
    pub fn list(&self) -> &[Account] {
        &self.list
    }

    /// The account with this id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Account> {
        self.list.iter().find(|account| account.id == id)
    }

    /// The account a virtual path is under.
    #[must_use]
    pub fn of(&self, path: &Path) -> Option<&Account> {
        let Virtual {
            provider, label, ..
        } = parse_virtual(path)?;
        self.list.iter().find(|account| {
            account.provider == provider && account.label.to_lowercase() == label.to_lowercase()
        })
    }

    /// Adds an account and returns it; do it inside [`Accounts::edit`] to keep it.
    ///
    /// # Errors
    /// `BadRequest` when the name is empty, too long or holds a character a file name cannot, when
    /// the provider does not have that way to sign in, when something that way needs is empty
    /// ([`SignIn::missing`]), or when the provider already has an account of that name; `Io` when
    /// there is no randomness for the id.
    pub fn add(
        &mut self,
        provider: Provider,
        label: &str,
        sign_in: SignIn,
    ) -> crate::Result<Account> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > MAX_LABEL || component(label) != label {
            return Err(crate::Error::BadRequest(format!(
                "The account name must be 1 to {MAX_LABEL} characters and cannot hold \\ / : * ? \" < > | or a dot or space at the end."
            )));
        }
        if !sign_in.fits(provider) {
            return Err(crate::Error::BadRequest(format!(
                "{} cannot be signed in to that way.",
                provider.name()
            )));
        }
        if let Some(what) = sign_in.missing() {
            return Err(crate::Error::BadRequest(format!("Fill in {what}.")));
        }
        if self.list.iter().any(|account| {
            account.provider == provider && account.label.to_lowercase() == label.to_lowercase()
        }) {
            return Err(crate::Error::BadRequest(format!(
                "There is already a {} account called {label}.",
                provider.name()
            )));
        }
        let mut random = [0_u8; 8];
        sys::fill_random(&mut random)?;
        let account = Account {
            id: random
                .iter()
                .fold(String::with_capacity(16), |mut id, byte| {
                    let _ = write!(id, "{byte:02x}");
                    id
                }),
            provider,
            label: label.to_owned(),
            sign_in,
        };
        self.list.push(account.clone());
        Ok(account)
    }

    /// Removes the account with this id and returns it; do it inside [`Accounts::edit`] to keep
    /// that.
    pub fn remove(&mut self, id: &str) -> Option<Account> {
        let at = self.list.iter().position(|account| account.id == id)?;
        Some(self.list.remove(at))
    }
}

/// Adds a cloud account to the data folder `data`: its settings (no secret) in `sources.json`
/// and, for a way to sign in that has one ([`SignIn::needs_secret`]), the client secret in the
/// token store. Returns the account. The person still has to sign in
/// ([`SignIn::needs_browser`]; see [`connect`]).
///
/// # Errors
/// As [`Accounts::add`]; `BadRequest` when a client secret is needed and none was given;
/// `Dpapi` or `Io` when the secret cannot be kept (then nothing is saved).
pub fn add_account(
    data: &Path,
    provider: Provider,
    label: &str,
    sign_in: SignIn,
    client_secret: Option<&str>,
) -> crate::Result<Account> {
    let secret = client_secret
        .map(str::trim)
        .filter(|secret| !secret.is_empty());
    if sign_in.needs_secret() && secret.is_none() {
        return Err(crate::Error::BadRequest(
            "Fill in the client secret.".to_owned(),
        ));
    }
    let tokens = TokenStore::new(data);
    Accounts::edit(data, |accounts| {
        let account = accounts.add(provider, label, sign_in)?;
        if let Some(secret) = secret.filter(|_| account.sign_in.needs_secret()) {
            tokens.save(&account.id, &Secrets::default().with_client_secret(secret))?;
        }
        Ok(account)
    })
}

/// Removes the account `id`: its secrets and tokens, its settings, and the cursors of its
/// locations. Returns it, or `None` when there is no such account. What is the caller's: the
/// inventory's entries of the account (`Inventory::forget_under` its [`Account::root`]) and the
/// locations that name it.
///
/// # Errors
/// `Io` or `Dpapi` when the secrets cannot be deleted (then the account stays); `Io` and `Busy`
/// as for [`Accounts::edit`].
pub fn remove_account(data: &Path, id: &str) -> crate::Result<Option<Account>> {
    let Some(account) = Accounts::open(data)?.get(id).cloned() else {
        return Ok(None);
    };
    TokenStore::new(data).remove(&account.id)?;
    Accounts::edit(data, |accounts| Ok(accounts.remove(&account.id)))?;
    Cursors::new(data).forget_under(&account.root())?;
    Ok(Some(account))
}

/// An account's virtual path, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Virtual {
    pub provider: Provider,
    /// The account's name: the share part of the path.
    pub label: String,
    /// What is below the account's top, relative: empty for the account itself.
    pub rest: PathBuf,
}

/// Takes a virtual path apart; `None` for any other path (a drive letter, a share of a real
/// server). A real server that is called `Box` or `Dropbox` would read as a cloud account: it is
/// told apart by [`Accounts::of`], which needs the account.
#[must_use]
pub fn parse_virtual(path: &Path) -> Option<Virtual> {
    let mut parts = path.components();
    let Some(Component::Prefix(prefix)) = parts.next() else {
        return None;
    };
    let Prefix::UNC(server, share) = prefix.kind() else {
        return None;
    };
    let provider = Provider::from_name(server.to_str()?)?;
    let label = share.to_str()?.to_owned();
    let rest = parts
        .filter(|part| !matches!(part, Component::RootDir))
        .collect();
    Some(Virtual {
        provider,
        label,
        rest,
    })
}

/// Whether `path` is under (or is) the top of a cloud account, that is, whether [`parse_virtual`]
/// takes it apart.
#[must_use]
pub fn is_virtual(path: &Path) -> bool {
    parse_virtual(path).is_some()
}

/// `name` as one part of a virtual path: a legal Windows file name. A character Windows does not
/// allow in one (`\ / : * ? " < > |`) becomes its full-width look-alike, a control character
/// `_`, a dot or space at the end `_`, and a name of a device (`CON`, `NUL`, `COM1`...) gets a `_`
/// in front. So the part is one component whatever the service allows in a name, and a copy of
/// the file can be written under it.
#[must_use]
pub fn component(name: &str) -> String {
    let mut part: String = name
        .chars()
        .map(|c| match c {
            '\\' => '＼',
            '/' => '／',
            ':' => '：',
            '*' => '＊',
            '?' => '？',
            '"' => '＂',
            '<' => '＜',
            '>' => '＞',
            '|' => '｜',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let kept = part.trim_end_matches(['.', ' ']).len();
    let trailing = part.len() - kept;
    part.truncate(kept);
    part.extend(std::iter::repeat_n('_', trailing));
    if part.is_empty() {
        part.push('_');
    }
    let stem = part.split('.').next().unwrap_or_default().trim_end();
    if is_device(stem) {
        part.insert(0, '_');
    }
    part
}

/// Whether Windows takes `stem` for a device rather than a file.
fn is_device(stem: &str) -> bool {
    const DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    let upper = stem.to_ascii_uppercase();
    DEVICES.contains(&upper.as_str())
        || ["COM", "LPT"].iter().any(|prefix| {
            upper
                .strip_prefix(prefix)
                .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
        })
}

/// `name` below the virtual path `base`, as [`component`] spells it.
#[must_use]
pub fn child(base: &Path, name: &str) -> PathBuf {
    base.join(component(name))
}

/// A time as the services write it (RFC 3339): `2023-05-30T12:41:22Z`, with fractions of a second
/// (`2023-05-30T12:41:22.123Z`) or a zone (`2012-12-12T10:53:43-08:00`). `None` for anything
/// else, and for a time before 1970.
#[must_use]
pub(crate) fn parse_time(text: &str) -> Option<SystemTime> {
    let (date, rest) = text.trim().split_once(['T', 't', ' '])?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some()
        || !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let (clock, offset) = if let Some(clock) = rest.strip_suffix(['Z', 'z']) {
        (clock, 0)
    } else {
        let (clock, zone) = rest.split_at(rest.rfind(['+', '-'])?);
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let digits: String = zone[1..].chars().filter(char::is_ascii_digit).collect();
        if digits.len() != 4 {
            return None;
        }
        let hours: i64 = digits[..2].parse().ok()?;
        let minutes: i64 = digits[2..].parse().ok()?;
        (clock, sign * (hours * 3600 + minutes * 60))
    };
    let (whole, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    let mut clock = whole.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.parse().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut nanos = 0_u32;
    for (place, digit) in fraction.chars().take(9).enumerate() {
        let digit = digit.to_digit(10)?;
        nanos += digit * 10_u32.pow(8 - u32::try_from(place).ok()?);
    }
    // Days since 1970 of a civil date: Howard Hinnant's algorithm, with the year starting in March.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(u64::try_from(seconds).ok()?, nanos))
}

/// A folder of an account, as a provider names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFolder {
    /// The provider's own handle for it (a drive and an item id, a path, a folder id): whatever
    /// its connector needs to list it. Nobody else reads it.
    pub id: String,
    /// Its virtual path.
    pub path: PathBuf,
    /// Where a browser opens it; empty when the provider has no page for it.
    pub web_url: String,
}

/// The file formats a Google Docs, Sheets or Slides file is downloaded as, since it has no bytes of
/// its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Export {
    /// A document, as a Word file.
    Docx,
    /// A spreadsheet, as an Excel file.
    Xlsx,
    /// A presentation, as a `PowerPoint` file.
    Pptx,
}

impl Export {
    /// The media type to ask for.
    #[must_use]
    pub const fn mime(self) -> &'static str {
        match self {
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Self::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            Self::Pptx => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
        }
    }

    /// The file name extension of the format.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
        }
    }
}

/// A file of an account, as a provider lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteItem {
    /// The provider's own handle for it: whatever its connector needs to download it.
    pub id: String,
    /// Its virtual path.
    pub path: PathBuf,
    /// Its size in bytes as the listing says; 0 when the provider does not say (a Google Docs
    /// file has no size of its own).
    pub size: u64,
    /// When the service last saw its contents change.
    pub modified: SystemTime,
    /// Something that changes when the contents do: a content hash, a revision, an `ETag`. The
    /// scan reads the file again when it differs from the one it saw. Prefer what does not change
    /// when only the name or the sharing does.
    pub version: String,
    /// Where a browser opens the file; empty when the provider has no page for it.
    pub web_url: String,
    /// Set for a file with no bytes of its own: the format to download it as.
    pub export: Option<Export>,
}

/// What a path of an account names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    Folder(RemoteFolder),
    File(RemoteItem),
}

/// What happened in a folder and below it since a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changes {
    /// The files that are new or changed. Only files: a folder is nothing the inventory keeps.
    pub items: Vec<RemoteItem>,
    /// The virtual paths (of files or folders) that are gone or moved away: the inventory
    /// forgets what it holds at and under each. A feed that cannot name where something was
    /// answers with a full listing instead.
    pub removed: Vec<PathBuf>,
    /// Where to go on from next time. Opaque to everyone but the connector.
    pub cursor: String,
    /// `items` is every file under the root, not only what changed (a first listing, or a
    /// cursor the service no longer knows): what the inventory holds under the root that is not in
    /// `items` is gone.
    pub full: bool,
}

/// What a provider offers, for one connected account. Everything is read-only.
pub trait Connector: Send + Sync {
    /// The provider this connector talks to.
    fn provider(&self) -> Provider;

    /// The folders directly in `under`; for `None`, the top of the account (its drives, sites
    /// or "My Drive"): what a person picks a location from.
    ///
    /// # Errors
    /// A [`Error`] that says what to do about it.
    fn browse(&self, under: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>>;

    /// The folder or file at a virtual path of this account.
    ///
    /// # Errors
    /// `NotFound` when nothing is there.
    fn resolve(&self, path: &Path) -> Result<Resolved>;

    /// What changed in `root` and below since `cursor` (everything for `None`, or for a cursor
    /// the service no longer knows: then [`Changes::full`] is set). It follows the feed to its
    /// end, and gives up with `Cancelled` between two pages when `cancel` is set.
    ///
    /// # Errors
    /// A [`Error`] that says what to do about it.
    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<Changes>;

    /// The contents of `item`: at most `max` bytes. It is read in pieces, and gives up with
    /// `Cancelled` within a moment when `cancel` is set.
    ///
    /// # Errors
    /// `TooLarge` when it has more; `Cancelled`; a [`Error`] that says what to do about it.
    fn download(&self, item: &RemoteItem, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>>;

    /// The folder at a virtual path.
    ///
    /// # Errors
    /// `NotFound` when nothing is there, or a file is.
    fn folder(&self, path: &Path) -> Result<RemoteFolder> {
        match self.resolve(path)? {
            Resolved::Folder(folder) => Ok(folder),
            Resolved::File(_) => Err(Error::not_found(self.provider(), "a file, not a folder")),
        }
    }

    /// The file at a virtual path.
    ///
    /// # Errors
    /// `NotFound` when nothing is there, or a folder is.
    fn file(&self, path: &Path) -> Result<RemoteItem> {
        match self.resolve(path)? {
            Resolved::File(item) => Ok(item),
            Resolved::Folder(_) => Err(Error::not_found(self.provider(), "a folder, not a file")),
        }
    }
}

/// Why something with a cloud account failed. Each variant but the last two is a way to say it to
/// the person at the screen, with what to do about it (see [`fmt::Display`]): never an HTTP code.
/// What the service said is kept in `detail` for a person who is looking into it (it is in the
/// `Debug` text, never in the `Display` text, and never holds a token).
#[derive(Debug)]
pub enum Error {
    /// The account has to sign in again: the service no longer accepts what piikey holds.
    SignInNeeded { provider: Provider, detail: String },
    /// The service asks piikey to slow down; `retry_after` is how long it asked to wait.
    Throttled {
        provider: Provider,
        retry_after: Option<Duration>,
        detail: String,
    },
    /// The account may not read this: a permission or an administrator's consent is missing.
    Forbidden { provider: Provider, detail: String },
    /// The folder or file is not there (any more).
    NotFound { provider: Provider, detail: String },
    /// The service could not be reached, or did not answer in time.
    Network { provider: Provider, detail: String },
    /// The service answered something piikey cannot use.
    Unexpected { provider: Provider, detail: String },
    /// A file is over the size limit.
    TooLarge,
    /// The scan was stopped.
    Cancelled,
    /// Not about the cloud: this PC's inventory, a lock, the data folder.
    Local(crate::Error),
}

impl Error {
    /// [`Error::SignInNeeded`].
    #[must_use]
    pub fn sign_in_needed(provider: Provider, detail: impl Into<String>) -> Self {
        Self::SignInNeeded {
            provider,
            detail: detail.into(),
        }
    }

    /// [`Error::Throttled`].
    #[must_use]
    pub fn throttled(
        provider: Provider,
        retry_after: Option<Duration>,
        detail: impl Into<String>,
    ) -> Self {
        Self::Throttled {
            provider,
            retry_after,
            detail: detail.into(),
        }
    }

    /// [`Error::Forbidden`].
    #[must_use]
    pub fn forbidden(provider: Provider, detail: impl Into<String>) -> Self {
        Self::Forbidden {
            provider,
            detail: detail.into(),
        }
    }

    /// [`Error::NotFound`].
    #[must_use]
    pub fn not_found(provider: Provider, detail: impl Into<String>) -> Self {
        Self::NotFound {
            provider,
            detail: detail.into(),
        }
    }

    /// [`Error::Network`].
    #[must_use]
    pub fn network(provider: Provider, detail: impl Into<String>) -> Self {
        Self::Network {
            provider,
            detail: detail.into(),
        }
    }

    /// [`Error::Unexpected`].
    #[must_use]
    pub fn unexpected(provider: Provider, detail: impl Into<String>) -> Self {
        Self::Unexpected {
            provider,
            detail: detail.into(),
        }
    }

    /// The provider the failure is about, when there is one.
    #[must_use]
    pub const fn provider(&self) -> Option<Provider> {
        match self {
            Self::SignInNeeded { provider, .. }
            | Self::Throttled { provider, .. }
            | Self::Forbidden { provider, .. }
            | Self::NotFound { provider, .. }
            | Self::Network { provider, .. }
            | Self::Unexpected { provider, .. } => Some(*provider),
            Self::TooLarge | Self::Cancelled | Self::Local(_) => None,
        }
    }

    /// Whether trying again later can work without anyone doing anything: the service was busy or
    /// out of reach.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Throttled { .. } | Self::Network { .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignInNeeded { provider, .. } => {
                write!(f, "Sign in to {} again.", provider.name())
            }
            Self::Throttled { provider, .. } => write!(
                f,
                "{} is asking piikey to slow down. piikey will try again later.",
                provider.name()
            ),
            Self::Forbidden { provider, .. } => write!(
                f,
                "{} does not allow piikey to read this. Check what piikey may read there.",
                provider.name()
            ),
            Self::NotFound { provider, .. } => write!(
                f,
                "That folder or file is no longer in {}. It may have been moved, renamed or deleted.",
                provider.name()
            ),
            Self::Network { provider, .. } => write!(
                f,
                "piikey cannot reach {}. Check the internet connection and try again.",
                provider.name()
            ),
            Self::Unexpected { provider, .. } => write!(
                f,
                "{} gave an answer piikey cannot use. Try again later.",
                provider.name()
            ),
            Self::TooLarge => f.write_str("The file is too large to be read."),
            Self::Cancelled => f.write_str("The scan was stopped."),
            Self::Local(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Local(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Local(error.into())
    }
}

/// A failure on its way out of the library: the plain message is kept, the class is not.
/// `Throttled` and a service that cannot be reached become `Busy` (try again later), a local
/// failure stays what it was, and the rest become `BadRequest`.
impl From<Error> for crate::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Local(error) => error,
            Error::Throttled { .. } | Error::Network { .. } | Error::Cancelled => {
                Self::Busy(error.to_string())
            }
            _ => Self::BadRequest(error.to_string()),
        }
    }
}

/// Result alias for what talks to a cloud account.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The connector for `account`, talking to the real service. It signs in with what `tokens`
/// keeps for the account (see [`connect`]) and asks for a new access token when one is needed.
///
/// # Errors
/// `Local` with `BadRequest` when the account's way to sign in is not one its provider has.
pub fn connector(account: &Account, tokens: &TokenStore) -> Result<Box<dyn Connector>> {
    Ok(match account.provider {
        Provider::Microsoft365 | Provider::OneDrive => {
            Box::new(graph::Graph::new(account, tokens)?)
        }
        Provider::GoogleDrive => Box::new(google::Google::new(account, tokens)?),
        Provider::Dropbox => Box::new(dropbox::Dropbox::new(account, tokens)?),
        Provider::Box => Box::new(boxcom::BoxCom::new(account, tokens)?),
    })
}

/// Signs `account` in. For a way that has a person sign in ([`SignIn::needs_browser`]) that is
/// the whole browser flow: `open` is given the address to open (the app opens the browser, the
/// command line prints it), then this waits until the person has finished, for up to
/// [`SIGN_IN_TIMEOUT`] or until `cancel` is set, and the token store keeps what lets piikey read
/// the account from then on. For an app that holds its own credentials it asks the service for a
/// token once, which shows that the credentials work. The client secret, when the way has one,
/// must be in the token store already (see [`add_account`]).
///
/// # Errors
/// `Cancelled` when `cancel` was set; `Forbidden` when the person did not allow it or the
/// credentials do not work; `SignInNeeded` when the person did not finish in time; `Network`,
/// `Throttled` and `Unexpected` as for any call; `Local` for what is wrong on this PC (a key file
/// that cannot be read, the port of the sign-in is taken).
pub fn connect(
    account: &Account,
    tokens: &TokenStore,
    open: &dyn Fn(&str),
    cancel: &AtomicBool,
) -> Result<()> {
    let session = match account.provider {
        Provider::Microsoft365 | Provider::OneDrive => graph::session(account, tokens)?,
        Provider::GoogleDrive => google::session(account, tokens)?,
        Provider::Dropbox => dropbox::session(account, tokens)?,
        Provider::Box => boxcom::session(account, tokens)?,
    };
    session.connect(open, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_and_ids_round_trip() {
        for provider in Provider::ALL {
            assert_eq!(Provider::parse(provider.id()), Some(provider));
            assert_eq!(
                Provider::from_name(&provider.name().to_uppercase()),
                Some(provider)
            );
        }
        assert_eq!(Provider::parse("gdrive"), None);
    }

    #[test]
    fn a_virtual_path_is_taken_apart_into_account_and_rest() {
        let got = parse_virtual(Path::new(
            r"\\Google Drive\jan@acme.com\My Drive\Clients\a.docx",
        ));
        assert_eq!(
            got,
            Some(Virtual {
                provider: Provider::GoogleDrive,
                label: "jan@acme.com".to_owned(),
                rest: PathBuf::from(r"My Drive\Clients\a.docx"),
            })
        );
        let top = parse_virtual(Path::new(r"\\dropbox\Work")).map(|v| (v.provider, v.rest));
        assert_eq!(top, Some((Provider::Dropbox, PathBuf::new())));
        assert!(is_virtual(Path::new(r"\\Microsoft 365\Contoso\Finance")));
        for other in [
            r"C:\Users\jan",
            r"\\fileserver\share\x.txt",
            r"\\Box",
            r"relative\path",
            "",
        ] {
            assert!(!is_virtual(Path::new(other)), "{other}");
        }
    }

    #[test]
    fn an_account_root_is_a_virtual_path_of_its_own() {
        let account = Account {
            id: "0011223344556677".to_owned(),
            provider: Provider::OneDrive,
            label: "jan@outlook.com".to_owned(),
            sign_in: SignIn::MicrosoftDelegated {
                tenant: "consumers".to_owned(),
                client_id: "id".to_owned(),
            },
        };
        let root = account.root();
        assert_eq!(root, Path::new(r"\\OneDrive\jan@outlook.com"));
        let below = child(&root, "Documents");
        assert!(crate::sys::is_under(&below, &root));
        assert_eq!(
            parse_virtual(&below).map(|v| v.rest),
            Some(PathBuf::from("Documents"))
        );
    }

    #[test]
    fn a_name_becomes_one_legal_part() {
        for (name, part) in [
            ("Q1/Q2: plan?.docx", "Q1／Q2： plan？.docx"),
            (r"a\b", "a＼b"),
            ("Notes. ", "Notes__"),
            ("..", "__"),
            ("", "_"),
            ("tab\there", "tab_here"),
            ("con", "_con"),
            ("NUL.txt", "_NUL.txt"),
            ("com3", "_com3"),
            ("com0", "com0"),
            ("console", "console"),
            ("C:", "C："),
        ] {
            assert_eq!(component(name), part, "{name:?}");
        }
        let joined = child(Path::new(r"\\Box\Work"), "a/b");
        assert_eq!(
            joined.components().count(),
            3,
            "one prefix, one root, one part: {joined:?}"
        );
    }

    #[test]
    fn accounts_are_added_saved_and_found_by_their_virtual_path() -> crate::Result<()> {
        let data = crate::testing::temp_dir("accounts");
        assert!(Accounts::open(&data)?.list().is_empty());
        let sign_in = SignIn::GoogleDelegated {
            client_id: "client".to_owned(),
        };
        let account = Accounts::edit(&data, |accounts| {
            accounts.add(Provider::GoogleDrive, " jan@acme.com ", sign_in.clone())
        })?;
        assert_eq!(account.label, "jan@acme.com");
        assert_eq!(account.id.len(), 16);

        let again = Accounts::open(&data)?;
        assert_eq!(again.list(), std::slice::from_ref(&account));
        assert_eq!(again.get(&account.id), Some(&account));
        let file = child(&child(&account.root(), "My Drive"), "a.docx");
        assert_eq!(again.of(&file), Some(&account));
        assert_eq!(again.of(Path::new(r"\\Google Drive\other\x")), None);
        assert_eq!(
            again.of(Path::new(r"\\google drive\JAN@ACME.COM\x")),
            Some(&account)
        );

        // What is refused saves nothing, and neither does a change that fails.
        let refused = |label: &str, provider| {
            Accounts::edit(&data, |accounts| {
                accounts.add(provider, label, sign_in.clone()).map(|_| ())
            })
        };
        assert!(refused("JAN@acme.com", Provider::GoogleDrive).is_err());
        assert!(refused("a/b", Provider::GoogleDrive).is_err());
        assert!(refused("  ", Provider::GoogleDrive).is_err());
        assert!(refused("jan@acme.com", Provider::Dropbox).is_err());
        let failed = Accounts::edit(&data, |accounts| {
            accounts.remove(&account.id);
            Err::<(), _>(crate::Error::Poisoned)
        });
        assert!(failed.is_err());
        assert_eq!(
            Accounts::open(&data)?.list(),
            std::slice::from_ref(&account)
        );

        // Two processes that each saw the file before the other changed it lose nothing.
        let other = Accounts::edit(&data, |accounts| {
            accounts.add(Provider::GoogleDrive, "kim@acme.com", sign_in.clone())
        })?;
        assert_eq!(
            Accounts::open(&data)?.list(),
            [account.clone(), other.clone()]
        );
        let removed = Accounts::edit(&data, |accounts| Ok(accounts.remove(&account.id)))?;
        assert_eq!(removed, Some(account));
        assert_eq!(Accounts::open(&data)?.list(), [other]);
        Ok(())
    }

    #[test]
    fn what_the_service_said_stays_out_of_the_message() {
        let error = Error::forbidden(Provider::Box, "403 insufficient_scope for token abc");
        let shown = error.to_string();
        assert!(shown.contains("Box"), "{shown}");
        assert!(!shown.contains("403") && !shown.contains("abc"), "{shown}");
        assert!(format!("{error:?}").contains("403"));
        assert_eq!(
            Error::sign_in_needed(Provider::GoogleDrive, "x").to_string(),
            "Sign in to Google Drive again."
        );
        assert!(Error::network(Provider::Dropbox, "x").is_transient());
        assert!(!Error::forbidden(Provider::Dropbox, "x").is_transient());
    }

    #[test]
    fn an_error_leaves_the_library_as_a_plain_message() {
        let busy: crate::Error = Error::throttled(Provider::Box, None, "429").into();
        assert!(
            matches!(&busy, crate::Error::Busy(m) if m.contains("slow down")),
            "{busy}"
        );
        let local: crate::Error = Error::Local(crate::Error::Poisoned).into();
        assert!(matches!(local, crate::Error::Poisoned));
        let other: crate::Error = Error::not_found(Provider::Dropbox, "path/not_found").into();
        assert!(matches!(other, crate::Error::BadRequest(_)));
    }

    #[test]
    fn times_are_read_as_the_services_write_them() {
        let since_epoch = |text: &str| {
            parse_time(text).and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        };
        let at = Some(Duration::from_secs(1_700_000_000));
        assert_eq!(since_epoch("2023-11-14T22:13:20Z"), at);
        assert_eq!(since_epoch("2023-11-14T23:13:20+01:00"), at);
        assert_eq!(since_epoch("2023-11-14T14:13:20-08:00"), at);
        assert_eq!(since_epoch("2023-11-14T23:13:20+0100"), at);
        assert_eq!(
            since_epoch("2000-02-29T00:00:00Z"),
            Some(Duration::from_hours(264_384))
        );
        assert_eq!(
            since_epoch("2023-11-14T22:13:20.250Z"),
            Some(Duration::new(1_700_000_000, 250_000_000))
        );
        assert_eq!(
            // Windows keeps a time in 100 ns ticks: the last two digits are dropped.
            since_epoch("2023-11-14T22:13:20.1234567891Z"),
            Some(Duration::new(1_700_000_000, 123_456_700))
        );
        for bad in [
            "",
            "yesterday",
            "1969-12-31T23:59:59Z",
            "2023-13-01T00:00:00Z",
            "2023-11-14",
            "2023-11-14T25:00:00Z",
            "2023-11-14T10:00:00",
        ] {
            assert_eq!(since_epoch(bad), None, "{bad:?}");
        }
    }

    /// One of every way to sign in, with everything filled in.
    fn every_sign_in() -> Vec<(Provider, SignIn)> {
        let key = |name: &str| PathBuf::from(format!(r"C:\keys\{name}"));
        let certificate = || Credential::Certificate {
            key_file: key("app.key"),
            cert_file: key("app.crt"),
        };
        vec![
            (
                Provider::Microsoft365,
                SignIn::MicrosoftDelegated {
                    tenant: "organizations".to_owned(),
                    client_id: "c1".to_owned(),
                },
            ),
            (
                Provider::OneDrive,
                SignIn::MicrosoftDelegated {
                    tenant: "consumers".to_owned(),
                    client_id: "c1".to_owned(),
                },
            ),
            (
                Provider::Microsoft365,
                SignIn::MicrosoftApp {
                    tenant: "contoso.onmicrosoft.com".to_owned(),
                    client_id: "c2".to_owned(),
                    credential: Credential::Secret,
                },
            ),
            (
                Provider::Microsoft365,
                SignIn::MicrosoftAppSelected {
                    tenant: "t".to_owned(),
                    client_id: "c3".to_owned(),
                    credential: certificate(),
                    sites: vec!["https://contoso.sharepoint.com/sites/Finance".to_owned()],
                },
            ),
            (
                Provider::GoogleDrive,
                SignIn::GoogleDelegated {
                    client_id: "g1".to_owned(),
                },
            ),
            (
                Provider::GoogleDrive,
                SignIn::GoogleServiceAccount {
                    key_file: key("sa.json"),
                    users: vec!["jan@acme.com".to_owned()],
                },
            ),
            (
                Provider::Dropbox,
                SignIn::DropboxDelegated {
                    app_key: "k".to_owned(),
                },
            ),
            (
                Provider::Box,
                SignIn::BoxDelegated {
                    client_id: "b1".to_owned(),
                },
            ),
            (
                Provider::Box,
                SignIn::BoxApp {
                    client_id: "b2".to_owned(),
                    subject: BoxSubject::Enterprise("123".to_owned()),
                },
            ),
            (
                Provider::Box,
                SignIn::BoxApp {
                    client_id: "b2".to_owned(),
                    subject: BoxSubject::User("456".to_owned()),
                },
            ),
        ]
    }

    #[test]
    fn every_way_to_sign_in_is_saved_and_read_back_and_fits_only_its_provider() -> crate::Result<()>
    {
        let data = crate::testing::temp_dir("sign-ins");
        for (n, (provider, sign_in)) in every_sign_in().into_iter().enumerate() {
            assert_eq!(sign_in.missing(), None, "{sign_in:?}");
            assert!(sign_in.fits(provider), "{sign_in:?} {provider:?}");
            // Microsoft's browser sign-in serves both of its providers; nothing else is shared.
            let microsoft = |p: Provider| matches!(p, Provider::Microsoft365 | Provider::OneDrive);
            for other in Provider::ALL {
                if other != provider && !(microsoft(other) && microsoft(provider)) {
                    assert!(!sign_in.fits(other), "{sign_in:?} {other:?}");
                }
            }
            Accounts::edit(&data, |accounts| {
                accounts
                    .add(provider, &format!("account {n}"), sign_in.clone())
                    .map(|_| ())
            })?;
        }
        let saved = Accounts::open(&data)?;
        let back: Vec<SignIn> = saved.list().iter().map(|a| a.sign_in.clone()).collect();
        let sent: Vec<SignIn> = every_sign_in()
            .into_iter()
            .map(|(_, sign_in)| sign_in)
            .collect();
        assert_eq!(back, sent);

        // The file names no secret, only what the person typed in and where the files are.
        let text = fs::read_to_string(data.join(ACCOUNTS_FILE))?;
        assert!(
            text.contains(r#""mode": "microsoft_app_selected""#),
            "{text}"
        );
        assert!(
            text.contains(r#""type": "enterprise""#) && text.contains(r#""id": "123""#),
            "{text}"
        );
        assert!(
            !text.contains("client_secret")
                && !text.contains("refresh_token")
                && !text.contains("access_token"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn what_a_way_to_sign_in_needs_is_asked_for_in_plain_words() {
        let key = PathBuf::new();
        let blank = Credential::Certificate {
            key_file: key.clone(),
            cert_file: PathBuf::from("a.crt"),
        };
        for (sign_in, what) in [
            (
                SignIn::MicrosoftDelegated {
                    tenant: " ".to_owned(),
                    client_id: "c".to_owned(),
                },
                "the tenant",
            ),
            (
                SignIn::MicrosoftApp {
                    tenant: "t".to_owned(),
                    client_id: String::new(),
                    credential: Credential::Secret,
                },
                "the application (client) ID",
            ),
            (
                SignIn::MicrosoftApp {
                    tenant: "t".to_owned(),
                    client_id: "c".to_owned(),
                    credential: blank.clone(),
                },
                "the private key file",
            ),
            (
                SignIn::MicrosoftAppSelected {
                    tenant: "t".to_owned(),
                    client_id: "c".to_owned(),
                    credential: Credential::Secret,
                    sites: vec![" ".to_owned()],
                },
                "at least one site",
            ),
            (
                SignIn::GoogleDelegated {
                    client_id: String::new(),
                },
                "the client ID",
            ),
            (
                SignIn::GoogleServiceAccount {
                    key_file: PathBuf::from("k.json"),
                    users: Vec::new(),
                },
                "at least one user",
            ),
            (
                SignIn::DropboxDelegated {
                    app_key: String::new(),
                },
                "the app key",
            ),
            (
                SignIn::BoxApp {
                    client_id: "c".to_owned(),
                    subject: BoxSubject::User(String::new()),
                },
                "the user ID",
            ),
        ] {
            assert_eq!(sign_in.missing(), Some(what), "{sign_in:?}");
        }
        let mut accounts = Accounts::default();
        let error = accounts
            .add(
                Provider::Dropbox,
                "work",
                SignIn::DropboxDelegated {
                    app_key: String::new(),
                },
            )
            .err()
            .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("Fill in the app key."));
    }

    #[test]
    fn an_account_is_connected_when_what_it_needs_is_kept() -> crate::Result<()> {
        let data = crate::testing::temp_dir("connected");
        let tokens = TokenStore::new(&data);
        let box_app = Account {
            id: "00000000000000a1".to_owned(),
            provider: Provider::Box,
            label: "x".to_owned(),
            sign_in: SignIn::BoxApp {
                client_id: "c".to_owned(),
                subject: BoxSubject::Enterprise("1".to_owned()),
            },
        };
        let google = Account {
            id: "00000000000000a2".to_owned(),
            provider: Provider::GoogleDrive,
            label: "y".to_owned(),
            sign_in: SignIn::GoogleDelegated {
                client_id: "c".to_owned(),
            },
        };
        let service = Account {
            id: "00000000000000a3".to_owned(),
            provider: Provider::GoogleDrive,
            label: "z".to_owned(),
            sign_in: SignIn::GoogleServiceAccount {
                key_file: data.join("sa.json"),
                users: vec!["a@b.c".to_owned()],
            },
        };
        assert!(!box_app.is_connected(&tokens)?);
        assert!(!google.is_connected(&tokens)?);
        assert!(!service.is_connected(&tokens)?);
        tokens.save(&box_app.id, &Secrets::default().with_client_secret("s"))?;
        tokens.save(&google.id, &Secrets::default().with_client_secret("s"))?;
        fs::write(data.join("sa.json"), b"{}")?;
        assert!(box_app.is_connected(&tokens)?);
        assert!(
            !google.is_connected(&tokens)?,
            "a client secret is not a sign-in"
        );
        assert!(service.is_connected(&tokens)?);
        tokens.save(&google.id, &Secrets::default().with_refresh_token("r"))?;
        assert!(google.is_connected(&tokens)?);
        tokens.remove(&google.id)?;
        assert!(!google.is_connected(&tokens)?);
        Ok(())
    }

    #[test]
    fn an_account_is_added_with_its_secret_in_the_token_store_and_removed_with_everything()
    -> crate::Result<()> {
        let data = crate::testing::temp_dir("add-account");
        let sign_in = SignIn::BoxDelegated {
            client_id: "client".to_owned(),
        };

        // A way to sign in that needs a secret is not added without one.
        let refused = add_account(&data, Provider::Box, "team", sign_in.clone(), Some("  "));
        assert!(
            matches!(&refused, Err(crate::Error::BadRequest(m)) if m == "Fill in the client secret.")
        );
        assert!(Accounts::open(&data)?.list().is_empty());

        let account = add_account(&data, Provider::Box, "team", sign_in, Some("s3cr3t"))?;
        let tokens = TokenStore::new(&data);
        assert_eq!(
            tokens.load(&account.id)?.client_secret.as_deref(),
            Some("s3cr3t")
        );
        let settings = fs::read_to_string(data.join(ACCOUNTS_FILE))?;
        assert!(
            settings.contains("team") && !settings.contains("s3cr3t"),
            "{settings}"
        );

        // A secret given to a way that has none is not kept.
        let dropbox = add_account(
            &data,
            Provider::Dropbox,
            "work",
            SignIn::DropboxDelegated {
                app_key: "k".to_owned(),
            },
            Some("ignored"),
        )?;
        assert_eq!(tokens.load(&dropbox.id)?.client_secret, None);

        let cursors = Cursors::new(&data);
        cursors.set(&child(&account.root(), "Projects"), "c1")?;
        cursors.set(&child(&dropbox.root(), "Docs"), "c2")?;
        assert_eq!(remove_account(&data, "ffffffffffffffff")?, None);
        assert_eq!(remove_account(&data, &account.id)?, Some(account.clone()));
        assert_eq!(
            Accounts::open(&data)?.list(),
            std::slice::from_ref(&dropbox)
        );
        assert_eq!(
            tokens.load(&account.id)?.client_secret,
            None,
            "its secrets are gone"
        );
        assert_eq!(cursors.get(&child(&account.root(), "Projects"))?, None);
        assert_eq!(
            cursors.get(&child(&dropbox.root(), "Docs"))?.as_deref(),
            Some("c2")
        );
        Ok(())
    }

    #[test]
    fn every_account_gets_the_connector_of_its_provider() -> crate::Result<()> {
        let data = crate::testing::temp_dir("connectors");
        let tokens = TokenStore::new(&data);
        for (n, (provider, sign_in)) in every_sign_in().into_iter().enumerate() {
            let account = Account {
                id: format!("{n:016x}"),
                provider,
                label: format!("account {n}"),
                sign_in,
            };
            assert_eq!(connector(&account, &tokens)?.provider(), provider);
        }
        // A way to sign in the provider does not have is refused, by both entry points.
        let wrong = Account {
            id: format!("{:016x}", 99),
            provider: Provider::Box,
            label: "x".to_owned(),
            sign_in: SignIn::DropboxDelegated {
                app_key: "k".to_owned(),
            },
        };
        assert!(matches!(
            connector(&wrong, &tokens),
            Err(Error::Local(crate::Error::BadRequest(_)))
        ));
        let stopped = AtomicBool::new(false);
        assert!(matches!(
            connect(&wrong, &tokens, &|_| {}, &stopped),
            Err(Error::Local(crate::Error::BadRequest(_)))
        ));
        Ok(())
    }
}
