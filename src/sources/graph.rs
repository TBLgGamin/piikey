//! The Microsoft Graph connector: Microsoft 365 (`SharePoint` and `OneDrive` for Business) and
//! personal `OneDrive`.
//!
//! What a person picks as a location is a `SharePoint` site (all its document libraries), one
//! document library (a "drive" to Graph) or any folder in a library. Below the account's top the
//! virtual paths read `<site or OneDrive>\<library>\<folder>\...\<file>`; a personal `OneDrive`
//! (and the user's own `OneDrive` for Business, listed as `OneDrive`) has no site, so its libraries
//! are the drive itself.
//!
//! A person signs in as a public client (the authorization code with PKCE). Microsoft Entra
//! registers the loopback redirect of such an app as `http://localhost` and then takes
//! `http://localhost:<any port>`; it does not take `http://127.0.0.1:<port>`. So the address sent
//! names `localhost`, while the listener is on `127.0.0.1` only: a browser that tries `::1` first
//! finds nothing there and falls back to it.
//!
//! Change tracking is the drive's delta feed (`GET /drives/{id}/root/delta`). What the feed
//! promises, and how the code relies on it (see also the comments next to each use):
//! - `OneDrive` for Business and `SharePoint` support delta only on the root of a drive, so a
//!   location that is a folder takes the drive-wide feed and keeps what is under the folder.
//! - A delta page never has `parentReference.path` (renaming a folder returns none of its
//!   descendants), so items are tracked by id and their paths are built from the `parent id and
//!   name` chain.
//! - A removed item has the `deleted` facet and, on `OneDrive` for Business, only an id.
//! - A feed gives the latest state of an item and may name it more than once: the last one wins.
//! - `410 Gone` (`resyncRequired`, `syncStateNotFound`) says the delta link is no good any more.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, IgnoredAny},
};

use super::{
    Account, Changes, Connector, Credential, Error, Provider, RemoteFolder, RemoteItem, Resolved,
    Result, SignIn,
    auth::{App, AppCredential, Browser, ClientAuth, Grant, LOCALHOST, Session, TokenStore},
    child, component,
    http::{Http, Reply, Request, encode, encode_path, pages},
    parse_time, parse_virtual,
};

/// Where Graph is.
const GRAPH: &str = "https://graph.microsoft.com/v1.0";
/// Where Microsoft's sign-in is.
const LOGIN: &str = "https://login.microsoftonline.com";
/// What a person at a work or school account lets piikey read.
const SCOPE_WORK: &str = "Files.Read.All Sites.Read.All offline_access User.Read";
/// What a person at a personal Microsoft account lets piikey read.
const SCOPE_PERSONAL: &str = "Files.Read offline_access";
/// An app gets what its registration was given consent for.
const SCOPE_APP: &str = "https://graph.microsoft.com/.default";
/// The properties of an item piikey asks for.
const ITEM_FIELDS: &str = "id,name,size,file,folder,package,deleted,root,parentReference,\
                           lastModifiedDateTime,cTag,eTag,webUrl";
/// The properties of a folder piikey asks for to list folders.
const FOLDER_FIELDS: &str = "id,name,folder,package,webUrl";
/// A page of a folder's children (the most Graph gives for it).
const CHILDREN_PAGE: &str = "200";
/// A page of a delta feed.
const DELTA_PAGE: &str = "1000";
/// How long a delta link is trusted: what a feed cannot say (a file or folder moved or renamed
/// has no old path in it) is made good by a full listing at least this often. In seconds.
const RESYNC_AFTER: u64 = 7 * 24 * 3600;
/// The deepest folder tree followed: more means the feed loops.
const MAX_DEPTH: usize = 1000;
/// What the user's own drive is called in the paths.
const OWN_DRIVE: &str = "OneDrive";

/// The addresses of the services; a test points both at its mock.
#[derive(Debug, Clone)]
struct Endpoints {
    /// Microsoft Graph, with its version.
    graph: String,
    /// The sign-in service; the tenant and `/oauth2/v2.0/...` follow.
    login: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            graph: GRAPH.to_owned(),
            login: LOGIN.to_owned(),
        }
    }
}

/// What the account can see at the top.
#[derive(Debug, Clone)]
enum Mode {
    /// A person signed in: their own drive, the sites they follow and the sites a search finds.
    Delegated,
    /// An app with the rights to every site.
    App,
    /// An app with the rights to the listed sites (their addresses) only.
    Selected(Vec<String>),
}

/// A location in the account, as `RemoteFolder::id` spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    /// A `SharePoint` site: all its document libraries. `site:<site id>`.
    Site(String),
    /// A document library or a `OneDrive`. `drive:<drive id>`.
    Drive(String),
    /// A folder of a drive. `item:<drive id>|<item id>`.
    Folder {
        /// The drive that holds it.
        drive: String,
        /// The folder's item id.
        item: String,
    },
}

impl Place {
    /// The text `RemoteFolder::id` holds.
    fn id(&self) -> String {
        match self {
            Self::Site(site) => format!("site:{site}"),
            Self::Drive(drive) => format!("drive:{drive}"),
            Self::Folder { drive, item } => format!("item:{drive}|{item}"),
        }
    }

    /// The place `id` spells.
    fn parse(id: &str) -> Option<Self> {
        let (kind, rest) = id.split_once(':')?;
        match kind {
            "site" if !rest.is_empty() => Some(Self::Site(rest.to_owned())),
            "drive" if !rest.is_empty() => Some(Self::Drive(rest.to_owned())),
            "item" => {
                let (drive, item) = rest.split_once('|')?;
                (!drive.is_empty() && !item.is_empty()).then(|| Self::Folder {
                    drive: drive.to_owned(),
                    item: item.to_owned(),
                })
            }
            _ => None,
        }
    }
}

/// The connector for a Microsoft 365 or `OneDrive` account.
pub(crate) struct Graph {
    /// Microsoft 365 or `OneDrive`.
    provider: Provider,
    /// Signs the requests.
    session: Session,
    /// Graph's address with its version, without a slash at the end.
    base: String,
    /// The account's top: `\\<provider>\<label>`.
    root: PathBuf,
    /// The account's label, to tell its paths from those of another account.
    label: String,
    /// What the top lists.
    mode: Mode,
}

impl Graph {
    /// For a connected account, talking to Microsoft.
    ///
    /// # Errors
    /// `Local` (`BadRequest`) when the account's way of signing in does not fit Microsoft 365 or
    /// `OneDrive`, or lacks what it needs.
    pub(crate) fn new(account: &Account, tokens: &TokenStore) -> Result<Self> {
        Self::with(
            account,
            tokens,
            Http::new(account.provider),
            &Endpoints::default(),
        )
    }

    /// The connector over `http`, at the addresses `endpoints` names.
    fn with(
        account: &Account,
        tokens: &TokenStore,
        http: Http,
        endpoints: &Endpoints,
    ) -> Result<Self> {
        let (grant, mode) = setup(account, endpoints)?;
        Ok(Self {
            provider: account.provider,
            session: Session::new(http, tokens.clone(), &account.id, grant),
            base: endpoints.graph.trim_end_matches('/').to_owned(),
            root: account.root(),
            label: account.label.clone(),
            mode,
        })
    }
}

/// The session that signs the account in: `sources::connect` calls `session(..)?.connect(..)`.
///
/// # Errors
/// As [`Graph::new`].
pub(crate) fn session(account: &Account, tokens: &TokenStore) -> Result<Session> {
    let (grant, _) = setup(account, &Endpoints::default())?;
    Ok(Session::new(
        Http::new(account.provider),
        tokens.clone(),
        &account.id,
        grant,
    ))
}

/// A refusal to work with an account, in a plain sentence.
fn bad(text: impl Into<String>) -> Error {
    Error::Local(crate::Error::BadRequest(text.into()))
}

/// How the account signs in, and what it sees at the top.
fn setup(account: &Account, endpoints: &Endpoints) -> Result<(Grant, Mode)> {
    let name = account.provider.name();
    if !matches!(
        account.provider,
        Provider::Microsoft365 | Provider::OneDrive
    ) || !account.sign_in.fits(account.provider)
    {
        return Err(bad(format!(
            "This account cannot be read as {name}: the way it signs in does not fit."
        )));
    }
    let (tenant, client_id) = match &account.sign_in {
        SignIn::MicrosoftDelegated { tenant, client_id }
        | SignIn::MicrosoftApp {
            tenant, client_id, ..
        }
        | SignIn::MicrosoftAppSelected {
            tenant, client_id, ..
        } => (tenant.trim(), client_id.trim()),
        _ => return Err(bad(format!("This account does not sign in to {name}."))),
    };
    if client_id.is_empty() {
        return Err(bad(format!(
            "Add the application (client) ID of the app registration to read {name}."
        )));
    }
    let login = endpoints.login.trim_end_matches('/');
    let tenant = if tenant.is_empty() && account.sign_in.needs_browser() {
        if account.provider == Provider::OneDrive {
            "consumers"
        } else {
            "organizations"
        }
    } else {
        tenant
    };
    if tenant.is_empty() {
        return Err(bad(format!(
            "Add the directory (tenant) ID of the app registration to read {name}."
        )));
    }
    let token_url = format!("{login}/{}/oauth2/v2.0/token", encode(tenant));
    let credential = |credential: &Credential| match credential {
        Credential::Secret => AppCredential::Secret(ClientAuth::Body),
        Credential::Certificate {
            key_file,
            cert_file,
        } => AppCredential::Certificate {
            key_file: key_file.clone(),
            cert_file: cert_file.clone(),
        },
    };
    let app = |provided: &Credential| {
        Grant::App(App {
            token_url: token_url.clone(),
            client_id: client_id.to_owned(),
            scope: Some(SCOPE_APP.to_owned()),
            credential: credential(provided),
            extra: Vec::new(),
        })
    };
    Ok(match &account.sign_in {
        SignIn::MicrosoftDelegated { .. } => {
            let scope = if account.provider == Provider::OneDrive {
                SCOPE_PERSONAL
            } else {
                SCOPE_WORK
            };
            (
                Grant::Browser(Browser {
                    authorize_url: format!("{login}/{}/oauth2/v2.0/authorize", encode(tenant)),
                    token_url: token_url.clone(),
                    client_id: client_id.to_owned(),
                    scope: scope.to_owned(),
                    authorize_extra: Vec::new(),
                    client_auth: ClientAuth::None,
                    // Entra takes `http://localhost:<any port>` for the `http://localhost` that a
                    // public client is registered with, and not `http://127.0.0.1:<port>`.
                    redirect_host: LOCALHOST,
                    port: 0,
                    redirect_path: String::new(),
                    pkce: true,
                }),
                Mode::Delegated,
            )
        }
        SignIn::MicrosoftApp {
            credential: provided,
            ..
        } => (app(provided), Mode::App),
        SignIn::MicrosoftAppSelected {
            credential: provided,
            sites,
            ..
        } => (app(provided), Mode::Selected(sites.clone())),
        _ => return Err(bad(format!("This account does not sign in to {name}."))),
    })
}

/// A field that may be `null` or missing is its default.
fn or_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A page of a Graph collection.
#[derive(Deserialize)]
struct Page<T> {
    /// What the page holds.
    #[serde(default = "Vec::new")]
    value: Vec<T>,
    /// The next page, when there is one.
    #[serde(default, rename = "@odata.nextLink", deserialize_with = "or_default")]
    next: String,
    /// Where a delta feed goes on from, on its last page.
    #[serde(default, rename = "@odata.deltaLink", deserialize_with = "or_default")]
    delta: String,
}

/// Where an item is: its parent.
#[derive(Deserialize, Default)]
struct Parent {
    /// The parent's id; none for the root of a drive.
    #[serde(default, deserialize_with = "or_default")]
    id: String,
}

/// A drive item, as much of it as piikey asks for.
#[derive(Deserialize, Default)]
struct Item {
    #[serde(default, deserialize_with = "or_default")]
    id: String,
    #[serde(default, deserialize_with = "or_default")]
    name: String,
    #[serde(default, deserialize_with = "or_default")]
    size: u64,
    /// When the contents last changed (not `fileSystemInfo`, which a client may set).
    #[serde(
        default,
        rename = "lastModifiedDateTime",
        deserialize_with = "or_default"
    )]
    modified: String,
    #[serde(default, rename = "cTag", deserialize_with = "or_default")]
    ctag: String,
    #[serde(default, rename = "eTag", deserialize_with = "or_default")]
    etag: String,
    #[serde(default, rename = "webUrl", deserialize_with = "or_default")]
    web_url: String,
    /// Set for a file.
    #[serde(default)]
    file: Option<IgnoredAny>,
    /// Set for a folder.
    #[serde(default)]
    folder: Option<IgnoredAny>,
    /// Set for a `OneNote` notebook and the like, which is neither a file nor a folder to piikey.
    #[serde(default)]
    package: Option<IgnoredAny>,
    /// Set for an item a delta feed says is gone.
    #[serde(default)]
    deleted: Option<IgnoredAny>,
    /// Set for the root of a drive.
    #[serde(default)]
    root: Option<IgnoredAny>,
    #[serde(default, rename = "parentReference", deserialize_with = "or_default")]
    parent: Parent,
}

impl Item {
    /// Whether it is a file.
    const fn is_file(&self) -> bool {
        self.file.is_some()
    }

    /// Whether it is a folder with files in it (a notebook is not).
    const fn is_folder(&self) -> bool {
        self.folder.is_some() && self.package.is_none()
    }

    /// What changes when the contents do: the `cTag` (which the name, place and sharing leave
    /// alone) where there is one, else the `eTag`. A delta feed of `OneDrive` for Business has no
    /// `cTag` for an item.
    fn version(&self) -> String {
        if self.ctag.is_empty() {
            self.etag.clone()
        } else {
            self.ctag.clone()
        }
    }

    /// Where it hangs in a drive, when the item says so: a root, or a name and a parent.
    fn node(&self) -> Option<Node> {
        if self.root.is_some() {
            return Some(Node {
                parent: None,
                name: String::new(),
            });
        }
        (!self.parent.id.is_empty() && !self.name.is_empty()).then(|| Node {
            parent: Some(self.parent.id.clone()),
            name: self.name.clone(),
        })
    }

    /// Where it hangs, from the answer to a request for this one item: no parent is a root.
    fn fetched(&self) -> Node {
        Node {
            parent: (!self.parent.id.is_empty()).then(|| self.parent.id.clone()),
            name: self.name.clone(),
        }
    }

    /// The file for the inventory, at `path` in `drive`.
    fn remote(&self, drive: &str, path: PathBuf) -> RemoteItem {
        RemoteItem {
            id: format!("{drive}|{}", self.id),
            path,
            size: self.size,
            modified: parse_time(&self.modified).unwrap_or(UNIX_EPOCH),
            version: self.version(),
            web_url: self.web_url.clone(),
            export: None,
        }
    }
}

/// A site, or a drive: what the lists of them have in common.
#[derive(Deserialize, Default)]
struct Entry {
    #[serde(default, deserialize_with = "or_default")]
    id: String,
    #[serde(default, deserialize_with = "or_default")]
    name: String,
    #[serde(default, rename = "displayName", deserialize_with = "or_default")]
    display_name: String,
    #[serde(default, rename = "webUrl", deserialize_with = "or_default")]
    web_url: String,
}

impl Entry {
    /// What a person calls it.
    fn title(&self) -> String {
        [&self.display_name, &self.name, &self.id]
            .into_iter()
            .find(|text| !text.is_empty())
            .cloned()
            .unwrap_or_default()
    }
}

/// An item's place in the tree of its drive.
#[derive(Debug, Clone)]
struct Node {
    /// The folder that holds it; none for the root of the drive.
    parent: Option<String>,
    /// Its name.
    name: String,
}

/// A file a delta feed named.
struct File {
    /// The folder that holds it.
    parent: String,
    /// Its name.
    name: String,
    /// The file for the inventory, without its path.
    item: Item,
}

/// What a delta feed said, merged: the last word on each item.
#[derive(Default)]
struct Feed {
    /// Where the next feed goes on from.
    link: String,
    /// What is known of the tree: name and parent of every item that said so.
    nodes: HashMap<String, Node>,
    /// The files that are there.
    files: HashMap<String, File>,
    /// The ids that were removed.
    deleted: HashSet<String>,
}

impl Feed {
    /// Takes one item of a page: it replaces what the feed said of it before.
    fn take(&mut self, item: Item) {
        if item.id.is_empty() {
            return;
        }
        // A removed item may still say its name and parent (a personal OneDrive does; OneDrive
        // for Business gives an id only): what an earlier page said stays when it does not.
        if let Some(node) = item.node() {
            self.nodes.insert(item.id.clone(), node);
        }
        if item.deleted.is_some() {
            self.files.remove(&item.id);
            self.deleted.insert(item.id);
            return;
        }
        self.deleted.remove(&item.id);
        if item.is_file() && !item.parent.id.is_empty() && !item.name.is_empty() {
            self.files.insert(
                item.id.clone(),
                File {
                    parent: item.parent.id.clone(),
                    name: item.name.clone(),
                    item,
                },
            );
        } else {
            self.files.remove(&item.id);
        }
    }
}

/// Why a feed could not be turned into changes.
enum Break {
    /// The feed cannot be used: only a full listing is right.
    Resync,
    /// Something failed.
    Fail(Error),
}

impl From<Error> for Break {
    fn from(error: Error) -> Self {
        Self::Fail(error)
    }
}

/// A result that may ask for a full listing.
type Walk<T> = std::result::Result<T, Break>;

/// Paths of the folders of a drive, built from the ids a feed gave.
struct Paths<'a> {
    /// Where unseen parents are asked for.
    graph: &'a Graph,
    /// The drive.
    drive: &'a str,
    /// The virtual path of what the scan is about (the drive, or the folder).
    base: &'a Path,
    /// The id of the folder the scan is about, when it is not the whole drive.
    top: Option<&'a str>,
    /// What is known of the tree.
    nodes: HashMap<String, Node>,
    /// Ids that were asked for and are not there.
    gone: HashSet<String>,
    /// The paths worked out so far; none is outside what the scan is about.
    known: HashMap<String, Option<PathBuf>>,
}

impl Paths<'_> {
    /// Where item `id` hangs: from the feed, or else asked for (once).
    fn node(&mut self, id: &str) -> Walk<Node> {
        if let Some(node) = self.nodes.get(id) {
            return Ok(node.clone());
        }
        if self.gone.contains(id) {
            return Err(Break::Resync);
        }
        let request = Request::get(self.graph.url(&format!(
            "/drives/{}/items/{}",
            seg(self.drive),
            seg(id)
        )))
        .query("$select", "id,name,root,parentReference");
        let reply = self.graph.session.send(&request)?;
        if !reply.is_success() {
            let error = failure(self.graph.provider, &reply);
            if matches!(error, Error::NotFound { .. }) {
                self.gone.insert(id.to_owned());
                return Err(Break::Resync);
            }
            return Err(Break::Fail(error));
        }
        let node = reply.json::<Item>()?.fetched();
        self.nodes.insert(id.to_owned(), node.clone());
        Ok(node)
    }

    /// The virtual path of folder `start`; `None` when it is not under what the scan is about.
    fn folder(&mut self, start: &str) -> Walk<Option<PathBuf>> {
        // The chain from `start` upwards, to the first folder whose path is known.
        let mut chain: Vec<(String, String)> = Vec::new();
        let mut at = start.to_owned();
        let mut path = loop {
            if self.top == Some(at.as_str()) {
                break Some(self.base.to_path_buf());
            }
            if let Some(known) = self.known.get(&at) {
                break known.clone();
            }
            let node = self.node(&at)?;
            let Some(parent) = node.parent else {
                // The root of the drive: everything is under it, or nothing is under the folder.
                break self.top.is_none().then(|| self.base.to_path_buf());
            };
            if chain.len() >= MAX_DEPTH {
                return Err(Break::Fail(Error::unexpected(
                    self.graph.provider,
                    "the folders nest without an end",
                )));
            }
            chain.push((at, node.name));
            at = parent;
        };
        for (id, name) in chain.into_iter().rev() {
            path = path.map(|above| child(&above, &name));
            self.known.insert(id, path.clone());
        }
        Ok(path)
    }
}

/// A library or the like, as the account's top and a site list it.
struct Top {
    /// What it is called in the paths.
    name: String,
    /// Where it is: a site or a drive.
    place: Place,
    /// Where a browser opens it.
    web_url: String,
}

/// A drive a scan covers.
struct DriveRef {
    /// The drive's id.
    id: String,
    /// The last part of its virtual path: a library that is renamed is told by it.
    name: String,
    /// Its virtual path.
    base: PathBuf,
}

impl DriveRef {
    /// The drive `id` that is at `base`.
    fn new(id: String, base: PathBuf) -> Self {
        let name = base
            .file_name()
            .map(|part| part.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self { id, name, base }
    }
}

/// What a scan covers: drives, and the folder in them when it is not the whole of them.
struct Scope {
    /// The drives: one, or the libraries of a site.
    drives: Vec<DriveRef>,
    /// The folder's item id, when the location is a folder.
    top: Option<String>,
}

/// One drive's place in a cursor.
#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    /// The last part of the drive's virtual path when the link was taken.
    #[serde(rename = "n")]
    name: String,
    /// The delta link to go on from.
    #[serde(rename = "l")]
    link: String,
}

/// What [`Changes::cursor`] holds, as JSON: the delta link of each drive of the location.
#[derive(Clone, Serialize, Deserialize)]
struct Cursor {
    /// The location it is for (`RemoteFolder::id`).
    #[serde(rename = "s")]
    scope: String,
    /// When the last full listing was taken, in seconds since the Unix epoch.
    #[serde(rename = "t")]
    full_at: u64,
    /// The drive id and its link.
    #[serde(rename = "d")]
    drives: BTreeMap<String, Stored>,
}

impl Cursor {
    /// The cursor `text` when it is good for `scope` and these `drives` at time `now`: the same
    /// libraries under the same names (a library that was added, removed or renamed needs a full
    /// listing) and not too old.
    fn accept(text: &str, scope: &str, drives: &[DriveRef], now: u64) -> Option<Self> {
        let cursor: Self = serde_json::from_str(text).ok()?;
        let same = cursor.scope == scope
            && cursor.drives.len() == drives.len()
            && drives.iter().all(|drive| {
                cursor
                    .drives
                    .get(&drive.id)
                    .is_some_and(|stored| stored.name == drive.name)
            });
        (same && now.saturating_sub(cursor.full_at) < RESYNC_AFTER).then_some(cursor)
    }
}

/// Seconds since the Unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// An id as one segment of a URL's path. Graph writes ids with `!` and `,` as they are.
fn seg(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    let mut start = 0;
    for (at, c) in id.char_indices() {
        if matches!(c, ',' | '!') {
            out.push_str(&encode(&id[start..at]));
            out.push(c);
            start = at + 1;
        }
    }
    out.push_str(&encode(&id[start..]));
    out
}

/// What a part of a path is compared by: letter case does not count.
fn key(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// The entries in the order given, each with its virtual path under `base`; a name that is taken
/// is followed by ` (2)`, ` (3)`...
fn named<T>(base: &Path, entries: Vec<(String, T)>) -> Vec<(PathBuf, T)> {
    let mut taken = HashSet::new();
    entries
        .into_iter()
        .map(|(name, value)| {
            let mut number = 1_u32;
            loop {
                let label = if number == 1 {
                    name.clone()
                } else {
                    format!("{name} ({number})")
                };
                let path = child(base, &label);
                if taken.insert(key(&path)) {
                    break (path, value);
                }
                number += 1;
            }
        })
        .collect()
}

/// Whether `component` may have changed the name a part of a path stands for.
fn may_be_changed(part: &str) -> bool {
    part.starts_with('_')
        || part.ends_with('_')
        || part.chars().any(|c| {
            matches!(
                c,
                '＼' | '／' | '：' | '＊' | '？' | '＂' | '＜' | '＞' | '｜'
            )
        })
}

/// What Graph said was wrong, as the JSON body gives it.
#[derive(Deserialize, Default)]
struct Fault {
    #[serde(default, deserialize_with = "or_default")]
    code: String,
    #[serde(default, deserialize_with = "or_default")]
    message: String,
}

/// The body of an error answer: `{"error": {"code": ..., "message": ...}}`.
#[derive(Deserialize, Default)]
struct Failure {
    #[serde(default, deserialize_with = "or_default")]
    error: Fault,
}

/// What a reply that is not a success stands for. Graph's own code says more than the status:
/// `itemNotFound`, `accessDenied`, `InvalidAuthenticationToken` (after the session's one retry
/// with a new token), `activityLimitReached` and `TooManyRequests` (throttling; `Retry-After`
/// says for how long).
fn failure(provider: Provider, reply: &Reply) -> Error {
    let fault = serde_json::from_slice::<Failure>(&reply.body)
        .unwrap_or_default()
        .error;
    let mut detail = format!("HTTP {}: {}: {}", reply.status, fault.code, fault.message);
    detail.truncate(
        detail
            .char_indices()
            .nth(300)
            .map_or(detail.len(), |(at, _)| at),
    );
    match fault.code.to_ascii_lowercase().as_str() {
        "itemnotfound" => Error::not_found(provider, detail),
        "accessdenied" => Error::forbidden(provider, detail),
        "invalidauthenticationtoken" => Error::sign_in_needed(provider, detail),
        "activitylimitreached" | "toomanyrequests" => {
            Error::throttled(provider, reply.retry_after(), detail)
        }
        _ => reply.error(),
    }
}

/// Whether a reply says the delta link is no good any more: `410 Gone` with `resyncRequired` or
/// `syncStateNotFound` (Graph's docs name `resyncChangesApplyDifferences` and
/// `resyncChangesUploadDifferences` too). It then names a new link to start from: piikey takes
/// a full listing instead.
fn is_resync(reply: &Reply) -> bool {
    reply.status == 410
        || matches!(
            serde_json::from_slice::<Failure>(&reply.body)
                .unwrap_or_default()
                .error
                .code
                .to_ascii_lowercase()
                .as_str(),
            "resyncrequired"
                | "syncstatenotfound"
                | "resyncchangesapplydifferences"
                | "resyncchangesuploaddifferences"
        )
}

impl Graph {
    /// `path` at Graph.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Sends `request`; what is not a success is what Graph's error says it is.
    fn send(&self, request: &Request) -> Result<Reply> {
        let reply = self.session.send(request)?;
        if reply.is_success() {
            Ok(reply)
        } else {
            Err(failure(self.provider, &reply))
        }
    }

    /// Every item of a collection, from `first` through its last page.
    fn list<T: DeserializeOwned>(&self, first: Request, cancel: &AtomicBool) -> Result<Vec<T>> {
        let mut all = Vec::new();
        pages(
            self.provider,
            cancel,
            first,
            &|request| self.send(request),
            |reply| {
                let page: Page<T> = reply.json()?;
                all.extend(page.value);
                Ok((!page.next.is_empty()).then(|| Request::get(page.next)))
            },
        )?;
        Ok(all)
    }

    /// The children of folder `item` of `drive` (the root when none), `fields` of each.
    fn children(&self, drive: &str, item: Option<&str>, fields: &str) -> Request {
        let path = item.map_or_else(
            || format!("/drives/{}/root/children", seg(drive)),
            |item| format!("/drives/{}/items/{}/children", seg(drive), seg(item)),
        );
        Request::get(self.url(&path))
            .query("$select", fields)
            .query("$top", CHILDREN_PAGE)
    }

    /// The signed-in person's own drive.
    fn own_drive(&self) -> Result<Entry> {
        self.send(&Request::get(self.url("/me/drive")).query("$select", "id,name,webUrl"))?
            .json()
    }

    /// The site at an address such as `https://contoso.sharepoint.com/sites/Finance`, through
    /// `/sites/{hostname}:/{server-relative-path}`.
    fn site_at(&self, address: &str) -> Result<Entry> {
        let address = address.trim();
        let rest = address.split_once("://").map_or(address, |(_, rest)| rest);
        let rest = rest.split(['?', '#']).next().unwrap_or_default();
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = path.trim_matches('/');
        if host.is_empty() {
            return Err(Error::not_found(
                self.provider,
                "an address without a server",
            ));
        }
        let target = if path.is_empty() {
            format!("/sites/{}", encode(host))
        } else {
            format!("/sites/{}:/{}", encode(host), encode_path(path))
        };
        self.send(&Request::get(self.url(&target)).query("$select", "id,name,displayName,webUrl"))?
            .json()
    }

    /// What the account's top lists, in the order given: the user's own drive first, then the
    /// sites by name.
    fn tops(&self) -> Result<Vec<(PathBuf, Top)>> {
        let never = AtomicBool::new(false);
        let mut tops = Vec::new();
        let mut sites: Vec<Entry> = Vec::new();
        match &self.mode {
            Mode::Delegated => {
                match self.own_drive() {
                    Ok(drive) => tops.push(Top {
                        name: OWN_DRIVE.to_owned(),
                        place: Place::Drive(drive.id),
                        web_url: drive.web_url,
                    }),
                    // A work account may have no OneDrive (not set up, or no licence).
                    Err(Error::NotFound { .. } | Error::Forbidden { .. })
                        if self.provider == Provider::Microsoft365 => {}
                    Err(error) => return Err(error),
                }
                if self.provider == Provider::Microsoft365 {
                    match self.list(Request::get(self.url("/me/followedSites")), &never) {
                        Ok(followed) => sites.extend(followed),
                        Err(Error::NotFound { .. } | Error::Forbidden { .. }) => {}
                        Err(error) => return Err(error),
                    }
                    sites.extend(self.found_sites(&never)?);
                }
            }
            Mode::App => sites.extend(self.found_sites(&never)?),
            Mode::Selected(addresses) => {
                // The service cannot list what `Sites.Selected` was given: the account names it.
                for address in addresses {
                    match self.site_at(address) {
                        Ok(site) => sites.push(site),
                        Err(Error::NotFound { .. }) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        let mut seen = HashSet::new();
        sites.retain(|site| !site.id.is_empty() && seen.insert(site.id.clone()));
        sites.sort_by_cached_key(|site| (site.title().to_lowercase(), site.id.clone()));
        tops.extend(sites.into_iter().map(|site| Top {
            name: site.title(),
            place: Place::Site(site.id),
            web_url: site.web_url,
        }));
        Ok(named(
            &self.root,
            tops.into_iter()
                .map(|top| (top.name.clone(), top))
                .collect(),
        ))
    }

    /// The sites a search for everything finds (`GET /sites?search=*`).
    fn found_sites(&self, cancel: &AtomicBool) -> Result<Vec<Entry>> {
        self.list(
            Request::get(self.url("/sites")).query("search", "*"),
            cancel,
        )
    }

    /// The document libraries of a site, sorted, with their virtual paths under `base`.
    fn libraries(&self, site: &str, base: &Path) -> Result<Vec<(PathBuf, Entry)>> {
        let never = AtomicBool::new(false);
        let mut drives: Vec<Entry> = self.list(
            Request::get(self.url(&format!("/sites/{}/drives", seg(site)))),
            &never,
        )?;
        drives.retain(|drive| !drive.id.is_empty());
        drives.sort_by_cached_key(|drive| (drive.title().to_lowercase(), drive.id.clone()));
        Ok(named(
            base,
            drives
                .into_iter()
                .map(|drive| (drive.title(), drive))
                .collect(),
        ))
    }

    /// The folders in `item` of `drive`, as folders below the virtual path `base`.
    fn folders(&self, drive: &str, item: Option<&str>, base: &Path) -> Result<Vec<RemoteFolder>> {
        let never = AtomicBool::new(false);
        let mut found: Vec<Item> = self.list(self.children(drive, item, FOLDER_FIELDS), &never)?;
        found.retain(Item::is_folder);
        found.sort_by_cached_key(|folder| (folder.name.to_lowercase(), folder.id.clone()));
        Ok(named(
            base,
            found
                .into_iter()
                .map(|folder| (folder.name.clone(), folder))
                .collect(),
        )
        .into_iter()
        .map(|(path, folder)| RemoteFolder {
            id: Place::Folder {
                drive: drive.to_owned(),
                item: folder.id,
            }
            .id(),
            path,
            web_url: folder.web_url,
        })
        .collect())
    }

    /// The parts of `path` below the account's top.
    fn parts(&self, path: &Path) -> Result<Vec<String>> {
        let gone = || Error::not_found(self.provider, "a path of another account");
        let virtual_path = parse_virtual(path).ok_or_else(gone)?;
        if virtual_path.provider != self.provider
            || !virtual_path.label.eq_ignore_ascii_case(&self.label)
        {
            return Err(gone());
        }
        virtual_path
            .rest
            .components()
            .map(|part| part.as_os_str().to_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(gone)
    }

    /// What is at `parts` inside `drive`, whose virtual path is `base`.
    fn inside(
        &self,
        drive: &str,
        base: &Path,
        web_url: String,
        parts: &[String],
    ) -> Result<Resolved> {
        let Some((last, above)) = parts.split_last() else {
            return Ok(Resolved::Folder(RemoteFolder {
                id: Place::Drive(drive.to_owned()).id(),
                path: base.to_path_buf(),
                web_url,
            }));
        };
        let request = Request::get(self.url(&format!(
            "/drives/{}/root:/{}",
            seg(drive),
            encode_path(&parts.join("/"))
        )))
        .query("$select", ITEM_FIELDS);
        let item: Item = match self.send(&request) {
            Ok(reply) => reply.json()?,
            // A part that `component` may have changed is not a name Graph knows: look at the
            // names in each folder instead.
            Err(Error::NotFound { .. }) if parts.iter().any(|part| may_be_changed(part)) => {
                self.walk(drive, parts)?
            }
            Err(error) => return Err(error),
        };
        let mut path = base.to_path_buf();
        for part in above {
            path = child(&path, part);
        }
        let path = child(
            &path,
            if item.name.is_empty() {
                last
            } else {
                &item.name
            },
        );
        if item.is_file() {
            Ok(Resolved::File(item.remote(drive, path)))
        } else if item.is_folder() {
            Ok(Resolved::Folder(RemoteFolder {
                id: Place::Folder {
                    drive: drive.to_owned(),
                    item: item.id,
                }
                .id(),
                path,
                web_url: item.web_url,
            }))
        } else {
            Err(Error::not_found(
                self.provider,
                "neither a file nor a folder",
            ))
        }
    }

    /// The item at `parts` found by looking at the names in each folder from the top of `drive`.
    fn walk(&self, drive: &str, parts: &[String]) -> Result<Item> {
        let never = AtomicBool::new(false);
        let mut at: Option<String> = None;
        let mut found = None;
        for (number, part) in parts.iter().enumerate() {
            let want = part.to_lowercase();
            let hit: Item = self
                .list::<Item>(self.children(drive, at.as_deref(), ITEM_FIELDS), &never)?
                .into_iter()
                .find(|item| component(&item.name).to_lowercase() == want)
                .ok_or_else(|| Error::not_found(self.provider, "no item of that name"))?;
            if number + 1 < parts.len() && !hit.is_folder() {
                return Err(Error::not_found(
                    self.provider,
                    "a file where a folder was named",
                ));
            }
            at = Some(hit.id.clone());
            found = Some(hit);
        }
        found.ok_or_else(|| Error::not_found(self.provider, "no name"))
    }

    /// What a location covers.
    fn scope(&self, place: &Place, path: &Path) -> Result<Scope> {
        Ok(match place {
            Place::Drive(id) => Scope {
                drives: vec![DriveRef::new(id.clone(), path.to_path_buf())],
                top: None,
            },
            Place::Folder { drive, item } => Scope {
                drives: vec![DriveRef::new(drive.clone(), path.to_path_buf())],
                top: Some(item.clone()),
            },
            Place::Site(site) => Scope {
                drives: self
                    .libraries(site, path)?
                    .into_iter()
                    .map(|(base, drive)| DriveRef::new(drive.id, base))
                    .collect(),
                top: None,
            },
        })
    }

    /// The first request of a drive's delta feed.
    fn delta(&self, drive: &str) -> Request {
        Request::get(self.url(&format!("/drives/{}/root/delta", seg(drive))))
    }

    /// Reads a delta feed from `first` to its last page and merges it.
    fn feed(&self, first: Request, cancel: &AtomicBool) -> Walk<Feed> {
        let mut feed = Feed::default();
        let mut resync = false;
        let mut link = String::new();
        pages(
            self.provider,
            cancel,
            first,
            &|request| self.session.send(request),
            |reply| {
                if !reply.is_success() {
                    if is_resync(&reply) {
                        resync = true;
                        return Ok(None);
                    }
                    return Err(failure(self.provider, &reply));
                }
                let page: Page<Item> = reply.json()?;
                for item in page.value {
                    feed.take(item);
                }
                if page.next.is_empty() {
                    link = page.delta;
                    Ok(None)
                } else {
                    Ok(Some(Request::get(page.next)))
                }
            },
        )?;
        if resync {
            return Err(Break::Resync);
        }
        if link.is_empty() {
            return Err(Break::Fail(Error::unexpected(
                self.provider,
                "the change feed ended without a link to go on from",
            )));
        }
        feed.link = link;
        Ok(feed)
    }

    /// The files and removals a feed amounts to under `base` (the virtual path of `drive`, or of
    /// the folder `top` in it), and the link to go on from. A full feed has no removals.
    fn assemble(
        &self,
        drive: &str,
        top: Option<&str>,
        base: &Path,
        feed: Feed,
        removals: bool,
    ) -> Walk<(Vec<RemoteItem>, Vec<PathBuf>, String)> {
        let Feed {
            link,
            nodes,
            files,
            deleted,
        } = feed;
        let mut paths = Paths {
            graph: self,
            drive,
            base,
            top,
            nodes,
            gone: HashSet::new(),
            known: HashMap::new(),
        };
        let mut items = Vec::new();
        let mut seen = HashSet::new();
        for file in files.into_values() {
            // Only what is under the folder counts: a folder's feed is the drive's.
            let Some(dir) = paths.folder(&file.parent)? else {
                continue;
            };
            let path = child(&dir, &file.name);
            if seen.insert(path.clone()) {
                items.push(file.item.remote(drive, path));
            }
        }
        let mut removed = Vec::new();
        if removals {
            for id in deleted {
                if top == Some(id.as_str()) {
                    removed.push(base.to_path_buf());
                    continue;
                }
                // Only an earlier word of the same feed says where a removed item was: asking
                // for it now finds nothing, and a path that cannot be told is not guessed.
                let Some(node) = paths.nodes.get(&id).cloned() else {
                    return Err(Break::Resync);
                };
                let Some(parent) = node.parent else { continue };
                if let Some(dir) = paths.folder(&parent)? {
                    removed.push(child(&dir, &node.name));
                }
            }
        }
        items.sort_by_cached_key(|item| item.path.clone());
        removed.sort();
        removed.dedup();
        Ok((items, removed, link))
    }

    /// What changed since `saved`; `Resync` when only a full listing is right.
    fn incremental(&self, scope: &Scope, saved: &Cursor, cancel: &AtomicBool) -> Walk<Changes> {
        let mut items = Vec::new();
        let mut removed = Vec::new();
        let mut cursor = saved.clone();
        for drive in &scope.drives {
            let Some(stored) = saved.drives.get(&drive.id) else {
                return Err(Break::Resync);
            };
            // The stored link is requested as it is: it carries its own query.
            let feed = self.feed(Request::get(stored.link.clone()), cancel)?;
            let (more, gone, link) =
                self.assemble(&drive.id, scope.top.as_deref(), &drive.base, feed, true)?;
            items.extend(more);
            removed.extend(gone);
            cursor.drives.insert(
                drive.id.clone(),
                Stored {
                    name: drive.name.clone(),
                    link,
                },
            );
        }
        items.sort_by_cached_key(|item| item.path.clone());
        removed.sort();
        removed.dedup();
        Ok(Changes {
            items,
            removed,
            cursor: self.encode(&cursor)?,
            full: false,
        })
    }

    /// Every file under the location, and the cursor to go on from.
    fn full(&self, scope: &Scope, scope_id: &str, cancel: &AtomicBool) -> Result<Changes> {
        let mut items = Vec::new();
        let mut drives = BTreeMap::new();
        for drive in &scope.drives {
            let link = if let Some(folder) = &scope.top {
                // A folder has no delta of its own on OneDrive for Business or SharePoint (only
                // the root of a drive does), and `token=latest` gives the drive's link without
                // listing anything: it is taken BEFORE the folder is listed, so whatever changes
                // while the listing runs is in the next feed.
                let latest = self
                    .feed(self.delta(&drive.id).query("token", "latest"), cancel)
                    .map_err(|stop| self.settle(stop))?;
                items.extend(self.tree(&drive.id, folder, &drive.base, cancel)?);
                latest.link
            } else {
                // A feed started without a token lists the whole drive (the only way that is
                // sure to name every item, even while it is written to).
                let first = self
                    .delta(&drive.id)
                    .query("$select", ITEM_FIELDS)
                    .query("$top", DELTA_PAGE);
                let feed = self.feed(first, cancel).map_err(|stop| self.settle(stop))?;
                let (more, _, link) = self
                    .assemble(&drive.id, None, &drive.base, feed, false)
                    .map_err(|stop| self.settle(stop))?;
                items.extend(more);
                link
            };
            drives.insert(
                drive.id.clone(),
                Stored {
                    name: drive.name.clone(),
                    link,
                },
            );
        }
        items.sort_by_cached_key(|item| item.path.clone());
        let cursor = Cursor {
            scope: scope_id.to_owned(),
            full_at: now_secs(),
            drives,
        };
        Ok(Changes {
            items,
            removed: Vec::new(),
            cursor: self.encode(&cursor)?,
            full: true,
        })
    }

    /// The files under `folder` of `drive`, by listing it and its folders (`base` is its path).
    fn tree(
        &self,
        drive: &str,
        folder: &str,
        base: &Path,
        cancel: &AtomicBool,
    ) -> Result<Vec<RemoteItem>> {
        let mut items = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![(folder.to_owned(), base.to_path_buf())];
        while let Some((id, path)) = stack.pop() {
            let entries: Vec<Item> =
                self.list(self.children(drive, Some(&id), ITEM_FIELDS), cancel)?;
            for entry in entries {
                let at = child(&path, &entry.name);
                if entry.is_folder() {
                    stack.push((entry.id, at));
                } else if entry.is_file() && seen.insert(at.clone()) {
                    items.push(entry.remote(drive, at));
                }
            }
        }
        Ok(items)
    }

    /// A feed that asks for a full listing while one is being made is not usable.
    fn settle(&self, stop: Break) -> Error {
        match stop {
            Break::Fail(error) => error,
            Break::Resync => {
                Error::unexpected(self.provider, "the service keeps asking for a new listing")
            }
        }
    }

    /// The cursor as text.
    fn encode(&self, cursor: &Cursor) -> Result<String> {
        serde_json::to_string(cursor)
            .map_err(|error| Error::unexpected(self.provider, error.to_string()))
    }

    /// The place `folder` is at.
    fn place(folder: &RemoteFolder) -> Result<Place> {
        Place::parse(&folder.id).ok_or_else(|| bad("That location is not one of this account."))
    }
}

impl Connector for Graph {
    fn provider(&self) -> Provider {
        self.provider
    }

    fn browse(&self, under: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>> {
        let Some(folder) = under else {
            return Ok(self
                .tops()?
                .into_iter()
                .map(|(path, top)| RemoteFolder {
                    id: top.place.id(),
                    path,
                    web_url: top.web_url,
                })
                .collect());
        };
        match Self::place(folder)? {
            Place::Site(site) => Ok(self
                .libraries(&site, &folder.path)?
                .into_iter()
                .map(|(path, drive)| RemoteFolder {
                    id: Place::Drive(drive.id).id(),
                    path,
                    web_url: drive.web_url,
                })
                .collect()),
            Place::Drive(drive) => self.folders(&drive, None, &folder.path),
            Place::Folder { drive, item } => self.folders(&drive, Some(&item), &folder.path),
        }
    }

    fn resolve(&self, path: &Path) -> Result<Resolved> {
        let parts = self.parts(path)?;
        let Some((first, rest)) = parts.split_first() else {
            return Err(Error::not_found(
                self.provider,
                "the top of an account is not a location",
            ));
        };
        let want = first.to_lowercase();
        let (top_path, top) = self
            .tops()?
            .into_iter()
            .find(|(path, _)| key(path) == want)
            .ok_or_else(|| Error::not_found(self.provider, "nothing of that name at the top"))?;
        match top.place {
            Place::Drive(drive) => self.inside(&drive, &top_path, top.web_url, rest),
            Place::Site(site) => {
                let Some((library, rest)) = rest.split_first() else {
                    return Ok(Resolved::Folder(RemoteFolder {
                        id: Place::Site(site).id(),
                        path: top_path,
                        web_url: top.web_url,
                    }));
                };
                let want = library.to_lowercase();
                let (library_path, drive) = self
                    .libraries(&site, &top_path)?
                    .into_iter()
                    .find(|(path, _)| key(path) == want)
                    .ok_or_else(|| {
                        Error::not_found(self.provider, "no document library of that name")
                    })?;
                self.inside(&drive.id, &library_path, drive.web_url, rest)
            }
            Place::Folder { .. } => Err(Error::not_found(self.provider, "not a place at the top")),
        }
    }

    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<Changes> {
        let place = Self::place(root)?;
        let scope = self.scope(&place, &root.path)?;
        let saved =
            cursor.and_then(|text| Cursor::accept(text, &root.id, &scope.drives, now_secs()));
        if let Some(saved) = saved {
            match self.incremental(&scope, &saved, cancel) {
                Ok(changes) => return Ok(changes),
                Err(Break::Fail(error)) => return Err(error),
                // The link is no good, or a removal has no path: not guessed, listed again.
                Err(Break::Resync) => {}
            }
        }
        self.full(&scope, &root.id, cancel)
    }

    fn download(&self, item: &RemoteItem, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>> {
        let (drive, id) = item
            .id
            .split_once('|')
            .ok_or_else(|| bad("That file is not one of this account."))?;
        if item.size > max {
            return Err(Error::TooLarge);
        }
        // Graph answers with a 302 to an address that is signed already; the client follows it
        // without the bearer token.
        let request =
            Request::get(self.url(&format!("/drives/{}/items/{}/content", seg(drive), seg(id))));
        let reply = self.session.download(&request, max, cancel)?;
        if reply.is_success() {
            Ok(reply.body)
        } else {
            Err(failure(self.provider, &reply))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use serde_json::{Value, json};

    use super::*;
    use crate::{
        sources::{
            Secrets,
            testing::{Answer, Mock, Res, Seen},
        },
        testing::temp_dir,
    };

    const ID: &str = "0011223344556677";
    const DELTA: &str = "/v1.0/drives/d1/root/delta";
    const S1: &str = "contoso.sharepoint.com,aaa,bbb";
    const S2: &str = "contoso.sharepoint.com,ccc,ddd";
    const S3: &str = "contoso.sharepoint.com,eee,fff";

    fn account(provider: Provider, label: &str, sign_in: SignIn) -> Account {
        Account {
            id: ID.to_owned(),
            provider,
            label: label.to_owned(),
            sign_in,
        }
    }

    fn work() -> Account {
        account(
            Provider::Microsoft365,
            "Contoso",
            SignIn::MicrosoftDelegated {
                tenant: "contoso".to_owned(),
                client_id: "client".to_owned(),
            },
        )
    }

    fn personal() -> Account {
        account(
            Provider::OneDrive,
            "jan@outlook.com",
            SignIn::MicrosoftDelegated {
                tenant: "consumers".to_owned(),
                client_id: "client".to_owned(),
            },
        )
    }

    fn app(sites: Option<&[&str]>) -> Account {
        let credential = Credential::Secret;
        let sign_in = match sites {
            None => SignIn::MicrosoftApp {
                tenant: "contoso".to_owned(),
                client_id: "client".to_owned(),
                credential,
            },
            Some(sites) => SignIn::MicrosoftAppSelected {
                tenant: "contoso".to_owned(),
                client_id: "client".to_owned(),
                credential,
                sites: sites.iter().map(|site| (*site).to_owned()).collect(),
            },
        };
        account(Provider::Microsoft365, "Contoso", sign_in)
    }

    /// A connector over a mock server, with the waits it was asked to make noted.
    struct Rig {
        mock: Mock,
        graph: Graph,
        waits: Arc<Mutex<Vec<Duration>>>,
    }

    impl Rig {
        fn waited(&self) -> Vec<Duration> {
            self.waits
                .lock()
                .map(|waits| waits.clone())
                .unwrap_or_default()
        }

        /// The requests that were not for the token endpoint.
        fn calls(&self) -> Vec<Seen> {
            self.mock
                .seen()
                .into_iter()
                .filter(|seen| !seen.path().ends_with("/token"))
                .collect()
        }

        fn tokens(&self) -> Vec<Seen> {
            self.mock
                .seen()
                .into_iter()
                .filter(|seen| seen.path().ends_with("/token"))
                .collect()
        }
    }

    fn origin(seen: &Seen) -> String {
        format!("http://{}", seen.header("host").unwrap_or_default())
    }

    fn rig_with(
        account: &Account,
        secrets: &Secrets,
        handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static,
    ) -> Res<Rig> {
        let mock = Mock::start(handler)?;
        let store = TokenStore::new(&temp_dir("graph"));
        store.save(&account.id, secrets)?;
        let waits = Arc::new(Mutex::new(Vec::new()));
        let noted = Arc::clone(&waits);
        let http = Http::with_pause(account.provider, move |wait| {
            if let Ok(mut waits) = noted.lock() {
                waits.push(wait);
            }
        });
        let endpoints = Endpoints {
            graph: format!("{}/v1.0", mock.url()),
            login: mock.url(),
        };
        let graph = Graph::with(account, &store, http, &endpoints)?;
        Ok(Rig { mock, graph, waits })
    }

    /// A rig whose token endpoint numbers what it gives (`at-1`, `rt-1`, `at-2`...); the stored
    /// refresh token is `rt-0` and the client secret `shh`.
    fn rig(
        account: &Account,
        handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static,
    ) -> Res<Rig> {
        let secrets = Secrets::default()
            .with_refresh_token("rt-0")
            .with_client_secret("shh");
        let count = AtomicUsize::new(0);
        rig_with(account, &secrets, move |seen| {
            if seen.path().ends_with("/token") {
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                Answer::json(
                    200,
                    &json!({
                        "access_token": format!("at-{n}"),
                        "refresh_token": format!("rt-{n}"),
                        "expires_in": 3600,
                    }),
                )
            } else {
                handler(seen)
            }
        })
    }

    fn idle() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn page(items: Vec<Value>, next: Option<String>, delta: Option<String>) -> Answer {
        let mut body = json!({});
        body["value"] = Value::Array(items);
        if let Some(next) = next {
            body["@odata.nextLink"] = json!(next);
        }
        if let Some(delta) = delta {
            body["@odata.deltaLink"] = json!(delta);
        }
        Answer::json(200, &body)
    }

    fn file(id: &str, name: &str, parent: &str, size: u64) -> Value {
        json!({
            "id": id,
            "name": name,
            "size": size,
            "file": {},
            "cTag": format!("c-{id}"),
            "eTag": format!("e-{id}"),
            "lastModifiedDateTime": "2024-01-02T03:04:05Z",
            "webUrl": format!("https://web/{name}"),
            "parentReference": {"driveId": "d1", "id": parent},
        })
    }

    fn folder(id: &str, name: &str, parent: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "folder": {"childCount": 1},
            "webUrl": format!("https://web/{name}"),
            "parentReference": {"driveId": "d1", "id": parent},
        })
    }

    fn root() -> Value {
        json!({"id": "root1", "name": "root", "root": {}, "folder": {}, "parentReference": {"driveId": "d1"}})
    }

    fn site(id: &str, title: &str) -> Value {
        json!({
            "id": id,
            "name": title.to_lowercase(),
            "displayName": title,
            "webUrl": format!("https://contoso.sharepoint.com/sites/{title}"),
        })
    }

    fn library(id: &str, name: &str) -> Value {
        json!({"id": id, "name": name, "webUrl": format!("https://contoso.sharepoint.com/{name}")})
    }

    fn missing() -> Answer {
        Answer::json(
            404,
            &json!({"error": {"code": "itemNotFound", "message": "The resource could not be found."}}),
        )
    }

    fn at(id: &str, path: &Path) -> RemoteFolder {
        RemoteFolder {
            id: id.to_owned(),
            path: path.to_path_buf(),
            web_url: String::new(),
        }
    }

    fn paths(items: &[RemoteItem]) -> Vec<PathBuf> {
        items.iter().map(|item| item.path.clone()).collect()
    }

    fn sorted(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
        paths.sort();
        paths
    }

    fn documents() -> PathBuf {
        child(&work().root(), "Documents")
    }

    fn authorization(seen: &Seen) -> Option<&str> {
        seen.header("authorization")
    }

    fn kind(error: &Error) -> &'static str {
        match error {
            Error::SignInNeeded { .. } => "sign_in",
            Error::Throttled { .. } => "throttled",
            Error::Forbidden { .. } => "forbidden",
            Error::AdminApproval { .. } => "admin_approval",
            Error::NotFound { .. } => "not_found",
            Error::Network { .. } => "network",
            Error::Unexpected { .. } => "unexpected",
            Error::TooLarge => "too_large",
            Error::Cancelled => "cancelled",
            Error::Local(_) => "local",
        }
    }

    fn failed<T>(result: Result<T>) -> Res<Error> {
        match result {
            Err(error) => Ok(error),
            Ok(_) => Err("an error was expected".into()),
        }
    }

    fn cursor_json(changes: &Changes) -> Res<Value> {
        Ok(serde_json::from_str(&changes.cursor)?)
    }

    // ---- the layout of the top, and of what is below it

    /// A work account's mock: its own drive, a followed site, a search over two pages, the
    /// libraries of the first site and the folders of a library.
    fn tenant() -> impl Fn(&Seen) -> Answer + Send + Sync + 'static {
        |seen| {
            let libraries = format!("/v1.0/sites/{S1}/drives");
            match (seen.path(), seen.param("$skiptoken").as_deref()) {
                ("/v1.0/me/drive", _) => Answer::json(
                    200,
                    &json!({"id": "od", "name": "OneDrive", "webUrl": "https://my/od"}),
                ),
                ("/v1.0/me/followedSites", _) => page(vec![site(S1, "Finance")], None, None),
                ("/v1.0/sites", None) => page(
                    vec![site(S1, "Finance"), site(S2, "HR")],
                    Some(format!("{}/v1.0/sites?search=*&$skiptoken=2", origin(seen))),
                    None,
                ),
                ("/v1.0/sites", Some(_)) => page(vec![site(S3, "OneDrive")], None, None),
                (path, _) if path == libraries => page(
                    vec![library("dl", "Shared Documents"), library("da", "Archive")],
                    None,
                    None,
                ),
                ("/v1.0/drives/dl/root/children", _) => page(
                    vec![
                        folder("r1", "Reports", "dlroot"),
                        file("x1", "x.txt", "dlroot", 1),
                        folder("r2", "archive", "dlroot"),
                        json!({"id": "nb", "name": "Notebook", "folder": {}, "package": {"type": "oneNote"}}),
                    ],
                    None,
                    None,
                ),
                ("/v1.0/drives/dl/items/r1/children", _) => page(
                    vec![
                        folder("q1", "Q1", "r1"),
                        file("n1", "Notes. ", "r1", 2),
                        file("i9", "q1.xlsx", "r1", 5),
                    ],
                    None,
                    None,
                ),
                ("/v1.0/drives/dl/root:/Reports/q1.xlsx", _) => {
                    Answer::json(200, &file("i9", "q1.xlsx", "r1", 5))
                }
                ("/v1.0/drives/dl/root:/Reports/e.txt", _) => {
                    let mut item = file("e1", "e.txt", "r1", 3);
                    item["cTag"] = Value::Null;
                    Answer::json(200, &item)
                }
                ("/v1.0/drives/dl/root:/Reports", _) => {
                    Answer::json(200, &folder("r1", "Reports", "dlroot"))
                }
                _ => missing(),
            }
        }
    }

    #[test]
    fn the_top_of_a_work_account_is_its_own_drive_then_the_sites_it_can_see() -> Res {
        let rig = rig(&work(), tenant())?;
        let top = rig.graph.browse(None)?;
        let ids: Vec<&str> = top.iter().map(|folder| folder.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "drive:od".to_owned(),
                format!("site:{S1}"),
                format!("site:{S2}"),
                format!("site:{S3}"),
            ]
        );
        let root = work().root();
        assert_eq!(
            top.iter()
                .map(|folder| folder.path.clone())
                .collect::<Vec<_>>(),
            [
                child(&root, "OneDrive"),
                child(&root, "Finance"),
                child(&root, "HR"),
                // A site that is called what the own drive is called comes after it.
                child(&root, "OneDrive (2)"),
            ]
        );
        assert_eq!(
            top[1].web_url,
            "https://contoso.sharepoint.com/sites/Finance"
        );
        // The followed site is also found by the search: it is listed once.
        let calls = rig.calls();
        let search = calls
            .iter()
            .find(|seen| seen.path() == "/v1.0/sites" && seen.param("$skiptoken").is_none())
            .ok_or("the search was not made")?;
        assert_eq!(search.param("search").as_deref(), Some("*"));
        assert_eq!(
            calls
                .iter()
                .filter(|seen| seen.path() == "/v1.0/sites")
                .count(),
            2
        );
        assert!(
            calls
                .iter()
                .all(|seen| authorization(seen) == Some("Bearer at-1"))
        );
        Ok(())
    }

    #[test]
    fn a_site_lists_its_libraries_and_a_library_or_folder_its_folders_only() -> Res {
        let rig = rig(&work(), tenant())?;
        let top = rig.graph.browse(None)?;
        let libraries = rig.graph.browse(Some(&top[1]))?;
        assert_eq!(
            libraries
                .iter()
                .map(|folder| folder.id.as_str())
                .collect::<Vec<_>>(),
            ["drive:da", "drive:dl"]
        );
        assert_eq!(
            libraries[0].path,
            child(&child(&work().root(), "Finance"), "Archive")
        );

        let folders = rig.graph.browse(Some(&libraries[1]))?;
        assert_eq!(
            folders
                .iter()
                .map(|folder| folder.id.as_str())
                .collect::<Vec<_>>(),
            ["item:dl|r2", "item:dl|r1"],
            "sorted by name, letters' case ignored; files and notebooks are not folders"
        );
        let seen = rig
            .calls()
            .into_iter()
            .find(|seen| seen.path() == "/v1.0/drives/dl/root/children")
            .ok_or("the library was not listed")?;
        assert_eq!(seen.param("$select").as_deref(), Some(FOLDER_FIELDS));
        assert_eq!(seen.param("$top").as_deref(), Some("200"));

        let below = rig.graph.browse(Some(&folders[1]))?;
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].id, "item:dl|q1");
        assert_eq!(below[0].path, child(&folders[1].path, "Q1"));
        Ok(())
    }

    #[test]
    fn a_path_is_resolved_to_a_site_a_library_a_folder_or_a_file() -> Res {
        let rig = rig(&work(), tenant())?;
        let base = child(&child(&work().root(), "Finance"), "Shared Documents");

        let Resolved::File(file) = rig
            .graph
            .resolve(&child(&child(&base, "Reports"), "q1.xlsx"))?
        else {
            return Err("a file was expected".into());
        };
        assert_eq!(file.id, "dl|i9");
        assert_eq!(file.size, 5);
        assert_eq!(file.version, "c-i9", "the cTag");
        assert_eq!(file.web_url, "https://web/q1.xlsx");
        assert_eq!(
            file.modified,
            parse_time("2024-01-02T03:04:05Z").ok_or("time")?
        );
        assert_eq!(file.path, child(&child(&base, "Reports"), "q1.xlsx"));
        assert!(file.export.is_none());

        let Resolved::File(plain) = rig
            .graph
            .resolve(&child(&child(&base, "Reports"), "e.txt"))?
        else {
            return Err("a file was expected".into());
        };
        assert_eq!(plain.version, "e-e1", "no cTag: the eTag");

        let Resolved::Folder(reports) = rig.graph.resolve(&child(&base, "Reports"))? else {
            return Err("a folder was expected".into());
        };
        assert_eq!(reports.id, "item:dl|r1");
        assert_eq!(reports.path, child(&base, "Reports"));

        // Letter case is ignored, and the path that comes back is the service's spelling.
        let spelled = work().root().join("finance").join("shared documents");
        let Resolved::Folder(library) = rig.graph.resolve(&spelled)? else {
            return Err("a folder was expected".into());
        };
        assert_eq!(library.id, "drive:dl");
        assert_eq!(library.path, base);

        let Resolved::Folder(site) = rig.graph.resolve(&child(&work().root(), "Finance"))? else {
            return Err("a folder was expected".into());
        };
        assert_eq!(site.id, format!("site:{S1}"));
        let Resolved::Folder(own) = rig.graph.resolve(&child(&work().root(), "OneDrive"))? else {
            return Err("a folder was expected".into());
        };
        assert_eq!(own.id, "drive:od");

        let lookup = rig
            .calls()
            .into_iter()
            .find(|seen| seen.path() == "/v1.0/drives/dl/root:/Reports/q1.xlsx")
            .ok_or("the file was not looked up by its path")?;
        assert_eq!(lookup.param("$select").as_deref(), Some(ITEM_FIELDS));
        Ok(())
    }

    #[test]
    fn a_path_that_is_nothing_in_this_account_is_not_found() -> Res {
        let rig = rig(&work(), tenant())?;
        let base = child(&child(&work().root(), "Finance"), "Shared Documents");
        for path in [
            child(&base, "Missing"),
            child(&work().root(), "Nowhere"),
            child(&child(&work().root(), "Finance"), "No library"),
            PathBuf::from(r"\\Microsoft 365\Other\Finance"),
            PathBuf::from(r"\\OneDrive\Contoso\OneDrive"),
            PathBuf::from(r"C:\Users\jan"),
            work().root(),
        ] {
            let error = failed(rig.graph.resolve(&path))?;
            assert!(
                matches!(error, Error::NotFound { .. }),
                "{path:?}: {error:?}"
            );
        }
        // A file is not a folder, and a folder is not a file.
        let file = child(&child(&base, "Reports"), "q1.xlsx");
        assert!(matches!(
            rig.graph.folder(&file),
            Err(Error::NotFound { .. })
        ));
        assert!(matches!(
            rig.graph.file(&child(&base, "Reports")),
            Err(Error::NotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_name_that_was_made_legal_is_found_by_looking_in_the_folder() -> Res {
        let rig = rig(&work(), tenant())?;
        let reports = child(
            &child(&child(&work().root(), "Finance"), "Shared Documents"),
            "Reports",
        );
        let path = child(&reports, "Notes. ");
        assert!(path.ends_with("Notes__"), "{path:?}");
        let Resolved::File(notes) = rig.graph.resolve(&path)? else {
            return Err("a file was expected".into());
        };
        assert_eq!(notes.id, "dl|n1");
        assert_eq!(notes.path, path);
        let calls = rig.calls();
        assert!(
            calls
                .iter()
                .any(|seen| seen.path() == "/v1.0/drives/dl/root:/Reports/Notes__")
        );
        assert!(
            calls
                .iter()
                .any(|seen| seen.path() == "/v1.0/drives/dl/items/r1/children")
        );
        Ok(())
    }

    #[test]
    fn a_personal_onedrive_has_one_drive_called_onedrive() -> Res {
        let account = personal();
        let rig = rig(&account, |seen| match seen.path() {
            "/v1.0/me/drive" => Answer::json(
                200,
                &json!({"id": "pd", "name": "OneDrive", "webUrl": "https://onedrive.live.com/?id=pd"}),
            ),
            "/v1.0/drives/pd/root/children" => page(
                vec![
                    folder("p1", "Pictures", "proot"),
                    file("p2", "a.txt", "proot", 1),
                ],
                None,
                None,
            ),
            "/v1.0/drives/pd/root:/Pictures" => {
                Answer::json(200, &folder("p1", "Pictures", "proot"))
            }
            _ => missing(),
        })?;
        let top = rig.graph.browse(None)?;
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].id, "drive:pd");
        assert_eq!(
            top[0].path,
            Path::new(r"\\OneDrive\jan@outlook.com\OneDrive")
        );
        assert_eq!(top[0].web_url, "https://onedrive.live.com/?id=pd");
        let below = rig.graph.browse(Some(&top[0]))?;
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].id, "item:pd|p1");
        let Resolved::Folder(found) = rig.graph.resolve(&child(&top[0].path, "Pictures"))? else {
            return Err("a folder was expected".into());
        };
        assert_eq!(found, below[0].clone());
        // No sites, no followed sites: only the one drive was asked for.
        assert!(
            rig.calls()
                .iter()
                .all(|seen| seen.path().starts_with("/v1.0/me/drive")
                    || seen.path().starts_with("/v1.0/drives/pd/")),
            "{:?}",
            rig.calls()
        );
        Ok(())
    }

    #[test]
    fn an_app_sees_every_site_and_signs_in_with_its_secret() -> Res {
        let account = app(None);
        let rig = rig(&account, |seen| {
            match (seen.path(), seen.param("$skiptoken").as_deref()) {
                ("/v1.0/sites", None) => page(
                    vec![site(S2, "HR")],
                    Some(format!("{}/v1.0/sites?search=*&$skiptoken=2", origin(seen))),
                    None,
                ),
                ("/v1.0/sites", Some(_)) => page(vec![site(S1, "Finance")], None, None),
                _ => missing(),
            }
        })?;
        let top = rig.graph.browse(None)?;
        assert_eq!(
            top.iter()
                .map(|folder| folder.id.clone())
                .collect::<Vec<_>>(),
            [format!("site:{S1}"), format!("site:{S2}")]
        );
        assert!(
            rig.calls().iter().all(|seen| seen.path() == "/v1.0/sites"),
            "no own drive"
        );
        let tokens = rig.tokens();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].path(), "/contoso/oauth2/v2.0/token");
        assert_eq!(
            tokens[0].field("grant_type").as_deref(),
            Some("client_credentials")
        );
        assert_eq!(tokens[0].field("scope").as_deref(), Some(SCOPE_APP));
        assert_eq!(tokens[0].field("client_id").as_deref(), Some("client"));
        assert_eq!(tokens[0].field("client_secret").as_deref(), Some("shh"));
        Ok(())
    }

    #[test]
    fn an_app_with_selected_sites_lists_only_those_and_skips_one_that_is_not_there() -> Res {
        let account = app(Some(&[
            "https://contoso.sharepoint.com/sites/Finance",
            "https://contoso.sharepoint.com/sites/Gone/",
            "contoso.sharepoint.com/sites/Finance",
        ]));
        let rig = rig(&account, |seen| match seen.path() {
            "/v1.0/sites/contoso.sharepoint.com:/sites/Finance" => {
                Answer::json(200, &site(S1, "Finance"))
            }
            _ => Answer::json(
                404,
                &json!({"error": {"code": "itemNotFound", "message": "Requested site could not be found"}}),
            ),
        })?;
        let top = rig.graph.browse(None)?;
        assert_eq!(top.len(), 1, "{top:?}");
        assert_eq!(top[0].id, format!("site:{S1}"));
        assert_eq!(top[0].path, child(&account.root(), "Finance"));
        let asked: Vec<String> = rig
            .calls()
            .iter()
            .map(|seen| seen.path().to_owned())
            .collect();
        assert!(
            asked
                .iter()
                .all(|path| path.starts_with("/v1.0/sites/contoso.sharepoint.com:/sites/")),
            "no search, no own drive: {asked:?}"
        );
        assert!(asked.contains(&"/v1.0/sites/contoso.sharepoint.com:/sites/Gone".to_owned()));
        Ok(())
    }

    // ---- listings and the change feed

    #[test]
    fn a_listing_over_three_pages_has_every_file_and_no_folder() -> Res {
        let rig = rig(&work(), |seen| {
            let next = |token: &str| format!("{}{DELTA}?token={token}", origin(seen));
            match (seen.path(), seen.param("token").as_deref()) {
                (DELTA, None) => page(
                    vec![
                        root(),
                        folder("fa", "Docs", "root1"),
                        file("f1", "a.txt", "root1", 10),
                    ],
                    Some(next("p2")),
                    None,
                ),
                (DELTA, Some("p2")) => page(
                    vec![
                        file("f2", "Q1: plan?.docx", "fa", 20),
                        folder("fb", "Sub", "fa"),
                    ],
                    Some(next("p3")),
                    None,
                ),
                (DELTA, Some("p3")) => {
                    page(vec![file("f3", "c.txt", "fb", 30)], None, Some(next("end")))
                }
                _ => missing(),
            }
        })?;
        let base = documents();
        let got = rig.graph.changes(&at("drive:d1", &base), None, &idle())?;
        assert!(got.full);
        assert!(got.removed.is_empty());
        let docs = child(&base, "Docs");
        assert_eq!(
            paths(&got.items),
            sorted(vec![
                child(&base, "a.txt"),
                child(&docs, "Q1: plan?.docx"),
                child(&child(&docs, "Sub"), "c.txt"),
            ])
        );
        let first = got
            .items
            .iter()
            .find(|item| item.id == "d1|f1")
            .ok_or("f1")?;
        assert_eq!(first.size, 10);
        assert_eq!(first.version, "c-f1");
        assert_eq!(first.web_url, "https://web/a.txt");
        assert_eq!(
            first.modified,
            parse_time("2024-01-02T03:04:05Z").ok_or("time")?
        );
        assert!(got.items.iter().all(|item| item.export.is_none()));

        let calls = rig.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].param("$select").as_deref(), Some(ITEM_FIELDS));
        assert_eq!(calls[0].param("$top").as_deref(), Some("1000"));
        assert!(
            calls
                .iter()
                .all(|seen| authorization(seen) == Some("Bearer at-1"))
        );
        let cursor = cursor_json(&got)?;
        assert_eq!(
            cursor["d"]["d1"]["l"].as_str(),
            Some(format!("{}{DELTA}?token=end", rig.mock.url()).as_str())
        );
        Ok(())
    }

    #[test]
    fn the_second_call_requests_the_stored_link_and_reports_only_what_changed() -> Res {
        let rig = rig(&work(), |seen| {
            let o = origin(seen);
            match (seen.path(), seen.param("token").as_deref()) {
                (DELTA, None) => page(
                    vec![
                        root(),
                        folder("fa", "Docs", "root1"),
                        file("f1", "a.txt", "fa", 10),
                        file("f2", "b.txt", "root1", 20),
                        file("f9", "old.txt", "fa", 5),
                    ],
                    None,
                    Some(format!("{o}{DELTA}?token=t1")),
                ),
                (DELTA, Some("t1")) => {
                    let mut changed = file("f1", "a.txt", "fa", 11);
                    changed["cTag"] = json!("c-new");
                    page(
                        vec![
                            root(),
                            folder("fa", "Docs", "root1"),
                            changed,
                            // Renamed: the feed gives it under its new name.
                            file("f2", "b-new.txt", "root1", 20),
                            json!({"id": "f9", "name": "old.txt", "deleted": {}, "parentReference": {"id": "fa", "driveId": "d1"}}),
                        ],
                        None,
                        Some(format!("{o}{DELTA}?token=t2")),
                    )
                }
                _ => missing(),
            }
        })?;
        let base = documents();
        let place = at("drive:d1", &base);
        let first = rig.graph.changes(&place, None, &idle())?;
        assert!(first.full);
        let second = rig.graph.changes(&place, Some(&first.cursor), &idle())?;
        assert!(!second.full);
        let docs = child(&base, "Docs");
        assert_eq!(
            paths(&second.items),
            sorted(vec![child(&docs, "a.txt"), child(&base, "b-new.txt")])
        );
        let changed = second
            .items
            .iter()
            .find(|item| item.id == "d1|f1")
            .ok_or("f1")?;
        assert_eq!((changed.size, changed.version.as_str()), (11, "c-new"));
        assert_eq!(second.removed, [child(&docs, "old.txt")]);

        let calls = rig.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[1].target, "/v1.0/drives/d1/root/delta?token=t1",
            "exactly the stored link: no other query"
        );
        assert_eq!(authorization(&calls[1]), Some("Bearer at-1"));
        assert_eq!(
            cursor_json(&second)?["d"]["d1"]["l"].as_str(),
            Some(format!("{}{DELTA}?token=t2", rig.mock.url()).as_str())
        );
        // And the new cursor goes on from there.
        let third = rig.graph.changes(&place, Some(&second.cursor), &idle());
        assert!(
            matches!(third, Err(Error::NotFound { .. })),
            "the mock has no t2: {third:?}"
        );
        Ok(())
    }

    #[test]
    fn a_feed_without_paths_is_walked_by_ids_and_unseen_parents_are_asked_for() -> Res {
        let rig = rig(&work(), |seen| {
            let o = origin(seen);
            match (seen.path(), seen.param("token").as_deref()) {
                (DELTA, None) => page(vec![root()], None, Some(format!("{o}{DELTA}?token=t1"))),
                (DELTA, Some("t1")) => page(
                    // No folder of the hierarchy in the page: only parent ids.
                    vec![
                        file("f5", "five.txt", "fz", 6),
                        file("f6", "six.txt", "fz", 7),
                        file("f7", "seven.txt", "fz", 8),
                    ],
                    Some(format!("{o}{DELTA}?token=t1b")),
                    None,
                ),
                // A removed item of OneDrive for Business has an id and nothing else: its place
                // is what an earlier page of the feed said.
                (DELTA, Some("t1b")) => page(
                    vec![json!({"id": "f7", "deleted": {}})],
                    None,
                    Some(format!("{o}{DELTA}?token=t2")),
                ),
                ("/v1.0/drives/d1/items/fz", _) => Answer::json(
                    200,
                    &json!({"id": "fz", "name": "Zed", "parentReference": {"id": "root1", "driveId": "d1"}}),
                ),
                ("/v1.0/drives/d1/items/root1", _) => Answer::json(
                    200,
                    &json!({"id": "root1", "name": "root", "root": {}, "parentReference": {"driveId": "d1"}}),
                ),
                _ => missing(),
            }
        })?;
        let base = documents();
        let place = at("drive:d1", &base);
        let first = rig.graph.changes(&place, None, &idle())?;
        let second = rig.graph.changes(&place, Some(&first.cursor), &idle())?;
        assert!(!second.full);
        let zed = child(&base, "Zed");
        assert_eq!(
            paths(&second.items),
            sorted(vec![child(&zed, "five.txt"), child(&zed, "six.txt")])
        );
        assert_eq!(second.removed, [child(&zed, "seven.txt")]);
        let asks: Vec<Seen> = rig
            .calls()
            .into_iter()
            .filter(|seen| seen.path().contains("/items/"))
            .collect();
        assert_eq!(
            asks.iter().map(Seen::path).collect::<Vec<_>>(),
            ["/v1.0/drives/d1/items/fz", "/v1.0/drives/d1/items/root1"],
            "each parent once, the folder's path is kept for the second file"
        );
        let select = asks[0].param("$select").ok_or("no $select")?;
        assert!(
            select.contains("parentReference") && select.contains("name"),
            "{select}"
        );
        Ok(())
    }

    #[test]
    fn a_removal_whose_place_cannot_be_told_gets_a_full_listing() -> Res {
        let rig = rig(&work(), |seen| {
            let o = origin(seen);
            match (seen.path(), seen.param("token").as_deref()) {
                (DELTA, None) => page(
                    vec![root(), file("f1", "a.txt", "root1", 1)],
                    None,
                    Some(format!("{o}{DELTA}?token=t1")),
                ),
                (DELTA, Some("t1")) => page(
                    vec![json!({"id": "ghost", "deleted": {}})],
                    None,
                    Some(format!("{o}{DELTA}?token=t2")),
                ),
                _ => missing(),
            }
        })?;
        let place = at("drive:d1", &documents());
        let first = rig.graph.changes(&place, None, &idle())?;
        let second = rig.graph.changes(&place, Some(&first.cursor), &idle())?;
        assert!(second.full);
        assert!(second.removed.is_empty());
        assert_eq!(second.items.len(), 1);
        let targets: Vec<String> = rig.calls().iter().map(|seen| seen.target.clone()).collect();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[1], "/v1.0/drives/d1/root/delta?token=t1");
        assert!(
            targets[2].starts_with("/v1.0/drives/d1/root/delta?") && !targets[2].contains("token=")
        );
        Ok(())
    }

    #[test]
    fn a_link_the_service_no_longer_knows_gets_a_full_listing() -> Res {
        for code in ["resyncRequired", "syncStateNotFound"] {
            let rig = rig(&work(), move |seen| {
                let o = origin(seen);
                match (seen.path(), seen.param("token").as_deref()) {
                    (DELTA, None) => page(
                        vec![root(), file("f1", "a.txt", "root1", 1)],
                        None,
                        Some(format!("{o}{DELTA}?token=t1")),
                    ),
                    (DELTA, Some("t1")) => {
                        Answer::json(410, &json!({"error": {"code": code, "message": "gone"}}))
                            .header("Location", &format!("{o}{DELTA}?token=fresh"))
                    }
                    _ => missing(),
                }
            })?;
            let place = at("drive:d1", &documents());
            let first = rig.graph.changes(&place, None, &idle())?;
            let again = rig.graph.changes(&place, Some(&first.cursor), &idle())?;
            assert!(again.full, "{code}");
            assert_eq!(paths(&again.items), paths(&first.items), "{code}");
            assert_eq!(rig.calls().len(), 3, "{code}");
        }
        Ok(())
    }

    #[test]
    fn a_cursor_that_is_old_or_not_ours_is_not_used() -> Res {
        let rig = rig(&work(), |seen| {
            let o = origin(seen);
            match (seen.path(), seen.param("token").as_deref()) {
                (DELTA, None) => page(
                    vec![root(), file("f1", "a.txt", "root1", 1)],
                    None,
                    Some(format!("{o}{DELTA}?token=t1")),
                ),
                _ => missing(),
            }
        })?;
        let base = documents();
        let place = at("drive:d1", &base);
        let stale = json!({"s": "drive:d1", "t": 0, "d": {"d1": {"n": "Documents", "l": format!("{}{DELTA}?token=old", rig.mock.url())}}});
        let other = json!({"s": "drive:d2", "t": now_secs(), "d": {"d1": {"n": "Documents", "l": format!("{}{DELTA}?token=other", rig.mock.url())}}});
        for cursor in [
            stale.to_string(),
            other.to_string(),
            "not json".to_owned(),
            String::new(),
        ] {
            let got = rig.graph.changes(&place, Some(&cursor), &idle())?;
            assert!(got.full, "{cursor}");
        }
        assert!(
            rig.calls().iter().all(|seen| seen.param("token").is_none()),
            "no old link was asked"
        );
        Ok(())
    }

    #[test]
    fn a_folder_location_lists_the_folder_and_follows_the_drives_feed_for_what_is_under_it() -> Res
    {
        let rig = rig(&work(), |seen| {
            let o = origin(seen);
            match (seen.path(), seen.param("token").as_deref()) {
                (DELTA, Some("latest")) => {
                    page(Vec::new(), None, Some(format!("{o}{DELTA}?token=L0")))
                }
                ("/v1.0/drives/d1/items/fld/children", _) => page(
                    vec![file("fa1", "a.txt", "fld", 1), folder("sub", "Sub", "fld")],
                    None,
                    None,
                ),
                ("/v1.0/drives/d1/items/sub/children", _) => {
                    page(vec![file("fb1", "b.txt", "sub", 2)], None, None)
                }
                (DELTA, Some("L0")) => page(
                    vec![
                        root(),
                        folder("fld", "Fld", "root1"),
                        folder("sub", "Sub", "fld"),
                        file("fb1", "b.txt", "sub", 3),
                        folder("other", "Other", "root1"),
                        file("o1", "o.txt", "other", 4),
                        file("z1", "z.txt", "zz", 5),
                        json!({"id": "gone1", "name": "g.txt", "deleted": {}, "parentReference": {"id": "sub", "driveId": "d1"}}),
                        json!({"id": "gone2", "name": "h.txt", "deleted": {}, "parentReference": {"id": "other", "driveId": "d1"}}),
                    ],
                    None,
                    Some(format!("{o}{DELTA}?token=L1")),
                ),
                ("/v1.0/drives/d1/items/zz", _) => Answer::json(
                    200,
                    &json!({"id": "zz", "name": "Zed", "parentReference": {"id": "other", "driveId": "d1"}}),
                ),
                _ => missing(),
            }
        })?;
        let base = child(&documents(), "Fld");
        let place = at("item:d1|fld", &base);
        let first = rig.graph.changes(&place, None, &idle())?;
        assert!(first.full);
        assert_eq!(
            paths(&first.items),
            sorted(vec![
                child(&base, "a.txt"),
                child(&child(&base, "Sub"), "b.txt")
            ])
        );
        let calls = rig.calls();
        assert_eq!(
            calls[0].target, "/v1.0/drives/d1/root/delta?token=latest",
            "the link is taken before the folder is listed"
        );
        assert!(
            calls[1..]
                .iter()
                .all(|seen| seen.path().ends_with("/children"))
        );
        assert_eq!(calls[1].param("$top").as_deref(), Some("200"));
        assert_eq!(calls[1].param("$select").as_deref(), Some(ITEM_FIELDS));
        assert_eq!(
            cursor_json(&first)?["d"]["d1"]["l"].as_str(),
            Some(format!("{}{DELTA}?token=L0", rig.mock.url()).as_str())
        );

        let second = rig.graph.changes(&place, Some(&first.cursor), &idle())?;
        assert!(!second.full);
        assert_eq!(
            paths(&second.items),
            [child(&child(&base, "Sub"), "b.txt")],
            "nothing outside the folder"
        );
        assert_eq!(second.removed, [child(&child(&base, "Sub"), "g.txt")]);
        let asks: Vec<String> = rig
            .calls()
            .iter()
            .skip(calls.len())
            .map(|seen| seen.target.clone())
            .collect();
        assert_eq!(
            asks,
            [
                "/v1.0/drives/d1/root/delta?token=L0".to_owned(),
                "/v1.0/drives/d1/items/zz?%24select=id%2Cname%2Croot%2CparentReference".to_owned()
            ]
        );
        Ok(())
    }

    /// A site with these libraries, each with one file in its feed.
    fn site_rig(libraries: Vec<Value>) -> Res<Rig> {
        rig(&work(), move |seen| {
            let o = origin(seen);
            let feed = |drive: &str, token: Option<&str>| match (drive, token) {
                ("dl", None) => page(
                    vec![root(), file("y1", "y.txt", "root1", 1)],
                    None,
                    Some(format!("{o}/v1.0/drives/dl/root/delta?token=Ldl")),
                ),
                ("dz", None) => page(
                    vec![root(), file("z1", "z.txt", "root1", 1)],
                    None,
                    Some(format!("{o}/v1.0/drives/dz/root/delta?token=Ldz")),
                ),
                ("da", None) => page(
                    vec![root(), file("x1", "x.txt", "root1", 1)],
                    None,
                    Some(format!("{o}/v1.0/drives/da/root/delta?token=Lda")),
                ),
                ("dl", Some("Ldl")) => page(
                    vec![root(), file("y1", "y.txt", "root1", 9)],
                    None,
                    Some(format!("{o}/v1.0/drives/dl/root/delta?token=Ldl2")),
                ),
                ("da", Some("Lda")) => page(
                    vec![
                        root(),
                        json!({"id": "x1", "name": "x.txt", "deleted": {}, "parentReference": {"id": "root1", "driveId": "da"}}),
                    ],
                    None,
                    Some(format!("{o}/v1.0/drives/da/root/delta?token=Lda2")),
                ),
                _ => missing(),
            };
            match seen.path() {
                path if path == format!("/v1.0/sites/{S1}/drives") => {
                    page(libraries.clone(), None, None)
                }
                "/v1.0/drives/dl/root/delta" => feed("dl", seen.param("token").as_deref()),
                "/v1.0/drives/da/root/delta" => feed("da", seen.param("token").as_deref()),
                "/v1.0/drives/dz/root/delta" => feed("dz", seen.param("token").as_deref()),
                _ => missing(),
            }
        })
    }

    #[test]
    fn a_site_location_follows_each_of_its_libraries_and_keeps_every_link_in_its_cursor() -> Res {
        let rig = site_rig(vec![library("dl", "Documents"), library("da", "Archive")])?;
        let finance = child(&work().root(), "Finance");
        let place = at(&format!("site:{S1}"), &finance);
        let first = rig.graph.changes(&place, None, &idle())?;
        assert!(first.full);
        assert_eq!(
            paths(&first.items),
            sorted(vec![
                child(&child(&finance, "Archive"), "x.txt"),
                child(&child(&finance, "Documents"), "y.txt"),
            ])
        );
        let cursor = cursor_json(&first)?;
        let o = rig.mock.url();
        assert_eq!(
            cursor["d"]["dl"]["l"].as_str(),
            Some(format!("{o}/v1.0/drives/dl/root/delta?token=Ldl").as_str())
        );
        assert_eq!(
            cursor["d"]["da"]["l"].as_str(),
            Some(format!("{o}/v1.0/drives/da/root/delta?token=Lda").as_str())
        );
        assert_eq!(cursor["d"]["dl"]["n"].as_str(), Some("Documents"));

        let before = rig.calls().len();
        let second = rig.graph.changes(&place, Some(&first.cursor), &idle())?;
        assert!(!second.full);
        assert_eq!(
            paths(&second.items),
            [child(&child(&finance, "Documents"), "y.txt")]
        );
        assert_eq!(
            second.removed,
            [child(&child(&finance, "Archive"), "x.txt")]
        );
        let asked: Vec<String> = rig
            .calls()
            .iter()
            .skip(before)
            .map(|seen| seen.target.clone())
            .collect();
        assert_eq!(
            asked,
            [
                format!("/v1.0/sites/{S1}/drives"),
                "/v1.0/drives/da/root/delta?token=Lda".to_owned(),
                "/v1.0/drives/dl/root/delta?token=Ldl".to_owned(),
            ]
        );
        let cursor = cursor_json(&second)?;
        assert!(
            cursor["d"]["dl"]["l"]
                .as_str()
                .is_some_and(|link| link.ends_with("Ldl2"))
        );
        assert!(
            cursor["d"]["da"]["l"]
                .as_str()
                .is_some_and(|link| link.ends_with("Lda2"))
        );
        Ok(())
    }

    #[test]
    fn a_library_that_was_added_or_renamed_needs_a_full_listing() -> Res {
        let first_rig = site_rig(vec![library("dl", "Documents"), library("da", "Archive")])?;
        let finance = child(&work().root(), "Finance");
        let place = at(&format!("site:{S1}"), &finance);
        let first = first_rig.graph.changes(&place, None, &idle())?;
        for libraries in [
            vec![
                library("dl", "Documents"),
                library("da", "Archive"),
                library("dz", "New"),
            ],
            vec![library("dl", "Documents"), library("da", "Old archive")],
            vec![library("dl", "Documents")],
        ] {
            let later = site_rig(libraries)?;
            let got = later.graph.changes(&place, Some(&first.cursor), &idle())?;
            assert!(got.full);
            assert!(
                later
                    .calls()
                    .iter()
                    .all(|seen| seen.param("token").is_none())
            );
        }
        Ok(())
    }

    #[test]
    fn a_cancelled_listing_stops_between_pages() -> Res {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let rig = rig(&work(), move |seen| {
            flag.store(true, Ordering::SeqCst);
            page(
                vec![root(), file("f1", "a.txt", "root1", 1)],
                Some(format!("{}{DELTA}?token=p2", origin(seen))),
                None,
            )
        })?;
        let result = rig
            .graph
            .changes(&at("drive:d1", &documents()), None, &stop);
        assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");
        assert_eq!(rig.calls().len(), 1, "the second page was never asked for");

        let before = AtomicBool::new(true);
        let result = rig
            .graph
            .changes(&at("drive:d1", &documents()), None, &before);
        assert!(matches!(result, Err(Error::Cancelled)));
        assert_eq!(rig.calls().len(), 1);
        Ok(())
    }

    // ---- throttling, sign-in, errors

    #[test]
    fn a_429_in_the_middle_of_a_listing_is_waited_out() -> Res {
        let hits = AtomicUsize::new(0);
        let rig = rig(&work(), move |seen| {
            let o = origin(seen);
            match seen.param("token").as_deref() {
                None => page(
                    vec![root(), file("f1", "a.txt", "root1", 1)],
                    Some(format!("{o}{DELTA}?token=p2")),
                    None,
                ),
                Some("p2") if hits.fetch_add(1, Ordering::SeqCst) == 0 => Answer::json(
                    429,
                    &json!({"error": {"code": "activityLimitReached", "message": "slow down"}}),
                )
                .header("Retry-After", "3"),
                Some("p2") => page(
                    vec![file("f2", "b.txt", "root1", 2)],
                    None,
                    Some(format!("{o}{DELTA}?token=end")),
                ),
                _ => missing(),
            }
        })?;
        let got = rig
            .graph
            .changes(&at("drive:d1", &documents()), None, &idle())?;
        assert_eq!(got.items.len(), 2);
        assert_eq!(rig.waited(), [Duration::from_secs(3)]);
        assert_eq!(rig.calls().len(), 3);
        Ok(())
    }

    #[test]
    fn a_long_retry_after_is_given_back_not_waited_for() -> Res {
        let rig = rig(&work(), |_| {
            Answer::json(
                429,
                &json!({"error": {"code": "activityLimitReached", "message": "slow down"}}),
            )
            .header("Retry-After", "900")
        })?;
        let error = failed(
            rig.graph
                .changes(&at("drive:d1", &documents()), None, &idle()),
        )?;
        assert!(
            matches!(&error, Error::Throttled { retry_after: Some(wait), .. } if *wait == Duration::from_mins(15)),
            "{error:?}"
        );
        assert!(rig.waited().is_empty());
        assert_eq!(rig.calls().len(), 1);
        Ok(())
    }

    #[test]
    fn a_rejected_token_is_replaced_once_and_the_call_made_again() -> Res {
        let account = personal();
        let calls = AtomicUsize::new(0);
        let rig = rig(&account, move |_| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Answer::json(
                    401,
                    &json!({"error": {"code": "InvalidAuthenticationToken", "message": "expired"}}),
                )
            } else {
                Answer::json(200, &json!({"id": "pd", "name": "OneDrive", "webUrl": ""}))
            }
        })?;
        let top = rig.graph.browse(None)?;
        assert_eq!(top.len(), 1);
        let calls = rig.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(authorization(&calls[0]), Some("Bearer at-1"));
        assert_eq!(authorization(&calls[1]), Some("Bearer at-2"));
        let tokens = rig.tokens();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].path(), "/consumers/oauth2/v2.0/token");
        assert_eq!(
            tokens[0].field("grant_type").as_deref(),
            Some("refresh_token")
        );
        assert_eq!(tokens[0].field("refresh_token").as_deref(), Some("rt-0"));
        assert_eq!(tokens[0].field("client_id").as_deref(), Some("client"));
        assert_eq!(tokens[0].field("scope").as_deref(), Some(SCOPE_PERSONAL));
        assert_eq!(tokens[1].field("refresh_token").as_deref(), Some("rt-1"));
        Ok(())
    }

    #[test]
    fn a_refused_refresh_or_a_token_that_stays_rejected_needs_a_new_sign_in() -> Res {
        let account = personal();
        let secrets = Secrets::default().with_refresh_token("rt-0");
        let refused = rig_with(&account, &secrets, |seen| {
            if seen.path().ends_with("/token") {
                Answer::json(400, &json!({"error": "invalid_grant"}))
            } else {
                missing()
            }
        })?;
        let error = failed(refused.graph.browse(None))?;
        assert_eq!(kind(&error), "sign_in", "{error:?}");
        assert!(
            refused.calls().is_empty(),
            "nothing was sent without a token"
        );

        let rejected = rig(&account, |_| {
            Answer::json(
                401,
                &json!({"error": {"code": "InvalidAuthenticationToken", "message": "no"}}),
            )
        })?;
        let error = failed(rejected.graph.browse(None))?;
        assert_eq!(kind(&error), "sign_in", "{error:?}");
        assert_eq!(rejected.calls().len(), 2, "one retry, no more");
        Ok(())
    }

    #[test]
    fn graphs_error_codes_say_what_to_do() -> Res {
        for (status, code, retry, expected) in [
            (404, "itemNotFound", None, "not_found"),
            (403, "accessDenied", None, "forbidden"),
            (429, "TooManyRequests", Some("900"), "throttled"),
            (503, "activityLimitReached", Some("900"), "throttled"),
            (500, "generalException", None, "network"),
            (400, "invalidRequest", None, "unexpected"),
        ] {
            let rig = rig(&personal(), move |_| {
                let answer =
                    Answer::json(status, &json!({"error": {"code": code, "message": "text"}}));
                match retry {
                    Some(seconds) => answer.header("Retry-After", seconds),
                    None => answer,
                }
            })?;
            let error = failed(rig.graph.browse(None))?;
            assert_eq!(kind(&error), expected, "{status} {code}: {error:?}");
            let shown = error.to_string();
            assert!(!shown.contains("text") && !shown.contains(code), "{shown}");
            if let Error::Throttled { retry_after, .. } = &error {
                assert_eq!(*retry_after, Some(Duration::from_mins(15)));
            }
        }
        Ok(())
    }

    // ---- downloads

    fn content() -> impl Fn(&Seen) -> Answer + Send + Sync + 'static {
        |seen| match seen.path() {
            "/v1.0/drives/d1/items/i1/content" => {
                Answer::redirect(&format!("{}/blob/i1", origin(seen)))
            }
            "/v1.0/drives/d1/items/i2/content" => {
                Answer::redirect(&format!("{}/blob/i2", origin(seen)))
            }
            "/blob/i1" => Answer::bytes(200, vec![b'x'; 10]),
            "/blob/i2" => Answer::bytes(200, vec![b'y'; 11]),
            _ => missing(),
        }
    }

    fn remote(id: &str, size: u64) -> RemoteItem {
        RemoteItem {
            id: id.to_owned(),
            path: child(&documents(), "a.bin"),
            size,
            modified: SystemTime::UNIX_EPOCH,
            version: "v".to_owned(),
            web_url: String::new(),
            export: None,
        }
    }

    #[test]
    fn a_file_is_downloaded_through_the_address_graph_redirects_to() -> Res {
        let rig = rig(&work(), content())?;
        let bytes = rig.graph.download(&remote("d1|i1", 10), 10, &idle())?;
        assert_eq!(bytes, vec![b'x'; 10], "exactly max bytes: returned whole");
        let blob = rig.mock.seen_at("/blob/i1");
        assert_eq!(blob.len(), 1);
        assert!(
            authorization(&blob[0]).is_none(),
            "the signed address gets no bearer token"
        );
        let api = rig.mock.seen_at("/v1.0/drives/d1/items/i1/content");
        assert_eq!(authorization(&api[0]), Some("Bearer at-1"));
        Ok(())
    }

    #[test]
    fn a_file_over_the_cap_is_too_large_with_or_without_its_size() -> Res {
        let rig = rig(&work(), content())?;
        let error = failed(rig.graph.download(&remote("d1|i2", 11), 10, &idle()))?;
        assert!(matches!(error, Error::TooLarge));
        assert!(
            rig.mock.seen().is_empty(),
            "the size in the listing is enough: nothing was asked"
        );

        let error = failed(rig.graph.download(&remote("d1|i2", 0), 10, &idle()))?;
        assert!(matches!(error, Error::TooLarge), "{error:?}");
        assert_eq!(
            rig.graph.download(&remote("d1|i2", 0), 11, &idle())?.len(),
            11
        );
        Ok(())
    }

    #[test]
    fn a_download_stops_when_cancelled_and_says_what_went_wrong() -> Res {
        let rig = rig(&work(), content())?;
        let stop = AtomicBool::new(true);
        let error = failed(rig.graph.download(&remote("d1|i1", 10), 10, &stop))?;
        assert!(matches!(error, Error::Cancelled));
        assert!(rig.mock.seen().is_empty());

        let error = failed(rig.graph.download(&remote("d1|gone", 1), 10_000, &idle()))?;
        assert_eq!(kind(&error), "not_found", "{error:?}");
        let error = failed(rig.graph.download(&remote("no-drive", 1), 10, &idle()))?;
        assert_eq!(kind(&error), "local", "{error:?}");
        Ok(())
    }

    // ---- signing in

    #[test]
    fn each_way_to_sign_in_makes_its_own_grant() -> Res {
        let endpoints = Endpoints::default();
        let (Grant::Browser(work), Mode::Delegated) = setup(&work(), &endpoints)? else {
            return Err("a browser grant was expected".into());
        };
        assert_eq!(
            work.authorize_url,
            "https://login.microsoftonline.com/contoso/oauth2/v2.0/authorize"
        );
        assert_eq!(
            work.token_url,
            "https://login.microsoftonline.com/contoso/oauth2/v2.0/token"
        );
        assert_eq!(
            work.scope,
            "Files.Read.All Sites.Read.All offline_access User.Read"
        );
        assert_eq!(work.client_id, "client");
        assert_eq!(work.client_auth, ClientAuth::None);
        assert!(work.pkce && work.port == 0 && work.redirect_path.is_empty());
        assert_eq!(work.redirect_host, "localhost");

        let (Grant::Browser(own), _) = setup(&personal(), &endpoints)? else {
            return Err("a browser grant was expected".into());
        };
        assert_eq!(
            own.token_url,
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
        );
        assert_eq!(own.scope, "Files.Read offline_access");
        assert_eq!(own.redirect_host, "localhost");

        let (Grant::App(all), Mode::App) = setup(&app(None), &endpoints)? else {
            return Err("an app grant was expected".into());
        };
        assert_eq!(
            all.token_url,
            "https://login.microsoftonline.com/contoso/oauth2/v2.0/token"
        );
        assert_eq!(
            all.scope.as_deref(),
            Some("https://graph.microsoft.com/.default")
        );
        assert!(matches!(
            all.credential,
            AppCredential::Secret(ClientAuth::Body)
        ));

        let selected = app(Some(&["https://contoso.sharepoint.com/sites/Finance"]));
        let (Grant::App(_), Mode::Selected(sites)) = setup(&selected, &endpoints)? else {
            return Err("an app grant was expected".into());
        };
        assert_eq!(sites, ["https://contoso.sharepoint.com/sites/Finance"]);

        let certificate = account(
            Provider::Microsoft365,
            "Contoso",
            SignIn::MicrosoftApp {
                tenant: "contoso".to_owned(),
                client_id: "client".to_owned(),
                credential: Credential::Certificate {
                    key_file: PathBuf::from("key.pem"),
                    cert_file: PathBuf::from("cert.pem"),
                },
            },
        );
        let (Grant::App(signed), _) = setup(&certificate, &endpoints)? else {
            return Err("an app grant was expected".into());
        };
        assert!(matches!(
            &signed.credential,
            AppCredential::Certificate { key_file, cert_file }
                if key_file == Path::new("key.pem") && cert_file == Path::new("cert.pem")
        ));
        Ok(())
    }

    /// The value of the field `name` in the query of `url`, as it is written there (still
    /// percent-encoded).
    fn raw_field<'a>(url: &'a str, name: &str) -> Option<&'a str> {
        url.split_once('?')?
            .1
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
    }

    #[test]
    fn the_microsoft_sign_in_sends_localhost_and_the_code_is_exchanged_with_the_same_address() -> Res
    {
        use std::io::{Read, Write};

        for account in [work(), personal()] {
            let answer = |seen: &Seen| {
                if seen.path().ends_with("/token") {
                    Answer::json(
                        200,
                        &json!({"access_token": "at", "refresh_token": "rt", "expires_in": 3600}),
                    )
                } else {
                    Answer::empty(404)
                }
            };
            let rig = rig_with(&account, &Secrets::default(), answer)?;

            // The test is the browser: given the address to open, it comes back to the redirect
            // by the name the service was told, with a code. If it cannot, it stops the wait.
            let cancel = Arc::new(AtomicBool::new(false));
            let given = Mutex::new(String::new());
            let visitor = Mutex::new(None);
            let open = |address: &str| {
                if let Ok(mut given) = given.lock() {
                    address.clone_into(&mut given);
                }
                let redirect = raw_field(address, "redirect_uri").unwrap_or_default();
                let host = redirect
                    .strip_prefix("http%3A%2F%2F")
                    .unwrap_or_default()
                    .replace("%3A", ":");
                let state = raw_field(address, "state").unwrap_or_default().to_owned();
                let stop = Arc::clone(&cancel);
                let handle = std::thread::spawn(move || {
                    let visit = || -> std::io::Result<String> {
                        let mut stream = std::net::TcpStream::connect(host.as_str())?;
                        stream.set_read_timeout(Some(Duration::from_secs(20)))?;
                        write!(
                            stream,
                            "GET /?code=abc&state={state} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                        )?;
                        let mut page = String::new();
                        stream.read_to_string(&mut page)?;
                        Ok(page)
                    };
                    let page = visit();
                    if page.is_err() {
                        stop.store(true, Ordering::SeqCst);
                    }
                    page
                });
                if let Ok(mut visitor) = visitor.lock() {
                    *visitor = Some(handle);
                }
            };
            rig.graph.session.connect(&open, &cancel)?;

            // The service was told `localhost`, as Entra registers it...
            let first = given.into_inner().map_err(|_| "poisoned")?;
            assert!(
                first.contains("redirect_uri=http%3A%2F%2Flocalhost%3A"),
                "{first}"
            );
            let redirect = raw_field(&first, "redirect_uri").ok_or("no redirect address")?;
            let port = redirect
                .strip_prefix("http%3A%2F%2Flocalhost%3A")
                .ok_or("the redirect is not on localhost")?;
            assert!(
                !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
                "{redirect}"
            );

            // ...and the code was exchanged with the very same address.
            let tokens = rig.tokens();
            assert_eq!(tokens.len(), 1);
            assert_eq!(
                tokens[0].field("redirect_uri"),
                Some(format!("http://localhost:{port}"))
            );
            assert_eq!(tokens[0].field("code").as_deref(), Some("abc"));

            // The browser, which came back as `localhost:<port>`, was let in.
            let page = visitor
                .into_inner()
                .map_err(|_| "poisoned")?
                .ok_or("the browser never came back")?
                .join()
                .map_err(|_| "the browser's thread panicked")??;
            assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        }
        Ok(())
    }

    #[test]
    fn a_blank_tenant_means_any_work_account_or_a_personal_one() -> Res {
        let sign_in = |tenant: &str| SignIn::MicrosoftDelegated {
            tenant: tenant.to_owned(),
            client_id: "client".to_owned(),
        };
        let endpoints = Endpoints::default();
        for (provider, tenant, expected) in [
            (Provider::Microsoft365, " ", "organizations"),
            (Provider::OneDrive, "", "consumers"),
            (Provider::Microsoft365, "common", "common"),
        ] {
            let (Grant::Browser(browser), _) =
                setup(&account(provider, "x", sign_in(tenant)), &endpoints)?
            else {
                return Err("a browser grant was expected".into());
            };
            assert!(
                browser.token_url.contains(&format!("/{expected}/")),
                "{}",
                browser.token_url
            );
        }
        Ok(())
    }

    #[test]
    fn an_account_that_does_not_fit_is_refused_in_plain_words() -> Res {
        let endpoints = Endpoints::default();
        let google = SignIn::GoogleDelegated {
            client_id: "x".to_owned(),
        };
        let personal_app = SignIn::MicrosoftApp {
            tenant: "t".to_owned(),
            client_id: "c".to_owned(),
            credential: Credential::Secret,
        };
        let no_client = SignIn::MicrosoftDelegated {
            tenant: "t".to_owned(),
            client_id: " ".to_owned(),
        };
        let no_tenant = SignIn::MicrosoftApp {
            tenant: String::new(),
            client_id: "c".to_owned(),
            credential: Credential::Secret,
        };
        for (provider, sign_in) in [
            (Provider::Microsoft365, google.clone()),
            (Provider::GoogleDrive, google),
            (Provider::OneDrive, personal_app),
            (Provider::Microsoft365, no_client),
            (Provider::Microsoft365, no_tenant),
        ] {
            let error = failed(setup(&account(provider, "x", sign_in), &endpoints))?;
            let Error::Local(crate::Error::BadRequest(text)) = &error else {
                return Err(format!("a plain sentence was expected: {error:?}").into());
            };
            assert!(text.ends_with('.') && !text.contains("PII"), "{text}");
        }
        let store = TokenStore::new(&temp_dir("graph-refused"));
        let google_account = account(
            Provider::Microsoft365,
            "x",
            SignIn::GoogleDelegated {
                client_id: "x".to_owned(),
            },
        );
        assert!(Graph::new(&google_account, &store).is_err());
        assert!(session(&google_account, &store).is_err());
        assert!(session(&work(), &store).is_ok());
        Ok(())
    }

    #[test]
    fn a_place_is_spelled_and_read_back() {
        for place in [
            Place::Site(S1.to_owned()),
            Place::Drive("b!abc-_".to_owned()),
            Place::Folder {
                drive: "b!abc".to_owned(),
                item: "01ABC!123".to_owned(),
            },
        ] {
            assert_eq!(Place::parse(&place.id()), Some(place));
        }
        for bad in [
            "", "site:", "drive:", "item:a", "item:|b", "item:a|", "other:x", "x",
        ] {
            assert_eq!(Place::parse(bad), None, "{bad:?}");
        }
        assert_eq!(seg("b!abc,d e/f"), "b!abc,d%20e%2Ff");
    }
}
