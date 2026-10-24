//! The Dropbox connector: one tree per account, read through the HTTP API v2 (`files/list_folder`,
//! `list_folder/continue`, `get_metadata`, `files/download`).
//!
//! - **Sign-in.** The authorization code flow with PKCE and `token_access_type=offline` (a refresh
//!   token), for a public client: only the app key, never a secret. Dropbox compares the
//!   `redirect_uri` with the registered ones character by character, a loopback address and its
//!   port included, so the redirect is the one fixed address `http://127.0.0.1:53123/`
//!   ([`REDIRECT_PORT`]) that the person registers in the app console.
//! - **Paths.** A file's virtual path is the account's root plus the components of the entry's
//!   `path_display`, each through [`child`]. Dropbox's own path of the root is `""`; a folder is
//!   listed by its `id:...` so a rename does not break a stored location.
//! - **`resolve`.** A virtual path is turned back into a Dropbox path by undoing what
//!   [`component`] did to the full-width look-alikes (the 9 characters Windows forbids) and asking
//!   `get_metadata`; the answer's own `path_display` must spell the same virtual path, or the
//!   guess was wrong. When it was (a name that [`component`] changed in a way that cannot be
//!   undone: `Notes.` is `Notes_`, `con` is `_con`), the path is walked: each folder is listed and
//!   the entry whose name makes that component is taken. Folders seen by `browse` and `resolve`
//!   are remembered (virtual path to Dropbox path), which only saves the guess: the answer is
//!   always read from `get_metadata` again.
//! - **Changes.** A folder cursor is the change feed. `list_folder/continue` reports what was
//!   deleted after the cursor was taken whatever `include_deleted` was when it was made (Dropbox
//!   staff, on the developer forum: `include_deleted` only decides whether what was already
//!   deleted at that time is listed; the reference does not say more than that `DeletedMetadata`
//!   entries are applied by the same rules), so the first listing leaves deleted entries out and
//!   saves a large account the listing of its whole trash.

use std::{
    collections::HashMap,
    fmt::Write as _,
    path::{Component, Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Account, Changes, Connector, Error, Provider, RemoteFolder, RemoteItem, Resolved, Result,
    SignIn,
    auth::{Browser, ClientAuth, Grant, LOOPBACK, Session, TokenStore},
    child, component,
    http::{Http, Reply, Request, encode, encode_path, pages},
    parse_time, parse_virtual,
};
use crate::sys;

/// The port of the loopback redirect `http://127.0.0.1:53123/`. Dropbox matches the redirect
/// address exactly as it was registered in the app console, so the port cannot be any free one.
pub(crate) const REDIRECT_PORT: u16 = 53_123;
/// What follows the port in the redirect address: Dropbox registers the address with its slash.
const REDIRECT_PATH: &str = "/";
/// What piikey asks to read, and nothing more.
const SCOPES: &str = "files.metadata.read files.content.read";
/// The most entries Dropbox answers with in one page.
const PAGE: u32 = 2000;
/// The most folders `resolve` remembers: the cache saves requests, it is not a copy of the tree.
const CACHE_LIMIT: usize = 4096;
/// The characters [`component`] spells with a full-width look-alike, and their real forms.
const LOOKALIKES: [(char, char); 9] = [
    ('＼', '\\'),
    ('／', '/'),
    ('：', ':'),
    ('＊', '*'),
    ('？', '?'),
    ('＂', '"'),
    ('＜', '<'),
    ('＞', '>'),
    ('｜', '|'),
];

/// The addresses of the service: the real ones, or a test's server.
#[derive(Debug, Clone)]
struct Endpoints {
    /// Where the RPC calls go (`/2/files/list_folder`...).
    api: String,
    /// Where a file's bytes come from (`/2/files/download`).
    content: String,
    /// The page the browser signs in on.
    authorize: String,
    /// Where the code and the refresh token are exchanged.
    token: String,
    /// The web site, for the addresses that open a file or folder in a browser.
    web: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            api: "https://api.dropboxapi.com".to_owned(),
            content: "https://content.dropboxapi.com".to_owned(),
            authorize: "https://www.dropbox.com/oauth2/authorize".to_owned(),
            token: "https://api.dropboxapi.com/oauth2/token".to_owned(),
            web: "https://www.dropbox.com".to_owned(),
        }
    }
}

/// One entry of a listing or a `get_metadata` answer.
#[derive(Debug, Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum Entry {
    File(FileEntry),
    Folder(FolderEntry),
    Deleted(DeletedEntry),
    /// Something a later version of the API adds.
    #[serde(other)]
    Other,
}

impl Entry {
    /// The last component of the entry's path, for a file or a folder.
    fn name(&self) -> Option<&str> {
        match self {
            Self::File(file) => Some(&file.name),
            Self::Folder(folder) => Some(&folder.name),
            Self::Deleted(_) | Self::Other => None,
        }
    }
}

/// `FileMetadata`: the fields piikey reads.
#[derive(Debug, Deserialize)]
struct FileEntry {
    id: String,
    name: String,
    #[serde(default)]
    path_display: Option<String>,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    server_modified: Option<String>,
    #[serde(default)]
    client_modified: Option<String>,
    #[serde(default)]
    rev: Option<String>,
    #[serde(default)]
    content_hash: Option<String>,
    /// False for a file that can only be exported (a Google Docs file kept in Dropbox).
    #[serde(default = "yes")]
    is_downloadable: bool,
}

/// `FolderMetadata`.
#[derive(Debug, Deserialize)]
struct FolderEntry {
    id: String,
    name: String,
    #[serde(default)]
    path_display: Option<String>,
}

/// `DeletedMetadata`: where there used to be a file or a folder.
#[derive(Debug, Deserialize)]
struct DeletedEntry {
    #[serde(default)]
    path_display: Option<String>,
}

/// `serde`'s way to say a field is true when the service leaves it out.
const fn yes() -> bool {
    true
}

/// `ListFolderResult`.
#[derive(Debug, Deserialize)]
struct Page {
    #[serde(default)]
    entries: Vec<Entry>,
    cursor: String,
    #[serde(default)]
    has_more: bool,
}

/// What a listing or the feed since a cursor came to.
enum Listed {
    /// Every page was read; the cursor is the last page's.
    Done(Feed, String),
    /// The cursor is no good any more: Dropbox says to list again.
    Reset,
}

/// What the entries of a listing add up to, whatever their order.
#[derive(Debug, Default)]
struct Feed {
    /// The files, by the key of their virtual path: a file that comes twice is the later one.
    items: HashMap<String, RemoteItem>,
    /// The paths that are gone, by key. A path that is also a file of the feed is not here.
    removed: HashMap<String, PathBuf>,
    /// A deletion came without a path, so what it removed cannot be told.
    unplaced: bool,
}

impl Feed {
    /// Takes one entry in. Only what is under `root` counts.
    fn add(&mut self, entry: Entry, dropbox: &Dropbox, root: &Path) {
        match entry {
            Entry::File(file) => {
                if let Some(item) = dropbox.item(&file)
                    && sys::is_under(&item.path, root)
                {
                    let key = sys::path_key(&item.path);
                    self.removed.remove(&key);
                    self.items.insert(key, item);
                }
            }
            Entry::Deleted(gone) => match gone.path_display.as_deref() {
                Some(display) => {
                    let path = dropbox.virtual_of(display);
                    let key = sys::path_key(&path);
                    if sys::is_under(&path, root) && !self.items.contains_key(&key) {
                        self.removed.insert(key, path);
                    }
                }
                None => self.unplaced = true,
            },
            Entry::Folder(_) | Entry::Other => {}
        }
    }

    /// The files of a full listing, by path.
    fn full(self) -> Vec<RemoteItem> {
        let mut items: Vec<_> = self.items.into_values().collect();
        items.sort_by(|a, b| a.path.cmp(&b.path));
        items
    }

    /// What changed: the files, and the paths that are gone. `None` when that cannot be told from
    /// the feed (a deletion without a path, or a folder that was deleted and has files again: what
    /// was under it before is not named), and a full listing has to answer instead.
    fn changed(self) -> Option<(Vec<RemoteItem>, Vec<PathBuf>)> {
        if self.unplaced {
            return None;
        }
        let rebuilt = !self.removed.is_empty()
            && self.items.values().any(|item| {
                item.path
                    .ancestors()
                    .skip(1)
                    .any(|up| self.removed.contains_key(&sys::path_key(up)))
            });
        if rebuilt {
            return None;
        }
        let mut removed: Vec<_> = self.removed.into_values().collect();
        removed.sort();
        let mut items: Vec<_> = self.items.into_values().collect();
        items.sort_by(|a, b| a.path.cmp(&b.path));
        Some((items, removed))
    }
}

/// A connected Dropbox account.
#[derive(Debug)]
pub(crate) struct Dropbox {
    /// The account's virtual root: `\\Dropbox\<label>`.
    root: PathBuf,
    /// The account's label, for checking a path is its own.
    label: String,
    session: Session,
    endpoints: Endpoints,
    /// Folders `browse` and `resolve` have seen: the key of the virtual path, and its Dropbox
    /// path. It only saves a guess; every answer is read again.
    folders: Mutex<HashMap<String, String>>,
}

impl Dropbox {
    /// A connector for a connected account, talking to Dropbox.
    ///
    /// # Errors
    /// `Local` when the account does not sign in the way Dropbox does.
    pub(crate) fn new(account: &Account, tokens: &TokenStore) -> Result<Self> {
        Self::with(
            account,
            tokens,
            Http::new(Provider::Dropbox),
            Endpoints::default(),
        )
    }

    /// The connector over `http` and the services at `endpoints`.
    fn with(
        account: &Account,
        tokens: &TokenStore,
        http: Http,
        endpoints: Endpoints,
    ) -> Result<Self> {
        let session = session_with(account, tokens, http, &endpoints)?;
        Ok(Self {
            root: account.root(),
            label: account.label.clone(),
            session,
            endpoints,
            folders: Mutex::new(HashMap::new()),
        })
    }

    /// A call of the files API: a POST with a JSON body (the bearer is put on by the session).
    fn post(&self, route: &str, body: &Value) -> Request {
        Request::post(format!("{}/2/files/{route}", self.endpoints.api)).json(body)
    }

    /// The request for the next page after `cursor`.
    fn next(&self, cursor: &str) -> Request {
        self.post("list_folder/continue", &json!({ "cursor": cursor }))
    }

    /// The request that starts listing `path` (`""`, a path or an `id:...`).
    fn start(&self, path: &str, recursive: bool) -> Request {
        self.post(
            "list_folder",
            &json!({
                "path": path,
                "recursive": recursive,
                "include_deleted": false,
                "limit": PAGE,
                "include_non_downloadable_files": false,
            }),
        )
    }

    /// The virtual path of the Dropbox path `display`.
    fn virtual_of(&self, display: &str) -> PathBuf {
        display
            .split('/')
            .filter(|part| !part.is_empty())
            .fold(self.root.clone(), |path, name| child(&path, name))
    }

    /// Where a browser opens the folder at `display`.
    fn folder_url(&self, display: &str) -> String {
        format!("{}/home{}", self.endpoints.web, encode_path(display))
    }

    /// Where a browser opens the file `name` in the folder `display` is in.
    fn file_url(&self, display: &str, name: &str) -> String {
        let parent = display.rsplit_once('/').map_or("", |(parent, _)| parent);
        format!(
            "{}/home{}?preview={}",
            self.endpoints.web,
            encode_path(parent),
            encode(name)
        )
    }

    /// The account's top: the whole of the account, Dropbox's `""`.
    fn top(&self) -> RemoteFolder {
        RemoteFolder {
            id: String::new(),
            path: self.root.clone(),
            web_url: format!("{}/home", self.endpoints.web),
        }
    }

    /// A file as the inventory knows it; `None` when it has no path in this tree or cannot be
    /// downloaded.
    fn item(&self, file: &FileEntry) -> Option<RemoteItem> {
        let display = file.path_display.as_deref()?;
        if !file.is_downloadable {
            return None;
        }
        let time = |text: &Option<String>| text.as_deref().and_then(parse_time);
        let modified = time(&file.server_modified)
            .or_else(|| time(&file.client_modified))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let version = file
            .content_hash
            .clone()
            .filter(|hash| !hash.is_empty())
            .or_else(|| file.rev.clone())
            .unwrap_or_default();
        Some(RemoteItem {
            id: file.id.clone(),
            path: self.virtual_of(display),
            size: file.size,
            modified,
            version,
            web_url: self.file_url(display, &file.name),
            export: None,
        })
    }

    /// A folder, noted for `resolve`.
    fn folder_of(&self, folder: &FolderEntry) -> Option<RemoteFolder> {
        let display = folder.path_display.as_deref()?;
        let path = self.virtual_of(display);
        self.remember(&path, display);
        Some(RemoteFolder {
            id: folder.id.clone(),
            path,
            web_url: self.folder_url(display),
        })
    }

    /// What an entry names, when it names something that is there.
    fn resolved(&self, entry: &Entry) -> Option<Resolved> {
        match entry {
            Entry::File(file) => self.item(file).map(Resolved::File),
            Entry::Folder(folder) => self.folder_of(folder).map(Resolved::Folder),
            Entry::Deleted(_) | Entry::Other => None,
        }
    }

    /// The Dropbox path known for a virtual path.
    fn recall(&self, path: &Path) -> Option<String> {
        let folders = self.folders.lock().ok()?;
        folders.get(&sys::path_key(path)).cloned()
    }

    /// Notes the Dropbox path of a folder.
    fn remember(&self, path: &Path, display: &str) {
        if let Ok(mut folders) = self.folders.lock() {
            if folders.len() >= CACHE_LIMIT {
                folders.clear();
            }
            folders.insert(sys::path_key(path), display.to_owned());
        }
    }

    /// Forgets a folder that was not where it was noted.
    fn forget(&self, path: &Path) {
        if let Ok(mut folders) = self.folders.lock() {
            folders.remove(&sys::path_key(path));
        }
    }

    /// `path` when it is in this account.
    fn within(&self, path: &Path) -> Result<()> {
        if sys::is_under(path, &self.root) {
            Ok(())
        } else {
            Err(nothing("a path of another account"))
        }
    }

    /// The parts of a virtual path of this account below its top.
    fn parts(&self, path: &Path) -> Result<Vec<String>> {
        let here = parse_virtual(path).filter(|found| {
            found.provider == Provider::Dropbox
                && found.label.to_lowercase() == self.label.to_lowercase()
        });
        let here = here.ok_or_else(|| nothing("a path of another account"))?;
        here.rest
            .components()
            .map(|part| match part {
                Component::Normal(name) => name.to_str().map(str::to_owned),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| nothing("a path that goes nowhere"))
    }

    /// The entries directly in `path` that `keep` takes, through every page.
    fn list(&self, path: &str, keep: &dyn Fn(&Entry) -> bool) -> Result<Vec<Entry>> {
        let never = AtomicBool::new(false);
        let mut kept = Vec::new();
        pages(
            Provider::Dropbox,
            &never,
            self.start(path, false),
            &|request| self.session.send(request),
            |reply| {
                let page: Page = ok(reply)?.json()?;
                kept.extend(page.entries.into_iter().filter(|entry| keep(entry)));
                Ok(page.has_more.then(|| self.next(&page.cursor)))
            },
        )?;
        Ok(kept)
    }

    /// `get_metadata` of `path`; `None` when nothing is there.
    fn metadata(&self, path: &str) -> Result<Option<Entry>> {
        let reply = self
            .session
            .send(&self.post("get_metadata", &json!({ "path": path })))?;
        if reply.is_success() {
            return reply.json().map(Some);
        }
        match failure(&reply) {
            Error::NotFound { .. } => Ok(None),
            other => Err(other),
        }
    }

    /// Looks `parts` up folder by folder, for a name `component` changed beyond what the guess
    /// undoes.
    fn walk(&self, parts: &[String]) -> Result<Resolved> {
        let mut at = String::new();
        for (index, part) in parts.iter().enumerate() {
            let want = part.to_lowercase();
            let found = self.list(&at, &|entry| {
                entry
                    .name()
                    .is_some_and(|name| component(name).to_lowercase() == want)
            })?;
            let entry = found
                .into_iter()
                .next()
                .ok_or_else(|| nothing("nothing at that path"))?;
            if index + 1 == parts.len() {
                return self
                    .resolved(&entry)
                    .ok_or_else(|| nothing("nothing at that path"));
            }
            match &entry {
                Entry::Folder(folder) if folder.path_display.is_some() => {
                    self.folder_of(folder);
                    at = folder.path_display.clone().unwrap_or_default();
                }
                _ => return Err(nothing("a file where a folder was expected")),
            }
        }
        Err(nothing("nothing at that path"))
    }

    /// Lists `root` and what is below it, or reads what changed since `cursor`.
    fn feed(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<Listed> {
        let first = cursor.map_or_else(|| self.start(&root.id, true), |from| self.next(from));
        let mut continuing = cursor.is_some();
        let mut feed = Feed::default();
        let mut last = String::new();
        let mut reset = false;
        pages(
            Provider::Dropbox,
            cancel,
            first,
            &|request| self.session.send(request),
            |reply| {
                if continuing && is_reset(&reply) {
                    reset = true;
                    return Ok(None);
                }
                let page: Page = ok(reply)?.json()?;
                for entry in page.entries {
                    feed.add(entry, self, &root.path);
                }
                continuing = true;
                let more = page.has_more.then(|| self.next(&page.cursor));
                last = page.cursor;
                Ok(more)
            },
        )?;
        Ok(if reset {
            Listed::Reset
        } else {
            Listed::Done(feed, last)
        })
    }
}

impl Connector for Dropbox {
    fn provider(&self) -> Provider {
        Provider::Dropbox
    }

    fn browse(&self, under: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>> {
        let at = match under {
            Some(folder) => {
                self.within(&folder.path)?;
                folder.id.as_str()
            }
            None => "",
        };
        let folders = self.list(at, &|entry| matches!(entry, Entry::Folder(_)))?;
        let mut named: Vec<(String, RemoteFolder)> = folders
            .iter()
            .filter_map(|entry| match entry {
                Entry::Folder(folder) => self
                    .folder_of(folder)
                    .map(|found| (folder.name.to_lowercase(), found)),
                _ => None,
            })
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(named.into_iter().map(|(_, folder)| folder).collect())
    }

    fn resolve(&self, path: &Path) -> Result<Resolved> {
        let parts = self.parts(path)?;
        if parts.is_empty() {
            return Ok(Resolved::Folder(self.top()));
        }
        let known = self.recall(path);
        let guess = known.clone().unwrap_or_else(|| unfold(&parts));
        match self.metadata(&guess)? {
            Some(entry) => {
                if let Some(found) = self.resolved(&entry) {
                    let there = match &found {
                        Resolved::File(item) => &item.path,
                        Resolved::Folder(folder) => &folder.path,
                    };
                    if sys::same_path(there, path) {
                        return Ok(found);
                    }
                }
            }
            None if known.is_none() && parts.iter().all(|part| lossless(part)) => {
                return Err(nothing("nothing at that path"));
            }
            None => self.forget(path),
        }
        self.walk(&parts)
    }

    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<Changes> {
        self.within(&root.path)?;
        if let Some(cursor) = cursor
            && let Listed::Done(feed, next) = self.feed(root, Some(cursor), cancel)?
            && let Some((items, removed)) = feed.changed()
        {
            return Ok(Changes {
                items,
                removed,
                cursor: next,
                full: false,
            });
        }
        match self.feed(root, None, cancel)? {
            Listed::Done(feed, next) => Ok(Changes {
                items: feed.full(),
                removed: Vec::new(),
                cursor: next,
                full: true,
            }),
            Listed::Reset => Err(Error::unexpected(
                Provider::Dropbox,
                "the service asked to start over while listing",
            )),
        }
    }

    fn download(&self, item: &RemoteItem, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if item.size > max {
            return Err(Error::TooLarge);
        }
        let request = Request::post(format!("{}/2/files/download", self.endpoints.content))
            .header("Dropbox-API-Arg", &ascii_json(&json!({ "path": item.id })));
        let reply = self.session.download(&request, max, cancel)?;
        if reply.is_success() {
            Ok(reply.body)
        } else {
            Err(failure(&reply))
        }
    }
}

/// The session that signs a Dropbox account in: `sources::connect` calls
/// `session(..)?.connect(open, cancel)`.
///
/// # Errors
/// `Local` when the account does not sign in the way Dropbox does.
pub(crate) fn session(account: &Account, tokens: &TokenStore) -> Result<Session> {
    session_with(
        account,
        tokens,
        Http::new(Provider::Dropbox),
        &Endpoints::default(),
    )
}

/// [`session`] over `http` and the services at `endpoints`.
fn session_with(
    account: &Account,
    tokens: &TokenStore,
    http: Http,
    endpoints: &Endpoints,
) -> Result<Session> {
    let key = app_key(account)?;
    Ok(Session::new(
        http,
        tokens.clone(),
        &account.id,
        grant(key, endpoints),
    ))
}

/// The app key of an account that signs in the way Dropbox does.
fn app_key(account: &Account) -> Result<&str> {
    match &account.sign_in {
        SignIn::DropboxDelegated { app_key } if account.provider == Provider::Dropbox => {
            Ok(app_key)
        }
        _ => Err(Error::Local(crate::Error::BadRequest(
            "A Dropbox account signs in with the key of its Dropbox app.".to_owned(),
        ))),
    }
}

/// How a person signs in: a public client (PKCE, no secret) that gets a refresh token, over the
/// one loopback address the app console has registered.
fn grant(app_key: &str, endpoints: &Endpoints) -> Grant {
    Grant::Browser(Browser {
        authorize_url: endpoints.authorize.clone(),
        token_url: endpoints.token.clone(),
        client_id: app_key.to_owned(),
        scope: SCOPES.to_owned(),
        authorize_extra: vec![("token_access_type".to_owned(), "offline".to_owned())],
        client_auth: ClientAuth::None,
        redirect_host: LOOPBACK,
        port: REDIRECT_PORT,
        redirect_path: REDIRECT_PATH.to_owned(),
        pkce: true,
    })
}

/// [`Error::NotFound`] for something that is not there.
fn nothing(detail: &str) -> Error {
    Error::not_found(Provider::Dropbox, detail)
}

/// The `/`-separated Dropbox path a list of virtual components most likely stands for: the
/// full-width look-alikes are the characters they replace.
fn unfold(parts: &[String]) -> String {
    let mut path = String::new();
    for part in parts {
        path.push('/');
        path.extend(part.chars().map(|c| {
            LOOKALIKES
                .iter()
                .find_map(|&(lookalike, real)| (lookalike == c).then_some(real))
                .unwrap_or(c)
        }));
    }
    path
}

/// Whether the name that made `part` can be told from it alone. `component` leaves a name as it
/// is unless it has a character Windows forbids (a look-alike now), a control character, a dot or
/// space at the end, no letters at all or the name of a device (all `_`), so a part with neither
/// a look-alike nor an `_` is the name itself.
fn lossless(part: &str) -> bool {
    !part.contains('_')
        && !part
            .chars()
            .any(|c| LOOKALIKES.iter().any(|&(lookalike, _)| lookalike == c))
}

/// `value` as JSON that is plain ASCII: Dropbox wants the `Dropbox-API-Arg` header that way, so
/// every other character is `\uXXXX` (a pair for one outside the first plane).
fn ascii_json(value: &Value) -> String {
    let text = value.to_string();
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() && c != '\u{7f}' {
            out.push(c);
        } else {
            let mut units = [0_u16; 2];
            for unit in c.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// What Dropbox says about an error: the `error_summary` (`path/not_found/...`), and the body.
fn summary(reply: &Reply) -> (String, Value) {
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    let text = body
        .get("error_summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    (text, body)
}

/// Whether the answer to a `list_folder/continue` says the cursor is no good any more: a `reset`,
/// or a cursor the service cannot read at all (the call has no other argument to be wrong).
fn is_reset(reply: &Reply) -> bool {
    (reply.status == 409 && summary(reply).0.starts_with("reset")) || reply.status == 400
}

/// `reply` when it is a success, and otherwise what it stands for.
fn ok(reply: Reply) -> Result<Reply> {
    if reply.is_success() {
        Ok(reply)
    } else {
        Err(failure(&reply))
    }
}

/// What a reply that is not a success stands for. A 409 carries the endpoint's own error in its
/// JSON body: a path that is not there, is no file or is malformed is `NotFound`. A permission
/// that is missing is `Forbidden` (Dropbox says `missing_scope` with a 401). A 429 says how long
/// to wait in the header or, when that is missing, in `retry_after` of its body.
fn failure(reply: &Reply) -> Error {
    let provider = Provider::Dropbox;
    let (said, body) = summary(reply);
    let detail = format!(
        "HTTP {}: {}",
        reply.status,
        said.chars().take(200).collect::<String>()
    );
    let starts = |tags: &[&str]| tags.iter().any(|tag| said.starts_with(tag));
    match reply.status {
        409 if starts(&[
            "path/not_found",
            "path/not_file",
            "path/not_folder",
            "path/malformed_path",
        ]) =>
        {
            Error::not_found(provider, detail)
        }
        409 if starts(&["path/restricted_content"]) => Error::forbidden(provider, detail),
        401 | 403
            if starts(&[
                "missing_scope",
                "route_access_denied",
                "user_suspended",
                "no_permission",
            ]) =>
        {
            Error::forbidden(provider, detail)
        }
        409 => Error::unexpected(provider, detail),
        429 => {
            let wait = reply.retry_after().or_else(|| {
                body.pointer("/error/retry_after")
                    .and_then(Value::as_u64)
                    .map(Duration::from_secs)
            });
            Error::throttled(provider, wait, detail)
        }
        _ => reply.error(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::UNIX_EPOCH,
    };

    use super::*;
    use crate::{
        sources::{
            Secrets,
            testing::{Answer, Mock, Res, Seen},
        },
        testing::temp_dir,
    };

    /// The account of every test.
    fn account() -> Account {
        Account {
            id: "00112233aabbccdd".to_owned(),
            provider: Provider::Dropbox,
            label: "jan@acme.com".to_owned(),
            sign_in: SignIn::DropboxDelegated {
                app_key: "app-key".to_owned(),
            },
        }
    }

    /// A connector over a mock, the mock, and the waits the connector was asked to make.
    struct Rig {
        mock: Mock,
        dropbox: Dropbox,
        waits: Arc<Mutex<Vec<Duration>>>,
    }

    impl Rig {
        fn waited(&self) -> Vec<Duration> {
            self.waits
                .lock()
                .map(|waits| waits.clone())
                .unwrap_or_default()
        }

        /// The folder at the top of the account.
        fn root(&self) -> Res<RemoteFolder> {
            Ok(self.dropbox.folder(&account().root())?)
        }
    }

    /// A rig whose token endpoint hands out `token-1`, and whose API answers with `api`.
    fn rig(api: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Res<Rig> {
        rig_with_token(move |seen| {
            if seen.path() == "/oauth2/token" {
                Answer::json(
                    200,
                    &json!({"access_token": "token-1", "expires_in": 14400, "token_type": "bearer"}),
                )
            } else {
                api(seen)
            }
        })
    }

    /// A rig where `handler` answers everything, the token endpoint too.
    fn rig_with_token(handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Res<Rig> {
        let mock = Mock::start(handler)?;
        let waits = Arc::new(Mutex::new(Vec::new()));
        let noted = Arc::clone(&waits);
        let http = Http::with_pause(Provider::Dropbox, move |wait| {
            if let Ok(mut waits) = noted.lock() {
                waits.push(wait);
            }
        });
        let account = account();
        let store = TokenStore::new(&temp_dir("dropbox"));
        store.save(
            &account.id,
            &Secrets::default().with_refresh_token("refresh-1"),
        )?;
        let url = mock.url();
        let endpoints = Endpoints {
            api: url.clone(),
            content: url.clone(),
            authorize: format!("{url}/oauth2/authorize"),
            token: format!("{url}/oauth2/token"),
            ..Endpoints::default()
        };
        let dropbox = Dropbox::with(&account, &store, http, endpoints)?;
        Ok(Rig {
            mock,
            dropbox,
            waits,
        })
    }

    fn file(id: &str, display: &str, size: u64, hash: &str) -> Value {
        json!({
            ".tag": "file",
            "id": id,
            "name": display.rsplit('/').next().unwrap_or_default(),
            "path_lower": display.to_lowercase(),
            "path_display": display,
            "client_modified": "2024-01-02T03:04:05Z",
            "server_modified": "2024-01-02T03:04:05Z",
            "rev": "a1c10ce0dd78",
            "size": size,
            "is_downloadable": true,
            "content_hash": hash,
        })
    }

    fn folder(id: &str, display: &str) -> Value {
        json!({
            ".tag": "folder",
            "id": id,
            "name": display.rsplit('/').next().unwrap_or_default(),
            "path_lower": display.to_lowercase(),
            "path_display": display,
        })
    }

    fn deleted(display: &str) -> Value {
        json!({
            ".tag": "deleted",
            "name": display.rsplit('/').next().unwrap_or_default(),
            "path_lower": display.to_lowercase(),
            "path_display": display,
        })
    }

    fn page(entries: impl IntoIterator<Item = Value>, cursor: &str, more: bool) -> Answer {
        Answer::json(
            200,
            &json!({"entries": entries.into_iter().collect::<Vec<_>>(), "cursor": cursor, "has_more": more}),
        )
    }

    fn conflict(summary: &str) -> Answer {
        Answer::json(
            409,
            &json!({"error_summary": summary, "error": {".tag": summary.split('/').next().unwrap_or_default()}}),
        )
    }

    /// What a request's JSON body says in `field`.
    fn said(seen: &Seen, field: &str) -> String {
        seen.json()[field].as_str().unwrap_or_default().to_owned()
    }

    fn never() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn under(root: &Path, names: &[&str]) -> PathBuf {
        names
            .iter()
            .fold(root.to_path_buf(), |path, name| child(&path, name))
    }

    fn paths(items: &[RemoteItem]) -> Vec<PathBuf> {
        let mut paths: Vec<_> = items.iter().map(|item| item.path.clone()).collect();
        paths.sort();
        paths
    }

    fn item(id: &str, size: u64) -> RemoteItem {
        RemoteItem {
            id: id.to_owned(),
            path: under(&account().root(), &["f.txt"]),
            size,
            modified: UNIX_EPOCH,
            version: String::new(),
            web_url: String::new(),
            export: None,
        }
    }

    #[test]
    fn a_listing_over_three_pages_is_followed_to_the_end() -> Res {
        let rig = rig(|seen| {
            let cursor = said(seen, "cursor");
            match (seen.path(), cursor.as_str()) {
                ("/2/files/list_folder", _) => {
                    let mut hidden = file("id:x", "/Hidden.gdoc", 1, "hx");
                    hidden["is_downloadable"] = json!(false);
                    page(
                        vec![
                            file("id:1", "/Q1: plan.docx", 10, "h1"),
                            folder("id:f", "/Docs"),
                            hidden,
                            json!({".tag": "file", "id": "id:y", "name": "y", "size": 1, "rev": "abcdef123"}),
                        ],
                        "c1",
                        true,
                    )
                }
                ("/2/files/list_folder/continue", "c1") => {
                    page(vec![file("id:2", "/Docs/a.txt", 20, "h2")], "c2", true)
                }
                ("/2/files/list_folder/continue", "c2") => {
                    page(vec![file("id:3", "/Docs/Sub/b.txt", 30, "h3")], "c3", false)
                }
                _ => Answer::empty(404),
            }
        })?;
        let root = rig.root()?;
        let got = rig.dropbox.changes(&root, None, &never())?;

        assert!(got.full);
        assert!(got.removed.is_empty());
        assert_eq!(got.cursor, "c3");
        let base = account().root();
        assert_eq!(
            paths(&got.items),
            [
                under(&base, &["Docs", "Sub", "b.txt"]),
                under(&base, &["Docs", "a.txt"]),
                under(&base, &["Q1: plan.docx"]),
            ]
        );
        let q1 = got
            .items
            .iter()
            .find(|i| i.id == "id:1")
            .ok_or("the first file")?;
        assert_eq!((q1.size, q1.version.as_str()), (10, "h1"));
        assert_eq!(
            q1.path.file_name().and_then(|n| n.to_str()),
            Some("Q1： plan.docx")
        );
        assert_eq!(
            q1.web_url,
            "https://www.dropbox.com/home?preview=Q1%3A%20plan.docx"
        );
        assert_eq!(
            q1.modified,
            parse_time("2024-01-02T03:04:05Z").ok_or("a time")?
        );
        let nested = got
            .items
            .iter()
            .find(|i| i.id == "id:3")
            .ok_or("the third file")?;
        assert_eq!(
            nested.web_url,
            "https://www.dropbox.com/home/Docs/Sub?preview=b.txt"
        );

        let seen = rig.mock.seen();
        assert_eq!(seen.len(), 4, "one token call and three pages: {seen:?}");
        let first = rig.mock.seen_at("/2/files/list_folder");
        assert_eq!(
            first[0].json(),
            json!({"path": "", "recursive": true, "include_deleted": false, "limit": 2000, "include_non_downloadable_files": false})
        );
        assert_eq!(first[0].method, "POST");
        let cursors: Vec<_> = rig
            .mock
            .seen_at("/2/files/list_folder/continue")
            .iter()
            .map(|s| said(s, "cursor"))
            .collect();
        assert_eq!(cursors, ["c1", "c2"]);
        Ok(())
    }

    #[test]
    fn the_change_feed_gives_a_cursor_then_what_changed_since() -> Res {
        let rig = rig(|seen| match (seen.path(), said(seen, "cursor").as_str()) {
            ("/2/files/list_folder", _) => page(
                vec![
                    file("id:g", "/gone.txt", 1, "hg"),
                    file("id:b", "/b.txt", 2, "hb"),
                    file("id:m", "/m.txt", 3, "hm"),
                    file("id:o", "/Old/o.txt", 4, "ho"),
                ],
                "c1",
                false,
            ),
            ("/2/files/list_folder/continue", "c1") => page(
                vec![
                    deleted("/gone.txt"),
                    deleted("/Old"),
                    file("id:b", "/b.txt", 22, "hb2"),
                    file("id:m", "/New/m.txt", 3, "hm"),
                    folder("id:n", "/New"),
                    deleted("/m.txt"),
                ],
                "c2",
                false,
            ),
            _ => Answer::empty(404),
        })?;
        let root = rig.root()?;
        let first = rig.dropbox.changes(&root, None, &never())?;
        assert!(first.full);
        assert_eq!(first.items.len(), 4);

        let next = rig.dropbox.changes(&root, Some(&first.cursor), &never())?;
        let base = account().root();
        assert!(!next.full);
        assert_eq!(next.cursor, "c2");
        assert_eq!(paths(&next.items), {
            let mut want = vec![under(&base, &["b.txt"]), under(&base, &["New", "m.txt"])];
            want.sort();
            want
        });
        let changed = next
            .items
            .iter()
            .find(|i| i.id == "id:b")
            .ok_or("the changed file")?;
        assert_eq!((changed.size, changed.version.as_str()), (22, "hb2"));
        let mut removed = next.removed.clone();
        removed.sort();
        let mut want = vec![
            under(&base, &["gone.txt"]),
            under(&base, &["Old"]),
            under(&base, &["m.txt"]),
        ];
        want.sort();
        assert_eq!(removed, want);

        let again = rig.mock.seen_at("/2/files/list_folder/continue");
        assert_eq!(again.len(), 1);
        assert_eq!(said(&again[0], "cursor"), "c1");
        assert_eq!(rig.mock.seen_at("/2/files/list_folder").len(), 1);
        Ok(())
    }

    #[test]
    fn a_stored_cursor_is_posted_to_continue_and_every_page_after_it_is_followed() -> Res {
        let rig = rig(|seen| match said(seen, "cursor").as_str() {
            "stored" => page(vec![file("id:1", "/one.txt", 1, "h1")], "n1", true),
            "n1" => page(
                vec![file("id:2", "/two.txt", 2, "h2"), deleted("/old.txt")],
                "n2",
                false,
            ),
            _ => Answer::empty(404),
        })?;
        let root = rig.root()?;
        let got = rig.dropbox.changes(&root, Some("stored"), &never())?;
        assert!(!got.full);
        assert_eq!(got.cursor, "n2");
        assert_eq!(got.items.len(), 2);
        assert_eq!(got.removed, [under(&account().root(), &["old.txt"])]);
        let cursors: Vec<_> = rig
            .mock
            .seen()
            .iter()
            .filter(|s| s.path() != "/oauth2/token")
            .map(|s| (s.path().to_owned(), said(s, "cursor")))
            .collect();
        assert_eq!(
            cursors,
            [
                (
                    "/2/files/list_folder/continue".to_owned(),
                    "stored".to_owned()
                ),
                ("/2/files/list_folder/continue".to_owned(), "n1".to_owned()),
            ]
        );
        Ok(())
    }

    #[test]
    fn a_file_deleted_and_made_again_in_one_feed_stays_whatever_the_order() -> Res {
        let rig = rig(|seen| match (seen.path(), said(seen, "cursor").as_str()) {
            ("/2/files/list_folder/continue", "delete-first") => page(
                vec![deleted("/a.txt"), file("id:a", "/a.txt", 5, "ha")],
                "n1",
                false,
            ),
            ("/2/files/list_folder/continue", "item-first") => page(
                vec![file("id:a", "/a.txt", 5, "ha"), deleted("/A.TXT")],
                "n2",
                false,
            ),
            ("/2/files/list_folder/continue", "rebuilt") => page(
                vec![deleted("/Docs"), file("id:n", "/Docs/new.txt", 5, "hn")],
                "n3",
                false,
            ),
            ("/2/files/list_folder/continue", "unplaced") => {
                page(vec![json!({".tag": "deleted", "name": "x"})], "n4", false)
            }
            ("/2/files/list_folder", _) => {
                page(vec![file("id:z", "/Docs/new.txt", 5, "hn")], "fresh", false)
            }
            _ => Answer::empty(404),
        })?;
        let root = rig.root()?;
        let a = under(&root.path, &["a.txt"]);
        for cursor in ["delete-first", "item-first"] {
            let got = rig.dropbox.changes(&root, Some(cursor), &never())?;
            assert!(!got.full, "{cursor}");
            assert_eq!(paths(&got.items), std::slice::from_ref(&a), "{cursor}");
            assert!(got.removed.is_empty(), "{cursor}: {:?}", got.removed);
        }
        assert!(rig.mock.seen_at("/2/files/list_folder").is_empty());

        // What was under a folder that was deleted and made again is not named: list again.
        for cursor in ["rebuilt", "unplaced"] {
            let got = rig.dropbox.changes(&root, Some(cursor), &never())?;
            assert!(got.full, "{cursor}");
            assert_eq!(got.cursor, "fresh");
            assert!(got.removed.is_empty());
        }
        assert_eq!(rig.mock.seen_at("/2/files/list_folder").len(), 2);
        Ok(())
    }

    #[test]
    fn a_cursor_dropbox_does_not_take_is_answered_with_a_full_listing() -> Res {
        let rig = rig(|seen| match (seen.path(), said(seen, "cursor").as_str()) {
            ("/2/files/list_folder/continue", "reset") => conflict("reset/.."),
            ("/2/files/list_folder/continue", "garbled") => Answer::text(
                400,
                "Error in call to API function \"files/list_folder/continue\": cursor",
            ),
            ("/2/files/list_folder", _) => {
                page(vec![file("id:z", "/z.txt", 5, "hz")], "fresh", false)
            }
            _ => Answer::empty(404),
        })?;
        let root = rig.root()?;
        for cursor in ["reset", "garbled"] {
            let got = rig.dropbox.changes(&root, Some(cursor), &never())?;
            assert!(got.full, "{cursor}");
            assert_eq!(got.cursor, "fresh");
            assert_eq!(got.items.len(), 1);
        }
        let order: Vec<_> = rig
            .mock
            .seen()
            .iter()
            .filter(|s| s.path() != "/oauth2/token")
            .map(|s| s.path().to_owned())
            .collect();
        assert_eq!(
            order,
            [
                "/2/files/list_folder/continue",
                "/2/files/list_folder",
                "/2/files/list_folder/continue",
                "/2/files/list_folder",
            ]
        );
        Ok(())
    }

    #[test]
    fn a_subfolder_is_listed_by_id_and_only_what_is_under_it_is_kept() -> Res {
        let rig = rig(|seen| {
            match (
                seen.path(),
                said(seen, "path").as_str(),
                said(seen, "cursor").as_str(),
            ) {
                ("/2/files/list_folder", "id:docs", _) => page(
                    vec![
                        file("id:a", "/Docs/a.txt", 1, "ha"),
                        file("id:b", "/Other/b.txt", 1, "hb"),
                    ],
                    "c1",
                    false,
                ),
                ("/2/files/list_folder/continue", _, "c1") => page(
                    vec![deleted("/docs/gone.txt"), deleted("/Other/c.txt")],
                    "c2",
                    false,
                ),
                ("/2/files/list_folder/continue", _, "dead") => conflict("path/not_found/.."),
                _ => Answer::empty(404),
            }
        })?;
        let docs = RemoteFolder {
            id: "id:docs".to_owned(),
            path: under(&account().root(), &["Docs"]),
            web_url: String::new(),
        };
        let got = rig.dropbox.changes(&docs, None, &never())?;
        assert_eq!(paths(&got.items), [under(&docs.path, &["a.txt"])]);
        let next = rig.dropbox.changes(&docs, Some("c1"), &never())?;
        assert_eq!(next.removed.len(), 1);
        assert!(sys::same_path(
            &next.removed[0],
            &under(&docs.path, &["gone.txt"])
        ));
        let error = rig.dropbox.changes(&docs, Some("dead"), &never());
        assert!(matches!(error, Err(Error::NotFound { .. })), "{error:?}");

        let elsewhere = RemoteFolder {
            id: String::new(),
            path: PathBuf::from(r"\\Dropbox\other\Docs"),
            web_url: String::new(),
        };
        assert!(matches!(
            rig.dropbox.changes(&elsewhere, None, &never()),
            Err(Error::NotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_throttled_call_waits_as_asked_and_a_huge_wait_is_left_to_the_caller() -> Res {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let slow = rig(move |_| {
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                Answer::json(
                    429,
                    &json!({"error_summary": "too_many_requests/..", "error": {"reason": {".tag": "too_many_requests"}, "retry_after": 7}}),
                )
                .header("Retry-After", "7")
            } else {
                page(vec![file("id:1", "/a.txt", 1, "h")], "c", false)
            }
        })?;
        let root = slow.root()?;
        let got = slow.dropbox.changes(&root, None, &never())?;
        assert_eq!(got.items.len(), 1);
        assert_eq!(slow.waited(), [Duration::from_secs(7)]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let huge = rig(|_| {
            Answer::json(429, &json!({"error_summary": "too_many_requests/.."}))
                .header("Retry-After", "900")
        })?;
        let root = huge.root()?;
        let error = huge.dropbox.changes(&root, None, &never());
        assert!(
            matches!(&error, Err(Error::Throttled { retry_after: Some(wait), .. }) if *wait == Duration::from_mins(15)),
            "{error:?}"
        );
        assert!(huge.waited().is_empty());

        let body_only = rig(|_| {
            Answer::json(
                429,
                &json!({"error_summary": "too_many_requests/..", "error": {"retry_after": 300}}),
            )
        })?;
        let root = body_only.root()?;
        let error = body_only.dropbox.changes(&root, None, &never());
        assert!(
            matches!(&error, Err(Error::Throttled { retry_after: Some(wait), .. }) if *wait == Duration::from_mins(5)),
            "{error:?}"
        );
        Ok(())
    }

    #[test]
    fn an_expired_token_is_refreshed_once_and_a_refused_refresh_needs_a_new_sign_in() -> Res {
        let issued = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&issued);
        let rig = rig_with_token(move |seen| {
            if seen.path() == "/oauth2/token" {
                let n = counted.fetch_add(1, Ordering::SeqCst) + 1;
                return Answer::json(
                    200,
                    &json!({"access_token": format!("token-{n}"), "expires_in": 14400, "token_type": "bearer"}),
                );
            }
            match seen.header("authorization") {
                Some("Bearer token-1") => Answer::json(
                    401,
                    &json!({"error_summary": "expired_access_token/", "error": {".tag": "expired_access_token"}}),
                ),
                Some("Bearer token-2") => page(vec![folder("id:d", "/Docs")], "c", false),
                _ => Answer::empty(400),
            }
        })?;
        let got = rig.dropbox.browse(None)?;
        assert_eq!(got.len(), 1);

        let tokens = rig.mock.seen_at("/oauth2/token");
        assert_eq!(tokens.len(), 2);
        for token in &tokens {
            assert_eq!(token.field("grant_type").as_deref(), Some("refresh_token"));
            assert_eq!(token.field("refresh_token").as_deref(), Some("refresh-1"));
            assert_eq!(token.field("client_id").as_deref(), Some("app-key"));
            assert_eq!(token.field("client_secret"), None);
        }
        let calls = rig.mock.seen_at("/2/files/list_folder");
        let bearers: Vec<_> = calls
            .iter()
            .map(|c| c.header("authorization").unwrap_or_default().to_owned())
            .collect();
        assert_eq!(bearers, ["Bearer token-1", "Bearer token-2"]);

        let refused = rig_with_token(|seen| {
            if seen.path() == "/oauth2/token" {
                Answer::json(
                    400,
                    &json!({"error": "invalid_grant", "error_description": "refresh token is invalid or revoked"}),
                )
            } else {
                Answer::empty(500)
            }
        })?;
        let error = refused.dropbox.browse(None);
        assert!(
            matches!(error, Err(Error::SignInNeeded { .. })),
            "{error:?}"
        );
        assert!(refused.mock.seen_at("/2/files/list_folder").is_empty());
        Ok(())
    }

    #[test]
    fn what_dropbox_refuses_is_told_apart() -> Res {
        let rig = rig(|seen| match said(seen, "path").as_str() {
            "id:perm" => Answer::json(
                403,
                &json!({"error_summary": "no_permission/..", "error": {".tag": "no_permission"}}),
            ),
            "id:scope" => Answer::json(
                401,
                &json!({"error_summary": "missing_scope/..", "error": {".tag": "missing_scope"}}),
            ),
            "id:gone" => conflict("path/not_found/.."),
            "id:file" => conflict("path/not_file/.."),
            "id:odd" => conflict("something_else/.."),
            "id:signed-out" => Answer::json(
                401,
                &json!({"error_summary": "invalid_access_token/..", "error": {".tag": "invalid_access_token"}}),
            ),
            _ => Answer::empty(404),
        })?;
        let at = |id: &str| RemoteFolder {
            id: id.to_owned(),
            path: under(&account().root(), &["X"]),
            web_url: String::new(),
        };
        let browse = |id: &str| rig.dropbox.browse(Some(&at(id)));
        assert!(matches!(browse("id:perm"), Err(Error::Forbidden { .. })));
        assert!(matches!(browse("id:scope"), Err(Error::Forbidden { .. })));
        assert!(matches!(browse("id:gone"), Err(Error::NotFound { .. })));
        assert!(matches!(browse("id:file"), Err(Error::NotFound { .. })));
        assert!(matches!(browse("id:odd"), Err(Error::Unexpected { .. })));
        assert!(matches!(
            browse("id:signed-out"),
            Err(Error::SignInNeeded { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_download_is_posted_with_its_argument_in_a_header_and_capped_at_max() -> Res {
        let rig = rig(|seen| {
            let arg: Value = seen
                .header("dropbox-api-arg")
                .and_then(|arg| serde_json::from_str(arg).ok())
                .unwrap_or(Value::Null);
            match arg["path"].as_str() {
                Some("id:big") => Answer::bytes(200, vec![b'x'; 11]),
                Some("id:exact") => Answer::bytes(200, b"0123456789".to_vec()),
                Some("id:gone") => conflict("path/not_found/.."),
                _ => Answer::empty(404),
            }
        })?;
        let over = rig.dropbox.download(&item("id:big", 11), 10, &never());
        assert!(matches!(over, Err(Error::TooLarge)), "{over:?}");
        assert!(
            rig.mock.seen_at("/2/files/download").is_empty(),
            "the size said it all"
        );

        let unknown = rig.dropbox.download(&item("id:big", 0), 10, &never());
        assert!(matches!(unknown, Err(Error::TooLarge)), "{unknown:?}");

        let whole = rig.dropbox.download(&item("id:exact", 10), 10, &never())?;
        assert_eq!(whole, b"0123456789");
        let sent = rig.mock.seen_at("/2/files/download");
        assert_eq!(sent.len(), 2);
        let request = &sent[1];
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.header("dropbox-api-arg"),
            Some(r#"{"path":"id:exact"}"#)
        );
        assert_eq!(request.header("authorization"), Some("Bearer token-1"));
        assert!(request.body.is_empty());

        let missing = rig.dropbox.download(&item("id:gone", 1), 1000, &never());
        assert!(
            matches!(missing, Err(Error::NotFound { .. })),
            "{missing:?}"
        );
        Ok(())
    }

    #[test]
    fn a_download_is_not_started_once_cancelled() -> Res {
        let rig = rig(|_| Answer::bytes(200, b"abc".to_vec()))?;
        let cancel = AtomicBool::new(true);
        let error = rig.dropbox.download(&item("id:a", 3), 10, &cancel);
        assert!(matches!(error, Err(Error::Cancelled)), "{error:?}");
        assert!(rig.mock.seen().is_empty(), "nothing was sent");
        Ok(())
    }

    #[test]
    fn the_argument_header_is_plain_ascii_json_whatever_the_name() -> Res {
        let id = "/Ünï/日本😀.txt";
        let text = ascii_json(&json!({ "path": id }));
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            text,
            r#"{"path":"/\u00dcn\u00ef/\u65e5\u672c\ud83d\ude00.txt"}"#
        );
        assert_eq!(serde_json::from_str::<Value>(&text)?["path"], id);
        assert_eq!(
            ascii_json(&json!({"a": "tab\there\u{7f}"})),
            r#"{"a":"tab\there\u007f"}"#
        );

        let rig = rig(|_| Answer::bytes(200, b"bytes".to_vec()))?;
        assert_eq!(rig.dropbox.download(&item(id, 5), 100, &never())?, b"bytes");
        let sent = rig.mock.seen_at("/2/files/download");
        let header = sent[0].header("dropbox-api-arg").ok_or("the header")?;
        assert!(header.is_ascii());
        assert_eq!(header, text);
        Ok(())
    }

    #[test]
    fn resolve_finds_files_folders_and_the_top_and_browse_lists_folders_by_name() -> Res {
        let rig = rig(|seen| {
            let path = said(seen, "path").to_lowercase();
            match (seen.path(), path.as_str()) {
                ("/2/files/list_folder", "") => page(
                    vec![
                        folder("id:d", "/Docs"),
                        folder("id:c", "/cars"),
                        file("id:t", "/top.txt", 1, "h"),
                    ],
                    "c",
                    false,
                ),
                ("/2/files/list_folder", "id:d") => page(
                    vec![
                        folder("id:s", "/Docs/Sub"),
                        file("id:a", "/Docs/a.txt", 5, "ha"),
                    ],
                    "c",
                    false,
                ),
                ("/2/files/get_metadata", "/docs/a.txt") => {
                    Answer::json(200, &file("id:a", "/Docs/a.txt", 5, "ha"))
                }
                ("/2/files/get_metadata", "/docs") => Answer::json(200, &folder("id:d", "/Docs")),
                ("/2/files/get_metadata", _) => conflict("path/not_found/.."),
                _ => Answer::empty(404),
            }
        })?;
        let base = account().root();

        let top = rig.dropbox.resolve(&base)?;
        assert_eq!(
            top,
            Resolved::Folder(RemoteFolder {
                id: String::new(),
                path: base.clone(),
                web_url: "https://www.dropbox.com/home".to_owned(),
            })
        );
        assert!(rig.mock.seen().is_empty(), "the top needs no call");

        let folders = rig.dropbox.browse(None)?;
        let names: Vec<_> = folders.iter().map(|f| f.path.clone()).collect();
        assert_eq!(names, [under(&base, &["cars"]), under(&base, &["Docs"])]);
        assert_eq!(folders[1].id, "id:d");
        assert_eq!(folders[0].web_url, "https://www.dropbox.com/home/cars");
        let sub = rig.dropbox.browse(Some(&folders[1]))?;
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].path, under(&base, &["Docs", "Sub"]));

        let a = under(&base, &["Docs", "a.txt"]);
        let Resolved::File(found) = rig.dropbox.resolve(&a)? else {
            return Err("a file was expected".into());
        };
        assert_eq!(
            (found.id.as_str(), found.size, &found.path),
            ("id:a", 5, &a)
        );
        let Resolved::Folder(docs) = rig.dropbox.resolve(&under(&base, &["Docs"]))? else {
            return Err("a folder was expected".into());
        };
        assert_eq!(docs.id, "id:d");
        assert!(rig.dropbox.file(&under(&base, &["Docs"])).is_err());
        assert!(rig.dropbox.folder(&a).is_err());

        let loud = PathBuf::from(r"\\DROPBOX\JAN@ACME.COM\docs\A.TXT");
        let Resolved::File(again) = rig.dropbox.resolve(&loud)? else {
            return Err("a file was expected".into());
        };
        assert_eq!(again.path, a, "the path is spelled as Dropbox spells it");

        let before = rig.mock.seen_at("/2/files/list_folder").len();
        for missing in [
            under(&base, &["missing.txt"]),
            PathBuf::from(r"\\Dropbox\other\a.txt"),
            PathBuf::from(r"\\Box\jan@acme.com\a.txt"),
            PathBuf::from(r"C:\Users\jan\a.txt"),
        ] {
            let error = rig.dropbox.resolve(&missing);
            assert!(
                matches!(error, Err(Error::NotFound { .. })),
                "{missing:?}: {error:?}"
            );
        }
        assert_eq!(
            rig.mock.seen_at("/2/files/list_folder").len(),
            before,
            "nothing to walk"
        );
        Ok(())
    }

    #[test]
    fn a_name_with_characters_windows_forbids_round_trips_through_resolve_and_download() -> Res {
        let rig = rig(|seen| {
            let path = said(seen, "path");
            match (seen.path(), path.as_str()) {
                ("/2/files/get_metadata", "/Q1: plan/what?.txt") => {
                    Answer::json(200, &file("id:w", "/Q1: plan/what?.txt", 3, "hw"))
                }
                ("/2/files/get_metadata", "/Notes_/_con") => conflict("path/not_found/.."),
                ("/2/files/list_folder", "") => page(vec![folder("id:n", "/Notes.")], "c", false),
                ("/2/files/list_folder", "/Notes.") => {
                    page(vec![file("id:c", "/Notes./con", 3, "hc")], "c", false)
                }
                ("/2/files/download", _) => Answer::bytes(200, b"abc".to_vec()),
                _ => Answer::empty(404),
            }
        })?;
        let base = account().root();
        let weird = under(&base, &["Q1: plan", "what?.txt"]);
        assert!(weird.to_string_lossy().contains('？'));

        let Resolved::File(found) = rig.dropbox.resolve(&weird)? else {
            return Err("a file was expected".into());
        };
        assert_eq!((found.id.as_str(), &found.path), ("id:w", &weird));
        assert_eq!(rig.mock.seen_at("/2/files/get_metadata").len(), 1);
        assert_eq!(rig.dropbox.download(&found, 10, &never())?, b"abc");
        let sent = rig.mock.seen_at("/2/files/download");
        assert_eq!(
            sent[0].header("dropbox-api-arg"),
            Some(r#"{"path":"id:w"}"#)
        );

        // `Notes.` is `Notes_` and `con` is `_con`: no guess undoes that, so the folders are walked.
        let hard = under(&base, &["Notes.", "con"]);
        let Resolved::File(walked) = rig.dropbox.resolve(&hard)? else {
            return Err("a file was expected".into());
        };
        assert_eq!((walked.id.as_str(), &walked.path), ("id:c", &hard));
        assert_eq!(rig.mock.seen_at("/2/files/list_folder").len(), 2);
        Ok(())
    }

    #[test]
    fn changes_stops_when_cancelled_between_two_pages() -> Res {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let rig = rig(move |_| {
            flag.store(true, Ordering::SeqCst);
            page(vec![file("id:1", "/a.txt", 1, "h")], "c1", true)
        })?;
        let root = rig.root()?;
        let error = rig.dropbox.changes(&root, None, cancel.as_ref());
        assert!(matches!(error, Err(Error::Cancelled)), "{error:?}");
        assert_eq!(rig.mock.seen_at("/2/files/list_folder").len(), 1);
        assert!(rig.mock.seen_at("/2/files/list_folder/continue").is_empty());
        Ok(())
    }

    #[test]
    fn the_sign_in_is_pkce_with_a_refresh_token_over_the_registered_loopback_address() -> Res {
        let Grant::Browser(browser) = grant("app-key", &Endpoints::default()) else {
            return Err("a browser sign-in was expected".into());
        };
        assert_eq!(
            browser.authorize_url,
            "https://www.dropbox.com/oauth2/authorize"
        );
        assert_eq!(browser.token_url, "https://api.dropboxapi.com/oauth2/token");
        assert_eq!(browser.client_id, "app-key");
        assert_eq!(browser.scope, "files.metadata.read files.content.read");
        assert_eq!(
            browser.authorize_extra,
            [("token_access_type".to_owned(), "offline".to_owned())]
        );
        assert_eq!(browser.client_auth, ClientAuth::None);
        assert!(browser.pkce);
        assert_eq!(browser.port, REDIRECT_PORT);
        assert_eq!(browser.port, 53_123, "the port the app console registers");
        assert_eq!(browser.redirect_path, "/");
        assert_eq!(browser.redirect_host, "127.0.0.1");

        let store = TokenStore::new(&temp_dir("dropbox-session"));
        assert!(session(&account(), &store).is_ok());
        assert!(Dropbox::new(&account(), &store).is_ok());
        let mut other = account();
        other.sign_in = SignIn::BoxDelegated {
            client_id: "id".to_owned(),
        };
        assert!(matches!(session(&other, &store), Err(Error::Local(_))));
        assert!(matches!(Dropbox::new(&other, &store), Err(Error::Local(_))));
        Ok(())
    }
}
