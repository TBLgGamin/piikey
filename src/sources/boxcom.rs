//! The Box connector, through the Box Platform API (`https://api.box.com/2.0`).
//!
//! Box has one tree per account: the folder `0` ("All Files") holds everything. A virtual path is
//! the account's top followed by the names of the folders from that root and the item's name
//! (each spelled by [`child`]). Box has no way to address an item by its path, so a path is
//! walked down by listing each folder; the folder ids found are kept for a while and checked
//! against the path Box reports for the item at the end of a walk.
//!
//! The change feed is the user event stream (`GET /events?stream_type=changes`): its position is
//! the cursor. Box's events say where an item is *now* but never where it was, so an event that
//! moves or renames something, or that changes who may read what, is answered with a full
//! listing rather than a guess.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Component, Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::{
    Account, BoxSubject, Changes, Connector, Error, Provider, RemoteFolder, RemoteItem, Resolved,
    Result, SignIn, TokenStore,
    auth::{App, AppCredential, Browser, ClientAuth, Grant, Session},
    child, component,
    http::{Http, Request, encode, pages},
    parse_time, parse_virtual,
};
use crate::sys::{is_under, path_key, same_path};

/// The id of the folder that holds everything ("All Files").
const ROOT: &str = "0";
/// The id of the trash folder.
const TRASH: &str = "1";
/// The most items Box returns in a page of a folder.
const PAGE: &str = "1000";
/// The most events Box returns in a chunk.
const CHUNK: &str = "500";
/// What a listing asks Box for: the standard fields would be dropped as soon as `fields` is used.
const LIST_FIELDS: &str = "id,type,name,size,modified_at,sha1,etag,path_collection";
/// The same, for one file whose state is not known yet.
const FILE_FIELDS: &str = "id,type,name,size,modified_at,sha1,etag,path_collection,item_status";
/// What browsing needs.
const NAME_FIELDS: &str = "id,type,name";
/// The only scope piikey asks for: it narrows what the app is configured with.
const SCOPE: &str = "root_readonly";
/// The folders that are remembered at most.
const MAX_CACHED: usize = 10_000;

/// Where the services are: the real ones, or a test's mock.
#[derive(Debug, Clone)]
struct Endpoints {
    /// The API, without a slash at the end.
    api: String,
    /// Where a person is sent to allow piikey.
    authorize: String,
    /// Where codes and tokens are exchanged.
    token: String,
    /// Where a browser opens an item.
    web: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            api: "https://api.box.com/2.0".to_owned(),
            authorize: "https://account.box.com/api/oauth2/authorize".to_owned(),
            token: "https://api.box.com/oauth2/token".to_owned(),
            web: "https://app.box.com".to_owned(),
        }
    }
}

/// How the account gets its tokens.
fn grant(account: &Account, endpoints: &Endpoints) -> Result<Grant> {
    match &account.sign_in {
        // Box matches a loopback redirect with any port when the registered address has the same
        // scheme, host and path, so `http://127.0.0.1` is registered once. Box's authorization
        // code flow has no PKCE and its token endpoint wants the client secret in the form.
        SignIn::BoxDelegated { client_id } if account.provider == Provider::Box => {
            Ok(Grant::Browser(Browser {
                authorize_url: endpoints.authorize.clone(),
                token_url: endpoints.token.clone(),
                client_id: client_id.clone(),
                scope: SCOPE.to_owned(),
                authorize_extra: Vec::new(),
                client_auth: ClientAuth::Body,
                port: 0,
                redirect_path: String::new(),
                pkce: false,
            }))
        }
        SignIn::BoxApp { client_id, subject } if account.provider == Provider::Box => {
            let (kind, id) = match subject {
                BoxSubject::Enterprise(id) => ("enterprise", id),
                BoxSubject::User(id) => ("user", id),
            };
            Ok(Grant::App(App {
                token_url: endpoints.token.clone(),
                client_id: client_id.clone(),
                scope: None,
                credential: AppCredential::Secret(ClientAuth::Body),
                extra: vec![
                    ("box_subject_type".to_owned(), kind.to_owned()),
                    ("box_subject_id".to_owned(), id.clone()),
                ],
            }))
        }
        _ => Err(Error::Local(crate::Error::BadRequest(
            "That account does not sign in to Box this way.".to_owned(),
        ))),
    }
}

fn session_with(
    account: &Account,
    tokens: &TokenStore,
    http: Http,
    endpoints: &Endpoints,
) -> Result<Session> {
    let grant = grant(account, endpoints)?;
    Ok(Session::new(http, tokens.clone(), &account.id, grant))
}

/// The session that signs the account in.
///
/// # Errors
/// `BadRequest` when the account is not a Box account.
pub(crate) fn session(account: &Account, tokens: &TokenStore) -> Result<Session> {
    session_with(
        account,
        tokens,
        Http::new(Provider::Box),
        &Endpoints::default(),
    )
}

/// A connected Box account.
#[derive(Debug)]
pub(crate) struct BoxCom {
    account: Account,
    session: Session,
    endpoints: Endpoints,
    /// The id of folders walked down to, by virtual path: saves listing them again. Dropped
    /// whole when it is shown wrong.
    folders: Mutex<HashMap<String, String>>,
}

impl BoxCom {
    /// For a connected account, talking to the real service.
    ///
    /// # Errors
    /// `BadRequest` when the account is not a Box account.
    pub(crate) fn new(account: &Account, tokens: &TokenStore) -> Result<Self> {
        Self::with(
            account,
            tokens,
            Http::new(Provider::Box),
            Endpoints::default(),
        )
    }

    fn with(
        account: &Account,
        tokens: &TokenStore,
        http: Http,
        endpoints: Endpoints,
    ) -> Result<Self> {
        Ok(Self {
            session: session_with(account, tokens, http, &endpoints)?,
            account: account.clone(),
            endpoints,
            folders: Mutex::new(HashMap::new()),
        })
    }

    fn get(&self, path: &str) -> Request {
        Request::get(format!("{}{path}", self.endpoints.api))
    }

    fn url(&self, kind: &str, id: &str) -> String {
        format!("{}/{kind}/{id}", self.endpoints.web)
    }

    fn folder_at(&self, id: &str, path: PathBuf) -> RemoteFolder {
        RemoteFolder {
            id: id.to_owned(),
            path,
            web_url: self.url("folder", id),
        }
    }

    /// The whole account.
    fn top(&self) -> RemoteFolder {
        self.folder_at(ROOT, self.account.root())
    }

    fn item(&self, entry: &Entry, path: PathBuf) -> RemoteItem {
        let content = entry.sha1.as_deref().filter(|sha| !sha.is_empty());
        RemoteItem {
            id: entry.id.clone(),
            path,
            size: entry.size.unwrap_or(0),
            modified: entry
                .modified_at
                .as_deref()
                .and_then(parse_time)
                .unwrap_or(SystemTime::UNIX_EPOCH),
            version: content
                .or(entry.etag.as_deref())
                .unwrap_or_default()
                .to_owned(),
            web_url: self.url("file", &entry.id),
            export: None,
        }
    }

    fn items_request(&self, folder: &str, fields: &str, marker: Option<&str>) -> Request {
        let request = self
            .get(&format!("/folders/{}/items", encode(folder)))
            .query("fields", fields)
            .query("limit", PAGE)
            .query("usemarker", "true");
        match marker {
            Some(marker) => request.query("marker", marker),
            None => request,
        }
    }

    /// Hands each item of the folder `folder` to `each`, page after page, until it says `false`.
    fn list(
        &self,
        folder: &str,
        fields: &str,
        cancel: &AtomicBool,
        mut each: impl FnMut(Entry) -> bool,
    ) -> Result<()> {
        pages(
            Provider::Box,
            cancel,
            self.items_request(folder, fields, None),
            &|request| self.session.send(request),
            |reply| {
                let page: Page = reply.ok()?.json()?;
                for entry in page.entries {
                    if !each(entry) {
                        return Ok(None);
                    }
                }
                Ok(page
                    .next_marker
                    .filter(|marker| !marker.is_empty())
                    .map(|marker| self.items_request(folder, fields, Some(&marker))))
            },
        )
    }

    fn remember(&self, path: &Path, id: &str) {
        if let Ok(mut cache) = self.folders.lock() {
            if cache.len() >= MAX_CACHED {
                cache.clear();
            }
            cache.insert(path_key(path), id.to_owned());
        }
    }

    fn forget(&self) {
        if let Ok(mut cache) = self.folders.lock() {
            cache.clear();
        }
    }

    /// The deepest folder above the item at `parts` that is remembered: how far down it is and
    /// its id.
    fn cached(&self, parts: &[String]) -> Option<(usize, String)> {
        let cache = self.folders.lock().ok()?;
        (1..parts.len()).rev().find_map(|depth| {
            let path = parts[..depth]
                .iter()
                .fold(self.account.root(), |path, part| path.join(part));
            cache.get(&path_key(&path)).map(|id| (depth, id.clone()))
        })
    }

    /// The names of a virtual path of this account below its top.
    fn parts(&self, path: &Path) -> Result<Vec<String>> {
        let missing = || Error::not_found(Provider::Box, "the path is not in this account");
        let inside = parse_virtual(path)
            .filter(|found| {
                found.provider == Provider::Box
                    && found.label.to_lowercase() == self.account.label.to_lowercase()
            })
            .ok_or_else(missing)?;
        inside
            .rest
            .components()
            .map(|part| match part {
                Component::Normal(name) => Ok(name.to_string_lossy().into_owned()),
                _ => Err(missing()),
            })
            .collect()
    }

    /// The virtual path of the folders in `collection`, below the account's top.
    fn collection_path(&self, collection: &PathCollection) -> Option<PathBuf> {
        let mut entries = collection.entries.iter();
        if entries.next()?.id != ROOT {
            return None;
        }
        Some(entries.fold(self.account.root(), |path, folder| {
            child(&path, &folder.name)
        }))
    }

    /// Where Box says `entry` is.
    fn path_of(&self, entry: &Entry) -> Option<PathBuf> {
        let parent = self.collection_path(entry.path_collection.as_ref()?)?;
        Some(child(&parent, &entry.name))
    }

    /// Walks down from the folder `start`, which is `depth` names down, to the item at `parts`.
    /// With it comes the path Box reports for the item, to check a folder that was remembered.
    fn descend(
        &self,
        start: &str,
        depth: usize,
        parts: &[String],
    ) -> Result<(Resolved, Option<PathBuf>)> {
        let never = AtomicBool::new(false);
        let mut id = start.to_owned();
        let mut here = parts[..depth]
            .iter()
            .fold(self.account.root(), |path, part| path.join(part));
        for (at, part) in parts.iter().enumerate().skip(depth) {
            let last = at + 1 == parts.len();
            let want = part.to_lowercase();
            let mut found = None;
            self.list(&id, LIST_FIELDS, &never, |entry| {
                let fits = component(&entry.name).to_lowercase() == want
                    && (entry.kind == "folder" || (last && entry.kind == "file"));
                if fits {
                    found = Some(entry);
                }
                !fits
            })?;
            let Some(entry) = found else {
                break;
            };
            here = child(&here, &entry.name);
            if entry.kind == "folder" {
                self.remember(&here, &entry.id);
            }
            if last {
                let actual = self.path_of(&entry);
                // What was typed may differ in letter case: the path is Box's spelling.
                if let Some(actual) = &actual {
                    here.clone_from(actual);
                }
                let resolved = if entry.kind == "folder" {
                    Resolved::Folder(self.folder_at(&entry.id, here))
                } else {
                    Resolved::File(self.item(&entry, here))
                };
                return Ok((resolved, actual));
            }
            id = entry.id;
        }
        Err(Error::not_found(Provider::Box, "no such folder or file"))
    }

    /// The current stream position: what to ask for next time.
    fn position(&self) -> Result<String> {
        let request = self
            .get("/events")
            .query("stream_type", "changes")
            .query("stream_position", "now");
        let feed: Feed = self.session.send(&request)?.ok()?.json()?;
        if feed.next_stream_position.is_empty() {
            return Err(Error::unexpected(
                Provider::Box,
                "the service gave no stream position",
            ));
        }
        Ok(feed.next_stream_position)
    }

    /// Every file under `root`, with the position taken first so nothing is lost.
    fn full(&self, root: &RemoteFolder, cancel: &AtomicBool) -> Result<Changes> {
        let cursor = self.position()?;
        let items = self.walk(root, cancel)?;
        Ok(Changes {
            items,
            removed: Vec::new(),
            cursor,
            full: true,
        })
    }

    /// Every file in `root` and below.
    fn walk(&self, root: &RemoteFolder, cancel: &AtomicBool) -> Result<Vec<RemoteItem>> {
        let mut items = Vec::new();
        let mut known = HashSet::new();
        let mut folders = vec![(root.id.clone(), root.path.clone())];
        let mut first = true;
        while let Some((id, path)) = folders.pop() {
            let mut found = Vec::new();
            let listed = self.list(&id, LIST_FIELDS, cancel, |entry| {
                match entry.kind.as_str() {
                    "file" => {
                        let at = child(&path, &entry.name);
                        if known.insert(path_key(&at)) {
                            items.push(self.item(&entry, at));
                        }
                    }
                    "folder" => found.push((entry.id.clone(), child(&path, &entry.name))),
                    _ => {}
                }
                true
            });
            match listed {
                // A folder that went while the walk ran is gone from the listing too.
                Err(Error::NotFound { .. }) if !first => {}
                other => other?,
            }
            first = false;
            folders.extend(found);
        }
        Ok(items)
    }

    /// What changed since `position`; `None` when Box no longer knows the position or a change
    /// cannot be told from the events (the caller lists everything instead).
    fn incremental(
        &self,
        root: &RemoteFolder,
        position: &str,
        cancel: &AtomicBool,
    ) -> Result<Option<Changes>> {
        let events_from = |position: &str| {
            self.get("/events")
                .query("stream_type", "changes")
                .query("stream_position", position)
                .query("limit", CHUNK)
        };
        let mut events = Vec::new();
        let mut at = position.to_owned();
        let mut rejected = false;
        pages(
            Provider::Box,
            cancel,
            events_from(position),
            &|request| self.session.send(request),
            |reply| {
                if matches!(reply.status, 400 | 410) {
                    rejected = true;
                    return Ok(None);
                }
                let feed: Feed = reply.ok()?.json()?;
                let sent = std::mem::replace(&mut at, feed.next_stream_position.clone());
                let more = feed.chunk_size > 0
                    && !feed.entries.is_empty()
                    && !feed.next_stream_position.is_empty()
                    && feed.next_stream_position != sent;
                if feed.next_stream_position.is_empty() {
                    at = sent;
                }
                events.extend(feed.entries);
                Ok(more.then(|| events_from(&at)))
            },
        )?;
        if rejected {
            return Ok(None);
        }
        let Some(delta) = self.replay(root, events, cancel)? else {
            return Ok(None);
        };
        Ok(Some(Changes {
            items: delta.items.into_values().collect(),
            removed: delta.removed.into_values().collect(),
            cursor: at,
            full: false,
        }))
    }

    /// The events, in the order they happened and each once, added up. `None` when one of them
    /// cannot be placed.
    fn replay(
        &self,
        root: &RemoteFolder,
        mut events: Vec<Event>,
        cancel: &AtomicBool,
    ) -> Result<Option<Delta>> {
        let time = |event: &Event| event.created_at.as_deref().and_then(parse_time);
        // The feed may repeat and reorder events; the times say what came last.
        if events.iter().all(|event| time(event).is_some()) {
            events.sort_by_key(time);
        }
        let mut seen = HashSet::new();
        let mut run = Replay {
            root,
            cancel,
            delta: Delta::default(),
            parents: HashMap::new(),
        };
        for event in events {
            if !event.id.is_empty() && !seen.insert(event.id.clone()) {
                continue;
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let act = Act::of(&event.kind);
            match act {
                Act::Ignore => continue,
                Act::Resync => return Ok(None),
                Act::Appear | Act::Vanish => {}
            }
            let Some(source) = event
                .source
                .and_then(|source| serde_json::from_value::<Entry>(source).ok())
            else {
                return Ok(None);
            };
            if !self.apply(&mut run, &event.kind, act, &source)? {
                return Ok(None);
            }
        }
        Ok(Some(run.delta))
    }

    /// Adds one event to the changes; `false` when it cannot be placed.
    fn apply(
        &self,
        run: &mut Replay<'_>,
        event_type: &str,
        act: Act,
        source: &Entry,
    ) -> Result<bool> {
        let folder = match source.kind.as_str() {
            "file" => false,
            "folder" => true,
            _ => return Ok(true),
        };
        let restored = matches!(event_type, "ITEM_COPY" | "ITEM_UNDELETE_VIA_TRASH");
        if folder && matches!(act, Act::Appear) && !restored {
            // A folder that is new is empty: its files come with their own events.
            return Ok(true);
        }
        let Some(path) = self.locate(source, &mut run.parents)? else {
            return Ok(false);
        };
        let root = &run.root.path;
        let inside = is_under(&path, root);
        match act {
            Act::Vanish => {
                if inside {
                    run.delta.remove(path);
                } else if is_under(root, &path) {
                    // Something above the root went, and the root with it.
                    run.delta.remove(root.clone());
                }
                Ok(true)
            }
            Act::Appear if folder => {
                if !inside {
                    // A folder above the root that is back brings the root's files back.
                    return Ok(!(event_type == "ITEM_UNDELETE_VIA_TRASH" && is_under(root, &path)));
                }
                let top = self.folder_at(&source.id, path);
                let items = match self.walk(&top, run.cancel) {
                    Ok(items) => items,
                    Err(Error::NotFound { .. }) => Vec::new(),
                    Err(error) => return Err(error),
                };
                Ok(items.into_iter().all(|item| run.delta.add(item)))
            }
            Act::Appear if inside => self.appear(run, source, path),
            Act::Appear | Act::Ignore | Act::Resync => Ok(true),
        }
    }

    /// A file that is new or has new contents.
    fn appear(&self, run: &mut Replay<'_>, source: &Entry, path: PathBuf) -> Result<bool> {
        let fetched;
        let entry = if source.is_complete() {
            source
        } else {
            let request = self
                .get(&format!("/files/{}", encode(&source.id)))
                .query("fields", FILE_FIELDS);
            let reply = self.session.send(&request)?;
            if reply.status == 404 {
                run.delta.remove(path);
                return Ok(true);
            }
            fetched = reply.ok()?.json::<Entry>()?;
            &fetched
        };
        if entry.is_gone() {
            // In the trash: the event that put it there takes it out.
            return Ok(true);
        }
        Ok(run.delta.add(self.item(entry, path)))
    }

    /// The virtual path an event's item has, from the path Box reports for it or, for something
    /// in the trash, from the folder it was in. `None` when it cannot be told.
    fn locate(
        &self,
        source: &Entry,
        parents: &mut HashMap<String, Option<PathBuf>>,
    ) -> Result<Option<PathBuf>> {
        if let Some(collection) = &source.path_collection
            && collection.entries.iter().all(|folder| folder.id != TRASH)
            && let Some(parent) = self.collection_path(collection)
        {
            return Ok(Some(child(&parent, &source.name)));
        }
        let Some(parent) = &source.parent else {
            return Ok(None);
        };
        Ok(self
            .folder_path(&parent.id, parents)?
            .map(|path| child(&path, &source.name)))
    }

    /// The virtual path of the folder `id`; `None` when it is gone or in the trash.
    fn folder_path(
        &self,
        id: &str,
        parents: &mut HashMap<String, Option<PathBuf>>,
    ) -> Result<Option<PathBuf>> {
        if id == ROOT {
            return Ok(Some(self.account.root()));
        }
        if id == TRASH {
            return Ok(None);
        }
        if let Some(path) = parents.get(id) {
            return Ok(path.clone());
        }
        let request = self
            .get(&format!("/folders/{}", encode(id)))
            .query("fields", "id,type,name,path_collection,item_status");
        let reply = self.session.send(&request)?;
        let path = if reply.status == 404 {
            None
        } else {
            let folder: Entry = reply.ok()?.json()?;
            if folder.is_gone() {
                None
            } else {
                self.path_of(&folder)
            }
        };
        parents.insert(id.to_owned(), path.clone());
        Ok(path)
    }
}

impl Connector for BoxCom {
    fn provider(&self) -> Provider {
        Provider::Box
    }

    fn browse(&self, under: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>> {
        let (id, base) = match under {
            Some(folder) => (folder.id.clone(), folder.path.clone()),
            None => (ROOT.to_owned(), self.account.root()),
        };
        let mut folders = Vec::new();
        self.list(&id, NAME_FIELDS, &AtomicBool::new(false), |entry| {
            if entry.kind == "folder" {
                let path = child(&base, &entry.name);
                self.remember(&path, &entry.id);
                folders.push((entry.name.to_lowercase(), self.folder_at(&entry.id, path)));
            }
            true
        })?;
        folders.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(folders.into_iter().map(|(_, folder)| folder).collect())
    }

    fn resolve(&self, path: &Path) -> Result<Resolved> {
        let parts = self.parts(path)?;
        if parts.is_empty() {
            return Ok(Resolved::Folder(self.top()));
        }
        if let Some((depth, id)) = self.cached(&parts) {
            let wanted = parts
                .iter()
                .fold(self.account.root(), |path, part| path.join(part));
            match self.descend(&id, depth, &parts) {
                Ok((found, actual))
                    if actual
                        .as_deref()
                        .is_some_and(|actual| same_path(actual, &wanted)) =>
                {
                    return Ok(found);
                }
                // A remembered folder that is not where it was: look again from the top.
                Ok(_) | Err(Error::NotFound { .. }) => self.forget(),
                Err(error) => return Err(error),
            }
        }
        Ok(self.descend(ROOT, 0, &parts)?.0)
    }

    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<Changes> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if let Some(cursor) = cursor
            && let Some(changes) = self.incremental(root, cursor, cancel)?
        {
            return Ok(changes);
        }
        self.full(root, cancel)
    }

    fn download(&self, item: &RemoteItem, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>> {
        if item.size > max {
            return Err(Error::TooLarge);
        }
        let request = self.get(&format!("/files/{}/content", encode(&item.id)));
        let reply = self.session.download(&request, max, cancel)?;
        match reply.status {
            202 => Err(Error::throttled(
                Provider::Box,
                reply.retry_after(),
                "the file is not ready to be downloaded yet",
            )),
            200 => Ok(reply.body),
            _ => Err(reply.error()),
        }
    }
}

/// What an event does to the files.
#[derive(Debug, Clone, Copy)]
enum Act {
    /// Nothing that changes the files (a lock, a preview, a role).
    Ignore,
    /// Something is new or has new contents.
    Appear,
    /// Something is in the trash or gone.
    Vanish,
    /// Box does not say enough to tell what changed: list everything.
    Resync,
}

impl Act {
    fn of(event_type: &str) -> Self {
        match event_type {
            "ITEM_CREATE" | "ITEM_UPLOAD" | "ITEM_COPY" | "ITEM_UNDELETE_VIA_TRASH"
            | "ITEM_MAKE_CURRENT_VERSION" => Self::Appear,
            "ITEM_TRASH" | "ITEM_DELETE" => Self::Vanish,
            // The event has the new place only, not the old one that has to be forgotten.
            "ITEM_MOVE" | "ITEM_RENAME"
            // Who may read what changed: a whole folder may have appeared or gone.
            | "COLLAB_ADD_COLLABORATOR" | "COLLAB_REMOVE_COLLABORATOR" | "GROUP_ADD_USER"
            | "GROUP_REMOVE_USER" => Self::Resync,
            _ => Self::Ignore,
        }
    }
}

/// The changes a feed of events adds up to; a later event wins.
#[derive(Debug, Default)]
struct Delta {
    items: BTreeMap<String, RemoteItem>,
    removed: BTreeMap<String, PathBuf>,
}

impl Delta {
    /// A file is new or changed. `false` when a folder above it was removed before, which the
    /// events cannot square with it being back.
    fn add(&mut self, item: RemoteItem) -> bool {
        let key = path_key(&item.path);
        if self
            .removed
            .values()
            .any(|path| is_under(&item.path, path) && !same_path(&item.path, path))
        {
            return false;
        }
        self.removed.remove(&key);
        self.items.insert(key, item);
        true
    }

    /// `path` and what is below it are gone.
    fn remove(&mut self, path: PathBuf) {
        self.items.retain(|_, item| !is_under(&item.path, &path));
        self.removed.insert(path_key(&path), path);
    }
}

/// What replaying a feed of events keeps track of.
struct Replay<'a> {
    root: &'a RemoteFolder,
    cancel: &'a AtomicBool,
    delta: Delta,
    /// The path of each folder asked about, for an item that is in the trash.
    parents: HashMap<String, Option<PathBuf>>,
}

/// A number or text: Box writes ids both ways.
#[derive(Deserialize)]
#[serde(untagged)]
enum Text {
    Text(String),
    Number(serde_json::Number),
}

fn opt_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    Ok(
        Option::<Text>::deserialize(deserializer)?.map(|text| match text {
            Text::Text(text) => text,
            Text::Number(number) => number.to_string(),
        }),
    )
}

fn text<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<String, D::Error> {
    Ok(opt_text(deserializer)?.unwrap_or_default())
}

/// A folder in a path or a parent.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Mini {
    #[serde(deserialize_with = "text")]
    id: String,
    name: String,
}

/// The folders above an item, the first being "All Files".
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PathCollection {
    entries: Vec<Mini>,
}

/// A file or a folder, as Box lists it or as an event's source.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Entry {
    #[serde(rename = "type", alias = "item_type")]
    kind: String,
    #[serde(deserialize_with = "text", alias = "item_id")]
    id: String,
    #[serde(alias = "item_name")]
    name: String,
    size: Option<u64>,
    modified_at: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    sha1: Option<String>,
    #[serde(deserialize_with = "opt_text")]
    etag: Option<String>,
    path_collection: Option<PathCollection>,
    parent: Option<Mini>,
    item_status: Option<String>,
}

impl Entry {
    /// Whether it is in the trash or deleted.
    fn is_gone(&self) -> bool {
        matches!(self.item_status.as_deref(), Some("trashed" | "deleted"))
    }

    /// Whether it says all a listing would.
    fn is_complete(&self) -> bool {
        self.size.is_some()
            && self.modified_at.is_some()
            && (self.sha1.is_some() || self.etag.is_some())
    }
}

/// A page of a folder's items.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Page {
    entries: Vec<Entry>,
    next_marker: Option<String>,
}

/// A chunk of the event stream.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Feed {
    entries: Vec<Event>,
    chunk_size: u64,
    #[serde(deserialize_with = "text")]
    next_stream_position: String,
}

/// One event.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Event {
    #[serde(rename = "event_id")]
    id: String,
    #[serde(rename = "event_type")]
    kind: String,
    created_at: Option<String>,
    source: Option<Value>,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        sources::{
            Secrets,
            testing::{Answer, Mock, Res, Seen},
        },
        testing::temp_dir,
    };

    /// An access token that is good for centuries.
    const FAR: u64 = 32_503_680_000;

    fn account(sign_in: SignIn) -> Account {
        Account {
            id: "0123456789abcdef".to_owned(),
            provider: Provider::Box,
            label: "acme".to_owned(),
            sign_in,
        }
    }

    fn delegated() -> Account {
        account(SignIn::BoxDelegated {
            client_id: "cid".to_owned(),
        })
    }

    fn endpoints(base: &str) -> Endpoints {
        Endpoints {
            api: format!("{base}/2.0"),
            authorize: format!("{base}/authorize"),
            token: format!("{base}/token"),
            web: "https://app.box.com".to_owned(),
        }
    }

    struct Rig {
        mock: Mock,
        connector: BoxCom,
        store: TokenStore,
        account: Account,
        pauses: Arc<Mutex<Vec<Duration>>>,
    }

    impl Rig {
        fn new(handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Res<Self> {
            let secrets = Secrets::default()
                .with_client_secret("shh")
                .with_refresh_token("r1")
                .with_access_token("tok1", FAR);
            Self::with_secrets(handler, &secrets)
        }

        fn with_secrets(
            handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static,
            secrets: &Secrets,
        ) -> Res<Self> {
            let mock = Mock::start(handler)?;
            let account = delegated();
            let store = TokenStore::new(&temp_dir("box"));
            store.save(&account.id, secrets)?;
            let pauses = Arc::new(Mutex::new(Vec::new()));
            let http = Http::with_pause(Provider::Box, {
                let pauses = Arc::clone(&pauses);
                move |wait| {
                    if let Ok(mut pauses) = pauses.lock() {
                        pauses.push(wait);
                    }
                }
            });
            let connector = BoxCom::with(&account, &store, http, endpoints(&mock.url()))?;
            Ok(Self {
                mock,
                connector,
                store,
                account,
                pauses,
            })
        }

        /// The whole account.
        fn top(&self) -> RemoteFolder {
            self.connector.top()
        }

        /// A folder of the account, by id and virtual path.
        fn folder(&self, id: &str, names: &[&str]) -> RemoteFolder {
            let path = names
                .iter()
                .fold(self.account.root(), |path, name| child(&path, name));
            self.connector.folder_at(id, path)
        }

        fn path(&self, names: &[&str]) -> PathBuf {
            names
                .iter()
                .fold(self.account.root(), |path, name| child(&path, name))
        }

        fn waits(&self) -> Vec<Duration> {
            self.pauses
                .lock()
                .map(|pauses| pauses.clone())
                .unwrap_or_default()
        }
    }

    fn collection(parents: &[(&str, &str)]) -> Value {
        let mut entries = vec![json!({"type": "folder", "id": "0", "name": "All Files"})];
        entries.extend(
            parents
                .iter()
                .map(|(id, name)| json!({"type": "folder", "id": id, "name": name})),
        );
        json!({"total_count": entries.len(), "entries": entries})
    }

    fn file(id: &str, name: &str, size: u64, sha: &str, parents: &[(&str, &str)]) -> Value {
        json!({
            "type": "file", "id": id, "name": name, "size": size, "sha1": sha, "etag": "3",
            "modified_at": "2024-03-05T10:00:00-08:00",
            "path_collection": collection(parents),
        })
    }

    fn folder(id: &str, name: &str, parents: &[(&str, &str)]) -> Value {
        json!({
            "type": "folder", "id": id, "name": name, "etag": "0",
            "path_collection": collection(parents),
        })
    }

    fn page(entries: &[Value], next: Option<&str>) -> Answer {
        Answer::json(
            200,
            &json!({"entries": entries, "limit": 1000, "next_marker": next}),
        )
    }

    fn feed(entries: &[Value], next: &str) -> Answer {
        Answer::json(
            200,
            &json!({"chunk_size": entries.len(), "next_stream_position": next, "entries": entries}),
        )
    }

    fn event(id: &str, kind: &str, source: Value) -> Value {
        let mut event = json!({"type": "event", "event_id": id, "event_type": kind});
        event["source"] = source;
        event
    }

    fn stamped(id: &str, kind: &str, at: &str, source: Value) -> Value {
        let mut event = event(id, kind, source);
        event["created_at"] = json!(at);
        event
    }

    fn position(seen: &Seen) -> String {
        seen.param("stream_position").unwrap_or_default()
    }

    fn sorted(items: &[RemoteItem]) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = items.iter().map(|item| item.path.clone()).collect();
        paths.sort();
        paths
    }

    #[test]
    fn listing_follows_next_marker_over_three_pages_and_keeps_only_files() -> Res {
        let rig = Rig::new(
            |seen| match (seen.path(), seen.param("marker").as_deref()) {
                ("/2.0/events", _) => feed(&[], "100"),
                ("/2.0/folders/0/items", None) => {
                    page(&[file("1", "a.txt", 5, "aa", &[])], Some("m1"))
                }
                ("/2.0/folders/0/items", Some("m1")) => page(
                    &[
                        folder("10", "Docs", &[]),
                        file("2", "b:c.txt", 6, "bb", &[]),
                    ],
                    Some("m2"),
                ),
                ("/2.0/folders/0/items", Some("m2")) => {
                    page(&[file("3", "c.txt", 7, "cc", &[])], None)
                }
                ("/2.0/folders/10/items", _) => {
                    page(&[file("4", "d.txt", 8, "dd", &[("10", "Docs")])], Some(""))
                }
                _ => Answer::empty(404),
            },
        )?;
        let changes = rig
            .connector
            .changes(&rig.top(), None, &AtomicBool::new(false))?;
        assert!(changes.full);
        assert_eq!(changes.cursor, "100");
        assert!(changes.removed.is_empty());
        assert_eq!(
            sorted(&changes.items),
            vec![
                rig.path(&["Docs", "d.txt"]),
                rig.path(&["a.txt"]),
                rig.path(&["b:c.txt"]),
                rig.path(&["c.txt"]),
            ]
        );
        let mapped = changes
            .items
            .iter()
            .find(|item| item.id == "2")
            .ok_or("b:c.txt missing")?;
        assert!(mapped.path.ends_with("b：c.txt"));
        assert_eq!(mapped.version, "bb");
        assert_eq!(mapped.size, 6);
        assert_eq!(mapped.web_url, "https://app.box.com/file/2");

        let seen = rig.mock.seen();
        // The position is taken before the listing starts.
        assert_eq!(seen[0].path(), "/2.0/events");
        assert_eq!(seen[0].param("stream_type").as_deref(), Some("changes"));
        assert_eq!(seen[0].param("stream_position").as_deref(), Some("now"));
        let listing = rig.mock.seen_at("/2.0/folders/0/items");
        let markers: Vec<_> = listing.iter().map(|call| call.param("marker")).collect();
        assert_eq!(
            markers,
            [None, Some("m1".to_owned()), Some("m2".to_owned())]
        );
        assert_eq!(listing[0].param("usemarker").as_deref(), Some("true"));
        assert_eq!(listing[0].param("limit").as_deref(), Some("1000"));
        let fields = listing[0].param("fields").ok_or("no fields")?;
        for want in ["sha1", "etag", "path_collection", "modified_at", "size"] {
            assert!(fields.split(',').any(|field| field == want), "{want}");
        }
        assert_eq!(listing[0].header("authorization"), Some("Bearer tok1"));
        Ok(())
    }

    #[test]
    fn events_resume_from_the_stored_position_and_add_up() -> Res {
        let rig = Rig::new(|seen| match (seen.path(), position(seen).as_str()) {
            ("/2.0/events", "now") => feed(&[], "100"),
            ("/2.0/events", "100") => {
                let docs = [("10", "Docs")];
                let upload = event("e1", "ITEM_UPLOAD", file("5", "new.txt", 12, "n1", &docs));
                feed(
                    &[
                        upload.clone(),
                        // The feed may say the same thing twice.
                        upload,
                        event("e2", "ITEM_TRASH", file("7", "gone.txt", 3, "g1", &docs)),
                        event("e3", "ITEM_TRASH", folder("20", "Old", &[])),
                        // A source without the size and the hash is asked for again.
                        event(
                            "e4",
                            "ITEM_CREATE",
                            json!({"type": "file", "id": "6", "name": "bare.txt",
                                   "path_collection": collection(&docs)}),
                        ),
                        event("e5", "LOCK_CREATE", file("8", "locked.txt", 1, "l1", &docs)),
                        event("e6", "ITEM_PREVIEW", file("9", "seen.txt", 1, "p1", &docs)),
                    ],
                    "101",
                )
            }
            ("/2.0/events", "101") => feed(&[], "101"),
            ("/2.0/files/6", _) => {
                Answer::json(200, &file("6", "bare.txt", 20, "b6", &[("10", "Docs")]))
            }
            ("/2.0/folders/0/items", _) => page(&[], None),
            _ => Answer::empty(404),
        })?;
        let cancel = AtomicBool::new(false);
        let first = rig.connector.changes(&rig.top(), None, &cancel)?;
        assert!(first.full);
        assert_eq!(first.cursor, "100");

        let second = rig
            .connector
            .changes(&rig.top(), Some(&first.cursor), &cancel)?;
        assert!(!second.full);
        assert_eq!(second.cursor, "101");
        assert_eq!(
            sorted(&second.items),
            vec![
                rig.path(&["Docs", "bare.txt"]),
                rig.path(&["Docs", "new.txt"])
            ]
        );
        let added = second
            .items
            .iter()
            .find(|item| item.id == "5")
            .ok_or("new.txt missing")?;
        assert_eq!((added.size, added.version.as_str()), (12, "n1"));
        let mut removed = second.removed.clone();
        removed.sort();
        assert_eq!(
            removed,
            vec![rig.path(&["Docs", "gone.txt"]), rig.path(&["Old"])]
        );

        let calls = rig.mock.seen_at("/2.0/events");
        // now, then the stored position, then the position the chunk named.
        let sent: Vec<_> = calls.iter().map(position).collect();
        assert_eq!(sent, ["now", "100", "101"]);
        assert_eq!(calls[1].param("stream_type").as_deref(), Some("changes"));
        assert_eq!(calls[1].param("limit").as_deref(), Some("500"));
        let again = rig.mock.seen_at("/2.0/files/6");
        assert_eq!(again.len(), 1);
        assert!(
            again[0]
                .param("fields")
                .ok_or("no fields")?
                .contains("sha1")
        );
        Ok(())
    }

    #[test]
    fn a_trashed_item_is_placed_by_the_folder_it_was_in() -> Res {
        let rig = Rig::new(|seen| match (seen.path(), position(seen).as_str()) {
            ("/2.0/events", "5") => feed(
                &[event(
                    "t1",
                    "ITEM_TRASH",
                    json!({"type": "file", "id": "7", "name": "gone.txt",
                           "item_status": "trashed",
                           "parent": {"type": "folder", "id": "10", "name": "Docs"},
                           "path_collection": {"total_count": 2, "entries": [
                               {"type": "folder", "id": "0", "name": "All Files"},
                               {"type": "folder", "id": "1", "name": "Trash"}]}}),
                )],
                "6",
            ),
            ("/2.0/events", _) => feed(&[], "6"),
            ("/2.0/folders/10", _) => Answer::json(200, &folder("10", "Docs", &[])),
            _ => Answer::empty(404),
        })?;
        let changes = rig
            .connector
            .changes(&rig.top(), Some("5"), &AtomicBool::new(false))?;
        assert!(!changes.full);
        assert_eq!(changes.removed, vec![rig.path(&["Docs", "gone.txt"])]);
        assert_eq!(rig.mock.seen_at("/2.0/folders/10").len(), 1);
        Ok(())
    }

    #[test]
    fn a_moved_or_renamed_item_gives_a_full_listing_with_its_new_place() -> Res {
        for kind in ["ITEM_MOVE", "ITEM_RENAME"] {
            let rig = Rig::new(move |seen| match (seen.path(), position(seen).as_str()) {
                ("/2.0/events", "now") => feed(&[], "200"),
                ("/2.0/events", _) => feed(
                    &[event(
                        "m1",
                        kind,
                        file("1", "moved.txt", 5, "aa", &[("11", "New")]),
                    )],
                    "150",
                ),
                ("/2.0/folders/0/items", _) => page(&[folder("11", "New", &[])], None),
                ("/2.0/folders/11/items", _) => {
                    page(&[file("1", "moved.txt", 5, "aa", &[("11", "New")])], None)
                }
                _ => Answer::empty(404),
            })?;
            let changes =
                rig.connector
                    .changes(&rig.top(), Some("100"), &AtomicBool::new(false))?;
            // The event has no old place, so what the inventory holds there is left to the scan.
            assert!(changes.full, "{kind}");
            assert_eq!(changes.cursor, "200");
            assert_eq!(
                sorted(&changes.items),
                vec![rig.path(&["New", "moved.txt"])]
            );
        }
        Ok(())
    }

    #[test]
    fn events_outside_the_root_are_ignored() -> Res {
        let rig = Rig::new(|seen| match (seen.path(), position(seen).as_str()) {
            ("/2.0/events", "5") => {
                let docs = [("10", "Docs")];
                let other = [("20", "Other")];
                feed(
                    &[
                        event("o1", "ITEM_UPLOAD", file("1", "out.txt", 1, "x", &other)),
                        event("o2", "ITEM_TRASH", file("2", "out2.txt", 1, "y", &other)),
                        event("o3", "ITEM_UPLOAD", file("3", "in.txt", 1, "z", &docs)),
                    ],
                    "6",
                )
            }
            ("/2.0/events", _) => feed(&[], "6"),
            _ => Answer::empty(404),
        })?;
        let root = rig.folder("10", &["Docs"]);
        let changes = rig
            .connector
            .changes(&root, Some("5"), &AtomicBool::new(false))?;
        assert!(!changes.full);
        assert_eq!(sorted(&changes.items), vec![rig.path(&["Docs", "in.txt"])]);
        assert!(changes.removed.is_empty());
        Ok(())
    }

    #[test]
    fn a_position_box_rejects_is_a_full_listing() -> Res {
        for status in [400_u16, 410] {
            let rig = Rig::new(move |seen| match (seen.path(), position(seen).as_str()) {
                ("/2.0/events", "now") => feed(&[], "300"),
                ("/2.0/events", _) => Answer::json(
                    status,
                    &json!({"type": "error", "status": status, "code": "invalid_stream_position"}),
                ),
                ("/2.0/folders/0/items", _) => page(&[file("1", "a.txt", 5, "aa", &[])], None),
                _ => Answer::empty(404),
            })?;
            let changes = rig
                .connector
                .changes(&rig.top(), Some("1"), &AtomicBool::new(false))?;
            assert!(changes.full, "{status}");
            assert_eq!(changes.cursor, "300");
            assert_eq!(changes.items.len(), 1);
            assert_eq!(
                rig.mock.seen_at("/2.0/events")[0]
                    .param("stream_position")
                    .as_deref(),
                Some("1")
            );
        }
        Ok(())
    }

    #[test]
    fn events_are_replayed_in_the_order_they_happened() -> Res {
        let rig = Rig::new(|seen| match (seen.path(), position(seen).as_str()) {
            ("/2.0/events", "5") => {
                let docs = [("10", "Docs")];
                let same = file("1", "a.txt", 5, "aa", &docs);
                // The feed lists the trash first, but the upload came before it.
                feed(
                    &[
                        stamped("a", "ITEM_TRASH", "2024-03-05T10:00:05Z", same.clone()),
                        stamped("b", "ITEM_UPLOAD", "2024-03-05T10:00:01Z", same),
                    ],
                    "6",
                )
            }
            ("/2.0/events", _) => feed(&[], "6"),
            _ => Answer::empty(404),
        })?;
        let changes = rig
            .connector
            .changes(&rig.top(), Some("5"), &AtomicBool::new(false))?;
        assert!(changes.items.is_empty());
        assert_eq!(changes.removed, vec![rig.path(&["Docs", "a.txt"])]);
        Ok(())
    }

    #[test]
    fn a_folder_that_is_back_from_the_trash_is_listed() -> Res {
        let rig = Rig::new(|seen| match (seen.path(), position(seen).as_str()) {
            ("/2.0/events", "5") => feed(
                &[event(
                    "u1",
                    "ITEM_UNDELETE_VIA_TRASH",
                    folder("30", "Back", &[]),
                )],
                "6",
            ),
            ("/2.0/events", _) => feed(&[], "6"),
            ("/2.0/folders/30/items", _) => {
                page(&[file("9", "f.txt", 2, "ff", &[("30", "Back")])], None)
            }
            _ => Answer::empty(404),
        })?;
        let changes = rig
            .connector
            .changes(&rig.top(), Some("5"), &AtomicBool::new(false))?;
        assert!(!changes.full);
        assert_eq!(sorted(&changes.items), vec![rig.path(&["Back", "f.txt"])]);
        Ok(())
    }

    #[test]
    fn a_change_of_who_may_read_is_a_full_listing() -> Res {
        let rig = Rig::new(|seen| match (seen.path(), position(seen).as_str()) {
            ("/2.0/events", "now") => feed(&[], "9"),
            ("/2.0/events", _) => feed(
                &[event(
                    "c1",
                    "COLLAB_ADD_COLLABORATOR",
                    folder("40", "Shared", &[]),
                )],
                "8",
            ),
            _ => page(&[], None),
        })?;
        let changes = rig
            .connector
            .changes(&rig.top(), Some("5"), &AtomicBool::new(false))?;
        assert!(changes.full);
        Ok(())
    }

    #[test]
    fn a_429_is_waited_out_and_a_huge_wait_comes_back_without_waiting() -> Res {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let rig = Rig::new(move |_| {
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                Answer::json(429, &json!({"code": "rate_limit_exceeded"}))
                    .header("Retry-After", "3")
            } else {
                page(&[folder("10", "Docs", &[])], None)
            }
        })?;
        let folders = rig.connector.browse(None)?;
        assert_eq!(folders.len(), 1);
        assert_eq!(rig.waits(), [Duration::from_secs(3)]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let rig = Rig::new(|_| {
            Answer::json(429, &json!({"code": "rate_limit_exceeded"})).header("Retry-After", "3600")
        })?;
        let error = rig.connector.browse(None).err().ok_or("must fail")?;
        assert!(
            matches!(&error, Error::Throttled { retry_after: Some(wait), .. }
                if *wait == Duration::from_hours(1)),
            "{error:?}"
        );
        assert!(rig.waits().is_empty());
        assert_eq!(rig.mock.seen().len(), 1);
        Ok(())
    }

    #[test]
    fn a_401_gets_a_new_token_once_and_a_refused_refresh_needs_a_sign_in() -> Res {
        let rig = Rig::new(|seen| match seen.path() {
            "/token" => Answer::json(
                200,
                &json!({"access_token": "tok2", "refresh_token": "r2", "expires_in": 3600,
                        "token_type": "bearer"}),
            ),
            _ if seen.header("authorization") == Some("Bearer tok2") => {
                page(&[folder("10", "Docs", &[])], None)
            }
            _ => Answer::json(401, &json!({"code": "unauthorized"})),
        })?;
        assert_eq!(rig.connector.browse(None)?.len(), 1);
        let tokens = rig.mock.seen_at("/token");
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens[0].field("grant_type").as_deref(),
            Some("refresh_token")
        );
        assert_eq!(tokens[0].field("refresh_token").as_deref(), Some("r1"));
        assert_eq!(tokens[0].field("client_id").as_deref(), Some("cid"));
        assert_eq!(tokens[0].field("client_secret").as_deref(), Some("shh"));
        let calls = rig.mock.seen_at("/2.0/folders/0/items");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].header("authorization"), Some("Bearer tok1"));
        assert_eq!(calls[1].header("authorization"), Some("Bearer tok2"));
        // Box's refresh token works once: the new one is kept.
        assert_eq!(
            rig.store.load(&rig.account.id)?.refresh_token.as_deref(),
            Some("r2")
        );

        let rig = Rig::new(|seen| match seen.path() {
            "/token" => Answer::json(400, &json!({"error": "invalid_grant"})),
            _ => Answer::json(401, &json!({"code": "unauthorized"})),
        })?;
        let error = rig.connector.browse(None).err().ok_or("must fail")?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        Ok(())
    }

    #[test]
    fn download_over_the_cap_is_too_large_with_or_without_a_size() -> Res {
        let rig = Rig::new(|seen| match seen.path() {
            "/2.0/files/5/content" => Answer::redirect(&format!(
                "http://{}/dl/5",
                seen.header("host").unwrap_or_default()
            )),
            "/dl/5" => Answer::bytes(200, b"0123456789".to_vec()),
            _ => Answer::empty(404),
        })?;
        let item = |size| RemoteItem {
            id: "5".to_owned(),
            path: rig.path(&["a.txt"]),
            size,
            modified: SystemTime::UNIX_EPOCH,
            version: String::new(),
            web_url: String::new(),
            export: None,
        };
        let never = AtomicBool::new(false);
        // The size is known: nothing is asked for.
        let error = rig
            .connector
            .download(&item(10), 5, &never)
            .err()
            .ok_or("must fail")?;
        assert!(matches!(error, Error::TooLarge));
        assert!(rig.mock.seen().is_empty());
        // The size is not in the listing: the cap on the body does it.
        let error = rig
            .connector
            .download(&item(0), 5, &never)
            .err()
            .ok_or("must fail")?;
        assert!(matches!(error, Error::TooLarge));
        // Exactly the cap comes whole, through the redirect.
        assert_eq!(
            rig.connector.download(&item(10), 10, &never)?,
            b"0123456789"
        );
        let first = rig.mock.seen_at("/2.0/files/5/content");
        assert_eq!(
            first.last().and_then(|call| call.header("authorization")),
            Some("Bearer tok1")
        );
        Ok(())
    }

    #[test]
    fn download_that_is_not_ready_is_throttled_with_the_wait() -> Res {
        let rig = Rig::new(|_| Answer::empty(202).header("Retry-After", "7"))?;
        let item = RemoteItem {
            id: "5".to_owned(),
            path: rig.path(&["a.txt"]),
            size: 3,
            modified: SystemTime::UNIX_EPOCH,
            version: String::new(),
            web_url: String::new(),
            export: None,
        };
        let error = rig
            .connector
            .download(&item, 100, &AtomicBool::new(false))
            .err()
            .ok_or("must fail")?;
        assert!(
            matches!(&error, Error::Throttled { retry_after: Some(wait), .. }
                if *wait == Duration::from_secs(7)),
            "{error:?}"
        );
        assert!(rig.waits().is_empty());
        Ok(())
    }

    #[test]
    fn a_download_with_cancel_set_sends_nothing() -> Res {
        let rig = Rig::new(|_| Answer::bytes(200, b"x".to_vec()))?;
        let item = RemoteItem {
            id: "5".to_owned(),
            path: rig.path(&["a.txt"]),
            size: 1,
            modified: SystemTime::UNIX_EPOCH,
            version: String::new(),
            web_url: String::new(),
            export: None,
        };
        let error = rig
            .connector
            .download(&item, 100, &AtomicBool::new(true))
            .err()
            .ok_or("must fail")?;
        assert!(matches!(error, Error::Cancelled), "{error:?}");
        assert!(rig.mock.seen().is_empty());
        Ok(())
    }

    #[test]
    fn resolve_finds_files_folders_the_account_and_says_when_nothing_is_there() -> Res {
        let rig = Rig::new(|seen| match seen.path() {
            "/2.0/folders/0/items" => page(
                &[
                    folder("10", "Docs", &[]),
                    file("1", "top.txt", 4, "t1", &[]),
                    json!({"type": "web_link", "id": "99", "name": "link"}),
                ],
                None,
            ),
            "/2.0/folders/10/items" => {
                page(&[file("2", "a.txt", 9, "a1", &[("10", "Docs")])], None)
            }
            _ => Answer::empty(404),
        })?;
        let connector = &rig.connector;
        match connector.resolve(&rig.account.root())? {
            Resolved::Folder(top) => {
                assert_eq!((top.id.as_str(), top.path), ("0", rig.account.root()));
            }
            Resolved::File(_) => return Err("the account is a folder".into()),
        }
        let docs = connector.folder(&rig.path(&["Docs"]))?;
        assert_eq!(docs.id, "10");
        assert_eq!(docs.web_url, "https://app.box.com/folder/10");
        // Any letter case finds it.
        let upper = connector.file(&rig.account.root().join("DOCS").join("A.TXT"))?;
        assert_eq!((upper.id.as_str(), upper.size), ("2", 9));
        assert_eq!(upper.path, rig.path(&["Docs", "a.txt"]));
        assert_eq!(connector.file(&rig.path(&["top.txt"]))?.version, "t1");
        for missing in [
            rig.path(&["Docs", "nope.txt"]),
            rig.path(&["Nope", "a.txt"]),
            rig.path(&["link"]),
            rig.path(&["top.txt", "below"]),
        ] {
            let error = connector.resolve(&missing).err().ok_or("must be missing")?;
            assert!(
                matches!(error, Error::NotFound { .. }),
                "{missing:?}: {error:?}"
            );
        }
        // Another account or another provider.
        for other in [r"\\Box\other\Docs", r"\\Dropbox\acme\Docs", r"C:\Docs"] {
            let error = connector
                .resolve(Path::new(other))
                .err()
                .ok_or("must be missing")?;
            assert!(matches!(error, Error::NotFound { .. }), "{other}");
        }
        Ok(())
    }

    #[test]
    fn resolve_finds_a_name_that_component_changed() -> Res {
        let rig = Rig::new(|seen| match seen.path() {
            "/2.0/folders/0/items" => page(&[folder("10", "Q1: plan?", &[])], None),
            "/2.0/folders/10/items" => page(
                &[file("2", "what*.txt", 1, "w", &[("10", "Q1: plan?")])],
                None,
            ),
            _ => Answer::empty(404),
        })?;
        let path = child(&child(&rig.account.root(), "Q1: plan?"), "what*.txt");
        assert!(path.to_string_lossy().contains("Q1： plan？"));
        let found = rig.connector.file(&path)?;
        assert_eq!(found.id, "2");
        assert_eq!(found.path, path);
        Ok(())
    }

    #[test]
    fn a_remembered_folder_that_was_renamed_is_not_trusted() -> Res {
        let renamed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&renamed);
        let rig = Rig::new(move |seen| {
            let name = if flag.load(Ordering::SeqCst) {
                "Docs2"
            } else {
                "Docs"
            };
            match seen.path() {
                "/2.0/folders/0/items" => page(&[folder("10", name, &[])], None),
                "/2.0/folders/10/items" => {
                    page(&[file("2", "a.txt", 9, "a1", &[("10", name)])], None)
                }
                _ => Answer::empty(404),
            }
        })?;
        let path = rig.path(&["Docs", "a.txt"]);
        assert_eq!(rig.connector.file(&path)?.id, "2");
        assert_eq!(rig.connector.file(&path)?.id, "2");
        // The second walk started below the top, from the remembered folder.
        assert_eq!(rig.mock.seen_at("/2.0/folders/0/items").len(), 1);
        renamed.store(true, Ordering::SeqCst);
        let error = rig
            .connector
            .resolve(&path)
            .err()
            .ok_or("must be missing")?;
        assert!(matches!(error, Error::NotFound { .. }), "{error:?}");
        assert_eq!(rig.connector.file(&rig.path(&["Docs2", "a.txt"]))?.id, "2");
        Ok(())
    }

    #[test]
    fn browse_lists_folders_only_sorted_by_name() -> Res {
        let rig = Rig::new(
            |seen| match (seen.path(), seen.param("marker").as_deref()) {
                ("/2.0/folders/0/items", None) => page(
                    &[
                        folder("12", "beta", &[]),
                        file("1", "a.txt", 1, "a", &[]),
                        folder("11", "Alpha", &[]),
                    ],
                    Some("m1"),
                ),
                ("/2.0/folders/0/items", Some(_)) => page(&[folder("13", "Zed", &[])], None),
                ("/2.0/folders/11/items", _) => page(
                    &[
                        folder("21", "sub", &[("11", "Alpha")]),
                        file("2", "b.txt", 1, "b", &[("11", "Alpha")]),
                    ],
                    None,
                ),
                _ => Answer::empty(404),
            },
        )?;
        let top = rig.connector.browse(None)?;
        let names: Vec<_> = top.iter().map(|folder| folder.id.as_str()).collect();
        assert_eq!(names, ["11", "12", "13"]);
        assert_eq!(top[0].path, rig.path(&["Alpha"]));
        let inside = rig.connector.browse(Some(&top[0]))?;
        assert_eq!(inside.len(), 1);
        assert_eq!(inside[0].path, rig.path(&["Alpha", "sub"]));
        let asked = rig.mock.seen_at("/2.0/folders/11/items");
        assert_eq!(asked[0].param("usemarker").as_deref(), Some("true"));
        Ok(())
    }

    #[test]
    fn cancel_stops_a_listing_between_pages() -> Res {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let rig = Rig::new(
            move |seen| match (seen.path(), seen.param("marker").as_deref()) {
                ("/2.0/events", _) => feed(&[], "1"),
                ("/2.0/folders/0/items", None) => {
                    flag.store(true, Ordering::SeqCst);
                    page(&[file("1", "a.txt", 1, "a", &[])], Some("m1"))
                }
                _ => page(&[file("2", "b.txt", 1, "b", &[])], None),
            },
        )?;
        let error = rig
            .connector
            .changes(&rig.top(), None, &cancel)
            .err()
            .ok_or("must stop")?;
        assert!(matches!(error, Error::Cancelled), "{error:?}");
        assert_eq!(rig.mock.seen_at("/2.0/folders/0/items").len(), 1);
        Ok(())
    }

    #[test]
    fn errors_are_the_class_a_person_can_act_on() -> Res {
        let rig = Rig::new(|seen| match seen.path() {
            "/2.0/folders/404/items" => Answer::json(404, &json!({"code": "not_found"})),
            "/2.0/folders/403/items" => Answer::json(403, &json!({"code": "insufficient_scope"})),
            "/2.0/folders/405/items" => Answer::json(
                403,
                &json!({"code": "access_denied_insufficient_permissions"}),
            ),
            _ => Answer::empty(500),
        })?;
        let under = |id: &str| rig.folder(id, &["x"]);
        let not_found = rig
            .connector
            .browse(Some(&under("404")))
            .err()
            .ok_or("fail")?;
        assert!(matches!(not_found, Error::NotFound { .. }));
        for id in ["403", "405"] {
            let denied = rig.connector.browse(Some(&under(id))).err().ok_or("fail")?;
            assert!(
                matches!(denied, Error::Forbidden { .. }),
                "{id}: {denied:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn grants_for_both_sign_in_modes() -> Res {
        let real = Endpoints::default();
        let Grant::Browser(browser) = grant(&delegated(), &real)? else {
            return Err("a person signs in with a browser".into());
        };
        assert_eq!(
            browser.authorize_url,
            "https://account.box.com/api/oauth2/authorize"
        );
        assert_eq!(browser.token_url, "https://api.box.com/oauth2/token");
        assert_eq!(browser.client_id, "cid");
        assert_eq!(browser.scope, "root_readonly");
        assert!(matches!(browser.client_auth, ClientAuth::Body));
        assert_eq!(
            (browser.port, browser.redirect_path.as_str(), browser.pkce),
            (0, "", false)
        );

        for (subject, kind, id) in [
            (
                BoxSubject::Enterprise("555".to_owned()),
                "enterprise",
                "555",
            ),
            (BoxSubject::User("777".to_owned()), "user", "777"),
        ] {
            let app = account(SignIn::BoxApp {
                client_id: "app".to_owned(),
                subject,
            });
            let Grant::App(app) = grant(&app, &real)? else {
                return Err("an app signs in with its credentials".into());
            };
            assert_eq!(app.token_url, "https://api.box.com/oauth2/token");
            assert_eq!(app.client_id, "app");
            assert_eq!(app.scope, None);
            assert!(matches!(
                app.credential,
                AppCredential::Secret(ClientAuth::Body)
            ));
            assert_eq!(
                app.extra,
                [
                    ("box_subject_type".to_owned(), kind.to_owned()),
                    ("box_subject_id".to_owned(), id.to_owned()),
                ]
            );
        }

        let tokens = TokenStore::new(&temp_dir("box-grant"));
        session(&delegated(), &tokens)?;
        let other = Account {
            sign_in: SignIn::DropboxDelegated {
                app_key: "k".to_owned(),
            },
            ..delegated()
        };
        let error = session(&other, &tokens).err().ok_or("must fail")?;
        assert!(
            matches!(error, Error::Local(crate::Error::BadRequest(_))),
            "{error:?}"
        );
        assert!(BoxCom::new(&other, &tokens).is_err());
        Ok(())
    }
}
