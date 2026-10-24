//! The Google Drive connector (Drive API v3).
//!
//! Two ways to sign in, one connector:
//! - `GoogleDelegated`: a person signs in with a browser; the account is that person's Drive.
//!   The top of the account lists `My Drive` and each shared drive, by name.
//! - `GoogleServiceAccount`: a Workspace service account with domain-wide delegation reads the
//!   Drive of each user it is told to impersonate, each with that user's own token. The top of
//!   the account lists one folder per user (the email address: that user's `My Drive`) and
//!   `Shared drives`, the shared drives the first user sees.
//!
//! The handles ([`RemoteFolder::id`], [`RemoteItem::id`]) are `<user>:<place>:<file>:<drive>`: the
//! index of the user (the session that reads it), what the place is (`m` a My Drive, `d` a shared
//! drive, `f` a folder or file, `s` the list of shared drives), the Drive file id, and the id of
//! the shared drive the place is in (empty in a My Drive).
//!
//! Drive lets two files in one folder have one name; a virtual path cannot, so the second one is
//! shown as `name (2)` (and `name (2).ext`). A Google Docs, Sheets or Slides file has no bytes: it
//! is exported to Office format, and shown with that format's extension.
//!
//! The change feed (`changes.list`) names a removed file by its id only, and a moved folder
//! without its files. So the connector remembers, in memory, what each file it saw is called and
//! where it is (`Nodes`), and walks that up to a drive to tell a path. What it cannot tell, it
//! answers with a full listing.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Mutex, atomic::AtomicBool, atomic::Ordering},
    time::SystemTime,
};

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use super::{
    Account, Changes, Connector, Error, Export, Provider, RemoteFolder, RemoteItem, Resolved,
    Result, SignIn, TokenStore,
    auth::{Browser, ClientAuth, Grant, LOOPBACK, ServiceAccount, Session},
    child, component,
    http::{Http, Reply, Request, encode, pages},
    parse_time, parse_virtual,
};
use crate::sys;

/// The provider every error is about.
const PROVIDER: Provider = Provider::GoogleDrive;
/// The one scope: read, never write.
const SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
/// The media type of a Drive folder.
const FOLDER: &str = "application/vnd.google-apps.folder";
/// What a file of a listing says about itself.
const LIST_FIELDS: &str = "nextPageToken,files(id,name,mimeType,size,modifiedTime,md5Checksum,version,webViewLink,parents,trashed,shortcutDetails)";
/// What the change feed says.
const CHANGE_FIELDS: &str = "nextPageToken,newStartPageToken,changes(changeType,fileId,driveId,removed,file(id,name,mimeType,size,modifiedTime,md5Checksum,version,webViewLink,parents,trashed,shortcutDetails))";
/// The name of the list of shared drives in a service account's tree.
const SHARED_DRIVES: &str = "Shared drives";
/// The name of a person's own Drive.
const MY_DRIVE: &str = "My Drive";
/// Where a browser opens a person's own Drive.
const MY_DRIVE_URL: &str = "https://drive.google.com/drive/my-drive";
/// The most files Drive lists in a page.
const PAGE_SIZE: &str = "1000";
/// The most shared drives Drive lists in a page.
const DRIVES_PAGE_SIZE: &str = "100";
/// How many folders deep a path is walked up before it is given up on (a loop in the data).
const MAX_DEPTH: usize = 256;
/// The most files and folders whose place is remembered: more are asked for when needed.
const MAX_NODES: usize = 250_000;
/// Why Drive says "slow down" with a 403.
const RATE_LIMITED: [&str; 4] = [
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "sharingRateLimitExceeded",
    "dailyLimitExceeded",
];
/// Why Drive refuses to export a file that is too big (10 MB).
const EXPORT_TOO_BIG: &str = "exportSizeLimitExceeded";

/// Where the services are; a test points them at a mock.
#[derive(Debug, Clone)]
struct Endpoints {
    /// The Drive API, without a slash at the end.
    api: String,
    /// Where the browser signs a person in.
    authorize: String,
    /// Where a code or a refresh token is exchanged.
    token: String,
    /// Where a service account's JWT is exchanged, instead of what its key file says.
    service_token: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            api: "https://www.googleapis.com/drive/v3".to_owned(),
            authorize: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token: "https://oauth2.googleapis.com/token".to_owned(),
            service_token: None,
        }
    }
}

/// What a Drive file is to piikey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A folder.
    Folder,
    /// A file with bytes of its own.
    File,
    /// A Docs, Sheets or Slides file, read as the format.
    Export(Export),
    /// Something piikey does not read: a shortcut, a form, a drawing, a site...
    Skip,
}

/// What a handle's place is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// A person's own Drive.
    MyDrive,
    /// A shared drive.
    SharedDrive,
    /// A folder or file.
    Folder,
    /// The list of shared drives (a service account's tree).
    SharedDrives,
}

impl Place {
    /// The letter a handle spells it with.
    const fn letter(self) -> char {
        match self {
            Self::MyDrive => 'm',
            Self::SharedDrive => 'd',
            Self::Folder => 'f',
            Self::SharedDrives => 's',
        }
    }

    /// The place a letter stands for.
    fn from_letter(text: &str) -> Option<Self> {
        match text {
            "m" => Some(Self::MyDrive),
            "d" => Some(Self::SharedDrive),
            "f" => Some(Self::Folder),
            "s" => Some(Self::SharedDrives),
            _ => None,
        }
    }
}

/// A handle taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Id {
    /// The user whose session reads it (always 0 for a person who signed in).
    session: usize,
    place: Place,
    /// The Drive file id; empty for a My Drive (its root folder has an id the connector asks for)
    /// and for the list of shared drives.
    file: String,
    /// The shared drive it is in.
    drive: Option<String>,
}

impl Id {
    /// The handle of `file` read by `session`.
    fn of(session: usize, place: Place, file: &str, drive: Option<&str>) -> Self {
        Self {
            session,
            place,
            file: file.to_owned(),
            drive: drive.map(str::to_owned),
        }
    }

    /// The handle as text.
    fn text(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.session,
            self.place.letter(),
            self.file,
            self.drive.as_deref().unwrap_or_default()
        )
    }

    /// A handle that [`Id::text`] made.
    fn parse(text: &str) -> Result<Self> {
        let mut parts = text.splitn(4, ':');
        let session = parts.next().and_then(|part| part.parse().ok());
        let place = parts.next().and_then(Place::from_letter);
        let file = parts.next();
        let drive = parts.next();
        match (session, place, file, drive) {
            (Some(session), Some(place), Some(file), Some(drive)) => Ok(Self {
                session,
                place,
                file: file.to_owned(),
                drive: (!drive.is_empty()).then(|| drive.to_owned()),
            }),
            _ => Err(Error::Local(crate::Error::BadRequest(
                "That place does not belong to this Google Drive account.".to_owned(),
            ))),
        }
    }

    /// The shared drive this is in, or is.
    fn drive_id(&self) -> Option<String> {
        match self.place {
            Place::SharedDrive => Some(self.file.clone()),
            _ => self.drive.clone(),
        }
    }
}

/// A file or folder as Drive says it, as far as the field masks ask.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct File {
    id: String,
    name: String,
    mime_type: String,
    /// Bytes, as a text (a 64-bit number).
    size: Option<Value>,
    modified_time: String,
    md5_checksum: String,
    /// The number of the revision of the file, as a text (a 64-bit number).
    version: Option<Value>,
    web_view_link: String,
    parents: Vec<String>,
    trashed: bool,
}

/// One page of `files.list`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct FileList {
    files: Vec<File>,
    next_page_token: Option<String>,
}

/// A shared drive.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DriveInfo {
    id: String,
    name: String,
}

/// One page of `drives.list`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DriveList {
    drives: Vec<DriveInfo>,
    next_page_token: Option<String>,
}

/// One entry of the change feed.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Change {
    /// `file` or `drive`.
    #[serde(rename = "changeType")]
    kind: String,
    file_id: String,
    removed: bool,
    file: Option<File>,
}

impl Change {
    /// The id of the file the entry is about.
    fn key(&self) -> &str {
        match &self.file {
            Some(file) if self.file_id.is_empty() => &file.id,
            _ => &self.file_id,
        }
    }

    /// The file when it is there to be read: not removed, not in the trash.
    fn live(&self) -> Option<&File> {
        self.file
            .as_ref()
            .filter(|file| !self.removed && !file.trashed)
    }
}

/// One page of `changes.list`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct ChangeList {
    changes: Vec<Change>,
    next_page_token: Option<String>,
    new_start_page_token: Option<String>,
}

/// The answer of `changes.getStartPageToken`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct StartToken {
    start_page_token: String,
}

/// What Drive says in the body of an error.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ErrorBody {
    error: ErrorDetail,
}

/// The `error` of an error body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ErrorDetail {
    message: String,
    errors: Vec<ErrorReason>,
}

/// One of the `errors` of an error body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ErrorReason {
    reason: String,
}

/// What the connector remembers of a file or folder it saw: enough to tell its path.
#[derive(Debug, Clone)]
struct Node {
    /// The name Drive gave it.
    name: String,
    /// The name in a virtual path: unique in its folder, with an extension when it is exported.
    shown: String,
    /// The folder it is in; `None` when it is in none the user can see.
    parent: Option<String>,
}

/// What the connector remembers, by user and Drive file id.
#[derive(Debug, Default)]
struct Nodes {
    map: HashMap<(usize, String), Node>,
}

/// A folder of a listing still to read.
#[derive(Debug, Clone)]
struct Dir {
    id: String,
    path: PathBuf,
    /// The shared drive it is in.
    drive: Option<String>,
}

/// A shared drive and where it is in the account.
#[derive(Debug, Clone)]
struct Drive {
    id: String,
    path: PathBuf,
}

/// A child of a folder, named for a virtual path.
#[derive(Debug)]
struct Child {
    file: File,
    kind: Kind,
    shown: String,
}

/// What a change feed reads: one user's, a shared drive's, or all of a user's.
#[derive(Debug, Clone)]
struct Feed {
    session: usize,
    /// The shared drive it is limited to.
    drive: Option<String>,
    /// Limited to the user's own Drive.
    my_drive: bool,
}

impl Feed {
    /// The feed that tells about the place of `id`.
    fn of(id: &Id) -> Self {
        let drive = id.drive_id();
        Self {
            session: id.session,
            my_drive: drive.is_none() && id.place != Place::SharedDrives,
            drive,
        }
    }
}

/// What one `changes` call knows about where things are: paths of the roots of drives.
struct Cx {
    session: usize,
    /// The ids of folders that are the top of a place, and the virtual path of each.
    fixed: HashMap<String, PathBuf>,
    /// Whether the shared drives were asked for already.
    drives_loaded: bool,
}

impl Cx {
    /// A context for the feed of `id`, whose folder is `root`.
    fn new(id: &Id, root: &RemoteFolder) -> Self {
        let mut fixed = HashMap::new();
        if matches!(id.place, Place::SharedDrive | Place::Folder) {
            fixed.insert(id.file.clone(), root.path.clone());
        }
        Self {
            session: id.session,
            fixed,
            drives_loaded: false,
        }
    }
}

/// What the changes sorted out to.
#[derive(Default)]
struct Settled {
    items: Vec<RemoteItem>,
    removed: Vec<PathBuf>,
    /// Folders that are new here: moved in, renamed or restored. Their files are listed.
    subtrees: Vec<Dir>,
}

/// The Google Drive connector.
pub(crate) struct Google {
    /// The account's top: `\\Google Drive\<label>`.
    root: PathBuf,
    /// The account's name: the share part of its paths.
    label: String,
    /// The users a service account reads as; empty for a person who signed in.
    users: Vec<String>,
    /// The name of each user's folder, unique in the account.
    user_names: Vec<String>,
    /// One session per user (one for a person who signed in).
    sessions: Vec<Session>,
    endpoints: Endpoints,
    nodes: Mutex<Nodes>,
    /// The id of the root folder of each user's My Drive.
    roots: Mutex<HashMap<usize, String>>,
}

/// The ways to get a token that `account` has: one grant per user.
fn grants(account: &Account, endpoints: &Endpoints) -> Result<Vec<Grant>> {
    if account.provider != PROVIDER || !account.sign_in.fits(PROVIDER) {
        return Err(Error::Local(crate::Error::BadRequest(
            "This account is not a Google Drive account.".to_owned(),
        )));
    }
    match &account.sign_in {
        SignIn::GoogleDelegated { client_id } => Ok(vec![Grant::Browser(Browser {
            authorize_url: endpoints.authorize.clone(),
            token_url: endpoints.token.clone(),
            client_id: client_id.clone(),
            scope: SCOPE.to_owned(),
            authorize_extra: vec![
                ("access_type".to_owned(), "offline".to_owned()),
                ("prompt".to_owned(), "consent".to_owned()),
            ],
            client_auth: ClientAuth::Body,
            redirect_host: LOOPBACK,
            port: 0,
            redirect_path: String::new(),
            pkce: true,
        })]),
        SignIn::GoogleServiceAccount { key_file, users } if !users.is_empty() => Ok(users
            .iter()
            .map(|user| {
                Grant::ServiceAccount(ServiceAccount {
                    key_file: key_file.clone(),
                    user: user.clone(),
                    scope: SCOPE.to_owned(),
                    token_url: endpoints.service_token.clone(),
                })
            })
            .collect()),
        _ => Err(Error::Local(crate::Error::BadRequest(
            "Name at least one user whose Google Drive piikey may read.".to_owned(),
        ))),
    }
}

/// The session that signs the account in: for a service account, the one of the first user.
///
/// # Errors
/// `Local(BadRequest)` when the account does not sign in to Google Drive.
pub(crate) fn session(account: &Account, tokens: &TokenStore) -> Result<Session> {
    let grant = grants(account, &Endpoints::default())?
        .into_iter()
        .next()
        .ok_or_else(|| Error::unexpected(PROVIDER, "no way to sign in"))?;
    Ok(Session::new(
        Http::new(PROVIDER),
        tokens.clone(),
        &account.id,
        grant,
    ))
}

impl Google {
    /// The connector for a connected account, talking to Google.
    ///
    /// # Errors
    /// `Local(BadRequest)` when the account does not sign in to Google Drive.
    pub(crate) fn new(account: &Account, tokens: &TokenStore) -> Result<Self> {
        Self::with(account, tokens, &Http::new(PROVIDER), Endpoints::default())
    }

    /// The connector over `http`, with the services at `endpoints`.
    fn with(
        account: &Account,
        tokens: &TokenStore,
        http: &Http,
        endpoints: Endpoints,
    ) -> Result<Self> {
        let sessions = grants(account, &endpoints)?
            .into_iter()
            .map(|grant| Session::new(http.clone(), tokens.clone(), &account.id, grant))
            .collect();
        let users = match &account.sign_in {
            SignIn::GoogleServiceAccount { users, .. } => users.clone(),
            _ => Vec::new(),
        };
        let mut taken = HashSet::from([SHARED_DRIVES.to_lowercase()]);
        let user_names = users
            .iter()
            .map(|user| unique(&mut taken, user, Kind::Folder))
            .collect();
        Ok(Self {
            root: account.root(),
            label: account.label.clone(),
            users,
            user_names,
            sessions,
            endpoints,
            nodes: Mutex::new(Nodes::default()),
            roots: Mutex::new(HashMap::new()),
        })
    }

    /// Whether the account is a service account (a tree of users) and not one person's Drive.
    fn is_service(&self) -> bool {
        !self.users.is_empty()
    }

    /// The session of user `index`.
    fn session_of(&self, index: usize) -> Result<&Session> {
        self.sessions.get(index).ok_or_else(|| {
            Error::Local(crate::Error::BadRequest(
                "That place does not belong to this Google Drive account.".to_owned(),
            ))
        })
    }

    /// A GET of `path` of the Drive API.
    fn request(&self, path: &str) -> Request {
        Request::get(format!("{}{path}", self.endpoints.api))
    }

    /// Sends `request` as user `session`, whatever the status of the answer.
    fn send(&self, session: usize, request: &Request) -> Result<Reply> {
        self.session_of(session)?.send(request)
    }

    /// Sends `request` as user `session`; an answer that is not a success is an [`Error`].
    fn call(&self, session: usize, request: &Request) -> Result<Reply> {
        let reply = self.send(session, request)?;
        if reply.is_success() {
            Ok(reply)
        } else {
            Err(failure(&reply))
        }
    }

    /// Follows a listing from `first` to its last page. `page` takes each page and gives the
    /// token of the next one.
    fn paged<T: DeserializeOwned>(
        &self,
        session: usize,
        first: &Request,
        cancel: &AtomicBool,
        mut page: impl FnMut(T) -> Option<String>,
    ) -> Result<()> {
        pages(
            PROVIDER,
            cancel,
            first.clone(),
            &|request| self.call(session, request),
            |reply| {
                let body: T = reply.json()?;
                Ok(page(body)
                    .filter(|token| !token.is_empty())
                    .map(|token| first.clone().query("pageToken", &token)))
            },
        )
    }

    /// The id of the root folder of the Drive of user `session`.
    fn my_root(&self, session: usize) -> Result<String> {
        if let Some(id) = self.cached_root(session) {
            return Ok(id);
        }
        let reply = self.call(session, &self.request("/files/root").query("fields", "id"))?;
        let file: File = reply.json()?;
        if file.id.is_empty() {
            return Err(Error::unexpected(PROVIDER, "the root folder has no id"));
        }
        if let Ok(mut roots) = self.roots.lock() {
            roots.insert(session, file.id.clone());
        }
        Ok(file.id)
    }

    /// The root folder id of the Drive of `session`, when it was asked for already.
    fn cached_root(&self, session: usize) -> Option<String> {
        self.roots.lock().ok()?.get(&session).cloned()
    }

    /// Where the Drive of user `session` is in the account.
    fn my_drive_path(&self, session: usize) -> PathBuf {
        match self.user_names.get(session) {
            Some(name) if self.is_service() => self.root.join(name),
            _ => child(&self.root, MY_DRIVE),
        }
    }

    /// Where the shared drives are in the account.
    fn container(&self) -> PathBuf {
        if self.is_service() {
            child(&self.root, SHARED_DRIVES)
        } else {
            self.root.clone()
        }
    }

    /// The folder of the Drive of user `session`.
    fn my_drive_folder(&self, session: usize) -> RemoteFolder {
        RemoteFolder {
            id: Id::of(session, Place::MyDrive, "", None).text(),
            path: self.my_drive_path(session),
            web_url: MY_DRIVE_URL.to_owned(),
        }
    }

    /// The folder of the list of shared drives (a service account's tree).
    fn container_folder(&self) -> RemoteFolder {
        RemoteFolder {
            id: Id::of(0, Place::SharedDrives, "", None).text(),
            path: self.container(),
            web_url: String::new(),
        }
    }

    /// The folder of a shared drive, which user 0 sees.
    fn drive_folder(drive: &Drive) -> RemoteFolder {
        RemoteFolder {
            id: Id::of(0, Place::SharedDrive, &drive.id, Some(&drive.id)).text(),
            path: drive.path.clone(),
            web_url: format!("https://drive.google.com/drive/folders/{}", drive.id),
        }
    }

    /// The shared drives of the first user, below `base`, with names that are unique.
    fn drives(&self, base: &Path) -> Result<Vec<Drive>> {
        let never = AtomicBool::new(false);
        let first = self
            .request("/drives")
            .query("pageSize", DRIVES_PAGE_SIZE)
            .query("fields", "nextPageToken,drives(id,name)");
        let mut found: Vec<DriveInfo> = Vec::new();
        self.paged(0, &first, &never, |list: DriveList| {
            found.extend(list.drives);
            list.next_page_token
        })?;
        found.sort_by_cached_key(|drive| (drive.name.to_lowercase(), drive.id.clone()));
        let mut taken = HashSet::new();
        if !self.is_service() {
            taken.insert(MY_DRIVE.to_lowercase());
        }
        Ok(found
            .into_iter()
            .map(|drive| {
                let shown = unique(&mut taken, &drive.name, Kind::Folder);
                Drive {
                    id: drive.id,
                    path: base.join(shown),
                }
            })
            .collect())
    }

    /// The files and folders directly in the folder `parent` (of the shared drive `drive`, when
    /// it is in one), named for a virtual path: folders first, then by id, so the same names come
    /// out every time. With `folders_only`, only the folders.
    fn children(
        &self,
        session: usize,
        parent: &str,
        drive: Option<&str>,
        folders_only: bool,
        cancel: &AtomicBool,
    ) -> Result<Vec<Child>> {
        let mut query = format!("'{}' in parents and trashed=false", quoted(parent));
        if folders_only {
            query.push_str(" and mimeType='");
            query.push_str(FOLDER);
            query.push('\'');
        }
        let mut first = self
            .request("/files")
            .query("q", &query)
            .query("pageSize", PAGE_SIZE)
            .query("fields", LIST_FIELDS)
            .query("supportsAllDrives", "true")
            .query("includeItemsFromAllDrives", "true");
        if let Some(drive) = drive {
            first = first.query("corpora", "drive").query("driveId", drive);
        }
        let mut files: Vec<File> = Vec::new();
        self.paged(session, &first, cancel, |list: FileList| {
            files.extend(list.files);
            list.next_page_token
        })?;
        Ok(name_children(files))
    }

    /// Reads every folder of `start` and below, breadth first, into `items`.
    fn walk(
        &self,
        session: usize,
        start: Vec<Dir>,
        cancel: &AtomicBool,
        items: &mut Vec<RemoteItem>,
    ) -> Result<()> {
        let mut queue: VecDeque<Dir> = start.into();
        while let Some(dir) = queue.pop_front() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            for child in self.children(session, &dir.id, dir.drive.as_deref(), false, cancel)? {
                let path = dir.path.join(&child.shown);
                self.remember(session, &child, &dir.id);
                match child.kind {
                    Kind::Folder => queue.push_back(Dir {
                        id: child.file.id,
                        path,
                        drive: dir.drive.clone(),
                    }),
                    kind => items.extend(remote_item(session, &child.file, kind, path)),
                }
            }
        }
        Ok(())
    }

    /// Notes where `child` is, for the paths of the change feed.
    fn remember(&self, session: usize, child: &Child, parent: &str) {
        if let Ok(mut nodes) = self.nodes.lock()
            && nodes.map.len() < MAX_NODES
        {
            nodes.map.insert(
                (session, child.file.id.clone()),
                Node {
                    name: child.file.name.clone(),
                    shown: child.shown.clone(),
                    parent: Some(parent.to_owned()),
                },
            );
        }
    }

    /// Notes what the change feed says `file` is: its name (kept as shown when it is the same one)
    /// and its folder.
    fn upsert(&self, session: usize, file: &File) {
        let kind = classify(file);
        if let Ok(mut nodes) = self.nodes.lock() {
            let key = (session, file.id.clone());
            let shown = match nodes.map.get(&key) {
                Some(old) if old.name == file.name => old.shown.clone(),
                _ => component(&shown_name(&file.name, kind)),
            };
            if nodes.map.len() < MAX_NODES || nodes.map.contains_key(&key) {
                nodes.map.insert(
                    key,
                    Node {
                        name: file.name.clone(),
                        shown,
                        parent: file.parents.first().cloned(),
                    },
                );
            }
        }
    }

    /// Forgets `id`.
    fn forget(&self, session: usize, id: &str) {
        if let Ok(mut nodes) = self.nodes.lock() {
            nodes.map.remove(&(session, id.to_owned()));
        }
    }

    /// What is remembered of `id`.
    fn node(&self, session: usize, id: &str) -> Option<Node> {
        self.nodes
            .lock()
            .ok()?
            .map
            .get(&(session, id.to_owned()))
            .cloned()
    }

    /// Asks Drive for the name and folder of `id`, and remembers them. `None` when it is not
    /// there, or not for this user to see.
    fn fetch_node(&self, session: usize, id: &str) -> Result<Option<Node>> {
        let request = self
            .request(&format!("/files/{}", encode(id)))
            .query("fields", "id,name,parents")
            .query("supportsAllDrives", "true");
        let file: File = match self.call(session, &request) {
            Ok(reply) => reply.json()?,
            Err(Error::NotFound { .. } | Error::Forbidden { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        let node = Node {
            shown: component(&file.name),
            name: file.name,
            parent: file.parents.first().cloned(),
        };
        if let Ok(mut nodes) = self.nodes.lock()
            && nodes.map.len() < MAX_NODES
        {
            nodes.map.insert((session, id.to_owned()), node.clone());
        }
        Ok(Some(node))
    }

    /// The path of the top of a place, when `id` is one: the root of a My Drive, or of a shared
    /// drive. With `load`, the services are asked for what is not known yet.
    fn base_of(&self, cx: &mut Cx, id: &str, load: bool) -> Result<Option<PathBuf>> {
        if let Some(path) = cx.fixed.get(id) {
            return Ok(Some(path.clone()));
        }
        let root = if load {
            Some(self.my_root(cx.session)?)
        } else {
            self.cached_root(cx.session)
        };
        if root.as_deref() == Some(id) {
            return Ok(Some(self.my_drive_path(cx.session)));
        }
        if load && cx.session == 0 && !cx.drives_loaded {
            cx.drives_loaded = true;
            for drive in self.drives(&self.container())? {
                cx.fixed.entry(drive.id).or_insert(drive.path);
            }
            return Ok(cx.fixed.get(id).cloned());
        }
        Ok(None)
    }

    /// The virtual path of `id`, walking up its folders to the top of a drive. With `fetch`, a
    /// folder that is not remembered is asked for; without, the path is `None` then.
    fn path_of(&self, cx: &mut Cx, id: &str, fetch: bool) -> Result<Option<PathBuf>> {
        let mut names: Vec<String> = Vec::new();
        let mut current = id.to_owned();
        for _ in 0..MAX_DEPTH {
            if let Some(base) = self.base_of(cx, &current, false)? {
                return Ok(Some(below(base, &names)));
            }
            let node = if let Some(node) = self.node(cx.session, &current) {
                node
            } else {
                if let Some(base) = self.base_of(cx, &current, true)? {
                    return Ok(Some(below(base, &names)));
                }
                if !fetch {
                    return Ok(None);
                }
                let Some(node) = self.fetch_node(cx.session, &current)? else {
                    return Ok(None);
                };
                node
            };
            names.push(node.shown);
            let Some(parent) = node.parent else {
                return Ok(None);
            };
            current = parent;
        }
        Ok(None)
    }

    /// The token that tells where `feed` is now.
    fn start_token(&self, feed: &Feed) -> Result<String> {
        let mut request = self
            .request("/changes/startPageToken")
            .query("supportsAllDrives", "true");
        if let Some(drive) = &feed.drive {
            request = request.query("driveId", drive);
        }
        let token: StartToken = self.call(feed.session, &request)?.json()?;
        if token.start_page_token.is_empty() {
            return Err(Error::unexpected(PROVIDER, "no start page token"));
        }
        Ok(token.start_page_token)
    }

    /// The folders to read to list everything under the folder `root`.
    fn starts(&self, root: &RemoteFolder, id: &Id) -> Result<Vec<Dir>> {
        match id.place {
            Place::MyDrive => Ok(vec![Dir {
                id: self.my_root(id.session)?,
                path: root.path.clone(),
                drive: None,
            }]),
            Place::SharedDrive | Place::Folder => Ok(vec![Dir {
                id: id.file.clone(),
                path: root.path.clone(),
                drive: id.drive_id(),
            }]),
            Place::SharedDrives => Ok(self
                .drives(&root.path)?
                .into_iter()
                .map(|drive| Dir {
                    id: drive.id.clone(),
                    path: drive.path,
                    drive: Some(drive.id),
                })
                .collect()),
        }
    }

    /// Everything under `root`, and the token to go on from.
    fn full(
        &self,
        root: &RemoteFolder,
        id: &Id,
        feed: &Feed,
        cancel: &AtomicBool,
    ) -> Result<Changes> {
        let cursor = self.start_token(feed)?;
        let mut items = Vec::new();
        self.walk(id.session, self.starts(root, id)?, cancel, &mut items)?;
        Ok(Changes {
            items,
            removed: Vec::new(),
            cursor,
            full: true,
        })
    }

    /// What changed in `root` since `cursor`; `None` when the feed cannot tell (a token Drive no
    /// longer takes, a removal whose path is not known): the caller lists everything.
    fn incremental(
        &self,
        root: &RemoteFolder,
        id: &Id,
        feed: &Feed,
        cursor: &str,
        cancel: &AtomicBool,
    ) -> Result<Option<Changes>> {
        let mut base = self
            .request("/changes")
            .query("pageSize", PAGE_SIZE)
            .query("includeRemoved", "true")
            .query("supportsAllDrives", "true")
            .query("fields", CHANGE_FIELDS);
        base = match (&feed.drive, feed.my_drive) {
            (Some(drive), _) => base
                .query("driveId", drive)
                .query("includeItemsFromAllDrives", "true"),
            (None, true) => base
                .query("includeItemsFromAllDrives", "false")
                .query("restrictToMyDrive", "true"),
            (None, false) => base.query("includeItemsFromAllDrives", "true"),
        };
        let mut entries = Vec::new();
        let mut end = None;
        let mut stale = false;
        pages(
            PROVIDER,
            cancel,
            base.clone().query("pageToken", cursor),
            &|request| self.send(feed.session, request),
            |reply| {
                if matches!(reply.status, 400 | 404 | 410) {
                    stale = true;
                    return Ok(None);
                }
                if !reply.is_success() {
                    return Err(failure(&reply));
                }
                let list: ChangeList = reply.json()?;
                entries.extend(list.changes);
                if let Some(next) = list.next_page_token.filter(|token| !token.is_empty()) {
                    return Ok(Some(base.clone().query("pageToken", &next)));
                }
                end = list.new_start_page_token.filter(|token| !token.is_empty());
                Ok(None)
            },
        )?;
        if stale {
            return Ok(None);
        }
        let Some(end) = end else {
            return Err(Error::unexpected(PROVIDER, "the change list has no end"));
        };
        self.apply(root, id, feed, entries, end, cancel)
    }

    /// Sorts out what the feed's `entries` mean for `root`.
    fn apply(
        &self,
        root: &RemoteFolder,
        id: &Id,
        feed: &Feed,
        entries: Vec<Change>,
        cursor: String,
        cancel: &AtomicBool,
    ) -> Result<Option<Changes>> {
        if id.place == Place::SharedDrives && entries.iter().any(|c| c.kind == "drive") {
            return Ok(None);
        }
        let latest = latest_changes(entries);
        let mut cx = Cx::new(id, root);
        // The old place of everything that changed, before the feed's news is taken in.
        let mut olds = Vec::with_capacity(latest.len());
        for change in &latest {
            olds.push(self.path_of(&mut cx, change.key(), false)?);
        }
        for change in &latest {
            match change.live() {
                Some(file) => self.upsert(feed.session, file),
                None => self.forget(feed.session, change.key()),
            }
        }
        let mut settled = Settled::default();
        for (change, old) in latest.iter().zip(olds) {
            if !self.settle(&mut cx, root, feed, change, old, &mut settled)? {
                return Ok(None);
            }
        }
        let Settled {
            mut items,
            removed,
            mut subtrees,
        } = settled;
        subtrees.sort_by_key(|dir| dir.path.components().count());
        let mut listed: Vec<PathBuf> = Vec::new();
        for dir in subtrees {
            if listed.iter().any(|done| sys::is_under(&dir.path, done)) {
                continue;
            }
            listed.push(dir.path.clone());
            self.walk(feed.session, vec![dir], cancel, &mut items)?;
        }
        let items = first_per_path(items);
        let removed = removed_without(removed, &items);
        Ok(Some(Changes {
            items,
            removed,
            cursor,
            full: false,
        }))
    }

    /// Sorts out one change. `false` when it cannot be told where something that is gone was.
    fn settle(
        &self,
        cx: &mut Cx,
        root: &RemoteFolder,
        feed: &Feed,
        change: &Change,
        old: Option<PathBuf>,
        out: &mut Settled,
    ) -> Result<bool> {
        let inside = |path: &Path| sys::is_under(path, &root.path);
        let Some(file) = change.live() else {
            return Ok(match old {
                Some(old) => {
                    if inside(&old) {
                        out.removed.push(old);
                    }
                    true
                }
                None => false,
            });
        };
        let new = self
            .path_of(cx, &file.id, true)?
            .filter(|path| inside(path));
        if let Some(old) = &old {
            let same = new.as_ref().is_some_and(|new| sys::same_path(new, old));
            if inside(old) && !same {
                out.removed.push(old.clone());
            }
        }
        let Some(new) = new else {
            return Ok(true);
        };
        match classify(file) {
            Kind::Folder => {
                let moved = old.as_ref().is_none_or(|old| !sys::same_path(old, &new));
                if moved && !sys::same_path(&new, &root.path) {
                    out.subtrees.push(Dir {
                        id: file.id.clone(),
                        path: new,
                        drive: feed.drive.clone(),
                    });
                }
            }
            kind => out.items.extend(remote_item(feed.session, file, kind, new)),
        }
        Ok(true)
    }

    /// The top of the account.
    fn tops(&self) -> Result<Vec<RemoteFolder>> {
        let mut folders = if self.is_service() {
            let mut folders: Vec<RemoteFolder> = (0..self.users.len())
                .map(|session| self.my_drive_folder(session))
                .collect();
            folders.push(self.container_folder());
            folders
        } else {
            let mut folders = vec![self.my_drive_folder(0)];
            folders.extend(self.drives(&self.root)?.iter().map(Self::drive_folder));
            folders
        };
        sort_folders(&mut folders);
        Ok(folders)
    }

    /// The place of the first part of a path below the account's top, and how many parts of
    /// `parts` it took.
    fn top(&self, parts: &[String]) -> Result<(RemoteFolder, usize)> {
        let miss = || Error::not_found(PROVIDER, "no such place in this account");
        let first = parts.first().ok_or_else(miss)?.to_lowercase();
        if self.is_service() {
            if let Some(session) = self
                .user_names
                .iter()
                .position(|name| name.to_lowercase() == first)
            {
                return Ok((self.my_drive_folder(session), 1));
            }
            if first != SHARED_DRIVES.to_lowercase() {
                return Err(miss());
            }
            let Some(second) = parts.get(1) else {
                return Ok((self.container_folder(), 1));
            };
            let drive = self.drive_named(&self.container(), second)?;
            return Ok((Self::drive_folder(&drive), 2));
        }
        if first == MY_DRIVE.to_lowercase() {
            return Ok((self.my_drive_folder(0), 1));
        }
        let drive = self.drive_named(&self.root, &parts[0])?;
        Ok((Self::drive_folder(&drive), 1))
    }

    /// The shared drive below `base` that is called `name`.
    fn drive_named(&self, base: &Path, name: &str) -> Result<Drive> {
        let name = name.to_lowercase();
        self.drives(base)?
            .into_iter()
            .find(|drive| path_name(&drive.path).to_lowercase() == name)
            .ok_or_else(|| Error::not_found(PROVIDER, "no such shared drive"))
    }
}

/// The part of a path that is its last name.
fn path_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `folders` by name, letter case ignored.
fn sort_folders(folders: &mut [RemoteFolder]) {
    folders.sort_by_cached_key(|folder| path_name(&folder.path).to_lowercase());
}

/// `base` with each of `names` (the last one first, as they were found walking up) below it.
fn below(base: PathBuf, names: &[String]) -> PathBuf {
    names.iter().rev().fold(base, |path, name| path.join(name))
}

/// `text` as it goes between the single quotes of a `q` query.
fn quoted(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\'', "\\'")
}

/// What `file` is to piikey.
fn classify(file: &File) -> Kind {
    match file.mime_type.as_str() {
        FOLDER => Kind::Folder,
        "application/vnd.google-apps.document" => Kind::Export(Export::Docx),
        "application/vnd.google-apps.spreadsheet" => Kind::Export(Export::Xlsx),
        "application/vnd.google-apps.presentation" => Kind::Export(Export::Pptx),
        other if other.starts_with("application/vnd.google-apps.") => Kind::Skip,
        _ => Kind::File,
    }
}

/// `name` as it is called in a path: with the extension of the format when it is exported.
fn shown_name(name: &str, kind: Kind) -> String {
    match kind {
        Kind::Export(format) => {
            let extension = format!(".{}", format.extension());
            if name.to_lowercase().ends_with(&extension) {
                name.to_owned()
            } else {
                format!("{name}{extension}")
            }
        }
        _ => name.to_owned(),
    }
}

/// `name` with a number in front of its extension: `a (2).txt`.
fn numbered(name: &str, number: u32, extension: bool) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if extension && !stem.is_empty() => format!("{stem} ({number}).{ext}"),
        _ => format!("{name} ({number})"),
    }
}

/// `name` as a part of a path that is none of the `taken` ones (compared in lowercase); it is
/// taken then.
fn unique(taken: &mut HashSet<String>, name: &str, kind: Kind) -> String {
    let named = shown_name(name, kind);
    let mut shown = component(&named);
    let mut number = 2_u32;
    while !taken.insert(shown.to_lowercase()) {
        shown = component(&numbered(&named, number, kind != Kind::Folder));
        number += 1;
    }
    shown
}

/// The files of a folder that piikey reads, named: folders first, then by id.
fn name_children(files: Vec<File>) -> Vec<Child> {
    let mut kept: Vec<(File, Kind)> = files
        .into_iter()
        .map(|file| {
            let kind = classify(&file);
            (file, kind)
        })
        .filter(|(_, kind)| *kind != Kind::Skip)
        .collect();
    kept.sort_by(|(a, a_kind), (b, b_kind)| {
        (*b_kind == Kind::Folder, &a.id).cmp(&(*a_kind == Kind::Folder, &b.id))
    });
    let mut taken = HashSet::new();
    kept.into_iter()
        .map(|(file, kind)| {
            let shown = unique(&mut taken, &file.name, kind);
            Child { file, kind, shown }
        })
        .collect()
}

/// A number given as a text or as a number.
fn number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::String(text) => text.parse().ok(),
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// A number given as a text or as a number, as text.
fn number_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

/// `file` as an item at `path`; `None` for what piikey does not read.
fn remote_item(session: usize, file: &File, kind: Kind, path: PathBuf) -> Option<RemoteItem> {
    let export = match kind {
        Kind::File => None,
        Kind::Export(format) => Some(format),
        Kind::Folder | Kind::Skip => return None,
    };
    let version = if file.md5_checksum.is_empty() {
        number_text(file.version.as_ref())
    } else {
        file.md5_checksum.clone()
    };
    Some(RemoteItem {
        id: Id::of(session, Place::Folder, &file.id, None).text(),
        path,
        size: if export.is_some() {
            0
        } else {
            number(file.size.as_ref()).unwrap_or_default()
        },
        modified: parse_time(&file.modified_time).unwrap_or(SystemTime::UNIX_EPOCH),
        version,
        web_url: file.web_view_link.clone(),
        export,
    })
}

/// The last entry of the feed for each file, in the order the files first came.
fn latest_changes(entries: Vec<Change>) -> Vec<Change> {
    let mut latest: Vec<Change> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for change in entries {
        if change.kind == "drive" || change.key().is_empty() {
            continue;
        }
        let key = change.key().to_owned();
        if let Some(&index) = at.get(&key) {
            latest[index] = change;
        } else {
            at.insert(key, latest.len());
            latest.push(change);
        }
    }
    latest
}

/// `items` with one for each path (the first).
fn first_per_path(items: Vec<RemoteItem>) -> Vec<RemoteItem> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(sys::path_key(&item.path)))
        .collect()
}

/// `removed` once each, without the paths that `items` has a file at now.
fn removed_without(removed: Vec<PathBuf>, items: &[RemoteItem]) -> Vec<PathBuf> {
    let mut seen: HashSet<String> = items.iter().map(|item| sys::path_key(&item.path)).collect();
    removed
        .into_iter()
        .filter(|path| seen.insert(sys::path_key(path)))
        .collect()
}

/// What an answer that is not a success means: Drive says "slow down" and "too big to export"
/// with a 403, and why in the body.
fn failure(reply: &Reply) -> Error {
    let body: ErrorBody = serde_json::from_slice(&reply.body).unwrap_or_default();
    let reasons: Vec<&str> = body
        .error
        .errors
        .iter()
        .map(|reason| reason.reason.as_str())
        .collect();
    if reply.status == 403 && reasons.contains(&EXPORT_TOO_BIG) {
        return Error::TooLarge;
    }
    if matches!(reply.status, 403 | 429)
        && reasons.iter().any(|reason| RATE_LIMITED.contains(reason))
    {
        let message: String = body.error.message.chars().take(200).collect();
        return Error::throttled(
            PROVIDER,
            reply.retry_after(),
            format!("HTTP {}: {}: {message}", reply.status, reasons.join(",")),
        );
    }
    reply.error()
}

impl Connector for Google {
    fn provider(&self) -> Provider {
        PROVIDER
    }

    fn browse(&self, under: Option<&RemoteFolder>) -> Result<Vec<RemoteFolder>> {
        let Some(under) = under else {
            return self.tops();
        };
        let id = Id::parse(&under.id)?;
        let mut folders: Vec<RemoteFolder> = if id.place == Place::SharedDrives {
            self.drives(&under.path)?
                .iter()
                .map(Self::drive_folder)
                .collect()
        } else {
            let parent = match id.place {
                Place::MyDrive => self.my_root(id.session)?,
                _ => id.file.clone(),
            };
            let drive = id.drive_id();
            let never = AtomicBool::new(false);
            self.children(id.session, &parent, drive.as_deref(), true, &never)?
                .into_iter()
                .map(|child| RemoteFolder {
                    id: Id::of(id.session, Place::Folder, &child.file.id, drive.as_deref()).text(),
                    path: under.path.join(&child.shown),
                    web_url: child.file.web_view_link,
                })
                .collect()
        };
        sort_folders(&mut folders);
        Ok(folders)
    }

    fn resolve(&self, path: &Path) -> Result<Resolved> {
        let miss = || Error::not_found(PROVIDER, "no such place in this account");
        let virtual_path = parse_virtual(path)
            .filter(|parsed| {
                parsed.provider == PROVIDER
                    && parsed.label.to_lowercase() == self.label.to_lowercase()
            })
            .ok_or_else(miss)?;
        let parts: Vec<String> = virtual_path
            .rest
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        let (mut current, used) = self.top(&parts)?;
        let rest = &parts[used..];
        let never = AtomicBool::new(false);
        for (index, part) in rest.iter().enumerate() {
            let id = Id::parse(&current.id)?;
            if id.place == Place::SharedDrives {
                return Err(miss());
            }
            let parent = match id.place {
                Place::MyDrive => self.my_root(id.session)?,
                _ => id.file.clone(),
            };
            let drive = id.drive_id();
            let wanted = part.to_lowercase();
            let found = self
                .children(id.session, &parent, drive.as_deref(), false, &never)?
                .into_iter()
                .find(|child| child.shown.to_lowercase() == wanted)
                .ok_or_else(miss)?;
            let found_path = current.path.join(&found.shown);
            let last = index + 1 == rest.len();
            match found.kind {
                Kind::Folder => {
                    current = RemoteFolder {
                        id: Id::of(id.session, Place::Folder, &found.file.id, drive.as_deref())
                            .text(),
                        path: found_path,
                        web_url: found.file.web_view_link,
                    };
                }
                kind if last => {
                    return remote_item(id.session, &found.file, kind, found_path)
                        .map(Resolved::File)
                        .ok_or_else(miss);
                }
                _ => return Err(miss()),
            }
        }
        Ok(Resolved::Folder(current))
    }

    fn changes(
        &self,
        root: &RemoteFolder,
        cursor: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<Changes> {
        let id = Id::parse(&root.id)?;
        let feed = Feed::of(&id);
        if let Some(cursor) = cursor
            && let Some(changes) = self.incremental(root, &id, &feed, cursor, cancel)?
        {
            return Ok(changes);
        }
        self.full(root, &id, &feed, cancel)
    }

    fn download(&self, item: &RemoteItem, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let id = Id::parse(&item.id)?;
        let request = if let Some(format) = item.export {
            self.request(&format!("/files/{}/export", encode(&id.file)))
                .query("mimeType", format.mime())
        } else {
            if item.size > max {
                return Err(Error::TooLarge);
            }
            self.request(&format!("/files/{}", encode(&id.file)))
                .query("alt", "media")
                .query("supportsAllDrives", "true")
        };
        let reply = self
            .session_of(id.session)?
            .download(&request, max, cancel)?;
        if reply.is_success() {
            Ok(reply.body)
        } else {
            Err(failure(&reply))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Mutex, atomic::AtomicUsize},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    use super::*;
    use crate::{
        sources::{
            Secrets,
            testing::{Answer, Mock, Res, Seen},
        },
        testing::temp_dir,
    };

    const ID: &str = "0123456789abcdef";
    /// The top of the test account's own Drive.
    const MY: &str = r"\\Google Drive\jan@acme.com\My Drive";
    /// The top of the test account.
    const TOP: &str = r"\\Google Drive\jan@acme.com";
    /// Far in the future: seconds since the Unix epoch.
    const FAR: u64 = 4_102_444_800;
    const DOC: &str = "application/vnd.google-apps.document";
    const SHEET: &str = "application/vnd.google-apps.spreadsheet";
    const SLIDES: &str = "application/vnd.google-apps.presentation";
    const FORM: &str = "application/vnd.google-apps.form";
    const SHORTCUT: &str = "application/vnd.google-apps.shortcut";
    const FILES: &str = "/drive/v3/files";
    const CHANGES: &str = "/drive/v3/changes";
    const START: &str = "/drive/v3/changes/startPageToken";
    const DRIVES: &str = "/drive/v3/drives";
    const FIELDS: &str = "id,name,mimeType,size,modifiedTime,md5Checksum,version,webViewLink,parents,trashed,shortcutDetails";

    /// A throwaway RSA-2048 key, PKCS#8, as the base64 of its DER (the same as the one the tests
    /// of `auth` sign with).
    const KEY_PKCS8: &str = "\
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCTbVpCHMzYFU5n8pHQcv9P\
        dv0xXP26q1IceyO02qYsvghIeoJkvsnaHAk+1NXPDdPvyHiUFJrDyy6DyffuxkffGdZIUuhz\
        l3Nl7Iw0oX0fk+S+syYj1X7p5/pp3VaE2IXed8F2yGJg/5QoGPQu/lPwpeKUHC4dRsanlYde\
        EijQChiG+LuLCGGlOeqPc0SOORiEu54PvJSwnTPhytr/EY0d4GcYQF/ky2J40lf3JS5/+eUs\
        haviJ52/toWC7v06eD2AO749WE+J0IlAouJNpi9Z66tFx1S9s8/81QFieW6jfzS4GwGPoXxq\
        hM11BDmQZ9CcBXhjZdoC1fE27x9zVO65AgMBAAECggEADKfkiaxjQWGC25WNQvG8TRwP3D75\
        YR73643+oLXscgbWOzKZIwDl3x1tBcHLoPy05u60uzGRn6E/mvyplgvbe6GCLa9AWTv1IhjO\
        aG48iYtupZhHe+gF/xp0+sWPedQEmfZ52zKUj3MhStfpjmcy2YPEEabhpo2+3AAQINk6O7Gg\
        zanTgNrI7nCX9gVHEh+inIz0C0AbyjCXzjf8iCeK5t7tzOa6Gja034+GRnfSW/kIb9YnoTMi\
        6qEIR7/Fx0ZUUUO18nd9ajXgfk2tHzO3d2OlfstFi6pz7+OmjdxygTJRdNQsNTRkdLE4blh4\
        Tb2qw3DZuvqFI1UcZG6Wx/CdKQKBgQDI9ym9b/Gmt+DLtLUI+cCV+O0xHIyBeW2/Yya0yG9g\
        d9lWN2u8k5vEurU4b8+rHQG3IK08CipyOmMABNDCfelJalKyIAPahKnqi6x+bV9jftPC+KgA\
        OLOhDRIGSGwWQS7J1RDwqmnNvUAmHjJTiqNeLNFeviqAhPKS4KLJOm+uAwKBgQC7zNhQKYuu\
        xIIOFNbvzJbfXSPaa8OMbAre71DvgyqLXfVhVdcj9PXHI2KoxB8lHRq+V6BmxcC8mFlN8YLn\
        U844obHAY7QE0sQHQ75D++d7icY8GQgy/JUtpZxIeqesw0oEc/AVBNw8mM56CbJhghU8yAsA\
        zv4Blizp9g9mCIIBkwKBgCaeaKUAyB1TpJ1AwrFQ3VN0nJAdflq7LP3kXeHLyqttHJTW3ZtF\
        el+ZyY1o3y1wy42Xd/LbuUBuO+wbAMr/Sz9ScUXNpS/u4oAyCxnYhsYl7ye+hPpV6x791gLj\
        E/JK4GTkzvaQqPhib9tjXiRzteU5E5rzTFOaOMtE48NruV5lAoGBAIrjUAbY8ujpg5WOa/ck\
        w1+lrmJW2GP9c3y0WJMJ2mj/r/2wUk/RVgNUdB6EDNSR1bl3bLUVAxl3QnSWbE1QeW8AhkjW\
        c8gtZ7RHsWrt3aBLoEPJ73plup3roM0piOAH/bGVXLTux0I5cFpo2XerkLFG8HxEmS3rNoRA\
        6dp36E3pAoGAEVZ0k5+khDMBbfAf3WHxP8b2D1cP5KCNaKj/OU+Qq6xdl8jRhmyQsS2CVdnP\
        UrzudCy8mocoSHSgcpW2gLXXOPB8fDosttfwJvQVkoxL0nq5JDjkqAkTEHvgFFt+lr24+HNC\
        8BkM0yJxyllgO6P7tvM5aExxmnKuaIML2FmimLs=\
    ";

    // ---- the account, the fake service, the connector over it ----

    fn account(sign_in: SignIn) -> Account {
        Account {
            id: ID.to_owned(),
            provider: Provider::GoogleDrive,
            label: "jan@acme.com".to_owned(),
            sign_in,
        }
    }

    fn delegated() -> Account {
        account(SignIn::GoogleDelegated {
            client_id: "cid".to_owned(),
        })
    }

    fn pem(body: &str) -> String {
        let mut text = "-----BEGIN PRIVATE KEY-----\n".to_owned();
        for chunk in body.as_bytes().chunks(64) {
            text.push_str(&String::from_utf8_lossy(chunk));
            text.push('\n');
        }
        text.push_str("-----END PRIVATE KEY-----\n");
        text
    }

    /// A service account that acts as `users`, with a key file in a fresh folder.
    fn service(users: &[&str]) -> Res<Account> {
        let key_file = temp_dir("google-key").join("google.json");
        let key = json!({
            "type": "service_account",
            "client_email": "robot@project.iam.example",
            "private_key": pem(KEY_PKCS8),
            "token_uri": "https://unused.example/token",
        });
        fs::write(&key_file, key.to_string())?;
        Ok(account(SignIn::GoogleServiceAccount {
            key_file,
            users: users.iter().map(|user| (*user).to_owned()).collect(),
        }))
    }

    fn refresh_secrets() -> Secrets {
        Secrets::default()
            .with_refresh_token("rt-0")
            .with_client_secret("sec-0")
    }

    fn error_body(status: u16, reason: &str) -> Value {
        json!({"error": {"code": status, "message": "a message", "errors": [{"reason": reason}]}})
    }

    /// What the token endpoint says: for a service account's JWT a token named after the user it
    /// is for, otherwise one for the person.
    fn token(seen: &Seen) -> Answer {
        let user = seen.field("assertion").and_then(|jwt| {
            let claims = URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1)?).ok()?;
            let claims: Value = serde_json::from_slice(&claims).ok()?;
            claims["sub"].as_str().map(str::to_owned)
        });
        let access = user.map_or_else(|| "at-delegated".to_owned(), |user| format!("at-{user}"));
        Answer::json(200, &json!({"access_token": access, "expires_in": 3600}))
    }

    /// A file with bytes of its own.
    fn file(id: &str, name: &str, mime: &str, parent: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "mimeType": mime,
            "parents": [parent],
            "size": "5",
            "modifiedTime": "2024-01-02T03:04:05.000Z",
            "md5Checksum": format!("md5-{id}"),
            "version": "3",
            "webViewLink": format!("https://drive.google.com/file/d/{id}/view"),
        })
    }

    fn text(id: &str, name: &str, parent: &str) -> Value {
        file(id, name, "text/plain", parent)
    }

    fn folder(id: &str, name: &str, parent: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "mimeType": FOLDER,
            "parents": [parent],
            "modifiedTime": "2024-01-02T03:04:05.000Z",
            "webViewLink": format!("https://drive.google.com/drive/folders/{id}"),
        })
    }

    /// A Google Docs, Sheets, Slides... file: no size, no hash.
    fn native(id: &str, name: &str, mime: &str, parent: &str) -> Value {
        json!({
            "id": id,
            "name": name,
            "mimeType": mime,
            "parents": [parent],
            "version": "9",
            "modifiedTime": "2024-02-03T04:05:06.000Z",
            "webViewLink": format!("https://docs.google.com/d/{id}/edit"),
        })
    }

    fn gone(id: &str) -> Value {
        json!({"changeType": "file", "fileId": id, "removed": true})
    }

    fn changed(file: &Value) -> Value {
        json!({"changeType": "file", "fileId": file["id"], "removed": false, "file": file})
    }

    /// `files.list` over `files`, `per_page` at a time; the page token is how many came before.
    fn list(files: &[Value], per_page: usize, seen: &Seen) -> Answer {
        let q = seen.param("q").unwrap_or_default();
        let parent = q.split('\'').nth(1).unwrap_or_default().to_owned();
        let folders_only = q.contains(&format!("mimeType='{FOLDER}'"));
        let matching: Vec<&Value> = files
            .iter()
            .filter(|file| {
                file["parents"][0] == parent.as_str()
                    && file["trashed"] != true
                    && (!folders_only || file["mimeType"] == FOLDER)
            })
            .collect();
        let start: usize = seen
            .param("pageToken")
            .and_then(|token| token.parse().ok())
            .unwrap_or(0);
        let page: Vec<&Value> = matching
            .iter()
            .skip(start)
            .take(per_page)
            .copied()
            .collect();
        let mut body = json!({"files": page});
        if start + per_page < matching.len() {
            body["nextPageToken"] = json!((start + per_page).to_string());
        }
        Answer::json(200, &body)
    }

    /// What every test's service does unless it says otherwise: My Drive is `root0`, no shared
    /// drives, the change feed starts at `100`.
    fn standard(files: &[Value], per_page: usize, seen: &Seen) -> Option<Answer> {
        match seen.path() {
            "/drive/v3/files/root" => Some(Answer::json(200, &json!({"id": "root0"}))),
            FILES => Some(list(files, per_page, seen)),
            START => Some(Answer::json(200, &json!({"startPageToken": "100"}))),
            DRIVES => Some(Answer::json(200, &json!({"drives": []}))),
            _ => None,
        }
    }

    /// The connector, the service it talks to, and the waits it was asked to make.
    struct Rig {
        google: Google,
        mock: Mock,
        waits: Arc<Mutex<Vec<Duration>>>,
    }

    /// A connector for `account` over a service that answers with `handler` (and the token
    /// endpoint, unless `handler` does).
    fn start(
        account: &Account,
        secrets: &Secrets,
        handler: impl Fn(&Seen) -> Option<Answer> + Send + Sync + 'static,
    ) -> Res<Rig> {
        let mock = Mock::start(move |seen| {
            handler(seen).unwrap_or_else(|| {
                if seen.path() == "/token" {
                    token(seen)
                } else {
                    Answer::json(404, &error_body(404, "notFound"))
                }
            })
        })?;
        let store = TokenStore::new(&temp_dir("google"));
        store.save(&account.id, secrets)?;
        let waits = Arc::new(Mutex::new(Vec::new()));
        let noted = Arc::clone(&waits);
        let http = Http::with_pause(PROVIDER, move |wait| {
            if let Ok(mut waits) = noted.lock() {
                waits.push(wait);
            }
        });
        let base = mock.url();
        let endpoints = Endpoints {
            api: format!("{base}/drive/v3"),
            authorize: format!("{base}/authorize"),
            token: format!("{base}/token"),
            service_token: Some(format!("{base}/token")),
        };
        let google = Google::with(account, &store, &http, endpoints)?;
        Ok(Rig {
            google,
            mock,
            waits,
        })
    }

    /// A person's connector over `files`.
    fn over(files: Vec<Value>, per_page: usize) -> Res<Rig> {
        start(&delegated(), &refresh_secrets(), move |seen| {
            standard(&files, per_page, seen)
        })
    }

    fn waited(rig: &Rig) -> Vec<Duration> {
        rig.waits
            .lock()
            .map(|waits| waits.clone())
            .unwrap_or_default()
    }

    fn never() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// The virtual path of `rest` (parts joined with `/`) in the test account's own Drive.
    fn my(rest: &str) -> PathBuf {
        rest.split('/')
            .filter(|part| !part.is_empty())
            .fold(PathBuf::from(MY), |path, part| child(&path, part))
    }

    /// The folder at `path`.
    fn at(rig: &Rig, path: &Path) -> Res<RemoteFolder> {
        Ok(rig.google.folder(path)?)
    }

    /// `paths` below `base`, as text, in order.
    fn below_base<'a>(paths: impl Iterator<Item = &'a PathBuf>, base: &str) -> Vec<String> {
        let mut shown: Vec<String> = paths
            .map(|path| {
                path.strip_prefix(base).map_or_else(
                    |_| path.display().to_string(),
                    |rest| rest.display().to_string(),
                )
            })
            .collect();
        shown.sort();
        shown
    }

    fn items_of(changes: &Changes, base: &str) -> Vec<String> {
        below_base(changes.items.iter().map(|item| &item.path), base)
    }

    fn removed_of(changes: &Changes, base: &str) -> Vec<String> {
        below_base(changes.removed.iter(), base)
    }

    fn drive_paths(rig: &Rig) -> Vec<String> {
        rig.mock
            .seen()
            .iter()
            .map(|seen| seen.path().to_owned())
            .filter(|path| path.starts_with("/drive"))
            .collect()
    }

    /// A downloadable item for the Drive file `id` of the first user.
    fn item(id: &str, size: u64, export: Option<Export>) -> RemoteItem {
        RemoteItem {
            id: Id::of(0, Place::Folder, id, None).text(),
            path: my("x"),
            size,
            modified: SystemTime::UNIX_EPOCH,
            version: String::new(),
            web_url: String::new(),
            export,
        }
    }

    // ---- sign-in ----

    #[test]
    fn a_person_signs_in_with_the_browser_flow_and_the_read_only_scope() -> Res {
        let grants = grants(&delegated(), &Endpoints::default())?;
        let [Grant::Browser(browser)] = grants.as_slice() else {
            return Err("one browser grant".into());
        };
        assert_eq!(
            browser.authorize_url,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(browser.token_url, "https://oauth2.googleapis.com/token");
        assert_eq!(
            browser.scope,
            "https://www.googleapis.com/auth/drive.readonly"
        );
        assert_eq!(browser.client_id, "cid");
        assert_eq!(
            browser.authorize_extra,
            [
                ("access_type".to_owned(), "offline".to_owned()),
                ("prompt".to_owned(), "consent".to_owned())
            ]
        );
        assert_eq!(browser.client_auth, ClientAuth::Body);
        assert_eq!((browser.port, browser.pkce), (0, true));
        assert!(browser.redirect_path.is_empty());
        assert_eq!(browser.redirect_host, "127.0.0.1");
        let store = TokenStore::new(&temp_dir("google-session"));
        assert!(session(&delegated(), &store).is_ok());
        Ok(())
    }

    #[test]
    fn a_service_account_has_one_grant_for_each_user() -> Res {
        let account = service(&["a@acme.com", "b@acme.com"])?;
        let grants = grants(&account, &Endpoints::default())?;
        assert_eq!(grants.len(), 2);
        let users: Vec<&str> = grants
            .iter()
            .filter_map(|grant| match grant {
                Grant::ServiceAccount(service) => {
                    assert_eq!(
                        service.scope,
                        "https://www.googleapis.com/auth/drive.readonly"
                    );
                    assert!(service.token_url.is_none());
                    Some(service.user.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(users, ["a@acme.com", "b@acme.com"]);
        let store = TokenStore::new(&temp_dir("google-session"));
        assert!(session(&account, &store).is_ok());
        Ok(())
    }

    #[test]
    fn an_account_that_does_not_fit_is_a_plain_message() {
        let store = TokenStore::new(&temp_dir("google-misfit"));
        let mut other = delegated();
        other.sign_in = SignIn::DropboxDelegated {
            app_key: "k".to_owned(),
        };
        let nobody = account(SignIn::GoogleServiceAccount {
            key_file: PathBuf::from("key.json"),
            users: Vec::new(),
        });
        for account in [other, nobody] {
            assert!(matches!(
                Google::new(&account, &store).err(),
                Some(Error::Local(crate::Error::BadRequest(_)))
            ));
            assert!(matches!(
                session(&account, &store).err(),
                Some(Error::Local(crate::Error::BadRequest(_)))
            ));
        }
    }

    // ---- listing ----

    #[test]
    fn a_listing_follows_every_page_and_names_files_by_their_paths() -> Res {
        let files = vec![
            text("a", "a.txt", "root0"),
            text("b", "b.txt", "root0"),
            text("c", "c.txt", "root0"),
            folder("s1", "Sub", "root0"),
            text("d", "d.txt", "root0"),
            json!({"id": "v", "name": "v.bin", "mimeType": "application/octet-stream",
                "parents": ["root0"], "size": "3", "version": "7",
                "modifiedTime": "2024-01-02T03:04:05Z"}),
            text("e", "e.txt", "s1"),
            text("q", "what?.txt", "s1"),
        ];
        let rig = over(files, 2)?;
        let root = at(&rig, &my(""))?;
        let changes = rig.google.changes(&root, None, &never())?;
        assert!(changes.full && changes.removed.is_empty());
        assert_eq!(changes.cursor, "100");
        let mut got: Vec<PathBuf> = changes.items.iter().map(|item| item.path.clone()).collect();
        let mut want = vec![
            my("a.txt"),
            my("b.txt"),
            my("c.txt"),
            my("d.txt"),
            my("v.bin"),
            my("Sub/e.txt"),
            my("Sub/what?.txt"),
        ];
        got.sort();
        want.sort();
        assert_eq!(got, want, "folders are not items");
        let a = changes
            .items
            .iter()
            .find(|item| item.path == my("a.txt"))
            .ok_or("a.txt")?;
        assert_eq!(a.size, 5);
        assert_eq!(a.version, "md5-a", "the hash is the version");
        assert_eq!(
            a.modified,
            parse_time("2024-01-02T03:04:05Z").ok_or("time")?
        );
        assert_eq!(a.web_url, "https://drive.google.com/file/d/a/view");
        assert_eq!(a.export, None);
        let v = changes
            .items
            .iter()
            .find(|item| item.path == my("v.bin"))
            .ok_or("v.bin")?;
        assert_eq!(v.version, "7", "no hash: the revision is the version");
        // The cursor is taken before the listing starts.
        let order = drive_paths(&rig);
        assert_eq!(order.first().map(String::as_str), Some(START));
        // The request: the folder, the biggest page, the small field mask.
        let root_pages: Vec<Seen> = rig
            .mock
            .seen_at(FILES)
            .into_iter()
            .filter(|seen| {
                seen.param("q").as_deref() == Some("'root0' in parents and trashed=false")
            })
            .collect();
        let tokens: Vec<Option<String>> = root_pages.iter().map(|s| s.param("pageToken")).collect();
        assert_eq!(tokens, [None, Some("2".to_owned()), Some("4".to_owned())]);
        let first = &root_pages[0];
        assert_eq!(first.param("pageSize").as_deref(), Some("1000"));
        assert_eq!(first.param("supportsAllDrives").as_deref(), Some("true"));
        assert_eq!(
            first.param("includeItemsFromAllDrives").as_deref(),
            Some("true")
        );
        let fields = first.param("fields").ok_or("fields")?;
        assert!(
            fields.contains("nextPageToken") && fields.contains(FIELDS),
            "{fields}"
        );
        assert_eq!(first.header("authorization"), Some("Bearer at-delegated"));
        Ok(())
    }

    #[test]
    fn a_second_file_of_one_name_is_numbered() -> Res {
        let files = vec![
            text("b1", "a.txt", "root0"),
            text("a1", "a.txt", "root0"),
            folder("f1", "A.TXT", "root0"),
            native("n1", "Plan", DOC, "root0"),
            text("n2", "Plan.docx", "root0"),
        ];
        let rig = over(files, 1000)?;
        let root = at(&rig, &my(""))?;
        let changes = rig.google.changes(&root, None, &never())?;
        assert_eq!(
            items_of(&changes, MY),
            ["Plan (2).docx", "Plan.docx", "a (2).txt", "a (3).txt"],
            "the folder `A.TXT` has the first name"
        );
        Ok(())
    }

    #[test]
    fn google_documents_are_listed_as_office_files_and_forms_and_shortcuts_are_skipped() -> Res {
        let mut shortcut = native("sc", "Link to a", SHORTCUT, "root0");
        shortcut["shortcutDetails"] = json!({"targetId": "a", "targetMimeType": "text/plain"});
        let files = vec![
            native("d1", "Plan", DOC, "root0"),
            native("s1", "Budget", SHEET, "root0"),
            native("p1", "Deck", SLIDES, "root0"),
            native("f1", "Survey", FORM, "root0"),
            native(
                "x1",
                "Sketch",
                "application/vnd.google-apps.drawing",
                "root0",
            ),
            native("x2", "Site", "application/vnd.google-apps.site", "root0"),
            shortcut,
            text("a", "a.txt", "root0"),
        ];
        let rig = over(files, 1000)?;
        let root = at(&rig, &my(""))?;
        let changes = rig.google.changes(&root, None, &never())?;
        assert_eq!(
            items_of(&changes, MY),
            ["Budget.xlsx", "Deck.pptx", "Plan.docx", "a.txt"]
        );
        let by_name = |name: &str| changes.items.iter().find(|item| item.path == my(name));
        for (name, export) in [
            ("Plan.docx", Export::Docx),
            ("Budget.xlsx", Export::Xlsx),
            ("Deck.pptx", Export::Pptx),
        ] {
            let found = by_name(name).ok_or(name)?;
            assert_eq!(found.export, Some(export), "{name}");
            assert_eq!(found.size, 0, "{name}: no size of its own");
            assert_eq!(found.version, "9", "{name}: the revision");
            assert_eq!(
                found.modified,
                parse_time("2024-02-03T04:05:06Z").ok_or("time")?
            );
        }
        assert_eq!(by_name("a.txt").ok_or("a.txt")?.export, None);
        Ok(())
    }

    // ---- the change feed ----

    #[test]
    fn the_change_feed_gives_what_changed_what_is_gone_and_what_moved() -> Res {
        let files = vec![
            text("a", "a.txt", "root0"),
            text("m1", "m.txt", "root0"),
            folder("s1", "Sub", "root0"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            match (seen.path(), seen.param("pageToken").as_deref()) {
                (CHANGES, Some("100")) => {
                    let mut moved = text("m1", "m-renamed.txt", "s1");
                    moved["md5Checksum"] = json!("md5-new");
                    Some(Answer::json(
                        200,
                        &json!({"changes": [gone("a"), changed(&moved)], "nextPageToken": "101"}),
                    ))
                }
                (CHANGES, Some("101")) => Some(Answer::json(
                    200,
                    &json!({"changes": [changed(&text("n", "n.txt", "root0"))], "newStartPageToken": "102"}),
                )),
                _ => standard(&files, 1000, seen),
            }
        })?;
        let root = at(&rig, &my(""))?;
        let first = rig.google.changes(&root, None, &never())?;
        assert!(first.full);
        assert_eq!(first.cursor, "100");

        let second = rig.google.changes(&root, Some(&first.cursor), &never())?;
        assert!(!second.full);
        assert_eq!(items_of(&second, MY), [r"Sub\m-renamed.txt", "n.txt"]);
        assert_eq!(
            removed_of(&second, MY),
            ["a.txt", "m.txt"],
            "gone and moved away"
        );
        assert_eq!(second.cursor, "102", "the new start page token");
        let moved = second
            .items
            .iter()
            .find(|item| item.path == my("Sub/m-renamed.txt"))
            .ok_or("moved")?;
        assert_eq!(moved.version, "md5-new");

        let feed = rig.mock.seen_at(CHANGES);
        assert_eq!(feed.len(), 2);
        assert_eq!(feed[0].param("pageToken").as_deref(), Some("100"));
        assert_eq!(feed[1].param("pageToken").as_deref(), Some("101"));
        assert_eq!(feed[0].param("includeRemoved").as_deref(), Some("true"));
        assert_eq!(feed[0].param("supportsAllDrives").as_deref(), Some("true"));
        assert_eq!(feed[0].param("pageSize").as_deref(), Some("1000"));
        assert_eq!(feed[0].param("restrictToMyDrive").as_deref(), Some("true"));
        assert_eq!(feed[0].param("driveId"), None);
        let fields = feed[0].param("fields").ok_or("fields")?;
        assert!(
            fields.contains("newStartPageToken") && fields.contains("changes("),
            "{fields}"
        );
        assert!(fields.contains("file(id,name,mimeType"), "{fields}");
        Ok(())
    }

    #[test]
    fn each_call_goes_on_from_the_page_token_the_one_before_ended_with() -> Res {
        let rig = start(&delegated(), &refresh_secrets(), |seen| {
            if seen.path() == CHANGES {
                let next: u32 = seen.param("pageToken")?.parse().ok()?;
                return Some(Answer::json(
                    200,
                    &json!({"changes": [], "newStartPageToken": (next + 1).to_string()}),
                ));
            }
            standard(&[], 1000, seen)
        })?;
        let root = at(&rig, &my(""))?;
        let first = rig.google.changes(&root, None, &never())?;
        let second = rig.google.changes(&root, Some(&first.cursor), &never())?;
        let third = rig.google.changes(&root, Some(&second.cursor), &never())?;
        assert_eq!(
            (
                first.cursor.as_str(),
                second.cursor.as_str(),
                third.cursor.as_str()
            ),
            ("100", "101", "102")
        );
        assert!(!second.full && !third.full);
        assert!(second.items.is_empty() && second.removed.is_empty());
        let sent: Vec<Option<String>> = rig
            .mock
            .seen_at(CHANGES)
            .iter()
            .map(|seen| seen.param("pageToken"))
            .collect();
        assert_eq!(sent, [Some("100".to_owned()), Some("101".to_owned())]);
        Ok(())
    }

    #[test]
    fn a_page_token_drive_no_longer_takes_gives_a_full_listing() -> Res {
        for status in [400, 404] {
            let files = vec![text("a", "a.txt", "root0")];
            let rig = start(&delegated(), &refresh_secrets(), move |seen| {
                if seen.path() == CHANGES {
                    return Some(Answer::json(status, &error_body(status, "invalid")));
                }
                standard(&files, 1000, seen)
            })?;
            let root = at(&rig, &my(""))?;
            let changes = rig.google.changes(&root, Some("stale"), &never())?;
            assert!(changes.full, "{status}");
            assert_eq!(changes.cursor, "100");
            assert_eq!(items_of(&changes, MY), ["a.txt"]);
            assert_eq!(rig.mock.seen_at(CHANGES).len(), 1, "{status}");
        }
        Ok(())
    }

    #[test]
    fn a_removal_whose_path_is_not_known_gives_a_full_listing() -> Res {
        let files = vec![text("a", "a.txt", "root0")];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            match seen.path() {
                CHANGES => Some(Answer::json(
                    200,
                    &json!({"changes": [gone("never-seen")], "newStartPageToken": "101"}),
                )),
                START => Some(Answer::json(200, &json!({"startPageToken": "500"}))),
                _ => standard(&files, 1000, seen),
            }
        })?;
        let root = at(&rig, &my(""))?;
        // A new connector has seen no listing: it cannot tell where `never-seen` was.
        let changes = rig.google.changes(&root, Some("100"), &never())?;
        assert!(changes.full);
        assert_eq!(
            changes.cursor, "500",
            "the start token taken before the listing"
        );
        assert_eq!(items_of(&changes, MY), ["a.txt"]);
        Ok(())
    }

    #[test]
    fn a_trashed_file_is_removed_and_a_renamed_folder_is_listed_again_under_its_new_name() -> Res {
        let files = vec![
            text("a", "a.txt", "root0"),
            folder("s1", "Sub", "root0"),
            text("e", "e.txt", "s1"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            if seen.path() == CHANGES {
                let mut trashed = text("a", "a.txt", "root0");
                trashed["trashed"] = json!(true);
                return Some(Answer::json(
                    200,
                    &json!({"changes": [changed(&trashed), changed(&folder("s1", "Sub2", "root0"))],
                        "newStartPageToken": "101"}),
                ));
            }
            standard(&files, 1000, seen)
        })?;
        let root = at(&rig, &my(""))?;
        let first = rig.google.changes(&root, None, &never())?;
        let second = rig.google.changes(&root, Some(&first.cursor), &never())?;
        assert!(!second.full);
        assert_eq!(removed_of(&second, MY), ["Sub", "a.txt"]);
        assert_eq!(items_of(&second, MY), [r"Sub2\e.txt"]);
        Ok(())
    }

    #[test]
    fn a_root_below_the_drive_ignores_the_rest_of_the_drives_feed() -> Res {
        let files = vec![
            folder("s1", "Sub", "root0"),
            folder("o1", "Other", "root0"),
            text("x", "x.txt", "s1"),
            text("y", "y.txt", "o1"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            if seen.path() == CHANGES {
                return Some(Answer::json(
                    200,
                    &json!({"changes": [
                        changed(&text("y2", "y2.txt", "o1")),
                        changed(&text("x2", "x2.txt", "s1"))], "newStartPageToken": "101"}),
                ));
            }
            if seen.path() == "/drive/v3/files/o1" {
                return Some(Answer::json(
                    200,
                    &json!({"id": "o1", "name": "Other", "parents": ["root0"]}),
                ));
            }
            standard(&files, 1000, seen)
        })?;
        let root = at(&rig, &my("Sub"))?;
        let first = rig.google.changes(&root, None, &never())?;
        assert_eq!(items_of(&first, MY), [r"Sub\x.txt"]);
        let second = rig.google.changes(&root, Some(&first.cursor), &never())?;
        assert!(!second.full);
        assert!(second.removed.is_empty());
        assert_eq!(
            items_of(&second, MY),
            [r"Sub\x2.txt"],
            "y2.txt is outside the root"
        );
        // The root's own id is the top of the paths: its folders are not asked for.
        assert!(rig.mock.seen_at("/drive/v3/files/s1").is_empty());
        assert_eq!(rig.mock.seen_at("/drive/v3/files/o1").len(), 1);
        Ok(())
    }

    #[test]
    fn a_new_file_in_a_folder_the_connector_has_not_seen_has_its_folders_asked_for() -> Res {
        let files = vec![folder("s1", "Sub", "root0")];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            match seen.path() {
                CHANGES => Some(Answer::json(
                    200,
                    &json!({"changes": [
                    changed(&text("n", "n.txt", "deep")),
                    changed(&text("o", "o.txt", "elsewhere"))], "newStartPageToken": "101"}),
                )),
                "/drive/v3/files/deep" => Some(Answer::json(
                    200,
                    &json!({"id": "deep", "name": "Deep", "parents": ["s1"]}),
                )),
                "/drive/v3/files/elsewhere" => Some(Answer::json(
                    200,
                    &json!({"id": "elsewhere", "name": "Shared with me"}),
                )),
                _ => standard(&files, 1000, seen),
            }
        })?;
        let root = at(&rig, &my(""))?;
        let first = rig.google.changes(&root, None, &never())?;
        let second = rig.google.changes(&root, Some(&first.cursor), &never())?;
        assert!(!second.full);
        assert_eq!(
            items_of(&second, MY),
            [r"Sub\Deep\n.txt"],
            "o.txt is in no folder of this Drive"
        );
        let asked = rig.mock.seen_at("/drive/v3/files/deep");
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].param("fields").as_deref(), Some("id,name,parents"));
        assert_eq!(asked[0].param("supportsAllDrives").as_deref(), Some("true"));
        Ok(())
    }

    // ---- shared drives ----

    /// Two pages of shared drives: two called `Team` and one `Alpha`.
    fn drives_answer(seen: &Seen) -> Answer {
        if seen.param("pageToken").as_deref() == Some("t2") {
            Answer::json(
                200,
                &json!({"drives": [{"id": "d1", "name": "Team"}, {"id": "d3", "name": "Alpha"}]}),
            )
        } else {
            Answer::json(
                200,
                &json!({"drives": [{"id": "d2", "name": "Team"}], "nextPageToken": "t2"}),
            )
        }
    }

    #[test]
    fn the_top_of_an_account_is_my_drive_and_each_shared_drive_by_name() -> Res {
        let rig = start(&delegated(), &refresh_secrets(), |seen| {
            if seen.path() == DRIVES {
                return Some(drives_answer(seen));
            }
            standard(&[], 1000, seen)
        })?;
        let top = rig.google.browse(None)?;
        let shown: Vec<String> = top
            .iter()
            .map(|folder| {
                folder
                    .path
                    .strip_prefix(TOP)
                    .map_or_else(|_| String::new(), |p| p.display().to_string())
            })
            .collect();
        assert_eq!(shown, ["Alpha", "My Drive", "Team", "Team (2)"]);
        let pages = rig.mock.seen_at(DRIVES);
        assert_eq!(pages.len(), 2, "every page");
        assert_eq!(pages[0].param("pageSize").as_deref(), Some("100"));
        assert_eq!(pages[1].param("pageToken").as_deref(), Some("t2"));
        // The second `Team` is the one with the larger id.
        let ids: Vec<String> = top.iter().map(|folder| folder.id.clone()).collect();
        assert_eq!(Id::parse(&ids[2])?.file, "d1");
        assert_eq!(Id::parse(&ids[3])?.file, "d2");
        assert!(top.iter().all(|folder| folder.path.starts_with(TOP)));
        Ok(())
    }

    #[test]
    fn a_shared_drive_is_listed_and_followed_with_its_own_tokens() -> Res {
        let files = vec![
            text("a", "a.txt", "d1"),
            folder("s9", "Docs", "d1"),
            text("b", "b.txt", "s9"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            match seen.path() {
                DRIVES => Some(Answer::json(
                    200,
                    &json!({"drives": [{"id": "d1", "name": "Team"}]}),
                )),
                CHANGES => Some(Answer::json(
                    200,
                    &json!({"changes": [changed(&text("c", "c.txt", "s9"))], "newStartPageToken": "101"}),
                )),
                _ => standard(&files, 1000, seen),
            }
        })?;
        let team = format!(r"{TOP}\Team");
        let root = at(&rig, Path::new(&team))?;
        assert_eq!(Id::parse(&root.id)?.place, Place::SharedDrive);
        let first = rig.google.changes(&root, None, &never())?;
        assert!(first.full);
        assert_eq!(items_of(&first, &team), [r"Docs\b.txt", "a.txt"]);
        let start = rig.mock.seen_at(START);
        assert_eq!(start.len(), 1);
        assert_eq!(start[0].param("driveId").as_deref(), Some("d1"));
        assert_eq!(start[0].param("supportsAllDrives").as_deref(), Some("true"));
        for page in rig.mock.seen_at(FILES) {
            assert_eq!(page.param("corpora").as_deref(), Some("drive"));
            assert_eq!(page.param("driveId").as_deref(), Some("d1"));
            assert_eq!(
                page.param("includeItemsFromAllDrives").as_deref(),
                Some("true")
            );
            assert_eq!(page.param("supportsAllDrives").as_deref(), Some("true"));
        }

        let second = rig.google.changes(&root, Some(&first.cursor), &never())?;
        assert!(!second.full);
        assert_eq!(items_of(&second, &team), [r"Docs\c.txt"]);
        let feed = rig.mock.seen_at(CHANGES);
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].param("driveId").as_deref(), Some("d1"));
        assert_eq!(
            feed[0].param("includeItemsFromAllDrives").as_deref(),
            Some("true")
        );
        assert_eq!(feed[0].param("pageToken").as_deref(), Some("100"));
        assert_eq!(feed[0].param("restrictToMyDrive"), None);
        Ok(())
    }

    // ---- resolve and browse ----

    #[test]
    fn resolve_finds_files_folders_and_shared_drives_and_nothing_else() -> Res {
        let files = vec![
            folder("s1", "Sub", "root0"),
            folder("z1", "Zeta", "root0"),
            folder("a1", "alpha", "root0"),
            text("f1", "a.txt", "root0"),
            text("f2", "b.txt", "s1"),
            folder("d9", "Deep", "s1"),
            text("t1", "t.txt", "d2"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            if seen.path() == DRIVES {
                return Some(drives_answer(seen));
            }
            standard(&files, 1000, seen)
        })?;

        let Resolved::File(file) = rig.google.resolve(&my("Sub/b.txt"))? else {
            return Err("a file".into());
        };
        assert_eq!(file.path, my("Sub/b.txt"));
        assert_eq!(Id::parse(&file.id)?.file, "f2");
        assert_eq!(file.size, 5);

        let Resolved::Folder(sub) = rig
            .google
            .resolve(Path::new(r"\\google drive\JAN@acme.com\my drive\SUB"))?
        else {
            return Err("a folder".into());
        };
        assert_eq!(sub.path, my("Sub"), "the names as Drive has them");
        assert_eq!(Id::parse(&sub.id)?.file, "s1");

        let Resolved::Folder(drive) = rig.google.resolve(Path::new(&format!(r"{TOP}\Team (2)")))?
        else {
            return Err("a shared drive".into());
        };
        assert_eq!(Id::parse(&drive.id)?.file, "d2");
        assert!(rig.google.file(&my("Sub/b.txt")).is_ok());
        let Resolved::File(in_drive) = rig
            .google
            .resolve(Path::new(&format!(r"{TOP}\Team (2)\t.txt")))?
        else {
            return Err("a file in a shared drive".into());
        };
        assert_eq!(Id::parse(&in_drive.id)?.file, "t1");

        for gone in [
            my("Nope"),
            my("Sub/b.txt/deeper"),
            PathBuf::from(r"\\Google Drive\other@acme.com\My Drive"),
            PathBuf::from(r"\\Dropbox\jan@acme.com\My Drive"),
            PathBuf::from(TOP),
            PathBuf::from(r"\\Google Drive\jan@acme.com\No such drive"),
            PathBuf::from(r"C:\Users"),
        ] {
            assert!(
                matches!(rig.google.resolve(&gone), Err(Error::NotFound { .. })),
                "{}",
                gone.display()
            );
        }
        assert!(matches!(
            rig.google.folder(&my("Sub/b.txt")),
            Err(Error::NotFound { .. })
        ));
        assert!(matches!(
            rig.google.file(&my("Sub")),
            Err(Error::NotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn browse_lists_only_the_folders_of_a_folder_by_name() -> Res {
        let files = vec![
            folder("s1", "Sub", "root0"),
            folder("z1", "Zeta", "root0"),
            folder("a1", "alpha", "root0"),
            text("f1", "a.txt", "root0"),
            folder("d9", "Deep", "s1"),
            text("f2", "b.txt", "s1"),
        ];
        let rig = over(files, 1000)?;
        let top = at(&rig, &my(""))?;
        let folders = rig.google.browse(Some(&top))?;
        let paths: Vec<PathBuf> = folders.iter().map(|folder| folder.path.clone()).collect();
        assert_eq!(
            paths,
            [my("alpha"), my("Sub"), my("Zeta")],
            "by name, letter case ignored"
        );
        assert_eq!(
            folders[1].web_url,
            "https://drive.google.com/drive/folders/s1"
        );
        let query = rig
            .mock
            .seen_at(FILES)
            .last()
            .and_then(|seen| seen.param("q"))
            .ok_or("a listing")?;
        assert_eq!(
            query,
            format!("'root0' in parents and trashed=false and mimeType='{FOLDER}'")
        );
        let deeper = rig.google.browse(Some(&folders[1]))?;
        assert_eq!(deeper.len(), 1);
        assert_eq!(deeper[0].path, my("Sub/Deep"));
        Ok(())
    }

    // ---- reading ----

    #[test]
    fn a_file_is_downloaded_whole_up_to_the_size_cap_and_never_beyond() -> Res {
        let rig = start(&delegated(), &refresh_secrets(), |seen| {
            (seen.path() == "/drive/v3/files/fid")
                .then(|| Answer::bytes(200, b"0123456789".to_vec()))
        })?;
        let flag = never();
        // The listing said it is too large: nothing is asked for.
        assert!(matches!(
            rig.google.download(&item("fid", 11, None), 10, &flag),
            Err(Error::TooLarge)
        ));
        assert!(rig.mock.seen_at("/drive/v3/files/fid").is_empty());
        // No size in the listing: the cap stops it while it comes in.
        assert!(matches!(
            rig.google.download(&item("fid", 0, None), 9, &flag),
            Err(Error::TooLarge)
        ));
        // Exactly the cap.
        assert_eq!(
            rig.google.download(&item("fid", 10, None), 10, &flag)?,
            b"0123456789"
        );
        let asked = rig.mock.seen_at("/drive/v3/files/fid");
        let last = asked.last().ok_or("a download")?;
        assert_eq!(last.param("alt").as_deref(), Some("media"));
        assert_eq!(last.param("supportsAllDrives").as_deref(), Some("true"));
        assert_eq!(last.header("authorization"), Some("Bearer at-delegated"));
        Ok(())
    }

    #[test]
    fn a_download_that_is_stopped_asks_for_nothing() -> Res {
        let rig = over(Vec::new(), 1000)?;
        let stopped = AtomicBool::new(true);
        assert!(matches!(
            rig.google.download(&item("fid", 1, None), 10, &stopped),
            Err(Error::Cancelled)
        ));
        assert!(rig.mock.seen().is_empty());
        Ok(())
    }

    #[test]
    fn docs_sheets_and_slides_are_exported_as_office_files() -> Res {
        let files = vec![
            native("d1", "Plan", DOC, "root0"),
            native("s1", "Budget", SHEET, "root0"),
            native("p1", "Deck", SLIDES, "root0"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            if let Some(id) = seen
                .path()
                .strip_prefix("/drive/v3/files/")
                .and_then(|rest| rest.strip_suffix("/export"))
            {
                if id == "big" {
                    return Some(Answer::json(
                        403,
                        &error_body(403, "exportSizeLimitExceeded"),
                    ));
                }
                let mime = seen.param("mimeType").unwrap_or_default();
                return Some(Answer::bytes(200, format!("{id} as {mime}").into_bytes()));
            }
            standard(&files, 1000, seen)
        })?;
        let root = at(&rig, &my(""))?;
        let changes = rig.google.changes(&root, None, &never())?;
        assert_eq!(changes.items.len(), 3);
        for found in &changes.items {
            let format = found.export.ok_or("an export")?;
            let id = Id::parse(&found.id)?.file;
            let bytes = rig.google.download(found, 1 << 20, &never())?;
            assert_eq!(bytes, format!("{id} as {}", format.mime()).into_bytes());
        }
        let asked: Vec<(String, String)> = rig
            .mock
            .seen()
            .iter()
            .filter(|seen| seen.path().ends_with("/export"))
            .map(|seen| {
                (
                    seen.path().to_owned(),
                    seen.param("mimeType").unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(asked.len(), 3);
        for (path, mime) in [
            ("/drive/v3/files/d1/export", Export::Docx.mime()),
            ("/drive/v3/files/s1/export", Export::Xlsx.mime()),
            ("/drive/v3/files/p1/export", Export::Pptx.mime()),
        ] {
            assert!(
                asked.contains(&(path.to_owned(), mime.to_owned())),
                "{path}"
            );
        }
        // Over Google's limit for an export.
        assert!(matches!(
            rig.google
                .download(&item("big", 0, Some(Export::Docx)), 1 << 20, &never()),
            Err(Error::TooLarge)
        ));
        Ok(())
    }

    // ---- failures ----

    #[test]
    fn what_drive_says_with_a_403_or_a_404_is_sorted_by_its_reason() -> Res {
        let cases: [(u16, &str, Option<&str>, &str); 6] = [
            (403, "rateLimitExceeded", Some("3"), "throttled 3"),
            (403, "userRateLimitExceeded", None, "throttled"),
            (403, "sharingRateLimitExceeded", None, "throttled"),
            (403, "insufficientFilePermissions", None, "forbidden"),
            (403, "exportSizeLimitExceeded", None, "toolarge"),
            (404, "notFound", None, "notfound"),
        ];
        for (status, reason, wait, want) in cases {
            let rig = start(&delegated(), &refresh_secrets(), move |seen| {
                (seen.path() == "/drive/v3/files/fid").then(|| {
                    let answer = Answer::json(status, &error_body(status, reason));
                    match wait {
                        Some(wait) => answer.header("Retry-After", wait),
                        None => answer,
                    }
                })
            })?;
            let error = rig
                .google
                .download(&item("fid", 1, None), 4096, &never())
                .err()
                .ok_or("an error")?;
            let got = match &error {
                Error::Throttled {
                    retry_after: Some(wait),
                    ..
                } => format!("throttled {}", wait.as_secs()),
                Error::Throttled {
                    retry_after: None, ..
                } => "throttled".to_owned(),
                Error::Forbidden { .. } => "forbidden".to_owned(),
                Error::NotFound { .. } => "notfound".to_owned(),
                Error::TooLarge => "toolarge".to_owned(),
                other => format!("{other:?}"),
            };
            assert_eq!(got, want, "{reason}");
            let shown = error.to_string();
            assert!(!shown.contains("403") && !shown.contains(reason), "{shown}");
            assert!(waited(&rig).is_empty(), "a 403 is not retried");
        }
        Ok(())
    }

    #[test]
    fn a_429_is_waited_out_and_a_huge_wait_is_left_to_the_caller() -> Res {
        let files = vec![text("a", "a.txt", "root0")];
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let list_files = files.clone();
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            if seen.path() == FILES && counted.fetch_add(1, Ordering::SeqCst) == 0 {
                return Some(
                    Answer::json(429, &error_body(429, "rateLimitExceeded"))
                        .header("Retry-After", "7"),
                );
            }
            standard(&list_files, 1000, seen)
        })?;
        let root = at(&rig, &my(""))?;
        let changes = rig.google.changes(&root, None, &never())?;
        assert_eq!(items_of(&changes, MY), ["a.txt"]);
        assert_eq!(waited(&rig), [Duration::from_secs(7)]);
        assert_eq!(rig.mock.seen_at(FILES).len(), 2);

        let rig = start(&delegated(), &refresh_secrets(), |seen| {
            if seen.path() == FILES {
                return Some(
                    Answer::json(429, &error_body(429, "rateLimitExceeded"))
                        .header("Retry-After", "900"),
                );
            }
            standard(&[], 1000, seen)
        })?;
        let root = at(&rig, &my(""))?;
        let error = rig.google.changes(&root, None, &never());
        assert!(
            matches!(&error, Err(Error::Throttled { retry_after: Some(wait), .. }) if *wait == Duration::from_mins(15)),
            "{:?}",
            error.err()
        );
        assert!(waited(&rig).is_empty());
        assert_eq!(rig.mock.seen_at(FILES).len(), 1);
        Ok(())
    }

    #[test]
    fn a_rejected_token_is_refreshed_once_and_a_refused_refresh_needs_a_new_sign_in() -> Res {
        let secrets = refresh_secrets().with_access_token("at-stale", FAR);
        let rig = start(&delegated(), &secrets, |seen| match seen.path() {
            "/token" => Some(Answer::json(
                200,
                &json!({"access_token": "at-fresh", "expires_in": 3600}),
            )),
            DRIVES if seen.header("authorization") == Some("Bearer at-stale") => {
                Some(Answer::json(401, &error_body(401, "authError")))
            }
            _ => standard(&[], 1000, seen),
        })?;
        let top = rig.google.browse(None)?;
        assert_eq!(top.len(), 1, "My Drive only");
        let asked = rig.mock.seen_at(DRIVES);
        let tokens: Vec<Option<&str>> = asked
            .iter()
            .map(|seen| seen.header("authorization"))
            .collect();
        assert_eq!(tokens, [Some("Bearer at-stale"), Some("Bearer at-fresh")]);
        let refreshed = rig.mock.seen_at("/token");
        assert_eq!(refreshed.len(), 1);
        assert_eq!(
            refreshed[0].field("grant_type").as_deref(),
            Some("refresh_token")
        );
        assert_eq!(refreshed[0].field("refresh_token").as_deref(), Some("rt-0"));
        assert_eq!(refreshed[0].field("client_id").as_deref(), Some("cid"));
        assert_eq!(
            refreshed[0].field("client_secret").as_deref(),
            Some("sec-0")
        );

        let refused = start(&delegated(), &refresh_secrets(), |seen| {
            (seen.path() == "/token").then(|| {
                Answer::json(400, &json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}))
            })
        })?;
        let error = refused.google.browse(None).err().ok_or("an error")?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert!(refused.mock.seen_at(DRIVES).is_empty());
        Ok(())
    }

    #[test]
    fn a_listing_that_is_stopped_between_two_pages_is_cancelled() -> Res {
        let flag = Arc::new(AtomicBool::new(false));
        let raised = Arc::clone(&flag);
        let files = vec![
            text("a", "a.txt", "root0"),
            text("b", "b.txt", "root0"),
            text("c", "c.txt", "root0"),
        ];
        let rig = start(&delegated(), &refresh_secrets(), move |seen| {
            if seen.path() == FILES {
                raised.store(true, Ordering::SeqCst);
            }
            standard(&files, 1, seen)
        })?;
        let root = at(&rig, &my(""))?;
        let error = rig.google.changes(&root, None, &flag);
        assert!(matches!(error, Err(Error::Cancelled)), "{:?}", error.err());
        assert_eq!(rig.mock.seen_at(FILES).len(), 1, "no page after the stop");

        let stopped = AtomicBool::new(true);
        let error = rig.google.changes(&root, Some("100"), &stopped);
        assert!(matches!(error, Err(Error::Cancelled)));
        Ok(())
    }

    // ---- a service account ----

    /// A Workspace with two users and one shared drive, where each call has to carry the token of
    /// the user whose Drive it reads.
    fn workspace(seen: &Seen) -> Option<Answer> {
        let auth = seen.header("authorization").unwrap_or_default().to_owned();
        let wants = |user: &str| auth == format!("Bearer at-{user}");
        let allowed = match seen.path() {
            FILES => {
                let q = seen.param("q").unwrap_or_default();
                (q.starts_with("'rootA'") && wants("a@acme.com"))
                    || (q.starts_with("'rootB'") && wants("b@acme.com"))
                    || (q.starts_with("'d1'") && wants("a@acme.com"))
            }
            "/drive/v3/files/fa" | DRIVES => wants("a@acme.com"),
            "/drive/v3/files/fb" => wants("b@acme.com"),
            _ => true,
        };
        if !allowed {
            return Some(Answer::json(403, &error_body(403, "forbidden")));
        }
        let files = [
            text("fa", "a.txt", "rootA"),
            text("fb", "b.txt", "rootB"),
            text("fx", "x.txt", "d1"),
        ];
        match seen.path() {
            "/drive/v3/files/root" => {
                let root = if wants("a@acme.com") {
                    "rootA"
                } else {
                    "rootB"
                };
                Some(Answer::json(200, &json!({"id": root})))
            }
            DRIVES => Some(Answer::json(
                200,
                &json!({"drives": [{"id": "d1", "name": "Team"}]}),
            )),
            "/drive/v3/files/fa" => Some(Answer::bytes(200, b"a-bytes".to_vec())),
            "/drive/v3/files/fb" => Some(Answer::bytes(200, b"b-bytes".to_vec())),
            _ => standard(&files, 1000, seen),
        }
    }

    #[test]
    fn a_service_account_reads_each_users_drive_with_that_users_token() -> Res {
        let account = service(&["a@acme.com", "b@acme.com"])?;
        let rig = start(&account, &Secrets::default(), workspace)?;
        let top = rig.google.browse(None)?;
        let shown: Vec<String> = top
            .iter()
            .map(|folder| {
                folder
                    .path
                    .strip_prefix(TOP)
                    .map_or_else(|_| String::new(), |p| p.display().to_string())
            })
            .collect();
        assert_eq!(shown, ["a@acme.com", "b@acme.com", "Shared drives"]);
        assert_eq!(
            rig.mock.seen_at(DRIVES).len(),
            0,
            "the shared drives are asked for when opened"
        );

        let a = rig.google.changes(&top[0], None, &never())?;
        let b = rig.google.changes(&top[1], None, &never())?;
        assert_eq!(items_of(&a, TOP), [r"a@acme.com\a.txt"]);
        assert_eq!(items_of(&b, TOP), [r"b@acme.com\b.txt"]);
        assert_eq!(rig.google.download(&b.items[0], 100, &never())?, b"b-bytes");
        assert_eq!(rig.google.download(&a.items[0], 100, &never())?, b"a-bytes");

        // Which token went where.
        let listed: Vec<(String, String)> = rig
            .mock
            .seen_at(FILES)
            .iter()
            .map(|seen| {
                (
                    seen.param("q").unwrap_or_default(),
                    seen.header("authorization").unwrap_or_default().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                (
                    "'rootA' in parents and trashed=false".to_owned(),
                    "Bearer at-a@acme.com".to_owned()
                ),
                (
                    "'rootB' in parents and trashed=false".to_owned(),
                    "Bearer at-b@acme.com".to_owned()
                ),
            ]
        );
        let downloads: Vec<(String, String)> = rig
            .mock
            .seen()
            .iter()
            .filter(|seen| seen.param("alt").as_deref() == Some("media"))
            .map(|seen| {
                (
                    seen.path().to_owned(),
                    seen.header("authorization").unwrap_or_default().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            downloads,
            [
                (
                    "/drive/v3/files/fb".to_owned(),
                    "Bearer at-b@acme.com".to_owned()
                ),
                (
                    "/drive/v3/files/fa".to_owned(),
                    "Bearer at-a@acme.com".to_owned()
                ),
            ]
        );
        // Each user got a token with a JWT made for that user.
        let exchanged = rig.mock.seen_at("/token");
        assert_eq!(exchanged.len(), 2);
        for seen in &exchanged {
            assert_eq!(
                seen.field("grant_type").as_deref(),
                Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
            );
        }

        // The user's folder resolves to that user's files.
        let Resolved::File(found) = rig
            .google
            .resolve(Path::new(&format!(r"{TOP}\b@acme.com\b.txt")))?
        else {
            return Err("a file".into());
        };
        assert_eq!(Id::parse(&found.id)?.session, 1);
        Ok(())
    }

    #[test]
    fn a_service_accounts_shared_drives_are_the_first_users() -> Res {
        let account = service(&["a@acme.com", "b@acme.com"])?;
        let rig = start(&account, &Secrets::default(), workspace)?;
        let top = rig.google.browse(None)?;
        let shared = &top[2];
        let drives = rig.google.browse(Some(shared))?;
        assert_eq!(drives.len(), 1);
        assert_eq!(
            drives[0].path,
            PathBuf::from(format!(r"{TOP}\Shared drives\Team"))
        );
        assert_eq!(
            rig.mock.seen_at(DRIVES)[0].header("authorization"),
            Some("Bearer at-a@acme.com")
        );
        let everything = rig.google.changes(shared, None, &never())?;
        assert_eq!(items_of(&everything, TOP), [r"Shared drives\Team\x.txt"]);
        let one = rig.google.changes(&drives[0], None, &never())?;
        assert_eq!(items_of(&one, TOP), [r"Shared drives\Team\x.txt"]);
        let Resolved::Folder(again) = rig.google.resolve(&drives[0].path)? else {
            return Err("a folder".into());
        };
        assert_eq!(again.id, drives[0].id);
        Ok(())
    }
}
