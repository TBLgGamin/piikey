//! Signing in to a cloud account and staying signed in.
//!
//! - A person signs in once in a browser ([`Browser`]): the authorization code flow with PKCE over
//!   a loopback redirect. After that a refresh token gets every access token.
//! - An app signs in with its own credentials ([`App`]: a client secret, or a certificate whose
//!   private key signs a JWT assertion) or, for a Google service account, with a signed JWT
//!   ([`ServiceAccount`]).
//! - What must stay secret (a client secret, the refresh token, the latest access token) is kept
//!   by the [`TokenStore`], one DPAPI-protected file per account. The account settings hold none.
//!
//! A [`Session`] is what a connector holds: it hands out a bearer token that is good now, asks
//! for a new one when needed, and sends requests with it.

use std::{
    fmt::{self, Write as _},
    fs,
    io::{self, BufRead as _, BufReader, Read as _, Write as _},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{self, RsaKeyPair},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::{
    Error, Provider, Result,
    http::{self, Http, Reply, Request},
};
use crate::sys;

/// How long [`Session::connect`] waits for a person to finish signing in in the browser.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_mins(5);

/// A token is used only while it has more than this many seconds left.
const EXPIRY_MARGIN: u64 = 60;
/// How long an access token is good when the service does not say.
const DEFAULT_LIFETIME: u64 = 3600;
/// How long a JWT assertion of an app with a certificate is good, in seconds.
const CERTIFICATE_ASSERTION_LIFETIME: u64 = 600;
/// How long a JWT assertion of a Google service account is good, in seconds.
const SERVICE_ASSERTION_LIFETIME: u64 = 3600;
/// How often the wait for the browser looks at the cancel flag and the clock.
const POLL: Duration = Duration::from_millis(50);
/// How long one connection of the browser may take to say what it wants.
const REDIRECT_READ: Duration = Duration::from_secs(2);
/// The most of a browser's request that is read: the request line and its headers.
const REDIRECT_LIMIT: u64 = 32 * 1024;
/// How much of what a token endpoint says goes into the detail of an error.
const DETAIL_LEN: usize = 300;
/// The characters a PKCE code verifier may have (RFC 7636): letters, digits and `-._~`.
const PKCE_ALPHABET: &[u8; 66] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
/// The length of a PKCE code verifier.
const PKCE_LENGTH: usize = 64;
/// The `client_assertion_type` of a JWT assertion.
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The `grant_type` of a Google service account's JWT.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// What is said of a private key that cannot be used.
const KEY_PROBLEM: &str = "The private key file must be a PEM file without a password.";

/// What is kept secret for one account. It is wiped from memory when dropped, and its `Debug`
/// text says which parts are set, never what they are.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secrets {
    /// The client secret the person gave for the account (Google, Box, and a Microsoft app that
    /// signs in with a secret).
    pub client_secret: Option<String>,
    /// What gets a new access token without asking the person again. A service may replace it
    /// each time it is used; the new one is saved before it is relied on.
    pub refresh_token: Option<String>,
    /// The latest access token: a new process need not ask for one while this one is good.
    pub access_token: Option<String>,
    /// When `access_token` stops being good, in seconds since the Unix epoch.
    pub expires_at: u64,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.refresh_token.zeroize();
        self.access_token.zeroize();
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets")
            .field("client_secret", &self.client_secret.is_some())
            .field("refresh_token", &self.refresh_token.is_some())
            .field("access_token", &self.access_token.is_some())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Secrets {
    /// These secrets with the client secret set.
    #[must_use]
    pub fn with_client_secret(mut self, secret: &str) -> Self {
        self.client_secret = Some(secret.to_owned());
        self
    }

    /// These secrets with the refresh token set.
    #[must_use]
    pub fn with_refresh_token(mut self, token: &str) -> Self {
        self.refresh_token = Some(token.to_owned());
        self
    }

    /// These secrets with an access token that is good until `expires_at` (seconds since the
    /// Unix epoch).
    #[must_use]
    pub fn with_access_token(mut self, token: &str, expires_at: u64) -> Self {
        self.access_token = Some(token.to_owned());
        self.expires_at = expires_at;
        self
    }
}

/// What a token file holds, as it is read. Unset parts are left out of the file.
#[derive(Deserialize)]
struct StoredIn {
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    expires_at: u64,
}

/// What a token file holds, as it is written.
#[derive(Serialize)]
struct StoredOut<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

/// The DPAPI-protected files that hold the [`Secrets`] of the accounts: `<data folder>\sources\
/// <account id>.token`. Only the Windows user who wrote one can read it.
#[derive(Debug, Clone)]
pub struct TokenStore {
    dir: PathBuf,
}

impl TokenStore {
    /// The store in the data folder `data`.
    #[must_use]
    pub fn new(data: &Path) -> Self {
        Self {
            dir: data.join("sources"),
        }
    }

    /// What is kept for the account `id`; nothing set when there is no file yet.
    ///
    /// # Errors
    /// `Io` when the file cannot be read; `Dpapi` when it cannot be unwrapped (another Windows
    /// user, another machine, or damaged); `BadRequest` for an `id` that is not 16 hexadecimal
    /// digits.
    pub fn load(&self, id: &str) -> crate::Result<Secrets> {
        let path = self.path(id)?;
        let blob = match fs::read(&path) {
            Ok(blob) => blob,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Secrets::default());
            }
            Err(error) => return Err(sys::io_context(&error, "read", &path)),
        };
        let plain = sys::dpapi_unprotect(&blob, &entropy(id))?;
        let stored: StoredIn = serde_json::from_slice(&plain).map_err(|_| {
            let damaged =
                io::Error::new(io::ErrorKind::InvalidData, "the saved sign-in is damaged");
            sys::io_context(&damaged, "read", &path)
        })?;
        Ok(Secrets {
            client_secret: stored.client_secret,
            refresh_token: stored.refresh_token,
            access_token: stored.access_token,
            expires_at: stored.expires_at,
        })
    }

    /// Keeps `secrets` for the account `id`, replacing what was kept.
    ///
    /// # Errors
    /// As [`TokenStore::load`], and `Io` when the file cannot be written.
    pub fn save(&self, id: &str, secrets: &Secrets) -> crate::Result<()> {
        let path = self.path(id)?;
        let stored = StoredOut {
            client_secret: secrets.client_secret.as_deref(),
            refresh_token: secrets.refresh_token.as_deref(),
            access_token: secrets.access_token.as_deref(),
            expires_at: (secrets.expires_at != 0).then_some(secrets.expires_at),
        };
        let plain =
            Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| {
                crate::Error::Io(io::Error::other("the sign-in could not be written"))
            })?);
        let blob = sys::dpapi_protect(&plain, &entropy(id))?;
        fs::create_dir_all(&self.dir)
            .map_err(|error| sys::io_context(&error, "create", &self.dir))?;
        sys::write_atomic(&path, &blob)
    }

    /// Forgets everything kept for the account `id`; no file is fine.
    ///
    /// # Errors
    /// `Io` when the file exists and cannot be deleted; `BadRequest` as for load.
    pub fn remove(&self, id: &str) -> crate::Result<()> {
        let path = self.path(id)?;
        match fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                Err(sys::io_context(&error, "delete", &path))
            }
            _ => Ok(()),
        }
    }

    /// The file of the account `id`: only 16 lowercase hexadecimal digits make one, so an id
    /// never names a place outside the folder.
    fn path(&self, id: &str) -> crate::Result<PathBuf> {
        if id.len() == 16
            && id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            Ok(self.dir.join(format!("{id}.token")))
        } else {
            Err(crate::Error::BadRequest(
                "The account id is not valid.".to_owned(),
            ))
        }
    }
}

/// The extra bytes a token file is wrapped with, so a file copied to another account's name does
/// not unwrap.
fn entropy(id: &str) -> Vec<u8> {
    format!("piikey sources token v1 {id}").into_bytes()
}

/// How a token endpoint wants the client to say who it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientAuth {
    /// Only the client id, in the form: a public client.
    None,
    /// The client id and the stored client secret, as form fields.
    Body,
}

/// The host of a loopback redirect for a service that takes the address as it is:
/// `http://127.0.0.1:<port>`. It is also where the listener is, whichever host the redirect names.
pub(crate) const LOOPBACK: &str = "127.0.0.1";
/// The host of a loopback redirect for a service that is registered with the name:
/// `http://localhost:<port>`. Microsoft Entra registers the redirect of a public client as
/// `http://localhost` (the portal's "Mobile and desktop applications") and then takes `localhost`
/// with any port; it does not take `http://127.0.0.1:<port>` for that registration.
pub(crate) const LOCALHOST: &str = "localhost";

/// A person signs in with a browser: authorization code, with PKCE when `pkce` is set.
#[derive(Debug, Clone)]
pub(crate) struct Browser {
    /// Where the browser is sent.
    pub authorize_url: String,
    /// Where the code and, later, the refresh token are exchanged for access tokens.
    pub token_url: String,
    pub client_id: String,
    /// The scopes, separated by spaces.
    pub scope: String,
    /// More fields for the authorize URL, such as `access_type=offline` or
    /// `token_access_type=offline`.
    pub authorize_extra: Vec<(String, String)>,
    pub client_auth: ClientAuth,
    /// The host of the loopback redirect `http://<redirect_host>:<port>`: [`LOOPBACK`], or
    /// [`LOCALHOST`] for a service that is registered with that name. The listener is on
    /// `127.0.0.1` either way.
    pub redirect_host: &'static str,
    /// The port of the loopback redirect `http://<redirect_host>:<port>`; 0 takes any free port,
    /// for a service that matches the redirect without the port.
    pub port: u16,
    /// What follows the port in the redirect `http://<redirect_host>:<port><redirect_path>`:
    /// empty, or a path such as `/` that the service wants registered with it.
    pub redirect_path: String,
    pub pkce: bool,
}

/// How an app proves who it is when no person signs in.
#[derive(Debug, Clone)]
pub(crate) enum AppCredential {
    /// The client secret kept in the store, sent as `ClientAuth` says.
    Secret(ClientAuth),
    /// A JWT assertion signed RS256 with the private key; its header names the certificate with
    /// `x5t` (base64url of the SHA-1 of the certificate's DER). Both are PEM files.
    Certificate {
        key_file: PathBuf,
        cert_file: PathBuf,
    },
}

/// An app signs in with its own credentials (the client credentials grant).
#[derive(Debug, Clone)]
pub(crate) struct App {
    pub token_url: String,
    pub client_id: String,
    /// The `scope` field, when the service takes one (Microsoft: `https://graph.microsoft.com/.default`).
    pub scope: Option<String>,
    pub credential: AppCredential,
    /// More fields for the token request, such as Box's `box_subject_type`.
    pub extra: Vec<(String, String)>,
}

/// A Google service account that acts as `user` (domain-wide delegation): a JWT signed RS256 with
/// the key of the JSON key file is exchanged for an access token.
#[derive(Debug, Clone)]
pub(crate) struct ServiceAccount {
    /// The JSON key file Google issued (`client_email`, `private_key`, `token_uri`).
    pub key_file: PathBuf,
    /// The email address the access token is for (`sub`).
    pub user: String,
    pub scope: String,
    /// Where the JWT is exchanged, instead of the key file's `token_uri`: for a test.
    pub token_url: Option<String>,
}

/// How an account gets its access tokens.
#[derive(Debug, Clone)]
pub(crate) enum Grant {
    Browser(Browser),
    App(App),
    ServiceAccount(ServiceAccount),
}

/// The access token a session holds in memory.
struct Cached {
    token: Zeroizing<String>,
    expires_at: u64,
}

/// What a session remembers between calls; the lock around it makes threads share a refresh.
#[derive(Default)]
struct State {
    cached: Option<Cached>,
    /// The token last handed out was refused: an access token in the store is the same one (or
    /// an older one), so it is not taken.
    skip_stored: bool,
}

impl State {
    /// Whether the cached token has more than the margin left at `now`.
    fn good(&self, now: u64) -> Option<&str> {
        self.cached
            .as_ref()
            .filter(|cached| is_good(cached.expires_at, now))
            .map(|cached| cached.token.as_str())
    }

    /// Keeps `token` as the one to hand out; returns it.
    fn remember(&mut self, token: &str, expires_at: u64) -> String {
        self.cached = Some(Cached {
            token: Zeroizing::new(token.to_owned()),
            expires_at,
        });
        self.skip_stored = false;
        token.to_owned()
    }
}

/// Whether a token that ends at `expires_at` still has more than the margin left at `now`.
const fn is_good(expires_at: u64, now: u64) -> bool {
    now.saturating_add(EXPIRY_MARGIN) < expires_at
}

/// The seconds since the Unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A connector's way to a token and a signed-in request.
pub(crate) struct Session {
    http: Http,
    store: TokenStore,
    account: String,
    grant: Grant,
    state: Mutex<State>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// A session for the account `account` (its id), whose secrets are in `store`.
    pub(crate) fn new(http: Http, store: TokenStore, account: &str, grant: Grant) -> Self {
        Self {
            http,
            store,
            account: account.to_owned(),
            grant,
            state: Mutex::new(State::default()),
        }
    }

    /// An access token that is good now: the cached one, or one got with the refresh token, the
    /// app's credentials or the service account's key. Calls from several threads share one
    /// refresh.
    ///
    /// # Errors
    /// `SignInNeeded` when the service no longer accepts the refresh token, or there is none
    /// (the account was never connected); `Forbidden` when it refuses the app's credentials;
    /// `Network`, `Throttled`, `Unexpected` as for any call.
    pub(crate) fn bearer(&self) -> Result<String> {
        let mut state = self.lock()?;
        let now = now_secs();
        if let Some(token) = state.good(now) {
            return Ok(token.to_owned());
        }
        if let Grant::ServiceAccount(account) = &self.grant {
            return self.renew_in_memory(&mut state, account);
        }
        let mut secrets = self.store.load(&self.account)?;
        if !state.skip_stored
            && let Some(token) = &secrets.access_token
            && is_good(secrets.expires_at, now)
        {
            return Ok(state.remember(token, secrets.expires_at));
        }
        self.renew(&mut state, &mut secrets)
    }

    /// Sends `request` with a bearer token. A 401 is answered once by getting a new token and
    /// sending again. The reply has whatever status the service gave.
    ///
    /// # Errors
    /// As [`Session::bearer`] and [`Http::send`].
    pub(crate) fn send(&self, request: &Request) -> Result<Reply> {
        self.signed(request, &|request| self.http.send(request))
    }

    /// [`Session::send`] for a request that answers with a file of at most `max` bytes (see
    /// [`Http::download`]). Setting `cancel` stops it, before anything is sent or while the file
    /// comes in.
    ///
    /// # Errors
    /// As [`Session::send`], and `TooLarge` and `Cancelled`.
    pub(crate) fn download(
        &self,
        request: &Request,
        max: u64,
        cancel: &AtomicBool,
    ) -> Result<Reply> {
        if cancel.load(Ordering::SeqCst) {
            return Err(Error::Cancelled);
        }
        self.signed(request, &|request| self.http.download(request, max, cancel))
    }

    /// Connects the account. For a [`Browser`] grant that is the whole sign-in: it opens the
    /// authorize address through `open` (the app opens the browser, the command line prints it),
    /// waits for the redirect on the loopback for [`SIGN_IN_TIMEOUT`] or until `cancel` is set,
    /// exchanges the code, and keeps the refresh token. For an app or a service account it asks
    /// for a token, which proves the credentials work.
    ///
    /// # Errors
    /// `Cancelled` when `cancel` was set; `Forbidden` when the person refused or the credentials
    /// do not work; `SignInNeeded` when the browser flow timed out; `Network` and the rest as for
    /// any call.
    pub(crate) fn connect(&self, open: &dyn Fn(&str), cancel: &AtomicBool) -> Result<()> {
        self.connect_within(open, cancel, SIGN_IN_TIMEOUT)
    }

    /// [`Session::connect`] that waits `timeout` for the browser.
    fn connect_within(
        &self,
        open: &dyn Fn(&str),
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<()> {
        match &self.grant {
            Grant::Browser(browser) => self.sign_in(browser, open, cancel, timeout),
            Grant::App(_) => {
                let mut state = self.lock()?;
                let mut secrets = self.store.load(&self.account)?;
                self.renew(&mut state, &mut secrets).map(drop)
            }
            Grant::ServiceAccount(account) => {
                let mut state = self.lock()?;
                self.renew_in_memory(&mut state, account).map(drop)
            }
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| Error::Local(crate::Error::Poisoned))
    }

    /// `send` with a bearer token, and once more with a new one after a 401.
    fn signed(&self, request: &Request, send: &dyn Fn(&Request) -> Result<Reply>) -> Result<Reply> {
        let token = Zeroizing::new(self.bearer()?);
        let reply = send(&request.clone().bearer(&token))?;
        if reply.status != 401 {
            return Ok(reply);
        }
        self.refuse(&token);
        let token = Zeroizing::new(self.bearer()?);
        send(&request.clone().bearer(&token))
    }

    /// The service refused `token`. A token another thread got meanwhile is not forgotten.
    fn refuse(&self, token: &str) {
        if let Ok(mut state) = self.state.lock()
            && state
                .cached
                .as_ref()
                .is_none_or(|cached| cached.token.as_str() == token)
        {
            state.cached = None;
            state.skip_stored = true;
        }
    }

    /// A service account's token for its user. Every user of a domain has a session of its own
    /// over the same account id, so the token is never written to (or taken from) the store,
    /// which holds one access token per account.
    fn renew_in_memory(&self, state: &mut State, account: &ServiceAccount) -> Result<String> {
        let granted = self.service_account(account)?;
        Ok(state.remember(&granted.access_token, granted.expires_at))
    }

    /// Gets a new access token from the grant and keeps it, with a rotated refresh token, in the
    /// store before it is handed out.
    fn renew(&self, state: &mut State, secrets: &mut Secrets) -> Result<String> {
        let mut granted = self.acquire(secrets)?;
        granted.apply(secrets);
        self.store.save(&self.account, secrets)?;
        Ok(state.remember(&granted.access_token, granted.expires_at))
    }

    /// Asks the token endpoint for an access token, as the grant says.
    fn acquire(&self, secrets: &mut Secrets) -> Result<Granted> {
        match &self.grant {
            Grant::Browser(browser) => self.refresh(browser, secrets),
            Grant::App(app) => self.client_credentials(app, secrets),
            Grant::ServiceAccount(account) => self.service_account(account),
        }
    }

    /// The refresh token grant. A refresh token that was refused may have been replaced by
    /// another process meanwhile: the store is looked at again, and its token tried once.
    fn refresh(&self, browser: &Browser, secrets: &mut Secrets) -> Result<Granted> {
        let first = self.refresh_with(browser, secrets);
        if !matches!(first, Err(Error::SignInNeeded { .. })) {
            return first;
        }
        let latest = self.store.load(&self.account)?;
        if latest.refresh_token.is_none() || latest.refresh_token == secrets.refresh_token {
            return first;
        }
        *secrets = latest;
        self.refresh_with(browser, secrets)
    }

    fn refresh_with(&self, browser: &Browser, secrets: &Secrets) -> Result<Granted> {
        let refresh = secrets
            .refresh_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| self.not_connected())?;
        let request = Request::post(&browser.token_url)
            .form("grant_type", "refresh_token")
            .form("refresh_token", refresh)
            .form("scope", &browser.scope);
        let request = self.with_client(
            request,
            browser.client_auth,
            &browser.client_id,
            secrets.client_secret.as_deref(),
        )?;
        self.exchange(&request)
    }

    /// The client credentials grant of an app.
    fn client_credentials(&self, app: &App, secrets: &Secrets) -> Result<Granted> {
        let mut request = Request::post(&app.token_url).form("grant_type", "client_credentials");
        if let Some(scope) = &app.scope {
            request = request.form("scope", scope);
        }
        for (name, value) in &app.extra {
            request = request.form(name, value);
        }
        let request = match &app.credential {
            AppCredential::Secret(auth) => self.with_client(
                request,
                *auth,
                &app.client_id,
                secrets.client_secret.as_deref(),
            )?,
            AppCredential::Certificate {
                key_file,
                cert_file,
            } => {
                let assertion =
                    certificate_assertion(&app.token_url, &app.client_id, key_file, cert_file)?;
                request
                    .form("client_id", &app.client_id)
                    .form("client_assertion_type", ASSERTION_TYPE)
                    .form("client_assertion", &assertion)
            }
        };
        self.exchange(&request)
    }

    /// A Google service account's JWT, exchanged for an access token.
    fn service_account(&self, account: &ServiceAccount) -> Result<Granted> {
        let text = read_text(&account.key_file)?;
        let mut key: ServiceKey = serde_json::from_str(&text).map_err(|_| {
            bad_request("The key file is not a Google service account key (a JSON file).")
        })?;
        let jwt = Jwt::from_pem(&key.private_key);
        key.private_key.zeroize();
        let jwt = jwt?;
        let url = account.token_url.as_deref().unwrap_or(&key.token_uri);
        if key.client_email.is_empty() || url.is_empty() {
            return Err(bad_request(
                "The key file is not a Google service account key (a JSON file).",
            ));
        }
        let now = now_secs();
        let claims = json!({
            "iss": key.client_email,
            "sub": account.user,
            "scope": account.scope,
            "aud": url,
            "iat": now,
            "exp": now.saturating_add(SERVICE_ASSERTION_LIFETIME),
        });
        let assertion = Zeroizing::new(jwt.sign(&json!({"alg": "RS256", "typ": "JWT"}), &claims)?);
        let request = Request::post(url)
            .form("grant_type", JWT_BEARER_GRANT)
            .form("assertion", &assertion);
        self.exchange(&request)
    }

    /// Adds who the client is to a token request: the client id, and the stored client secret
    /// when `auth` wants it.
    fn with_client(
        &self,
        request: Request,
        auth: ClientAuth,
        client_id: &str,
        secret: Option<&str>,
    ) -> Result<Request> {
        let request = request.form("client_id", client_id);
        if auth == ClientAuth::None {
            return Ok(request);
        }
        let secret = secret.filter(|secret| !secret.is_empty()).ok_or_else(|| {
            Error::sign_in_needed(
                self.http.provider(),
                "no client secret is kept for this account",
            )
        })?;
        Ok(request.form("client_secret", secret))
    }

    /// Sends a token request and reads the access token (and the refresh token, if any) from the
    /// answer.
    fn exchange(&self, request: &Request) -> Result<Granted> {
        let provider = self.http.provider();
        let mut reply = self.http.send(request)?;
        if !reply.is_success() {
            return Err(token_error(provider, &reply));
        }
        let wire = serde_json::from_slice::<TokenReply>(&reply.body);
        reply.body.zeroize();
        let wire = wire.map_err(|_| {
            Error::unexpected(provider, "the token answer is not what was expected")
        })?;
        let Some(access_token) = wire.access_token.filter(|token| !token.is_empty()) else {
            return Err(Error::unexpected(
                provider,
                "the token answer holds no access token",
            ));
        };
        let lifetime = match &wire.expires_in {
            Some(Value::Number(number)) => number.as_u64(),
            Some(Value::String(text)) => text.trim().parse().ok(),
            _ => None,
        }
        .unwrap_or(DEFAULT_LIFETIME);
        Ok(Granted {
            access_token,
            refresh_token: wire.refresh_token.filter(|token| !token.is_empty()),
            expires_at: now_secs().saturating_add(lifetime),
        })
    }

    fn not_connected(&self) -> Error {
        Error::sign_in_needed(self.http.provider(), "the account was never connected")
    }

    /// The sign-in of a person: the browser is sent to the service, which sends it back to the
    /// loopback with a code, which is exchanged for the tokens.
    ///
    /// The listener is on `127.0.0.1` only, whatever [`Browser::redirect_host`] tells the service:
    /// a browser that goes to `localhost` tries `::1` first, finds nothing there and falls back to
    /// `127.0.0.1`. The `Host` the browser sends is not looked at: what shows that a visit is the
    /// one piikey waits for is its `state`.
    fn sign_in(
        &self,
        browser: &Browser,
        open: &dyn Fn(&str),
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<()> {
        // The IPv4 loopback, whatever host the redirect address names (see `redirect_host`).
        let listener = TcpListener::bind((LOOPBACK, browser.port)).map_err(|_| {
            bad_request(if browser.port == 0 {
                "piikey could not listen for the sign-in on this PC. Try again.".to_owned()
            } else {
                format!(
                    "piikey could not listen on port {} for the sign-in. Close what uses that port and try again.",
                    browser.port
                )
            })
        })?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!(
            "http://{}:{port}{}",
            browser.redirect_host, browser.redirect_path
        );
        let state = random_hex(16)?;
        let pkce = if browser.pkce {
            Some(Pkce::new()?)
        } else {
            None
        };
        open(&authorize_url(
            browser,
            &redirect_uri,
            &state,
            pkce.as_ref(),
        ));
        let (redirect, mut stream) =
            self.wait_for_redirect(&listener, &state, &browser.redirect_path, cancel, timeout)?;
        let outcome = match redirect {
            Redirect::Denied { error, description } => {
                let detail = format!("the sign-in was refused: {error} {description}");
                Err(if needs_admin(&error, &description) {
                    Error::AdminApproval {
                        provider: self.http.provider(),
                        detail,
                    }
                } else {
                    Error::forbidden(self.http.provider(), detail)
                })
            }
            Redirect::Code(code) => {
                self.finish_sign_in(browser, &redirect_uri, pkce.as_ref(), &code)
            }
        };
        self.respond_page(&mut stream, outcome.is_ok());
        outcome
    }

    /// Waits for the browser's visit with the code, or the person's refusal. Visits that are not
    /// that (a favicon, a probe, a page with another state) are answered and ignored.
    fn wait_for_redirect(
        &self,
        listener: &TcpListener,
        state: &str,
        path: &str,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<(Redirect, TcpStream)> {
        let deadline = Instant::now() + timeout;
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(Error::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Error::sign_in_needed(
                    self.http.provider(),
                    "the sign-in was not finished in time",
                ));
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Some(found) = read_redirect(stream, state, path) {
                        return Ok(found);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Exchanges the code for the tokens and keeps them.
    fn finish_sign_in(
        &self,
        browser: &Browser,
        redirect_uri: &str,
        pkce: Option<&Pkce>,
        code: &str,
    ) -> Result<()> {
        let mut state = self.lock()?;
        let mut secrets = self.store.load(&self.account)?;
        let mut request = Request::post(&browser.token_url)
            .form("grant_type", "authorization_code")
            .form("code", code)
            .form("redirect_uri", redirect_uri);
        if let Some(pkce) = pkce {
            request = request.form("code_verifier", &pkce.verifier);
        }
        let request = self.with_client(
            request,
            browser.client_auth,
            &browser.client_id,
            secrets.client_secret.as_deref(),
        )?;
        let mut granted = self.exchange(&request)?;
        if granted.refresh_token.is_none() {
            return Err(Error::unexpected(
                self.http.provider(),
                "no refresh token came back: offline access was not granted",
            ));
        }
        granted.apply(&mut secrets);
        self.store.save(&self.account, &secrets)?;
        state.remember(&granted.access_token, granted.expires_at);
        Ok(())
    }

    /// Tells the person in the browser how the sign-in went.
    fn respond_page(&self, stream: &mut TcpStream, connected: bool) {
        let name = self.http.provider().name();
        let text = if connected {
            format!("piikey is connected to {name}. You can close this tab and go back to piikey.")
        } else {
            format!(
                "piikey could not connect to {name}. You can close this tab and try again in piikey."
            )
        };
        respond(stream, "200 OK", &text);
    }
}

/// An access token, and what came with it, as a token endpoint gave it. It is wiped when dropped.
struct Granted {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
}

impl Granted {
    /// Puts this into `secrets`: the access token, and the refresh token if there is a new one.
    fn apply(&mut self, secrets: &mut Secrets) {
        secrets.access_token = Some(self.access_token.clone());
        secrets.expires_at = self.expires_at;
        if let Some(refresh) = self.refresh_token.take() {
            secrets.refresh_token = Some(refresh);
        }
    }
}

impl Drop for Granted {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// A token endpoint's success answer.
#[derive(Deserialize)]
struct TokenReply {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    /// A number, or a string of digits.
    #[serde(default)]
    expires_in: Option<Value>,
}

/// A token endpoint's failure answer (RFC 6749, 5.2).
#[derive(Deserialize, Default)]
struct Failure {
    #[serde(default)]
    error: Option<Value>,
    #[serde(default)]
    error_description: Option<Value>,
}

/// What a token endpoint's refusal stands for: by the `error` it names, else by the status.
fn token_error(provider: Provider, reply: &Reply) -> Error {
    let failure = serde_json::from_slice::<Failure>(&reply.body).unwrap_or_default();
    let Some(code) = failure.error.as_ref().and_then(Value::as_str) else {
        return reply.error();
    };
    let mut detail = format!("the token endpoint said {code}");
    if let Some(description) = failure.error_description.as_ref().and_then(Value::as_str) {
        detail.push_str(": ");
        detail.push_str(description);
    }
    let detail: String = detail
        .chars()
        .take(DETAIL_LEN)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if needs_admin(code, &detail) {
        return Error::AdminApproval { provider, detail };
    }
    match code {
        "invalid_grant" | "interaction_required" | "login_required" => {
            Error::sign_in_needed(provider, detail)
        }
        "invalid_client"
        | "unauthorized_client"
        | "invalid_scope"
        | "access_denied"
        | "consent_required"
        | "unsupported_grant_type"
        | "invalid_request" => Error::forbidden(provider, detail),
        "temporarily_unavailable" | "server_error" => Error::network(provider, detail),
        _ => reply.error(),
    }
}

/// Whether a refusal says that only an administrator can approve the app: Microsoft names it by a
/// code in the description (`AADSTS65001` no consent yet, `AADSTS90094` admin consent required,
/// `AADSTS90095` an admin consent request was made), whatever its `error` says.
fn needs_admin(error: &str, description: &str) -> bool {
    const CODES: [&str; 3] = ["AADSTS65001", "AADSTS90094", "AADSTS90095"];
    error == "admin_consent_required" || CODES.iter().any(|code| description.contains(code))
}

/// `text` as an error about this PC: a plain sentence.
fn bad_request(text: impl Into<String>) -> Error {
    Error::Local(crate::Error::BadRequest(text.into()))
}

/// `n` random bytes as lower-case hexadecimal.
fn random_hex(n: usize) -> Result<String> {
    let mut bytes = vec![0; n];
    sys::fill_random(&mut bytes)?;
    let mut out = String::with_capacity(n * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// A PKCE code verifier and the challenge that goes to the service.
struct Pkce {
    verifier: Zeroizing<String>,
    challenge: String,
}

impl Pkce {
    fn new() -> Result<Self> {
        let mut verifier = Zeroizing::new(String::with_capacity(PKCE_LENGTH));
        let mut bytes = Zeroizing::new([0_u8; PKCE_LENGTH]);
        while verifier.len() < PKCE_LENGTH {
            sys::fill_random(&mut *bytes)?;
            // A byte under 198 (3 times 66) maps to a character with no bias.
            for &byte in bytes.iter().filter(|&&byte| byte < 198) {
                if verifier.len() < PKCE_LENGTH
                    && let Some(&character) = PKCE_ALPHABET.get(usize::from(byte % 66))
                {
                    verifier.push(char::from(character));
                }
            }
        }
        let challenge =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
        Ok(Self {
            verifier,
            challenge,
        })
    }
}

/// The address the browser is sent to.
fn authorize_url(
    browser: &Browser,
    redirect_uri: &str,
    state: &str,
    pkce: Option<&Pkce>,
) -> String {
    let mut fields = vec![
        ("response_type", "code"),
        ("client_id", &browser.client_id),
        ("redirect_uri", redirect_uri),
        ("scope", &browser.scope),
        ("state", state),
    ];
    if let Some(pkce) = pkce {
        fields.push(("code_challenge", &pkce.challenge));
        fields.push(("code_challenge_method", "S256"));
    }
    for (name, value) in &browser.authorize_extra {
        fields.push((name, value));
    }
    let mut url = browser.authorize_url.clone();
    let mut separator = if url.contains('?') { '&' } else { '?' };
    for (name, value) in fields {
        let _ = write!(
            url,
            "{separator}{}={}",
            http::encode(name),
            http::encode(value)
        );
        separator = '&';
    }
    url
}

/// What the browser's visit to the redirect address said.
enum Redirect {
    /// The service sent a code.
    Code(Zeroizing<String>),
    /// The service sent an error: the person did not allow it, or may not. `description` is what
    /// it said about it, cut short.
    Denied { error: String, description: String },
}

/// Reads what the browser asks for. The visit that says how the sign-in went is returned with its
/// connection, to be answered once the code is exchanged; any other is answered here, and `None`
/// means keep waiting.
fn read_redirect(mut stream: TcpStream, state: &str, path: &str) -> Option<(Redirect, TcpStream)> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(REDIRECT_READ)).ok()?;
    stream.set_write_timeout(Some(REDIRECT_READ)).ok()?;
    let line = read_head(&stream)?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next()?, parts.next()?);
    let (target_path, query) = target.split_once('?').unwrap_or((target, ""));
    let wanted = if path.is_empty() { "/" } else { path };
    if method != "GET" || target_path != wanted {
        respond(&mut stream, "404 Not Found", "There is nothing here.");
        return None;
    }
    let fields = query_fields(query);
    let value = |name: &str| {
        fields
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
    };
    if value("state") != Some(state) {
        respond(
            &mut stream,
            "400 Bad Request",
            "This is not the sign-in piikey is waiting for.",
        );
        return None;
    }
    let redirect = if let Some(error) = value("error") {
        Redirect::Denied {
            error: error.chars().take(100).collect(),
            description: value("error_description")
                .unwrap_or_default()
                .chars()
                .take(300)
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect(),
        }
    } else if let Some(code) = value("code").filter(|code| !code.is_empty()) {
        Redirect::Code(Zeroizing::new(code.to_owned()))
    } else {
        respond(
            &mut stream,
            "400 Bad Request",
            "This is not the sign-in piikey is waiting for.",
        );
        return None;
    };
    Some((redirect, stream))
}

/// The request line of the browser's request, after reading its headers too: a connection closed
/// with unread bytes is reset, which can lose the answer.
fn read_head(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream.take(REDIRECT_LIMIT));
    let mut first = String::new();
    reader.read_line(&mut first).ok().filter(|&n| n > 0)?;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
            break;
        }
    }
    Some(first)
}

/// Answers the browser with a small page and closes the connection.
fn respond(stream: &mut TcpStream, status: &str, text: &str) {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>piikey</title></head>\
         <body style=\"font-family:Segoe UI,sans-serif;margin:3em\"><h1>piikey</h1><p>{text}</p></body></html>"
    );
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .and_then(|()| stream.flush());
    let _ = stream.shutdown(Shutdown::Write);
}

/// `a=1&b=two%20words` as pairs, decoded.
fn query_fields(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect()
}

/// Percent-decodes `text`; a `+` is a space.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let digits = bytes.get(at + 1..at + 3).and_then(|pair| {
                    let hex = |digit: u8| char::from(digit).to_digit(16);
                    Some(hex(*pair.first()?)? * 16 + hex(*pair.get(1)?)?)
                });
                if let Some(value) = digits.and_then(|value| u8::try_from(value).ok()) {
                    out.push(value);
                    at += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What of a Google service account key file is used.
#[derive(Deserialize)]
struct ServiceKey {
    #[serde(default)]
    client_email: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    token_uri: String,
}

/// The text of a file that may hold a key.
fn read_text(path: &Path) -> Result<Zeroizing<String>> {
    fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|error| Error::Local(sys::io_context(&error, "read", path)))
}

/// The JWT a certificate-holding app signs in with: signed with its private key, naming the
/// certificate by its thumbprints.
fn certificate_assertion(
    token_url: &str,
    client_id: &str,
    key_file: &Path,
    cert_file: &Path,
) -> Result<String> {
    let jwt = Jwt::from_pem(&read_text(key_file)?)?;
    let cert = read_text(cert_file)?;
    let der = pem_block(&cert, "CERTIFICATE")
        .ok_or_else(|| bad_request("The certificate file must be a PEM file."))?;
    let header = json!({
        "alg": "RS256",
        "typ": "JWT",
        "x5t": URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &der)),
        "x5t#S256": URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &der)),
    });
    let now = now_secs();
    let claims = json!({
        "aud": token_url,
        "iss": client_id,
        "sub": client_id,
        "jti": random_hex(16)?,
        "nbf": now,
        "exp": now.saturating_add(CERTIFICATE_ASSERTION_LIFETIME),
    });
    jwt.sign(&header, &claims)
}

/// The body of the first PEM block called `label` in `text`, decoded.
fn pem_block(text: &str, label: &str) -> Option<Zeroizing<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let rest = text.get(start..)?;
    let body: Zeroizing<String> = Zeroizing::new(
        rest.get(..rest.find(&end)?)?
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect(),
    );
    STANDARD.decode(body.as_bytes()).ok().map(Zeroizing::new)
}

/// An RSA private key that signs JWTs with RS256.
struct Jwt {
    key: RsaKeyPair,
}

impl Jwt {
    /// The key of a PEM text: `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` (PKCS#1).
    fn from_pem(text: &str) -> Result<Self> {
        let key = if let Some(der) = pem_block(text, "PRIVATE KEY") {
            RsaKeyPair::from_pkcs8(&der)
        } else if let Some(der) = pem_block(text, "RSA PRIVATE KEY") {
            RsaKeyPair::from_der(&der)
        } else {
            return Err(bad_request(KEY_PROBLEM));
        };
        key.map(|key| Self { key })
            .map_err(|_| bad_request(KEY_PROBLEM))
    }

    /// `header.claims.signature`, each part base64url without padding.
    fn sign(&self, header: &Value, claims: &Value) -> Result<String> {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| bad_request("The private key could not sign."))?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::TcpStream,
        sync::{
            Barrier,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use ring::signature::{KeyPair as _, UnparsedPublicKey};

    use super::*;
    use crate::{
        sources::testing::{Answer, Mock, Res, Seen},
        testing::temp_dir,
    };

    const ID: &str = "0123456789abcdef";
    const OTHER_ID: &str = "fedcba9876543210";

    /// A throwaway RSA-2048 key, PKCS#8, as the base64 of its DER (no PEM armour).
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

    /// The same key, PKCS#1.
    const KEY_PKCS1: &str = "\
        MIIEowIBAAKCAQEAk21aQhzM2BVOZ/KR0HL/T3b9MVz9uqtSHHsjtNqmLL4ISHqCZL7J2hwJ\
        PtTVzw3T78h4lBSaw8sug8n37sZH3xnWSFLoc5dzZeyMNKF9H5PkvrMmI9V+6ef6ad1WhNiF\
        3nfBdshiYP+UKBj0Lv5T8KXilBwuHUbGp5WHXhIo0AoYhvi7iwhhpTnqj3NEjjkYhLueD7yU\
        sJ0z4cra/xGNHeBnGEBf5MtieNJX9yUuf/nlLIWr4iedv7aFgu79Ong9gDu+PVhPidCJQKLi\
        TaYvWeurRcdUvbPP/NUBYnluo380uBsBj6F8aoTNdQQ5kGfQnAV4Y2XaAtXxNu8fc1TuuQID\
        AQABAoIBAAyn5ImsY0FhgtuVjULxvE0cD9w++WEe9+uN/qC17HIG1jsymSMA5d8dbQXBy6D8\
        tObutLsxkZ+hP5r8qZYL23uhgi2vQFk79SIYzmhuPImLbqWYR3voBf8adPrFj3nUBJn2edsy\
        lI9zIUrX6Y5nMtmDxBGm4aaNvtwAECDZOjuxoM2p04DayO5wl/YFRxIfopyM9AtAG8owl843\
        /Igniube7czmuho2tN+PhkZ30lv5CG/WJ6EzIuqhCEe/xcdGVFFDtfJ3fWo14H5NrR8zt3dj\
        pX7LRYuqc+/jpo3ccoEyUXTULDU0ZHSxOG5YeE29qsNw2br6hSNVHGRulsfwnSkCgYEAyPcp\
        vW/xprfgy7S1CPnAlfjtMRyMgXltv2MmtMhvYHfZVjdrvJObxLq1OG/Pqx0BtyCtPAoqcjpj\
        AATQwn3pSWpSsiAD2oSp6ousfm1fY37TwvioADizoQ0SBkhsFkEuydUQ8Kppzb1AJh4yU4qj\
        XizRXr4qgITykuCiyTpvrgMCgYEAu8zYUCmLrsSCDhTW78yW310j2mvDjGwK3u9Q74Mqi131\
        YVXXI/T1xyNiqMQfJR0avlegZsXAvJhZTfGC51POOKGxwGO0BNLEB0O+Q/vne4nGPBkIMvyV\
        LaWcSHqnrMNKBHPwFQTcPJjOegmyYYIVPMgLAM7+AZYs6fYPZgiCAZMCgYAmnmilAMgdU6Sd\
        QMKxUN1TdJyQHX5auyz95F3hy8qrbRyU1t2bRXpfmcmNaN8tcMuNl3fy27lAbjvsGwDK/0s/\
        UnFFzaUv7uKAMgsZ2IbGJe8nvoT6Vese/dYC4xPySuBk5M72kKj4Ym/bY14kc7XlOROa80xT\
        mjjLROPDa7leZQKBgQCK41AG2PLo6YOVjmv3JMNfpa5iVthj/XN8tFiTCdpo/6/9sFJP0VYD\
        VHQehAzUkdW5d2y1FQMZd0J0lmxNUHlvAIZI1nPILWe0R7Fq7d2gS6BDye96Zbqd66DNKYjg\
        B/2xlVy07sdCOXBaaNl3q5CxRvB8RJkt6zaEQOnad+hN6QKBgBFWdJOfpIQzAW3wH91h8T/G\
        9g9XD+SgjWio/zlPkKusXZfI0YZskLEtglXZz1K87nQsvJqHKEh0oHKVtoC11zjwfHw6LLbX\
        8Cb0FZKMS9J6uSQ45KgJExB74BRbfpa9uPhzQvAZDNMiccpZYDuj+7bzOWhMcZpyrmiDC9hZ\
        opi7\
    ";

    /// A self-signed certificate of that key, DER in base64.
    const CERT: &str = "\
        MIIDDzCCAfegAwIBAgIUEliqF18W4Xq49klyb1kdACb77P4wDQYJKoZIhvcNAQELBQAwFjEU\
        MBIGA1UEAwwLcGlpa2V5IHRlc3QwIBcNMjYxMDI0MTg0NjQwWhgPMjEyNjA5MzAxODQ2NDBa\
        MBYxFDASBgNVBAMMC3BpaWtleSB0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\
        AQEAk21aQhzM2BVOZ/KR0HL/T3b9MVz9uqtSHHsjtNqmLL4ISHqCZL7J2hwJPtTVzw3T78h4\
        lBSaw8sug8n37sZH3xnWSFLoc5dzZeyMNKF9H5PkvrMmI9V+6ef6ad1WhNiF3nfBdshiYP+U\
        KBj0Lv5T8KXilBwuHUbGp5WHXhIo0AoYhvi7iwhhpTnqj3NEjjkYhLueD7yUsJ0z4cra/xGN\
        HeBnGEBf5MtieNJX9yUuf/nlLIWr4iedv7aFgu79Ong9gDu+PVhPidCJQKLiTaYvWeurRcdU\
        vbPP/NUBYnluo380uBsBj6F8aoTNdQQ5kGfQnAV4Y2XaAtXxNu8fc1TuuQIDAQABo1MwUTAd\
        BgNVHQ4EFgQURhQFm1sqtYnHJ4YDNpyFG6Snm6IwHwYDVR0jBBgwFoAURhQFm1sqtYnHJ4YD\
        NpyFG6Snm6IwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAY2NticPx219d\
        rZxUA6DwnvbluwVNntQpbfUCfyZqY9/X2hft/pASWpljMl1mniWVLeglUUG94y5uBkdaQo/G\
        HZYPcx2Ha0qYzvexFghsFnERiqbGp/6tiVFr6eEMQJWT7qJCb3nF9omS/QK6gvs8s1qVGmri\
        o7twZa1KWMRKV5AWKD5N0P5ytphXRwyBffUG3nec/GmGsw2eswzZxIQIkgIOYL0s5FoE0RcZ\
        xivYWmRr6nuS6RUAtiwogekTN3tFSfr2ZlK2VRvlKtWlwoj+eBZMTB0MAxorK87NtIrt64wZ\
        RJbTRY3eXLt5cHMNHA6mtRE/H3xnYH+YrCyXOUUaJQ==\
    ";

    /// A PEM file's text for `body` (base64, no armour): the armour is put on here.
    fn pem(label: &str, body: &str) -> String {
        let mut text = format!("-----BEGIN {label}-----\n");
        for chunk in body.as_bytes().chunks(64) {
            text.push_str(&String::from_utf8_lossy(chunk));
            text.push('\n');
        }
        let _ = writeln!(text, "-----END {label}-----");
        text
    }

    /// Writes the key and the certificate as PEM files into `dir`.
    fn write_key_files(dir: &Path, pkcs1: bool) -> Res<(PathBuf, PathBuf)> {
        let key = dir.join("key.pem");
        let cert = dir.join("cert.pem");
        let text = if pkcs1 {
            pem("RSA PRIVATE KEY", KEY_PKCS1)
        } else {
            pem("PRIVATE KEY", KEY_PKCS8)
        };
        fs::write(&key, text)?;
        fs::write(&cert, pem("CERTIFICATE", CERT))?;
        Ok((key, cert))
    }

    fn start(handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Res<Mock> {
        Ok(Mock::start(handler)?)
    }

    /// A token endpoint at `/token` that numbers what it gives: `at-1`, `rt-1`, `at-2`...
    fn issuing() -> impl Fn(&Seen) -> Answer + Send + Sync + 'static {
        let count = AtomicUsize::new(0);
        move |seen| {
            if seen.path() != "/token" {
                return Answer::empty(404);
            }
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            Answer::json(
                200,
                &json!({
                    "access_token": format!("at-{n}"),
                    "refresh_token": format!("rt-{n}"),
                    "expires_in": 3600,
                }),
            )
        }
    }

    fn refused(error: &str) -> impl Fn(&Seen) -> Answer + Send + Sync + 'static {
        let body = json!({"error": error, "error_description": "no good"});
        move |_| Answer::json(400, &body)
    }

    fn browser_grant(mock: &Mock, client_auth: ClientAuth) -> Browser {
        Browser {
            authorize_url: "https://login.example/authorize".to_owned(),
            token_url: format!("{}/token", mock.url()),
            client_id: "client-1".to_owned(),
            scope: "files.read offline_access".to_owned(),
            authorize_extra: Vec::new(),
            client_auth,
            redirect_host: LOOPBACK,
            port: 0,
            redirect_path: String::new(),
            pkce: true,
        }
    }

    fn session(grant: Grant, store: &TokenStore) -> Session {
        Session::new(
            Http::with_pause(Provider::Box, |_| {}),
            store.clone(),
            ID,
            grant,
        )
    }

    fn store_with(dir: &Path, secrets: &Secrets) -> Res<TokenStore> {
        let store = TokenStore::new(dir);
        store.save(ID, secrets)?;
        Ok(store)
    }

    fn field(seen: &Seen, name: &str) -> Res<String> {
        Ok(seen.field(name).ok_or("a form field was missing")?)
    }

    fn failure<T>(result: Result<T>) -> Res<Error> {
        match result {
            Err(error) => Ok(error),
            Ok(_) => Err("an error was expected".into()),
        }
    }

    // ---- the token store

    #[test]
    fn token_store_round_trips_every_part() -> Res {
        let store = TokenStore::new(&temp_dir("auth-store"));
        let secrets = Secrets::default()
            .with_client_secret("shh")
            .with_refresh_token("refresh")
            .with_access_token("access", 1_900_000_000);
        store.save(ID, &secrets)?;
        assert_eq!(store.load(ID)?, secrets);
        let bytes = fs::read(store.path(ID)?)?;
        assert!(!String::from_utf8_lossy(&bytes).contains("refresh"));
        store.save(ID, &Secrets::default())?;
        assert_eq!(store.load(ID)?, Secrets::default());
        Ok(())
    }

    #[test]
    fn token_store_without_a_file_has_nothing_and_remove_forgets() -> Res {
        let store = TokenStore::new(&temp_dir("auth-store-none"));
        assert_eq!(store.load(ID)?, Secrets::default());
        store.remove(ID)?;
        store.save(ID, &Secrets::default().with_refresh_token("r"))?;
        assert!(store.path(ID)?.exists());
        store.remove(ID)?;
        assert!(!store.path(ID)?.exists());
        assert_eq!(store.load(ID)?, Secrets::default());
        Ok(())
    }

    #[test]
    fn token_store_blob_is_bound_to_its_account() -> Res {
        let store = TokenStore::new(&temp_dir("auth-store-bound"));
        store.save(ID, &Secrets::default().with_refresh_token("refresh"))?;
        fs::copy(store.path(ID)?, store.path(OTHER_ID)?)?;
        assert!(matches!(store.load(OTHER_ID), Err(crate::Error::Dpapi(_))));
        assert_eq!(store.load(ID)?.refresh_token.as_deref(), Some("refresh"));
        Ok(())
    }

    #[test]
    fn token_store_rejects_an_id_that_is_not_sixteen_hex_digits() {
        let store = TokenStore::new(&temp_dir("auth-store-id"));
        for id in [
            "",
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789ABCDEF",
            "0123456789abcdeg",
            "..\\..\\evil\\0123456",
            "../0123456789abcd",
        ] {
            assert!(
                matches!(store.load(id), Err(crate::Error::BadRequest(_))),
                "{id}"
            );
            assert!(
                matches!(store.remove(id), Err(crate::Error::BadRequest(_))),
                "{id}"
            );
            assert!(
                matches!(
                    store.save(id, &Secrets::default()),
                    Err(crate::Error::BadRequest(_))
                ),
                "{id}"
            );
        }
    }

    #[test]
    fn token_store_tells_a_damaged_file_from_a_foreign_one() -> Res {
        let store = TokenStore::new(&temp_dir("auth-store-damaged"));
        store.save(ID, &Secrets::default())?;
        let path = store.path(ID)?;
        // Unwraps, but is not what the store writes.
        sys::write_atomic(&path, &sys::dpapi_protect(b"not json", &entropy(ID))?)?;
        let Err(crate::Error::Io(error)) = store.load(ID) else {
            return Err("expected an Io error".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(ID));
        // Does not unwrap at all.
        fs::write(&path, b"garbage")?;
        assert!(matches!(store.load(ID), Err(crate::Error::Dpapi(_))));
        Ok(())
    }

    // ---- refresh

    #[test]
    fn refresh_sends_the_form_and_keeps_what_came_back() -> Res {
        let dir = temp_dir("auth-refresh");
        let store = store_with(
            &dir,
            &Secrets::default()
                .with_refresh_token("rt-0")
                .with_client_secret("sec-0"),
        )?;
        let mock = start(issuing())?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::Body)),
            &store,
        );
        assert_eq!(session.bearer()?, "at-1");
        let seen = mock.seen_at("/token");
        assert_eq!(seen.len(), 1);
        let form = &seen[0];
        assert_eq!(form.method, "POST");
        assert_eq!(field(form, "grant_type")?, "refresh_token");
        assert_eq!(field(form, "refresh_token")?, "rt-0");
        assert_eq!(field(form, "client_id")?, "client-1");
        assert_eq!(field(form, "scope")?, "files.read offline_access");
        assert_eq!(field(form, "client_secret")?, "sec-0");
        assert!(form.header("authorization").is_none());
        let kept = store.load(ID)?;
        assert_eq!(kept.access_token.as_deref(), Some("at-1"));
        assert_eq!(kept.refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(kept.client_secret.as_deref(), Some("sec-0"));
        assert!(kept.expires_at > now_secs() + 3000);
        // Good for now: no second request.
        assert_eq!(session.bearer()?, "at-1");
        assert_eq!(mock.seen_at("/token").len(), 1);
        Ok(())
    }

    #[test]
    fn refresh_of_a_public_client_sends_no_secret() -> Res {
        let store = store_with(
            &temp_dir("auth-public"),
            &Secrets::default()
                .with_refresh_token("rt-0")
                .with_client_secret("unused"),
        )?;
        let mock = start(issuing())?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        session.bearer()?;
        let seen = mock.seen_at("/token");
        assert!(seen[0].field("client_secret").is_none());
        assert!(seen[0].header("authorization").is_none());
        Ok(())
    }

    #[test]
    fn refresh_needs_a_refresh_token_and_the_secret_it_wants() -> Res {
        let mock = start(issuing())?;
        let store = store_with(&temp_dir("auth-nothing"), &Secrets::default())?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let error = failure(session.bearer())?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        let store = store_with(
            &temp_dir("auth-no-secret"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let session = session_for(&mock, &store, ClientAuth::Body);
        let error = failure(session.bearer())?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert!(mock.seen().is_empty());
        Ok(())
    }

    fn session_for(mock: &Mock, store: &TokenStore, auth: ClientAuth) -> Session {
        session(Grant::Browser(browser_grant(mock, auth)), store)
    }

    #[test]
    fn a_rotated_refresh_token_is_kept_and_used_next() -> Res {
        let store = store_with(
            &temp_dir("auth-rotate"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let mock = start(api(1))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let reply = session.send(&Request::get(format!("{}/api", mock.url())))?;
        assert_eq!(reply.status, 200);
        let seen = mock.seen_at("/token");
        assert_eq!(seen.len(), 2);
        assert_eq!(field(&seen[0], "refresh_token")?, "rt-0");
        assert_eq!(field(&seen[1], "refresh_token")?, "rt-1");
        assert_eq!(store.load(ID)?.refresh_token.as_deref(), Some("rt-2"));
        Ok(())
    }

    #[test]
    fn an_answer_without_a_new_refresh_token_keeps_the_old_one() -> Res {
        let store = store_with(
            &temp_dir("auth-keep"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let mock =
            start(|_| Answer::json(200, &json!({"access_token": "at", "expires_in": "120"})))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        assert_eq!(session.bearer()?, "at");
        let kept = store.load(ID)?;
        assert_eq!(kept.refresh_token.as_deref(), Some("rt-0"));
        assert!((now_secs() + 100..=now_secs() + 121).contains(&kept.expires_at));
        Ok(())
    }

    #[test]
    fn invalid_grant_with_an_unchanged_store_needs_a_new_sign_in() -> Res {
        let store = store_with(
            &temp_dir("auth-invalid"),
            &Secrets::default()
                .with_refresh_token("rt-secret-0")
                .with_client_secret("sec-secret"),
        )?;
        let mock = start(refused("invalid_grant"))?;
        let session = session_for(&mock, &store, ClientAuth::Body);
        let error = failure(session.bearer())?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert_eq!(mock.seen_at("/token").len(), 1);
        let text = format!("{error:?} {error}");
        assert!(!text.contains("secret"), "{text}");
        Ok(())
    }

    #[test]
    fn invalid_grant_after_another_process_rotated_is_tried_with_its_token() -> Res {
        let store = store_with(
            &temp_dir("auth-race"),
            &Secrets::default().with_refresh_token("rt-old"),
        )?;
        let other = store.clone();
        let mock = start(move |seen| {
            match seen.field("refresh_token").as_deref() {
                Some("rt-old") => {
                    // Another process refreshed first, and saved what the service gave it.
                    let saved = other.save(ID, &Secrets::default().with_refresh_token("rt-new"));
                    if saved.is_err() {
                        return Answer::empty(500);
                    }
                    Answer::json(400, &json!({"error": "invalid_grant"}))
                }
                Some("rt-new") => Answer::json(
                    200,
                    &json!({"access_token": "at-new", "refresh_token": "rt-newer", "expires_in": 60 * 60}),
                ),
                _ => Answer::empty(500),
            }
        })?;
        let session = session_for(&mock, &store, ClientAuth::None);
        assert_eq!(session.bearer()?, "at-new");
        assert_eq!(mock.seen_at("/token").len(), 2);
        assert_eq!(store.load(ID)?.refresh_token.as_deref(), Some("rt-newer"));
        // The second refusal is final.
        let store = store_with(
            &temp_dir("auth-race-2"),
            &Secrets::default().with_refresh_token("rt-old"),
        )?;
        let other = store.clone();
        let mock = start(move |seen| {
            if seen.field("refresh_token").as_deref() == Some("rt-old") {
                let _ = other.save(ID, &Secrets::default().with_refresh_token("rt-new"));
            }
            Answer::json(400, &json!({"error": "invalid_grant"}))
        })?;
        let error = failure(session_for(&mock, &store, ClientAuth::None).bearer())?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert_eq!(mock.seen_at("/token").len(), 2);
        Ok(())
    }

    #[test]
    fn a_good_stored_access_token_is_used_without_a_request() -> Res {
        let store = store_with(
            &temp_dir("auth-stored"),
            &Secrets::default()
                .with_refresh_token("rt-0")
                .with_access_token("stored-at", now_secs() + 3600),
        )?;
        let mock = start(issuing())?;
        let session = session_for(&mock, &store, ClientAuth::None);
        assert_eq!(session.bearer()?, "stored-at");
        assert_eq!(session.bearer()?, "stored-at");
        assert!(mock.seen().is_empty());
        Ok(())
    }

    #[test]
    fn a_stored_access_token_that_is_nearly_over_is_not_used() -> Res {
        let store = store_with(
            &temp_dir("auth-near-end"),
            &Secrets::default()
                .with_refresh_token("rt-0")
                .with_access_token("stale-at", now_secs() + 30),
        )?;
        let mock = start(issuing())?;
        assert_eq!(
            session_for(&mock, &store, ClientAuth::None).bearer()?,
            "at-1"
        );
        Ok(())
    }

    #[test]
    fn a_refused_token_is_not_taken_again_from_the_store() -> Res {
        let store = store_with(
            &temp_dir("auth-refused"),
            &Secrets::default()
                .with_refresh_token("rt-0")
                .with_access_token("stored-at", now_secs() + 3600),
        )?;
        let mock = start(api(1))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let reply = session.send(&Request::get(format!("{}/api", mock.url())))?;
        assert_eq!(reply.status, 200);
        let calls = mock.seen_at("/api");
        assert_eq!(calls[0].header("authorization"), Some("Bearer stored-at"));
        assert_eq!(calls[1].header("authorization"), Some("Bearer at-1"));
        assert_eq!(store.load(ID)?.access_token.as_deref(), Some("at-1"));
        Ok(())
    }

    #[test]
    fn threads_asking_at_once_share_one_token_request() -> Res {
        let store = store_with(
            &temp_dir("auth-threads"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let mock = start(issuing())?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let start = Barrier::new(8);
        let tokens = thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        session.bearer()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| "a thread panicked")?
                        .map_err(|e| e.to_string())
                })
                .collect::<std::result::Result<Vec<_>, String>>()
        })?;
        assert_eq!(tokens.len(), 8);
        assert!(tokens.iter().all(|token| token == "at-1"));
        assert_eq!(mock.seen_at("/token").len(), 1);
        Ok(())
    }

    #[test]
    fn every_token_endpoint_error_is_classed() -> Res {
        let store = store_with(
            &temp_dir("auth-classes"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let cases: [(u16, &str, &str); 13] = [
            (400, "invalid_grant", "sign_in"),
            (400, "interaction_required", "sign_in"),
            (400, "login_required", "sign_in"),
            (401, "invalid_client", "forbidden"),
            (400, "unauthorized_client", "forbidden"),
            (400, "invalid_scope", "forbidden"),
            (400, "access_denied", "forbidden"),
            (400, "consent_required", "forbidden"),
            (400, "unsupported_grant_type", "forbidden"),
            (400, "invalid_request", "forbidden"),
            (503, "temporarily_unavailable", "network"),
            (500, "server_error", "network"),
            (400, "something_new", "unexpected"),
        ];
        for (status, code, class) in cases {
            let mock = start(move |_| {
                Answer::json(
                    status,
                    &json!({"error": code, "error_description": "words", "error_codes": [70000]}),
                )
            })?;
            let error = failure(session_for(&mock, &store, ClientAuth::None).bearer())?;
            let matched = match class {
                "sign_in" => matches!(error, Error::SignInNeeded { .. }),
                "forbidden" => matches!(error, Error::Forbidden { .. }),
                "network" => matches!(error, Error::Network { .. }),
                _ => matches!(error, Error::Unexpected { .. }),
            };
            assert!(matched, "{code}: {error:?}");
            assert!(
                format!("{error:?}").contains("words") || class == "unexpected",
                "{error:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_token_endpoint_error_without_json_is_classed_by_its_status() -> Res {
        let store = store_with(
            &temp_dir("auth-status"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let cases: [(u16, &str); 4] = [
            (401, "sign_in"),
            (403, "forbidden"),
            (500, "network"),
            (429, "throttled"),
        ];
        for (status, class) in cases {
            let mock = start(move |_| Answer::text(status, "plain").header("Retry-After", "7"))?;
            let error = failure(session_for(&mock, &store, ClientAuth::None).bearer())?;
            let matched = match class {
                "sign_in" => matches!(error, Error::SignInNeeded { .. }),
                "forbidden" => matches!(error, Error::Forbidden { .. }),
                "network" => matches!(error, Error::Network { .. }),
                _ => matches!(error, Error::Throttled { .. }),
            };
            assert!(matched, "{status}: {error:?}");
        }
        Ok(())
    }

    #[test]
    fn a_success_answer_that_is_not_a_token_is_unexpected() -> Res {
        let store = store_with(
            &temp_dir("auth-odd"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        for body in [
            json!({"nothing": 1}),
            json!({"access_token": ""}),
            json!([1, 2]),
        ] {
            let mock = start(move |_| Answer::json(200, &body))?;
            let error = failure(session_for(&mock, &store, ClientAuth::None).bearer())?;
            assert!(matches!(error, Error::Unexpected { .. }), "{error:?}");
        }
        Ok(())
    }

    // ---- send and download

    /// A token endpoint that numbers its tokens, and an API at `/api` that answers 401 to
    /// `unauthorized` calls and 200 to the rest.
    fn api(unauthorized: usize) -> impl Fn(&Seen) -> Answer + Send + Sync + 'static {
        let tokens = issuing();
        let calls = AtomicUsize::new(0);
        move |seen| {
            if seen.path() == "/token" {
                return tokens(seen);
            }
            if calls.fetch_add(1, Ordering::SeqCst) < unauthorized {
                Answer::text(401, "no")
            } else {
                Answer::text(200, "the file")
            }
        }
    }

    #[test]
    fn send_answers_one_401_with_a_new_token() -> Res {
        let store = store_with(
            &temp_dir("auth-send"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let mock = start(api(1))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let reply = session.send(&Request::get(format!("{}/api", mock.url())))?;
        assert_eq!(reply.status, 200);
        let calls = mock.seen_at("/api");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].header("authorization"), Some("Bearer at-1"));
        assert_eq!(calls[1].header("authorization"), Some("Bearer at-2"));
        assert_eq!(mock.seen_at("/token").len(), 2);
        Ok(())
    }

    #[test]
    fn send_returns_a_second_401_as_it_is() -> Res {
        let store = store_with(
            &temp_dir("auth-send-401"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let mock = start(api(usize::MAX))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let reply = session.send(&Request::get(format!("{}/api", mock.url())))?;
        assert_eq!(reply.status, 401);
        assert_eq!(mock.seen_at("/api").len(), 2);
        assert_eq!(mock.seen_at("/token").len(), 2);
        Ok(())
    }

    #[test]
    fn send_does_not_retry_other_statuses_and_a_stored_token_needs_no_request() -> Res {
        let store = store_with(
            &temp_dir("auth-send-403"),
            &Secrets::default().with_access_token("stored-at", now_secs() + 3600),
        )?;
        let mock = start(|_| Answer::text(403, "no"))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let reply = session.send(&Request::get(format!("{}/api", mock.url())))?;
        assert_eq!(reply.status, 403);
        assert_eq!(mock.seen().len(), 1);
        assert_eq!(
            mock.seen()[0].header("authorization"),
            Some("Bearer stored-at")
        );
        Ok(())
    }

    #[test]
    fn download_signs_in_retries_once_and_keeps_the_size_cap() -> Res {
        let store = store_with(
            &temp_dir("auth-download"),
            &Secrets::default().with_refresh_token("rt-0"),
        )?;
        let mock = start(api(1))?;
        let session = session_for(&mock, &store, ClientAuth::None);
        let request = Request::get(format!("{}/api", mock.url()));
        let never = AtomicBool::new(false);
        let reply = session.download(&request, 8, &never)?;
        assert_eq!(reply.body, b"the file");
        let calls = mock.seen_at("/api");
        assert_eq!(calls[1].header("authorization"), Some("Bearer at-2"));
        assert!(matches!(
            session.download(&request, 7, &never),
            Err(Error::TooLarge)
        ));
        let before = mock.seen().len();
        let stop = AtomicBool::new(true);
        assert!(matches!(
            session.download(&request, 8, &stop),
            Err(Error::Cancelled)
        ));
        assert_eq!(mock.seen().len(), before);
        Ok(())
    }

    // ---- the browser

    /// The authorize address the test was given, taken apart.
    struct Authorize {
        fields: Vec<(String, String)>,
    }

    impl Authorize {
        fn parse(url: &str) -> Self {
            Self {
                fields: query_fields(url.split_once('?').map_or("", |(_, query)| query)),
            }
        }

        fn get(&self, name: &str) -> Res<&str> {
            self.fields
                .iter()
                .find_map(|(key, value)| (key == name).then_some(value.as_str()))
                .ok_or_else(|| format!("the authorize address has no {name}").into())
        }

        /// The `host:port` of the redirect.
        fn address(&self) -> Res<String> {
            let uri = self.get("redirect_uri")?;
            let rest = uri
                .strip_prefix("http://")
                .ok_or("the redirect is not http")?;
            Ok(rest.split('/').next().unwrap_or_default().to_owned())
        }

        /// The path of the redirect (what follows the port).
        fn path(&self) -> Res<String> {
            let uri = self.get("redirect_uri")?;
            let rest = uri
                .strip_prefix("http://")
                .ok_or("the redirect is not http")?;
            Ok(rest
                .find('/')
                .map_or(String::new(), |at| rest[at..].to_owned()))
        }

        fn state(&self) -> Res<String> {
            Ok(self.get("state")?.to_owned())
        }
    }

    /// One visit of the test, as the browser, to `address`: the whole answer.
    fn visit(address: &str, target: &str) -> String {
        let attempt = || -> io::Result<String> {
            let mut stream = TcpStream::connect(address)?;
            stream.set_read_timeout(Some(Duration::from_secs(20)))?;
            write!(
                stream,
                "GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )?;
            let mut answer = String::new();
            stream.read_to_string(&mut answer)?;
            Ok(answer)
        };
        attempt().unwrap_or_else(|error| format!("failed: {error}"))
    }

    /// What a flow showed: the authorize address it gave and the answers the test got as the
    /// browser.
    struct Flow {
        url: String,
        pages: Vec<String>,
    }

    /// Runs [`Session::connect_within`] with the test as the browser: once the authorize address
    /// is given, `script` says which targets of the redirect address to visit, in turn.
    fn run_flow(
        session: &Session,
        cancel: &AtomicBool,
        timeout: Duration,
        script: impl Fn(&Authorize) -> Res<Vec<String>>,
    ) -> Res<(Result<()>, Flow)> {
        let given = Mutex::new(String::new());
        let visitor: Mutex<Option<JoinHandle<Vec<String>>>> = Mutex::new(None);
        let open = |url: &str| {
            if let Ok(mut given) = given.lock() {
                url.clone_into(&mut given);
            }
            let authorize = Authorize::parse(url);
            if let (Ok(address), Ok(targets)) = (authorize.address(), script(&authorize)) {
                let handle = thread::spawn(move || {
                    targets
                        .iter()
                        .map(|target| visit(&address, target))
                        .collect()
                });
                if let Ok(mut visitor) = visitor.lock() {
                    *visitor = Some(handle);
                }
            }
        };
        let result = session.connect_within(&open, cancel, timeout);
        let handle = visitor.lock().map_err(|_| "poisoned")?.take();
        let pages = match handle {
            Some(handle) => handle.join().map_err(|_| "the visitor panicked")?,
            None => Vec::new(),
        };
        let url = given.lock().map_err(|_| "poisoned")?.clone();
        Ok((result, Flow { url, pages }))
    }

    fn not_cancelled() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn good_visit(authorize: &Authorize) -> Res<Vec<String>> {
        Ok(vec![format!(
            "{}?code=abc&state={}",
            authorize.path().map(|path| if path.is_empty() {
                "/".to_owned()
            } else {
                path
            })?,
            authorize.state()?
        )])
    }

    fn browser_mock() -> Res<Mock> {
        start(|seen| {
            if seen.path() != "/token" {
                return Answer::empty(404);
            }
            Answer::json(
                200,
                &json!({"access_token": "at-browser", "refresh_token": "rt-browser", "expires_in": "3600"}),
            )
        })
    }

    #[test]
    fn the_browser_flow_end_to_end() -> Res {
        let store = store_with(
            &temp_dir("auth-flow"),
            &Secrets::default().with_client_secret("sec-flow"),
        )?;
        let mock = browser_mock()?;
        let mut grant = browser_grant(&mock, ClientAuth::Body);
        grant.authorize_extra = vec![("access_type".to_owned(), "offline".to_owned())];
        let session = session(Grant::Browser(grant), &store);
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            good_visit,
        )?;
        result?;

        let authorize = Authorize::parse(&flow.url);
        assert!(flow.url.starts_with("https://login.example/authorize?response_type=code&client_id=client-1&redirect_uri=http%3A%2F%2F127.0.0.1%3A"));
        assert_eq!(authorize.get("response_type")?, "code");
        assert_eq!(authorize.get("client_id")?, "client-1");
        assert_eq!(authorize.get("scope")?, "files.read offline_access");
        assert_eq!(authorize.get("access_type")?, "offline");
        assert_eq!(authorize.get("code_challenge_method")?, "S256");
        let state = authorize.state()?;
        assert!(state.len() == 32 && state.bytes().all(|b| b.is_ascii_hexdigit()));

        let seen = mock.seen_at("/token");
        assert_eq!(seen.len(), 1);
        assert_eq!(field(&seen[0], "grant_type")?, "authorization_code");
        assert_eq!(field(&seen[0], "code")?, "abc");
        assert_eq!(field(&seen[0], "client_id")?, "client-1");
        assert_eq!(field(&seen[0], "client_secret")?, "sec-flow");
        assert_eq!(
            field(&seen[0], "redirect_uri")?,
            authorize.get("redirect_uri")?
        );
        let verifier = field(&seen[0], "code_verifier")?;
        assert_eq!(verifier.len(), 64);
        assert!(verifier.bytes().all(|b| PKCE_ALPHABET.contains(&b)));
        let challenge =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
        assert_eq!(authorize.get("code_challenge")?, challenge);

        let kept = store.load(ID)?;
        assert_eq!(kept.refresh_token.as_deref(), Some("rt-browser"));
        assert_eq!(kept.access_token.as_deref(), Some("at-browser"));
        assert_eq!(kept.client_secret.as_deref(), Some("sec-flow"));
        assert!(kept.expires_at > now_secs() + 3000);
        assert_eq!(session.bearer()?, "at-browser");
        assert_eq!(mock.seen_at("/token").len(), 1);

        let page = flow.pages.first().ok_or("the browser got no page")?;
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        assert!(
            page.contains(
                "piikey is connected to Box. You can close this tab and go back to piikey."
            )
        );
        assert!(!page.contains("abc"));
        Ok(())
    }

    #[test]
    fn a_grant_registered_with_localhost_sends_that_name_in_both_places() -> Res {
        let store = store_with(&temp_dir("auth-flow-localhost"), &Secrets::default())?;
        let mock = browser_mock()?;
        let mut grant = browser_grant(&mock, ClientAuth::None);
        grant.redirect_host = LOCALHOST;
        let session = session(Grant::Browser(grant), &store);
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            good_visit,
        )?;
        result?;

        // The service is told `localhost`, in the authorize address and in the exchange.
        let authorize = Authorize::parse(&flow.url);
        let uri = authorize.get("redirect_uri")?;
        let port = uri
            .strip_prefix("http://localhost:")
            .ok_or("the redirect is not on localhost")?;
        assert!(
            !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
            "{uri}"
        );
        assert!(
            flow.url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A"),
            "{}",
            flow.url
        );
        let seen = mock.seen_at("/token");
        assert_eq!(field(&seen[0], "redirect_uri")?, uri);

        // The test came back by that name (`Host: localhost:<port>`, reaching the IPv4 loopback
        // where the listener is) and was let in.
        assert_eq!(authorize.address()?, format!("localhost:{port}"));
        let page = flow.pages.first().ok_or("the browser got no page")?;
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        assert_eq!(store.load(ID)?.refresh_token.as_deref(), Some("rt-browser"));
        Ok(())
    }

    #[test]
    fn a_public_client_without_pkce_sends_neither_challenge_nor_verifier() -> Res {
        let store = store_with(&temp_dir("auth-flow-plain"), &Secrets::default())?;
        let mock = browser_mock()?;
        let mut grant = browser_grant(&mock, ClientAuth::None);
        grant.pkce = false;
        let session = session(Grant::Browser(grant), &store);
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            good_visit,
        )?;
        result?;
        assert!(!flow.url.contains("code_challenge"));
        let seen = mock.seen_at("/token");
        assert!(seen[0].field("code_verifier").is_none());
        assert!(seen[0].field("client_secret").is_none());
        Ok(())
    }

    #[test]
    fn an_authorize_address_that_has_a_query_already_gets_the_rest_after_it() -> Res {
        let store = store_with(&temp_dir("auth-flow-query"), &Secrets::default())?;
        let mock = browser_mock()?;
        let mut grant = browser_grant(&mock, ClientAuth::None);
        grant.authorize_url = "https://login.example/authorize?tenant=a%20b".to_owned();
        grant.authorize_extra = vec![("prompt".to_owned(), "select account&x=y".to_owned())];
        let session = session(Grant::Browser(grant), &store);
        let cancel = AtomicBool::new(false);
        let (result, flow) = run_flow(&session, &cancel, Duration::from_millis(100), |_| {
            Ok(Vec::new())
        })?;
        assert!(matches!(result, Err(Error::SignInNeeded { .. })));
        assert!(
            flow.url
                .starts_with("https://login.example/authorize?tenant=a%20b&response_type=code&")
        );
        let authorize = Authorize::parse(&flow.url);
        assert_eq!(authorize.get("tenant")?, "a b");
        assert_eq!(authorize.get("prompt")?, "select account&x=y");
        Ok(())
    }

    #[test]
    fn visits_that_are_not_the_redirect_are_answered_and_ignored() -> Res {
        let store = store_with(&temp_dir("auth-flow-stray"), &Secrets::default())?;
        let mock = browser_mock()?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            |authorize| {
                let state = authorize.state()?;
                Ok(vec![
                    "/favicon.ico".to_owned(),
                    format!("/?code=evil&state={}", "0".repeat(32)),
                    "/?code=evil".to_owned(),
                    format!("/?state={state}"),
                    format!("/?code=abc&state={state}"),
                ])
            },
        )?;
        result?;
        let starts: Vec<_> = flow
            .pages
            .iter()
            .map(|page| &page[..12.min(page.len())])
            .collect();
        assert_eq!(
            starts,
            [
                "HTTP/1.1 404",
                "HTTP/1.1 400",
                "HTTP/1.1 400",
                "HTTP/1.1 400",
                "HTTP/1.1 200"
            ]
        );
        let seen = mock.seen_at("/token");
        assert_eq!(seen.len(), 1);
        assert_eq!(field(&seen[0], "code")?, "abc");
        Ok(())
    }

    #[test]
    fn a_refusal_in_the_browser_is_forbidden_and_leaves_the_store_alone() -> Res {
        let store = store_with(
            &temp_dir("auth-flow-denied"),
            &Secrets::default().with_client_secret("s"),
        )?;
        let mock = browser_mock()?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::Body)),
            &store,
        );
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            |authorize| {
                Ok(vec![format!(
                    "/?error=access_denied&state={}",
                    authorize.state()?
                )])
            },
        )?;
        let error = failure(result)?;
        assert!(matches!(error, Error::Forbidden { .. }), "{error:?}");
        let page = flow.pages.first().ok_or("no page")?;
        assert!(page.contains(
            "piikey could not connect to Box. You can close this tab and try again in piikey."
        ));
        assert!(!page.contains("access_denied"));
        assert!(mock.seen().is_empty());
        assert_eq!(store.load(ID)?, Secrets::default().with_client_secret("s"));
        Ok(())
    }

    #[test]
    fn a_refusal_that_needs_an_administrator_says_so() -> Res {
        let store = store_with(&temp_dir("auth-flow-admin"), &Secrets::default())?;
        let mock = browser_mock()?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let (result, _) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            |authorize| {
                Ok(vec![format!(
                    "/?error=access_denied&error_description=AADSTS90094%3A+The+grant+requires+admin+permission.&state={}",
                    authorize.state()?
                )])
            },
        )?;
        let error = failure(result)?;
        assert!(matches!(error, Error::AdminApproval { .. }), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("administrator has to approve piikey")
        );
        assert!(!error.to_string().contains("AADSTS"));
        Ok(())
    }

    #[test]
    fn only_the_codes_of_an_administrators_approval_need_one() {
        assert!(needs_admin("consent_required", "AADSTS65001: no consent"));
        assert!(needs_admin("access_denied", "AADSTS90095: request sent"));
        assert!(needs_admin("admin_consent_required", ""));
        assert!(!needs_admin("access_denied", "The user cancelled."));
        assert!(!needs_admin("consent_required", "AADSTS70000"));
    }

    #[test]
    fn a_refusal_with_another_state_is_ignored() -> Res {
        let store = store_with(&temp_dir("auth-flow-forged"), &Secrets::default())?;
        let mock = browser_mock()?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let (result, _) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            |authorize| {
                Ok(vec![
                    "/?error=access_denied&state=forged".to_owned(),
                    format!("/?code=abc&state={}", authorize.state()?),
                ])
            },
        )?;
        result?;
        Ok(())
    }

    #[test]
    fn a_failed_exchange_shows_the_failure_page_and_comes_back_classified() -> Res {
        let store = store_with(&temp_dir("auth-flow-bad-code"), &Secrets::default())?;
        let mock = start(refused("invalid_grant"))?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            good_visit,
        )?;
        let error = failure(result)?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert!(flow.pages[0].contains("could not connect to Box"));
        assert_eq!(store.load(ID)?, Secrets::default());
        Ok(())
    }

    #[test]
    fn no_refresh_token_in_the_answer_is_unexpected() -> Res {
        let store = store_with(&temp_dir("auth-flow-online"), &Secrets::default())?;
        let mock =
            start(|_| Answer::json(200, &json!({"access_token": "at", "expires_in": 3600})))?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            good_visit,
        )?;
        let error = failure(result)?;
        assert!(matches!(error, Error::Unexpected { .. }), "{error:?}");
        assert!(flow.pages[0].contains("could not connect to Box"));
        assert_eq!(store.load(ID)?, Secrets::default());
        Ok(())
    }

    #[test]
    fn cancel_stops_the_wait() -> Res {
        let store = store_with(&temp_dir("auth-flow-cancel"), &Secrets::default())?;
        let mock = browser_mock()?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let cancel = AtomicBool::new(false);
        let open = |_: &str| cancel.store(true, Ordering::SeqCst);
        let error = failure(session.connect_within(&open, &cancel, Duration::from_secs(30)))?;
        assert!(matches!(error, Error::Cancelled), "{error:?}");
        Ok(())
    }

    #[test]
    fn the_wait_for_the_browser_times_out_as_a_sign_in_needed() -> Res {
        let store = store_with(&temp_dir("auth-flow-timeout"), &Secrets::default())?;
        let mock = browser_mock()?;
        let session = session(
            Grant::Browser(browser_grant(&mock, ClientAuth::None)),
            &store,
        );
        let started = Instant::now();
        let error =
            failure(session.connect_within(&|_| {}, &not_cancelled(), Duration::from_millis(120)))?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        Ok(())
    }

    /// A port that was free a moment ago.
    fn free_port() -> Res<u16> {
        Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
    }

    #[test]
    fn the_redirect_path_and_a_fixed_port_are_honoured() -> Res {
        let store = store_with(&temp_dir("auth-flow-path"), &Secrets::default())?;
        let mock = browser_mock()?;
        let port = free_port()?;
        let mut grant = browser_grant(&mock, ClientAuth::None);
        grant.port = port;
        grant.redirect_path = "/callback".to_owned();
        let session = session(Grant::Browser(grant), &store);
        let (result, flow) = run_flow(
            &session,
            &not_cancelled(),
            Duration::from_secs(30),
            |authorize| {
                let state = authorize.state()?;
                Ok(vec![
                    format!("/?code=abc&state={state}"),
                    format!("/callback?code=abc&state={state}"),
                ])
            },
        )?;
        result?;
        let authorize = Authorize::parse(&flow.url);
        assert_eq!(
            authorize.get("redirect_uri")?,
            format!("http://127.0.0.1:{port}/callback")
        );
        assert!(flow.pages[0].starts_with("HTTP/1.1 404"));
        assert!(flow.pages[1].starts_with("HTTP/1.1 200"));
        let seen = mock.seen_at("/token");
        assert_eq!(
            field(&seen[0], "redirect_uri")?,
            format!("http://127.0.0.1:{port}/callback")
        );
        Ok(())
    }

    #[test]
    fn a_port_that_is_taken_is_a_plain_message() -> Res {
        let store = store_with(&temp_dir("auth-flow-taken"), &Secrets::default())?;
        let mock = browser_mock()?;
        let taken = TcpListener::bind(("127.0.0.1", 0))?;
        let mut grant = browser_grant(&mock, ClientAuth::None);
        grant.port = taken.local_addr()?.port();
        let session = session(Grant::Browser(grant), &store);
        let error = failure(session.connect(&|_| {}, &not_cancelled()))?;
        assert!(
            matches!(error, Error::Local(crate::Error::BadRequest(_))),
            "{error:?}"
        );
        Ok(())
    }

    // ---- an app

    fn app_grant(mock: &Mock, credential: AppCredential) -> App {
        App {
            token_url: format!("{}/token", mock.url()),
            client_id: "app-1".to_owned(),
            scope: Some("https://graph.example/.default".to_owned()),
            credential,
            extra: vec![("box_subject_type".to_owned(), "enterprise".to_owned())],
        }
    }

    fn app_tokens() -> Res<Mock> {
        start(|seen| {
            if seen.path() == "/token" {
                Answer::json(
                    200,
                    &json!({"access_token": "at-app", "token_type": "Bearer", "expires_in": 1800}),
                )
            } else {
                Answer::empty(404)
            }
        })
    }

    #[test]
    fn client_credentials_with_the_secret_in_the_body() -> Res {
        let store = store_with(
            &temp_dir("auth-app-body"),
            &Secrets::default().with_client_secret("app-sec"),
        )?;
        let mock = app_tokens()?;
        let grant = app_grant(&mock, AppCredential::Secret(ClientAuth::Body));
        let session = session(Grant::App(grant), &store);
        assert_eq!(session.bearer()?, "at-app");
        let seen = mock.seen_at("/token");
        assert_eq!(field(&seen[0], "grant_type")?, "client_credentials");
        assert_eq!(field(&seen[0], "client_id")?, "app-1");
        assert_eq!(field(&seen[0], "client_secret")?, "app-sec");
        assert_eq!(field(&seen[0], "scope")?, "https://graph.example/.default");
        assert_eq!(field(&seen[0], "box_subject_type")?, "enterprise");
        let kept = store.load(ID)?;
        assert_eq!(kept.access_token.as_deref(), Some("at-app"));
        assert_eq!(kept.client_secret.as_deref(), Some("app-sec"));
        assert!(kept.refresh_token.is_none());
        Ok(())
    }

    #[test]
    fn client_credentials_without_a_scope_send_none() -> Res {
        let store = store_with(
            &temp_dir("auth-app-no-scope"),
            &Secrets::default().with_client_secret("app-sec"),
        )?;
        let mock = app_tokens()?;
        let mut grant = app_grant(&mock, AppCredential::Secret(ClientAuth::Body));
        grant.scope = None;
        let session = session(Grant::App(grant), &store);
        assert_eq!(session.bearer()?, "at-app");
        let seen = mock.seen_at("/token");
        assert!(seen[0].field("scope").is_none());
        assert_eq!(field(&seen[0], "client_secret")?, "app-sec");
        assert!(seen[0].header("authorization").is_none());
        Ok(())
    }

    #[test]
    fn client_credentials_without_the_stored_secret_need_a_sign_in() -> Res {
        let store = store_with(&temp_dir("auth-app-none"), &Secrets::default())?;
        let mock = app_tokens()?;
        let session = session(
            Grant::App(app_grant(&mock, AppCredential::Secret(ClientAuth::Body))),
            &store,
        );
        let error = failure(session.bearer())?;
        assert!(matches!(error, Error::SignInNeeded { .. }), "{error:?}");
        assert!(mock.seen().is_empty());
        Ok(())
    }

    #[test]
    fn connecting_an_app_proves_the_credentials_and_classes_a_refusal() -> Res {
        let store = store_with(
            &temp_dir("auth-app-connect"),
            &Secrets::default().with_client_secret("s"),
        )?;
        let mock = app_tokens()?;
        let grant = app_grant(&mock, AppCredential::Secret(ClientAuth::Body));
        let session = session(Grant::App(grant), &store);
        session.connect(&|_| {}, &not_cancelled())?;
        assert_eq!(store.load(ID)?.access_token.as_deref(), Some("at-app"));
        assert_eq!(session.bearer()?, "at-app");
        assert_eq!(mock.seen_at("/token").len(), 1);

        let mock = start(refused("invalid_client"))?;
        let grant = app_grant(&mock, AppCredential::Secret(ClientAuth::Body));
        let error = failure(session_for_app(grant, &store).connect(&|_| {}, &not_cancelled()))?;
        assert!(matches!(error, Error::Forbidden { .. }), "{error:?}");
        Ok(())
    }

    fn session_for_app(grant: App, store: &TokenStore) -> Session {
        session(Grant::App(grant), store)
    }

    /// The parts of a JWT, after its signature is checked against the test key.
    fn verified(jwt: &str) -> Res<(Value, Value)> {
        let parts: Vec<&str> = jwt.split('.').collect();
        let [header, claims, signature] = parts[..] else {
            return Err("a JWT has three parts".into());
        };
        let der = STANDARD.decode(KEY_PKCS8)?;
        let pair = RsaKeyPair::from_pkcs8(&der).map_err(|_| "the test key is not usable")?;
        UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            pair.public_key().as_ref(),
        )
        .verify(
            format!("{header}.{claims}").as_bytes(),
            &URL_SAFE_NO_PAD.decode(signature)?,
        )
        .map_err(|_| "the signature does not verify")?;
        Ok((
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?,
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims)?)?,
        ))
    }

    fn text<'a>(value: &'a Value, name: &str) -> Res<&'a str> {
        Ok(value
            .get(name)
            .and_then(Value::as_str)
            .ok_or("a JWT field was missing")?)
    }

    fn number(value: &Value, name: &str) -> Res<u64> {
        Ok(value
            .get(name)
            .and_then(Value::as_u64)
            .ok_or("a JWT number was missing")?)
    }

    #[test]
    fn a_certificate_signs_the_assertion() -> Res {
        let dir = temp_dir("auth-cert");
        let store = store_with(&dir, &Secrets::default())?;
        let (key_file, cert_file) = write_key_files(&dir, false)?;
        let mock = app_tokens()?;
        let credential = AppCredential::Certificate {
            key_file,
            cert_file,
        };
        let session = session(Grant::App(app_grant(&mock, credential)), &store);
        assert_eq!(session.bearer()?, "at-app");
        let seen = mock.seen_at("/token");
        assert_eq!(field(&seen[0], "grant_type")?, "client_credentials");
        assert_eq!(field(&seen[0], "client_id")?, "app-1");
        assert_eq!(field(&seen[0], "client_assertion_type")?, ASSERTION_TYPE);
        assert!(seen[0].field("client_secret").is_none());
        let (header, claims) = verified(&field(&seen[0], "client_assertion")?)?;
        let der = STANDARD.decode(CERT)?;
        assert_eq!(text(&header, "alg")?, "RS256");
        assert_eq!(text(&header, "typ")?, "JWT");
        assert_eq!(
            text(&header, "x5t")?,
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &der))
        );
        assert_eq!(
            text(&header, "x5t#S256")?,
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, &der))
        );
        assert_eq!(text(&claims, "aud")?, format!("{}/token", mock.url()));
        assert_eq!(text(&claims, "iss")?, "app-1");
        assert_eq!(text(&claims, "sub")?, "app-1");
        assert_eq!(text(&claims, "jti")?.len(), 32);
        let nbf = number(&claims, "nbf")?;
        assert!(nbf.abs_diff(now_secs()) < 120);
        assert_eq!(number(&claims, "exp")? - nbf, 600);
        Ok(())
    }

    #[test]
    fn a_certificate_assertion_has_a_new_id_every_time() -> Res {
        let dir = temp_dir("auth-cert-jti");
        let (key_file, cert_file) = write_key_files(&dir, true)?;
        let first = certificate_assertion("https://t.example/token", "c", &key_file, &cert_file)?;
        let second = certificate_assertion("https://t.example/token", "c", &key_file, &cert_file)?;
        let (_, one) = verified(&first)?;
        let (_, two) = verified(&second)?;
        assert_ne!(text(&one, "jti")?, text(&two, "jti")?);
        Ok(())
    }

    #[test]
    fn a_certificate_file_that_is_not_pem_is_a_plain_message() -> Res {
        let dir = temp_dir("auth-cert-bad");
        let (key_file, cert_file) = write_key_files(&dir, false)?;
        fs::write(&cert_file, "not a certificate")?;
        let error = failure(certificate_assertion("u", "c", &key_file, &cert_file))?;
        assert!(
            matches!(error, Error::Local(crate::Error::BadRequest(_))),
            "{error:?}"
        );
        let error = failure(certificate_assertion(
            "u",
            "c",
            &key_file,
            &dir.join("missing.pem"),
        ))?;
        assert!(
            matches!(error, Error::Local(crate::Error::Io(_))),
            "{error:?}"
        );
        Ok(())
    }

    /// A Google key file for the test key.
    fn write_google_key(dir: &Path, token_uri: &str) -> Res<PathBuf> {
        let path = dir.join("google.json");
        let key = json!({
            "type": "service_account",
            "client_email": "robot@project.iam.example",
            "private_key": pem("PRIVATE KEY", KEY_PKCS8),
            "token_uri": token_uri,
        });
        fs::write(&path, key.to_string())?;
        Ok(path)
    }

    #[test]
    fn service_account_users_sharing_an_account_id_each_get_their_own_token() -> Res {
        let dir = temp_dir("auth-google-users");
        let store = store_with(&dir, &Secrets::default())?;
        let mock = start(|seen| {
            let claims = seen
                .field("assertion")
                .and_then(|jwt| jwt.split('.').nth(1).map(str::to_owned))
                .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
            match claims
                .as_ref()
                .and_then(|claims| claims.get("sub"))
                .and_then(Value::as_str)
            {
                Some(user) => Answer::json(
                    200,
                    &json!({"access_token": format!("token-of-{user}"), "expires_in": 3600}),
                ),
                None => Answer::empty(400),
            }
        })?;
        let key_file = write_google_key(&dir, &format!("{}/token", mock.url()))?;
        let for_user = |user: &str| {
            session(
                Grant::ServiceAccount(ServiceAccount {
                    key_file: key_file.clone(),
                    user: user.to_owned(),
                    scope: "s".to_owned(),
                    token_url: None,
                }),
                &store,
            )
        };
        let (a, b) = (for_user("a@example.com"), for_user("b@example.com"));
        assert_eq!(a.bearer()?, "token-of-a@example.com");
        assert_eq!(b.bearer()?, "token-of-b@example.com");
        assert_eq!(a.bearer()?, "token-of-a@example.com");
        assert_eq!(mock.seen_at("/token").len(), 2);
        // Nothing of it was written to the store.
        assert_eq!(store.load(ID)?, Secrets::default());
        // `connect` proves the key the same way.
        for_user("c@example.com").connect(&|_| {}, &not_cancelled())?;
        assert_eq!(store.load(ID)?, Secrets::default());
        Ok(())
    }

    #[test]
    fn a_google_service_account_signs_a_jwt_for_the_user() -> Res {
        let dir = temp_dir("auth-google");
        let stores = temp_dir("auth-google-stores");
        let mock = app_tokens()?;
        let target = format!("{}/token", mock.url());
        for (n, explicit) in [true, false].into_iter().enumerate() {
            let store = store_with(&stores.join(n.to_string()), &Secrets::default())?;
            let key_file = write_google_key(
                &dir,
                if explicit {
                    "https://unused.example/token"
                } else {
                    &target
                },
            )?;
            let grant = ServiceAccount {
                key_file,
                user: "someone@example.com".to_owned(),
                scope: "https://www.googleapis.com/auth/drive.readonly".to_owned(),
                token_url: explicit.then(|| target.clone()),
            };
            let session = session(Grant::ServiceAccount(grant), &store);
            assert_eq!(session.bearer()?, "at-app");
        }
        let seen = mock.seen_at("/token");
        assert_eq!(seen.len(), 2);
        for request in &seen {
            assert_eq!(field(request, "grant_type")?, JWT_BEARER_GRANT);
            let (header, claims) = verified(&field(request, "assertion")?)?;
            assert_eq!(text(&header, "alg")?, "RS256");
            assert_eq!(text(&claims, "iss")?, "robot@project.iam.example");
            assert_eq!(text(&claims, "sub")?, "someone@example.com");
            assert_eq!(
                text(&claims, "scope")?,
                "https://www.googleapis.com/auth/drive.readonly"
            );
            assert_eq!(text(&claims, "aud")?, target);
            assert_eq!(number(&claims, "exp")? - number(&claims, "iat")?, 3600);
            assert!(number(&claims, "iat")?.abs_diff(now_secs()) < 120);
        }
        Ok(())
    }

    #[test]
    fn a_google_key_file_that_is_wrong_is_a_plain_message() -> Res {
        let dir = temp_dir("auth-google-bad");
        let store = store_with(&dir, &Secrets::default())?;
        let mock = app_tokens()?;
        let make = |key_file: PathBuf| {
            session(
                Grant::ServiceAccount(ServiceAccount {
                    key_file,
                    user: "u@example.com".to_owned(),
                    scope: "s".to_owned(),
                    token_url: Some(format!("{}/token", mock.url())),
                }),
                &store,
            )
        };
        let path = dir.join("not-json.json");
        fs::write(&path, "this is not json")?;
        let error = failure(make(path).bearer())?;
        assert!(
            matches!(error, Error::Local(crate::Error::BadRequest(_))),
            "{error:?}"
        );
        let path = dir.join("no-key.json");
        fs::write(
            &path,
            json!({"client_email": "a@b", "private_key": "nope"}).to_string(),
        )?;
        let error = failure(make(path).bearer())?;
        assert!(
            matches!(error, Error::Local(crate::Error::BadRequest(_))),
            "{error:?}"
        );
        let error = failure(make(dir.join("missing.json")).bearer())?;
        assert!(
            matches!(error, Error::Local(crate::Error::Io(_))),
            "{error:?}"
        );
        assert!(mock.seen().is_empty());
        Ok(())
    }

    // ---- the private helpers

    #[test]
    fn a_jwt_signer_reads_pkcs8_and_pkcs1_keys() -> Res {
        for text in [
            pem("PRIVATE KEY", KEY_PKCS8),
            pem("RSA PRIVATE KEY", KEY_PKCS1),
        ] {
            let jwt = Jwt::from_pem(&text)?;
            let signed = jwt.sign(&json!({"alg": "RS256"}), &json!({"n": 1}))?;
            let (header, claims) = verified(&signed)?;
            assert_eq!(text_of(&header, "alg"), Some("RS256"));
            assert_eq!(claims.get("n").and_then(Value::as_u64), Some(1));
        }
        Ok(())
    }

    fn text_of<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
        value.get(name).and_then(Value::as_str)
    }

    #[test]
    fn a_key_that_is_encrypted_or_not_a_key_is_a_plain_message() -> Res {
        let cases = [
            pem("ENCRYPTED PRIVATE KEY", KEY_PKCS8),
            pem("EC PRIVATE KEY", KEY_PKCS8),
            pem("PRIVATE KEY", "AAAA"),
            pem("PRIVATE KEY", "!!! not base64 !!!"),
            pem("CERTIFICATE", CERT),
            String::new(),
        ];
        for text in cases {
            let Err(Error::Local(crate::Error::BadRequest(message))) = Jwt::from_pem(&text) else {
                return Err("a plain message was expected".into());
            };
            assert_eq!(message, KEY_PROBLEM);
        }
        Ok(())
    }

    #[test]
    fn a_missing_key_file_names_its_path() -> Res {
        let path = temp_dir("auth-nokey").join("absent.pem");
        let error = failure(read_text(&path))?;
        let Error::Local(crate::Error::Io(io_error)) = &error else {
            return Err("an Io error was expected".into());
        };
        assert_eq!(io_error.kind(), io::ErrorKind::NotFound);
        assert!(io_error.to_string().contains("absent.pem"));
        Ok(())
    }

    #[test]
    fn pem_blocks_are_found_by_label_and_whitespace_is_dropped() {
        let text = format!(
            "{}\n{}",
            pem("CERTIFICATE", "AAAA"),
            pem("PRIVATE KEY", "BBBB")
        )
        .replace('\n', "\r\n  ");
        assert_eq!(
            pem_block(&text, "CERTIFICATE")
                .as_deref()
                .map(Vec::as_slice),
            Some(&[0, 0, 0][..])
        );
        assert_eq!(
            pem_block(&text, "PRIVATE KEY")
                .as_deref()
                .map(Vec::as_slice),
            Some(&[0x04, 0x10, 0x41][..])
        );
        assert!(pem_block(&text, "RSA PRIVATE KEY").is_none());
    }

    #[test]
    fn the_pkce_verifier_is_random_and_has_only_legal_characters() -> Res {
        let one = Pkce::new()?;
        let two = Pkce::new()?;
        assert_ne!(*one.verifier, *two.verifier);
        for pkce in [&one, &two] {
            assert_eq!(pkce.verifier.len(), 64);
            assert!(
                pkce.verifier
                    .bytes()
                    .all(|byte| PKCE_ALPHABET.contains(&byte))
            );
            assert_eq!(
                pkce.challenge,
                URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, pkce.verifier.as_bytes()))
            );
            assert!(!pkce.challenge.contains(['=', '+', '/']));
        }
        Ok(())
    }

    #[test]
    fn percent_decoding_reads_what_a_browser_sends() {
        assert_eq!(percent_decode("a%20b+c%2Fd%zz%4"), "a b c/d%zz%4");
        assert_eq!(
            query_fields("code=4%2F0AX&state=ab&flag&&x="),
            vec![
                ("code".to_owned(), "4/0AX".to_owned()),
                ("state".to_owned(), "ab".to_owned()),
                ("flag".to_owned(), String::new()),
                ("x".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn secrets_say_what_is_set_and_never_what_it_is() {
        let secrets = Secrets::default()
            .with_refresh_token("very-secret")
            .with_client_secret("also");
        let text = format!("{secrets:?}");
        assert!(
            !text.contains("very-secret") && !text.contains("also"),
            "{text}"
        );
        assert!(text.contains("refresh_token: true") && text.contains("access_token: false"));
    }
}
