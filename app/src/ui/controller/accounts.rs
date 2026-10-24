//! The cloud accounts as the controller serves them: the list with how each stands, signing in
//! (on a thread of its own: the person may take minutes in the browser), disconnecting, the
//! folders of an account for the picker, a cloud item's web page, and what a failing account does
//! to the window.
//!
//! A cloud location is scanned and monitored like a folder on this PC: see
//! [`inventory`](super::inventory) and [`watch`](super::watch), which call [`Controller::cloud_failed`]
//! and [`Controller::cloud_worked`] with what an account answers.
//!
//! The accounts themselves (`sources.json`, the tokens, the cursors) belong to
//! [`piikey::sources`] and live in the data folder; the controller holds a copy of the list with
//! what it knows of each, which [`Controller::refresh_accounts`] brings up to date.

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use piikey::{
    Error,
    policy::{Policy, SettingsPatch},
    sources::{self, Account, Accounts, Provider, Resolved, SignIn, TokenStore},
};

use super::{Controller, Notice};
use crate::Res;

/// How long disconnecting an account waits for the scan thread to forget what its locations held.
const FORGET_WAIT: Duration = Duration::from_secs(30);

/// A cloud account as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    pub account: Account,
    pub status: AccountStatus,
}

/// How an account stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStatus {
    /// piikey holds what it needs to read the account, and its last call worked (or none was made).
    Connected,
    /// The person has to sign in: piikey holds nothing that reads the account, or the service no
    /// longer accepts it.
    SignInNeeded,
    /// Something else is wrong, in words for the user: a missing permission, a service that
    /// cannot be reached, tokens that cannot be read.
    Problem(String),
}

impl AccountView {
    /// The words of [`AccountStatus`] for a row: `Connected`, `Needs sign-in` or the problem.
    #[must_use]
    pub fn status_text(&self) -> &str {
        match &self.status {
            AccountStatus::Connected => "Connected",
            AccountStatus::SignInNeeded => "Needs sign-in",
            AccountStatus::Problem(why) => why,
        }
    }
}

/// A sign-in somebody started, as the window follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connecting {
    /// Grows with every sign-in: the window tells its own from an older one by it.
    pub seq: u64,
    pub provider: Provider,
    /// The account's name.
    pub label: String,
    pub state: ConnectState,
}

/// How far a sign-in is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectState {
    /// Waiting for the person in the browser, or for the service to check the credentials.
    Working,
    /// The account is signed in.
    Done,
    /// It did not work; the message says why, in words for the user. Nothing of a new account
    /// stays.
    Failed(String),
    /// Only an administrator of the organization can let piikey in: `why` says so, `link` is
    /// where the administrator approves it. Nothing of a new account stays.
    NeedsApproval { why: String, link: String },
}

/// What the Add account dialog collects: a new account.
#[derive(Clone, PartialEq, Eq)]
pub struct NewAccount {
    pub provider: Provider,
    /// What the person calls it; unique among the accounts of the provider.
    pub label: String,
    pub sign_in: SignIn,
    /// The client secret, for a way to sign in that has one ([`SignIn::needs_secret`]): it goes to
    /// the DPAPI-protected token store, never to the settings.
    pub client_secret: Option<String>,
}

// The secret stays out of a log and out of a failed test's output.
impl fmt::Debug for NewAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewAccount")
            .field("provider", &self.provider)
            .field("label", &self.label)
            .field("sign_in", &self.sign_in)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<hidden>"),
            )
            .finish()
    }
}

/// What disconnecting an account removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedAccount {
    pub account: Account,
    /// The locations that were taken off the list: the account's folders.
    pub locations: Vec<PathBuf>,
    /// How many files of the account the inventory held (they are forgotten).
    pub forgotten: usize,
}

/// What the button of a notice does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoticeAction {
    /// Sign the account in again: `account` is its id, `provider` whose sign-in it is (the
    /// button says "Sign in to Google Drive").
    SignIn { account: String, provider: Provider },
}

/// Whose sign-in to start.
pub(super) enum SignInFor {
    /// A new account: added first, and taken away again when it does not sign in.
    New(NewAccount),
    /// An account that is there: the id.
    Account(String),
}

/// What is wrong with an account, as its last call said.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Issue {
    SignIn,
    Problem(String),
}

/// What the controller keeps of the accounts.
#[derive(Default)]
pub(super) struct AccountsState {
    /// The accounts as `sources.json` has them, with how each stands.
    pub(super) views: Vec<AccountView>,
    /// What is wrong with an account, by its id; gone when a call to it works again.
    issues: HashMap<String, Issue>,
    /// The sign-in that runs or ran last: [`Snapshot::connecting`](super::Snapshot::connecting).
    pub(super) connecting: Option<Connecting>,
    /// Stops the sign-in that runs.
    cancel: Option<Arc<AtomicBool>>,
    /// Numbers the sign-ins.
    seq: u64,
}

impl Controller {
    /// The data folder: where `sources.json`, the tokens and the cursors of the cloud accounts
    /// live, next to the vault.
    pub fn data_dir(&self) -> &Path {
        self.vault_path.parent().unwrap_or_else(|| Path::new("."))
    }

    /// The connected accounts and how each stands, as of the last [`Controller::refresh_accounts`].
    pub fn accounts(&self) -> Vec<AccountView> {
        self.lock().accounts.views.clone()
    }

    /// Whether a connected account holds `path`, a virtual path (`\\Google Drive\jan@acme.com\...`).
    /// A location of that kind may only be added while its account exists.
    pub fn knows_account(&self, path: &Path) -> bool {
        Accounts::open(self.data_dir()).is_ok_and(|accounts| accounts.of(path).is_some())
    }

    /// Applies `patch` to `policy` as [`SettingsPatch::apply`] does, with this controller's data
    /// folder saying which cloud accounts exist.
    ///
    /// # Errors
    /// As [`SettingsPatch::apply`].
    pub fn apply_patch(&self, patch: &SettingsPatch, policy: &mut Policy) -> piikey::Result<()> {
        patch.apply_with(policy, &|path| self.knows_account(path))
    }

    /// Reads the accounts again, with how each stands, and tells the window when that differs.
    /// An account stands as connected when piikey holds what reads it and its last call worked.
    pub(super) fn refresh_accounts(&self) {
        let data = self.data_dir();
        let accounts = match Accounts::open(data) {
            Ok(accounts) => accounts,
            Err(error) => {
                let text = format!("Could not read your connected accounts: {error}");
                let shown = self.lock().notice.as_ref().is_some_and(|n| n.text == text);
                if !shown {
                    self.notify(Notice::error(text));
                }
                return;
            }
        };
        let tokens = TokenStore::new(data);
        let issues = self.lock().accounts.issues.clone();
        let views: Vec<AccountView> = accounts
            .list()
            .iter()
            .map(|account| AccountView {
                status: match account.is_connected(&tokens) {
                    Ok(true) => match issues.get(&account.id) {
                        None => AccountStatus::Connected,
                        Some(Issue::SignIn) => AccountStatus::SignInNeeded,
                        Some(Issue::Problem(why)) => AccountStatus::Problem(why.clone()),
                    },
                    Ok(false) => AccountStatus::SignInNeeded,
                    Err(error) => AccountStatus::Problem(error.to_string()),
                },
                account: account.clone(),
            })
            .collect();
        let known: Vec<&str> = views.iter().map(|view| view.account.id.as_str()).collect();
        let stale = issues.keys().any(|id| !known.contains(&id.as_str()));
        if stale || self.lock().accounts.views != views {
            self.update(|state| {
                state
                    .accounts
                    .issues
                    .retain(|id, _| known.contains(&id.as_str()));
                state.accounts.views.clone_from(&views);
            });
        }
    }

    /// The account with this id.
    ///
    /// # Errors
    /// `BadRequest` when there is none; `Io` when the accounts cannot be read.
    fn find_account(&self, id: &str) -> piikey::Result<Account> {
        Accounts::open(self.data_dir())?
            .get(id)
            .cloned()
            .ok_or_else(|| Error::BadRequest(format!("There is no connected account {id}.")))
    }

    /// Adds an account: its settings and, for a way to sign in that has one, its client secret. It
    /// is not signed in: see [`Controller::connect_account`]. For the API, which asks for each
    /// step on its own; the window's Connect does both, see [`Command::AddAccount`](super::Command).
    ///
    /// # Errors
    /// `BadRequest` for a name, a way to sign in or a value that is not allowed (the message says
    /// which); `Dpapi` or `Io` when the secret or the list cannot be kept.
    pub fn add_account(&self, new: NewAccount) -> piikey::Result<Account> {
        let account = sources::add_account(
            self.data_dir(),
            new.provider,
            &new.label,
            new.sign_in,
            new.client_secret.as_deref(),
        )?;
        self.refresh_accounts();
        Ok(account)
    }

    /// Signs the account with this id in and waits for it: for a person that is the browser (the
    /// backend opens it), for up to five minutes or until `cancel` is set. For the API; the
    /// window does it on a thread of its own, see [`Command::ConnectAccount`](super::Command).
    ///
    /// # Errors
    /// `BadRequest` when there is no such account or the service refuses; `Busy` when it cannot be
    /// reached, is asking piikey to slow down, or `cancel` was set.
    pub fn connect_account(&self, id: &str, cancel: &AtomicBool) -> piikey::Result<Account> {
        let account = self.find_account(id)?;
        self.sign_in(&account, cancel).map_err(Error::from)?;
        self.cloud_worked(&account);
        Ok(account)
    }

    /// Opens the browser at the sign-in address (or, when it cannot be opened, shows the address
    /// in a notice so that the person can open it) and waits for the sign-in of `account`.
    fn sign_in(&self, account: &Account, cancel: &AtomicBool) -> sources::Result<()> {
        let open = |url: &str| {
            if let Err(error) = self.backend.open_url(url) {
                self.notify(Notice::warning(format!(
                    "{error} Open this address in your browser to sign in: {url}"
                )));
            }
        };
        self.backend.connect(account, &open, cancel)
    }

    /// Starts the sign-in of `what` on a thread of its own and shows it as
    /// [`Snapshot::connecting`](super::Snapshot::connecting). One sign-in at a time.
    pub(super) fn start_sign_in(self: &Arc<Self>, what: SignInFor) {
        let (provider, label) = match &what {
            SignInFor::New(new) => (new.provider, new.label.trim().to_owned()),
            SignInFor::Account(id) => match self.find_account(id) {
                Ok(account) => (account.provider, account.label),
                Err(error) => {
                    self.notify(Notice::error(error.to_string()));
                    return;
                }
            },
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let started = self.update(|state| {
            let working = state
                .accounts
                .connecting
                .as_ref()
                .is_some_and(|connecting| connecting.state == ConnectState::Working);
            if working {
                return None;
            }
            state.accounts.seq += 1;
            let seq = state.accounts.seq;
            state.accounts.cancel = Some(Arc::clone(&cancel));
            state.accounts.connecting = Some(Connecting {
                seq,
                provider,
                label,
                state: ConnectState::Working,
            });
            Some(seq)
        });
        let Some(seq) = started else {
            self.notify(Notice::warning(
                "Finish the sign-in that is open first, or stop it.",
            ));
            return;
        };
        let controller = Arc::downgrade(self);
        let spawned = thread::Builder::new()
            .name("piikey-signin".into())
            .spawn(move || {
                if let Some(controller) = controller.upgrade() {
                    controller.run_sign_in(seq, what, &cancel);
                }
            });
        if let Err(error) = spawned {
            self.sign_in_ended(
                seq,
                ConnectState::Failed(format!("Could not start the sign-in: {error}")),
            );
        }
    }

    /// The sign-in thread: does it and says how it went.
    fn run_sign_in(&self, seq: u64, what: SignInFor, cancel: &AtomicBool) {
        let again = match &what {
            SignInFor::Account(id) => Some(id.clone()),
            SignInFor::New(_) => None,
        };
        let approval = match &what {
            SignInFor::New(new) => new.sign_in.admin_consent_url(),
            SignInFor::Account(id) => self
                .find_account(id)
                .ok()
                .and_then(|account| account.sign_in.admin_consent_url()),
        };
        let result = match what {
            SignInFor::New(new) => self.add_and_sign_in(new, cancel),
            SignInFor::Account(id) => self
                .find_account(&id)
                .map_err(sources::Error::from)
                .and_then(|account| {
                    self.sign_in(&account, cancel)?;
                    self.cloud_worked(&account);
                    Ok(())
                }),
        };
        if result.is_ok() {
            // The notice that asked for this sign-in has done its work.
            if let Some(id) = again {
                self.update(|state| {
                    let asked = state.notice.as_ref().is_some_and(|notice| {
                        matches!(&notice.action, Some(NoticeAction::SignIn { account, .. }) if *account == id)
                    });
                    if asked {
                        state.notice = None;
                    }
                });
            }
        }
        self.sign_in_ended(
            seq,
            match result {
                Ok(()) => ConnectState::Done,
                Err(sources::Error::Cancelled) => {
                    ConnectState::Failed("The sign-in was stopped.".to_owned())
                }
                Err(error @ sources::Error::AdminApproval { .. }) => match approval {
                    Some(link) => ConnectState::NeedsApproval {
                        why: error.to_string(),
                        link,
                    },
                    None => ConnectState::Failed(error.to_string()),
                },
                Err(error) => ConnectState::Failed(error.to_string()),
            },
        );
    }

    /// Adds the account and signs it in; when that fails nothing of it stays.
    fn add_and_sign_in(&self, new: NewAccount, cancel: &AtomicBool) -> sources::Result<()> {
        let account = self.add_account(new)?;
        let signed_in = self.sign_in(&account, cancel);
        if signed_in.is_err() {
            if let Err(error) = sources::remove_account(self.data_dir(), &account.id) {
                self.notify(Notice::error(format!(
                    "Could not take {} away again: {error}",
                    account.label
                )));
            }
            self.refresh_accounts();
        } else {
            self.cloud_worked(&account);
        }
        signed_in
    }

    /// The sign-in numbered `seq` is over.
    fn sign_in_ended(&self, seq: u64, state: ConnectState) {
        self.update(|inner| {
            if let Some(connecting) = inner
                .accounts
                .connecting
                .as_mut()
                .filter(|connecting| connecting.seq == seq)
            {
                connecting.state = state;
                inner.accounts.cancel = None;
            }
        });
    }

    /// Stops the sign-in numbered `seq` if it still waits for the browser.
    pub(super) fn cancel_sign_in(&self, seq: u64) {
        let state = self.lock();
        let working = state
            .accounts
            .connecting
            .as_ref()
            .is_some_and(|connecting| {
                connecting.seq == seq && connecting.state == ConnectState::Working
            });
        if working && let Some(cancel) = &state.accounts.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Disconnects the account with this id, for [`Command::RemoveAccount`](super::Command).
    pub(super) fn disconnect_account(&self, id: &str) {
        if let Err(error) = self.remove_account(id) {
            self.notify(Notice::error(format!(
                "Could not disconnect the account: {error}"
            )));
        }
    }

    /// Disconnects the account with this id: its locations come off the list (which stops what
    /// scans and monitors them), what the inventory holds of it is forgotten, and what piikey keeps
    /// of it (the settings, the secrets, the cursors) is deleted. Waits until the scan thread has
    /// forgotten what the locations held.
    ///
    /// # Errors
    /// `BadRequest` when there is no such account, or when the settings cannot be saved (then
    /// nothing is removed); `Io`, `Busy` and `Dpapi` when what is kept cannot be deleted.
    pub fn remove_account(&self, id: &str) -> piikey::Result<RemovedAccount> {
        let controller = self
            .me
            .upgrade()
            .ok_or_else(|| Error::Busy("piikey is shutting down".to_owned()))?;
        let account = self.find_account(id)?;
        let root = account.root();
        let forgotten = self.inventory.entries(Some(&root), 0).len();
        // What the account holds goes first: nothing is scanned of it while it goes.
        let mut policy = self.policy();
        let locations = policy.remove_under(&root);
        if !locations.is_empty() && !controller.commit(&policy) {
            return Err(Error::BadRequest(
                "The settings could not be saved, so the account stays.".to_owned(),
            ));
        }
        self.wait_scans(FORGET_WAIT);
        self.inventory.forget_under(&root)?;
        sources::remove_account(self.data_dir(), &account.id)?;
        let totals = self.inventory.totals();
        self.update(|state| state.inventory_totals = totals);
        self.refresh_accounts();
        Ok(RemovedAccount {
            account,
            locations,
            forgotten,
        })
    }

    /// The folders directly in `under`, a virtual path of the account with this id, or the top of
    /// the account (its drives, sites or "My Drive") for `None`: what the folder picker lists.
    /// Waits on the service, so it is for the background.
    ///
    /// # Errors
    /// `BadRequest` when there is no such account or `under` is no folder of it; `Busy` when the
    /// service cannot be reached; the message says what to do.
    pub fn browse_cloud(&self, id: &str, under: Option<&Path>) -> piikey::Result<Vec<PathBuf>> {
        let account = self.find_account(id)?;
        let connector = self.backend.connector(&account).map_err(Error::from)?;
        match sources::browse(&*connector, under) {
            Ok(folders) => {
                self.cloud_worked(&account);
                Ok(folders.into_iter().map(|folder| folder.path).collect())
            }
            Err(error) => {
                self.note_issue(&account, &error);
                Err(error.into())
            }
        }
    }

    /// Where a browser opens the file or folder at `path`, a virtual path of a connected account.
    /// Waits on the service, so it is for the background.
    ///
    /// # Errors
    /// `BadRequest` when `path` is not in a connected account or the provider has no page for it;
    /// the errors of the account otherwise.
    pub fn web_url(&self, path: &Path) -> piikey::Result<String> {
        let account = Accounts::open(self.data_dir())?
            .of(path)
            .cloned()
            .ok_or_else(|| {
                Error::BadRequest(format!(
                    "{} is not in a connected account.",
                    sources::shown(path)
                ))
            })?;
        let connector = self.backend.connector(&account).map_err(Error::from)?;
        let url = match connector.resolve(path).map_err(Error::from)? {
            Resolved::File(item) => item.web_url,
            Resolved::Folder(folder) => folder.web_url,
        };
        if url.is_empty() {
            return Err(Error::BadRequest(format!(
                "{} has no web page for this.",
                account.provider.name()
            )));
        }
        Ok(url)
    }

    /// Opens `url` in the user's browser.
    ///
    /// # Errors
    /// The message says why it could not be opened.
    pub fn open_url(&self, url: &str) -> Res<()> {
        self.backend.open_url(url)
    }

    /// What a failed call to a cloud location does to the window, and the words for the
    /// location's row: it is remembered as what is wrong with the account (its row in Settings
    /// says), and the user is told once, when it is news: a sign-in that has to be done again
    /// raises a notice whose button signs in, any other failure a plain notice. `account` is
    /// `None` when the location has none any more.
    pub(super) fn cloud_failed(&self, account: Option<&Account>, error: &sources::Error) -> String {
        let text = error.to_string();
        let Some(account) = account else {
            return text;
        };
        if self.note_issue(account, error) {
            let notice = match error {
                sources::Error::SignInNeeded { provider, .. } => Notice::warning(text.clone())
                    .with_action(NoticeAction::SignIn {
                        account: account.id.clone(),
                        provider: *provider,
                    }),
                other if other.is_transient() => {
                    Notice::warning(format!("{}: {text}", account.label))
                }
                _ => Notice::error(format!("{}: {text}", account.label)),
            };
            self.notify(notice);
        }
        text
    }

    /// A call to `account` worked: nothing is wrong with it now.
    pub(super) fn cloud_worked(&self, account: &Account) {
        let had = self.lock().accounts.issues.contains_key(&account.id);
        if had {
            self.update(|state| {
                state.accounts.issues.remove(&account.id);
            });
        }
        self.refresh_accounts();
    }

    /// Remembers what a failed call says is wrong with `account`; `true` when that is news.
    fn note_issue(&self, account: &Account, error: &sources::Error) -> bool {
        let issue = match error {
            sources::Error::Cancelled => return false,
            sources::Error::SignInNeeded { .. } => Issue::SignIn,
            other => Issue::Problem(other.to_string()),
        };
        let news = self.lock().accounts.issues.get(&account.id) != Some(&issue);
        if news {
            self.update(|state| {
                state.accounts.issues.insert(account.id.clone(), issue);
            });
            self.refresh_accounts();
        }
        news
    }
}
