//! What the window keeps for the Browse cloud dialog of Inventory: the account and the folder
//! being looked at, what the account listed there, and what the dialog's controls do. The page
//! draws it ([`pages::cloud`](crate::ui::pages)); the controller lists the folders
//! ([`Controller::browse_cloud`](crate::ui::controller::Controller::browse_cloud)) and adds the
//! chosen one as a location ([`Command::AddLocation`](crate::ui::controller::Command)).
//!
//! A listing waits on the service, so it runs in the background, and every one has a number: what
//! comes back for a folder the user has left is dropped.

use std::{
    cmp::Ordering,
    path::{Path, PathBuf},
    sync::Arc,
};

use piikey::sources;
use windows_reactor::ComponentContext;

use super::{MainWindow, Msg};
use crate::ui::controller::Command;

/// What the Browse cloud dialog asks of the window.
#[derive(Clone)]
pub enum CloudMsg {
    /// "Browse cloud" of Inventory: the dialog opens at the top of the first account.
    Open,
    /// An account picked in the dialog, by its place in the list of accounts.
    Account(usize),
    /// A folder of the listing opened.
    Enter(PathBuf),
    /// The way up, one folder.
    Up,
    /// Ask for the listing again, after it failed.
    Retry,
    /// What the listing with this number brought: the folders, or why it failed.
    Listed(u64, Result<Vec<PathBuf>, String>),
    /// "Choose this folder": it becomes a location, and is scanned.
    Choose,
    /// The dialog was closed or cancelled.
    Close,
}

/// What the Browse cloud dialog keeps.
#[derive(Default)]
pub struct CloudState {
    /// The dialog is open.
    pub(in crate::ui) open: bool,
    /// The account being looked at, by its id.
    pub(in crate::ui) account: String,
    /// The folder being looked at, a virtual path; `None` is the top of the account.
    pub(in crate::ui) at: Option<PathBuf>,
    /// The folders directly in `at`; `None` while they are being asked for.
    pub(in crate::ui) listing: Option<Result<Vec<PathBuf>, String>>,
    /// The number of the latest listing asked for.
    seq: u64,
}

impl CloudState {
    /// The folder above `at`, or `None` when that is the top of the account.
    fn up(at: &Path) -> Option<PathBuf> {
        let parent = at.parent()?;
        sources::parse_virtual(parent)
            .filter(|above| !above.rest.as_os_str().is_empty())
            .map(|_| parent.to_path_buf())
    }

    /// The dialog is shut: what it kept goes, and a listing that is still coming is not wanted.
    fn close(&mut self) {
        self.open = false;
        self.account.clear();
        self.at = None;
        self.listing = None;
        self.seq += 1;
    }
}

/// How the folders of a listing are ordered: by name, without regard to letter case, as Explorer
/// does.
fn by_name(a: &Path, b: &Path) -> Ordering {
    let name = |path: &Path| {
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase()
    };
    name(a).cmp(&name(b)).then_with(|| a.cmp(b))
}

impl MainWindow {
    /// Asks the controller, in the background, for the folders directly in the place on show.
    fn list_cloud(&mut self, context: &ComponentContext<Self>) {
        let cloud = &mut self.cloud;
        cloud.seq += 1;
        cloud.listing = None;
        let number = cloud.seq;
        let account = cloud.account.clone();
        let at = cloud.at.clone();
        let controller = Arc::clone(&self.input.controller.0);
        context.spawn_background(move |_| {
            let listed = controller
                .browse_cloud(&account, at.as_deref())
                .map_err(|error| error.to_string());
            Msg::Cloud(CloudMsg::Listed(number, listed))
        });
    }

    /// Shows `at` of the account on show, and asks for its folders.
    fn look_at(&mut self, at: Option<PathBuf>, context: &ComponentContext<Self>) {
        self.cloud.at = at;
        self.list_cloud(context);
    }

    /// Runs what a control of the dialog asks for.
    pub(super) fn update_cloud(&mut self, message: CloudMsg, context: &ComponentContext<Self>) {
        match message {
            CloudMsg::Open => {
                let Some(first) = self.snap.accounts.first() else {
                    return;
                };
                self.cloud.open = true;
                self.cloud.account.clone_from(&first.account.id);
                self.look_at(None, context);
            }
            CloudMsg::Account(index) => {
                let Some(picked) = self.snap.accounts.get(index) else {
                    return;
                };
                if self.cloud.open && picked.account.id != self.cloud.account {
                    self.cloud.account.clone_from(&picked.account.id);
                    self.look_at(None, context);
                }
            }
            CloudMsg::Enter(folder) => {
                if self.cloud.open {
                    self.look_at(Some(folder), context);
                }
            }
            CloudMsg::Up => {
                if self.cloud.open
                    && let Some(at) = self.cloud.at.clone()
                {
                    self.look_at(CloudState::up(&at), context);
                }
            }
            CloudMsg::Retry => {
                if self.cloud.open {
                    self.list_cloud(context);
                }
            }
            CloudMsg::Listed(number, listed) => {
                if self.cloud.open && number == self.cloud.seq {
                    self.cloud.listing = Some(listed.map(|mut folders| {
                        folders.sort_by(|a, b| by_name(a, b));
                        folders
                    }));
                }
            }
            CloudMsg::Choose => {
                // The top of an account is not a folder to scan: the button is off there.
                if self.cloud.open
                    && let Some(folder) = self.cloud.at.clone()
                {
                    self.input.controller.submit(Command::AddLocation(folder));
                }
                self.cloud.close();
            }
            CloudMsg::Close => self.cloud.close(),
        }
    }

    /// A snapshot came: the dialog closes when the account it looks at is gone (disconnected in
    /// Settings, or from the command line).
    pub(super) fn adopt_cloud(&mut self, _context: &ComponentContext<Self>) {
        if self.cloud.open
            && !self
                .snap
                .accounts
                .iter()
                .any(|view| view.account.id == self.cloud.account)
        {
            self.cloud.close();
        }
    }
}
