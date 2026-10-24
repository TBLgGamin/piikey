//! What the window keeps for Settings > Connected accounts and for the Add account dialog, and
//! what their controls do. The pages draw it ([`pages::accounts`](crate::ui::pages)); the
//! controller does the work ([`Command::AddAccount`] and the other account commands).
//!
//! The dialog's values are kept as the person typed them, by the key of their field (the page
//! says which fields a way to sign in has). Nothing is checked here: the page builds the
//! [`NewAccount`] when its fields are complete, and Connect hands it over. The client secret is
//! the one value that never stays: Connect and every way out of the dialog drop it.

use std::{collections::HashMap, path::PathBuf};

use piikey::sources::Provider;
use windows_reactor::ComponentContext;

use super::{MainWindow, Msg};
use crate::ui::controller::{Command, ConnectState, Connecting, NewAccount, NoticeAction};

/// Where the Add account dialog is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Which service.
    Provider,
    /// How to sign in to it; skipped when it has one way.
    Way,
    /// What that way needs.
    Fields,
    /// Connect was pressed: waiting for the browser or for the service to check the credentials.
    Working,
}

/// A sign-in that the dialog started: how it is told from the others in the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    provider: Provider,
    label: String,
    /// The number of the newest sign-in there was before, so an older one is never taken for it.
    after: u64,
}

impl Pending {
    fn is(&self, connecting: &Connecting) -> bool {
        connecting.seq > self.after
            && connecting.provider == self.provider
            && connecting.label == self.label
    }
}

/// What the Connected accounts section and the Add account dialog ask of the window.
#[derive(Clone)]
pub enum AccountMsg {
    /// "Add account": opens the dialog at its first step.
    Add,
    /// The dialog was closed or cancelled; a sign-in that waits is stopped.
    Close,
    /// A service was picked.
    Provider(Provider),
    /// A way to sign in was picked: its place in the page's list for the service.
    Way(usize),
    /// Next or Back: the step to show.
    Go(Step),
    /// The text or the choice of the field with this key.
    Field(&'static str, String),
    /// The client secret.
    Secret(String),
    /// "Browse...": picks a file for the field with this key; the title is the picker's.
    Pick(&'static str, &'static str),
    /// A file was picked for the field with this key.
    Picked(&'static str, PathBuf),
    /// Connect: add the account and sign it in.
    Connect(Box<NewAccount>),
    /// "Copy approval link": puts the link that lets an administrator approve piikey on the
    /// clipboard.
    CopyApproval,
    /// The link is on the clipboard.
    ApprovalCopied,
    /// "Sign in again" on the account with this id.
    SignIn(String),
    /// "Disconnect" on the account with this id: asks first.
    Disconnect(String),
    /// The answer to that question: `true` disconnects.
    Disconnected(bool),
}

/// What the Connected accounts section and the Add account dialog keep.
#[derive(Default)]
pub struct AccountsState {
    /// The step of the Add account dialog; `None` while it is closed.
    pub(in crate::ui) step: Option<Step>,
    pub(in crate::ui) provider: Option<Provider>,
    /// The way to sign in, as its place in the page's list for `provider`.
    pub(in crate::ui) way: usize,
    /// What was typed or chosen, by field key.
    pub(in crate::ui) values: HashMap<&'static str, String>,
    pub(in crate::ui) secret: String,
    /// Why the last Connect did not work, in words for the user.
    pub(in crate::ui) failure: Option<String>,
    /// Where an administrator approves piikey, when that is why it did not work.
    pub(in crate::ui) approval: Option<String>,
    /// The approval link was copied.
    pub(in crate::ui) approval_copied: bool,
    /// The sign-in the dialog waits for, once Connect was pressed.
    pending: Option<Pending>,
    /// Its number, once the snapshot has shown it: what Cancel stops.
    seq: Option<u64>,
    /// A sign-in whose dialog was closed before the snapshot showed it: stopped when it shows.
    abandoned: Option<Pending>,
    /// The id of the account whose Disconnect asks its question.
    pub(in crate::ui) disconnecting: Option<String>,
}

impl AccountsState {
    /// Closes the Add account dialog and forgets what it held, the secret first.
    fn end(&mut self) {
        self.secret.clear();
        self.values.clear();
        self.step = None;
        self.provider = None;
        self.way = 0;
        self.failure = None;
        self.approval = None;
        self.approval_copied = false;
        self.pending = None;
        self.seq = None;
    }
}

impl MainWindow {
    /// Runs what a control of the accounts asks for.
    pub(super) fn update_accounts(
        &mut self,
        message: AccountMsg,
        context: &ComponentContext<Self>,
    ) {
        match message {
            AccountMsg::Add => {
                self.accounts.end();
                self.accounts.step = Some(Step::Provider);
            }
            AccountMsg::Close => self.close_add_account(),
            AccountMsg::Provider(provider) => {
                if self.accounts.provider != Some(provider) {
                    self.accounts.way = 0;
                    self.accounts.secret.clear();
                }
                self.accounts.provider = Some(provider);
            }
            AccountMsg::Way(way) => {
                if self.accounts.way != way {
                    self.accounts.secret.clear();
                }
                self.accounts.way = way;
            }
            AccountMsg::Go(step) => {
                let reachable = match step {
                    Step::Provider => true,
                    Step::Way | Step::Fields => self.accounts.provider.is_some(),
                    Step::Working => false,
                };
                if reachable && self.accounts.step.is_some() {
                    self.accounts.step = Some(step);
                    self.accounts.failure = None;
                    self.accounts.approval = None;
                    self.accounts.approval_copied = false;
                }
            }
            AccountMsg::Field(key, text) => {
                self.accounts.values.insert(key, text);
            }
            AccountMsg::Secret(text) => self.accounts.secret = text,
            AccountMsg::Pick(key, title) => {
                context.spawn_background(move |_| {
                    rfd::FileDialog::new()
                        .set_title(title)
                        .pick_file()
                        .map_or(Msg::Noop, |path| {
                            Msg::Account(AccountMsg::Picked(key, path))
                        })
                });
            }
            AccountMsg::Picked(key, path) => {
                self.accounts.values.insert(key, path.display().to_string());
            }
            AccountMsg::Connect(new) => self.connect_new_account(*new),
            AccountMsg::CopyApproval => {
                if let Some(link) = self.accounts.approval.clone() {
                    self.background(context, move |_| {
                        clipboard_win::set_clipboard_string(&link)
                            .map_err(|error| format!("Could not copy the link: {error}"))?;
                        Ok(Msg::Account(AccountMsg::ApprovalCopied))
                    });
                }
            }
            AccountMsg::ApprovalCopied => self.accounts.approval_copied = true,
            AccountMsg::SignIn(id) => self.input.controller.submit(Command::ConnectAccount(id)),
            AccountMsg::Disconnect(id) => self.accounts.disconnecting = Some(id),
            AccountMsg::Disconnected(yes) => {
                if let Some(id) = self.accounts.disconnecting.take().filter(|_| yes) {
                    self.input.controller.submit(Command::RemoveAccount(id));
                }
            }
        }
    }

    /// Connect: hands the new account to the controller, which adds it and signs it in, and waits
    /// for what the snapshot says of that. The secret leaves the window with it.
    fn connect_new_account(&mut self, new: NewAccount) {
        let working = self
            .snap
            .connecting
            .as_ref()
            .is_some_and(|connecting| connecting.state == ConnectState::Working);
        if working {
            // The controller does one sign-in at a time and would refuse this one.
            self.accounts.failure =
                Some("Finish the sign-in that is open first, or stop it.".to_owned());
            return;
        }
        self.accounts.secret.clear();
        self.accounts.failure = None;
        self.accounts.approval = None;
        self.accounts.approval_copied = false;
        self.accounts.seq = None;
        self.accounts.pending = Some(Pending {
            provider: new.provider,
            label: new.label.trim().to_owned(),
            after: self
                .snap
                .connecting
                .as_ref()
                .map_or(0, |connecting| connecting.seq),
        });
        self.accounts.step = Some(Step::Working);
        self.input.controller.submit(Command::AddAccount(new));
    }

    /// The dialog was closed. A sign-in that waits for the browser is stopped; one that the
    /// controller has not shown yet is stopped as soon as it shows.
    fn close_add_account(&mut self) {
        if self.accounts.step == Some(Step::Working) {
            match self.accounts.seq {
                Some(seq) => self.input.controller.submit(Command::CancelConnect(seq)),
                None => self.accounts.abandoned = self.accounts.pending.take(),
            }
        }
        self.accounts.end();
    }

    /// A snapshot came: what the dialog waits for may have happened, and the account a Disconnect
    /// asks about may be gone.
    pub(super) fn adopt_accounts(&mut self, _context: &ComponentContext<Self>) {
        if let Some(id) = &self.accounts.disconnecting
            && !self.snap.accounts.iter().any(|view| view.account.id == *id)
        {
            self.accounts.disconnecting = None;
        }
        let Some(connecting) = self.snap.connecting.clone() else {
            return;
        };
        if self
            .accounts
            .abandoned
            .as_ref()
            .is_some_and(|pending| pending.is(&connecting))
        {
            if connecting.state == ConnectState::Working {
                self.input
                    .controller
                    .submit(Command::CancelConnect(connecting.seq));
            }
            self.accounts.abandoned = None;
        }
        if self.accounts.step != Some(Step::Working)
            || !self
                .accounts
                .pending
                .as_ref()
                .is_some_and(|pending| pending.is(&connecting))
        {
            return;
        }
        self.accounts.seq = Some(connecting.seq);
        match connecting.state {
            ConnectState::Working => {}
            ConnectState::Done => self.accounts.end(),
            ConnectState::Failed(text) => {
                self.accounts.step = Some(Step::Fields);
                self.accounts.failure = Some(text);
                self.accounts.pending = None;
                self.accounts.seq = None;
            }
            ConnectState::NeedsApproval { why, link } => {
                self.accounts.step = Some(Step::Fields);
                self.accounts.failure = Some(why);
                self.accounts.approval = Some(link);
                self.accounts.approval_copied = false;
                self.accounts.pending = None;
                self.accounts.seq = None;
            }
        }
    }

    /// The button of the notice on show does what the notice asks for.
    pub(super) fn notice_button(&mut self, action: NoticeAction) {
        match action {
            NoticeAction::SignIn { account, .. } => self
                .input
                .controller
                .submit(Command::ConnectAccount(account)),
        }
    }
}
