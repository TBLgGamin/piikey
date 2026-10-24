//! Connected accounts: the section of Settings that lists the cloud accounts piikey may read, and
//! the dialogs of adding and disconnecting one.
//!
//! What the Add account dialog asks is a catalog of plain data and functions ([`modes`],
//! [`fields`], [`build`], [`problem`], [`help`]): the ways to sign in each service has, the fields
//! each way needs, the [`NewAccount`] the typed values make, and what is still missing. The dialog's
//! widgets only draw the catalog. The window keeps the values by field key.

use std::{collections::HashMap, path::PathBuf, rc::Rc};

use piikey::sources::{BoxSubject, Credential, Provider, SignIn};
use windows_reactor::{
    Button, ButtonStyle, ComboBox, ContentDialog, ContentDialogButton, ContentDialogResult, Grid,
    GridLength, HorizontalAlignment, InfoBarSeverity, Orientation, PasswordBox, PasswordRevealMode,
    ProgressRing, RadioButton, RadioButtons, StackPanel, TextBlock, TextBox, TextWrapping,
    VerticalAlignment, View,
};

use super::kit::{
    Context, Row, body, caption, info, provider_icon, section_with, subtitle, toned_glyph, web_link,
};
use crate::ui::{
    assets,
    controller::{AccountStatus, AccountView, ConnectState, Connecting, NewAccount},
    status::Tone,
    window::{AccountMsg, MainWindow, Msg, Step},
};

/// The size of every provider logo: small, so no provider outshines piikey.
const LOGO: f64 = 24.0;
/// How wide the Add account dialog's content is, in DIPs.
const DIALOG_WIDTH: f64 = 460.0;
/// How wide the words of an account's state run before they wrap, in DIPs.
const STATE_WIDTH: f64 = 220.0;
/// The rows of a box that takes one entry per line.
const LINES_HEIGHT: f64 = 88.0;

/// What the section is for, in one line.
const INTRO: &str =
    "Scan the files in your cloud storage. piikey only reads them, and nothing leaves this PC.";

// ---- The catalog ----

/// What the person typed or chose, by the key of its field.
type Values = HashMap<&'static str, String>;

const NAME: &str = "name";
const TENANT: &str = "tenant";
const CLIENT_ID: &str = "client_id";
const CREDENTIAL: &str = "credential";
const KEY_FILE: &str = "key_file";
const CERT_FILE: &str = "cert_file";
const SITES: &str = "sites";
const SERVICE_KEY: &str = "service_key";
const USERS: &str = "users";
const APP_KEY: &str = "app_key";
const ACT_AS: &str = "act_as";
const ACT_ID: &str = "act_id";
/// The key of the client secret's field: its value is kept apart from the others.
const CLIENT_SECRET: &str = "client_secret";

/// The tenant of a personal Microsoft account.
const PERSONAL_TENANT: &str = "consumers";

/// How an app proves who it is, as the dialog offers it: the key of the choice and its words.
const CREDENTIALS: &[(&str, &str)] = &[("secret", "Client secret"), ("certificate", "Certificate")];
/// Whom a Box app acts as.
const SUBJECTS: &[(&str, &str)] = &[("enterprise", "Enterprise ID"), ("user", "User ID")];

/// A way to sign in that the dialog offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    MicrosoftBrowser,
    MicrosoftApp,
    MicrosoftAppSelected,
    OneDriveBrowser,
    GoogleBrowser,
    GoogleServiceAccount,
    DropboxBrowser,
    BoxBrowser,
    BoxApp,
}

/// The ways to sign in that `provider` has, the usual one first.
const fn modes(provider: Provider) -> &'static [Mode] {
    match provider {
        Provider::Microsoft365 => &[
            Mode::MicrosoftBrowser,
            Mode::MicrosoftApp,
            Mode::MicrosoftAppSelected,
        ],
        Provider::OneDrive => &[Mode::OneDriveBrowser],
        Provider::GoogleDrive => &[Mode::GoogleBrowser, Mode::GoogleServiceAccount],
        Provider::Dropbox => &[Mode::DropboxBrowser],
        Provider::Box => &[Mode::BoxBrowser, Mode::BoxApp],
    }
}

impl Mode {
    /// The way an account that is there signs in.
    const fn of(sign_in: &SignIn) -> Self {
        match sign_in {
            SignIn::MicrosoftDelegated { .. } => Self::MicrosoftBrowser,
            SignIn::MicrosoftApp { .. } => Self::MicrosoftApp,
            SignIn::MicrosoftAppSelected { .. } => Self::MicrosoftAppSelected,
            SignIn::GoogleDelegated { .. } => Self::GoogleBrowser,
            SignIn::GoogleServiceAccount { .. } => Self::GoogleServiceAccount,
            SignIn::DropboxDelegated { .. } => Self::DropboxBrowser,
            SignIn::BoxDelegated { .. } => Self::BoxBrowser,
            SignIn::BoxApp { .. } => Self::BoxApp,
        }
    }

    /// What the way is called.
    const fn label(self) -> &'static str {
        match self {
            Self::MicrosoftBrowser
            | Self::OneDriveBrowser
            | Self::GoogleBrowser
            | Self::DropboxBrowser
            | Self::BoxBrowser => "Sign in with a browser",
            Self::MicrosoftApp => "App registration, whole tenant",
            Self::MicrosoftAppSelected => "App registration, selected sites",
            Self::GoogleServiceAccount => "Service account (Google Workspace)",
            Self::BoxApp => "App (client credentials)",
        }
    }
}

/// What to register at the provider for `mode` and what to paste here: one paragraph, in plain
/// words. The redirect addresses are the ones the sign-in sends.
const fn help(mode: Mode) -> &'static str {
    match mode {
        Mode::MicrosoftBrowser => {
            "Register an app in Microsoft Entra ID (Azure) as a public client: in Authentication, add the platform Mobile and desktop applications with the redirect address http://localhost, and in API permissions add Files.Read.All and Sites.Read.All as delegated permissions. You then sign in with your work or school account in your browser, and piikey reads what you can read. The tenant is its ID, its domain, or organizations for any work or school account."
        }
        Mode::MicrosoftApp => {
            "Register an app in Microsoft Entra ID (Azure) and give it the application permissions Files.Read.All and Sites.Read.All, with consent from an administrator. The app reads the whole tenant and nobody signs in. It proves who it is with a client secret, or with a certificate: keep the private key and the certificate as PEM files on this PC."
        }
        Mode::MicrosoftAppSelected => {
            "Register an app in Microsoft Entra ID (Azure) and give it the application permission Sites.Selected, then have an administrator grant it read access to each site. The app reads only those sites, so list them here, one address per line, such as https://contoso.sharepoint.com/sites/Finance. It proves who it is with a client secret, or with a certificate: keep the private key and the certificate as PEM files on this PC."
        }
        Mode::OneDriveBrowser => {
            "Register an app in Microsoft Entra ID (Azure) for personal Microsoft accounts as a public client: in Authentication, add the platform Mobile and desktop applications with the redirect address http://localhost, and in API permissions add Files.Read as a delegated permission. You then sign in with your own Microsoft account in your browser."
        }
        Mode::GoogleBrowser => {
            "In the Google Cloud console, turn on the Google Drive API and create a client ID of the type Desktop app; there is no redirect address to register. You then sign in with your Google account in your browser, and piikey reads what you can read."
        }
        Mode::GoogleServiceAccount => {
            "For Google Workspace. In the Google Cloud console, create a service account, save its JSON key file, and in the Workspace admin console give it domain-wide delegation for the read-only Drive scope. piikey reads the Drive of each user you list, as that user."
        }
        Mode::DropboxBrowser => {
            "In the Dropbox App Console, create an app with the permissions files.metadata.read and files.content.read, and add exactly this redirect address: http://127.0.0.1:53123/. You then sign in with your Dropbox account in your browser. The app key is on the app's Settings tab."
        }
        Mode::BoxBrowser => {
            "In the Box Developer Console, create an app with User Authentication, turn on read access to all files and folders, and add the redirect address http://127.0.0.1. You then sign in with your Box account in your browser."
        }
        Mode::BoxApp => {
            "In the Box Developer Console, create an app with Server Authentication (Client Credentials Grant), turn on read access to all files and folders, and have an administrator authorize it in the Box Admin Console. piikey reads as the enterprise or the user you name."
        }
    }
}

/// The heading of the setup guide that tells how to set `provider` up.
const fn anchor(provider: Provider) -> &'static str {
    match provider {
        Provider::Microsoft365 => "microsoft-365",
        Provider::OneDrive => "onedrive",
        Provider::GoogleDrive => "google-drive",
        Provider::Dropbox => "dropbox",
        Provider::Box => "box",
    }
}

/// The address of the setup guide, at the heading of `provider`.
fn guide(provider: Provider) -> String {
    format!(
        "{}/blob/main/docs/sources.md#{}",
        env!("CARGO_PKG_REPOSITORY"),
        anchor(provider)
    )
}

/// How a field is filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Input {
    /// One line of text.
    Text,
    /// One entry per line.
    Lines,
    /// The client secret: a password box, kept apart from the other values.
    Secret,
    /// A file: its path, and a Browse button whose picker has this title.
    File(&'static str),
    /// One of these: the key of each and its words. The first is what is chosen until the person
    /// chooses.
    Choice(&'static [(&'static str, &'static str)]),
}

/// A field of the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Field {
    key: &'static str,
    label: &'static str,
    /// What an empty box says.
    hint: &'static str,
    input: Input,
}

impl Field {
    const fn new(key: &'static str, label: &'static str, input: Input) -> Self {
        Self {
            key,
            label,
            hint: "",
            input,
        }
    }

    const fn hint(mut self, hint: &'static str) -> Self {
        self.hint = hint;
        self
    }
}

/// What was typed or chosen for `key`.
fn value<'a>(values: &'a Values, key: &str) -> &'a str {
    values.get(key).map_or("", String::as_str)
}

/// The fields `mode` has, in the order they are asked, given what is filled in so far (the
/// credential of an app and whom a Box app acts as change what follows them).
fn fields(mode: Mode, values: &Values) -> Vec<Field> {
    let text = |key, label| Field::new(key, label, Input::Text);
    let client_secret = Field::new(CLIENT_SECRET, "Client secret", Input::Secret);
    let client_id = text(CLIENT_ID, "Client ID");
    let tenant = text(TENANT, "Tenant").hint("Tenant ID, domain or organizations");
    let application = text(CLIENT_ID, "Application (client) ID");
    let mut list = vec![
        Field::new(NAME, "Account name", Input::Text)
            .hint("What you call it, such as Finance or Jan at work"),
    ];
    match mode {
        Mode::MicrosoftBrowser => list.extend([tenant, application]),
        Mode::OneDriveBrowser => list.push(application),
        Mode::MicrosoftApp | Mode::MicrosoftAppSelected => {
            list.extend([
                tenant,
                application,
                Field::new(CREDENTIAL, "Credential", Input::Choice(CREDENTIALS)),
            ]);
            if value(values, CREDENTIAL) == "certificate" {
                list.extend([
                    Field::new(
                        KEY_FILE,
                        "Private key file (PEM)",
                        Input::File("Choose the private key file"),
                    ),
                    Field::new(
                        CERT_FILE,
                        "Certificate file (PEM)",
                        Input::File("Choose the certificate file"),
                    ),
                ]);
            } else {
                list.push(client_secret);
            }
            if mode == Mode::MicrosoftAppSelected {
                list.push(
                    Field::new(SITES, "Sites", Input::Lines)
                        .hint("One site address per line, such as https://contoso.sharepoint.com/sites/Finance"),
                );
            }
        }
        Mode::GoogleBrowser | Mode::BoxBrowser => list.extend([client_id, client_secret]),
        Mode::GoogleServiceAccount => list.extend([
            Field::new(
                SERVICE_KEY,
                "Key file (JSON)",
                Input::File("Choose the key file"),
            ),
            Field::new(USERS, "Users", Input::Lines).hint("One email address per line"),
        ]),
        Mode::DropboxBrowser => list.push(text(APP_KEY, "App key")),
        Mode::BoxApp => {
            let user = value(values, ACT_AS) == "user";
            list.extend([
                client_id,
                client_secret,
                Field::new(ACT_AS, "Act as", Input::Choice(SUBJECTS)),
                text(ACT_ID, if user { "User ID" } else { "Enterprise ID" }),
            ]);
        }
    }
    list
}

/// The entries of a box that takes one per line: trimmed, none empty.
fn lines(text: &str) -> Vec<String> {
    text.split(['\n', '\r'])
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The account the values make for `provider` signing in the way `mode`. Nothing is checked: see
/// [`problem`].
fn build(provider: Provider, mode: Mode, values: &Values, secret: &str) -> NewAccount {
    let text = |key: &str| value(values, key).trim().to_owned();
    let credential = || {
        if value(values, CREDENTIAL) == "certificate" {
            Credential::Certificate {
                key_file: PathBuf::from(text(KEY_FILE)),
                cert_file: PathBuf::from(text(CERT_FILE)),
            }
        } else {
            Credential::Secret
        }
    };
    let sign_in = match mode {
        Mode::MicrosoftBrowser => SignIn::MicrosoftDelegated {
            tenant: text(TENANT),
            client_id: text(CLIENT_ID),
        },
        Mode::OneDriveBrowser => SignIn::MicrosoftDelegated {
            tenant: PERSONAL_TENANT.to_owned(),
            client_id: text(CLIENT_ID),
        },
        Mode::MicrosoftApp => SignIn::MicrosoftApp {
            tenant: text(TENANT),
            client_id: text(CLIENT_ID),
            credential: credential(),
        },
        Mode::MicrosoftAppSelected => SignIn::MicrosoftAppSelected {
            tenant: text(TENANT),
            client_id: text(CLIENT_ID),
            credential: credential(),
            sites: lines(value(values, SITES)),
        },
        Mode::GoogleBrowser => SignIn::GoogleDelegated {
            client_id: text(CLIENT_ID),
        },
        Mode::GoogleServiceAccount => SignIn::GoogleServiceAccount {
            key_file: PathBuf::from(text(SERVICE_KEY)),
            users: lines(value(values, USERS)),
        },
        Mode::DropboxBrowser => SignIn::DropboxDelegated {
            app_key: text(APP_KEY),
        },
        Mode::BoxBrowser => SignIn::BoxDelegated {
            client_id: text(CLIENT_ID),
        },
        Mode::BoxApp => SignIn::BoxApp {
            client_id: text(CLIENT_ID),
            subject: if value(values, ACT_AS) == "user" {
                BoxSubject::User(text(ACT_ID))
            } else {
                BoxSubject::Enterprise(text(ACT_ID))
            },
        },
    };
    let client_secret = sign_in.needs_secret().then(|| secret.trim().to_owned());
    NewAccount {
        provider,
        label: text(NAME),
        sign_in,
        client_secret,
    }
}

/// What is still to be filled in before `new` can be connected, as a sentence; `None` when
/// nothing is.
fn problem(new: &NewAccount) -> Option<String> {
    let missing = if new.label.is_empty() {
        Some("the account name")
    } else {
        new.sign_in.missing().or_else(|| {
            new.client_secret
                .as_deref()
                .is_some_and(str::is_empty)
                .then_some("the client secret")
        })
    };
    missing.map(|what| format!("Fill in {what}."))
}

/// The way and the service the dialog is at: what the window's choice points to.
fn current(window: &MainWindow) -> Option<(Provider, Mode)> {
    let provider = window.accounts.provider?;
    let ways = modes(provider);
    let mode = ways.get(window.accounts.way).or_else(|| ways.first())?;
    Some((provider, *mode))
}

/// The step after the service: how to sign in, or the fields for a service with one way.
fn step_after_provider(provider: Provider) -> Step {
    if modes(provider).len() > 1 {
        Step::Way
    } else {
        Step::Fields
    }
}

/// The step Back goes to from the fields: the way to sign in, if the person had a choice of ways.
fn step_before_fields(provider: Provider) -> Step {
    if modes(provider).len() > 1 {
        Step::Way
    } else {
        Step::Provider
    }
}

// ---- The section ----

/// The sign-in that runs for `view`, or the last that ended, if one is of this account.
fn signing_in<'a>(window: &'a MainWindow, view: &AccountView) -> Option<&'a Connecting> {
    window.snap.connecting.as_ref().filter(|connecting| {
        connecting.provider == view.account.provider && connecting.label == view.account.label
    })
}

/// How an account stands: the tone of its glyph (none while a sign-in runs), whether one runs, and
/// the words. What a sign-in that did not work said stays until the account is fine again.
fn standing(view: &AccountView, connecting: Option<&Connecting>) -> (Tone, bool, String) {
    let connected = view.status == AccountStatus::Connected;
    match connecting.map(|connecting| &connecting.state) {
        Some(ConnectState::Working) => (
            Tone::Busy,
            true,
            if view.account.sign_in.needs_browser() {
                "Waiting for you to sign in\u{2026}"
            } else {
                "Checking the credentials\u{2026}"
            }
            .to_owned(),
        ),
        Some(ConnectState::Failed(why)) if !connected => (Tone::Caution, false, why.clone()),
        _ if connected => (Tone::Good, false, view.status_text().to_owned()),
        _ => (Tone::Caution, false, view.status_text().to_owned()),
    }
}

/// The row of one account: its logo, name and way to sign in, how it stands, and its buttons.
fn account_row(window: &MainWindow, view: &AccountView, context: Context<'_>) -> View {
    let account = &view.account;
    let (tone, working, words) = standing(view, signing_in(window, view));
    let lead: View = if working {
        ProgressRing::new()
            .is_active(true)
            .width(16.0)
            .height(16.0)
            .into()
    } else if tone == Tone::Good {
        toned_glyph("\u{E73E}", 16.0, tone, window.dark).into()
    } else {
        toned_glyph("\u{E7BA}", 16.0, tone, window.dark).into()
    };
    let mut controls: Vec<View> = vec![
        lead,
        TextBlock::new()
            .text(words)
            .text_wrapping(TextWrapping::Wrap)
            .max_width(STATE_WIDTH)
            .opacity(0.72)
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
    ];
    if view.status != AccountStatus::Connected {
        controls.push(
            Button::new()
                .content("Sign in again")
                .is_enabled(!working)
                .on_click(context.message(Msg::Account(AccountMsg::SignIn(account.id.clone()))))
                .into(),
        );
    }
    controls.push(
        Button::new()
            .content("Disconnect")
            .on_click(context.message(Msg::Account(AccountMsg::Disconnect(account.id.clone()))))
            .into(),
    );
    let provider = assets::provider_name(account);
    let way = Mode::of(&account.sign_in).label();
    Row::new(&account.label)
        .logo(provider_icon(
            account.provider,
            Some(&account.label),
            LOGO,
            window.dark,
        ))
        .description(format!("{provider} \u{b7} {way}"))
        .control(
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .spacing(12.0)
                .vertical_alignment(VerticalAlignment::Center)
                .children(controls),
        )
        .build()
}

/// Settings > Connected accounts: what it is for and a row for each account. How to set each one
/// up is in the Add account dialog.
pub(super) fn section(window: &MainWindow, context: Context<'_>) -> View {
    let accounts = &window.snap.accounts;
    let mut rows: Vec<View> = vec![caption(INTRO).into()];
    rows.extend(
        accounts
            .iter()
            .map(|view| account_row(window, view, context)),
    );
    if accounts.is_empty() {
        rows.push(caption("No account connected yet.").into());
    }
    let add = Button::new()
        .content("Add account")
        .on_click(context.message(Msg::Account(AccountMsg::Add)));
    section_with("Connected accounts", vec![add.into()], rows)
}

// ---- The dialogs ----

/// The dialog of the accounts on show (Add account, Disconnect), if one is.
pub(super) fn dialog(window: &MainWindow, context: Context<'_>) -> Option<ContentDialog> {
    if let Some(step) = window.accounts.step {
        return Some(add_dialog(window, step, context));
    }
    let id = window.accounts.disconnecting.as_ref()?;
    let view = window
        .snap
        .accounts
        .iter()
        .find(|view| view.account.id == *id)?;
    Some(disconnect_dialog(view, context))
}

/// The question Disconnect asks before it takes an account away.
fn disconnect_dialog(view: &AccountView, context: Context<'_>) -> ContentDialog {
    let provider = assets::provider_name(&view.account);
    ContentDialog::new()
        .is_open(true)
        .title(format!("Disconnect {}?", view.account.label))
        .content(
            body(format!(
                "piikey stops scanning its locations, removes them from Inventory and forgets what was found in them. Nothing is deleted from {provider}."
            ))
            .max_width(DIALOG_WIDTH),
        )
        .primary_button_text("Disconnect")
        .close_button_text("Cancel")
        .default_button(ContentDialogButton::Close)
        .on_closed(context.callback(|result: ContentDialogResult| {
            Msg::Account(AccountMsg::Disconnected(
                result == ContentDialogResult::Primary,
            ))
        }))
}

/// The Add account dialog at `step`. Its own button is Cancel, which closes it; Back, Next and
/// Connect are buttons of the content, so moving on never closes it.
fn add_dialog(window: &MainWindow, step: Step, context: Context<'_>) -> ContentDialog {
    let body = match step {
        Step::Provider => provider_step(window, context),
        Step::Way => way_step(window, context),
        Step::Fields => fields_step(window, context),
        Step::Working => working_step(window),
    };
    ContentDialog::new()
        .is_open(true)
        .title("Add account")
        .content(
            StackPanel::new()
                .width(DIALOG_WIDTH)
                .spacing(12.0)
                .children(body),
        )
        .close_button_text("Cancel")
        // Enter in a box must not cancel the dialog.
        .default_button(ContentDialogButton::None)
        .on_closed(context.callback(|_: ContentDialogResult| Msg::Account(AccountMsg::Close)))
}

/// Back on the left of Next or Connect, both on the right.
fn navigation(back: Option<Step>, forward: Button, context: Context<'_>) -> View {
    let mut buttons: Vec<View> = Vec::new();
    if let Some(step) = back {
        buttons.push(
            Button::new()
                .content("Back")
                .on_click(context.message(Msg::Account(AccountMsg::Go(step))))
                .into(),
        );
    }
    buttons.push(forward.into());
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(8.0)
        .horizontal_alignment(HorizontalAlignment::Right)
        .children(buttons)
        .into()
}

/// The next button: it moves to `step` when it is `enabled`.
fn next_button(label: &str, enabled: bool, step: Step, context: Context<'_>) -> Button {
    Button::new()
        .content(label)
        .style(ButtonStyle::Accent)
        .is_enabled(enabled)
        .on_click(context.message(Msg::Account(AccountMsg::Go(step))))
}

/// A service as the dialog lists it: its logo and its name, both small.
fn provider_label(provider: Provider, dark: bool) -> View {
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(12.0)
        .children((
            provider_icon(provider, None, LOGO, dark),
            TextBlock::new()
                .text(provider.name())
                .vertical_alignment(VerticalAlignment::Center),
        ))
        .into()
}

/// Step one: which service.
fn provider_step(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let chosen = window.accounts.provider;
    let mut parts: Vec<View> = vec![body("Which service do you want piikey to read?").into()];
    parts.extend(Provider::ALL.into_iter().map(|provider| {
        RadioButton::new()
            .group_name("provider")
            .is_checked(chosen == Some(provider))
            .automation_name(provider.name())
            .content(provider_label(provider, window.dark))
            .on_checked(context.callback(move |checked: Option<bool>| {
                if checked == Some(true) {
                    Msg::Account(AccountMsg::Provider(provider))
                } else {
                    Msg::Noop
                }
            }))
            .into()
    }));
    let next = chosen.map_or(Step::Fields, step_after_provider);
    parts.push(navigation(
        None,
        next_button("Next", chosen.is_some(), next, context),
        context,
    ));
    parts
}

/// Step two: how to sign in, for a service that has more than one way.
fn way_step(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let Some(provider) = window.accounts.provider else {
        return Vec::new();
    };
    let ways = modes(provider);
    vec![
        body(format!("How do you sign in to {}?", provider.name())).into(),
        RadioButtons::new()
            .items_source(ways.iter().map(|mode| mode.label()))
            .selected_index(Some(window.accounts.way))
            .on_selection_changed(context.callback(|index: Option<usize>| {
                index.map_or(Msg::Noop, |way| Msg::Account(AccountMsg::Way(way)))
            }))
            .into(),
        navigation(
            Some(Step::Provider),
            next_button("Next", true, Step::Fields, context),
            context,
        ),
    ]
}

/// The box of a field that is typed in.
fn text_box(field: Field, window: &MainWindow, context: Context<'_>) -> TextBox {
    let key = field.key;
    TextBox::new()
        .text(value(&window.accounts.values, key))
        .placeholder_text(field.hint)
        .automation_name(field.label)
        .on_text_changed(
            context.callback(move |text: Rc<str>| {
                Msg::Account(AccountMsg::Field(key, text.to_string()))
            }),
        )
}

/// A field as a view: its label over its box.
fn field_view(field: Field, window: &MainWindow, context: Context<'_>) -> View {
    let key = field.key;
    let label = TextBlock::new().text(field.label);
    match field.input {
        Input::Text => text_box(field, window, context).header(label).into(),
        Input::Lines => text_box(field, window, context)
            .accepts_return(true)
            .height(LINES_HEIGHT)
            .header(label)
            .into(),
        Input::Secret => PasswordBox::new()
            .password(&window.accounts.secret)
            .password_reveal_mode(PasswordRevealMode::Hidden)
            .automation_name(field.label)
            .header(label)
            .on_password_changed(
                context
                    .callback(|text: Rc<str>| Msg::Account(AccountMsg::Secret(text.to_string()))),
            )
            .into(),
        Input::File(title) => StackPanel::new()
            .spacing(4.0)
            .children((
                label,
                Grid::new()
                    .columns([GridLength::STAR, GridLength::Auto])
                    .column_spacing(8.0)
                    .children((
                        text_box(field, window, context),
                        Button::new()
                            .content("Browse\u{2026}")
                            .grid_column(1)
                            .automation_name(format!("Browse for {}", field.label))
                            .on_click(context.message(Msg::Account(AccountMsg::Pick(key, title)))),
                    )),
            ))
            .into(),
        Input::Choice(options) => {
            let chosen = options
                .iter()
                .position(|&(option, _)| option == value(&window.accounts.values, key))
                .unwrap_or(0);
            ComboBox::new()
                .items_source(options.iter().map(|&(_, words)| words))
                .selected_index(Some(chosen))
                .automation_name(field.label)
                .header(label)
                .on_selection_changed(context.callback(move |index: Option<usize>| {
                    index
                        .and_then(|i| options.get(i))
                        .map_or(Msg::Noop, |&(option, _)| {
                            Msg::Account(AccountMsg::Field(key, option.to_owned()))
                        })
                }))
                .into()
        }
    }
}

/// Step three: what the way needs.
fn fields_step(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let Some((provider, mode)) = current(window) else {
        return Vec::new();
    };
    let new = build(
        provider,
        mode,
        &window.accounts.values,
        &window.accounts.secret,
    );
    let missing = problem(&new);
    let mut parts: Vec<View> = vec![
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(12.0)
            .children((
                provider_icon(provider, None, LOGO, window.dark),
                subtitle(&format!("{} \u{b7} {}", provider.name(), mode.label()))
                    .font_size(14.0)
                    .vertical_alignment(VerticalAlignment::Center),
            ))
            .into(),
    ];
    if let Some(failure) = &window.accounts.failure {
        parts.push(info("Could not connect", failure, InfoBarSeverity::Warning).into());
    }
    if window.accounts.approval.is_some() {
        parts.push(
            Button::new()
                .content("Copy approval link")
                .on_click(context.message(Msg::Account(AccountMsg::CopyApproval)))
                .into(),
        );
        if window.accounts.approval_copied {
            parts.push(
                caption("Copied. Once your administrator has approved piikey, sign in again.")
                    .into(),
            );
        }
    }
    parts.push(caption(help(mode)).into());
    parts.push(web_link("Setup guide", &guide(provider)));
    parts.extend(
        fields(mode, &window.accounts.values)
            .into_iter()
            .map(|field| field_view(field, window, context)),
    );
    if let Some(missing) = &missing {
        parts.push(caption(missing).into());
    }
    let back = step_before_fields(provider);
    let connect = Button::new()
        .content("Connect")
        .style(ButtonStyle::Accent)
        .is_enabled(missing.is_none())
        .on_click(context.message(Msg::Account(AccountMsg::Connect(Box::new(new)))));
    parts.push(navigation(Some(back), connect, context));
    parts
}

/// Step four: waiting. The way tells what for; Cancel is the dialog's own button.
fn working_step(window: &MainWindow) -> Vec<View> {
    let Some((provider, mode)) = current(window) else {
        return Vec::new();
    };
    let words = if build(provider, mode, &window.accounts.values, "")
        .sign_in
        .needs_browser()
    {
        "Waiting for you to sign in in your browser\u{2026}"
    } else {
        "Checking the credentials\u{2026}"
    };
    vec![
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(12.0)
            .children((
                ProgressRing::new().is_active(true).width(24.0).height(24.0),
                body(words).vertical_alignment(VerticalAlignment::Center),
            ))
            .into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    type Test = Result<(), String>;

    /// Every field of `mode` filled in with something, as a person who finished would have it.
    fn filled(mode: Mode, certificate: bool) -> Values {
        let mut values = Values::new();
        values.insert(NAME, "Work".to_owned());
        if certificate {
            values.insert(CREDENTIAL, "certificate".to_owned());
        }
        for field in fields(mode, &values) {
            if !matches!(field.input, Input::Secret | Input::Choice(_)) {
                values.insert(field.key, "x".to_owned());
            }
        }
        values
    }

    #[test]
    fn each_service_offers_the_ways_it_has() {
        let ways = |provider| {
            modes(provider)
                .iter()
                .map(|mode| mode.label())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ways(Provider::Microsoft365),
            [
                "Sign in with a browser",
                "App registration, whole tenant",
                "App registration, selected sites"
            ]
        );
        assert_eq!(ways(Provider::OneDrive), ["Sign in with a browser"]);
        assert_eq!(
            ways(Provider::GoogleDrive),
            [
                "Sign in with a browser",
                "Service account (Google Workspace)"
            ]
        );
        assert_eq!(ways(Provider::Dropbox), ["Sign in with a browser"]);
        assert_eq!(
            ways(Provider::Box),
            ["Sign in with a browser", "App (client credentials)"]
        );
    }

    #[test]
    fn what_a_way_builds_is_a_way_its_service_has() -> Test {
        for provider in Provider::ALL {
            for &mode in modes(provider) {
                for certificate in [false, true] {
                    let values = filled(mode, certificate);
                    let new = build(provider, mode, &values, "secret");
                    if !new.sign_in.fits(provider) {
                        return Err(format!("{mode:?} does not fit {provider:?}"));
                    }
                    if Mode::of(&new.sign_in).label() != mode.label() {
                        return Err(format!("{mode:?} is read back as another way"));
                    }
                    if let Some(missing) = problem(&new) {
                        return Err(format!("{mode:?} filled in still says: {missing}"));
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn every_way_starts_with_the_name_and_has_each_field_once() {
        for provider in Provider::ALL {
            for &mode in modes(provider) {
                for certificate in [false, true] {
                    let values = filled(mode, certificate);
                    let list = fields(mode, &values);
                    assert_eq!(list.first().map(|field| field.key), Some(NAME));
                    let mut keys: Vec<&str> = list.iter().map(|field| field.key).collect();
                    keys.sort_unstable();
                    keys.dedup();
                    assert_eq!(keys.len(), list.len(), "{mode:?} repeats a field");
                }
            }
        }
    }

    #[test]
    fn the_fields_of_each_way_are_the_ones_that_way_needs() {
        let keys = |mode, values: &Values| -> Vec<&'static str> {
            fields(mode, values).iter().map(|field| field.key).collect()
        };
        let none = Values::new();
        assert_eq!(
            keys(Mode::MicrosoftBrowser, &none),
            [NAME, TENANT, CLIENT_ID]
        );
        assert_eq!(keys(Mode::OneDriveBrowser, &none), [NAME, CLIENT_ID]);
        assert_eq!(
            keys(Mode::MicrosoftApp, &none),
            [NAME, TENANT, CLIENT_ID, CREDENTIAL, CLIENT_SECRET]
        );
        let certificate = Values::from([(CREDENTIAL, "certificate".to_owned())]);
        assert_eq!(
            keys(Mode::MicrosoftAppSelected, &certificate),
            [
                NAME, TENANT, CLIENT_ID, CREDENTIAL, KEY_FILE, CERT_FILE, SITES
            ]
        );
        assert_eq!(
            keys(Mode::GoogleBrowser, &none),
            [NAME, CLIENT_ID, CLIENT_SECRET]
        );
        assert_eq!(
            keys(Mode::GoogleServiceAccount, &none),
            [NAME, SERVICE_KEY, USERS]
        );
        assert_eq!(keys(Mode::DropboxBrowser, &none), [NAME, APP_KEY]);
        assert_eq!(
            keys(Mode::BoxApp, &none),
            [NAME, CLIENT_ID, CLIENT_SECRET, ACT_AS, ACT_ID]
        );
    }

    #[test]
    fn a_box_app_asks_for_the_id_of_whom_it_acts_as() {
        let mut values = Values::new();
        let label = |values: &Values| fields(Mode::BoxApp, values).last().map(|field| field.label);
        assert_eq!(label(&values), Some("Enterprise ID"));
        values.insert(ACT_AS, "user".to_owned());
        assert_eq!(label(&values), Some("User ID"));
        values.insert(ACT_ID, " 77 ".to_owned());
        values.insert(CLIENT_ID, "id".to_owned());
        values.insert(NAME, "Box".to_owned());
        let new = build(Provider::Box, Mode::BoxApp, &values, " s3cret ");
        assert_eq!(
            new.sign_in,
            SignIn::BoxApp {
                client_id: "id".to_owned(),
                subject: BoxSubject::User("77".to_owned()),
            }
        );
        assert_eq!(new.client_secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn a_personal_onedrive_is_always_the_consumers_tenant() {
        let values = Values::from([(NAME, "Me".to_owned()), (CLIENT_ID, " abc ".to_owned())]);
        let new = build(Provider::OneDrive, Mode::OneDriveBrowser, &values, "");
        assert_eq!(
            new.sign_in,
            SignIn::MicrosoftDelegated {
                tenant: "consumers".to_owned(),
                client_id: "abc".to_owned(),
            }
        );
        assert_eq!(new.client_secret, None);
        assert_eq!(problem(&new), None);
    }

    #[test]
    fn an_app_with_a_certificate_keeps_the_files_and_no_secret() {
        let values = Values::from([
            (NAME, "Tenant".to_owned()),
            (TENANT, "contoso.com".to_owned()),
            (CLIENT_ID, "app".to_owned()),
            (CREDENTIAL, "certificate".to_owned()),
            (KEY_FILE, "C:\\keys\\app.key".to_owned()),
            (CERT_FILE, "C:\\keys\\app.pem".to_owned()),
            (SITES, "https://contoso.sharepoint.com/sites/Finance\r\n\r\n  \n https://contoso.sharepoint.com/sites/HR ".to_owned()),
        ]);
        let new = build(
            Provider::Microsoft365,
            Mode::MicrosoftAppSelected,
            &values,
            "left over",
        );
        assert_eq!(
            new.sign_in,
            SignIn::MicrosoftAppSelected {
                tenant: "contoso.com".to_owned(),
                client_id: "app".to_owned(),
                credential: Credential::Certificate {
                    key_file: PathBuf::from("C:\\keys\\app.key"),
                    cert_file: PathBuf::from("C:\\keys\\app.pem"),
                },
                sites: vec![
                    "https://contoso.sharepoint.com/sites/Finance".to_owned(),
                    "https://contoso.sharepoint.com/sites/HR".to_owned(),
                ],
            }
        );
        assert_eq!(new.client_secret, None, "a certificate has no secret");
        assert_eq!(problem(&new), None);
    }

    #[test]
    fn what_is_missing_is_said_in_the_words_of_a_form() {
        let mut values = Values::new();
        let new = |values: &Values, secret: &str| {
            build(Provider::GoogleDrive, Mode::GoogleBrowser, values, secret)
        };
        assert_eq!(
            problem(&new(&values, "")).as_deref(),
            Some("Fill in the account name.")
        );
        values.insert(NAME, "Jan".to_owned());
        assert_eq!(
            problem(&new(&values, "")).as_deref(),
            Some("Fill in the client ID.")
        );
        values.insert(CLIENT_ID, "id".to_owned());
        assert_eq!(
            problem(&new(&values, "  ")).as_deref(),
            Some("Fill in the client secret.")
        );
        assert_eq!(problem(&new(&values, "s")), None);
    }

    #[test]
    fn the_names_that_are_asked_are_the_names_of_the_form() {
        let values = Values::from([(NAME, "Work".to_owned())]);
        let tenant = build(Provider::Microsoft365, Mode::MicrosoftBrowser, &values, "");
        assert_eq!(problem(&tenant).as_deref(), Some("Fill in the tenant."));
        let dropbox = build(Provider::Dropbox, Mode::DropboxBrowser, &values, "");
        assert_eq!(problem(&dropbox).as_deref(), Some("Fill in the app key."));
        let google = build(
            Provider::GoogleDrive,
            Mode::GoogleServiceAccount,
            &values,
            "",
        );
        assert_eq!(problem(&google).as_deref(), Some("Fill in the key file."));
    }

    #[test]
    fn the_help_names_the_redirect_address_the_sign_in_sends() {
        assert!(help(Mode::DropboxBrowser).contains("http://127.0.0.1:53123/"));
        assert!(help(Mode::BoxBrowser).contains("http://127.0.0.1"));
        assert!(help(Mode::MicrosoftBrowser).contains("http://localhost"));
        assert!(help(Mode::OneDriveBrowser).contains("http://localhost"));
    }

    #[test]
    fn the_help_speaks_in_the_words_of_the_glossary() {
        for provider in Provider::ALL {
            for &mode in modes(provider) {
                let text = help(mode);
                for banned in [
                    "PII", "keyed", "program", "kind", "Watch", "OAuth", "token", "HTTP",
                ] {
                    assert!(!text.contains(banned), "{mode:?} says {banned:?}");
                }
                assert!(text.ends_with('.'), "{mode:?} is a sentence");
            }
        }
    }

    #[test]
    fn the_guide_has_a_heading_for_each_service() {
        let anchors: Vec<&str> = Provider::ALL.into_iter().map(anchor).collect();
        assert_eq!(
            anchors,
            [
                "microsoft-365",
                "onedrive",
                "google-drive",
                "dropbox",
                "box"
            ]
        );
        let repo = env!("CARGO_PKG_REPOSITORY");
        assert_eq!(
            guide(Provider::Dropbox),
            format!("{repo}/blob/main/docs/sources.md#dropbox")
        );
    }

    #[test]
    fn a_state_that_needs_the_person_is_a_caution_and_a_running_sign_in_is_not() {
        use piikey::sources::Account;
        let account = Account {
            id: "0123456789abcdef".to_owned(),
            provider: Provider::Dropbox,
            label: "Me".to_owned(),
            sign_in: SignIn::DropboxDelegated {
                app_key: "k".to_owned(),
            },
        };
        let view = |status| AccountView {
            account: account.clone(),
            status,
        };
        let working = Connecting {
            seq: 1,
            provider: Provider::Dropbox,
            label: "Me".to_owned(),
            state: ConnectState::Working,
        };
        let failed = Connecting {
            state: ConnectState::Failed("Dropbox did not accept it.".to_owned()),
            ..working.clone()
        };
        assert_eq!(
            standing(&view(AccountStatus::Connected), None),
            (Tone::Good, false, "Connected".to_owned())
        );
        assert_eq!(
            standing(&view(AccountStatus::SignInNeeded), None),
            (Tone::Caution, false, "Needs sign-in".to_owned())
        );
        assert_eq!(
            standing(&view(AccountStatus::SignInNeeded), Some(&working)),
            (
                Tone::Busy,
                true,
                "Waiting for you to sign in\u{2026}".to_owned()
            )
        );
        assert_eq!(
            standing(&view(AccountStatus::SignInNeeded), Some(&failed)),
            (
                Tone::Caution,
                false,
                "Dropbox did not accept it.".to_owned()
            )
        );
        assert_eq!(
            standing(&view(AccountStatus::Connected), Some(&failed)),
            (Tone::Good, false, "Connected".to_owned())
        );
    }

    #[test]
    fn a_service_with_one_way_skips_the_step_of_ways() {
        for provider in Provider::ALL {
            let choice = modes(provider).len() > 1;
            assert_eq!(
                step_after_provider(provider),
                if choice { Step::Way } else { Step::Fields }
            );
            assert_eq!(
                step_before_fields(provider),
                if choice { Step::Way } else { Step::Provider }
            );
        }
        assert_eq!(step_after_provider(Provider::OneDrive), Step::Fields);
        assert_eq!(step_after_provider(Provider::Dropbox), Step::Fields);
        assert_eq!(step_after_provider(Provider::Microsoft365), Step::Way);
    }
}
