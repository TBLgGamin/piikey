//! The command line: `lexopt` tokens turned into one [`Cli`].
//!
//! Every command but `serve` becomes one API [`Request`], so the CLI offers nothing the API does
//! not, and every operation the API has (but `explorer_scan`, which only the Explorer menu uses)
//! has a command here.

use std::{
    ffi::{OsStr, OsString},
    mem,
    path::PathBuf,
};

use lexopt::{Arg, Parser, ValueExt};
use piikey::{
    api::{Format, Request},
    detect::EntityKind,
    policy::{Highlight, KEYS, SettingsPatch, valid_port},
    sources::{BoxSubject, Credential, Provider, SignIn},
};

/// A parsed command line.
#[derive(Debug, PartialEq)]
pub struct Cli {
    /// `--json`: print the result as JSON instead of a table.
    pub json: bool,
    /// `--local`: work in this process even when the app answers.
    pub local: bool,
    /// `--vault PATH`: the vault this process works on; implies `--local`.
    pub vault: Option<PathBuf>,
    pub command: Command,
}

impl Cli {
    fn bare(command: Command) -> Self {
        Self {
            json: false,
            local: false,
            vault: None,
            command,
        }
    }

    /// Whether the command works in this process instead of asking the app first.
    #[must_use]
    pub fn in_process(&self) -> bool {
        self.local || self.vault.is_some()
    }
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    Version,
    /// Serve the API from this process.
    Serve(Serve),
    /// One API request, and what the CLI does around it.
    Call(Call),
}

/// `serve`: which transports to open.
#[derive(Debug, PartialEq, Eq)]
pub struct Serve {
    /// Also serve HTTP on `127.0.0.1`.
    pub http: bool,
    /// The HTTP port; the saved setting when `None`.
    pub port: Option<u16>,
    /// The pipe name; the per-user default when `None`.
    pub pipe: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct Call {
    pub input: Input,
    /// `scan --fail-on`: the kinds whose presence makes the command exit 1.
    pub fail_on: Option<FailOn>,
}

#[derive(Debug, PartialEq)]
pub enum Input {
    Request(Request),
    /// The text on stdin, as one text through a text operation.
    Stdin(Text),
    /// `account add --client-secret-stdin`: the first line of stdin is the client secret.
    Secret(NewAccount),
}

/// An account to add whose client secret is still to be read from stdin.
#[derive(Debug, PartialEq)]
pub struct NewAccount {
    pub provider: Provider,
    pub label: String,
    pub sign_in: SignIn,
}

impl NewAccount {
    /// The request that adds the account with `secret` as its client secret.
    #[must_use]
    pub fn request(self, secret: String) -> Request {
        Request::AccountAdd {
            provider: self.provider,
            label: self.label,
            sign_in: self.sign_in,
            client_secret: Some(secret),
        }
    }
}

/// The operations that work on text, for stdin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text {
    Scan,
    Anonymize,
    Deanonymize { tolerant: bool },
}

impl Text {
    /// The request that sends `text` through this operation.
    #[must_use]
    pub fn request(self, text: String) -> Request {
        let texts = vec![text];
        match self {
            Self::Scan => Request::ScanText { texts },
            Self::Anonymize => Request::Anonymize { texts },
            Self::Deanonymize { tolerant } => Request::Deanonymize { texts, tolerant },
        }
    }
}

/// What `scan --fail-on` fails on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailOn {
    /// Any kind.
    Any,
    Kinds(Vec<EntityKind>),
}

impl FailOn {
    /// Whether finding a value of the kind named `kind` (its `EntityKind::as_str` name) fails
    /// the scan.
    #[must_use]
    pub fn matches(&self, kind: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Kinds(kinds) => kinds.iter().any(|k| k.as_str() == kind),
        }
    }
}

/// Why a command line was rejected (always exit code 2).
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The command line does not follow the grammar: print the message and the usage text.
    Usage(String),
    /// A known command got a wrong value or lacks one: the message says it all.
    Invalid(String),
}

impl From<lexopt::Error> for ParseError {
    fn from(e: lexopt::Error) -> Self {
        Self::Usage(e.to_string())
    }
}

fn usage(message: impl Into<String>) -> ParseError {
    ParseError::Usage(message.into())
}

fn invalid(message: impl Into<String>) -> ParseError {
    ParseError::Invalid(message.into())
}

/// Every option, so a flag a command does not take can be named in the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    Json,
    Local,
    Vault,
    Out,
    Tolerant,
    FailOn,
    NoRecord,
    Value,
    Query,
    Kind,
    Limit,
    Offset,
    Format,
    Under,
    Yes,
    Rotate,
    Http,
    Port,
    Pipe,
    Label,
    Mode,
    Tenant,
    ClientId,
    AppKey,
    KeyFile,
    CertFile,
    Site,
    User,
    EnterpriseId,
    UserId,
    ClientSecretStdin,
}

/// The long names, without the dashes.
const OPTS: [(&str, Opt); 31] = [
    ("json", Opt::Json),
    ("local", Opt::Local),
    ("vault", Opt::Vault),
    ("out", Opt::Out),
    ("tolerant", Opt::Tolerant),
    ("fail-on", Opt::FailOn),
    ("no-record", Opt::NoRecord),
    ("value", Opt::Value),
    ("query", Opt::Query),
    ("kind", Opt::Kind),
    ("limit", Opt::Limit),
    ("offset", Opt::Offset),
    ("format", Opt::Format),
    ("under", Opt::Under),
    ("yes", Opt::Yes),
    ("rotate", Opt::Rotate),
    ("http", Opt::Http),
    ("port", Opt::Port),
    ("pipe", Opt::Pipe),
    ("label", Opt::Label),
    ("mode", Opt::Mode),
    ("tenant", Opt::Tenant),
    ("client-id", Opt::ClientId),
    ("app-key", Opt::AppKey),
    ("key-file", Opt::KeyFile),
    ("cert-file", Opt::CertFile),
    ("site", Opt::Site),
    ("user", Opt::User),
    ("enterprise-id", Opt::EnterpriseId),
    ("user-id", Opt::UserId),
    ("client-secret-stdin", Opt::ClientSecretStdin),
];

impl Opt {
    /// The option as typed: `--fail-on`.
    fn flag(self) -> String {
        let long = OPTS
            .iter()
            .find(|(_, opt)| *opt == self)
            .map_or("?", |(long, _)| *long);
        format!("--{long}")
    }

    /// Whether every command takes it.
    fn is_global(self) -> bool {
        matches!(self, Self::Json | Self::Local | Self::Vault)
    }
}

/// What the options said. Switches are only recorded in `seen`.
#[derive(Default)]
struct Flags {
    /// Every option given, in order, for the check of what a command takes.
    seen: Vec<Opt>,
    vault: Option<PathBuf>,
    out: Option<PathBuf>,
    under: Option<PathBuf>,
    fail_on: Option<FailOn>,
    values: Vec<String>,
    query: Option<String>,
    kind: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    format: Option<Format>,
    port: Option<u16>,
    pipe: Option<String>,
    label: Option<String>,
    mode: Option<String>,
    tenant: Option<String>,
    client_id: Option<String>,
    app_key: Option<String>,
    key_file: Option<PathBuf>,
    cert_file: Option<PathBuf>,
    sites: Vec<String>,
    users: Vec<String>,
    enterprise_id: Option<String>,
    user_id: Option<String>,
}

/// Parses the arguments after the program name.
///
/// # Errors
/// [`ParseError`] for anything the grammar does not allow.
pub fn parse<I>(args: I) -> Result<Cli, ParseError>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut parser = Parser::from_args(args);
    let mut flags = Flags::default();
    let mut words: Vec<OsString> = Vec::new();
    while let Some(arg) = parser.next()? {
        let opt = match arg {
            Arg::Short('h') | Arg::Long("help") => return Ok(Cli::bare(Command::Help)),
            Arg::Short('V') | Arg::Long("version") => return Ok(Cli::bare(Command::Version)),
            Arg::Long(name) => match OPTS.iter().find(|(long, _)| *long == name) {
                Some(&(_, opt)) => opt,
                None => return Err(Arg::Long(name).unexpected().into()),
            },
            Arg::Value(word) => {
                words.push(word);
                continue;
            }
            other @ Arg::Short(_) => return Err(other.unexpected().into()),
        };
        flags.read(opt, &mut parser)?;
    }
    flags.finish(&words)
}

impl Flags {
    /// Records `opt` and reads its value, if it takes one.
    fn read(&mut self, opt: Opt, parser: &mut Parser) -> Result<(), ParseError> {
        match opt {
            Opt::Json
            | Opt::Local
            | Opt::Tolerant
            | Opt::NoRecord
            | Opt::Yes
            | Opt::Rotate
            | Opt::Http
            | Opt::ClientSecretStdin => {}
            Opt::Vault => self.vault = Some(path(parser.value()?)?),
            Opt::Out => self.out = Some(path(parser.value()?)?),
            Opt::Under => self.under = Some(path(parser.value()?)?),
            Opt::FailOn => {
                let text = parser.value()?.string()?;
                self.fail_on = Some(fail_on(self.fail_on.take(), &text)?);
            }
            Opt::Value => self.values.push(parser.value()?.string()?),
            Opt::Query => self.query = Some(parser.value()?.string()?),
            Opt::Kind => self.kind = Some(parser.value()?.string()?),
            Opt::Limit => self.limit = Some(number(parser, opt)?),
            Opt::Offset => self.offset = Some(number(parser, opt)?),
            Opt::Format => self.format = Some(format(&parser.value()?.string()?)?),
            Opt::Port => self.port = Some(port(parser)?),
            Opt::Pipe => self.pipe = Some(parser.value()?.string()?),
            Opt::Label => self.label = Some(parser.value()?.string()?),
            Opt::Mode => self.mode = Some(parser.value()?.string()?),
            Opt::Tenant => self.tenant = Some(parser.value()?.string()?),
            Opt::ClientId => self.client_id = Some(parser.value()?.string()?),
            Opt::AppKey => self.app_key = Some(parser.value()?.string()?),
            Opt::KeyFile => self.key_file = Some(path(parser.value()?)?),
            Opt::CertFile => self.cert_file = Some(path(parser.value()?)?),
            Opt::Site => self.sites.push(parser.value()?.string()?),
            Opt::User => self.users.push(parser.value()?.string()?),
            Opt::EnterpriseId => self.enterprise_id = Some(parser.value()?.string()?),
            Opt::UserId => self.user_id = Some(parser.value()?.string()?),
        }
        self.seen.push(opt);
        Ok(())
    }

    fn has(&self, opt: Opt) -> bool {
        self.seen.contains(&opt)
    }

    /// Fails when an option was given that `command` does not take. The global ones always fit.
    fn only(&self, command: &str, allowed: &[Opt]) -> Result<(), ParseError> {
        match self
            .seen
            .iter()
            .find(|opt| !opt.is_global() && !allowed.contains(opt))
        {
            Some(opt) => Err(usage(format!("{} is not valid for {command}", opt.flag()))),
            None => Ok(()),
        }
    }

    /// Picks the command from the first word and builds it from the rest.
    fn finish(mut self, words: &[OsString]) -> Result<Cli, ParseError> {
        let Some((name, rest)) = words.split_first() else {
            return Err(usage("missing command"));
        };
        let command = match utf8(name)? {
            "scan" => self.scan(rest)?,
            "anonymize" => self.rewrite(false, rest)?,
            "deanonymize" => self.rewrite(true, rest)?,
            "subject" => self.subject(rest)?,
            "vault" => self.vault_command(rest)?,
            "inventory" => self.inventory(rest)?,
            "settings" => self.settings(rest)?,
            "account" => self.account(rest)?,
            "kinds" => self.plain("kinds", Request::Kinds, rest)?,
            "model" => self.model(rest)?,
            "token" => self.token(rest)?,
            "status" => self.plain("status", Request::Status, rest)?,
            "protection" => self.protection(rest)?,
            "open" => self.plain("open", Request::ShowWindow, rest)?,
            "serve" => self.serve(rest)?,
            other => return Err(usage(format!("unknown command '{other}'"))),
        };
        Ok(Cli {
            json: self.has(Opt::Json),
            local: self.has(Opt::Local),
            vault: self.vault,
            command,
        })
    }

    fn scan(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        self.only("scan", &[Opt::FailOn, Opt::NoRecord])?;
        let paths = paths(rest)?;
        let input = if paths.is_empty() {
            Input::Stdin(Text::Scan)
        } else {
            Input::Request(Request::ScanFiles {
                paths,
                record: !self.has(Opt::NoRecord),
            })
        };
        Ok(Command::Call(Call {
            input,
            fail_on: self.fail_on.take(),
        }))
    }

    /// `anonymize` and `deanonymize`: stdin to stdout, or files into `--out`.
    fn rewrite(&mut self, deanonymize: bool, rest: &[OsString]) -> Result<Command, ParseError> {
        let name = if deanonymize {
            "deanonymize"
        } else {
            "anonymize"
        };
        let allowed: &[Opt] = if deanonymize {
            &[Opt::Out, Opt::Tolerant]
        } else {
            &[Opt::Out]
        };
        self.only(name, allowed)?;
        let tolerant = self.has(Opt::Tolerant);
        let paths = paths(rest)?;
        let input = if paths.is_empty() {
            if self.out.is_some() {
                return Err(invalid("--out is only valid with input paths"));
            }
            Input::Stdin(if deanonymize {
                Text::Deanonymize { tolerant }
            } else {
                Text::Anonymize
            })
        } else {
            let out = self
                .out
                .take()
                .ok_or_else(|| invalid("--out is required with input paths"))?;
            Input::Request(if deanonymize {
                Request::DeanonymizeFiles {
                    paths,
                    out,
                    tolerant,
                }
            } else {
                Request::AnonymizeFiles { paths, out }
            })
        };
        Ok(Command::Call(Call {
            input,
            fail_on: None,
        }))
    }

    fn subject(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        self.only("subject", &[Opt::Value])?;
        if self.values.is_empty() {
            return Err(invalid("subject needs at least one --value"));
        }
        Ok(call(Request::SubjectSearch {
            values: mem::take(&mut self.values),
            paths: paths(rest)?,
        }))
    }

    fn vault_command(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        const SUB: &str = "list, forget, export or wipe";
        let (sub, rest) = subcommand("vault", SUB, rest)?;
        match sub {
            "list" => {
                self.only(
                    "vault list",
                    &[Opt::Query, Opt::Kind, Opt::Limit, Opt::Offset],
                )?;
                no_arguments("vault list", rest)?;
                Ok(call(Request::VaultList {
                    query: self.query.take(),
                    kind: self.kind.take(),
                    limit: self.limit,
                    offset: self.offset.unwrap_or(0),
                }))
            }
            "forget" => {
                self.only("vault forget", &[])?;
                let values = strings(rest)?;
                if values.is_empty() {
                    return Err(invalid("vault forget needs at least one VALUE"));
                }
                Ok(call(Request::VaultForget { values }))
            }
            "export" => {
                self.only("vault export", &[Opt::Out, Opt::Format])?;
                no_arguments("vault export", rest)?;
                Ok(call(Request::VaultExport {
                    path: self.required_out("vault export")?,
                    format: self.format.unwrap_or_default(),
                }))
            }
            "wipe" => {
                self.only("vault wipe", &[Opt::Yes])?;
                no_arguments("vault wipe", rest)?;
                if !self.has(Opt::Yes) {
                    return Err(invalid(
                        "vault wipe deletes every record from the vault: add --yes to confirm",
                    ));
                }
                Ok(call(Request::VaultWipe { confirm: true }))
            }
            other => Err(unknown_sub("vault", other, SUB)),
        }
    }

    fn inventory(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        const SUB: &str = "status, list, tree, rescan or report";
        let (sub, rest) = subcommand("inventory", SUB, rest)?;
        match sub {
            "status" => self.plain("inventory status", Request::InventoryStatus, rest),
            "list" => {
                self.only("inventory list", &[Opt::Under, Opt::Limit, Opt::Offset])?;
                no_arguments("inventory list", rest)?;
                Ok(call(Request::InventoryList {
                    under: self.under.take(),
                    limit: self.limit,
                    offset: self.offset.unwrap_or(0),
                }))
            }
            "tree" => {
                self.only("inventory tree", &[Opt::Under])?;
                no_arguments("inventory tree", rest)?;
                Ok(call(Request::InventoryTree {
                    under: self.under.take(),
                }))
            }
            "rescan" => self.plain("inventory rescan", Request::InventoryRescan, rest),
            "report" => {
                self.only("inventory report", &[Opt::Out, Opt::Format])?;
                no_arguments("inventory report", rest)?;
                Ok(call(Request::InventoryReport {
                    path: self.required_out("inventory report")?,
                    format: self.format.unwrap_or_default(),
                }))
            }
            other => Err(unknown_sub("inventory", other, SUB)),
        }
    }

    fn settings(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        const SUB: &str = "get or set";
        let (sub, rest) = subcommand("settings", SUB, rest)?;
        match sub {
            "get" => self.plain("settings get", Request::SettingsGet, rest),
            "set" => {
                self.only("settings set", &[])?;
                Ok(call(Request::SettingsSet {
                    settings: settings_patch(rest)?,
                }))
            }
            other => Err(unknown_sub("settings", other, SUB)),
        }
    }

    fn account(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        const SUB: &str = "list, add, connect, remove or browse";
        let (sub, rest) = subcommand("account", SUB, rest)?;
        match sub {
            "list" => self.plain("account list", Request::AccountsList, rest),
            "add" => self.account_add(rest),
            "connect" => {
                self.only("account connect", &[])?;
                Ok(call(Request::AccountConnect {
                    id: account_id("account connect", rest)?,
                }))
            }
            "remove" => {
                self.only("account remove", &[Opt::Yes])?;
                let id = account_id("account remove", rest)?;
                if !self.has(Opt::Yes) {
                    return Err(invalid(
                        "account remove takes the account's locations off the list and makes the inventory forget its files: add --yes to confirm",
                    ));
                }
                Ok(call(Request::AccountRemove { id }))
            }
            "browse" => {
                self.only("account browse", &[Opt::Under])?;
                Ok(call(Request::AccountBrowse {
                    id: account_id("account browse", rest)?,
                    under: self.under.take(),
                }))
            }
            other => Err(unknown_sub("account", other, SUB)),
        }
    }

    /// `account add PROVIDER --label NAME ...`: the options of the way to sign in become the
    /// `sign_in` of the request.
    fn account_add(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        const PROVIDERS: &str = "microsoft365, onedrive, google_drive, dropbox or box";
        let [word] = rest else {
            return Err(usage(format!("account add needs a PROVIDER: {PROVIDERS}")));
        };
        let name = utf8(word)?;
        let provider = Provider::parse(name)
            .ok_or_else(|| usage(format!("unknown provider '{name}': use {PROVIDERS}")))?;
        let way = self.way(provider)?;
        let command = format!("account add {}", way.mode);
        let allowed: Vec<Opt> = [Opt::Label, Opt::Mode, Opt::ClientSecretStdin]
            .into_iter()
            .chain(way.takes.iter().copied())
            .collect();
        self.only(&command, &allowed)?;
        let label = self
            .label
            .take()
            .ok_or_else(|| invalid(format!("{command} needs --label NAME")))?;
        let sign_in = self.sign_in(provider, way.mode, &command)?;
        let stdin = self.has(Opt::ClientSecretStdin);
        match (sign_in.needs_secret(), stdin) {
            (true, false) => Err(invalid(format!(
                "{command} needs the client secret: give it on stdin with --client-secret-stdin"
            ))),
            (false, true) => Err(invalid(format!(
                "{command} has no client secret: --client-secret-stdin is not valid"
            ))),
            (true, true) => Ok(Command::Call(Call {
                input: Input::Secret(NewAccount {
                    provider,
                    label,
                    sign_in,
                }),
                fail_on: None,
            })),
            (false, false) => Ok(call(Request::AccountAdd {
                provider,
                label,
                sign_in,
                client_secret: None,
            })),
        }
    }

    /// The way to sign in that `--mode` names, or the only one `provider` has.
    fn way(&mut self, provider: Provider) -> Result<&'static Way, ParseError> {
        let ways: Vec<&'static Way> = WAYS
            .iter()
            .filter(|way| way.providers.contains(&provider))
            .collect();
        let names = |ways: &[&Way]| {
            ways.iter()
                .map(|way| way.mode)
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self.mode.take() {
            Some(mode) => ways
                .iter()
                .copied()
                .find(|way| way.mode == mode)
                .ok_or_else(|| {
                    invalid(format!(
                        "{} cannot sign in with '{mode}': use {}",
                        provider.id(),
                        names(&ways)
                    ))
                }),
            None => match ways.as_slice() {
                [only] => Ok(*only),
                _ => Err(invalid(format!(
                    "{} has more than one way to sign in: give --mode {}",
                    provider.id(),
                    names(&ways)
                ))),
            },
        }
    }

    /// The `sign_in` for `mode` from the options given; `command` names it in the errors.
    fn sign_in(
        &mut self,
        provider: Provider,
        mode: &str,
        command: &str,
    ) -> Result<SignIn, ParseError> {
        fn need<T>(value: Option<T>, command: &str, flag: &str) -> Result<T, ParseError> {
            value.ok_or_else(|| invalid(format!("{command} needs {flag}")))
        }
        let tenant = |this: &mut Self| match (provider, this.tenant.take()) {
            (Provider::OneDrive, None) => Ok("consumers".to_owned()),
            (Provider::OneDrive, Some(tenant)) if tenant != "consumers" => Err(invalid(format!(
                "{command} uses the tenant consumers, not '{tenant}'"
            ))),
            (_, tenant) => need(tenant, command, "--tenant T"),
        };
        Ok(match mode {
            "microsoft_delegated" => SignIn::MicrosoftDelegated {
                tenant: tenant(self)?,
                client_id: need(self.client_id.take(), command, "--client-id ID")?,
            },
            "microsoft_app" => SignIn::MicrosoftApp {
                tenant: tenant(self)?,
                client_id: need(self.client_id.take(), command, "--client-id ID")?,
                credential: self.credential(command)?,
            },
            "microsoft_app_selected" => SignIn::MicrosoftAppSelected {
                tenant: tenant(self)?,
                client_id: need(self.client_id.take(), command, "--client-id ID")?,
                credential: self.credential(command)?,
                sites: match mem::take(&mut self.sites) {
                    sites if sites.is_empty() => {
                        return Err(invalid(format!("{command} needs at least one --site URL")));
                    }
                    sites => sites,
                },
            },
            "google_delegated" => SignIn::GoogleDelegated {
                client_id: need(self.client_id.take(), command, "--client-id ID")?,
            },
            "google_service_account" => SignIn::GoogleServiceAccount {
                key_file: need(self.key_file.take(), command, "--key-file FILE")?,
                users: match mem::take(&mut self.users) {
                    users if users.is_empty() => {
                        return Err(invalid(format!(
                            "{command} needs at least one --user EMAIL"
                        )));
                    }
                    users => users,
                },
            },
            "dropbox_delegated" => SignIn::DropboxDelegated {
                app_key: need(self.app_key.take(), command, "--app-key KEY")?,
            },
            "box_delegated" => SignIn::BoxDelegated {
                client_id: need(self.client_id.take(), command, "--client-id ID")?,
            },
            _ => SignIn::BoxApp {
                client_id: need(self.client_id.take(), command, "--client-id ID")?,
                subject: match (self.enterprise_id.take(), self.user_id.take()) {
                    (Some(id), None) => BoxSubject::Enterprise(id),
                    (None, Some(id)) => BoxSubject::User(id),
                    _ => {
                        return Err(invalid(format!(
                            "{command} needs --enterprise-id ID or --user-id ID, one of them"
                        )));
                    }
                },
            },
        })
    }

    /// How a Microsoft app proves who it is: a certificate when both files are given, else a
    /// secret.
    fn credential(&mut self, command: &str) -> Result<Credential, ParseError> {
        match (self.key_file.take(), self.cert_file.take()) {
            (Some(key_file), Some(cert_file)) => Ok(Credential::Certificate {
                key_file,
                cert_file,
            }),
            (None, None) => Ok(Credential::Secret),
            _ => Err(invalid(format!(
                "{command}: --key-file and --cert-file go together"
            ))),
        }
    }

    fn model(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        const SUB: &str = "status or download";
        let (sub, rest) = subcommand("model", SUB, rest)?;
        match sub {
            "status" => self.plain("model status", Request::ModelStatus, rest),
            "download" => self.plain("model download", Request::ModelDownload, rest),
            other => Err(unknown_sub("model", other, SUB)),
        }
    }

    fn token(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        self.only("token", &[Opt::Rotate])?;
        no_arguments("token", rest)?;
        Ok(call(Request::ApiToken {
            rotate: self.has(Opt::Rotate),
        }))
    }

    fn protection(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        self.only("protection", &[])?;
        let [state] = rest else {
            return Err(usage("protection needs on or off"));
        };
        match utf8(state)? {
            "on" => Ok(call(Request::Protection { on: true })),
            "off" => Ok(call(Request::Protection { on: false })),
            other => Err(usage(format!("protection needs on or off, not '{other}'"))),
        }
    }

    fn serve(&mut self, rest: &[OsString]) -> Result<Command, ParseError> {
        self.only("serve", &[Opt::Http, Opt::Port, Opt::Pipe])?;
        no_arguments("serve", rest)?;
        let http = self.has(Opt::Http);
        if self.port.is_some() && !http {
            return Err(invalid("--port needs --http"));
        }
        Ok(Command::Serve(Serve {
            http,
            port: self.port,
            pipe: self.pipe.take(),
        }))
    }

    /// A command that takes no options and no arguments.
    fn plain(
        &mut self,
        command: &str,
        request: Request,
        rest: &[OsString],
    ) -> Result<Command, ParseError> {
        self.only(command, &[])?;
        no_arguments(command, rest)?;
        Ok(call(request))
    }

    fn required_out(&mut self, command: &str) -> Result<PathBuf, ParseError> {
        self.out
            .take()
            .ok_or_else(|| invalid(format!("{command} needs --out FILE")))
    }
}

fn call(request: Request) -> Command {
    Command::Call(Call {
        input: Input::Request(request),
        fail_on: None,
    })
}

/// One way to sign in to an account: its `mode` in the API, the providers that have it and the
/// options it takes besides `--label`, `--mode` and `--client-secret-stdin`.
struct Way {
    mode: &'static str,
    providers: &'static [Provider],
    takes: &'static [Opt],
}

/// Every way to sign in, the way `account add` offers them.
const WAYS: [Way; 8] = [
    Way {
        mode: "microsoft_delegated",
        providers: &[Provider::Microsoft365, Provider::OneDrive],
        takes: &[Opt::Tenant, Opt::ClientId],
    },
    Way {
        mode: "microsoft_app",
        providers: &[Provider::Microsoft365],
        takes: &[Opt::Tenant, Opt::ClientId, Opt::KeyFile, Opt::CertFile],
    },
    Way {
        mode: "microsoft_app_selected",
        providers: &[Provider::Microsoft365],
        takes: &[
            Opt::Tenant,
            Opt::ClientId,
            Opt::KeyFile,
            Opt::CertFile,
            Opt::Site,
        ],
    },
    Way {
        mode: "google_delegated",
        providers: &[Provider::GoogleDrive],
        takes: &[Opt::ClientId],
    },
    Way {
        mode: "google_service_account",
        providers: &[Provider::GoogleDrive],
        takes: &[Opt::KeyFile, Opt::User],
    },
    Way {
        mode: "dropbox_delegated",
        providers: &[Provider::Dropbox],
        takes: &[Opt::AppKey],
    },
    Way {
        mode: "box_delegated",
        providers: &[Provider::Box],
        takes: &[Opt::ClientId],
    },
    Way {
        mode: "box_app",
        providers: &[Provider::Box],
        takes: &[Opt::ClientId, Opt::EnterpriseId, Opt::UserId],
    },
];

/// The one account id of `account connect`, `remove` or `browse`.
fn account_id(command: &str, rest: &[OsString]) -> Result<String, ParseError> {
    let [id] = rest else {
        return Err(usage(format!(
            "{command} needs an account ID (see piikey-cli account list)"
        )));
    };
    Ok(utf8(id)?.to_owned())
}

/// The word after a command group: `vault` is followed by `list`, `forget`...
fn subcommand<'a>(
    group: &str,
    choices: &str,
    rest: &'a [OsString],
) -> Result<(&'a str, &'a [OsString]), ParseError> {
    let Some((word, tail)) = rest.split_first() else {
        return Err(usage(format!("{group} needs {choices}")));
    };
    Ok((utf8(word)?, tail))
}

fn unknown_sub(group: &str, word: &str, choices: &str) -> ParseError {
    usage(format!("unknown {group} command '{word}': use {choices}"))
}

fn no_arguments(command: &str, rest: &[OsString]) -> Result<(), ParseError> {
    match rest.first() {
        Some(extra) => Err(usage(format!(
            "{command} takes no arguments, not '{}'",
            extra.to_string_lossy()
        ))),
        None => Ok(()),
    }
}

fn utf8(word: &OsStr) -> Result<&str, ParseError> {
    word.to_str()
        .ok_or_else(|| usage("arguments must be valid Unicode"))
}

/// A path argument; an empty one is a mistake (a variable that was not set).
fn path(word: OsString) -> Result<PathBuf, ParseError> {
    if word.is_empty() {
        return Err(invalid("a path is empty"));
    }
    Ok(PathBuf::from(word))
}

fn paths(words: &[OsString]) -> Result<Vec<PathBuf>, ParseError> {
    words.iter().cloned().map(path).collect()
}

fn strings(words: &[OsString]) -> Result<Vec<String>, ParseError> {
    words
        .iter()
        .map(|word| {
            word.to_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("{} is not valid Unicode", word.to_string_lossy())))
        })
        .collect()
}

fn number(parser: &mut Parser, opt: Opt) -> Result<usize, ParseError> {
    let value = parser.value()?;
    let text = value.to_string_lossy();
    text.parse()
        .map_err(|_| invalid(format!("{} needs a number, not '{text}'", opt.flag())))
}

fn port(parser: &mut Parser) -> Result<u16, ParseError> {
    let value = parser.value()?;
    let text = value.to_string_lossy();
    parse_port(&text)
        .ok_or_else(|| invalid(format!("--port needs a port from 1 to 65535, not '{text}'")))
}

/// `text` as a port the API can listen on.
fn parse_port(text: &str) -> Option<u16> {
    text.parse().ok().filter(|&port| valid_port(port))
}

fn format(text: &str) -> Result<Format, ParseError> {
    match text.to_ascii_lowercase().as_str() {
        "json" => Ok(Format::Json),
        "csv" => Ok(Format::Csv),
        _ => Err(invalid(format!("--format needs json or csv, not '{text}'"))),
    }
}

/// `--fail-on`: kind names, comma separated, or `any`. Repeating the option adds to the kinds.
fn fail_on(before: Option<FailOn>, text: &str) -> Result<FailOn, ParseError> {
    let mut any = matches!(before, Some(FailOn::Any));
    let mut kinds = match before {
        Some(FailOn::Kinds(kinds)) => kinds,
        _ => Vec::new(),
    };
    let mut named = false;
    for name in text
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        named = true;
        let name = name.to_ascii_lowercase();
        if name == "any" {
            any = true;
        } else {
            let kind = EntityKind::parse(&name).ok_or_else(|| {
                invalid(format!(
                    "--fail-on: '{name}' is not a kind of personal data (see piikey-cli kinds)"
                ))
            })?;
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
    }
    if !named {
        return Err(invalid("--fail-on needs kinds, comma separated, or any"));
    }
    Ok(if any {
        FailOn::Any
    } else {
        FailOn::Kinds(kinds)
    })
}

/// The keys `settings set` takes: the `guard.cfg` keys, except `enabled` (that is `protection`).
fn settings_keys() -> String {
    let keys: Vec<&str> = KEYS.into_iter().filter(|key| *key != "enabled").collect();
    keys.join(", ")
}

/// `settings set KEY=VALUE...` as a patch. A list key repeats, once per element; with an empty
/// value it empties the list.
fn settings_patch(pairs: &[OsString]) -> Result<SettingsPatch, ParseError> {
    if pairs.is_empty() {
        return Err(invalid("settings set needs KEY=VALUE..."));
    }
    let mut patch = SettingsPatch::default();
    for pair in pairs {
        let pair = utf8(pair)?;
        let Some((key, value)) = pair.split_once('=') else {
            return Err(invalid(format!(
                "settings set needs KEY=VALUE, not '{pair}'"
            )));
        };
        match key {
            "site" => push(&mut patch.sites, value),
            "program" => push(&mut patch.programs, value),
            "disabled_kind" => push(&mut patch.disabled_kinds, value),
            "inventory_root" => push(&mut patch.inventory_roots, value),
            "monitor_root" => push(&mut patch.monitored_roots, value),
            "highlight" => {
                patch.highlight = Some(Highlight::parse(value).ok_or_else(|| {
                    invalid(format!(
                        "highlight needs off, always or hotkey, not '{value}'"
                    ))
                })?);
            }
            "explorer_menu" => patch.explorer_menu = Some(switch(key, value)?),
            "background" => patch.background = Some(switch(key, value)?),
            "http_api" => patch.http_api = Some(switch(key, value)?),
            "http_port" => {
                patch.http_port = Some(parse_port(value).ok_or_else(|| {
                    invalid(format!(
                        "http_port needs a port from 1 to 65535, not '{value}'"
                    ))
                })?);
            }
            "enabled" => {
                return Err(invalid(
                    "protection is not a setting: use piikey-cli protection on or off",
                ));
            }
            other => {
                return Err(invalid(format!(
                    "unknown setting '{other}': the settings are {}",
                    settings_keys()
                )));
            }
        }
    }
    Ok(patch)
}

/// Adds `value` to the list a `KEY=VALUE` names; an empty value only makes the list present,
/// so the patch empties it.
fn push<T: From<String>>(list: &mut Option<Vec<T>>, value: &str) {
    let list = list.get_or_insert_with(Vec::new);
    if !value.is_empty() {
        list.push(T::from(value.to_owned()));
    }
}

fn switch(key: &str, value: &str) -> Result<bool, ParseError> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(format!("{key} needs true or false, not '{value}'"))),
    }
}

#[cfg(test)]
mod tests;
