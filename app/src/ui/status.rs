//! What piikey is doing, said once.
//!
//! The hero of Overview, the chip under the navigation pane, the tray's tooltip, its menu header and
//! its icon all render one [`Status`], so they cannot disagree. It is derived from nothing but the
//! controller's [`Snapshot`] and the window's optimistic wish ([`Status::of`]), so every sentence a
//! user can read about the state of protection is tested here, without a window.

use super::{
    assets::TrayIcon,
    controller::{Busy, Cert, Model, Severity, Snapshot},
};

/// What the controller is working on, as the user reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Starting,
    Stopping,
    /// Windows is adding the certificate and asks the user to confirm.
    InstallingCertificate,
}

/// The latest masking or restoring this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Last {
    /// The site the traffic went to.
    pub host: String,
    /// When, as the activity feed tells times: `14:05`, `yesterday 14:05`, `Mon 14:05`, `12 Oct`.
    pub at: String,
}

/// The one cause of a status that needs the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// Windows does not trust the piikey certificate, so the HTTPS of protected sites cannot be read.
    CertificateMissing,
    /// The detection model could not be downloaded; the message says why.
    ModelFailed(String),
    /// An action failed and the controller raised an error notice with this text.
    Error(String),
}

/// The button that fixes a [`Cause`], when one button can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fix {
    InstallCertificate,
    RetryModel,
}

impl Fix {
    /// The text of the button.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InstallCertificate => "Install certificate",
            Self::RetryModel => "Try again",
        }
    }
}

impl Cause {
    /// The title of the message bar that carries the cause.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {
            Self::CertificateMissing => "Certificate not installed",
            Self::ModelFailed(_) => "Download failed",
            Self::Error(_) => "Something went wrong",
        }
    }

    /// What the message bar says: why it matters, or what went wrong in the system's words.
    #[must_use]
    pub fn explanation(&self) -> String {
        match self {
            Self::CertificateMissing => "piikey needs it to read the HTTPS traffic of your protected sites and apps. Windows asks you to confirm once.".to_owned(),
            Self::ModelFailed(message) | Self::Error(message) => message.clone(),
        }
    }

    /// The one button that fixes it; an error is only read and closed.
    #[must_use]
    pub const fn fix(&self) -> Option<Fix> {
        match self {
            Self::CertificateMissing => Some(Fix::InstallCertificate),
            Self::ModelFailed(_) => Some(Fix::RetryModel),
            Self::Error(_) => None,
        }
    }

    /// One sentence for the hero; `running` is whether protection is on meanwhile.
    fn sentence(&self, running: bool) -> String {
        match self {
            Self::CertificateMissing if running => {
                "Windows does not trust the piikey certificate, so HTTPS sites cannot be masked."
                    .to_owned()
            }
            Self::CertificateMissing => {
                "The piikey certificate is not installed, so protection cannot start.".to_owned()
            }
            Self::ModelFailed(_) => "The detection model could not be downloaded.".to_owned(),
            Self::Error(message) => message.clone(),
        }
    }

    /// A short clause for the tray's tooltip, which Windows cuts at 127 characters.
    fn short(&self) -> String {
        match self {
            Self::CertificateMissing => "The certificate is not installed.".to_owned(),
            Self::ModelFailed(_) => "The detection model could not be downloaded.".to_owned(),
            Self::Error(message) => clip(message, 80),
        }
    }
}

/// How a status looks beside its words: the glyph's colour and whether it is a spinner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Off, or nothing to say: the theme's text colour, dimmed.
    Neutral,
    /// Protection runs: Windows' success colour.
    Good,
    /// The user is needed: Windows' caution colour.
    Caution,
    /// Something is on its way: the accent colour, and a spinner where there is room.
    Busy,
}

/// What the primary button of the hero does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    TurnOn,
    TurnOff,
    /// Neither, for the reason given (none while the controller is only busy).
    Unavailable(Option<&'static str>),
}

/// The state of the background worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Nothing is read or changed. `needs_certificate`: it cannot be turned on until Windows
    /// trusts the certificate.
    Off { needs_certificate: bool },
    /// The controller is switching protection or installing the certificate.
    Busy(Work),
    /// Masking runs for `protected` sites and apps.
    On { protected: u64, last: Option<Last> },
    /// Something needs the user. `running` says protection is on meanwhile.
    NeedsAttention { running: bool, cause: Cause },
    /// The detection model downloads; protection can start when it has.
    ModelDownloading { done: u64, total: u64 },
}

/// What Off says: the best sentence of the app.
const OFF: &str = "Nothing is read or changed, and your Windows proxy settings are your own.";

impl Status {
    /// The status of `snap`. `desired` is what the window's switch shows while the controller is
    /// still getting there: only while commands are pending does it say more than the snapshot.
    #[must_use]
    pub fn of(snap: &Snapshot, desired: Option<bool>) -> Self {
        match &snap.model {
            Model::Downloading { done, total } => {
                return Self::ModelDownloading {
                    done: *done,
                    total: *total,
                };
            }
            Model::Failed(message) => {
                return Self::NeedsAttention {
                    running: snap.enabled,
                    cause: Cause::ModelFailed(message.clone()),
                };
            }
            Model::Ready | Model::Skipped => {}
        }
        if let Some(work) = work(snap, desired) {
            return Self::Busy(work);
        }
        let certificate_missing = snap.cert == Cert::Missing;
        let error = snap
            .notice
            .as_ref()
            .filter(|notice| notice.severity == Severity::Error);
        // The certificate is the cause that one click fixes: it wins over the error it may be
        // behind.
        let cause = if certificate_missing && (snap.enabled || error.is_some()) {
            Some(Cause::CertificateMissing)
        } else {
            error.map(|notice| Cause::Error(notice.text.clone()))
        };
        match cause {
            Some(cause) => Self::NeedsAttention {
                running: snap.enabled,
                cause,
            },
            None if snap.enabled => Self::On {
                protected: protected(snap),
                last: snap.last_activity.as_ref().map(|sent| Last {
                    host: sent.host.clone(),
                    at: sent.at.clone(),
                }),
            },
            None => Self::Off {
                needs_certificate: certificate_missing,
            },
        }
    }

    /// The headline: the hero's title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {
            Self::Off { .. } => "Protection is off",
            Self::Busy(Work::Starting) => "Starting protection\u{2026}",
            Self::Busy(Work::Stopping) => "Stopping protection\u{2026}",
            Self::Busy(Work::InstallingCertificate) => "Installing the certificate\u{2026}",
            Self::On { .. } => "Protection is on",
            Self::NeedsAttention { running: true, .. } => "Protection is on, but needs attention",
            Self::NeedsAttention { running: false, .. } => "Protection needs attention",
            Self::ModelDownloading { .. } => "Downloading the detection model",
        }
    }

    /// The one specific sentence under the headline.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::Off { .. } => OFF.to_owned(),
            Self::Busy(Work::Starting) => {
                "Checking the certificate and pointing Windows at piikey.".to_owned()
            }
            Self::Busy(Work::Stopping) => "Giving Windows its proxy settings back.".to_owned(),
            Self::Busy(Work::InstallingCertificate) => {
                "Waiting for Windows to add the certificate.".to_owned()
            }
            Self::On {
                protected: 0,
                last: _,
            } => "No sites or apps are protected yet. Add one on the Protection page.".to_owned(),
            Self::On {
                protected,
                last: Some(last),
            } => format!(
                "Masking {}. Last swap: {} {}.",
                protected_text(*protected),
                last.host,
                when(&last.at)
            ),
            Self::On {
                protected,
                last: None,
            } => format!(
                "Waiting for traffic from your {}.",
                if *protected == 1 {
                    "protected site or app".to_owned()
                } else {
                    format!("{protected} protected sites and apps")
                }
            ),
            Self::NeedsAttention { running, cause } => cause.sentence(*running),
            Self::ModelDownloading { done, total } => download_sentence(*done, *total),
        }
    }

    /// The line under the pane: a glyph and these few words.
    #[must_use]
    pub const fn chip(&self) -> &'static str {
        match self {
            Self::Off { .. } => "Protection off",
            Self::Busy(Work::Starting) => "Starting\u{2026}",
            Self::Busy(Work::Stopping) => "Stopping\u{2026}",
            Self::Busy(Work::InstallingCertificate) => "Adding certificate\u{2026}",
            Self::On { .. } => "Protection on",
            Self::NeedsAttention { .. } => "Needs attention",
            Self::ModelDownloading { .. } => "Downloading model\u{2026}",
        }
    }

    /// What the tray shows when the pointer rests on its icon: at most 127 characters.
    #[must_use]
    pub fn tooltip(&self) -> String {
        match self {
            Self::Off { .. } => "piikey: protection off".to_owned(),
            Self::Busy(Work::Starting) => "piikey: starting protection\u{2026}".to_owned(),
            Self::Busy(Work::Stopping) => "piikey: stopping protection\u{2026}".to_owned(),
            Self::Busy(Work::InstallingCertificate) => {
                "piikey: waiting for Windows to add the certificate".to_owned()
            }
            Self::On { protected, .. } => {
                format!("piikey: protection on, {}", protected_text(*protected))
            }
            Self::NeedsAttention { running, cause } => format!(
                "piikey: {} needs attention. {}",
                if *running {
                    "protection is on but"
                } else {
                    "protection"
                },
                cause.short()
            ),
            Self::ModelDownloading { done, total } => {
                format!(
                    "piikey: downloading the detection model, {}%",
                    percent(*done, *total)
                )
            }
        }
    }

    /// A Segoe Fluent Icons glyph: an outline shield for off, a shield with a keyhole for on, one
    /// with an exclamation mark when the user is needed.
    #[must_use]
    pub const fn glyph(&self) -> &'static str {
        match self {
            Self::Off { .. } => "\u{EA18}",
            Self::Busy(_) => "\u{E895}",
            Self::On { .. } => "\u{E705}",
            Self::NeedsAttention { .. } => "\u{E730}",
            Self::ModelDownloading { .. } => "\u{E896}",
        }
    }

    /// How the glyph is coloured.
    #[must_use]
    pub const fn tone(&self) -> Tone {
        match self {
            Self::Off { .. } => Tone::Neutral,
            Self::Busy(_) | Self::ModelDownloading { .. } => Tone::Busy,
            Self::On { .. } => Tone::Good,
            Self::NeedsAttention { .. } => Tone::Caution,
        }
    }

    /// The tray icon of this status: the key in grey while off or downloading, the app icon while
    /// protection runs or starts, with an amber dot while the user is needed.
    #[must_use]
    pub const fn icon(&self) -> TrayIcon {
        match self {
            Self::Off { .. } | Self::ModelDownloading { .. } => TrayIcon::Off,
            Self::Busy(_) | Self::On { .. } => TrayIcon::On,
            Self::NeedsAttention { .. } => TrayIcon::Attention,
        }
    }

    /// What the hero's primary button does.
    #[must_use]
    pub const fn action(&self) -> Action {
        match self {
            Self::Off {
                needs_certificate: true,
            }
            | Self::NeedsAttention {
                running: false,
                cause: Cause::CertificateMissing,
            } => Action::Unavailable(Some("Install the certificate first.")),
            Self::Off { .. }
            | Self::NeedsAttention {
                running: false,
                cause: Cause::Error(_),
            } => Action::TurnOn,
            Self::On { .. } | Self::NeedsAttention { running: true, .. } => Action::TurnOff,
            Self::Busy(_) => Action::Unavailable(None),
            Self::NeedsAttention {
                running: false,
                cause: Cause::ModelFailed(_),
            } => Action::Unavailable(Some("The detection model has to download first.")),
            Self::ModelDownloading { .. } => {
                Action::Unavailable(Some("Protection can start when the model has downloaded."))
            }
        }
    }

    /// Whether protection is on, or on its way: what a toggle inverts.
    #[must_use]
    pub const fn is_on(&self) -> bool {
        matches!(
            self,
            Self::Busy(Work::Starting)
                | Self::On { .. }
                | Self::NeedsAttention { running: true, .. }
        )
    }

    /// Whether the controller is in the middle of something: a spinner shows.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        matches!(self, Self::Busy(_))
    }

    /// The one problem to fix, with its fix: what needs the user, or what stands in the way of
    /// turning protection on. `None` when there is nothing.
    #[must_use]
    pub fn problem(&self) -> Option<Cause> {
        match self {
            Self::NeedsAttention { cause, .. } => Some(cause.clone()),
            Self::Off {
                needs_certificate: true,
            } => Some(Cause::CertificateMissing),
            _ => None,
        }
    }
}

/// What the controller is working on: a command is running, or a wish is on its way.
fn work(snap: &Snapshot, desired: Option<bool>) -> Option<Work> {
    match snap.busy {
        Some(Busy::Starting) => Some(Work::Starting),
        Some(Busy::Stopping) => Some(Work::Stopping),
        Some(Busy::InstallingCertificate) => Some(Work::InstallingCertificate),
        None if snap.pending > 0 => match desired {
            Some(true) if !snap.enabled => Some(Work::Starting),
            Some(false) if snap.enabled => Some(Work::Stopping),
            _ => None,
        },
        None => None,
    }
}

/// How many sites and apps the settings protect.
#[must_use]
pub fn protected(snap: &Snapshot) -> u64 {
    let count = snap.policy.sites.len() + snap.policy.programs.len();
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// `4 sites and apps`, `1 site or app`.
#[must_use]
pub fn protected_text(count: u64) -> String {
    match count {
        0 => "no sites or apps".to_owned(),
        1 => "1 site or app".to_owned(),
        n => format!("{n} sites and apps"),
    }
}

/// `at 14:05`, `yesterday at 14:05`, `on Mon at 14:05`, `on 12 Oct`: the feed's time, as a clause.
fn when(at: &str) -> String {
    match at.split_once(' ') {
        None if at.contains(':') => format!("at {at}"),
        Some(("yesterday", clock)) => format!("yesterday at {clock}"),
        Some((day, clock)) if clock.contains(':') => format!("on {day} at {clock}"),
        _ => format!("on {at}"),
    }
}

/// Whole percent of `done` in `total`, at most 100.
fn percent(done: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    u64::try_from((u128::from(done) * 100 / u128::from(total)).min(100)).unwrap_or(100)
}

/// `42% of 380 MB. Protection can start when it has finished.`
fn download_sentence(done: u64, total: u64) -> String {
    let megabytes = |bytes: u64| bytes.saturating_add(500_000) / 1_000_000;
    if total == 0 {
        return "Protection can start when it has finished.".to_owned();
    }
    format!(
        "{}% of {} MB. Protection can start when it has finished.",
        percent(done, total),
        megabytes(total)
    )
}

/// `text` on one line and cut to at most `max` UTF-16 units, which is what the tray counts in,
/// with an ellipsis where it was cut. A control character (a line break, a null: the tray refuses
/// a tooltip with a null in it) becomes a space.
fn clip(text: &str, max: usize) -> String {
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if line.encode_utf16().count() <= max {
        return line;
    }
    let mut clipped = String::new();
    let mut used = 0;
    for c in line.chars() {
        // One unit stays free for the ellipsis.
        if used + c.len_utf16() + 1 > max {
            break;
        }
        used += c.len_utf16();
        clipped.push(c);
    }
    clipped.push('\u{2026}');
    clipped
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        super::{
            controller::{Controller, Notice, Sent},
            testing::{TempDir, stub_controller},
        },
        *,
    };

    type Test = Result<(), String>;

    /// A snapshot of an idle controller with the certificate trusted, its model ready and nothing
    /// protected, for a test to change.
    fn quiet(dir: &TempDir) -> Result<(Arc<Controller>, Snapshot), String> {
        let controller = stub_controller(dir)?;
        let mut snap = controller.snapshot();
        snap.cert = Cert::Installed;
        snap.policy.sites = vec!["chatgpt.com".to_owned(), "claude.ai".to_owned()];
        snap.policy.programs = vec!["chrome.exe".to_owned(), "code.exe".to_owned()];
        Ok((controller, snap))
    }

    fn sent(at: &str) -> Sent {
        Sent {
            host: "chatgpt.com".to_owned(),
            exe: None,
            at: at.to_owned(),
        }
    }

    #[test]
    fn off_says_nothing_is_touched_and_offers_to_turn_on() -> Test {
        let dir = TempDir::new()?;
        let (_controller, snap) = quiet(&dir)?;
        let status = Status::of(&snap, None);
        assert_eq!(
            status,
            Status::Off {
                needs_certificate: false
            }
        );
        assert_eq!(status.title(), "Protection is off");
        assert_eq!(
            status.sentence(),
            "Nothing is read or changed, and your Windows proxy settings are your own."
        );
        assert_eq!(status.chip(), "Protection off");
        assert_eq!(status.tooltip(), "piikey: protection off");
        assert_eq!(status.action(), Action::TurnOn);
        assert_eq!(status.icon(), TrayIcon::Off);
        assert_eq!(status.tone(), Tone::Neutral);
        assert!(!status.is_on() && !status.is_busy());
        assert_eq!(status.problem(), None);
        Ok(())
    }

    #[test]
    fn without_the_certificate_off_waits_for_it_and_names_the_fix() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.cert = Cert::Missing;
        let status = Status::of(&snap, None);
        // Nobody asked for protection: this is still Off, not an alarm.
        assert_eq!(
            status,
            Status::Off {
                needs_certificate: true
            }
        );
        assert_eq!(status.title(), "Protection is off");
        assert_eq!(
            status.action(),
            Action::Unavailable(Some("Install the certificate first."))
        );
        let problem = status.problem();
        assert_eq!(problem, Some(Cause::CertificateMissing));
        assert_eq!(
            problem.and_then(|cause| cause.fix()).map(Fix::label),
            Some("Install certificate")
        );
        assert_eq!(status.icon(), TrayIcon::Off);
        Ok(())
    }

    #[test]
    fn on_says_what_is_masked_and_when_the_last_swap_was() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.enabled = true;
        let idle = Status::of(&snap, None);
        assert_eq!(idle.title(), "Protection is on");
        assert_eq!(
            idle.sentence(),
            "Waiting for traffic from your 4 protected sites and apps."
        );
        assert_eq!(idle.chip(), "Protection on");
        assert_eq!(idle.tooltip(), "piikey: protection on, 4 sites and apps");
        assert_eq!(idle.action(), Action::TurnOff);
        assert_eq!(idle.icon(), TrayIcon::On);
        assert_eq!(idle.tone(), Tone::Good);
        assert!(idle.is_on());

        for (at, clause) in [
            ("14:05", "chatgpt.com at 14:05"),
            ("yesterday 14:05", "chatgpt.com yesterday at 14:05"),
            ("Mon 14:05", "chatgpt.com on Mon at 14:05"),
            ("12 Oct", "chatgpt.com on 12 Oct"),
        ] {
            snap.last_activity = Some(sent(at));
            assert_eq!(
                Status::of(&snap, None).sentence(),
                format!("Masking 4 sites and apps. Last swap: {clause}."),
                "{at}"
            );
        }
        Ok(())
    }

    #[test]
    fn on_counts_one_site_and_none_without_the_plural() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.enabled = true;
        snap.policy.sites = vec!["chatgpt.com".to_owned()];
        snap.policy.programs.clear();
        assert_eq!(
            Status::of(&snap, None).sentence(),
            "Waiting for traffic from your protected site or app."
        );
        snap.last_activity = Some(sent("14:05"));
        assert_eq!(
            Status::of(&snap, None).sentence(),
            "Masking 1 site or app. Last swap: chatgpt.com at 14:05."
        );
        snap.policy.sites.clear();
        let empty = Status::of(&snap, None);
        assert_eq!(
            empty.sentence(),
            "No sites or apps are protected yet. Add one on the Protection page."
        );
        assert_eq!(protected_text(0), "no sites or apps");
        Ok(())
    }

    #[test]
    fn a_busy_controller_is_starting_stopping_or_installing() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        for (busy, work, title, chip) in [
            (
                Busy::Starting,
                Work::Starting,
                "Starting protection\u{2026}",
                "Starting\u{2026}",
            ),
            (
                Busy::Stopping,
                Work::Stopping,
                "Stopping protection\u{2026}",
                "Stopping\u{2026}",
            ),
            (
                Busy::InstallingCertificate,
                Work::InstallingCertificate,
                "Installing the certificate\u{2026}",
                "Adding certificate\u{2026}",
            ),
        ] {
            snap.busy = Some(busy);
            let status = Status::of(&snap, None);
            assert_eq!(status, Status::Busy(work));
            assert_eq!(status.title(), title);
            assert_eq!(status.chip(), chip);
            assert_eq!(status.action(), Action::Unavailable(None));
            assert!(status.is_busy());
            assert!(!status.sentence().is_empty());
            assert!(status.tooltip().starts_with("piikey: "));
        }
        // A start the tray asked for counts as on: its toggle must turn it off next.
        snap.busy = Some(Busy::Starting);
        assert!(Status::of(&snap, None).is_on());
        assert_eq!(Status::of(&snap, None).icon(), TrayIcon::On);
        Ok(())
    }

    #[test]
    fn a_wish_the_controller_has_not_reached_yet_shows_as_busy_only_while_it_is_pending() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.pending = 1;
        assert_eq!(
            Status::of(&snap, Some(true)),
            Status::Busy(Work::Starting),
            "the switch went on, the worker has not begun"
        );
        snap.enabled = true;
        assert_eq!(Status::of(&snap, Some(false)), Status::Busy(Work::Stopping));
        // The wish is what the snapshot already is: nothing to wait for.
        assert!(matches!(Status::of(&snap, Some(true)), Status::On { .. }));
        // Nothing pending: the controller is where it ended up, whatever was wished.
        snap.pending = 0;
        snap.enabled = false;
        assert!(matches!(Status::of(&snap, Some(true)), Status::Off { .. }));
        Ok(())
    }

    #[test]
    fn a_missing_certificate_while_on_needs_attention_and_can_still_be_turned_off() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.enabled = true;
        snap.cert = Cert::Missing;
        let status = Status::of(&snap, None);
        assert_eq!(
            status,
            Status::NeedsAttention {
                running: true,
                cause: Cause::CertificateMissing
            }
        );
        assert_eq!(status.title(), "Protection is on, but needs attention");
        assert_eq!(
            status.sentence(),
            "Windows does not trust the piikey certificate, so HTTPS sites cannot be masked."
        );
        assert_eq!(status.chip(), "Needs attention");
        assert_eq!(status.action(), Action::TurnOff);
        assert_eq!(status.icon(), TrayIcon::Attention);
        assert_eq!(status.tone(), Tone::Caution);
        assert!(status.is_on());
        assert_eq!(
            status.tooltip(),
            "piikey: protection is on but needs attention. The certificate is not installed."
        );
        Ok(())
    }

    #[test]
    fn an_error_notice_is_the_cause_and_a_warning_is_not() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.notice = Some(Notice::warning(
            "piikey turns on as soon as the model has downloaded.",
        ));
        assert!(
            matches!(Status::of(&snap, None), Status::Off { .. }),
            "a warning is read, not acted on"
        );

        snap.notice = Some(Notice::error(
            "Could not start the proxy on 127.0.0.1:8080: port in use",
        ));
        let status = Status::of(&snap, None);
        assert_eq!(
            status,
            Status::NeedsAttention {
                running: false,
                cause: Cause::Error(
                    "Could not start the proxy on 127.0.0.1:8080: port in use".to_owned()
                )
            }
        );
        assert_eq!(status.title(), "Protection needs attention");
        assert_eq!(
            status.sentence(),
            "Could not start the proxy on 127.0.0.1:8080: port in use"
        );
        // Trying again is turning on again.
        assert_eq!(status.action(), Action::TurnOn);
        assert_eq!(status.icon(), TrayIcon::Attention);
        assert_eq!(status.problem().and_then(|cause| cause.fix()), None);

        // While on, the same error leaves protection on.
        snap.enabled = true;
        assert_eq!(
            Status::of(&snap, None).title(),
            "Protection is on, but needs attention"
        );
        Ok(())
    }

    #[test]
    fn the_certificate_is_named_when_it_is_behind_an_error() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.cert = Cert::Missing;
        snap.notice = Some(Notice::error(
            "Could not install the certificate: cancelled",
        ));
        let status = Status::of(&snap, None);
        assert_eq!(
            status,
            Status::NeedsAttention {
                running: false,
                cause: Cause::CertificateMissing
            }
        );
        assert_eq!(
            status.sentence(),
            "The piikey certificate is not installed, so protection cannot start."
        );
        assert_eq!(
            status.action(),
            Action::Unavailable(Some("Install the certificate first."))
        );
        Ok(())
    }

    #[test]
    fn the_model_download_is_a_state_of_its_own_with_its_progress() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.model = Model::Downloading {
            done: 159_600_000,
            total: 380_000_000,
        };
        let status = Status::of(&snap, None);
        assert_eq!(
            status,
            Status::ModelDownloading {
                done: 159_600_000,
                total: 380_000_000
            }
        );
        assert_eq!(status.title(), "Downloading the detection model");
        assert_eq!(
            status.sentence(),
            "42% of 380 MB. Protection can start when it has finished."
        );
        assert_eq!(
            status.tooltip(),
            "piikey: downloading the detection model, 42%"
        );
        assert_eq!(status.chip(), "Downloading model\u{2026}");
        assert_eq!(status.icon(), TrayIcon::Off);
        assert_eq!(status.tone(), Tone::Busy);
        assert!(matches!(status.action(), Action::Unavailable(Some(_))));

        // An empty total is an unknown one: no division by zero, no percentage made up.
        snap.model = Model::Downloading { done: 0, total: 0 };
        let unknown = Status::of(&snap, None);
        assert_eq!(
            unknown.sentence(),
            "Protection can start when it has finished."
        );
        assert!(unknown.tooltip().ends_with("0%"));
        Ok(())
    }

    #[test]
    fn a_failed_download_needs_attention_and_offers_to_try_again() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.model = Model::Failed("no network".to_owned());
        let status = Status::of(&snap, None);
        assert_eq!(
            status,
            Status::NeedsAttention {
                running: false,
                cause: Cause::ModelFailed("no network".to_owned())
            }
        );
        assert_eq!(
            status.sentence(),
            "The detection model could not be downloaded."
        );
        let cause = status.problem();
        assert_eq!(
            cause.as_ref().map(Cause::explanation).as_deref(),
            Some("no network")
        );
        assert_eq!(
            cause.and_then(|cause| cause.fix()).map(Fix::label),
            Some("Try again")
        );
        assert!(matches!(status.action(), Action::Unavailable(Some(_))));
        // A download that failed while protection runs (patterns only) leaves it running, and the
        // switch can still turn it off.
        snap.enabled = true;
        let running = Status::of(&snap, None);
        assert_eq!(running.title(), "Protection is on, but needs attention");
        assert_eq!(running.action(), Action::TurnOff);
        snap.enabled = false;
        // Skipping the model is the user's choice: protection still works with patterns.
        snap.model = Model::Skipped;
        assert!(matches!(Status::of(&snap, None), Status::Off { .. }));
        Ok(())
    }

    #[test]
    fn the_tooltip_always_fits_what_windows_shows() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        snap.notice = Some(Notice::error("x".repeat(400)));
        snap.enabled = true;
        let tooltip = Status::of(&snap, None).tooltip();
        assert!(tooltip.encode_utf16().count() <= 127, "{tooltip}");
        assert!(
            tooltip.ends_with('\u{2026}') || tooltip.ends_with('.'),
            "{tooltip}"
        );
        assert_eq!(clip("short", 80), "short");
        assert_eq!(clip("abcdef", 4), "abc\u{2026}");
        // A character of two units is never cut in half, a break or a null never gets through.
        assert_eq!(clip("a\u{1F511}\u{1F511}b", 4), "a\u{1F511}\u{2026}");
        assert_eq!(clip("one\r\ntwo\0", 80), "one  two ");
        let emoji = Status::NeedsAttention {
            running: true,
            cause: Cause::Error("\u{1F511}".repeat(200)),
        };
        assert!(emoji.tooltip().encode_utf16().count() <= 127);
        Ok(())
    }

    #[test]
    fn every_state_tells_itself_apart_by_words_glyph_and_icon() -> Test {
        let dir = TempDir::new()?;
        let (_controller, mut snap) = quiet(&dir)?;
        let mut all = vec![Status::of(&snap, None)];
        snap.enabled = true;
        all.push(Status::of(&snap, None));
        snap.cert = Cert::Missing;
        all.push(Status::of(&snap, None));
        snap.cert = Cert::Installed;
        snap.busy = Some(Busy::Starting);
        all.push(Status::of(&snap, None));
        snap.busy = None;
        snap.model = Model::Downloading { done: 1, total: 2 };
        all.push(Status::of(&snap, None));
        for status in &all {
            assert!(!status.sentence().is_empty(), "{status:?}");
            assert!(status.tooltip().starts_with("piikey: "), "{status:?}");
            assert!(status.tooltip().encode_utf16().count() <= 127, "{status:?}");
        }
        // Off, on, attention, busy and downloading: five states, five titles, five chips.
        let titles: Vec<&str> = all.iter().map(Status::title).collect();
        let chips: Vec<&str> = all.iter().map(Status::chip).collect();
        for mut words in [titles, chips] {
            words.sort_unstable();
            words.dedup();
            assert_eq!(words.len(), all.len());
        }
        // The glyph tells off, on and attention apart too; colour never carries it alone.
        let glyphs: Vec<&str> = all[..3].iter().map(Status::glyph).collect();
        assert!(glyphs[0] != glyphs[1] && glyphs[1] != glyphs[2] && glyphs[0] != glyphs[2]);
        Ok(())
    }
}
