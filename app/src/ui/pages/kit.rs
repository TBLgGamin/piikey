//! The widgets every page is made of: the type styles, the card, the row, the section, the page
//! column and the status colours. A row on Overview, on Protection and in Settings is the same
//! widget, so the pages cannot drift apart.
//!
//! Colours come from the theme. The reactor offers no app-wide accent, so interactive controls
//! follow the accent the user chose in Windows, and nothing here competes with it. The brand purple
//! is for the logo and the icons of folders and files; the dashboards colour by type of personal
//! data. Status is a glyph and words first, and a colour second.

use piikey::{detect::EntityKind, sources::Provider};
use windows_reactor::{
    Border, Brush, Button, ButtonStyle, Callback, Color, DateTime, FontIcon, FontWeight, Grid,
    GridLength, HorizontalAlignment, HyperlinkButton, Image, InfoBar, InfoBarSeverity, Orientation,
    ProgressRing, ScrollViewer, StackPanel, Stretch, TextBlock, TextWrapping, ThemeBrush,
    Thickness, ToggleSwitch, VerticalAlignment, View, ViewContext,
};

use crate::ui::{
    activity, assets,
    controller::{Busy, Model, NoticeAction, Severity, Snapshot},
    status::{Cause, Fix, Status, Tone},
    window::{MainWindow, Msg, Page},
};

/// What a page's builder is given to make callbacks with.
pub(super) type Context<'a> = &'a ViewContext<'a, MainWindow>;

/// The widest the content column grows, in DIPs; wider windows leave the rest empty.
pub(super) const COLUMN: f64 = 1000.0;
/// The widest a line of explanation runs, in DIPs: about sixty characters of caption.
pub(super) const MEASURE: f64 = 560.0;
/// Space between the sections of a page.
const SECTIONS: f64 = 28.0;
/// Space between the parts of a dashboard page.
const DASHBOARD_GAP: f64 = 12.0;
/// Space between a section's header and its first row.
const HEADER_GAP: f64 = 8.0;
/// Space between the rows of a section.
const ROW_GAP: f64 = 4.0;
/// The least a row is high: the Windows settings card.
pub(super) const ROW_HEIGHT: f64 = 68.0;
/// What a card keeps clear around its content.
const PAD: f64 = 16.0;
/// How far `ButtonStyle::Subtle` pads the content of a button, which a clickable row takes back so
/// its content sits where the content of a plain row does.
const BUTTON_PAD: (f64, f64, f64) = (8.0, 5.0, 6.0);

// ---- Type ----

/// A page title: Title, 28 semibold. Like every text style here, it can be selected and copied;
/// text inside a button must turn that off, or the text takes the button's clicks.
pub(super) fn title(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(28.0)
        .font_weight(FontWeight::SEMI_BOLD)
        .is_text_selection_enabled(true)
}

/// The line that says what is on: Subtitle, 20 semibold.
pub(super) fn subtitle(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(20.0)
        .font_weight(FontWeight::SEMI_BOLD)
        .text_wrapping(TextWrapping::Wrap)
        .is_text_selection_enabled(true)
}

/// A section header: Body Strong, 14 semibold.
pub(super) fn heading(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(14.0)
        .font_weight(FontWeight::SEMI_BOLD)
        .is_text_selection_enabled(true)
}

/// Running text: Body, 14.
pub(super) fn body(text: impl AsRef<str>) -> TextBlock {
    TextBlock::new()
        .text(text)
        .text_wrapping(TextWrapping::Wrap)
        .is_text_selection_enabled(true)
}

/// Secondary text: Caption, 12, the theme's text colour dimmed.
pub(super) fn caption(text: impl AsRef<str>) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(12.0)
        .text_wrapping(TextWrapping::Wrap)
        .opacity(0.72)
        .is_text_selection_enabled(true)
}

// ---- Colour and glyphs ----

/// Windows' success colour (`SystemFillColorSuccess`), for the shield of a protection that runs.
const fn success(dark: bool) -> Color {
    if dark {
        Color::rgb(0x6c, 0xcb, 0x5f)
    } else {
        Color::rgb(0x0f, 0x7b, 0x0f)
    }
}

/// Windows' caution colour (`SystemFillColorCaution`), for a status that needs the user.
const fn caution(dark: bool) -> Color {
    if dark {
        Color::rgb(0xfc, 0xe1, 0x00)
    } else {
        Color::rgb(0x9d, 0x5d, 0x00)
    }
}

/// The brush of a status glyph. The theme has no success or caution brush, so those two are
/// Windows' own values for the current theme.
pub(super) fn tone_brush(tone: Tone, dark: bool) -> Brush {
    match tone {
        Tone::Neutral => Brush::Theme(ThemeBrush::PrimaryText),
        Tone::Good => Brush::Solid(success(dark)),
        Tone::Caution => Brush::Solid(caution(dark)),
        Tone::Busy => Brush::Theme(ThemeBrush::AccentText),
    }
}

/// A Segoe Fluent Icons glyph in the theme's text colour.
pub(super) fn glyph(code: &str, size: f64) -> FontIcon {
    FontIcon::new()
        .glyph(code)
        .font_size(size)
        .foreground(ThemeBrush::PrimaryText)
}

/// A Segoe Fluent Icons glyph for `kind`. Types of one group share a glyph.
pub(super) const fn kind_glyph(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Email
        | EntityKind::PhoneNumber
        | EntityKind::ContactHandle
        | EntityKind::PostalAddress => "\u{E715}",
        EntityKind::Phone => "\u{E717}",
        EntityKind::Person
        | EntityKind::PersonAlias
        | EntityKind::PersonIdentifier
        | EntityKind::PersonAttribute
        | EntityKind::PersonRole
        | EntityKind::DateOfBirth => "\u{E77B}",
        EntityKind::Iban
        | EntityKind::CreditCard
        | EntityKind::BankAccount
        | EntityKind::PaymentCard
        | EntityKind::CardSecurity
        | EntityKind::FinancialAmount => "\u{E8C7}",
        EntityKind::NlBsn
        | EntityKind::UsSsn
        | EntityKind::DocumentId
        | EntityKind::DocumentReference
        | EntityKind::VehicleId => "\u{E779}",
        EntityKind::Ipv4
        | EntityKind::Ipv6
        | EntityKind::Mac
        | EntityKind::DeviceId
        | EntityKind::IdentifyingLink
        | EntityKind::AccountId => "\u{E968}",
        EntityKind::Secret | EntityKind::AuthSecret => "\u{E72E}",
        EntityKind::UrlCredential => "\u{E71B}",
        EntityKind::Location | EntityKind::GeoLocation => "\u{E707}",
        EntityKind::OrganizationName | EntityKind::OrganizationId | EntityKind::ProperName => {
            "\u{E821}"
        }
        EntityKind::HealthData
        | EntityKind::BiometricData
        | EntityKind::EthnicOrigin
        | EntityKind::PoliticalOpinion
        | EntityKind::ReligionOrBelief
        | EntityKind::SexualOrientation
        | EntityKind::TradeUnion
        | EntityKind::CriminalOffence => "\u{E8D7}",
    }
}

/// A status glyph: coloured by its tone, and dimmed when the tone is none at all.
pub(super) fn toned_glyph(code: &str, size: f64, tone: Tone, dark: bool) -> FontIcon {
    let icon = FontIcon::new()
        .glyph(code)
        .font_size(size)
        .foreground(tone_brush(tone, dark));
    if tone == Tone::Neutral {
        icon.opacity(0.72)
    } else {
        icon
    }
}

/// The brand colour for the theme, as the logo kit gives it: purple `#6f49b1` on light, lilac
/// `#d6c9f9` on dark.
pub(super) const fn brand(dark: bool) -> Color {
    if dark {
        Color::rgb(0xd6, 0xc9, 0xf9)
    } else {
        Color::rgb(0x6f, 0x49, 0xb1)
    }
}

/// The icon of a folder (`is_dir`) or a file, in the brand colour.
pub(super) fn place_glyph(is_dir: bool, size: f64, dark: bool) -> FontIcon {
    FontIcon::new()
        .glyph(if is_dir { "\u{E8B7}" } else { "\u{E7C3}" })
        .font_size(size)
        .foreground(Brush::Solid(brand(dark)))
}

/// The logo of a cloud provider, `size` px square, kept as the provider ships it (never
/// recoloured, never stretched). `label` is the account's name when the icon stands for one: the
/// pretend account of a debug build gets the cloud glyph in the brand colour instead (see
/// [`assets::shows_logo`]). The provider's name is always written beside the icon.
pub(super) fn provider_icon(
    provider: Provider,
    label: Option<&str>,
    size: f64,
    dark: bool,
) -> View {
    if label.is_some_and(|label| !assets::shows_logo(provider, label)) {
        return FontIcon::new()
            .glyph(assets::CLOUD_GLYPH)
            .font_size(size * 0.9)
            .foreground(Brush::Solid(brand(dark)))
            .into();
    }
    Image::new()
        .source_svg(assets::provider_logo(provider, dark))
        .stretch(Stretch::Uniform)
        .width(size)
        .height(size)
        .into()
}

// ---- Containers ----

/// A card: the card colour, a one pixel stroke, rounded corners, room around the content.
pub(super) fn card(content: impl Into<View>) -> Border {
    shell(PAD).content(content)
}

/// The card's Border, with `padding` around what goes in.
fn shell(padding: f64) -> Border {
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .padding(padding)
}

/// A page: its sections in a column that scrolls, at most [`COLUMN`] wide and against the left
/// edge, with room for the scroll bar on the right.
pub(super) fn column(children: Vec<View>) -> View {
    ScrollViewer::new()
        .content(
            Grid::new()
                .columns([GridLength::STAR.max(COLUMN)])
                .margin(Thickness::new(0.0, 0.0, 16.0, 0.0))
                .children((StackPanel::new().spacing(SECTIONS).children(children),)),
        )
        .into()
}

/// A page that uses the whole width, for the dashboards: its sections in a column that scrolls
/// when the window is too small for them, with room for the scroll bar on the right.
pub(super) fn wide_column(children: Vec<View>) -> View {
    ScrollViewer::new()
        .content(
            StackPanel::new()
                .spacing(DASHBOARD_GAP)
                .margin(Thickness::new(0.0, 0.0, 16.0, 0.0))
                .children(children),
        )
        .into()
}

/// Keeps one child within [`COLUMN`], against the left edge: for what sits outside a scroller.
pub(super) fn measured(child: impl Into<View>) -> View {
    Grid::new()
        .columns([GridLength::STAR.max(COLUMN)])
        .children((child.into(),))
        .into()
}

/// A page's top: the title and what the page is in one sentence, and on the right the control that
/// switches its feature, when it has one.
pub(super) fn page_header(
    page: &str,
    definition: &str,
    control: impl IntoIterator<Item = View>,
) -> View {
    let controls: Vec<View> = control.into_iter().collect();
    Grid::new()
        .columns([GridLength::STAR, GridLength::Auto])
        .column_spacing(16.0)
        .children((
            StackPanel::new().spacing(4.0).children((
                title(page),
                caption(definition)
                    .max_width(MEASURE)
                    .horizontal_alignment(HorizontalAlignment::Left),
            )),
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .spacing(8.0)
                .grid_column(1)
                .vertical_alignment(VerticalAlignment::Top)
                .margin(Thickness::new(0.0, 6.0, 0.0, 0.0))
                .children(controls),
        ))
        .into()
}

/// A group of rows under a header: 8 below the header, 4 between the rows.
pub(super) fn section(header: &str, rows: Vec<View>) -> View {
    section_with(header, Vec::new(), rows)
}

/// [`section`] with buttons on the right of its header.
pub(super) fn section_with(header: &str, actions: Vec<View>, rows: Vec<View>) -> View {
    let top: View = if actions.is_empty() {
        heading(header).into()
    } else {
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .column_spacing(12.0)
            .children((
                heading(header).vertical_alignment(VerticalAlignment::Center),
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(8.0)
                    .grid_column(1)
                    .children(actions),
            ))
            .into()
    };
    StackPanel::new()
        .spacing(HEADER_GAP)
        .children((top, StackPanel::new().spacing(ROW_GAP).children(rows)))
        .into()
}

// ---- The row ----

/// One row of a page: an icon, a title and what it says, and on the right a state, a control or a
/// way on. The settings card of Windows, built once so every page speaks the same way.
///
/// A row with a click is one button over the whole card, with a chevron; a row with a control is
/// not, so a switch is never nested in a button.
#[derive(Debug)]
pub(super) struct Row {
    lead: Option<Lead>,
    title: String,
    description: Option<String>,
    state: Option<String>,
    control: Option<View>,
    click: Option<Callback<()>>,
}

/// What stands in front of a row's title.
#[derive(Debug)]
enum Lead {
    /// A Segoe Fluent Icons glyph.
    Glyph(&'static str),
    /// Any view: a provider's logo.
    View(View),
}

impl Row {
    pub(super) fn new(title: impl Into<String>) -> Self {
        Self {
            lead: None,
            title: title.into(),
            description: None,
            state: None,
            control: None,
            click: None,
        }
    }

    /// A Segoe Fluent Icons glyph, 20 px, in front of the title.
    pub(super) fn icon(mut self, glyph: &'static str) -> Self {
        self.lead = Some(Lead::Glyph(glyph));
        self
    }

    /// A view in front of the title instead of an icon: the logo of a provider, about 24 px.
    pub(super) fn logo(mut self, logo: impl Into<View>) -> Self {
        self.lead = Some(Lead::View(logo.into()));
        self
    }

    /// What the row is about, in Caption under the title.
    pub(super) fn description(mut self, text: impl Into<String>) -> Self {
        self.description = Some(text.into());
        self
    }

    /// The row's own state, as words on the right.
    pub(super) fn state(mut self, text: impl Into<String>) -> Self {
        self.state = Some(text.into());
        self
    }

    /// A control on the right: a switch, a combo box, buttons.
    pub(super) fn control(mut self, control: impl Into<View>) -> Self {
        self.control = Some(control.into());
        self
    }

    /// Makes the whole row a button that sends `callback`, with a chevron on the right.
    pub(super) fn on_click(mut self, callback: Callback<()>) -> Self {
        self.click = Some(callback);
        self
    }

    /// The row as a view. The texts of a row that is no button can be selected and copied.
    pub(super) fn build(self) -> View {
        let Self {
            lead,
            title,
            description,
            state,
            control,
            click,
        } = self;
        let layout = row_layout(
            lead,
            row_texts(&title, description, click.is_none()),
            row_trailing(state, control, click.is_some()),
        );
        match click {
            None => card(layout.vertical_alignment(VerticalAlignment::Center))
                .min_height(ROW_HEIGHT)
                .into(),
            Some(callback) => shell(0.0)
                .min_height(ROW_HEIGHT)
                .content(
                    Button::new()
                        .style(ButtonStyle::Subtle)
                        .horizontal_alignment(HorizontalAlignment::Stretch)
                        .vertical_alignment(VerticalAlignment::Stretch)
                        .horizontal_content_alignment(HorizontalAlignment::Stretch)
                        .vertical_content_alignment(VerticalAlignment::Center)
                        .min_height(ROW_HEIGHT - 2.0)
                        // No `ControlCornerRadius` override: on a Subtle button it makes WinUI fail
                        // fast at startup (stowed exception 0xC000027B); the default radius stays.
                        .automation_name(&title)
                        .on_click(callback)
                        .content(layout.margin(Thickness::new(
                            PAD - BUTTON_PAD.0,
                            PAD - BUTTON_PAD.1,
                            PAD - BUTTON_PAD.0,
                            PAD - BUTTON_PAD.2,
                        ))),
                )
                .into(),
        }
    }
}

/// The title of a row, and under it what it says; `selectable` when the row is no button.
fn row_texts(title: &str, description: Option<String>, selectable: bool) -> Vec<View> {
    let mut texts: Vec<View> = vec![
        TextBlock::new()
            .text(title)
            .text_wrapping(TextWrapping::Wrap)
            .is_text_selection_enabled(selectable)
            .into(),
    ];
    texts.extend(
        description.map(|text| View::from(caption(text).is_text_selection_enabled(selectable))),
    );
    texts
}

/// What stands on the right of a row: its state in words, its control, and the chevron of a row
/// that is a button.
fn row_trailing(state: Option<String>, control: Option<View>, chevron: bool) -> Vec<View> {
    let mut right: Vec<View> = Vec::new();
    right.extend(state.map(|text| {
        View::from(
            TextBlock::new()
                .text(text)
                .text_wrapping(TextWrapping::Wrap)
                .opacity(0.72)
                .vertical_alignment(VerticalAlignment::Center),
        )
    }));
    right.extend(control);
    if chevron {
        right.push(
            glyph("\u{E76C}", 12.0)
                .opacity(0.72)
                .vertical_alignment(VerticalAlignment::Center)
                .into(),
        );
    }
    right
}

/// The grid of a row: its lead, its texts and what stands on the right.
fn row_layout(lead: Option<Lead>, texts: Vec<View>, right: Vec<View>) -> Grid {
    let mut cells: Vec<View> = Vec::new();
    let mut columns: Vec<GridLength> = Vec::new();
    if let Some(lead) = lead {
        columns.push(GridLength::Auto);
        let gap = Thickness::new(0.0, 0.0, 16.0, 0.0);
        cells.push(match lead {
            Lead::Glyph(code) => glyph(code, 20.0)
                .grid_column(0)
                .vertical_alignment(VerticalAlignment::Center)
                .margin(gap)
                .into(),
            Lead::View(view) => StackPanel::new()
                .grid_column(0)
                .vertical_alignment(VerticalAlignment::Center)
                .margin(gap)
                .children([view])
                .into(),
        });
    }
    let text_column = i32::try_from(columns.len()).unwrap_or(0);
    columns.push(GridLength::STAR);
    cells.push(
        StackPanel::new()
            .spacing(2.0)
            .grid_column(text_column)
            .vertical_alignment(VerticalAlignment::Center)
            .children(texts)
            .into(),
    );
    if !right.is_empty() {
        columns.push(GridLength::Auto);
        cells.push(
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .spacing(12.0)
                .grid_column(text_column + 1)
                .vertical_alignment(VerticalAlignment::Center)
                .margin(Thickness::new(16.0, 0.0, 0.0, 0.0))
                .children(right)
                .into(),
        );
    }
    Grid::new().columns(columns).children(cells)
}

// ---- Messages and controls ----

/// A message bar that stays open and has no close button.
pub(super) fn info(title: &str, message: impl AsRef<str>, severity: InfoBarSeverity) -> InfoBar {
    InfoBar::new()
        .title(title)
        .message(message)
        .severity(severity)
        .is_open(true)
        .is_closable(false)
}

/// A message bar with a close button, which sends `closed`.
pub(super) fn dismissible(
    title: &str,
    message: impl AsRef<str>,
    severity: InfoBarSeverity,
    closed: Msg,
    context: Context<'_>,
) -> View {
    info(title, message, severity)
        .is_closable(true)
        .on_closed(context.message(closed))
        .into()
}

/// What the controller wants the user to read: a warning or an error, until closed, with the
/// button that does what it asks for under it when it has one.
pub(super) fn notice(snap: &Snapshot, context: Context<'_>) -> Option<View> {
    let notice = snap.notice.as_ref()?;
    let (title, severity) = match notice.severity {
        Severity::Warning => ("Heads up", InfoBarSeverity::Warning),
        Severity::Error => ("Something went wrong", InfoBarSeverity::Error),
    };
    let bar = dismissible(title, &notice.text, severity, Msg::DismissNotice, context);
    Some(match &notice.action {
        None => bar,
        Some(action) => {
            let label = match action {
                NoticeAction::SignIn { account, provider } => {
                    let name = snap
                        .accounts
                        .iter()
                        .find(|view| view.account.id == *account)
                        .map_or(provider.name(), |view| assets::provider_name(&view.account));
                    format!("Sign in to {name}")
                }
            };
            let button = Button::new()
                .content(label)
                .style(ButtonStyle::Accent)
                .on_click(context.message(Msg::NoticeButton(action.clone())));
            StackPanel::new()
                .spacing(8.0)
                .children((bar, button))
                .into()
        }
    })
}

/// Why the last "Add" was refused, closable; nothing when it was not.
pub(super) fn form_error(window: &MainWindow, context: Context<'_>) -> Option<View> {
    window.form_error.as_ref().map(|error| {
        dismissible(
            "Not added",
            error,
            InfoBarSeverity::Warning,
            Msg::DismissForm,
            context,
        )
    })
}

/// The one cause that needs the user, as a message bar with the button that fixes it under it: one
/// cause, one fix. A cause without a button (an error) is the message bar alone, which closes.
pub(super) fn attention(window: &MainWindow, cause: &Cause, context: Context<'_>) -> View {
    let severity = match cause {
        Cause::CertificateMissing => InfoBarSeverity::Warning,
        Cause::ModelFailed(_) | Cause::Error(_) => InfoBarSeverity::Error,
    };
    let mut parts: Vec<View> = Vec::new();
    match cause {
        Cause::Error(text) => parts.push(dismissible(
            cause.title(),
            text,
            severity,
            Msg::DismissNotice,
            context,
        )),
        _ => parts.push(info(cause.title(), cause.explanation(), severity).into()),
    }
    if let Some(fix) = cause.fix() {
        let message = match fix {
            Fix::InstallCertificate => Msg::InstallCertificate,
            Fix::RetryModel => Msg::RetryModel,
        };
        parts.push(
            Button::new()
                .content(fix.label())
                .style(ButtonStyle::Accent)
                .is_enabled(fix_available(window, fix))
                .on_click(context.message(message))
                .into(),
        );
    }
    StackPanel::new().spacing(8.0).children(parts).into()
}

/// Whether the button of `fix` can be pressed. Only the work the button starts holds it still: a
/// scan, or the model loading in the background, can take a long time and has nothing to do with
/// the fix, so it never disables it.
fn fix_available(window: &MainWindow, fix: Fix) -> bool {
    match fix {
        Fix::InstallCertificate => {
            !window.asked.certificate && window.snap.busy != Some(Busy::InstallingCertificate)
        }
        Fix::RetryModel => !matches!(window.snap.model, Model::Downloading { .. }),
    }
}

/// The switch of a feature of the settings; `to_message` turns the new state into the message.
pub(super) fn feature_switch(
    name: &str,
    on: bool,
    to_message: impl Fn(bool) -> Msg + 'static,
    context: Context<'_>,
) -> ToggleSwitch {
    ToggleSwitch::new()
        .is_on(on)
        .on_content("On")
        .off_content("Off")
        .automation_name(name)
        .on_toggled(context.callback(to_message))
}

/// A link to a web address; when the address is not one Windows takes, the words alone.
pub(super) fn web_link(text: &str, url: &str) -> View {
    match HyperlinkButton::new().content(text).navigate_uri(url) {
        Ok(link) => link.into(),
        Err(_) => body(text).into(),
    }
}

/// The status's glyph with a ring in its place while the controller works: the lead of the hero and
/// of the chip, `size` px.
pub(super) fn status_glyph(status: &Status, size: f64, dark: bool) -> View {
    if status.is_busy() {
        ProgressRing::new()
            .is_active(true)
            .width(size)
            .height(size)
            .into()
    } else {
        toned_glyph(status.glyph(), size, status.tone(), dark).into()
    }
}

/// The line under the navigation pane: the status in a glyph and a few words. A button, so it takes
/// the user to Overview, where the status says the rest.
pub(in crate::ui) fn status_chip(
    window: &MainWindow,
    status: &Status,
    context: Context<'_>,
) -> View {
    Button::new()
        .style(ButtonStyle::Subtle)
        .horizontal_alignment(HorizontalAlignment::Stretch)
        .horizontal_content_alignment(HorizontalAlignment::Left)
        .margin(Thickness::new(8.0, 0.0, 8.0, 8.0))
        .automation_name(status.chip())
        .on_click(context.message(Msg::Nav(Page::Overview)))
        .content(
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .spacing(10.0)
                .children((
                    status_glyph(status, 16.0, window.dark),
                    TextBlock::new()
                        .text(status.chip())
                        .vertical_alignment(VerticalAlignment::Center),
                )),
        )
        .into()
}

// ---- Numbers and times ----

/// A time, in seconds since the Unix epoch, as the vault's list tells times: `14:05`,
/// `yesterday 14:05`, `Mon 14:05`, `12 Oct`.
pub(super) fn when(unix: u64) -> String {
    let secs = i64::try_from(unix).unwrap_or(i64::MAX);
    let local = DateTime::from_unix_secs(secs).to_local().ticks();
    activity::when(local, activity::now())
}

/// `12,345`.
pub(super) fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `1 file`, `2 files`.
pub(super) fn counted(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", thousands(n), if n == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn counts_take_the_plural_that_fits() {
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(0, "file", "files"), "0 files");
        assert_eq!(counted(1_500, "value", "values"), "1,500 values");
    }

    #[test]
    fn status_colours_are_the_windows_ones_for_the_theme() {
        assert_eq!(success(false), Color::rgb(0x0f, 0x7b, 0x0f));
        assert_eq!(success(true), Color::rgb(0x6c, 0xcb, 0x5f));
        assert_eq!(caution(false), Color::rgb(0x9d, 0x5d, 0x00));
        assert_eq!(caution(true), Color::rgb(0xfc, 0xe1, 0x00));
        assert_eq!(
            tone_brush(Tone::Good, false),
            Brush::Solid(Color::rgb(0x0f, 0x7b, 0x0f))
        );
        assert_eq!(
            tone_brush(Tone::Neutral, true),
            Brush::Theme(ThemeBrush::PrimaryText)
        );
    }
}
