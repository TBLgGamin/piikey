//! The three pages of the window: Home, Keyed values and Settings.
//!
//! Text, cards, lists and controls take their colours from the theme, so they follow light or dark
//! mode and the accent colour. Only the brand parts use the piikey colours: the logo and the kind
//! icons, purple `#6f49b1` in light mode and lilac `#d6c9f9` in dark mode, as the logo kit
//! (`assets/brand/piikey-logo-kit`) prescribes. The treemap of the inventory on Home colours its
//! tiles by the group of the kind found most, the same in both themes, under white text.

use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use piikey::{
    detect::{EntityKind, KIND_GROUPS},
    inventory::{Entry, MAX_FILE, Node, Status},
    policy::{Highlight, PRESETS},
    service::default_pipe,
};
use windows_reactor::{
    Border, Button, ButtonStyle, Callback, Canvas, CheckBox, Color, ComboBox, CornerRadius,
    DataItem, DateTime, Expander, FontIcon, FontWeight, Grid, GridLength, HorizontalAlignment,
    HyperlinkButton, Image, InfoBar, InfoBarSeverity, KeyedView, ListView, ListViewSelectionMode,
    Orientation, ProgressBar, ProgressRing, ResourceOverrides, RichText, RichTextBlock,
    RichTextInline, RichTextRun, ScrollBarVisibility, ScrollViewer, SelectorBar, SelectorBarItem,
    StackPanel, Stretch, TextBlock, TextBox, TextTrimming, TextWrapping, ThemeBrush, Thickness,
    ToggleSwitch, TooltipExt, VerticalAlignment, View, ViewContext, Viewbox,
};

use super::{
    activity, assets,
    controller::{Busy, Cert, InventoryView, Keyed, Model, Period, RECENT, Severity, Snapshot},
    treemap::{Rect, squarify},
    window::{KEYED_LIMIT, MainWindow, Msg, Page, Selection, SettingsTab},
};
use crate::proxy::PORT;

/// Height of one list row in DIPs.
const ROW: f64 = 40.0;
/// Height of a keyed value row: value over proxy.
const KEYED_ROW: f64 = 56.0;

type Context<'a> = &'a ViewContext<'a, MainWindow>;

/// The page the navigation selected, under the notice the controller may have raised.
pub fn page(window: &MainWindow, context: Context<'_>) -> View {
    let body = match window.page {
        Page::Home => home(window, context),
        Page::Keyed => keyed(window, context),
        Page::Settings => settings(window, context),
    };
    let notices: Vec<View> = notice(&window.snap, context).into_iter().collect();
    Grid::new()
        .rows([GridLength::Auto, GridLength::STAR])
        .margin(Thickness::new(24.0, 8.0, 24.0, 16.0))
        .row_spacing(12.0)
        .children((
            StackPanel::new().grid_row(0).children(notices),
            Border::new().grid_row(1).content(body),
        ))
        .into()
}

/// The brand colour for the theme.
const fn brand(dark: bool) -> Color {
    if dark {
        Color::rgb(0xd6, 0xc9, 0xf9)
    } else {
        Color::rgb(0x6f, 0x49, 0xb1)
    }
}

fn title(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(28.0)
        .font_weight(FontWeight::SEMI_BOLD)
}

fn heading(text: &str) -> TextBlock {
    TextBlock::new()
        .text(text)
        .font_size(18.0)
        .font_weight(FontWeight::SEMI_BOLD)
}

/// Secondary text: the theme's text color, dimmed.
fn caption(text: impl AsRef<str>) -> TextBlock {
    TextBlock::new()
        .text(text)
        .text_wrapping(TextWrapping::Wrap)
        .opacity(0.72)
}

fn card(content: impl Into<View>) -> Border {
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(1.0)
        .corner_radius(8.0)
        .padding(16.0)
        .content(content)
}

/// A scrolling column of sections, with room for the scroll bar.
fn column(children: Vec<View>) -> View {
    ScrollViewer::new()
        .content(
            StackPanel::new()
                .spacing(12.0)
                .margin(Thickness::new(0.0, 0.0, 16.0, 0.0))
                .children(children),
        )
        .into()
}

fn info(title: &str, message: impl AsRef<str>, severity: InfoBarSeverity) -> InfoBar {
    InfoBar::new()
        .title(title)
        .message(message)
        .severity(severity)
        .is_open(true)
        .is_closable(false)
}

/// What the controller wants the user to read: a warning or an error, until closed.
fn notice(snap: &Snapshot, context: Context<'_>) -> Option<View> {
    let notice = snap.notice.as_ref()?;
    let (title, severity) = match notice.severity {
        Severity::Warning => ("Heads up", InfoBarSeverity::Warning),
        Severity::Error => ("Something went wrong", InfoBarSeverity::Error),
    };
    Some(
        InfoBar::new()
            .title(title)
            .message(&notice.text)
            .severity(severity)
            .is_open(true)
            .is_closable(true)
            .on_closed(context.message(Msg::DismissNotice))
            .into(),
    )
}

fn busy_text(busy: Busy) -> &'static str {
    match busy {
        Busy::Starting => "Starting piikey...",
        Busy::Stopping => "Stopping piikey...",
        Busy::InstallingCertificate => "Waiting for Windows to add the certificate...",
    }
}

/// `12,345`.
fn thousands(n: u64) -> String {
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

fn grid_index(i: usize) -> i32 {
    i32::try_from(i).unwrap_or(i32::MAX)
}

/// A Segoe Fluent Icons glyph for `kind`. Kinds of one group share a glyph.
const fn kind_glyph(kind: EntityKind) -> &'static str {
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

// ---- Home ----

fn home(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut children: Vec<View> = vec![brand_header(window.dark), switch_card(window, context)];
    if snap.cert != Cert::Installed {
        children.push(certificate(window, context));
    }
    children.push(numbers(snap));
    children.push(inventory_card(window, context));
    children.push(recent(window, context));
    column(children)
}

/// The logo lockup, which already reads "piikey".
fn brand_header(dark: bool) -> View {
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(12.0)
        .children((Image::new()
            .source_svg(assets::lockup(dark))
            .stretch(Stretch::Uniform)
            .height(36.0),))
        .into()
}

/// The controller is busy, or has commands it has not finished.
fn is_working(snap: &Snapshot) -> bool {
    snap.busy.is_some() || snap.pending > 0
}

/// The on/off switch of protection. It waits while the controller works, and stays off the
/// moment the certificate is missing.
fn protection_switch(window: &MainWindow, context: Context<'_>) -> ToggleSwitch {
    let snap = &window.snap;
    ToggleSwitch::new()
        .is_on(window.desired.unwrap_or(snap.enabled))
        .is_enabled(!is_working(snap) && snap.cert == Cert::Installed)
        .on_content("On")
        .off_content("Off")
        .on_toggled(context.callback(Msg::Toggle))
}

/// The on/off switch and what it means right now.
fn switch_card(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let on = window.desired.unwrap_or(snap.enabled);
    let protected = snap.policy.sites.len() + snap.policy.programs.len();
    let (state, summary) = match snap.busy {
        Some(busy) => ("Working", busy_text(busy).to_owned()),
        None if on => (
            "Protection is on",
            format!(
                "Personal data sent to your {protected} protected sites and programs is replaced by stand-ins, and put back in the answers."
            ),
        ),
        None => (
            "Protection is off",
            "Nothing is read or changed, and your Windows proxy settings are your own.".to_owned(),
        ),
    };
    let last = snap.last_activity.as_ref().map_or_else(
        || "No traffic yet this session.".to_owned(),
        |activity| format!("Last activity: {} at {}", activity.host, activity.at),
    );
    card(
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .column_spacing(16.0)
            .children((
                StackPanel::new().spacing(4.0).children((
                    heading(state),
                    caption(summary),
                    caption(last),
                )),
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(12.0)
                    .grid_column(1)
                    .vertical_alignment(VerticalAlignment::Center)
                    .children((
                        ProgressRing::new()
                            .is_active(is_working(snap))
                            .width(20.0)
                            .height(20.0),
                        protection_switch(window, context),
                    )),
            )),
    )
    .into()
}

/// One key number: big value over its label.
fn number(value: String, label: &str, column: usize) -> View {
    card(
        StackPanel::new().spacing(2.0).children((
            TextBlock::new()
                .text(value)
                .font_size(28.0)
                .font_weight(FontWeight::SEMI_BOLD),
            caption(label),
        )),
    )
    .grid_column(grid_index(column))
    .into()
}

fn numbers(snap: &Snapshot) -> View {
    let (files, found) = snap.inventory_totals;
    let protected = snap.policy.sites.len() + snap.policy.programs.len();
    Grid::new()
        .columns([GridLength::STAR; 4])
        .column_spacing(12.0)
        .children(vec![
            number(thousands(snap.issued), "values keyed, all time", 0),
            number(thousands(files), "files with personal data", 1),
            number(thousands(found), "personal data found in files", 2),
            number(
                thousands(u64::try_from(protected).unwrap_or(u64::MAX)),
                "sites and programs protected",
                3,
            ),
        ])
        .into()
}

// ---- Home: where the personal data is ----

/// Width and height of the treemap's canvas in its own units; the viewbox scales it to the card.
const MAP_W: f64 = 1000.0;
const MAP_H: f64 = 420.0;
/// Tiles that get a place of their own; the nodes after them share one "+N more" tile.
const MAX_TILES: usize = 60;
/// How far a tile keeps clear of its neighbours on each side.
const TILE_INSET: f64 = 2.0;
/// The plan's floor for a tile that carries its name and counts: this wide and this high, on the
/// canvas. [`shows_label`] asks for the room the two lines take as well, which is more.
const LABEL_MIN: (f64, f64) = (90.0, 40.0);
/// The font size of a tile's name grows with the tile, between these limits. The viewbox shrinks
/// the canvas to the card, mostly to between a third and two thirds, so the text is set big.
const NAME_SIZES: (f64, f64) = (22.0, 28.0);
/// The height of a line of text, in font sizes.
const LINE: f64 = 1.35;
/// What a button keeps clear of its text, above and below together.
const TILE_PADDING: f64 = 10.0;
/// Width of the side panel in DIPs.
const SIDE_WIDTH: f64 = 300.0;
/// Kinds the side panel lists.
const SIDE_KINDS: usize = 8;
/// Nodes the "+N more" list shows at most; it scrolls.
const MORE_ROWS: usize = 1000;
/// Rows of the "+N more" list that show without scrolling.
const MORE_VISIBLE: usize = 8;

/// Tile colours, one per group of [`KIND_GROUPS`], in the same order.
const GROUP_COLORS: [Color; 9] = [
    Color::rgb(0x6f, 0x49, 0xb1),
    Color::rgb(0x2f, 0x80, 0xc0),
    Color::rgb(0x2e, 0x9d, 0x6a),
    Color::rgb(0xc7, 0x7d, 0x1a),
    Color::rgb(0xc0, 0x39, 0x2b),
    Color::rgb(0x8e, 0x44, 0xad),
    Color::rgb(0x16, 0xa0, 0x85),
    Color::rgb(0x5d, 0x6d, 0x7e),
    Color::rgb(0xd3, 0x54, 0x00),
];
const _: () = assert!(GROUP_COLORS.len() == KIND_GROUPS.len());
/// The colour of the "+N more" tile, and of a tile with no kind to colour it by.
const NEUTRAL: Color = Color::rgb(0x4b, 0x55, 0x63);
const WHITE: Color = Color::rgb(0xff, 0xff, 0xff);
const BLACK: Color = Color::rgb(0x00, 0x00, 0x00);
/// Where a tile is before the layout has placed it.
const NO_RECT: Rect = Rect {
    x: 0.0,
    y: 0.0,
    w: 0.0,
    h: 0.0,
};

/// What a treemap tile stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TileOf {
    /// The node with this path (empty for "Other scans").
    Node(PathBuf),
    /// The nodes after the first [`MAX_TILES`], as one tile.
    More,
}

/// One tile of the treemap: where it lies on the canvas and what it says.
#[derive(Debug, Clone, PartialEq)]
struct Tile {
    of: TileOf,
    rect: Rect,
    color: Color,
    /// The name, or "+N more".
    title: String,
    /// "12 in 3 files".
    detail: String,
}

/// One step of the way from the top level to the folder on show.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Crumb {
    label: String,
    /// The folder it leads to; empty is the top level.
    target: PathBuf,
}

/// The buttons of the side panel, by what they act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Buttons {
    /// Nothing to act on.
    None,
    /// The top level: scan every watched folder again.
    All,
    /// A folder: show it, scan it again, leave it out.
    Folder,
    /// A file: open it, show it, scan it again, make a masked copy, leave it out.
    File,
}

/// What the side panel says and offers, apart from how it looks.
#[derive(Debug, PartialEq)]
struct Panel<'a> {
    /// The name of the folder or file, or "+N more".
    title: String,
    /// The full path, or where the numbers come from.
    detail: String,
    /// "12 values in 3 files", or why a file has none.
    summary: String,
    /// The kinds found most, at most [`SIDE_KINDS`], with how many of each.
    kinds: Vec<(EntityKind, u32)>,
    /// When the file was scanned, in seconds since the Unix epoch.
    scanned: Option<u64>,
    /// The file or folder the buttons act on.
    target: Option<&'a Path>,
    buttons: Buttons,
    /// The nodes of the "+N more" tile, listed in the panel.
    rest: &'a [Node],
}

/// A node's share of the treemap: the values found under it.
#[expect(
    clippy::cast_precision_loss,
    reason = "a tile's area needs no precision beyond 2^53 values"
)]
fn weight(hits: u64) -> f64 {
    hits as f64
}

/// `12 in 3 files`: what a tile says under its name.
fn tile_detail(hits: u64, files: u64) -> String {
    format!("{} in {}", thousands(hits), counted(files, "file", "files"))
}

/// `12 values in 3 files`.
fn found_text(hits: u64, files: u64) -> String {
    format!(
        "{} in {}",
        counted(hits, "value", "values"),
        counted(files, "file", "files")
    )
}

/// `1 file`, `2 files`.
fn counted(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", thousands(n), if n == 1 { one } else { many })
}

/// The values and the files of `nodes`, added up.
fn totals(nodes: &[Node]) -> (u64, u64) {
    nodes.iter().fold((0, 0), |(hits, files), node| {
        (hits + node.hits, files + u64::from(node.files))
    })
}

/// The kinds found most, at most [`SIDE_KINDS`], with how many of each; the counts of one kind
/// are added up.
fn top_kinds(counts: impl IntoIterator<Item = (EntityKind, u32)>) -> Vec<(EntityKind, u32)> {
    let mut per_kind: BTreeMap<EntityKind, u32> = BTreeMap::new();
    for (kind, n) in counts {
        let total = per_kind.entry(kind).or_default();
        *total = total.saturating_add(n);
    }
    let mut kinds: Vec<(EntityKind, u32)> = per_kind.into_iter().collect();
    // Stable: kinds with as many findings stay in the order of the kinds.
    kinds.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    kinds.truncate(SIDE_KINDS);
    kinds
}

/// The kind with most findings; the first of them when several tie.
fn dominant_kind(counts: &[(EntityKind, u32)]) -> Option<EntityKind> {
    // `max_by_key` keeps the last of equal maxima, so walk backwards to get the first.
    counts
        .iter()
        .rev()
        .max_by_key(|&&(_, n)| n)
        .map(|&(kind, _)| kind)
}

/// Where `kind` stands in [`KIND_GROUPS`].
fn group_index(kind: EntityKind) -> Option<usize> {
    KIND_GROUPS
        .iter()
        .position(|(_, kinds)| kinds.contains(&kind))
}

/// The colour of a tile whose files hold `counts`: that of the group of the kind found most.
fn kind_color(counts: &[(EntityKind, u32)]) -> Color {
    dominant_kind(counts)
        .and_then(group_index)
        .and_then(|group| GROUP_COLORS.get(group).copied())
        .unwrap_or(NEUTRAL)
}

/// `from`, `percent` of the way to `to`.
fn blend(from: Color, to: Color, percent: u16) -> Color {
    let percent = percent.min(100);
    let mix = |a: u8, b: u8| {
        let value = (u16::from(a) * (100 - percent) + u16::from(b) * percent) / 100;
        u8::try_from(value).unwrap_or(u8::MAX)
    };
    Color::rgb(mix(from.r, to.r), mix(from.g, to.g), mix(from.b, to.b))
}

/// The frame of the selected tile: what the text colour is in this theme.
const fn selection_ring(dark: bool) -> Color {
    if dark {
        WHITE
    } else {
        Color::rgb(0x20, 0x20, 0x20)
    }
}

/// `rect` pulled in by [`TILE_INSET`] on every side; less for a tile too small to spare it.
fn inset(rect: Rect) -> Rect {
    let by = TILE_INSET.min(rect.w / 4.0).min(rect.h / 4.0);
    Rect {
        x: rect.x + by,
        y: rect.y + by,
        w: rect.w - 2.0 * by,
        h: rect.h - 2.0 * by,
    }
}

/// The font sizes of a tile's name and its counts: they grow with the tile, within limits.
fn label_sizes(rect: &Rect) -> (f64, f64) {
    let name = (rect.w.min(rect.h) / 5.0).clamp(NAME_SIZES.0, NAME_SIZES.1);
    (name, name * 0.8)
}

/// Whether a tile has room for its name and counts: the plan's [`LABEL_MIN`], and the height of
/// the two lines at the sizes [`label_sizes`] picks.
fn shows_label(rect: &Rect) -> bool {
    let (name, counts) = label_sizes(rect);
    let lines = (name + counts) * LINE + TILE_PADDING;
    rect.w >= LABEL_MIN.0 && rect.h >= LABEL_MIN.1 && rect.h >= lines
}

fn node_tile(node: &Node) -> Tile {
    Tile {
        of: TileOf::Node(node.path.clone()),
        rect: NO_RECT,
        color: kind_color(&node.counts),
        title: node.name.clone(),
        detail: tile_detail(node.hits, u64::from(node.files)),
    }
}

/// The tile for the nodes that did not get one of their own.
fn more_tile(rest: &[Node]) -> Tile {
    let (hits, files) = totals(rest);
    Tile {
        of: TileOf::More,
        rect: NO_RECT,
        color: NEUTRAL,
        title: format!(
            "+{} more",
            thousands(u64::try_from(rest.len()).unwrap_or(u64::MAX))
        ),
        detail: tile_detail(hits, files),
    }
}

/// The treemap of `nodes`, the one with most values first: a tile for each of the first
/// [`MAX_TILES`] and one for all the others, sized by the values found and laid out on the canvas.
fn tiles(nodes: &[Node]) -> Vec<Tile> {
    let (head, others) = nodes.split_at(nodes.len().min(MAX_TILES));
    let mut items: Vec<(f64, Tile)> = head
        .iter()
        .map(|node| (weight(node.hits), node_tile(node)))
        .collect();
    if !others.is_empty() {
        let hits: u64 = others.iter().map(|node| node.hits).sum();
        items.push((weight(hits), more_tile(others)));
    }
    // The biggest first makes the squarest tiles; tiles of equal weight keep their order.
    items.sort_by(|a, b| b.0.total_cmp(&a.0));
    let weights: Vec<f64> = items.iter().map(|(w, _)| *w).collect();
    let area = Rect {
        x: 0.0,
        y: 0.0,
        w: MAP_W,
        h: MAP_H,
    };
    items
        .into_iter()
        .zip(squarify(&weights, area))
        .filter_map(|((_, tile), rect)| {
            let rect = inset(rect);
            (rect.w > 0.0 && rect.h > 0.0).then_some(Tile { rect, ..tile })
        })
        .collect()
}

/// Whether the side panel shows the tile standing for `of`.
fn is_selected(of: &TileOf, selected: Option<&Selection>) -> bool {
    match (of, selected) {
        (TileOf::Node(path), Some(Selection::Node(chosen))) => path == chosen,
        (TileOf::More, Some(Selection::More)) => true,
        _ => false,
    }
}

/// The last component of `path`: the name of a folder or a file; a drive keeps its whole path.
fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Whether `path` is `prefix` or lies below it. Windows paths are not case sensitive, and neither
/// is this.
fn is_under(path: &Path, prefix: &Path) -> bool {
    let mut path = path.components();
    prefix.components().all(|want| {
        path.next()
            .is_some_and(|have| have.as_os_str().eq_ignore_ascii_case(want.as_os_str()))
    })
}

/// The crumbs from "This PC" to `at`. Everything up to the deepest of the watched `roots` that
/// holds `at` is one crumb, named after that folder. Without such a folder every component is a
/// crumb, except that the drive and its root (`C:` and `\`) are one: `C:\`.
fn crumbs(at: &Path, roots: &[PathBuf]) -> Vec<Crumb> {
    let mut trail = vec![Crumb {
        label: "This PC".to_owned(),
        target: PathBuf::new(),
    }];
    let deepest = roots
        .iter()
        .filter(|root| is_under(at, root))
        .max_by_key(|root| root.components().count());
    let (mut path, skip) = if let Some(root) = deepest {
        (root.clone(), root.components().count())
    } else {
        let lead = at
            .components()
            .take_while(|part| matches!(part, Component::Prefix(_) | Component::RootDir));
        (lead.clone().collect::<PathBuf>(), lead.count())
    };
    if skip > 0 {
        trail.push(Crumb {
            label: name_of(&path),
            target: path.clone(),
        });
    }
    for part in at.components().skip(skip) {
        path.push(part.as_os_str());
        trail.push(Crumb {
            label: part.as_os_str().to_string_lossy().into_owned(),
            target: path.clone(),
        });
    }
    trail
}

/// What the scan of a file came to, as the side panel puts it.
fn entry_summary(entry: &Entry) -> String {
    match &entry.status {
        Status::Ok if entry.hits() == 0 => "No personal data found.".to_owned(),
        Status::Ok => found_text(entry.hits(), 1),
        Status::Unsupported => "piikey cannot read this kind of file.".to_owned(),
        Status::TooLarge => format!(
            "Too large to scan: piikey skips files over {} MB.",
            MAX_FILE >> 20
        ),
        Status::Failed(error) => format!("Could not be scanned: {error}"),
    }
}

/// The panel for the folder `at` itself (the top level when it is empty), when nothing is
/// selected. `watching` is whether the inventory keeps the watched folders scanned.
fn folder_panel<'a>(view: &InventoryView, at: &'a Path, watching: bool) -> Panel<'a> {
    let top = at.as_os_str().is_empty();
    let (hits, files) = totals(&view.nodes);
    let buttons = match (top, watching) {
        (false, _) => Buttons::Folder,
        (true, true) => Buttons::All,
        (true, false) => Buttons::None,
    };
    Panel {
        title: if top {
            "This PC".to_owned()
        } else {
            name_of(at)
        },
        detail: if top {
            "Every folder piikey watches, and what you scanned from Explorer.".to_owned()
        } else {
            at.display().to_string()
        },
        summary: found_text(hits, files),
        kinds: top_kinds(
            view.nodes
                .iter()
                .flat_map(|node| node.counts.iter().copied()),
        ),
        scanned: None,
        target: (!top).then_some(at),
        buttons,
        rest: &[],
    }
}

/// The panel for the nodes beyond the tiles: their numbers, and the nodes as a list.
fn rest_panel(rest: &[Node]) -> Panel<'_> {
    let (hits, files) = totals(rest);
    Panel {
        title: format!(
            "+{} more",
            thousands(u64::try_from(rest.len()).unwrap_or(u64::MAX))
        ),
        detail: "The smaller ones, the biggest first. Pick one to look at it.".to_owned(),
        summary: found_text(hits, files),
        kinds: top_kinds(rest.iter().flat_map(|node| node.counts.iter().copied())),
        scanned: None,
        target: None,
        buttons: Buttons::None,
        rest,
    }
}

/// The panel for the file or folder `chosen`: a tile of the view, or a file the scan found
/// nothing in, which has no tile but may have an entry.
fn chosen_panel<'a>(view: &'a InventoryView, chosen: &'a Path) -> Panel<'a> {
    let entry = view.entry.as_ref().filter(|entry| entry.path == chosen);
    let Some(node) = view.nodes.iter().find(|node| node.path == chosen) else {
        return Panel {
            title: name_of(chosen),
            detail: chosen.display().to_string(),
            summary: entry.map_or_else(|| "No scan of this file yet.".to_owned(), entry_summary),
            kinds: entry.map_or_else(Vec::new, |entry| top_kinds(entry.counts.iter().copied())),
            scanned: entry.map(|entry| entry.scanned),
            target: Some(chosen),
            buttons: Buttons::File,
            rest: &[],
        };
    };
    // The "Other scans" node gathers files from everywhere: its path is empty, and there is
    // nothing to open, show or scan.
    let other = node.path.as_os_str().is_empty();
    let buttons = match (other, node.is_dir) {
        (true, _) => Buttons::None,
        (false, true) => Buttons::Folder,
        (false, false) => Buttons::File,
    };
    Panel {
        title: node.name.clone(),
        detail: if other {
            "Scans of files outside the folders piikey watches.".to_owned()
        } else {
            node.path.display().to_string()
        },
        summary: found_text(node.hits, u64::from(node.files)),
        kinds: top_kinds(node.counts.iter().copied()),
        scanned: entry.map(|entry| entry.scanned),
        target: (!other).then_some(node.path.as_path()),
        buttons,
        rest: &[],
    }
}

/// What the side panel describes: what is `selected` among the tiles of `view`, or the folder
/// `at` itself.
fn panel<'a>(
    view: &'a InventoryView,
    at: &'a Path,
    selected: Option<&'a Selection>,
    watching: bool,
) -> Panel<'a> {
    match selected {
        Some(Selection::Node(chosen)) => chosen_panel(view, chosen),
        Some(Selection::More) => view
            .nodes
            .get(MAX_TILES..)
            .filter(|rest| !rest.is_empty())
            .map_or_else(|| folder_panel(view, at, watching), rest_panel),
        None => folder_panel(view, at, watching),
    }
}

/// "Last scanned 14:05": when a scan looked at the file, told the way the feed of Keyed values
/// tells times.
fn scanned_text(scanned: u64) -> String {
    let secs = i64::try_from(scanned).unwrap_or(i64::MAX);
    let local = DateTime::from_unix_secs(secs).to_local().ticks();
    format!("Last scanned {}", activity::when(local, activity::now()))
}

/// Home's map of where the personal data is: a treemap of the folder on show, with a side panel
/// for what is selected in it.
fn inventory_card(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut rows: Vec<View> = vec![inventory_header(window, context)];
    if let Some((done, total)) = snap.scan {
        rows.push(scan_progress(done, total));
    }
    // Until the first load has come back the card does not claim that there is nothing to see.
    if window.inv_loaded {
        if window.inv_view.nodes.is_empty() {
            if snap.scan.is_none() {
                rows.push(inventory_empty(window, context));
            }
        } else {
            rows.push(inventory_map(window, context));
        }
    }
    card(StackPanel::new().spacing(12.0).children(rows)).into()
}

/// The heading, the way back up (every crumb but the last is a link) and the report button.
fn inventory_header(window: &MainWindow, context: Context<'_>) -> View {
    let trail = crumbs(&window.inv_at, &window.inv_view.roots);
    let mut steps: Vec<View> = Vec::new();
    for (i, crumb) in trail.iter().enumerate() {
        if i > 0 {
            steps.push(
                FontIcon::new()
                    .glyph("\u{E76C}")
                    .font_size(10.0)
                    .opacity(0.6)
                    .vertical_alignment(VerticalAlignment::Center)
                    .into(),
            );
        }
        if i + 1 == trail.len() {
            steps.push(
                TextBlock::new()
                    .text(&crumb.label)
                    .font_weight(FontWeight::SEMI_BOLD)
                    .vertical_alignment(VerticalAlignment::Center)
                    .margin(Thickness::new(8.0, 0.0, 8.0, 0.0))
                    .into(),
            );
        } else {
            steps.push(
                HyperlinkButton::new()
                    .content(crumb.label.as_str())
                    .on_click(context.message(Msg::InvNav(crumb.target.clone())))
                    .into(),
            );
        }
    }
    StackPanel::new()
        .spacing(4.0)
        .children((
            Grid::new()
                .columns([GridLength::STAR, GridLength::Auto])
                .column_spacing(12.0)
                .children((
                    heading("Where your personal data is"),
                    Button::new()
                        .content("Export report")
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Center)
                        .is_enabled(!window.inv_view.nodes.is_empty())
                        .on_click(context.message(Msg::InvReport)),
                )),
            StackPanel::new()
                .orientation(Orientation::Horizontal)
                .children(steps),
        ))
        .into()
}

/// The progress of a scan: the bar, and what it has done.
fn scan_progress(done: u64, total: u64) -> View {
    let (bar, text) = if total == 0 {
        (
            ProgressBar::new().is_indeterminate(true),
            "Looking for files…".to_owned(),
        )
    } else {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a progress bar needs no precision beyond 2^53 files"
        )]
        let (done_f, total_f) = (done as f64, total as f64);
        (
            ProgressBar::new()
                .minimum(0.0)
                .maximum(total_f)
                .value(done_f),
            format!("Scanned {} of {} files…", thousands(done), thousands(total)),
        )
    };
    StackPanel::new()
        .spacing(4.0)
        .children((bar, caption(text)))
        .into()
}

/// What the card says when there is nothing to draw and no scan is running.
fn inventory_empty(window: &MainWindow, context: Context<'_>) -> View {
    // The file an Explorer scan was about, else the folder on show.
    let scanned = match &window.inv_selected {
        Some(Selection::Node(file)) if !file.as_os_str().is_empty() => file.as_path(),
        _ => window.inv_at.as_path(),
    };
    if !scanned.as_os_str().is_empty() {
        return caption(format!("No personal data found in {}.", scanned.display())).into();
    }
    if window.snap.policy.inventory {
        return caption("Nothing found yet. piikey checks your folders in the background; the files that hold personal data show up here.").into();
    }
    StackPanel::new()
        .spacing(8.0)
        .children((
            caption(
                "Turn on the PII inventory to see which files in your folders hold personal data, or right-click a file or folder in Explorer and choose Scan for PII.",
            ),
            Button::new()
                .content("Turn on inventory")
                .style(ButtonStyle::Accent)
                .on_click(context.message(Msg::Inventory(true))),
        ))
        .into()
}

/// The treemap with its side panel.
fn inventory_map(window: &MainWindow, context: Context<'_>) -> View {
    let selected = window.inv_selected.as_ref();
    let buttons: Vec<View> = tiles(&window.inv_view.nodes)
        .iter()
        .map(|tile| tile_button(tile, is_selected(&tile.of, selected), window.dark, context))
        .collect();
    Grid::new()
        .columns([GridLength::STAR, GridLength::Pixel(SIDE_WIDTH)])
        .column_spacing(16.0)
        .children((
            Viewbox::new()
                .stretch(Stretch::Uniform)
                .vertical_alignment(VerticalAlignment::Top)
                .content(Canvas::new().width(MAP_W).height(MAP_H).children(buttons)),
            side_panel(window, context).grid_column(1),
        ))
        .into()
}

/// One tile as a button on the canvas, in the colour of its tile. The theme's button colours are
/// replaced for this button only, so hover and press keep the tile's colour.
fn tile_button(tile: &Tile, selected: bool, dark: bool, context: Context<'_>) -> View {
    let message = match &tile.of {
        TileOf::Node(path) => Msg::InvOpen(path.clone()),
        TileOf::More => Msg::InvMore,
    };
    let ring = if selected {
        selection_ring(dark)
    } else {
        Color::transparent()
    };
    let resources = ResourceOverrides::new()
        .set("ButtonBackground", tile.color)
        .set("ButtonBackgroundPointerOver", blend(tile.color, WHITE, 18))
        .set("ButtonBackgroundPressed", blend(tile.color, BLACK, 18))
        .set("ButtonForeground", WHITE)
        .set("ButtonForegroundPointerOver", WHITE)
        .set("ButtonForegroundPressed", WHITE)
        .set("ButtonBorderBrush", ring)
        .set("ButtonBorderBrushPointerOver", ring)
        .set("ButtonBorderBrushPressed", ring)
        .set(
            "ButtonBorderThemeThickness",
            Thickness::uniform(if selected { 3.0 } else { 0.0 }),
        )
        .set("ControlCornerRadius", CornerRadius::uniform(4.0));
    let said = format!("{}: {}", tile.title, tile.detail);
    let mut button = Button::new()
        .canvas_left(tile.rect.x)
        .canvas_top(tile.rect.y)
        .width(tile.rect.w)
        .height(tile.rect.h)
        .min_width(0.0)
        .min_height(0.0)
        .background(tile.color)
        .horizontal_content_alignment(HorizontalAlignment::Left)
        .vertical_content_alignment(VerticalAlignment::Top)
        .resource_overrides(resources)
        .automation_name(&said)
        .on_click(context.message(message));
    if shows_label(&tile.rect) {
        button = button.content(tile_label(tile));
    }
    button.tooltip(said)
}

/// A tile's name over its counts, in white.
fn tile_label(tile: &Tile) -> View {
    let (name_size, detail_size) = label_sizes(&tile.rect);
    StackPanel::new()
        .children((
            TextBlock::new()
                .text(&tile.title)
                .font_size(name_size)
                .font_weight(FontWeight::SEMI_BOLD)
                .foreground(WHITE)
                .text_trimming(TextTrimming::CharacterEllipsis),
            TextBlock::new()
                .text(&tile.detail)
                .font_size(detail_size)
                .foreground(WHITE)
                .opacity(0.9)
                .text_trimming(TextTrimming::CharacterEllipsis),
        ))
        .into()
}

/// The side panel: what is selected (the folder on show when nothing is), its numbers, and what
/// can be done with it.
fn side_panel(window: &MainWindow, context: Context<'_>) -> StackPanel {
    let subject = panel(
        &window.inv_view,
        &window.inv_at,
        window.inv_selected.as_ref(),
        window.snap.policy.inventory,
    );
    let mut children: Vec<View> = vec![
        TextBlock::new()
            .text(&subject.title)
            .font_size(16.0)
            .font_weight(FontWeight::SEMI_BOLD)
            .text_trimming(TextTrimming::CharacterEllipsis)
            .into(),
        caption(&subject.detail)
            .is_text_selection_enabled(true)
            .into(),
        TextBlock::new()
            .text(&subject.summary)
            .text_wrapping(TextWrapping::Wrap)
            .into(),
    ];
    children.extend(subject.kinds.iter().map(|&(kind, n)| kind_row(kind, n)));
    if let Some(scanned) = subject.scanned {
        children.push(caption(scanned_text(scanned)).into());
    }
    if !subject.rest.is_empty() {
        children.push(rest_list(subject.rest, context));
    }
    children.extend(action_buttons(&subject, context));
    StackPanel::new().spacing(6.0).children(children)
}

/// One kind found, with how many.
fn kind_row(kind: EntityKind, n: u32) -> View {
    Grid::new()
        .columns([GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((
            TextBlock::new()
                .text(kind.label())
                .text_trimming(TextTrimming::CharacterEllipsis),
            TextBlock::new()
                .text(thousands(u64::from(n)))
                .opacity(0.72)
                .grid_column(1),
        ))
        .into()
}

/// The nodes of the "+N more" tile, each a link that does what its tile would have done.
fn rest_list(rest: &[Node], context: Context<'_>) -> View {
    let shown = rest.len().min(MORE_ROWS);
    let list = ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(list_height(shown.min(MORE_VISIBLE)))
        .items(rest.iter().take(shown).map(|node| {
            DataItem::new(format!("more:{}", node.path.display()), &node.name).content(
                Grid::new()
                    .columns([GridLength::STAR, GridLength::Auto])
                    .column_spacing(8.0)
                    .children((
                        HyperlinkButton::new()
                            .content(node.name.as_str())
                            .on_click(context.message(Msg::InvOpen(node.path.clone()))),
                        TextBlock::new()
                            .text(thousands(node.hits))
                            .opacity(0.72)
                            .vertical_alignment(VerticalAlignment::Center)
                            .grid_column(1),
                    )),
            )
        }));
    if rest.len() > shown {
        let more = u64::try_from(rest.len() - shown).unwrap_or(u64::MAX);
        return StackPanel::new()
            .spacing(4.0)
            .children((
                list,
                caption(format!("and {} smaller ones.", thousands(more))),
            ))
            .into();
    }
    list.into()
}

/// The buttons that apply to what the panel describes, or none.
fn action_buttons(panel: &Panel<'_>, context: Context<'_>) -> Option<View> {
    let button = |label: &str, message: Msg| -> View {
        Button::new()
            .content(label)
            .horizontal_alignment(HorizontalAlignment::Stretch)
            .horizontal_content_alignment(HorizontalAlignment::Left)
            .on_click(context.message(message))
            .into()
    };
    let buttons: Vec<View> = match (panel.buttons, panel.target) {
        (Buttons::File, Some(file)) => vec![
            button("Open", Msg::InvLaunch(file.to_path_buf())),
            button("Show in Explorer", Msg::InvShow(file.to_path_buf())),
            button("Rescan", Msg::InvRescan(file.to_path_buf())),
            button("Make masked copy", Msg::InvMask(file.to_path_buf())),
            button("Exclude", Msg::InvExclude(file.to_path_buf())),
        ],
        (Buttons::Folder, Some(folder)) => vec![
            button("Show in Explorer", Msg::InvShow(folder.to_path_buf())),
            button("Rescan", Msg::InvRescan(folder.to_path_buf())),
            button("Exclude", Msg::InvExclude(folder.to_path_buf())),
        ],
        (Buttons::All, _) => vec![button("Rescan", Msg::RescanAll)],
        _ => Vec::new(),
    };
    (!buttons.is_empty()).then(|| {
        StackPanel::new()
            .spacing(6.0)
            .margin(Thickness::new(0.0, 6.0, 0.0, 0.0))
            .children(buttons)
            .into()
    })
}

/// One keyed value: kind icon, the value over its stand-in, and where it went. With `on_forget`
/// the row ends in a button that forgets the value.
fn keyed_row(item: &Keyed, dark: bool, on_forget: Option<Callback<()>>) -> View {
    let detail = item.sent.as_ref().map_or_else(
        || item.kind.label().to_owned(),
        |sent| match &sent.exe {
            Some(exe) => format!("{} · {exe} · {}", sent.host, sent.at),
            None => format!("{} · {}", sent.host, sent.at),
        },
    );
    let mut columns = vec![GridLength::Auto, GridLength::STAR, GridLength::Auto];
    let mut cells: Vec<View> = vec![
        Border::new()
            .width(32.0)
            .height(32.0)
            .corner_radius(6.0)
            .background(ThemeBrush::CardBackground)
            .border_brush(ThemeBrush::CardStroke)
            .border_thickness(1.0)
            .vertical_alignment(VerticalAlignment::Center)
            .content(
                FontIcon::new()
                    .glyph(kind_glyph(item.kind))
                    .font_size(16.0)
                    .foreground(brand(dark)),
            )
            .into(),
        StackPanel::new()
            .grid_column(1)
            .vertical_alignment(VerticalAlignment::Center)
            .children((
                TextBlock::new()
                    .text(&item.original)
                    .font_weight(FontWeight::SEMI_BOLD)
                    .text_trimming(TextTrimming::CharacterEllipsis),
                TextBlock::new()
                    .text(format!("→ {}", item.proxy))
                    .opacity(0.72)
                    .text_trimming(TextTrimming::CharacterEllipsis),
            ))
            .into(),
        caption(detail)
            .grid_column(2)
            .vertical_alignment(VerticalAlignment::Center)
            .into(),
    ];
    if let Some(on_forget) = on_forget {
        columns.push(GridLength::Auto);
        cells.push(
            Button::new()
                .content(FontIcon::new().glyph("\u{E74D}").font_size(14.0))
                .style(ButtonStyle::Subtle)
                .automation_name("Forget")
                .grid_column(3)
                .vertical_alignment(VerticalAlignment::Center)
                .on_click(on_forget)
                .tooltip("Forget this value"),
        );
    }
    Grid::new()
        .columns(columns)
        .column_spacing(12.0)
        .children(cells)
        .into()
}

/// The most recently sent values, with the way to all of them.
fn recent(window: &MainWindow, context: Context<'_>) -> View {
    let snap = &window.snap;
    let mut rows: Vec<View> = vec![
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .children((
                heading("Recent activity"),
                HyperlinkButton::new()
                    .content("View all")
                    .grid_column(1)
                    .is_enabled(snap.issued > 0)
                    .on_click(context.message(Msg::Nav(Page::Keyed))),
            ))
            .into(),
    ];
    if snap.recent.is_empty() {
        rows.push(
            caption("Nothing yet. Turn protection on and use one of your sites: every value that gets a stand-in shows up here.")
                .into(),
        );
    }
    rows.extend(
        snap.recent
            .iter()
            .take(RECENT)
            .map(|item| keyed_row(item, window.dark, None)),
    );
    card(StackPanel::new().spacing(10.0).children(rows)).into()
}

// ---- Keyed values ----

/// The Keyed values kind filter: "All kinds", then every kind of [`KIND_GROUPS`] in their order.
fn kind_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    let kinds: Vec<EntityKind> = KIND_GROUPS
        .iter()
        .flat_map(|&(_, kinds)| kinds.iter().copied())
        .collect();
    ComboBox::new()
        .items_source(std::iter::once("All kinds").chain(kinds.iter().map(|&kind| kind.label())))
        .selected_index(Some(
            window
                .keyed
                .kind
                .and_then(|kind| kinds.iter().position(|&k| k == kind))
                .map_or(0, |i| i + 1),
        ))
        .width(170.0)
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::KeyedKind(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| kinds.get(i).copied()),
            )
        }))
}

/// The Keyed values site filter: "All sites", then every site a value went to, most recent first.
/// The chosen site stays listed even when the last search no longer returned it.
fn site_filter(window: &MainWindow, context: Context<'_>) -> Grid {
    let mut sites: Vec<String> = window
        .keyed_page
        .as_ref()
        .map(|page| page.sites.clone())
        .unwrap_or_default();
    if let Some(site) = &window.keyed.site
        && !sites.contains(site)
    {
        sites.insert(0, site.clone());
    }
    let selected = window
        .keyed
        .site
        .as_ref()
        .and_then(|site| sites.iter().position(|s| s == site))
        .map_or(0, |i| i + 1);
    // The list of sites arrives after the page is first drawn. A new list clears the choice of
    // the combo box that held the old one, and a `selected_index` that did not change is not
    // set again, so the box would stay empty: each list gets a combo box of its own.
    let key = sites.join("\n");
    let choice = ComboBox::new()
        .items_source(std::iter::once("All sites").chain(sites.iter().map(String::as_str)))
        .selected_index(Some(selected))
        .width(190.0)
        .on_selection_changed(context.callback(move |index: Option<usize>| {
            Msg::KeyedSite(
                index
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| sites.get(i).cloned()),
            )
        }));
    Grid::new().keyed_children([KeyedView::new(key, choice)])
}

/// The Keyed values time filter.
fn period_filter(window: &MainWindow, context: Context<'_>) -> ComboBox {
    ComboBox::new()
        .items_source(Period::ALL.iter().map(|period| period.label()))
        .selected_index(Period::ALL.iter().position(|&p| p == window.keyed.period))
        .width(150.0)
        .on_selection_changed(context.callback(|index: Option<usize>| {
            Msg::KeyedPeriod(
                index
                    .and_then(|i| Period::ALL.get(i).copied())
                    .unwrap_or_default(),
            )
        }))
}

fn keyed(window: &MainWindow, context: Context<'_>) -> View {
    let search = Grid::new()
        .columns([
            GridLength::STAR,
            GridLength::Auto,
            GridLength::Auto,
            GridLength::Auto,
        ])
        .column_spacing(8.0)
        .children((
            TextBox::new()
                .text(&window.keyed.text)
                .placeholder_text("Search values, stand-ins, sites or programs")
                .on_text_changed(
                    context.callback(|text: Rc<str>| Msg::KeyedQuery(text.to_string())),
                ),
            kind_filter(window, context).grid_column(1),
            site_filter(window, context).grid_column(2),
            period_filter(window, context).grid_column(3),
        ));

    let (count, list): (String, View) = match &window.keyed_page {
        None => (
            "Loading...".to_owned(),
            ProgressRing::new()
                .is_active(true)
                .width(32.0)
                .height(32.0)
                .into(),
        ),
        Some(page) if page.items.is_empty() => (
            if window.snap.issued == 0 {
                "Nothing keyed yet.".to_owned()
            } else {
                "No keyed value matches.".to_owned()
            },
            StackPanel::new().into(),
        ),
        Some(page) => {
            let total = u64::try_from(page.matched).unwrap_or(u64::MAX);
            let count = if page.matched > page.items.len() {
                format!(
                    "Showing the {} most recent of {}. Search to narrow them down.",
                    thousands(u64::try_from(KEYED_LIMIT).unwrap_or(u64::MAX)),
                    thousands(total)
                )
            } else if page.matched == 1 {
                "1 value".to_owned()
            } else {
                format!("{} values, most recently sent first", thousands(total))
            };
            let list = ListView::new()
                .selection_mode(ListViewSelectionMode::None)
                .items(page.items.iter().map(|item| {
                    let forget = context.message(Msg::Forget(item.original.clone()));
                    DataItem::new(item.proxy.clone(), &item.original).content(
                        Border::new().height(KEYED_ROW).content(keyed_row(
                            item,
                            window.dark,
                            Some(forget),
                        )),
                    )
                }))
                .into();
            (count, list)
        }
    };

    Grid::new()
        .rows([
            GridLength::Auto,
            GridLength::Auto,
            GridLength::Auto,
            GridLength::STAR,
        ])
        .row_spacing(12.0)
        .children((
            Grid::new()
                .columns([GridLength::STAR, GridLength::Auto])
                .column_spacing(12.0)
                .children((
                    StackPanel::new().spacing(4.0).children((
                        title(Page::Keyed.title()),
                        caption("Every value piikey has given a stand-in, from the vault on this PC. The stand-in is what the site saw; piikey turns it back into the value in the answers."),
                    )),
                    Button::new()
                        .content("Export…")
                        .grid_column(1)
                        .vertical_alignment(VerticalAlignment::Top)
                        .is_enabled(window.snap.issued > 0)
                        .on_click(context.message(Msg::ExportVault)),
                )),
            search.grid_row(1),
            caption(count).grid_row(2),
            Border::new().grid_row(3).content(list),
        ))
        .into()
}

// ---- Settings ----

/// The Settings page: its title and tab bar stay where they are while the tab under them
/// scrolls.
fn settings(window: &MainWindow, context: Context<'_>) -> View {
    let tab = window.settings_tab;
    let mut head: Vec<View> = vec![title(Page::Settings.title()).into(), tab_bar(tab, context)];
    if let Some(error) = &window.form_error {
        head.push(
            InfoBar::new()
                .title("Not added")
                .message(error)
                .severity(InfoBarSeverity::Warning)
                .is_open(true)
                .is_closable(true)
                .on_closed(context.message(Msg::DismissForm))
                .into(),
        );
    }
    let body = match tab {
        SettingsTab::General => general(window, context),
        SettingsTab::Masking => masking(window, context),
        SettingsTab::Detection => column(vec![kinds_card(window, context)]),
        SettingsTab::Inventory => inventory_tab(window, context),
        SettingsTab::Api => api_tab(window, context),
        SettingsTab::Vault => vault_tab(window, context),
        SettingsTab::About => column(vec![about_card(window)]),
    };
    Grid::new()
        .rows([GridLength::Auto, GridLength::STAR])
        .row_spacing(12.0)
        .children((
            StackPanel::new().spacing(12.0).children(head),
            // Keyed by the tab: each one opens at its top, with nothing left of the scroll
            // position or the open expanders of the last.
            Grid::new()
                .grid_row(1)
                .keyed_children([KeyedView::new(tab.label(), body)]),
        ))
        .into()
}

/// The tabs of Settings. The bar reports a pick by the text of the tab. In a window too narrow
/// for all of them it scrolls sideways, so no tab is cut off out of reach.
fn tab_bar(selected: SettingsTab, context: Context<'_>) -> View {
    let tabs = SelectorBar::new()
        .on_selected_text_changed(context.callback(|text: Option<Rc<str>>| {
            text.as_deref()
                .and_then(SettingsTab::from_label)
                .map_or(Msg::Noop, Msg::Tab)
        }))
        .keyed_items(SettingsTab::ALL.map(|tab| {
            KeyedView::new(
                tab.label(),
                SelectorBarItem::new()
                    .text(tab.label())
                    .is_selected(tab == selected),
            )
        }));
    ScrollViewer::new()
        .horizontal_scroll_bar_visibility(ScrollBarVisibility::Auto)
        .vertical_scroll_bar_visibility(ScrollBarVisibility::Disabled)
        .content(tabs)
        .into()
}

/// A card for every feature: its switch, and a link to the tab with the rest of its settings.
fn general(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    column(vec![
        setting_card(
            "\u{E72E}",
            "Mask what you send",
            "Replaces personal data in what you send to your protected sites and programs, and restores it in the answers.",
            Some(masking_link(window, context)),
            protection_switch(window, context).automation_name("Mask what you send"),
        ),
        setting_card(
            "\u{E7B3}",
            "Highlight personal data as you type",
            "Outlines the field you type in when it holds personal data, in any app. Nothing leaves your PC.",
            None,
            highlight_choice(window, context),
        ),
        setting_card(
            "\u{E8B7}",
            "Scan for PII in Explorer",
            "Adds Scan for PII to the right-click menu of files and folders (Show more options on Windows 11).",
            None,
            feature_switch(
                "Scan for PII in Explorer",
                policy.explorer_menu,
                Msg::ExplorerMenu,
                context,
            ),
        ),
        setting_card(
            "\u{E71D}",
            "PII inventory",
            "Keeps a map of which files in your folders hold personal data, scanning changed files in the background.",
            Some(flush(tab_link(
                "Inventory settings ›",
                SettingsTab::Inventory,
                context,
            ))),
            feature_switch("PII inventory", policy.inventory, Msg::Inventory, context),
        ),
        setting_card(
            "\u{E943}",
            "Local HTTP API",
            "Lets your scripts call piikey at 127.0.0.1 with a token. The CLI and the named pipe work without it.",
            Some(flush(tab_link("API settings ›", SettingsTab::Api, context))),
            feature_switch("Local HTTP API", policy.http_api, Msg::HttpApi, context),
        ),
    ])
}

/// The certificate masking needs, then the sites and programs it applies to.
fn masking(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![
        caption("Where piikey swaps your personal data for stand-ins.").into(),
        certificate(window, context),
        sites_card(window, context),
        programs_card(window, context),
    ])
}

/// What the Highlight setting offers, in the order of its list.
const HIGHLIGHTS: [(Highlight, &str); 3] = [
    (Highlight::Off, "Off"),
    (Highlight::Always, "Always"),
    (Highlight::Hotkey, "When I press Ctrl+Alt+P"),
];

/// One setting as a card: its icon, its name, what it does and, when more of it is on another
/// tab, the way there, with the control that sets it on the right.
fn setting_card(
    glyph: &str,
    name: &str,
    about: &str,
    more: Option<View>,
    control: impl Into<View>,
) -> View {
    let mut text: Vec<View> = vec![
        TextBlock::new()
            .text(name)
            .font_size(14.0)
            .font_weight(FontWeight::SEMI_BOLD)
            .text_wrapping(TextWrapping::Wrap)
            .into(),
        caption(about).into(),
    ];
    text.extend(more);
    card(
        Grid::new()
            .columns([GridLength::Auto, GridLength::STAR, GridLength::Auto])
            .column_spacing(16.0)
            .children((
                FontIcon::new()
                    .glyph(glyph)
                    .font_size(20.0)
                    .vertical_alignment(VerticalAlignment::Center),
                StackPanel::new()
                    .spacing(2.0)
                    .grid_column(1)
                    .vertical_alignment(VerticalAlignment::Center)
                    .children(text),
                Border::new()
                    .grid_column(2)
                    .vertical_alignment(VerticalAlignment::Center)
                    .content(control),
            )),
    )
    .into()
}

/// How far `TextBlockButtonStyle` pads the text of a link button from its left edge, in DIPs.
const LINK_PAD: f64 = 11.0;

/// A link that opens `tab` of Settings.
fn tab_link(text: &str, tab: SettingsTab, context: Context<'_>) -> Button {
    Button::new()
        .content(text)
        .style(ButtonStyle::TextLink)
        .on_click(context.message(Msg::Tab(tab)))
}

/// `link` with its text in line with the text above it: the padding is pulled out to the left.
fn flush(link: Button) -> View {
    link.margin(Thickness::new(-LINK_PAD, 0.0, 0.0, 0.0)).into()
}

/// What goes under "Mask what you send": why its switch is off while the certificate is missing,
/// else the way to the tab with its sites and programs.
fn masking_link(window: &MainWindow, context: Context<'_>) -> View {
    if window.snap.cert == Cert::Missing {
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(6.0)
            .children((
                caption("Needs the piikey certificate first.")
                    .vertical_alignment(VerticalAlignment::Center),
                tab_link("Install it ›", SettingsTab::Masking, context),
            ))
            .into()
    } else {
        flush(tab_link(
            "Masking settings ›",
            SettingsTab::Masking,
            context,
        ))
    }
}

/// The switch of a feature of the policy; `to_message` turns the new state into the message.
fn feature_switch(
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

/// The choice of when the field in focus is outlined.
fn highlight_choice(window: &MainWindow, context: Context<'_>) -> ComboBox {
    ComboBox::new()
        .items_source(HIGHLIGHTS.iter().map(|&(_, label)| label))
        .selected_index(
            HIGHLIGHTS
                .iter()
                .position(|&(mode, _)| mode == window.snap.policy.highlight),
        )
        .width(210.0)
        .automation_name("Highlight personal data as you type")
        .on_selection_changed(context.callback(|index: Option<usize>| {
            index
                .and_then(|i| HIGHLIGHTS.get(i))
                .map_or(Msg::Noop, |&(mode, _)| Msg::Highlight(mode))
        }))
}

fn certificate(window: &MainWindow, context: Context<'_>) -> View {
    let working = window.snap.busy.is_some() || window.snap.pending > 0;
    match window.snap.cert {
        Cert::Installed => info(
            "Certificate installed",
            "Windows trusts the piikey certificate, so piikey can read the HTTPS traffic of the sites and programs you select.",
            InfoBarSeverity::Success,
        )
        .into(),
        Cert::Missing => StackPanel::new()
            .spacing(8.0)
            .children((
                info(
                    "Certificate not installed",
                    "piikey needs it to read HTTPS traffic of the sites and programs you select. Windows asks you to confirm once.",
                    InfoBarSeverity::Warning,
                ),
                Button::new()
                    .content("Install certificate")
                    .style(ButtonStyle::Accent)
                    .is_enabled(!working)
                    .on_click(context.message(Msg::InstallCertificate)),
            ))
            .into(),
        Cert::Unknown => info(
            "Certificate",
            "Checking whether Windows trusts the piikey certificate...",
            InfoBarSeverity::Informational,
        )
        .into(),
    }
}

/// A check box row of a list.
fn check_row(
    key: String,
    label: &str,
    checked: bool,
    on_change: impl Fn(bool) -> Msg + 'static,
    context: Context<'_>,
) -> DataItem {
    DataItem::new(key, label).content(
        CheckBox::new()
            .is_checked(checked)
            .content(label)
            .on_is_checked_changed(
                context.callback(move |value: Option<bool>| on_change(value.unwrap_or(false))),
            ),
    )
}

/// A row with a label and a button on its right.
fn remove_row(key: String, label: &str, action: Msg, context: Context<'_>) -> DataItem {
    DataItem::new(key, label).content(
        Grid::new()
            .columns([GridLength::STAR, GridLength::Auto])
            .column_spacing(12.0)
            .children((
                TextBlock::new()
                    .text(label)
                    .text_trimming(TextTrimming::CharacterEllipsis)
                    .margin(Thickness::new(0.0, 8.0, 0.0, 0.0)),
                Button::new()
                    .content("Remove")
                    .style(ButtonStyle::Subtle)
                    .grid_column(1)
                    .on_click(context.message(action)),
            )),
    )
}

fn list_height(rows: usize) -> f64 {
    // Row counts are tiny, so the conversion is exact.
    #[allow(clippy::cast_precision_loss)]
    let rows = rows as f64;
    ROW * rows + 8.0
}

/// A text box with its button on the right.
fn add_row(
    placeholder: &str,
    draft: &str,
    button: &str,
    on_text: impl Fn(String) -> Msg + 'static,
    on_add: Msg,
    context: Context<'_>,
) -> View {
    Grid::new()
        .columns([GridLength::STAR, GridLength::Auto])
        .column_spacing(8.0)
        .children((
            TextBox::new()
                .text(draft)
                .placeholder_text(placeholder)
                .on_text_changed(context.callback(move |text: Rc<str>| on_text(text.to_string()))),
            Button::new()
                .content(button)
                .grid_column(1)
                .is_enabled(!draft.trim().is_empty())
                .on_click(context.message(on_add)),
        ))
        .into()
}

/// The preset sites with check boxes, then the sites the user added with a remove button each.
fn sites_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let presets = ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(list_height(PRESETS.len()))
        .items(PRESETS.iter().map(|&preset| {
            let site = preset.to_owned();
            check_row(
                format!("preset:{preset}"),
                preset,
                policy.sites.iter().any(|s| s == preset),
                move |on| Msg::Site(site.clone(), on),
                context,
            )
        }));
    let custom: Vec<&String> = policy
        .sites
        .iter()
        .filter(|site| !PRESETS.contains(&site.as_str()))
        .collect();
    let custom: View = if custom.is_empty() {
        caption("No other sites yet.").into()
    } else {
        ListView::new()
            .selection_mode(ListViewSelectionMode::None)
            .height(list_height(custom.len()))
            .items(custom.iter().map(|site| {
                remove_row(
                    format!("site:{site}"),
                    site,
                    Msg::Site((*site).clone(), false),
                    context,
                )
            }))
            .into()
    };
    card(
        StackPanel::new().spacing(8.0).children((
            heading("Sites"),
            caption("Only traffic to the sites you tick, and from the programs you tick below, is read and anonymized. Everything else passes through untouched."),
            presets,
            custom,
            add_row(
                "Another site, e.g. example.com or *.example.com",
                &window.site_draft,
                "Add site",
                Msg::SiteDraft,
                Msg::AddSite,
                context,
            ),
        )),
    )
    .into()
}

/// Running programs, plus any configured program that is not running now, with check boxes.
fn programs_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let mut programs: Vec<&str> = window
        .processes
        .iter()
        .chain(&policy.programs)
        .map(String::as_str)
        .collect();
    programs.sort_unstable();
    programs.dedup();
    let list = ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(ROW * 7.0)
        .items(programs.iter().map(|&exe| {
            let owned = exe.to_owned();
            check_row(
                format!("program:{exe}"),
                exe,
                policy.programs.iter().any(|p| p == exe),
                move |on| Msg::Program(owned.clone(), on),
                context,
            )
        }));
    card(
        StackPanel::new().spacing(8.0).children((
            heading("Programs"),
            caption("Every site a ticked program visits is protected. Works for programs that follow the Windows proxy settings: browsers, Electron apps, .NET apps, curl. The list refreshes every few seconds."),
            list,
            add_row(
                "Another program, e.g. chrome.exe",
                &window.program_draft,
                "Add program",
                Msg::ProgramDraft,
                Msg::AddProgram,
                context,
            ),
        )),
    )
    .into()
}

/// One collapsed expander per kind group, each listing its kinds as check boxes.
fn kinds_card(window: &MainWindow, context: Context<'_>) -> View {
    let disabled = &window.snap.policy.disabled_kinds;
    let mut children: Vec<View> = vec![
        heading("What piikey looks for").into(),
        caption(
            "Applies to masking, highlighting, scans and the inventory. Everything is on by default. Turning a type off only affects new text; values piikey already replaced still come back.",
        )
        .into(),
    ];
    children.extend(KIND_GROUPS.iter().map(|&(group, kinds)| {
        let on = kinds.iter().filter(|kind| !disabled.contains(kind)).count();
        let list = ListView::new()
            .selection_mode(ListViewSelectionMode::None)
            .height(list_height(kinds.len()))
            .items(kinds.iter().map(|&kind| {
                check_row(
                    format!("kind:{}", kind.as_str()),
                    kind.label(),
                    !disabled.contains(&kind),
                    move |on| Msg::Kind(kind, on),
                    context,
                )
            }));
        Expander::new()
            .is_expanded(false)
            .horizontal_alignment(HorizontalAlignment::Stretch)
            .horizontal_content_alignment(HorizontalAlignment::Stretch)
            .header(TextBlock::new().text(format!("{group} ({on}/{})", kinds.len())))
            .content(list)
            .into()
    }));
    card(StackPanel::new().spacing(8.0).children(children)).into()
}

/// A list of paths with a remove button each; `key` and `remove` make the row of a path.
fn path_list(
    paths: &[PathBuf],
    key: &str,
    remove: impl Fn(PathBuf) -> Msg,
    context: Context<'_>,
) -> View {
    ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(list_height(paths.len()))
        .items(paths.iter().map(|path| {
            remove_row(
                format!("{key}:{}", path.display()),
                &path.display().to_string(),
                remove(path.clone()),
                context,
            )
        }))
        .into()
}

/// The state of the inventory with its rescan button, the folders it scans and what it leaves
/// out. Its switch is in General.
fn inventory_tab(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![
        inventory_status(window, context),
        folders_card(window, context),
        left_out_card(window, context),
    ])
}

/// Whether the inventory runs, with the button that scans its folders again now.
fn inventory_status(window: &MainWindow, context: Context<'_>) -> View {
    let on = window.snap.policy.inventory;
    let (name, about) = if on {
        (
            "PII inventory is on",
            "Looks through the folders below in the background. The files that hold personal data show up on Home.",
        )
    } else {
        (
            "PII inventory is off",
            "Switch it on in General to look through the folders below in the background.",
        )
    };
    setting_card(
        "\u{E71D}",
        name,
        about,
        (!on).then(|| flush(tab_link("General ›", SettingsTab::General, context))),
        Button::new()
            .content("Rescan now")
            .is_enabled(on)
            .on_click(context.message(Msg::RescanAll)),
    )
}

/// The folders the inventory scans, with a box to add one.
fn folders_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let folders: View = if policy.inventory_roots.is_empty() {
        caption(
            "None chosen: switching the inventory on scans your Documents, Desktop and Downloads.",
        )
        .into()
    } else {
        path_list(
            &policy.inventory_roots,
            "root",
            |path| Msg::Root(path, false),
            context,
        )
    };
    card(StackPanel::new().spacing(8.0).children((
        heading("Folders to scan"),
        caption("The inventory looks through these folders and everything in them."),
        folders,
        add_row(
            "C:\\Users\\you\\Documents",
            &window.root_draft,
            "Add folder",
            Msg::RootDraft,
            Msg::AddRoot,
            context,
        ),
    )))
    .into()
}

/// The files and folders the inventory skips.
fn left_out_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let left_out: View = if policy.inventory_exclude.is_empty() {
        caption("Nothing is left out.").into()
    } else {
        path_list(
            &policy.inventory_exclude,
            "exclude",
            |path| Msg::Exclude(path, false),
            context,
        )
    };
    card(
        StackPanel::new().spacing(8.0).children((
            heading("Left out"),
            caption("The inventory skips these files and folders, and everything in them. To add one, choose Exclude on the map on Home."),
            left_out,
        )),
    )
    .into()
}

/// How scripts reach the app: the named pipe, and the HTTP address with its token. The switch of
/// the HTTP API is in General.
fn api_tab(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![pipe_card(), http_card(window, context)])
}

fn pipe_card() -> View {
    card(StackPanel::new().spacing(8.0).children((
        heading("Named pipe"),
        caption("The command line and Explorer's Scan for PII reach the app here while it runs."),
        caption(default_pipe()).is_text_selection_enabled(true),
    )))
    .into()
}

/// The HTTP address, whether it listens, and the token scripts send to it.
fn http_card(window: &MainWindow, context: Context<'_>) -> View {
    let status: View = if window.snap.http {
        caption("Listening.").into()
    } else {
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(6.0)
            .children((
                caption("Off.").vertical_alignment(VerticalAlignment::Center),
                tab_link(
                    "Switch on Local HTTP API in General ›",
                    SettingsTab::General,
                    context,
                ),
            ))
            .into()
    };
    let mut children: Vec<View> = vec![
        heading("HTTP").into(),
        caption("Scripts on this PC call this address and send the token below as an Authorization: Bearer header.").into(),
        caption(format!(
            "http://127.0.0.1:{}/v1/<op>",
            window.snap.policy.http_port
        ))
        .is_text_selection_enabled(true)
        .into(),
        status,
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(8.0)
            .children((
                Button::new()
                    .content("Copy token")
                    .on_click(context.message(Msg::CopyToken)),
                Button::new()
                    .content("New token")
                    .on_click(context.message(Msg::RotateToken)),
            ))
            .into(),
        caption("Copy token puts the token on the clipboard. New token replaces it: scripts have to use the new one.").into(),
    ];
    if let Some(note) = window.token_note {
        children.push(caption(note).into());
    }
    card(StackPanel::new().spacing(8.0).children(children)).into()
}

/// What the armed Wipe vault button says it will do.
fn wipe_armed_text(records: u64) -> String {
    if records == 1 {
        "Click again to wipe the record".to_owned()
    } else {
        format!("Click again to wipe all {} records", thousands(records))
    }
}

/// The vault file, and what can be done with all of its records. Wiping takes two clicks: the
/// first one only changes the button.
fn vault_tab(window: &MainWindow, context: Context<'_>) -> View {
    let records = window.snap.issued;
    let (wipe, wipe_style) = if window.wipe_armed {
        (wipe_armed_text(records), ButtonStyle::Accent)
    } else {
        ("Wipe vault".to_owned(), ButtonStyle::Default)
    };
    column(vec![
        card(
            StackPanel::new().spacing(8.0).children((
                heading("Vault file"),
                caption("Every value piikey swapped for a stand-in, kept encrypted on this PC."),
                caption(window.input.controller.vault_path().display().to_string())
                    .is_text_selection_enabled(true),
                caption(counted(records, "record", "records")),
            )),
        )
        .into(),
        setting_card(
            "\u{E896}",
            "Export vault",
            "Writes every value with its stand-in to a CSV file in Downloads. The file holds the values themselves: keep it safe.",
            None,
            Button::new()
                .content("Export…")
                .is_enabled(records > 0)
                .on_click(context.message(Msg::ExportVault)),
        ),
        setting_card(
            "\u{E74D}",
            "Wipe the vault",
            "Removes every record, so stand-ins that were already sent can no longer be turned back into values.",
            None,
            Button::new()
                .content(wipe)
                .style(wipe_style)
                .is_enabled(records > 0)
                .on_click(context.message(Msg::WipeVault)),
        ),
    ])
}

fn about_card(window: &MainWindow) -> View {
    let proxy = format!(
        "127.0.0.1:{PORT}, {}",
        if window.snap.enabled {
            "listening"
        } else {
            "stopped"
        }
    );
    card(
        Grid::new()
            .columns([GridLength::Auto, GridLength::STAR])
            .column_spacing(16.0)
            .children((
                Image::new()
                    .source_svg(assets::symbol(window.dark))
                    .stretch(Stretch::Uniform)
                    .width(48.0)
                    .height(48.0)
                    .vertical_alignment(VerticalAlignment::Top),
                StackPanel::new().spacing(8.0).grid_column(1).children((
                    heading(&format!("piikey {}", env!("CARGO_PKG_VERSION"))),
                    caption(format!("Local proxy: {proxy}")),
                )),
            )),
    )
    .into()
}

/// Lines the loading screen rotates through while the model downloads.
pub const FLAVOR: [&str; 12] = [
    "Teaching piikey that 'Jan Jansen' is a person and 'Jansen Bakery' is bread.",
    "Swapping your name for a nicer one. Don't worry, you get yours back.",
    "Your IBAN goes in, a perfectly fake IBAN comes out.",
    "Convincing the chatbot that you are Haley Marian from Westbrook.",
    "Learning 24 languages so your aunt's Polish address stays private too.",
    "Hiding your phone number from the robots. Politely.",
    "'Hi, I'm jan.jansen@acme.nl' becomes 'Hi, I'm lotte.peters@mail.nl'. Magic.",
    "Downloading a small brain. It only knows about privacy.",
    "Making sure your doctor's note stays between you and your doctor.",
    "Your secrets are safe. Your typos are still all yours.",
    "Calibrating the 'is this a name or a pizza topping' detector.",
    "Everything runs on this PC. Nothing about you leaves it in clear.",
];

/// The first-run screen: the model download's progress, or why it failed.
pub fn loading(window: &MainWindow, context: Context<'_>) -> StackPanel {
    let mut children: Vec<View> = vec![
        Image::new()
            .source_svg(assets::stacked(window.dark))
            .stretch(Stretch::Uniform)
            .height(120.0)
            .into(),
        TextBlock::new()
            .text("Getting piikey ready")
            .font_size(24.0)
            .font_weight(FontWeight::SEMI_BOLD)
            .horizontal_alignment(HorizontalAlignment::Center)
            .into(),
    ];
    match &window.snap.model {
        Model::Failed(message) => {
            children.push(info("Download failed", message, InfoBarSeverity::Error).into());
            children.push(
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(8.0)
                    .horizontal_alignment(HorizontalAlignment::Center)
                    .children((
                        Button::new()
                            .content("Try again")
                            .style(ButtonStyle::Accent)
                            .on_click(context.message(Msg::RetryModel)),
                        Button::new()
                            .content("Continue without it")
                            .on_click(context.message(Msg::SkipModel)),
                    ))
                    .into(),
            );
        }
        model => {
            let (done, total) = match *model {
                Model::Downloading { done, total } => (done, total),
                _ => (0, 0),
            };
            #[expect(
                clippy::cast_precision_loss,
                reason = "a progress bar needs no byte precision"
            )]
            let (done_f, total_f) = (done as f64, total.max(1) as f64);
            children.push(
                ProgressBar::new()
                    .minimum(0.0)
                    .maximum(total_f)
                    .value(done_f)
                    .width(360.0)
                    .horizontal_alignment(HorizontalAlignment::Center)
                    .into(),
            );
            children.push(
                caption(format!(
                    "{} MB of {} MB",
                    (done + 500_000) / 1_000_000,
                    (total + 500_000) / 1_000_000
                ))
                .horizontal_alignment(HorizontalAlignment::Center)
                .into(),
            );
        }
    }
    children.push(
        RichTextBlock::new()
            .paragraphs(RichText::single_paragraph([RichTextInline::Run(
                RichTextRun {
                    text: FLAVOR[window.flavor % FLAVOR.len()].to_owned(),
                    is_italic: true,
                    ..RichTextRun::default()
                },
            )]))
            .text_wrapping(TextWrapping::Wrap)
            .opacity(0.8)
            .horizontal_alignment(HorizontalAlignment::Center)
            .into(),
    );
    StackPanel::new()
        .spacing(16.0)
        .max_width(440.0)
        .horizontal_alignment(HorizontalAlignment::Center)
        .vertical_alignment(VerticalAlignment::Center)
        .children(children)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-6
    }

    /// A file node of `C:\Data` with `hits` values of `kind`.
    fn node(name: &str, hits: u64, kind: EntityKind) -> Node {
        Node {
            path: PathBuf::from(format!(r"C:\Data\{name}")),
            name: name.to_owned(),
            is_dir: false,
            hits,
            files: 1,
            counts: vec![(kind, u32::try_from(hits).unwrap_or(u32::MAX))],
        }
    }

    /// `n` nodes with the most values first.
    fn nodes(n: usize) -> Vec<Node> {
        (0..n)
            .map(|i| {
                let hits = u64::try_from(n - i).unwrap_or(1) * 10;
                node(&format!("n{i}"), hits, EntityKind::Email)
            })
            .collect()
    }

    fn view_of(nodes: Vec<Node>) -> InventoryView {
        InventoryView {
            nodes,
            ..InventoryView::default()
        }
    }

    fn entry(path: &str, status: Status, counts: Vec<(EntityKind, u32)>) -> Entry {
        Entry {
            path: PathBuf::from(path),
            size: 10,
            modified: 0,
            scanned: 1_700_000_000,
            status,
            counts,
        }
    }

    fn roots(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn labels(trail: &[Crumb]) -> Vec<&str> {
        trail.iter().map(|crumb| crumb.label.as_str()).collect()
    }

    fn targets(trail: &[Crumb]) -> Vec<&Path> {
        trail.iter().map(|crumb| crumb.target.as_path()).collect()
    }

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn counts_read_as_sentences_with_the_right_plural() {
        assert_eq!(found_text(12, 3), "12 values in 3 files");
        assert_eq!(found_text(1, 1), "1 value in 1 file");
        assert_eq!(found_text(1_500, 2), "1,500 values in 2 files");
        assert_eq!(tile_detail(12, 3), "12 in 3 files");
        assert_eq!(tile_detail(1, 1), "1 in 1 file");
    }

    #[test]
    fn only_the_first_sixty_nodes_get_a_tile_and_the_rest_share_one() {
        let nodes = nodes(100);
        let tiles = tiles(&nodes);
        assert_eq!(tiles.len(), MAX_TILES + 1);
        let own: Vec<&PathBuf> = tiles
            .iter()
            .filter_map(|tile| match &tile.of {
                TileOf::Node(path) => Some(path),
                TileOf::More => None,
            })
            .collect();
        assert_eq!(own.len(), MAX_TILES);
        for node in &nodes[..MAX_TILES] {
            assert!(own.contains(&&node.path), "{} has no tile", node.name);
        }
        let more: Vec<&Tile> = tiles
            .iter()
            .filter(|tile| tile.of == TileOf::More)
            .collect();
        assert_eq!(more.len(), 1);
        assert_eq!(more[0].title, "+40 more");
        let rest_hits: u64 = nodes[MAX_TILES..].iter().map(|node| node.hits).sum();
        assert_eq!(more[0].detail, tile_detail(rest_hits, 40));
        assert_eq!(more[0].color, NEUTRAL);
    }

    #[test]
    fn few_nodes_need_no_more_tile() {
        let tiles = tiles(&nodes(MAX_TILES));
        assert_eq!(tiles.len(), MAX_TILES);
        assert!(tiles.iter().all(|tile| tile.of != TileOf::More));
        assert!(super::tiles(&[]).is_empty());
    }

    #[test]
    fn the_more_tile_is_placed_by_its_weight_among_the_others() {
        // Sixty tiles of one value, and forty more of one: together the biggest tile of all.
        let nodes: Vec<Node> = (0..100)
            .map(|i| node(&format!("n{i}"), 1, EntityKind::Email))
            .collect();
        let tiles = tiles(&nodes);
        assert_eq!(tiles[0].of, TileOf::More);
        assert!(tiles[0].rect.w * tiles[0].rect.h > tiles[1].rect.w * tiles[1].rect.h);
    }

    #[test]
    fn a_lone_tile_fills_the_canvas_less_the_inset() {
        let tiles = tiles(&nodes(1));
        assert_eq!(tiles.len(), 1);
        let rect = tiles[0].rect;
        assert!(near(rect.x, TILE_INSET) && near(rect.y, TILE_INSET));
        assert!(near(rect.w, MAP_W - 2.0 * TILE_INSET));
        assert!(near(rect.h, MAP_H - 2.0 * TILE_INSET));
    }

    #[test]
    fn tiles_stay_on_the_canvas_and_apart() {
        let tiles = tiles(&nodes(100));
        for (i, a) in tiles.iter().enumerate() {
            let ra = a.rect;
            assert!(
                ra.x >= 0.0 && ra.y >= 0.0,
                "{} starts off the canvas",
                a.title
            );
            assert!(ra.x + ra.w <= MAP_W + 1e-6 && ra.y + ra.h <= MAP_H + 1e-6);
            for b in &tiles[i + 1..] {
                let rb = b.rect;
                let apart = ra.x + ra.w <= rb.x
                    || rb.x + rb.w <= ra.x
                    || ra.y + ra.h <= rb.y
                    || rb.y + rb.h <= ra.y;
                assert!(apart, "{} and {} overlap", a.title, b.title);
            }
        }
    }

    #[test]
    fn a_tile_too_small_to_spare_the_inset_keeps_some_size() {
        let small = inset(Rect {
            x: 10.0,
            y: 10.0,
            w: 6.0,
            h: 100.0,
        });
        assert!(small.w > 0.0 && near(small.w, 3.0));
        assert!(near(small.x, 11.5));
        let none = inset(Rect {
            x: 10.0,
            y: 10.0,
            w: 0.0,
            h: 0.0,
        });
        assert!(near(none.w, 0.0) && near(none.h, 0.0));
    }

    #[test]
    fn text_needs_ninety_by_forty_and_room_for_its_two_lines() {
        let rect = |w: f64, h: f64| Rect {
            x: 0.0,
            y: 0.0,
            w,
            h,
        };
        assert!(shows_label(&rect(400.0, 300.0)));
        assert!(shows_label(&rect(90.0, 70.0)));
        // Below the plan's floor, in either direction.
        assert!(!shows_label(&rect(89.9, 300.0)));
        assert!(!shows_label(&rect(30.0, 300.0)));
        assert!(!shows_label(&rect(300.0, 39.9)));
        // Over the floor, but not high enough for two lines at the smallest size.
        assert!(!shows_label(&rect(90.0, 40.0)));
        assert!(!shows_label(&rect(300.0, 60.0)));
    }

    #[test]
    fn label_sizes_grow_with_the_tile_within_limits() {
        let size = |w: f64, h: f64| {
            label_sizes(&Rect {
                x: 0.0,
                y: 0.0,
                w,
                h,
            })
        };
        let (small, small_counts) = size(90.0, 70.0);
        assert!(near(small, NAME_SIZES.0) && small_counts < small);
        let (mid, _) = size(200.0, 125.0);
        assert!(near(mid, 25.0));
        let (big, _) = size(900.0, 400.0);
        assert!(near(big, NAME_SIZES.1));
    }

    #[test]
    fn a_tile_takes_the_colour_of_the_group_of_the_kind_found_most() {
        assert_eq!(kind_color(&[(EntityKind::Person, 1)]), GROUP_COLORS[0]);
        assert_eq!(kind_color(&[(EntityKind::Email, 9)]), GROUP_COLORS[1]);
        assert_eq!(kind_color(&[(EntityKind::Iban, 2)]), GROUP_COLORS[3]);
        assert_eq!(kind_color(&[(EntityKind::Secret, 2)]), GROUP_COLORS[6]);
        assert_eq!(kind_color(&[(EntityKind::HealthData, 2)]), GROUP_COLORS[8]);
        // The most found wins, not the first listed.
        assert_eq!(
            kind_color(&[(EntityKind::Email, 2), (EntityKind::Iban, 7)]),
            GROUP_COLORS[3]
        );
        // A tie goes to the first.
        assert_eq!(
            kind_color(&[(EntityKind::Iban, 5), (EntityKind::Email, 5)]),
            GROUP_COLORS[3]
        );
        assert_eq!(kind_color(&[]), NEUTRAL);
    }

    #[test]
    fn every_kind_has_a_group_colour() {
        assert_eq!(GROUP_COLORS.len(), KIND_GROUPS.len());
        for kind in EntityKind::ALL {
            assert!(group_index(kind).is_some(), "{kind:?} is in no group");
        }
    }

    #[test]
    fn blending_moves_each_channel_towards_the_other_colour() {
        assert_eq!(blend(BLACK, WHITE, 0), BLACK);
        assert_eq!(blend(BLACK, WHITE, 100), WHITE);
        assert_eq!(blend(BLACK, WHITE, 50), Color::rgb(127, 127, 127));
        assert_eq!(blend(BLACK, WHITE, 250), WHITE);
    }

    #[test]
    fn the_side_panel_lists_the_eight_kinds_found_most() {
        let counts: Vec<(EntityKind, u32)> =
            EntityKind::ALL.into_iter().take(12).zip(1..).collect();
        let top = top_kinds(counts.iter().copied());
        assert_eq!(top.len(), SIDE_KINDS);
        assert!(top.windows(2).all(|pair| pair[0].1 >= pair[1].1));
        assert_eq!(top[0].1, 12);
        // The counts of one kind, from several nodes, are added up.
        let merged = top_kinds([
            (EntityKind::Email, 2),
            (EntityKind::Iban, 3),
            (EntityKind::Email, 4),
        ]);
        assert_eq!(merged, [(EntityKind::Email, 6), (EntityKind::Iban, 3)]);
    }

    #[test]
    fn the_way_up_starts_at_this_pc_and_folds_the_watched_folder_into_one_crumb() {
        let roots = roots(&[r"C:\Users\me\Documents"]);
        let top = crumbs(Path::new(""), &roots);
        assert_eq!(labels(&top), ["This PC"]);
        assert_eq!(targets(&top), [Path::new("")]);

        let deep = crumbs(Path::new(r"C:\Users\me\Documents\Taxes\2024"), &roots);
        assert_eq!(labels(&deep), ["This PC", "Documents", "Taxes", "2024"]);
        assert_eq!(
            targets(&deep),
            [
                Path::new(""),
                Path::new(r"C:\Users\me\Documents"),
                Path::new(r"C:\Users\me\Documents\Taxes"),
                Path::new(r"C:\Users\me\Documents\Taxes\2024"),
            ]
        );

        let at_root = crumbs(Path::new(r"C:\Users\me\Documents"), &roots);
        assert_eq!(labels(&at_root), ["This PC", "Documents"]);
    }

    #[test]
    fn the_deepest_watched_folder_names_the_first_crumb() {
        let roots = roots(&[r"C:\Users\me", r"C:\Users\me\Documents"]);
        let trail = crumbs(Path::new(r"C:\Users\me\Documents\Taxes"), &roots);
        assert_eq!(labels(&trail), ["This PC", "Documents", "Taxes"]);
        let trail = crumbs(Path::new(r"C:\Users\me\Pictures"), &roots);
        assert_eq!(labels(&trail), ["This PC", "me", "Pictures"]);
    }

    #[test]
    fn watched_folders_match_without_regard_to_case() {
        let roots = roots(&[r"C:\Users\Me\Documents"]);
        let trail = crumbs(Path::new(r"c:\users\me\documents\x"), &roots);
        assert_eq!(labels(&trail), ["This PC", "Documents", "x"]);
        assert_eq!(trail[1].target, Path::new(r"C:\Users\Me\Documents"));
    }

    #[test]
    fn without_a_watched_folder_every_component_is_a_crumb_and_the_drive_is_one() {
        let trail = crumbs(
            Path::new(r"C:\Temp\pk"),
            &roots(&[r"C:\Users\me\Documents"]),
        );
        assert_eq!(labels(&trail), ["This PC", r"C:\", "Temp", "pk"]);
        assert_eq!(
            targets(&trail),
            [
                Path::new(""),
                Path::new(r"C:\"),
                Path::new(r"C:\Temp"),
                Path::new(r"C:\Temp\pk"),
            ]
        );
    }

    #[test]
    fn the_selected_tile_is_the_one_the_panel_shows() {
        let file = TileOf::Node(PathBuf::from(r"C:\Data\a.txt"));
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\a.txt"));
        let other = Selection::Node(PathBuf::from(r"C:\Data\b.txt"));
        assert!(is_selected(&file, Some(&chosen)));
        assert!(!is_selected(&file, Some(&other)));
        assert!(!is_selected(&file, Some(&Selection::More)));
        assert!(!is_selected(&file, None));
        assert!(is_selected(&TileOf::More, Some(&Selection::More)));
        assert!(!is_selected(&TileOf::More, Some(&chosen)));
    }

    #[test]
    fn with_nothing_selected_the_panel_describes_the_folder_on_show() {
        let view = view_of(vec![
            node("a.txt", 10, EntityKind::Email),
            node("b.txt", 5, EntityKind::Iban),
        ]);
        let top = panel(&view, Path::new(""), None, true);
        assert_eq!(top.title, "This PC");
        assert_eq!(top.summary, "15 values in 2 files");
        assert_eq!(top.kinds, [(EntityKind::Email, 10), (EntityKind::Iban, 5)]);
        assert_eq!(top.target, None);
        assert_eq!(top.buttons, Buttons::All);
        assert_eq!(
            panel(&view, Path::new(""), None, false).buttons,
            Buttons::None
        );

        let folder = panel(&view, Path::new(r"C:\Data"), None, false);
        assert_eq!(folder.title, "Data");
        assert_eq!(folder.detail, r"C:\Data");
        assert_eq!(folder.target, Some(Path::new(r"C:\Data")));
        assert_eq!(folder.buttons, Buttons::Folder);
    }

    #[test]
    fn a_selected_file_gets_the_file_buttons_and_its_scan_time() {
        let mut view = view_of(vec![node("id.pdf", 4, EntityKind::Iban)]);
        view.entry = Some(entry(
            r"C:\Data\id.pdf",
            Status::Ok,
            vec![(EntityKind::Iban, 4)],
        ));
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\id.pdf"));
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.title, "id.pdf");
        assert_eq!(panel.summary, "4 values in 1 file");
        assert_eq!(panel.kinds, [(EntityKind::Iban, 4)]);
        assert_eq!(panel.scanned, Some(1_700_000_000));
        assert_eq!(panel.target, Some(Path::new(r"C:\Data\id.pdf")));
        assert_eq!(panel.buttons, Buttons::File);
    }

    #[test]
    fn a_selected_folder_tile_gets_no_file_buttons() {
        let mut folder = node("Taxes", 9, EntityKind::Iban);
        folder.is_dir = true;
        folder.files = 3;
        let view = view_of(vec![folder]);
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\Taxes"));
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.summary, "9 values in 3 files");
        assert_eq!(panel.buttons, Buttons::Folder);
        assert_eq!(panel.scanned, None);
    }

    #[test]
    fn the_other_scans_node_shows_its_numbers_without_buttons() {
        let other = Node {
            path: PathBuf::new(),
            name: "Other scans".to_owned(),
            is_dir: true,
            hits: 7,
            files: 2,
            counts: vec![(EntityKind::Email, 7)],
        };
        let view = view_of(vec![other]);
        let chosen = Selection::Node(PathBuf::new());
        let panel = panel(&view, Path::new(""), Some(&chosen), true);
        assert_eq!(panel.title, "Other scans");
        assert_eq!(panel.summary, "7 values in 2 files");
        assert_eq!(panel.target, None);
        assert_eq!(panel.buttons, Buttons::None);
    }

    #[test]
    fn a_selected_file_without_findings_says_so() {
        let mut view = view_of(vec![node("other.txt", 2, EntityKind::Email)]);
        view.entry = Some(entry(r"C:\Data\clean.txt", Status::Ok, Vec::new()));
        let chosen = Selection::Node(PathBuf::from(r"C:\Data\clean.txt"));
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.title, "clean.txt");
        assert_eq!(panel.summary, "No personal data found.");
        assert_eq!(panel.buttons, Buttons::File);
        assert_eq!(panel.target, Some(Path::new(r"C:\Data\clean.txt")));

        // The entry of another file is not this file's.
        view.entry = Some(entry(r"C:\Data\other.txt", Status::Ok, Vec::new()));
        let panel = super::panel(&view, Path::new(r"C:\Data"), Some(&chosen), true);
        assert_eq!(panel.summary, "No scan of this file yet.");
    }

    #[test]
    fn a_file_that_could_not_be_scanned_says_why() {
        let too_large = entry(r"C:\Data\disk.img", Status::TooLarge, Vec::new());
        assert!(entry_summary(&too_large).contains("64 MB"));
        let failed = entry(
            r"C:\Data\a.docx",
            Status::Failed("bad zip".to_owned()),
            Vec::new(),
        );
        assert_eq!(entry_summary(&failed), "Could not be scanned: bad zip");
        let unsupported = entry(r"C:\Data\a.bin", Status::Unsupported, Vec::new());
        assert_eq!(
            entry_summary(&unsupported),
            "piikey cannot read this kind of file."
        );
    }

    #[test]
    fn the_more_tile_selects_the_nodes_without_a_tile() {
        let more = Selection::More;
        let all = nodes(MAX_TILES + 2);
        let view = view_of(all.clone());
        let panel = panel(&view, Path::new(r"C:\Data"), Some(&more), true);
        assert_eq!(panel.title, "+2 more");
        assert_eq!(panel.rest, &all[MAX_TILES..]);
        assert_eq!(panel.buttons, Buttons::None);
        assert_eq!(panel.target, None);

        // With no node beyond the tiles there is nothing for it to select.
        let view = view_of(nodes(MAX_TILES));
        let panel = super::panel(&view, Path::new(r"C:\Data"), Some(&more), true);
        assert_eq!(panel.title, "Data");
        assert!(panel.rest.is_empty());
    }

    #[test]
    fn the_armed_wipe_button_names_what_it_will_remove_in_the_right_number() {
        assert_eq!(wipe_armed_text(1), "Click again to wipe the record");
        assert_eq!(wipe_armed_text(2), "Click again to wipe all 2 records");
        assert_eq!(
            wipe_armed_text(12_345),
            "Click again to wipe all 12,345 records"
        );
    }
}
