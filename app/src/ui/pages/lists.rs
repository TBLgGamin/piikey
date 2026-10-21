//! The cards of Settings that edit a list: sites, programs, the kinds piikey looks for, and the
//! folders the inventory scans or leaves out.

use std::{path::PathBuf, rc::Rc};

use piikey::{detect::KIND_GROUPS, policy::PRESETS};
use windows_reactor::{
    Button, ButtonStyle, CheckBox, DataItem, Expander, Grid, GridLength, HorizontalAlignment,
    ListView, ListViewSelectionMode, StackPanel, TextBlock, TextBox, TextTrimming, Thickness, View,
};

use super::{Context, ROW, caption, card, heading, list_height};
use crate::ui::window::{MainWindow, Msg};

/// A list of `items` that cannot be selected, `height` DIPs high.
fn plain_list(height: f64, items: impl IntoIterator<Item = DataItem>) -> ListView {
    ListView::new()
        .selection_mode(ListViewSelectionMode::None)
        .height(height)
        .items(items)
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
pub(super) fn sites_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let presets = plain_list(
        list_height(PRESETS.len()),
        PRESETS.iter().map(|&preset| {
            let site = preset.to_owned();
            check_row(
                format!("preset:{preset}"),
                preset,
                policy.sites.iter().any(|s| s == preset),
                move |on| Msg::Site(site.clone(), on),
                context,
            )
        }),
    );
    let custom: Vec<&String> = policy
        .sites
        .iter()
        .filter(|site| !PRESETS.contains(&site.as_str()))
        .collect();
    let custom: View = if custom.is_empty() {
        caption("No other sites yet.").into()
    } else {
        plain_list(
            list_height(custom.len()),
            custom.iter().map(|site| {
                remove_row(
                    format!("site:{site}"),
                    site,
                    Msg::Site((*site).clone(), false),
                    context,
                )
            }),
        )
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
pub(super) fn programs_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let mut programs: Vec<&str> = window
        .processes
        .iter()
        .chain(&policy.programs)
        .map(String::as_str)
        .collect();
    programs.sort_unstable();
    programs.dedup();
    let list = plain_list(
        ROW * 7.0,
        programs.iter().map(|&exe| {
            let owned = exe.to_owned();
            check_row(
                format!("program:{exe}"),
                exe,
                policy.programs.iter().any(|p| p == exe),
                move |on| Msg::Program(owned.clone(), on),
                context,
            )
        }),
    );
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
pub(super) fn kinds_card(window: &MainWindow, context: Context<'_>) -> View {
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
        let list = plain_list(
            list_height(kinds.len()),
            kinds.iter().map(|&kind| {
                check_row(
                    format!("kind:{}", kind.as_str()),
                    kind.label(),
                    !disabled.contains(&kind),
                    move |on| Msg::Kind(kind, on),
                    context,
                )
            }),
        );
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

/// A list of paths with a remove button each, or `empty` when there are none; `key` and `remove`
/// make the row of a path.
fn path_list(
    paths: &[PathBuf],
    key: &str,
    empty: &str,
    remove: impl Fn(PathBuf) -> Msg,
    context: Context<'_>,
) -> View {
    if paths.is_empty() {
        return caption(empty).into();
    }
    plain_list(
        list_height(paths.len()),
        paths.iter().map(|path| {
            remove_row(
                format!("{key}:{}", path.display()),
                &path.display().to_string(),
                remove(path.clone()),
                context,
            )
        }),
    )
    .into()
}

/// The folders the inventory scans, with a box to add one.
pub(super) fn folders_card(window: &MainWindow, context: Context<'_>) -> View {
    card(StackPanel::new().spacing(8.0).children((
        heading("Folders to scan"),
        caption("The inventory looks through these folders and everything in them."),
        path_list(
            &window.snap.policy.inventory_roots,
            "root",
            "None chosen: switching the inventory on scans your Documents, Desktop and Downloads.",
            |path| Msg::Root(path, false),
            context,
        ),
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
pub(super) fn left_out_card(window: &MainWindow, context: Context<'_>) -> View {
    card(
        StackPanel::new().spacing(8.0).children((
            heading("Left out"),
            caption("The inventory skips these files and folders, and everything in them. To add one, choose Exclude on the map on Home."),
            path_list(
                &window.snap.policy.inventory_exclude,
                "exclude",
                "Nothing is left out.",
                |path| Msg::Exclude(path, false),
                context,
            ),
        )),
    )
    .into()
}
