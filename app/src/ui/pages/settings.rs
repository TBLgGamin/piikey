//! Settings: what changes the app or the engine all the jobs share. One scrolling page.

use piikey::{api::openapi::REFERENCE_URL, detect::KIND_GROUPS};
use windows_reactor::{
    Button, Expander, HorizontalAlignment, Image, Orientation, StackPanel, Stretch, TextBlock, View,
};

use super::{
    kit::{
        Context, Row, caption, card, column, feature_switch, section, subtitle, title, web_link,
    },
    lists::{check_row, list_height, plain_list},
};
use crate::{
    proxy::PORT,
    ui::{
        assets,
        controller::Model,
        window::{MainWindow, Msg, Page},
    },
};

/// The Settings page: one scrolling column of sections.
pub(super) fn settings(window: &MainWindow, context: Context<'_>) -> View {
    column(vec![
        title(Page::Settings.title()).into(),
        section("General", general(window, context)),
        section("Types of personal data", kinds(window, context)),
        section("Developer access", developer(window, context)),
        section("Privacy & data", privacy(window, context)),
        section("About", vec![about(window)]),
    ])
}

/// What is wrong with the detection model, and the button that fixes it: only a model that was
/// skipped or failed has something to say. A model that is there, or on its way, is not worth a
/// row. Returns the title, what it means and the button's label.
fn model_notice(model: &Model) -> Option<(&'static str, &'static str, &'static str)> {
    match model {
        Model::Skipped => Some((
            "Detection model not installed",
            "Names and addresses are found only by patterns.",
            "Download model",
        )),
        Model::Failed(_) => Some((
            "Detection model failed",
            "Names and addresses are found only by patterns.",
            "Try again",
        )),
        Model::Ready | Model::Downloading { .. } => None,
    }
}

/// The header of a group of types: its name and how many of its types are on.
fn group_header(group: &str, on: usize, total: usize) -> String {
    format!("{group} ({on}/{total})")
}

fn general(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    vec![
        Row::new("Start piikey when I sign in")
            .icon("\u{E7E8}")
            .description("piikey starts in the tray, without its window.")
            .control(
                feature_switch(
                    "Start piikey when I sign in",
                    window.startup.unwrap_or(false),
                    Msg::SetStartup,
                    context,
                )
                .is_enabled(window.startup.is_some()),
            )
            .build(),
        Row::new("Scan for personal data in Explorer")
            .icon("\u{E8B7}")
            .description("Adds it to the right-click menu of files and folders, and shows what they hold in piikey. On Windows 11 it is under Show more options.")
            .control(feature_switch(
                "Scan for personal data in Explorer",
                window.snap.policy.explorer_menu,
                Msg::ExplorerMenu,
                context,
            ))
            .build(),
        Row::new("Keep piikey running in the tray when I close the window")
            .icon("\u{E946}")
            .description("On: protection, highlighting, monitoring and the API keep working with the window closed. Off: closing the window quits piikey.")
            .control(feature_switch(
                "Keep piikey running in the tray when I close the window",
                window.snap.policy.background,
                Msg::Background,
                context,
            ))
            .build(),
    ]
}

fn kinds(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let disabled = &window.snap.policy.disabled_kinds;
    let mut rows: Vec<View> = Vec::new();
    // Only a model that is missing has anything to say, and the button that brings it.
    if let Some((title, meaning, label)) = model_notice(&window.snap.model) {
        rows.push(
            Row::new(title)
                .icon("\u{E9D9}")
                .description(meaning)
                .control(
                    Button::new()
                        .content(label)
                        .on_click(context.message(Msg::RetryModel)),
                )
                .build(),
        );
    }
    rows.push(
        caption(
            "Applies to masking, highlighting, scans and the inventory. Everything is on by default. Turning a type off only affects new text; values piikey already swapped still turn back.",
        )
        .into(),
    );
    rows.extend(KIND_GROUPS.iter().map(|&(group, kinds)| {
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
            .header(TextBlock::new().text(group_header(group, on, kinds.len())))
            .content(list)
            .into()
    }));
    rows
}

fn developer(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let policy = &window.snap.policy;
    let token_text = window.token_note.map_or_else(
        || {
            "Scripts send it as an Authorization: Bearer header. Copy token puts it on the clipboard; New token replaces it, so scripts have to use the new one.".to_owned()
        },
        str::to_owned,
    );
    vec![
        Row::new("Local HTTP API")
            .icon("\u{E943}")
            .description("Lets your scripts call piikey at 127.0.0.1 with a token.")
            .control(feature_switch(
                "Local HTTP API",
                policy.http_api,
                Msg::HttpApi,
                context,
            ))
            .build(),
        Row::new("API reference")
            .icon("\u{E8A5}")
            .description("Every operation, with examples.")
            .control(web_link("Open", REFERENCE_URL))
            .build(),
        Row::new("Token")
            .icon("\u{E8D7}")
            .description(token_text)
            .control(
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
                    )),
            )
            .build(),
    ]
}

fn privacy(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let vault = window.input.controller.vault_path();
    let folder = vault.parent().unwrap_or(vault).display().to_string();
    vec![
        Row::new("Data folder")
            .icon("\u{E8B7}")
            .description(folder)
            .control(
                Button::new()
                    .content("Open folder")
                    .on_click(context.message(Msg::OpenDataFolder)),
            )
            .build(),
        caption("Settings, the encrypted vault, the activity feed, the inventory, the certificate and the detection model are kept in this folder. The inventory holds counts and paths, never the values.").into(),
    ]
}

fn about(window: &MainWindow) -> View {
    let repo = env!("CARGO_PKG_REPOSITORY");
    let proxy = format!(
        "Local proxy: 127.0.0.1:{PORT}, {}",
        if window.snap.enabled {
            "listening"
        } else {
            "stopped"
        }
    );
    card(
        StackPanel::new()
            .orientation(Orientation::Horizontal)
            .spacing(16.0)
            .children((
                Image::new()
                    .source_svg(assets::symbol(window.dark))
                    .stretch(Stretch::Uniform)
                    .width(48.0)
                    .height(48.0),
                StackPanel::new().spacing(8.0).children((
                    subtitle(&format!("piikey {}", env!("CARGO_PKG_VERSION"))),
                    caption(proxy),
                    StackPanel::new()
                        .orientation(Orientation::Horizontal)
                        .spacing(8.0)
                        .children((
                            web_link("Source", repo),
                            web_link("Report an issue", &format!("{repo}/issues")),
                            web_link("License", &format!("{repo}/blob/main/LICENSE")),
                        )),
                )),
            )),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_model_that_is_missing_has_a_row_with_the_button_that_brings_it() {
        let Some((title, meaning, label)) = model_notice(&Model::Skipped) else {
            panic!("a skipped model has a row");
        };
        assert_eq!(title, "Detection model not installed");
        assert!(meaning.contains("only by patterns"));
        assert_eq!(label, "Download model");
        let Some((title, _, label)) = model_notice(&Model::Failed(String::new())) else {
            panic!("a failed model has a row");
        };
        assert_eq!(title, "Detection model failed");
        assert_eq!(label, "Try again");
        assert_eq!(model_notice(&Model::Ready), None);
        assert_eq!(
            model_notice(&Model::Downloading { done: 0, total: 1 }),
            None
        );
    }

    #[test]
    fn group_header_counts_types_on() {
        assert_eq!(group_header("Contact", 3, 5), "Contact (3/5)");
    }
}
