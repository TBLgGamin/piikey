//! Settings: what changes the app or the engine all the jobs share. One scrolling page.

use piikey::{
    api::{http, reply::Device},
    detect::KIND_GROUPS,
    service::default_pipe,
};
use windows_reactor::{
    Button, Expander, HorizontalAlignment, HyperlinkButton, Image, Orientation, StackPanel,
    Stretch, TextBlock, View,
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
        section("Detection", detection(window, context)),
        section("Types of personal data", kinds(window, context)),
        section("Developer access", developer(window, context)),
        section("Privacy & data", privacy(window, context)),
        section("About", vec![about(window)]),
    ])
}

/// The state of the detection model in words.
fn model_state(model: &Model) -> &'static str {
    match model {
        Model::Ready => "Model ready",
        Model::Skipped => "Patterns only (model skipped)",
        Model::Failed(_) => "Model failed",
        Model::Downloading { .. } => "Downloading\u{2026}",
    }
}

/// Where the model runs, or what decides it while that is not known yet.
fn device_text(device: Option<&Device>) -> &'static str {
    match device {
        Some(Device::Cpu) => "Runs on CPU",
        Some(Device::Hybrid) => "Runs on CPU and GPU",
        None => "The device is chosen the first time the model loads.",
    }
}

/// The button that fetches the model again: only after a skip or a failure.
fn model_retry(model: &Model) -> Option<&'static str> {
    match model {
        Model::Skipped => Some("Download model"),
        Model::Failed(_) => Some("Try again"),
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
        Row::new("Closing the window")
            .icon("\u{E946}")
            .description("Keeps piikey running in the tray while protection, highlighting, the inventory or the API is on.")
            .build(),
    ]
}

fn detection(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let model = &window.snap.model;
    let mut row = Row::new("Detection model")
        .icon("\u{E9D9}")
        .description(device_text(window.device.as_ref()))
        .state(model_state(model));
    if let Some(label) = model_retry(model) {
        row = row.control(
            Button::new()
                .content(label)
                .on_click(context.message(Msg::RetryModel)),
        );
    }
    vec![
        row.build(),
        caption("Used by Masking, Highlighting and Inventory.").into(),
    ]
}

fn kinds(window: &MainWindow, context: Context<'_>) -> Vec<View> {
    let disabled = &window.snap.policy.disabled_kinds;
    let mut rows: Vec<View> = vec![
        caption(
            "Applies to masking, highlighting, scans and the inventory. Everything is on by default. Turning a type off only affects new text; values piikey already swapped still turn back.",
        )
        .into(),
    ];
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
            .description("Lets your scripts call piikey at 127.0.0.1 with a token. The command line and the named pipe work without it.")
            .control(feature_switch(
                "Local HTTP API",
                policy.http_api,
                Msg::HttpApi,
                context,
            ))
            .build(),
        Row::new("Address")
            .description(http::url(policy.http_port))
            .selectable()
            .state(if window.snap.http { "Listening" } else { "Off" })
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
        Row::new("Named pipe")
            .icon("\u{E756}")
            .description(default_pipe())
            .selectable()
            .build(),
        Row::new("Command line")
            .description("piikey-cli runs in a terminal and works without the HTTP API.")
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
            .selectable()
            .control(
                Button::new()
                    .content("Open folder")
                    .on_click(context.message(Msg::OpenDataFolder)),
            )
            .build(),
        caption("Settings, the encrypted vault, the activity feed, the inventory, the certificate and the detection model are kept in this folder. The inventory holds counts and paths, never the values.").into(),
        HyperlinkButton::new()
            .content("Export or wipe the vault")
            .on_click(context.message(Msg::Nav(Page::Vault)))
            .into(),
        HyperlinkButton::new()
            .content("Export the inventory report")
            .on_click(context.message(Msg::Nav(Page::Inventory)))
            .into(),
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
    fn model_state_names_each_model() {
        assert_eq!(model_state(&Model::Ready), "Model ready");
        assert_eq!(
            model_state(&Model::Skipped),
            "Patterns only (model skipped)"
        );
        assert_eq!(model_state(&Model::Failed(String::new())), "Model failed");
        assert_eq!(
            model_state(&Model::Downloading { done: 0, total: 1 }),
            "Downloading\u{2026}"
        );
    }

    #[test]
    fn retry_only_after_skip_or_failure() {
        assert_eq!(model_retry(&Model::Skipped), Some("Download model"));
        assert_eq!(
            model_retry(&Model::Failed(String::new())),
            Some("Try again")
        );
        assert_eq!(model_retry(&Model::Ready), None);
    }

    #[test]
    fn device_text_covers_each_device() {
        assert_eq!(device_text(Some(&Device::Cpu)), "Runs on CPU");
        assert_eq!(device_text(Some(&Device::Hybrid)), "Runs on CPU and GPU");
        assert!(device_text(None).contains("first time"));
    }

    #[test]
    fn group_header_counts_types_on() {
        assert_eq!(group_header("Contact", 3, 5), "Contact (3/5)");
    }
}
