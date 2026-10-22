//! Protection: what piikey keeps from leaving, and where: the master switch, the certificate, the
//! protected sites and apps, and the highlighting of personal data as you type.

use piikey::policy::{Highlight, PRESETS};
use windows_reactor::{ComboBox, StackPanel, View};

use super::{
    kit::{
        Context, Row, attention, caption, card, column, form_error, page_header, protection_switch,
        section,
    },
    lists::{ROW, add_row, check_row, list_height, plain_list, remove_row},
};
use crate::ui::{
    controller::Cert,
    status::{Cause, Status},
    window::{MainWindow, Msg, Page},
};

/// What the page is, in a sentence.
const DEFINITION: &str = "Swaps personal data for stand-ins in what you send to your protected sites and apps, and turns it back in the replies.";

/// The choices of when the field in focus is outlined, with their words.
const HIGHLIGHTS: [(Highlight, &str); 3] = [
    (Highlight::Off, "Off"),
    (Highlight::Always, "Always"),
    (Highlight::Hotkey, "When I press Ctrl+Alt+P"),
];

pub(super) fn protection(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let mut children: Vec<View> = vec![page_header(
        Page::Protection.title(),
        DEFINITION,
        [View::from(protection_switch(status, context))],
    )];
    children.extend(form_error(window, context));
    children.push(certificate(window, context));
    children.push(section(
        "Protected sites",
        vec![
            caption("Only traffic to the sites you tick, and from the apps you tick below, is read and swapped. Everything else passes through untouched.").into(),
            sites_card(window, context),
        ],
    ));
    children.push(section(
        "Protected apps",
        vec![
            caption("Every site a ticked app visits is protected. Works for apps that follow the Windows proxy settings: browsers, Electron apps, .NET apps, curl. The list refreshes every few seconds.").into(),
            apps_card(window, context),
        ],
    ));
    children.push(highlighting(window, status, context));
    column(children)
}

/// Whether Windows trusts the certificate masking needs, with the fix when it does not.
fn certificate(window: &MainWindow, context: Context<'_>) -> View {
    let row = match window.snap.cert {
        Cert::Installed => Row::new("Certificate installed")
            .icon("\u{E8D7}")
            .description("Windows trusts the piikey certificate, so piikey can read the HTTPS traffic of your protected sites and apps.")
            .build(),
        Cert::Missing => attention(window, &Cause::CertificateMissing, context),
        Cert::Unknown => Row::new("Certificate")
            .icon("\u{E8D7}")
            .description("Checking whether Windows trusts the piikey certificate\u{2026}")
            .build(),
    };
    section("Certificate", vec![row])
}

/// The preset sites with check boxes, then the sites the user added with a remove button each.
fn sites_card(window: &MainWindow, context: Context<'_>) -> View {
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
    card(StackPanel::new().spacing(8.0).children((
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
    )))
    .into()
}

/// The running apps and the configured ones, sorted and without repeats.
fn app_names<'a>(running: &'a [String], configured: &'a [String]) -> Vec<&'a str> {
    let mut apps: Vec<&str> = running
        .iter()
        .chain(configured)
        .map(String::as_str)
        .collect();
    apps.sort_unstable();
    apps.dedup();
    apps
}

/// Running apps, plus any configured app that is not running now, with check boxes.
fn apps_card(window: &MainWindow, context: Context<'_>) -> View {
    let policy = &window.snap.policy;
    let list = plain_list(
        ROW * 7.0,
        app_names(&window.apps, &policy.programs)
            .into_iter()
            .map(|exe| {
                let owned = exe.to_owned();
                check_row(
                    format!("app:{exe}"),
                    exe,
                    policy.programs.iter().any(|p| p == exe),
                    move |on| Msg::App(owned.clone(), on),
                    context,
                )
            }),
    );
    card(StackPanel::new().spacing(8.0).children((
        list,
        add_row(
            "Another app, e.g. chrome.exe",
            &window.app_draft,
            "Add app",
            Msg::AppDraft,
            Msg::AddApp,
            context,
        ),
    )))
    .into()
}

/// What the state line says when the highlighting is paused, which the choice itself does not: in
/// Always mode the shortcut pauses it and brings it back.
fn paused_text(mode: Highlight, paused: bool) -> Option<&'static str> {
    (mode == Highlight::Always && paused).then_some("Paused: Ctrl+Alt+P resumes it")
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

/// The highlighting of personal data in the field you type in.
fn highlighting(window: &MainWindow, status: &Status, context: Context<'_>) -> View {
    let mode = window.snap.policy.highlight;
    let mut row = Row::new("Highlight personal data as you type")
        .icon("\u{E7B3}")
        .description("Outlines the field you type in when it holds personal data, in any app. Nothing leaves your PC.")
        .control(highlight_choice(window, context));
    if let Some(state) = paused_text(mode, window.snap.highlight_paused) {
        row = row.state(state);
    }
    let mut rows: Vec<View> = vec![row.build()];
    if !status.is_on() && mode == Highlight::Off {
        rows.push(caption("Try highlighting before you turn masking on.").into());
    }
    section("Highlighting", rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_are_sorted_and_deduped() {
        let running = vec!["b.exe".to_owned(), "a.exe".to_owned()];
        let configured = vec!["b.exe".to_owned(), "c.exe".to_owned()];
        assert_eq!(
            app_names(&running, &configured),
            ["a.exe", "b.exe", "c.exe"]
        );
    }

    #[test]
    fn a_pause_is_said_only_where_the_shortcut_pauses() {
        assert_eq!(
            paused_text(Highlight::Always, true),
            Some("Paused: Ctrl+Alt+P resumes it")
        );
        assert_eq!(paused_text(Highlight::Always, false), None);
        assert_eq!(paused_text(Highlight::Hotkey, true), None);
        assert_eq!(paused_text(Highlight::Off, true), None);
    }
}
