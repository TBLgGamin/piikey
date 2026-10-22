//! The first-run screen, shown instead of the pages while the detection model downloads.

use windows_reactor::{
    Button, ButtonStyle, HorizontalAlignment, Image, InfoBarSeverity, Orientation, ProgressBar,
    RichText, RichTextBlock, RichTextInline, RichTextRun, StackPanel, Stretch, TextAlignment,
    TextWrapping, VerticalAlignment, View,
};

use super::kit::{Context, body, caption, info, subtitle};
use crate::ui::{
    assets,
    controller::Model,
    window::{MainWindow, Msg},
};

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

/// Whole megabytes, rounded, as the download's progress says them.
const fn megabytes(bytes: u64) -> u64 {
    bytes.saturating_add(500_000) / 1_000_000
}

/// The first-run screen: the model download's progress, or why it failed.
pub fn screen(window: &MainWindow, context: Context<'_>) -> StackPanel {
    let mut children: Vec<View> = vec![
        Image::new()
            .source_svg(assets::stacked(window.dark))
            .stretch(Stretch::Uniform)
            .height(120.0)
            .into(),
        subtitle("Getting piikey ready")
            .horizontal_alignment(HorizontalAlignment::Center)
            .into(),
        body("piikey downloads the detection model once. It finds names and addresses on this PC, and nothing about you leaves it.")
            .text_alignment(TextAlignment::Center)
            .opacity(0.72)
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
                caption(format!("{} MB of {} MB", megabytes(done), megabytes(total)))
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
