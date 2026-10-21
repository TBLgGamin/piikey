//! Email: `.eml` messages (and, through [`render`], Outlook `.msg` files)
//! rendered as text, attachments processed recursively.
//!
//! The rendering is `From`/`To`/`Cc`/`Bcc`/`Reply-To`, `Subject`, `Date`, a
//! blank line and the text bodies, then each attachment under an
//! `--- attachment: NAME ---` line. Rebuilding MIME byte for byte would add a
//! lot of code for little value, so the output is text.

use std::{borrow::Cow, fmt::Write as _};

use mail_parser::{Address, DateTime, MessageParser, MimeHeaders};

use super::{MAX_DEPTH, Output, Pass, process_pass as process_any, same_text};
use crate::{Error, Result};

/// Shown for an attachment without a file name.
pub(super) const UNNAMED: &str = "attachment";

/// A message reduced to what is rendered.
#[derive(Debug, Default)]
pub(super) struct Mail<'a> {
    pub(super) from: Vec<String>,
    pub(super) to: Vec<String>,
    pub(super) cc: Vec<String>,
    pub(super) bcc: Vec<String>,
    pub(super) reply_to: Vec<String>,
    pub(super) subject: Option<String>,
    pub(super) date: Option<String>,
    pub(super) bodies: Vec<String>,
    pub(super) attachments: Vec<Attachment<'a>>,
}

#[derive(Debug)]
pub(super) struct Attachment<'a> {
    pub(super) name: String,
    pub(super) content: Content<'a>,
}

/// What an attachment holds.
#[derive(Debug)]
pub(super) enum Content<'a> {
    /// A file of its own, of any format.
    Bytes(Cow<'a, [u8]>),
    /// A message that is already read (an embedded message of a `.msg`).
    Message(Mail<'a>),
}

/// Renders an `.eml` message.
pub(super) fn process(pass: &Pass<'_>, bytes: &[u8], depth: u8) -> Result<Output> {
    let message = MessageParser::default()
        .parse(bytes)
        .ok_or_else(|| Error::Mail("unparseable message".into()))?;
    let mail = Mail {
        from: addresses(message.from()),
        to: addresses(message.to()),
        cc: addresses(message.cc()),
        bcc: addresses(message.bcc()),
        reply_to: addresses(message.reply_to()),
        subject: message.subject().map(str::to_owned),
        date: message.date().map(DateTime::to_rfc822),
        bodies: (0..message.text_body_count())
            .filter_map(|i| message.body_text(i))
            .map(Cow::into_owned)
            .collect(),
        attachments: message
            .attachments()
            .map(|part| Attachment {
                name: part.attachment_name().unwrap_or(UNNAMED).to_owned(),
                content: Content::Bytes(Cow::Borrowed(part.contents())),
            })
            .collect(),
    };
    render(pass, depth, &mail)
}

/// `Name <address>`, or whichever of the two exists.
pub(super) fn display(name: Option<&str>, address: Option<&str>) -> Option<String> {
    match (
        name.filter(|n| !n.is_empty()),
        address.filter(|a| !a.is_empty()),
    ) {
        (Some(name), Some(address)) => Some(format!("{name} <{address}>")),
        (Some(only), None) | (None, Some(only)) => Some(only.to_owned()),
        (None, None) => None,
    }
}

fn addresses(list: Option<&Address<'_>>) -> Vec<String> {
    list.into_iter()
        .flat_map(Address::iter)
        .filter_map(|addr| display(addr.name(), addr.address()))
        .collect()
}

/// Renders `mail` and runs the engine over it.
///
/// One engine call covers the headers, the bodies and the attachment names
/// (a file name can hold PII too). Each attachment is processed by its own
/// recursive [`process_any`] call, and its already-transformed text is
/// appended unchanged.
pub(super) fn render(pass: &Pass<'_>, depth: u8, mail: &Mail<'_>) -> Result<Output> {
    rendered(pass, depth, mail).map(Output::Text)
}

/// [`render`] for the message at `depth`, as text.
fn rendered(pass: &Pass<'_>, depth: u8, mail: &Mail<'_>) -> Result<String> {
    let mut head = String::new();
    for (label, list) in [
        ("From", &mail.from),
        ("To", &mail.to),
        ("Cc", &mail.cc),
        ("Bcc", &mail.bcc),
        ("Reply-To", &mail.reply_to),
    ] {
        if !list.is_empty() {
            let _ = writeln!(head, "{label}: {}", list.join(", "));
        }
    }
    if let Some(subject) = &mail.subject {
        let _ = writeln!(head, "Subject: {subject}");
    }
    if let Some(date) = &mail.date {
        let _ = writeln!(head, "Date: {date}");
    }
    head.push('\n');
    for body in &mail.bodies {
        head.push_str(body);
        if !body.ends_with('\n') {
            head.push('\n');
        }
    }

    let mut texts = vec![head.as_str()];
    texts.extend(mail.attachments.iter().map(|a| a.name.as_str()));
    let mut done = pass.run(&texts)?.into_iter();
    let mut out = done.next().unwrap_or_default();
    // One after the other: a scan reports what it found in reading order.
    for (attachment, name) in mail.attachments.iter().zip(done) {
        let body = attachment_text(pass, depth, &attachment.content)?;
        let _ = write!(out, "\n--- attachment: {name} ---\n{body}");
    }
    Ok(out)
}

/// The transformed text of one attachment of the message at `depth`; it sits one level
/// deeper. Attachments that cannot be read render as `[unsupported: …]`; failures of the
/// engine itself still fail the whole message.
fn attachment_text(pass: &Pass<'_>, depth: u8, content: &Content<'_>) -> Result<String> {
    let depth = depth.saturating_add(1);
    let text = match content {
        Content::Bytes(data) => match process_any(pass, data, depth) {
            Ok(Output::Text(text)) => Ok(text),
            Ok(Output::Same(bytes)) => same_text(&bytes),
            Err(e) => Err(e),
        },
        // Same limit as `process_pass` puts on byte attachments.
        Content::Message(_) if depth > MAX_DEPTH => {
            Err(Error::UnsupportedFormat("nesting too deep"))
        }
        Content::Message(mail) => rendered(pass, depth, mail),
    };
    match text {
        Err(e) if e.is_unreadable() => Ok(format!("[unsupported: {e}]")),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_joins_name_and_address() {
        assert_eq!(
            display(Some("Jan"), Some("jan@x.nl")).as_deref(),
            Some("Jan <jan@x.nl>")
        );
        assert_eq!(display(None, Some("jan@x.nl")).as_deref(), Some("jan@x.nl"));
        assert_eq!(display(Some("Jan"), None).as_deref(), Some("Jan"));
        assert_eq!(display(Some(""), Some("")), None);
    }
}
