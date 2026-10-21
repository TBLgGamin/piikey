//! Outlook `.msg` files (compound files), rendered as text like `.eml`.
//!
//! Strings come from the UTF-16LE (`001F`) streams, falling back to the ANSI
//! (`001E`) ones; streams that are missing are skipped. Attachments that are
//! embedded messages (a storage, not a stream) are not read.

use std::{
    borrow::Cow,
    io::{Cursor, Read},
};

use cfb::CompoundFile;

use super::{
    Output, Pass,
    eml::{Attachment, Mail, display, render},
    text,
};
use crate::{Error, Result};

type Cfb<'a> = CompoundFile<Cursor<&'a [u8]>>;

/// Present in every `.msg`, absent in `.doc`/`.xls`/`.ppt`.
const PROPERTIES: &str = "/__properties_version1.0";
const RECIPIENT_PREFIX: &str = "__recip_version1.0_#";
const ATTACHMENT_PREFIX: &str = "__attach_version1.0_#";
/// `PidTagRecipientType` as stored in a property stream: type `0x0003` (long), id `0x0C15`.
const RECIPIENT_TYPE_TAG: u32 = 0x0C15_0003;
const RECIPIENT_TO: u32 = 1;
const RECIPIENT_CC: u32 = 2;
const RECIPIENT_BCC: u32 = 3;
/// Property streams of recipients and attachments: 8 reserved bytes, then
/// 16-byte entries (tag, flags, 8 value bytes).
const PROPERTY_HEADER: usize = 8;
const PROPERTY_ENTRY: usize = 16;
const UNNAMED: &str = "attachment";

pub(super) fn process(pass: &Pass<'_>, bytes: &[u8], depth: u8) -> Result<Output> {
    let mut file = CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| Error::Mail(format!("compound file: {e}")))?;
    if !file.is_stream(PROPERTIES) {
        return Err(Error::UnsupportedFormat(
            "legacy binary Office (.doc/.xls/.ppt)",
        ));
    }

    let mut mail = Mail::default();
    let sender_name = string(&mut file, "", "0C1A");
    let sender_address = string(&mut file, "", "5D01").or_else(|| string(&mut file, "", "0C1F"));
    mail.from = display(sender_name.as_deref(), sender_address.as_deref())
        .into_iter()
        .collect();
    mail.subject = string(&mut file, "", "0037");
    mail.bodies = string(&mut file, "", "1000").into_iter().collect();

    for dir in storages(&file, RECIPIENT_PREFIX) {
        let name = string(&mut file, &dir, "3001");
        let address = string(&mut file, &dir, "39FE").or_else(|| string(&mut file, &dir, "3003"));
        let Some(who) = display(name.as_deref(), address.as_deref()) else {
            continue;
        };
        match recipient_type(&mut file, &dir) {
            RECIPIENT_CC => mail.cc.push(who),
            RECIPIENT_BCC => mail.bcc.push(who),
            _ => mail.to.push(who),
        }
    }

    for dir in storages(&file, ATTACHMENT_PREFIX) {
        let Some(data) = stream(&mut file, &format!("{dir}/__substg1.0_37010102")) else {
            continue;
        };
        let name = string(&mut file, &dir, "3707")
            .or_else(|| string(&mut file, &dir, "3704"))
            .unwrap_or_else(|| UNNAMED.to_owned());
        mail.attachments.push(Attachment {
            name,
            data: Cow::Owned(data),
        });
    }
    render(pass, depth, &mail)
}

/// Paths (`/NAME`) of the root storages whose names start with `prefix`, in name order.
fn storages(file: &Cfb<'_>, prefix: &str) -> Vec<String> {
    let mut paths: Vec<String> = file
        .read_root_storage()
        .filter(|entry| entry.is_storage() && entry.name().starts_with(prefix))
        .map(|entry| format!("/{}", entry.name()))
        .collect();
    paths.sort();
    paths
}

fn stream(file: &mut Cfb<'_>, path: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    file.open_stream(path).ok()?.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// The string property `tag` (four hex digits) of storage `dir` (`""` for the root).
fn string(file: &mut Cfb<'_>, dir: &str, tag: &str) -> Option<String> {
    let text = if let Some(bytes) = stream(file, &format!("{dir}/__substg1.0_{tag}001F")) {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let bytes = stream(file, &format!("{dir}/__substg1.0_{tag}001E"))?;
        text::decode(&bytes).ok()?.0.into_owned()
    };
    let text = text.trim_end_matches('\0');
    (!text.is_empty()).then(|| text.to_owned())
}

/// Whether the recipient in storage `dir` is a To, Cc or Bcc; To when unknown.
fn recipient_type(file: &mut Cfb<'_>, dir: &str) -> u32 {
    let Some(props) = stream(file, &format!("{dir}/__properties_version1.0")) else {
        return RECIPIENT_TO;
    };
    props
        .get(PROPERTY_HEADER..)
        .unwrap_or_default()
        .chunks_exact(PROPERTY_ENTRY)
        .find_map(|entry| {
            let (tag, rest) = entry.split_first_chunk::<4>()?;
            let value = rest.get(4..8)?.first_chunk::<4>()?;
            (u32::from_le_bytes(*tag) == RECIPIENT_TYPE_TAG).then(|| u32::from_le_bytes(*value))
        })
        .unwrap_or(RECIPIENT_TO)
}
