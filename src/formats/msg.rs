//! Outlook `.msg` files (compound files), rendered as text like `.eml`.
//!
//! Strings come from the UTF-16LE (`001F`) streams, falling back to the ANSI
//! (`001E`) ones; streams that are missing are skipped. Attachments are read when
//! they are files (a `__substg1.0_37010102` stream) or embedded messages (a
//! `__substg1.0_3701000D` storage holding its own `__properties_version1.0`,
//! rendered like the message that carries it). Other attachments are skipped
//! with their names: OLE objects, attachments by reference, and anything else
//! without file contents. Only the plain text body (`1000`) is read, not an HTML
//! or RTF one.
//!
//! The streams of a real message never overlap, so together they cannot be longer than the
//! file. A hostile file can point thousands of directory entries at one big sector chain,
//! so every stream's declared length is charged against the file's length before it is
//! read.

use std::{
    borrow::Cow,
    io::{Cursor, Read},
};

use cfb::CompoundFile;

use super::{
    MAX_DEPTH, Output, Pass,
    eml::{Attachment, Content, Mail, UNNAMED, display, render},
    text,
};
use crate::{Error, Result};

type Cfb<'a> = CompoundFile<Cursor<&'a [u8]>>;

/// Present in every `.msg`, absent in `.doc`/`.xls`/`.ppt`.
const PROPERTIES: &str = "__properties_version1.0";
const RECIPIENT_PREFIX: &str = "__recip_version1.0_#";
const ATTACHMENT_PREFIX: &str = "__attach_version1.0_#";
/// The storage of an embedded message inside its attachment.
const EMBEDDED: &str = "__substg1.0_3701000D";
/// The stream of a file attachment.
const ATTACHMENT_DATA: &str = "__substg1.0_37010102";
/// `PidTagRecipientType` as stored in a property stream: type `0x0003` (long), id `0x0C15`.
const RECIPIENT_TYPE_TAG: u32 = 0x0C15_0003;
const RECIPIENT_TO: u32 = 1;
const RECIPIENT_CC: u32 = 2;
const RECIPIENT_BCC: u32 = 3;
/// Property streams of recipients and attachments: 8 reserved bytes, then
/// 16-byte entries (tag, flags, 8 value bytes).
const PROPERTY_HEADER: usize = 8;
const PROPERTY_ENTRY: usize = 16;

pub(super) fn process(pass: &Pass<'_>, bytes: &[u8], depth: u8) -> Result<Output> {
    let limit = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mail = read(bytes, limit, depth)?;
    render(pass, depth, &mail)
}

/// The message in `bytes`, whose streams may add up to `limit` bytes. `depth` is the
/// nesting level of the message.
///
/// # Errors
/// `UnsupportedFormat` for a legacy Office file, `Mail` for a file that is no compound file
/// or whose streams add up to more than `limit`.
pub(super) fn read(bytes: &[u8], limit: u64, depth: u8) -> Result<Mail<'static>> {
    let file = CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| Error::Mail(format!("compound file: {e}")))?;
    if !file.is_stream(format!("/{PROPERTIES}")) {
        return Err(Error::UnsupportedFormat(
            "legacy binary Office (.doc/.xls/.ppt)",
        ));
    }
    Reader {
        file,
        limit,
        left: limit,
    }
    .message("", depth)
}

/// A compound file and how many more stream bytes it may hand out.
struct Reader<'a> {
    file: Cfb<'a>,
    limit: u64,
    left: u64,
}

impl Reader<'_> {
    /// The message stored in storage `dir` (`""` for the root), at nesting level `depth`.
    fn message(&mut self, dir: &str, depth: u8) -> Result<Mail<'static>> {
        let mut mail = Mail {
            // Named after it when the attachment has no name of its own, even if it is too
            // deep to be rendered.
            subject: self.string(dir, "0037")?,
            ..Mail::default()
        };
        // The renderer refuses a message this deep, so the rest is not read. This also
        // bounds the recursion on a file with storages nested without end.
        if depth > MAX_DEPTH {
            return Ok(mail);
        }
        let sender_name = self.string(dir, "0C1A")?;
        let sender_address = self.first_string(dir, &["5D01", "0C1F"])?;
        mail.from = display(sender_name.as_deref(), sender_address.as_deref())
            .into_iter()
            .collect();
        mail.bodies = self.string(dir, "1000")?.into_iter().collect();

        for recipient in self.storages(dir, RECIPIENT_PREFIX) {
            let name = self.string(&recipient, "3001")?;
            let address = self.first_string(&recipient, &["39FE", "3003"])?;
            let Some(who) = display(name.as_deref(), address.as_deref()) else {
                continue;
            };
            match self.recipient_type(&recipient)? {
                RECIPIENT_CC => mail.cc.push(who),
                RECIPIENT_BCC => mail.bcc.push(who),
                _ => mail.to.push(who),
            }
        }

        for storage in self.storages(dir, ATTACHMENT_PREFIX) {
            if let Some(attachment) = self.attachment(&storage, depth)? {
                mail.attachments.push(attachment);
            }
        }
        Ok(mail)
    }

    /// The attachment in storage `dir` of a message at `depth`; `None` when it is neither a
    /// file nor an embedded message.
    fn attachment(&mut self, dir: &str, depth: u8) -> Result<Option<Attachment<'static>>> {
        let content = if let Some(data) = self.stream(&format!("{dir}/{ATTACHMENT_DATA}"))? {
            Content::Bytes(Cow::Owned(data))
        } else {
            // An OLE object is a storage here too, but without message properties.
            let embedded = format!("{dir}/{EMBEDDED}");
            if !self.file.is_stream(format!("{embedded}/{PROPERTIES}")) {
                return Ok(None);
            }
            Content::Message(self.message(&embedded, depth.saturating_add(1))?)
        };
        let name = match (self.first_string(dir, &["3707", "3704"])?, &content) {
            (Some(name), _) => name,
            (
                None,
                Content::Message(Mail {
                    subject: Some(s), ..
                }),
            ) => s.clone(),
            (None, _) => UNNAMED.to_owned(),
        };
        Ok(Some(Attachment { name, content }))
    }

    /// Paths (`DIR/NAME`) of the storages in `dir` whose names start with `prefix`, in name
    /// order. The numbers in the names have a fixed width, so name order is number order.
    fn storages(&self, dir: &str, prefix: &str) -> Vec<String> {
        let listing = if dir.is_empty() {
            Some(self.file.read_root_storage())
        } else {
            self.file.read_storage(dir).ok()
        };
        let mut paths: Vec<String> = listing
            .into_iter()
            .flatten()
            .filter(|entry| entry.is_storage() && entry.name().starts_with(prefix))
            .map(|entry| format!("{dir}/{}", entry.name()))
            .collect();
        paths.sort();
        paths
    }

    /// The stream at `path`, `None` when there is none.
    ///
    /// # Errors
    /// `Mail` when its declared length does not fit in what is left of the budget.
    fn stream(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let Ok(entry) = self.file.entry(path) else {
            return Ok(None);
        };
        if !entry.is_stream() {
            return Ok(None);
        }
        let len = entry.len();
        self.left = self.left.checked_sub(len).ok_or_else(|| {
            Error::Mail(format!(
                "the streams add up to more than the {} bytes of the file",
                self.limit
            ))
        })?;
        let Ok(stream) = self.file.open_stream(path) else {
            return Ok(None);
        };
        let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        Ok(stream.take(len).read_to_end(&mut bytes).ok().map(|_| bytes))
    }

    /// The string property `tag` (four hex digits) of storage `dir` (`""` for the root).
    fn string(&mut self, dir: &str, tag: &str) -> Result<Option<String>> {
        if let Some(bytes) = self.stream(&format!("{dir}/__substg1.0_{tag}001F"))? {
            let text = unicode(&bytes);
            if !text.is_empty() {
                return Ok(Some(text));
            }
        }
        let bytes = self.stream(&format!("{dir}/__substg1.0_{tag}001E"))?;
        Ok(bytes
            .map(|bytes| ansi(&bytes))
            .filter(|text| !text.is_empty()))
    }

    /// The first of the properties `tags` that holds a string.
    fn first_string(&mut self, dir: &str, tags: &[&str]) -> Result<Option<String>> {
        for tag in tags {
            if let Some(text) = self.string(dir, tag)? {
                return Ok(Some(text));
            }
        }
        Ok(None)
    }

    /// Whether the recipient in storage `dir` is a To, Cc or Bcc; To when unknown.
    fn recipient_type(&mut self, dir: &str) -> Result<u32> {
        let Some(props) = self.stream(&format!("{dir}/{PROPERTIES}"))? else {
            return Ok(RECIPIENT_TO);
        };
        Ok(props
            .get(PROPERTY_HEADER..)
            .unwrap_or_default()
            .chunks_exact(PROPERTY_ENTRY)
            .find_map(|entry| {
                let (tag, rest) = entry.split_first_chunk::<4>()?;
                let value = rest.get(4..8)?.first_chunk::<4>()?;
                (u32::from_le_bytes(*tag) == RECIPIENT_TYPE_TAG).then(|| u32::from_le_bytes(*value))
            })
            .unwrap_or(RECIPIENT_TO))
    }
}

/// A `001F` string: UTF-16LE, usually ended by a NUL unit.
fn unicode(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_owned()
}

/// A `001E` string: one byte per character, in UTF-8 or Windows-1252, usually ended by a NUL.
///
/// The NULs are cut off before decoding: left on, a short string such as `ab\0` has as many
/// NUL bytes as UTF-16 text and would be read as that. A NUL inside the string is kept, and
/// the text on either side of it decoded on its own, so one cannot make the rest unreadable.
fn ansi(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |last| last + 1);
    let mut parts = bytes
        .get(..end)
        .unwrap_or_default()
        .split(|&byte| byte == 0)
        .map(|part| match text::decode(part) {
            Ok((text, _)) => text.into_owned(),
            Err(_) => String::from_utf8_lossy(part).into_owned(),
        });
    let mut joined = parts.next().unwrap_or_default();
    for part in parts {
        joined.push('\0');
        joined.push_str(&part);
    }
    joined
}
