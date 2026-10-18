//! `OpenDocument` packages (`.odt`, `.ods`, `.odp`, …).
//!
//! Every `.xml` part is scanned for text (`content.xml`, `styles.xml` headers
//! and footers, `meta.xml`, …) and for `href` attribute values, where
//! `mailto:` links live.

use std::io::Read;

use super::{package::Archive, xmltext::Attrs};
use crate::Result;

const MIMETYPE: &str = "mimetype";
const MIME_PREFIX: &[u8] = b"application/vnd.oasis.opendocument.";

/// True when the first entry is a `mimetype` part naming an `OpenDocument` type.
pub(super) fn matches(archive: &mut Archive<'_>) -> Result<bool> {
    let first_is_mimetype = archive
        .name_for_index(0)
        .transpose()?
        .is_some_and(|name| name == MIMETYPE);
    if !first_is_mimetype {
        return Ok(false);
    }
    let mut head = Vec::with_capacity(MIME_PREFIX.len());
    archive
        .by_index(0)?
        .take(MIME_PREFIX.len() as u64)
        .read_to_end(&mut head)?;
    Ok(head == MIME_PREFIX)
}

/// Which parts hold text, by entry name.
pub(super) fn scope(name: &str) -> Option<Attrs> {
    let extension = name.rsplit('.').next()?;
    extension.eq_ignore_ascii_case("xml").then_some(Attrs::Href)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_picks_xml_parts() {
        assert_eq!(scope("content.xml"), Some(Attrs::Href));
        assert_eq!(scope("META-INF/manifest.xml"), Some(Attrs::Href));
        assert_eq!(scope("Pictures/image.png"), None);
        assert_eq!(scope("mimetype"), None);
        assert_eq!(scope("Configurations2/"), None);
    }
}
