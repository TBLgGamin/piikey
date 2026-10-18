//! Office Open XML packages (`.docx`, `.xlsx`, `.pptx`, …).
//!
//! Every `.xml` part is scanned for text (document bodies, shared strings,
//! slides, comments, headers, `docProps/core.xml`, …). Relationship parts
//! (`.rels`) are scanned for `Target` values, where `mailto:` links live.

use super::{package::Archive, xmltext::Attrs};

/// True when the package has a `[Content_Types].xml` part.
pub(super) fn matches(archive: &Archive<'_>) -> bool {
    archive.index_for_name("[Content_Types].xml").is_some()
}

/// Which parts hold text, by entry name.
pub(super) fn scope(name: &str) -> Option<Attrs> {
    let extension = name.rsplit('.').next()?;
    if extension.eq_ignore_ascii_case("xml") {
        Some(Attrs::None)
    } else if extension.eq_ignore_ascii_case("rels") {
        Some(Attrs::Target)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_picks_xml_and_relationship_parts() {
        assert_eq!(scope("word/document.xml"), Some(Attrs::None));
        assert_eq!(scope("docProps/CORE.XML"), Some(Attrs::None));
        assert_eq!(scope("_rels/.rels"), Some(Attrs::Target));
        assert_eq!(scope("word/_rels/document.xml.rels"), Some(Attrs::Target));
        assert_eq!(scope("word/media/image1.png"), None);
        assert_eq!(scope("word/"), None);
        assert_eq!(scope("mimetype"), None);
    }
}
