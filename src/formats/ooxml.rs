//! Office Open XML packages (`.docx`, `.xlsx`, `.pptx`, …).
//!
//! Every `.xml` part is scanned for text (document bodies, shared strings,
//! slides, comments, headers, `docProps/core.xml`, …). Relationship parts
//! (`.rels`) are scanned for `Target` values, where `mailto:` links live.
//! Entries of an `embeddings` folder (`word/embeddings`, `ppt/embeddings`, `xl/embeddings`)
//! that are packages themselves, like the workbook behind a chart, are read as packages of
//! their own; pictures and other binary objects are not read.

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

/// True when the entry lies in a folder named `embeddings`, at any depth.
pub(super) fn in_embeddings(name: &str) -> bool {
    let mut folders = name.split('/');
    // The last component is the entry itself, not a folder.
    folders.next_back();
    folders.any(|folder| folder.eq_ignore_ascii_case("embeddings"))
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

    #[test]
    fn embeddings_are_the_entries_in_an_embeddings_folder() {
        assert!(in_embeddings("word/embeddings/Microsoft_Excel_Sheet1.xlsx"));
        assert!(in_embeddings("ppt/Embeddings/a.bin"));
        assert!(in_embeddings("embeddings/a.docx"));
        assert!(in_embeddings("xl/embeddings/nested/a.xlsx"));
        assert!(!in_embeddings("word/embeddings"));
        assert!(!in_embeddings("embeddings"));
        assert!(!in_embeddings("word/media/embeddings.png"));
        assert!(!in_embeddings("word/my_embeddings/a.xlsx"));
    }
}
