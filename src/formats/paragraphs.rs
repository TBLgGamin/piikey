//! Which paragraph of a word-processing document a text came from, and the page it starts on,
//! for the findings of a scan.
//!
//! Only the body counts (`word/document.xml`); a header, a footer, a note at the foot of a page
//! and a comment are parts of their own and have no place. The paragraphs are counted from 1 in
//! the order of the file, the ones in the cells of a table included. A paragraph inside another
//! (the text of a text box lies in paragraphs that are in the paragraph it is anchored in) is not
//! counted: its text belongs to the paragraph that holds it.
//!
//! A document does not store its pages: a program lays the text out when it shows it. Two things
//! in the file say where a page begins. Word marks the place at which each page began when it
//! last laid the document out (`w:lastRenderedPageBreak`), so a document saved by Word has them,
//! and one that Word never saved does not; and the text may break the page itself
//! (`<w:br w:type="page"/>`, `w:pageBreakBefore`). The marks of Word are used when there are any,
//! and the page breaks of the text when there are not; a document with neither has no pages. A
//! paragraph is on the page it starts on, so a paragraph that runs onto the next page names the
//! first one.

use std::ops::{ControlFlow, Range};

use quick_xml::events::{BytesStart, Event};

use super::{
    Location,
    sheets::{Docs, attribute},
    xmltext::XmlDoc,
};

/// The part that holds the body of a document.
const DOCUMENT: &str = "word/document.xml";

/// Where each of the texts `wanted` (their numbers among the texts of the package, see [`Docs`])
/// is, for the findings of a document: the paragraph of the body it is in, and its page when the
/// file says. A text of any other part has no place.
pub(super) fn places(docs: &Docs<'_>, wanted: &[usize]) -> Vec<Option<Location>> {
    let mut answers = vec![None; wanted.len()];
    let Some(index) = docs.find(DOCUMENT) else {
        return answers;
    };
    let Some(asks) = docs.asked(wanted).remove(&index) else {
        return answers;
    };
    let Some(doc) = docs.doc(index) else {
        return answers;
    };
    let body = Body::read(doc);
    for ask in asks {
        answers[ask.slot] = body.place(ask.offset);
    }
    answers
}

/// The paragraphs of the body of a document and the places its pages begin at.
struct Body {
    /// Each paragraph as the range it takes in the source, in the order of the file.
    paragraphs: Vec<Range<usize>>,
    /// Where each page after the first begins in the source, in order; none when the file does
    /// not say.
    pages: Vec<usize>,
}

impl Body {
    /// The paragraphs of the body `doc` and its page marks.
    fn read(doc: &XmlDoc) -> Self {
        let mut paragraphs = Vec::new();
        let mut rendered = Vec::new();
        let mut broken = Vec::new();
        // How many paragraphs are open, and where the outermost starts.
        let mut open = 0_usize;
        let mut start = 0_usize;
        doc.walk(|event, range| {
            match event {
                Event::Start(tag) | Event::Empty(tag) => {
                    let begins = matches!(event, Event::Start(_));
                    match tag.local_name().into_inner() {
                        "p" if begins => {
                            if open == 0 {
                                start = range.start;
                            }
                            open += 1;
                        }
                        "p" if open == 0 => paragraphs.push(range),
                        // Only the paragraphs of the body itself say where its pages begin.
                        "lastRenderedPageBreak" if open == 1 => rendered.push(range.start),
                        "br" if open == 1
                            && attribute(tag, "type").is_some_and(|t| t == "page") =>
                        {
                            broken.push(range.start);
                        }
                        "pageBreakBefore" if open == 1 && !is_off(tag) => broken.push(range.start),
                        _ => {}
                    }
                }
                Event::End(tag) if tag.local_name().into_inner() == "p" => {
                    open = open.saturating_sub(1);
                    if open == 0 {
                        paragraphs.push(start..range.end);
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        });
        Self {
            paragraphs,
            pages: if rendered.is_empty() {
                broken
            } else {
                rendered
            },
        }
    }

    /// The place of the text that starts at the source offset `at`: its paragraph, and the page
    /// that paragraph starts on. A page begins at its mark, so what stands after a mark is on the
    /// page the mark begins.
    fn place(&self, at: usize) -> Option<Location> {
        let before = self
            .paragraphs
            .partition_point(|paragraph| paragraph.start <= at);
        let index = before.checked_sub(1)?;
        self.paragraphs
            .get(index)
            .filter(|paragraph| at < paragraph.end)?;
        let page = (!self.pages.is_empty())
            .then(|| self.pages.partition_point(|&mark| mark < at) + 1)
            .and_then(|page| u32::try_from(page).ok());
        Some(Location::Paragraph {
            paragraph: u32::try_from(index + 1).ok()?,
            page,
        })
    }
}

/// Whether the on/off property `tag` is switched off (`w:val` is `0` or `false`).
fn is_off(tag: &BytesStart<'_>) -> bool {
    attribute(tag, "val").is_some_and(|value| matches!(&*value, "0" | "false" | "off"))
}

#[cfg(test)]
mod tests {
    use super::super::xmltext::{Attrs, segments};
    use super::*;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// The place of each text of the body `xml`, in the order of the file, as
    /// `(text, paragraph, page)`.
    fn placed(xml: &str) -> Fallible<Vec<(String, u32, Option<u32>)>> {
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let body = Body::read(&doc);
        let texts: Vec<&str> = doc.texts().collect();
        let mut out = Vec::new();
        for (segment, text) in texts.iter().enumerate() {
            let at = doc.offset(segment).ok_or("no source")?;
            if let Some(Location::Paragraph { paragraph, page }) = body.place(at) {
                out.push(((*text).to_owned(), paragraph, page));
            }
        }
        Ok(out)
    }

    fn run(text: &str) -> String {
        format!("<w:r><w:t>{text}</w:t></w:r>")
    }

    #[test]
    fn paragraphs_count_from_one_cells_of_a_table_included() -> Fallible<()> {
        let xml = format!(
            "<w:body><w:p>{}</w:p><w:p/><w:tbl><w:tr><w:tc><w:p>{}</w:p></w:tc>\
             <w:tc><w:p>{}</w:p></w:tc></w:tr></w:tbl><w:p>{}</w:p></w:body>",
            run("one"),
            run("cell a"),
            run("cell b"),
            run("last"),
        );
        // The empty paragraph is the second, and counts.
        assert_eq!(
            placed(&xml)?,
            [
                ("one".into(), 1, None),
                ("cell a".into(), 3, None),
                ("cell b".into(), 4, None),
                ("last".into(), 5, None),
            ]
        );
        Ok(())
    }

    #[test]
    fn the_text_of_a_text_box_belongs_to_the_paragraph_it_is_anchored_in() -> Fallible<()> {
        let xml = format!(
            "<w:body><w:p>{}<w:r><w:pict><w:txbxContent><w:p>{}</w:p><w:p>{}</w:p></w:txbxContent>\
             </w:pict></w:r></w:p><w:p>{}</w:p></w:body>",
            run("anchor"),
            run("boxed"),
            run("more"),
            run("next"),
        );
        let found = placed(&xml)?;
        let paragraphs: Vec<(&str, u32)> = found
            .iter()
            .map(|(text, paragraph, _)| (text.as_str(), *paragraph))
            .collect();
        // The anchor's own text and what is in the box are one paragraph's.
        assert!(
            paragraphs
                .iter()
                .all(|&(text, number)| { number == if text == "next" { 2 } else { 1 } }),
            "{paragraphs:?}"
        );
        assert!(paragraphs.iter().any(|&(text, _)| text == "next"));
        Ok(())
    }

    #[test]
    fn a_page_begins_at_the_mark_word_left_and_the_paragraph_is_on_the_page_it_starts_on()
    -> Fallible<()> {
        let xml = format!(
            "<w:body><w:p>{}</w:p>\
             <w:p><w:r><w:lastRenderedPageBreak/><w:t>top of two</w:t></w:r></w:p>\
             <w:p>{}<w:r><w:lastRenderedPageBreak/><w:t>runs on</w:t></w:r></w:p>\
             <w:p>{}</w:p></w:body>",
            run("one"),
            run("starts on two"),
            run("three"),
        );
        assert_eq!(
            placed(&xml)?,
            [
                ("one".into(), 1, Some(1)),
                // The mark comes before its first text: the paragraph starts the page.
                ("top of two".into(), 2, Some(2)),
                // The mark comes after the first text: the paragraph starts on the page before.
                ("starts on tworuns on".into(), 3, Some(2)),
                ("three".into(), 4, Some(3)),
            ]
        );
        Ok(())
    }

    #[test]
    fn a_document_without_marks_has_the_pages_its_text_breaks_and_otherwise_none() -> Fallible<()> {
        let broken = format!(
            "<w:body><w:p>{}</w:p><w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>\
             <w:p>{}</w:p><w:p><w:pPr><w:pageBreakBefore/></w:pPr>{}</w:p>\
             <w:p><w:pPr><w:pageBreakBefore w:val=\"0\"/></w:pPr>{}</w:p></w:body>",
            run("one"),
            run("two"),
            run("three"),
            run("still three"),
        );
        assert_eq!(
            placed(&broken)?,
            [
                ("one".into(), 1, Some(1)),
                ("two".into(), 3, Some(2)),
                ("three".into(), 4, Some(3)),
                ("still three".into(), 5, Some(3)),
            ]
        );
        // A line break is no page break.
        let plain = "<w:body><w:p><w:r><w:br/><w:t>x</w:t></w:r></w:p></w:body>";
        assert_eq!(placed(plain)?, [("\nx".into(), 1, None)]);
        // Marks of Word win over the breaks of the text, which Word marks again by itself.
        let both = "<w:body><w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>\
             <w:p><w:r><w:lastRenderedPageBreak/><w:t>on two</w:t></w:r></w:p></w:body>";
        assert_eq!(placed(both)?, [("on two".into(), 2, Some(2))]);
        Ok(())
    }

    #[test]
    fn marks_inside_a_text_box_do_not_turn_the_page() -> Fallible<()> {
        let xml = format!(
            "<w:body><w:p><w:r><w:pict><w:txbxContent><w:p><w:r><w:lastRenderedPageBreak/>\
             <w:t>boxed</w:t></w:r></w:p></w:txbxContent></w:pict></w:r></w:p><w:p>{}</w:p></w:body>",
            run("after"),
        );
        let found = placed(&xml)?;
        assert!(found.iter().all(|(_, _, page)| page.is_none()), "{found:?}");
        Ok(())
    }
}
