//! PDF: the text layer of every page, scanned pages through OCR; the output is text.
//!
//! PDF text cannot be rewritten faithfully through font encodings, so the
//! result is the anonymized text, one page after another.

use lopdf::Document;
use rayon::prelude::*;

use super::{Output, Pass, places::Layout, run_text};
use crate::{Result, ocr};

/// A page with fewer non-blank characters than this has no usable text layer.
const MIN_TEXT_CHARS: usize = 16;
/// Between two pages in the extracted text.
const PAGE_BREAK: &str = "\n\u{c}\n";

/// Anonymizes or deanonymizes the text of a PDF. A scan that is asked for findings names the page
/// of each value (a page that was read by OCR counts like the others), when the file is not one
/// that sits inside another (`depth` above 0).
pub(super) fn process(pass: &Pass<'_>, bytes: &[u8], depth: u8) -> Result<Output> {
    let doc = Document::load_mem(bytes)?;
    let numbers: Vec<u32> = doc.get_pages().into_keys().collect();
    let pages = numbers
        .par_iter()
        .map(|&number| page_text(&doc, bytes, number))
        .collect::<Result<Vec<_>>>()?;
    let starts = if pass.wants_places(depth) {
        page_starts(&pages)
    } else {
        Vec::new()
    };
    let layout = if starts.is_empty() {
        Layout::Nowhere
    } else {
        Layout::Pages(&starts)
    };
    run_text(pass, &layout, &pages.join(PAGE_BREAK)).map(Output::Text)
}

/// The byte offset at which each of `pages` begins in the text they are joined to with
/// [`PAGE_BREAK`].
fn page_starts(pages: &[String]) -> Vec<usize> {
    let mut next = 0;
    pages
        .iter()
        .map(|page| {
            let start = next;
            next += page.len() + PAGE_BREAK.len();
            start
        })
        .collect()
}

/// The text of page `number` (1-based): its text layer, or OCR when that has
/// next to no text.
fn page_text(doc: &Document, pdf: &[u8], number: u32) -> Result<String> {
    // A text layer that cannot be decoded is as good as none.
    let text = doc.extract_text(&[number]).unwrap_or_default();
    if text.trim().chars().count() >= MIN_TEXT_CHARS {
        Ok(text)
    } else {
        ocr::pdf_page(pdf, number.saturating_sub(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_begins_after_the_text_and_the_page_break_of_the_pages_before_it() {
        let pages = [
            "abc".to_owned(),
            String::new(),
            "é".to_owned(),
            "x".to_owned(),
        ];
        // "abc", a break, nothing, a break, "é" (two bytes), a break, "x".
        let starts = page_starts(&pages);
        assert_eq!(starts, [0, 6, 9, 14]);
        let joined = pages.join(PAGE_BREAK);
        assert!(joined[starts[2]..].starts_with('é'));
        assert!(joined[starts[3]..].starts_with('x'));
        assert!(page_starts(&[]).is_empty());
    }
}
