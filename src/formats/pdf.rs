//! PDF: the text layer of every page, scanned pages through OCR; the output is text.
//!
//! PDF text cannot be rewritten faithfully through font encodings, so the
//! result is the anonymized text, one page after another.
//!
//! The text layers of all the pages are read first, then the pages that have none are read by OCR,
//! which takes a second or more for each: a read of findings is told how many there are and how
//! far it is, and does not go on with them once its reader asked to stop.

use std::sync::atomic::{AtomicUsize, Ordering};

use lopdf::Document;
use rayon::prelude::*;

use super::{Busy, Output, Pass, places::Layout, run_text};
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
    let pages = page_texts(pass, &doc, bytes, &numbers)?;
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

/// The text of every page of `numbers` (1-based), in order: its text layer, or what OCR reads of
/// it when that has next to no text.
fn page_texts(pass: &Pass<'_>, doc: &Document, pdf: &[u8], numbers: &[u32]) -> Result<Vec<String>> {
    let layers: Vec<Option<String>> = numbers
        .par_iter()
        .map(|&number| text_layer(doc, number))
        .collect();
    let scanned = layers.iter().filter(|layer| layer.is_none()).count();
    if scanned == 0 {
        return Ok(layers.into_iter().flatten().collect());
    }
    let done = AtomicUsize::new(0);
    pass.busy(Busy::Pages {
        done: 0,
        total: scanned,
    });
    numbers
        .par_iter()
        .zip(layers)
        .map(|(&number, layer)| match layer {
            Some(text) => Ok(text),
            // The reader of the findings has had enough: what is left is not read.
            None if pass.stopped() => Ok(String::new()),
            None => {
                let text = ocr::pdf_page(pdf, number.saturating_sub(1));
                pass.busy(Busy::Pages {
                    done: done.fetch_add(1, Ordering::Relaxed) + 1,
                    total: scanned,
                });
                text
            }
        })
        .collect()
}

/// The text layer of page `number` (1-based), `None` when it has next to no text.
fn text_layer(doc: &Document, number: u32) -> Option<String> {
    // A text layer that cannot be decoded is as good as none.
    let text = doc.extract_text(&[number]).unwrap_or_default();
    (text.trim().chars().count() >= MIN_TEXT_CHARS).then_some(text)
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
