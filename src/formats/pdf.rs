//! PDF: the text layer of every page, scanned pages through OCR; the output is text.
//!
//! PDF text cannot be rewritten faithfully through font encodings, so the
//! result is the anonymized text, one page after another.

use lopdf::Document;
use rayon::prelude::*;

use super::{Output, run_text};
use crate::{Result, detect::Mode, engine::Engine, ocr};

/// A page with fewer non-blank characters than this has no usable text layer.
const MIN_TEXT_CHARS: usize = 16;
/// Between two pages in the extracted text.
const PAGE_BREAK: &str = "\n\u{c}\n";

pub(super) fn process(engine: &Engine, mode: Mode, bytes: &[u8]) -> Result<Output> {
    let doc = Document::load_mem(bytes)?;
    let numbers: Vec<u32> = doc.get_pages().into_keys().collect();
    let pages = numbers
        .par_iter()
        .map(|&number| page_text(&doc, bytes, number))
        .collect::<Result<Vec<_>>>()?;
    run_text(engine, mode, &pages.join(PAGE_BREAK)).map(Output::Text)
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
