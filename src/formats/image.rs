//! Images (PNG, JPEG, GIF, BMP, TIFF, WebP, HEIF): OCR text; the output is text.
//!
//! Proxies cannot be drawn into pixels believably, so the result is the
//! anonymized text found in the picture. A value in a picture has no place in its file.

use super::{Busy, Output, Pass, places::Layout, run_text};
use crate::{Result, ocr};

pub(super) fn process(pass: &Pass<'_>, bytes: &[u8]) -> Result<Output> {
    pass.busy(Busy::Picture);
    let text = ocr::image(bytes)?;
    run_text(pass, &Layout::Nowhere, &text).map(Output::Text)
}
