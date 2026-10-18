//! Images (PNG, JPEG, GIF, BMP, TIFF, WebP, HEIF): OCR text; the output is text.
//!
//! Proxies cannot be drawn into pixels believably, so the result is the
//! anonymized text found in the picture.

use super::{Output, run_text};
use crate::{Result, detect::Mode, engine::Engine, ocr};

pub(super) fn process(engine: &Engine, mode: Mode, bytes: &[u8]) -> Result<Output> {
    let text = ocr::image(bytes)?;
    run_text(engine, mode, &text).map(Output::Text)
}
