//! Windows.Media.Ocr + Windows.Data.Pdf page rendering.
//!
//! The `WinRT` async operations are blocked on with `join()` (inherent method
//! from `windows-future`, re-exported through the `windows` crate). The
//! `windows` crate initialises the MTA on demand when an activation factory
//! lookup reports `CO_E_NOTINITIALIZED`, so no explicit COM init is needed.

use windows::{
    Data::Pdf::{PdfDocument, PdfPageRenderOptions},
    Graphics::Imaging::{
        BitmapAlphaMode, BitmapDecoder, BitmapInterpolationMode, BitmapPixelFormat,
        BitmapTransform, ColorManagementMode, ExifOrientationMode, SoftwareBitmap,
    },
    Media::Ocr::OcrEngine,
    Storage::Streams::{DataWriter, InMemoryRandomAccessStream},
};

use crate::{Error, Result};

/// PDF pages are rendered at this multiple of their nominal (96 dpi) size so
/// that small body text is large enough for the recognizer.
const PDF_RENDER_SCALE: f32 = 2.0;

const NO_LANGUAGE: &str = "no OCR language installed; add one in Settings > Time & language";

/// True when at least one OCR recognizer language is installed: the tests that need one skip
/// when it is not.
#[cfg(test)]
pub(crate) fn available() -> bool {
    OcrEngine::AvailableRecognizerLanguages()
        .and_then(|languages| languages.Size())
        .is_ok_and(|n| n > 0)
}

/// Size and first pixel (blue, green, red, alpha) of the picture in `bytes` as Windows decodes
/// it: what Explorer, which uses the same decoders, would show.
#[cfg(test)]
pub(crate) fn first_pixel(bytes: &[u8]) -> Result<(u32, u32, [u8; 4])> {
    use windows::Storage::Streams::{Buffer, DataReader};

    let decoder = BitmapDecoder::CreateAsync(&stream_from_bytes(bytes)?)?.join()?;
    let (width, height) = (decoder.PixelWidth()?, decoder.PixelHeight()?);
    let bitmap = decode_bitmap(&decoder, OcrEngine::MaxImageDimension()?)?;
    let length = width * height * 4;
    let buffer = Buffer::Create(length)?;
    bitmap.CopyToBuffer(&buffer)?;
    buffer.SetLength(length)?;
    let mut pixel = [0; 4];
    DataReader::FromBuffer(&buffer)?.ReadBytes(&mut pixel)?;
    Ok((width, height, pixel))
}

/// OCR text of an encoded image (PNG/JPEG/GIF/BMP/TIFF/WebP/HEIF); lines
/// joined with `\n`.
///
/// # Errors
/// `Ocr` on decode/recognition failure or no installed language.
pub fn image(bytes: &[u8]) -> Result<String> {
    let stream = stream_from_bytes(bytes)?;
    recognize(&stream)
}

/// Renders page `index` (0-based) of `pdf` and OCRs it.
///
/// # Errors
/// `Ocr` on load/render/recognition failure.
pub fn pdf_page(pdf: &[u8], index: u32) -> Result<String> {
    let source = stream_from_bytes(pdf)?;
    let document = PdfDocument::LoadFromStreamAsync(&source)?.join()?;
    let page = document.GetPage(index)?;

    let size = page.Size()?;
    let options = PdfPageRenderOptions::new()?;
    options.SetDestinationWidth(scaled(size.Width))?;
    options.SetDestinationHeight(scaled(size.Height))?;

    let rendered = InMemoryRandomAccessStream::new()?;
    page.RenderWithOptionsToStreamAsync(&rendered, &options)?
        .join()?;
    rendered.Seek(0)?;
    recognize(&rendered)
}

/// Page dimension in device pixels after applying [`PDF_RENDER_SCALE`]; at
/// least 1.
fn scaled(points: f32) -> u32 {
    let px = (points * PDF_RENDER_SCALE).round();
    if px.is_finite() && px >= 1.0 {
        // Saturating float-to-int; page sizes are far below `u32::MAX`.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "value is finite and >= 1.0; `as` saturates at u32::MAX"
        )]
        let px = px as u32;
        px
    } else {
        1
    }
}

/// Copies `bytes` into a fresh in-memory stream positioned at 0.
fn stream_from_bytes(bytes: &[u8]) -> Result<InMemoryRandomAccessStream> {
    let stream = InMemoryRandomAccessStream::new()?;
    let writer = DataWriter::CreateDataWriter(&stream)?;
    writer.WriteBytes(bytes)?;
    writer.StoreAsync()?.join()?;
    // Detach so dropping the writer doesn't close the stream.
    writer.DetachStream()?;
    stream.Seek(0)?;
    Ok(stream)
}

/// Decodes the image in `stream` and runs the OCR engine over it.
fn recognize(stream: &InMemoryRandomAccessStream) -> Result<String> {
    let engine = OcrEngine::TryCreateFromUserProfileLanguages()
        .map_err(|_| Error::Ocr(NO_LANGUAGE.into()))?;
    let decoder = BitmapDecoder::CreateAsync(stream)?.join()?;
    let bitmap = decode_bitmap(&decoder, OcrEngine::MaxImageDimension()?)?;
    let result = engine.RecognizeAsync(&bitmap)?.join()?;

    let lines = result.Lines()?;
    let mut text = String::new();
    for (i, line) in lines.into_iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        text.push_str(&line.Text()?.to_string_lossy());
    }
    Ok(text)
}

/// Bgra8 / premultiplied bitmap, downscaled proportionally when either side
/// exceeds the OCR engine's maximum dimension.
fn decode_bitmap(decoder: &BitmapDecoder, max_dimension: u32) -> Result<SoftwareBitmap> {
    let width = decoder.PixelWidth()?;
    let height = decoder.PixelHeight()?;
    let longest = width.max(height);

    if longest <= max_dimension {
        return Ok(decoder
            .GetSoftwareBitmapConvertedAsync(
                BitmapPixelFormat::Bgra8,
                BitmapAlphaMode::Premultiplied,
            )?
            .join()?);
    }

    let fit = |side: u32| {
        let scaled = u64::from(side) * u64::from(max_dimension) / u64::from(longest);
        // `scaled <= max_dimension <= u32::MAX` because `side <= longest`.
        u32::try_from(scaled).unwrap_or(max_dimension).max(1)
    };
    let transform = BitmapTransform::new()?;
    transform.SetScaledWidth(fit(width))?;
    transform.SetScaledHeight(fit(height))?;
    transform.SetInterpolationMode(BitmapInterpolationMode::Fant)?;
    Ok(decoder
        .GetSoftwareBitmapTransformedAsync(
            BitmapPixelFormat::Bgra8,
            BitmapAlphaMode::Premultiplied,
            &transform,
            ExifOrientationMode::IgnoreExifOrientation,
            ColorManagementMode::DoNotColorManage,
        )?
        .join()?)
}

#[cfg(test)]
mod tests {
    use lopdf::{
        Document, Object, Stream,
        content::{Content, Operation},
        dictionary,
    };

    use super::*;

    /// One A4 page with `text` in 40 pt Helvetica.
    fn pdf_with_text(text: &str) -> Result<Vec<u8>> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! { "F1" => font_id },
        });
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 40.into()]),
                Operation::new("Td", vec![40.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal(text)]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode()?));
        let leaf_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![leaf_id.into()],
                "Count" => 1,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            }),
        );
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut out = Vec::new();
        doc.save_to(&mut out)?;
        Ok(out)
    }

    #[test]
    fn pdf_page_ocr_reads_phone_number() -> Result<()> {
        if !available() {
            eprintln!("skipping: no OCR language");
            return Ok(());
        }
        let pdf = pdf_with_text("call +31 6 12345678")?;
        let text = pdf_page(&pdf, 0)?;
        assert!(text.contains("12345678"), "OCR text was {text:?}");
        Ok(())
    }

    #[test]
    fn pdf_page_out_of_range_is_error() -> Result<()> {
        let pdf = pdf_with_text("hello")?;
        assert!(matches!(pdf_page(&pdf, 5), Err(Error::Ocr(_))));
        Ok(())
    }

    #[test]
    fn garbage_image_is_error() {
        assert!(matches!(image(b"not an image at all"), Err(Error::Ocr(_))));
    }

    #[test]
    fn scaled_clamps() {
        assert_eq!(scaled(0.0), 1);
        assert_eq!(scaled(f32::NAN), 1);
        assert_eq!(scaled(595.0), 1190);
    }
}
