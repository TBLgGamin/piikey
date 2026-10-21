//! Where what was read goes: [`Sink`], and [`Store`], the real one.

use std::sync::{Arc, PoisonError};

use piikey::engine::Engine;

use crate::{
    highlight::{Mark, Overlay, Rect},
    proxy::Shared,
};

/// Where what was read goes.
pub(super) trait Sink {
    /// Keeps the text for the next [`flush`](Self::flush).
    fn push(&self, text: String);
    /// Runs detection over everything pushed so far.
    fn flush(&self);
    /// Whether detection finds personal data in `text`, keeping nothing and writing nothing to the
    /// vault; `None` when it cannot tell.
    fn holds_pii(&self, text: &str) -> Option<bool>;
    /// Outlines the field at `field` in the colour of `mark`; asked again at every look, because
    /// the overlay lets an outline that is not asked for go.
    fn show(&self, field: Rect, mark: Mark);
    /// Takes the outline away.
    fn hide(&self);
}

/// The real sink: the store the proxy reads, flushed with the engine that is current now, the
/// engine that checks fields, and the overlay once it runs.
pub(super) struct Store<'a>(pub(super) &'a Shared);

impl Store<'_> {
    /// The engine that is current now. Never kept: it can be swapped under a running proxy.
    fn engine(&self) -> Arc<Engine> {
        Arc::clone(&self.0.engine.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl Sink for Store<'_> {
    fn push(&self, text: String) {
        self.0.typed.push(text);
    }

    fn flush(&self) {
        // A failed flush keeps its text, and every request flushes before it reads the store.
        let _ = self.0.typed.flush(&self.engine());
    }

    fn holds_pii(&self, text: &str) -> Option<bool> {
        let found = self.engine().scan(&[text]).ok()?;
        Some(found.iter().any(|spans| !spans.is_empty()))
    }

    fn show(&self, field: Rect, mark: Mark) {
        // Before the overlay runs, or after it died, nothing is drawn.
        if let Some(overlay) = Overlay::get() {
            overlay.show(field, mark);
        }
    }

    fn hide(&self) {
        Overlay::hide_any();
    }
}
