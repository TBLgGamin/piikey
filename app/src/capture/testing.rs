//! What the tests of capture share: a desktop they script, a sink that writes down what reached
//! it, and a store over a real engine.

use std::{
    cell::{Cell, RefCell},
    num::NonZeroU32,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use piikey::{
    engine::Engine,
    policy::{Highlight, Policy},
};

use super::{
    desktop::{Clip, Desktop, Field, Focus},
    sink::{Sink, Store},
};
use crate::{
    Describe,
    highlight::{Mark, Rect},
    ledger::Ledger,
    proxy::{Purpose, Shared, Typed},
};

/// A text field at the top of the screen.
pub(super) const FIELD: Rect = Rect {
    left: 100,
    top: 200,
    right: 500,
    bottom: 240,
};

/// Text that holds personal data.
pub(super) const EMAIL: &str = "mail jan.jansen@acme.nl";

/// A desktop the test scripts: what has the focus, its text and the clipboard.
#[derive(Default)]
pub(super) struct Fake {
    /// The element with the focus and whether it is protected.
    pub(super) focus: Option<(Vec<i32>, bool)>,
    pub(super) text: Option<String>,
    pub(super) seq: Option<NonZeroU32>,
    pub(super) clipboard: Option<String>,
    /// The next this many reads of the clipboard find it busy.
    pub(super) busy: usize,
    /// The element as a field to outline: where it is and what it holds.
    pub(super) field: Option<(Rect, String)>,
    /// The element is a password field.
    pub(super) password: bool,
    /// `with_text` of every `focus` call.
    pub(super) asked: Vec<bool>,
    pub(super) protected_calls: usize,
    pub(super) text_calls: usize,
    pub(super) clipboard_reads: usize,
    pub(super) field_calls: usize,
    pub(super) bounds_calls: usize,
}

impl Fake {
    pub(super) fn on(id: i32, protected: bool) -> Self {
        Self {
            focus: Some((vec![42, id], protected)),
            ..Self::default()
        }
    }

    /// The focus moves to element `id`.
    pub(super) fn moves_to(&mut self, id: i32, protected: bool) {
        self.focus = Some((vec![42, id], protected));
    }

    pub(super) fn types(&mut self, text: &str) {
        self.text = Some(text.to_owned());
    }

    /// The element is a field at `rect` holding `text`.
    pub(super) fn shows(&mut self, rect: Rect, text: &str) {
        self.field = Some((rect, text.to_owned()));
    }

    pub(super) fn copies(&mut self, seq: u32, text: &str) {
        self.seq = NonZeroU32::new(seq);
        self.clipboard = Some(text.to_owned());
    }
}

impl Desktop for Fake {
    fn focus(&mut self, with_text: bool) -> Option<Focus> {
        self.asked.push(with_text);
        let (id, _) = self.focus.as_ref()?;
        Some(Focus {
            id: id.clone(),
            password: self.password,
        })
    }

    fn protected(&mut self) -> bool {
        self.protected_calls += 1;
        self.focus.as_ref().is_some_and(|&(_, protected)| protected)
    }

    fn text(&mut self) -> Option<String> {
        self.text_calls += 1;
        self.text.clone()
    }

    fn field(&mut self) -> Option<Field> {
        self.field_calls += 1;
        let (rect, text) = self.field.clone()?;
        // As the real desktop does: a password field is none.
        Field::of(self.password, false, Some(text), Some(rect))
    }

    fn bounds(&mut self) -> Option<Rect> {
        self.bounds_calls += 1;
        self.field.as_ref().map(|&(rect, _)| rect)
    }

    fn clipboard_seq(&mut self) -> Option<NonZeroU32> {
        self.seq
    }

    fn clipboard_text(&mut self) -> Clip {
        self.clipboard_reads += 1;
        if self.busy > 0 {
            self.busy -= 1;
            return Clip::Busy;
        }
        self.clipboard.clone().map_or(Clip::NoText, Clip::Text)
    }
}

/// Records what reached the store and the overlay, in order. It checks fields for personal data
/// with the detection of a real store, when it has one.
#[derive(Default)]
pub(super) struct Log {
    lines: RefCell<Vec<String>>,
    store: Option<Arc<Shared>>,
    /// Texts checked for personal data.
    pub(super) scans: Cell<usize>,
}

impl Log {
    pub(super) fn with(shared: &Arc<Shared>) -> Self {
        Self {
            store: Some(Arc::clone(shared)),
            ..Self::default()
        }
    }

    pub(super) fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.lines.borrow_mut())
    }
}

impl Sink for Log {
    fn push(&self, text: String) {
        self.lines.borrow_mut().push(format!("push {text}"));
    }

    fn flush(&self) {
        self.lines.borrow_mut().push("flush".to_owned());
    }

    fn holds_pii(&self, text: &str) -> Option<bool> {
        self.scans.set(self.scans.get() + 1);
        Store(self.store.as_ref()?).holds_pii(text)
    }

    fn show(&self, field: Rect, mark: Mark) {
        self.lines.borrow_mut().push(show(mark, field));
    }

    fn hide(&self) {
        self.lines.borrow_mut().push("hide".to_owned());
    }
}

/// What [`Log`] writes for an outline.
pub(super) fn show(mark: Mark, field: Rect) -> String {
    format!(
        "show {mark:?} ({},{},{},{})",
        field.left, field.top, field.right, field.bottom
    )
}

/// A purpose that only outlines, the way `mode` says: no protection.
pub(super) fn lamp(mode: Highlight) -> Arc<Purpose> {
    let purpose = Arc::new(Purpose::default());
    purpose.set_mask(false);
    purpose.set_highlight(mode);
    purpose
}

pub(super) fn after(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

/// A vault folder that goes away with the test.
pub(super) struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A store over a real engine, with protection on but nothing protected.
pub(super) fn shared(tag: &str) -> Result<(Arc<Shared>, Folder), String> {
    let dir = std::env::temp_dir().join(format!("piikey-capture-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).describe()?;
    let folder = Folder(dir);
    let engine = Engine::open(&folder.0.join("vault.pkv")).describe()?;
    let shared = Arc::new(Shared {
        engine: RwLock::new(Arc::new(engine)),
        policy: RwLock::new(Policy {
            enabled: true,
            ..Policy::default()
        }),
        ledger: Ledger::default(),
        typed: Typed::new(),
        purpose: Arc::default(),
    });
    Ok((shared, folder))
}
