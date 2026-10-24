//! Where what was read goes: [`Sink`], and [`Store`], the real one.

use std::sync::{Arc, PoisonError};

use piikey::{detect::Span, engine::Engine};

use super::desktop::Value;
use crate::{
    highlight::{Mark, Overlay, Rect},
    proxy::Shared,
};

/// The most values of one field that are told apart: a field with more is outlined for the first
/// of them.
pub(super) const MAX_VALUES: usize = 16;

/// Where what was read goes.
pub(super) trait Sink {
    /// Keeps the text for the next [`flush`](Self::flush).
    fn push(&self, text: String);
    /// Runs detection over everything pushed so far.
    fn flush(&self);
    /// The personal data detection finds in `text`, in reading order, keeping nothing and writing
    /// nothing to the vault; empty when there is none, `None` when it cannot tell.
    fn values(&self, text: &str) -> Option<Vec<Value>>;
    /// Outlines each of `rects` in the colour of `mark`; asked again at every look, because the
    /// overlay lets outlines that are not asked for go.
    fn show(&self, rects: &[Rect], mark: Mark);
    /// Takes the outlines away.
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

    fn values(&self, text: &str) -> Option<Vec<Value>> {
        let found = self.engine().scan(&[text]).ok()?;
        Some(values_of(text, found.first()?))
    }

    fn show(&self, rects: &[Rect], mark: Mark) {
        // Before the overlay runs, or after it died, nothing is drawn.
        if let Some(overlay) = Overlay::get() {
            overlay.show(rects, mark);
        }
    }

    fn hide(&self) {
        Overlay::hide_any();
    }
}

/// The values the detector found in `text`, as `spans`, in reading order and as the text control
/// is asked to find them: what each says, and which of the places where those words stand in the
/// text it is. A span that is blank or not on character boundaries of the text is no value, and
/// there are at most [`MAX_VALUES`].
fn values_of(text: &str, spans: &[Span]) -> Vec<Value> {
    let mut ordered: Vec<&Span> = spans.iter().collect();
    ordered.sort_by_key(|span| span.start);
    ordered
        .into_iter()
        .filter_map(|span| {
            let value = text.get(span.start..span.end)?;
            if value.trim().is_empty() {
                return None;
            }
            // The same words stand earlier in the text as often as they are found before this one.
            let nth = text.get(..span.start)?.matches(value).count();
            Some(Value {
                text: value.to_owned(),
                nth,
            })
        })
        .take(MAX_VALUES)
        .collect()
}

#[cfg(test)]
mod tests {
    use piikey::detect::EntityKind;

    use super::*;

    fn span(text: &str, of: &str, nth: usize) -> Span {
        let start = text
            .match_indices(of)
            .nth(nth)
            .map_or(usize::MAX, |(start, _)| start);
        Span {
            start,
            end: start.saturating_add(of.len()),
            kind: EntityKind::Email,
        }
    }

    fn value(text: &str, nth: usize) -> Value {
        Value {
            text: text.to_owned(),
            nth,
        }
    }

    #[test]
    fn a_span_becomes_the_words_it_covers() {
        let text = "mail jan@acme.nl en NL91ABNA0417164300";
        let spans = [
            span(text, "jan@acme.nl", 0),
            span(text, "NL91ABNA0417164300", 0),
        ];
        assert_eq!(
            values_of(text, &spans),
            [value("jan@acme.nl", 0), value("NL91ABNA0417164300", 0)]
        );
    }

    #[test]
    fn the_same_words_twice_are_told_apart_by_their_place() {
        let text = "jan@acme.nl, mail jan@acme.nl of jan@acme.nl";
        let spans = [
            span(text, "jan@acme.nl", 2),
            span(text, "jan@acme.nl", 0),
            span(text, "jan@acme.nl", 1),
        ];
        // In reading order, whatever order the detector gave them in.
        assert_eq!(
            values_of(text, &spans),
            [
                value("jan@acme.nl", 0),
                value("jan@acme.nl", 1),
                value("jan@acme.nl", 2)
            ]
        );
    }

    #[test]
    fn words_that_stand_there_but_were_not_found_still_count_for_the_place() {
        // The first "jan" is part of a longer word and is no value; the second is.
        let text = "janssen en jan";
        let spans = [span(text, "jan", 1)];
        assert_eq!(values_of(text, &spans), [value("jan", 1)]);
    }

    #[test]
    fn a_span_that_is_blank_or_off_the_text_is_no_value() {
        let text = "a  b ë";
        let blank = Span {
            start: 1,
            end: 3,
            kind: EntityKind::Email,
        };
        // Inside the two bytes of `ë`.
        let torn = Span {
            start: 6,
            end: 7,
            kind: EntityKind::Email,
        };
        let past = Span {
            start: 4,
            end: 99,
            kind: EntityKind::Email,
        };
        assert_eq!(values_of(text, &[blank, torn, past]), Vec::<Value>::new());
        assert_eq!(values_of(text, &[]), Vec::<Value>::new());
    }

    #[test]
    fn a_field_with_very_many_values_is_told_apart_for_the_first_ones() {
        let text = "x@y.nl ".repeat(MAX_VALUES + 5);
        let spans: Vec<Span> = (0..MAX_VALUES + 5)
            .map(|n| span(&text, "x@y.nl", n))
            .collect();
        let values = values_of(&text, &spans);
        assert_eq!(values.len(), MAX_VALUES);
        assert_eq!(values.last().map(|v| v.nth), Some(MAX_VALUES - 1));
    }
}
