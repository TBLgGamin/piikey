//! What the loop reads from Windows: [`Desktop`], and the types it answers with.

use std::num::NonZeroU32;

use crate::highlight::Rect;

/// The element that has the keyboard focus, as far as the loop tells one element from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Focus {
    /// What identifies the element among the elements on the desktop.
    pub id: Vec<i32>,
    /// It is a password field, or Windows will not say it is none: nothing of it is read. Part of
    /// the identity, so a field that turns into a password field, or back, is judged afresh.
    pub password: bool,
}

/// A text field the user can type in, as the outline sees it.
pub(super) struct Field {
    /// Where it is on the screen.
    pub rect: Rect,
    /// What it holds.
    pub text: String,
}

impl Field {
    /// The field the outline is about, from what was read of the focused element: none for a
    /// password field, one of piikey's own windows, an element that holds no text the user can
    /// type, or one that has no place on the screen.
    pub(super) fn of(
        password: bool,
        own: bool,
        text: Option<String>,
        rect: Option<Rect>,
    ) -> Option<Self> {
        if password || own {
            return None;
        }
        Some(Self {
            rect: rect?,
            text: text?,
        })
    }
}

/// A piece of personal data in the text of a field, as the text control is asked to find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Value {
    /// What it says.
    pub text: String,
    /// Which of the places in the field's text where that text stands it is, counted from 0: the
    /// same words can be in the field twice.
    pub nth: usize,
}

/// What the clipboard holds.
pub(super) enum Clip {
    /// Text.
    Text(String),
    /// Nothing, or nothing that is text: there is nothing to read until the clipboard changes.
    NoText,
    /// Text that could not be read just now, because another program has the clipboard open while
    /// it writes to it: ask again.
    Busy,
}

/// What the loop reads from Windows. [`Uia`](super::uia::Uia) is the real one; the tests script one.
pub(super) trait Desktop {
    /// Reads the element with the keyboard focus and returns what identifies it: it differs from
    /// the last one when the focus moved. `None` when nothing readable has the focus. `with_text`
    /// asks for the element's text along with it, which the caller wants when it will read that.
    fn focus(&mut self, with_text: bool) -> Option<Focus>;
    /// Whether the element [`focus`](Self::focus) returned, which is no password field, is in a
    /// protected page or program.
    fn protected(&mut self) -> bool;
    /// What the user has typed into that element; `None` when it is no text field, cannot be read
    /// or is read-only.
    fn text(&mut self) -> Option<String>;
    /// That element as a field to outline: where it is on the screen and what it holds. `None` when
    /// it is no text field the user can type in (a page, a read-only field, a password field),
    /// belongs to piikey itself, or is not on the screen in one piece.
    fn field(&mut self) -> Option<Field>;
    /// Where that element is on the screen now; `None` when that cannot be told.
    fn bounds(&mut self) -> Option<Rect>;
    /// Where `values` are on the screen, in the text of the element [`focus`](Self::focus)
    /// returned: a rectangle around each line of each one that is in view, in reading order, as
    /// close to the text as its text control lets them be. Empty when that element has no text
    /// control that can say, or none of the values is in view.
    fn places(&mut self, values: &[Value]) -> Vec<Rect>;
    /// Whether the first value that the last call to [`places`](Self::places) found is still at
    /// `rect`: the text may have scrolled or moved since. `false` when that cannot be told.
    fn still_at(&mut self, rect: Rect) -> bool;
    /// Changes whenever the clipboard does; `None` when Windows will not tell.
    fn clipboard_seq(&mut self) -> Option<NonZeroU32>;
    /// The text on the clipboard.
    fn clipboard_text(&mut self) -> Clip;
}

#[cfg(test)]
mod tests {
    use super::Field;
    use crate::capture::testing::{EMAIL, FIELD};

    #[test]
    fn a_password_field_is_no_field() {
        let rect = Some(FIELD);
        let text = || Some(EMAIL.to_owned());
        assert!(Field::of(true, false, text(), rect).is_none(), "password");
        assert!(Field::of(true, true, text(), rect).is_none(), "both");
        assert!(
            Field::of(false, true, text(), rect).is_none(),
            "piikey's own window"
        );
        assert!(
            Field::of(false, false, None, rect).is_none(),
            "no text to type in"
        );
        assert!(
            Field::of(false, false, text(), None).is_none(),
            "not on the screen"
        );
        let field = Field::of(false, false, text(), rect).map(|field| (field.rect, field.text));
        assert_eq!(field, Some((FIELD, EMAIL.to_owned())));
    }
}
