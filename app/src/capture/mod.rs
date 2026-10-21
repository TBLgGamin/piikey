//! Reads the focused text field: what the user types or pastes into a protected site or program,
//! and whether the field holds personal data, to outline it.
//!
//! While protection or highlighting is on, [`start`] runs a `piikey-capture` worker thread, watched
//! by a `piikey-capture-watch` supervisor (see `supervisor`). A few times a second the worker asks
//! Windows UI Automation, the interface screen readers use, for the element that has the keyboard
//! focus: one call, which returns the handful of properties the thread needs along with it.
//! Only when the focus moves to another element does it work out whether that element sits in a
//! protected page or program (and is no password field); until then nothing else is asked of the
//! system. For an element that does, and while protection is on, it reads the text of the field and,
//! when the clipboard changed, the clipboard, and hands both to [`Typed`](crate::proxy::Typed),
//! which keeps the personal data in them so the proxy can mask exactly those values in what the
//! page sends.
//!
//! The highlight ([`Purpose::highlight`](crate::proxy::Purpose::highlight)) uses the same reader.
//! In `Always` mode the text of every field in focus that is no password and not piikey's own is
//! checked for personal data a moment after it stops changing; in `Hotkey` mode the field is
//! checked when the shortcut is pressed. [`Engine::scan`](piikey::engine::Engine::scan) does the
//! checking, which keeps nothing and writes nothing to the vault. The verdict goes to the
//! [overlay](crate::highlight::Overlay), which outlines the field's rectangle on the screen.
//!
//! No browser setting or extension is needed: Chromium builds its accessibility tree by itself when
//! a UI Automation client asks for it, and its page element carries the page's address as its value.
//! Text the thread reads goes nowhere but into `Typed` and detection, and is never logged.
//!
//! The parts: `uia` reads Windows; `watcher` and `outline` decide what a look means and know
//! nothing of Windows, they run against the `desktop` and the `sink` the tests script; and
//! `supervisor` runs them on threads.

mod desktop;
mod outline;
mod sink;
mod supervisor;
#[cfg(test)]
mod testing;
mod uia;
mod watcher;

use std::time::Duration;

pub(crate) use self::supervisor::{Capture, start};

/// How often the focus is read while it is in a protected page or program: a paste or a message
/// sent right after typing must still find its text.
const FAST: Duration = Duration::from_millis(100);
/// How often it is read anywhere else.
const SLOW: Duration = Duration::from_millis(400);
/// Text that has not changed for this long goes to detection.
const SETTLE: Duration = Duration::from_millis(300);
/// How long the outline that answers the shortcut stays, unless something ends it sooner.
const SHOW_FOR: Duration = Duration::from_secs(10);
/// How long the green flash that says a field holds no personal data stays.
const FLASH_FOR: Duration = Duration::from_millis(1_200);
