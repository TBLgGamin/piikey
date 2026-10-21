//! The timer that wakes the application thread while no window is open.
//!
//! The application thread only runs when a message reaches it. `Application` gives no other
//! thread a way to send one: its senders and callbacks are bound to that thread, and the
//! dispatcher behind them is private to windows-reactor. With a window open, the window's own poll
//! of the controller reaches the application; with none, nothing does, so a scan that ends while
//! the app is only a tray icon, or a protection switch made through the API, would wait for the
//! next click on the icon. This timer fills the gap: a few times a second, on the application
//! thread, it compares what the tray shows and the number of the latest scan that asks to be shown
//! with what it saw last, and calls `wake` when they differ.

use std::{cell::Cell, sync::Arc, time::Duration};

use windows_reactor::LiveTickSubscription;

use super::controller::{Controller, Tray};

/// How often the timer looks. The look is one short lock and a compare, so this can be often
/// enough for a window that opens at once without costing anything while the app idles.
const EVERY: Duration = Duration::from_millis(250);

/// Keeps the timer running; dropping it stops the timer.
#[must_use = "dropping the ticker stops the timer"]
pub(super) struct Ticker {
    _timer: LiveTickSubscription,
}

impl Ticker {
    /// Starts the timer on the calling thread, which must be the application thread. `None` when
    /// the runtime refuses a timer: the tray then follows the app only while a window is open.
    pub(super) fn start(controller: Arc<Controller>, wake: impl Fn() + 'static) -> Option<Self> {
        let seen = Seen::new(controller.tray());
        windows_reactor::subscribe_live_interval(EVERY, move || {
            if seen.changed(controller.tray()) {
                wake();
            }
        })
        .inspect_err(|error| {
            eprintln!("piikey: the tray cannot follow the app while its window is closed: {error}");
        })
        .ok()
        .map(|timer| Self { _timer: timer })
    }
}

/// What the timer saw last.
struct Seen(Cell<Tray>);

impl Seen {
    const fn new(tray: Tray) -> Self {
        Self(Cell::new(tray))
    }

    /// Whether `now` differs from what was seen last, which `now` then becomes.
    fn changed(&self, now: Tray) -> bool {
        self.0.replace(now) != now
    }
}

#[cfg(test)]
mod tests {
    use super::{Seen, Tray};

    const IDLE: Tray = Tray {
        on: false,
        highlight_paused: false,
        reveal: 0,
    };

    #[test]
    fn it_wakes_the_application_once_per_change() {
        let seen = Seen::new(IDLE);
        assert!(!seen.changed(IDLE), "nothing changed since the start");
        let scanned = Tray { reveal: 1, ..IDLE };
        assert!(seen.changed(scanned), "a scan asks to be shown");
        assert!(!seen.changed(scanned), "asked once, not at every look");
        let on = Tray {
            on: true,
            ..scanned
        };
        assert!(seen.changed(on), "the tray's icon follows protection");
        let paused = Tray {
            highlight_paused: true,
            ..on
        };
        assert!(seen.changed(paused), "and the paused highlight");
        assert!(seen.changed(Tray {
            reveal: 2,
            ..paused
        }));
        assert!(seen.changed(IDLE), "a change back is a change too");
    }
}
