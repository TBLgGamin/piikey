//! The timer that wakes the application thread while no window is open.
//!
//! The application thread only runs when a message reaches it. `Application` gives no other
//! thread a way to send one: its senders and callbacks are bound to that thread, and the
//! dispatcher behind them is private to windows-reactor. With a window open, the window's own poll
//! of the controller reaches the application; with none, nothing does, so a scan that ends while
//! the app is only a tray icon, a protection switch made through the API, or a second start of the
//! app asking for its window would wait for the next click on the icon. This timer fills the gap: a
//! few times a second, on the application thread, it compares what the tray shows (its [`Tray`] and
//! the [`Status`] it says), the number of the latest scan that asks to be shown and the number of
//! requests for the window with what it saw last, and calls `wake` when they differ.

use std::{
    cell::{Cell, RefCell},
    sync::Arc,
    time::Duration,
};

use windows_reactor::LiveTickSubscription;

use super::{
    controller::{Controller, Snapshot, Tray},
    status::Status,
};

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
        let seen = Seen::new(controller.tray(), &controller.snapshot());
        windows_reactor::subscribe_live_interval(EVERY, move || {
            if seen.changed(&controller) {
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
struct Seen {
    tray: Cell<Tray>,
    /// The version of the snapshot `status` was made from: the status is only made anew when the
    /// controller has changed, which is rare next to how often the timer looks.
    version: Cell<u64>,
    status: RefCell<Status>,
}

impl Seen {
    fn new(tray: Tray, snapshot: &Snapshot) -> Self {
        Self {
            tray: Cell::new(tray),
            version: Cell::new(snapshot.version),
            status: RefCell::new(Status::of(snapshot, None)),
        }
    }

    /// Whether the controller shows something else than at the last look.
    fn changed(&self, controller: &Controller) -> bool {
        let tray = controller.tray();
        let snapshot = controller.wait_changed(self.version.get(), Duration::ZERO);
        let status = snapshot.map(|snapshot| {
            self.version.set(snapshot.version);
            Status::of(&snapshot, None)
        });
        self.look(tray, status)
    }

    /// Whether `tray` or `status` (`None` while the controller has not changed) differs from what
    /// was seen last, which they then become.
    fn look(&self, tray: Tray, status: Option<Status>) -> bool {
        let tray_changed = self.tray.replace(tray) != tray;
        let status_changed = status.is_some_and(|status| {
            let changed = *self.status.borrow() != status;
            *self.status.borrow_mut() = status;
            changed
        });
        tray_changed || status_changed
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::testing::{TempDir, stub_controller},
        Seen, Status, Tray,
    };

    const IDLE: Tray = Tray {
        on: false,
        highlight_paused: false,
        reveal: 0,
        show: 0,
    };

    const OFF: Status = Status::Off {
        needs_certificate: false,
    };

    #[test]
    fn it_wakes_the_application_once_per_change() -> Result<(), String> {
        let dir = TempDir::new()?;
        let controller = stub_controller(&dir)?;
        let seen = Seen::new(IDLE, &controller.snapshot());
        assert!(!seen.look(IDLE, None), "nothing changed since the start");
        let scanned = Tray { reveal: 1, ..IDLE };
        assert!(seen.look(scanned, None), "a scan asks to be shown");
        assert!(!seen.look(scanned, None), "asked once, not at every look");
        let on = Tray {
            on: true,
            ..scanned
        };
        assert!(seen.look(on, None), "the tray's icon follows protection");
        let paused = Tray {
            highlight_paused: true,
            ..on
        };
        assert!(seen.look(paused, None), "and the paused highlight");
        assert!(seen.look(
            Tray {
                reveal: 2,
                ..paused
            },
            None
        ));
        assert!(
            seen.look(Tray { show: 1, ..IDLE }, None),
            "a request to bring the window forward"
        );
        assert!(seen.look(IDLE, None), "a change back is a change too");
        Ok(())
    }

    #[test]
    fn it_wakes_the_application_when_what_the_tray_says_changes_alone() -> Result<(), String> {
        let dir = TempDir::new()?;
        let controller = stub_controller(&dir)?;
        let seen = Seen::new(IDLE, &controller.snapshot());
        // The certificate went missing while protection ran: the tray's state did not change,
        // what it says did.
        let attention = Status::NeedsAttention {
            running: true,
            cause: super::super::status::Cause::CertificateMissing,
        };
        assert!(!seen.look(IDLE, Some(OFF)), "the same status is no change");
        assert!(seen.look(IDLE, Some(attention.clone())));
        assert!(!seen.look(IDLE, Some(attention)), "said once");
        assert!(seen.look(IDLE, Some(OFF)), "and said again when it ends");
        Ok(())
    }

    #[test]
    fn a_look_at_an_unchanged_controller_makes_no_status() -> Result<(), String> {
        let dir = TempDir::new()?;
        let controller = stub_controller(&dir)?;
        let seen = Seen::new(controller.tray(), &controller.snapshot());
        assert!(!seen.changed(&controller), "nothing happened");
        assert!(!seen.changed(&controller), "nor since");
        controller.request_window();
        assert!(
            seen.changed(&controller),
            "a request for the window is a change"
        );
        assert!(!seen.changed(&controller));
        Ok(())
    }
}
