//! "Open at this place": opens a file where a value was found in it, as far as the app that opens
//! it allows. What was done is an [`Outcome`], best first:
//!
//! 1. **Placed.** The app that shows the file is an editor that takes a line and column on its
//!    command line: VS Code (and Insiders), Notepad++ and Sublime Text. It is known by the exe the
//!    registry names for the file type (`default_app`), or, when the registry names none (an app
//!    Windows starts through a package, as the Store VS Code), by the process of the window that
//!    has or gets the file open; it is started with the place (`editors`), and its running window
//!    goes there.
//! 2. **Marked.** Any other app. When a window already has the file open (its title names it), the
//!    value is looked for there and the file is not opened again. Otherwise Explorer hands the
//!    file to the app, as a double click would, and `uia` waits for its window. Either way it finds
//!    the text control that holds the value, selects the value there and has the highlight overlay
//!    outline it for two seconds, around the text and nothing else: `crate::uia_text` finds the
//!    rectangle of each line of the value through hit tests (the safe `uiautomation` wrapper has
//!    no `GetBoundingRectangles`, which is `unsafe`). `office` knows `PowerPoint` (the slide, then its
//!    shapes) and Excel (the sheet, then the cell), `needles` says what to look for when the value
//!    as shown is not what the text holds, and `titles` tells which window is the one.
//! 3. **Opened.** The file is open; piikey could not point at the value in the app that has it.
//!
//! Everything that merely fails to place the value is an `Opened`: it is a best effort, and quiet:
//! nothing is logged or printed, and no value is kept. It reads the app's text and selects the
//! value in it, and does nothing else to it but ask a window that had the file open already for
//! the focus, so that it comes to the front. The only error is a file that cannot be opened at all.
//!
//! [`open_at`] blocks for as long as it takes the app to show the file, up to about twelve
//! seconds, so it belongs on a thread of its own, never the UI's. UI Automation calls into a hung
//! app can wait for a long time; they run on a thread of their own that the caller does not wait
//! for past that time.
//!
//! A debug build opens the file with the exe that the environment variable `PIIKEY_OPEN_WITH`
//! names instead of through Explorer, when it is set: the screenshots are made on a private
//! desktop, and Explorer may hand the file to the shell on the desktop of the user.

mod default_app;
mod editors;
mod needles;
mod office;
mod titles;
mod uia;

use std::{
    ffi::OsString,
    io::ErrorKind,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use piikey::{formats::Location, sys::CREATE_NO_WINDOW};

use self::{
    default_app::default_exe,
    editors::Editor,
    uia::{Job, Search},
};
use super::explorer;
use crate::{Res, proxy::Purpose};

/// How long [`open_at`] waits for the app to show the file and the value to be found in it, from
/// the moment it starts to open it.
const BUDGET: Duration = Duration::from_secs(12);
/// How long the search may take to see which windows are open before the file is opened.
const LOOK_WAIT: Duration = Duration::from_secs(2);
/// The environment variable that names the exe a debug build opens files with.
#[cfg(debug_assertions)]
const OPEN_WITH: &str = "PIIKEY_OPEN_WITH";

/// What "Open at this place" opens, and where in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The file to open.
    pub file: PathBuf,
    /// The value to find in the file, as the findings list shows it: runs of white space are one
    /// space, and a value that was cut ends in `…`.
    pub value: String,
    /// Where the format says the value is, when it says: a line and column of a text, a page, a
    /// sheet and cell, a slide.
    pub place: Option<Location>,
}

/// What "Open at this place" did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The default app is an editor that takes a position (VS Code, Notepad++, Sublime Text) and
    /// was started at the line.
    Placed,
    /// The value was selected in the window of the app that opened the file and outlined for about
    /// two seconds.
    Marked,
    /// The file was opened; piikey could not point at the value in the app that has it.
    Opened,
}

/// Opens `target.file`, at its line and column when the app takes them, else with the value
/// selected and outlined in the app's window when that can be done. `purpose` is the one of the
/// app: the highlight overlay that draws the outline counts the presses of its shortcut on it.
///
/// Blocks for up to about twelve seconds: call it from a background thread.
///
/// # Errors
/// The file is no longer there, or Explorer cannot be started. The message is for the user.
pub fn open_at(target: &Target, purpose: &Arc<Purpose>) -> Res<Outcome> {
    open_and_mark(target, purpose)
}

/// How the default app of the file is started at the line of the target, when it is an editor
/// that takes a place: its exe and the arguments. `None` for any other app.
fn placing(target: &Target) -> Option<(PathBuf, Vec<OsString>)> {
    let Some(Location::Line { line, column }) = target.place else {
        return None;
    };
    let exe = default_exe(&target.file)?;
    let arguments = Editor::of(&exe)?.arguments(&target.file, line, column);
    Some((exe, arguments))
}

/// Starts `exe` with `arguments` and leaves it running, without a console window. Whether it
/// started.
fn start(exe: &Path, arguments: &[OsString]) -> bool {
    Command::new(exe)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .is_ok()
}

/// Looks for the value in a window that has the file open already, and goes straight to it there;
/// otherwise opens the file with its default app, and looks for the value in the window that shows
/// it.
fn open_and_mark(target: &Target, purpose: &Arc<Purpose>) -> Res<Outcome> {
    if let Err(error) = std::fs::metadata(&target.file)
        && error.kind() == ErrorKind::NotFound
    {
        return Err(format!(
            "Could not open {}: the file is no longer there.",
            name_of(&target.file)
        ));
    }
    let deadline = Instant::now() + BUDGET;
    let placing = placing(target);
    let job = Job::of(target, purpose).map(|mut job| {
        // The editor is started at the place: the window it shows is not sent there again.
        job.placed = placing.is_some();
        job
    });
    let mut search = job.and_then(Search::start);
    if let Some(search) = &mut search {
        let outcome = search.first(LOOK_WAIT);
        if outcome != Outcome::Opened {
            // The file is open and the value is pointed at, or its editor was told where to go:
            // opening it again would only open it twice.
            return Ok(outcome);
        }
    }
    // Dropping the search, when this fails, tells its thread to stop.
    let fallback = match placing {
        Some((exe, arguments)) if start(&exe, &arguments) => Outcome::Placed,
        _ => {
            open_file(&target.file)?;
            Outcome::Opened
        }
    };
    Ok(
        search.map_or(fallback, |mut search| match search.finish(deadline) {
            Outcome::Opened => fallback,
            outcome => outcome,
        }),
    )
}

/// Opens `file` in the app that Windows opens it with: Explorer hands it over, as a double click
/// does. A debug build uses the exe that `PIIKEY_OPEN_WITH` names, when it is set.
fn open_file(file: &Path) -> Res<()> {
    open_with_override(file).unwrap_or_else(|| explorer::open(file))
}

/// Starts the exe named by `PIIKEY_OPEN_WITH` with `file`; `None` when it is not set.
#[cfg(debug_assertions)]
fn open_with_override(file: &Path) -> Option<Res<()>> {
    let exe = std::env::var_os(OPEN_WITH).filter(|exe| !exe.is_empty())?;
    Some(
        Command::new(exe)
            .arg(file)
            .spawn()
            .map(|_| ())
            .map_err(|error| format!("Could not start the app: {error}")),
    )
}

/// A release build always uses Explorer.
#[cfg(not(debug_assertions))]
fn open_with_override(_file: &Path) -> Option<Res<()>> {
    None
}

/// The name of `file`, for a message to the user.
fn name_of(file: &Path) -> String {
    file.file_name().map_or_else(
        || file.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_gone_cannot_be_opened() {
        let target = Target {
            file: std::env::temp_dir().join("piikey-goto-test-there-is-no-such-file.txt"),
            value: "Jan Jansen".to_owned(),
            place: None,
        };
        let opened = open_at(&target, &Arc::new(Purpose::default()));
        assert_eq!(
            opened,
            Err("Could not open piikey-goto-test-there-is-no-such-file.txt: the file is no longer there.".to_owned())
        );
    }

    #[test]
    fn the_name_of_a_file_is_what_the_user_is_told() {
        assert_eq!(name_of(Path::new(r"C:\a b\c d.txt")), "c d.txt");
        assert_eq!(name_of(Path::new(r"C:\")), r"C:\");
    }
}
