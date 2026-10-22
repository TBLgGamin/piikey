//! The system's side of the watch: file-system change notifications for the folders the user
//! asked to be watched, as [`Change`]s for the controller (see `controller/watch.rs`, which
//! lets them settle and scans what they name). The Windows API behind it is wrapped by the
//! `notify` crate, because calling it takes `unsafe`.

use std::{path::PathBuf, sync::mpsc::Sender};

use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
    event::{ModifyKind, RenameMode},
};

use super::controller::{Change, Running, Started};
use crate::Res;

/// What the user is told of a folder that is not there.
const GONE: &str = "The folder is not there.";

/// Watches `folders`, below them too, and sends every change in them to `changes`. A folder that
/// cannot be watched (it is gone, or not allowed) is named in the answer with why, and the others
/// are watched all the same.
///
/// # Errors
/// The system would not make a watcher at all.
pub fn start(folders: &[PathBuf], changes: Sender<Change>) -> Res<Started> {
    let mut watcher = RecommendedWatcher::new(
        move |event: notify::Result<Event>| match event {
            Ok(event) => {
                for change in changes_of(&event) {
                    if changes.send(change).is_err() {
                        return;
                    }
                }
            }
            // The system could not say what happened: anything may have.
            Err(_) => drop(changes.send(Change::Everything)),
        },
        Config::default(),
    )
    .map_err(|error| error.to_string())?;
    let mut failed = Vec::new();
    for folder in folders {
        if !folder.is_dir() {
            failed.push((folder.clone(), GONE.to_owned()));
        } else if let Err(error) = watcher.watch(folder, RecursiveMode::Recursive) {
            failed.push((folder.clone(), error.to_string()));
        }
    }
    Ok(Started {
        running: Box::new(watcher),
        failed,
    })
}

// Dropping the watcher ends it, and with it the handler that owns the sender of the changes.
impl Running for RecommendedWatcher {
    fn stop(self: Box<Self>) {
        drop(self);
    }
}

/// What a report of the system says changed: a path that was written, created or removed, or that
/// the system lost track of. A path that is created or renamed to is fresh.
fn changes_of(event: &Event) -> Vec<Change> {
    if event.need_rescan() {
        return vec![Change::Everything];
    }
    let at = |path: &PathBuf, fresh: bool| Change::Path {
        path: path.clone(),
        fresh,
    };
    match event.kind {
        EventKind::Access(_) => Vec::new(),
        // Both names in one report: the first is where it was, the second where it is now.
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => match event.paths.as_slice() {
            [from, to] => vec![at(from, false), at(to, true)],
            paths => paths.iter().map(|path| at(path, true)).collect(),
        },
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            event.paths.iter().map(|path| at(path, true)).collect()
        }
        EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Any | EventKind::Other => {
            event.paths.iter().map(|path| at(path, false)).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::mpsc::{self, RecvTimeoutError},
        time::{Duration, Instant},
    };

    use notify::event::{AccessKind, CreateKind, DataChange, Flag, RemoveKind};

    use super::*;
    use crate::ui::testing::TempDir;

    fn at(path: &str, fresh: bool) -> Change {
        Change::Path {
            path: PathBuf::from(path),
            fresh,
        }
    }

    fn event(kind: EventKind, paths: &[&str]) -> Event {
        paths.iter().fold(Event::new(kind), |event, path| {
            event.add_path(PathBuf::from(path))
        })
    }

    #[test]
    fn what_is_created_or_renamed_to_is_fresh_and_the_rest_is_just_changed() {
        let made = event(EventKind::Create(CreateKind::File), &["a"]);
        assert_eq!(changes_of(&made), [at("a", true)]);
        let to = event(EventKind::Modify(ModifyKind::Name(RenameMode::To)), &["b"]);
        assert_eq!(changes_of(&to), [at("b", true)]);
        let from = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            &["c"],
        );
        assert_eq!(changes_of(&from), [at("c", false)]);
        let written = event(EventKind::Modify(ModifyKind::Data(DataChange::Any)), &["d"]);
        assert_eq!(changes_of(&written), [at("d", false)]);
        let any = event(EventKind::Modify(ModifyKind::Any), &["e"]);
        assert_eq!(changes_of(&any), [at("e", false)]);
        let removed = event(EventKind::Remove(RemoveKind::File), &["f"]);
        assert_eq!(changes_of(&removed), [at("f", false)]);
        assert_eq!(changes_of(&event(EventKind::Any, &["g"])), [at("g", false)]);
    }

    #[test]
    fn a_rename_that_names_both_is_where_it_was_and_where_it_is() {
        let both = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            &["old", "new"],
        );
        assert_eq!(changes_of(&both), [at("old", false), at("new", true)]);
        // A report that does not name two is not trusted to say which is which.
        let odd = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            &["one"],
        );
        assert_eq!(changes_of(&odd), [at("one", true)]);
    }

    #[test]
    fn a_read_says_nothing_and_a_lost_report_says_everything() {
        let read = event(EventKind::Access(AccessKind::Any), &["a"]);
        assert!(changes_of(&read).is_empty());
        let lost = Event::new(EventKind::Other).set_flag(Flag::Rescan);
        assert_eq!(changes_of(&lost), [Change::Everything]);
        let lost_here = event(EventKind::Modify(ModifyKind::Any), &["a"]).set_flag(Flag::Rescan);
        assert_eq!(changes_of(&lost_here), [Change::Everything]);
        assert!(changes_of(&Event::new(EventKind::Other)).is_empty());
        let many = event(EventKind::Create(CreateKind::Any), &["a", "b"]);
        assert_eq!(changes_of(&many), [at("a", true), at("b", true)]);
    }

    /// Waits for a change at `file`, which the system reports a moment after the file is
    /// written.
    fn wait_for(changes: &mpsc::Receiver<Change>, file: &std::path::Path) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or("the system never reported the file")?;
            match changes.recv_timeout(left) {
                Ok(Change::Path { path, .. }) if path == file => return Ok(()),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    return Err("the system never reported the file".to_owned());
                }
                Err(RecvTimeoutError::Disconnected) => return Err("the watch ended".to_owned()),
            }
        }
    }

    #[test]
    fn the_system_reports_a_file_written_in_a_watched_folder_below_it_too() -> Result<(), String> {
        let dir = TempDir::new()?;
        let sub = dir.0.join("sub");
        fs::create_dir_all(&sub).map_err(|e| e.to_string())?;
        let (sender, changes) = mpsc::channel();
        let started = start(std::slice::from_ref(&dir.0), sender)?;
        assert!(started.failed.is_empty());

        let first = dir.0.join("a.txt");
        fs::write(&first, "x").map_err(|e| e.to_string())?;
        wait_for(&changes, &first)?;
        let deep = sub.join("b.txt");
        fs::write(&deep, "y").map_err(|e| e.to_string())?;
        wait_for(&changes, &deep)?;
        fs::remove_file(&first).map_err(|e| e.to_string())?;
        wait_for(&changes, &first)?;

        // Stopping ends the watch: the sender it held is dropped.
        started.running.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match changes.recv_timeout(Duration::from_millis(200)) {
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
                Ok(_) | Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                _ => return Err("the watch did not end".to_owned()),
            }
        }
    }

    #[test]
    fn a_folder_that_is_not_there_is_named_and_the_others_are_watched() -> Result<(), String> {
        let dir = TempDir::new()?;
        let gone = dir.0.join("gone");
        let file = dir.0.join("not-a-folder.txt");
        fs::write(&file, "x").map_err(|e| e.to_string())?;
        let (sender, changes) = mpsc::channel();
        let started = start(&[gone.clone(), dir.0.clone(), file.clone()], sender)?;
        assert_eq!(
            started.failed,
            [(gone, GONE.to_owned()), (file, GONE.to_owned())]
        );
        let written = dir.0.join("w.txt");
        fs::write(&written, "x").map_err(|e| e.to_string())?;
        wait_for(&changes, &written)?;
        started.running.stop();
        Ok(())
    }
}
