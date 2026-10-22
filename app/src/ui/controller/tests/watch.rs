use super::*;

/// A folder `watched` in `dir` with one file that holds an email address.
fn watched(dir: &TempDir) -> Result<PathBuf, String> {
    let folder = dir.0.join("watched");
    fs::create_dir(&folder).describe()?;
    fs::write(folder.join("a.txt"), "mail jan.jansen@acme.nl").describe()?;
    Ok(folder)
}

/// A rig whose settings keep an eye on `folders`, with the watch `on`.
fn rig_watching(folders: &[&Path], on: bool) -> Result<Rig, String> {
    rig(
        true,
        Policy {
            watch: on,
            watch_folders: folders.iter().map(|folder| folder.to_path_buf()).collect(),
            ..quiet()
        },
    )
}

/// Waits until the watch has scanned and holds `totals`.
fn watch_holds(rig: &Rig, totals: (u64, u64)) -> Result<Snapshot, String> {
    wait_for(&rig.controller, |s| {
        s.watch.totals == totals && s.watch.scanning.is_none()
    })
}

fn statuses(snapshot: &Snapshot) -> Vec<FolderStatus> {
    snapshot
        .watch
        .folders
        .iter()
        .map(|folder| folder.status.clone())
        .collect()
}

#[test]
fn switching_the_watch_on_starts_the_watcher_and_catches_up_into_its_own_inventory() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], false)?;
    // Off: nothing watches and nothing is scanned, whatever the folders say.
    let before = rig.controller.snapshot();
    assert_eq!(statuses(&before), [FolderStatus::Off]);
    assert_eq!(before.watch.folders[0].path, folder);
    assert_eq!(before.watch.folders[0].last_change, None);
    assert!(
        !rig.calls()
            .iter()
            .any(|call| call.starts_with("start_watch"))
    );

    rig.run(Command::Edit(Edit::Watch(true)))?;
    assert!(has_call(&rig, "start_watch(1)"));
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert!(rig.fake.last_saved()?.watch);
    // It is the watch's: the inventory knows nothing of it, and the dialog is not asked for.
    assert_eq!(snapshot.inventory_totals, (0, 0));
    assert_eq!(rig.controller.inventory().totals().files, 0);
    assert_eq!(rig.controller.watch_store.totals().files, 1);
    assert_eq!(snapshot.reveal, None);
    // The model is kept for as long as the watch watches.
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert!(has_call(&rig, "load_model"));
    assert_ne!(
        rig.calls().last().map(String::as_str),
        Some("release_model")
    );
    Ok(())
}

#[test]
fn a_change_is_scanned_once_it_has_settled_and_a_removed_file_is_forgotten() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], true)?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    // The system reports a new file, and the watch looks at it after it has been quiet.
    let new = folder.join("b.txt");
    fs::write(&new, "call +31 6 12345678").describe()?;
    let reported = Instant::now();
    rig.fake.report(Change::Path {
        path: new.clone(),
        fresh: true,
    })?;
    let snapshot = watch_holds(&rig, (2, 2))?;
    assert!(
        reported.elapsed() >= Duration::from_secs(1),
        "it waited for the file to settle"
    );
    assert!(snapshot.watch.folders[0].last_change.is_some());
    let top = rig
        .controller
        .inventory_view(Store::Watch, Path::new(""), None);
    assert_eq!(top.nodes.len(), 1);
    assert_eq!((top.nodes[0].files, top.nodes[0].hits), (2, 2));
    // The top of the tree is the drive; the watched folder's own counts are its place's.
    let places = rig.controller.places(Store::Watch);
    assert_eq!(places.len(), 1);
    assert_eq!(places[0].path, folder);
    assert_eq!((places[0].files, places[0].hits), (2, 2));

    // A file that is removed is gone from what the watch found.
    fs::remove_file(&new).describe()?;
    rig.fake.report(Change::Path {
        path: new,
        fresh: false,
    })?;
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(snapshot.inventory_totals, (0, 0));
    Ok(())
}

#[test]
fn a_file_written_again_and_again_is_scanned_once_when_the_writing_stops() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], true)?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    let file = folder.join("c.txt");
    fs::write(&file, "call +31 6 12345678").describe()?;
    for _ in 0..5 {
        rig.fake.report(Change::Path {
            path: file.clone(),
            fresh: false,
        })?;
        thread::sleep(Duration::from_millis(300));
    }
    // Nothing was scanned while it was being written.
    assert_eq!(rig.controller.watch_store.totals().files, 1);
    watch_holds(&rig, (2, 2))?;
    Ok(())
}

#[test]
fn reports_that_may_have_been_lost_make_the_watch_look_at_everything() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], true)?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    // A file nobody reported, and then the system says it lost track.
    fs::write(folder.join("quiet.txt"), "call +31 6 12345678").describe()?;
    rig.fake.report(Change::Everything)?;
    watch_holds(&rig, (2, 2))?;
    Ok(())
}

#[test]
fn what_cannot_be_watched_is_named_and_the_rest_is_watched() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let gone = dir.0.join("gone");
    let rig = rig_watching(&[&folder, &gone], true)?;
    rig.fake
        .watch_unavailable
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((gone.clone(), "The folder is not there.".to_owned()));
    rig.run(Command::Startup)?;
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(
        statuses(&snapshot),
        [
            FolderStatus::Watching,
            FolderStatus::Unavailable("The folder is not there.".to_owned())
        ]
    );
    assert_eq!(snapshot.watch.folders[1].path, gone);
    assert!(snapshot.notice.is_none(), "a status, not a notice");
    Ok(())
}

#[test]
fn when_the_system_will_not_watch_the_user_is_told_and_nothing_runs() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], false)?;
    fail(&rig.fake.fail_watch);
    rig.run(Command::Edit(Edit::Watch(true)))?;
    let snapshot = rig.controller.snapshot();
    assert_eq!(
        statuses(&snapshot),
        [FolderStatus::Unavailable("no watcher".to_owned())]
    );
    let notice = snapshot.notice.ok_or("no notice")?;
    assert!(
        notice
            .text
            .starts_with("Could not watch your folders: no watcher"),
        "{}",
        notice.text
    );
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.watch_store.totals().files, 0);
    // The switch is still on: the user decides, and the next change of the folders tries again.
    assert!(snapshot.policy.watch);
    Ok(())
}

#[test]
fn switching_the_watch_off_stops_the_watcher_and_keeps_what_it_found() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], true)?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    rig.run(Command::Edit(Edit::Watch(false)))?;
    assert!(has_call(&rig, "stop_watch"));
    assert!(
        rig.fake.report(Change::Everything).is_err(),
        "nothing watches"
    );
    let snapshot = rig.controller.snapshot();
    assert_eq!(statuses(&snapshot), [FolderStatus::Off]);
    assert_eq!(
        snapshot.watch.totals,
        (1, 1),
        "what it found is still there to look at"
    );
    // Nothing needs the model any more.
    eventually("the model to be released", || {
        rig.calls()
            .last()
            .is_some_and(|call| call == "release_model")
    })?;

    // Switched on again, it catches up on what happened meanwhile.
    fs::write(folder.join("later.txt"), "call +31 6 12345678").describe()?;
    rig.run(Command::Edit(Edit::Watch(true)))?;
    watch_holds(&rig, (2, 2))?;
    Ok(())
}

#[test]
fn adding_and_removing_a_watched_folder_restarts_the_watcher_and_forgets_what_left() -> Test {
    let dir = TempDir::new()?;
    let first = watched(&dir)?;
    let second = dir.0.join("second");
    fs::create_dir(&second).describe()?;
    fs::write(second.join("s.txt"), "call +31 6 12345678").describe()?;
    let rig = rig_watching(&[&first], true)?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;

    rig.run(Command::Edit(Edit::WatchFolder {
        path: second.clone(),
        on: true,
    }))?;
    assert!(has_call(&rig, "start_watch(2)"));
    assert!(has_call(&rig, "stop_watch"), "the old watcher ended first");
    let snapshot = watch_holds(&rig, (2, 2))?;
    assert_eq!(
        snapshot
            .watch
            .folders
            .iter()
            .map(|folder| folder.path.clone())
            .collect::<Vec<_>>(),
        [first.clone(), second.clone()]
    );

    rig.run(Command::Edit(Edit::WatchFolder {
        path: first,
        on: false,
    }))?;
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(snapshot.watch.folders.len(), 1);
    assert_eq!(snapshot.watch.folders[0].path, second);
    assert_eq!(rig.controller.watch_store.totals().files, 1);

    // A folder that is no folder is refused with a notice, and the watch goes on.
    rig.run(Command::Edit(Edit::WatchFolder {
        path: dir.0.join("nothing"),
        on: true,
    }))?;
    let notice = rig.controller.snapshot().notice.ok_or("no notice")?;
    assert!(notice.text.starts_with("Not a folder:"), "{}", notice.text);
    Ok(())
}

#[test]
fn the_saved_watch_starts_with_the_app_and_ends_with_it() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_watching(&[&folder], true)?;
    rig.run(Command::Startup)?;
    assert!(has_call(&rig, "start_watch(1)"));
    watch_holds(&rig, (1, 1))?;
    rig.controller.shutdown();
    assert!(has_call(&rig, "stop_watch"));
    Ok(())
}

#[test]
fn a_watch_with_no_folder_has_nothing_to_watch() -> Test {
    let rig = rig_watching(&[], false)?;
    rig.run(Command::Edit(Edit::Watch(true)))?;
    assert!(
        !rig.calls()
            .iter()
            .any(|call| call.starts_with("start_watch"))
    );
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.policy.watch);
    assert!(snapshot.watch.folders.is_empty());
    assert!(!has_call(&rig, "load_model"), "nothing to scan, no model");
    Ok(())
}

#[test]
fn what_the_user_asks_for_goes_into_the_inventory_and_not_into_the_watch() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let elsewhere = dir.0.join("elsewhere");
    fs::create_dir(&elsewhere).describe()?;
    fs::write(elsewhere.join("e.txt"), "call +31 6 12345678").describe()?;
    let rig = rig_watching(&[&folder], true)?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;

    rig.run(Command::ScanFiles {
        paths: vec![folder.clone(), elsewhere],
        reveal: true,
    })?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| matches!(reveal.state, RevealState::Done(_)))
            && s.scan.is_none()
    })?;
    assert_eq!(snapshot.inventory_totals, (2, 2));
    assert_eq!(snapshot.watch.totals, (1, 1), "the watch's own, untouched");
    assert_eq!(rig.controller.inventory().totals().files, 2);
    assert_eq!(rig.controller.watch_store.totals().files, 1);
    Ok(())
}
