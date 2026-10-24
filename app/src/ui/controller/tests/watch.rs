use super::*;

/// A folder `watched` in `dir` with one file that holds an email address.
fn watched(dir: &TempDir) -> Result<PathBuf, String> {
    let folder = dir.0.join("watched");
    fs::create_dir(&folder).describe()?;
    fs::write(folder.join("a.txt"), "mail jan.jansen@acme.nl").describe()?;
    Ok(folder)
}

/// A rig whose locations are `folders`, none of them monitored.
fn rig_locations(folders: &[&Path]) -> Result<Rig, String> {
    rig(
        true,
        Policy {
            inventory_roots: folders.iter().map(|folder| folder.to_path_buf()).collect(),
            ..quiet()
        },
    )
}

/// A rig whose locations are `folders`, all of them monitored.
fn rig_monitoring(folders: &[&Path]) -> Result<Rig, String> {
    let folders: Vec<PathBuf> = folders.iter().map(|folder| folder.to_path_buf()).collect();
    rig(
        true,
        Policy {
            inventory_roots: folders.clone(),
            monitored_roots: folders,
            ..quiet()
        },
    )
}

/// Waits until monitoring has scanned and the inventory holds `totals`.
fn watch_holds(rig: &Rig, totals: (u64, u64)) -> Result<Snapshot, String> {
    wait_for(&rig.controller, |s| {
        s.inventory_totals == totals && s.watch.scanning.is_none()
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
fn monitoring_a_location_starts_the_watcher_and_catches_up_into_the_inventory() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_locations(&[&folder])?;
    // A location that is not monitored: nothing watches it and nothing is scanned.
    let before = rig.controller.snapshot();
    assert!(before.watch.folders.is_empty());
    assert!(
        !rig.calls()
            .iter()
            .any(|call| call.starts_with("start_watch"))
    );

    rig.run(Command::Edit(Edit::Monitor {
        path: folder.clone(),
        on: true,
    }))?;
    assert!(has_call(&rig, "start_watch(1)"));
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(statuses(&snapshot), [FolderStatus::Watching]);
    assert_eq!(snapshot.watch.folders[0].path, folder);
    assert_eq!(snapshot.watch.folders[0].last_change, None);
    assert_eq!(rig.fake.last_saved()?.monitored_roots, [folder]);
    // What it found is in the inventory itself, and the dialog is not asked for.
    assert_eq!(rig.controller.inventory().totals().files, 1);
    assert_eq!(snapshot.reveal, None);
    // The model is kept for as long as the location is monitored.
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
    let rig = rig_monitoring(&[&folder])?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    // The system reports a new file, and monitoring looks at it after it has been quiet.
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
    let top = rig.controller.inventory_view(Path::new(""), None);
    assert_eq!(top.nodes.len(), 1);
    assert_eq!((top.nodes[0].files, top.nodes[0].hits), (2, 2));
    // The top of the tree is the drive; the location's own counts are its place's.
    let places = rig.controller.places();
    assert_eq!(places.len(), 1);
    assert_eq!(places[0].path, folder);
    assert_eq!((places[0].files, places[0].hits), (2, 2));

    // A file that is removed is gone from what monitoring found.
    fs::remove_file(&new).describe()?;
    rig.fake.report(Change::Path {
        path: new,
        fresh: false,
    })?;
    watch_holds(&rig, (1, 1))?;
    Ok(())
}

#[test]
fn a_file_written_again_and_again_is_scanned_once_when_the_writing_stops() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_monitoring(&[&folder])?;
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
    assert_eq!(rig.controller.inventory().totals().files, 1);
    watch_holds(&rig, (2, 2))?;
    Ok(())
}

#[test]
fn reports_that_may_have_been_lost_make_the_watch_look_at_everything() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_monitoring(&[&folder])?;
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
    let rig = rig_monitoring(&[&folder, &gone])?;
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
    let rig = rig_locations(&[&folder])?;
    fail(&rig.fake.fail_watch);
    rig.run(Command::Edit(Edit::Monitor {
        path: folder.clone(),
        on: true,
    }))?;
    let snapshot = rig.controller.snapshot();
    assert_eq!(
        statuses(&snapshot),
        [FolderStatus::Unavailable("no watcher".to_owned())]
    );
    let notice = snapshot.notice.ok_or("no notice")?;
    assert!(
        notice
            .text
            .starts_with("Could not monitor your locations: no watcher"),
        "{}",
        notice.text
    );
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.inventory().totals().files, 0);
    // The location is still monitored: the user decides, and the next change of the locations
    // tries again.
    assert_eq!(rig.controller.policy().monitored_roots, [folder]);
    Ok(())
}

#[test]
fn turning_monitoring_off_stops_the_watcher_and_keeps_what_was_found() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_monitoring(&[&folder])?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    rig.run(Command::Edit(Edit::Monitor {
        path: folder.clone(),
        on: false,
    }))?;
    assert!(has_call(&rig, "stop_watch"));
    assert!(
        rig.fake.report(Change::Everything).is_err(),
        "nothing watches"
    );
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.watch.folders.is_empty());
    assert_eq!(
        snapshot.inventory_totals,
        (1, 1),
        "what it found is still there to look at"
    );
    assert!(
        snapshot.policy.inventory_roots.contains(&folder),
        "the location stays"
    );
    // Nothing needs the model any more.
    eventually("the model to be released", || {
        rig.calls()
            .last()
            .is_some_and(|call| call == "release_model")
    })?;

    // Monitored again, it catches up on what happened meanwhile.
    fs::write(folder.join("later.txt"), "call +31 6 12345678").describe()?;
    rig.run(Command::Edit(Edit::Monitor {
        path: folder,
        on: true,
    }))?;
    watch_holds(&rig, (2, 2))?;
    Ok(())
}

#[test]
fn removing_a_monitored_location_stops_monitoring_it_and_forgets_what_it_held() -> Test {
    let dir = TempDir::new()?;
    let first = watched(&dir)?;
    let second = dir.0.join("second");
    fs::create_dir(&second).describe()?;
    fs::write(second.join("s.txt"), "call +31 6 12345678").describe()?;
    let rig = rig_monitoring(&[&first, &second])?;
    rig.run(Command::Startup)?;
    assert!(has_call(&rig, "start_watch(2)"));
    watch_holds(&rig, (2, 2))?;

    rig.run(Command::Edit(Edit::InventoryRoot {
        path: first.clone(),
        on: false,
    }))?;
    assert!(has_call(&rig, "start_watch(1)"));
    assert!(has_call(&rig, "stop_watch"), "the old watcher ended first");
    // What the removed location held is forgotten once the scan that ran has saved.
    let snapshot = watch_holds(&rig, (1, 1))?;
    assert_eq!(
        rig.controller.policy().monitored_roots,
        std::slice::from_ref(&second)
    );
    assert_eq!(snapshot.watch.folders.len(), 1);
    assert_eq!(snapshot.watch.folders[0].path, second);
    assert_eq!(rig.controller.inventory().totals().files, 1);
    let places: Vec<PathBuf> = rig
        .controller
        .places()
        .into_iter()
        .map(|place| place.path)
        .collect();
    assert_eq!(places, std::slice::from_ref(&second));

    // A path that is no location cannot be monitored: a notice says so, and monitoring goes on.
    rig.run(Command::Edit(Edit::Monitor {
        path: first,
        on: true,
    }))?;
    let notice = rig.controller.snapshot().notice.ok_or("no notice")?;
    assert!(
        notice.text.starts_with("Not a location:"),
        "{}",
        notice.text
    );
    assert_eq!(
        rig.controller.policy().monitored_roots,
        std::slice::from_ref(&second)
    );

    // The last one goes: nothing is monitored, and nothing of it is kept.
    rig.run(Command::Edit(Edit::InventoryRoot {
        path: second,
        on: false,
    }))?;
    assert!(rig.controller.policy().monitored_roots.is_empty());
    let snapshot = watch_holds(&rig, (0, 0))?;
    assert!(snapshot.watch.folders.is_empty());
    assert_eq!(rig.controller.inventory().totals().files, 0);
    Ok(())
}

#[test]
fn saved_monitoring_starts_with_the_app_and_ends_with_it() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_monitoring(&[&folder])?;
    rig.run(Command::Startup)?;
    assert!(has_call(&rig, "start_watch(1)"));
    watch_holds(&rig, (1, 1))?;
    rig.controller.shutdown();
    assert!(has_call(&rig, "stop_watch"));
    Ok(())
}

#[test]
fn locations_that_are_not_monitored_start_no_watcher() -> Test {
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let rig = rig_locations(&[&folder])?;
    rig.run(Command::Startup)?;
    assert!(
        !rig.calls()
            .iter()
            .any(|call| call.starts_with("start_watch"))
    );
    let snapshot = rig.controller.snapshot();
    assert!(snapshot.policy.monitored_roots.is_empty());
    assert!(snapshot.watch.folders.is_empty());
    assert!(!has_call(&rig, "load_model"), "nothing to scan, no model");
    Ok(())
}

#[test]
fn a_scan_outside_the_locations_is_shown_and_leaves_the_inventory_as_monitoring_filled_it() -> Test
{
    let dir = TempDir::new()?;
    let folder = watched(&dir)?;
    let elsewhere = dir.0.join("elsewhere");
    fs::create_dir(&elsewhere).describe()?;
    fs::write(elsewhere.join("e.txt"), "call +31 6 12345678").describe()?;
    let rig = rig_monitoring(&[&folder])?;
    rig.run(Command::Startup)?;
    watch_holds(&rig, (1, 1))?;

    rig.run(Command::ScanFiles {
        paths: vec![elsewhere.clone()],
        reveal: true,
    })?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| matches!(reveal.state, RevealState::Done(_)))
            && s.scan.is_none()
    })?;
    let Some(RevealState::Done(summary)) = snapshot.reveal.map(|reveal| reveal.state) else {
        return Err("the scan is not done".into());
    };
    assert_eq!(summary.hits, 1, "the dialog has the result");
    // The inventory holds what monitoring found in the location, and nothing from elsewhere.
    assert_eq!(snapshot.inventory_totals, (1, 1));
    assert_eq!(rig.controller.inventory().totals().files, 1);
    let listed = rig
        .controller
        .finding_files(std::slice::from_ref(&elsewhere));
    assert_eq!(listed.files.len(), 1, "its findings view still reads it");
    Ok(())
}
