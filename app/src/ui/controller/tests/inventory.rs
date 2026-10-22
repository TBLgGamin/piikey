use std::sync::mpsc;

use piikey::inventory::Inventory;

use super::*;
use crate::ui::controller::FindingsEvent;
use crate::ui::scanner::{Job, Kind, Request};

/// A folder `docs` in `dir` with one file that holds an email address.
fn docs(dir: &TempDir) -> Result<PathBuf, String> {
    let folder = dir.0.join("docs");
    fs::create_dir(&folder).describe()?;
    fs::write(folder.join("a.txt"), "mail jan.jansen@acme.nl").describe()?;
    Ok(folder)
}

/// The latest scan that asked to be shown, once it is over.
fn shown(controller: &Controller) -> Result<Snapshot, String> {
    wait_for(controller, |s| {
        s.reveal.as_ref().is_some_and(|reveal| {
            matches!(reveal.state, RevealState::Done(_) | RevealState::Failed(_))
        }) && s.scan.is_none()
    })
}

fn summary_of(snapshot: &Snapshot) -> Result<ScanSummary, String> {
    match snapshot.reveal.as_ref().map(|reveal| &reveal.state) {
        Some(RevealState::Done(summary)) => Ok(summary.clone()),
        other => Err(format!("the scan is not done: {other:?}")),
    }
}

#[test]
fn an_explorer_scan_fills_the_inventory_and_the_dialog_gets_its_result() -> Test {
    let rig = rig(true, quiet())?;
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let file = folder.join("a.txt");
    rig.run(Command::ScanFiles {
        paths: vec![folder.clone()],
        reveal: true,
    })?;
    let snapshot = shown(&rig.controller)?;
    assert_eq!(snapshot.inventory_totals, (1, 1));
    let reveal = snapshot.reveal.clone().ok_or("no dialog")?;
    assert_eq!(
        (reveal.seq, &reveal.paths, &reveal.at, &reveal.select),
        (1, &vec![folder.clone()], &folder, &None)
    );
    assert_eq!(
        summary_of(&snapshot)?,
        ScanSummary {
            files: 1,
            files_with_data: 1,
            hits: 1,
            counts: vec![(EntityKind::Email, 1)],
            unread: 0
        }
    );
    // The application thread's timer sees the request without a window: the tray state
    // carries its number, and nothing else of the rig's state has changed.
    assert_eq!(
        rig.controller.tray(),
        Tray {
            on: false,
            highlight_paused: false,
            reveal: 1,
            show: 0
        }
    );
    // A scan writes nothing to the vault.
    let engine = rig.controller.engine();
    let records = engine.vault().read().describe()?.record_count();
    assert_eq!(records, 0);
    // The watch has seen nothing of it: it is the inventory's.
    assert_eq!(rig.controller.snapshot().watch.totals, (0, 0));
    assert_eq!(rig.controller.watch_store.totals().files, 0);

    // Outside the locations: the node for "Other scans", which has no path.
    let top = rig
        .controller
        .inventory_view(Store::Inventory, Path::new(""), None);
    assert_eq!(top.nodes.len(), 1);
    assert!(top.nodes[0].path.as_os_str().is_empty());
    // No location chosen: nothing to group by.
    assert!(top.roots.is_empty());
    let level = rig
        .controller
        .inventory_view(Store::Inventory, &folder, Some(&file));
    assert_eq!(level.nodes.len(), 1);
    assert_eq!(level.nodes[0].name, "a.txt");
    assert_eq!(level.entry.map(|entry| entry.hits()), Some(1));

    // The scan of one file shows its folder with the file selected, and its summary is the
    // file's.
    rig.run(Command::ScanFiles {
        paths: vec![file.clone()],
        reveal: true,
    })?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| reveal.seq == 2 && matches!(reveal.state, RevealState::Done(_)))
    })?;
    let reveal = snapshot.reveal.clone().ok_or("no dialog")?;
    assert_eq!(
        (&reveal.paths, &reveal.at, &reveal.select),
        (&vec![file.clone()], &folder, &Some(file.clone()))
    );
    assert_eq!(summary_of(&snapshot)?.files, 1);
    assert_eq!(rig.controller.tray().reveal, 2);
    // The model was loaded for the scans and given back.
    assert!(has_call(&rig, "load_model"));
    eventually("the model to be released", || {
        rig.calls()
            .last()
            .is_some_and(|call| call == "release_model")
    })
}

#[test]
fn the_dialog_is_there_from_the_moment_the_scan_is_queued_and_the_newest_request_keeps_it() -> Test
{
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let other = dir.0.join("other");
    fs::create_dir(&other).describe()?;
    fs::write(other.join("b.txt"), "call +31 6 12345678").describe()?;
    let rig = rig(true, quiet())?;

    // The first scan stops where the model loads, so what the dialog says can be looked at.
    let (entered, in_scan) = mpsc::channel();
    let (release, hold) = mpsc::channel::<()>();
    *rig.fake
        .on_load
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(move || {
        let _ = entered.send(());
        let _ = hold.recv();
    }));
    rig.run(Command::ScanFiles {
        paths: vec![folder.clone()],
        reveal: true,
    })?;
    in_scan
        .recv_timeout(Duration::from_secs(20))
        .map_err(|error| error.to_string())?;
    let snapshot = rig.controller.snapshot();
    let first = snapshot.reveal.clone().ok_or("no dialog")?;
    assert_eq!((first.seq, &first.state), (1, &RevealState::Scanning));
    assert!(snapshot.scan.is_some(), "its progress is the snapshot's");
    assert_eq!(rig.controller.tray().reveal, 1, "the window opens at once");

    // A second request queues behind it and takes the dialog over at once.
    rig.run(Command::ScanFiles {
        paths: vec![other.clone()],
        reveal: true,
    })?;
    let second = rig.controller.snapshot().reveal.ok_or("no dialog")?;
    assert_eq!(
        (second.seq, &second.paths, &second.state),
        (2, &vec![other.clone()], &RevealState::Waiting)
    );
    assert_eq!(rig.controller.tray().reveal, 2);

    // The first scan ends: it does not take the dialog back.
    release.send(()).map_err(|error| error.to_string())?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| matches!(reveal.state, RevealState::Done(_)))
            && s.scan.is_none()
            && s.inventory_totals == (2, 2)
    })?;
    let last = snapshot.reveal.clone().ok_or("no dialog")?;
    assert_eq!((last.seq, &last.paths), (2, &vec![other]));
    let summary = summary_of(&snapshot)?;
    assert_eq!(
        (summary.files, summary.files_with_data, summary.hits),
        (1, 1, 1)
    );
    assert_eq!(summary.counts, [(EntityKind::Phone, 1)]);
    Ok(())
}

#[test]
fn a_scan_that_could_not_run_tells_the_dialog_why() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(true, quiet())?;
    // A `piikey-cli` run on its own holds the inventory.
    let held = rig.controller.inventory().lock_scan().describe()?;
    rig.run(Command::ScanFiles {
        paths: vec![folder.clone()],
        reveal: true,
    })?;
    let snapshot = shown(&rig.controller)?;
    let Some(RevealState::Failed(why)) = snapshot.reveal.as_ref().map(|reveal| &reveal.state)
    else {
        return Err(format!("it should have failed: {:?}", snapshot.reveal));
    };
    assert!(why.contains("another inventory scan is running"), "{why}");
    assert!(
        snapshot
            .notice
            .as_ref()
            .is_some_and(|notice| notice.text.contains("Could not scan")),
        "{:?}",
        snapshot.notice
    );
    assert_eq!(snapshot.inventory_totals, (0, 0));
    drop(held);
    // Without the other scan the same request works.
    rig.run(Command::ScanFiles {
        paths: vec![folder],
        reveal: true,
    })?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| reveal.seq == 2 && matches!(reveal.state, RevealState::Done(_)))
    })?;
    assert_eq!(snapshot.inventory_totals, (1, 1));
    Ok(())
}

#[test]
fn a_scan_nobody_asked_to_see_leaves_the_window_alone_and_nothing_scans_by_itself() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(
        true,
        Policy {
            inventory_roots: vec![folder.clone()],
            ..quiet()
        },
    )?;
    // The settings and the start of the app scan nothing: the inventory is what was scanned.
    rig.run(Command::Startup)?;
    rig.run(Command::Edit(Edit::ExplorerMenu(true)))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
    assert!(!has_call(&rig, "load_model"), "no scan, no model");

    // The Scan button scans the locations, and says nothing to the window.
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    let snapshot = rig.controller.snapshot();
    assert_eq!(snapshot.inventory_totals, (1, 1));
    assert_eq!(
        snapshot.reveal, None,
        "a scan nobody asked to see does not take the window"
    );
    assert_eq!(rig.controller.tray().reveal, 0);
    let top = rig
        .controller
        .inventory_view(Store::Inventory, Path::new(""), None);
    assert_eq!(top.nodes.len(), 1);
    assert_eq!(top.nodes[0].path, folder);
    assert_eq!(top.roots, std::slice::from_ref(&folder));

    // A second press reads nothing again: the file did not change.
    fs::write(folder.join("b.txt"), "call +31 6 12345678").describe()?;
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (2, 2));
    Ok(())
}

#[test]
fn removing_a_location_forgets_what_it_held_and_nothing_comes_back() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(
        true,
        Policy {
            inventory_roots: vec![folder.clone()],
            ..quiet()
        },
    )?;
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (1, 1));

    rig.run(Command::Edit(Edit::InventoryRoot {
        path: folder,
        on: false,
    }))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    let snapshot = rig.controller.snapshot();
    assert!(
        snapshot.policy.inventory_roots.is_empty(),
        "no folder in its place"
    );
    assert_eq!(snapshot.inventory_totals, (0, 0));
    assert_eq!(rig.controller.inventory().totals().files, 0);
    Ok(())
}

#[test]
fn adding_a_location_adds_the_folder_and_scans_it_with_the_dialog() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let anchor = TempDir::new()?;
    let rig = rig(
        true,
        Policy {
            inventory_roots: vec![anchor.0.clone()],
            ..quiet()
        },
    )?;
    rig.run(Command::AddLocation(folder.clone()))?;
    let snapshot = shown(&rig.controller)?;
    assert_eq!(
        snapshot.policy.inventory_roots,
        [anchor.0.clone(), folder.clone()]
    );
    assert_eq!(
        rig.fake.last_saved()?.inventory_roots,
        snapshot.policy.inventory_roots
    );
    assert_eq!(summary_of(&snapshot)?.hits, 1);
    assert_eq!(snapshot.inventory_totals, (1, 1));

    // A folder that is a location already is scanned again all the same.
    rig.run(Command::AddLocation(folder.clone()))?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal
            .as_ref()
            .is_some_and(|reveal| reveal.seq == 2 && matches!(reveal.state, RevealState::Done(_)))
    })?;
    assert_eq!(snapshot.policy.inventory_roots.len(), 2);

    // A path that is no folder is refused, and nothing is scanned or shown for it.
    let file = folder.join("a.txt");
    rig.run(Command::AddLocation(file))?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    let snapshot = rig.controller.snapshot();
    assert_eq!(snapshot.policy.inventory_roots.len(), 2);
    assert_eq!(snapshot.reveal.map(|reveal| reveal.seq), Some(2));
    assert!(
        snapshot
            .notice
            .is_some_and(|notice| notice.text.starts_with("Not a folder:"))
    );
    Ok(())
}

/// What `read_findings` reports for `files` with at most `limit` values, until `go_on` (told how
/// many reports there are) says stop.
fn read_events(
    controller: &Controller,
    files: &[PathBuf],
    limit: usize,
    mut go_on: impl FnMut(usize) -> bool + Send,
) -> Vec<FindingsEvent> {
    let mut events = Vec::new();
    controller.read_findings(files, limit, |event| {
        events.push(event);
        go_on(events.len())
    });
    events
}

/// The values the events report for `path`, and how the file ended: `None` while it did not.
fn of_file(
    events: &[FindingsEvent],
    path: &Path,
) -> (Vec<piikey::inventory::Finding>, Option<Result<(), String>>) {
    let mut values = Vec::new();
    let mut ended = None;
    for event in events {
        match event {
            FindingsEvent::Found(file, list) if file == path => values.extend(list.iter().cloned()),
            FindingsEvent::Done(file, result) if file == path => ended = Some(result.clone()),
            _ => {}
        }
    }
    (values, ended)
}

#[test]
fn the_findings_of_files_are_read_on_request_with_the_model_and_kept_nowhere() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let file = folder.join("a.txt");
    let missing = dir.0.join("missing.txt");
    let rig = rig(true, quiet())?;
    let events = read_events(
        &rig.controller,
        &[file.clone(), missing.clone()],
        1_000,
        |_| true,
    );
    // The model is loaded first: that is the first thing said.
    assert!(
        matches!(events.first(), Some(FindingsEvent::Loading)),
        "{events:?}"
    );
    let (found, ended) = of_file(&events, &file);
    assert_eq!(ended, Some(Ok(())));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, EntityKind::Email);
    assert_eq!(&*found[0].value, "jan.jansen@acme.nl");
    assert_eq!(&*found[0].snippet, "mail jan.jansen@acme.nl");
    assert_eq!(
        found[0].location,
        Some(piikey::inventory::Location::Line { line: 1, column: 6 })
    );
    // A file that is not there says so, and the others are read all the same.
    let (none, ended) = of_file(&events, &missing);
    assert!(none.is_empty());
    assert!(ended.is_some_and(|result| result.is_err_and(|error| error.contains("cannot read"))));
    // The model is there for the detection, and given back when nothing else needs it.
    assert!(has_call(&rig, "load_model"));
    eventually("the model to be released", || {
        rig.calls()
            .last()
            .is_some_and(|call| call == "release_model")
    })?;
    // Nothing was stored: not in the inventory, not in the watch's, and not as a file.
    assert_eq!(rig.controller.inventory().totals().files, 0);
    assert_eq!(rig.controller.watch_store.totals().files, 0);
    assert!(!dir.0.join("inventory.jsonl").exists());
    assert!(!dir.0.join("watch.jsonl").exists());
    assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
    // Nothing to read: the model is not loaded for it.
    let calls = rig.calls().len();
    assert!(read_events(&rig.controller, &[], 1_000, |_| true).is_empty());
    assert_eq!(rig.calls().len(), calls);
    Ok(())
}

#[test]
fn files_are_read_a_few_at_a_time_and_the_reader_or_the_limit_can_stop_the_rest() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let files: Vec<PathBuf> = (0..9)
        .map(|i| {
            let file = folder.join(format!("f{i}.txt"));
            fs::write(&file, format!("mail jan{i}.jansen@acme.nl")).describe()?;
            Ok(file)
        })
        .collect::<Result<_, String>>()?;
    let rig = rig(true, quiet())?;
    let all = read_events(&rig.controller, &files, 1_000, |_| true);
    for file in &files {
        let (found, ended) = of_file(&all, file);
        assert_eq!((found.len(), ended), (1, Some(Ok(()))), "{file:?}");
    }
    // Whoever reads says when to stop: nothing is reported past the report that was refused.
    let some = read_events(&rig.controller, &files, 1_000, |reports| reports < 3);
    assert_eq!(some.len(), 3, "{some:?}");
    // So does the limit: the files that were not started are left alone.
    let few = read_events(&rig.controller, &files, 2, |_| true);
    let values: usize = few
        .iter()
        .map(|event| match event {
            FindingsEvent::Found(_, list) => list.len(),
            _ => 0,
        })
        .sum();
    assert!((2..9).contains(&values), "{values}");
    Ok(())
}

#[test]
fn the_model_stays_for_a_while_after_a_read_of_findings_and_what_comes_next_keeps_it() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let file = folder.join("a.txt");
    let rig = rig(true, quiet())?;
    *rig.fake.idle.lock().map_err(|error| error.to_string())? = Duration::from_millis(400);
    let releases = |rig: &Rig| {
        rig.calls()
            .iter()
            .filter(|call| *call == "release_model")
            .count()
    };
    read_events(&rig.controller, std::slice::from_ref(&file), 1_000, |_| {
        true
    });
    // Nothing needs the model any more, and it is still there.
    assert!(has_call(&rig, "load_model"));
    assert_eq!(releases(&rig), 0, "{:?}", rig.calls());
    // Another read in the meantime has it at once, and the time starts again after it.
    std::thread::sleep(Duration::from_millis(250));
    read_events(&rig.controller, std::slice::from_ref(&file), 1_000, |_| {
        true
    });
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        releases(&rig),
        0,
        "kept by the second read: {:?}",
        rig.calls()
    );
    // And when it is up, the model goes.
    eventually("the model to be released", || releases(&rig) == 1)?;
    Ok(())
}

#[test]
fn a_folder_result_lists_the_files_with_personal_data_the_most_first_and_a_named_file_always()
-> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    fs::write(folder.join("b.txt"), "nothing to see here").describe()?;
    let sub = folder.join("sub");
    fs::create_dir(&sub).describe()?;
    fs::write(
        sub.join("c.txt"),
        "jan.jansen@acme.nl and piet.pietersen@acme.nl",
    )
    .describe()?;
    let rig = rig(true, quiet())?;
    rig.run(Command::ScanFiles {
        paths: vec![folder.clone()],
        reveal: false,
    })?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));

    let listed = rig
        .controller
        .finding_files(Store::Inventory, std::slice::from_ref(&folder));
    let labels: Vec<&str> = listed
        .files
        .iter()
        .map(|file| file.label.as_str())
        .collect();
    assert_eq!(labels, [r"sub\c.txt", "a.txt"]);
    assert_eq!(listed.files[0].path, sub.join("c.txt"));
    assert_eq!(listed.left_out, 0);

    // A file that was named is listed whether or not the inventory found anything in it, and a
    // path that is no folder is a file: reading it says what is wrong with it.
    let clean = folder.join("b.txt");
    let gone = dir.0.join("gone.txt");
    let named = rig
        .controller
        .finding_files(Store::Inventory, &[clean.clone(), gone.clone()]);
    let paths: Vec<&PathBuf> = named.files.iter().map(|file| &file.path).collect();
    assert_eq!(paths, [&clean, &gone]);
    assert_eq!(named.files[0].label, "b.txt");

    // The watch's inventory knows nothing of what was scanned into the main one.
    let watched = rig
        .controller
        .finding_files(Store::Watch, std::slice::from_ref(&folder));
    assert!(watched.files.is_empty());
    Ok(())
}

#[test]
fn the_views_read_the_inventory_they_are_asked_for() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let watched = dir.0.join("watched");
    fs::create_dir(&watched).describe()?;
    let rig = rig(
        true,
        Policy {
            inventory_roots: vec![folder.clone()],
            watch_folders: vec![watched.clone()],
            ..quiet()
        },
    )?;
    rig.run(Command::ScanAll)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    let file = |name: &str| watched.join(name);
    rig.controller
        .watch_store
        .record(vec![
            entry_of(&file("w1.txt"), &[(EntityKind::Iban, 3)]),
            entry_of(
                &file("w2.txt"),
                &[(EntityKind::Phone, 1), (EntityKind::Iban, 1)],
            ),
        ])
        .describe()?;

    let top = |store| rig.controller.inventory_view(store, Path::new(""), None);
    let main = top(Store::Inventory);
    assert_eq!(main.roots, std::slice::from_ref(&folder));
    assert_eq!(main.nodes.len(), 1);
    assert_eq!(main.nodes[0].hits, 1);
    let watch = top(Store::Watch);
    assert_eq!(watch.roots, std::slice::from_ref(&watched));
    assert_eq!(watch.nodes.len(), 1);
    assert_eq!((watch.nodes[0].hits, watch.nodes[0].files), (5, 2));
    assert_eq!(watch.nodes[0].dominant(), Some(EntityKind::Iban));

    let tiles = rig.controller.tiles(Store::Watch, Path::new(""), 1);
    assert_eq!(tiles.tiles.len(), 1);
    assert_eq!(tiles.tiles[0].path, file("w1.txt"));
    assert_eq!((tiles.rest.files, tiles.rest.hits), (1, 2));
    let legend = rig.controller.type_totals(Store::Watch, &watched);
    assert_eq!(
        legend
            .iter()
            .map(|total| (total.kind, total.hits, total.files))
            .collect::<Vec<_>>(),
        [(EntityKind::Iban, 4, 2), (EntityKind::Phone, 1, 1)]
    );
    // What was scanned into the inventory is not in the watch's views, and the other way round.
    assert_eq!(
        rig.controller
            .tiles(Store::Inventory, Path::new(""), 10)
            .tiles
            .len(),
        1
    );
    assert!(rig.controller.type_totals(Store::Watch, &folder).is_empty());
    let selected = rig
        .controller
        .inventory_view(Store::Watch, &watched, Some(&file("w2.txt")));
    assert_eq!(selected.entry.map(|entry| entry.hits()), Some(2));
    Ok(())
}

/// An entry as a scan would make it, for a file that is not on disk.
fn entry_of(path: &Path, counts: &[(EntityKind, u32)]) -> piikey::inventory::Entry {
    piikey::inventory::Entry {
        path: path.to_path_buf(),
        size: 1,
        modified: 1,
        scanned: 1_700_000_000,
        status: piikey::inventory::Status::Ok,
        counts: counts.to_vec(),
        hash: None,
    }
}

#[test]
fn the_inventory_and_the_watch_are_two_files() -> Test {
    let rig = rig(true, quiet())?;
    let (main, watch) = (rig.fake.open_inventory()?, rig.fake.open_watch()?);
    let names = |inventory: &Inventory| format!("{inventory:?}");
    assert!(names(&main).contains("inventory.jsonl"), "{}", names(&main));
    assert!(names(&watch).contains("watch.jsonl"), "{}", names(&watch));
    Ok(())
}

#[test]
fn work_in_the_scan_pool_runs_on_half_the_cores() -> Test {
    let rig = rig(true, quiet())?;
    let cores = thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let (workers, thread_name) = rig.controller.in_scan_pool(|| {
        (
            rayon::current_num_threads(),
            thread::current().name().map(str::to_owned),
        )
    });
    assert_eq!(workers, (cores / 2).max(1));
    assert!(
        thread_name.is_some_and(|name| name.starts_with("piikey-scan-")),
        "the work leaves the calling thread"
    );
    Ok(())
}

#[test]
fn a_scan_that_is_stopped_before_it_ends_says_so_to_the_dialog() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(true, quiet())?;
    let seq = rig.controller.begin_reveal(std::slice::from_ref(&folder));
    let job = Job {
        kind: Kind::Asked(Request {
            paths: vec![folder],
            reveal: Some(seq),
        }),
        cancel: Arc::new(AtomicBool::new(true)),
    };
    rig.controller.run_scan(&job);
    // A stopped scan may go on later without a removed folder: its dialog keeps waiting.
    let reveal = rig.controller.snapshot().reveal.ok_or("no dialog")?;
    assert_eq!(reveal.state, RevealState::Scanning);
    // Nothing of it goes on: the scan thread says so.
    rig.controller.scan_stopped(&job);
    let reveal = rig.controller.snapshot().reveal.ok_or("no dialog")?;
    assert_eq!(
        reveal.state,
        RevealState::Failed("The scan was stopped.".to_owned())
    );
    assert_eq!(rig.controller.inventory().totals().files, 0);
    Ok(())
}
