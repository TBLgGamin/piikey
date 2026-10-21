use super::*;
use crate::ui::scanner::{Job, Kind, Request};

/// A folder `docs` in `dir` with one file that holds an email address.
fn docs(dir: &TempDir) -> Result<PathBuf, String> {
    let folder = dir.0.join("docs");
    fs::create_dir(&folder).describe()?;
    fs::write(folder.join("a.txt"), "mail jan.jansen@acme.nl").describe()?;
    Ok(folder)
}

#[test]
fn an_explorer_scan_fills_the_inventory_and_asks_the_window_to_show_it() -> Test {
    let rig = rig(true, quiet())?;
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let file = folder.join("a.txt");
    rig.run(Command::ScanFiles {
        paths: vec![folder.clone()],
        reveal: true,
    })?;
    let snapshot = wait_for(&rig.controller, |s| s.reveal.is_some() && s.scan.is_none())?;
    assert_eq!(snapshot.inventory_totals, (1, 1));
    assert_eq!(
        snapshot.reveal,
        Some(Reveal {
            seq: 1,
            at: folder.clone(),
            select: None
        })
    );
    // The application thread's timer sees the request without a window: the tray state
    // carries its number, and nothing else of the rig's state has changed.
    assert_eq!(
        rig.controller.tray(),
        Tray {
            on: false,
            highlight_paused: false,
            reveal: 1
        }
    );
    // A scan writes nothing to the vault.
    let engine = rig.controller.engine();
    let records = engine.vault().read().describe()?.record_count();
    assert_eq!(records, 0);
    // Outside the watched folders: the tile for "Other scans", which has no path.
    let top = rig.controller.inventory_view(Path::new(""), None);
    assert_eq!(top.nodes.len(), 1);
    assert!(top.nodes[0].path.as_os_str().is_empty());
    // No folder chosen: the view groups by the usual ones, which is what the scans watch and
    // what the breadcrumb must collapse.
    assert_eq!(top.roots, quiet().inventory_roots_or_default());
    let level = rig.controller.inventory_view(&folder, Some(&file));
    assert_eq!(level.nodes.len(), 1);
    assert_eq!(level.nodes[0].name, "a.txt");
    assert_eq!(level.entry.map(|entry| entry.hits()), Some(1));
    // The scan of one file shows its folder with the file selected.
    rig.run(Command::ScanFiles {
        paths: vec![file.clone()],
        reveal: true,
    })?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.reveal.as_ref().is_some_and(|reveal| reveal.seq == 2) && s.scan.is_none()
    })?;
    assert_eq!(
        snapshot.reveal,
        Some(Reveal {
            seq: 2,
            at: folder,
            select: Some(file)
        })
    );
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
fn the_inventory_scans_the_watched_folders_until_it_is_switched_off() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(
        true,
        Policy {
            inventory_roots: vec![folder.clone()],
            ..quiet()
        },
    )?;
    rig.run(Command::Edit(Edit::Inventory(true)))?;
    let snapshot = wait_for(&rig.controller, |s| {
        s.inventory_totals == (1, 1) && s.scan.is_none()
    })?;
    assert_eq!(
        snapshot.reveal, None,
        "a scan nobody asked to see does not take the window"
    );
    let top = rig.controller.inventory_view(Path::new(""), None);
    assert_eq!(top.nodes.len(), 1);
    assert_eq!(top.nodes[0].path, folder);
    assert_eq!(top.roots, std::slice::from_ref(&folder));
    // What is left out is forgotten at once, and stays out of every scan.
    rig.run(Command::Edit(Edit::InventoryExclude {
        path: folder.join("a.txt"),
        on: true,
    }))?;
    assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
    rig.run(Command::Rescan)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
    Ok(())
}

#[test]
fn a_rescan_scans_the_watched_folders_even_with_the_inventory_off() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(
        true,
        Policy {
            inventory_roots: vec![folder],
            ..quiet()
        },
    )?;
    rig.run(Command::Rescan)?;
    assert!(rig.controller.wait_scans(Duration::from_secs(20)));
    assert_eq!(rig.controller.snapshot().inventory_totals, (1, 1));
    Ok(())
}

#[test]
fn a_folder_left_out_while_a_scan_runs_is_forgotten_when_it_ends() -> Test {
    let dir = TempDir::new()?;
    let folder = docs(&dir)?;
    let rig = rig(true, quiet())?;
    // The scan reads the settings, then loads the model: that is when the user leaves the folder
    // out, so the scan goes on by the list it began with.
    let shared = Arc::clone(&rig.controller.shared);
    let inventory = rig.controller.inventory();
    let left_out = folder.clone();
    *rig.fake
        .on_load
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(move || {
        shared
            .policy
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .inventory_exclude
            .push(left_out.clone());
        // As leaving a folder out does at once; the scan has nothing of it yet.
        let _ = inventory.forget_under(&left_out);
    }));
    let job = Job {
        kind: Kind::Asked(Request {
            paths: vec![folder],
            reveal: false,
        }),
        cancel: Arc::new(AtomicBool::new(false)),
    };
    rig.controller.run_scan(&job);
    assert_eq!(rig.controller.snapshot().inventory_totals, (0, 0));
    assert_eq!(rig.controller.inventory().totals().files, 0);
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
