use super::*;

#[test]
fn edits_report_whether_they_changed_anything() -> Test {
    let mut policy = Policy::default();
    let add_site = Edit::Site {
        site: "claude.ai".into(),
        on: true,
    };
    assert!(apply_edit(&mut policy, &add_site)?);
    assert!(!apply_edit(&mut policy, &add_site)?);
    assert!(apply_edit(
        &mut policy,
        &Edit::Site {
            site: "claude.ai".into(),
            on: false
        }
    )?);
    let kind = |kind, on| Edit::Kind { kind, on };
    assert!(apply_edit(&mut policy, &kind(EntityKind::Phone, false))?);
    assert!(apply_edit(&mut policy, &kind(EntityKind::Email, false))?);
    assert_eq!(
        policy.disabled_kinds,
        [EntityKind::Email, EntityKind::Phone],
        "the list stays in kind order"
    );
    assert!(!apply_edit(&mut policy, &kind(EntityKind::Email, false))?);
    assert!(apply_edit(&mut policy, &kind(EntityKind::Email, true))?);
    assert!(!apply_edit(&mut policy, &kind(EntityKind::Email, true))?);
    assert_eq!(policy.disabled_kinds, [EntityKind::Phone]);
    Ok(())
}

#[test]
fn feature_edits_report_whether_they_changed_anything() -> Test {
    let mut policy = quiet();
    assert!(apply_edit(
        &mut policy,
        &Edit::Highlight(Highlight::Always)
    )?);
    assert!(!apply_edit(
        &mut policy,
        &Edit::Highlight(Highlight::Always)
    )?);
    assert_eq!(policy.highlight, Highlight::Always);
    assert!(apply_edit(&mut policy, &Edit::ExplorerMenu(true))?);
    assert!(!apply_edit(&mut policy, &Edit::ExplorerMenu(true))?);
    assert!(apply_edit(&mut policy, &Edit::HttpApi(true))?);
    assert!(!apply_edit(&mut policy, &Edit::HttpApi(true))?);
    assert!(policy.explorer_menu && policy.http_api);
    assert!(apply_edit(&mut policy, &Edit::HttpApi(false))?);
    assert!(!policy.http_api);
    // Closing the window keeps piikey in the tray unless the user says otherwise.
    assert!(policy.background);
    assert!(!apply_edit(&mut policy, &Edit::Background(true))?);
    assert!(apply_edit(&mut policy, &Edit::Background(false))?);
    assert!(!policy.background);
    assert!(apply_edit(&mut policy, &Edit::Background(true))?);
    Ok(())
}

#[test]
fn there_is_no_location_until_one_is_added_and_removing_all_leaves_none() -> Test {
    let dir = TempDir::new()?;
    let other = TempDir::new()?;
    let root = |path: &Path, on| Edit::InventoryRoot {
        path: path.to_path_buf(),
        on,
    };
    let mut policy = quiet();
    assert!(policy.inventory_roots.is_empty());
    assert!(apply_edit(&mut policy, &root(&dir.0, true))?);
    assert!(apply_edit(&mut policy, &root(&other.0, true))?);
    assert!(apply_edit(&mut policy, &root(&dir.0, false))?);
    assert!(apply_edit(&mut policy, &root(&other.0, false))?);
    // Nothing comes back in their place.
    assert!(policy.inventory_roots.is_empty());
    // Taking off what is not there changes nothing.
    assert!(!apply_edit(&mut policy, &root(&dir.0, false))?);
    Ok(())
}

#[test]
fn locations_must_be_folders_and_are_not_added_twice() -> Test {
    let dir = TempDir::new()?;
    let anchor = TempDir::new()?;
    let mut policy = Policy {
        inventory_roots: vec![anchor.0.clone()],
        ..quiet()
    };
    let root = |path: &Path, on| Edit::InventoryRoot {
        path: path.to_path_buf(),
        on,
    };
    assert!(apply_edit(&mut policy, &root(&dir.0, true))?);
    assert!(
        !apply_edit(&mut policy, &root(&dir.0, true))?,
        "twice is once"
    );
    let shouted = PathBuf::from(dir.0.to_string_lossy().to_ascii_uppercase());
    assert!(
        !apply_edit(&mut policy, &root(&shouted, true))?,
        "Windows paths ignore case"
    );
    assert_eq!(policy.inventory_roots, [anchor.0.clone(), dir.0.clone()]);
    let missing = apply_edit(&mut policy, &root(&dir.0.join("missing"), true))
        .err()
        .ok_or("a folder that is not there is refused")?;
    assert!(missing.starts_with("Not a folder:"), "{missing}");
    let file = dir.0.join("a.txt");
    fs::write(&file, "x").describe()?;
    assert!(
        apply_edit(&mut policy, &root(&file, true)).is_err(),
        "a file is no folder"
    );
    // Taking one off ignores letter case too.
    assert!(apply_edit(&mut policy, &root(&shouted, false))?);
    assert!(!apply_edit(&mut policy, &root(&dir.0, false))?);
    assert_eq!(policy.inventory_roots, std::slice::from_ref(&anchor.0));
    Ok(())
}

#[test]
fn only_a_location_can_be_monitored_and_removing_it_ends_its_monitoring() -> Test {
    let dir = TempDir::new()?;
    let other = TempDir::new()?;
    let mut policy = quiet();
    let root = |path: &Path, on| Edit::InventoryRoot {
        path: path.to_path_buf(),
        on,
    };
    let monitor = |path: &Path, on| Edit::Monitor {
        path: path.to_path_buf(),
        on,
    };

    // A folder that is no location cannot be monitored.
    assert!(policy.monitored_roots.is_empty());
    let refused = apply_edit(&mut policy, &monitor(&dir.0, true))
        .err()
        .ok_or("only a location can be monitored")?;
    assert_eq!(refused, format!("Not a location: {}", dir.0.display()));
    assert!(policy.monitored_roots.is_empty());
    assert!(
        !apply_edit(&mut policy, &monitor(&dir.0, false))?,
        "what is not monitored is not taken off"
    );

    // A location can, once, whatever the letter case of the path.
    assert!(apply_edit(&mut policy, &root(&dir.0, true))?);
    assert!(apply_edit(&mut policy, &root(&other.0, true))?);
    assert!(
        policy.monitored_roots.is_empty(),
        "a location is not monitored until the user says so"
    );
    assert!(apply_edit(&mut policy, &monitor(&dir.0, true))?);
    assert!(
        !apply_edit(&mut policy, &monitor(&dir.0, true))?,
        "twice is once"
    );
    let shouted = PathBuf::from(dir.0.to_string_lossy().to_ascii_uppercase());
    assert!(
        !apply_edit(&mut policy, &monitor(&shouted, true))?,
        "Windows paths ignore case"
    );
    assert_eq!(policy.monitored_roots, std::slice::from_ref(&dir.0));
    assert!(apply_edit(&mut policy, &monitor(&other.0, true))?);
    assert_eq!(policy.monitored_roots, [dir.0.clone(), other.0.clone()]);

    // Turning it off ignores the letter case too, and the location stays.
    assert!(apply_edit(&mut policy, &monitor(&shouted, false))?);
    assert!(!apply_edit(&mut policy, &monitor(&dir.0, false))?);
    assert_eq!(policy.monitored_roots, std::slice::from_ref(&other.0));
    assert_eq!(policy.inventory_roots, [dir.0.clone(), other.0.clone()]);

    // Taking a location off the list ends its monitoring.
    assert!(apply_edit(&mut policy, &root(&other.0, false))?);
    assert!(policy.monitored_roots.is_empty());
    assert_eq!(policy.inventory_roots, std::slice::from_ref(&dir.0));
    assert!(
        apply_edit(&mut policy, &monitor(&other.0, true)).is_err(),
        "it is no location any more"
    );
    Ok(())
}

#[test]
fn a_location_in_a_cloud_account_is_no_folder_on_this_pc_and_needs_none() -> Test {
    let drive = PathBuf::from(r"\\Google Drive\jan@acme.com\My Drive");
    let shouted = PathBuf::from(drive.to_string_lossy().to_ascii_uppercase());
    let root = |path: &Path, on| Edit::InventoryRoot {
        path: path.to_path_buf(),
        on,
    };
    let monitor = |path: &Path, on| Edit::Monitor {
        path: path.to_path_buf(),
        on,
    };
    let mut policy = quiet();

    // The disk has nothing to say of it: Windows would look for a server of that name.
    assert!(apply_edit(&mut policy, &root(&drive, true))?);
    assert!(
        !apply_edit(&mut policy, &root(&drive, true))?,
        "twice is once"
    );
    assert!(
        !apply_edit(&mut policy, &root(&shouted, true))?,
        "Windows paths ignore case"
    );
    assert_eq!(policy.inventory_roots, std::slice::from_ref(&drive));

    // It is monitored as any location is, spelled as the location is, and taking it off ends that.
    assert!(apply_edit(&mut policy, &monitor(&shouted, true))?);
    assert_eq!(policy.monitored_roots, std::slice::from_ref(&drive));
    assert!(apply_edit(&mut policy, &monitor(&drive, false))?);
    assert!(apply_edit(&mut policy, &monitor(&drive, true))?);
    assert!(apply_edit(&mut policy, &root(&shouted, false))?);
    assert!(policy.inventory_roots.is_empty());
    assert!(policy.monitored_roots.is_empty());
    Ok(())
}
