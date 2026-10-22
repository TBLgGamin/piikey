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
    // The watch is off until the user switches it on.
    assert!(!policy.watch);
    assert!(apply_edit(&mut policy, &Edit::Watch(true))?);
    assert!(!apply_edit(&mut policy, &Edit::Watch(true))?);
    assert!(policy.watch);
    assert!(apply_edit(&mut policy, &Edit::Watch(false))?);
    assert!(!policy.watch);
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
fn locations_and_watched_folders_must_be_folders_and_are_not_added_twice() -> Test {
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

    // The watch's folders are a list of their own, and just as strict.
    let mut policy = quiet();
    let watch = |path: &Path, on| Edit::WatchFolder {
        path: path.to_path_buf(),
        on,
    };
    assert!(apply_edit(&mut policy, &watch(&dir.0, true))?);
    assert!(!apply_edit(&mut policy, &watch(&shouted, true))?);
    assert!(apply_edit(&mut policy, &watch(&anchor.0, true))?);
    assert_eq!(policy.watch_folders, [dir.0.clone(), anchor.0.clone()]);
    assert!(
        policy.inventory_roots.is_empty(),
        "no folder of the inventory's"
    );
    assert!(apply_edit(&mut policy, &watch(&file, true)).is_err());
    assert!(apply_edit(&mut policy, &watch(&dir.0.join("gone"), true)).is_err());
    assert!(
        apply_edit(&mut policy, &watch(Path::new(r"relative\folder"), true)).is_err(),
        "a folder is a full path"
    );
    assert!(apply_edit(&mut policy, &watch(&shouted, false))?);
    assert_eq!(policy.watch_folders, std::slice::from_ref(&anchor.0));
    assert!(!apply_edit(&mut policy, &watch(&dir.0, false))?);
    Ok(())
}
