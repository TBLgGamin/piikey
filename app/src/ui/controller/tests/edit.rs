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
    Ok(())
}

#[test]
fn switching_the_inventory_on_watches_the_usual_folders_only_when_none_were_chosen() -> Test {
    let mut policy = quiet();
    assert!(apply_edit(&mut policy, &Edit::Inventory(true))?);
    assert!(policy.inventory);
    assert_eq!(policy.inventory_roots, quiet().inventory_roots_or_default());
    assert!(!apply_edit(&mut policy, &Edit::Inventory(true))?);

    let dir = TempDir::new()?;
    let mut chosen = Policy {
        inventory_roots: vec![dir.0.clone()],
        ..quiet()
    };
    assert!(apply_edit(&mut chosen, &Edit::Inventory(true))?);
    assert_eq!(
        chosen.inventory_roots,
        std::slice::from_ref(&dir.0),
        "the user's folders stay"
    );
    assert!(apply_edit(&mut chosen, &Edit::Inventory(false))?);
    assert_eq!(
        chosen.inventory_roots,
        std::slice::from_ref(&dir.0),
        "also while it is off"
    );
    Ok(())
}

#[test]
fn watched_folders_must_be_folders_and_are_not_added_twice() -> Test {
    let dir = TempDir::new()?;
    let mut policy = quiet();
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
    assert_eq!(policy.inventory_roots, std::slice::from_ref(&dir.0));
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
    assert!(apply_edit(&mut policy, &root(&dir.0, false))?);
    assert!(!apply_edit(&mut policy, &root(&dir.0, false))?);
    assert!(policy.inventory_roots.is_empty());
    Ok(())
}

#[test]
fn excluded_paths_need_not_exist_but_must_be_full_paths() -> Test {
    let mut policy = quiet();
    let exclude = |path: &str, on| Edit::InventoryExclude {
        path: PathBuf::from(path),
        on,
    };
    assert!(apply_edit(
        &mut policy,
        &exclude(r"C:\Users\you\Taxes\2024.pdf", true)
    )?);
    assert!(!apply_edit(
        &mut policy,
        &exclude(r"c:\users\YOU\taxes\2024.pdf", true)
    )?);
    assert_eq!(policy.inventory_exclude.len(), 1);
    assert!(apply_edit(&mut policy, &exclude(r"relative\path", true)).is_err());
    assert!(apply_edit(
        &mut policy,
        &exclude(r"C:\Users\you\Taxes\2024.pdf", false)
    )?);
    assert!(policy.inventory_exclude.is_empty());
    Ok(())
}
