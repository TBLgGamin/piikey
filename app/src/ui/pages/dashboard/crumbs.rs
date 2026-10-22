//! The way back up from the folder a dashboard shows: "This PC", the location the folder lies in,
//! and the folders below it, each a step to go back to.

use std::path::{Component, Path, PathBuf};

use piikey::sys::is_under;

use crate::ui::controller::Store;

/// One step of the way from the top level to the folder on show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Crumb {
    pub(super) label: String,
    /// The folder it leads to; empty is the top level.
    pub(super) target: PathBuf,
}

/// The last component of `path`: the name of a folder or a file; a drive keeps its whole path.
pub(super) fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// What the top level of a store is called.
pub(super) const fn top_label(store: Store) -> &'static str {
    match store {
        Store::Inventory => "This PC",
        Store::Watch => "Watched folders",
    }
}

/// The crumbs from the top level, called `top`, to `at`. Everything up to the deepest of the
/// `roots` that holds `at` is one crumb, named after that folder. Without such a folder every
/// component is a crumb, except that the drive and its root (`C:` and `\`) are one: `C:\`.
pub(super) fn crumbs(at: &Path, roots: &[PathBuf], top: &str) -> Vec<Crumb> {
    let mut trail = vec![Crumb {
        label: top.to_owned(),
        target: PathBuf::new(),
    }];
    let deepest = roots
        .iter()
        .filter(|root| is_under(at, root))
        .max_by_key(|root| root.components().count());
    let (mut path, skip) = if let Some(root) = deepest {
        (root.clone(), root.components().count())
    } else {
        let lead = at
            .components()
            .take_while(|part| matches!(part, Component::Prefix(_) | Component::RootDir));
        (lead.clone().collect::<PathBuf>(), lead.count())
    };
    if skip > 0 {
        trail.push(Crumb {
            label: name_of(&path),
            target: path.clone(),
        });
    }
    for part in at.components().skip(skip) {
        path.push(part.as_os_str());
        trail.push(Crumb {
            label: part.as_os_str().to_string_lossy().into_owned(),
            target: path.clone(),
        });
    }
    trail
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn labels(trail: &[Crumb]) -> Vec<&str> {
        trail.iter().map(|crumb| crumb.label.as_str()).collect()
    }

    fn targets(trail: &[Crumb]) -> Vec<&Path> {
        trail.iter().map(|crumb| crumb.target.as_path()).collect()
    }

    #[test]
    fn the_way_up_starts_at_this_pc_and_folds_the_location_into_one_crumb() {
        let roots = roots(&[r"C:\Users\me\Documents"]);
        let top = crumbs(Path::new(""), &roots, "This PC");
        assert_eq!(labels(&top), ["This PC"]);
        assert_eq!(targets(&top), [Path::new("")]);

        let deep = crumbs(
            Path::new(r"C:\Users\me\Documents\Taxes\2024"),
            &roots,
            "This PC",
        );
        assert_eq!(labels(&deep), ["This PC", "Documents", "Taxes", "2024"]);
        assert_eq!(
            targets(&deep),
            [
                Path::new(""),
                Path::new(r"C:\Users\me\Documents"),
                Path::new(r"C:\Users\me\Documents\Taxes"),
                Path::new(r"C:\Users\me\Documents\Taxes\2024"),
            ]
        );

        let at_root = crumbs(Path::new(r"C:\Users\me\Documents"), &roots, "This PC");
        assert_eq!(labels(&at_root), ["This PC", "Documents"]);
    }

    #[test]
    fn the_deepest_location_names_the_first_crumb() {
        let roots = roots(&[r"C:\Users\me", r"C:\Users\me\Documents"]);
        let trail = crumbs(Path::new(r"C:\Users\me\Documents\Taxes"), &roots, "This PC");
        assert_eq!(labels(&trail), ["This PC", "Documents", "Taxes"]);
        let trail = crumbs(Path::new(r"C:\Users\me\Pictures"), &roots, "This PC");
        assert_eq!(labels(&trail), ["This PC", "me", "Pictures"]);
    }

    #[test]
    fn locations_match_without_regard_to_case_even_beyond_ascii() {
        let roots = roots(&[r"C:\Users\Me\Documents"]);
        let trail = crumbs(Path::new(r"c:\users\me\documents\x"), &roots, "This PC");
        assert_eq!(labels(&trail), ["This PC", "Documents", "x"]);
        assert_eq!(trail[1].target, Path::new(r"C:\Users\Me\Documents"));

        let roots = self::roots(&[r"C:\Users\ÜNAL\Documents"]);
        let trail = crumbs(Path::new(r"c:\users\ünal\documents\x"), &roots, "This PC");
        assert_eq!(labels(&trail), ["This PC", "Documents", "x"]);
        assert_eq!(trail[1].target, Path::new(r"C:\Users\ÜNAL\Documents"));
    }

    #[test]
    fn without_a_location_every_component_is_a_crumb_and_the_drive_is_one() {
        let trail = crumbs(
            Path::new(r"C:\Temp\pk"),
            &roots(&[r"C:\Users\me\Documents"]),
            "This PC",
        );
        assert_eq!(labels(&trail), ["This PC", r"C:\", "Temp", "pk"]);
        assert_eq!(
            targets(&trail),
            [
                Path::new(""),
                Path::new(r"C:\"),
                Path::new(r"C:\Temp"),
                Path::new(r"C:\Temp\pk"),
            ]
        );
    }

    #[test]
    fn each_store_names_its_top_level() {
        assert_eq!(top_label(Store::Inventory), "This PC");
        assert_eq!(top_label(Store::Watch), "Watched folders");
        let trail = crumbs(
            Path::new(r"C:\Down"),
            &roots(&[r"C:\Down"]),
            "Watched folders",
        );
        assert_eq!(labels(&trail), ["Watched folders", "Down"]);
    }

    #[test]
    fn a_file_or_a_drive_is_named_by_its_last_component() {
        assert_eq!(name_of(Path::new(r"C:\Docs\a.pdf")), "a.pdf");
        assert_eq!(name_of(Path::new(r"C:\")), r"C:\");
    }
}
