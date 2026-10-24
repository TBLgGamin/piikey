//! The way back up from the folder a dashboard shows: "This PC", the drive the folder is on and
//! the real folders from there down to it, each a step to go back to.

use std::path::{Component, Path, PathBuf};

use piikey::{
    sources::{Virtual, parse_virtual},
    sys::volume_len,
};

/// What the top level is called.
pub(super) const TOP: &str = "This PC";

/// One step of the way from the top level to the folder on show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Crumb {
    pub(super) label: String,
    /// The folder it leads to; empty is the top level.
    pub(super) target: PathBuf,
}

/// The name of a file or folder: its last component. A drive or a share has none and is called
/// by its own name (`C:`, `\\server\share`), as the tree calls it.
pub(super) fn name_of(path: &Path) -> String {
    path.file_name()
        .or_else(|| path.components().next().map(Component::as_os_str))
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}

/// The account of the cloud that `path` is the top of (`\\Google Drive\jan@acme.com`), or `None`
/// for any other path, including everything below an account's top.
pub(super) fn account_top(path: &Path) -> Option<Virtual> {
    parse_virtual(path).filter(|account| account.rest.as_os_str().is_empty())
}

/// The crumbs from the top level, called `top`, to `at`: the drive or share it is on (its name
/// and its root are one crumb, `C:` leading to `C:\`) and every folder from there down.
pub(super) fn crumbs(at: &Path, top: &str) -> Vec<Crumb> {
    let mut trail = vec![Crumb {
        label: top.to_owned(),
        target: PathBuf::new(),
    }];
    let mut parts = at.components();
    let mut path: PathBuf = parts.by_ref().take(volume_len(at)).collect();
    if !path.as_os_str().is_empty() {
        trail.push(Crumb {
            label: account_top(&path).map_or_else(|| name_of(&path), |account| account.label),
            target: path.clone(),
        });
    }
    for part in parts {
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

    fn labels(trail: &[Crumb]) -> Vec<&str> {
        trail.iter().map(|crumb| crumb.label.as_str()).collect()
    }

    fn targets(trail: &[Crumb]) -> Vec<&Path> {
        trail.iter().map(|crumb| crumb.target.as_path()).collect()
    }

    #[test]
    fn the_way_up_starts_at_this_pc_and_goes_down_through_the_real_folders_from_the_drive() {
        let top = crumbs(Path::new(""), "This PC");
        assert_eq!(labels(&top), ["This PC"]);
        assert_eq!(targets(&top), [Path::new("")]);

        let deep = crumbs(Path::new(r"C:\Users\me\Documents\Taxes"), "This PC");
        assert_eq!(
            labels(&deep),
            ["This PC", "C:", "Users", "me", "Documents", "Taxes"]
        );
        assert_eq!(
            targets(&deep),
            [
                Path::new(""),
                Path::new(r"C:\"),
                Path::new(r"C:\Users"),
                Path::new(r"C:\Users\me"),
                Path::new(r"C:\Users\me\Documents"),
                Path::new(r"C:\Users\me\Documents\Taxes"),
            ]
        );

        let drive = crumbs(Path::new(r"C:\"), "This PC");
        assert_eq!(labels(&drive), ["This PC", "C:"]);
        assert_eq!(targets(&drive), [Path::new(""), Path::new(r"C:\")]);
    }

    #[test]
    fn a_network_share_is_a_drive_and_the_spelling_of_the_path_is_kept() {
        let trail = crumbs(Path::new(r"\\nas\Share\docs\2024"), "This PC");
        assert_eq!(labels(&trail), ["This PC", r"\\nas\Share", "docs", "2024"]);
        assert_eq!(
            targets(&trail),
            [
                Path::new(""),
                Path::new(r"\\nas\Share\"),
                Path::new(r"\\nas\Share\docs"),
                Path::new(r"\\nas\Share\docs\2024"),
            ]
        );
        let lower = crumbs(Path::new(r"d:\Mixed\Case"), "This PC");
        assert_eq!(labels(&lower), ["This PC", "d:", "Mixed", "Case"]);
    }

    #[test]
    fn a_path_that_names_no_drive_has_a_crumb_for_each_component() {
        let trail = crumbs(Path::new(r"docs\2024"), "This PC");
        assert_eq!(labels(&trail), ["This PC", "docs", "2024"]);
        assert_eq!(
            targets(&trail),
            [Path::new(""), Path::new("docs"), Path::new(r"docs\2024")]
        );
        let rooted = crumbs(Path::new(r"\docs"), "This PC");
        assert_eq!(labels(&rooted), ["This PC", r"\", "docs"]);
    }

    #[test]
    fn the_top_level_is_named_by_the_caller() {
        let trail = crumbs(Path::new(r"C:\Down"), "This PC");
        assert_eq!(labels(&trail), ["This PC", "C:", "Down"]);
    }

    #[test]
    fn a_file_or_folder_is_named_by_its_last_component_and_a_drive_by_its_own_name() {
        assert_eq!(name_of(Path::new(r"C:\Docs\a.pdf")), "a.pdf");
        assert_eq!(name_of(Path::new(r"C:\")), "C:");
        assert_eq!(name_of(Path::new(r"\\nas\share\")), r"\\nas\share");
        assert_eq!(name_of(Path::new(r"\\nas\share\docs")), "docs");
    }

    #[test]
    fn only_the_top_of_a_cloud_account_is_an_account() {
        let top = account_top(Path::new(r"\\Google Drive\jan@acme.com"));
        assert_eq!(
            top.map(|account| (account.provider.name(), account.label)),
            Some(("Google Drive", "jan@acme.com".to_owned()))
        );
        assert!(account_top(Path::new(r"\\Google Drive\jan@acme.com\My Drive")).is_none());
        assert!(account_top(Path::new(r"\\nas\share")).is_none());
        assert!(account_top(Path::new(r"C:\")).is_none());
    }
}
