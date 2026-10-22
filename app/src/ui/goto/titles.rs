//! Which top-level window is the one that has the file open, told from what the desktop shows:
//! a title that holds the name of the file, and a window that is new since the file was opened.
//!
//! Nothing here talks to Windows: the search reads the windows into [`Window`]s, and this decides.

use std::{collections::HashMap, path::Path};

/// The fewest characters the name of a file without its extension needs to count as a name in a
/// title: a shorter one is in too many titles.
const MIN_STEM: usize = 3;

/// A top-level window, as far as the search tells windows apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Window {
    /// What identifies the window on the desktop for as long as it lives.
    pub(super) id: Vec<i32>,
    pub(super) title: String,
}

/// The windows that were open before the file was opened, with their titles.
#[derive(Debug, Default)]
pub(super) struct Before(HashMap<Vec<i32>, String>);

impl Before {
    /// What `windows` show now.
    pub(super) fn of<'a>(windows: impl IntoIterator<Item = &'a Window>) -> Self {
        Self(
            windows
                .into_iter()
                .map(|window| (window.id.clone(), window.title.clone()))
                .collect(),
        )
    }

    /// Whether opening the file made `window`, or changed it: it was not there before, or its
    /// title was another one (an app that opens the file in a window it has, as a tab, shows the
    /// name of the file in the title then).
    fn is_new(&self, window: &Window) -> bool {
        self.0.get(&window.id) != Some(&window.title)
    }
}

/// What names a file in a title: its name, and its name without the extension, both in lower
/// case. An app that hides the extension of known file types shows the second.
#[derive(Debug)]
pub(super) struct Names {
    name: String,
    stem: Option<String>,
}

impl Names {
    /// The names of `file`; `None` when it has none.
    pub(super) fn of(file: &Path) -> Option<Self> {
        let name = file.file_name()?.to_string_lossy().to_lowercase();
        let stem = file
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_lowercase())
            .filter(|stem| *stem != name && stem.chars().count() >= MIN_STEM);
        (!name.is_empty()).then_some(Self { name, stem })
    }
}

/// The window of `windows` that has the file open, as the index of it, or `None` for no window
/// yet. A window that is new (see [`Before`]) and has the name of the file in its title is the
/// one; else a new window that has the name without the extension; else, once `grace_over`, a
/// window that was already there with the name: the app had the file open, and showed it. Of
/// several, the first: the desktop lists windows from the top of the stack.
pub(super) fn pick(
    windows: &[Window],
    before: &Before,
    names: &Names,
    grace_over: bool,
) -> Option<usize> {
    let find = |wanted: &str, new_only: bool| {
        windows.iter().position(|window| {
            (!new_only || before.is_new(window)) && window.title.to_lowercase().contains(wanted)
        })
    };
    find(&names.name, true)
        .or_else(|| names.stem.as_deref().and_then(|stem| find(stem, true)))
        .or_else(|| {
            if grace_over {
                find(&names.name, false)
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(id: i32, title: &str) -> Window {
        Window {
            id: vec![42, id],
            title: title.to_owned(),
        }
    }

    fn named(file: &str) -> Result<Names, String> {
        Names::of(Path::new(file)).ok_or_else(|| format!("{file:?} has no name"))
    }

    #[test]
    fn a_new_window_with_the_name_of_the_file_is_the_one() -> Result<(), String> {
        let before = Before::of(&[window(1, "Notes - Notepad"), window(2, "Inbox - Mail")]);
        let now = [
            window(3, "a.txt - Notepad"),
            window(1, "Notes - Notepad"),
            window(2, "Inbox - Mail"),
        ];
        let names = named(r"C:\data\a.txt")?;
        assert_eq!(pick(&now, &before, &names, false), Some(0));
        Ok(())
    }

    #[test]
    fn the_title_is_compared_in_any_letter_case() -> Result<(), String> {
        let now = [window(3, "REPORT.DOCX - Word")];
        let names = named(r"C:\Docs\Report.docx")?;
        assert_eq!(pick(&now, &Before::default(), &names, false), Some(0));
        Ok(())
    }

    #[test]
    fn a_window_whose_title_changed_is_new() -> Result<(), String> {
        // Notepad++ has a window and opens the file as a tab: the title is the file's now.
        let before = Before::of(&[window(7, "new 1 - Notepad++")]);
        let now = [window(7, r"C:\data\a.txt - Notepad++")];
        let names = named(r"C:\data\a.txt")?;
        assert_eq!(pick(&now, &before, &names, false), Some(0));
        Ok(())
    }

    #[test]
    fn a_window_that_had_the_file_already_is_used_after_the_grace_only() -> Result<(), String> {
        let now = [window(7, "a.txt - Notepad")];
        let before = Before::of(&now);
        let names = named(r"C:\data\a.txt")?;
        // A new window for the file may still be on its way.
        assert_eq!(pick(&now, &before, &names, false), None);
        assert_eq!(pick(&now, &before, &names, true), Some(0));
        Ok(())
    }

    #[test]
    fn a_new_window_wins_over_an_old_one_with_the_name_at_any_time() -> Result<(), String> {
        let old = window(7, "a.txt - Notepad");
        let before = Before::of(std::slice::from_ref(&old));
        let now = [old, window(8, "a.txt - Notepad")];
        let names = named(r"C:\data\a.txt")?;
        assert_eq!(pick(&now, &before, &names, false), Some(1));
        assert_eq!(pick(&now, &before, &names, true), Some(1));
        Ok(())
    }

    #[test]
    fn the_name_without_the_extension_counts_for_a_new_window_only() -> Result<(), String> {
        // Word shows `Report` when the extension of known file types is hidden.
        let names = named(r"C:\Docs\Report.docx")?;
        let new = [window(3, "Report - Word")];
        assert_eq!(pick(&new, &Before::default(), &names, false), Some(0));
        // A window that was there with such a title tells nothing about this file.
        let old = [window(3, "Report - Word")];
        assert_eq!(pick(&old, &Before::of(&old), &names, true), None);
        Ok(())
    }

    #[test]
    fn a_short_name_without_the_extension_is_in_too_many_titles() -> Result<(), String> {
        let names = named(r"C:\data\ab.txt")?;
        let now = [window(3, "ab - Calculator")];
        assert_eq!(pick(&now, &Before::default(), &names, true), None);
        // A name that is nothing but an extension has no name without it.
        assert_eq!(named(r"C:\data\.gitignore")?.stem, None);
        Ok(())
    }

    #[test]
    fn a_window_without_the_name_is_not_the_one() -> Result<(), String> {
        let now = [window(1, "Notes - Notepad"), window(2, "")];
        let names = named(r"C:\data\a.txt")?;
        assert_eq!(pick(&now, &Before::default(), &names, true), None);
        assert_eq!(pick(&[], &Before::default(), &names, true), None);
        Ok(())
    }

    #[test]
    fn a_path_without_a_name_has_no_names() {
        assert!(Names::of(Path::new(r"C:\")).is_none());
        assert!(Names::of(Path::new("")).is_none());
    }
}
