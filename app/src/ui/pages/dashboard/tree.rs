//! The tree of a dashboard: the folders and files that hold personal data, the ones that hold most
//! first, and the folders the user opened. This decides which rows there are; the widgets in
//! [`super`] draw them.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use piikey::{detect::EntityKind, inventory::Node, sys::is_under};

use super::map::weigh;

/// Rows a folder lists at most; the others are one line that says how many they are.
pub(super) const MAX_SIBLINGS: usize = 200;
/// Rows the tree has at most, however many folders are open.
pub(super) const MAX_ROWS: usize = 1_000;

/// One row of the tree: a folder or a file.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Row<'a> {
    pub(super) node: &'a Node,
    /// How many folders lie between it and the top of the tree.
    pub(super) depth: usize,
    /// It is a folder and its contents are listed below it.
    pub(super) open: bool,
    /// What it holds: everything, or only what is of the type on show.
    pub(super) found: u64,
    /// Its share of what its folder holds, from 0 to 1.
    pub(super) share: f64,
}

/// One line of the tree.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Line<'a> {
    Row(Row<'a>),
    /// The folders and files of a folder beyond [`MAX_SIBLINGS`], as one line.
    More {
        /// Of the folder `depth` levels down.
        depth: usize,
        /// How many they are.
        count: usize,
        /// What they hold together.
        found: u64,
        /// The folder they are in.
        folder: &'a Path,
    },
    /// The tree stops here: [`MAX_ROWS`].
    Cut,
}

impl Line<'_> {
    /// The path the line selects, if it is a row.
    pub(super) fn path(&self) -> Option<&Path> {
        match self {
            Self::Row(row) => Some(&row.node.path),
            Self::More { .. } | Self::Cut => None,
        }
    }
}

/// A share of a whole, from 0 to 1.
#[expect(
    clippy::cast_precision_loss,
    reason = "a bar needs no precision beyond 2^53 values"
)]
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64).clamp(0.0, 1.0)
    }
}

/// The nodes of one level that hold something, as `(node, found)`, the ones that hold most first.
/// With a `pin` the folder it lies in, and the file, come before the others.
fn level<'a>(
    nodes: &'a [Node],
    kind: Option<EntityKind>,
    pin: Option<&Path>,
) -> Vec<(&'a Node, u64)> {
    let mut held: Vec<(&Node, u64)> = nodes
        .iter()
        .map(|node| (node, weigh(&node.counts, node.hits, kind)))
        .filter(|&(_, found)| found > 0)
        .collect();
    let pinned = |node: &Node| pin.is_some_and(|pin| is_under(pin, &node.path));
    held.sort_by(|a, b| {
        pinned(b.0)
            .cmp(&pinned(a.0))
            .then(b.1.cmp(&a.1))
            .then_with(|| a.0.name.to_lowercase().cmp(&b.0.name.to_lowercase()))
    });
    held
}

/// Adds the rows of the folder `folder`, and of the folders open in it, to `out`.
fn list<'a>(
    folder: &'a Path,
    depth: usize,
    levels: &'a HashMap<PathBuf, Vec<Node>>,
    open: &HashSet<PathBuf>,
    pin: Option<&Path>,
    kind: Option<EntityKind>,
    out: &mut Vec<Line<'a>>,
) {
    let Some(nodes) = levels.get(folder) else {
        return;
    };
    let held = level(nodes, kind, pin);
    let whole: u64 = held.iter().map(|&(_, found)| found).sum();
    for (i, &(node, found)) in held.iter().enumerate() {
        if out.len() >= MAX_ROWS {
            if !matches!(out.last(), Some(Line::Cut)) {
                out.push(Line::Cut);
            }
            return;
        }
        if i == MAX_SIBLINGS {
            let rest = &held[i..];
            out.push(Line::More {
                depth,
                count: rest.len(),
                found: rest.iter().map(|&(_, found)| found).sum(),
                folder,
            });
            return;
        }
        let row = Row {
            node,
            depth,
            open: open.contains(&node.path) && levels.contains_key(&node.path),
            found,
            share: share(found, whole),
        };
        let inner = row.open && node.is_dir;
        out.push(Line::Row(row));
        if inner {
            list(&node.path, depth + 1, levels, open, pin, kind, out);
        }
    }
}

/// The lines of the tree under `at` (the top level when it is empty), given the `levels` loaded
/// (a folder's path leads to the nodes in it) and the folders `open`. With a `kind` only what is
/// of that type counts; with a `pin` the way to that path is listed first at each level.
pub(super) fn lines<'a>(
    levels: &'a HashMap<PathBuf, Vec<Node>>,
    at: &'a Path,
    open: &HashSet<PathBuf>,
    pin: Option<&Path>,
    kind: Option<EntityKind>,
) -> Vec<Line<'a>> {
    let mut out = Vec::new();
    list(at, 0, levels, open, pin, kind, &mut out);
    out
}

/// The types a bar tells apart; the others share one grey segment.
const BAR_TYPES: usize = 3;

/// How a bar `width` long is divided among the types of `counts` (the ones `kind` leaves): a
/// segment for each of the [`BAR_TYPES`] that hold most, and one for all the others, `None`.
pub(super) fn segments(
    counts: &[(EntityKind, u32)],
    kind: Option<EntityKind>,
    width: f64,
) -> Vec<(Option<EntityKind>, f64)> {
    let held: Vec<(EntityKind, u32)> = counts
        .iter()
        .copied()
        .filter(|&(of, n)| n > 0 && kind.is_none_or(|kind| kind == of))
        .collect();
    let total: f64 = held.iter().map(|&(_, n)| f64::from(n)).sum();
    if total <= 0.0 || width <= 0.0 {
        return Vec::new();
    }
    let mut out: Vec<(Option<EntityKind>, f64)> = held
        .iter()
        .take(BAR_TYPES)
        .map(|&(of, n)| (Some(of), width * f64::from(n) / total))
        .collect();
    let rest: f64 = held
        .iter()
        .skip(BAR_TYPES)
        .map(|&(_, n)| f64::from(n))
        .sum();
    if rest > 0.0 {
        out.push((None, width * rest / total));
    }
    out
}

/// The index of the row of `path` among `lines`.
pub(super) fn position(lines: &[Line<'_>], path: &Path) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.path().is_some_and(|row| row == path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(path: &str, is_dir: bool, counts: &[(EntityKind, u32)]) -> Node {
        let hits = counts.iter().map(|&(_, n)| u64::from(n)).sum();
        Node {
            path: PathBuf::from(path),
            name: path
                .trim_end_matches('\\')
                .rsplit('\\')
                .next()
                .unwrap_or_default()
                .to_owned(),
            is_dir,
            hits,
            files: 1,
            counts: counts.to_vec(),
        }
    }

    /// Two drives; `C:` holds `Docs` (with `Taxes` in it and a file) and `Mail`.
    fn levels() -> HashMap<PathBuf, Vec<Node>> {
        let mut levels = HashMap::new();
        levels.insert(
            PathBuf::new(),
            vec![
                node(
                    r"C:\",
                    true,
                    &[(EntityKind::Email, 45), (EntityKind::Person, 10)],
                ),
                node(r"D:\", true, &[(EntityKind::Iban, 2)]),
            ],
        );
        levels.insert(
            PathBuf::from(r"C:\"),
            vec![
                node(
                    r"C:\Docs",
                    true,
                    &[(EntityKind::Email, 40), (EntityKind::Person, 10)],
                ),
                node(r"C:\Mail", true, &[(EntityKind::Email, 5)]),
            ],
        );
        levels.insert(
            PathBuf::from(r"C:\Docs"),
            vec![
                node(r"C:\Docs\a.pdf", false, &[(EntityKind::Email, 3)]),
                node(
                    r"C:\Docs\Taxes",
                    true,
                    &[(EntityKind::Email, 37), (EntityKind::Person, 10)],
                ),
            ],
        );
        levels
    }

    fn names<'a>(lines: &[Line<'a>]) -> Vec<&'a str> {
        lines
            .iter()
            .map(|line| match line {
                Line::Row(row) => row.node.name.as_str(),
                Line::More { .. } => "more",
                Line::Cut => "cut",
            })
            .collect()
    }

    fn open(folders: &[&str]) -> HashSet<PathBuf> {
        folders.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn the_top_level_lists_the_drives_that_hold_most_first() {
        let levels = levels();
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None, None);
        assert_eq!(names(&lines), ["C:", "D:"]);
    }

    #[test]
    fn an_open_folder_lists_its_contents_under_it_indented() {
        let levels = levels();
        let open = open(&[r"C:\", r"C:\Docs"]);
        let lines = lines(&levels, Path::new(""), &open, None, None);
        assert_eq!(
            names(&lines),
            ["C:", "Docs", "Taxes", "a.pdf", "Mail", "D:"]
        );
        let depths: Vec<usize> = lines
            .iter()
            .filter_map(|line| match line {
                Line::Row(row) => Some(row.depth),
                _ => None,
            })
            .collect();
        assert_eq!(depths, [0, 1, 2, 2, 1, 0]);
        // Whether it is open is what the row says.
        assert!(matches!(&lines[0], Line::Row(row) if row.open));
        assert!(matches!(&lines[4], Line::Row(row) if !row.open));
    }

    #[test]
    fn a_folder_that_is_open_but_not_loaded_has_nothing_under_it_yet() {
        let levels = levels();
        let lines = lines(&levels, Path::new(""), &open(&[r"D:\"]), None, None);
        assert_eq!(names(&lines), ["C:", "D:"]);
        assert!(matches!(&lines[1], Line::Row(row) if !row.open));
    }

    #[test]
    fn a_folder_on_show_is_the_top_of_the_tree_and_not_a_row() {
        let levels = levels();
        let lines = lines(&levels, Path::new(r"C:\"), &open(&[r"C:\Docs"]), None, None);
        assert_eq!(names(&lines), ["Docs", "Taxes", "a.pdf", "Mail"]);
        assert!(matches!(&lines[0], Line::Row(row) if row.depth == 0));
    }

    #[test]
    fn a_type_leaves_what_holds_none_of_it_and_counts_only_that_type() {
        let levels = levels();
        let lines = lines(
            &levels,
            Path::new(""),
            &HashSet::new(),
            None,
            Some(EntityKind::Person),
        );
        assert_eq!(names(&lines), ["C:"]);
        let Line::Row(row) = &lines[0] else {
            panic!("a row");
        };
        assert_eq!(row.found, 10);
        assert!((row.share - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_share_is_of_what_the_folder_holds() {
        let levels = levels();
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None, None);
        let shares: Vec<f64> = lines
            .iter()
            .filter_map(|line| match line {
                Line::Row(row) => Some(row.share),
                _ => None,
            })
            .collect();
        assert!((shares[0] - 55.0 / 57.0).abs() < 1e-9);
        assert!((shares.iter().sum::<f64>() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn the_way_to_the_pinned_path_comes_first_at_each_level() {
        let levels = levels();
        // The small file is pinned: its folder is listed first anyway, and the file before the
        // folder next to it that holds more.
        let lines = lines(
            &levels,
            Path::new(""),
            &open(&[r"C:\", r"C:\Docs"]),
            Some(Path::new(r"C:\Docs\a.pdf")),
            None,
        );
        assert_eq!(
            names(&lines),
            ["C:", "Docs", "a.pdf", "Taxes", "Mail", "D:"]
        );
        // A pin on the mail puts Mail ahead of Docs.
        let lines = super::lines(
            &levels,
            Path::new(""),
            &open(&[r"C:\"]),
            Some(Path::new(r"C:\Mail")),
            None,
        );
        assert_eq!(names(&lines), ["C:", "Mail", "Docs", "D:"]);
        // A pin on a file of the smaller drive puts that drive first.
        let lines = super::lines(
            &levels,
            Path::new(""),
            &HashSet::new(),
            Some(Path::new(r"D:\Backup\a.txt")),
            None,
        );
        assert_eq!(names(&lines), ["D:", "C:"]);
    }

    #[test]
    fn a_folder_with_very_many_entries_ends_in_one_line_that_counts_the_rest() {
        let many: Vec<Node> = (0..MAX_SIBLINGS + 30)
            .map(|i| {
                node(
                    &format!(r"C:\Big\f{i:04}"),
                    false,
                    &[(EntityKind::Email, 1)],
                )
            })
            .collect();
        let mut levels = HashMap::new();
        levels.insert(PathBuf::new(), many);
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None, None);
        assert_eq!(lines.len(), MAX_SIBLINGS + 1);
        assert!(matches!(
            lines.last(),
            Some(Line::More {
                count: 30,
                found: 30,
                ..
            })
        ));
    }

    #[test]
    fn the_tree_stops_at_the_most_rows_it_has() {
        let mut levels = HashMap::new();
        let mut open = HashSet::new();
        let tops: Vec<Node> = (0..10)
            .map(|i| node(&format!(r"C:\T{i}"), true, &[(EntityKind::Email, 100)]))
            .collect();
        for top in &tops {
            let inner: Vec<Node> = (0..MAX_SIBLINGS)
                .map(|i| {
                    node(
                        &format!(r"{}\f{i}", top.path.display()),
                        false,
                        &[(EntityKind::Email, 1)],
                    )
                })
                .collect();
            open.insert(top.path.clone());
            levels.insert(top.path.clone(), inner);
        }
        levels.insert(PathBuf::new(), tops);
        let lines = lines(&levels, Path::new(""), &open, None, None);
        assert!(lines.len() <= MAX_ROWS + 1, "{} lines", lines.len());
        assert!(matches!(lines.last(), Some(Line::Cut)));
    }

    #[test]
    fn a_bar_is_divided_among_the_three_types_that_hold_most_and_the_rest() {
        let counts = [
            (EntityKind::Email, 50),
            (EntityKind::Person, 25),
            (EntityKind::Phone, 15),
            (EntityKind::Iban, 6),
            (EntityKind::Mac, 4),
        ];
        let parts = segments(&counts, None, 100.0);
        let kinds: Vec<Option<EntityKind>> = parts.iter().map(|part| part.0).collect();
        assert_eq!(
            kinds,
            [
                Some(EntityKind::Email),
                Some(EntityKind::Person),
                Some(EntityKind::Phone),
                None
            ]
        );
        let widths: Vec<f64> = parts.iter().map(|part| part.1).collect();
        assert!((widths[0] - 50.0).abs() < 1e-9 && (widths[3] - 10.0).abs() < 1e-9);
        assert!((widths.iter().sum::<f64>() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn a_bar_of_one_type_is_that_type_only() {
        let counts = [(EntityKind::Email, 5), (EntityKind::Person, 5)];
        assert_eq!(
            segments(&counts, Some(EntityKind::Person), 80.0),
            [(Some(EntityKind::Person), 80.0)]
        );
        assert!(segments(&counts, Some(EntityKind::Mac), 80.0).is_empty());
        assert!(segments(&[], None, 80.0).is_empty());
        assert!(segments(&counts, None, 0.0).is_empty());
    }

    #[test]
    fn a_row_is_found_again_by_its_path() {
        let levels = levels();
        let open = open(&[r"C:\", r"C:\Docs"]);
        let lines = lines(&levels, Path::new(""), &open, None, None);
        assert_eq!(position(&lines, Path::new(r"C:\Docs\a.pdf")), Some(3));
        assert_eq!(position(&lines, Path::new(r"C:\Gone")), None);
    }
}
