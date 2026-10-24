//! The tree of a dashboard: the folders and files that hold personal data, in the order Explorer
//! lists them (folders first, then files, each by name; the drives `C:`, `D:`, ... and then the
//! shares), and the folders the user opened. This decides which rows there are; the widgets in
//! [`super`] draw them. A row's place never changes but by rows coming or going above it, so a
//! folder opened only adds its contents under it.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use piikey::{detect::EntityKind, inventory::Node};

use super::map::weigh;

/// Rows a folder lists at most; the others are one line that says how many they are.
pub(super) const MAX_SIBLINGS: usize = 200;
/// Rows the tree has at most, however many folders are open.
pub(super) const MAX_ROWS: usize = 1_000;

/// One row of the tree: a folder or a file.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Row {
    pub(super) node: Node,
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
pub(super) enum Line {
    Row(Row),
    /// The folders and files of a folder beyond [`MAX_SIBLINGS`], as one line.
    More {
        /// Of the folder `depth` levels down.
        depth: usize,
        /// How many they are.
        count: usize,
        /// What they hold together.
        found: u64,
        /// The folder they are in.
        folder: PathBuf,
    },
    /// The tree stops here: [`MAX_ROWS`].
    Cut,
}

impl Line {
    /// What tells the line apart from the others of the tree, whatever its place: the path of a
    /// row, the folder of a line of more.
    pub(super) fn key(&self) -> String {
        match self {
            Self::Row(row) => format!("row:{}", row.node.path.display()),
            Self::More { folder, .. } => format!("more:{}", folder.display()),
            Self::Cut => "cut".to_owned(),
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

/// Explorer's order: folders before files, each by name without regard to letter case; at the top
/// the drives before the network shares (`\\server\share`).
fn explorer_order(a: &Node, b: &Node) -> Ordering {
    let share = |node: &Node| node.name.starts_with(r"\\");
    b.is_dir
        .cmp(&a.is_dir)
        .then_with(|| share(a).cmp(&share(b)))
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        .then_with(|| a.name.cmp(&b.name))
}

/// The nodes of one level that hold something, as `(node, found)`, in [`explorer_order`].
fn level(nodes: &[Node], kind: Option<EntityKind>) -> Vec<(&Node, u64)> {
    let mut held: Vec<(&Node, u64)> = nodes
        .iter()
        .map(|node| (node, weigh(&node.counts, node.hits, kind)))
        .filter(|&(_, found)| found > 0)
        .collect();
    held.sort_by(|a, b| explorer_order(a.0, b.0));
    held
}

/// Adds the rows of the folder `folder`, and of the folders open in it, to `out`.
fn list(
    folder: &Path,
    depth: usize,
    levels: &HashMap<PathBuf, Vec<Node>>,
    open: &HashSet<PathBuf>,
    kind: Option<EntityKind>,
    out: &mut Vec<Line>,
) {
    let Some(nodes) = levels.get(folder) else {
        return;
    };
    let held = level(nodes, kind);
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
                folder: folder.to_path_buf(),
            });
            return;
        }
        let inner = node.is_dir && open.contains(&node.path) && levels.contains_key(&node.path);
        out.push(Line::Row(Row {
            node: node.clone(),
            depth,
            open: inner,
            found,
            share: share(found, whole),
        }));
        if inner {
            list(&node.path, depth + 1, levels, open, kind, out);
        }
    }
}

/// The lines of the tree under `at` (the top level when it is empty), given the `levels` loaded
/// (a folder's path leads to the nodes in it) and the folders `open`. With a `kind` only what is
/// of that type counts.
pub(super) fn lines(
    levels: &HashMap<PathBuf, Vec<Node>>,
    at: &Path,
    open: &HashSet<PathBuf>,
    kind: Option<EntityKind>,
) -> Vec<Line> {
    let mut out = Vec::new();
    list(at, 0, levels, open, kind, &mut out);
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

    fn names(lines: &[Line]) -> Vec<&str> {
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
    fn the_top_level_lists_the_drives_by_letter_and_then_the_shares() {
        let mut levels = HashMap::new();
        levels.insert(
            PathBuf::new(),
            vec![
                node(r"\\nas\team", true, &[(EntityKind::Email, 90)]),
                node(r"X:\", true, &[(EntityKind::Email, 1)]),
                node(r"C:\", true, &[(EntityKind::Email, 2)]),
                node(r"D:\", true, &[(EntityKind::Email, 50)]),
            ],
        );
        // The name of a share is its whole `\\server\share`.
        if let Some(share) = levels.get_mut(&PathBuf::new()).and_then(|v| v.first_mut()) {
            share.name = r"\\nas\team".to_owned();
        }
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None);
        assert_eq!(names(&lines), ["C:", "D:", "X:", r"\\nas\team"]);
    }

    #[test]
    fn folders_come_before_files_each_by_name_whatever_they_hold() {
        let mut levels = HashMap::new();
        levels.insert(
            PathBuf::new(),
            vec![
                node(r"C:\b.txt", false, &[(EntityKind::Email, 1)]),
                node(r"C:\Zeta", true, &[(EntityKind::Email, 1)]),
                node(r"C:\A.txt", false, &[(EntityKind::Email, 99)]),
                node(r"C:\alpha", true, &[(EntityKind::Email, 40)]),
            ],
        );
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None);
        assert_eq!(names(&lines), ["alpha", "Zeta", "A.txt", "b.txt"]);
    }

    #[test]
    fn opening_a_folder_only_adds_its_contents_under_it() {
        let levels = levels();
        let keys = |lines: &[Line]| lines.iter().map(Line::key).collect::<Vec<_>>();
        let closed = keys(&lines(&levels, Path::new(""), &open(&[r"C:\"]), None));
        let opened = keys(&lines(
            &levels,
            Path::new(""),
            &open(&[r"C:\", r"C:\Docs"]),
            None,
        ));
        let kept: Vec<&String> = opened.iter().filter(|key| closed.contains(key)).collect();
        assert_eq!(kept, closed.iter().collect::<Vec<_>>());
        assert_eq!(opened.len(), closed.len() + 2);
    }

    #[test]
    fn an_open_folder_lists_its_contents_under_it_indented() {
        let levels = levels();
        let open = open(&[r"C:\", r"C:\Docs"]);
        let lines = lines(&levels, Path::new(""), &open, None);
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
        let lines = lines(&levels, Path::new(""), &open(&[r"D:\"]), None);
        assert_eq!(names(&lines), ["C:", "D:"]);
        assert!(matches!(&lines[1], Line::Row(row) if !row.open));
    }

    #[test]
    fn a_folder_on_show_is_the_top_of_the_tree_and_not_a_row() {
        let levels = levels();
        let lines = lines(&levels, Path::new(r"C:\"), &open(&[r"C:\Docs"]), None);
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
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None);
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
        let lines = lines(&levels, Path::new(""), &HashSet::new(), None);
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
        let lines = lines(&levels, Path::new(""), &open, None);
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
}
