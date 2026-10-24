//! What the window keeps for the findings view: the values found in the files of a result, how the
//! list is narrowed down, and what "Open at this place" has done.
//!
//! The values are read in the background, a few files at a time (see
//! [`Controller::read_findings`]), and come to the window in batches. They live here and nowhere
//! else: the view keeps them while it is open, and closing it drops them, and with them the reading
//! that was still going on. The inventory keeps counts, never the values, and nothing here is
//! written to disk.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

use piikey::{
    detect::EntityKind,
    inventory::{Busy, Finding},
    sources,
};
use windows_reactor::{ComponentContext, ComponentTask};

use super::{MainWindow, Msg, dashboard::open_web_page};
use crate::{
    Res,
    ui::{
        controller::{Controller, FindingFiles, FindingsEvent, Notice},
        goto,
    },
};

/// The most values the view keeps: a folder of spreadsheets can hold millions, which no list is
/// for. What is left out is counted and said.
pub const MOST_VALUES: usize = 100_000;

/// A file of the view.
#[derive(Debug, PartialEq, Eq)]
pub struct FileRef {
    pub path: PathBuf,
    /// What the view calls the file: its name, or its path below the folder it was found in.
    pub label: String,
    /// The name of the file alone, for a row.
    pub name: String,
}

/// One value found, as a row of the list.
#[derive(Debug)]
pub struct Row {
    /// Where the row is among everything read; stays when the list is narrowed down.
    pub id: u32,
    pub file: Rc<FileRef>,
    pub finding: Finding,
}

/// What a reading is doing now, for the line of progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Working {
    /// Loading the detection model, which nothing is read without.
    Model,
    /// A file that is being read, and what that takes a while for.
    File(PathBuf, Busy),
}

/// How far the reading is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// The files are being looked for.
    Listing,
    /// `done` of `total` files are read.
    Files { done: usize, total: usize },
    /// Everything there was to read is read.
    Done,
}

/// The findings view: what it reads, what it has read, and how the list is narrowed down.
pub struct FindingsView {
    /// What the view was asked for: the files and folders of a result.
    pub roots: Vec<PathBuf>,
    /// The number of this reading: what comes back for an older one is dropped.
    pub seq: u64,
    /// The task that reads, cancelled when the view closes.
    task: Option<ComponentTask>,
    pub reading: Reading,
    /// What the reading is doing now, when it takes a while: loading the model, reading a picture.
    pub working: Option<Working>,
    /// The files to read, in the order they are listed.
    pub files: Vec<Rc<FileRef>>,
    /// How many files there are beyond the ones that are read.
    pub left_out_files: usize,
    /// Files that were read, and how many of them: the batches come in the order of `files`.
    pub read: usize,
    /// The files that could not be read, and why.
    pub failed: Vec<(Rc<FileRef>, String)>,
    /// Everything that was read, in the order of the files and, in a file, as it is read.
    pub rows: Vec<Rc<Row>>,
    /// How many values were read beyond [`MOST_VALUES`].
    pub left_out_values: usize,
    /// The search box.
    pub search: String,
    /// The only type on show, or all.
    pub kind: Option<EntityKind>,
    /// The only file on show (an index into `files`), or all.
    pub file: Option<usize>,
    /// The rows the search, the type and the file leave.
    pub shown: Rc<Vec<Rc<Row>>>,
    /// How many rows each type has among the ones the search and the file leave, the most first.
    pub counts: Vec<(EntityKind, u64)>,
    /// Grows whenever `shown` changes, so the list knows its rows are others.
    pub revision: u64,
    /// The row whose "Open at this place" is running.
    pub opening: Option<u32>,
    /// Rows whose "Open at this place" could not point at the value.
    pub opened_only: Rc<Vec<u32>>,
}

impl FindingsView {
    /// A view that has read nothing yet.
    pub fn new(roots: Vec<PathBuf>, seq: u64) -> Self {
        Self {
            roots,
            seq,
            task: None,
            reading: Reading::Listing,
            working: None,
            files: Vec::new(),
            left_out_files: 0,
            read: 0,
            failed: Vec::new(),
            rows: Vec::new(),
            left_out_values: 0,
            search: String::new(),
            kind: None,
            file: None,
            shown: Rc::new(Vec::new()),
            counts: Vec::new(),
            revision: 0,
            opening: None,
            opened_only: Rc::new(Vec::new()),
        }
    }

    /// Whether the result is about one file: its rows have no need to name it.
    pub fn single(&self) -> bool {
        self.files.len() <= 1
    }

    /// Whether the search, a type or a file narrows the list down.
    pub fn narrowed(&self) -> bool {
        !self.search.trim().is_empty() || self.kind.is_some() || self.file.is_some()
    }

    /// The files are known: the reading of them is next.
    pub fn list(&mut self, listed: FindingFiles) {
        self.files = listed
            .files
            .into_iter()
            .map(|file| {
                Rc::new(FileRef {
                    name: name_of(&file.path),
                    label: file.label,
                    path: file.path,
                })
            })
            .collect();
        self.left_out_files = listed.left_out;
        self.reading = if self.files.is_empty() {
            Reading::Done
        } else {
            Reading::Files {
                done: 0,
                total: self.files.len(),
            }
        };
        self.refilter();
    }

    /// Takes in what a batch of files held.
    pub fn take(&mut self, batch: Vec<(PathBuf, Result<Vec<Finding>, String>)>) {
        for (path, result) in batch {
            let at = if self
                .files
                .get(self.read)
                .is_some_and(|file| file.path == path)
            {
                Some(self.read)
            } else {
                self.files.iter().position(|file| file.path == path)
            };
            let Some(file) = at.and_then(|at| self.files.get(at)).map(Rc::clone) else {
                continue;
            };
            self.read += 1;
            match result {
                Ok(list) => self.add(&file, list),
                Err(error) => self.failed.push((file, error)),
            }
        }
        self.reading = if self.read >= self.files.len() {
            Reading::Done
        } else {
            Reading::Files {
                done: self.read,
                total: self.files.len(),
            }
        };
        self.refilter();
    }

    /// Adds the findings of `file` as rows, as many as [`MOST_VALUES`] leaves room for.
    fn add(&mut self, file: &Rc<FileRef>, list: Vec<Finding>) {
        let room = MOST_VALUES.saturating_sub(self.rows.len());
        self.left_out_values += list.len().saturating_sub(room);
        for finding in list.into_iter().take(room) {
            let id = u32::try_from(self.rows.len()).unwrap_or(u32::MAX);
            self.rows.push(Rc::new(Row {
                id,
                file: Rc::clone(file),
                finding,
            }));
        }
    }

    /// Everything was read, whatever the batches said.
    pub fn finish(&mut self) {
        self.reading = Reading::Done;
        self.working = None;
    }

    /// More values of the file at `path`, which is still being read: they follow the ones
    /// before them. What the list is cut at is counted and said once it is full.
    pub fn more(&mut self, path: &Path, list: Vec<Finding>) {
        let Some(file) = self
            .files
            .iter()
            .find(|file| file.path == path)
            .map(Rc::clone)
        else {
            return;
        };
        self.add(&file, list);
        if self.rows.len() >= MOST_VALUES {
            self.left_out_values = self.left_out_values.max(1);
        }
        self.refilter();
    }

    /// Makes `shown`, the counts and the revision of what the search, the type and the file leave.
    pub fn refilter(&mut self) {
        let needle = self.search.trim().to_lowercase();
        let only_file = self.file.and_then(|index| self.files.get(index));
        let mut per_kind: BTreeMap<EntityKind, u64> = BTreeMap::new();
        let mut shown: Vec<Rc<Row>> = Vec::new();
        for row in &self.rows {
            if only_file.is_some_and(|file| !Rc::ptr_eq(file, &row.file)) {
                continue;
            }
            if !needle.is_empty() && !row.matches(&needle) {
                continue;
            }
            *per_kind.entry(row.finding.kind).or_default() += 1;
            if self.kind.is_none_or(|kind| kind == row.finding.kind) {
                shown.push(Rc::clone(row));
            }
        }
        // The type on show keeps its chip, even when the search leaves none of it.
        if let Some(kind) = self.kind {
            per_kind.entry(kind).or_default();
        }
        let mut counts: Vec<(EntityKind, u64)> = per_kind.into_iter().collect();
        counts.sort_by_key(|&(kind, n)| (std::cmp::Reverse(n), kind));
        self.counts = counts;
        self.shown = Rc::new(shown);
        self.revision += 1;
    }

    /// The row numbered `id`.
    pub fn row(&self, id: u32) -> Option<&Rc<Row>> {
        self.rows.get(usize::try_from(id).ok()?)
    }

    /// Notes that "Open at this place" of row `id` is done, and how it went.
    fn opened(&mut self, id: u32, outcome: goto::Outcome) {
        if self.opening == Some(id) {
            self.opening = None;
        }
        if outcome == goto::Outcome::Opened {
            let mut ids = self.opened_only.as_ref().clone();
            if !ids.contains(&id) {
                ids.push(id);
            }
            self.opened_only = Rc::new(ids);
        }
    }
}

impl Row {
    /// Whether the search, written in lowercase, is in the value, its type, its file or the text
    /// around it.
    fn matches(&self, needle: &str) -> bool {
        contains_fold(&self.finding.value, needle)
            || contains_fold(self.finding.kind.label(), needle)
            || contains_fold(&self.file.label, needle)
            || contains_fold(&self.finding.snippet, needle)
    }

    /// What "Open at this place" opens for the row: its file, the value to bring into view, and
    /// where the format says it is.
    pub fn target(&self) -> goto::Target {
        goto::Target {
            file: self.file.path.clone(),
            value: self.finding.value.to_string(),
            place: self.finding.location.clone(),
        }
    }
}

/// Whether `haystack` holds `needle`, which is lowercase, in any letter case.
fn contains_fold(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.is_ascii() && needle.is_ascii() {
        let needle = needle.as_bytes();
        haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    } else {
        haystack.to_lowercase().contains(needle)
    }
}

/// The name of the file at `path`.
fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(
        || sources::display_path(path).unwrap_or_else(|| path.display().to_string()),
        |name| name.to_string_lossy().into_owned(),
    )
}

impl MainWindow {
    /// Opens the findings view for `roots`, files and folders, and starts reading what they hold in
    /// the background. A view that is open is closed first, and its reading stops.
    pub(in crate::ui) fn open_findings(
        &mut self,
        roots: Vec<PathBuf>,
        context: &ComponentContext<Self>,
    ) {
        self.close_findings();
        self.findings_seq += 1;
        let seq = self.findings_seq;
        let mut view = FindingsView::new(roots.clone(), seq);
        let controller = Arc::clone(&self.input.controller.0);
        let sender = context.completion();
        view.task = Some(context.spawn_background(move |token| {
            let listed = controller.finding_files(&roots);
            let files: Vec<PathBuf> = listed.files.iter().map(|file| file.path.clone()).collect();
            if token.is_cancelled() || !sender.clone().complete(Msg::FindingsListed(seq, listed)) {
                return Msg::Noop;
            }
            controller.read_findings(&files, MOST_VALUES, |event| {
                if token.is_cancelled() {
                    return false;
                }
                let message = match event {
                    FindingsEvent::Loading => Msg::FindingsBusy(seq, Working::Model),
                    FindingsEvent::Busy(path, busy) => {
                        Msg::FindingsBusy(seq, Working::File(path, busy))
                    }
                    FindingsEvent::Found(path, list) => Msg::FindingsMore(seq, path, list),
                    FindingsEvent::Done(path, result) => {
                        Msg::FindingsRead(seq, vec![(path, result.map(|()| Vec::new()))])
                    }
                };
                sender.clone().complete(message)
            });
            Msg::FindingsDone(seq)
        }));
        self.findings = Some(view);
    }

    /// Closes the findings view: the values go, and what still reads them stops.
    pub(in crate::ui) fn close_findings(&mut self) {
        if let Some(view) = self.findings.take()
            && let Some(task) = &view.task
        {
            task.cancel();
        }
    }

    /// The view, when it is the one reading number `seq`.
    fn findings_of(&mut self, seq: u64) -> Option<&mut FindingsView> {
        self.findings.as_mut().filter(|view| view.seq == seq)
    }

    /// The findings view's own messages. [`Component::update`](windows_reactor::Component::update)
    /// routes them here.
    pub(super) fn update_findings(&mut self, message: Msg, context: &ComponentContext<Self>) {
        match message {
            Msg::FindingsListed(seq, listed) => {
                if let Some(view) = self.findings_of(seq) {
                    view.list(listed);
                }
            }
            Msg::FindingsRead(seq, batch) => {
                if let Some(view) = self.findings_of(seq) {
                    view.take(batch);
                }
            }
            Msg::FindingsMore(seq, path, list) => {
                if let Some(view) = self.findings_of(seq) {
                    view.more(&path, list);
                }
            }
            Msg::FindingsBusy(seq, working) => {
                if let Some(view) = self.findings_of(seq) {
                    view.working = Some(working);
                }
            }
            Msg::FindingsDone(seq) => {
                if let Some(view) = self.findings_of(seq) {
                    view.finish();
                }
            }
            Msg::FindingsSearch(text) => {
                if let Some(view) = &mut self.findings
                    && view.search != text
                {
                    view.search = text;
                    view.refilter();
                }
            }
            Msg::FindingsType(kind) => {
                if let Some(view) = &mut self.findings
                    && view.kind != kind
                {
                    view.kind = kind;
                    view.refilter();
                }
            }
            Msg::FindingsFile(file) => {
                if let Some(view) = &mut self.findings
                    && view.file != file
                {
                    view.file = file;
                    view.refilter();
                }
            }
            Msg::FindingsClose => self.close_findings(),
            Msg::FindingsOpen(id) => self.open_at_place(id, context),
            Msg::FindingsOpened(id, outcome) => {
                if let Some(view) = &mut self.findings {
                    view.opened(id, outcome);
                }
            }
            _ => {}
        }
    }

    /// "Open at this place": opens the file of row `id` in the background and, where the app
    /// allows, brings the value into view. One at a time: the row that is being opened holds the
    /// others still.
    fn open_at_place(&mut self, id: u32, context: &ComponentContext<Self>) {
        let Some(view) = &mut self.findings else {
            return;
        };
        if view.opening.is_some() {
            return;
        }
        let Some(row) = view.row(id).map(Rc::clone) else {
            return;
        };
        view.opening = Some(id);
        let target = row.target();
        self.background(context, move |controller| {
            // Whatever happens, the row is let go of: an error is a notice, the row is done.
            match open_row(controller, &target) {
                Ok(outcome) => Ok(Msg::FindingsOpened(id, outcome)),
                Err(error) => {
                    controller.notify(Notice::error(error));
                    Ok(Msg::FindingsOpened(id, goto::Outcome::Opened))
                }
            }
        });
    }
}

/// Opens the file of a row at the place of its value. A file in the cloud has no app on this PC to
/// take to the value: its web page opens in the browser, which is as far as piikey can go there.
pub(super) fn open_row(controller: &Controller, target: &goto::Target) -> Res<goto::Outcome> {
    if sources::is_virtual(&target.file) {
        open_web_page(controller, &target.file)?;
        Ok(goto::Outcome::Opened)
    } else {
        goto::open_at(target, &controller.purpose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::controller::FindingFile;
    use piikey::inventory::Location;

    fn finding(kind: EntityKind, value: &str, snippet: &str, line: u32) -> Finding {
        Finding {
            kind,
            value: value.into(),
            snippet: snippet.into(),
            location: Some(Location::Line { line, column: 1 }),
        }
    }

    fn listed(files: &[(&str, &str)], left_out: usize) -> FindingFiles {
        FindingFiles {
            files: files
                .iter()
                .map(|&(path, label)| FindingFile {
                    path: PathBuf::from(path),
                    label: label.to_owned(),
                })
                .collect(),
            left_out,
        }
    }

    /// A view of two files that has read both.
    fn view() -> FindingsView {
        let mut view = FindingsView::new(vec![PathBuf::from(r"C:\Docs")], 1);
        view.list(listed(
            &[
                (r"C:\Docs\a.txt", "a.txt"),
                (r"C:\Docs\sub\b.csv", r"sub\b.csv"),
            ],
            0,
        ));
        view.take(vec![
            (
                PathBuf::from(r"C:\Docs\a.txt"),
                Ok(vec![
                    finding(EntityKind::Email, "jan@acme.nl", "mail jan@acme.nl now", 3),
                    finding(EntityKind::Person, "Jan Jansen", "dear Jan Jansen,", 1),
                    finding(EntityKind::Email, "piet@acme.nl", "cc piet@acme.nl", 7),
                ]),
            ),
            (
                PathBuf::from(r"C:\Docs\sub\b.csv"),
                Ok(vec![finding(
                    EntityKind::Iban,
                    "NL91ABNA0417164300",
                    "pay NL91ABNA0417164300",
                    2,
                )]),
            ),
        ]);
        view
    }

    fn values(view: &FindingsView) -> Vec<&str> {
        view.shown.iter().map(|row| &*row.finding.value).collect()
    }

    #[test]
    fn a_view_lists_what_was_read_in_the_order_of_the_files_and_each_file_as_it_reads() {
        let view = view();
        assert_eq!(
            values(&view),
            [
                "jan@acme.nl",
                "Jan Jansen",
                "piet@acme.nl",
                "NL91ABNA0417164300"
            ]
        );
        assert_eq!(view.reading, Reading::Done);
        assert_eq!(view.read, 2);
        assert!(!view.single());
        // Every row has its own number, which stays when the list is narrowed down.
        let ids: Vec<u32> = view.rows.iter().map(|row| row.id).collect();
        assert_eq!(ids, [0, 1, 2, 3]);
        assert_eq!(view.row(3).map(|row| row.file.name.as_str()), Some("b.csv"));
        assert!(view.row(4).is_none());
    }

    #[test]
    fn the_counts_of_the_types_are_the_most_first() {
        let view = view();
        assert_eq!(
            view.counts,
            [
                (EntityKind::Email, 2),
                (EntityKind::Iban, 1),
                (EntityKind::Person, 1)
            ]
        );
    }

    #[test]
    fn the_search_matches_the_value_the_type_the_file_and_the_text_around_it() {
        let mut view = view();
        let search = |view: &mut FindingsView, text: &str| {
            view.search = text.to_owned();
            view.refilter();
            view.shown.len()
        };
        // The value, in any letter case.
        assert_eq!(search(&mut view, "JANSEN"), 1);
        // The type's name as it is on screen.
        assert_eq!(search(&mut view, "iban"), 1);
        assert_eq!(search(&mut view, "email"), 2);
        // The file: its name, and its path below the folder.
        assert_eq!(search(&mut view, "b.csv"), 1);
        assert_eq!(search(&mut view, r"sub\"), 1);
        // The text around the value.
        assert_eq!(search(&mut view, "dear"), 1);
        assert_eq!(search(&mut view, "cc piet"), 1);
        // Nothing, and white space only, narrow nothing down.
        assert_eq!(search(&mut view, "no such text"), 0);
        assert_eq!(search(&mut view, "   "), 4);
        assert_eq!(search(&mut view, ""), 4);
        // Letters with marks fold too.
        view.rows = vec![Rc::new(Row {
            id: 0,
            file: Rc::clone(&view.files[0]),
            finding: finding(
                EntityKind::Person,
                "Zo\u{eb} de Vries",
                "Zo\u{eb} de Vries",
                1,
            ),
        })];
        assert_eq!(search(&mut view, "zo\u{ca}"), 0);
        assert_eq!(search(&mut view, "ZO\u{cb}"), 1);
    }

    #[test]
    fn a_type_and_a_file_narrow_the_list_and_the_counts_follow_the_search_not_the_type() {
        let mut view = view();
        view.kind = Some(EntityKind::Email);
        view.refilter();
        assert_eq!(values(&view), ["jan@acme.nl", "piet@acme.nl"]);
        // The chips still count every type, so another can be picked.
        assert_eq!(view.counts.len(), 3);
        // A search that leaves none of the type on show keeps its chip, with none.
        view.search = "jansen".to_owned();
        view.refilter();
        assert!(values(&view).is_empty());
        assert!(view.counts.contains(&(EntityKind::Email, 0)));
        assert!(view.counts.contains(&(EntityKind::Person, 1)));
        // A file: only its rows.
        view.search.clear();
        view.kind = None;
        view.file = Some(1);
        view.refilter();
        assert_eq!(values(&view), ["NL91ABNA0417164300"]);
        assert_eq!(view.counts, [(EntityKind::Iban, 1)]);
        assert!(view.narrowed());
        view.file = None;
        view.refilter();
        assert!(!view.narrowed());
    }

    #[test]
    fn the_list_has_a_new_revision_whenever_its_rows_change() {
        let mut view = view();
        let before = view.revision;
        view.search = "jan".to_owned();
        view.refilter();
        assert!(view.revision > before);
        let after = view.revision;
        view.take(Vec::new());
        assert!(view.revision > after);
    }

    #[test]
    fn a_file_that_could_not_be_read_is_kept_with_what_went_wrong() {
        let mut view = FindingsView::new(vec![PathBuf::from(r"C:\Docs")], 1);
        view.list(listed(
            &[(r"C:\Docs\a.bin", "a.bin"), (r"C:\Docs\b.txt", "b.txt")],
            0,
        ));
        assert_eq!(view.reading, Reading::Files { done: 0, total: 2 });
        view.take(vec![(
            PathBuf::from(r"C:\Docs\a.bin"),
            Err("not a format piikey reads".to_owned()),
        )]);
        assert_eq!(view.reading, Reading::Files { done: 1, total: 2 });
        assert_eq!(view.failed.len(), 1);
        assert_eq!(view.failed[0].0.name, "a.bin");
        assert_eq!(view.failed[0].1, "not a format piikey reads");
        view.take(vec![(
            PathBuf::from(r"C:\Docs\b.txt"),
            Ok(vec![finding(
                EntityKind::Email,
                "jan@acme.nl",
                "jan@acme.nl",
                1,
            )]),
        )]);
        assert_eq!(view.reading, Reading::Done);
        assert_eq!(view.rows.len(), 1);
    }

    #[test]
    fn a_view_with_no_files_is_done_at_once_and_a_batch_for_no_listed_file_is_ignored() {
        let mut view = FindingsView::new(vec![PathBuf::from(r"C:\Docs")], 1);
        assert_eq!(view.reading, Reading::Listing);
        view.list(listed(&[], 0));
        assert_eq!(view.reading, Reading::Done);
        view.take(vec![(
            PathBuf::from(r"C:\Elsewhere\x.txt"),
            Ok(vec![finding(
                EntityKind::Email,
                "jan@acme.nl",
                "jan@acme.nl",
                1,
            )]),
        )]);
        assert!(view.rows.is_empty());
    }

    #[test]
    fn the_view_keeps_at_most_so_many_values_and_counts_the_rest() {
        let mut view = FindingsView::new(vec![PathBuf::from(r"C:\Docs\a.txt")], 1);
        view.list(listed(&[(r"C:\Docs\a.txt", "a.txt")], 0));
        let many: Vec<Finding> = (0..MOST_VALUES + 5)
            .map(|i| finding(EntityKind::Email, &format!("a{i}@acme.nl"), "x", 1))
            .collect();
        view.take(vec![(PathBuf::from(r"C:\Docs\a.txt"), Ok(many))]);
        assert_eq!(view.rows.len(), MOST_VALUES);
        assert_eq!(view.left_out_values, 5);
        assert!(view.single());
    }

    #[test]
    fn a_row_that_could_only_be_opened_is_remembered_and_the_row_is_let_go_of() {
        let mut view = view();
        view.opening = Some(2);
        view.opened(2, goto::Outcome::Opened);
        assert_eq!(view.opening, None);
        assert_eq!(*view.opened_only, [2]);
        view.opened(2, goto::Outcome::Opened);
        view.opened(1, goto::Outcome::Marked);
        assert_eq!(*view.opened_only, [2]);
    }

    #[test]
    fn a_row_opens_its_file_with_the_value_to_find_and_the_line_when_there_is_one() {
        let view = view();
        assert_eq!(
            view.rows[0].target(),
            goto::Target {
                file: PathBuf::from(r"C:\Docs\a.txt"),
                value: "jan@acme.nl".to_owned(),
                place: Some(Location::Line { line: 3, column: 1 }),
            }
        );
        let sheet = view.rows[3].target();
        assert_eq!(sheet.file, PathBuf::from(r"C:\Docs\sub\b.csv"));
        assert_eq!(sheet.value, "NL91ABNA0417164300");
    }
}
