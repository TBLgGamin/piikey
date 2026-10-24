//! Where the values of a scan stand in their file: the line and column in a text, the page of a
//! PDF, the cell of a sheet.
//!
//! A format that has a place to name hands its [`Layout`] to the pass beside the texts it reads
//! (`Pass::plan`, `Pass::run`). Only a scan that was asked for findings looks at it, so every
//! other pass pays nothing. Only the file itself has places: what sits in it (an attachment, a
//! package embedded in a package, the text of a picture) is read with [`Layout::Nowhere`],
//! because a position in a file of its own is no position in this one.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickKind};

use super::{Finding, Location, MAX_VALUE};
use crate::detect::Span;

/// The most bytes of values that the file of a message is searched for in one go. Every distinct
/// value is a pattern of one automaton, so a message with endless values cannot take the memory
/// of the process: the values past it have no place.
const MAX_SEARCHED: usize = 1 << 20;

/// Where the texts that a format hands to the engine stand in the file they were read from.
#[derive(Clone, Copy)]
pub(super) enum Layout<'a> {
    /// Nowhere that the file names: a text in an attachment, in an embedded package or in a
    /// picture, and every format that has no place to name.
    Nowhere,
    /// Each text is a whole text file as an editor shows it, once decoded: a line and a column.
    Lines,
    /// The one text is the pages of a PDF joined together; these are the byte offsets at which
    /// each page begins, in order.
    Pages(&'a [usize]),
    /// The texts are a rendering of a message that came from this file, decoded to this text:
    /// each value is looked for in the file.
    Raw(&'a str),
    /// The format says for itself. Given the numbers (among the texts) of the texts that hold a
    /// value, in increasing order, it answers with the place of each.
    Texts(&'a dyn Fn(&[usize]) -> Vec<Option<Location>>),
}

impl Layout<'_> {
    /// Whether a value is placed by looking at every value of its call together, and so cannot be
    /// placed before the call is done: a message's values are looked up in its file, the `k`th
    /// finding of a value at its `k`th occurrence.
    pub(super) fn needs_the_whole_call(&self) -> bool {
        matches!(self, Self::Raw(_))
    }

    /// Gives the findings in `made` their places. They are the findings of `spans`, text after
    /// text: the findings of `texts[0]` first, one for each of `spans[0]`, then those of
    /// `texts[1]`, and so on.
    pub(super) fn locate(self, texts: &[&str], spans: &[Vec<Span>], made: &mut [Finding]) {
        match self {
            Self::Nowhere => {}
            Self::Lines => {
                let mut left = made.iter_mut();
                for (text, in_text) in texts.iter().zip(spans) {
                    let mut cursor = Cursor::new(text);
                    for (span, one) in in_text.iter().zip(left.by_ref().take(in_text.len())) {
                        one.location = Some(cursor.at(span.start));
                    }
                }
            }
            Self::Pages(starts) => {
                for (span, one) in spans.iter().flatten().zip(made) {
                    let page = starts.partition_point(|&start| start <= span.start).max(1);
                    one.location = Some(Location::Page(u32::try_from(page).unwrap_or(u32::MAX)));
                }
            }
            Self::Raw(raw) => in_raw(raw, made),
            Self::Texts(locate) => by_text(locate, spans, made),
        }
    }
}

/// Asks `locate` once about the texts that hold a value and gives each of their findings the
/// answer for its text. `made` are the findings of `spans`, as for [`Layout::locate`].
fn by_text(
    locate: &dyn Fn(&[usize]) -> Vec<Option<Location>>,
    spans: &[Vec<Span>],
    made: &mut [Finding],
) {
    let held: Vec<usize> = spans
        .iter()
        .enumerate()
        .filter(|(_, in_text)| !in_text.is_empty())
        .map(|(index, _)| index)
        .collect();
    let mut answers = locate(held.as_slice()).into_iter();
    let mut from = 0;
    for in_text in spans {
        let to = from + in_text.len();
        if !in_text.is_empty() {
            let place = answers.next().flatten();
            for one in made.get_mut(from..to).unwrap_or_default() {
                one.location.clone_from(&place);
            }
        }
        from = to;
    }
}

/// Counts lines and columns going forward through a text, so that the places of many offsets,
/// asked for in increasing order, cost one read of the text and not one read each.
///
/// A line ends at `\n`, at `\r\n` or at a `\r` that no `\n` follows. Columns count characters
/// (Unicode scalar values: a tab is one), not bytes.
struct Cursor<'t> {
    bytes: &'t [u8],
    /// The offset that the counts below are for.
    at: usize,
    /// The line that `at` is in, from 1.
    line: u32,
    /// The characters of that line before `at`.
    before: u32,
    /// Whether the byte before `at` is a `\r`, so that a `\n` right after it is the same break.
    after_cr: bool,
}

impl<'t> Cursor<'t> {
    fn new(text: &'t str) -> Self {
        Self::top(text.as_bytes())
    }

    fn top(bytes: &'t [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            line: 1,
            before: 0,
            after_cr: false,
        }
    }

    /// The line and the column, both from 1, of byte offset `to`. Asked for an offset before
    /// the last one, it counts again from the top of the text; one past the end counts as the
    /// end.
    fn at(&mut self, to: usize) -> Location {
        if to < self.at {
            *self = Self::top(self.bytes);
        }
        let bytes = self.bytes;
        let to = to.min(bytes.len());
        for &byte in bytes.get(self.at..to).unwrap_or_default() {
            if byte == b'\n' && self.after_cr {
                // The other half of a `\r\n`, whose break was counted at the `\r`.
            } else if byte == b'\n' || byte == b'\r' {
                self.line = self.line.saturating_add(1);
                self.before = 0;
            } else if byte & 0xC0 != 0x80 {
                // Not a continuation byte of a character that has been counted already.
                self.before = self.before.saturating_add(1);
            }
            self.after_cr = byte == b'\r';
        }
        self.at = to;
        Location::Line {
            line: self.line,
            column: self.before.saturating_add(1),
        }
    }
}

/// Gives each finding of `made`, the findings of a message, the line and column in `raw`, the
/// file of the message decoded as text, where its value stands in that file. See [`occurrences`].
fn in_raw(raw: &str, made: &mut [Finding]) {
    let values: Vec<&str> = made.iter().map(|one| &*one.value).collect();
    let found = occurrences(raw, &values, MAX_SEARCHED);
    // The cursor goes forward only: ask it in the order of the file.
    let mut order: Vec<(usize, usize)> = found
        .iter()
        .enumerate()
        .filter_map(|(index, at)| at.map(|at| (at, index)))
        .collect();
    order.sort_unstable();
    let mut cursor = Cursor::new(raw);
    for (at, index) in order {
        if let Some(one) = made.get_mut(index) {
            one.location = Some(cursor.at(at));
        }
    }
}

/// For each of `values`, where in `raw` it is written: the byte offset of the first occurrence of
/// it that no earlier one of the same value has, or `None` when there is no such occurrence.
///
/// So the `k`th finding of a value gets the `k`th occurrence of it, as written: a value that was
/// collapsed from one that spans a line break, or that is not in the file as such (it is inside
/// a base64 body, or it was decoded from a header), has none. Occurrences of one value do not
/// overlap. A value that was cut to [`MAX_VALUE`] characters is looked for by what comes before
/// its `…`.
///
/// One pass over `raw` finds the occurrences of every value, however many: the values are the
/// patterns of one automaton. It takes `budget` bytes of distinct values; the ones past it, and
/// empty ones, have no place.
fn occurrences(raw: &str, values: &[&str], budget: usize) -> Vec<Option<usize>> {
    // The distinct values to look for, how many findings each has, and which value each finding
    // is.
    let mut ids: HashMap<&str, usize> = HashMap::new();
    let mut keys: Vec<&str> = Vec::new();
    let mut needed: Vec<usize> = Vec::new();
    let mut owners: Vec<Option<usize>> = Vec::with_capacity(values.len());
    let mut bytes = 0_usize;
    for &value in values {
        let key = searched(value);
        let owner = if let Some(&id) = ids.get(key) {
            needed[id] += 1;
            Some(id)
        } else if !key.is_empty() && bytes.saturating_add(key.len()) <= budget {
            bytes += key.len();
            ids.insert(key, keys.len());
            keys.push(key);
            needed.push(1);
            Some(keys.len() - 1)
        } else {
            None
        };
        owners.push(owner);
    }

    // Where each value was found, as many times as it has findings. The contiguous automaton is
    // the one whose size follows the values alone: the automatic choice is a table of all 256
    // bytes for each state when there are few values, however long they are.
    let mut at: Vec<Vec<usize>> = vec![Vec::new(); keys.len()];
    if !keys.is_empty()
        && let Ok(automaton) = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(&keys)
        && let Ok(hits) = automaton.try_find_overlapping_iter(raw)
    {
        let mut ends = vec![0_usize; keys.len()];
        let mut open = keys.len();
        for hit in hits {
            let id = hit.pattern().as_usize();
            if at[id].len() < needed[id] && hit.start() >= ends[id] {
                at[id].push(hit.start());
                ends[id] = hit.end();
                if at[id].len() == needed[id] {
                    open -= 1;
                    if open == 0 {
                        break;
                    }
                }
            }
        }
    }

    let mut used = vec![0_usize; keys.len()];
    owners
        .into_iter()
        .map(|owner| {
            let id = owner?;
            let nth = used[id];
            used[id] += 1;
            at[id].get(nth).copied()
        })
        .collect()
}

/// What to look for in a file for a finding with `value`: all of it, or for a value that was cut
/// to [`MAX_VALUE`] characters what comes before the `…` that says so.
fn searched(value: &str) -> &str {
    match value.char_indices().nth(MAX_VALUE) {
        Some((end, '…')) => &value[..end],
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::EntityKind;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the helper stands for the Option that a finding carries, so tests compare like with like"
    )]
    fn line(line: u32, column: u32) -> Option<Location> {
        Some(Location::Line { line, column })
    }

    fn found(value: &str) -> Finding {
        Finding {
            kind: EntityKind::Email,
            value: value.into(),
            snippet: value.into(),
            location: None,
        }
    }

    fn span(start: usize, end: usize) -> Span {
        Span {
            start,
            end,
            kind: EntityKind::Email,
        }
    }

    /// The places of the bytes `at` of `text`, asked for in that order.
    fn places(text: &str, at: &[usize]) -> Vec<Option<Location>> {
        let mut cursor = Cursor::new(text);
        at.iter().map(|&to| Some(cursor.at(to))).collect()
    }

    /// [`occurrences`] with the budget a message has.
    fn in_file(raw: &str, values: &[&str]) -> Vec<Option<usize>> {
        occurrences(raw, values, MAX_SEARCHED)
    }

    #[test]
    fn lines_end_at_lf_crlf_and_a_lone_cr() {
        // a b \r \n c d \r e f \n g h \n \r i j   (bytes 0 to 15)
        let text = "ab\r\ncd\ref\ngh\n\rij";
        assert_eq!(
            places(text, &[0, 1, 4, 5, 7, 8, 10, 11, 13, 14, 15]),
            [
                line(1, 1),
                line(1, 2),
                line(2, 1),
                line(2, 2),
                line(3, 1),
                line(3, 2),
                line(4, 1),
                line(4, 2),
                // The empty line that a `\r` after a `\n` ends.
                line(5, 1),
                line(6, 1),
                line(6, 2),
            ]
        );
    }

    #[test]
    fn a_cr_before_a_crlf_is_a_break_of_its_own() {
        // x \r \r \n y: the first \r is a break, the second pairs with the \n.
        assert_eq!(places("x\r\r\ny", &[4]), [line(3, 1)]);
        // x \r \n \n y: a CRLF, then a LF.
        assert_eq!(places("x\r\n\ny", &[4]), [line(3, 1)]);
    }

    #[test]
    fn columns_count_characters_not_bytes() {
        // Two bytes, four bytes and three bytes for the three characters before the `x`.
        let text = "é😀€x";
        assert_eq!(places(text, &[text.len() - 1]), [line(1, 4)]);
        // A tab is one character.
        assert_eq!(places("a\t\tb", &[3]), [line(1, 4)]);
        // The next line starts at 1, after a character of two bytes and the break.
        assert_eq!(places("é\nx", &[3]), [line(2, 1)]);
    }

    #[test]
    fn a_cursor_asked_backwards_counts_again_from_the_top() {
        let text = "ab\ncd\nef";
        assert_eq!(
            places(text, &[7, 4, 7, 0, 3, 3]),
            [
                line(3, 2),
                line(2, 2),
                line(3, 2),
                line(1, 1),
                line(2, 1),
                line(2, 1)
            ]
        );
        // Past the end is the end.
        assert_eq!(places(text, &[1000]), [line(3, 3)]);
        assert_eq!(places("", &[0, 5]), [line(1, 1), line(1, 1)]);
    }

    #[test]
    fn a_long_line_is_walked_once() -> Fallible<()> {
        // A quadratic walk would read about 1.6 million million bytes here.
        let text = "x".repeat(8_000_000);
        let mut cursor = Cursor::new(&text);
        let mut last = 0;
        let mut place = None;
        for at in (0..400_000).map(|index| index * 20) {
            last = at;
            place = Some(cursor.at(at));
        }
        assert_eq!(place, line(1, u32::try_from(last + 1)?));
        Ok(())
    }

    #[test]
    fn the_kth_finding_of_a_value_gets_the_kth_occurrence_of_it() {
        //  0         1
        //  01234567890123456789
        let raw = "a@x.nl b@x.nl a@x.nl";
        let at = in_file(raw, &["a@x.nl", "b@x.nl", "a@x.nl", "a@x.nl"]);
        assert_eq!(at, [Some(0), Some(7), Some(14), None]);
        // Another order of the findings does not change which occurrences a value has.
        let at = in_file(raw, &["b@x.nl", "a@x.nl", "b@x.nl", "a@x.nl"]);
        assert_eq!(at, [Some(7), Some(0), None, Some(14)]);
    }

    #[test]
    fn only_what_is_written_exactly_as_the_value_is_found() {
        let raw = "Jan\r\nJansen jan a@X.nl";
        let at = in_file(raw, &["Jan Jansen", "a@x.nl", "", "Jansen", "Jan"]);
        // The value that spans a line break, the one in another case and the empty one have no
        // place.
        assert_eq!(at, [None, None, None, Some(5), Some(0)]);
    }

    #[test]
    fn occurrences_of_one_value_do_not_overlap_and_a_value_inside_another_has_its_own() {
        assert_eq!(in_file("aaa", &["aa", "aa"]), [Some(0), None]);
        assert_eq!(in_file("aaaa", &["aa", "aa"]), [Some(0), Some(2)]);
        assert_eq!(
            in_file("Jan Jansen", &["Jan Jansen", "Jansen", "Jan"]),
            [Some(0), Some(4), Some(0)]
        );
    }

    #[test]
    fn a_value_cut_to_its_limit_is_looked_for_by_what_comes_before_the_ellipsis() {
        let long = "k".repeat(MAX_VALUE);
        let cut = format!("{long}…");
        assert_eq!(searched(&cut), long);
        assert_eq!(searched(&long), long, "not cut: all of it is looked for");
        // A value that ends in an ellipsis of its own is not a cut one.
        assert_eq!(searched("see more…"), "see more…");
        let raw = format!("x {long} y");
        assert_eq!(in_file(&raw, &[cut.as_str()]), [Some(2)]);
    }

    #[test]
    fn values_past_the_budget_have_no_place_and_the_rest_still_do() {
        let raw = "abcd efgh abcd ijk";
        // `abcd` and `efgh` use up the 8 bytes; `ijk` finds none left. The second `abcd` is
        // another finding of a value that is being looked for.
        let at = occurrences(raw, &["abcd", "efgh", "abcd", "ijk"], 8);
        assert_eq!(at, [Some(0), Some(5), Some(10), None]);
        // A value longer than the whole budget is never looked for.
        assert_eq!(occurrences(raw, &["abcd efgh abcd"], 8), [None]);
        assert_eq!(occurrences(raw, &["abcd efgh abcd"], 14), [Some(0)]);
    }

    #[test]
    fn a_layout_gives_each_finding_the_place_of_its_span() {
        let text = "one\ntwo mail a@x.nl";
        let spans = vec![vec![span(4, 7), span(13, 19)]];
        let mut made = vec![found("two"), found("a@x.nl")];
        Layout::Lines.locate(&[text], &spans, &mut made);
        assert_eq!(made[0].location, line(2, 1));
        assert_eq!(made[1].location, line(2, 10));

        // Each text has a cursor of its own.
        let texts = ["ab", "cd\nef"];
        let spans = vec![vec![span(1, 2)], vec![span(3, 5)]];
        let mut made = vec![found("b"), found("ef")];
        Layout::Lines.locate(&texts, &spans, &mut made);
        assert_eq!(made[0].location, line(1, 2));
        assert_eq!(made[1].location, line(2, 1));

        let mut made = vec![found("b")];
        Layout::Nowhere.locate(&texts, &spans[..1], &mut made);
        assert_eq!(made[0].location, None);
    }

    #[test]
    fn a_page_is_the_number_of_pages_that_have_begun() {
        // Three pages: of 5 bytes, of none and of 3, with the 3 bytes of a page break between.
        let starts = [0, 8, 11];
        let spans = vec![vec![
            span(0, 1),
            span(4, 5),
            span(8, 9),
            span(11, 12),
            span(13, 14),
        ]];
        let mut made: Vec<Finding> = (0..5).map(|_| found("x")).collect();
        Layout::Pages(&starts).locate(&[""], &spans, &mut made);
        let pages: Vec<Option<Location>> = made.into_iter().map(|one| one.location).collect();
        assert_eq!(
            pages,
            [
                Some(Location::Page(1)),
                Some(Location::Page(1)),
                Some(Location::Page(2)),
                Some(Location::Page(3)),
                Some(Location::Page(3))
            ]
        );
    }

    #[test]
    fn a_message_finds_its_values_in_the_raw_file() {
        let raw = "From: <a@x.nl>\r\n\r\nmail a@x.nl or 06-12345678\r\n";
        let spans = vec![vec![span(0, 1), span(0, 1), span(0, 1), span(0, 1)]];
        let mut made = vec![
            found("a@x.nl"),
            found("a@x.nl"),
            found("06-12345678"),
            found("+31 6 12345678"),
        ];
        Layout::Raw(raw).locate(&[""], &spans, &mut made);
        // The first finding of the address is the first occurrence and the second the second;
        // a value that is not in the file as such has no place.
        assert_eq!(made[0].location, line(1, 8));
        assert_eq!(made[1].location, line(3, 6));
        assert_eq!(made[2].location, line(3, 16));
        assert_eq!(made[3].location, None);
    }

    #[test]
    fn a_format_that_answers_for_itself_is_asked_once_about_the_texts_with_values() {
        let asked = std::cell::RefCell::new(Vec::new());
        let locate = |wanted: &[usize]| -> Vec<Option<Location>> {
            asked.borrow_mut().push(wanted.to_vec());
            wanted
                .iter()
                .map(|&text| line(u32::try_from(text).unwrap_or(0) + 10, 1))
                .collect()
        };
        let spans = vec![
            vec![span(0, 1)],
            vec![],
            vec![span(0, 1), span(2, 3)],
            vec![],
        ];
        let mut made = vec![found("a"), found("b"), found("c")];
        Layout::Texts(&locate).locate(&["", "", "", ""], &spans, &mut made);
        assert_eq!(asked.into_inner(), [vec![0, 2]]);
        assert_eq!(made[0].location, line(10, 1));
        assert_eq!(made[1].location, line(12, 1));
        assert_eq!(made[2].location, line(12, 1));

        // A format that has no answer for a text leaves its findings without a place.
        let none = |wanted: &[usize]| -> Vec<Option<Location>> { vec![None; wanted.len()] };
        let mut made = vec![found("a"), found("b"), found("c")];
        Layout::Texts(&none).locate(&["", "", "", ""], &spans, &mut made);
        assert!(made.iter().all(|one| one.location.is_none()));
    }
}
