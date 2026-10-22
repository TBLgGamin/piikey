//! Which cell of which sheet a text of a spreadsheet package came from, for the findings of a
//! scan.
//!
//! A package plans all the segments of its XML parts in one call. The parts of a spreadsheet are
//! walked once more after the engine has run, and only for the texts that hold a value: `ooxml`
//! does it for a workbook (`.xlsx`) and `odf` for a sheet of `OpenDocument` (`.ods`). This module
//! holds what the two share: the parts of the package by name, and the cells.

use std::{borrow::Cow, collections::BTreeMap};

use quick_xml::{XmlVersion, events::BytesStart};

use super::{Location, package::Archive, xmltext::XmlDoc};

/// A cell that holds something, and where its element is in the source of its XML part.
#[derive(Debug, Clone, Copy)]
pub(super) struct Cell {
    /// Where its start tag begins in the source.
    pub(super) start: usize,
    /// Where its end tag ends in the source.
    pub(super) end: usize,
    /// The table of the part that it is in, counted from 0. A worksheet part has one table.
    pub(super) table: u32,
    /// Row and column, both counted from 1.
    pub(super) row: u32,
    pub(super) col: u32,
}

impl Cell {
    /// The address as a person writes it: the letters of the column, then the row (`B7`).
    pub(super) fn address(&self) -> Box<str> {
        format!("{}{}", letters(self.col), self.row).into()
    }
}

/// The place of `cell` of the sheet called `sheet`.
pub(super) fn location(sheet: &str, cell: &Cell) -> Location {
    Location::Cell {
        sheet: sheet.into(),
        cell: cell.address(),
    }
}

/// The letters of column `number`, counted from 1: `A` to `Z`, then `AA`, `AB` and on.
fn letters(mut number: u32) -> String {
    let mut reversed = Vec::new();
    while number > 0 {
        number -= 1;
        reversed.push(char::from(b'A' + u8::try_from(number % 26).unwrap_or(0)));
        number /= 26;
    }
    reversed.iter().rev().collect()
}

/// The row and the column of a reference such as `B7`, both counted from 1.
pub(super) fn reference(text: &str) -> Option<(u32, u32)> {
    let (letters, digits) = text.split_at(text.find(|c: char| c.is_ascii_digit())?);
    if letters.is_empty() || !letters.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    let col = letters.bytes().try_fold(0_u32, |col, byte| {
        let letter = u32::from(byte.to_ascii_uppercase() - b'A' + 1);
        col.checked_mul(26)?.checked_add(letter)
    })?;
    let row = digits.parse().ok().filter(|&row| row > 0)?;
    Some((row, col))
}

/// The cell that holds the source offset `at`. `cells` are in the order of the source, and no
/// cell starts inside another.
pub(super) fn holding(cells: &[Cell], at: usize) -> Option<&Cell> {
    let before = cells.partition_point(|cell| cell.start <= at);
    cells
        .get(before.checked_sub(1)?)
        .filter(|cell| at < cell.end)
}

/// The value of the attribute of `tag` called `local`, whichever prefix it has, with character
/// references and the predefined entities resolved.
pub(super) fn attribute<'t>(tag: &'t BytesStart<'_>, local: &str) -> Option<Cow<'t, str>> {
    tag.attributes()
        .with_checks(false)
        .flatten()
        .find(|attr| attr.key.local_name().into_inner() == local)
        .and_then(|attr| attr.normalized_value(XmlVersion::Implicit1_0).ok())
}

/// One text of the package that is asked about.
#[derive(Debug)]
pub(super) struct Ask {
    /// Where in the source of its part it starts.
    pub(super) offset: usize,
    /// Which of the answers is its own.
    pub(super) slot: usize,
}

/// The XML parts of a package that were read, with the names of their entries, to trace a text
/// of the package to the part and to the place in it that it came from.
#[derive(Debug)]
pub(super) struct Docs<'d> {
    /// The parts, each with its number among the entries of the package.
    parts: &'d [(usize, XmlDoc)],
    /// The entry name of each part.
    names: Vec<Box<str>>,
    /// The number of the first text of each part among the texts of all of them.
    firsts: Vec<usize>,
}

impl<'d> Docs<'d> {
    /// The parts `docs` of `archive`. A part whose name cannot be read has an empty one.
    pub(super) fn new(archive: &Archive<'_>, docs: &'d [(usize, XmlDoc)]) -> Self {
        let names: Vec<Box<str>> = docs
            .iter()
            .map(|(entry, _)| {
                archive
                    .name_for_index(*entry)
                    .and_then(Result::ok)
                    .map_or_else(Box::default, |name| Box::from(&*name))
            })
            .collect();
        let mut next = 0;
        let firsts: Vec<usize> = docs
            .iter()
            .map(|(_, doc)| {
                let first = next;
                next += doc.len();
                first
            })
            .collect();
        Self {
            parts: docs,
            names,
            firsts,
        }
    }

    /// The number of the part whose entry is called `name`, the case of the letters aside.
    pub(super) fn find(&self, name: &str) -> Option<usize> {
        self.names
            .iter()
            .position(|entry| entry.eq_ignore_ascii_case(name))
    }

    /// The part with number `index`.
    pub(super) fn doc(&self, index: usize) -> Option<&'d XmlDoc> {
        self.parts.get(index).map(|(_, doc)| doc)
    }

    /// The texts `wanted`, given by their number among the texts of all the parts, grouped by the
    /// part they are in. The answer to the `i`th of them is slot `i`.
    pub(super) fn asked(&self, wanted: &[usize]) -> BTreeMap<usize, Vec<Ask>> {
        let mut by_doc: BTreeMap<usize, Vec<Ask>> = BTreeMap::new();
        for (slot, &text) in wanted.iter().enumerate() {
            let Some(index) = self
                .firsts
                .partition_point(|&first| first <= text)
                .checked_sub(1)
            else {
                continue;
            };
            let offset = self
                .firsts
                .get(index)
                .and_then(|&first| self.doc(index)?.offset(text.saturating_sub(first)));
            if let Some(offset) = offset {
                by_doc.entry(index).or_default().push(Ask { offset, slot });
            }
        }
        by_doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(start: usize, end: usize) -> Cell {
        Cell {
            start,
            end,
            table: 0,
            row: 1,
            col: 1,
        }
    }

    #[test]
    fn columns_are_lettered_like_a_spreadsheet_does() {
        let lettered: Vec<String> = [1, 2, 26, 27, 28, 52, 53, 702, 703, 16_384]
            .into_iter()
            .map(letters)
            .collect();
        assert_eq!(
            lettered,
            ["A", "B", "Z", "AA", "AB", "AZ", "BA", "ZZ", "AAA", "XFD"]
        );
        assert_eq!(letters(0), "");
    }

    #[test]
    fn an_address_is_the_column_and_the_row() {
        let at = |row, col| Cell {
            row,
            col,
            ..cell(0, 0)
        };
        assert_eq!(&*at(7, 2).address(), "B7");
        assert_eq!(&*at(1, 1).address(), "A1");
        assert_eq!(&*at(1_048_576, 16_384).address(), "XFD1048576");
    }

    #[test]
    fn a_reference_is_read_back_into_its_row_and_column() {
        assert_eq!(reference("B7"), Some((7, 2)));
        assert_eq!(reference("a1"), Some((1, 1)));
        assert_eq!(reference("AA10"), Some((10, 27)));
        assert_eq!(reference("XFD1048576"), Some((1_048_576, 16_384)));
        for odd in ["", "7", "B", "B0", "7B", "B7x", "$B$7", "B-7", "Ü7"] {
            assert_eq!(reference(odd), None, "{odd:?}");
        }
        // Too many letters for a number.
        assert_eq!(reference("AAAAAAAAAAAAAAAA1"), None);
    }

    #[test]
    fn the_cell_that_holds_an_offset_is_the_one_it_is_inside() {
        let cells = [cell(10, 20), cell(30, 31), cell(40, 60)];
        assert!(holding(&cells, 9).is_none(), "before the first");
        assert_eq!(holding(&cells, 10).map(|c| c.end), Some(20));
        assert_eq!(holding(&cells, 19).map(|c| c.end), Some(20));
        assert!(holding(&cells, 20).is_none(), "between two cells");
        assert!(holding(&cells, 29).is_none());
        assert_eq!(holding(&cells, 30).map(|c| c.end), Some(31));
        assert!(holding(&cells, 31).is_none());
        assert_eq!(holding(&cells, 59).map(|c| c.end), Some(60));
        assert!(holding(&cells, 60).is_none(), "after the last");
        assert!(holding(&[], 5).is_none());
    }

    #[test]
    fn an_attribute_is_found_by_its_local_name_and_unescaped() {
        let tag = BytesStart::from_content(r#"sheet name="Q&amp;A" r:id="rId2" sheetId="3""#, 5);
        assert_eq!(attribute(&tag, "name").as_deref(), Some("Q&A"));
        assert_eq!(attribute(&tag, "id").as_deref(), Some("rId2"));
        assert_eq!(attribute(&tag, "sheetId").as_deref(), Some("3"));
        assert_eq!(attribute(&tag, "Id"), None);
        assert_eq!(attribute(&tag, "sheet"), None);
    }
}
