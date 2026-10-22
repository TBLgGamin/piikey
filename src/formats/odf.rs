//! `OpenDocument` packages (`.odt`, `.ods`, `.odp`, …).
//!
//! Every `.xml` part is scanned for text (`content.xml`, `styles.xml` headers
//! and footers, `meta.xml`, …) and for `href` attribute values, where
//! `mailto:` links live.
//!
//! A scan that is asked for findings also says which cell of a sheet each text is in
//! ([`places`]).

use std::{io::Read, ops::ControlFlow};

use quick_xml::events::{BytesStart, Event};

use super::{
    Location,
    package::Archive,
    sheets::{Cell, Docs, attribute, holding, location},
    xmltext::{Attrs, XmlDoc},
};
use crate::Result;

const MIMETYPE: &str = "mimetype";
const MIME_PREFIX: &[u8] = b"application/vnd.oasis.opendocument.";

/// True when the first entry is a `mimetype` part naming an `OpenDocument` type.
pub(super) fn matches(archive: &mut Archive<'_>) -> Result<bool> {
    let first_is_mimetype = archive
        .name_for_index(0)
        .transpose()?
        .is_some_and(|name| name == MIMETYPE);
    if !first_is_mimetype {
        return Ok(false);
    }
    let mut head = Vec::with_capacity(MIME_PREFIX.len());
    archive
        .by_index(0)?
        .take(MIME_PREFIX.len() as u64)
        .read_to_end(&mut head)?;
    Ok(head == MIME_PREFIX)
}

/// Which parts hold text, by entry name.
pub(super) fn scope(name: &str) -> Option<Attrs> {
    let extension = name.rsplit('.').next()?;
    extension.eq_ignore_ascii_case("xml").then_some(Attrs::Href)
}

/// The part that holds the content of a document.
const CONTENT: &str = "content.xml";

/// The cell of each of the texts `wanted` (their numbers among the texts of the package, see
/// [`Docs`]), for the findings of a spreadsheet. A text of `content.xml` is in the cell whose
/// element it is in, found by counting the rows and the columns that the tables list, repeats
/// included: a cell that stands for several is at the first of them. A table in a text document
/// or in the cell of another table is no sheet. Every other text (the meta data, the headers and
/// footers of `styles.xml`, a note outside the cells) has no cell.
pub(super) fn places(docs: &Docs<'_>, wanted: &[usize]) -> Vec<Option<Location>> {
    let mut answers = vec![None; wanted.len()];
    let Some(index) = docs.find(CONTENT) else {
        return answers;
    };
    let Some(asks) = docs.asked(wanted).remove(&index) else {
        return answers;
    };
    let Some(doc) = docs.doc(index) else {
        return answers;
    };
    let Tables { names, cells } = tables(doc);
    for ask in asks {
        answers[ask.slot] = holding(&cells, ask.offset).and_then(|cell| {
            let name = names.get(usize::try_from(cell.table).ok()?)?;
            Some(location(name, cell))
        });
    }
    answers
}

/// The sheets of a spreadsheet and the cells in them that hold something.
struct Tables {
    /// The name of each sheet, in the order of the document.
    names: Vec<Box<str>>,
    /// The cells in the order of the source.
    cells: Vec<Cell>,
}

/// A cell whose end tag has not been read yet.
struct Open {
    start: usize,
    table: u32,
    row: u32,
    col: u32,
}

/// The sheets of the document `doc` and its cells that hold something.
///
/// The sheets are the `table:table` elements of `office:spreadsheet`, and the cells their
/// `table:table-cell` and `table:covered-table-cell` elements. A row or a cell may stand for
/// several (`table:number-rows-repeated`, `table:number-columns-repeated`): they count for all
/// of them, and a cell with content is at the first. What lies inside a cell, a table of its own
/// included, belongs to that cell.
fn tables(doc: &XmlDoc) -> Tables {
    let mut found = Tables {
        names: Vec::new(),
        cells: Vec::new(),
    };
    // Inside the spreadsheet, and how many tables are open.
    let mut in_sheets = false;
    let mut open_tables = 0_u32;
    // The rows and columns used up by what has been read, repeats included, and the row of the
    // cells being read.
    let (mut rows, mut cols, mut row) = (0_u32, 0_u32, 0_u32);
    let mut cell: Option<Open> = None;
    doc.walk(|event, range| {
        match event {
            Event::Start(tag) => match tag.local_name().into_inner() {
                "spreadsheet" => in_sheets = true,
                "table" if in_sheets => {
                    open_tables += 1;
                    if open_tables == 1 {
                        let name: Box<str> = attribute(tag, "name")
                            .map_or_else(Box::default, |name| Box::from(&*name));
                        found.names.push(name);
                        rows = 0;
                    }
                }
                "table-row" if open_tables == 1 => {
                    row = rows.saturating_add(1);
                    rows = rows.saturating_add(repeats(tag, "number-rows-repeated"));
                    cols = 0;
                }
                "table-cell" | "covered-table-cell" if open_tables == 1 => {
                    cell = Some(Open {
                        start: range.start,
                        table: u32::try_from(found.names.len().saturating_sub(1))
                            .unwrap_or(u32::MAX),
                        row,
                        col: cols.saturating_add(1),
                    });
                    cols = cols.saturating_add(repeats(tag, "number-columns-repeated"));
                }
                _ => {}
            },
            // Nothing in them: they only use up rows and columns.
            Event::Empty(tag) => match tag.local_name().into_inner() {
                "table-row" if open_tables == 1 => {
                    rows = rows.saturating_add(repeats(tag, "number-rows-repeated"));
                }
                "table-cell" | "covered-table-cell" if open_tables == 1 => {
                    cols = cols.saturating_add(repeats(tag, "number-columns-repeated"));
                }
                _ => {}
            },
            Event::End(tag) => match tag.local_name().into_inner() {
                "spreadsheet" => in_sheets = false,
                "table" if in_sheets => open_tables = open_tables.saturating_sub(1),
                "table-cell" | "covered-table-cell" if open_tables == 1 => {
                    if let Some(done) = cell.take() {
                        found.cells.push(Cell {
                            start: done.start,
                            end: range.end,
                            table: done.table,
                            row: done.row,
                            col: done.col,
                        });
                    }
                }
                _ => {}
            },
            _ => {}
        }
        ControlFlow::Continue(())
    });
    found
}

/// How many rows or columns `tag` stands for: its attribute `local`, or one without it.
fn repeats(tag: &BytesStart<'_>, local: &str) -> u32 {
    attribute(tag, local)
        .and_then(|times| times.parse::<u32>().ok())
        .map_or(1, |times| times.max(1))
}

#[cfg(test)]
mod tests {
    use super::super::xmltext::segments;
    use super::*;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// The cells of the document `xml` that hold something, as `Sheet!Cell`.
    fn addresses(xml: &str) -> Fallible<Vec<String>> {
        let doc = segments(xml.as_bytes().to_vec(), Attrs::Href)?;
        let Tables { names, cells } = tables(&doc);
        let mut out = Vec::new();
        for cell in &cells {
            let name = names.get(usize::try_from(cell.table)?);
            out.push(format!(
                "{}!{}",
                name.ok_or("no such sheet")?,
                cell.address()
            ));
        }
        Ok(out)
    }

    /// Each text of the document `xml` with the cell it is in, as `text @ Sheet!Cell`.
    fn placed(xml: &str) -> Fallible<Vec<String>> {
        let doc = segments(xml.as_bytes().to_vec(), Attrs::Href)?;
        let Tables { names, cells } = tables(&doc);
        let mut out = Vec::new();
        for (segment, text) in doc.texts().enumerate() {
            let at = doc.offset(segment).ok_or("no such text")?;
            let place = match holding(&cells, at) {
                Some(cell) => {
                    let name = names.get(usize::try_from(cell.table)?);
                    format!("{}!{}", name.ok_or("no such sheet")?, cell.address())
                }
                None => "nowhere".to_owned(),
            };
            out.push(format!("{text} @ {place}"));
        }
        Ok(out)
    }

    const SPREADSHEET: &str = concat!(
        "<office:document-content><office:body><office:spreadsheet>",
        r#"<table:table table:name="Klanten">"#,
        r#"<table:table-column table:number-columns-repeated="3"/>"#,
        r#"<table:table-row table:number-rows-repeated="2"><table:table-cell/></table:table-row>"#,
        "<table:table-row>",
        r#"<table:table-cell table:number-columns-repeated="2"/>"#,
        "<table:table-cell><text:p>one</text:p></table:table-cell>",
        "<table:covered-table-cell/>",
        r#"<table:table-cell table:number-columns-repeated="3"><text:p>two</text:p></table:table-cell>"#,
        "</table:table-row>",
        r#"<table:table-row table:number-rows-repeated="3">"#,
        "<table:table-cell><text:p>three</text:p></table:table-cell></table:table-row>",
        "</table:table>",
        r#"<table:table table:name="Q&amp;A">"#,
        "<table:table-row><table:table-cell><text:p>four</text:p></table:table-cell></table:table-row>",
        "</table:table>",
        "</office:spreadsheet></office:body></office:document-content>",
    );

    #[test]
    fn scope_picks_xml_parts() {
        assert_eq!(scope("content.xml"), Some(Attrs::Href));
        assert_eq!(scope("META-INF/manifest.xml"), Some(Attrs::Href));
        assert_eq!(scope("Pictures/image.png"), None);
        assert_eq!(scope("mimetype"), None);
        assert_eq!(scope("Configurations2/"), None);
    }

    #[test]
    fn rows_and_columns_are_counted_over_their_repeats() -> Fallible<()> {
        // Two empty rows, then a row with two empty cells, the one with `one`, a covered cell
        // and one that stands for three; then three rows alike, on the sheet `Klanten`.
        assert_eq!(
            addresses(SPREADSHEET)?,
            ["Klanten!C3", "Klanten!E3", "Klanten!A4", "Q&A!A1"]
        );
        Ok(())
    }

    #[test]
    fn a_text_is_in_the_cell_whose_element_it_is_in() -> Fallible<()> {
        assert_eq!(
            placed(SPREADSHEET)?,
            [
                "one @ Klanten!C3",
                "two @ Klanten!E3",
                "three @ Klanten!A4",
                "four @ Q&A!A1"
            ]
        );
        Ok(())
    }

    #[test]
    fn text_outside_the_cells_is_in_none() -> Fallible<()> {
        let xml = concat!(
            "<office:spreadsheet>",
            r#"<table:table table:name="S"><table:shapes><text:p>note</text:p></table:shapes>"#,
            "<table:table-row><table:table-cell><text:p>in</text:p></table:table-cell></table:table-row>",
            "</table:table></office:spreadsheet>",
            "<text:p>after</text:p>",
        );
        assert_eq!(
            placed(xml)?,
            ["note @ nowhere", "in @ S!A1", "after @ nowhere"]
        );
        Ok(())
    }

    #[test]
    fn only_the_tables_of_a_spreadsheet_are_sheets_and_a_table_in_a_cell_is_part_of_it()
    -> Fallible<()> {
        // The table of a text document is no sheet.
        let text = concat!(
            r#"<office:text><table:table table:name="T"><table:table-row>"#,
            "<table:table-cell><text:p>x</text:p></table:table-cell>",
            "</table:table-row></table:table></office:text>",
        );
        assert!(addresses(text)?.is_empty());
        assert_eq!(placed(text)?, ["x @ nowhere"]);

        // Nor is a table inside a cell: what is in it is in the cell around it.
        let nested = concat!(
            "<office:spreadsheet>",
            r#"<table:table table:name="S"><table:table-row>"#,
            "<table:table-cell><text:p>outer</text:p>",
            r#"<table:table table:name="inner"><table:table-row>"#,
            "<table:table-cell><text:p>in</text:p></table:table-cell>",
            "</table:table-row></table:table>",
            "</table:table-cell>",
            "<table:table-cell><text:p>next</text:p></table:table-cell>",
            "</table:table-row></table:table></office:spreadsheet>",
        );
        assert_eq!(addresses(nested)?, ["S!A1", "S!B1"]);
        assert_eq!(
            placed(nested)?,
            ["outer @ S!A1", "in @ S!A1", "next @ S!B1"]
        );
        Ok(())
    }

    #[test]
    fn a_link_in_a_cell_is_in_that_cell() -> Fallible<()> {
        let xml = concat!(
            r#"<office:spreadsheet><table:table table:name="S"><table:table-row>"#,
            "<table:table-cell/>",
            r#"<table:table-cell><text:p><text:a xlink:href="mailto:a@x.nl">mail</text:a></text:p></table:table-cell>"#,
            "</table:table-row></table:table></office:spreadsheet>",
        );
        // The link target is a segment of its own, flushed before the paragraph it is in.
        assert_eq!(placed(xml)?, ["mailto:a@x.nl @ S!B1", "mail @ S!B1"]);
        Ok(())
    }
}
