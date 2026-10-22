//! Office Open XML packages (`.docx`, `.xlsx`, `.pptx`, …).
//!
//! Every `.xml` part is scanned for text (document bodies, shared strings,
//! slides, comments, headers, `docProps/core.xml`, …). Relationship parts
//! (`.rels`) are scanned for `Target` values, where `mailto:` links live.
//! Entries of an `embeddings` folder (`word/embeddings`, `ppt/embeddings`, `xl/embeddings`)
//! that are packages themselves, like the workbook behind a chart, are read as packages of
//! their own; pictures and other binary objects are not read.
//!
//! A scan that is asked for findings also says which cell of a workbook each text is in
//! ([`places`]).

use std::{collections::HashMap, ops::ControlFlow};

use quick_xml::events::Event;

use super::{
    Location,
    package::Archive,
    sheets::{Cell, Docs, attribute, holding, location, reference},
    xmltext::{Attrs, XmlDoc},
};

/// True when the package has a `[Content_Types].xml` part.
pub(super) fn matches(archive: &Archive<'_>) -> bool {
    archive.index_for_name("[Content_Types].xml").is_some()
}

/// Which parts hold text, by entry name.
pub(super) fn scope(name: &str) -> Option<Attrs> {
    let extension = name.rsplit('.').next()?;
    if extension.eq_ignore_ascii_case("xml") {
        Some(Attrs::None)
    } else if extension.eq_ignore_ascii_case("rels") {
        Some(Attrs::Target)
    } else {
        None
    }
}

/// True when the entry lies in a folder named `embeddings`, at any depth.
pub(super) fn in_embeddings(name: &str) -> bool {
    let mut folders = name.split('/');
    // The last component is the entry itself, not a folder.
    folders.next_back();
    folders.any(|folder| folder.eq_ignore_ascii_case("embeddings"))
}

/// The workbook part, and the relationships that name the parts of its sheets.
const WORKBOOK: &str = "xl/workbook.xml";
const WORKBOOK_RELATIONSHIPS: &str = "xl/_rels/workbook.xml.rels";
/// The folder those relationships' targets are relative to.
const WORKBOOK_FOLDER: &str = "xl/";
/// The part of the shared strings, when the relationships name no other.
const SHARED_STRINGS: &str = "xl/sharedStrings.xml";
/// How the type of the relationship of the shared strings ends.
const SHARED_STRINGS_TYPE: &str = "/sharedStrings";

/// The cell of each of the texts `wanted` (their numbers among the texts of the package, see
/// [`Docs`]), for the findings of a workbook. A text of a worksheet is in the cell it is read
/// from, whether an inline string or the plain value of the cell. A shared string is in the first
/// cell that shows it, going through the sheets in the order of the workbook and through the
/// cells in the order of the sheet. Every other text (headers and footers, comments, a shared
/// string no cell shows) has no cell, nor has anything in a package whose workbook cannot be
/// read.
pub(super) fn places(docs: &Docs<'_>, wanted: &[usize]) -> Vec<Option<Location>> {
    let mut answers = vec![None; wanted.len()];
    let Some(book) = Workbook::read(docs) else {
        return answers;
    };
    let mut asked = docs.asked(wanted);

    // The shared strings that are asked about, by number, and the answers that wait for the
    // first cell that shows them.
    let mut waiting: HashMap<usize, Vec<usize>> = HashMap::new();
    if let Some(index) = book.shared
        && let Some(asks) = asked.remove(&index)
        && let Some(doc) = docs.doc(index)
    {
        let starts = string_starts(doc);
        for ask in asks {
            let before = starts.partition_point(|&start| start <= ask.offset);
            if let Some(number) = before.checked_sub(1) {
                waiting.entry(number).or_default().push(ask.slot);
            }
        }
    }

    for (name, index) in &book.sheets {
        let own = asked.remove(index);
        let Some(doc) = docs.doc(*index) else {
            continue;
        };
        if own.is_none() && waiting.is_empty() {
            continue;
        }
        // The cells are kept for the texts of the sheet itself; for a shared string alone the
        // walk ends at the cell that is the last one waited for.
        let keep = own.is_some();
        let mut cells = Vec::new();
        scan_sheet(doc, |cell, shared| {
            if let Some(number) = shared
                && let Some(slots) = waiting.remove(&number)
            {
                for slot in slots {
                    answers[slot] = Some(location(name, cell));
                }
            }
            if keep {
                cells.push(*cell);
            }
            if keep || !waiting.is_empty() {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(())
            }
        });
        for ask in own.unwrap_or_default() {
            answers[ask.slot] = holding(&cells, ask.offset).map(|cell| location(name, cell));
        }
    }
    answers
}

/// The sheets of a workbook, in the order it lists them, and where its shared strings are.
struct Workbook {
    /// The name of each sheet, and the number of the part it is in.
    sheets: Vec<(Box<str>, usize)>,
    /// The number of the part of the shared strings.
    shared: Option<usize>,
}

impl Workbook {
    /// The workbook of the package: its sheets are the `<sheet>` elements of `xl/workbook.xml`,
    /// and the relationships of that part say which part each one is. `None` when the package
    /// has neither.
    fn read(docs: &Docs<'_>) -> Option<Self> {
        let workbook = docs.doc(docs.find(WORKBOOK)?)?;
        let relationships = docs.doc(docs.find(WORKBOOK_RELATIONSHIPS)?)?;

        // Each sheet: its name, and the id of the relationship that names its part.
        let mut listed: Vec<(Box<str>, Box<str>)> = Vec::new();
        workbook.walk(|event, _| {
            if let Event::Start(tag) | Event::Empty(tag) = event
                && tag.local_name().into_inner() == "sheet"
                && let (Some(name), Some(id)) = (attribute(tag, "name"), attribute(tag, "id"))
            {
                listed.push((Box::from(&*name), Box::from(&*id)));
            }
            ControlFlow::Continue(())
        });

        // Each relationship that names a part of the package: the part, by id.
        let mut targets: HashMap<Box<str>, usize> = HashMap::new();
        let mut shared = None;
        relationships.walk(|event, _| {
            if let Event::Start(tag) | Event::Empty(tag) = event
                && tag.local_name().into_inner() == "Relationship"
                && let (Some(id), Some(target)) = (attribute(tag, "Id"), attribute(tag, "Target"))
                && let Some(part) = docs.find(&resolve(&target))
            {
                if attribute(tag, "Type").is_some_and(|kind| kind.ends_with(SHARED_STRINGS_TYPE)) {
                    shared = Some(part);
                }
                targets.insert(Box::from(&*id), part);
            }
            ControlFlow::Continue(())
        });

        let sheets = listed
            .into_iter()
            .filter_map(|(name, id)| Some((name, *targets.get(&id)?)))
            .collect();
        Some(Self {
            sheets,
            shared: shared.or_else(|| docs.find(SHARED_STRINGS)),
        })
    }
}

/// The name of the entry that a relationship of the workbook points to with `target`: relative
/// to the folder of the workbook, or from the root of the package when it starts with `/`.
fn resolve(target: &str) -> String {
    let full = target
        .strip_prefix('/')
        .map_or_else(|| format!("{WORKBOOK_FOLDER}{target}"), str::to_owned);
    let mut kept: Vec<&str> = Vec::new();
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                kept.pop();
            }
            other => kept.push(other),
        }
    }
    kept.join("/")
}

/// A cell of a worksheet whose end tag has not been read yet.
struct Open {
    start: usize,
    row: u32,
    col: u32,
    /// Whether its type is `s`: its value is the number of a shared string.
    shared: bool,
    /// That number, once its value is read.
    number: Option<usize>,
    /// Whether the walk is inside its value element.
    in_value: bool,
}

/// Calls `each` with every cell of the worksheet `doc` that holds anything, as its end tag is
/// read, and with the number of the shared string it shows (a cell of type `s`). `each` ends the
/// walk by breaking.
///
/// A cell is at the address in its `r` attribute. Without one it follows the cell before it in
/// its row, and a row without one follows the row before it.
fn scan_sheet(doc: &XmlDoc, mut each: impl FnMut(&Cell, Option<usize>) -> ControlFlow<()>) {
    let (mut row, mut col) = (0_u32, 0_u32);
    let mut open: Option<Open> = None;
    doc.walk(|event, range| {
        match event {
            Event::Start(tag) | Event::Empty(tag) => match tag.local_name().into_inner() {
                "row" => {
                    row = attribute(tag, "r")
                        .and_then(|number| number.parse().ok())
                        .unwrap_or_else(|| row.saturating_add(1));
                    col = 0;
                }
                "c" => {
                    (row, col) = attribute(tag, "r")
                        .and_then(|address| reference(&address))
                        .unwrap_or((row, col.saturating_add(1)));
                    if matches!(event, Event::Start(_)) {
                        open = Some(Open {
                            start: range.start,
                            row,
                            col,
                            shared: attribute(tag, "t").is_some_and(|kind| kind == "s"),
                            number: None,
                            in_value: false,
                        });
                    }
                }
                "v" if matches!(event, Event::Start(_)) => {
                    if let Some(cell) = &mut open {
                        cell.in_value = true;
                    }
                }
                _ => {}
            },
            Event::Text(text) => {
                if let Some(cell) = &mut open
                    && cell.in_value
                    && cell.shared
                {
                    cell.number = text.trim().parse().ok();
                }
            }
            Event::End(tag) => match tag.local_name().into_inner() {
                "v" => {
                    if let Some(cell) = &mut open {
                        cell.in_value = false;
                    }
                }
                "c" => {
                    if let Some(done) = open.take() {
                        let cell = Cell {
                            start: done.start,
                            end: range.end,
                            table: 0,
                            row: done.row,
                            col: done.col,
                        };
                        return each(&cell, done.number);
                    }
                }
                _ => {}
            },
            _ => {}
        }
        ControlFlow::Continue(())
    });
}

/// Where each shared string (`<si>`) starts in the source of the part `doc`, in the order of the
/// strings: the position of an offset in this list is the number of the string it is in.
fn string_starts(doc: &XmlDoc) -> Vec<usize> {
    let mut starts = Vec::new();
    doc.walk(|event, range| {
        if let Event::Start(tag) | Event::Empty(tag) = event
            && tag.local_name().into_inner() == "si"
        {
            starts.push(range.start);
        }
        ControlFlow::Continue(())
    });
    starts
}

#[cfg(test)]
mod tests {
    use super::super::xmltext::segments;
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    /// A cell as `(row, column, shared string)`.
    type Seen = (u32, u32, Option<usize>);

    /// Every cell of the worksheet `xml` that holds anything.
    fn cells_of(xml: &str) -> std::result::Result<Vec<Seen>, Box<dyn std::error::Error>> {
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let mut cells = Vec::new();
        scan_sheet(&doc, |cell, shared| {
            cells.push((cell.row, cell.col, shared));
            ControlFlow::Continue(())
        });
        Ok(cells)
    }

    #[test]
    fn scope_picks_xml_and_relationship_parts() {
        assert_eq!(scope("word/document.xml"), Some(Attrs::None));
        assert_eq!(scope("docProps/CORE.XML"), Some(Attrs::None));
        assert_eq!(scope("_rels/.rels"), Some(Attrs::Target));
        assert_eq!(scope("word/_rels/document.xml.rels"), Some(Attrs::Target));
        assert_eq!(scope("word/media/image1.png"), None);
        assert_eq!(scope("word/"), None);
        assert_eq!(scope("mimetype"), None);
    }

    #[test]
    fn embeddings_are_the_entries_in_an_embeddings_folder() {
        assert!(in_embeddings("word/embeddings/Microsoft_Excel_Sheet1.xlsx"));
        assert!(in_embeddings("ppt/Embeddings/a.bin"));
        assert!(in_embeddings("embeddings/a.docx"));
        assert!(in_embeddings("xl/embeddings/nested/a.xlsx"));
        assert!(!in_embeddings("word/embeddings"));
        assert!(!in_embeddings("embeddings"));
        assert!(!in_embeddings("word/media/embeddings.png"));
        assert!(!in_embeddings("word/my_embeddings/a.xlsx"));
    }

    #[test]
    fn a_relationship_target_is_a_name_in_the_package() {
        assert_eq!(resolve("worksheets/sheet1.xml"), "xl/worksheets/sheet1.xml");
        assert_eq!(
            resolve("/xl/worksheets/sheet2.xml"),
            "xl/worksheets/sheet2.xml"
        );
        assert_eq!(resolve("../customXml/item1.xml"), "customXml/item1.xml");
        assert_eq!(resolve("./sharedStrings.xml"), "xl/sharedStrings.xml");
        assert_eq!(resolve("a//b.xml"), "xl/a/b.xml");
    }

    #[test]
    fn cells_are_read_with_their_addresses_and_the_shared_string_they_show() -> TestResult {
        let xml = concat!(
            "<worksheet><sheetData>",
            r#"<row r="2"><c r="B2" t="s"><v>5</v></c><c r="C2" s="1"/>"#,
            r#"<c r="D2" t="inlineStr"><is><t>x</t></is></c></row>"#,
            r#"<row><c t="s"><v> 7 </v></c><c><v>1</v></c></row>"#,
            r#"<row r="9"><c r="AA9" t="str"><f>A1</f><v>abc</v></c></row>"#,
            "</sheetData></worksheet>",
        );
        // The empty cell is left out; a cell or a row without an address follows the one before.
        assert_eq!(
            cells_of(xml)?,
            [
                (2, 2, Some(5)),
                (2, 4, None),
                (3, 1, Some(7)),
                (3, 2, None),
                (9, 27, None),
            ]
        );
        Ok(())
    }

    #[test]
    fn a_cell_spans_its_element_and_holds_the_text_inside_it() -> TestResult {
        let xml = concat!(
            r#"<worksheet><sheetData><row r="1"><c r="A1"><v>1</v></c> "#,
            r#"<c r="B1" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>"#,
        );
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let mut cells = Vec::new();
        scan_sheet(&doc, |cell, _| {
            cells.push(*cell);
            ControlFlow::Continue(())
        });
        let elements: Vec<&str> = cells
            .iter()
            .map(|cell| &xml[cell.start..cell.end])
            .collect();
        assert_eq!(
            elements,
            [
                r#"<c r="A1"><v>1</v></c>"#,
                r#"<c r="B1" t="inlineStr"><is><t>x</t></is></c>"#
            ]
        );
        assert_eq!(doc.len(), 2);
        for (segment, address) in [(0, "A1"), (1, "B1")] {
            let at = doc.offset(segment).ok_or("no such segment")?;
            let held = holding(&cells, at).map(Cell::address);
            assert_eq!(held.as_deref(), Some(address));
        }
        Ok(())
    }

    #[test]
    fn the_walk_over_a_sheet_ends_when_told() -> TestResult {
        let xml = r#"<sheetData><row r="1"><c r="A1"><v>1</v></c><c r="B1"><v>2</v></c></row></sheetData>"#;
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let mut seen = 0;
        scan_sheet(&doc, |_, _| {
            seen += 1;
            ControlFlow::Break(())
        });
        assert_eq!(seen, 1);
        Ok(())
    }

    #[test]
    fn every_shared_string_element_starts_a_string_even_an_empty_one() -> TestResult {
        let xml = "<sst><si><t>a</t></si><si/><si><r><t>b</t></r></si></sst>";
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let starts = string_starts(&doc);
        let expected: Vec<usize> = xml.match_indices("<si").map(|(at, _)| at).collect();
        assert_eq!(expected.len(), 3);
        assert_eq!(starts, expected);
        // Two segments have text: the first and the third string.
        let numbers: Vec<usize> = (0..doc.len())
            .filter_map(|segment| {
                let at = doc.offset(segment)?;
                starts.partition_point(|&start| start <= at).checked_sub(1)
            })
            .collect();
        assert_eq!(numbers, [0, 2]);
        Ok(())
    }
}
