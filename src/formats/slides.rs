//! Which slide of a presentation a text came from, and which shape of it, for the findings of a
//! scan.
//!
//! A slide is where `ppt/presentation.xml` lists it, not where the number in the name of its part
//! says: `slide7.xml` stays `slide7.xml` when the slide is moved, and a slide that was deleted
//! leaves a gap in the numbers. The relationships of the presentation say which part each listed
//! slide is. The speaker notes of a slide are a part of their own, which a relationship of the
//! slide names. Every other part (the layouts and masters the slides are made from, comments,
//! the properties of the document) is on no slide.
//!
//! The shapes of a slide are the elements that lie directly in its shape tree (`p:spTree`), in
//! the order of the file, which is the order they are stacked in: a picture, a table and a group
//! are shapes too, and what a group holds is part of the group.

use std::{
    collections::HashMap,
    ops::{ControlFlow, Range},
};

use quick_xml::events::{BytesStart, Event};

use super::{
    Location,
    ooxml::{folder_of, relationships, rels_of},
    sheets::Docs,
    xmltext::XmlDoc,
};

/// The presentation, and the relationships that name the part of each of its slides.
const PRESENTATION: &str = "ppt/presentation.xml";
const PRESENTATION_RELATIONSHIPS: &str = "ppt/_rels/presentation.xml.rels";
/// How the type of the relationship from a slide to its notes ends.
const NOTES_TYPE: &str = "/notesSlide";
/// What a shape tree holds besides shapes (local names): the properties of the tree itself.
const NOT_SHAPES: [&str; 3] = ["nvGrpSpPr", "grpSpPr", "extLst"];

/// Where each of the texts `wanted` (their numbers among the texts of the package, see [`Docs`])
/// is, for the findings of a presentation: the slide and the shape of it for a text on a slide,
/// the slide for a text in its notes. Every other text has no place.
pub(super) fn places(docs: &Docs<'_>, wanted: &[usize]) -> Vec<Option<Location>> {
    let mut answers = vec![None; wanted.len()];
    let asked = docs.asked(wanted);
    if asked.is_empty() {
        return answers;
    }
    let parts = slide_parts(docs);
    for (index, asks) in asked {
        let Some(&(slide, notes)) = parts.get(&index) else {
            continue;
        };
        if notes {
            for ask in asks {
                answers[ask.slot] = Some(Location::Notes(slide));
            }
        } else if let Some(doc) = docs.doc(index) {
            let shapes = shapes(doc);
            for ask in asks {
                answers[ask.slot] = Some(Location::Slide {
                    slide,
                    shape: shape_at(&shapes, ask.offset),
                });
            }
        }
    }
    answers
}

/// The parts that belong to a slide, by part number: the slide number (counted from 1 in the
/// order of the presentation) and whether the part is the notes of the slide, not the slide.
fn slide_parts(docs: &Docs<'_>) -> HashMap<usize, (u32, bool)> {
    let mut parts = HashMap::new();
    let Some(presentation) = docs.find(PRESENTATION).and_then(|index| docs.doc(index)) else {
        return parts;
    };
    // The id of the relationship that names each slide, in the order the presentation lists them.
    let mut listed: Vec<Box<str>> = Vec::new();
    presentation.walk(|event, _| {
        if let Event::Start(tag) | Event::Empty(tag) = event
            && tag.local_name().into_inner() == "sldId"
            && let Some(id) = relationship_id(tag)
        {
            listed.push(id);
        }
        ControlFlow::Continue(())
    });
    let targets: HashMap<Box<str>, usize> =
        relationships(docs, PRESENTATION_RELATIONSHIPS, folder_of(PRESENTATION))
            .into_iter()
            .filter_map(|relation| Some((relation.id, docs.find(&relation.target)?)))
            .collect();
    for (number, id) in listed.iter().enumerate() {
        let Some(&part) = targets.get(id) else {
            continue;
        };
        let slide = u32::try_from(number + 1).unwrap_or(u32::MAX);
        parts.insert(part, (slide, false));
        let Some(name) = docs.name(part) else {
            continue;
        };
        for relation in relationships(docs, &rels_of(name), folder_of(name)) {
            if relation.kind.ends_with(NOTES_TYPE)
                && let Some(notes) = docs.find(&relation.target)
            {
                parts.insert(notes, (slide, true));
            }
        }
    }
    parts
}

/// The id of the relationship that `tag` names: its attribute `r:id`, the one of its attributes
/// called `id` that has a prefix (`<p:sldId id="256" r:id="rId2"/>` has a plain one as well).
fn relationship_id(tag: &BytesStart<'_>) -> Option<Box<str>> {
    tag.attributes()
        .with_checks(false)
        .flatten()
        .find(|attr| attr.key.local_name().into_inner() == "id" && attr.key.prefix().is_some())
        .and_then(|attr| {
            attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()
                .map(|id| Box::from(&*id))
        })
}

/// The shapes of the slide `doc` as the ranges they take in its source, in the order of the file:
/// each element that lies directly in the shape tree, apart from the properties of the tree.
fn shapes(doc: &XmlDoc) -> Vec<Range<usize>> {
    let mut found = Vec::new();
    // How many elements are open; how many were when the shape tree opened; where the shape that
    // is open starts.
    let mut depth = 0_usize;
    let mut tree: Option<usize> = None;
    let mut open: Option<usize> = None;
    doc.walk(|event, range| {
        match event {
            Event::Start(tag) => {
                depth += 1;
                match tree {
                    None if tag.local_name().into_inner() == "spTree" => tree = Some(depth),
                    Some(at) if depth == at + 1 && is_shape(tag.local_name().into_inner()) => {
                        open = Some(range.start);
                    }
                    _ => {}
                }
            }
            Event::Empty(tag)
                if tree.is_some_and(|at| depth == at)
                    && is_shape(tag.local_name().into_inner()) =>
            {
                found.push(range);
            }
            Event::End(_) => {
                match tree {
                    // The shape tree is closed: nothing after it is on the slide's shapes.
                    Some(at) if depth == at => return ControlFlow::Break(()),
                    Some(at) if depth == at + 1 => {
                        if let Some(start) = open.take() {
                            found.push(start..range.end);
                        }
                    }
                    _ => {}
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        ControlFlow::Continue(())
    });
    found
}

fn is_shape(local: &str) -> bool {
    !NOT_SHAPES.contains(&local)
}

/// The number, counted from 1, of the shape that holds the source offset `at`, if one does.
fn shape_at(shapes: &[Range<usize>], at: usize) -> Option<u32> {
    let before = shapes.partition_point(|shape| shape.start <= at);
    let index = before.checked_sub(1)?;
    shapes
        .get(index)
        .filter(|shape| at < shape.end)
        .and_then(|_| u32::try_from(index + 1).ok())
}

#[cfg(test)]
mod tests {
    use super::super::xmltext::{Attrs, segments};
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    /// A text and the shape it is in.
    type Placed = (String, Option<u32>);

    const SLIDE: &str = concat!(
        r#"<p:sld xmlns:a="a" xmlns:p="p"><p:cSld><p:spTree>"#,
        r#"<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>"#,
        // 1: a text box
        r#"<p:sp><p:txBody><a:p><a:r><a:t>Title</a:t></a:r></a:p></p:txBody></p:sp>"#,
        // 2: a picture, which holds no text
        r#"<p:pic><p:nvPicPr/></p:pic>"#,
        // 3: a group with two shapes in it
        r#"<p:grpSp><p:sp><p:txBody><a:p><a:r><a:t>In</a:t></a:r></a:p></p:txBody></p:sp>"#,
        r#"<p:sp><p:txBody><a:p><a:r><a:t>group</a:t></a:r></a:p></p:txBody></p:sp></p:grpSp>"#,
        // 4: a shape that is an empty element
        r#"<p:cxnSp/>"#,
        // 5: a table
        r#"<p:graphicFrame><a:tbl><a:tr><a:tc><a:txBody><a:p><a:r><a:t>Cell</a:t></a:r></a:p></a:txBody></a:tc></a:tr></a:tbl></p:graphicFrame>"#,
        r#"<p:extLst/>"#,
        r#"</p:spTree></p:cSld><p:extLst><a:p><a:r><a:t>Outside</a:t></a:r></a:p></p:extLst></p:sld>"#,
    );

    /// The shape of each text of `xml`, in the order of the file, as `Some(number)`.
    fn shapes_of_texts(xml: &str) -> std::result::Result<Vec<Placed>, Box<dyn std::error::Error>> {
        let doc = segments(xml.as_bytes().to_vec(), Attrs::None)?;
        let shapes = shapes(&doc);
        let texts: Vec<&str> = doc.texts().collect();
        Ok((0..doc.len())
            .map(|segment| {
                let at = doc.offset(segment).unwrap_or(0);
                (texts[segment].to_owned(), shape_at(&shapes, at))
            })
            .collect())
    }

    #[test]
    fn the_shapes_of_a_slide_are_what_lies_directly_in_its_shape_tree() -> TestResult {
        let doc = segments(SLIDE.as_bytes().to_vec(), Attrs::None)?;
        let elements: Vec<&str> = shapes(&doc)
            .into_iter()
            .map(|range| &SLIDE[range])
            .map(|element| element.split_once('>').map_or(element, |(open, _)| open))
            .collect();
        // The tree's own properties are no shapes; a group is one, with what is in it.
        assert_eq!(
            elements,
            [
                "<p:sp",
                "<p:pic",
                "<p:grpSp",
                "<p:cxnSp/",
                "<p:graphicFrame"
            ]
        );
        Ok(())
    }

    #[test]
    fn a_text_is_in_the_shape_it_stands_in_and_a_group_holds_what_it_contains() -> TestResult {
        assert_eq!(
            shapes_of_texts(SLIDE)?,
            [
                ("Title".to_owned(), Some(1)),
                ("In".to_owned(), Some(3)),
                ("group".to_owned(), Some(3)),
                ("Cell".to_owned(), Some(5)),
                // After the shape tree: on the slide, in no shape.
                ("Outside".to_owned(), None),
            ]
        );
        Ok(())
    }

    #[test]
    fn a_slide_without_a_shape_tree_has_no_shapes() -> TestResult {
        assert_eq!(
            shapes_of_texts("<p:sld><a:p><a:r><a:t>x</a:t></a:r></a:p></p:sld>")?,
            [("x".to_owned(), None)]
        );
        Ok(())
    }

    #[test]
    fn a_slide_is_named_by_the_attribute_with_a_prefix_not_by_its_number() -> TestResult {
        let doc = segments(
            br#"<p:sldIdLst><p:sldId id="256" r:id="rId7"/><p:sldId r:id="rId9" id="257"/></p:sldIdLst>"#
                .to_vec(),
            Attrs::None,
        )?;
        let mut ids: Vec<Box<str>> = Vec::new();
        doc.walk(|event, _| {
            if let Event::Empty(tag) = event
                && let Some(id) = relationship_id(tag)
            {
                ids.push(id);
            }
            ControlFlow::Continue(())
        });
        assert_eq!(ids, ["rId7".into(), "rId9".into()]);
        Ok(())
    }
}
