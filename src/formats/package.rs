//! Zip packages (OOXML, ODF): the XML parts are rewritten, every other entry
//! is copied through.
//!
//! The XML parts are read and scanned in parallel, one engine call
//! covers every segment of the package, and the changed parts are rebuilt and
//! compressed in parallel. The output keeps the original entry order; parts
//! without changes are copied compressed, byte for byte.

use std::{
    collections::HashMap,
    io::{Cursor, Read, Write},
};

use rayon::prelude::*;
use zip::{
    ZipArchive, ZipWriter,
    write::{PreparedZipFile, ZipFileBuilder},
};

use super::{
    Pass,
    xmltext::{Attrs, XmlDoc, segments},
};
use crate::{Error, Result, engine::Replacement};

/// A package read from memory.
pub(super) type Archive<'a> = ZipArchive<Cursor<&'a [u8]>>;

/// Decides per entry name whether it is an XML part, and which attribute
/// values of it hold text.
pub(super) type Scope = fn(&str) -> Option<Attrs>;

/// Largest buffer reserved up front for an entry, whatever size it declares.
const MAX_RESERVE: u64 = 1 << 26;

/// Opens `bytes` as a zip archive.
pub(super) fn open(bytes: &[u8]) -> Result<Archive<'_>> {
    Ok(ZipArchive::new(Cursor::new(bytes))?)
}

/// Anonymizes or deanonymizes every XML part of `archive`, returning the new
/// package (the original bytes when nothing changes). A scan reads the same
/// segments and returns nothing.
pub(super) fn rewrite(pass: &Pass<'_>, mut archive: Archive<'_>, scope: Scope) -> Result<Vec<u8>> {
    let docs = read_docs(&archive, scope)?;
    let texts: Vec<&str> = docs.iter().flat_map(|(_, doc)| doc.texts()).collect();
    let plans = if texts.is_empty() {
        Vec::new()
    } else {
        pass.plan(&texts)?
    };

    let mut jobs: Vec<(usize, &XmlDoc, &[Vec<Replacement>])> = Vec::new();
    let mut rest = plans.as_slice();
    for (index, doc) in &docs {
        let (mine, tail) = rest
            .split_at_checked(doc.len())
            .ok_or_else(|| Error::Xml("engine returned fewer plans than segments".into()))?;
        rest = tail;
        if mine.iter().any(|reps| !reps.is_empty()) {
            jobs.push((*index, doc, mine));
        }
    }

    let original = archive.clone().into_inner().into_inner();
    if jobs.is_empty() {
        return Ok(pass.unchanged(original));
    }
    let mut prepared: HashMap<usize, PreparedZipFile> = jobs
        .par_iter()
        .map_init(
            || archive.clone(),
            |ar, &(index, doc, reps)| compress(ar, index, doc, reps),
        )
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    let mut out = ZipWriter::new(Cursor::new(Vec::with_capacity(original.len())));
    out.set_raw_comment(archive.comment().into())?;
    for index in 0..archive.len() {
        match prepared.remove(&index) {
            Some(file) => out.add_prepared_file(file)?,
            None => out.raw_copy_file(archive.by_index_raw(index)?)?,
        }
    }
    Ok(out.finish()?.into_inner())
}

/// All segment texts of the package's XML parts, one per line.
pub(super) fn texts(archive: &Archive<'_>, scope: Scope) -> Result<String> {
    let docs = read_docs(archive, scope)?;
    let mut out = String::new();
    for text in docs.iter().flat_map(|(_, doc)| doc.texts()) {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(text);
    }
    Ok(out)
}

/// Reads and scans every XML part, in parallel; `(entry index, document)` in entry order.
fn read_docs(archive: &Archive<'_>, scope: Scope) -> Result<Vec<(usize, XmlDoc)>> {
    let mut parts = Vec::new();
    for index in 0..archive.len() {
        if let Some(name) = archive.name_for_index(index)
            && let Some(attrs) = scope(&name?)
        {
            parts.push((index, attrs));
        }
    }
    parts
        .par_iter()
        .map_init(
            || archive.clone(),
            |ar, &(index, attrs)| {
                let mut file = ar.by_index(index)?;
                let name = file.name()?.into_owned();
                let reserve = usize::try_from(file.size().min(MAX_RESERVE)).unwrap_or(0);
                let mut bytes = Vec::with_capacity(reserve);
                file.read_to_end(&mut bytes)
                    .map_err(|e| Error::Zip(format!("{name}: {e}")))?;
                segments(bytes, attrs)
                    .map(|doc| (index, doc))
                    .map_err(|e| in_part(&name, e))
            },
        )
        .collect()
}

/// Rebuilds the part at `index` and compresses it with its original method,
/// timestamp and attributes; `None` when `reps` change nothing.
fn compress(
    archive: &mut Archive<'_>,
    index: usize,
    doc: &XmlDoc,
    reps: &[Vec<Replacement>],
) -> Result<Option<(usize, PreparedZipFile)>> {
    let Some(bytes) = doc.rebuild(reps)? else {
        return Ok(None);
    };
    let entry = archive.by_index_raw(index)?;
    let mut builder = ZipFileBuilder::new(entry.name()?, entry.options())?;
    builder.write_all(&bytes)?;
    Ok(Some((index, builder.finish()?)))
}

/// Names the package part an XML error came from.
fn in_part(name: &str, error: Error) -> Error {
    match error {
        Error::Xml(message) => Error::Xml(format!("{name}: {message}")),
        other => other,
    }
}
