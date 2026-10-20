//! Corpus loading: normalized JSONL (see `eval/fetch.py`) into documents with gold spans.
//!
//! Every span is checked (inside the text, on character boundaries, in order, no overlap, a
//! label of the source's table) and a corpus that breaks a rule is refused with the line that did.

use std::{collections::BTreeMap, fs, path::Path};

use serde_json::Value;

use crate::{
    Res,
    taxonomy::{Cat, Taxonomy},
};

/// A ground-truth span: byte offsets into the document text.
#[derive(Debug, Clone)]
pub struct Gold {
    pub start: usize,
    pub end: usize,
    /// The label as the source wrote it (the first part's when parts were merged).
    pub label: String,
    pub cat: Cat,
}

/// One document of a corpus.
#[derive(Debug)]
pub struct Doc {
    pub id: String,
    pub lang: String,
    /// What kind of document it is, when the source says (finance document type, domain).
    pub group: String,
    pub text: String,
    pub gold: Vec<Gold>,
}

/// A loaded corpus.
#[derive(Debug)]
pub struct Source {
    pub name: String,
    pub docs: Vec<Doc>,
    pub bytes: usize,
    /// First 16 hex digits of the BLAKE3 hash of the file: names the data a result came from.
    pub fingerprint: String,
    /// Every PII value is labelled (see `labels.toml`).
    pub exhaustive: bool,
    /// Per category: a prediction of it can be judged against this source.
    pub judged: Vec<bool>,
    /// Source label: its category and how many spans carry it (before merging parts).
    pub labels: BTreeMap<String, (Cat, usize)>,
    /// Gold spans that were merged into a neighbour (see [`merge_parts`]).
    pub merged: usize,
}

impl Source {
    /// Loads `path` as the corpus `name`, keeping at most `limit` documents.
    ///
    /// # Errors
    /// The file is unreadable or malformed, or `labels.toml` has no table for `name`.
    pub fn load(tax: &Taxonomy, name: &str, path: &Path, limit: Option<usize>) -> Res<Self> {
        let table = tax
            .source(name)
            .ok_or_else(|| format!("labels.toml has no [source.{name}] table"))?;
        let raw = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let text = std::str::from_utf8(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        let fingerprint = blake3::hash(&raw).to_hex().as_str()[..16].to_owned();

        let mut docs = Vec::new();
        let mut labels: BTreeMap<String, (Cat, usize)> = BTreeMap::new();
        let mut merged = 0;
        for (n, line) in text
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            if limit.is_some_and(|max| docs.len() >= max) {
                break;
            }
            let at = format!("{}:{}", path.display(), n + 1);
            let doc = parse_doc(line, name, &table.labels).map_err(|e| format!("{at}: {e}"))?;
            for g in &doc.gold {
                labels.entry(g.label.clone()).or_insert((g.cat, 0)).1 += 1;
            }
            let before = doc.gold.len();
            // A hand-labelled corpus says where a span ends; the others cut entities into parts.
            let gold = if table.exhaustive {
                doc.gold
            } else {
                merge_parts(tax, &doc.text, doc.gold)
            };
            merged += before - gold.len();
            docs.push(Doc { gold, ..doc });
        }
        if docs.is_empty() {
            return Err(format!("{}: no documents", path.display()).into());
        }

        let annotated: Vec<bool> = tax
            .all()
            .map(|c| table.labels.values().any(|l| *l == c))
            .collect();
        let judged = tax
            .all()
            .map(|c| {
                table.exhaustive
                    || annotated[c.0]
                    || tax.all().any(|d| annotated[d.0] && tax.compatible(c, d))
            })
            .collect();
        let bytes = docs.iter().map(|d| d.text.len()).sum();
        Ok(Self {
            name: name.to_owned(),
            docs,
            bytes,
            fingerprint,
            exhaustive: table.exhaustive,
            judged,
            labels,
            merged,
        })
    }

    /// Gold spans after merging.
    #[must_use]
    pub fn gold_spans(&self) -> usize {
        self.docs.iter().map(|d| d.gold.len()).sum()
    }
}

fn parse_doc(line: &str, source: &str, table: &BTreeMap<String, Cat>) -> Result<Doc, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let field = |key: &str| v.get(key).and_then(Value::as_str);
    let id = field("id").ok_or("no id")?.to_owned();
    if field("source") != Some(source) {
        return Err(format!("{id}: source is not {source:?}"));
    }
    let text = field("text")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| format!("{id}: no text"))?
        .to_owned();
    let spans = v
        .get("spans")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{id}: no spans array"))?;

    let mut gold = Vec::with_capacity(spans.len());
    for span in spans {
        let offset = |key: &str| {
            span.get(key)
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
        };
        let (Some(start), Some(end)) = (offset("start"), offset("end")) else {
            return Err(format!("{id}: a span without integer offsets"));
        };
        let label = span
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let at = format!("{id}: span {label:?} [{start}, {end})");
        if !(start < end && end <= text.len()) {
            return Err(format!("{at}: outside the text (0..{})", text.len()));
        }
        if !(text.is_char_boundary(start) && text.is_char_boundary(end)) {
            return Err(format!("{at}: cuts a character"));
        }
        if text[start..end].trim() != &text[start..end] {
            return Err(format!("{at}: edge whitespace"));
        }
        let cat = *table
            .get(label)
            .ok_or_else(|| format!("{at}: the label is not in labels.toml"))?;
        gold.push(Gold {
            start,
            end,
            label: label.to_owned(),
            cat,
        });
    }
    gold.sort_by_key(|g| (g.start, g.end));
    if let Some(pair) = gold.windows(2).find(|w| w[0].end > w[1].start) {
        return Err(format!("{id}: spans overlap at byte {}", pair[1].start));
    }
    Ok(Doc {
        id,
        lang: field("lang").unwrap_or("?").to_owned(),
        group: field("group").unwrap_or_default().to_owned(),
        text,
        gold,
    })
}

/// Joins gold spans of one category that touch. The sources cut an entity into parts the model
/// reads as one: `OpenPII` labels `GIVENNAME` and `SURNAME` apart, and a street from its number.
/// Two parts join when at most two characters lie between them and each is a space, tab, hyphen
/// or no-break space, or one of the category's own joiners (`[merge]` in `labels.toml`: a comma
/// and a period inside an address).
pub fn merge_parts(tax: &Taxonomy, text: &str, gold: Vec<Gold>) -> Vec<Gold> {
    let mut out: Vec<Gold> = Vec::with_capacity(gold.len());
    for g in gold {
        if let Some(prev) = out.last_mut()
            && prev.cat == g.cat
            && tax.joins(g.cat, &text[prev.end..g.start])
        {
            prev.end = g.end;
        } else {
            out.push(g);
        }
    }
    out
}
