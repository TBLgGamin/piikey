//! `docs/api/prose.toml`: the text a person wrote for the reference, and the fingerprints that say
//! which contract each piece was written against.
//!
//! The file is one table per operation (`[scan_text]`) and one for the introduction (`[intro]`).
//! A table has the text and the `reviewed` fingerprint of the generated contract it was reviewed
//! against, so a change of that contract leaves the table flagged until someone has read it again.
//! `cargo api-docs --accept` changes the fingerprints and nothing else in the file.

use std::{collections::BTreeMap, ops::Range};

use serde::Deserialize;
use toml::Spanned;

use super::DocsError;

/// Where the prose lives, from the root of the repository.
pub const PROSE_PATH: &str = "docs/api/prose.toml";

/// A table of the file, as it is written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Written {
    /// The fingerprint, with its place in the file.
    reviewed: Spanned<String>,
    /// Markdown, put after the generated description.
    text: String,
}

/// A table of the file, read.
#[derive(Debug, Clone)]
struct Entry {
    reviewed: String,
    text: String,
    /// Where the quoted fingerprint stands in the file.
    at: Range<usize>,
}

/// The tables of `prose.toml` by name: an operation, or `intro`.
#[derive(Debug, Clone, Default)]
pub struct Prose {
    entries: BTreeMap<String, Entry>,
}

impl Prose {
    /// Reads the prose from the text of `prose.toml`.
    ///
    /// # Errors
    /// The text is not TOML of the shape above: a table with other keys than `reviewed` and
    /// `text`, a fingerprint that is not 16 hexadecimal digits, or no text.
    pub fn parse(source: &str) -> Result<Self, DocsError> {
        let written: BTreeMap<String, Written> = toml::from_str(source)
            .map_err(|error| DocsError::new(format!("{PROSE_PATH} is not valid: {error}")))?;
        let mut entries = BTreeMap::new();
        for (name, table) in written {
            let reviewed = table.reviewed.get_ref().clone();
            if reviewed.len() != 16 || !reviewed.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
            {
                return Err(DocsError::new(format!(
                    "{PROSE_PATH} [{name}]: `reviewed` must be 16 lowercase hexadecimal digits, as `cargo api-docs --accept {name}` writes it"
                )));
            }
            let text = table.text.trim().to_owned();
            if text.is_empty() {
                return Err(DocsError::new(format!(
                    "{PROSE_PATH} [{name}] has no text: remove the table, or write the text"
                )));
            }
            entries.insert(
                name,
                Entry {
                    reviewed,
                    text,
                    at: table.reviewed.span(),
                },
            );
        }
        Ok(Self { entries })
    }

    /// The text of the table `name`.
    pub(super) fn text(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|entry| entry.text.as_str())
    }

    /// The fingerprint the table `name` was reviewed against.
    pub(super) fn reviewed(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|entry| entry.reviewed.as_str())
    }

    /// The names of the tables, in order.
    pub(super) fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// `source`, the text this prose was read from, with the fingerprint of each table named in
    /// `stamps` (a name and a fingerprint) replaced. Nothing else in the text changes.
    ///
    /// # Errors
    /// A name that has no table, or a `source` that is not the text this was read from.
    pub(super) fn restamp(
        &self,
        source: &str,
        stamps: &[(&str, &str)],
    ) -> Result<String, DocsError> {
        let mut edits: Vec<(Range<usize>, &str)> = Vec::new();
        for (name, fingerprint) in stamps {
            let entry = self
                .entries
                .get(*name)
                .ok_or_else(|| DocsError::new(format!("{PROSE_PATH} has no table [{name}]")))?;
            let old = source.get(entry.at.clone()).unwrap_or_default();
            if !(old.starts_with('"') || old.starts_with('\'')) || !old.contains(&entry.reviewed) {
                return Err(DocsError::new(format!(
                    "{PROSE_PATH} [{name}]: the text changed while it was read"
                )));
            }
            edits.push((entry.at.clone(), fingerprint));
        }
        // From the end, so the places of the others stay where they were read.
        edits.sort_by_key(|edit| std::cmp::Reverse(edit.0.start));
        let mut stamped = source.to_owned();
        for (at, fingerprint) in edits {
            stamped.replace_range(at, &format!("\"{fingerprint}\""));
        }
        Ok(stamped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# A comment that stays.
[intro]
reviewed = "0123456789abcdef"
text = '''
Hello, \\.\pipe\ and "quotes".
'''

[scan_text]   # so does this one
reviewed = 'fedcba9876543210'
text = """
Spans are bytes.
"""
"#;

    #[test]
    fn the_tables_are_read_with_their_text_trimmed() -> Result<(), DocsError> {
        let prose = Prose::parse(SAMPLE)?;
        assert_eq!(prose.names().collect::<Vec<_>>(), ["intro", "scan_text"]);
        assert_eq!(prose.reviewed("intro"), Some("0123456789abcdef"));
        assert_eq!(prose.text("scan_text"), Some("Spans are bytes."));
        assert_eq!(
            prose.text("intro"),
            Some(r#"Hello, \\.\pipe\ and "quotes"."#)
        );
        assert_eq!(prose.text("nothing"), None);
        Ok(())
    }

    #[test]
    fn a_stamp_changes_the_fingerprint_and_nothing_else() -> Result<(), DocsError> {
        let prose = Prose::parse(SAMPLE)?;
        let stamped = prose.restamp(
            SAMPLE,
            &[
                ("intro", "aaaaaaaaaaaaaaaa"),
                ("scan_text", "bbbbbbbbbbbbbbbb"),
            ],
        )?;
        assert_eq!(
            stamped,
            SAMPLE
                .replace("0123456789abcdef", "aaaaaaaaaaaaaaaa")
                .replace("'fedcba9876543210'", "\"bbbbbbbbbbbbbbbb\"")
        );
        // What was written reads back with the new fingerprints.
        let again = Prose::parse(&stamped)?;
        assert_eq!(again.reviewed("scan_text"), Some("bbbbbbbbbbbbbbbb"));
        assert_eq!(again.text("intro"), prose.text("intro"));
        Ok(())
    }

    #[test]
    fn what_is_not_a_table_of_the_shape_is_refused() {
        for bad in [
            "[a]\nreviewed = \"0123456789abcdef\"\n",
            "[a]\ntext = \"x\"\n",
            "[a]\nreviewed = \"0123456789abcdef\"\ntext = \"x\"\nextra = 1\n",
            "[a]\nreviewed = \"0123456789ABCDEF\"\ntext = \"x\"\n",
            "[a]\nreviewed = \"0123\"\ntext = \"x\"\n",
            "[a]\nreviewed = \"0123456789abcdef\"\ntext = \"  \"\n",
            "title = \"x\"\n",
            "[a\n",
        ] {
            assert!(Prose::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_stamp_for_a_missing_table_is_refused() -> Result<(), DocsError> {
        let prose = Prose::parse(SAMPLE)?;
        assert!(
            prose
                .restamp(SAMPLE, &[("nothing", "aaaaaaaaaaaaaaaa")])
                .is_err()
        );
        // A text other than the one that was read is refused, not damaged.
        assert!(
            prose
                .restamp("short", &[("intro", "aaaaaaaaaaaaaaaa")])
                .is_err()
        );
        Ok(())
    }
}
