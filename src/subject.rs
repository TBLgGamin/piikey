//! Subject search, for a data subject access request: which files hold the values that identify
//! one person (their name, email address, phone number, IBAN, ...).
//!
//! A file holds a value when either
//!
//! 1. the text has it as a whole word, in any letter case, where the value's spaces match any
//!    run of whitespace (a name split over two lines is still the name). Only ASCII letters and
//!    digits make a word longer: a value written straight against accented text still counts; or
//! 2. the detector found a value of the file that is the same once both are spelled in
//!    lowercase with only letters, digits and `@` kept. That makes `+31 6 1234 5678` and
//!    `+31612345678` the same value, and `NL91 ABNA 0417 1643 00` the IBAN
//!    `NL91ABNA0417164300`. A different prefix is a different value: `0612345678` is not
//!    `+31612345678`.
//!
//! Only what the detector can read is searched, so a kind switched off in Settings is not found
//! the second way, and a file piikey cannot read (binary data, a damaged document) is not
//! searched at all. Neither is a file that is only in the cloud (a `OneDrive` file that is not on
//! this PC) and found in a folder, unless it is named: reading it would download it.

use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use aho_corasick::{AhoCorasick, Input};
use rayon::prelude::*;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    Error, Result,
    engine::Engine,
    files,
    formats::{self, Scanned},
    inventory::{MAX_FILE, read_capped},
};

/// A file that holds some of the values searched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectMatch {
    pub path: PathBuf,
    /// Which of the values searched for it holds, as indexes into them, in order.
    pub values: Vec<usize>,
    /// How many times, of all the values it holds added up. A value that stands in the file as
    /// it was given and is also found by the detector counts once.
    pub count: u32,
}

/// A [`SubjectMatch`] as it is written and read.
#[derive(Serialize, Deserialize)]
struct Shape<'a> {
    path: Cow<'a, str>,
    values: Cow<'a, [usize]>,
    count: u32,
}

impl Serialize for SubjectMatch {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        Shape {
            path: self.path.to_string_lossy(),
            values: Cow::Borrowed(&self.values),
            count: self.count,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SubjectMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let shape = Shape::deserialize(deserializer)?;
        Ok(Self {
            path: PathBuf::from(shape.path.into_owned()),
            values: shape.values.into_owned(),
            count: shape.count,
        })
    }
}

/// The API's view of a match, as `Serialize` writes it.
impl JsonSchema for SubjectMatch {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("SubjectMatch")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "description": "A file that holds some of the values searched for.",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file's path."
                },
                "values": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 0},
                    "description": "Which of the values searched for the file holds, as indexes into them, in order."
                },
                "count": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "How many times the file holds them, of all the values it holds added up. A value that stands in the file as it was given and is also found by the detector counts once."
                }
            },
            "required": ["path", "values", "count"]
        })
    }
}

/// The files under `paths` (a file as itself, a folder recursively, no links followed) that hold
/// any of `values`, the one with the most occurrences first. Files without any are left out, and
/// so are files over [`MAX_FILE`]. Several files are read at once on the rayon pool the caller
/// runs in. When `cancel` is set the search stops and gives what it found up to then.
///
/// # Errors
/// `BadRequest` when there is no value to search for, or one that is blank.
pub fn search(
    engine: &Engine,
    values: &[String],
    paths: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<Vec<SubjectMatch>> {
    let needles = Needles::new(values)?;
    let walked = files::walk(paths, &|_, _| cancel.load(Ordering::Relaxed));
    let mut found: Vec<SubjectMatch> = walked
        .files
        .par_iter()
        .filter(|(_, meta)| meta.len() <= MAX_FILE)
        .filter_map(|(path, _)| {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            search_file(engine, &needles, path)
        })
        .collect();
    found.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.path.cmp(&b.path)));
    Ok(found)
}

/// What `path` holds of the values, or `None` when it holds none or cannot be read.
fn search_file(engine: &Engine, needles: &Needles, path: &Path) -> Option<SubjectMatch> {
    let bytes = read_capped(path).ok().flatten()?;
    let scanned = formats::scan(engine, &bytes, true).ok()?;
    let counts = needles.count_in(&scanned);
    let values: Vec<usize> = counts
        .iter()
        .enumerate()
        .filter(|&(_, &n)| n > 0)
        .map(|(i, _)| i)
        .collect();
    (!values.is_empty()).then(|| SubjectMatch {
        path: path.to_path_buf(),
        values,
        count: counts.iter().fold(0, |sum, &n| u32::saturating_add(sum, n)),
    })
}

/// The values searched for, ready to be looked for in many files.
struct Needles {
    /// Every value, trimmed, with its whitespace runs collapsed, in lowercase. The pattern
    /// index is the index of the value.
    words: AhoCorasick,
    /// Which values a normalized spelling stands for.
    by_spelling: HashMap<String, Vec<usize>>,
    /// Whether a value holds a space. Only then do the texts have to be collapsed to be searched.
    spaced: bool,
    /// Whether a value holds a letter outside ASCII. Only then do texts that do have to be
    /// lowercased to be searched: the automaton folds the case of ASCII letters only.
    unicode: bool,
}

impl Needles {
    fn new(values: &[String]) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::BadRequest("no value to search for".into()));
        }
        let mut patterns = Vec::with_capacity(values.len());
        let mut by_spelling: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, value) in values.iter().enumerate() {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::BadRequest("a value to search for is blank".into()));
            }
            patterns.push(collapse(value).to_lowercase());
            let spelling = normalize(value);
            if !spelling.is_empty() {
                by_spelling.entry(spelling).or_default().push(index);
            }
        }
        let spaced = patterns.iter().any(|pattern| pattern.contains(' '));
        let unicode = patterns.iter().any(|pattern| !pattern.is_ascii());
        let words = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::BadRequest(format!("cannot search for those values: {e}")))?;
        Ok(Self {
            words,
            by_spelling,
            spaced,
            unicode,
        })
    }

    /// How often each value occurs in what was scanned, by value.
    fn count_in(&self, scanned: &Scanned) -> Vec<u32> {
        let mut literal = vec![0_u32; self.words.patterns_len()];
        for text in &scanned.texts {
            let text = if self.spaced {
                collapse(text)
            } else {
                Cow::Borrowed(text.as_str())
            };
            let text = if self.unicode && !text.is_ascii() {
                Cow::Owned(text.to_lowercase())
            } else {
                text
            };
            for hit in self.words.find_overlapping_iter(Input::new(&*text)) {
                if stands_alone(&text, hit.start(), hit.end())
                    && let Some(n) = literal.get_mut(hit.pattern().as_usize())
                {
                    *n = n.saturating_add(1);
                }
            }
        }
        let mut detected = vec![0_u32; literal.len()];
        for (_, value) in &scanned.found {
            for &index in self
                .by_spelling
                .get(&normalize(value))
                .into_iter()
                .flatten()
            {
                detected[index] = detected[index].saturating_add(1);
            }
        }
        literal
            .into_iter()
            .zip(detected)
            .map(|(a, b)| a.max(b))
            .collect()
    }
}

/// `value` spelled for comparison: lowercase, with only letters, digits and `@` kept. Spacing,
/// dots, dashes and a leading `+` do not tell two spellings of a number, an IBAN or an address
/// apart; a different digit or a different prefix (`06` for `+316`) does.
fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '@')
        .flat_map(char::to_lowercase)
        .collect()
}

/// `text` with every run of whitespace as one space; borrowed when it already is.
fn collapse(text: &str) -> Cow<'_, str> {
    let mut after_space = false;
    let tidy = text.chars().all(|c| {
        let space = c.is_whitespace();
        let fine = !space || (c == ' ' && !after_space);
        after_space = space;
        fine
    });
    if tidy {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut after_space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            if !after_space {
                out.push(' ');
            }
            after_space = true;
        } else {
            out.push(c);
            after_space = false;
        }
    }
    Cow::Owned(out)
}

/// True when `text[start..end]` is not part of a longer word: the bytes on either side of it, if
/// there are any, are not ASCII letters or digits. The rule the engine uses for the stand-ins it
/// issued, so a value written straight against accented text still counts.
fn stands_alone(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    let after = bytes.get(end);
    !before.is_some_and(u8::is_ascii_alphanumeric) && !after.is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::atomic::AtomicUsize};

    use super::*;

    type Res<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    /// Temp directory removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> std::io::Result<Self> {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "piikey-subject-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(dir.join("docs"))?;
            Ok(Self(dir))
        }

        /// The folder that is searched; the vault is beside it.
        fn docs(&self) -> PathBuf {
            self.0.join("docs")
        }

        fn engine(&self) -> crate::Result<Engine> {
            Engine::open(&self.0.join("v.pkv"))
        }

        fn put(&self, name: &str, text: &str) -> std::io::Result<()> {
            fs::write(self.docs().join(name), text)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn values(list: &[&str]) -> Vec<String> {
        list.iter().map(|&v| v.to_owned()).collect()
    }

    /// Searches `tmp` for `list`: `(file name, value indexes, count)` per match.
    fn find(tmp: &TempDir, list: &[&str]) -> Res<Vec<(String, Vec<usize>, u32)>> {
        let engine = tmp.engine()?;
        let found = search(
            &engine,
            &values(list),
            &[tmp.docs()],
            &AtomicBool::new(false),
        )?;
        Ok(found
            .into_iter()
            .map(|m| {
                let name = m.path.file_name().map(|n| n.to_string_lossy().into_owned());
                (name.unwrap_or_default(), m.values, m.count)
            })
            .collect())
    }

    #[test]
    fn spellings_of_a_number_are_one_value_but_a_prefix_is_not() {
        assert_eq!(normalize("+31 6 1234 5678"), normalize("+31612345678"));
        assert_eq!(normalize("+31-6-1234-5678"), "31612345678");
        assert_ne!(normalize("0612345678"), normalize("+31612345678"));
        assert_eq!(normalize("NL91 ABNA 0417 1643 00"), "nl91abna0417164300");
        assert_eq!(normalize("Jan.Jansen@ACME.nl"), "janjansen@acmenl");
        assert_eq!(normalize("---"), "");
    }

    #[test]
    fn whitespace_runs_collapse_to_one_space() {
        assert_eq!(collapse("Jan  \r\n\tJansen"), "Jan Jansen");
        assert!(matches!(collapse("Jan Jansen"), Cow::Borrowed(_)));
        assert!(matches!(collapse("Jan\tJansen"), Cow::Owned(_)));
        assert_eq!(collapse(" a "), " a ");
    }

    #[test]
    fn a_value_is_found_as_a_whole_word_in_any_case() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "Mail JAN.JANSEN@acme.nl or jan.jansen@acme.nl.")?;
        tmp.put("b.txt", "xjan.jansen@acme.nl and nothing else")?;
        tmp.put("c.txt", "nothing")?;
        assert_eq!(
            find(&tmp, &["jan.jansen@acme.nl"])?,
            [("a.txt".to_owned(), vec![0], 2)]
        );
        Ok(())
    }

    #[test]
    fn a_name_is_not_found_inside_a_longer_word() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "Jansenberg and Dejansen")?;
        tmp.put("b.txt", "Mevrouw Jansen, goedendag. JANSEN")?;
        assert_eq!(find(&tmp, &["Jansen"])?, [("b.txt".to_owned(), vec![0], 2)]);
        Ok(())
    }

    #[test]
    fn a_name_split_over_lines_is_still_the_name() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "Dossier van Jan\r\n    Jansen, Utrecht")?;
        assert_eq!(
            find(&tmp, &["Jan Jansen"])?,
            [("a.txt".to_owned(), vec![0], 1)]
        );
        Ok(())
    }

    #[test]
    fn detected_values_match_by_normalized_spelling() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "bel +31 6 12345678 of mail jan.jansen@acme.nl")?;
        tmp.put("b.txt", "rekening NL91ABNA0417164300")?;
        assert_eq!(
            find(&tmp, &["+31612345678"])?,
            [("a.txt".to_owned(), vec![0], 1)]
        );
        // Not the same number: `06` is not `+316`.
        assert!(find(&tmp, &["0612345678"])?.is_empty());
        assert_eq!(
            find(&tmp, &["NL91 ABNA 0417 1643 00"])?,
            [("b.txt".to_owned(), vec![0], 1)]
        );
        // Several values at once: the file says which it holds, the most occurrences first.
        assert_eq!(
            find(
                &tmp,
                &[
                    "JAN.JANSEN@ACME.NL",
                    "0612345678",
                    "+31 6 12345678",
                    "NL91ABNA0417164300"
                ]
            )?,
            [
                ("a.txt".to_owned(), vec![0, 2], 2),
                ("b.txt".to_owned(), vec![3], 1),
            ]
        );
        Ok(())
    }

    #[test]
    fn a_value_with_accents_is_found_in_any_letter_case() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "DOSSIER JOSÉ MARTÍNEZ, Utrecht")?;
        tmp.put("b.txt", "Mevrouw José Martínez")?;
        tmp.put("c.txt", "JOSÉ MARTINEZ")?;
        assert_eq!(
            find(&tmp, &["José Martínez"])?,
            [
                ("a.txt".to_owned(), vec![0], 1),
                ("b.txt".to_owned(), vec![0], 1),
            ]
        );
        Ok(())
    }

    #[test]
    fn the_same_value_twice_is_found_under_both_indexes() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "Mevrouw Jansen")?;
        assert_eq!(
            find(&tmp, &["Jansen", "JANSEN", "Pietersen"])?,
            [("a.txt".to_owned(), vec![0, 1], 2)]
        );
        Ok(())
    }

    #[test]
    fn nothing_to_search_for_is_a_bad_request() -> Res {
        let tmp = TempDir::new()?;
        let engine = tmp.engine()?;
        let no = AtomicBool::new(false);
        let paths = [tmp.docs()];
        assert!(matches!(
            search(&engine, &[], &paths, &no),
            Err(Error::BadRequest(_))
        ));
        assert!(matches!(
            search(&engine, &values(&["Jan", "  "]), &paths, &no),
            Err(Error::BadRequest(_))
        ));
        assert!(search(&engine, &values(&["Jan"]), &[], &no)?.is_empty());
        Ok(())
    }

    #[test]
    fn a_cancelled_search_gives_nothing_more() -> Res {
        let tmp = TempDir::new()?;
        tmp.put("a.txt", "Jan Jansen")?;
        let engine = tmp.engine()?;
        let found = search(
            &engine,
            &values(&["Jan"]),
            &[tmp.docs()],
            &AtomicBool::new(true),
        )?;
        assert!(found.is_empty());
        Ok(())
    }

    #[test]
    fn a_match_goes_through_json_and_comes_back_equal() -> Res {
        let one = SubjectMatch {
            path: PathBuf::from(r"C:\x\a.txt"),
            values: vec![0, 2],
            count: 3,
        };
        let json = serde_json::to_value(&one)?;
        assert_eq!(
            json,
            serde_json::json!({"path": r"C:\x\a.txt", "values": [0, 2], "count": 3})
        );
        assert_eq!(serde_json::from_value::<SubjectMatch>(json)?, one);
        Ok(())
    }

    #[test]
    fn the_schema_of_a_match_names_what_it_serializes() -> Res {
        let schema = SubjectMatch::json_schema(&mut SchemaGenerator::default()).to_value();
        let one = SubjectMatch {
            path: PathBuf::from(r"C:\x\a.txt"),
            values: vec![0, 2],
            count: 3,
        };
        let json = serde_json::to_value(&one)?;
        let keys = json.as_object().ok_or("not an object")?;
        let properties = schema["properties"].as_object().ok_or("no properties")?;
        let required = schema["required"].as_array().ok_or("no required")?;
        for key in keys.keys() {
            assert!(properties.contains_key(key), "{key} is not in the schema");
        }
        for key in required {
            let key = key.as_str().ok_or("a required name is no string")?;
            assert!(keys.contains_key(key), "{key} is required but not written");
        }
        assert!(!properties.contains_key("hash"));
        assert!(!required.iter().any(|key| key.as_str() == Some("hash")));
        Ok(())
    }
}
