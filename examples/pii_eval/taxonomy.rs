//! The label table `eval/labels.toml`: the shared categories, how piikey's kinds fold into them,
//! and the labels of each source.
//!
//! The file uses a small subset of TOML (`[section]` headers, `KEY = "string"` lines, `#`
//! comments), read here by hand: a TOML crate would be a dependency for forty lines of syntax.
//! Anything outside the subset is an error, never a silent skip.

use std::{collections::BTreeMap, fs, path::Path};

use piikey::detect::EntityKind;

use crate::Res;

/// A category of the shared taxonomy, as an index into [`Taxonomy::cats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cat(pub usize);

/// One category.
#[derive(Debug)]
pub struct Category {
    pub name: String,
    pub about: String,
    /// The piikey kinds that fold into it. Empty: piikey cannot produce this category.
    pub kinds: Vec<EntityKind>,
}

/// The labels of one source and how the benchmark judges it.
#[derive(Debug)]
pub struct SourceTable {
    pub labels: BTreeMap<String, Cat>,
    /// Every PII value in the text is labelled, so any unmatched prediction is a false positive.
    pub exhaustive: bool,
}

/// The parsed label table.
#[derive(Debug)]
pub struct Taxonomy {
    pub cats: Vec<Category>,
    /// Category of each kind, indexed by `kind as usize`.
    kind_cat: Vec<Cat>,
    /// `compat[a][b]`: category `a` counts as `b` for the overlap-and-category metric.
    compat: Vec<Vec<bool>>,
    /// Per category: characters, besides a space or hyphen, that may lie between two gold parts
    /// that join into one span.
    merge: Vec<String>,
    /// Categories the model card's seven type groups cover, as this benchmark reads them.
    card: Vec<bool>,
    sources: BTreeMap<String, SourceTable>,
}

type Section = (String, Vec<(String, String)>);

impl Taxonomy {
    /// # Errors
    /// The file is unreadable, uses syntax outside the subset, or does not map every kind.
    pub fn load(path: &Path) -> Res<Self> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()).into())
    }

    fn parse(text: &str) -> Result<Self, String> {
        let sections = sections(text)?;
        let find = |name: &str| -> Result<&[(String, String)], String> {
            sections
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, pairs)| pairs.as_slice())
                .ok_or_else(|| format!("no [{name}] section"))
        };

        let mut cats: Vec<Category> = find("categories")?
            .iter()
            .map(|(name, about)| Category {
                name: name.clone(),
                about: about.clone(),
                kinds: Vec::new(),
            })
            .collect();
        let lookup = |name: &str, what: &str| -> Result<Cat, String> {
            cats.iter()
                .position(|c| c.name == name)
                .map(Cat)
                .ok_or_else(|| format!("{what}: unknown category {name:?}"))
        };

        let mut kind_cat = vec![Cat(usize::MAX); EntityKind::ALL.len() + 1];
        let mut kinds_of: Vec<(Cat, EntityKind)> = Vec::new();
        for (key, value) in find("piikey")? {
            let kind =
                EntityKind::parse(key).ok_or_else(|| format!("[piikey]: unknown kind {key:?}"))?;
            let cat = lookup(value, &format!("[piikey] {key}"))?;
            kind_cat[kind as usize] = cat;
            kinds_of.push((cat, kind));
        }
        if let Some(kind) = EntityKind::ALL
            .into_iter()
            .find(|k| kind_cat[*k as usize].0 == usize::MAX)
        {
            return Err(format!(
                "[piikey]: kind {:?} has no category",
                kind.as_str()
            ));
        }

        let mut compat = vec![vec![false; cats.len()]; cats.len()];
        for (i, row) in compat.iter_mut().enumerate() {
            row[i] = true;
        }
        for (a, b) in find("compat")? {
            let (a, b) = (lookup(a, "[compat]")?, lookup(b, "[compat]")?);
            compat[a.0][b.0] = true;
            compat[b.0][a.0] = true;
        }

        let mut merge = vec![String::new(); cats.len()];
        if let Ok(pairs) = find("merge") {
            for (name, joiners) in pairs {
                merge[lookup(name, "[merge]")?.0].clone_from(joiners);
            }
        }

        let mut card = vec![false; cats.len()];
        if let Ok(pairs) = find("card") {
            for (key, value) in pairs {
                if key != "types" {
                    return Err(format!("[card]: unknown key {key:?}"));
                }
                for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                    card[lookup(name, "[card] types")?.0] = true;
                }
            }
        }
        let policy = find("policy")?;
        let mut sources = BTreeMap::new();
        for (name, pairs) in &sections {
            let Some(source) = name.strip_prefix("source.") else {
                continue;
            };
            let mut labels = BTreeMap::new();
            for (label, cat) in pairs {
                labels.insert(label.clone(), lookup(cat, &format!("[{name}] {label}"))?);
            }
            let exhaustive = match policy.iter().find(|(k, _)| k == source) {
                Some((_, v)) if v == "exhaustive" => true,
                Some((_, v)) if v == "partial" => false,
                Some((_, v)) => {
                    return Err(format!(
                        "[policy] {source}: {v:?} is not exhaustive or partial"
                    ));
                }
                None => false,
            };
            sources.insert(source.to_owned(), SourceTable { labels, exhaustive });
        }

        for (cat, kind) in kinds_of {
            cats[cat.0].kinds.push(kind);
        }
        Ok(Self {
            cats,
            kind_cat,
            compat,
            merge,
            card,
            sources,
        })
    }

    #[must_use]
    pub fn cat_of(&self, kind: EntityKind) -> Cat {
        self.kind_cat[kind as usize]
    }

    #[must_use]
    pub fn name(&self, cat: Cat) -> &str {
        &self.cats[cat.0].name
    }

    /// Whether `gap`, the text between two gold parts of `cat`, lets them join: at most two
    /// characters, each a space, tab, hyphen, no-break space or a joiner of the category.
    #[must_use]
    pub fn joins(&self, cat: Cat, gap: &str) -> bool {
        gap.chars().count() <= 2
            && gap
                .chars()
                .all(|c| matches!(c, ' ' | '\t' | '-' | '\u{a0}') || self.merge[cat.0].contains(c))
    }

    /// Whether the overlap-and-category metric accepts category `a` where `b` is expected.
    #[must_use]
    pub fn compatible(&self, a: Cat, b: Cat) -> bool {
        self.compat[a.0][b.0]
    }

    /// Whether piikey has at least one kind in `cat`.
    #[must_use]
    pub fn supported(&self, cat: Cat) -> bool {
        !self.cats[cat.0].kinds.is_empty()
    }

    #[must_use]
    pub fn source(&self, name: &str) -> Option<&SourceTable> {
        self.sources.get(name)
    }

    /// Whether the model card's scoring covers `cat` (see `[card]` in `labels.toml`).
    #[must_use]
    pub fn is_card_type(&self, cat: Cat) -> bool {
        self.card[cat.0]
    }

    pub fn all(&self) -> impl Iterator<Item = Cat> + use<> {
        (0..self.cats.len()).map(Cat)
    }
}

/// The sections of `text` in order, each with its `key = "value"` pairs in order.
fn sections(text: &str) -> Result<Vec<Section>, String> {
    let mut out: Vec<Section> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let at = n + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("line {at}: unclosed section header"))?
                .trim();
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
                || name.is_empty()
            {
                return Err(format!("line {at}: bad section name {name:?}"));
            }
            if out.iter().any(|(n, _)| n == name) {
                return Err(format!("line {at}: section [{name}] appears twice"));
            }
            out.push((name.to_owned(), Vec::new()));
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {at}: expected KEY = \"value\""))?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!("line {at}: bad key {key:?}"));
        }
        let value = value
            .trim()
            .strip_prefix('"')
            .ok_or_else(|| format!("line {at}: the value of {key} must be a \"string\""))?;
        let close = value
            .find('"')
            .ok_or_else(|| format!("line {at}: unterminated string"))?;
        let (value, tail) = value.split_at(close);
        let tail = tail[1..].trim();
        if !(tail.is_empty() || tail.starts_with('#')) || value.contains('\\') {
            return Err(format!(
                "line {at}: strings are plain (no escapes, nothing after the closing quote)"
            ));
        }
        let (_, pairs) = out
            .last_mut()
            .ok_or_else(|| format!("line {at}: a key before any [section]"))?;
        if pairs.iter().any(|(k, _)| k == key) {
            return Err(format!("line {at}: {key} appears twice in the section"));
        }
        pairs.push((key.to_owned(), value.to_owned()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::sections;

    #[test]
    fn parses_the_subset() -> Result<(), String> {
        let text = "# c\n[a.b]\nK = \"v w\"  # tail\n\n[c]\nX-1 = \"\"\n";
        let parsed = sections(text)?;
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "a.b");
        assert_eq!(parsed[0].1, vec![("K".to_owned(), "v w".to_owned())]);
        assert_eq!(parsed[1].1, vec![("X-1".to_owned(), String::new())]);
        Ok(())
    }

    #[test]
    fn rejects_what_is_outside_the_subset() {
        for bad in [
            "K = \"v\"\n",
            "[a]\nK = v\n",
            "[a]\nK = \"v\\n\"\n",
            "[a]\nK = [\"v\"]\n",
            "[a]\nK = \"v\" x\n",
            "[a]\nK = \"v\"\nK = \"w\"\n",
            "[a]\n[a]\n",
            "[a\n",
        ] {
            assert!(sections(bad).is_err(), "{bad:?}");
        }
    }
}
