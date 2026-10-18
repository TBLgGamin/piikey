//! Anonymize / deanonymize over batches of texts.

use std::{collections::HashSet, path::Path};

use rayon::prelude::*;

use crate::{
    Result,
    detect::{Detector, EntityKind, Mode, RegexDetector, Span},
    proxy::watermark_ok,
    vault::Vault,
};

/// Replace `text[start..end]` with `with`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub start: usize,
    pub end: usize,
    pub with: Box<str>,
}

/// Detector + vault.
#[derive(Debug)]
pub struct Engine {
    detector: Box<dyn Detector>,
    vault: Vault,
}

impl Engine {
    /// Opens the vault at `vault_path` with the regex detector.
    ///
    /// # Errors
    /// Vault open failures.
    pub fn open(vault_path: &Path) -> Result<Self> {
        Ok(Self::new(
            Box::new(RegexDetector::new()?),
            Vault::open(vault_path)?,
        ))
    }

    #[must_use]
    pub fn new(detector: Box<dyn Detector>, vault: Vault) -> Self {
        Self { detector, vault }
    }

    /// Replacements per text, sorted and non-overlapping. Anonymize issues
    /// new proxies in one vault write; already-issued proxies are left alone,
    /// so anonymize is idempotent.
    ///
    /// # Errors
    /// Vault failures.
    pub fn plan(&self, mode: Mode, texts: &[&str]) -> Result<Vec<Vec<Replacement>>> {
        let spans: Vec<Vec<Span>> = texts
            .par_iter()
            .map(|t| self.detector.detect(t, mode))
            .collect();
        match mode {
            Mode::Anonymize => self.plan_anonymize(texts, &spans),
            Mode::Deanonymize => self.plan_deanonymize(texts, &spans),
        }
    }

    fn plan_anonymize(&self, texts: &[&str], spans: &[Vec<Span>]) -> Result<Vec<Vec<Replacement>>> {
        let missing: Vec<(EntityKind, Box<str>)> = {
            let view = self.vault.read()?;
            let mut seen = HashSet::new();
            texts
                .iter()
                .zip(spans)
                .flat_map(|(t, ss)| ss.iter().map(move |s| (s.kind, &t[s.start..s.end])))
                // Skip values that are already issued proxies of any kind: a
                // proxy may be re-detected under another kind (e.g. a bare
                // SSN proxy read as a phone number without its keyword).
                .filter(|&(k, v)| view.proxy_for(k, v).is_none() && view.original_for(v).is_none())
                .filter(|&(k, v)| seen.insert((k, v)))
                .map(|(k, v)| (k, Box::from(v)))
                .collect()
        };
        if !missing.is_empty() {
            self.vault.resolve(missing)?;
        }
        // Never hold a VaultView across rayon work: a worker blocked in a
        // par_iter may run another queued engine call on this thread, which
        // would wait on the vault lock we hold. Hash lookups are cheap.
        let view = self.vault.read()?;
        Ok(texts
            .iter()
            .zip(spans)
            .map(|(t, ss)| {
                ss.iter()
                    .filter_map(|s| {
                        let value = &t[s.start..s.end];
                        view.proxy_for(s.kind, value).map(|p| Replacement {
                            start: s.start,
                            end: s.end,
                            with: Box::from(p),
                        })
                    })
                    .collect()
            })
            .collect())
    }

    fn plan_deanonymize(
        &self,
        texts: &[&str],
        spans: &[Vec<Span>],
    ) -> Result<Vec<Vec<Replacement>>> {
        // Watermark checks (hashing) run in parallel without the lock; vault
        // lookups run sequentially under it (see plan_anonymize).
        let keys = self.vault.proxy_keys();
        let marked: Vec<Vec<Span>> = texts
            .par_iter()
            .zip(spans)
            .map(|(t, ss)| {
                ss.iter()
                    .filter(|s| watermark_ok(keys, s.kind, &t[s.start..s.end]))
                    .copied()
                    .collect()
            })
            .collect();
        let view = self.vault.read()?;
        Ok(texts
            .iter()
            .zip(&marked)
            .map(|(t, ss)| {
                ss.iter()
                    .filter_map(|s| {
                        view.original_for(&t[s.start..s.end]).map(|o| Replacement {
                            start: s.start,
                            end: s.end,
                            with: Box::from(o),
                        })
                    })
                    .collect()
            })
            .collect())
    }

    /// Applies sorted, non-overlapping replacements in one pass.
    #[must_use]
    pub fn apply(text: &str, reps: &[Replacement]) -> String {
        let delta: isize = reps
            .iter()
            .map(|r| r.with.len().cast_signed() - (r.end - r.start).cast_signed())
            .sum();
        let mut out = String::with_capacity(text.len().saturating_add_signed(delta));
        let mut pos = 0;
        for r in reps {
            out.push_str(&text[pos..r.start]);
            out.push_str(&r.with);
            pos = r.end;
        }
        out.push_str(&text[pos..]);
        out
    }

    /// `plan` + `apply` for every text.
    ///
    /// # Errors
    /// Vault failures.
    pub fn run(&self, mode: Mode, texts: &[&str]) -> Result<Vec<String>> {
        let plans = self.plan(mode, texts)?;
        Ok(texts
            .par_iter()
            .zip(&plans)
            .map(|(t, reps)| Self::apply(t, reps))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Engine, Replacement};
    use crate::detect::Mode;

    /// One value of every kind, as it appears in the corpus (the URL
    /// credential's PII is the `user:pass` part).
    const ORIGINALS: [&str; 11] = [
        "AKIAIOSFODNN7EXAMPLE",
        "admin:hunter2",
        "jan.jansen@acme.nl",
        "NL91ABNA0417164300",
        "4111 1111 1111 1111",
        "2001:db8:85a3::8a2e:370:7334",
        "00:1A:2B:3C:4D:5E",
        "203.0.113.42",
        "123-45-6789",
        "111222333",
        "+31 6 12345678",
    ];

    const CORPUS: [&str; 3] = [
        "key AKIAIOSFODNN7EXAMPLE db https://admin:hunter2@db.example.com/x",
        "Mail jan.jansen@acme.nl, IBAN NL91ABNA0417164300, card 4111 1111 1111 1111.\n\
         host 2001:db8:85a3::8a2e:370:7334 mac 00:1A:2B:3C:4D:5E ip 203.0.113.42",
        "SSN 123-45-6789, BSN 111222333, bel +31 6 12345678 of jan.jansen@acme.nl",
    ];

    fn temp_vault(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piikey-engine-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir.join("vault.pkv")
    }

    #[test]
    fn anonymize_hides_every_kind_and_deanonymize_restores() -> crate::Result<()> {
        let engine = Engine::open(&temp_vault("roundtrip"))?;
        let anon = engine.run(Mode::Anonymize, &CORPUS)?;
        for out in &anon {
            for orig in ORIGINALS {
                assert!(!out.contains(orig), "{orig:?} leaked into {out:?}");
            }
        }
        let refs: Vec<&str> = anon.iter().map(String::as_str).collect();
        assert_eq!(engine.run(Mode::Deanonymize, &refs)?, CORPUS);
        Ok(())
    }

    #[test]
    fn anonymize_is_idempotent_and_stable_across_runs_and_reopen() -> crate::Result<()> {
        let path = temp_vault("stable");
        let engine = Engine::open(&path)?;
        let first = engine.run(Mode::Anonymize, &CORPUS)?;
        let refs: Vec<&str> = first.iter().map(String::as_str).collect();
        assert_eq!(engine.run(Mode::Anonymize, &refs)?, first, "idempotent");
        assert_eq!(
            engine.run(Mode::Anonymize, &CORPUS)?,
            first,
            "same run twice"
        );
        drop(engine);
        let reopened = Engine::open(&path)?;
        assert_eq!(
            reopened.run(Mode::Anonymize, &CORPUS)?,
            first,
            "after reopen"
        );
        Ok(())
    }

    #[test]
    fn deanonymize_ignores_lookalikes_not_issued_by_the_vault() -> crate::Result<()> {
        let engine = Engine::open(&temp_vault("lookalike"))?;
        let text = ["call +31 6 87654321 or mail piet@example.org"];
        assert_eq!(engine.run(Mode::Deanonymize, &text)?, text);
        Ok(())
    }

    #[test]
    fn issued_proxies_survive_reanonymize_without_their_keyword() -> crate::Result<()> {
        // Bare (separator-less) SSNs need the keyword; their proxies, seen
        // without it, may be detected as another kind and must still be left
        // alone.
        let engine = Engine::open(&temp_vault("crosskind"))?;
        let originals: Vec<String> = (10..90).map(|n| format!("SSN 1234567{n}")).collect();
        let refs: Vec<&str> = originals.iter().map(String::as_str).collect();
        for anon in engine.run(Mode::Anonymize, &refs)? {
            let text = format!("id {}", anon.trim_start_matches("SSN "));
            assert_eq!(
                engine.run(Mode::Anonymize, &[&text])?,
                std::slice::from_ref(&text)
            );
        }
        Ok(())
    }

    #[test]
    fn apply_handles_growth_shrink_and_edges() {
        let reps = [
            Replacement {
                start: 0,
                end: 1,
                with: "XYZ".into(),
            },
            Replacement {
                start: 4,
                end: 7,
                with: "".into(),
            },
            Replacement {
                start: 9,
                end: 10,
                with: "!".into(),
            },
        ];
        assert_eq!(Engine::apply("a123bcd45e", &reps), "XYZ12345!");
    }
}
