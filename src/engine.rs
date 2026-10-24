//! Anonymize / deanonymize over batches of texts.

use std::{
    cmp::Reverse,
    collections::HashSet,
    ops::ControlFlow,
    path::Path,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use rayon::prelude::*;

use crate::{
    Error, Result,
    detect::{
        CompositeDetector, Detector, EntityKind, IssuedProxies, KindSet, Mode, NerDetector,
        RegexDetector, Span, Step, Words, overlaps,
    },
    proxy::watermark_ok,
    vault::{Vault, VaultView},
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
    /// Finds the vault's proxies of the listed kinds in text, see [`Engine::matcher`].
    listed: RwLock<Option<Matcher>>,
    /// Finds its proxies of the patterned kinds.
    patterned: RwLock<Option<Matcher>>,
    /// The kinds Anonymize masks, as [`KindSet::bits`]; see [`Engine::set_enabled`].
    enabled: AtomicU64,
}

/// Which of the vault's proxies a [`Matcher`] looks for.
#[derive(Debug, Clone, Copy)]
enum Class {
    /// The kinds no pattern describes: names, addresses, organizations and the rest.
    Listed,
    /// The kinds the regexes find.
    Patterned,
}

impl Class {
    const fn holds(self, kind: EntityKind) -> bool {
        match self {
            Self::Listed => kind.is_listed(),
            Self::Patterned => kind.is_patterned(),
        }
    }
}

/// A matcher's delta is merged into its base once it holds more than a `DELTA_SHARE`-th of the
/// base's records, but not before it holds `MIN_DELTA`: a handful of records is not worth
/// rebuilding the base for.
const DELTA_SHARE: u64 = 8;
const MIN_DELTA: u64 = 64;
/// The delta is rebuilt on every growth, so it stays small however large the base is.
const MAX_DELTA: u64 = 4096;

/// The proxies of one [`Class`] a vault held when it had `records` records, as automata.
///
/// A vault that grows by a few records at a time would otherwise have its automaton rebuilt over
/// everything on every restore. So the automata are two: `base`, over the first `base_records`
/// records and rebuilt rarely, and a small one over the records since, rebuilt as it grows.
/// `current` is both. All of it is only good for the vault's `generation`: when the records are
/// replaced (see [`VaultView::generation`]) they are not a prefix of the new ones any more.
#[derive(Debug)]
struct Matcher {
    generation: u64,
    records: u64,
    base_records: u64,
    base: Arc<IssuedProxies>,
    current: Arc<IssuedProxies>,
}

/// A value of a kind, as it stands in a text.
type Value<'t> = (EntityKind, &'t str);

/// Stand-ins a client already received, which it may send back as they are (a chat client
/// resends its history); see [`Engine::anonymize`].
#[derive(Clone, Copy)]
pub enum Resent<'a> {
    /// None: text equal to a listed stand-in is masked as a value of its own.
    None,
    /// Every stand-in the vault issued.
    All,
    /// The stand-ins this says yes to, e.g. the ones sent to the same site.
    These(&'a (dyn Fn(&str) -> bool + Sync)),
}

impl Resent<'_> {
    fn contains(&self, stand_in: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::These(sent) => sent(stand_in),
        }
    }
}

impl std::fmt::Debug for Resent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::All => "All",
            Self::These(_) => "These(..)",
        })
    }
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

    /// Opens the vault with the regex detector followed by the detection
    /// `model`, which fills in what no pattern finds (names, addresses, ...).
    ///
    /// # Errors
    /// Vault open failures. A model that cannot load is not an error here: it
    /// loads on first use and finds nothing when it fails.
    pub fn open_with_model(vault_path: &Path, model: NerDetector) -> Result<Self> {
        let detector = CompositeDetector(vec![Box::new(RegexDetector::new()?), Box::new(model)]);
        Ok(Self::new(Box::new(detector), Vault::open(vault_path)?))
    }

    /// An engine that masks every kind its detector finds, until [`Engine::set_enabled`] says
    /// otherwise.
    #[must_use]
    pub fn new(detector: Box<dyn Detector>, vault: Vault) -> Self {
        Self {
            detector,
            vault,
            listed: RwLock::new(None),
            patterned: RwLock::new(None),
            enabled: AtomicU64::new(KindSet::ALL.bits()),
        }
    }

    /// The vault behind the engine.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Sets the kinds Anonymize masks; values of any other kind stay in the text. It applies to
    /// the plans made from now on. Deanonymize always restores every kind: a proxy issued while
    /// its kind was on must still come back after the kind is turned off.
    pub fn set_enabled(&self, kinds: KindSet) {
        self.enabled.store(kinds.bits(), Ordering::Relaxed);
    }

    /// The kinds Anonymize masks, see [`Engine::set_enabled`].
    #[must_use]
    pub fn enabled(&self) -> KindSet {
        KindSet::from_bits(self.enabled.load(Ordering::Relaxed))
    }

    /// Replacements per text, sorted and non-overlapping.
    ///
    /// Anonymize issues new proxies in one vault write, and does what it can so that
    /// deanonymizing the result gives the input back exactly:
    ///
    /// - A new proxy of a listed kind (a name, an address, a year, ...) equals no word, number
    ///   or phrase of the text the output keeps. Such a proxy has no watermark and is found by
    ///   its text alone, so one that read like text the output keeps would turn that text into
    ///   the value it stands for. The proxies of the other kinds carry the watermark, which
    ///   ordinary text does not.
    /// - Text equal to a stand-in of a listed kind issued earlier is masked like a value of
    ///   that kind, and gets a proxy of its own: a year or a name that is just what piikey once
    ///   gave out for another value would otherwise come back as that value. This holds for
    ///   every kind, enabled or not. When it is not ordinary text but a stand-in the client
    ///   received and sends back (a chat history), pass it in [`Resent`] to
    ///   [`Engine::anonymize`]: it then goes out as it is, and so does any detected span over
    ///   it, so stand-ins never chain. Text with no proxy left for it stays as it is.
    /// - A value that is a proxy of a patterned kind is one piikey sent before: it is left
    ///   alone, so anonymizing a masked text of those kinds changes nothing.
    ///
    /// Deanonymize restores every proxy the vault issued, of any kind, by looking for the
    /// proxies themselves. A text a service wrote that happens to equal a proxy is restored
    /// like the proxy: nothing tells them apart.
    ///
    /// # Errors
    /// Vault failures.
    pub fn plan(&self, mode: Mode, texts: &[&str]) -> Result<Vec<Vec<Replacement>>> {
        match mode {
            Mode::Anonymize => self.anonymize(texts, Resent::None),
            Mode::Deanonymize => {
                let spans = self.detector.detect_batch(texts, mode, KindSet::ALL, &[]);
                self.plan_deanonymize(texts, &spans)
            }
        }
    }

    /// [`Engine::plan`] for [`Mode::Anonymize`], where the stand-ins in `resent` are ones the
    /// client already received: a chat client resends its history, which carries them. Those
    /// go out as they are, so a reply that names one restores to the value in one step. Text
    /// equal to any other listed stand-in is masked as a value of its own, as `plan` does.
    ///
    /// # Errors
    /// Vault failures.
    pub fn anonymize(&self, texts: &[&str], resent: Resent<'_>) -> Result<Vec<Vec<Replacement>>> {
        let (wanted, spans) = self.detect_wanted(texts);
        self.plan_anonymize(texts, spans, !wanted.is_empty(), resent)
    }

    /// What the detector finds in `texts` of the kinds [`Engine::enabled`] says, with the
    /// kinds. A detector may skip the kinds nobody wants, but need not: what it reports of them
    /// stays in the text.
    fn detect_wanted(&self, texts: &[&str]) -> (KindSet, Vec<Vec<Span>>) {
        let wanted = self.enabled();
        let mut spans = self
            .detector
            .detect_batch(texts, Mode::Anonymize, wanted, &[]);
        if wanted != KindSet::ALL {
            for found in &mut spans {
                found.retain(|s| wanted.contains(s.kind));
            }
        }
        (wanted, spans)
    }

    /// What the detector finds in each of `texts`, as spans sorted by start and never
    /// overlapping: the values [`Engine::anonymize`] would mask, without masking anything.
    ///
    /// Nothing is issued or resolved, so the vault is exactly as it was. A span whose text is a
    /// stand-in the vault issued is left out: a text piikey masked scans as clean, and a scan
    /// never counts piikey's own output as personal data. The kinds are the ones
    /// [`Engine::enabled`] says.
    ///
    /// # Errors
    /// `Poisoned`.
    pub fn scan(&self, texts: &[&str]) -> Result<Vec<Vec<Span>>> {
        let (_, mut spans) = self.detect_wanted(texts);
        // Hash lookups, sequential and short: see `plan_anonymize` on holding the view.
        let view = self.vault.read()?;
        for (text, found) in texts.iter().zip(&mut spans) {
            found.retain(|s| view.kind_of(&text[s.start..s.end]).is_none());
        }
        Ok(spans)
    }

    /// [`Engine::scan`] in steps: `step` is handed what the detector finds as it finds it, with
    /// what a scan leaves out (the kinds that are off, the stand-ins the vault issued) left out
    /// of it. The patterns come first and the model after, a group of texts at a time (see
    /// [`Detector::detect_batch_steps`]), so a caller can show the first values while the model
    /// still reads. Everything the steps hold together is what `scan` returns, as a sum and not
    /// in order. `step` ends the scan by breaking. The vault is only read for the length of one
    /// step, never while the model runs.
    ///
    /// # Errors
    /// `Poisoned`.
    pub fn scan_steps(
        &self,
        texts: &[&str],
        mut step: impl FnMut(Step) -> ControlFlow<()>,
    ) -> Result<()> {
        let wanted = self.enabled();
        let mut failure = None;
        self.detector
            .detect_batch_steps(texts, Mode::Anonymize, wanted, &[], &mut |mut found| {
                if wanted != KindSet::ALL {
                    for spans in &mut found.spans {
                        spans.retain(|s| wanted.contains(s.kind));
                    }
                }
                match self.vault.read() {
                    Ok(view) => {
                        for (text, spans) in texts.iter().zip(&mut found.spans) {
                            spans.retain(|s| view.kind_of(&text[s.start..s.end]).is_none());
                        }
                    }
                    Err(error) => {
                        failure = Some(error);
                        return ControlFlow::Break(());
                    }
                }
                step(found)
            });
        failure.map_or(Ok(()), Err)
    }

    /// The stand-ins the vault issued that each of `texts` holds, as spans sorted by start and
    /// never overlapping, found by exact whole-word lookup of the stand-ins themselves: where
    /// [`Mode::Deanonymize`] would put the originals back, without running the detector, so for
    /// a caller that only wants to know which stand-ins a text holds (the app notes the ones it
    /// sends) this costs a fraction of `plan`.
    ///
    /// # Errors
    /// `Poisoned`.
    pub fn proxies_in(&self, texts: &[&str]) -> Result<Vec<Vec<Span>>> {
        let listed = self.matcher(Class::Listed)?;
        let patterned = self.matcher(Class::Patterned)?;
        let issued = listed.union(&patterned);
        Ok(texts.par_iter().map(|text| issued.spans(text)).collect())
    }

    /// `masking`: some kind is on. With none on, the text is left exactly as it is.
    fn plan_anonymize(
        &self,
        texts: &[&str],
        found: Vec<Vec<Span>>,
        masking: bool,
        resent: Resent<'_>,
    ) -> Result<Vec<Vec<Replacement>>> {
        let (spans, optional) = self.with_lookalikes(texts, found, masking, resent)?;
        let (missing, optional_missing, kept) = {
            let view = self.vault.read()?;
            // Only the proxies of the listed kinds have to stay clear of what is kept.
            let keeping = spans.iter().flatten().any(|s| !s.kind.is_patterned());
            let mut seen = HashSet::new();
            let mut missing: Vec<(EntityKind, Box<str>)> = Vec::new();
            let mut optional_missing: Vec<(EntityKind, Box<str>)> = Vec::new();
            let mut kept: Vec<&str> = Vec::new();
            for (text, in_text) in texts.iter().copied().zip(&spans) {
                let mut from = 0;
                for s in in_text {
                    let value = &text[s.start..s.end];
                    let known = view.proxy_for(s.kind, value).is_some();
                    // A value that is a stand-in of a patterned kind (even one found as another
                    // kind, a bare SSN proxy read as a phone number without its keyword), or a
                    // resent one, was sent before: it stays, and counts as text the output keeps.
                    if !known
                        && view
                            .kind_of(value)
                            .is_some_and(|kind| kind.is_patterned() || resent.contains(value))
                    {
                        continue;
                    }
                    if keeping {
                        if s.start > from {
                            kept.push(&text[from..s.start]);
                        }
                        from = s.end;
                    }
                    if !known && seen.insert((s.kind, value)) {
                        let wanted = (s.kind, Box::from(value));
                        if optional.contains(&(s.kind, value)) {
                            optional_missing.push(wanted);
                        } else {
                            missing.push(wanted);
                        }
                    }
                }
                if keeping && from < text.len() {
                    kept.push(&text[from..]);
                }
            }
            (missing, optional_missing, kept)
        };
        if !missing.is_empty() || !optional_missing.is_empty() {
            let words = missing
                .iter()
                .chain(&optional_missing)
                .any(|(kind, _)| !kind.is_patterned())
                .then(|| Words::new(kept));
            let avoid = |kind: EntityKind, candidate: &str| {
                !kind.is_patterned() && words.as_ref().is_some_and(|w| w.contains(candidate))
            };
            issue(&self.vault, missing, optional_missing, &avoid)?;
        }
        // Never hold a VaultView across rayon work: a worker blocked in a
        // par_iter may run another queued engine call on this thread, which
        // would wait on the vault lock we hold. Hash lookups are cheap.
        let view = self.vault.read()?;
        Ok(texts
            .iter()
            .zip(&spans)
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

    /// `found` without the spans that overlap a resent listed stand-in (those stay as they
    /// are), plus a span for each other listed stand-in that stands alone where no span covers
    /// it: text that reads like an earlier stand-in, which is masked as a value of its own.
    /// Also the values only those extra spans need a proxy for.
    fn with_lookalikes<'t>(
        &self,
        texts: &[&'t str],
        found: Vec<Vec<Span>>,
        masking: bool,
        resent: Resent<'_>,
    ) -> Result<(Vec<Vec<Span>>, HashSet<Value<'t>>)> {
        if !masking {
            return Ok((found, HashSet::new()));
        }
        let issued = self.matcher(Class::Listed)?;
        if issued.is_empty() {
            return Ok((found, HashSet::new()));
        }
        let (spans, extras): (Vec<Vec<Span>>, Vec<Vec<Span>>) = texts
            .par_iter()
            .zip(found)
            .map(|(text, mut spans)| {
                let (kept, others): (Vec<Span>, Vec<Span>) = issued
                    .spans(text)
                    .into_iter()
                    .partition(|s| resent.contains(&text[s.start..s.end]));
                spans.retain(|s| !overlaps(&kept, s));
                let extra = others
                    .into_iter()
                    .filter(|s| !overlaps(&spans, s))
                    .collect();
                (spans, extra)
            })
            .unzip();
        // A value that something else needs a proxy for as well is not optional.
        let mut only_lookalikes: HashSet<Value<'t>> = texts
            .iter()
            .copied()
            .zip(&extras)
            .flat_map(|(text, spans)| spans.iter().map(move |s| (s.kind, &text[s.start..s.end])))
            .collect();
        for (text, spans) in texts.iter().copied().zip(&spans) {
            for s in spans {
                only_lookalikes.remove(&(s.kind, &text[s.start..s.end]));
            }
        }
        let spans = spans
            .into_iter()
            .zip(extras)
            .map(|(mut spans, extra)| {
                if !extra.is_empty() {
                    spans.extend(extra);
                    spans.sort_by_key(|s| s.start);
                }
                spans
            })
            .collect();
        Ok((spans, only_lookalikes))
    }

    fn plan_deanonymize(
        &self,
        texts: &[&str],
        spans: &[Vec<Span>],
    ) -> Result<Vec<Vec<Replacement>>> {
        // Watermark checks (hashing) and the search for proxies run in parallel without the
        // lock; vault lookups run sequentially under it (see plan_anonymize).
        let keys = self.vault.proxy_keys();
        let listed = self.matcher(Class::Listed)?;
        let patterned = self.matcher(Class::Patterned)?;
        let issued = listed.union(&patterned);
        let found: Vec<(Vec<Span>, Vec<Span>)> = texts
            .par_iter()
            .zip(spans)
            .map(|(t, ss)| {
                // The regexes find a proxy of a patterned kind by its shape and watermark.
                // A detector's spans of listed kinds are values as the user wrote them, never
                // proxies.
                let marked = ss
                    .iter()
                    .filter(|s| {
                        !s.kind.is_listed() && watermark_ok(keys, s.kind, &t[s.start..s.end])
                    })
                    .copied()
                    .collect();
                // The proxies themselves are found wherever they stand, which the regexes do
                // not promise: a shape they have no pattern for, or a longer match that
                // starts earlier hides the proxy from them.
                (marked, issued.spans(t))
            })
            .collect();
        let view = self.vault.read()?;
        Ok(texts
            .iter()
            .zip(&found)
            .map(|(t, (marked, issued))| {
                let reps = restorations(&view, t, marked);
                if issued.is_empty() {
                    reps
                } else {
                    merge(reps, restorations(&view, t, issued))
                }
            })
            .collect())
    }

    /// The matcher for the vault's proxies of `class`, as of now: it is rebuilt when the vault
    /// has grown since it was, and only as far as the growth makes necessary, see [`Matcher`],
    /// or from scratch when the vault's records were replaced.
    fn matcher(&self, class: Class) -> Result<Arc<IssuedProxies>> {
        let cache = match class {
            Class::Listed => &self.listed,
            Class::Patterned => &self.patterned,
        };
        let view = self.vault.read()?;
        let records = view.record_count();
        let generation = view.generation();
        let (base_records, base) = match cache.read()?.as_ref() {
            Some(cached) if cached.generation == generation => {
                if cached.records == records {
                    return Ok(Arc::clone(&cached.current));
                }
                (cached.base_records, Arc::clone(&cached.base))
            }
            // None, or built for records the vault does not hold anymore.
            _ => (0, Arc::default()),
        };
        let issued_since = |from| -> Vec<(EntityKind, &str)> {
            view.issued_since(from)
                .filter(|&(kind, _)| class.holds(kind))
                .collect()
        };
        let delta_cap = (base_records / DELTA_SHARE).clamp(MIN_DELTA, MAX_DELTA);
        let (base_records, base, current) = if records.saturating_sub(base_records) <= delta_cap {
            let current = Arc::new(base.plus(&issued_since(base_records))?);
            (base_records, base, current)
        } else {
            let all = Arc::new(IssuedProxies::new(&issued_since(0))?);
            (records, Arc::clone(&all), all)
        };
        // A concurrent call may have stored a newer matcher already; keep that one.
        let mut cached = cache.write()?;
        if cached
            .as_ref()
            .is_none_or(|m| (m.generation, m.records) < (generation, records))
        {
            *cached = Some(Matcher {
                generation,
                records,
                base_records,
                base,
                current: Arc::clone(&current),
            });
        }
        Ok(current)
    }

    /// Forgets the automata over the vault's issued proxies, so the next call builds them
    /// again from the vault as it is then. [`Engine::forget`] and [`Engine::wipe`] do this. The
    /// automata notice by themselves when the vault's records were replaced (see
    /// [`VaultView::generation`]), so it frees them early rather than making them right.
    fn reset_issued(&self) {
        // Clearing is valid whatever a panicking thread left behind.
        for cache in [&self.listed, &self.patterned] {
            *cache.write().unwrap_or_else(PoisonError::into_inner) = None;
        }
    }

    /// Forgets the vault's records of `values`: every record whose original or stand-in is one
    /// of them. The file is rewritten without them, and a stand-in that was issued for one is
    /// ordinary text again, which [`Mode::Deanonymize`] leaves as it is. Returns how many
    /// records there were.
    ///
    /// # Errors
    /// Vault failures.
    pub fn forget(&self, values: &[&str]) -> Result<usize> {
        let wanted: HashSet<&str> = values.iter().copied().collect();
        let forgotten = self
            .vault
            .forget(&|_, original, proxy| wanted.contains(original) || wanted.contains(proxy));
        // Also when it failed: the vault may have taken over another process's forget on its way.
        self.reset_issued();
        forgotten
    }

    /// Forgets every record of the vault, see [`Engine::forget`]. The vault keeps its key.
    ///
    /// # Errors
    /// Vault failures.
    pub fn wipe(&self) -> Result<usize> {
        let wiped = self.vault.wipe();
        self.reset_issued();
        wiped
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

/// Issues proxies for the `required` values, and for each of the `optional` ones that a proxy is
/// left for. A proxy equals nothing `avoid` turns down, see [`Vault::resolve`].
///
/// # Errors
/// Vault failures, and no proxy left for a required value.
fn issue(
    vault: &Vault,
    required: Vec<(EntityKind, Box<str>)>,
    optional: Vec<(EntityKind, Box<str>)>,
    avoid: &dyn Fn(EntityKind, &str) -> bool,
) -> Result<()> {
    if optional.is_empty() {
        return vault.resolve(required, avoid);
    }
    let all = required.iter().chain(&optional).cloned().collect();
    match vault.resolve(all, avoid) {
        // Text that only reads like an earlier proxy is masked when a proxy is left for it, and
        // stays as it is otherwise: that must not fail the request.
        Err(Error::ProxyExhausted { .. }) => {
            vault.resolve(required, avoid)?;
            for value in optional {
                match vault.resolve(vec![value], avoid) {
                    Err(Error::ProxyExhausted { .. }) => {}
                    done => done?,
                }
            }
            Ok(())
        }
        done => done,
    }
}

/// A replacement for every span of `text` that is a proxy the vault issued.
fn restorations(view: &VaultView<'_>, text: &str, spans: &[Span]) -> Vec<Replacement> {
    spans
        .iter()
        .filter_map(|s| {
            view.original_for(&text[s.start..s.end])
                .map(|original| Replacement {
                    start: s.start,
                    end: s.end,
                    with: Box::from(original),
                })
        })
        .collect()
}

/// Two lists of sorted, non-overlapping replacements as one. Where two overlap, the one that
/// starts first wins, the longer one when they start together, and `first` when they are
/// equal.
fn merge(first: Vec<Replacement>, second: Vec<Replacement>) -> Vec<Replacement> {
    let mut first = first.into_iter().peekable();
    let mut second = second.into_iter().peekable();
    let mut merged: Vec<Replacement> = Vec::new();
    loop {
        let next = match (first.peek(), second.peek()) {
            (Some(a), Some(b)) if (b.start, Reverse(b.end)) < (a.start, Reverse(a.end)) => {
                second.next()
            }
            (Some(_), _) => first.next(),
            (None, Some(_)) => second.next(),
            (None, None) => break,
        };
        if let Some(next) = next
            && merged.last().is_none_or(|last| last.end <= next.start)
        {
            merged.push(next);
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Reverse,
        collections::HashSet,
        fmt,
        ops::ControlFlow,
        path::{Path, PathBuf},
        sync::{Arc, Mutex, PoisonError},
    };

    use super::{Engine, Replacement, Resent, merge};
    use crate::{
        detect::{
            CompositeDetector, Detector, EntityKind, KindSet, Mode, RegexDetector, Span, Step,
        },
        proxy::{generate, watermark_ok},
        vault::Vault,
    };

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
        crate::testing::temp_dir(tag).join("vault.pkv")
    }

    /// Stands in for the detection model: reports each value it was given as its kind, in any
    /// ASCII case, wherever it stands alone. It reports in both modes, so the tests also show
    /// that deanonymize leaves what a detector reports for a listed kind alone.
    struct Finds(Vec<(String, EntityKind)>);

    // Hand-written, like the real detectors': the values are personal data.
    impl fmt::Debug for Finds {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Finds").finish_non_exhaustive()
        }
    }

    impl Finds {
        fn people(names: &[&str]) -> Self {
            Self(
                names
                    .iter()
                    .map(|&name| (name.to_owned(), EntityKind::Person))
                    .collect(),
            )
        }
    }

    impl Detector for Finds {
        fn detect(&self, text: &str, _mode: Mode) -> Vec<Span> {
            let lower = text.to_ascii_lowercase();
            let bytes = text.as_bytes();
            let mut spans = Vec::new();
            for (value, kind) in &self.0 {
                for (start, found) in lower.match_indices(&value.to_ascii_lowercase()) {
                    let end = start + found.len();
                    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
                    let after = bytes.get(end);
                    if !before.is_some_and(u8::is_ascii_alphanumeric)
                        && !after.is_some_and(u8::is_ascii_alphanumeric)
                    {
                        spans.push(Span {
                            start,
                            end,
                            kind: *kind,
                        });
                    }
                }
            }
            // Sorted, never overlapping: the leftmost wins, the longest of those that start
            // together.
            spans.sort_by_key(|s| (s.start, Reverse(s.end)));
            let mut taken = 0;
            spans.retain(|s| {
                let free = s.start >= taken;
                if free {
                    taken = s.end;
                }
                free
            });
            spans
        }
    }

    /// An engine on the vault at `path` that finds what the regexes find, and then what `finds`
    /// does. Where they overlap, the regex match wins.
    fn engine_at(path: &Path, finds: Finds) -> crate::Result<Engine> {
        let detector = CompositeDetector(vec![Box::new(RegexDetector::new()?), Box::new(finds)]);
        Ok(Engine::new(Box::new(detector), Vault::open(path)?))
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

    /// What `scan` found in `texts`, as `(kind, value)` per text.
    fn scanned<'t>(
        engine: &Engine,
        texts: &[&'t str],
    ) -> crate::Result<Vec<Vec<(EntityKind, &'t str)>>> {
        Ok(texts
            .iter()
            .zip(engine.scan(texts)?)
            .map(|(text, spans)| {
                spans
                    .into_iter()
                    .map(|s| (s.kind, &text[s.start..s.end]))
                    .collect()
            })
            .collect())
    }

    #[test]
    fn scan_reports_what_anonymize_masks_and_leaves_the_vault_alone() -> crate::Result<()> {
        let engine = engine_at(&temp_vault("scan"), Finds::people(&["Marieke de Vries"]))?;
        let texts = [
            CORPUS[2],
            "Marieke de Vries woont hier, mail marieke@example.org",
        ];
        let found = scanned(&engine, &texts)?;
        let values: HashSet<&str> = found.iter().flatten().map(|&(_, value)| value).collect();
        let expected = [
            "123-45-6789",
            "111222333",
            "+31 6 12345678",
            "jan.jansen@acme.nl",
            "Marieke de Vries",
            "marieke@example.org",
        ];
        for value in expected {
            assert!(values.contains(value), "{value:?} not found in {values:?}");
        }
        assert!(found[1].contains(&(EntityKind::Person, "Marieke de Vries")));
        assert_eq!(
            engine.vault().read()?.record_count(),
            0,
            "a scan issued something"
        );
        // Masking the same texts afterwards still hides every one of them, and now issues.
        let masked = engine.run(Mode::Anonymize, &texts)?;
        for value in expected {
            assert!(
                masked.iter().all(|out| !out.contains(value)),
                "{value:?} leaked into {masked:?}"
            );
        }
        assert!(engine.vault().read()?.record_count() > 0);
        Ok(())
    }

    #[test]
    fn scan_honours_the_enabled_kinds() -> crate::Result<()> {
        let engine = Engine::open(&temp_vault("scan-enabled"))?;
        let text = ["mail jan.jansen@acme.nl, IBAN NL91ABNA0417164300"];
        assert_eq!(scanned(&engine, &text)?[0].len(), 2);
        engine.set_enabled(KindSet::ALL.without(EntityKind::Email));
        assert_eq!(
            scanned(&engine, &text)?[0],
            [(EntityKind::Iban, "NL91ABNA0417164300")]
        );
        engine.set_enabled(KindSet::EMPTY);
        assert!(scanned(&engine, &text)?[0].is_empty());
        Ok(())
    }

    #[test]
    fn scan_ignores_the_stand_ins_the_vault_issued() -> crate::Result<()> {
        let engine = engine_at(
            &temp_vault("scan-proxies"),
            Finds::people(&["Marieke de Vries"]),
        )?;
        let originals = [
            CORPUS[2],
            "Marieke de Vries woont in Utrecht, mail marieke@example.org",
        ];
        let masked = engine.run(Mode::Anonymize, &originals)?;
        let masked: Vec<&str> = masked.iter().map(String::as_str).collect();
        let records = engine.vault().read()?.record_count();
        assert!(records > 0);
        for (text, found) in masked.iter().zip(scanned(&engine, &masked)?) {
            assert!(
                found.is_empty(),
                "{found:?} reported in the masked {text:?}"
            );
        }
        // What was masked is still reported where it stands in the clear.
        assert!(!scanned(&engine, &originals)?[0].is_empty());
        assert_eq!(engine.vault().read()?.record_count(), records);
        Ok(())
    }

    /// What `scan_steps` hands over for `texts`, until `stop_after` steps have come.
    fn stepped(engine: &Engine, texts: &[&str], stop_after: usize) -> crate::Result<Vec<Step>> {
        let mut steps = Vec::new();
        engine.scan_steps(texts, |step| {
            steps.push(step);
            if steps.len() >= stop_after {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;
        Ok(steps)
    }

    /// The values of the spans of `steps`, `(kind, value)`, per text and in order of position.
    fn step_values<'t>(steps: &[Step], texts: &[&'t str]) -> Vec<Vec<(EntityKind, &'t str)>> {
        texts
            .iter()
            .enumerate()
            .map(|(at, text)| {
                let mut spans: Vec<Span> = steps
                    .iter()
                    .flat_map(|step| step.spans[at].iter().copied())
                    .collect();
                spans.sort_by_key(|span| span.start);
                spans
                    .into_iter()
                    .map(|s| (s.kind, &text[s.start..s.end]))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn scan_in_steps_gives_the_patterns_first_and_the_rest_after_and_the_same_in_all()
    -> crate::Result<()> {
        let engine = engine_at(&temp_vault("steps"), Finds::people(&["Marieke de Vries"]))?;
        let texts = [
            CORPUS[2],
            "Marieke de Vries woont hier, mail marieke@example.org",
        ];
        let steps = stepped(&engine, &texts, usize::MAX)?;
        assert_eq!(steps.len(), 2, "the patterns, then the names");
        assert_eq!(steps[0].more, Some((0, 0)));
        assert_eq!(steps[1].more, None);
        assert!(
            steps[0]
                .spans
                .iter()
                .flatten()
                .all(|span| span.kind.is_patterned())
        );
        assert!(
            steps[1]
                .spans
                .iter()
                .flatten()
                .all(|span| span.kind == EntityKind::Person)
        );
        assert_eq!(step_values(&steps, &texts), scanned(&engine, &texts)?);
        assert_eq!(engine.vault().read()?.record_count(), 0);
        Ok(())
    }

    #[test]
    fn scan_in_steps_leaves_out_what_a_scan_leaves_out_and_stops_when_told() -> crate::Result<()> {
        let engine = engine_at(
            &temp_vault("steps-left-out"),
            Finds::people(&["Marieke de Vries"]),
        )?;
        let originals = ["Marieke de Vries woont in Utrecht, mail marieke@example.org"];
        // The kinds that are off.
        engine.set_enabled(KindSet::ALL.without(EntityKind::Email));
        let steps = stepped(&engine, &originals, usize::MAX)?;
        assert_eq!(
            step_values(&steps, &originals),
            [[(EntityKind::Person, "Marieke de Vries")]]
        );
        engine.set_enabled(KindSet::ALL);
        // The stand-ins the vault issued.
        let masked = engine.run(Mode::Anonymize, &originals)?;
        let masked: Vec<&str> = masked.iter().map(String::as_str).collect();
        let steps = stepped(&engine, &masked, usize::MAX)?;
        assert!(
            steps
                .iter()
                .all(|step| step.spans.iter().all(Vec::is_empty))
        );
        // A stop after the first step is the end of it.
        let steps = stepped(&engine, &originals, 1)?;
        assert_eq!(steps.len(), 1);
        Ok(())
    }

    #[test]
    fn reset_issued_drops_the_matchers_and_the_next_call_builds_them_again() -> crate::Result<()> {
        let engine = Engine::open(&temp_vault("reset-issued"))?;
        let anon = engine.run(Mode::Anonymize, &CORPUS)?;
        let refs: Vec<&str> = anon.iter().map(String::as_str).collect();
        assert_eq!(engine.run(Mode::Deanonymize, &refs)?, CORPUS);
        assert!(engine.listed.read()?.is_some() && engine.patterned.read()?.is_some());
        engine.reset_issued();
        assert!(engine.listed.read()?.is_none() && engine.patterned.read()?.is_none());
        assert_eq!(
            engine.run(Mode::Deanonymize, &refs)?,
            CORPUS,
            "built from the vault"
        );
        Ok(())
    }

    #[test]
    fn forget_and_wipe_remove_records_and_their_stand_ins_stop_being_restored() -> crate::Result<()>
    {
        let engine = engine_at(&temp_vault("forget"), Finds::people(&["Marieke de Vries"]))?;
        let originals = [CORPUS[2], "Marieke de Vries woont hier"];
        let masked = engine.run(Mode::Anonymize, &originals)?;
        let masked: Vec<&str> = masked.iter().map(String::as_str).collect();
        assert_eq!(engine.run(Mode::Deanonymize, &masked)?, originals);
        assert!(engine.listed.read()?.is_some() && engine.patterned.read()?.is_some());
        let records = engine.vault().read()?.record_count();
        let stand_in = |kind, original: &str| -> crate::Result<String> {
            let found = engine
                .vault()
                .read()?
                .proxy_for(kind, original)
                .map(str::to_owned);
            found.ok_or_else(|| crate::Error::BadRequest(format!("no stand-in for {original}")))
        };

        // By original: the email comes back as its stand-in, the rest of the text is restored.
        let email = stand_in(EntityKind::Email, "jan.jansen@acme.nl")?;
        assert_eq!(engine.forget(&["jan.jansen@acme.nl"])?, 1);
        assert!(engine.listed.read()?.is_none() && engine.patterned.read()?.is_none());
        assert_eq!(engine.vault().read()?.record_count(), records - 1);
        let restored = engine.run(Mode::Deanonymize, &masked)?;
        assert_eq!(restored[0], CORPUS[2].replace("jan.jansen@acme.nl", &email));
        assert_eq!(restored[1], originals[1]);

        // By stand-in: the name goes the same way.
        let name = stand_in(EntityKind::Person, "Marieke de Vries")?;
        assert_eq!(engine.forget(&[name.as_str()])?, 1);
        assert_eq!(engine.run(Mode::Deanonymize, &masked)?[1], masked[1]);

        assert_eq!(engine.forget(&["nobody@example.org"])?, 0);
        assert_eq!(engine.forget(&[])?, 0);

        // Everything.
        assert_eq!(u64::try_from(engine.wipe()?).ok(), Some(records - 2));
        assert_eq!(engine.vault().read()?.record_count(), 0);
        assert_eq!(engine.run(Mode::Deanonymize, &masked)?, masked);
        Ok(())
    }

    #[test]
    fn a_forget_in_another_instance_does_not_leave_stale_matchers_behind() -> crate::Result<()> {
        // Two engines on one vault file, as two processes are. `b` forgets one of three records
        // `a` issued, and `a` then issues a fourth: it holds three records again, but not the
        // ones its matchers were built for.
        let path = temp_vault("forget-elsewhere");
        let names = [
            "Marieke de Vries",
            "Pieter van der Berg",
            "Sanne de Boer",
            "Fatima El Amrani",
        ];
        let a = engine_at(&path, Finds::people(&names))?;
        let b = engine_at(&path, Finds::people(&names))?;
        let first = a.run(Mode::Anonymize, &names[..3])?;
        let first: Vec<&str> = first.iter().map(String::as_str).collect();
        assert_eq!(a.run(Mode::Deanonymize, &first)?, names[..3]);

        assert_eq!(b.forget(&[names[0]])?, 1);
        let fourth = a.run(Mode::Anonymize, &names[3..])?;
        assert_eq!(a.vault().read()?.record_count(), 3);
        let fourth: Vec<&str> = fourth.iter().map(String::as_str).collect();
        assert_eq!(a.run(Mode::Deanonymize, &fourth)?, names[3..]);
        assert_eq!(a.run(Mode::Deanonymize, &first[1..])?, names[1..3]);
        assert_eq!(a.run(Mode::Deanonymize, &first[..1])?, first[..1]);
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

    fn rep(start: usize, end: usize, with: &str) -> Replacement {
        Replacement {
            start,
            end,
            with: with.into(),
        }
    }

    #[test]
    fn merge_keeps_the_earlier_start_then_the_longer_replacement() {
        let first = vec![rep(0, 4, "a"), rep(10, 12, "b"), rep(20, 25, "c")];
        let second = vec![rep(3, 8, "x"), rep(10, 15, "y"), rep(26, 28, "z")];
        // [0, 4) starts before [3, 8); [10, 15) is longer than [10, 12); the rest is free.
        assert_eq!(
            merge(first, second),
            [
                rep(0, 4, "a"),
                rep(10, 15, "y"),
                rep(20, 25, "c"),
                rep(26, 28, "z")
            ]
        );
        // Equal spans: the first list wins. Touching spans do not overlap.
        assert_eq!(
            merge(vec![rep(0, 5, "a")], vec![rep(0, 5, "b")]),
            [rep(0, 5, "a")]
        );
        assert_eq!(
            merge(vec![rep(0, 5, "a")], vec![rep(5, 8, "b")]),
            [rep(0, 5, "a"), rep(5, 8, "b")]
        );
        assert_eq!(merge(vec![], vec![rep(1, 2, "b")]), [rep(1, 2, "b")]);
        assert_eq!(merge(vec![rep(1, 2, "a")], vec![]), [rep(1, 2, "a")]);
        assert!(merge(vec![], vec![]).is_empty());
    }

    #[test]
    fn merge_equals_a_greedy_pass_over_both_lists_sorted_together() {
        // Random sorted, disjoint lists against the plain definition: sort everything by
        // start, then longest first, then list, and keep what does not overlap what was kept.
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let list = |tag: &str, next: &mut dyn FnMut(u64) -> u64| {
            let mut at = 0;
            let mut reps = Vec::new();
            for i in 0..8 {
                at += usize::try_from(next(6)).unwrap_or(0);
                let len = 1 + usize::try_from(next(6)).unwrap_or(0);
                reps.push(rep(at, at + len, &format!("{tag}{i}")));
                at += len;
            }
            reps
        };
        for _ in 0..500 {
            let (a, b) = (list("a", &mut next), list("b", &mut next));
            let mut all: Vec<(usize, Reverse<usize>, usize, Replacement)> = a
                .iter()
                .map(|r| (r.start, Reverse(r.end), 0, r.clone()))
                .chain(b.iter().map(|r| (r.start, Reverse(r.end), 1, r.clone())))
                .collect();
            all.sort_by(|x, y| (x.0, &x.1, x.2).cmp(&(y.0, &y.1, y.2)));
            let mut expected: Vec<Replacement> = Vec::new();
            for (.., r) in all {
                if expected.last().is_none_or(|last| last.end <= r.start) {
                    expected.push(r);
                }
            }
            assert_eq!(merge(a.clone(), b.clone()), expected, "{a:?} + {b:?}");
        }
    }

    #[test]
    fn a_found_name_becomes_a_name_of_the_same_shape_and_comes_back() -> crate::Result<()> {
        let path = temp_vault("names");
        let engine = engine_at(&path, Finds::people(&["Jeroen de Vries"]))?;
        let anon = engine.run(Mode::Anonymize, &["Call Jeroen de Vries"])?;
        let Some(name) = anon[0].strip_prefix("Call ") else {
            panic!("lost the text around the name: {:?}", anon[0]);
        };
        let words: Vec<&str> = name.split(' ').collect();
        assert_eq!(words.len(), 3, "{name}");
        assert_eq!(words[1], "de", "{name}");
        // No word of the original is reused. A word of the proxy that merely contains one
        // (`Devries` has `vries`) is another word.
        assert!(
            anon[0]
                .split(|c: char| !c.is_alphabetic())
                .all(|word| !["jeroen", "vries"].contains(&word.to_lowercase().as_str())),
            "{name}"
        );

        let refs = [anon[0].as_str()];
        assert_eq!(
            engine.run(Mode::Deanonymize, &refs)?,
            ["Call Jeroen de Vries"]
        );
        // The plan says where each proxy sits, which is what the app records.
        let plans = engine.plan(Mode::Deanonymize, &refs)?;
        let [rep] = plans[0].as_slice() else {
            panic!("expected one replacement: {:?}", plans[0]);
        };
        assert_eq!(&anon[0][rep.start..rep.end], name);
        assert_eq!(&*rep.with, "Jeroen de Vries");
        // The vault is enough: an engine that finds no names restores them too.
        drop(engine);
        let plain = Engine::open(&path)?;
        assert_eq!(
            plain.run(Mode::Deanonymize, &refs)?,
            ["Call Jeroen de Vries"]
        );
        Ok(())
    }

    #[test]
    fn values_of_every_listed_kind_come_back_through_the_listed_matcher() -> crate::Result<()> {
        let finds = Finds(vec![
            ("Jeroen de Vries".to_owned(), EntityKind::Person),
            (
                "Keizersgracht 123, 1015 CJ Amsterdam".to_owned(),
                EntityKind::PostalAddress,
            ),
            ("diabetes".to_owned(), EntityKind::HealthData),
        ]);
        let path = temp_vault("listed");
        let engine = engine_at(&path, finds)?;
        let text = "Mijn naam is Jeroen de Vries, ik woon op Keizersgracht 123, 1015 CJ Amsterdam \
                    en heb diabetes.";
        let anon = engine.run(Mode::Anonymize, &[text])?.remove(0);
        for leaked in ["Jeroen", "Vries", "Keizersgracht", "diabetes"] {
            assert!(!anon.contains(leaked), "{leaked} leaked into {anon:?}");
        }
        {
            // One record per value, each under its own kind.
            let view = engine.vault().read()?;
            for kind in [
                EntityKind::Person,
                EntityKind::PostalAddress,
                EntityKind::HealthData,
            ] {
                assert_eq!(view.proxies_of(kind).count(), 1, "{kind:?}");
            }
        }
        assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text]);
        // The vault is enough: an engine that finds none of these kinds restores them too.
        drop(engine);
        let plain = Engine::open(&path)?;
        assert_eq!(plain.run(Mode::Deanonymize, &[&anon])?, [text]);
        Ok(())
    }

    #[test]
    fn the_listed_matcher_follows_the_vault_as_it_grows() -> crate::Result<()> {
        let engine = engine_at(
            &temp_vault("grows"),
            Finds::people(&["Jeroen de Vries", "Haley Brooks"]),
        )?;
        // No proxy of a listed kind yet.
        assert_eq!(
            engine.run(Mode::Deanonymize, &["Haley Brooks"])?,
            ["Haley Brooks"]
        );
        let first = engine.run(Mode::Anonymize, &["Jeroen de Vries"])?.remove(0);
        assert_eq!(
            engine.run(Mode::Deanonymize, &[&first])?,
            ["Jeroen de Vries"]
        );
        // Another proxy changes the vault; the matcher has to learn it.
        let second = engine.run(Mode::Anonymize, &["Haley Brooks"])?.remove(0);
        assert_eq!(engine.run(Mode::Deanonymize, &[&second])?, ["Haley Brooks"]);
        assert_eq!(
            engine.run(Mode::Deanonymize, &[&first])?,
            ["Jeroen de Vries"]
        );
        Ok(())
    }

    #[test]
    fn only_whole_proxies_in_their_own_case_are_restored() -> crate::Result<()> {
        let engine = engine_at(&temp_vault("whole"), Finds::people(&["Jeroen de Vries"]))?;
        let proxy = engine.run(Mode::Anonymize, &["Jeroen de Vries"])?.remove(0);
        let lower = proxy.to_lowercase();
        let text = format!("{proxy}'s car, {proxy}s, x{proxy}, {lower}, ({proxy})");
        let expected =
            format!("Jeroen de Vries's car, {proxy}s, x{proxy}, {lower}, (Jeroen de Vries)");
        assert_eq!(engine.run(Mode::Deanonymize, &[&text])?, [expected]);
        Ok(())
    }

    #[test]
    fn found_names_in_a_response_are_left_alone() -> crate::Result<()> {
        let engine = engine_at(&temp_vault("alone"), Finds::people(&["Jeroen de Vries"]))?;
        let text = ["Jeroen de Vries called"];
        assert_eq!(engine.run(Mode::Deanonymize, &text)?, text);
        // With a proxy issued, the name itself is still not a proxy.
        engine.run(Mode::Anonymize, &text)?;
        assert_eq!(engine.run(Mode::Deanonymize, &text)?, text);
        Ok(())
    }

    #[test]
    fn a_name_inside_an_email_or_credential_does_not_cut_it_short() -> crate::Result<()> {
        let engine = engine_at(&temp_vault("inside"), Finds::people(&["Jan"]))?;
        let text = "Hi Jan, mail jan.jansen@acme.nl, db https://jan:hunter2@db.example.com/x";
        let anon = engine.run(Mode::Anonymize, &[text])?.remove(0);
        // The proxies are drawn from lists of names, so one may contain a word of the original
        // (`jansen`): what must not be left is the values around the name, and the text between
        // them must be.
        for leaked in ["jan.jansen@acme.nl", "acme.nl", "jan:hunter2", "hunter2"] {
            assert!(!anon.contains(leaked), "{leaked} leaked into {anon:?}");
        }
        assert!(
            anon.starts_with("Hi ")
                && !anon.starts_with("Hi Jan,")
                && anon.contains(", mail ")
                && anon.contains(", db https://")
                && anon.ends_with("@db.example.com/x"),
            "{anon:?}"
        );
        assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text]);
        Ok(())
    }

    #[test]
    fn a_kind_that_is_turned_off_stays_in_the_text_while_the_others_are_masked() -> crate::Result<()>
    {
        let engine = Engine::open(&temp_vault("off"))?;
        assert_eq!(engine.enabled(), KindSet::ALL);
        let text = "mail jan.jansen@acme.nl or call +31 6 12345678";

        let without_email = KindSet::ALL.without(EntityKind::Email);
        engine.set_enabled(without_email);
        assert_eq!(engine.enabled(), without_email);
        let anon = engine.run(Mode::Anonymize, &[text])?.remove(0);
        assert!(anon.contains("jan.jansen@acme.nl"), "{anon}");
        assert!(!anon.contains("+31 6 12345678"), "{anon}");

        // Turned back on, the same text is masked in full.
        engine.set_enabled(KindSet::ALL);
        let anon = engine.run(Mode::Anonymize, &[text])?.remove(0);
        assert!(!anon.contains("jan.jansen@acme.nl"), "{anon}");
        assert!(!anon.contains("+31 6 12345678"), "{anon}");
        Ok(())
    }

    #[test]
    fn nothing_is_masked_or_issued_when_every_kind_is_off() -> crate::Result<()> {
        let engine = Engine::open(&temp_vault("none"))?;
        engine.set_enabled(KindSet::EMPTY);
        assert_eq!(engine.run(Mode::Anonymize, &CORPUS)?, CORPUS);
        assert_eq!(engine.vault().read()?.record_count(), 0);
        Ok(())
    }

    #[test]
    fn a_proxy_of_a_kind_that_was_turned_off_is_still_restored() -> crate::Result<()> {
        let engine = Engine::open(&temp_vault("restore-off"))?;
        let text = "mail jan.jansen@acme.nl or call +31 6 12345678";
        let anon = engine.run(Mode::Anonymize, &[text])?.remove(0);
        engine.set_enabled(KindSet::EMPTY);
        assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text]);
        Ok(())
    }

    #[test]
    fn what_a_detector_finds_of_a_kind_that_is_turned_off_stays_in_the_text() -> crate::Result<()> {
        let engine = engine_at(
            &temp_vault("names-off"),
            Finds::people(&["Jeroen de Vries"]),
        )?;
        engine.set_enabled(KindSet::ALL.without(EntityKind::Person));
        let anon = engine
            .run(
                Mode::Anonymize,
                &["Jeroen de Vries mailt jan.jansen@acme.nl"],
            )?
            .remove(0);
        assert!(anon.starts_with("Jeroen de Vries mailt "), "{anon}");
        assert!(!anon.contains("jan.jansen"), "{anon}");
        // A proxy issued while names were on still comes back.
        engine.set_enabled(KindSet::ALL);
        let issued = engine.run(Mode::Anonymize, &["Jeroen de Vries"])?.remove(0);
        engine.set_enabled(KindSet::EMPTY);
        assert_eq!(
            engine.run(Mode::Deanonymize, &[&issued])?,
            ["Jeroen de Vries"]
        );
        Ok(())
    }

    /// Notes what the engine asks of its detector; finds nothing.
    #[derive(Debug)]
    struct Asked(Arc<Mutex<Vec<(Mode, KindSet, usize)>>>);

    impl Detector for Asked {
        fn detect(&self, _text: &str, _mode: Mode) -> Vec<Span> {
            Vec::new()
        }

        fn detect_batch(
            &self,
            texts: &[&str],
            mode: Mode,
            wanted: KindSet,
            taken: &[Vec<Span>],
        ) -> Vec<Vec<Span>> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((mode, wanted, taken.len()));
            vec![Vec::new(); texts.len()]
        }
    }

    #[test]
    fn the_detector_is_asked_for_the_enabled_kinds_to_mask_and_every_kind_to_restore()
    -> crate::Result<()> {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let engine = Engine::new(
            Box::new(Asked(Arc::clone(&asked))),
            Vault::open(&temp_vault("asked"))?,
        );
        let without_people = KindSet::ALL.without(EntityKind::Person);
        engine.set_enabled(without_people);
        engine.run(Mode::Anonymize, &["a", "b"])?;
        engine.run(Mode::Deanonymize, &["a", "b"])?;
        let asked = asked.lock().unwrap_or_else(PoisonError::into_inner);
        // One batch per call, with nothing taken yet.
        assert_eq!(
            *asked,
            [
                (Mode::Anonymize, without_people, 0),
                (Mode::Deanonymize, KindSet::ALL, 0)
            ]
        );
        Ok(())
    }

    /// The `i`-th of a series of distinct single-word names (`Zqaaaa`, `Zqbaaa`, ...).
    fn word(i: u32) -> String {
        let letters: String = (0..4)
            .map(|d| char::from(b'a' + u8::try_from(i / 26u32.pow(d) % 26).unwrap_or(0)))
            .collect();
        format!("Zq{letters}")
    }

    #[test]
    fn many_single_word_names_all_get_distinct_proxies() -> crate::Result<()> {
        // One list word per name would give out after about a dozen.
        let owned: Vec<String> = (0..150).map(word).collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        let engine = engine_at(&temp_vault("many"), Finds::people(&names))?;
        let text = names.join(", ");
        let anon = engine.run(Mode::Anonymize, &[&text])?.remove(0);
        for name in &names {
            assert!(!anon.contains(name), "{name} leaked");
        }
        let proxies: HashSet<&str> = anon.split(", ").collect();
        assert_eq!(proxies.len(), names.len());
        assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text]);
        Ok(())
    }

    #[test]
    fn threads_issuing_and_restoring_names_at_once_stay_consistent() -> crate::Result<()> {
        let owned: Vec<String> = (0..64).map(word).collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        let engine = engine_at(&temp_vault("race"), Finds::people(&names))?;
        let outcomes = std::thread::scope(|scope| {
            let workers: Vec<_> = owned
                .chunks(16)
                .map(|mine| {
                    let engine = &engine;
                    scope.spawn(move || -> crate::Result<()> {
                        for name in mine {
                            let text = format!("hello {name}!");
                            let anon = engine.run(Mode::Anonymize, &[&text])?.remove(0);
                            assert!(!anon.contains(name.as_str()), "{name} leaked");
                            assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text]);
                        }
                        Ok(())
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(std::thread::ScopedJoinHandle::join)
                .collect::<Vec<_>>()
        });
        for outcome in outcomes {
            let Ok(done) = outcome else {
                panic!("a worker thread panicked");
            };
            done?;
        }
        Ok(())
    }

    #[test]
    fn debug_output_hides_the_names() -> crate::Result<()> {
        let engine = engine_at(&temp_vault("debug"), Finds::people(&["Jeroen de Vries"]))?;
        let anon = engine.run(Mode::Anonymize, &["Jeroen de Vries"])?.remove(0);
        engine.run(Mode::Deanonymize, &[&anon])?;
        let shown = format!("{engine:?}");
        assert!(
            !shown.contains("Jeroen") && !shown.contains("Vries") && !shown.contains(&anon),
            "{shown}"
        );
        Ok(())
    }

    /// `(start, end)` of each of `texts`' stand-ins as a deanonymize plan restores them.
    fn restored_spans(engine: &Engine, texts: &[&str]) -> crate::Result<Vec<Vec<(usize, usize)>>> {
        let plans = engine.plan(Mode::Deanonymize, texts)?;
        Ok(plans
            .iter()
            .map(|reps| reps.iter().map(|r| (r.start, r.end)).collect())
            .collect())
    }

    /// `(start, end)` of each of `texts`' stand-ins as `proxies_in` finds them.
    fn held_spans(engine: &Engine, texts: &[&str]) -> crate::Result<Vec<Vec<(usize, usize)>>> {
        Ok(engine
            .proxies_in(texts)?
            .iter()
            .map(|spans| spans.iter().map(|s| (s.start, s.end)).collect())
            .collect())
    }

    #[test]
    fn proxies_in_finds_the_stand_ins_a_deanonymize_restores() -> crate::Result<()> {
        let finds = Finds(vec![
            ("Jeroen de Vries".to_owned(), EntityKind::Person),
            ("1968".to_owned(), EntityKind::DateOfBirth),
        ]);
        let engine = engine_at(&temp_vault("proxies-in"), finds)?;
        let masked = engine.run(Mode::Anonymize, &CORPUS)?;
        let mut stand_ins = engine.run(Mode::Anonymize, &["Jeroen de Vries", "1968"])?;
        let born = stand_ins.remove(1);
        let name = stand_ins.remove(0);
        let phone = engine.run(Mode::Anonymize, &[ORIGINALS[10]])?.remove(0);
        let mut texts: Vec<String> = masked;
        for stand_in in [&name, &born, &phone] {
            // Where a stand-in stands in real text: punctuation, possessives, glued to words.
            for shape in [
                "{}",
                "call {}, then",
                "({})",
                "{}'s car",
                "{} {}",
                "x{}",
                "{}x",
                "{}.{}",
            ] {
                texts.push(shape.replace("{}", stand_in));
            }
        }
        // The bare number and the SSN keyword: see `issued_proxies_survive_reanonymize_...`.
        texts.push("nothing issued in this text, 1234 or 12345678".to_owned());
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let held = held_spans(&engine, &refs)?;
        assert_eq!(held, restored_spans(&engine, &refs)?);
        assert!(
            held.iter().flatten().count() > 10,
            "the texts must hold stand-ins"
        );
        Ok(())
    }

    /// The first `n` proxies the vault would try for `original`, in order: the candidates that
    /// differ from it and carry the watermark where the kind needs one.
    fn candidates(engine: &Engine, kind: EntityKind, original: &str, n: usize) -> Vec<String> {
        let keys = engine.vault().proxy_keys();
        (0..4096)
            .map(|attempt| generate(keys, kind, original, attempt))
            .filter(|c| c != original && (!kind.is_watermarked() || watermark_ok(keys, kind, c)))
            .take(n)
            .collect()
    }

    #[test]
    fn a_proxy_never_equals_ordinary_text_of_its_batch() -> crate::Result<()> {
        // Ordinary text that no detector reports stays in the output. A proxy equal to it would
        // be restored there too, and the text would not come back as it went in.
        let born = Finds(vec![("1968".to_owned(), EntityKind::DateOfBirth)]);
        let engine = engine_at(&temp_vault("ordinary"), born)?;
        let likely = candidates(&engine, EntityKind::DateOfBirth, "1968", 3);
        assert_eq!(likely.len(), 3);
        // The text in the way is next to the value, or in another text of the batch.
        let texts = [
            format!("born 1968, but {} stays", likely[0]),
            format!("{} and {} too", likely[1], likely[2]),
        ];
        let refs = [texts[0].as_str(), texts[1].as_str()];
        let anon = engine.run(Mode::Anonymize, &refs)?;
        assert!(!anon[0].contains("1968"), "{}", anon[0]);
        assert_eq!(anon[1], texts[1], "nothing to mask there");
        let back = [anon[0].as_str(), anon[1].as_str()];
        assert_eq!(engine.run(Mode::Deanonymize, &back)?, texts);
        Ok(())
    }

    #[test]
    fn a_resent_history_keeps_its_stand_ins_and_the_reply_restores_in_one_step() -> crate::Result<()>
    {
        // The model finds the name in the first message, and in the resent history it finds
        // the stand-in as a name as well, the way it would any name.
        let path = temp_vault("resent");
        let proxy = {
            let probe = engine_at(&path, Finds(Vec::new()))?;
            candidates(&probe, EntityKind::Person, "Jeroen de Vries", 1).remove(0)
        };
        let engine = engine_at(&path, Finds::people(&["Jeroen de Vries", proxy.as_str()]))?;
        let first = engine
            .run(Mode::Anonymize, &["Mijn naam is Jeroen de Vries"])?
            .remove(0);
        assert_eq!(first, format!("Mijn naam is {proxy}"));
        // The client resends the history with the next message: the stand-in it received goes
        // out as it is.
        let history = format!("{first}\nMet welke letter start mijn naam?");
        let sent = |s: &str| s == proxy;
        let resent = engine.anonymize(&[&history], Resent::These(&sent))?;
        assert_eq!(resent, [Vec::<Replacement>::new()]);
        assert_eq!(
            engine.vault().read()?.record_count(),
            1,
            "no stand-in for a stand-in"
        );
        // The reply names the stand-in, and the user reads the name.
        let reply = format!("Je naam is {proxy}.");
        assert_eq!(
            engine.run(Mode::Deanonymize, &[&reply])?,
            ["Je naam is Jeroen de Vries."]
        );
        Ok(())
    }

    #[test]
    fn a_span_stretched_over_a_stand_in_leaves_it_alone() -> crate::Result<()> {
        let path = temp_vault("stretched");
        let proxy = {
            let probe = engine_at(&path, Finds(Vec::new()))?;
            candidates(&probe, EntityKind::Person, "Jeroen de Vries", 1).remove(0)
        };
        // A model that reads the stand-in with the word after it as one name.
        let stretched = format!("{proxy}mail");
        let engine = engine_at(
            &path,
            Finds::people(&["Jeroen de Vries", stretched.as_str()]),
        )?;
        engine.run(Mode::Anonymize, &["ik ben Jeroen de Vries"])?;
        let text = format!("ik ben {proxy} mail");
        assert_eq!(
            engine.anonymize(&[&text], Resent::All)?,
            [Vec::<Replacement>::new()]
        );
        assert_eq!(engine.vault().read()?.record_count(), 1);
        Ok(())
    }

    #[test]
    fn ordinary_text_equal_to_a_stand_in_not_resent_is_masked_and_comes_back() -> crate::Result<()>
    {
        let born = Finds(vec![("1968".to_owned(), EntityKind::DateOfBirth)]);
        let engine = engine_at(&temp_vault("lookalike-text"), born)?;
        let first = engine.run(Mode::Anonymize, &["born 1968"])?.remove(0);
        let Some(proxy) = first.strip_prefix("born ") else {
            panic!("lost the text around the value: {first:?}");
        };
        // A later request that happens to say what an earlier stand-in says, to a site that
        // was never sent it. No detector finds it.
        let text = format!("the book {proxy} sold well, as did {proxy}");
        let anon = engine.run(Mode::Anonymize, &[&text])?.remove(0);
        assert!(!anon.contains(proxy), "{anon}");
        assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text.as_str()]);
        assert_eq!(engine.run(Mode::Deanonymize, &[&first])?, ["born 1968"]);
        // Told that the site received that stand-in, it goes out as it is.
        assert_eq!(
            engine.anonymize(&[&text], Resent::All)?,
            [Vec::<Replacement>::new()]
        );
        Ok(())
    }

    #[test]
    fn a_proxy_the_regexes_cannot_read_still_comes_back() -> crate::Result<()> {
        // The model finds this as a phone number; no pattern describes its shape, so no regex
        // finds the stand-in again.
        let model = Finds(vec![("55-5555-5555".to_owned(), EntityKind::Phone)]);
        let path = temp_vault("unreadable");
        let engine = engine_at(&path, model)?;
        let text = "número de teléfono: 55-5555-5555, o jan.jansen@acme.nl.\n\nGracias";
        let anon = engine.run(Mode::Anonymize, &[text])?.remove(0);
        assert!(!anon.contains("55-5555-5555"), "{anon}");
        assert_eq!(engine.run(Mode::Deanonymize, &[&anon])?, [text]);
        // The vault is enough, and a masked text is not masked a second time.
        drop(engine);
        let plain = Engine::open(&path)?;
        assert_eq!(plain.run(Mode::Deanonymize, &[&anon])?, [text]);
        assert_eq!(plain.run(Mode::Anonymize, &[&anon])?, [anon]);
        Ok(())
    }

    #[test]
    fn a_proxy_that_a_longer_lookalike_hides_from_the_regexes_still_comes_back() -> crate::Result<()>
    {
        // `2022-002-555-561020-960` is a card number as far as its digits go (Luhn holds for
        // about one in ten), and it starts before the phone number inside it, so a scan for
        // the phone number never gets to see it.
        let engine = Engine::open(&temp_vault("hidden"))?;
        let texts: Vec<String> = (0..300u32)
            .map(|i| {
                let n = 100_000 + i * 37;
                format!(":64:2022-002-555-{n}-000\n:70:2022-002-555-{n}-000\n:71F:2022")
            })
            .collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let anon = engine.run(Mode::Anonymize, &refs)?;
        let back: Vec<&str> = anon.iter().map(String::as_str).collect();
        assert_eq!(engine.run(Mode::Deanonymize, &back)?, texts);
        Ok(())
    }

    #[test]
    fn the_matchers_follow_a_vault_that_grows_in_steps() -> crate::Result<()> {
        // Enough records for the base to be rebuilt several times, with the growth in between
        // served by a small automaton of its own.
        let owned: Vec<String> = (0..300).map(word).collect();
        let names: Vec<&str> = owned.iter().map(String::as_str).collect();
        let engine = engine_at(&temp_vault("steps"), Finds::people(&names))?;
        let mut masked: Vec<(String, String)> = Vec::new();
        let mut bases = HashSet::new();
        let mut with_delta = 0;
        for step in names.chunks(10) {
            let text = step.join(", ");
            let anon = engine.run(Mode::Anonymize, &[&text])?.remove(0);
            masked.push((text, anon));
            // Everything issued so far comes back, so the matcher is current after each step.
            for (text, anon) in &masked {
                assert_eq!(engine.run(Mode::Deanonymize, &[anon])?, [text.as_str()]);
            }
            let cached = engine.listed.read()?;
            let Some(matcher) = cached.as_ref() else {
                panic!("the matcher was not built");
            };
            bases.insert(matcher.base_records);
            with_delta += usize::from(matcher.base_records < matcher.records);
        }
        assert!(with_delta > 10, "{with_delta} steps had a delta");
        assert!(
            bases.len() >= 3,
            "the base was rebuilt {} times",
            bases.len()
        );
        Ok(())
    }

    #[test]
    fn random_batches_of_numbers_and_names_come_back_exactly() -> crate::Result<()> {
        // Kinds with small spaces of proxies (years, three-digit amounts), names, and the plain
        // numbers and words around them that the detector does not report: whatever the vault
        // has handed out before, a text must come back as it went in.
        let kinds = [EntityKind::DateOfBirth, EntityKind::FinancialAmount];
        let mut found: Vec<(String, EntityKind)> = Vec::new();
        found.extend((1950..1962).map(|y| (y.to_string(), kinds[0])));
        found.extend((200..212).map(|a| (a.to_string(), kinds[1])));
        found.extend((0..8).map(|i| (word(i), EntityKind::Person)));
        let engine = engine_at(&temp_vault("random"), Finds(found.clone()))?;

        let mut state = 0xA076_1D64_78BD_642F_u64;
        let mut below = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(n).unwrap_or(1)).unwrap_or(0)
        };
        for round in 0..16 {
            let texts: Vec<String> = (0..6)
                .map(|_| {
                    let tokens: Vec<String> = (0..2 + below(12))
                        .map(|_| match below(10) {
                            0..=2 => found[below(found.len())].0.clone(),
                            3..=5 => (1940 + below(70)).to_string(),
                            6..=7 => (150 + below(200)).to_string(),
                            8 => word(8 + u32::try_from(below(8)).unwrap_or(0)),
                            _ => ["and", "the", "in", "x-1", "(3)"][below(5)].to_owned(),
                        })
                        .collect();
                    tokens.join([" ", ", ", "\n", "; "][below(4)])
                })
                .collect();
            let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
            let anon = engine.run(Mode::Anonymize, &refs)?;
            let back: Vec<&str> = anon.iter().map(String::as_str).collect();
            assert_eq!(
                engine.run(Mode::Deanonymize, &back)?,
                texts,
                "round {round}"
            );
        }
        Ok(())
    }
}
