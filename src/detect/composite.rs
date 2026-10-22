//! Runs several detectors over the same texts; the earlier detector wins overlaps.

use std::ops::ControlFlow;

use rayon::prelude::*;

use super::{Detector, KindSet, Mode, Span, Step};

/// Detectors run in order, each over every text. A span that shares a byte with a span of an
/// earlier detector is dropped, so the order is the priority. The result is sorted by start and
/// never overlaps, as a [`Detector`] must return it.
///
/// A batch runs one detector at a time over all its texts, and tells each later detector which
/// spans the earlier ones kept (`taken`), so that it can skip text with nothing left for it. A
/// composite is the outermost detector: the `taken` it is called with is not used.
#[derive(Debug)]
pub struct CompositeDetector(pub Vec<Box<dyn Detector>>);

impl Detector for CompositeDetector {
    fn detect(&self, text: &str, mode: Mode) -> Vec<Span> {
        self.detect_batch(&[text], mode, KindSet::ALL, &[])
            .pop()
            .unwrap_or_default()
    }

    fn detect_batch(
        &self,
        texts: &[&str],
        mode: Mode,
        wanted: KindSet,
        _taken: &[Vec<Span>],
    ) -> Vec<Vec<Span>> {
        let mut members = self.0.iter();
        let Some(first) = members.next() else {
            return vec![Vec::new(); texts.len()];
        };
        let mut kept = first.detect_batch(texts, mode, wanted, &[]);
        for member in members {
            let found = member.detect_batch(texts, mode, wanted, &kept);
            kept.par_iter_mut()
                .zip(found)
                .for_each(|(mine, found)| claim(mine, found));
        }
        kept
    }

    /// One member after the other, as [`CompositeDetector::detect_batch`] runs them, each
    /// member's steps passed on with the spans an earlier member kept left out. A member that
    /// is not the last says that more follows, so a caller that shows the first step knows the
    /// model that comes after the patterns is still at work.
    fn detect_batch_steps(
        &self,
        texts: &[&str],
        mode: Mode,
        wanted: KindSet,
        _taken: &[Vec<Span>],
        step: &mut dyn FnMut(Step) -> ControlFlow<()>,
    ) {
        // What the members before the one at work have kept.
        let mut kept: Vec<Vec<Span>> = Vec::new();
        let last = self.0.len().saturating_sub(1);
        for (at, member) in self.0.iter().enumerate() {
            let mut added: Vec<Vec<Span>> = vec![Vec::new(); texts.len()];
            let mut stopped = false;
            member.detect_batch_steps(texts, mode, wanted, &kept, &mut |mut found| {
                if !kept.is_empty() {
                    for (own, claimed) in found.spans.iter_mut().zip(&kept) {
                        own.retain(|span| !overlaps(claimed, span));
                    }
                }
                for (all, new) in added.iter_mut().zip(&found.spans) {
                    all.extend_from_slice(new);
                }
                // Only the last member's last step is the last.
                if at < last && found.more.is_none() {
                    found.more = Some((0, 0));
                }
                let flow = step(found);
                stopped = flow.is_break();
                flow
            });
            if stopped {
                return;
            }
            if kept.is_empty() {
                kept = added;
            } else {
                for (all, new) in kept.iter_mut().zip(added) {
                    all.extend(new);
                    all.sort_by_key(|span| span.start);
                }
            }
        }
    }
}

/// Adds the spans of `found` that overlap none of `kept` to it. Both are sorted and disjoint,
/// and so is the result.
fn claim(kept: &mut Vec<Span>, found: Vec<Span>) {
    if kept.is_empty() {
        *kept = found;
        return;
    }
    let free: Vec<Span> = found
        .into_iter()
        .filter(|span| !overlaps(kept, span))
        .collect();
    if !free.is_empty() {
        kept.extend(free);
        // Two sorted runs: the sort merges them.
        kept.sort_by_key(|span| span.start);
    }
}

/// True when `span` shares a byte with a span of `kept`, which is sorted and
/// disjoint.
pub(crate) fn overlaps(kept: &[Span], span: &Span) -> bool {
    overlaps_bytes(kept, span.start, span.end)
}

/// True when the bytes `start..end` share a byte with a span of `kept`, which is sorted and
/// disjoint.
pub(crate) fn overlaps_bytes(kept: &[Span], start: usize, end: usize) -> bool {
    // Disjoint and sorted by start means sorted by end too: the first span
    // that ends after `start` is the only one that can overlap it.
    let next = kept.partition_point(|k| k.end <= start);
    kept.get(next).is_some_and(|k| k.start < end)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, PoisonError};

    use super::*;
    use crate::{
        Result,
        detect::{EntityKind, RegexDetector},
    };

    /// Reports the spans it was built with, whatever the text.
    #[derive(Debug)]
    struct Fixed(Vec<Span>);

    impl Detector for Fixed {
        fn detect(&self, _text: &str, _mode: Mode) -> Vec<Span> {
            self.0.clone()
        }
    }

    /// Reports `kind` for every run of ASCII digits, or of ASCII letters when `digits` is off.
    #[derive(Debug)]
    struct Runs {
        kind: EntityKind,
        digits: bool,
    }

    impl Detector for Runs {
        fn detect(&self, text: &str, _mode: Mode) -> Vec<Span> {
            let wanted = |b: u8| {
                if self.digits {
                    b.is_ascii_digit()
                } else {
                    b.is_ascii_alphabetic()
                }
            };
            let mut spans = Vec::new();
            let mut start = None;
            for (at, byte) in text.bytes().chain([b' ']).enumerate() {
                match (start, wanted(byte)) {
                    (None, true) => start = Some(at),
                    (Some(from), false) => {
                        spans.push(Span {
                            start: from,
                            end: at,
                            kind: self.kind,
                        });
                        start = None;
                    }
                    _ => {}
                }
            }
            spans
        }
    }

    /// What every `detect_batch` call of a [`Spy`] was given as `taken`.
    type Calls = Arc<Mutex<Vec<Vec<Vec<Span>>>>>;

    /// Reports the spans it was built with for every text, and notes the `taken` it is given.
    #[derive(Debug)]
    struct Spy {
        spans: Vec<Span>,
        calls: Calls,
    }

    impl Detector for Spy {
        fn detect(&self, _text: &str, _mode: Mode) -> Vec<Span> {
            self.spans.clone()
        }

        fn detect_batch(
            &self,
            texts: &[&str],
            _mode: Mode,
            _wanted: KindSet,
            taken: &[Vec<Span>],
        ) -> Vec<Vec<Span>> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(taken.to_vec());
            vec![self.spans.clone(); texts.len()]
        }
    }

    fn spy(spans: &[Span]) -> (Box<dyn Detector>, Calls) {
        let calls = Calls::default();
        let detector = Spy {
            spans: spans.to_vec(),
            calls: Arc::clone(&calls),
        };
        (Box::new(detector), calls)
    }

    fn seen(calls: &Calls) -> Vec<Vec<Vec<Span>>> {
        calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn span(start: usize, end: usize, kind: EntityKind) -> Span {
        Span { start, end, kind }
    }

    fn composite(parts: &[&[Span]]) -> CompositeDetector {
        CompositeDetector(
            parts
                .iter()
                .map(|spans| Box::new(Fixed(spans.to_vec())) as Box<dyn Detector>)
                .collect(),
        )
    }

    #[test]
    fn the_earlier_detector_wins_every_overlap() {
        use EntityKind::{Email, Person, Phone};
        let names = [span(0, 10, Person), span(30, 35, Person)];
        let regex = [span(5, 15, Phone), span(20, 25, Email), span(33, 40, Phone)];

        assert_eq!(
            composite(&[&names, &regex]).detect("", Mode::Anonymize),
            [
                span(0, 10, Person),
                span(20, 25, Email),
                span(30, 35, Person)
            ]
        );
        assert_eq!(
            composite(&[&regex, &names]).detect("", Mode::Anonymize),
            [span(5, 15, Phone), span(20, 25, Email), span(33, 40, Phone)]
        );
    }

    #[test]
    fn touching_spans_do_not_overlap_and_the_result_is_sorted() {
        use EntityKind::{Email, Person, Phone};
        let a = [span(10, 20, Person), span(40, 50, Person)];
        let b = [span(0, 10, Phone), span(20, 30, Email), span(50, 60, Phone)];
        assert_eq!(
            composite(&[&a, &b]).detect("", Mode::Deanonymize),
            [
                span(0, 10, Phone),
                span(10, 20, Person),
                span(20, 30, Email),
                span(40, 50, Person),
                span(50, 60, Phone),
            ]
        );
    }

    #[test]
    fn a_range_overlaps_the_kept_spans_it_shares_a_byte_with() {
        let kept = [
            span(5, 10, EntityKind::Person),
            span(20, 30, EntityKind::Person),
        ];
        for (start, end, shares) in [
            (0, 6, true),
            (9, 12, true),
            (22, 24, true),
            (0, 100, true),
            (0, 5, false),
            (10, 20, false),
            (30, 40, false),
        ] {
            let probe = span(start, end, EntityKind::Email);
            assert_eq!(overlaps(&kept, &probe), shares, "{start}..{end}");
            assert_eq!(overlaps_bytes(&kept, start, end), shares, "{start}..{end}");
        }
        assert!(!overlaps(&[], &span(0, 5, EntityKind::Email)));
    }

    #[test]
    fn a_span_inside_or_around_an_earlier_one_is_dropped() {
        use EntityKind::{Person, Phone};
        let first = [span(10, 20, Person)];
        let inside = [span(12, 15, Phone)];
        let around = [span(5, 30, Phone)];
        let both_sides = [span(0, 11, Phone), span(19, 25, Phone)];
        for later in [&inside[..], &around[..], &both_sides[..]] {
            assert_eq!(
                composite(&[&first, later]).detect("", Mode::Anonymize),
                first,
                "{later:?}"
            );
        }
    }

    #[test]
    fn three_detectors_rank_by_position_in_the_list() {
        use EntityKind::{Email, Person, Phone};
        let one = [span(0, 5, Person)];
        let two = [span(3, 8, Phone), span(10, 12, Phone)];
        let three = [span(7, 11, Email), span(20, 22, Email)];
        assert_eq!(
            composite(&[&one, &two, &three]).detect("", Mode::Anonymize),
            [span(0, 5, Person), span(10, 12, Phone), span(20, 22, Email)]
        );
    }

    #[test]
    fn nothing_to_merge_passes_through() {
        use EntityKind::Person;
        let spans = [span(1, 4, Person), span(6, 9, Person)];
        assert!(composite(&[]).detect("x", Mode::Anonymize).is_empty());
        assert_eq!(composite(&[&spans]).detect("x", Mode::Anonymize), spans);
        assert_eq!(
            composite(&[&[], &spans]).detect("x", Mode::Anonymize),
            spans
        );
        assert_eq!(
            composite(&[&spans, &[]]).detect("x", Mode::Anonymize),
            spans
        );
        assert!(
            composite(&[&[], &[]])
                .detect("x", Mode::Anonymize)
                .is_empty()
        );
    }

    #[test]
    fn a_batch_is_merged_text_by_text() {
        use EntityKind::{Person, Phone};
        let detector = CompositeDetector(vec![
            Box::new(Runs {
                kind: Person,
                digits: false,
            }),
            Box::new(Runs {
                kind: Phone,
                digits: true,
            }),
            Box::new(Fixed(vec![span(0, 2, EntityKind::Email)])),
        ]);
        let texts = ["ab 12 cd", "7", "", "xy 345"];
        let spans = detector.detect_batch(&texts, Mode::Anonymize, KindSet::ALL, &[]);
        assert_eq!(
            spans,
            [
                vec![span(0, 2, Person), span(3, 5, Phone), span(6, 8, Person)],
                vec![span(0, 1, Phone)],
                vec![span(0, 2, EntityKind::Email)],
                vec![span(0, 2, Person), span(3, 6, Phone)],
            ]
        );
        // One text at a time gives what the batch gave.
        for (text, expected) in texts.iter().zip(&spans) {
            assert_eq!(
                &detector.detect(text, Mode::Anonymize),
                expected,
                "{text:?}"
            );
        }
        assert!(
            detector
                .detect_batch(&[], Mode::Anonymize, KindSet::ALL, &[])
                .is_empty()
        );
    }

    #[test]
    fn a_later_detector_is_told_what_the_earlier_ones_kept() {
        use EntityKind::{Email, Person, Phone};
        let (first, first_calls) = spy(&[span(0, 4, Person), span(10, 12, Person)]);
        let (second, second_calls) = spy(&[span(2, 6, Phone), span(14, 16, Phone)]);
        let (third, third_calls) = spy(&[span(15, 20, Email)]);
        let detector = CompositeDetector(vec![first, second, third]);

        let spans = detector.detect_batch(&["a", "b"], Mode::Anonymize, KindSet::ALL, &[]);
        let kept = vec![
            span(0, 4, Person),
            span(10, 12, Person),
            span(14, 16, Phone),
        ];
        assert_eq!(spans, [kept.clone(), kept]);

        // The first has nothing to be told; the others get the spans kept so far, per text.
        assert_eq!(seen(&first_calls), [Vec::<Vec<Span>>::new()]);
        let after_first = vec![span(0, 4, Person), span(10, 12, Person)];
        assert_eq!(
            seen(&second_calls),
            [vec![after_first.clone(), after_first]]
        );
        let after_second = vec![
            span(0, 4, Person),
            span(10, 12, Person),
            span(14, 16, Phone),
        ];
        assert_eq!(
            seen(&third_calls),
            [vec![after_second.clone(), after_second]]
        );
    }

    #[test]
    fn the_wanted_kinds_reach_every_detector() {
        #[derive(Debug)]
        struct Wants(Arc<Mutex<Vec<KindSet>>>);

        impl Detector for Wants {
            fn detect(&self, _text: &str, _mode: Mode) -> Vec<Span> {
                Vec::new()
            }

            fn detect_batch(
                &self,
                texts: &[&str],
                _mode: Mode,
                wanted: KindSet,
                _taken: &[Vec<Span>],
            ) -> Vec<Vec<Span>> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(wanted);
                vec![Vec::new(); texts.len()]
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let detector = CompositeDetector(vec![
            Box::new(Wants(Arc::clone(&log))),
            Box::new(Wants(Arc::clone(&log))),
        ]);
        let wanted = KindSet::ALL.without(EntityKind::Email);
        detector.detect_batch(&["x"], Mode::Anonymize, wanted, &[]);
        let log = log.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(*log, [wanted, wanted]);
    }

    #[test]
    fn a_name_beats_a_regex_match_only_when_it_is_listed_first() -> Result<()> {
        let text = "mail jan.jansen@acme.nl or +31 6 12345678";
        let at = text.find("jan.jansen").unwrap_or(0);
        let names = || {
            Fixed(vec![
                span(at, at + 3, EntityKind::Person),
                span(at + 4, at + 10, EntityKind::Person),
            ])
        };
        let spans_of =
            |order: Vec<Box<dyn Detector>>| CompositeDetector(order).detect(text, Mode::Anonymize);
        let words = |spans: &[Span]| -> Vec<(EntityKind, String)> {
            spans
                .iter()
                .map(|s| (s.kind, text[s.start..s.end].to_owned()))
                .collect()
        };

        let names_first = spans_of(vec![Box::new(names()), Box::new(RegexDetector::new()?)]);
        assert_eq!(
            words(&names_first),
            [
                (EntityKind::Person, "jan".to_owned()),
                (EntityKind::Person, "jansen".to_owned()),
                (EntityKind::Phone, "+31 6 12345678".to_owned()),
            ]
        );

        let regex_first = spans_of(vec![Box::new(RegexDetector::new()?), Box::new(names())]);
        assert_eq!(
            words(&regex_first),
            [
                (EntityKind::Email, "jan.jansen@acme.nl".to_owned()),
                (EntityKind::Phone, "+31 6 12345678".to_owned()),
            ]
        );
        Ok(())
    }

    /// Every step the composite reports for `texts`, until `stop_after` of them have come.
    fn steps_of(detector: &CompositeDetector, texts: &[&str], stop_after: usize) -> Vec<Step> {
        let mut steps = Vec::new();
        detector.detect_batch_steps(texts, Mode::Anonymize, KindSet::ALL, &[], &mut |step| {
            steps.push(step);
            if steps.len() >= stop_after {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        steps
    }

    #[test]
    fn the_steps_are_what_each_member_keeps_and_together_they_are_the_batch() {
        use EntityKind::{Email, Person, Phone};
        let names = [span(0, 10, Person), span(30, 35, Person)];
        let regex = [span(5, 15, Phone), span(20, 25, Email), span(33, 40, Phone)];
        let detector = composite(&[&names, &regex]);
        let texts = ["one", "two"];

        let steps = steps_of(&detector, &texts, usize::MAX);
        assert_eq!(steps.len(), 2);
        // The first member's step says more follows, though not how much; the last says nothing
        // does. What the second member found over the first's spans is left out of its step.
        assert_eq!(steps[0].more, Some((0, 0)));
        assert_eq!(steps[1].more, None);
        assert_eq!(steps[0].spans, vec![names.to_vec(); 2]);
        assert_eq!(steps[1].spans, vec![vec![span(20, 25, Email)]; 2]);

        let mut together = vec![Vec::new(); texts.len()];
        for step in &steps {
            for (all, spans) in together.iter_mut().zip(&step.spans) {
                all.extend(spans.iter().copied());
            }
        }
        for spans in &mut together {
            spans.sort_by_key(|span| span.start);
        }
        assert_eq!(
            together,
            detector.detect_batch(&texts, Mode::Anonymize, KindSet::ALL, &[])
        );
    }

    #[test]
    fn a_later_member_is_told_what_the_earlier_ones_kept_and_a_stop_ends_the_work() {
        use EntityKind::{Person, Phone};
        let (second, calls) = spy(&[span(5, 15, Phone)]);
        let detector = CompositeDetector(vec![Box::new(Fixed(vec![span(0, 10, Person)])), second]);
        let steps = steps_of(&detector, &["a", "b"], usize::MAX);
        assert_eq!(steps.len(), 2);
        assert_eq!(seen(&calls), [vec![vec![span(0, 10, Person)]; 2]]);

        // Told to stop after the first step, the second member is never asked.
        let before = seen(&calls).len();
        let steps = steps_of(&detector, &["a", "b"], 1);
        assert_eq!(steps.len(), 1);
        assert_eq!(seen(&calls).len(), before);
    }
}
