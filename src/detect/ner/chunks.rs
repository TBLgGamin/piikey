//! Which pieces of text the model reads: texts cut into chunks, data blobs left out, and the
//! chunks of a call grouped by size.

use std::ops::Range;

use super::gate::{key, worth_running};
use crate::detect::Span;

/// Longest text the model reads in one piece. A longer one is cut after a whitespace.
const CHUNK_BYTES: usize = 256 << 10;

/// A run of this many bytes without whitespace is data, not prose: the model never reads it.
const BLOB_BYTES: usize = 1024;

/// Text the model reads at a time, in a call with more: it keeps the tokens of one group in
/// memory, not of all texts of the call, and a caller that is shown what the model found (see
/// [`Detector::detect_batch_steps`](crate::detect::Detector::detect_batch_steps)) gets it a group
/// at a time: one chunk of a long text, which the model takes seconds to read, not minutes.
pub(super) const GROUP_BYTES: usize = CHUNK_BYTES;

/// One text to run: a text of the batch, or a piece of a long one.
pub(super) struct Job<'a> {
    /// Index into the texts of the call.
    pub(super) text: usize,
    /// Where `chunk` starts in that text.
    pub(super) base: usize,
    pub(super) chunk: &'a str,
    pub(super) key: [u8; 32],
}

/// The pieces of `texts` the model should read, in order.
pub(super) fn plan<'a>(texts: &[&'a str], taken: &[Vec<Span>]) -> Vec<Job<'a>> {
    let mut jobs = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        let claimed: &[Span] = taken.get(i).map_or(&[], Vec::as_slice);
        for (base, chunk) in chunks(text) {
            let free = if chunk.len() == text.len() {
                worth_running(chunk, claimed)
            } else {
                worth_running(chunk, &relative(claimed, base, chunk.len()))
            };
            if free {
                jobs.push(Job {
                    text: i,
                    base,
                    chunk,
                    key: key(chunk),
                });
            }
        }
    }
    jobs
}

/// The parts of `text` the model reads, each with its offset: the text without its blobs, cut
/// into pieces of at most `CHUNK_BYTES`.
fn chunks(text: &str) -> impl Iterator<Item = (usize, &str)> {
    prose(text)
        .into_iter()
        .flat_map(|(base, part)| split(part).map(move |(at, piece)| (base + at, piece)))
}

/// `text` without its blobs, as `(offset, part)`. A blob is a run of `BLOB_BYTES` or more bytes
/// without ASCII whitespace: base64, hex, a minified file. It says nothing about people and, run
/// through the model, would cost minutes. Every part starts and ends at whitespace or at the
/// edge of the text, so no word is cut; a part of whitespace only is dropped.
fn prose(text: &str) -> Vec<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut keep = |from: usize, to: usize| {
        let part = &text[from..to];
        if !part.trim_ascii().is_empty() {
            parts.push((from, part));
        }
    };
    let mut part_start = 0;
    let mut run_start = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if !byte.is_ascii_whitespace() {
            continue;
        }
        if i - run_start >= BLOB_BYTES {
            keep(part_start, run_start);
            part_start = i;
        }
        run_start = i + 1;
    }
    if bytes.len() - run_start >= BLOB_BYTES {
        keep(part_start, run_start);
        part_start = bytes.len();
    }
    keep(part_start, bytes.len());
    parts
}

/// `text` as pieces of at most `CHUNK_BYTES`, each with its offset. A piece ends after a
/// whitespace when it can, so no word is cut.
fn split(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let rest = text.get(at..).filter(|rest| !rest.is_empty())?;
        let len = if rest.len() <= CHUNK_BYTES {
            rest.len()
        } else {
            let mut limit = CHUNK_BYTES;
            while !rest.is_char_boundary(limit) {
                limit -= 1;
            }
            rest[..limit]
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace())
                .map_or(limit, |(i, c)| i + c.len_utf8())
        };
        let piece = (at, &rest[..len]);
        at += len;
        Some(piece)
    })
}

/// `sizes` as runs of consecutive entries that together stay within `limit`, as ranges of
/// indices. An entry over the limit is a run of its own.
pub(super) fn groups(sizes: &[usize], limit: usize) -> Vec<Range<usize>> {
    let mut groups = Vec::new();
    let mut from = 0;
    let mut total = 0;
    for (i, &size) in sizes.iter().enumerate() {
        if total > 0 && total + size > limit {
            groups.push(from..i);
            from = i;
            total = 0;
        }
        total += size;
    }
    if from < sizes.len() {
        groups.push(from..sizes.len());
    }
    groups
}

/// The part of `claimed` that lies in `base..base + len`, relative to `base`.
fn relative(claimed: &[Span], base: usize, len: usize) -> Vec<Span> {
    claimed
        .iter()
        .filter(|span| span.end > base && span.start < base + len)
        .map(|span| Span {
            start: span.start.saturating_sub(base),
            end: (span.end - base).min(len),
            kind: span.kind,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::EntityKind;

    fn text_of(len: usize) -> String {
        "word ".repeat(len / 5 + 1)
    }

    #[test]
    fn short_texts_are_one_chunk() {
        let chunks: Vec<_> = chunks("Jan Jansen").collect();
        assert_eq!(chunks, [(0, "Jan Jansen")]);
        assert_eq!(super::chunks("").count(), 0);
        let big = text_of(CHUNK_BYTES);
        assert!(big.len() > CHUNK_BYTES);
        assert!(super::chunks(&big[..CHUNK_BYTES]).count() == 1);
    }

    #[test]
    fn long_texts_are_cut_after_whitespace_without_losing_or_repeating_a_byte() {
        let text = text_of(CHUNK_BYTES * 3 + 1234);
        let pieces: Vec<(usize, &str)> = chunks(&text).collect();
        assert!(pieces.len() >= 4);
        let mut rebuilt = String::new();
        let mut at = 0;
        for (base, piece) in &pieces {
            assert_eq!(*base, at);
            assert!(piece.len() <= CHUNK_BYTES);
            assert!(!piece.is_empty());
            at += piece.len();
            rebuilt.push_str(piece);
        }
        assert_eq!(rebuilt, text);
        for (_, piece) in &pieces[..pieces.len() - 1] {
            assert!(piece.ends_with(' '), "a piece ends after a whitespace");
        }
    }

    #[test]
    fn cutting_never_splits_a_character_and_copes_with_text_without_whitespace() {
        // Two-byte characters straddling the limit, and no whitespace at all.
        let text = "\u{e9}".repeat(CHUNK_BYTES);
        let pieces: Vec<(usize, &str)> = split(&text).collect();
        assert_eq!(
            pieces.iter().map(|(_, p)| p.len()).sum::<usize>(),
            text.len()
        );
        assert!(pieces.iter().all(|(_, p)| p.len() <= CHUNK_BYTES));
        assert!(pieces.len() >= 2);
        // Four-byte characters, whitespace first.
        let text = format!(" {}", "\u{1f600}".repeat(CHUNK_BYTES / 2));
        let total: usize = split(&text).map(|(_, p)| p.len()).sum();
        assert_eq!(total, text.len());
    }

    #[test]
    fn blobs_are_cut_out_and_the_text_around_them_keeps_its_offsets() {
        let blob = "A1b2".repeat(BLOB_BYTES / 4 + 1);
        assert!(blob.len() > BLOB_BYTES);
        let text = format!("Hello Jan {blob} and Piet {blob}\n{blob}");
        let pieces: Vec<(usize, &str)> = chunks(&text).collect();
        for (base, piece) in &pieces {
            assert_eq!(&text[*base..*base + piece.len()], *piece);
            assert!(!piece.contains("A1b2"), "a blob reached the model");
        }
        let words: Vec<&str> = pieces
            .iter()
            .flat_map(|(_, p)| p.split_whitespace())
            .collect();
        assert_eq!(words, ["Hello", "Jan", "and", "Piet"]);

        // Nothing but data: nothing to read.
        assert_eq!(chunks(&blob).count(), 0);
        assert_eq!(chunks(&format!("{blob} {blob}")).count(), 0);
        assert_eq!(chunks(&format!("  {blob}\n")).count(), 0);
    }

    #[test]
    fn a_run_is_data_from_the_blob_size_up_and_text_below_it() {
        let almost = "x".repeat(BLOB_BYTES - 1);
        assert_eq!(chunks(&almost).count(), 1);
        assert_eq!(chunks(&"x".repeat(BLOB_BYTES)).count(), 0);
        // Only ASCII whitespace ends a run: other runs of the size are data too.
        assert_eq!(chunks(&"\u{e9}".repeat(BLOB_BYTES / 2)).count(), 0);
        // Whitespace inside the data makes it prose again.
        let lines = format!(
            "{}\n{}",
            "x".repeat(BLOB_BYTES - 1),
            "y".repeat(BLOB_BYTES - 1)
        );
        assert_eq!(chunks(&lines).count(), 1);
    }

    #[test]
    fn blobs_at_the_edges_leave_the_prose_between() {
        let blob = "z".repeat(BLOB_BYTES);
        let text = format!("{blob} Jan Piet {blob}");
        let pieces: Vec<(usize, &str)> = chunks(&text).collect();
        assert_eq!(pieces, [(BLOB_BYTES, " Jan Piet ")]);
    }

    #[test]
    fn a_job_is_planned_for_each_part_the_model_can_still_add_to() {
        let span = |start, end| Span {
            start,
            end,
            kind: EntityKind::Email,
        };
        let blob = "z".repeat(BLOB_BYTES);
        let text = format!("Jan {blob} Piet {blob} and");
        let piet = text.find("Piet").unwrap_or(0);
        let planned = |claimed: Vec<Span>| -> Vec<(usize, usize, String)> {
            plan(&[text.as_str(), "Anna"], &[claimed])
                .iter()
                .map(|job| (job.text, job.base, job.chunk.to_owned()))
                .collect()
        };
        let anna = (1, 0, "Anna".to_owned());

        // `Jan` is taken: what is left to read is ` Piet ` (`and` is no name), and `Anna`.
        assert_eq!(
            planned(vec![span(0, 3)]),
            [(0, 4 + BLOB_BYTES, " Piet ".to_owned()), anna.clone()]
        );
        // `Piet` is taken instead: its place in the whole text is not its place in its part.
        assert_eq!(
            planned(vec![span(piet, piet + 4)]),
            [(0, 0, "Jan ".to_owned()), anna.clone()]
        );
        assert_eq!(planned(Vec::new()).len(), 3);
    }

    #[test]
    fn work_is_grouped_by_size_without_splitting_a_text() {
        let ranges = |pairs: &[(usize, usize)]| -> Vec<Range<usize>> {
            pairs.iter().map(|&(from, to)| from..to).collect()
        };
        assert!(groups(&[], 10).is_empty());
        assert_eq!(groups(&[3, 3, 3], 10), ranges(&[(0, 3)]));
        assert_eq!(groups(&[4, 4, 4], 10), ranges(&[(0, 2), (2, 3)]));
        assert_eq!(groups(&[20, 1, 1], 10), ranges(&[(0, 1), (1, 3)]));
        assert_eq!(groups(&[5, 20, 5], 10), ranges(&[(0, 1), (1, 2), (2, 3)]));
        assert_eq!(groups(&[10, 10], 10), ranges(&[(0, 1), (1, 2)]));
        assert_eq!(groups(&[10], 10), ranges(&[(0, 1)]));
        // Whatever the sizes, every entry is in exactly one group, in order.
        let sizes: Vec<usize> = (0..100).map(|i| (i * 37) % 23).collect();
        let all = groups(&sizes, 40);
        let mut next = 0;
        for group in &all {
            assert_eq!(group.start, next);
            assert!(group.end > group.start);
            next = group.end;
            let total: usize = sizes[group.clone()].iter().sum();
            assert!(total <= 40 || group.len() == 1, "{group:?}");
        }
        assert_eq!(next, sizes.len());
    }

    #[test]
    fn claimed_spans_are_made_relative_to_a_chunk() {
        let span = |start, end| Span {
            start,
            end,
            kind: EntityKind::Email,
        };
        let claimed = [span(2, 6), span(10, 20), span(30, 40)];
        let rel = relative(&claimed, 8, 20);
        assert_eq!(rel, [span(2, 12)]);
        assert_eq!(rel[0].kind, EntityKind::Email);
        assert_eq!(relative(&claimed, 6, 4), []);
        assert_eq!(relative(&claimed, 0, 100), claimed);
    }
}
