//! From a text's tokens to model inputs and back: the windows cut over the tokens, the padded
//! batch a run takes, and the reading of its logits.

use std::ops::Range;

use tokenizers::Encoding;

use super::{
    decode::{Tokens, pool},
    labels::LABELS,
};

/// Tokens of text in a window: the model reads 512 positions, two of them `<bos>` and `<eos>`.
const WINDOW: usize = 510;

/// Tokens two neighbouring windows share, so an entity at a seam is whole in one of them.
const OVERLAP: usize = 128;

/// How far a window starts after the one before it.
const STEP: usize = WINDOW - OVERLAP;

/// Token ids of the model's vocabulary.
const PAD: i64 = 0;
const EOS: i64 = 1;
const BOS: i64 = 2;

/// A window: some of the tokens of one text.
pub(super) struct Window {
    /// Index into the texts being run.
    pub(super) text: usize,
    pub(super) tokens: Range<usize>,
}

/// The windows over `tokens` tokens: each `WINDOW` long, each starting `STEP` after the one
/// before, the last one reaching the end.
pub(super) fn windows_of(tokens: usize) -> Vec<Range<usize>> {
    let mut windows = Vec::new();
    let mut from = 0;
    while from < tokens {
        let to = (from + WINDOW).min(tokens);
        windows.push(from..to);
        if to == tokens {
            break;
        }
        from += STEP;
    }
    windows
}

/// The inputs of one run: `rows` windows of `width` positions, padded on the right.
#[derive(Clone)]
pub(super) struct Input {
    pub(super) ids: Vec<i64>,
    pub(super) mask: Vec<i64>,
    pub(super) rows: usize,
    pub(super) width: usize,
}

impl Input {
    /// Each window wrapped in `<bos>` and `<eos>`, padded on the right to the longest.
    pub(super) fn of(batch: &[Window], encodings: &[Encoding]) -> Self {
        let width = batch.iter().map(|w| w.tokens.len()).max().unwrap_or(0) + 2;
        let mut ids = vec![PAD; batch.len() * width];
        let mut mask = vec![0; batch.len() * width];
        for (row, window) in batch.iter().enumerate() {
            let tokens = encodings[window.text]
                .get_ids()
                .get(window.tokens.clone())
                .unwrap_or_default();
            let line = row * width;
            ids[line] = BOS;
            for (slot, &id) in ids[line + 1..].iter_mut().zip(tokens) {
                *slot = i64::from(id);
            }
            ids[line + 1 + tokens.len()] = EOS;
            mask[line..line + tokens.len() + 2].fill(1);
        }
        Self {
            ids,
            mask,
            rows: batch.len(),
            width,
        }
    }

    /// `rows` copies of `ids`, cycled to fill the width, in `<bos>` and `<eos>`.
    pub(super) fn filled(ids: &[u32], rows: usize, width: usize) -> Option<Self> {
        if ids.is_empty() || width < 2 {
            return None;
        }
        let mut all = Vec::with_capacity(rows * width);
        for _ in 0..rows {
            all.push(BOS);
            all.extend(ids.iter().cycle().take(width - 2).map(|&id| i64::from(id)));
            all.push(EOS);
        }
        Some(Self {
            mask: vec![1; all.len()],
            ids: all,
            rows,
            width,
        })
    }
}

/// Feeds the probabilities of every token of a batch to the text it belongs to. Row `r` of
/// `logits` is `<bos>`, then one position per token of the `r`th window; the positions of
/// `<eos>` and of the padding are not read.
pub(super) fn absorb(
    logits: &[f32],
    width: usize,
    batch: &[Window],
    encodings: &[Encoding],
    texts: &[&str],
    tokens: &mut [Tokens],
) {
    let (positions, _) = logits.as_chunks::<LABELS>();
    for (row, window) in batch.iter().enumerate() {
        let offsets = encodings[window.text]
            .get_offsets()
            .get(window.tokens.clone())
            .unwrap_or_default();
        let own = positions.get(row * width + 1..).unwrap_or_default();
        for (&(start, end), logits) in offsets.iter().zip(own) {
            tokens[window.text].push(texts[window.text], start, end, &pool(logits));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokenizers::{
        Tokenizer, models::wordlevel::WordLevel, pre_tokenizers::whitespace::Whitespace,
    };

    use super::*;
    use crate::{
        Result,
        detect::{
            EntityKind,
            ner::{gate::RawSpan, labels::TYPES, model_err},
        },
    };

    /// The token a stand-in model takes for a name: `Jan`. Every other word is token 3.
    const NAME: u32 = 5;

    fn encodings_of(texts: &[&str]) -> Result<Vec<Encoding>> {
        let vocab = [("[UNK]".to_owned(), 3), ("Jan".to_owned(), NAME)]
            .into_iter()
            .collect();
        let model = WordLevel::builder()
            .vocab(vocab)
            .unk_token("[UNK]".to_owned())
            .build()
            .map_err(model_err)?;
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(Whitespace));
        texts
            .iter()
            .map(|text| tokenizer.encode(*text, false).map_err(model_err))
            .collect()
    }

    /// What a stand-in model says of every position of `input`: a name begins at each `NAME`
    /// token, nothing anywhere else.
    fn logits_of(input: &Input) -> Vec<f32> {
        let name = 1 + 2 * TYPES
            .iter()
            .position(|(name, ..)| *name == "PERSON_NAME")
            .unwrap_or(0);
        let mut logits = vec![0.0; input.rows * input.width * LABELS];
        for (token, row) in input.ids.iter().zip(logits.chunks_exact_mut(LABELS)) {
            row[if *token == i64::from(NAME) { name } else { 0 }] = 30.0;
        }
        logits
    }

    fn person(start: u32, end: u32) -> RawSpan {
        RawSpan {
            start,
            end,
            kind: EntityKind::Person,
        }
    }

    fn decoded(tokens: Vec<Tokens>, texts: &[&str]) -> Vec<Vec<RawSpan>> {
        tokens
            .into_iter()
            .zip(texts)
            .map(|(tokens, text)| tokens.decode(text))
            .collect()
    }

    #[test]
    fn every_token_is_in_one_window_or_two_and_the_last_window_reaches_the_last_token() {
        assert!(windows_of(0).is_empty());
        for tokens in (1..=3 * WINDOW).chain([100_000]) {
            let windows = windows_of(tokens);
            let mut seen = vec![0u8; tokens];
            for window in &windows {
                assert!(!window.is_empty() && window.len() <= WINDOW, "{tokens}");
                for token in window.clone() {
                    seen[token] += 1;
                }
            }
            assert!(
                seen.iter().all(|times| (1..=2).contains(times)),
                "{tokens} tokens"
            );
            assert_eq!(windows.first().map(|w| w.start), Some(0));
            assert_eq!(windows.last().map(|w| w.end), Some(tokens));
            for pair in windows.windows(2) {
                assert_eq!(pair[1].start, pair[0].start + STEP);
                // What one window cuts at its edge is whole in the next.
                assert!(pair[0].end - pair[1].start >= OVERLAP, "{tokens} tokens");
            }
        }
    }

    #[test]
    fn a_batch_is_padded_to_its_longest_window_whatever_the_order() -> Result<()> {
        let texts = ["Jan and Jan and", "Jan"];
        let encodings = encodings_of(&texts)?;
        let short = Window {
            text: 1,
            tokens: 0..1,
        };
        let long = Window {
            text: 0,
            tokens: 0..4,
        };
        let input = Input::of(&[short, long], &encodings);
        assert_eq!((input.rows, input.width), (2, 6));
        assert_eq!(&input.ids[..6], [BOS, 5, EOS, PAD, PAD, PAD]);
        assert_eq!(&input.mask[..6], [1, 1, 1, 0, 0, 0]);
        assert_eq!(&input.ids[6..], [BOS, 5, 3, 5, 3, EOS]);
        assert!(input.mask[6..].iter().all(|&m| m == 1));
        Ok(())
    }

    #[test]
    fn a_window_over_part_of_a_text_wraps_only_its_own_tokens() -> Result<()> {
        let encodings = encodings_of(&["Jan and Jan and Jan"])?;
        let window = Window {
            text: 0,
            tokens: 2..4,
        };
        let input = Input::of(&[window], &encodings);
        assert_eq!((input.rows, input.width), (1, 4));
        assert_eq!(input.ids, [BOS, 5, 3, EOS]);
        assert_eq!(input.mask, [1, 1, 1, 1]);
        Ok(())
    }

    #[test]
    fn the_logits_of_each_row_reach_the_text_of_its_window() -> Result<()> {
        // "Jan and Jan": names at 0..3 and 8..11. "and Jan": one at 4..7.
        let texts = ["Jan and Jan", "and Jan"];
        let encodings = encodings_of(&texts)?;
        let batch = [
            Window {
                text: 0,
                tokens: 0..3,
            },
            Window {
                text: 1,
                tokens: 0..2,
            },
        ];
        let input = Input::of(&batch, &encodings);
        let mut tokens = vec![Tokens::default(), Tokens::default()];
        absorb(
            &logits_of(&input),
            input.width,
            &batch,
            &encodings,
            &texts,
            &mut tokens,
        );
        assert_eq!(
            decoded(tokens, &texts),
            [vec![person(0, 3), person(8, 11)], vec![person(4, 7)]]
        );

        // A window over the end of a text only reads its own tokens.
        let tail = [Window {
            text: 0,
            tokens: 1..3,
        }];
        let input = Input::of(&tail, &encodings);
        let mut tokens = vec![Tokens::default(), Tokens::default()];
        absorb(
            &logits_of(&input),
            input.width,
            &tail,
            &encodings,
            &texts,
            &mut tokens,
        );
        assert_eq!(decoded(tokens, &texts), [vec![person(8, 11)], vec![]]);
        Ok(())
    }

    #[test]
    fn fewer_logits_than_the_batch_needs_are_read_as_far_as_they_go() -> Result<()> {
        let texts = ["Jan and Jan", "Jan"];
        let encodings = encodings_of(&texts)?;
        let batch = [
            Window {
                text: 0,
                tokens: 0..3,
            },
            Window {
                text: 1,
                tokens: 0..1,
            },
        ];
        let input = Input::of(&batch, &encodings);
        let logits = logits_of(&input);
        // `<bos>`, the first token and a few values of the second: the second row is not there.
        let mut tokens = vec![Tokens::default(), Tokens::default()];
        absorb(
            &logits[..LABELS * 2 + 5],
            input.width,
            &batch,
            &encodings,
            &texts,
            &mut tokens,
        );
        assert_eq!(decoded(tokens, &texts), [vec![person(0, 3)], vec![]]);
        Ok(())
    }

    #[test]
    fn calibration_input_is_cycled_and_wrapped() {
        let input = Input::filled(&[10, 11, 12], 2, 8);
        let Some(input) = input else {
            panic!("input for a non-empty sentence");
        };
        assert_eq!((input.rows, input.width), (2, 8));
        assert_eq!(input.ids.len(), 16);
        assert_eq!(&input.ids[..8], [BOS, 10, 11, 12, 10, 11, 12, EOS]);
        assert_eq!(&input.ids[8..], &input.ids[..8]);
        assert!(input.mask.iter().all(|&m| m == 1));
        assert!(Input::filled(&[], 2, 8).is_none());
        assert!(Input::filled(&[1], 2, 1).is_none());
    }
}
