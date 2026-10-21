//! The verdict: this run next to the numbers other people published.

use super::{Report, Run, Table, dec, pct};
use crate::bench::Config;

impl Report<'_> {
    /// The run of `source` for the headline configuration: regex+model when it ran.
    fn headline_run(&self, source: usize) -> Option<&Run> {
        [Config::RegexModel, Config::Model, Config::Regex]
            .into_iter()
            .find_map(|c| {
                self.runs
                    .iter()
                    .find(|r| r.source == source && r.config == c)
            })
    }

    pub(super) fn verdict(&self) -> String {
        let mut t = Table::new(&[
            ("corpus", false),
            ("configuration", false),
            ("strict F1", true),
            ("overlap F1", true),
            ("any-cat recall", true),
            ("leak", true),
            ("FP masked", true),
            ("overlap F1, card types", true),
            ("any-cat recall, card types", true),
        ]); // fmt: skip
        let mut reading = String::new();
        for (i, s) in self.sources.iter().enumerate() {
            let Some(run) = self.headline_run(i) else {
                continue;
            };
            let total = &run.agg.total;
            let sup = total.sum(|c| self.tax.supported(c));
            let card = total.sum(|c| self.tax.supported(c) && self.tax.is_card_type(c));
            t.row([
                s.name.clone(),
                run.config.name().to_owned(),
                dec(sup.strict().f1()),
                dec(sup.overlap().f1()),
                dec(sup.any().r),
                pct(sup.leak()),
                pct(total.fp_rate()),
                dec(card.overlap().f1()),
                dec(card.any().r),
            ]);
            let nearest = COUNTERPARTS
                .iter()
                .find(|(name, _)| *name == s.name)
                .map_or("none: no published number for this corpus", |(_, text)| {
                    *text
                });
            put!(
                reading,
                "- **{}** ({}): overlap F1 {} over every supported category and {} over the card's type groups; \
                 {} of the gold characters leak. Nearest published number: {nearest}.\n",
                s.name,
                run.config.name(),
                dec(sup.overlap().f1()),
                dec(card.overlap().f1()),
                pct(sup.leak()),
            );
        }
        let mut published = Table::new(&[
            ("source", false),
            ("measure", false),
            ("number", true),
            ("data", false),
        ]);
        for (source, measure, number, data) in PUBLISHED {
            published.row([
                (*source).to_owned(),
                (*measure).to_owned(),
                (*number).to_owned(),
                (*data).to_owned(),
            ]);
        }
        format!(
            "\n## Verdict\n\nThis run (best configuration per corpus, categories piikey can produce). \
             *card types* restricts the same scores to the categories that this benchmark reads the model \
             card's seven type groups as (`[card]` in `labels.toml`).\n\n{}\n{reading}\n\
             Published numbers, for orientation only:\n\n{}\n{VERDICT_CAVEATS}",
            t.render(),
            published.render()
        )
    }
}

/// The nearest published number for a corpus. `(corpus, what and where)`.
const COUNTERPARTS: &[(&str, &str)] = &[
    (
        "finance_multilingual",
        "the model card's 0.692 on the same dataset (strict, word level, 7 type groups, out of distribution)",
    ),
    (
        "openpii",
        "the model card's 0.997 on the same dataset (strict, word level, 7 type groups, its train split is in the training data)",
    ),
    (
        "gretel_en",
        "arXiv 2608.02616's 0.554 (OpenAI Privacy Filter) and 0.388 (Presidio) on the same dataset (zero-shot, English, n=2000, its own F1)",
    ),
];

/// Numbers other people measured. `(source, measure, number, data)`.
pub(super) const PUBLISHED: &[(&str, &str, &str, &str)] = &[
    (
        "model card, bardsai/eu-pii-anonimization-multilang-v2",
        "strict span F1, 7 coarse types, FP32",
        "0.973",
        "455 hand-checked spans of real web text (held-out domains)",
    ),
    (
        "same model card",
        "same, INT8 `model_quantized.onnx` (the file piikey ships)",
        "0.968",
        "same 455 spans",
    ),
    (
        "same model card",
        "span F1 on gretelai finance PII multilingual (out of distribution)",
        "0.692",
        "the corpus behind our `finance_multilingual`",
    ),
    (
        "same model card",
        "span F1 on nvidia/Nemotron-PII (its train split is in the training data)",
        "0.933",
        "not run here",
    ),
    (
        "same model card",
        "span F1 on ai4privacy OpenPII (its train split is in the training data)",
        "0.997",
        "the corpus behind our `openpii`",
    ),
    (
        "arXiv 2608.02616",
        "OpenAI Privacy Filter, zero-shot span F1 on AI4Privacy (Presidio 0.431)",
        "0.855",
        "English, n=2000",
    ),
    (
        "arXiv 2608.02616",
        "OpenAI Privacy Filter, zero-shot span F1 on gretel_en (Presidio 0.388)",
        "0.554",
        "English, n=2000",
    ),
];

const VERDICT_CAVEATS: &str = "\
These are not apples to apples, and none of them is a number to \"beat\":

- **Matching.** The model card scores *strict at the word level over 7 coarse types* (a gold span \
counts as found only if every letter and digit is predicted with the right type; a prediction is \
right if it lies inside a gold span of the same type). The arXiv paper reports a span F1 of its own. \
This benchmark reports three criteria over the categories of `labels.toml`, and its *strict* needs \
the exact span too. None of the three is the card's scorer, and the *card types* columns only \
restrict our scores to the categories the card's seven groups are read as here.
- **Gold.** Our gold is after joining parts of an entity (`GIVENNAME` + `SURNAME`), only for the \
categories piikey can produce, and a prediction in a category a corpus does not annotate is not \
judged. The corpora label differently from each other and from the model: OpenPII calls every date \
`DATE`, and the finance corpus labels timestamps, template fields such as `[Phone Number]`, plain \
words such as `Damen` and fragments such as `:` as PII.
- **Data.** The samples are language-balanced (Dutch, English, German weighted up), capped and fixed \
by a seed; the published numbers are on full test sets or other samples. `openpii` is in-distribution: \
the model was trained on its train split, so read it as an upper bound. `finance_multilingual` is \
the one the card calls out of distribution.
- **System.** piikey is not the bare model: the regex pass and its validators run first and win \
overlaps, the model's types go through validators that can drop them (a name must look like a name), \
the file is INT8 and its decoding is piikey's own port of the reference word decoder.
- **Hand-made set.** 200 short prompts is small: one span moves a percentage by a fraction of a \
point, a category with ten spans by ten. It is the only corpus that is labelled exhaustively, so \
its false-positive numbers are the only ones that are not an upper bound.
";
