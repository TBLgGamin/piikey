# piikey quality benchmark

How much PII does piikey mask, how much does it leave behind, and how much does it mask that it
should not? This folder answers that on labelled corpora in Dutch, English, German and a few other
languages. It is for finding what leaks and where, not for ranking models.

```sh
python eval/fetch.py                       # once: ~2000 documents per corpus, a few minutes, needs the network
cargo run --release --example pii_eval     # regex, then regex+model, on every corpus; Markdown on stdout
```

The model configurations need the detection model that `piikey.exe` downloads to
`%LOCALAPPDATA%\piikey\models` on its first start. The benchmark never downloads or copies it; with
no model installed it runs the regex configuration only and says so.

## What is here

| Path | What |
|---|---|
| `fetch.py`, `common.py` | Download the corpora from the Hugging Face datasets-server API and convert them to one JSONL format. Python 3.11+, standard library only. |
| `labels.toml` | The label table: the shared categories, how piikey's 44 kinds fold into them, each corpus's labels, and how each corpus is judged. |
| `handmade.py`, `handmade.jsonl` | The hand-written set (202 NL/EN/DE prompts, 358 gold spans, 26 with no PII at all) and the script that builds it from inline-marked text. Checked in. |
| `../examples/pii_eval/` | The benchmark itself (a Rust example: taxonomy, corpus loader, scoring, round trip, timing, report). |
| `data/` | The fetched corpora and `MANIFEST.json`. Git-ignored; sampled JSONL only, no raw dumps. |
| `results/` | One `<timestamp>.json` (everything, with failure examples) and `.md` (the report) per run. Git-ignored. |

## Run it

```text
cargo run --release --example pii_eval -- [OPTIONS]

--sources A,B      corpora to score (default: every one in eval/data, plus handmade)
--configs A,B      regex | regex+model | model (default: regex,regex+model)
--limit N          documents per corpus (default: all the file holds)
--batch N          documents per detector call in the throughput passes (default 32)
--latency-docs N   single-document calls timed per corpus (default 100; 0 skips)
--roundtrip N      documents per corpus through the real Engine (default 300; 0 skips)
--examples N       examples shown per failure list (default 3)
--json-examples N  examples of each failure list kept in the JSON (default 60)
--model-dir DIR    detection model folder (default: the app's)
--device D         run the model on cpu, gpu or hybrid instead of the saved choice (restored afterwards)
--recalibrate      measure GPU against CPU again on the first load (the old choice is restored)
--eval-dir DIR     the eval folder (default: eval/ of this repository)
--out DIR          results folder (default: <eval-dir>/results)
--no-write         print only; write no result files
--note TEXT        a line about this machine or run, kept in the report
```

`python eval/fetch.py --help` lists the fetch options: `--cap N` documents per corpus (default
2000), `--seed N`, `--sources`, `--threads`, `--keep-raw`. The fetch is resumable: pages are cached in
`eval/data/raw/` while it runs and deleted when it finishes, so only the sampled JSONL files and the
manifest stay on disk. The sample is a pure function of the seed, the cap and the dataset revision
(recorded in `MANIFEST.json`); the benchmark prints the hash of each file it read.

A full run (three fetched corpora and the hand-made set, both configurations, round trips and timings)
takes a few minutes. `--device` and `--recalibrate` write the model folder's `device.cfg` for the
duration of the run and put the old content back at the end; a run that is killed leaves it as it was
set, so delete the file to let the app measure again.

## Corpora

| Corpus | Source | Licence | Sample | Notes |
|---|---|---|---|---|
| `finance_multilingual` | [`gretelai/synthetic_pii_finance_multilingual`](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual), test split | Apache-2.0 | 2000 of 5594 documents: en 600, nl 400, de 400, fr/es/it/sv 150 each | Long synthetic finance documents (a few hundred to 8000 characters: SWIFT and EDI messages, JSON, CSV, letters), 29 labels. The model card calls it out of distribution. Its labels are noisy (timestamps, fragments such as `:`, field names labelled as names). |
| `openpii` | [`ai4privacy/pii-masking-openpii-1m`](https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m), validation split | CC-BY-4.0 (Ai4Privacy / Ai Suisse SA) | 2000 of 284,746: nl, en, de 440 each, fr/es/it 120 each, pl/sv 80, bg/el 60, cs 40 | Short synthetic texts, 19 labels, 23 languages. **Possibly in-distribution**: the detection model was trained on this dataset's train split, so read it as an upper bound. |
| `gretel_en` | [`gretelai/gretel-pii-masking-en-v1`](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1), test split | Apache-2.0 | 2000 of 5000 documents | Short English synthetic documents (about 200 characters), 41 labels. Gives entity strings, not offsets: every whole-token occurrence is a span. |
| `handmade` | `handmade.jsonl` | this repository | 202 documents: en 91, nl 62, de 49 | Prompts like the ones people paste into a chatbot: emails, CVs, medical notes, invoices, tickets, code with secrets, JSON, addresses, names that are also words, and PII-free hard negatives. Every PII value is labelled, so every unmatched prediction counts as a false positive. |

### The normalized format

One JSON object per line, UTF-8:

```json
{"id": "openpii-20538906", "source": "openpii", "lang": "nl", "group": "NL",
 "text": "Voor deelname vraagt Charoula Adamowicz ...",
 "spans": [{"start": 21, "end": 40, "label": "GIVENNAME"}]}
```

`start` and `end` are **byte** offsets into the UTF-8 `text`. `label` is the corpus's own label; the
shared category comes from `labels.toml` when the benchmark runs, so a changed mapping needs no new
download. `group` is optional (finance document type, gretel domain, openpii region). The converters
trim whitespace from span edges, resolve overlapping spans by keeping the longest, and validate every
span (inside the text, on a character boundary, in order); the benchmark checks them again on load and
refuses a corpus that breaks a rule. `MANIFEST.json` counts what the converters had to repair.

## The label table

`labels.toml` maps three vocabularies onto 18 categories: `PERSON`, `PERSON_ATTR`, `EMAIL`, `PHONE`,
`ADDRESS`, `LOCATION`, `GEO` (coordinates), `ORG`, `DATE`, `DOB`, `ID_NUMBER`, `ACCOUNT`, `FINANCIAL`,
`AMOUNT`, `NETWORK`, `SECRET`, `SENSITIVE`, `OTHER`.

- **piikey kinds** (`[piikey]`): all 44 `EntityKind`s must be mapped, or the benchmark refuses to run.
  A category no kind maps to (today only `DATE`: piikey masks a date of birth, not dates in general)
  has **no piikey counterpart**. Its gold spans are reported and flagged `*`, never silently dropped,
  and left out of the `ALL supported` rows that the headline uses.
- **Corpus labels** (`[source.<corpus>]`): a corpus annotates only the categories its labels map to.
  A prediction in another category (organizations in OpenPII, say) cannot be judged: it is counted as
  *unjudged* and never as a false positive. `handmade` is `exhaustive` in `[policy]`: it labels
  everything, so all predictions are judged.
- **Compatible categories** (`[compat]`): `ADDRESS` ~ `LOCATION` and `DATE` ~ `DOB`. The overlap metric
  accepts either side (OpenPII calls the city of an address `CITY`, the model folds it into the
  address; OpenPII calls every date `DATE`, the model can tell a birth date). The strict metric never
  does.
- **Parts** (`[merge]`): corpora that cut one entity into parts (OpenPII: `GIVENNAME` + `SURNAME`,
  `STREET` + `BUILDINGNUM`) would make an exact match impossible against a model that reads the entity
  whole. Two gold spans of one category join when at most two characters (spaces, tabs, hyphens, and
  in an address commas and periods) lie between them. The report prints how many parts were merged.

## Metrics

Everything is computed per category, per corpus and per configuration, on the gold spans of the
categories piikey can produce unless a row says `ALL`.

**Span level**, each with precision (of the predictions the corpus can judge), recall (of the gold
spans) and F1:

| | A prediction is right when | A gold span is found when |
|---|---|---|
| **strict** | same start, same end, same category | an identical span of that category exists |
| **overlap** | it shares a character with a gold span of the same (or a compatible) category | a prediction of that category shares a character with it |
| **any-cat** | it shares a character with any gold span | any prediction shares a character with it |

*any-cat recall* is "was it masked at all". It is the only recall piikey's privacy promise needs: the
category only picks the stand-in.

**Character level**, independent of how a span is cut. A character is a non-whitespace Unicode scalar.

- **leak**: the share of gold characters that no prediction covers, per category. The privacy number.
  *fully masked* is the share of gold spans covered completely: a half-masked IBAN counts as found by
  *any-cat* recall but not as fully masked.
- **FP masked**: the share of characters outside every gold span that a (judged) prediction masks. The
  cost to the usefulness of the text. On the three fetched corpora this is an **upper bound**: a value
  piikey masks that the corpus did not label is counted here although it may well be PII. Only
  `handmade` is labelled exhaustively.

**Round trip.** A sample of each corpus goes through the real `Engine` on a throw-away vault:
anonymize, then deanonymize. *exact* means the restored text equals the original byte for byte.
*gold value left* means a labelled value (3 characters or more, of a category piikey can produce) still
appears as a whole token in the anonymized text, checked by string, so a value masked in one place and
left in another counts.

**Speed.** *cold*: one pass over a corpus in batches, from an empty model cache (the model is reloaded
between measurements and the reload is not timed). *warm*: the same pass again with the cache full, as
when a chat client resends its history. *single doc*: one document per call, cold; p50/p95/max over an
evenly spaced sample. The device comes from `NerDetector::state()`; the first model load, which
includes the GPU/CPU calibration when no `device.cfg` is saved, is reported on its own.

## Reading the report

1. **Setup**, **Corpora**, **Label coverage**: what was run on what, and how each corpus's labels
   fold into the categories.
2. **Headline**: one row per configuration and corpus. Start here.
3. **Leakage by category**: where the leaks are.
4. **Details**: per configuration and corpus, the category table, a table by language (and, for the
   finance corpus, by document kind), and the failure tables: what was missed outright, what was only
   partly covered, what was masked under another category, what was masked without a gold span, the most
   common confusions.
5. **Engine round trip**, **Speed**.
6. **Verdict**: this run next to published numbers, with why they are not comparable.

The JSON has the same numbers (raw counts included) and up to 60 examples of every failure list with a
window of context.

## Adding a corpus

Add a converter and a `SOURCES` entry in `fetch.py` (it must emit the normalized format with the
corpus's own labels), a `[source.<name>]` table and a `[policy]` line in `labels.toml`, and, if it
should sort somewhere other than last, the name in `ORDER` in `examples/pii_eval/main.rs`. A label
the table does not know stops the conversion.

## A run: 2026-10-20, AMD Ryzen 5 9600X (6C/12T), model on the CPU

Three fetched corpora of 2000 documents, the hand-made set, all three configurations, 300 engine round
trips and 100 single-document timings per corpus: 506 s wall time. The full report is
`results/<timestamp>.md`; these are its headline numbers (categories piikey can produce; the model ran on
the CPU because `device.cfg` said `cpu`, the faster device on this machine when it was measured).

| configuration | corpus | gold | strict F1 | overlap F1 | any-cat recall | leak | fully masked | FP masked |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| regex | handmade | 358 | 0.462 | 0.466 | 0.304 | 58.3% | 30.2% | 0.2% |
| regex | finance_multilingual | 9,629 | 0.155 | 0.166 | 0.095 | 88.5% | 8.9% | 0.1% |
| regex | gretel_en | 7,571 | 0.346 | 0.354 | 0.234 | 73.8% | 22.1% | 0.1% |
| regex | openpii | 10,787 | 0.275 | 0.287 | 0.196 | 75.3% | 18.7% | 0.0% |
| regex+model | handmade | 358 | 0.897 | 0.945 | 0.950 | 5.4% | 90.8% | 1.0% |
| regex+model | finance_multilingual | 9,629 | 0.535 | 0.690 | 0.747 | 23.6% | 60.2% | 1.6% |
| regex+model | gretel_en | 7,571 | 0.805 | 0.889 | 0.969 | 3.5% | 92.0% | 1.1% |
| regex+model | openpii (in-distribution) | 10,787 | 0.652 | 0.866 | 0.902 | 2.9% | 88.8% | 0.7% |
| model alone | handmade | 358 | 0.879 | 0.927 | 0.947 | 5.7% | 90.5% | 1.0% |
| model alone | finance_multilingual | 9,629 | 0.523 | 0.681 | 0.726 | 26.5% | 58.2% | 1.5% |
| model alone | gretel_en | 7,571 | 0.809 | 0.896 | 0.964 | 3.7% | 92.3% | 1.0% |
| model alone | openpii (in-distribution) | 10,787 | 0.678 | 0.890 | 0.898 | 3.2% | 89.1% | 0.7% |

The regex pass alone leaks three quarters of the PII of these corpora (it finds what has a format: emails,
phones, IBANs, cards, IPs). The model closes most of that. Dropping the regex pass costs recall on
emails (the model alone leaks 41.6% of the finance corpus's email characters, against 4.8% with the regex
pass in front) and on a few other formats; it gains nothing anywhere else. Leakage of `regex+model` by
category (`n` = gold spans):

| category | handmade | finance_multilingual | gretel_en | openpii |
|---|---:|---:|---:|---:|
| PERSON | 1.5% (138) | 34.7% (4,220) | 1.9% (900) | 1.6% (1,962) |
| PERSON_ATTR | 0.0% (3) | - | - | 15.2% (2,349) |
| EMAIL | 0.0% (41) | 4.8% (449) | 0.0% (416) | 1.6% (1,091) |
| PHONE | 0.0% (29) | 5.5% (300) | 3.3% (354) | 1.9% (804) |
| ADDRESS | 1.4% (8) | 5.4% (1,512) | 1.6% (591) | 0.8% (1,299) |
| LOCATION | 0.0% (26) | - | 3.8% (89) | 0.8% (954) |
| ORG | 20.5% (38) | 36.9% (2,191) | 8.9% (75) | - |
| DOB | 0.0% (6) | 21.5% (76) | 7.9% (916) | - |
| ID_NUMBER | 0.0% (8) | 12.8% (132) | 2.4% (2,187) | 3.6% (1,877) |
| ACCOUNT | 0.0% (3) | 12.3% (161) | 8.0% (950) | - |
| FINANCIAL | 0.0% (27) | 19.9% (326) | 4.5% (430) | 0.0% (451) |
| NETWORK | 27.8% (6) | 0.7% (105) | 4.2% (520) | - |
| SECRET | 5.5% (7) | 6.7% (128) | 1.8% (48) | - |
| SENSITIVE | 81.5% (14) | - | 15.5% (57) | - |
| AMOUNT | 17.6% (4) | - | - | - |
| DATE* (no piikey kind) | - | 96.5% (3,267) | 48.4% (595) | 54.3% (1,698) |

Round trip through the real engine, `regex+model` (sample of 202 / 300 / 300 / 300 documents): exact
restore 100% handmade, 98.0% finance, 99.7% gretel, 96.7% openpii (`regex` alone: 100%, 99.7%, 100%,
100%). A gold value still in the anonymized text afterwards: 5.0% of the checked values on handmade,
26.6% finance, 2.6% gretel, 1.5% openpii.

Speed (CPU, 12 logical processors): the model loads in 1.3 s once the device is saved. Cold, in batches
of 32 documents: 188 docs/s on the hand-made set (78 B average), 68 on gretel_en (242 B), 50 on openpii
(362 B), 12.7 on finance_multilingual (1290 B), that is 15-18 KB/s of text whatever the corpus. One
document per call: p50 8 ms (78 B), 18 ms (242 B), 20 ms (362 B), 65 ms (1290 B); p95 11-99 ms; the
slowest 1290 B document took 475 ms. With the cache full (a chat client resending its history) 140,000 to
250,000 docs/s. The regex pass alone: 190,000 to 600,000 docs/s (15 to 363 MB/s). The first load of a
machine also measures GPU against CPU; that run was not repeated here (`--recalibrate` does it).

## Top failure modes of `regex+model`

Numbers are gold spans of the categories piikey can produce. *Missed*: no prediction touches the span;
*partial*: touched but not covered completely.

1. **Names and organizations in long, structured documents (finance corpus).** PERSON leaks 34.7% of its
   characters (1,521 missed, 311 partial of 4,220), ORG 36.9% (648 missed, 730 partial, 339 masked only as
   another category); the worst document kinds are contracts and prospectuses (Shareholder Agreement
   81% leak, Investment Prospectus 65%). Dutch is hit hardest (33.1% leak, against 13.4% for English).
   Part of this is the corpus: 200 missed spans are template fields (`[Phone Number]`,
   `[Indirizzo di residenza]`, `[Date of Birth]`), and 1,038 are single words such as `Damen`, `Herren`,
   `Bedrag` (German "ladies", "gentlemen", Dutch "amount" labelled as names) or `Corporation`. The
   benchmark cannot tell label noise from a miss; the *value shape* table in the report counts them apart.
2. **GDPR special categories.** SENSITIVE leaks 81.5% on the hand-made set (10 of 14 spans missed:
   `type 2 diabetes`, `convicted of burglary in 2019`, `ADHD`, ...) and 15.5% on gretel_en.
3. **Well-known company names and personal links.** On the hand-made set 7 of 38 organizations are
   missed (`Heineken` x3, `Booking.com` x2, `Deutschen Bahn`; ORG leak 20.5%) and one personal link
   (`https://samkowalczyk.dev/about`; NETWORK leak 27.8% of 6). On gretel_en 16 URLs and 33 more are masked
   only as another category.
4. **Bare dates.** Dates in general are not masked by design (DATE* leaks 48-97%, no piikey kind), but a
   date of birth in a plain sentence is missed too: 72 of 916 on gretel_en (`2015-09-13`, `2019-11-21`),
   21.5% of the finance corpus's DOB characters (template fields among them).
5. **Single-letter and short attributes (OpenPII).** 908 of 2,349 `PERSON_ATTR` spans are never touched:
   `M` x88, `F` x84, `O` x17 (sex and gender values). 849 more are covered only by a name span (a
   title swallowed into the name; also why strict PERSON recall there is 0.543 against 0.984 by overlap).
6. **Identifier kinds are confused, not leaked.** `ID_NUMBER` spans are masked as another category 321
   times on gretel_en (142 of them under OTHER, a document reference or proper name, 117 as ACCOUNT) and 274 times on openpii (264 as a phone
   number, because the phone pattern wins the overlap). The value is hidden but gets a stand-in of the
   wrong shape.
7. **Over-masking (upper bounds, except on the hand-made set).** Hand-made, exhaustively labelled: 1.0% of
   non-PII characters masked, from `Canada`, `Australia`, `Amsterdam` (general-knowledge places),
   `24.99` and `2,50` (prices as `financial_amount`), `Luhn` and `Jane Doe` (as `person`), `ENG-1423`,
   `jane@example.com`, `assistant` (as a role) and `7781-ZX` (as an address). On the other corpora the
   biggest groups are places the corpus does not label (`USA` x62, `Netherlands` x46: 1,057 on finance),
   example values (`123456789` as a bank account x28, `0123456789` as a phone number), `John Doe` x23,
   and job titles in OpenPII (`person_role`: 169, `Program Coordinator`).
8. **The engine does not always put the original back (96.7-99.7% exact, finance 98.0%).** The traces in
   the report show three causes:
   - *a stand-in that equals ordinary text*: `1984` came back as `1968` and `12/10/1951` as `20/08/1943`
     (the text's own year or date was never masked, but equals the stand-in issued for another date in
     the same vault), and `**** 962` as `**** 976` (a short digit run);
   - *a stand-in the deanonymizer does not find again*: a phone `55-5555-5555` became `51-9941-4427`,
     an IPv4 `153.147.25.41` became `91.28.30.77`, and, with the regex configuration alone, a repeated
     `002-555-123456-000` became `002-555-561020-960`, none of which came back;
   - *an engine error*: `no unused proxy left for location` on one finance document (it also fails alone).

## Verdict

`regex+model` on the hand-made prompts: overlap F1 0.945 (0.983 over the card's seven type groups, as read
here), any-category recall 0.950, 5.4% of the gold characters leak, 1.0% of the rest is masked. On the
three corpora it ranges from 2.9% leakage (OpenPII, in-distribution) and 3.5% (gretel_en) to 23.6% on
the long finance documents (0.690 overlap F1; the card reports 0.692 for the same dataset, out of
distribution). The regex pass alone leaks 58% to 89%.

Against published numbers (model card: strict word-level F1 0.973 FP32 / 0.968 INT8 on 455 real spans, 0.692
on the finance corpus, 0.997 on OpenPII; arXiv 2608.02616: OpenAI Privacy Filter 0.855 and Presidio 0.431 on
AI4Privacy, 0.554 and 0.388 on gretel_en) these results are **not apples to apples**: different matching
(the card scores seven type groups strictly at word level; this benchmark has three criteria over 18
categories and a leakage measure), different gold (merged parts, partial annotation, corpus label noise),
different samples (language-balanced, capped, seeded), and piikey is the regex pass plus the INT8 model plus
its own decoder, not the bare model. They agree on the shape: near the top on a corpus the model trained on,
clearly lower on out-of-distribution long documents, and the model's weak spots are names in tables and
boilerplate, organizations and the special categories.
