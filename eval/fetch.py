#!/usr/bin/env python3
"""Downloads the ground-truth corpora and converts them to one normalized JSONL format.

    python eval/fetch.py                       # all sources, 2000 documents each
    python eval/fetch.py --cap 500             # a quick, smaller sample
    python eval/fetch.py --sources openpii     # one source

Each source becomes `eval/data/<source>.jsonl`, one document per line:

    {"id": "...", "source": "...", "lang": "nl", "group": "...",
     "text": "...", "spans": [{"start": 0, "end": 12, "label": "name"}]}

`start` and `end` are byte offsets into the UTF-8 text; `label` is the label of the source (the
mapping to the shared categories lives in eval/labels.toml and is applied by the benchmark, so a
changed mapping needs no new download). `eval/data/MANIFEST.json` records where each file came from.

The data comes from the Hugging Face datasets-server `rows` API (no extra Python packages). Pages are
cached in `eval/data/raw/` while a run is going, so a run that fails halfway resumes where it
stopped; a run that finishes deletes the cache (keep it with `--keep-raw`), leaving only the sampled
JSONL files and the manifest on disk. The sample is a pure function of
`--seed`, `--cap` and the dataset revision, with a language mix that favours Dutch, English and
German (see the weights below).

Python 3.11+, standard library only.
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import random
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from common import (
    EVAL_DIR,
    SpanStats,
    char_spans_to_byte_spans,
    load_labels,
    source_map,
    validate_doc,
    write_jsonl,
)

API = "https://datasets-server.huggingface.co"
HUB = "https://huggingface.co/api/datasets"
PAGE = 100  # most rows the rows endpoint returns per call

# Share of the sample per language. Dutch, English and German get most of it; the rest checks that
# other Latin-script languages (and a few that are not Latin) work too.
FINANCE_WEIGHTS = {"en": 0.30, "nl": 0.20, "de": 0.20, "fr": 0.075, "es": 0.075, "it": 0.075, "sv": 0.075}
OPENPII_WEIGHTS = {
    "nl": 0.22, "en": 0.22, "de": 0.22,
    "fr": 0.06, "es": 0.06, "it": 0.06,
    "pl": 0.04, "sv": 0.04, "bg": 0.03, "el": 0.03, "cs": 0.02,
}  # fmt: skip

FINANCE_LANGS = {
    "English": "en", "German": "de", "Dutch": "nl", "Spanish": "es",
    "Italian": "it", "Swedish": "sv", "France": "fr", "French": "fr",
}  # fmt: skip  ("France" is how the dataset spells French)


# --- HTTP ----------------------------------------------------------------------------------------
# The datasets-server rate-limits bursts (HTTP 429). Request starts are spread out across all threads.
MIN_INTERVAL = 0.3  # seconds between two request starts
_throttle_lock = threading.Lock()
_next_start = 0.0


def throttle() -> None:
    global _next_start
    with _throttle_lock:
        now = time.monotonic()
        wait = _next_start - now
        _next_start = max(now, _next_start) + MIN_INTERVAL
    if wait > 0:
        time.sleep(wait)


def retry_after(headers: Any) -> float:
    """The seconds a `Retry-After` header asks for; 0 when it is absent or an HTTP date."""
    try:
        return float(headers.get("Retry-After") or 0)
    except ValueError:
        return 0.0


def get_json(url: str, tries: int = 8) -> Any:
    """GETs `url` as JSON, retrying rate limits, server errors and the index-is-loading answer."""
    delay = 2.0
    for attempt in range(tries):
        throttle()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "piikey-eval/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            retriable = e.code in (429, 500, 502, 503, 504)
            if not retriable or attempt == tries - 1:
                raise
            wait = max(retry_after(e.headers), delay)
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == tries - 1:
                raise
            wait = delay
        time.sleep(wait)
        delay = min(delay * 2, 60.0)
    raise AssertionError("unreachable")


def hub_revision(dataset: str) -> dict[str, str]:
    """The commit the dataset is at now, for the manifest."""
    info = get_json(f"{HUB}/{dataset}")
    return {"sha": info.get("sha", ""), "last_modified": info.get("lastModified", "")}


class Pager:
    """`rows` pages of one dataset split, cached on disk (only the columns that are used)."""

    def __init__(self, dataset: str, split: str, cache: Path, columns: tuple[str, ...]) -> None:
        self.dataset, self.split, self.cache, self.columns = dataset, split, cache, columns
        self._truncated: dict[str, int] = {}  # per page: rows the API cut short
        cache.mkdir(parents=True, exist_ok=True)

    @property
    def truncated(self) -> int:
        """Rows skipped because a cell the API cut short is unusable (cached pages included)."""
        return sum(self._truncated.values())

    def rows(self, offset: int, length: int) -> tuple[list[dict], int]:
        """`(rows, total)`: rows `offset..offset+length` as `{"idx": row_idx, "row": {...}}`."""
        path = self.cache / f"{self.split}-{offset}-{length}.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self._truncated[path.name] = data.get("truncated", 0)
            return data["rows"], data["total"]
        query = urllib.parse.urlencode(
            {"dataset": self.dataset, "config": "default", "split": self.split,
             "offset": offset, "length": length}
        )  # fmt: skip
        page = get_json(f"{API}/rows?{query}")
        rows = []
        truncated = 0
        for item in page["rows"]:
            if set(item.get("truncated_cells") or []) & set(self.columns):
                truncated += 1
                continue
            rows.append({"idx": item["row_idx"], "row": {c: item["row"].get(c) for c in self.columns}})
        total = page["num_rows_total"]
        # Written aside and renamed: a run killed mid-write must not leave a page that cannot be read.
        partial = path.with_suffix(".tmp")
        partial.write_text(
            json.dumps({"rows": rows, "total": total, "truncated": truncated}, ensure_ascii=False),
            encoding="utf-8",
        )
        partial.replace(path)
        self._truncated[path.name] = truncated
        return rows, total


def fetch_all(pager: Pager, threads: int) -> list[dict]:
    """Every row of the split (for splits of a few thousand rows)."""
    _, total = pager.rows(0, PAGE)
    offsets = range(0, total, PAGE)
    with ThreadPoolExecutor(threads) as pool:
        pages = list(pool.map(lambda o: pager.rows(o, PAGE)[0], offsets))
    return [row for page in pages for row in page]


# --- sampling ------------------------------------------------------------------------------------
def quotas(weights: dict[str, float], cap: int) -> dict[str, int]:
    return {lang: max(1, round(cap * w)) for lang, w in weights.items()}


def sample_by_language(
    pool: dict[str, list[Any]], weights: dict[str, float], cap: int, seed: int, source: str
) -> list[Any]:
    """Items per language by its weight (all of a language when it has fewer), shuffled together.

    Each language is shuffled on its own seed and the first `quota` kept, so a larger `cap`
    returns a superset of a smaller one.
    """
    chosen: list[Any] = []
    for lang, quota in quotas(weights, cap).items():
        items = sorted(pool.get(lang, []), key=lambda r: r["idx"])
        random.Random(f"{seed}:{source}:{lang}").shuffle(items)
        if len(items) < quota:
            log(f"  {source}: only {len(items)} {lang} documents for a quota of {quota}")
        chosen.extend(items[:quota])
    random.Random(f"{seed}:{source}:order").shuffle(chosen)
    return chosen


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# --- converters ----------------------------------------------------------------------------------
def convert_finance(item: dict, label_map: dict[str, str], stats: SpanStats) -> dict | None:
    row = item["row"]
    text = row["generated_text"]
    if not isinstance(text, str) or not text:
        return None
    spans = [(s["start"], s["end"], s["label"]) for s in json.loads(row["pii_spans"] or "[]")]
    return {
        "id": f"finance_multilingual-{item['idx']}",
        "source": "finance_multilingual",
        "lang": FINANCE_LANGS[row["language"]],  # fetch_finance pooled only the languages it knows
        "group": row.get("document_type") or "",
        "text": text,
        "spans": char_spans_to_byte_spans(text, spans, label_map, stats),
    }


def convert_openpii(item: dict, label_map: dict[str, str], stats: SpanStats) -> dict | None:
    row = item["row"]
    text = row["source_text"]
    if not isinstance(text, str) or not text:
        return None
    spans = []
    for s in row["privacy_mask"]:
        if text[s["start"] : s["end"]] != s["value"]:
            stats.dropped_invalid += 1  # the offsets do not point at the value
            continue
        spans.append((s["start"], s["end"], s["label"]))
    return {
        "id": f"openpii-{row['uid']}",
        "source": "openpii",
        "lang": row["language"],
        "group": row.get("region") or "",
        "text": text,
        "spans": char_spans_to_byte_spans(text, spans, label_map, stats),
    }


def occurrences(text: str, value: str) -> list[int]:
    """Where `value` occurs in `text` as a whole token (not inside a longer word or number)."""
    found, i = [], 0
    while (j := text.find(value, i)) >= 0:
        before = text[j - 1] if j > 0 else " "
        after = text[j + len(value)] if j + len(value) < len(text) else " "
        glued_left = before.isalnum() and value[0].isalnum()
        glued_right = after.isalnum() and value[-1].isalnum()
        if not glued_left and not glued_right:
            found.append(j)
        i = j + len(value)
    return found


def convert_gretel_en(item: dict, label_map: dict[str, str], stats: SpanStats) -> dict | None:
    """Gretel gives the entity strings, not offsets: every whole-token occurrence is a span."""
    row = item["row"]
    text = row["text"]
    if not isinstance(text, str) or not text:
        return None
    entities = row["entities"]
    if isinstance(entities, str):
        entities = ast.literal_eval(entities)
    spans = []
    for entity in entities:
        value, label = entity["entity"], entity["types"][0]
        if not value.strip():
            stats.dropped_invalid += 1
            continue
        starts = occurrences(text, value)
        if not starts and (j := text.find(value)) >= 0:
            starts = [j]  # glued to a neighbour (a unit, a prefix): still the entity
        if not starts:
            stats.not_found += 1
        spans.extend((s, s + len(value), label) for s in starts)
    return {
        "id": f"gretel_en-{row['uid']}",
        "source": "gretel_en",
        "lang": "en",
        "group": row.get("domain") or "",
        "text": text,
        "spans": char_spans_to_byte_spans(text, spans, label_map, stats),
    }


# --- sources -------------------------------------------------------------------------------------
def fetch_finance(args: argparse.Namespace, cache: Path) -> list[dict]:
    pager = Pager(
        "gretelai/synthetic_pii_finance_multilingual", "test", cache,
        ("generated_text", "pii_spans", "language", "document_type"),
    )  # fmt: skip
    rows = fetch_all(pager, args.threads)
    pool: dict[str, list[dict]] = {}
    for item in rows:
        pool.setdefault(FINANCE_LANGS.get(item["row"]["language"], "?"), []).append(item)
    if pager.truncated:
        log(f"  finance_multilingual: skipped {pager.truncated} rows with truncated cells")
    return sample_by_language(pool, FINANCE_WEIGHTS, args.cap, args.seed, "finance_multilingual")


def fetch_gretel_en(args: argparse.Namespace, cache: Path) -> list[dict]:
    pager = Pager(
        "gretelai/gretel-pii-masking-en-v1", "test", cache,
        ("uid", "domain", "entities", "text"),
    )  # fmt: skip
    rows = fetch_all(pager, args.threads)
    if pager.truncated:
        log(f"  gretel_en: skipped {pager.truncated} rows with truncated cells")
    return sample_by_language({"en": rows}, {"en": 1.0}, args.cap, args.seed, "gretel_en")


def openpii_blocks(pager: Pager) -> dict[str, tuple[int, int]]:
    """`{language: (first row, row count)}` of the validation split, or `{}` when it is not ordered.

    The split is sorted by language, alphabetically, and the statistics endpoint gives the size of
    each language, so the blocks follow from a running sum. The first and the last row of every
    block are fetched to confirm it.
    """
    query = urllib.parse.urlencode({"dataset": pager.dataset, "config": "default", "split": pager.split})
    stats = get_json(f"{API}/statistics?{query}")
    freq = next(
        c["column_statistics"]["frequencies"]
        for c in stats["statistics"]
        if c["column_name"] == "language"
    )
    blocks, first = {}, 0
    for lang in sorted(freq):
        blocks[lang] = (first, freq[lang])
        first += freq[lang]
    for lang in OPENPII_WEIGHTS:
        if lang not in blocks:
            return {}
        start, count = blocks[lang]
        for idx in (start, start + count - 1):
            rows, _ = pager.rows(idx, 1)
            if not rows or rows[0]["row"]["language"] != lang:
                return {}
    return blocks


def fetch_openpii(args: argparse.Namespace, cache: Path) -> list[dict]:
    pager = Pager(
        "ai4privacy/pii-masking-openpii-1m", "validation", cache,
        ("source_text", "privacy_mask", "uid", "language", "region"),
    )  # fmt: skip
    blocks = openpii_blocks(pager)
    block = args.openpii_block
    if blocks:
        wanted = quotas(OPENPII_WEIGHTS, args.cap)
        plan = {lang: blocks[lang] for lang in wanted}
    else:
        log("  openpii: the split is not ordered by language any more; sampling it uniformly")
        _, total = pager.rows(0, 1)
        wanted = {"*": args.cap}
        plan = {"*": (0, total)}

    jobs: list[tuple[str, int]] = []  # (language, first row of a block of `block` rows)
    for lang, (start, count) in plan.items():
        rng = random.Random(f"{args.seed}:openpii:{lang}")
        # A few blocks more than the quota needs: a block the server cannot serve is skipped.
        wanted_blocks = math.ceil(wanted[lang] * 1.15 / block) + 1
        starts = rng.sample(range(count // block), min(count // block, wanted_blocks))
        jobs.extend((lang, start + i * block) for i in starts)
    log(f"  openpii: {len(jobs)} requests of {block} rows")

    def fetch_block(job: tuple[str, int]) -> list[dict]:
        try:
            return pager.rows(job[1], block)[0]
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            log(f"  openpii: the block at row {job[1]} failed ({e}); skipped")
            return []

    with ThreadPoolExecutor(args.threads) as pool:
        pages = list(pool.map(fetch_block, jobs))
    pool_by_lang: dict[str, list[dict]] = {}
    for (lang, _), rows in zip(jobs, pages):
        for item in rows:
            key = item["row"]["language"] if lang == "*" else lang
            pool_by_lang.setdefault(key, []).append(item)
    weights = OPENPII_WEIGHTS if blocks else {k: 1 / len(pool_by_lang) for k in pool_by_lang}
    return sample_by_language(pool_by_lang, weights, args.cap, args.seed, "openpii")


SOURCES: dict[str, dict[str, Any]] = {
    "finance_multilingual": {
        "dataset": "gretelai/synthetic_pii_finance_multilingual", "split": "test",
        "license": "Apache-2.0", "fetch": fetch_finance, "convert": convert_finance,
    },
    "openpii": {
        "dataset": "ai4privacy/pii-masking-openpii-1m", "split": "validation",
        "license": "CC-BY-4.0 (attribution: Ai4Privacy / Ai Suisse SA)",
        "fetch": fetch_openpii, "convert": convert_openpii,
        "note": "The detection model was trained on this dataset's train split: in-distribution.",
    },
    "gretel_en": {
        "dataset": "gretelai/gretel-pii-masking-en-v1", "split": "test",
        "license": "Apache-2.0", "fetch": fetch_gretel_en, "convert": convert_gretel_en,
    },
}  # fmt: skip


def run_source(name: str, args: argparse.Namespace, labels: dict, out: Path) -> dict:
    spec = SOURCES[name]
    log(f"{name}: {spec['dataset']} ({spec['split']})")
    label_map = source_map(labels, name)
    items = spec["fetch"](args, out / "raw" / name)
    convert: Callable = spec["convert"]
    stats = SpanStats()
    docs, problems = [], 0
    for item in items:
        doc = convert(item, label_map, stats)
        if doc is None:
            continue
        issues = validate_doc(doc, label_map)
        if issues:
            problems += 1
            log(f"  dropped {doc['id']}: {issues[0]}")
            continue
        docs.append(doc)
    sha256 = write_jsonl(out / f"{name}.jsonl", docs)
    label_counts = Counter(s["label"] for d in docs for s in d["spans"])
    log(f"  wrote {len(docs)} documents, {sum(label_counts.values())} spans -> {name}.jsonl")
    return {
        "dataset": spec["dataset"],
        "split": spec["split"],
        "license": spec["license"],
        "note": spec.get("note", ""),
        "revision": hub_revision(spec["dataset"]),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": args.seed,
        "cap": args.cap,
        "docs": len(docs),
        "docs_rejected_by_validation": problems,
        "bytes": sum(len(d["text"].encode("utf-8")) for d in docs),
        "languages": dict(Counter(d["lang"] for d in docs).most_common()),
        "labels": dict(label_counts.most_common()),
        "span_repairs": stats.as_dict(),
        "sha256": sha256,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--sources", default=",".join(SOURCES), help="comma-separated; default: all")
    parser.add_argument("--cap", type=int, default=2000, help="documents per source (default 2000)")
    parser.add_argument("--seed", type=int, default=20261020, help="sampling seed")
    parser.add_argument("--out", type=Path, default=EVAL_DIR / "data", help="output folder")
    parser.add_argument("--threads", type=int, default=3, help="parallel requests (default 3)")
    parser.add_argument("--openpii-block", type=int, default=5,
                        help="OpenPII rows per request: consecutive rows of one random block")  # fmt: skip
    parser.add_argument("--keep-raw", action="store_true",
                        help="keep the downloaded pages in <out>/raw after a successful run")  # fmt: skip
    args = parser.parse_args()

    names = [n for n in args.sources.split(",") if n]
    unknown = [n for n in names if n not in SOURCES]
    if unknown:
        parser.error(f"unknown source(s) {unknown}; choose from {list(SOURCES)}")
    labels = load_labels()
    manifest_path = args.out / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    for name in names:
        manifest[name] = run_source(name, args, labels, args.out)
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if not args.keep_raw:
        shutil.rmtree(args.out / "raw", ignore_errors=True)
    log(f"done: {manifest_path}")


if __name__ == "__main__":
    main()
