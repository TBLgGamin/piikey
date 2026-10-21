"""Shared helpers of the eval scripts: the label table, span conversion and validation, JSONL I/O.

Python 3.11+, standard library only.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
LABELS_PATH = EVAL_DIR / "labels.toml"


def load_labels(path: Path = LABELS_PATH) -> dict:
    """The parsed label table (`eval/labels.toml`)."""
    with path.open("rb") as f:
        return tomllib.load(f)


def source_map(labels: dict, source: str) -> dict[str, str]:
    """The labels of `source` and the category of each, or SystemExit when the source is unknown."""
    table = labels.get("source", {}).get(source)
    if table is None:
        raise SystemExit(f"labels.toml has no [source.{source}] table")
    unknown = {c for c in table.values() if c not in labels["categories"]}
    if unknown:
        raise SystemExit(f"[source.{source}] maps to unknown categories {sorted(unknown)}")
    return table


def byte_offsets(text: str) -> list[int]:
    """`offsets[i]` is the UTF-8 byte offset of character `i` (and `offsets[len(text)]` the length)."""
    offsets = [0] * (len(text) + 1)
    total = 0
    for i, ch in enumerate(text):
        offsets[i] = total
        total += len(ch.encode("utf-8"))
    offsets[len(text)] = total
    return offsets


class SpanStats:
    """Counts of what a converter had to repair, kept in the manifest."""

    def __init__(self) -> None:
        self.kept = 0
        self.dropped_invalid = 0
        self.dropped_overlap = 0
        self.dropped_unmapped = 0
        self.trimmed = 0
        self.not_found = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


def char_spans_to_byte_spans(
    text: str,
    spans: list[tuple[int, int, str]],
    label_map: dict[str, str],
    stats: SpanStats,
) -> list[dict]:
    """Normalizes `(char_start, char_end, label)` spans of `text` into JSONL spans.

    - Whitespace at either edge is trimmed; a span left empty or out of range is dropped.
    - A label that `label_map` does not know is dropped and counted (never silently mapped).
    - Overlapping spans keep the longest (ties: the earlier); the others are dropped.
    - Offsets become UTF-8 byte offsets, sorted by start.
    """
    offsets = byte_offsets(text)
    n = len(text)
    clean: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if not (0 <= start < end <= n):
            stats.dropped_invalid += 1
            continue
        s, e = start, end
        while s < e and text[s].isspace():
            s += 1
        while e > s and text[e - 1].isspace():
            e -= 1
        if s >= e:
            stats.dropped_invalid += 1
            continue
        if (s, e) != (start, end):
            stats.trimmed += 1
        if label not in label_map:
            stats.dropped_unmapped += 1
            continue
        clean.append((s, e, label))

    accepted: list[tuple[int, int, str]] = []
    # Longest first; of two of the same length, the earlier start.
    for s, e, label in sorted(clean, key=lambda t: (-(t[1] - t[0]), t[0])):
        if any(s < a_end and a_start < e for a_start, a_end, _ in accepted):
            stats.dropped_overlap += 1
        else:
            accepted.append((s, e, label))
    accepted.sort()
    stats.kept += len(accepted)
    return [{"start": offsets[s], "end": offsets[e], "label": label} for s, e, label in accepted]


def validate_doc(doc: dict, label_map: dict[str, str]) -> list[str]:
    """What is wrong with `doc` (empty when it is a well-formed JSONL record)."""
    problems: list[str] = []
    for key in ("id", "source", "lang", "text", "spans"):
        if key not in doc:
            problems.append(f"missing {key!r}")
    if problems:
        return problems
    text = doc["text"]
    if not isinstance(text, str) or not text:
        return ["empty text"]
    raw = text.encode("utf-8")
    last_end = 0
    for i, span in enumerate(doc["spans"]):
        start, end, label = span.get("start"), span.get("end"), span.get("label")
        where = f"span {i} {label!r} [{start}, {end})"
        if not (isinstance(start, int) and isinstance(end, int)):
            problems.append(f"{where}: offsets are not integers")
            continue
        if not (0 <= start < end <= len(raw)):
            problems.append(f"{where}: out of range 0..{len(raw)}")
            continue
        if start < last_end:
            problems.append(f"{where}: overlaps or is out of order")
        last_end = max(last_end, end)
        try:
            value = raw[start:end].decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{where}: cuts a UTF-8 character")
            continue
        if value != value.strip():
            problems.append(f"{where}: value {value!r} has edge whitespace")
        if label not in label_map:
            problems.append(f"{where}: label not in the label table")
    return problems


def write_jsonl(path: Path, docs: list[dict]) -> str:
    """Writes `docs` as UTF-8 JSONL (one compact object per line) and returns the SHA-256 of the file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with path.open("wb") as f:
        for doc in docs:
            line = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
            digest.update(line)
            f.write(line)
    return digest.hexdigest()
