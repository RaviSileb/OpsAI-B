"""Pattern mining and anomaly heuristics without AI (TZ FR-200..205).

Two backends share one output shape: deterministic regex normalization and
Drain3 clustering (optional ``drain3`` package, stateless per call).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from statistics import median

BACKENDS = ("auto", "regex", "drain3")


class DrainUnavailableError(Exception):
    """Raised when the drain3 backend is requested but not installed."""


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NUM_RE = re.compile(r"\b\d+(?:[.,]\d+)*\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_PATH_RE = re.compile(r"(?:/[A-Za-z0-9_.-]+)+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass(frozen=True)
class TemplateInfo:
    """One message template with its count and stable hash."""

    template: str
    count: int
    hash: str


def normalize_message(message: str) -> str:
    """Replace variable parts of a message with placeholders."""
    text = _EMAIL_RE.sub("<*>", message)
    text = _IP_RE.sub("<*>", text)
    text = _UUID_RE.sub("<*>", text)
    text = _HEX_RE.sub("<*>", text)
    text = _PATH_RE.sub("<*>", text)
    return _NUM_RE.sub("<*>", text)


def template_hash(template: str) -> str:
    """Return the stable hash identifying a template."""
    return hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]


def resolve_backend(requested: str = "auto") -> str:
    """Resolve ``auto``/``regex``/``drain3`` to the backend to use."""
    name = (requested or "auto").lower()
    if name not in BACKENDS:
        msg = f"Unknown patterns backend {requested!r} (expected one of {', '.join(BACKENDS)})"
        raise ValueError(msg)
    if name == "auto":
        from opsai.core.drain_miner import available

        return "drain3" if available() else "regex"
    if name == "drain3":
        from opsai.core.drain_miner import available

        if not available():
            msg = "drain3 backend requested but the 'drain3' package is not installed"
            raise DrainUnavailableError(msg)
    return name


def compute_templates(messages: list[str], backend: str = "auto") -> list[TemplateInfo]:
    """Group messages into templates sorted by count descending."""
    if resolve_backend(backend) == "drain3":
        from opsai.core.drain_miner import mine

        return mine(messages)
    counts: dict[str, int] = {}
    for message in messages:
        template = normalize_message(message or "")
        counts[template] = counts.get(template, 0) + 1
    infos = [TemplateInfo(template=t, count=c, hash=template_hash(t)) for t, c in counts.items()]
    infos.sort(key=lambda info: (-info.count, info.template))
    return infos


def compare_windows(
    old: list[str], new: list[str], backend: str = "auto"
) -> dict[str, list[dict[str, object]]]:
    """Compare template distributions of two windows (FR-205)."""
    old_counts = {t.template: t.count for t in compute_templates(old, backend)}
    new_counts = {t.template: t.count for t in compute_templates(new, backend)}
    gone = [
        {"template": t, "count": c} for t, c in sorted(old_counts.items()) if t not in new_counts
    ]
    fresh = [
        {"template": t, "count": c} for t, c in sorted(new_counts.items()) if t not in old_counts
    ]
    changed: list[dict[str, object]] = []
    for template, new_count in sorted(new_counts.items()):
        old_count = old_counts.get(template)
        if old_count is None or old_count < 5:
            continue
        ratio = new_count / old_count
        if ratio >= 2.0 or ratio <= 0.5:
            changed.append({"template": template, "old": old_count, "new": new_count})
    return {"new": fresh, "gone": gone, "changed": changed}


def spike_buckets(counts: list[int], threshold: float = 3.5) -> list[int]:
    """Return bucket indexes whose robust z-score exceeds the threshold."""
    if len(counts) < 10:
        return []
    med = median(counts)
    deviations = sorted(abs(c - med) for c in counts)
    mad = median(deviations)
    if mad == 0:
        return [i for i, count in enumerate(counts) if count > med]
    scale = 1.4826 * mad
    return [i for i, count in enumerate(counts) if abs(count - med) / scale >= threshold]
