"""Drain3 template mining backend (TZ FR-200..204).

Stateless per call: a fresh in-memory miner groups the given messages, so
OQL-filtered subsets never pollute any shared state. The ``drain3`` package
is optional; :func:`available` reports whether it can be imported.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opsai.core.patterns import TemplateInfo, template_hash

if TYPE_CHECKING:
    from drain3 import TemplateMiner


def available() -> bool:
    """Return True when the optional ``drain3`` package is importable."""
    try:
        import drain3  # noqa: F401
    except ImportError:
        return False
    return True


def _new_miner() -> TemplateMiner:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig

    # Explicit default config: no drain3.ini lookup, no stdout noise.
    return TemplateMiner(config=TemplateMinerConfig())


def mine(messages: list[str]) -> list[TemplateInfo]:
    """Group messages with Drain3; same output shape as the regex backend."""
    miner = _new_miner()
    for message in messages:
        miner.add_log_message(message or "")
    infos = [
        TemplateInfo(
            template=" ".join(cluster.log_template_tokens),
            count=cluster.size,
            hash=template_hash(" ".join(cluster.log_template_tokens)),
        )
        for cluster in miner.drain.clusters
    ]
    infos.sort(key=lambda info: (-info.count, info.template))
    return infos
