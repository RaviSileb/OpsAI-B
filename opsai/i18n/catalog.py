"""Message catalog loader with cs/en fallback."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_CATALOG_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=4)
def _load(lang: str) -> dict[str, str]:
    path = _CATALOG_DIR / f"{lang}.json"
    if not path.exists():
        path = _CATALOG_DIR / "en.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): str(v) for k, v in data.items()}


def t(lang: str, key: str) -> str:
    """Translate a key, falling back to English and then the key itself."""
    catalog = _load(lang if lang in {"cs", "en"} else "en")
    if key in catalog:
        return catalog[key]
    fallback = _load("en")
    return fallback.get(key, key)
