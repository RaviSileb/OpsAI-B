"""Masking engine: consistent pseudonymization and verification.

Implements TZ FR-400..FR-408 and FR-412..FR-415 (MVP scope): default masking
step, fail-closed behavior flag, post-mask verification, consistent tokens
``<<TYPE_NNN>>``, encrypted pseudonym map, payload modes, manual masking and
allowlist-first matching.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from opsai.core.patterns import compute_templates
from opsai.masking.detectors import (
    DetectorFinding,
    detect_birth_numbers,
    detect_emails,
    detect_hostnames,
    detect_ips,
    detect_passwords,
    detect_tokens,
    detect_usernames,
)
from opsai.masking.presidio_backend import PresidioUnavailableError, available, detect_presidio

TOKEN_RE = re.compile(r"<<([A-Z0-9_]+?)>>")
NORMALIZE_TOKEN_RE = re.compile(
    r"<<\s*([a-z]+(?:_[a-z]+)*)_0*(\d+)\s*>>"
    r"|(?<![\w<])([a-z]+(?:_[a-z]+)*)_0*(\d+)(?![\w>])",
    re.IGNORECASE,
)
KNOWN_TOKEN_ENTITIES = frozenset(
    {
        "IP_PRIV",
        "IP_PUB",
        "IP6",
        "IP_LOOPBACK",
        "IP_LINKLOCAL",
        "EMAIL",
        "SECRET",
        "TOKEN",
        "USER",
        "RC",
        "HOST",
        "MANUAL",
        "URLPARAM",
        "CARD",
        "ACCT",
        "PHONE",
        "PERSON",
    }
)

DEFAULT_ALLOWLIST = frozenset({"root", "system", "localsystem", "administrator", "localhost"})


@dataclass
class MaskResult:
    """Result of masking one text."""

    masked: str
    findings: list[DetectorFinding]
    counts: dict[str, int]


class PseudonymMap:
    """Consistent value -> token mapping for one session (FR-403, FR-404)."""

    def __init__(self) -> None:
        self._token_by_key: dict[str, str] = {}
        self._value_by_token: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    @staticmethod
    def _norm_key(entity: str, value: str) -> str:
        if entity in {"HOST", "EMAIL", "USER"}:
            return f"{entity}:{value.lower()}"
        return f"{entity}:{value}"

    def token_for(self, entity: str, value: str) -> str:
        """Return the stable token for a value, creating it on first use."""
        key = self._norm_key(entity, value)
        existing = self._token_by_key.get(key)
        if existing:
            return existing
        number = self._counters.get(entity, 0) + 1
        self._counters[entity] = number
        token = f"<<{entity}_{number:03d}>>"
        self._token_by_key[key] = token
        self._value_by_token[token] = value
        return token

    def value_for(self, token: str) -> str | None:
        """Return the original value for a token (None = unknown token)."""
        return self._value_by_token.get(token)

    def as_dict(self) -> dict[str, str]:
        """Return a copy of the token -> value mapping."""
        return dict(self._value_by_token)

    def save_encrypted(self, path: Path, key: bytes) -> None:
        """Save the mapping encrypted with AES-256-GCM (never exported raw)."""
        if len(key) != 32:
            msg = "Pseudonym map key must be 32 bytes"
            raise ValueError(msg)
        nonce = os.urandom(12)
        body = json.dumps(self._value_by_token, ensure_ascii=False).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, body, None)
        payload = {
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(ciphertext).decode(),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    @classmethod
    def load_encrypted(cls, path: Path, key: bytes) -> PseudonymMap:
        """Load a mapping saved with :meth:`save_encrypted`."""
        if len(key) != 32:
            msg = "Pseudonym map key must be 32 bytes"
            raise ValueError(msg)
        payload = json.loads(path.read_text(encoding="utf-8"))
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["data"])
        body = AESGCM(key).decrypt(nonce, ciphertext, None)
        mapping: dict[str, str] = json.loads(body.decode("utf-8"))
        result = cls()
        for token, value in mapping.items():
            result._value_by_token[token] = value
            match = TOKEN_RE.fullmatch(token)
            if match:
                entity = match.group(1).rsplit("_", 1)[0]
                result._token_by_key[result._norm_key(entity, value)] = token
                try:
                    number = int(match.group(1).rsplit("_", 1)[1])
                except ValueError:
                    number = 0
                result._counters[entity] = max(result._counters.get(entity, 0), number)
        return result


@dataclass
class MaskingEngine:
    """Stateless detectors plus one session-scoped pseudonym map."""

    allowlist: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWLIST))
    known_hosts: list[str] = field(default_factory=list)
    pseudonyms: PseudonymMap = field(default_factory=PseudonymMap)
    presidio: str = "auto"

    def __post_init__(self) -> None:
        if self.presidio not in {"auto", "on", "off"}:
            msg = f"Invalid presidio mode {self.presidio!r}, expected auto/on/off"
            raise ValueError(msg)

    def _is_allowed(self, value: str) -> bool:
        return value.lower() in {item.lower() for item in self.allowlist}

    def _use_presidio(self) -> bool:
        if self.presidio == "off":
            return False
        if available():
            return True
        if self.presidio == "on":
            msg = "presidio mode 'on' but the 'presidio-analyzer' package is not installed"
            raise PresidioUnavailableError(msg)
        return False

    def scan(self, text: str) -> list[DetectorFinding]:
        """Run detectors M-01..M-07 plus Presidio gaps; allowlist wins (M-14)."""
        raw: list[DetectorFinding] = []
        raw.extend(detect_ips(text))
        raw.extend(detect_emails(text))
        raw.extend(detect_passwords(text))
        raw.extend(detect_tokens(text))
        raw.extend(detect_usernames(text))
        raw.extend(detect_birth_numbers(text))
        raw.extend(detect_hostnames(text, self.known_hosts))
        if self._use_presidio():
            # Presidio runs last: regex findings win overlap ties in mask_text.
            raw.extend(detect_presidio(text))
        filtered = [f for f in raw if not self._is_allowed(f.value)]
        return _deduplicate(filtered)

    def mask_text(self, text: str) -> MaskResult:
        """Mask sensitive values with consistent tokens."""
        findings = self.scan(text)
        # Replace from the end so offsets stay valid; skip overlaps.
        ordered = sorted(findings, key=lambda f: (f.start, f.end))
        chosen: list[DetectorFinding] = []
        last_end = -1
        for finding in ordered:
            if finding.start < last_end:
                continue
            chosen.append(finding)
            last_end = finding.end
        masked = text
        for finding in reversed(chosen):
            token = self.pseudonyms.token_for(finding.entity, finding.value)
            masked = masked[: finding.start] + token + masked[finding.end :]
        counts: dict[str, int] = {}
        for finding in chosen:
            counts[finding.entity] = counts.get(finding.entity, 0) + 1
        return MaskResult(masked=masked, findings=chosen, counts=counts)

    def mask_manual(self, text: str, expression: str) -> MaskResult:
        """Mask every occurrence of a manually picked expression (FR-408)."""
        if not expression:
            return MaskResult(masked=text, findings=[], counts={})
        token = self.pseudonyms.token_for("MANUAL", expression)
        masked = text.replace(expression, token)
        count = text.count(expression)
        return MaskResult(masked=masked, findings=[], counts={"MANUAL": count} if count else {})

    def verify_masked(self, masked: str) -> list[DetectorFinding]:
        """Rescan masked payload; token spans and allowlist are excluded (FR-402)."""
        spans = [(m.start(), m.end()) for m in TOKEN_RE.finditer(masked)]

        def inside_token(start: int, end: int) -> bool:
            return any(start >= s and end <= e for s, e in spans)

        findings = self.scan(masked)
        return [f for f in findings if not inside_token(f.start, f.end)]

    @staticmethod
    def depseudonymize(text: str, mapping: dict[str, str]) -> tuple[str, list[str]]:
        """Restore values; tolerate mangled tokens (FR-414).

        Returns ``(restored_text, unknown_tokens)``. Unknown tokens must
        block execution (FR-405).
        """
        unknown: list[str] = []

        def restore(match: re.Match[str]) -> str:
            bracketed = match.group(1) is not None
            entity = (match.group(1) or match.group(3) or "").upper()
            number = match.group(2) or match.group(4) or "0"
            if not bracketed and entity not in KNOWN_TOKEN_ENTITIES:
                return match.group(0)
            candidates = [
                f"<<{entity}_{int(number):03d}>>",
                f"<<{entity}_{number}>>",
            ]
            for candidate in candidates:
                if candidate in mapping:
                    return mapping[candidate]
            unknown.append(match.group(0))
            return match.group(0)

        return NORMALIZE_TOKEN_RE.sub(restore, text), unknown


def _deduplicate(findings: list[DetectorFinding]) -> list[DetectorFinding]:
    seen: set[tuple[str, int, int]] = set()
    unique: list[DetectorFinding] = []
    for finding in findings:
        key = (finding.entity, finding.start, finding.end)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def build_payload(
    records: list[dict[str, Any]],
    mode: str,
    max_chars: int = 60_000,
) -> tuple[str, dict[str, Any]]:
    """Build the AI payload text in ``full`` / ``messages`` / ``patterns`` mode."""
    if mode not in {"full", "messages", "patterns"}:
        msg = f"Unknown payload mode {mode!r}"
        raise ValueError(msg)
    if mode == "patterns":
        messages = [str(r.get("message", "")) for r in records]
        templates = compute_templates(messages)
        lines = [f"- {item.template}  [x{item.count}]" for item in templates[:20]]
        lines.extend(f"  sample: {sample[:300]}" for sample in messages[:3])
        text = "Log patterns with counts:\n" + "\n".join(lines[:50])
    elif mode == "messages":
        lines = [f"R{i + 1}: {r.get('message', '')}" for i, r in enumerate(records)]
        text = "\n".join(lines)
    else:
        lines = [
            f"R{i + 1} [{r.get('ts', '')}] [{r.get('level', '?')}]"
            f" {r.get('origin_host', '?')}/{r.get('service', '?')}: {r.get('message', '')}"
            for i, r in enumerate(records)
        ]
        text = "\n".join(lines)
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    meta = {
        "mode": mode,
        "records": len(records),
        "chars": len(text),
        "truncated": truncated,
        "sha256": digest,
    }
    return text, meta
