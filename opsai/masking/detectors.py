"""Detectors for sensitive entities M-01..M-07 (TZ 8.1).

No detector reaches 100% recall; post-mask verification (FR-402) and the
user preview stay mandatory. All detectors return findings with absolute
offsets into the scanned text.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]+\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PASSWORD_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|secret|credentials|credential|heslo)"
    r"\s*[:=]\s*([^\s,;\"']+)"
)
_URL_PASSWORD_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@]+)@")
_CONNSTRING_RE = re.compile(r"(?i)\b(password|pwd)\s*=\s*([^;]+);")
_CLI_PASSWORD_RE = re.compile(r"(?:^|\s)(?:-p|--password|-Password)\s+([^\s]+)")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_BEARER_RE = re.compile(r"(?i)\b(?:authorization\s*:\s*(?:bearer|basic)\s+)([^\s,;\"']+)")
_PREFIXED_TOKEN_RE = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"
    r"|\bghp_[A-Za-z0-9]{20,}\b"
    r"|\bgho_[A-Za-z0-9]{20,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{10,}\b"
    r"|\bglpat-[A-Za-z0-9_-]{10,}\b"
    r"|\bxox[abpr]-[A-Za-z0-9-]+\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{10,}\b"
    r"|\bAIza[A-Za-z0-9_-]{20,}\b"
    r"|\bsk-[A-Za-z0-9]{10,}\b"
)
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9+/=._-]{24,}\b")
_USERNAME_RE = re.compile(
    r"(?i:\b(?:user|username|login|uid|sAMAccountName|TargetUserName|SubjectUserName)"
    r"\s*[:=]\s*([A-Za-z0-9_][A-Za-z0-9_@.-]*))"
    r"|(?i:\bFailed password for (?:invalid user )?([A-Za-z0-9_][A-Za-z0-9_.-]*))"
    r"|(?i:\bfor user ([A-Za-z0-9_][A-Za-z0-9_.-]*))"
)
_HOME_DIR_RE = re.compile(r"(?:/home/|C:\\Users\\)([A-Za-z0-9_][A-Za-z0-9_.-]*)")
_RC_RE = re.compile(r"\b(\d{6})/?(\d{3,4})\b")
_FQDN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:cz|sk|com|org|net|io|eu|local|internal|lan|corp)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DetectorFinding:
    """One detected sensitive span."""

    entity: str
    value: str
    start: int
    end: int


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_ips(text: str) -> list[DetectorFinding]:
    """Detect IPv4/IPv6 addresses, keeping the address class in the entity."""
    findings: list[DetectorFinding] = []
    for match in _IPV4_RE.finditer(text):
        try:
            addr = ipaddress.IPv4Address(match.group(0))
        except ipaddress.AddressValueError:
            continue
        if addr.is_loopback:
            entity = "IP_LOOPBACK"
        elif addr.is_private:
            entity = "IP_PRIV"
        elif addr.is_link_local:
            entity = "IP_LINKLOCAL"
        else:
            entity = "IP_PUB"
        findings.append(DetectorFinding(entity, match.group(0), match.start(), match.end()))
    for match in _IPV6_CANDIDATE_RE.finditer(text):
        try:
            ipaddress.IPv6Address(match.group(0).strip(".:"))
        except ipaddress.AddressValueError:
            continue
        findings.append(DetectorFinding("IP6", match.group(0), match.start(), match.end()))
    return findings


def detect_emails(text: str) -> list[DetectorFinding]:
    """Detect e-mail addresses."""
    return [
        DetectorFinding("EMAIL", m.group(0), m.start(), m.end()) for m in _EMAIL_RE.finditer(text)
    ]


def detect_passwords(text: str) -> list[DetectorFinding]:
    """Detect passwords in key=value pairs, URLs, connection strings, CLI args."""
    findings: list[DetectorFinding] = []
    for match in _PASSWORD_KV_RE.finditer(text):
        findings.append(DetectorFinding("SECRET", match.group(2), match.start(2), match.end(2)))
    for match in _URL_PASSWORD_RE.finditer(text):
        findings.append(DetectorFinding("SECRET", match.group(2), match.start(2), match.end(2)))
    for match in _CONNSTRING_RE.finditer(text):
        findings.append(DetectorFinding("SECRET", match.group(2), match.start(2), match.end(2)))
    for match in _CLI_PASSWORD_RE.finditer(text):
        findings.append(DetectorFinding("SECRET", match.group(1), match.start(1), match.end(1)))
    return findings


def detect_tokens(text: str) -> list[DetectorFinding]:
    """Detect JWT, bearer tokens, provider keys, PEM blocks, high-entropy strings."""
    findings: list[DetectorFinding] = []
    for match in _JWT_RE.finditer(text):
        findings.append(DetectorFinding("TOKEN", match.group(0), match.start(), match.end()))
    for match in _BEARER_RE.finditer(text):
        findings.append(DetectorFinding("TOKEN", match.group(1), match.start(1), match.end(1)))
    for match in _PREFIXED_TOKEN_RE.finditer(text):
        findings.append(DetectorFinding("TOKEN", match.group(0), match.start(), match.end()))
    for match in _PEM_RE.finditer(text):
        findings.append(DetectorFinding("TOKEN", match.group(0), match.start(), match.end()))
    for match in _HIGH_ENTROPY_RE.finditer(text):
        candidate = match.group(0).strip("._-=")
        if len(candidate) < 24:
            continue
        alphabet = set(candidate)
        if len(alphabet) < 10:
            continue
        if _shannon_entropy(candidate) > 4.0:
            findings.append(DetectorFinding("TOKEN", candidate, match.start(), match.end()))
    return findings


def detect_usernames(text: str) -> list[DetectorFinding]:
    """Detect usernames from context patterns and home directories."""
    findings: list[DetectorFinding] = []
    for match in _USERNAME_RE.finditer(text):
        for group_no in range(1, 4):
            value = match.group(group_no)
            if value:
                findings.append(
                    DetectorFinding("USER", value, match.start(group_no), match.end(group_no))
                )
                break
    for match in _HOME_DIR_RE.finditer(text):
        findings.append(DetectorFinding("USER", match.group(1), match.start(1), match.end(1)))
    return findings


def _valid_czech_birth_number(first: str, second: str) -> bool:
    year = int(first[0:2])
    month = int(first[2:4])
    day = int(first[4:6])
    month_norm = month % 50 if month > 12 else month
    extra = month - month_norm
    if month_norm < 1 or month_norm > 12:
        return False
    if day < 1 or day > 31:
        return False
    if len(second) == 4:
        number = int(first + second)
        if number % 11 != 0:
            # Numbers assigned before 1986 allow check digit 0 with remainder 10.
            if not (year <= 85 and extra == 0 and second.endswith("0")):
                return False
        return True
    return year < 54


def detect_birth_numbers(text: str) -> list[DetectorFinding]:
    """Detect Czech birth numbers (rodna cisla) with validation."""
    findings: list[DetectorFinding] = []
    for match in _RC_RE.finditer(text):
        if _valid_czech_birth_number(match.group(1), match.group(2)):
            findings.append(DetectorFinding("RC", match.group(0), match.start(), match.end()))
    return findings


def detect_hostnames(text: str, known_hosts: list[str]) -> list[DetectorFinding]:
    """Detect known hosts (exact, case-insensitive) and FQDN values."""
    findings: list[DetectorFinding] = []
    lowered = text.lower()
    for host in known_hosts:
        needle = host.strip().lower()
        if len(needle) < 2:
            continue
        start = 0
        while True:
            pos = lowered.find(needle, start)
            if pos < 0:
                break
            findings.append(
                DetectorFinding("HOST", text[pos : pos + len(needle)], pos, pos + len(needle))
            )
            start = pos + len(needle)
    for match in _FQDN_RE.finditer(text):
        findings.append(DetectorFinding("HOST", match.group(0), match.start(), match.end()))
    return findings
