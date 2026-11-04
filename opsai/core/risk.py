"""Local command risk classification and deny list (TZ FR-541..FR-544).

The local verdict always wins over the AI label: resulting risk is
``max(ai_risk, local_risk)``. Chaining operators are blocked by default;
a single pipe is allowed.
"""

from __future__ import annotations

import re

_RISK_ORDER = {"read_only": 0, "change": 1, "destructive": 2}

_DESTRUCTIVE_RES = [
    re.compile(r"(?i)\brm\s+.*-r"),
    re.compile(r"(?i)\bmkfs\b"),
    re.compile(r"(?i)\bdd\s+.*of=/dev/"),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"(?i)\bkubectl\s+delete\s+(ns|namespace|node|pv|crd)\b"),
    re.compile(r"(?i)\bkafka-(topics|delete-records)\b.*--(delete|execute)\b"),
    re.compile(r"(?i)\bRemove-Item\b.*-Recurse"),
    re.compile(r"(?i)\bFormat-Volume\b"),
    re.compile(r"(?i)\bDROP\s+(DATABASE|TABLE)\b"),
    re.compile(r"(?i)\bTRUNCATE\b"),
    re.compile(r"(?i)\bkill\s+-9\b"),
    re.compile(r"(?i)\bscale\b.*--replicas=0\b"),
    re.compile(r"(?i)\b(shutdown|reboot|halt|poweroff)\b"),
    re.compile(r"(?i)\biptables\s+-F\b"),
]

_CHANGE_RES = [
    re.compile(r"(?i)\bsystemctl\s+(start|stop|restart|enable|disable)\b"),
    re.compile(r"(?i)\bservice\s+\S+\s+(start|stop|restart)\b"),
    re.compile(r"(?i)\bkubectl\s+(apply|patch|set|edit|delete|scale|rollout\s+restart)\b"),
    re.compile(r"(?i)\b(chmod|chown|chgrp)\b"),
    re.compile(r"(?i)\b(mkdir|rmdir|touch|mv|cp)\b"),
    re.compile(r"(?i)\b(Set-|New-|Restart-Service|Stop-Service|Start-Service)\b"),
    re.compile(r"(?i)\bdocker\s+(rm|rmi|stop|kill|restart|update)\b"),
    re.compile(r"(?i)\bsudo\b"),
]

_READ_ONLY_RES = [
    re.compile(
        r"(?i)^\s*(get|describe|logs|cat|ls|ps|top|df|du|journalctl|tail|head|grep|find|"
        r"stat|id|whoami|uname|env|printenv|echo|kubectl\s+(get|describe|logs|top)|"
        r"docker\s+(ps|logs|inspect|images)|systemctl\s+status|Get-|Test-)\b"
    ),
]

_DENY_RES = [
    re.compile(r"(?i)\brm\s+-rf\s+/(\s|$)"),
    re.compile(r"(?i)\bmkfs\b"),
    re.compile(r"(?i)\bdd\s+if=.*of=/dev/"),
    re.compile(r":\(\)\s*\{"),
    re.compile(r"(?i)\bkubectl\s+delete\s+(ns|namespace|node|pv|crd)\b"),
    re.compile(r"(?i)\bDROP\s+(DATABASE|TABLE)\b"),
]

_CHAIN_RES = [
    re.compile(r";"),
    re.compile(r"&&"),
    re.compile(r"\|\|"),
    re.compile(r"\$\("),
    re.compile(r"`"),
    re.compile(r"\n"),
]


def classify_risk(command: str) -> str:
    """Classify a command locally; unknown commands are at least ``change``."""
    text = (command or "").strip()
    if not text:
        return "change"
    for pattern in _DESTRUCTIVE_RES:
        if pattern.search(text):
            return "destructive"
    for pattern in _CHANGE_RES:
        if pattern.search(text):
            return "change"
    for pattern in _READ_ONLY_RES:
        if pattern.search(text):
            return "read_only"
    return "change"


def combine_risk(ai_risk: str, command: str) -> str:
    """Return ``max(ai_risk, local_risk)`` with unknown AI labels failing up."""
    local = classify_risk(command)
    ai_rank = _RISK_ORDER.get(ai_risk, 1)
    local_rank = _RISK_ORDER[local]
    rank = max(ai_rank, local_rank)
    for name, value in _RISK_ORDER.items():
        if value == rank:
            return name
    return "change"


def check_policy(command: str) -> tuple[bool, str]:
    """Check deny list and chaining; return ``(allowed, reason)``."""
    text = command or ""
    for pattern in _DENY_RES:
        if pattern.search(text):
            return False, f"Blocked by deny list: {pattern.pattern}"
    for pattern in _CHAIN_RES:
        if pattern.search(text):
            return False, f"Blocked command chaining: {pattern.pattern!r}"
    return True, ""
