"""Connector registry: new sources plug in without core changes."""

from __future__ import annotations

from opsai.connectors.base import Connector

_REGISTRY: dict[str, type[Connector]] = {}


def register(connector_cls: type[Connector]) -> type[Connector]:
    """Register a connector class under its ``name``."""
    _REGISTRY[connector_cls.name] = connector_cls
    return connector_cls


def get_connector(name: str) -> Connector:
    """Instantiate a registered connector by name."""
    cls = _REGISTRY.get(name)
    if cls is None:
        msg = f"Unknown connector {name!r}; registered: {sorted(_REGISTRY)}"
        raise KeyError(msg)
    return cls()


def list_connectors() -> list[str]:
    """Return sorted names of registered connectors."""
    return sorted(_REGISTRY)


def ensure_builtin_connectors() -> None:
    """Import built-in connectors so they self-register."""
    from opsai.connectors import azure as _azure  # noqa: F401
    from opsai.connectors import docker as _docker  # noqa: F401
    from opsai.connectors import elasticsearch as _elasticsearch  # noqa: F401
    from opsai.connectors import file as _file  # noqa: F401
    from opsai.connectors import journald as _journald  # noqa: F401
    from opsai.connectors import kafka as _kafka  # noqa: F401
    from opsai.connectors import kubernetes as _kubernetes  # noqa: F401
    from opsai.connectors import loki as _loki  # noqa: F401
    from opsai.connectors import syslog as _syslog  # noqa: F401
    from opsai.connectors import windows as _windows  # noqa: F401
