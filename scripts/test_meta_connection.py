#!/usr/bin/env python3
"""Meta Model API connectivity test (variant B, TBD-101, FR-208).

Steps: DNS resolve -> TCP connect -> TLS handshake -> auth (GET /v1/models)
-> minimal read (muse-spark-1.3 listed) -> latency. Stdlib only.

Usage:
    python3 scripts/test_meta_connection.py --api-key "$OPSAI_META_API_KEY"
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import sys
import time
import urllib.parse

HOST = "api.meta.ai"
PORT = 443
BASE_PATH = "/v1"
EXPECTED_MODEL = "muse-spark-1.3"


def step(ok: bool, name: str, detail: str = "") -> bool:
    """Print one step result and return its status."""
    mark = "OK  " if ok else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"[{mark}] {name}{suffix}")
    return ok


def main() -> int:
    """Run all connectivity steps; return 0 only when all pass."""
    parser = argparse.ArgumentParser(description="Test Meta Model API connectivity.")
    parser.add_argument("--api-key", required=True, help="MODEL_API_KEY value")
    parser.add_argument("--host", default=HOST, help="API hostname")
    parser.add_argument("--timeout", type=float, default=15.0, help="Socket timeout (s)")
    args = parser.parse_args()

    results: list[bool] = []
    started = time.monotonic()

    try:
        infos = socket.getaddrinfo(args.host, PORT, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
    except OSError as exc:
        results.append(step(False, "DNS resolve", str(exc)))
        return _finish(results, started)
    results.append(step(True, "DNS resolve", ", ".join(ips)))

    raw: socket.socket | None = None
    try:
        raw = socket.create_connection((args.host, PORT), timeout=args.timeout)
    except OSError as exc:
        results.append(step(False, "TCP connect", str(exc)))
        return _finish(results, started)
    results.append(step(True, "TCP connect", f"{args.host}:{PORT}"))

    context = ssl.create_default_context()
    try:
        tls = context.wrap_socket(raw, server_hostname=args.host)
        cert = tls.getpeercert()
        version = tls.version() or "?"
    except (OSError, ssl.SSLError, ssl.CertificateError) as exc:
        raw.close()
        results.append(step(False, "TLS handshake", str(exc)))
        return _finish(results, started)
    subject = urllib.parse.quote(str(cert.get("subject", ""))[:80]) if cert else "?"
    results.append(step(True, "TLS handshake", f"{version}, subject={subject}"))

    conn = http.client.HTTPSConnection(args.host, PORT, timeout=args.timeout, context=context)
    try:
        conn.request(
            "GET", f"{BASE_PATH}/models", headers={"Authorization": f"Bearer {args.api_key}"}
        )
        response = conn.getresponse()
        body = response.read().decode("utf-8", "replace")
    except OSError as exc:
        results.append(step(False, "Auth GET /v1/models", str(exc)))
        return _finish(results, started)
    finally:
        conn.close()
    tls.close()
    if response.status in (401, 403):
        results.append(
            step(
                False,
                "Auth GET /v1/models",
                f"HTTP {response.status} — invalid key or inactive billing",
            )
        )
        return _finish(results, started)
    if response.status != 200:
        results.append(step(False, "Auth GET /v1/models", f"HTTP {response.status}: {body[:200]}"))
        return _finish(results, started)
    results.append(step(True, "Auth GET /v1/models", "HTTP 200"))

    try:
        data = json.loads(body)
        ids = [m.get("id", "") for m in data.get("data", [])]
    except ValueError:
        results.append(step(False, "Minimal read", "response is not JSON"))
        return _finish(results, started)
    if EXPECTED_MODEL not in ids:
        results.append(step(False, "Minimal read", f"{EXPECTED_MODEL} not in {len(ids)} models"))
        return _finish(results, started)
    results.append(step(True, "Minimal read", f"{EXPECTED_MODEL} listed"))
    return _finish(results, started)


def _finish(results: list[bool], started: float) -> int:
    elapsed_ms = int((time.monotonic() - started) * 1000)
    print(f"Latency (total): {elapsed_ms} ms")
    failed = [r for r in results if not r]
    print(
        f"Result: {'PASS' if not failed else 'FAIL'} "
        f"({len(results) - len(failed)}/{len(results)} steps)"
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
