#!/usr/bin/env python3
"""API endpoint enumeration and method switching probe.

Tests:
- Directory brute-forcing under /api/engine/
- Swagger / OpenAPI / API docs discovery
- HTTP method switching (GET, PUT, PATCH, DELETE, OPTIONS, TRACE)
- Path normalization bypasses
- Header-based routing bypass (X-HTTP-Method-Override)

ROE: Amendment 04, Section 3.4 — Dev API only.
"""

from __future__ import annotations

import argparse
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
    build_request_body,
)


def _send_raw(
    url: str,
    method: str,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, str, float, dict[str, str] | None]:
    import time as time_mod

    t0 = time_mod.perf_counter()
    try:
        fn = getattr(requests, method.lower())
        kwargs: dict[str, Any] = {"headers": headers, "timeout": timeout}
        if body is not None and method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = body
        resp = fn(url, **kwargs)
        elapsed = (time_mod.perf_counter() - t0) * 1000
        resp_headers = dict(resp.headers) if resp.status_code < 400 else None
        return resp.status_code, resp.text, elapsed, resp_headers
    except requests.exceptions.Timeout:
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return 0, "TIMEOUT", elapsed, None
    except requests.exceptions.ConnectionError as exc:
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return 0, f"CONN_ERR: {exc}", elapsed, None


def probe_directory_enum(base_url: str, authkey: str, orgid: str) -> list[ProbeResult]:
    """Brute-force common API paths."""
    results: list[ProbeResult] = []
    base = base_url.rsplit("/", 1)[0]  # e.g. https://.../api/engine

    paths = [
        "internal",
        "external",
        "public",
        "batch",
        "async",
        "upload",
        "process",
        "extract",
        "health",
        "status",
        "ready",
        "live",
        "metrics",
        "prometheus",
        "debug",
        "test",
        "config",
        "swagger.json",
        "swagger-ui.html",
        "api-docs",
        "openapi.json",
        "openapi.yaml",
        "v1",
        "v2",
        "v1/process",
        "v1/upload",
        "documents",
        "jobs",
        "tasks",
        "results",
        "feedback",
        "webhook",
        "callback",
        "auth",
        "login",
        "token",
        "oauth",
        "users",
        "orgs",
        "organizations",
    ]

    headers = {
        "apiversion": API_VERSION,
        "authkey": authkey,
        "orgid": orgid,
        "content-type": "application/json",
    }

    for path in paths:
        url = f"{base}/{path}"
        status, text, elapsed, resp_headers = _send_raw(url, "GET", headers)

        # Any response other than 404 suggests the endpoint exists
        if status != 404:
            finding = f"Endpoint exists: {url} (status={status})"
            severity = "medium" if status == 200 else "low"
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


def probe_method_switch(endpoint: str, authkey: str, orgid: str) -> list[ProbeResult]:
    """Switch HTTP methods on the main processing endpoint."""
    results: list[ProbeResult] = []
    methods = ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD"]

    base_body = build_request_body(
        file_data="https://example.com/sample.pdf",
        prompt="What is this document?",
    )

    headers = {
        "apiversion": API_VERSION,
        "authkey": authkey,
        "orgid": orgid,
        "content-type": "application/json",
    }

    for method in methods:
        status, text, elapsed, resp_headers = _send_raw(
            endpoint, method, headers, body=base_body if method != "GET" else None
        )

        if status == 200 and method != "POST":
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


def probe_path_traversal(base_url: str, authkey: str, orgid: str) -> list[ProbeResult]:
    """Path normalization and traversal bypass attempts."""
    results: list[ProbeResult] = []
    base = base_url.rsplit("/", 1)[0]

    traversals = [
        "internal/../external",
        "internal/./../external",
        "internal/%2e%2e/external",
        "internal..;/external",
        "internal;/../external",
        "..%00/internal",
        "..%0d/internal",
        "..%0a/internal",
        "internal/../../",
        "internal/%2e%2e/%2e%2e/",
    ]

    headers = {
        "apiversion": API_VERSION,
        "authkey": authkey,
        "orgid": orgid,
        "content-type": "application/json",
    }

    for traversal in traversals:
        url = f"{base}/{traversal}"
        status, text, elapsed, resp_headers = _send_raw(url, "GET", headers)

        if status != 404 and status != 400:
            finding = f"Path traversal bypass: {url} (status={status})"
            severity = "high"
        else:
            finding = None
            severity = "info"

        results.append(
            ProbeResult(
                probe_name="path_traversal",
                iteration=len(results) + 1,
                payload_id=f"traversal_{traversal.replace('/', '_').replace('.', '_')}",
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text[:500],
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [traversal] {url}: status={status} finding={finding}")
    return results


def probe_method_override(endpoint: str, authkey: str, orgid: str) -> list[ProbeResult]:
    """X-HTTP-Method-Override and similar header bypasses."""
    results: list[ProbeResult] = []
    overrides = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "_method",
    ]

    base_body = build_request_body(
        file_data="https://example.com/sample.pdf",
        prompt="What is this document?",
    )

    for header_name in overrides:
        headers = {
            "apiversion": API_VERSION,
            "authkey": authkey,
            "orgid": orgid,
            "content-type": "application/json",
            header_name: "DELETE",
        }
        status, text, elapsed, resp_headers = _send_raw(
            endpoint, "POST", headers, body=base_body
        )

        if status == 200:
            finding = f"Method override accepted: {header_name}=DELETE"
            severity = "high"
        elif status == 405:
            finding = None
            severity = "info"
        else:
            finding = f"Method override {header_name} returned {status}"
            severity = "info"

        results.append(
            ProbeResult(
                probe_name="method_override",
                iteration=len(results) + 1,
                payload_id=f"override_{header_name.lower().replace('-', '_')}",
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text[:500],
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [override] {header_name}: status={status} finding={finding}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Endpoint enumeration probe")
    parser.add_argument("--endpoint", default="https://api-dev.gcp.lzrops.com/api/engine/internal")
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/fuzz"))
    args = parser.parse_args()

    session = ProbeSession(
        probe_name="endpoint_enum",
        endpoint=args.endpoint,
        started_at=__import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
    )

    print(f"[ENUM] Directory enumeration…")
    for r in probe_directory_enum(args.endpoint, args.authkey, args.orgid):
        session.add(r)

    print(f"[ENUM] Method switching…")
    for r in probe_method_switch(args.endpoint, args.authkey, args.orgid):
        session.add(r)

    print(f"[ENUM] Path traversal…")
    for r in probe_path_traversal(args.endpoint, args.authkey, args.orgid):
        session.add(r)

    print(f"[ENUM] Method override headers…")
    for r in probe_method_override(args.endpoint, args.authkey, args.orgid):
        session.add(r)

    out_file = session.save(args.output_dir)
    print(f"\n[ENUM] Results: {out_file}")
    print(f"[ENUM] {len(session.iterations)} iterations, {len(session.findings)} findings")
    for f in session.findings:
        print(f"  ! {f}")

    if session.findings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
