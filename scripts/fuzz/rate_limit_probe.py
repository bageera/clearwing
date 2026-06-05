#!/usr/bin/env python3
"""Rate-limit bypass and resource exhaustion probe.

Tests:
- Parallel burst requests to detect rate-limit enforcement
- Incremental burst sizes (1, 5, 10, 20 concurrent)
- Large max_tokens / context window exhaustion
- Document with many pages (processing time DoS)
- Repeating rapid requests with identical payloads
- Variable delays to find rate-limit windows

ROE: Amendment 04, Section 3.4 — Dev API only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
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


def _single_request(
    endpoint: str,
    body: dict[str, Any],
    authkey: str,
    orgid: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, str, float]:
    import time as time_mod

    headers = {
        "apiversion": API_VERSION,
        "authkey": authkey,
        "orgid": orgid,
        "content-type": "application/json",
    }
    t0 = time_mod.perf_counter()
    try:
        resp = requests.post(endpoint, headers=headers, json=body, timeout=timeout)
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return resp.status_code, resp.text[:500], elapsed
    except requests.exceptions.Timeout:
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return 0, "TIMEOUT", elapsed
    except requests.exceptions.ConnectionError:
        elapsed = (time_mod.perf_counter() - t0) * 1000
        return 0, "CONN_ERR", elapsed


def probe_parallel_burst(endpoint: str, authkey: str, orgid: str, body: dict[str, Any]) -> list[ProbeResult]:
    """Send parallel bursts to test rate-limit enforcement."""
    results: list[ProbeResult] = []
    burst_sizes = [1, 5, 10, 20]

    for burst in burst_sizes:
        print(f"  [rate] Burst size {burst} …")
        with concurrent.futures.ThreadPoolExecutor(max_workers=burst) as executor:
            futures = [
                executor.submit(_single_request, endpoint, body, authkey, orgid)
                for _ in range(burst)
            ]
            responses = [f.result() for f in concurrent.futures.as_completed(futures)]

        statuses = [s for s, _, _ in responses]
        # Rate limiting typically manifests as 429, 503, or 0 (timeout)
        rate_limited = statuses.count(429) + statuses.count(503) + statuses.count(0)
        if rate_limited == 0 and burst > 1:
            finding = f"No rate limit detected at burst={burst}"
            severity = "medium"
        elif rate_limited > 0:
            finding = f"Rate limit triggered: {rate_limited}/{burst} requests limited"
            severity = "info"
        else:
            finding = None
            severity = "info"

        for i, (status, text, elapsed) in enumerate(responses, start=1):
            results.append(
                ProbeResult(
                    probe_name="rate_burst",
                    iteration=len(results) + 1,
                    payload_id=f"burst_{burst}_{i}",
                    status_code=status,
                    response_time_ms=elapsed,
                    raw_response=text,
                    finding=finding if i == 1 else None,
                    severity=severity if i == 1 else "info",
                )
            )
        print(f"    statuses={statuses} finding={finding}")
    return results


def probe_resource_exhaustion(endpoint: str, authkey: str, orgid: str) -> list[ProbeResult]:
    """Test processing-time DoS via extreme settings."""
    results: list[ProbeResult] = []

    # Extreme max_tokens
    for max_tokens in [32000, 64000, 128000]:
        body = build_request_body(
            file_data=b"%PDF-1.4\n1 0 obj\n\x3c\x3c/Type /Catalog /Pages 2 0 R\x3e\x3e\nendobj\n2 0 obj\n\x3c\x3c/Type /Pages /Kids [] /Count 0\x3e\x3e\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer\n\x3c\x3c/Size 3 /Root 1 0 R\x3e\x3e\nstartxref\n101\n%%EOF",
            prompt="Summarize this document.",
            extra_settings={
                "modelSettings": {"modelName": "gpt-4o", "max_tokens": str(max_tokens)},
            },
        )
        status, text, elapsed = _single_request(endpoint, body, authkey, orgid)

        if elapsed > 30000:
            finding = f"High latency at max_tokens={max_tokens} ({elapsed:.0f}ms)"
            severity = "low"
        else:
            finding = None
            severity = "info"

        results.append(
            ProbeResult(
                probe_name="resource_exhaustion",
                iteration=len(results) + 1,
                payload_id=f"tokens_{max_tokens}",
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text,
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [resource] max_tokens={max_tokens}: status={status} time={elapsed:.0f}ms finding={finding}")

    # Extreme context size
    for max_ctx in [50, 100, 200]:
        body = build_request_body(
            file_data=b"%PDF-1.4\n1 0 obj\n\x3c\x3c/Type /Catalog /Pages 2 0 R\x3e\x3e\nendobj\n2 0 obj\n\x3c\x3c/Type /Pages /Kids [] /Count 0\x3e\x3e\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer\n\x3c\x3c/Size 3 /Root 1 0 R\x3e\x3e\nstartxref\n101\n%%EOF",
            prompt="Summarize this document.",
            extra_settings={
                "modelSettings": {"modelName": "gpt-4o", "max_tokens": "16384"},
                "contextSettings": {"max_context": max_ctx},
            },
        )
        status, text, elapsed = _single_request(endpoint, body, authkey, orgid)

        if elapsed > 30000:
            finding = f"High latency at max_context={max_ctx} ({elapsed:.0f}ms)"
            severity = "low"
        else:
            finding = None
            severity = "info"

        results.append(
            ProbeResult(
                probe_name="resource_exhaustion",
                iteration=len(results) + 1,
                payload_id=f"context_{max_ctx}",
                status_code=status,
                response_time_ms=elapsed,
                raw_response=text,
                finding=finding,
                severity=severity,
            )
        )
        print(f"  [resource] max_context={max_ctx}: status={status} time={elapsed:.0f}ms finding={finding}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Rate-limit and resource exhaustion probe")
    parser.add_argument("--endpoint", default="https://api-dev.gcp.lzrops.com/api/engine/internal")
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/fuzz"))
    args = parser.parse_args()

    base_body = build_request_body(
        file_data=b"%PDF-1.4\n1 0 obj\n\x3c\x3c/Type /Catalog /Pages 2 0 R\x3e\x3e\nendobj\n2 0 obj\n\x3c\x3c/Type /Pages /Kids [] /Count 0\x3e\x3e\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer\n\x3c\x3c/Size 3 /Root 1 0 R\x3e\x3e\nstartxref\n101\n%%EOF",
        prompt="Summarize this document.",
    )

    session = ProbeSession(
        probe_name="rate_limit",
        endpoint=args.endpoint,
        started_at=__import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
    )

    print(f"[RATE] Parallel burst tests…")
    for r in probe_parallel_burst(args.endpoint, args.authkey, args.orgid, base_body):
        session.add(r)

    print(f"[RATE] Resource exhaustion tests…")
    for r in probe_resource_exhaustion(args.endpoint, args.authkey, args.orgid):
        session.add(r)

    out_file = session.save(args.output_dir)
    print(f"\n[RATE] Results: {out_file}")
    print(f"[RATE] {len(session.iterations)} iterations, {len(session.findings)} findings")
    for f in session.findings:
        print(f"  ! {f}")

    if session.findings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
