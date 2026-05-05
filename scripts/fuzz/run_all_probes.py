#!/usr/bin/env python3
"""Master orchestrator for the Clearwing LLM API pentest probe suite.

Runs all probe modules in sequence, aggregates results, and produces a
unified findings report.

Usage:
    python scripts/fuzz/run_all_probes.py --authkey [REDACTED] --orgid [REDACTED]

ROE: Amendment 04, Section 3.4 — Authorized fuzzing on dev API only.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROBES = [
    ("ssrf", "scripts/fuzz/ssrf_probe.py"),
    ("auth", "scripts/fuzz/auth_probe.py"),
    ("injection", "scripts/fuzz/injection_probe.py"),
    ("jailbreak", "scripts/fuzz/llm_jailbreak_probe.py"),
    ("file_abuse", "scripts/fuzz/file_abuse_probe.py"),
    ("endpoint_enum", "scripts/fuzz/endpoint_enum.py"),
    ("rate_limit", "scripts/fuzz/rate_limit_probe.py"),
]


def run_probe(name: str, script: str, endpoint: str, authkey: str, orgid: str, output_dir: Path) -> dict[str, Any]:
    """Execute a single probe script and return summary."""
    print(f"\n{'=' * 60}")
    print(f"[MASTER] Starting probe: {name}")
    print(f"{'=' * 60}")

    cmd = [
        sys.executable,
        script,
        "--endpoint", endpoint,
        "--authkey", authkey,
        "--orgid", orgid,
        "--output-dir", str(output_dir),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    return {
        "name": name,
        "script": script,
        "returncode": result.returncode,
        "stdout": result.stdout[-2000:],  # tail only
        "stderr": result.stderr[-500:],
    }


def aggregate_results(output_dir: Path) -> dict[str, Any]:
    """Read all JSON result files and build a summary report."""
    import glob

    reports = []
    for path in sorted(output_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            reports.append({
                "file": str(path.name),
                "probe_name": data.get("probe_name", "unknown"),
                "endpoint": data.get("endpoint", "unknown"),
                "started_at": data.get("started_at", "unknown"),
                "iterations": len(data.get("iterations", [])),
                "findings_count": len(data.get("findings", [])),
                "findings": data.get("findings", []),
                "findings_by_severity": _severity_breakdown(data.get("iterations", [])),
            })
        except Exception as exc:
            reports.append({"file": str(path.name), "error": str(exc)})

    total_iterations = sum(r["iterations"] for r in reports if "error" not in r)
    total_findings = sum(r["findings_count"] for r in reports if "error" not in r)

    return {
        "reports": reports,
        "total_iterations": total_iterations,
        "total_findings": total_findings,
    }


def _severity_breakdown(iterations: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for it in iterations:
        sev = it.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def main():
    parser = argparse.ArgumentParser(description="Run all LLM API pentest probes")
    parser.add_argument("--endpoint", default="https://api-dev.gcp.lzrops.com/api/engine/internal")
    parser.add_argument("--authkey", required=True)
    parser.add_argument("--orgid", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/fuzz"))
    parser.add_argument(
        "--probes",
        nargs="+",
        choices=[name for name, _ in PROBES],
        default=None,
        help="Run only specific probes (default: all)",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    active_probes = PROBES if args.probes is None else [(n, s) for n, s in PROBES if n in args.probes]
    probe_results: list[dict[str, Any]] = []

    for name, script in active_probes:
        probe_results.append(
            run_probe(
                name=name,
                script=script,
                endpoint=args.endpoint,
                authkey=args.authkey,
                orgid=args.orgid,
                output_dir=args.output_dir,
            )
        )

    # Aggregate
    summary = aggregate_results(args.output_dir)
    summary["probe_results"] = probe_results
    summary["timestamp"] = __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())

    summary_path = args.output_dir / "master_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, default=str))

    print(f"\n{'=' * 60}")
    print(f"[MASTER] All probes complete")
    print(f"[MASTER] Total iterations: {summary['total_iterations']}")
    print(f"[MASTER] Total findings: {summary['total_findings']}")
    print(f"[MASTER] Summary saved to {summary_path}")
    print(f"{'=' * 60}")

    for r in summary["reports"]:
        if "error" not in r and r["findings_count"] > 0:
            print(f"\n[{r['probe_name']}] {r['findings_count']} findings:")
            for f in r["findings"]:
                print(f"  ! {f}")

    if summary["total_findings"] > 0:
        print(f"\n[!] Findings detected — review individual probe JSON files.")
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
