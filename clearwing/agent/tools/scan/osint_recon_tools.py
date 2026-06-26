"""OSINT Recon Tools — amass, subfinder, recon-ng, assetfinder, findomain.

All container-based tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 19: Domain & Subdomain Enumeration
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=False)
def run_amass(
    domain: str,
    mode: str = "enum",
    options: str = "",
    timeout_minutes: int = 30,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run OWASP Amass for DNS enumeration and network mapping.

    Amass performs open-source intelligence gathering and DNS enumeration
    using graph theory to map attack surfaces. Modes: intel, enum, viz,
    track, db.

    Args:
        domain: Target domain (e.g. "example.com").
        mode: Amass mode — "intel", "enum", "viz", "track", or "db".
        options: Extra flags (e.g. "-active -brute -w wordlist.txt").
        timeout_minutes: Maximum runtime before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"timeout {timeout_minutes}m amass {mode} -d {domain} {options}"
    logger.info("[%s] amass (%s): %s", distro, mode, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_subfinder(
    domain: str,
    sources: str = "all",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Fast passive subdomain discovery with subfinder.

    subfinder discovers valid subdomains for websites by using passive
    online sources. Supports recursive resolution, output to JSON,
    and integration with ProjectDiscovery's chaos API.

    Args:
        domain: Target domain.
        sources: Comma-separated source list, or "all" (default).
        options: Extra flags (e.g. "-recursive -o subdomains.txt").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    source_flag = f"-sources {sources}" if sources != "all" else ""
    cmd = f"subfinder -d {domain} {source_flag} {options}"
    logger.info("[%s] subfinder: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_recon_ng(
    workspace: str,
    module: str = "",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run recon-ng OSINT framework module against a workspace.

    recon-ng is a full-featured Web Reconnaissance framework written in
    Python. Load a workspace, run specific modules (e.g. recon/domains-
    hosts/hackertarget), and export results.

    Args:
        workspace: recon-ng workspace name.
        module: Specific module path (e.g. "recon/domains-hosts/hackertarget").
        options: Extra flags or script commands.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    module_cmd = f"-m {module}" if module else ""
    cmd = f"recon-ng -w {workspace} {module_cmd} {options}"
    logger.info("[%s] recon-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_assetfinder(
    domain: str,
    subs_only: bool = True,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Passive subdomain discovery via assetfinder (Tomnomnom).

    assetfinder finds domains and subdomains related to a given domain
    by querying passive resources ( crt.sh, certspotter, hackertarget,
    threatcrowd, urlscan, etc.).

    Args:
        domain: Target domain.
        subs_only: Only print subdomains (default True).
        options: Extra flags (e.g. "-subs-only" is implicit when True).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    flag = "-subs-only" if subs_only else ""
    cmd = f"assetfinder {flag} {domain} {options}"
    logger.info("[%s] assetfinder: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_findomain(
    domain: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Fast cross-platform subdomain enumerator (findomain).

    findomain queries certspotter, crt.sh, sublist3r, threatcrowd,
    anubis, urlscan, and more. Written in Rust; very fast.

    Args:
        domain: Target domain.
        options: Extra flags (e.g. "-o findomain.txt").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"findomain -t {domain} {options}"
    logger.info("[%s] findomain: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_httpx(
    target_file: str,
    options: str = "-sc -cl -ct -rt",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Fast and multi-purpose HTTP toolkit for probing web servers.

    httpx is a fast and multi-purpose HTTP toolkit that allows running
    multiple probes using the retryablehttp library which allows to
    check for hosts availability and supports variety of protocols.

    Args:
        target_file: Path to file containing targets (one per line) inside container.
        options: Extra flags (e.g. "-sc -cl -ct -rt" for status code, content length, content type, response time).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"httpx -l {target_file} {options}"
    logger.info("[%s] httpx: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_dnsx(
    domain: str,
    options: str = "-a -aaaa -cname -ns -txt -mx -soa -axfr",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Fast and multi-purpose DNS toolkit for DNS recon and probing.

    dnsx is a fast and multi-purpose DNS toolkit allow to run multiple
    DNS queries of your choice with a user-supplied resolvers list.

    Args:
        domain: Target domain.
        options: DNS query types to perform.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"echo '{domain}' | dnsx {options}"
    logger.info("[%s] dnsx: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


# ════════════════════════════════════════════════════════════════════════════
# Phase 20: Web Archive & URL Enumeration
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=False)
def run_gau(
    domain: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """GetAllUrls (gau) — fetch known URLs from AlienVault's OTX, Wayback
    Machine, Common Crawl, and URLScan for a domain.

    Args:
        domain: Target domain.
        options: Extra flags (e.g. "--providers wayback,otx").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"gau {domain} {options}"
    logger.info("[%s] gau: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_waybackurls(
    domain: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Fetch URLs from the Wayback Machine for a domain (waybackurls).

    Args:
        domain: Target domain.
        options: Extra flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"echo '{domain}' | waybackurls {options}"
    logger.info("[%s] waybackurls: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_gowitness(
    target_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Screenshot and web reconnaissance with gowitness.

    Takes screenshots of websites, extracts page titles, headers,
    technologies, and TLS certificates. Reads target URLs from a file.

    Args:
        target_file: Path to file containing URLs (one per line).
        options: Extra flags (e.g. "--threads 5 --timeout 10").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"gowitness file -f {target_file} {options}"
    logger.info("[%s] gowitness: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )
