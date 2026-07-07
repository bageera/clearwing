"""Automated OSINT workflows that chain multiple tools together.

This module provides orchestrated workflows that combine multiple OSINT tools
to perform comprehensive reconnaissance activities.
"""

import logging
from datetime import datetime
from typing import Any

from nightwing.agent.tools.scan.ct_log_tools import query_certspotter, query_crt_sh
from nightwing.agent.tools.scan.github_leak_tools import search_github_code, search_github_commits

# Import the OSINT tools
from nightwing.agent.tools.scan.osint_recon_tools import (
    run_amass,
    run_assetfinder,
    run_findomain,
    run_gau,
    run_subfinder,
    run_waybackurls,
)
from nightwing.data.database.recon_store import ReconResult, ReconStore
from nightwing.utils.output_parsers import parse_amass_json, parse_subfinder_json

logger = logging.getLogger(__name__)


def run_complete_domain_recon(
    domain: str, store: ReconStore | None = None, scan_id: str | None = None
) -> dict[str, Any]:
    """Run a comprehensive domain reconnaissance workflow.

    This workflow executes multiple OSINT tools in sequence to gather
    comprehensive information about a target domain.

    Args:
        domain: Target domain to recon
        store: Optional ReconStore instance for persisting results
        scan_id: Optional identifier for this scan

    Returns:
        Dictionary containing all reconnaissance results
    """
    if store is None:
        store = ReconStore()

    if scan_id is None:
        scan_id = f"domain_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    logger.info(f"Starting comprehensive domain reconnaissance for {domain}")

    results = {
        "scan_id": scan_id,
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "tools_executed": [],
        "findings": {},
    }

    # Phase 1: Certificate Transparency Logs
    logger.info("Phase 1: Querying Certificate Transparency logs")
    try:
        crt_sh_result = query_crt_sh(domain)
        results["findings"]["crt_sh"] = crt_sh_result
        results["tools_executed"].append("crt_sh")

        # Store results
        store.store_result(
            ReconResult(
                tool_name="crt_sh",
                target=domain,
                result_type="subdomain",
                data={"subdomains": crt_sh_result.get("subdomains", [])},
                timestamp=datetime.now().isoformat(),
                scan_id=scan_id,
            )
        )

        certspotter_result = query_certspotter(domain)
        results["findings"]["certspotter"] = certspotter_result
        results["tools_executed"].append("certspotter")

        # Store results
        store.store_result(
            ReconResult(
                tool_name="certspotter",
                target=domain,
                result_type="subdomain",
                data={"subdomains": certspotter_result.get("subdomains", [])},
                timestamp=datetime.now().isoformat(),
                scan_id=scan_id,
            )
        )
    except Exception as e:
        logger.error(f"Error in Certificate Transparency phase: {e}")
        results["errors"] = results.get("errors", []) + [f"CRT phase: {str(e)}"]

    # Phase 2: Subdomain Enumeration
    logger.info("Phase 2: Running subdomain enumeration tools")
    try:
        # Run Amass
        amass_result = run_amass(domain, mode="enum", options="-json")
        results["findings"]["amass"] = amass_result
        results["tools_executed"].append("amass")

        # Parse and store Amass results
        if amass_result.get("exit_code") == 0:
            parsed_amass = parse_amass_json(amass_result.get("output", ""))
            store.store_result(
                ReconResult(
                    tool_name="amass",
                    target=domain,
                    result_type="subdomain",
                    data=parsed_amass,
                    timestamp=datetime.now().isoformat(),
                    scan_id=scan_id,
                )
            )

        # Run Subfinder
        subfinder_result = run_subfinder(domain, options="-json")
        results["findings"]["subfinder"] = subfinder_result
        results["tools_executed"].append("subfinder")

        # Parse and store Subfinder results
        if subfinder_result.get("exit_code") == 0:
            parsed_subfinder = parse_subfinder_json(subfinder_result.get("output", ""))
            store.store_result(
                ReconResult(
                    tool_name="subfinder",
                    target=domain,
                    result_type="subdomain",
                    data=parsed_subfinder,
                    timestamp=datetime.now().isoformat(),
                    scan_id=scan_id,
                )
            )

        # Run Assetfinder
        assetfinder_result = run_assetfinder(domain)
        results["findings"]["assetfinder"] = assetfinder_result
        results["tools_executed"].append("assetfinder")

        # Parse and store Assetfinder results
        if assetfinder_result.get("exit_code") == 0:
            # Assetfinder outputs one subdomain per line
            subdomains = [
                line.strip()
                for line in assetfinder_result.get("output", "").split("\n")
                if line.strip()
            ]
            store.store_result(
                ReconResult(
                    tool_name="assetfinder",
                    target=domain,
                    result_type="subdomain",
                    data={"subdomains": subdomains},
                    timestamp=datetime.now().isoformat(),
                    scan_id=scan_id,
                )
            )

        # Run Findomain
        findomain_result = run_findomain(domain)
        results["findings"]["findomain"] = findomain_result
        results["tools_executed"].append("findomain")

        # Parse and store Findomain results
        if findomain_result.get("exit_code") == 0:
            # Findomain outputs one subdomain per line
            subdomains = [
                line.strip()
                for line in findomain_result.get("output", "").split("\n")
                if line.strip()
            ]
            store.store_result(
                ReconResult(
                    tool_name="findomain",
                    target=domain,
                    result_type="subdomain",
                    data={"subdomains": subdomains},
                    timestamp=datetime.now().isoformat(),
                    scan_id=scan_id,
                )
            )

    except Exception as e:
        logger.error(f"Error in subdomain enumeration phase: {e}")
        results["errors"] = results.get("errors", []) + [f"Subdomain enumeration phase: {str(e)}"]

    # Phase 3: Web Archive Enumeration
    logger.info("Phase 3: Querying web archives")
    try:
        # Run GAU
        gau_result = run_gau(domain)
        results["findings"]["gau"] = gau_result
        results["tools_executed"].append("gau")

        # Parse and store GAU results
        if gau_result.get("exit_code") == 0:
            urls = [
                line.strip() for line in gau_result.get("output", "").split("\n") if line.strip()
            ]
            store.store_result(
                ReconResult(
                    tool_name="gau",
                    target=domain,
                    result_type="url",
                    data={"urls": urls},
                    timestamp=datetime.now().isoformat(),
                    scan_id=scan_id,
                )
            )

        # Run Waybackurls
        wayback_result = run_waybackurls(domain)
        results["findings"]["waybackurls"] = wayback_result
        results["tools_executed"].append("waybackurls")

        # Parse and store Waybackurls results
        if wayback_result.get("exit_code") == 0:
            urls = [
                line.strip()
                for line in wayback_result.get("output", "").split("\n")
                if line.strip()
            ]
            store.store_result(
                ReconResult(
                    tool_name="waybackurls",
                    target=domain,
                    result_type="url",
                    data={"urls": urls},
                    timestamp=datetime.now().isoformat(),
                    scan_id=scan_id,
                )
            )

    except Exception as e:
        logger.error(f"Error in web archive phase: {e}")
        results["errors"] = results.get("errors", []) + [f"Web archive phase: {str(e)}"]

    # Phase 4: GitHub Code Search
    logger.info("Phase 4: Searching GitHub for code leaks")
    try:
        # Search for potential leaks
        github_code_result = search_github_code(f"org:{domain} OR filename:.env OR filename:id_rsa")
        results["findings"]["github_code"] = github_code_result
        results["tools_executed"].append("github_code")

        # Store results
        store.store_result(
            ReconResult(
                tool_name="github_code",
                target=domain,
                result_type="code_leak",
                data=github_code_result,
                timestamp=datetime.now().isoformat(),
                scan_id=scan_id,
            )
        )

        # Search for commit history
        github_commit_result = search_github_commits(f"org:{domain} removed password OR api_key")
        results["findings"]["github_commits"] = github_commit_result
        results["tools_executed"].append("github_commits")

        # Store results
        store.store_result(
            ReconResult(
                tool_name="github_commits",
                target=domain,
                result_type="commit_leak",
                data=github_commit_result,
                timestamp=datetime.now().isoformat(),
                scan_id=scan_id,
            )
        )

    except Exception as e:
        logger.error(f"Error in GitHub search phase: {e}")
        results["errors"] = results.get("errors", []) + [f"GitHub search phase: {str(e)}"]

    logger.info(f"Completed comprehensive domain reconnaissance for {domain}")
    return results


def run_passive_subdomain_recon(
    domain: str, store: ReconStore | None = None, scan_id: str | None = None
) -> dict[str, Any]:
    """Run a passive subdomain reconnaissance workflow.

    This workflow focuses specifically on passive subdomain discovery
    using certificate transparency and passive DNS sources.

    Args:
        domain: Target domain to recon
        store: Optional ReconStore instance for persisting results
        scan_id: Optional identifier for this scan

    Returns:
        Dictionary containing subdomain reconnaissance results
    """
    if store is None:
        store = ReconStore()

    if scan_id is None:
        scan_id = f"passive_subdomain_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    logger.info(f"Starting passive subdomain reconnaissance for {domain}")

    results = {
        "scan_id": scan_id,
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "tools_executed": [],
        "findings": {},
    }

    # Certificate Transparency sources
    try:
        crt_sh_result = query_crt_sh(domain)
        results["findings"]["crt_sh"] = crt_sh_result
        results["tools_executed"].append("crt_sh")

        # Store results
        store.store_result(
            ReconResult(
                tool_name="crt_sh",
                target=domain,
                result_type="subdomain",
                data={"subdomains": crt_sh_result.get("subdomains", [])},
                timestamp=datetime.now().isoformat(),
                scan_id=scan_id,
            )
        )

        certspotter_result = query_certspotter(domain)
        results["findings"]["certspotter"] = certspotter_result
        results["tools_executed"].append("certspotter")

        # Store results
        store.store_result(
            ReconResult(
                tool_name="certspotter",
                target=domain,
                result_type="subdomain",
                data={"subdomains": certspotter_result.get("subdomains", [])},
                timestamp=datetime.now().isoformat(),
                scan_id=scan_id,
            )
        )
    except Exception as e:
        logger.error(f"Error in passive subdomain discovery: {e}")
        results["errors"] = results.get("errors", []) + [f"Passive discovery: {str(e)}"]

    logger.info(f"Completed passive subdomain reconnaissance for {domain}")
    return results


def aggregate_and_correlate_findings(domain: str, store: ReconStore) -> dict[str, Any]:
    """Aggregate and correlate findings from multiple reconnaissance activities.

    This function combines results from different tools and identifies
    relationships and patterns in the collected data.

    Args:
        domain: Target domain
        store: ReconStore instance with existing results

    Returns:
        Dictionary with correlated findings and insights
    """
    logger.info(f"Aggregating and correlating findings for {domain}")

    # Get combined results from the store
    combined_results = store.get_combined_recon_results(domain)

    # Extract key data
    subdomains = set(combined_results["findings"]["subdomains"])
    ips = set(combined_results["findings"]["ips"])
    urls = set(combined_results["findings"]["urls"])

    # Correlation analysis
    correlations = {
        "subdomain_ip_mapping": {},
        "url_subdomain_mapping": {},
        "unique_entities": {"subdomains": len(subdomains), "ips": len(ips), "urls": len(urls)},
    }

    # Simple correlation: map URLs to subdomains
    for url in urls:
        # Extract potential subdomain from URL
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname and hostname in subdomains:
                if hostname not in correlations["url_subdomain_mapping"]:
                    correlations["url_subdomain_mapping"][hostname] = []
                correlations["url_subdomain_mapping"][hostname].append(url)
        except Exception:
            logger.debug("Silent exception in osint_workflow", exc_info=True)
            pass  # Ignore malformed URLs

    logger.info(f"Completed correlation analysis for {domain}")
    return {
        "target": domain,
        "combined_results": combined_results,
        "correlations": correlations,
        "timestamp": datetime.now().isoformat(),
    }
