"""Proxy-based Web Application Security Testing Tools.

Provides Burp Suite and OWASP ZAP integration for intercepting,
scanning, and fuzzing web/API traffic via the Kali/Parrot
PentestContainer infrastructure.
"""

import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


@tool(requires_approval=True)
def run_burp(
    target: str,
    action: str = "spider",
    options: str = "",
    report_format: str = "xml",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run Burp Suite (Community or Pro) from inside a pentest container.

    Supports spidering, active scanning, and API endpoint enumeration.
    Traffic is proxied through Burp's embedded proxy for interception
    and analysis. Results are exported in XML or JSON format.

    Args:
        target: Target URL or API base URL to scan.
        action: Burp action — "spider", "scan", "crawl", "api_discovery".
        options: Additional Burp CLI flags or configuration file path.
        report_format: Output format — "xml", "json", "html".
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"burpsuite --headless --target '{target}' --action {action} --report-format {report_format} {options}"
    logger.info("[%s] burp (%s): %s", distro, action, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_owaspzap(
    target: str,
    action: str = "spider",
    options: str = "",
    report_format: str = "xml",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run OWASP ZAP (Zed Attack Proxy) from inside a pentest container.

    Automated web application and API security scanner. Supports
    spidering, active scanning, AJAX spidering, and OpenAPI/GraphQL
    endpoint discovery. Results exported in XML, JSON, or HTML.

    Args:
        target: Target URL or API base URL to scan.
        action: ZAP action — "spider", "ascan", "ajaxspider", "openapi", "graphql".
        options: Additional ZAP CLI flags or context file path.
        report_format: Output format — "xml", "json", "html".
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"zap.sh -cmd -quickurl '{target}' -quickout /tmp/zap-report.{report_format} "
        f"-quickprogress {options}"
    )
    logger.info("[%s] owaspzap (%s): %s", distro, action, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_burp_intruder(
    target: str,
    request_template: str,
    payload_file: str = "/usr/share/wordlists/dirb/common.txt",
    attack_type: str = "sniper",
    threads: int = 10,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Burp Intruder — automated payload fuzzing against API endpoints.

    Replays a request template with variable positions (§marker§) and
    substitutes payloads from a wordlist. Supports sniper, battering ram,
    pitchfork, and cluster bomb attack types.

    Args:
        target: Base URL of the API.
        request_template: Raw HTTP request with §markers§ for payload positions.
        payload_file: Wordlist path inside the container.
        attack_type: "sniper", "battering_ram", "pitchfork", "cluster_bomb".
        threads: Concurrent threads (default: 10).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = (
        f"python3 /opt/burp-intruder-cli/intruder.py "
        f"--target '{target}' --template {repr(request_template)} "
        f"--payloads {payload_file} --attack {attack_type} --threads {threads}"
    )
    logger.info("[%s] burp intruder (%s): %s", distro, attack_type, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_zap_api_scan(
    openapi_url: str,
    options: str = "-a",
    report_format: str = "xml",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """OWASP ZAP OpenAPI / API schema security scan.

    Imports an OpenAPI/Swagger or GraphQL schema and fuzzes all
    declared endpoints with active scan rules. Ideal for discovering
    mass assignment, injection, and authentication bypass in REST APIs.

    Args:
        openapi_url: URL to the OpenAPI JSON/YAML spec or GraphQL introspection endpoint.
        options: ZAP options (default: -a for active scan).
        report_format: Output format — "xml", "json", "html".
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"zap-api-scan.py -t '{openapi_url}' {options} -r /tmp/zap-api-report.{report_format}"
    logger.info("[%s] zap api scan: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
