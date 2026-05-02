import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import KALI, PARROT

logger = logging.getLogger(__name__)


@tool(requires_approval=False)
def run_nmap_scan(
    target: str,
    options: str = "-sT -Pn --top-ports 1000 -oX -",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run nmap from inside a Kali/Parrot Docker container against a target.

    Returns raw XML output which can be parsed downstream or saved for later
    analysis. Requires a running container; use `kali_setup` or `parrot_setup`
    first if one isn't running.

    Args:
        target: IP address, hostname, or CIDR range to scan.
        options: CLI flags passed directly to nmap. Default is TCP connect
            scan against top 1000 ports with XML output to stdout.
        container_id: Docker container ID to execute inside. If None,
            attempts to find a running clearwing-kali or clearwing-parrot
            container.
        distro: Which pentest distro to use if container_id is not provided.
            Must be "kali" or "parrot".

    Returns:
        Dict with keys:
            - exit_code: 0 if nmap finished successfully.
            - output: XML string from nmap.
            - error: stderr if any.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"nmap {options} {target}"
    logger.info("Executing nmap in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_gobuster(
    url: str,
    wordlist_path: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run gobuster dir search from inside a Kali/Parrot container.

    Args:
        url: Full target URL (e.g. http://example.com).
        wordlist_path: Path to wordlist inside the container.
        extensions: Comma-separated file extensions to search for
            (e.g. "php,txt,bak"). Defaults to None (directories only).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    ext_flag = f" -x {extensions}" if extensions else ""
    cmd = f"gobuster dir -u {url} -w {wordlist_path}{ext_flag} -k -e"
    logger.info("Executing gobuster in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_sqlmap(
    url: str,
    options: str = "--batch --random-agent --level=2",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run sqlmap against a target URL from inside a pentest container.

    By default runs in batch mode with a random User-Agent string and
    level 2 heuristic tests.

    Args:
        url: Target URL with a query parameter to test (e.g.
            http://target.com/search?id=1).
        options: Additional sqlmap flags. Default: --batch --random-agent --level=2.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"sqlmap -u '{url}' {options}"
    logger.info("Executing sqlmap in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_enum4linux(
    target: str,
    options: str = "-a",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run enum4linux against an SMB target from inside a pentest container.

    Args:
        target: IP address or hostname of the SMB target.
        options: enum4linux flags. Default: -a (all enumeration).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"enum4linux {options} {target}"
    logger.info("Executing enum4linux in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_nikto(
    target: str,
    options: str = "-h",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run Nikto web vulnerability scanner from inside a pentest container.

    Args:
        target: Target HTTP URL or IP address (with Nikto's -h format).
        options: Additional Nikto flags. Default: -h.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"nikto {options} {target}"
    logger.info("Executing nikto in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_hydra(
    target: str,
    service: str,
    user_list: str = "admin",
    wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
    container_id: str | None = None,
    distro: str = "kali",
    requires_approval: bool = True,
) -> dict[str, Any]:
    """Run Hydra brute-forcer inside a pentest container.

    Args:
        target: IP address or hostname to attack.
        service: Protocol/service name (e.g. ssh, ftp, http-post-form).
        user_list: Username(s) to test (comma-separated).
        wordlist_path: Path to password wordlist inside the container.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".
        requires_approval: Whether to gate behind human approval.
            Defaults to True because active brute-forcing may cause
            account lockouts.

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"hydra -l {user_list} -P {wordlist_path} {target} {service}"
    logger.info("Executing hydra in %s container: %s", distro, cmd)
    mgr = KALI if distro == "kali" else PARROT
    return mgr.execute(container_id, cmd, requires_approval=requires_approval)


@tool(requires_approval=False)
def run_snmpwalk(
    target: str,
    community: str = "public",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run snmpwalk against a target from inside a pentest container.

    Args:
        target: IP address or hostname of the SNMP target.
        community: SNMP community string. Default: public.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"snmpwalk -v2c -c {community} {target}"
    logger.info("Executing snmpwalk in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_whatweb(
    target: str,
    options: str = "-a 3",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run WhatWeb fingerprinting tool from inside a pentest container.

    Args:
        target: URL or IP to fingerprint.
        options: WhatWeb aggression level or flags. Default: -a 3.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"whatweb {options} {target}"
    logger.info("Executing whatweb in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


# ─── Phase 4: API Pentest Tools ────────────────────────────────────────────

@tool(requires_approval=False)
def run_ffuf(
    target: str,
    wordlist_path: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    extensions: str | None = None,
    headers: str | None = None,
    post_data: str | None = None,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run ffuf (fast web fuzzer) from inside a Kali/Parrot container.

    ffuf is excellent for API endpoint discovery, directory brute-forcing,
    virtual host discovery, and parameter fuzzing. Supports POST body fuzzing
    and custom headers for API testing.

    Args:
        target: Target URL with FUZZ keyword (e.g. https://api.example.com/FUZZ
            or https://api.example.com/v1/FUZZ).
        wordlist_path: Path to wordlist inside container.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH). Default: GET.
        extensions: Comma-separated extensions (e.g. "json,php,bak,txt").
        headers: Additional headers as semicolon-separated key:value pairs
            (e.g. "Authorization: Bearer token;Content-Type: application/json").
        post_data: POST body with FUZZ keyword for parameter fuzzing
            (e.g. '{"username":"FUZZ","password":"test"}').
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    ext_flag = f" -e {extensions}" if extensions else ""
    method_flag = f" -X {method}" if method != "GET" else ""
    header_flags = ""
    if headers:
        for h in headers.split(";"):
            header_flags += f' -H "{h.strip()}"'
    data_flag = f' -d "{post_data}"' if post_data else ""

    cmd = f'ffuf -u "{target}" -w {wordlist_path}{ext_flag}{method_flag}{header_flags}{data_flag} -mc all -fc 404'
    logger.info("Executing ffuf in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_httpx(
    targets: str,
    options: str = "-status-code -title -tech-detect -json",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run httpx (fast HTTP prober) from inside a Kali/Parrot container.

    httpx probes multiple targets concurrently to detect status codes,
    page titles, technologies, server headers, and response bodies. Ideal
    for rapid API reconnaissance and service enumeration.

    Args:
        targets: Single URL, file path, or comma-separated URLs.
            Can also be a file inside the container (e.g. /tmp/targets.txt).
        options: Additional httpx flags. Default: -status-code -title
            -tech-detect -json.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f'httpx -u "{targets}" {options}'
    logger.info("Executing httpx in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_jwt_tool(
    target_jwt: str,
    options: str = "-t",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run jwt_tool (JWT analysis & exploitation) from inside a pentest container.

    jwt_tool automates JWT vulnerability testing: weak signatures, none alg,
    key confusion, expired tokens, and secret brute-forcing. Essential for
    API authentication assessment.

    Args:
        target_jwt: The JWT string to analyze.
        options: jwt_tool flags. Default: -t (full test mode).
            Common: -t (all tests), -C (crack with wordlist),
            -X (exploit), -S (sign with key).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"jwt_tool.py '{target_jwt}' {options}"
    logger.info("Executing jwt_tool in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_arjun(
    target: str,
    method: str = "GET",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run Arjun (HTTP parameter discovery) from inside a Kali/Parrot container.

    Arjun finds hidden HTTP parameters in GET/POST/JSON requests. Critical
    for discovering API parameters that developers assumed were secret.

    Args:
        target: Target URL to probe for hidden parameters.
        method: HTTP method (GET, POST, JSON). Default: GET.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"arjun -u '{target}' -m {method}"
    logger.info("Executing arjun in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_dalfox(
    target: str,
    options: str = "--silence --only-poc 'vuln'",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run DalFox (XSS scanner) from inside a Kali/Parrot container.

    DalFox finds and verifies XSS vulnerabilities in URLs, forms, and API
    parameters. Supports reflected, stored, and DOM-based XSS detection.

    Args:
        target: Target URL to scan for XSS (e.g. https://example.com?q=test).
        options: DalFox flags. Default: --silence --only-poc 'vuln'.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"dalfox url '{target}' {options}"
    logger.info("Executing dalfox in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


# ─── Phase 4: Database Pentest Tools ───────────────────────────────────────

@tool(requires_approval=False)
def run_nosqlmap(
    target: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run NoSQLMap (NoSQL injection scanner) from inside a pentest container.

    NoSQLMap tests MongoDB, CouchDB, and Redis for injection vulnerabilities,
    authentication bypasses, and data extraction. Complements sqlmap for
    modern NoSQL-backed APIs.

    Args:
        target: Target URL or IP to test (e.g. http://target.com/api/user).
        options: Additional NoSQLMap flags.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"nosqlmap.py {options} {target}"
    logger.info("Executing nosqlmap in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_oscanner(
    target: str,
    options: str = "-s",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run Oscanner (Oracle assessment tool) from inside a pentest container.

    Oscanner scans Oracle databases for vulnerabilities, weak configurations,
    and default credentials. Useful for enterprise environments with Oracle
    backends.

    Args:
        target: Target IP or hostname running Oracle TNS listener.
        options: Additional oscanner flags. Default: -s (sid enumeration).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"oscanner {options} {target}"
    logger.info("Executing oscanner in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_sqlninja(
    target: str,
    options: str = "-m test",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run SQLninja (MS SQL Server exploitation) from inside a pentest container.

    SQLninja specializes in Microsoft SQL Server exploitation: fingerprinting,
    data extraction, and privilege escalation via SQL injection.

    Args:
        target: Target URL with vulnerable SQL Server parameter.
        options: SQLninja flags. Default: -m test (fingerprinting mode).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"sqlninja {options} -u '{target}'"
    logger.info("Executing sqlninja in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_sqlsus(
    target: str,
    options: str = "--guess",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run SQLsus (MySQL exploitation framework) from inside a pentest container.

    SQLsus automates MySQL database takeover via SQL injection: fingerprinting,
    data extraction, file read/write, and command execution.

    Args:
        target: Target URL with MySQL injection vulnerability.
        options: SQLsus flags. Default: --guess (auto-detect injection point).
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"sqlsus {options} '{target}'"
    logger.info("Executing sqlsus in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )


@tool(requires_approval=False)
def run_sqlmate(
    target: str,
    options: str = "--batch",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run SQLMate (SQL injection companion) from inside a pentest container.

    SQLMate assists sqlmap by providing intelligent payload generation,
    tamper script suggestions, and blind SQL injection optimization.
    Useful when sqlmap fails to detect a vulnerability.

    Args:
        target: Target URL with potential SQL injection parameter.
        options: SQLMate flags. Default: --batch.
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        setup_result = manager.setup()
        container_id = setup_result["container_id"]

    cmd = f"sqlmate {options} -u '{target}'"
    logger.info("Executing sqlmate in %s container: %s", distro, cmd)
    return KALI.execute(
        container_id, cmd, requires_approval=False
    ) if distro == "kali" else PARROT.execute(
        container_id, cmd, requires_approval=False
    )
