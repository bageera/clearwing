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
