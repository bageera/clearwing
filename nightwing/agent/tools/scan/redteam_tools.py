import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


@tool(requires_approval=True)
def run_chisel(
    action: str,
    target: str,
    port: int = 8080,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run chisel (fast TCP/UDP tunnel over HTTP) from inside a pentest container.

    Chisel is a fast TCP/UDP tunnel transported over HTTP and secured via SSH.
    Used for pivoting through compromised hosts or exfiltrating data.

    Args:
        action: "server" or "client".
        target: For server: listen address (e.g. "0.0.0.0").
                For client: server address (e.g. "10.0.0.1:8080").
        port: Listen / connect port.
        options: Additional chisel flags (e.g. "--reverse --socks5").
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    if action == "server":
        cmd = f"chisel server --host {target} --port {port} {options}"
    else:
        cmd = f"chisel client {target}:{port} {options}"

    logger.info("Executing chisel (%s) in %s container: %s", action, distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_crackmapexec(
    target: str,
    protocol: str = "smb",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run CrackMapExec (CME) for SMB/WinRM/SSH/LDAP/MSSQL enumeration and credential testing.

    CrackMapExec is a post-exploitation tool for evaluating Active Directory
    security by enumerating shares, sessions, users, and testing credentials
    across multiple protocols.

    Args:
        target: IP, hostname, or CIDR range.
        protocol: Protocol module — smb, winrm, ssh, ldap, mssql.
        options: CME flags (e.g. "-u admin -p Password123 --shares").
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"crackmapexec {protocol} {target} {options}"
    logger.info("Executing crackmapexec in %s container: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_bloodhound(
    domain: str,
    options: str = "-c All",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Run BloodHound.py for Active Directory attack path enumeration.

    Collects AD objects (users, groups, computers, ACLs, trusts) and exports
    them in JSON format for import into the BloodHound visual analysis tool.

    Args:
        domain: Fully qualified domain name (e.g. "corp.local").
        options: bloodhound-python flags. Default: "-c All".
        container_id: Docker container ID. If None auto-discovers one.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"bloodhound-python -d {domain} {options}"
    logger.info("Executing bloodhound-python in %s container: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
