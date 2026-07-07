"""Network Discovery Tools — Phase 11.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 11: Network Discovery
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_netdiscover(
    target_range: str,
    interface: str = "eth0",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Active/passive ARP-based network host discovery.

    netdiscover scans LANs by sending ARP requests and passively sniffing
    for replies. Ideal for mapping internal subnets during post-exploitation
    or red-team engagements where stealth is preferred over TCP scanning.

    Args:
        target_range: CIDR range to scan (e.g. "10.0.0.0/24").
        interface: Network interface to use.
        options: Extra flags (e.g. "-P" for passive mode).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"netdiscover -r {target_range} -i {interface} {options}"
    logger.info("[%s] netdiscover: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_masscan(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Ultra-fast asynchronous TCP port scanner (masscan).

    masscan scans the entire Internet in ~6 minutes at 10 Mpps. It uses
    its own TCP/IP stack and is ideal for wide-scale port discovery on
    internal networks or CIDR blocks.

    Args:
        target: IP, hostname, or CIDR range.
        ports: Port range (default: 1-65535).
        rate: Packets per second (default: 1000).
        options: Extra masscan flags (e.g. "--banners").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"masscan {target} -p{ports} --rate {rate} {options}"
    logger.info("[%s] masscan: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_arp_scan(
    target_range: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """ARP scanning and fingerprinting with arp-scan.

    arp-scan sends ARP packets to specified hosts and displays any
    responses. Can fingerprint vendors via MAC address OUI lookup.

    Args:
        target_range: CIDR or IP range (e.g. "192.168.1.0/24").
        options: Extra flags (e.g. "-I eth0 -g").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"arp-scan {target_range} {options}"
    logger.info("[%s] arp-scan: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=False)
def run_traceroute(
    target: str,
    protocol: str = "icmp",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Network path tracing with traceroute.

    Maps the route packets take to a network host, revealing intermediate
    hops, firewalls, and network topology.

    Args:
        target: Hostname or IP to trace.
        protocol: "icmp", "udp", or "tcp".
        options: Extra traceroute flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    proto_flag = {"icmp": "-I", "udp": "-U", "tcp": "-T"}.get(protocol, "-I")
    cmd = f"traceroute {proto_flag} {options} {target}"
    logger.info("[%s] traceroute: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )
