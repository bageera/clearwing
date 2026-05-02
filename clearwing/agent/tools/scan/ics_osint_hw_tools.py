"""ICS/SCADA, OSINT, and Social Engineering Pentest Tools — Phase 16+.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import KALI, PARROT

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 16: ICS / SCADA Security
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_modbus_scan(
    target: str,
    port: int = 502,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Modbus TCP/RTU device scanning and enumeration.

    Identifies Modbus slaves, reads holding registers, coils,
    and detects unauthorized access to industrial control systems.

    Args:
        target: IP address of the Modbus master/gateway.
        port: Modbus TCP port (default: 502).
        options: Extra flags (e.g. "--function-code 3 --register 0-100").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"modbus-cli scan {target}:{port} {options}"
    logger.info("[%s] modbus scan: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_s7_scan(
    target: str,
    port: int = 102,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Siemens S7 PLC scanning and enumeration (s7scan / iso-tsap).

    Discovers Siemens S7-300/400/1200/1500 PLCs, reads status,
    firmware version, and identifies blocks without authentication.

    Args:
        target: IP address of the S7 PLC.
        port: S7 port (default: 102).
        options: Extra flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"s7scan {target} -p {port} {options}"
    logger.info("[%s] s7scan: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_dnp3_scan(
    target: str,
    port: int = 20000,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """DNP3 (Distributed Network Protocol) scanning and assessment.

    DNP3 is widely used in electric utilities and water systems.
    This tool scans for DNP3 masters/outstations and tests for
    unauthorized control operations.

    Args:
        target: IP address of the DNP3 device.
        port: DNP3 port (default: 20000).
        options: Extra flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"dnp3scan {target}:{port} {options}"
    logger.info("[%s] dnp3scan: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_ethernet_ip_scan(
    target: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """EtherNet/IP (ENIP/CIP) device discovery and enumeration.

    EtherNet/IP is used in Rockwell/Allen-Bradley PLCs and
    industrial automation. Identifies devices, firmware versions,
    and potential misconfigurations on TCP/44818 and UDP/2222.

    Args:
        target: IP address or CIDR range.
        options: Extra flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"enipscan {target} {options}"
    logger.info("[%s] enipscan: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_bacnet_scan(
    target: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """BACnet (Building Automation and Control Networks) scanning.

    BACnet is used in HVAC, lighting, and building management systems.
    Scans UDP/47808 for devices, objects, and property values.

    Args:
        target: IP address or CIDR range.
        options: Extra flags (e.g. "--enumerate-objects").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"bacnetscan {target} {options}"
    logger.info("[%s] bacnetscan: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_ics_fuzzer(
    protocol: str,
    target: str,
    port: int,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """ICS/SCADA protocol fuzzer (Modbus, S7, DNP3, ENIP, BACnet).

    Sends malformed protocol packets to industrial devices to test
    for crashes, hangs, or unexpected behavior. Use with extreme care.

    Args:
        protocol: Protocol name ("modbus", "s7", "dnp3", "enip", "bacnet").
        target: IP address of the target device.
        port: Target port.
        options: Extra fuzzer flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"icspuzzer -p {protocol} -t {target}:{port} {options}"
    logger.info("[%s] ics fuzzer (%s): %s", distro, protocol, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


# ════════════════════════════════════════════════════════════════════════════
# Phase 17: OSINT / Social Engineering
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=False)
def run_theharvester(
    domain: str,
    sources: str = "baidu,bing,google,yahoo",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Email and subdomain enumeration via OSINT (theHarvester).

    Scrapes search engines, Shodan, and public databases for
    email addresses, subdomains, and employee names associated
    with a target domain.

    Args:
        domain: Target domain (e.g. "lazarusai.com").
        sources: Comma-separated search sources.
        options: Extra flags (e.g. "--limit 500").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"theHarvester -d {domain} -b {sources} {options}"
    logger.info("[%s] theHarvester: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=False) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=False)


@tool(requires_approval=False)
def run_maltego(
    target: str,
    transform: str = "",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Graph-based OSINT and link analysis with Maltego.

    Maltego visualizes relationships between domains, IP addresses,
    emails, social profiles, and infrastructure. Useful for mapping
    an organization's digital footprint.

    Args:
        target: Domain, IP, email, or entity to investigate.
        transform: Specific transform to run (optional).
        options: Extra flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    transform_flag = f"-t {transform}" if transform else ""
    cmd = f"maltego {options} {transform_flag} -e {target}"
    logger.info("[%s] maltego: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=False) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=False)


@tool(requires_approval=True)
def run_social_engineer_toolkit(
    attack_type: str,
    target: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Social Engineer Toolkit (SET) for phishing and credential harvesting.

    SET automates spear-phishing, credential harvesting, and 
    mass-mailer attacks. Requires explicit approval for any
    email-sending or credential-collection operations.

    Args:
        attack_type: "spear-phishing", "credential-harvester", "mass-mailer", etc.
        target: Target email or domain.
        options: Extra SET flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"setoolkit --attack {attack_type} --target {target} {options}"
    logger.info("[%s] SET (%s): %s", distro, attack_type, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_gophish(
    action: str,
    campaign: str = "",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Phishing campaign management with GoPhish.

    GoPhish is a powerful open-source phishing framework for
    security awareness training and authorized red-team exercises.
    Requires explicit approval for any email sending.

    Args:
        action: "launch", "results", "templates", or "reports".
        campaign: Campaign name or ID.
        options: Extra GoPhish flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"gophish {action} {campaign} {options}"
    logger.info("[%s] gophish (%s): %s", distro, action, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=False)
def run_osint_framework(
    target: str,
    category: str = "all",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """OSINT framework aggregator (recon-ng / spiderfoot / osintframework).

    Runs multiple OSINT modules against a target, gathering data
    from public sources, social media, WHOIS, DNS, and more.

    Args:
        target: Domain, IP, email, or username to investigate.
        category: Category to focus on ("all", "dns", "email", "social", "web").
        options: Extra flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"recon-ng -r {target} -c {category} {options}"
    logger.info("[%s] recon-ng (%s): %s", distro, category, cmd)
    return KALI.execute(container_id, cmd, requires_approval=False) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=False)


# ════════════════════════════════════════════════════════════════════════════
# Phase 18: Hardware / Side-Channel
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_chipwhisperer(
    target: str,
    attack_type: str = "cpa",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Power analysis side-channel attack with ChipWhisperer.

    ChipWhisperer is an open-source platform for side-channel power
    analysis and glitching attacks. Used to extract cryptographic
    keys from embedded devices.

    Args:
        target: Target firmware or device description.
        attack_type: "cpa", "dpa", or "glitch".
        options: Extra ChipWhisperer flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"chipwhisperer {attack_type} {target} {options}"
    logger.info("[%s] chipwhisperer (%s): %s", distro, attack_type, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)


@tool(requires_approval=True)
def run_jtag_enum(
    target: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """JTAG/SWD debugging interface enumeration.

    JTAG (Joint Test Action Group) and SWD (Serial Wire Debug) are
    hardware debugging interfaces. Enumerating them on embedded
    devices can reveal firmware extraction paths and debug access.

    Args:
        target: Target device IP or serial port.
        options: Extra flags (e.g. "--interface jtag --speed 1000").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """
    if container_id is None:
        manager = KALI if distro == "kali" else PARROT
        container_id = manager.setup()["container_id"]

    cmd = f"jtagenum {target} {options}"
    logger.info("[%s] jtagenum: %s", distro, cmd)
    return KALI.execute(container_id, cmd, requires_approval=True) \
        if distro == "kali" else PARROT.execute(container_id, cmd, requires_approval=True)
