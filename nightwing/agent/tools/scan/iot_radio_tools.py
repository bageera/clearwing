"""IoT Radio Protocol Pentest Tools — Phase 14d.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.

These tools cover Zigbee (IEEE 802.15.4), LoRaWAN, and Sub-GHz
ISM band protocols used in IoT and smart home devices.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 14d: IoT Radio Protocols (Zigbee, LoRaWAN, Sub-GHz)
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_killerbee(
    action: str = "scan",
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Zigbee (IEEE 802.15.4) scanning, sniffing, and injection with KillerBee.

    KillerBee is a framework for Zigbee security testing. It can scan
    for networks, sniff traffic, and inject packets. Useful for
    testing smart home, industrial, and IoT Zigbee deployments.

    Args:
        action: KillerBee action — "scan", "sniff", "inject", "forge".
        options: Extra KillerBee flags (e.g. "-f 11" for channel 11).
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a Zigbee adapter (ApiSpec, Atmel RZUSBSTICK, or
    ZiSTICK) passed through via USB or serial.
    """

    cmd = (
        f"timeout {duration} zbstumbler -w {options}"
        if action == "scan"
        else (f"timeout {duration} zbdump {options}")
    )
    logger.info("[%s] killerbee (%s): %s", distro, action, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_zbstumbler(
    options: str = "",
    duration: int = 30,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Zigbee network discovery with zbstumbler.

    zbstumbler is a passive/active Zigbee network discovery tool —
    analogous to airodump-ng for Zigbee. Discovers PAN IDs, channels,
    and network topologies.

    Args:
        options: Extra zbstumbler flags (e.g. "-c 11" for channel 11).
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a Zigbee adapter (ApiSpec, RZUSBSTICK, or ZiSTICK).
    """

    cmd = f"timeout {duration} zbstumbler {options}"
    logger.info("[%s] zbstumbler: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_lorawan_scanner(
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """LoRaWAN gateway and node discovery.

    Scans for LoRaWAN gateways and nodes operating in regional ISM bands
    (EU 868MHz, US 915MHz, etc.). Identifies gateway EUIs, frequencies,
    and spreading factors in use.

    Args:
        options: Extra scanner flags (e.g. "-f 868" for EU frequency).
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a LoRa adapter (e.g. SX127x, CC1310) passed
    through as a serial device (e.g. --device /dev/ttyUSB0).
    """

    cmd = f"timeout {duration} lorawan-scanner {options}"
    logger.info("[%s] lorawan-scanner: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_subghz_scan(
    frequency: int = 433,
    duration: int = 60,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Sub-GHz ISM band scanning for keyfobs, remotes, and sensors.

    Scans the Sub-GHz ISM bands (315MHz, 433MHz, 868MHz, 915MHz) for
    signals from garage door remotes, weather sensors, wireless
    doorbells, and other short-range RF devices. Uses rtl_433 in
    analysis mode to decode protocols.

    Args:
        frequency: Frequency in MHz (default: 433, also 315, 868, 915).
        duration: Seconds to run before terminating.
        options: Extra rtl_433 flags (e.g. "-A" for active mode, "-R 40"
            for specific protocol decoder).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires RTL-SDR passed through via USB.
    """

    cmd = f"timeout {duration} rtl_433 -f {frequency}M -a {options}"
    logger.info("[%s] subghz_scan: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
