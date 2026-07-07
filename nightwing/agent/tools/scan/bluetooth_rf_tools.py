"""Bluetooth & RF Pentest Tools — Phase 14.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 14: Bluetooth & RF
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_bettercap_bluetooth(
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Bluetooth Low Energy (BLE) reconnaissance with bettercap.

    bettercap can scan for BLE devices, read characteristics, and
    potentially exploit weak pairing mechanisms.

    Args:
        options: Extra bettercap flags.
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a Bluetooth adapter (built-in or USB).
    """

    cmd = f"timeout {duration} bettercap {options} -eval 'ble.recon on; sleep {duration}'"
    logger.info("[%s] bettercap BLE: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_ubertooth(
    command: str = "scan",
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Bluetooth sniffing and discovery with Ubertooth.

    Ubertooth One is an open source Bluetooth test tool for sniffing
    BLE and classic Bluetooth traffic. Requires Ubertooth hardware.

    Args:
        command: ubertooth command (e.g. "scan", "dump", "follow").
        options: Extra ubertooth flags.
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires Ubertooth One passed through to the container.
    """

    cmd = f"timeout {duration} ubertooth-{command} {options}"
    logger.info("[%s] ubertooth: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Phase 14a: Bluetooth (Classic + BLE) — NEW
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=False)
def run_bluez_scan(
    duration: int = 15,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Classic Bluetooth device discovery with Bluez (hcitool).

    Scans for discoverable Bluetooth (Classic) devices in range using
    the Bluez stack (hcitool). Works with built-in Bluetooth adapters.

    Args:
        duration: Seconds to scan (passed to hcitool scan).
        options: Extra hcitool flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a Bluetooth adapter (built-in or USB).
    """

    cmd = f"hcitool scan --length {duration} {options}"
    logger.info("[%s] bluez scan: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=False)
def run_bluez_info(
    bdaddr: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Get detailed Bluetooth device info with Bluez (hcitool info).

    Retrieves device class, features, and manufacturer information for
    a discovered Bluetooth device.

    Args:
        bdaddr: Bluetooth MAC address (e.g. "AA:BB:CC:DD:EE:FF").
        options: Extra hcitool flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a Bluetooth adapter (built-in or USB).
    """

    cmd = f"hcitool info {bdaddr} {options}"
    logger.info("[%s] bluez info: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=True)
def run_btlejack(
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """BLE link-layer jamming and hijacking with btlejack.

    btlejack can jam, sniff, and hijack Bluetooth Low Energy connections.
    Useful for attacking BLE devices that use weak or no encryption.

    Args:
        options: Extra btlejack flags (e.g. "-s" to sniff).
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a BLE adapter (built-in or USB Bluetooth 4.0+).
    """

    cmd = f"timeout {duration} btlejack {options}"
    logger.info("[%s] btlejack: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_sniffle(
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """BLE 5 sniffer with Sniffle (TI CC1352/CC26x2 hardware).

    Sniffle is a Bluetooth Low Energy 5 sniffer that requires TI
    CC1352R or CC26x2 hardware. Supports BLE 5 long-range and
    coded PHY modes.

    Args:
        options: Extra sniffle flags (e.g. "-c 37" for channel 37).
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires TI CC1352R or CC26x2 LaunchPad passed through
    as a serial device (e.g. --device /dev/ttyACM0).
    """

    cmd = f"timeout {duration} sniffle {options}"
    logger.info("[%s] sniffle: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
