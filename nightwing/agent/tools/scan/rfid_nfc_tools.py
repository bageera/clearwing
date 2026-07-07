"""RFID / NFC Pentest Tools — Phase 14b.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.

These tools cover low-frequency (125kHz), high-frequency (13.56MHz),
and NFC tag reading, writing, sniffing, and cloning.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 14b: RFID / NFC
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_proxmark3(
    command: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Proxmark3 RFID tool — read/write/sniff/clone LF and HF tags.

    Proxmark3 is a versatile RFID tool supporting both low-frequency
    (125kHz) and high-frequency (13.56MHz) tag operations. Can read,
    write, sniff, and clone tags across multiple protocols (HID, Mifare,
    EM410x, Indala, etc.).

    Args:
        command: Proxmark3 command (e.g. "hf search", "lf search",
            "hf mf dump", "lf hid clone", "hf mf restore").
        options: Extra pm3 flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires Proxmark3 device passed through as a serial
    device (e.g. --device /dev/ttyACM0).
    """

    cmd = f"pm3 -c {command!r} {options}"
    logger.info("[%s] proxmark3: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_mfoc(
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Mifare Classic Offline Cracking (nested attack) with mfoc.

    mfoc recovers all keys of a Mifare Classic 1K/4K tag using the
    "nested" attack — given one known key, it can derive the rest.
    Requires an NFC reader (typically ACR122U) and a Mifare Classic tag.

    Args:
        options: Extra mfoc flags (e.g. "-O /tmp/dump.mfd" for output,
            "-k FFFFFFFFFFFF" to specify a known key).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires an NFC reader (ACR122U) passed through via USB
    and a Mifare Classic tag on the reader.
    """

    cmd = f"mfoc {options}"
    logger.info("[%s] mfoc: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_mfuk(
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Mifare Classic key recovery via known-key attack with mfuk.

    mfuk (Mifare Classic Ultimate Key) recovers keys from Mifare Classic
    tags using known-key attacks. An alternative to mfoc when nested
    attack is not applicable.

    Args:
        options: Extra mfuk flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires an NFC reader (ACR122U) and a Mifare Classic tag.
    """

    cmd = f"mfuk {options}"
    logger.info("[%s] mfuk: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=False)
def run_nfc_tool(
    action: str = "list",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """NFC tag operations with libnfc tools (nfc-list, nfc-mfclassic, etc.).

    libnfc provides a suite of tools for NFC tag reading and writing.
    This tool wraps the common operations: listing tags, reading/writing
    Mifare Classic, and emulating NFC tags.

    Args:
        action: Operation to perform — "list" (nfc-list), "read"
            (nfc-mfclassic r), "write" (nfc-mfclassic w), "format"
            (nfc-mfclassic f).
        options: Extra libnfc flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires an NFC reader (ACR122U) passed through via USB.
    """

    action_map = {
        "list": "nfc-list",
        "read": "nfc-mfclassic r a /tmp/dump.mfd",
        "write": "nfc-mfclassic w a /tmp/dump.mfd",
        "format": "nfc-mfclassic f",
    }
    cmd = action_map.get(action, "nfc-list")
    cmd = f"{cmd} {options}"
    logger.info("[%s] nfc-tool (%s): %s", distro, action, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=True)
def run_rfidiot(
    script: str = "rfidiot.py",
    action: str = "read",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Multi-protocol RFID toolkit (RFID IO Tools).

    RFID IO Tools (rfidiot) is a collection of Python scripts for
    reading, writing, and cloning RFID tags across multiple protocols
    (HID, EM410x, Indala, Mifare, etc.). Works with Proxmark3 or ACR122.

    Args:
        script: RFIDiot script name (e.g. "rfidiot.py", "lfhid.py").
        action: Action to perform (e.g. "read", "write", "clone").
        options: Extra rfidiot flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires Proxmark3 or ACR122 NFC reader passed through.
    """

    cmd = f"python3 {script} --{action} {options}"
    logger.info("[%s] rfidiot: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
