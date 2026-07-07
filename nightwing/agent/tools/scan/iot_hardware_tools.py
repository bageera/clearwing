"""IoT & Hardware Pentest Tools — Phase 15.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 15: IoT & Hardware
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_firmwalker(
    firmware_path: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Firmware static analysis with firmwalker.

    firmwalker scans extracted firmware filesystems for interesting
    files, hardcoded credentials, certificates, and potential backdoors.

    Args:
        firmware_path: Path to extracted firmware directory.
        options: Extra firmwalker flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"firmwalker {options} {firmware_path}"
    logger.info("[%s] firmwalker: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_binwalk(
    firmware_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Firmware extraction and analysis with binwalk.

    binwalk identifies and extracts embedded files and executable code
    from firmware images, embedded devices, and binary blobs.

    Args:
        firmware_file: Path to firmware binary.
        options: Extra binwalk flags (e.g. "-e" to extract).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"binwalk {options} {firmware_file}"
    logger.info("[%s] binwalk: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
