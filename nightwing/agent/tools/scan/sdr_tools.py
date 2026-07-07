"""SDR / Radio Frequency Pentest Tools — Phase 14c.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.

These tools cover HackRF, RTL-SDR, and general RF signal analysis
for spectrum scanning, signal decoding, and RF reconnaissance.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 14c: SDR / Radio Frequency
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=False)
def run_hackrf_info(
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Check HackRF hardware presence and capabilities.

    hackrf_info displays the serial number, board ID, and firmware
    version of a connected HackRF One. Useful for verifying hardware
    is properly passed through to the container.

    Args:
        options: Extra hackrf_info flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires HackRF One passed through via USB
    (e.g. --device /dev/bus/usb/XXX/YYY).
    """

    cmd = f"hackrf_info {options}"
    logger.info("[%s] hackrf_info: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=True)
def run_hackrf_sweep(
    freq_min: int = 1,
    freq_max: int = 6000,
    duration: int = 30,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Wideband spectrum sweep with HackRF.

    Scans a frequency range to find active signals. Outputs
    a waterfall plot of signal power vs frequency. Useful for
    discovering unknown transmitters in a target environment.

    Args:
        freq_min: Start frequency in MHz (default: 1).
        freq_max: End frequency in MHz (default: 6000).
        duration: Seconds to run the sweep.
        options: Extra hackrf_sweep flags (e.g. "-w 1000000" for 1MHz bins).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires HackRF One passed through via USB.
    """

    cmd = f"timeout {duration} hackrf_sweep -f {freq_min}:{freq_max} {options}"
    logger.info("[%s] hackrf_sweep: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_rtl_433(
    frequency: int = 433,
    duration: int = 60,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """433MHz ISM band receiver with rtl_433.

    rtl_433 decodes signals from 433MHz (or other ISM band) devices
    such as weather stations, thermometers, smart meters, remote
    outlets, and keyfobs. Supports many device protocols.

    Args:
        frequency: Frequency in MHz (default: 433, also supports 868, 915).
        duration: Seconds to run before terminating.
        options: Extra rtl_433 flags (e.g. "-A" for active mode, "-R 40"
            for specific protocol).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires RTL-SDR passed through via USB.
    """

    cmd = f"timeout {duration} rtl_433 -f {frequency}M {options}"
    logger.info("[%s] rtl_433: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_rtl_power(
    freq_min: int = 1,
    freq_max: int = 6000,
    duration: int = 60,
    bin_size: int = 10000,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Spectrum power profiling with rtl_power.

    rtl_power measures signal power across a frequency range, producing
    a CSV that can be visualized as a waterfall plot. Useful for
    identifying active frequencies before targeting specific signals.

    Args:
        freq_min: Start frequency in MHz (default: 1).
        freq_max: End frequency in MHz (default: 6000).
        duration: Seconds to run before terminating.
        bin_size: Frequency bin size in Hz (default: 10000).
        options: Extra rtl_power flags (e.g. "-i 1s" for integration time).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires RTL-SDR passed through via USB.
    """

    cmd = f"timeout {duration} rtl_power -f {freq_min}M:{freq_max}M:{bin_size} {options}"
    logger.info("[%s] rtl_power: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_gqrx(
    frequency: int = 433,
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Software-defined radio receiver with Gqrx.

    Gqrx is an SDR receiver that supports FM, AM, SSB, and other
    demodulation modes. Typically a GUI application, but can run
    headless for automated signal capture.

    Args:
        frequency: Center frequency in MHz (default: 433).
        options: Extra Gqrx flags.
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires an SDR (RTL-SDR, HackRF, etc.) passed through via USB.
    """

    cmd = f"timeout {duration} gqrx -f {frequency}e6 {options}"
    logger.info("[%s] gqrx: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=False)
def run_inspectrum(
    input_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Offline RF signal analysis with inspectrum.

    inspectrum analyzes recorded RF signals (in .cf32 format) to
    visualize spectrum, extract symbols, and reverse-engineer signal
    modulation. Runs offline — no hardware needed.

    Args:
        input_file: Path to captured .cf32 file inside the container.
        options: Extra inspectrum flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"inspectrum {options} {input_file}"
    logger.info("[%s] inspectrum: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )
