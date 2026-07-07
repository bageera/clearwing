"""Wireless (Wi-Fi) Pentest Tools — Phase 12.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from nightwing.agent.tooling import tool
from nightwing.agent.tools.ops.pentest_container import run_in_pentest_container

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Phase 12: Wireless Pentesting — Existing tools
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_aircrack_ng(
    pcap_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """WPA/WPA2-PSK key recovery with aircrack-ng.

    Cracks wireless capture files (handshakes) against a wordlist.
    Requires a .cap or .pcap containing a valid 4-way handshake.

    Args:
        pcap_file: Path to capture file inside the container.
        wordlist: Path to password wordlist.
        options: Extra aircrack-ng flags (e.g. "-b AA:BB:CC:DD:EE:FF").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"aircrack-ng {options} -w {wordlist} {pcap_file}"
    logger.info("[%s] aircrack-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_airodump_ng(
    interface: str,
    options: str = "",
    duration: int = 30,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Wireless AP and client discovery with airodump-ng.

    Scans for nearby Wi-Fi access points, clients, and captures
    4-way handshakes for later cracking.

    Args:
        interface: Wireless interface in monitor mode (e.g. "wlan0mon").
        options: Extra airodump-ng flags (e.g. "--bssid AA:BB:CC:DD:EE:FF -c 6").
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    """

    cmd = f"timeout {duration} airodump-ng {options} {interface}"
    logger.info("[%s] airodump-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_wifite(
    options: str = "",
    duration: int = 300,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Automated wireless attack tool (Wifite).

    Automatically attacks multiple WEP, WPA, and WPS encrypted networks
    in range. Simplifies the aircrack-ng workflow.

    Args:
        options: Extra wifite flags (e.g. "--wps-only --pixie").
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    """

    cmd = f"timeout {duration} wifite {options}"
    logger.info("[%s] wifite: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_reaver(
    bssid: str,
    interface: str = "wlan0mon",
    options: str = "",
    duration: int = 300,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """WPS PIN brute-forcing with reaver.

    Attacks Wi-Fi Protected Setup (WPS) to recover the WPA/WPA2 PSK
    via brute-force or Pixie Dust attacks.

    Args:
        bssid: Target access point MAC address.
        interface: Wireless interface in monitor mode.
        options: Extra reaver flags (e.g. "-K 1" for Pixie Dust).
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    """

    cmd = f"timeout {duration} reaver -i {interface} -b {bssid} {options}"
    logger.info("[%s] reaver: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_bully(
    bssid: str,
    interface: str = "wlan0mon",
    options: str = "",
    duration: int = 300,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """WPS PIN brute-forcing with bully (faster alternative to reaver).

    bully is a modern, streamlined WPS brute-forcing tool with better
    performance and reliability against modern APs.

    Args:
        bssid: Target access point MAC address.
        interface: Wireless interface in monitor mode.
        options: Extra bully flags.
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    """

    cmd = f"timeout {duration} bully -b {bssid} -i {interface} {options}"
    logger.info("[%s] bully: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Phase 12a: Monitor Mode & Interface Management (NEW)
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_airmon_ng(
    interface: str,
    action: str = "start",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enable/disable monitor mode on a wireless interface.

    airmon-ng manages wireless interface modes and kills processes
    that interfere with monitor mode (NetworkManager, wpa_supplicant).

    Args:
        interface: Wireless interface (e.g. "wlan0").
        action: "start" to enable monitor mode, "stop" to disable,
            "check" to list interfering processes.
        options: Extra airmon-ng flags (e.g. "-e").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter passed
    through to the container (e.g. --device /dev/bus/usb/...).
    """

    if action == "check":
        cmd = f"airmon-ng check {options}"
    else:
        cmd = f"airmon-ng {action} {interface} {options}"
    logger.info("[%s] airmon-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_airbase_ng(
    interface: str,
    ssid: str,
    channel: int = 1,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Create a rogue AP / evil twin with airbase-ng.

    airbase-ng creates a fake access point for evil twin attacks,
    captive portals, and credential harvesting. Requires a wireless
    interface in monitor mode.

    Args:
        interface: Wireless interface in monitor mode (e.g. "wlan0mon").
        ssid: SSID for the rogue AP.
        channel: Channel to broadcast on (default: 1).
        options: Extra airbase-ng flags (e.g. "-W 1" for WPA beacon).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    """

    cmd = f"airbase-ng -a 00:11:22:33:44:55 -e {ssid!r} -c {channel} {options} {interface}"
    logger.info("[%s] airbase-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_aireplay_ng(
    interface: str,
    attack_mode: str = "deauth",
    options: str = "",
    duration: int = 30,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Packet injection with aireplay-ng.

    aireplay-ng injects wireless frames for deauthentication, fake
    authentication, ARP replay, and other attacks. Used to capture
    WPA handshakes or disrupt wireless clients.

    Args:
        interface: Wireless interface in monitor mode (e.g. "wlan0mon").
        attack_mode: Attack type — "deauth", "fakeauth", "arpreplay",
            "chopchop", "caffeelatte", or "fragment".
        options: Extra aireplay-ng flags (e.g. "--bssid AA:BB:CC:DD:EE:FF").
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires an injection-capable USB Wi-Fi adapter.
    """

    mode_map = {
        "deauth": "--deauth",
        "fakeauth": "--fakeauth",
        "arpreplay": "--arpreplay",
        "chopchop": "--chopchop",
        "caffeelatte": "--caffe-latte",
        "fragment": "--fragment",
    }
    flag = mode_map.get(attack_mode, "--deauth")
    cmd = f"timeout {duration} aireplay-ng {flag} {options} {interface}"
    logger.info("[%s] aireplay-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_airdecap_ng(
    pcap_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Decrypt WEP/WPA capture files with airdecap-ng.

    airdecap-ng decrypts encrypted wireless capture files using a known
    key (WEP, WPA-PSK, or WPA-PMK). Runs offline — no hardware needed.

    Args:
        pcap_file: Path to encrypted capture file inside the container.
        options: Extra airdecap-ng flags (e.g. "-e SSID -p PASSWORD").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"airdecap-ng {options} {pcap_file}"
    logger.info("[%s] airdecap-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_wash(
    interface: str = "wlan0mon",
    options: str = "",
    duration: int = 30,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Detect WPS-enabled access points with wash.

    wash scans for APs that have WPS (Wi-Fi Protected Setup) enabled,
    which are potential targets for reaver/bully WPS brute-force attacks.
    Can scan from a live interface or from a captured pcap file.

    Args:
        interface: Wireless interface in monitor mode, or path to a pcap.
        options: Extra wash flags (e.g. "-C" to ignore checksum errors).
        duration: Seconds to run before terminating (live scan only).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter for live scan.
    """

    cmd = f"timeout {duration} wash -i {interface} {options}"
    logger.info("[%s] wash: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# Phase 12b: Wireless Reconnaissance (NEW)
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_kismet(
    interface: str = "wlan0",
    options: str = "",
    duration: int = 60,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Passive wireless scanner and IDS with Kismet.

    Kismet is a passive wireless scanner — it listens without injecting
    packets, making it ideal for stealthy reconnaissance. Supports
    Wi-Fi, Bluetooth, and SDR data sources.

    Args:
        interface: Wireless interface (e.g. "wlan0"). Kismet will put it
            into monitor mode automatically.
        options: Extra Kismet flags (e.g. "--daemonize").
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a Wi-Fi adapter (any monitor-mode-capable adapter).
    """

    cmd = f"timeout {duration} kismet -c {interface} --quiet --logtypes none {options}"
    logger.info("[%s] kismet: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=False)
def run_airgraph_ng(
    input_csv: str,
    graph_type: str = "CAPR",
    output_dir: str = "/tmp/airgraph",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Visualize airodump-ng capture data as graphs with airgraph-ng.

    airgraph-ng generates relationship diagrams from airodump-ng CSV
    output. Supports "CAPR" (Client-AP-Relationship) and "CPG"
    (Common-Password-Graph) graph types. Runs offline — no hardware needed.

    Args:
        input_csv: Path to airodump-ng CSV file inside the container.
        graph_type: Graph type — "CAPR" or "CPG".
        output_dir: Directory for output graph image.
        options: Extra airgraph-ng flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"airgraph-ng -i {input_csv} -g {graph_type} -o {output_dir}/graph.png {options}"
    logger.info("[%s] airgraph-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=False,
    )


@tool(requires_approval=True)
def run_horst(
    interface: str = "wlan0mon",
    options: str = "",
    duration: int = 30,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Fast 802.11 scanner for roaming analysis with horst.

    horst is a lightweight 802.11 scanning and analysis tool optimized
    for fast roaming detection and signal quality analysis.

    Args:
        interface: Wireless interface in monitor mode.
        options: Extra horst flags.
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    """

    cmd = f"timeout {duration} horst -i {interface} {options}"
    logger.info("[%s] horst: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


# ═════════════════════════════════════════════════════                                              ════════════
# Phase 12c: Enterprise Wireless / 802.1X (NEW)
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_eaphammer(
    interface: str,
    ssid: str,
    options: str = "",
    duration: int = 300,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Evil twin + EAP credential harvesting with eaphammer.

    eaphammer creates rogue 802.1X/EAP access points to harvest
    enterprise credentials (PEAP, EAP-TTLS). Supports credential
    harvesting without requiring certificate trust on the client side.

    Args:
        interface: Wireless interface in monitor mode.
        ssid: SSID for the rogue enterprise AP.
        options: Extra eaphammer flags (e.g. "--auth wpa-eap").
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    Prerequisites: eaphammer must be installed in the container
    (e.g. `apt-get install eaphammer`).
    """

    cmd = f"timeout {duration} eaphammer -i {interface} --essid {ssid!r} {options}"
    logger.info("[%s] eaphammer: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_hostapd_wpe(
    interface: str,
    config_file: str,
    options: str = "",
    duration: int = 300,
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Rogue AP with EAP credential capture via hostapd-wpe.

    hostapd-wpe (Wireless Pwn Edition) is a patched hostapd that captures
    MS-CHAPv2 challenge/response hashes from 802.1X EAP clients. Requires
    a pre-generated config file with cert paths and SSID.

    Args:
        interface: Wireless interface in monitor mode.
        config_file: Path to hostapd-wpe config file inside the container.
        options: Extra hostapd-wpe flags.
        duration: Seconds to run before terminating.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter.
    Prerequisites: hostapd-wpe must be installed and configured with certs.
    """

    cmd = f"timeout {duration} hostapd-wpe {options} {config_file}"
    logger.info("[%s] hostapd-wpe: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_asleap(
    pcap_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Recover LEAP/MS-CHAPv2 passwords from captures with asleap.

    asleap recovers LEAP and MS-CHAPv2 credentials from wireless capture
    files. Used after hostapd-wpe or eaphammer capture sessions.
    Runs offline — no hardware needed.

    Args:
        pcap_file: Path to capture file with LEAP/MS-CHAPv2 traffic.
        options: Extra asleap flags (e.g. "-W wordlist.txt").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"asleap -r {pcap_file} {options}"
    logger.info("[%s] asleap: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
