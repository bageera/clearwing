"""Network Discovery, Wireless, and Mobile Pentest Tools — Phase 11+.

All tools execute inside Kali/Parrot Docker containers via the
PentestContainerManager dual-distro infrastructure.
"""

import logging
from typing import Any

from clearwing.agent.tooling import tool
from clearwing.agent.tools.ops.pentest_container import run_in_pentest_container

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


# ════════════════════════════════════════════════════════════════════════════
# Phase 12: Wireless Pentesting
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
# Phase 13: Mobile Pentesting
# ════════════════════════════════════════════════════════════════════════════


@tool(requires_approval=True)
def run_frida(
    target_app: str,
    script: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Dynamic instrumentation of mobile apps with Frida.

    Injects JavaScript into running Android/iOS processes to hook
    functions, bypass SSL pinning, intercept crypto calls, and more.

    Args:
        target_app: Package name (Android) or process name (iOS).
        script: Path to Frida script inside container, or None for default.
        options: Extra frida flags (e.g. "--no-pause").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    script_flag = f"-l {script}" if script else ""
    cmd = f"frida {options} {script_flag} -f {target_app}"
    logger.info("[%s] frida: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_objection(
    target_app: str,
    command: str = "explore",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Runtime mobile exploration with objection.

    objection is a runtime mobile exploration toolkit built on Frida.
    Provides high-level commands for SSL pinning bypass, root/jailbreak
    detection bypass, heap dumping, and more.

    Args:
        target_app: Package name (Android) or bundle ID (iOS).
        command: objection command to run (default: "explore").
        options: Extra objection flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"objection {options} --gadget {target_app} {command}"
    logger.info("[%s] objection: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_mobsf(
    apk_file: str,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Mobile Security Framework (MobSF) static analysis.

    Performs automated static analysis on Android APK, iOS IPA, or
    Windows APPX files. Identifies hardcoded secrets, insecure configs,
    and known vulnerabilities.

    Args:
        apk_file: Path to mobile app package inside the container.
        options: Extra MobSF CLI flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"mobsf {options} {apk_file}"
    logger.info("[%s] mobsf: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_apktool(
    apk_file: str,
    output_dir: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """APK decompilation and reverse engineering with apktool.

    Disassembles Android APK files to smali code and extracts resources
    for manual analysis or modification.

    Args:
        apk_file: Path to APK inside the container.
        output_dir: Directory for decompiled output (default: apk name + ".out").
        options: Extra apktool flags (e.g. "-s" to skip disassembly).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    out_flag = f"-o {output_dir}" if output_dir else ""
    cmd = f"apktool d {options} {out_flag} {apk_file}"
    logger.info("[%s] apktool: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_jadx(
    apk_file: str,
    output_dir: str | None = None,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Android APK decompiler to Java source with jadx.

    Converts APK/DEX files back to readable Java source code for
    security auditing and reverse engineering.

    Args:
        apk_file: Path to APK inside the container.
        output_dir: Directory for decompiled Java sources.
        options: Extra jadx flags (e.g. "--deobf" for deobfuscation).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    out_flag = f"-d {output_dir}" if output_dir else ""
    cmd = f"jadx {options} {out_flag} {apk_file}"
    logger.info("[%s] jadx: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


@tool(requires_approval=True)
def run_drozer(
    package: str,
    command: str = "list",
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Android security assessment framework (drozer).

    drozer allows you to search for security vulnerabilities in apps and
    devices by assuming the role of an app and interacting with the
    Android runtime and other apps.

    Args:
        package: Target Android package name.
        command: drozer module to run (e.g. "app.package.info").
        options: Extra drozer flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.
    """

    cmd = f"drozer {options} console connect -c 'run {command} {package}'"
    logger.info("[%s] drozer: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )


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
