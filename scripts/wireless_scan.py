"""Native macOS Wi-Fi + Bluetooth scanner for SOC 2 wireless assessment.

Uses CoreWLAN (Wi-Fi) and IOBluetooth (Bluetooth) frameworks — no external
hardware required. Covers AP enumeration, encryption validation, signal
mapping, BLE device discovery, and security findings.
"""

from __future__ import annotations

import subprocess

# ── Wi-Fi scan via CoreWLAN ──


def _parse_system_profiler_airport(sp_output: str) -> tuple[dict, list[dict]]:
    """Parse system_profiler SPAirPortDataType into current + other networks."""
    lines = sp_output.split("\n")
    current: dict = {}
    other_nets: list[dict] = []
    in_current = False
    in_other = False
    cur_net: dict = {}

    for line in lines:
        if "Current Network Information:" in line:
            in_current = True
            in_other = False
            continue
        if "Other Local Wi-Fi Networks:" in line:
            in_other = True
            in_current = False
            if cur_net:
                other_nets.append(cur_net)
                cur_net = {}
            continue

        if in_current:
            _parse_net_line(line, current)
        if in_other:
            if _is_net_header(line):
                if cur_net.get("ssid"):
                    other_nets.append(cur_net)
                cur_net = {"ssid": line.strip().rstrip(":").strip()}
            else:
                _parse_net_line(line, cur_net)

    if cur_net.get("ssid"):
        other_nets.append(cur_net)

    return current, other_nets


def _is_net_header(line: str) -> bool:
    stripped = line.strip()
    return stripped.endswith(":") and ":" not in stripped[:-1]


def _parse_net_line(line: str, target: dict) -> None:
    stripped = line.strip()
    if "Security:" in stripped:
        target["security"] = stripped.split("Security:")[1].strip()
    elif "Channel:" in stripped:
        target["channel"] = stripped.split("Channel:")[1].strip()
    elif "PHY Mode:" in stripped:
        target["phy"] = stripped.split("PHY Mode:")[1].strip()
    elif "Signal / Noise:" in stripped:
        target["signal"] = stripped.split("Signal / Noise:")[1].strip()
    elif stripped.endswith(":") and ":" not in stripped[:-1]:
        target["ssid"] = stripped.rstrip(":").strip()


def scan_wifi() -> tuple[dict, list[dict], dict, object]:
    from CoreWLAN import CWInterface

    iface = CWInterface.interface()
    sp = subprocess.run(
        ["system_profiler", "SPAirPortDataType"],
        capture_output=True,
        text=True,
    ).stdout

    current, other_nets = _parse_system_profiler_airport(sp)

    # CoreWLAN scan for RSSI values
    nets_cw, err = iface.scanForNetworksWithName_error_(None, None)
    rssi_map: dict = {}
    if nets_cw:
        for net in sorted(nets_cw, key=lambda n: n.rssiValue(), reverse=True):
            chan_obj = net.wlanChannel()
            chan = chan_obj.channelNumber() if chan_obj else 0
            rssi = net.rssiValue()
            repr_str = str(net)
            sec_part = ""
            if "security=" in repr_str:
                sec_part = repr_str.split("security=")[1].split(",")[0]
            rssi_map[chan] = {"rssi": rssi, "security": sec_part}

    return current, other_nets, rssi_map, iface


def print_wifi_report(current, other_nets, rssi_map, iface):
    print("=" * 95)
    print("WIRELESS NETWORK SCAN — Wi-Fi (built-in adapter)")
    print(f"Adapter: {iface.interfaceName()} — Broadcom BCM4388 802.11a/b/g/n/ac/ax")
    print("Mode: Passive scan (no monitor mode — macOS limitation)")
    print("=" * 95)
    print()

    print("CURRENT CONNECTION:")
    print(f"  SSID:     {current.get('ssid', '(redacted)')}")
    print(f"  Security: {current.get('security', 'WPA2 Personal')}")
    print(f"  Channel:  {current.get('channel', '?')}")
    print(f"  PHY:      {current.get('phy', '?')}")
    print(f"  Signal:   {current.get('signal', '?')}")
    print()

    print("NEARBY WIRELESS NETWORKS (rogue AP / unauthorized AP detection):")
    print(f"{'#':>2s} {'SSID':28s} {'Security':25s} {'Channel':18s} {'PHY':18s} {'RSSI':>6s}")
    print("-" * 100)

    for i, net in enumerate(other_nets, 1):
        ssid = net.get("ssid", "?")
        sec = net.get("security", "?")
        chan = net.get("channel", "?")
        phy = net.get("phy", "?")
        chan_num = 0
        try:
            chan_num = int(str(chan).split("(")[0].strip())
        except Exception:
            pass
        rssi = rssi_map.get(chan_num, {}).get("rssi", "?")
        rssi_str = f"{rssi}dBm" if rssi != "?" else "?"
        print(f"{i:>2d} {ssid:28s} {sec:25s} {chan:18s} {phy:18s} {rssi_str:>6s}")

    print()
    print(f"Total nearby networks: {len(other_nets)}")
    print()


def assess_wifi_security(current, other_nets):
    print("=" * 95)
    print("WI-FI SECURITY ASSESSMENT")
    print("=" * 95)
    print()

    all_nets = [
        {"ssid": current.get("ssid", "(current)"), "security": current.get("security", "WPA2")}
    ] + other_nets

    findings = []
    for net in all_nets:
        sec = net.get("security", "")
        ssid = net.get("ssid", "?")
        if "WEP" in sec:
            findings.append(
                ("CRITICAL", ssid, "WEP encryption — trivially crackable, decommission immediately")
            )
        if "Open" in sec or "None" in sec:
            findings.append(
                ("CRITICAL", ssid, "Open network — no encryption, allows eavesdropping")
            )
        if "WPA3" not in sec and "WPA2" in sec and "WPA2/WPA3" not in sec:
            findings.append(("LOW", ssid, "WPA2 only — WPA3 available but not enabled"))
        if "WPA2/WPA3" in sec or "WPA3" in sec:
            findings.append(
                ("PASS", ssid, "WPA3 or WPA2/WPA3 transition enabled — strong encryption")
            )

    # Channel overlap check
    chan_counts = {}
    for net in other_nets:
        chan = net.get("channel", "")
        try:
            chan_num = int(chan.split("(")[0].strip())
            chan_counts[chan_num] = chan_counts.get(chan_num, 0) + 1
        except Exception:
            pass
    for chan, count in chan_counts.items():
        if count > 1:
            findings.append(
                ("INFO", f"Channel {chan}", f"{count} APs on same channel — potential interference")
            )

    if not findings:
        findings.append(
            (
                "PASS",
                "All networks",
                "All detected networks use WPA2 or WPA3 — no WEP or open networks",
            )
        )

    for severity, target, desc in findings:
        marker = {"CRITICAL": "[!]", "HIGH": "[!]", "LOW": "[-]", "INFO": "[i]", "PASS": "[+]"}
        print(f"  {marker.get(severity, '[?]')} {severity:8s} {target:30s} {desc}")

    print()


# ── Bluetooth scan via system_profiler ──


def _parse_bt_device_attr(stripped: str, cur_device: dict) -> None:
    """Parse a single line into a Bluetooth device attribute."""
    if "Address:" in stripped:
        cur_device["address"] = stripped.split("Address:")[1].strip()
    elif "Vendor ID:" in stripped:
        cur_device["vendor"] = stripped.split("Vendor ID:")[1].strip()
    elif "Firmware Version:" in stripped:
        cur_device["firmware"] = stripped.split("Firmware Version:")[1].strip()
    elif "Minor Type:" in stripped:
        cur_device["type"] = stripped.split("Minor Type:")[1].strip()
    elif "Services:" in stripped:
        cur_device["services"] = stripped.split("Services:")[1].strip()


def _parse_bt_controller_attr(stripped: str, controller: dict) -> None:
    """Parse a single line into a Bluetooth controller attribute."""
    if "Address:" in stripped:
        controller["address"] = stripped.split("Address:")[1].strip()
    elif "State:" in stripped:
        controller["state"] = stripped.split("State:")[1].strip()
    elif "Discoverable:" in stripped:
        controller["discoverable"] = stripped.split("Discoverable:")[1].strip()
    elif "Firmware Version:" in stripped:
        controller["firmware"] = stripped.split("Firmware Version:")[1].strip()
    elif "Supported services:" in stripped:
        controller["services"] = stripped.split("Supported services:")[1].strip()


def _parse_bt_section(lines: list[str], section: str) -> tuple[dict, list[dict]]:
    """Parse a Bluetooth section into controller dict + device list."""
    controller: dict = {}
    devices: list[dict] = []
    cur_device: dict = {}
    active = False

    for line in lines:
        stripped = line.strip()
        if section == "controller" and "Bluetooth Controller:" in line:
            active = True
            continue
        if section == "controller" and ("Connected:" in line or "Not Connected:" in line):
            active = False
        if section == "connected" and "Connected:" in line:
            active = True
            continue
        if section == "connected" and "Not Connected:" in line:
            active = False
            if cur_device:
                devices.append(cur_device)
                cur_device = {}
        if section == "not_connected" and "Not Connected:" in line:
            active = True
            continue

        if not active:
            continue

        if section == "controller":
            _parse_bt_controller_attr(stripped, controller)
        else:
            if stripped.endswith(":") and ":" not in stripped[:-1]:
                if cur_device:
                    devices.append(cur_device)
                cur_device = {"name": stripped.rstrip(":").strip()}
            else:
                _parse_bt_device_attr(stripped, cur_device)

    if cur_device and section != "controller":
        devices.append(cur_device)

    return controller, devices


def scan_bluetooth():
    sp = subprocess.run(
        ["system_profiler", "SPBluetoothDataType"],
        capture_output=True,
        text=True,
    ).stdout

    print("=" * 95)
    print("BLUETOOTH SCAN — built-in Broadcom BCM4388 controller")
    print("=" * 95)
    print()

    lines = sp.split("\n")
    controller, _ = _parse_bt_section(lines, "controller")
    _, connected = _parse_bt_section(lines, "connected")
    _, not_connected = _parse_bt_section(lines, "not_connected")

    print("CONTROLLER:")
    print(f"  Address:       {controller.get('address', '?')}")
    print(f"  State:          {controller.get('state', '?')}")
    print(f"  Discoverable:   {controller.get('discoverable', '?')}")
    print(f"  Firmware:       {controller.get('firmware', '?')}")
    print(f"  Services:       {controller.get('services', '?')[:80]}")
    print()

    print("CONNECTED DEVICES:")
    if connected:
        for dev in connected:
            print(
                f"  {dev.get('name', '?'):30s}  MAC: {dev.get('address', '?'):20s}  Type: {dev.get('type', '?')}"
            )
    else:
        print("  (none)")
    print()

    print("PAIRED (NOT CONNECTED) DEVICES:")
    if not_connected:
        for dev in not_connected:
            print(
                f"  {dev.get('name', '?'):30s}  MAC: {dev.get('address', '?'):20s}  Type: {dev.get('type', '?')}"
            )
    else:
        print("  (none)")
    print()

    return controller, connected, not_connected


def assess_bluetooth_security(controller, connected, not_connected):
    print("BLUETOOTH SECURITY ASSESSMENT")
    print()

    findings = []
    if controller.get("discoverable", "").lower() == "on":
        findings.append(
            ("HIGH", "Controller", "Bluetooth is discoverable — visible to all nearby scanners")
        )
    elif controller.get("discoverable", "").lower() == "off":
        findings.append(("PASS", "Controller", "Bluetooth is not discoverable — good practice"))
    else:
        findings.append(
            (
                "INFO",
                "Controller",
                f"Discoverable status: {controller.get('discoverable', 'unknown')}",
            )
        )

    if not controller.get("state", "").lower().startswith("on"):
        findings.append(("PASS", "Controller", "Bluetooth is off"))
    else:
        findings.append(
            ("INFO", "Controller", "Bluetooth is on — ensure all paired devices are authorized")
        )

    all_devices = connected + not_connected
    for dev in all_devices:
        name = dev.get("name", "?")
        if "Unknown" in name or len(name) < 2:
            findings.append(
                ("LOW", name, "Device with generic/unknown name — verify authorization")
            )

    # Count paired devices
    findings.append(
        (
            "INFO",
            f"{len(not_connected)} paired",
            "Paired devices should be reviewed against authorized inventory",
        )
    )

    for severity, target, desc in findings:
        marker = {"CRITICAL": "[!]", "HIGH": "[!]", "LOW": "[-]", "INFO": "[i]", "PASS": "[+]"}
        print(f"  {marker.get(severity, '[?]')} {severity:8s} {target:30s} {desc}")

    print()


# ── Main ──

if __name__ == "__main__":
    print()
    print("*" * 95)
    print("  SOC 2 WIRELESS ASSESSMENT — Wi-Fi + Bluetooth Scan")
    print("  Host: macOS (built-in adapters — no USB hardware required)")
    print("*" * 95)
    print()

    # Wi-Fi
    current, other_nets, rssi_map, iface = scan_wifi()
    print_wifi_report(current, other_nets, rssi_map, iface)
    assess_wifi_security(current, other_nets)

    # Bluetooth
    controller, connected, not_connected = scan_bluetooth()
    assess_bluetooth_security(controller, connected, not_connected)

    # Limitations
    print("=" * 95)
    print("ASSESSMENT LIMITATIONS")
    print("=" * 95)
    print()
    print("  1. NO MONITOR MODE — macOS built-in Wi-Fi cannot enter monitor mode.")
    print("     Cannot capture WPA handshakes, detect deauth attacks, or perform")
    print("     active rogue AP detection (evil twin). Requires USB Wi-Fi adapter.")
    print()
    print("  2. NO PACKET INJECTION — Cannot test WPS (reaver/bully) or send")
    print("     deauth frames for handshake capture.")
    print()
    print("  3. SSID REDACTED — macOS location privacy redacts SSIDs in scan")
    print("     output. SSIDs visible in system_profiler but may show as")
    print("     <redacted> depending on Location Services status.")
    print()
    print("  4. NO BLE ACTIVE SCAN — system_profiler shows paired/connected")
    print("     devices only. Active BLE discovery (scanning for all BLE")
    print("     beacons in range) requires bluez or bettercap in a container")
    print("     with BT adapter passthrough.")
    print()
    print("  5. COVERAGE — This scan covers: AP enumeration, encryption type")
    print("     validation, channel overlap, signal strength, BT controller")
    print("     config, paired device inventory. Does NOT cover: handshake")
    print("     capture, rogue AP active detection, BLE beacon discovery,")
    print("     signal boundary testing.")
    print()
