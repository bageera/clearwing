"""Backward-compat re-export shim for the old network_wireless_mobile_tools module.

The original 687-line megafile has been split into phase-specific modules:
  - network_discovery_tools.py  (Phase 11)
  - wireless_tools.py             (Phase 12)
  - mobile_tools.py               (Phase 13)
  - bluetooth_rf_tools.py         (Phase 14)
  - iot_hardware_tools.py         (Phase 15)

This shim re-exports all names so existing imports continue to work.
New code should import from the split modules directly.
"""

# ruff: noqa: F401
from nightwing.agent.tools.scan.bluetooth_rf_tools import (
    run_bettercap_bluetooth,
    run_bluez_info,
    run_bluez_scan,
    run_btlejack,
    run_sniffle,
    run_ubertooth,
)
from nightwing.agent.tools.scan.iot_hardware_tools import run_binwalk, run_firmwalker
from nightwing.agent.tools.scan.mobile_tools import (
    run_apktool,
    run_drozer,
    run_frida,
    run_jadx,
    run_mobsf,
    run_objection,
)
from nightwing.agent.tools.scan.network_discovery_tools import (
    run_arp_scan,
    run_masscan,
    run_netdiscover,
    run_traceroute,
)
from nightwing.agent.tools.scan.wireless_tools import (
    run_airbase_ng,
    run_aircrack_ng,
    run_airdecap_ng,
    run_aireplay_ng,
    run_airgraph_ng,
    run_airmon_ng,
    run_airodump_ng,
    run_asleap,
    run_bully,
    run_eaphammer,
    run_horst,
    run_hostapd_wpe,
    run_kismet,
    run_reaver,
    run_wash,
    run_wifite,
)

__all__ = [
    # Phase 11
    "run_netdiscover",
    "run_masscan",
    "run_arp_scan",
    "run_traceroute",
    # Phase 12
    "run_aircrack_ng",
    "run_airodump_ng",
    "run_wifite",
    "run_reaver",
    "run_bully",
    "run_airmon_ng",
    "run_airbase_ng",
    "run_aireplay_ng",
    "run_airdecap_ng",
    "run_wash",
    "run_kismet",
    "run_airgraph_ng",
    "run_horst",
    "run_eaphammer",
    "run_hostapd_wpe",
    "run_asleap",
    # Phase 13
    "run_frida",
    "run_objection",
    "run_mobsf",
    "run_apktool",
    "run_jadx",
    "run_drozer",
    # Phase 14
    "run_bettercap_bluetooth",
    "run_ubertooth",
    "run_bluez_scan",
    "run_bluez_info",
    "run_btlejack",
    "run_sniffle",
    # Phase 15
    "run_firmwalker",
    "run_binwalk",
]
