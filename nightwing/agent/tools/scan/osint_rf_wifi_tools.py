"""RF + Wi-Fi OSINT agent tools.

Thin @tool wrappers over :mod:`nightwing.native.wigle_tools` and
:mod:`nightwing.native.adsb_tools` (keyless). Read-only recon, no approval
gate — same posture as the OSINT recon container tools.
"""

from typing import Any

from nightwing.agent.tooling import tool
from nightwing.native import adsb_tools, wigle_tools


@tool(requires_approval=False)
def wigle_wifi_search(
    ssid: str = "",
    bssid: str = "",
    latrange1: float | None = None,
    latrange2: float | None = None,
    longrange1: float | None = None,
    longrange2: float | None = None,
    results_per_page: int = 25,
) -> dict[str, Any]:
    """Observed Wi-Fi networks from the WiGLE wardriving database.

    Passive OSINT: locates SSIDs/BSSIDs on a map, maps a physical site's
    wireless footprint, or finds where a corporate SSID has been observed.
    Set NIGHTWING_WIGLE_AUTH to your wigle.net credentials string.

    Args:
        ssid: SSID substring to match.
        bssid: Exact BSSID (AP MAC), e.g. '00:11:22:33:44:55'.
        latrange1: Lower latitude bound (with latrange2 = geo box).
        latrange2: Upper latitude bound.
        longrange1: Lower longitude bound.
        longrange2: Upper longitude bound.
        results_per_page: Max results (default 25).

    Returns:
        Dict with WiGLE results (network observations with geo coordinates).
    """
    return wigle_tools.wigle_search_wifi(
        ssid=ssid or None,
        bssid=bssid or None,
        latrange1=latrange1,
        latrange2=latrange2,
        longrange1=longrange1,
        longrange2=longrange2,
        results_per_page=results_per_page,
    )


@tool(requires_approval=False)
def wigle_bt_search(
    name: str = "",
    key: str = "",
    results_per_page: int = 25,
) -> dict[str, Any]:
    """Observed Bluetooth devices from the WiGLE database.

    Args:
        name: Device name to match.
        key: Bluetooth MAC key to match.
        results_per_page: Max results (default 25).

    Returns:
        Dict with WiGLE Bluetooth results.
    """
    return wigle_tools.wigle_search_bluetooth(
        name=name or None,
        key=key or None,
        results_per_page=results_per_page,
    )


@tool(requires_approval=False)
def adsb_near(lat: float, lon: float, radius_nm: float = 50.0) -> dict[str, Any]:
    """Aircraft currently within a radius of coordinates (RF ADS-B data).

    Passive OSINT: operator/corporate aircraft on site, airport traffic
    context. Data is keyless via adsb.lol.

    Args:
        lat: Latitude decimal degrees.
        lon: Longitude decimal degrees.
        radius_nm: Search radius in nautical miles (max 250).

    Returns:
        Dict with aircraft list (each entry has hex, registration, type,
        altitude, position).
    """
    return adsb_tools.adsb_point(lat, lon, radius_nm)


@tool(requires_approval=False)
def adsb_lookup(handle: str) -> dict[str, Any]:
    """Look up one aircraft by ICAO24 hex address or radio callsign.

    Args:
        handle: 6-hex ICAO24 address (e.g. 'adsb0a1b2c') or callsign
            (e.g. 'KAL826'); hex if it is 6 hex characters, callsign otherwise.

    Returns:
        Dict with the aircraft's current position, registration and type.
    """
    h = handle.strip()
    if len(h) == 6 and all(c in "0123456789abcdefABCDEF" for c in h):
        return adsb_tools.adsb_hex(h)
    return adsb_tools.adsb_callsign(h)
