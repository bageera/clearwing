"""Native RF OSINT: ADS-B aircraft lookup via the keyless adsb.lol API.

Mirrors :mod:`nightwing.native.shodan_tools`: plain urllib, no container.
ADS-B receivers worldwide feed adsb.lol; useful to OSINT a target site's
logistics (operator aircraft on-site, nearby airports' traffic patterns).
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_ADSB_API_BASE = "https://api.adsb.lol/v2"


def _adsb_get(path: str) -> dict[str, Any]:
    url = f"{_ADSB_API_BASE}/{urllib.parse.quote(path.lstrip('/'), safe='/@,.-')}"
    logger.info("adsb.lol API: %s", path)
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Nightwing-ADSB-Client/1.0",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "no ADS-B contact for that query"}
        if e.code == 429:
            return {"error": "adsb.lol rate limit exceeded"}
        return {"error": f"adsb.lol HTTP error {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"adsb.lol URL error: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse adsb.lol response: {str(e)}"}


def adsb_point(lat: float, lon: float, radius_nm: float = 50.0) -> dict[str, Any]:
    """Aircraft within `radius_nm` (max 250) of (lat, lon)."""
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return {"error": f"invalid coordinates lat={lat} lon={lon}"}
    radius = int(min(float(radius_nm), 250.0))
    return _adsb_get(f"point/{lat}/{lon}/{radius}")


def adsb_hex(icao24: str) -> dict[str, Any]:
    """Aircraft by 6-hex ICAO24 address."""
    return _adsb_get(f"hex/{icao24.lstrip('#').strip()}")


def adsb_callsign(callsign: str) -> dict[str, Any]:
    """Aircraft by radio callsign (e.g. 'KAL826')."""
    return _adsb_get(f"callsign/{callsign.strip().upper()}")
