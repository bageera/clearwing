"""Native WiGLE Wi-Fi/Bluetooth OSINT API integration.

Mirrors :mod:`nightwing.native.shodan_tools`: plain urllib, no container.
Set ``NIGHTWING_WIGLE_AUTH`` to your WiGLE API credentials string
(the "encoded" value from wigle.net, sent as HTTP Basic). Without it the
functions return a ``{"error": ...}`` dict instead of contacting the API.
"""

import base64
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_WIGLE_API_BASE = "https://api.wigle.net/api/v2"

_ENV_AUTH = "NIGHTWING_WIGLE_AUTH"


def _auth_header() -> dict[str, str] | dict[str, Any]:
    auth = os.environ.get(_ENV_AUTH, "")
    if not auth:
        return {"error": f"set {_ENV_AUTH} to your wigle.net API credentials string"}
    if auth.startswith("Basic "):
        auth = auth[6:]  # caller sent the full header value
    elif ":" in auth:
        # accept user:pass form and encode it
        auth = base64.b64encode(auth.encode()).decode()
    return {"Authorization": f"Basic {auth}", "Accept": "application/json"}


def _wigle_get(path: str, params: dict[str, Any]) -> dict[str, Any]:
    headers = _auth_header()
    if "error" in headers:
        return headers  # type: ignore[return-value]
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{_WIGLE_API_BASE}/{path}"
    if qs:
        url += f"?{qs}"
    logger.info("WiGLE API: %s", path)
    try:
        req = urllib.request.Request(url, headers=headers)  # type: ignore[arg-type]
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return data
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"error": "WiGLE authentication failed — check " + _ENV_AUTH}
        if e.code == 429:
            return {"error": "WiGLE rate limit exceeded"}
        return {"error": f"WiGLE HTTP error {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"WiGLE URL error: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse WiGLE response: {str(e)}"}


def wigle_search_wifi(
    ssid: str | None = None,
    bssid: str | None = None,
    latrange1: float | None = None,
    latrange2: float | None = None,
    longrange1: float | None = None,
    longrange2: float | None = None,
    results_per_page: int = 25,
) -> dict[str, Any]:
    """Search WiGLE for observed Wi-Fi networks by SSID, BSSID or geo box."""
    return _wigle_get(
        "network/search",
        {
            "ssid": ssid,
            "bssid": bssid,
            "latrange1": latrange1,
            "latrange2": latrange2,
            "longrange1": longrange1,
            "longrange2": longrange2,
            "onlymine": "false",
            "resultsPerPage": results_per_page,
        },
    )


def wigle_search_bluetooth(
    name: str | None = None,
    key: str | None = None,
    latrange1: float | None = None,
    latrange2: float | None = None,
    longrange1: float | None = None,
    longrange2: float | None = None,
    results_per_page: int = 25,
) -> dict[str, Any]:
    """Search WiGLE for observed Bluetooth devices by name (address) or key."""
    return _wigle_get(
        "bluetooth/search",
        {
            "name": name,
            "key": key,
            "latrange1": latrange1,
            "latrange2": latrange2,
            "longrange1": longrange1,
            "longrange2": longrange2,
            "resultsPerPage": results_per_page,
        },
    )
