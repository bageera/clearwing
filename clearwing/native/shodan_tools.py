"""Native Shodan API integration.

This module provides native Python implementations for Shodan API queries
without requiring external tools or containers.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_SHODAN_API_BASE = "https://api.shodan.io"


def query_shodan(
    query: str, api_key: str, limit: int = 100, facets: str | None = None
) -> dict[str, Any]:
    """Query Shodan API for host information.

    Args:
        query: Shodan search query (e.g., "hostname:example.com")
        api_key: Shodan API key
        limit: Maximum number of results to return (default: 100)
        facets: Comma-separated list of facets to get summary information

    Returns:
        Dictionary containing Shodan search results
    """
    # Construct the API URL
    url = f"{_SHODAN_API_BASE}/shodan/host/search"
    params = f"?key={api_key}&query={urllib.parse.quote(query)}&limit={limit}"

    if facets:
        params += f"&facets={urllib.parse.quote(facets)}"

    full_url = url + params

    logger.info(f"Querying Shodan API: {query}")

    try:
        # Make the request
        req = urllib.request.Request(
            full_url,
            headers={"User-Agent": "Clearwing-Shodan-Client/1.0", "Accept": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        logger.info(f"Shodan query returned {data.get('total', 0)} results")
        return data

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"error": "Invalid Shodan API key"}
        elif e.code == 403:
            return {"error": "Shodan API access forbidden"}
        elif e.code == 429:
            return {"error": "Shodan API rate limit exceeded"}
        else:
            return {"error": f"Shodan API HTTP error {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Shodan API URL error: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse Shodan API response: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error querying Shodan: {str(e)}"}


def get_host_info(ip: str, api_key: str, history: bool = False) -> dict[str, Any]:
    """Get detailed information about a specific host/IP.

    Args:
        ip: IP address to query
        api_key: Shodan API key
        history: Include historical data (default: False)

    Returns:
        Dictionary containing host information
    """
    # Construct the API URL
    url = f"{_SHODAN_API_BASE}/shodan/host/{ip}"
    params = f"?key={api_key}"

    if history:
        params += "&history=true"

    full_url = url + params

    logger.info(f"Getting Shodan host info for {ip}")

    try:
        # Make the request
        req = urllib.request.Request(
            full_url,
            headers={"User-Agent": "Clearwing-Shodan-Client/1.0", "Accept": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))

        return data

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"error": "Invalid Shodan API key"}
        elif e.code == 403:
            return {"error": "Shodan API access forbidden"}
        elif e.code == 404:
            return {"error": "Host not found in Shodan"}
        elif e.code == 429:
            return {"error": "Shodan API rate limit exceeded"}
        else:
            return {"error": f"Shodan API HTTP error {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"Shodan API URL error: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse Shodan API response: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error querying Shodan host info: {str(e)}"}


def get_shodan_facets(query: str, api_key: str, facets: list[str]) -> dict[str, Any]:
    """Get facet information for a Shodan query.

    Args:
        query: Shodan search query
        api_key: Shodan API key
        facets: List of facets to retrieve

    Returns:
        Dictionary containing facet information
    """
    facets_str = ",".join(facets)
    return query_shodan(query, api_key, limit=0, facets=facets_str)


def parse_shodan_results(results: dict[str, Any]) -> dict[str, Any]:
    """Parse Shodan results into a more structured format.

    Args:
        results: Raw Shodan API results

    Returns:
        Dictionary with parsed and structured information
    """
    if "error" in results:
        return results

    parsed = {
        "total_results": results.get("total", 0),
        "matches": [],
        "facets": results.get("facets", {}),
        "ips": set(),
        "ports": set(),
        "services": set(),
        "organizations": set(),
        "countries": set(),
    }

    for match in results.get("matches", []):
        parsed_match = {
            "ip": match.get("ip_str"),
            "port": match.get("port"),
            "service": match.get("product", "unknown"),
            "version": match.get("version", ""),
            "organization": match.get("org", ""),
            "location": {
                "country": match.get("location", {}).get("country_name", ""),
                "city": match.get("location", {}).get("city", ""),
                "latitude": match.get("location", {}).get("latitude"),
                "longitude": match.get("location", {}).get("longitude"),
            },
            "timestamp": match.get("timestamp"),
            "ssl": match.get("ssl", {}),
            "http": match.get("http", {}),
            "data": match.get("data", ""),
        }

        parsed["matches"].append(parsed_match)

        # Collect unique values
        if parsed_match["ip"]:
            parsed["ips"].add(parsed_match["ip"])
        if parsed_match["port"]:
            parsed["ports"].add(parsed_match["port"])
        if parsed_match["service"] and parsed_match["service"] != "unknown":
            parsed["services"].add(parsed_match["service"])
        if parsed_match["organization"]:
            parsed["organizations"].add(parsed_match["organization"])
        if parsed_match["location"]["country"]:
            parsed["countries"].add(parsed_match["location"]["country"])

    # Convert sets to lists for JSON serialization
    parsed["ips"] = list(parsed["ips"])
    parsed["ports"] = list(parsed["ports"])
    parsed["services"] = list(parsed["services"])
    parsed["organizations"] = list(parsed["organizations"])
    parsed["countries"] = list(parsed["countries"])

    return parsed
