"""Certificate Transparency Log Tools — native Python, no container needed.

Queries crt.sh, CertSpotter, and other CT log aggregators to discover
subdomains and certificate history for a target domain.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import tool

logger = logging.getLogger(__name__)

_CRT_SH_URL = "https://crt.sh/?q={}&output=json"
_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert"


@tool(
    name="query_crt_sh",
    description=(
        "Query crt.sh Certificate Transparency logs for subdomains and "
        "certificate history of a target domain. Returns structured JSON."
    ),
)
def query_crt_sh(
    domain: str,
    exclude_expired: bool = False,
    deduplicate: bool = True,
) -> dict[str, Any]:
    """Query crt.sh for certificate transparency data.

    Args:
        domain: Target domain (e.g. "example.com").
        exclude_expired: Omit expired certificates from results.
        deduplicate: Collapse duplicate subdomain entries.

    Returns:
        Dict with subdomains, certificate IDs, issuers, and entry timestamps.
    """
    url = _CRT_SH_URL.format(urllib.request.quote(domain))
    logger.info("Querying crt.sh: %s", url)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Clearwing-CT-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as e:
        return {"error": f"crt.sh query failed: {e}"}

    subdomains: set[str] = set()
    certs: list[dict[str, Any]] = []

    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lstrip("*.")
            if line and domain in line:
                subdomains.add(line.lower())

        cert_entry = {
            "id": entry.get("id"),
            "logged_at": entry.get("entry_timestamp"),
            "issuer_name": entry.get("issuer_name"),
            "not_before": entry.get("not_before"),
            "not_after": entry.get("not_after"),
            "serial_number": entry.get("serial_number"),
        }
        if exclude_expired and cert_entry.get("not_after"):
            from datetime import datetime, timezone

            try:
                expiry = datetime.strptime(cert_entry["not_after"], "%Y-%m-%dT%H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
                if expiry < datetime.now(timezone.utc):
                    continue
            except ValueError:
                pass
        certs.append(cert_entry)

    result = {
        "domain": domain,
        "source": "crt.sh",
        "subdomains": sorted(subdomains) if deduplicate else list(subdomains),
        "subdomain_count": len(subdomains),
        "certificates": certs,
        "cert_count": len(certs),
    }
    logger.info("crt.sh returned %d subdomains, %d certs", len(subdomains), len(certs))
    return result


@tool(
    name="query_certspotter",
    description=(
        "Query CertSpotter API for certificate issuances on a domain and "
        "its subdomains. Requires no API key for low-volume use."
    ),
)
def query_certspotter(
    domain: str,
    after_id: str = "",
) -> dict[str, Any]:
    """Query CertSpotter for certificate issuances.

    Args:
        domain: Target domain.
        after_id: Pagination cursor from a previous query (optional).

    Returns:
        Dict with issuances, dns_names, issuer details, and pagination cursor.
    """
    url = _CERTSPOTTER_URL.format(urllib.request.quote(domain))
    if after_id:
        url += f"&after={urllib.request.quote(after_id)}"

    logger.info("Querying certspotter: %s", url)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Clearwing-CT-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as e:
        return {"error": f"certspotter query failed: {e}"}

    issuances = data if isinstance(data, list) else data.get("issuances", [])
    subdomains: set[str] = set()
    for issuance in issuances:
        for name in issuance.get("dns_names", []):
            subdomains.add(name.lower().lstrip("*."))

    result = {
        "domain": domain,
        "source": "certspotter",
        "subdomains": sorted(subdomains),
        "subdomain_count": len(subdomains),
        "issuances": issuances,
        "issuance_count": len(issuances),
        "pagination": {"after_id": after_id, "has_more": len(issuances) >= 100},
    }
    logger.info("certspotter returned %d subdomains, %d issuances", len(subdomains), len(issuances))
    return result
