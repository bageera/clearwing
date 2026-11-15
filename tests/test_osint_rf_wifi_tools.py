"""Tests for WiGLE + ADS-B OSINT modules (native clients and agent wrappers)."""

import base64
import json
import urllib.error
from email.message import Message
from unittest.mock import patch

from nightwing.agent.tools.scan import osint_rf_wifi_tools as wr
from nightwing.native import adsb_tools, wigle_tools


class _FakeResp:
    """Minimal context-manager response standing in for urllib.urlopen()."""

    def __init__(self, payload: bytes | str):
        self._payload = payload if isinstance(payload, bytes) else payload.encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._payload


def _capturing_urlopen():
    """Patch urlopen to capture the request and return a canned response."""
    captured: dict = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        return _FakeResp(json.dumps({"success": True}))

    return captured, patch("urllib.request.urlopen", new=fake_urlopen)


def _raise_http_error(code: int):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, code, "reason", hdrs=Message(), fp=None)

    return patch("urllib.request.urlopen", new=fake_urlopen)


class TestWigleAuth:
    def test_no_env_returns_error_dict_without_network(self, monkeypatch):
        monkeypatch.delenv("NIGHTWING_WIGLE_AUTH", raising=False)
        out = wigle_tools.wigle_search_wifi(ssid="corp_ssid")
        assert "error" in out and "NIGHTWING_WIGLE_AUTH" in out["error"]

    def test_user_pass_env_is_basic_encoded(self, monkeypatch):
        monkeypatch.setenv("NIGHTWING_WIGLE_AUTH", "me:pass")
        captured, p = _capturing_urlopen()
        with p:
            out = wigle_tools.wigle_search_wifi(ssid="corp_ssid")
        assert out == {"success": True}
        expected = base64.b64encode(b"me:pass").decode()
        assert captured["headers"]["Authorization"] == f"Basic {expected}"
        assert "/network/search" in captured["url"]
        assert "ssid=corp_ssid" in captured["url"]

    def test_preencoded_env_passed_through(self, monkeypatch):
        monkeypatch.setenv("NIGHTWING_WIGLE_AUTH", "Basic QUJD")
        captured, p = _capturing_urlopen()
        with p:
            wigle_tools.wigle_search_bluetooth(name="JBL")
        assert captured["headers"]["Authorization"] == "Basic QUJD"
        assert "/bluetooth/search" in captured["url"]

    def test_http_401_maps_to_auth_error(self, monkeypatch):
        monkeypatch.setenv("NIGHTWING_WIGLE_AUTH", "me:pass")
        with _raise_http_error(401):
            out = wigle_tools.wigle_search_wifi(ssid="x")
        assert "error" in out and "authentication" in out["error"]


class TestAdsb:
    def test_point_validates_coords_without_network(self):
        out = adsb_tools.adsb_point(99.0, 700.0)
        assert "error" in out and "invalid coordinates" in out["error"]

    def test_point_url_contains_coords_and_capped_radius(self):
        captured, p = _capturing_urlopen()
        with p:
            adsb_tools.adsb_point(45.5, -73.5, radius_nm=999)
        assert captured["url"].endswith("/point/45.5/-73.5/250")

    def test_hex_strips_hash(self):
        captured, p = _capturing_urlopen()
        with p:
            adsb_tools.adsb_hex("#0A1B2C")
        assert captured["url"].endswith("/hex/0A1B2C")

    def test_callsign_uppercased(self):
        captured, p = _capturing_urlopen()
        with p:
            adsb_tools.adsb_callsign("kal826")
        assert captured["url"].endswith("/callsign/KAL826")


class TestAgentWrappers:
    def test_adsb_lookup_dispatches_hex(self):
        with patch("nightwing.native.adsb_tools._adsb_get", return_value={"hex": "OK"}) as mock_get:
            out = wr.adsb_lookup.func(handle="0A1B2C")
        assert "hex/" in mock_get.call_args[0][0]
        assert out == {"hex": "OK"}

    def test_adsb_lookup_dispatches_callsign(self):
        with patch("nightwing.native.adsb_tools._adsb_get", return_value={"cs": "OK"}) as mock_get:
            wr.adsb_lookup.func(handle="KAL826")
        assert mock_get.call_args[0][0].startswith("callsign/")

    def test_wigle_wrapper_plumbs_native(self):
        with patch(
            "nightwing.native.wigle_tools.wigle_search_wifi",
            return_value={"success": True},
        ) as mock_query:
            out = wr.wigle_wifi_search.func(ssid="corp", results_per_page=10)
        mock_query.assert_called_once_with(
            ssid="corp",
            bssid=None,
            latrange1=None,
            latrange2=None,
            longrange1=None,
            longrange2=None,
            results_per_page=10,
        )
        assert out == {"success": True}
