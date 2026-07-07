"""Unit tests for Phase 14 Bluetooth & RF pentest tools."""

from unittest.mock import patch

import pytest

from nightwing.agent.tools.scan.bluetooth_rf_tools import (
    run_bettercap_bluetooth,
    run_bluez_info,
    run_bluez_scan,
    run_btlejack,
    run_sniffle,
    run_ubertooth,
)


@pytest.fixture
def mock_container():
    with patch(
        "nightwing.agent.tools.scan.bluetooth_rf_tools.run_in_pentest_container"
    ) as mock_run:
        mock_run.return_value = {"exit_code": 0, "output": "", "error": ""}
        yield mock_run


class TestPhase14Bluetooth:
    """Tests for Phase 14 Bluetooth tools."""

    def test_bettercap_bluetooth_basic(self, mock_container):
        run_bettercap_bluetooth()
        cmd = _cmd(mock_container)
        assert "bettercap" in cmd
        assert "ble.recon on" in cmd

    def test_ubertooth_basic(self, mock_container):
        run_ubertooth("scan")
        cmd = _cmd(mock_container)
        assert "ubertooth-scan" in cmd

    def test_bluez_scan_basic(self, mock_container):
        run_bluez_scan()
        cmd = _cmd(mock_container)
        assert "hcitool scan" in cmd

    def test_bluez_info_basic(self, mock_container):
        run_bluez_info("AA:BB:CC:DD:EE:FF")
        cmd = _cmd(mock_container)
        assert "hcitool info" in cmd
        assert "AA:BB:CC:DD:EE:FF" in cmd

    def test_btlejack_basic(self, mock_container):
        run_btlejack(duration=30)
        cmd = _cmd(mock_container)
        assert "btlejack" in cmd
        assert "timeout 30" in cmd

    def test_sniffle_basic(self, mock_container):
        run_sniffle(duration=45)
        cmd = _cmd(mock_container)
        assert "sniffle" in cmd
        assert "timeout 45" in cmd


class TestBluetoothToolsRegistered:
    """Verify Bluetooth tools are registered in get_all_tools()."""

    def test_bluetooth_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_bettercap_bluetooth",
            "run_ubertooth",
            "run_bluez_scan",
            "run_bluez_info",
            "run_btlejack",
            "run_sniffle",
        }

        missing = expected - tool_names
        assert not missing, f"Bluetooth tools not registered: {missing}"


def _cmd(mock_container):
    call_args = mock_container.call_args
    return call_args.kwargs.get("command", call_args.args[0] if call_args.args else "")
