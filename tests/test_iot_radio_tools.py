"""Unit tests for Phase 14d IoT radio protocol pentest tools."""

from unittest.mock import patch

import pytest

from nightwing.agent.tools.scan.iot_radio_tools import (
    run_killerbee,
    run_lorawan_scanner,
    run_subghz_scan,
    run_zbstumbler,
)


@pytest.fixture
def mock_container():
    with patch("nightwing.agent.tools.scan.iot_radio_tools.run_in_pentest_container") as mock_run:
        mock_run.return_value = {"exit_code": 0, "output": "", "error": ""}
        yield mock_run


class TestPhase14dIoTRadio:
    """Tests for Phase 14d IoT radio tools."""

    def test_killerbee_scan(self, mock_container):
        run_killerbee("scan")
        cmd = _cmd(mock_container)
        assert "zbstumbler" in cmd

    def test_killerbee_sniff(self, mock_container):
        run_killerbee("sniff")
        cmd = _cmd(mock_container)
        assert "zbdump" in cmd

    def test_zbstumbler_basic(self, mock_container):
        run_zbstumbler(duration=30)
        cmd = _cmd(mock_container)
        assert "zbstumbler" in cmd
        assert "timeout 30" in cmd

    def test_lorawan_scanner_basic(self, mock_container):
        run_lorawan_scanner(duration=60)
        cmd = _cmd(mock_container)
        assert "lorawan-scanner" in cmd
        assert "timeout 60" in cmd

    def test_subghz_scan_basic(self, mock_container):
        run_subghz_scan(frequency=433, duration=30)
        cmd = _cmd(mock_container)
        assert "rtl_433" in cmd
        assert "-f 433M" in cmd
        assert "-a" in cmd
        assert "timeout 30" in cmd

    def test_subghz_scan_custom_freq(self, mock_container):
        run_subghz_scan(frequency=868)
        cmd = _cmd(mock_container)
        assert "-f 868M" in cmd


class TestIoTRadioToolsRegistered:
    """Verify IoT radio tools are registered in get_all_tools()."""

    def test_iot_radio_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_killerbee",
            "run_zbstumbler",
            "run_lorawan_scanner",
            "run_subghz_scan",
        }

        missing = expected - tool_names
        assert not missing, f"IoT radio tools not registered: {missing}"


def _cmd(mock_container):
    call_args = mock_container.call_args
    return call_args.kwargs.get("command", call_args.args[0] if call_args.args else "")
