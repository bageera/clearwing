"""Unit tests for Phase 14c SDR / RF pentest tools."""

from unittest.mock import patch

import pytest

from nightwing.agent.tools.scan.sdr_tools import (
    run_gqrx,
    run_hackrf_info,
    run_hackrf_sweep,
    run_inspectrum,
    run_rtl_433,
    run_rtl_power,
)


@pytest.fixture
def mock_container():
    with patch("nightwing.agent.tools.scan.sdr_tools.run_in_pentest_container") as mock_run:
        mock_run.return_value = {"exit_code": 0, "output": "", "error": ""}
        yield mock_run


class TestPhase14cSDR:
    """Tests for Phase 14c SDR/RF tools."""

    def test_hackrf_info_basic(self, mock_container):
        run_hackrf_info()
        cmd = _cmd(mock_container)
        assert "hackrf_info" in cmd

    def test_hackrf_sweep_basic(self, mock_container):
        run_hackrf_sweep()
        cmd = _cmd(mock_container)
        assert "hackrf_sweep" in cmd
        assert "-f 1:6000" in cmd
        assert "timeout 30" in cmd

    def test_hackrf_sweep_custom_range(self, mock_container):
        run_hackrf_sweep(freq_min=100, freq_max=200, duration=60)
        cmd = _cmd(mock_container)
        assert "-f 100:200" in cmd
        assert "timeout 60" in cmd

    def test_rtl_433_basic(self, mock_container):
        run_rtl_433()
        cmd = _cmd(mock_container)
        assert "rtl_433" in cmd
        assert "-f 433M" in cmd
        assert "timeout 60" in cmd

    def test_rtl_433_custom_freq(self, mock_container):
        run_rtl_433(frequency=868, duration=30)
        cmd = _cmd(mock_container)
        assert "-f 868M" in cmd
        assert "timeout 30" in cmd

    def test_rtl_power_basic(self, mock_container):
        run_rtl_power()
        cmd = _cmd(mock_container)
        assert "rtl_power" in cmd
        assert "1M:6000M" in cmd
        assert "timeout 60" in cmd

    def test_gqrx_basic(self, mock_container):
        run_gqrx(frequency=433)
        cmd = _cmd(mock_container)
        assert "gqrx" in cmd
        assert "433e6" in cmd

    def test_inspectrum_basic(self, mock_container):
        run_inspectrum("/tmp/signal.cf32")
        cmd = _cmd(mock_container)
        assert "inspectrum" in cmd
        assert "/tmp/signal.cf32" in cmd


class TestSDRToolsRegistered:
    """Verify SDR tools are registered in get_all_tools()."""

    def test_sdr_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_hackrf_info",
            "run_hackrf_sweep",
            "run_rtl_433",
            "run_rtl_power",
            "run_gqrx",
            "run_inspectrum",
        }

        missing = expected - tool_names
        assert not missing, f"SDR tools not registered: {missing}"


def _cmd(mock_container):
    call_args = mock_container.call_args
    return call_args.kwargs.get("command", call_args.args[0] if call_args.args else "")
