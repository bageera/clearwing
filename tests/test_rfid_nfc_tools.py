"""Unit tests for Phase 14b RFID / NFC pentest tools."""

from unittest.mock import patch

import pytest

from nightwing.agent.tools.scan.rfid_nfc_tools import (
    run_mfoc,
    run_mfuk,
    run_nfc_tool,
    run_proxmark3,
    run_rfidiot,
)


@pytest.fixture
def mock_container():
    with patch("nightwing.agent.tools.scan.rfid_nfc_tools.run_in_pentest_container") as mock_run:
        mock_run.return_value = {"exit_code": 0, "output": "", "error": ""}
        yield mock_run


class TestPhase14bRFIDNFC:
    """Tests for Phase 14b RFID/NFC tools."""

    def test_proxmark3_basic(self, mock_container):
        run_proxmark3("hf search")
        cmd = _cmd(mock_container)
        assert "pm3" in cmd
        assert "hf search" in cmd

    def test_proxmark3_lf_search(self, mock_container):
        run_proxmark3("lf search")
        cmd = _cmd(mock_container)
        assert "lf search" in cmd

    def test_mfoc_basic(self, mock_container):
        run_mfoc()
        cmd = _cmd(mock_container)
        assert "mfoc" in cmd

    def test_mfoc_with_options(self, mock_container):
        run_mfoc(options="-O /tmp/dump.mfd")
        cmd = _cmd(mock_container)
        assert "mfoc" in cmd
        assert "-O /tmp/dump.mfd" in cmd

    def test_mfuk_basic(self, mock_container):
        run_mfuk()
        cmd = _cmd(mock_container)
        assert "mfuk" in cmd

    def test_nfc_tool_list(self, mock_container):
        run_nfc_tool("list")
        cmd = _cmd(mock_container)
        assert "nfc-list" in cmd

    def test_nfc_tool_read(self, mock_container):
        run_nfc_tool("read")
        cmd = _cmd(mock_container)
        assert "nfc-mfclassic r" in cmd

    def test_rfidiot_basic(self, mock_container):
        run_rfidiot(action="read")
        cmd = _cmd(mock_container)
        assert "rfidiot.py" in cmd
        assert "--read" in cmd


class TestRFIDNFCToolsRegistered:
    """Verify RFID/NFC tools are registered in get_all_tools()."""

    def test_rfid_nfc_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_proxmark3",
            "run_mfoc",
            "run_mfuk",
            "run_nfc_tool",
            "run_rfidiot",
        }

        missing = expected - tool_names
        assert not missing, f"RFID/NFC tools not registered: {missing}"


def _cmd(mock_container):
    call_args = mock_container.call_args
    return call_args.kwargs.get("command", call_args.args[0] if call_args.args else "")
