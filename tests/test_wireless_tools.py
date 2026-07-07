"""Unit tests for Phase 12 wireless pentest tools."""

from unittest.mock import patch

import pytest

from nightwing.agent.tools.scan.wireless_tools import (
    run_airbase_ng,
    run_aircrack_ng,
    run_airdecap_ng,
    run_aireplay_ng,
    run_airgraph_ng,
    run_airmon_ng,
    run_airodump_ng,
    run_asleap,
    run_bully,
    run_eaphammer,
    run_horst,
    run_hostapd_wpe,
    run_kismet,
    run_reaver,
    run_wash,
    run_wifite,
)


@pytest.fixture
def mock_container():
    """Return a mocked container manager that captures executed commands."""
    with (
        patch("nightwing.agent.tools.scan.wireless_tools.run_in_pentest_container") as mock_run,
    ):
        mock_run.return_value = {
            "exit_code": 0,
            "output": "mocked output",
            "error": "",
        }
        yield mock_run


class TestPhase12ExistingTools:
    """Tests for the original 5 wireless tools (now in wireless_tools.py)."""

    def test_aircrack_ng_basic(self, mock_container):
        result = run_aircrack_ng("/tmp/capture.cap")
        assert result["exit_code"] == 0
        cmd = mock_run_call(mock_container)
        assert "aircrack-ng" in cmd
        assert "/usr/share/wordlists/rockyou.txt" in cmd
        assert "/tmp/capture.cap" in cmd

    def test_aircrack_ng_custom_wordlist(self, mock_container):
        run_aircrack_ng("/tmp/cap.pcap", wordlist="/tmp/words.txt")
        cmd = mock_run_call(mock_container)
        assert "-w /tmp/words.txt" in cmd

    def test_airodump_ng_basic(self, mock_container):
        result = run_airodump_ng("wlan0mon")
        assert result["exit_code"] == 0
        cmd = mock_run_call(mock_container)
        assert "airodump-ng" in cmd
        assert "wlan0mon" in cmd
        assert "timeout 30" in cmd

    def test_airodump_ng_custom_duration(self, mock_container):
        run_airodump_ng("wlan0mon", duration=120)
        cmd = mock_run_call(mock_container)
        assert "timeout 120" in cmd

    def test_wifite_basic(self, mock_container):
        run_wifite()
        cmd = mock_run_call(mock_container)
        assert "wifite" in cmd
        assert "timeout 300" in cmd

    def test_reaver_basic(self, mock_container):
        run_reaver("AA:BB:CC:DD:EE:FF")
        cmd = mock_run_call(mock_container)
        assert "reaver" in cmd
        assert "-b AA:BB:CC:DD:EE:FF" in cmd
        assert "-i wlan0mon" in cmd

    def test_bully_basic(self, mock_container):
        run_bully("AA:BB:CC:DD:EE:FF")
        cmd = mock_run_call(mock_container)
        assert "bully" in cmd
        assert "-b AA:BB:CC:DD:EE:FF" in cmd


class TestPhase12aMonitorMode:
    """Tests for Phase 12a monitor mode & interface management tools."""

    def test_airmon_ng_start(self, mock_container):
        run_airmon_ng("wlan0")
        cmd = mock_run_call(mock_container)
        assert "airmon-ng" in cmd
        assert "start wlan0" in cmd

    def test_airmon_ng_stop(self, mock_container):
        run_airmon_ng("wlan0mon", action="stop")
        cmd = mock_run_call(mock_container)
        assert "stop wlan0mon" in cmd

    def test_airmon_ng_check(self, mock_container):
        run_airmon_ng("wlan0", action="check")
        cmd = mock_run_call(mock_container)
        assert "airmon-ng check" in cmd

    def test_airbase_ng_basic(self, mock_container):
        run_airbase_ng("wlan0mon", "FreeWiFi", channel=6)
        cmd = mock_run_call(mock_container)
        assert "airbase-ng" in cmd
        assert "FreeWiFi" in cmd
        assert "-c 6" in cmd

    def test_aireplay_ng_deauth(self, mock_container):
        run_aireplay_ng("wlan0mon", attack_mode="deauth")
        cmd = mock_run_call(mock_container)
        assert "aireplay-ng" in cmd
        assert "--deauth" in cmd

    def test_aireplay_ng_fakeauth(self, mock_container):
        run_aireplay_ng("wlan0mon", attack_mode="fakeauth")
        cmd = mock_run_call(mock_container)
        assert "--fakeauth" in cmd

    def test_airdecap_ng_basic(self, mock_container):
        run_airdecap_ng("/tmp/capture.pcap")
        cmd = mock_run_call(mock_container)
        assert "airdecap-ng" in cmd
        assert "/tmp/capture.pcap" in cmd

    def test_wash_basic(self, mock_container):
        run_wash("wlan0mon")
        cmd = mock_run_call(mock_container)
        assert "wash" in cmd
        assert "-i wlan0mon" in cmd


class TestPhase12bRecon:
    """Tests for Phase 12b wireless reconnaissance tools."""

    def test_kismet_basic(self, mock_container):
        run_kismet("wlan0")
        cmd = mock_run_call(mock_container)
        assert "kismet" in cmd
        assert "-c wlan0" in cmd

    def test_airgraph_ng_basic(self, mock_container):
        run_airgraph_ng("/tmp/airodump.csv")
        cmd = mock_run_call(mock_container)
        assert "airgraph-ng" in cmd
        assert "/tmp/airodump.csv" in cmd
        assert "CAPR" in cmd

    def test_horst_basic(self, mock_container):
        run_horst("wlan0mon")
        cmd = mock_run_call(mock_container)
        assert "horst" in cmd
        assert "-i wlan0mon" in cmd


class TestPhase12cEnterprise:
    """Tests for Phase 12c enterprise wireless / 802.1X tools."""

    def test_eaphammer_basic(self, mock_container):
        run_eaphammer("wlan0mon", "CorpWiFi")
        cmd = mock_run_call(mock_container)
        assert "eaphammer" in cmd
        assert "-i wlan0mon" in cmd
        assert "CorpWiFi" in cmd

    def test_hostapd_wpe_basic(self, mock_container):
        run_hostapd_wpe("wlan0mon", "/etc/hostapd-wpe/hostapd-wpe.conf")
        cmd = mock_run_call(mock_container)
        assert "hostapd-wpe" in cmd
        assert "/etc/hostapd-wpe/hostapd-wpe.conf" in cmd

    def test_asleap_basic(self, mock_container):
        run_asleap("/tmp/capture.pcap")
        cmd = mock_run_call(mock_container)
        assert "asleap" in cmd
        assert "/tmp/capture.pcap" in cmd


class TestWirelessToolsRegistered:
    """Verify all wireless tools are registered in get_all_tools()."""

    def test_wireless_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_aircrack_ng",
            "run_airodump_ng",
            "run_wifite",
            "run_reaver",
            "run_bully",
            "run_airmon_ng",
            "run_airbase_ng",
            "run_aireplay_ng",
            "run_airdecap_ng",
            "run_wash",
            "run_kismet",
            "run_airgraph_ng",
            "run_horst",
            "run_eaphammer",
            "run_hostapd_wpe",
            "run_asleap",
        }

        missing = expected - tool_names
        assert not missing, f"Wireless tools not registered: {missing}"


def mock_run_call(mock_container):
    """Extract the command string from the mock container's call args."""
    call_args = mock_container.call_args
    return call_args.kwargs.get("command", call_args.args[0] if call_args.args else "")
