"""Unit tests for Phase 4 enumeration tools (API + Database).

These tests verify command construction for containerized pentest tools
by mocking ``run_in_pentest_container``.
"""

from unittest.mock import patch

import pytest

from nightwing.agent.tools.scan.enumeration_tools import (
    run_arjun,
    run_dalfox,
    run_ffuf,
    run_httpx,
    run_jwt_tool,
    run_nosqlmap,
    run_oscanner,
    run_sqlmate,
    run_sqlninja,
    run_sqlsus,
)


@pytest.fixture
def mock_container():
    """Mock run_in_pentest_container and return the mock."""
    with patch("nightwing.agent.tools.scan.enumeration_tools.run_in_pentest_container") as mock_run:
        mock_run.return_value = {
            "exit_code": 0,
            "output": "mocked output",
            "error": "",
        }
        yield mock_run


def _cmd(mock_run):
    """Extract the command string from the mock's call args."""
    call = mock_run.call_args
    # run_in_pentest_container(command, ...) — command is first positional arg
    return call.args[0] if call.args else call.kwargs.get("command", "")


class TestPhase4APITools:
    """Unit tests for API pentesting tools (ffuf, httpx, jwt_tool, arjun, dalfox)."""

    # ── ffuf ──────────────────────────────────────────────────────────
    def test_ffuf_basic_get(self, mock_container):
        result = run_ffuf("https://api.example.com/FUZZ")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "ffuf" in cmd
        assert "https://api.example.com/FUZZ" in cmd
        assert "-w /usr/share/wordlists/dirb/common.txt" in cmd
        assert "-mc all -fc 404" in cmd

    def test_ffuf_post_with_data(self, mock_container):
        run_ffuf(
            "https://api.example.com/auth",
            method="POST",
            post_data='{"username":"FUZZ","password":"test"}',
            headers="Authorization: Bearer token;Content-Type: application/json",
        )
        cmd = _cmd(mock_container)
        assert "-X POST" in cmd
        assert "-d" in cmd
        assert "-H" in cmd

    def test_ffuf_extensions(self, mock_container):
        run_ffuf(
            "https://api.example.com/FUZZ",
            extensions="json,php,bak,txt",
        )
        cmd = _cmd(mock_container)
        assert "-e json,php,bak,txt" in cmd

    def test_ffuf_uses_parrot(self, mock_container):
        run_ffuf("https://api.example.com/FUZZ", distro="parrot")
        assert mock_container.call_args.kwargs.get("distro") == "parrot"

    # ── httpx ───────────────────────────────────────────────────────────
    def test_httpx_basic(self, mock_container):
        result = run_httpx("https://api.example.com")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "httpx" in cmd
        assert "-status-code -title -tech-detect -json" in cmd

    def test_httpx_custom_options(self, mock_container):
        run_httpx(
            "https://api.example.com",
            options="-status-code -web-server -ip -cdn",
        )
        cmd = _cmd(mock_container)
        assert "-web-server" in cmd

    # ── jwt_tool ──────────────────────────────────────────────────────
    def test_jwt_tool_basic(self, mock_container):
        result = run_jwt_tool("eyJhbGciOiJIUzI1NiIs...")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "jwt_tool.py" in cmd
        assert "eyJhbGciOiJIUzI1NiIs..." in cmd
        assert "-t" in cmd

    def test_jwt_tool_custom_options(self, mock_container):
        run_jwt_tool(
            "eyJhbGciOiJIUzI1NiIs...",
            options="-C /usr/share/wordlists/rockyou.txt",
        )
        cmd = _cmd(mock_container)
        assert "-C" in cmd

    # ── arjun ───────────────────────────────────────────────────────────
    def test_arjun_get(self, mock_container):
        result = run_arjun("https://api.example.com/search")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "arjun" in cmd
        assert "-u 'https://api.example.com/search'" in cmd
        assert "-m GET" in cmd

    def test_arjun_post(self, mock_container):
        run_arjun(
            "https://api.example.com/search",
            method="POST",
        )
        cmd = _cmd(mock_container)
        assert "-m POST" in cmd

    # ── dalfox ──────────────────────────────────────────────────────────
    def test_dalfox_basic(self, mock_container):
        result = run_dalfox("https://example.com?q=test")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "dalfox" in cmd
        assert "url 'https://example.com?q=test'" in cmd
        assert "--silence" in cmd

    def test_dalfox_custom_options(self, mock_container):
        run_dalfox(
            "https://example.com?q=test",
            options="--mining-dom --follow-redirects",
        )
        cmd = _cmd(mock_container)
        assert "--mining-dom" in cmd


class TestPhase4DatabaseTools:
    """Unit tests for database pentesting tools (nosqlmap, oscanner, sqlninja, sqlsus, sqlmate)."""

    # ── nosqlmap ──────────────────────────────────────────────────────
    def test_nosqlmap_basic(self, mock_container):
        result = run_nosqlmap("http://target.com/api/user")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "nosqlmap.py" in cmd
        assert "http://target.com/api/user" in cmd

    def test_nosqlmap_options(self, mock_container):
        run_nosqlmap(
            "http://target.com/api/user",
            options="--attack --dbs",
        )
        cmd = _cmd(mock_container)
        assert "--attack" in cmd

    # ── oscanner ──────────────────────────────────────────────────────
    def test_oscanner_basic(self, mock_container):
        result = run_oscanner("10.0.0.1")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "oscanner" in cmd
        assert "-s" in cmd
        assert "10.0.0.1" in cmd

    def test_oscanner_custom_options(self, mock_container):
        run_oscanner("10.0.0.1", options="-P 1521")
        cmd = _cmd(mock_container)
        assert "-P 1521" in cmd

    # ── sqlninja ──────────────────────────────────────────────────────
    def test_sqlninja_basic(self, mock_container):
        result = run_sqlninja("http://target.com/search?id=1")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "sqlninja" in cmd
        assert "-m test" in cmd
        assert "-u 'http://target.com/search?id=1'" in cmd

    def test_sqlninja_exploit_mode(self, mock_container):
        run_sqlninja(
            "http://target.com/search?id=1",
            options="-m fingerprint",
        )
        cmd = _cmd(mock_container)
        assert "-m fingerprint" in cmd

    # ── sqlsus ────────────────────────────────────────────────────────
    def test_sqlsus_basic(self, mock_container):
        result = run_sqlsus("http://target.com/login")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "sqlsus" in cmd
        assert "--guess" in cmd
        assert "http://target.com/login" in cmd

    def test_sqlsus_custom_options(self, mock_container):
        run_sqlsus(
            "http://target.com/login",
            options="--interactive",
        )
        cmd = _cmd(mock_container)
        assert "--interactive" in cmd

    # ── sqlmate ─────────────────────────────────────────────────────────
    def test_sqlmate_basic(self, mock_container):
        result = run_sqlmate("http://target.com/page?id=1")
        assert result["exit_code"] == 0
        cmd = _cmd(mock_container)
        assert "sqlmate" in cmd
        assert "--batch" in cmd
        assert "-u 'http://target.com/page?id=1'" in cmd

    def test_sqlmate_custom_options(self, mock_container):
        run_sqlmate(
            "http://target.com/page?id=1",
            options="--level 3 --risk 2",
        )
        cmd = _cmd(mock_container)
        assert "--level 3" in cmd


class TestToolSignatures:
    """Verify all new tools have correct function signatures and docstrings."""

    tools = [
        run_ffuf,
        run_httpx,
        run_jwt_tool,
        run_arjun,
        run_dalfox,
        run_nosqlmap,
        run_oscanner,
        run_sqlninja,
        run_sqlsus,
        run_sqlmate,
    ]

    @pytest.mark.parametrize("tool", tools)
    def test_tool_has_docstring(self, tool):
        assert tool.__doc__ is not None
        assert len(tool.__doc__) > 50

    @pytest.mark.parametrize("tool", tools)
    def test_tool_returns_dict(self, tool):
        with patch(
            "nightwing.agent.tools.scan.enumeration_tools.run_in_pentest_container"
        ) as mock_run:
            mock_run.return_value = {"exit_code": 0, "output": "", "error": ""}
            result = tool("http://example.com")
            assert isinstance(result, dict)
            assert "exit_code" in result
            assert "output" in result
            assert "error" in result


class TestAllToolsRegistered:
    """Verify all Phase 4 tools are importable from the package registry."""

    def test_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_ffuf",
            "run_httpx",
            "run_jwt_tool",
            "run_arjun",
            "run_dalfox",
            "run_nosqlmap",
            "run_oscanner",
            "run_sqlninja",
            "run_sqlsus",
            "run_sqlmate",
        }

        missing = expected - tool_names
        assert not missing, f"Tools not registered: {missing}"


class TestCloudToolsRegistered:
    """Verify GCP/AWS cloud pentest tools are registered in get_all_tools()."""

    def test_cloud_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_gcp_bucket_enum",
            "run_gcp_metadata_exploit",
            "run_gcp_iam_audit",
            "run_gcp_secrets_enum",
            "run_gcp_cloudfunction_enum",
            "run_aws_s3_enum",
            "run_aws_ec2_enum",
            "run_aws_metadata_exploit",
            "run_aws_secrets_enum",
            "run_aws_lambda_enum",
            "run_aws_iam_escalation",
        }

        missing = expected - tool_names
        assert not missing, f"Cloud tools not registered: {missing}"


class TestLLMToolsRegistered:
    """Verify LLM security testing tools are registered in get_all_tools()."""

    def test_llm_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_prompt_injection_scanner",
            "run_jailbreak_tester",
            "run_indirect_prompt_injection",
            "run_system_prompt_extraction",
            "run_training_data_extraction",
            "run_pii_extraction_tester",
            "run_model_consistency_tester",
            "run_toxicity_regression_tester",
            "run_bias_detector",
            "run_agent_escape_tester",
            "run_tool_poisoning_tester",
            "run_multi_turn_poisoning",
            "run_token_smuggling_tester",
            "run_adversarial_vision_tester",
        }

        missing = expected - tool_names
        assert not missing, f"LLM tools not registered: {missing}"


class TestAPIToolsRegistered:
    """Verify API security testing tools are registered in get_all_tools()."""

    def test_api_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_graphqlmap",
            "run_grpcurl",
            "run_wsprobe",
            "run_idor_scanner",
            "run_race_condition_tester",
            "run_swagger_abuse",
            "run_2fa_bypass_tester",
            "run_cors_misconfig_tester",
        }

        missing = expected - tool_names
        assert not missing, f"API tools not registered: {missing}"


class TestCICDToolsRegistered:
    """Verify CI/CD security tools are registered in get_all_tools()."""

    def test_cicd_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_gitleaks",
            "run_trufflehog",
            "run_checkov",
            "run_trivy",
            "run_semgrep",
            "run_dependency_audit",
            "run_kube_hunter",
        }

        missing = expected - tool_names
        assert not missing, f"CI/CD tools not registered: {missing}"


class TestNetworkWirelessMobileToolsRegistered:
    """Verify Phase 11+ network, wireless, mobile, and hardware tools are registered."""

    def test_network_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_netdiscover",
            "run_masscan",
            "run_arp_scan",
            "run_traceroute",
        }

        missing = expected - tool_names
        assert not missing, f"Network tools not registered: {missing}"

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

    def test_mobile_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_frida",
            "run_objection",
            "run_mobsf",
            "run_apktool",
            "run_jadx",
            "run_drozer",
        }

        missing = expected - tool_names
        assert not missing, f"Mobile tools not registered: {missing}"

    def test_bluetooth_rfid_nfc_tools_in_get_all_tools(self):
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
            "run_proxmark3",
            "run_mfoc",
            "run_mfuk",
            "run_nfc_tool",
            "run_rfidiot",
        }

        missing = expected - tool_names
        assert not missing, f"Bluetooth/RFID/NFC tools not registered: {missing}"

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

    def test_bluetooth_iot_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_firmwalker",
            "run_binwalk",
        }

        missing = expected - tool_names
        assert not missing, f"IoT hardware tools not registered: {missing}"


class TestICSOSINTHWToolsRegistered:
    """Verify Phase 16+ ICS, OSINT, and hardware tools are registered."""

    def test_ics_tools_in_get_all_tools(self):
        from nightwing.agent.tools import get_all_tools

        tools = get_all_tools()
        tool_names = {t.name for t in tools}

        expected = {
            "run_modbus_scan",
            "run_s7_scan",
            "run_dnp3_scan",
            "run_ethernet_ip_scan",
            "run_bacnet_scan",
            "run_ics_fuzzer",
        }

        missing = expected - tool_names
        assert not missing, f"ICS tools not registered: {missing}"
