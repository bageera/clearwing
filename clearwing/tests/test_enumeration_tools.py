"""Unit tests for Phase 4 enumeration tools (API + Database)."""

import pytest
from unittest.mock import MagicMock, patch

from clearwing.agent.tools.scan.enumeration_tools import (
    run_arjun,
    run_dalfox,
    run_enum4linux,
    run_ffuf,
    run_gobuster,
    run_hydra,
    run_httpx,
    run_jwt_tool,
    run_nikto,
    run_nmap_scan,
    run_nosqlmap,
    run_oscanner,
    run_snmpwalk,
    run_sqlmap,
    run_sqlmate,
    run_sqlninja,
    run_sqlsus,
    run_whatweb,
)


class TestPhase4APITools:
    """Unit tests for API pentesting tools (ffuf, httpx, jwt_tool, arjun, dalfox)."""

    @pytest.fixture
    def mock_container(self):
        """Return a mocked container manager that captures executed commands."""
        with patch(
            "clearwing.agent.tools.scan.enumeration_tools.KALI"
        ) as mock_kali, patch(
            "clearwing.agent.tools.scan.enumeration_tools.PARROT"
        ) as mock_parrot:
            mgr = MagicMock()
            mgr.setup.return_value = {"container_id": "test-cid"}
            mgr.execute.return_value = {
                "exit_code": 0,
                "output": "mocked output",
                "error": "",
            }
            mock_kali.return_value = mgr
            mock_parrot.return_value = mgr
            yield mgr

    # ── ffuf ──────────────────────────────────────────────────────────
    def test_ffuf_basic_get(self, mock_container):
        result = run_ffuf("https://api.example.com/FUZZ")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "ffuf" in cmd
        assert "https://api.example.com/FUZZ" in cmd
        assert "-w /usr/share/wordlists/dirb/common.txt" in cmd
        assert "-mc all -fc 404" in cmd

    def test_ffuf_post_with_data(self, mock_container):
        result = run_ffuf(
            "https://api.example.com/auth",
            method="POST",
            post_data='{"username":"FUZZ","password":"test"}',
            headers="Authorization: Bearer token;Content-Type: application/json",
        )
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "-X POST" in cmd
        assert "-d" in cmd
        assert "-H" in cmd

    def test_ffuf_extensions(self, mock_container):
        result = run_ffuf(
            "https://api.example.com/FUZZ",
            extensions="json,php,bak,txt",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "-e json,php,bak,txt" in cmd

    def test_ffuf_uses_parrot(self, mock_container):
        run_ffuf("https://api.example.com/FUZZ", distro="parrot")
        # Should still work (mocked)
        assert mock_container.execute.called

    # ── httpx ───────────────────────────────────────────────────────────
    def test_httpx_basic(self, mock_container):
        result = run_httpx("https://api.example.com")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "httpx" in cmd
        assert "-status-code -title -tech-detect -json" in cmd

    def test_httpx_custom_options(self, mock_container):
        result = run_httpx(
            "https://api.example.com",
            options="-status-code -web-server -ip -cdn",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "-web-server" in cmd

    # ── jwt_tool ──────────────────────────────────────────────────────
    def test_jwt_tool_basic(self, mock_container):
        result = run_jwt_tool("eyJhbGciOiJIUzI1NiIs...")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "jwt_tool.py" in cmd
        assert "eyJhbGciOiJIUzI1NiIs..." in cmd
        assert "-t" in cmd

    def test_jwt_tool_custom_options(self, mock_container):
        result = run_jwt_tool(
            "eyJhbGciOiJIUzI1NiIs...",
            options="-C /usr/share/wordlists/rockyou.txt",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "-C" in cmd

    # ── arjun ───────────────────────────────────────────────────────────
    def test_arjun_get(self, mock_container):
        result = run_arjun("https://api.example.com/search")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "arjun" in cmd
        assert "-u 'https://api.example.com/search'" in cmd
        assert "-m GET" in cmd

    def test_arjun_post(self, mock_container):
        result = run_arjun(
            "https://api.example.com/search",
            method="POST",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "-m POST" in cmd

    # ── dalfox ──────────────────────────────────────────────────────────
    def test_dalfox_basic(self, mock_container):
        result = run_dalfox("https://example.com?q=test")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "dalfox" in cmd
        assert "url 'https://example.com?q=test'" in cmd
        assert "--silence" in cmd

    def test_dalfox_custom_options(self, mock_container):
        result = run_dalfox(
            "https://example.com?q=test",
            options="--mining-dom --follow-redirects",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "--mining-dom" in cmd


class TestPhase4DatabaseTools:
    """Unit tests for database pentesting tools (nosqlmap, oscanner, sqlninja, sqlsus, sqlmate)."""

    @pytest.fixture
    def mock_container(self):
        with patch(
            "clearwing.agent.tools.scan.enumeration_tools.KALI"
        ) as mock_kali, patch(
            "clearwing.agent.tools.scan.enumeration_tools.PARROT"
        ) as mock_parrot:
            mgr = MagicMock()
            mgr.setup.return_value = {"container_id": "test-cid"}
            mgr.execute.return_value = {
                "exit_code": 0,
                "output": "mocked output",
                "error": "",
            }
            mock_kali.return_value = mgr
            mock_parrot.return_value = mgr
            yield mgr

    # ── nosqlmap ──────────────────────────────────────────────────────
    def test_nosqlmap_basic(self, mock_container):
        result = run_nosqlmap("http://target.com/api/user")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "nosqlmap.py" in cmd
        assert "http://target.com/api/user" in cmd

    def test_nosqlmap_options(self, mock_container):
        result = run_nosqlmap(
            "http://target.com/api/user",
            options="--attack --dbs",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "--attack" in cmd

    # ── oscanner ──────────────────────────────────────────────────────
    def test_oscanner_basic(self, mock_container):
        result = run_oscanner("10.0.0.1")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "oscanner" in cmd
        assert "-s" in cmd
        assert "10.0.0.1" in cmd

    def test_oscanner_custom_options(self, mock_container):
        result = run_oscanner("10.0.0.1", options="-P 1521")
        cmd = mock_container.execute.call_args[0][1]
        assert "-P 1521" in cmd

    # ── sqlninja ──────────────────────────────────────────────────────
    def test_sqlninja_basic(self, mock_container):
        result = run_sqlninja("http://target.com/search?id=1")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "sqlninja" in cmd
        assert "-m test" in cmd
        assert "-u 'http://target.com/search?id=1'" in cmd

    def test_sqlninja_exploit_mode(self, mock_container):
        result = run_sqlninja(
            "http://target.com/search?id=1",
            options="-m fingerprint",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "-m fingerprint" in cmd

    # ── sqlsus ────────────────────────────────────────────────────────
    def test_sqlsus_basic(self, mock_container):
        result = run_sqlsus("http://target.com/login")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "sqlsus" in cmd
        assert "--guess" in cmd
        assert "http://target.com/login" in cmd

    def test_sqlsus_custom_options(self, mock_container):
        result = run_sqlsus(
            "http://target.com/login",
            options="--interactive",
        )
        cmd = mock_container.execute.call_args[0][1]
        assert "--interactive" in cmd

    # ── sqlmate ─────────────────────────────────────────────────────────
    def test_sqlmate_basic(self, mock_container):
        result = run_sqlmate("http://target.com/page?id=1")
        assert result["exit_code"] == 0
        cmd = mock_container.execute.call_args[0][1]
        assert "sqlmate" in cmd
        assert "--batch" in cmd
        assert "-u 'http://target.com/page?id=1'" in cmd

    def test_sqlmate_custom_options(self, mock_container):
        result = run_sqlmate(
            "http://target.com/page?id=1",
            options="--level 3 --risk 2",
        )
        cmd = mock_container.execute.call_args[0][1]
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
            "clearwing.agent.tools.scan.enumeration_tools.KALI"
        ) as mock_kali:
            mgr = MagicMock()
            mgr.setup.return_value = {"container_id": "cid"}
            mgr.execute.return_value = {
                "exit_code": 0,
                "output": "",
                "error": "",
            }
            mock_kali.return_value = mgr
            result = tool("http://example.com")
            assert isinstance(result, dict)
            assert "exit_code" in result
            assert "output" in result
            assert "error" in result

    @pytest.mark.parametrize("tool", tools)
    def test_tool_requires_approval_false(self, tool):
        from clearwing.agent.tooling import _get_tool_metadata
        meta = _get_tool_metadata(tool)
        assert meta.requires_approval is False


class TestAllToolsRegistered:
    """Verify all Phase 4 tools are importable from the package registry."""

    def test_tools_in_get_all_tools(self):
        from clearwing.agent.tools import get_all_tools
        tools = get_all_tools()
        tool_names = {t.__name__ for t in tools}

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
