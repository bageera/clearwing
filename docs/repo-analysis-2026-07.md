# Nightwing Repo Analysis & Improvement Plan

**Date:** July 7, 2026
**Scope:** Full repo audit + wireless scanning expansion plan

---

## 1. Repo Overview

| Metric | Value |
|--------|-------|
| Source files | 287 Python modules |
| Source LOC | ~64,500 |
| Test files | 116 test modules |
| Test LOC | ~33,600 |
| Test/source ratio | ~0.52 (decent, but skewed by sourcehunt-heavy coverage) |
| Docs | 20 markdown files under `docs/` |
| CI | GitHub Actions — ruff + mypy scoped gate + pytest --cov + pip-audit + build |
| Python support | 3.10–3.14 (matrix in CI) |
| Architecture | Dual-mode: network-pentest agent (255 tools) + source-code hunter pipeline |

---

## 2. Code Quality Findings

### 2.1 Strengths

1. **Well-structured tool registry** — `agent/tools/__init__.py` uses lazy imports with try/except for optional tools (browser, proxy, crypto), preventing import failures from cascading. The `@tool` decorator + `AgentTool` dataclass is clean and consistent.

2. **Container infrastructure** — `PentestContainerManager` (dual-distro Kali/Parrot) is well-factored with a shared `run_in_pentest_container()` convenience wrapper. Distinct from `SandboxContainer` (sourcehunt isolation) with appropriate separation of concerns.

3. **CI gate is real** — ruff + mypy scoped gate + pytest --cov + pip-audit + build/twine. Coverage floor at 65%. Matrix across 5 Python versions.

4. **Typing discipline** — Scoped mypy gate with `disallow_untyped_defs` on core modules. `py.typed` shipped. Per-file complexity overrides documented with rationale.

5. **Test coverage for tool registration** — `test_enumeration_tools.py` has registration tests (`TestAllToolsRegistered`, `TestCloudToolsRegistered`, etc.) that verify tools appear in `get_all_tools()`. Good pattern.

### 2.2 Issues to Fix

#### ISSUE 1: Only 1 test file under `nightwing/tests/` — the rest are under top-level `tests/`

`nightwing/tests/test_enumeration_tools.py` is inside the package (ships in the wheel via `package-data`). The other 115 test files are under top-level `tests/`. This is a packaging hazard — the in-package test file will be installed into user environments.

**Fix:** Move `nightwing/tests/test_enumeration_tools.py` to `tests/test_enumeration_tools.py` (the canonical location). Remove `nightwing/tests/` from the package. Update any imports.

#### ISSUE 2: `PentestContainerManager.execute()` returns inconsistent dict shapes

`execute()` returns `{"exit_code": ..., "output": ...}` (no `"error"` key), but test fixtures and tool docstrings expect `{"exit_code", "output", "error"}`. The `run_in_pentest_container` wrapper inherits this. All container tool tests mock `KALI.execute` returning 3-key dicts, but the real implementation only returns 2 keys. Tools that check `result["error"]` will KeyError at runtime.

**Fix:** Add `"error": ""` to the return dict in `PentestContainerManager.execute()` and `PentestContainerManager.install()`.

#### ISSUE 3: `PentestContainerManager` has no `error` field and no timeout

`execute()` calls `container.exec_run(command, tty=True)` with no timeout. A hung tool (e.g., `airodump-ng` without the `timeout` wrapper) will block indefinitely. Some tools self-wrap with `timeout {duration}` (airodump, wifite, reaver, bully, bettercap, ubertooth), but others don't (aircrack-ng, netdiscover, masscan, arp-scan, frida, objection, mobsf, apktool, jadx, drozer, firmwalker, binwalk, all ICS tools, all OSINT tools).

**Fix:** Add a `timeout_seconds` parameter to `execute()` and shell-wrap with `timeout --kill-after=2 {timeout} {command}` when set. Default to 600s (10 min). This matches the `SandboxContainer` pattern.

#### ISSUE 4: No cleanup/teardown for pentest containers

`PentestContainerManager.setup()` creates/reuses containers but there's no automatic teardown. Containers persist across runs (by design — reuse), but there's no `nightwing` CLI command to clean them up. `KALI.cleanup()` and `PARROT.cleanup()` exist but aren't wired to any user-facing command.

**Fix:** Add a `nightwing containers cleanup` CLI command, or wire cleanup into `nightwing doctor`.

#### ISSUE 5: `network_wireless_mobile_tools.py` is a 687-line megafile

This single file contains 4 phases (11-15: Network Discovery, Wireless, Mobile, Bluetooth, IoT) with 19 tools. It should be split by phase for maintainability, matching how `ics_osint_hw_tools.py` is separate.

**Fix:** Split into:
- `network_discovery_tools.py` (Phase 11: netdiscover, masscan, arp-scan, traceroute)
- `wireless_tools.py` (Phase 12: aircrack, airodump, wifite, reaver, bully)
- `mobile_tools.py` (Phase 13: frida, objection, mobsf, apktool, jadx, drozer)
- `bluetooth_rf_tools.py` (Phase 14: bettercap, ubertooth)
- `iot_hardware_tools.py` (Phase 15: firmwalker, binwalk)

Keep backward-compatible re-exports from `network_wireless_mobile_tools.py` if needed, or update `__init__.py` imports.

#### ISSUE 6: No tests for wireless, mobile, bluetooth, IoT, ICS, OSINT, or CI/CD tools

`test_enumeration_tools.py` only tests Phase 4 tools (ffuf, httpx, jwt_tool, arjun, dalfox, nosqlmap, oscanner, sqlninja, sqlsus, sqlmate). It has registration tests for later phases but no command-construction tests. The wireless tools (aircrack, airodump, wifite, reaver, bully) have zero command-construction tests.

**Fix:** Add test classes for each tool category — at minimum, test that the command string is constructed correctly (like the Phase 4 tests do).

#### ISSUE 7: `PentestContainerManager.execute()` doesn't handle `docker` import errors gracefully

Every call to `execute()` does `import docker` inside the method. If Docker isn't installed, the user gets an opaque `ImportError` mid-execution. The `SandboxContainer` pattern uses a lazy `_get_client()` with a clear error message.

**Fix:** Add a `_get_client()` method to `PentestContainerManager` with a helpful error message mentioning `pip install docker` or system Docker installation.

#### ISSUE 8: macOS network_mode="bridge" breaks host-network tools

On macOS, `PentestContainerConfig` defaults to `network_mode="bridge"`. This means containerized nmap/airodump/netdiscover can't reach the host's LAN by default. The `SandboxContainer` correctly defaults to `"none"` (for isolation), but the pentest containers need host network access on Linux and `--network host` doesn't work on macOS Docker Desktop — you need `bridge` + port forwarding or the Docker Desktop networking workaround.

**Fix:** Document this limitation in `docs/architecture.md` and add a runtime warning in `setup()` when `platform.system() != "Linux"` and the tool requires host network access. Consider adding a `--network` override.

#### ISSUE 9: `requires_approval=True` is set at the `@tool` decorator level AND passed to `run_in_pentest_container()`

Several tools like `run_aircrack_ng` set `@tool(requires_approval=True)` and then also pass `requires_approval=True` to `run_in_pentest_container()`. The `@tool` decorator's `requires_approval` is not actually used by `AgentTool` (it's captured but `AgentTool.__call__` doesn't check it). Only the `run_in_pentest_container(requires_approval=True)` call actually triggers the `interrupt()` gate. The decorator-level flag is misleading.

**Fix:** Either wire `AgentTool.requires_approval` into the call path, or remove it from the decorator and rely solely on the `run_in_pentest_container` parameter. Document the convention.

#### ISSUE 10: No `AGENTS.md` or `CLAUDE.md` in the repo

There's no agent-guidance file. `CONTRIBUTING.md` exists but doesn't cover the tool-adding workflow in enough detail for an AI agent to follow the repo conventions.

**Fix:** Add an `AGENTS.md` with: tool pattern (decorator + pentest_container + registration), test pattern (mock KALI/PARROT, assert command string), CI gate requirements, and the split-file convention.

---

## 3. Architecture Observations

### Tool Pipeline

All 255 tools follow one of two patterns:

**Pattern A — Native Python tools** (scanner_tools.py, crypto, recon):
```python
@tool
async def scan_ports(target: str, ...) -> list[dict]:
    scanner = scanning.PortScanner()
    return await scanner.scan(...)
```

**Pattern B — Container tools** (enumeration, wireless, cloud, ICS, OSINT):
```python
@tool(requires_approval=True)
def run_nmap_scan(target: str, ..., distro: str = "kali") -> dict[str, Any]:
    cmd = f"nmap {options} {target}"
    return run_in_pentest_container(cmd, distro=distro, requires_approval=True)
```

Pattern B tools are thin wrappers — they build a command string and delegate to the container manager. This is the correct pattern for adding new wireless tools.

### Registration Flow

1. Define tool in `agent/tools/scan/<category>_tools.py`
2. Import in `agent/tools/__init__.py:get_all_tools()`
3. Add to the `tools` list
4. Update `EXPECTED_TOOL_COUNT` in `test_tool_registry.py` (if it exists)
5. Add registration test in `test_enumeration_tools.py`

---

## 4. Wireless, RF & NFC Scanning Expansion Plan

### Current State

Existing wireless/RF/hardware coverage is thin:

**Phase 12 (Wi-Fi) — 5 tools in `network_wireless_mobile_tools.py`:**

| Tool | Purpose | Self-wraps timeout? |
|------|---------|---------------------|
| `run_aircrack_ng` | WPA/WPA2-PSK handshake cracking (offline) | No |
| `run_airodump_ng` | AP + client discovery (monitor mode) | Yes |
| `run_wifite` | Automated WEP/WPA/WPS attacks | Yes |
| `run_reaver` | WPS PIN brute-force / Pixie Dust | Yes |
| `run_bully` | WPS PIN brute-force (faster alt) | Yes |

**Phase 14 (Bluetooth) — 2 tools in `network_wireless_mobile_tools.py`:**

| Tool | Purpose |
|------|---------|
| `run_bettercap_bluetooth` | BLE recon via bettercap |
| `run_ubertooth` | BT sniffing (requires Ubertooth hardware) |

**Phase 18 (Hardware/Side-Channel) — 2 tools in `ics_osint_hw_tools.py`:**

| Tool | Purpose |
|------|---------|
| `run_chipwhisperer` | Power analysis side-channel attacks |
| `run_jtag_enum` | JTAG/SWD interface enumeration |

**Missing entirely:** aircrack-ng suite (airmon/aireplay/airbase/airdecap), Kismet, SDR tools (HackRF/RTL-SDR), RFID/NFC tools, Zigbee, LoRaWAN, Sub-GHz, classic Bluetooth (non-BLE), and enterprise 802.1X attack tools.

---

### Proposed New Tools (31 tools across 7 sub-phases)

#### Phase 12a: Monitor Mode & Interface Management (5 tools)

The aircrack-ng suite is incomplete — we have airodump (discovery) and aircrack (cracking) but are missing the tools that connect them. These are the core workflow tools for any Wi-Fi assessment.

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_airmon_ng` | `airmon-ng` | Enable/disable monitor mode, kill interfering processes | Yes — USB Wi-Fi adapter |
| `run_airbase_ng` | `airbase-ng` | Create rogue AP / evil twin / captive portal | Yes — USB Wi-Fi adapter |
| `run_aireplay_ng` | `aireplay-ng` | Packet injection (deauth, fake auth, ARP replay) | Yes — injection-capable adapter |
| `run_airdecap_ng` | `airdecap-ng` | Decrypt WEP/WPA capture files offline | No — offline pcap processing |
| `run_wash` | `wash` | Detect WPS-enabled APs from a capture | Yes (live) / No (from pcap) |

#### Phase 12b: Wireless Reconnaissance (4 tools)

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_kismet` | `kismet` | Passive wireless scanner + IDS (no injection needed) | Yes — any Wi-Fi adapter |
| `run_airgraph_ng` | `airgraph-ng` | Visualize airodump-ng CSV data as relationship graphs | No — offline CSV processing |
| `run_wifite2` | `wifite --kill --pow --dict` | Wifite v2 with extended options (separate from existing `run_wifite`) | Yes — USB adapter |
| `run_bully_wps` | `bully` | Extended bully WPS options (run alongside existing `run_bully`) | Yes — USB adapter |

Wait — `run_bully` and `run_wifite` already exist. Instead of duplicating, add the missing recon tools only:

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_kismet` | `kismet` | Passive wireless scanner + IDS | Yes — Wi-Fi adapter |
| `run_airgraph_ng` | `airgraph-ng` | Visualize airodump-ng CSV data | No — offline |
| `run_horst` | `horst` | Fast 802.11 scanner for roaming analysis | Yes — Wi-Fi adapter |
| `run_wifite` | (already exists) | (keep, no change) | |

#### Phase 12c: Enterprise Wireless / 802.1X (3 tools)

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_eaphammer` | `eaphammer` | Evil twin + EAP credential harvesting (PEAP/EAP-TTLS) | Yes — USB adapter |
| `run_hostapd_wpe` | `hostapd-wpe` | Wireless Pwn Edition — rogue AP with EAP cred capture | Yes — USB adapter |
| `run_asleap` | `asleap` | Recover LEAP/MS-CHAPv2 passwords from captures | No — offline pcap |

#### Phase 14a: Bluetooth (Classic + BLE) (4 new tools, 2 existing moved)

Existing `run_bettercap_bluetooth` and `run_ubertooth` move to `bluetooth_rf_tools.py`. New:

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_bluez_scan` | `hcitool scan` / `bluetoothctl` | Classic Bluetooth device discovery (built-in BT works) | Yes — any BT adapter |
| `run_bluez_info` | `hcitool info` | Get detailed info about a BT device (class, features) | Yes — BT adapter |
| `run_btlejack` | `btlejack` | BLE link-layer jamming and hijacking | Yes — BLE adapter |
| `run_sniffle` | `sniffle` | BLE 5 sniffer with TI CC1352/CC26x2 hardware | Yes — CC1352/CC26x2 |

#### Phase 14b: RFID / NFC (5 tools) — NEW DOMAIN

No RFID/NFC tools exist. These cover low-frequency (125kHz), high-frequency (13.56MHz), and NFC:

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_proxmark3` | `pm3` | Proxmark3 — RFID tag read/write/sniff/clone (LF + HF) | Yes — Proxmark3 device |
| `run_mfoc` | `mfoc` | Mifare Classic Offline Cracking (nested attack) | Yes — NFC reader (ACR122) |
| `run_mfuk` | `mfuk` | Mifare Classic key recovery via known-key attack | Yes — NFC reader |
| `run_nfc_tool` | `nfc-list` / `nfc-mfclassic` | libnfc tools — list, read, write NFC tags | Yes — NFC reader |
| `run_rfidiot` | `rfidiot.py` | RFID IO Tools — multi-protocol RFID toolkit | Yes — Proxmark3 or ACR122 |

#### Phase 14c: SDR / Radio Frequency (6 tools) — NEW DOMAIN

No SDR tools exist. These cover HackRF, RTL-SDR, and general RF analysis:

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_hackrf_info` | `hackrf_info` | Check HackRF hardware presence and capabilities | Yes — HackRF One |
| `run_hackrf_sweep` | `hackrf_sweep` | Wideband spectrum sweep (find active frequencies) | Yes — HackRF One |
| `run_rtl_433` | `rtl_433` | 433MHz ISM band receiver (weather stations, thermometers, smart meters, keyfobs) | Yes — RTL-SDR |
| `run_rtl_power` | `rtl_power` | Spectrum power profiling over frequency range | Yes — RTL-SDR |
| `run_gqrx` | `gqrx` | Software-defined radio receiver GUI (FM, AM, SSB, etc.) | Yes — SDR |
| `run_inspectrum` | `inspectrum` | Offline RF signal analysis from .cf32 captures | No — offline analysis |

#### Phase 14d: IoT Radio Protocols (4 tools) — NEW DOMAIN

| Tool | Binary | Purpose | Hardware? |
|------|--------|---------|-----------|
| `run_killerbee` | `killerbee` | Zigbee (IEEE 802.15.4) scanning, sniffing, and injection | Yes — Zigbee adapter (ApiSpec) |
| `run_zbstumbler` | `zbstumbler` | Zigbee network discovery (like airodump for Zigbee) | Yes — Zigbee adapter |
| `run_lorawan_scanner` | `lorawan-scanner` | LoRaWAN gateway and node discovery | Yes — LoRa adapter |
| `run_subghz_scan` | `Universal Radio Hacker` / `rtl_433 -a` | Sub-GHz ISM band scanning (garage door remotes, weather sensors) | Yes — RTL-SDR |

---

### Summary: New Tool Count

| Sub-phase | Tools | New? |
|-----------|-------|------|
| 12a: Monitor mode | 5 | All new |
| 12b: Wireless recon | 3 | All new |
| 12c: Enterprise Wi-Fi | 3 | All new |
| 14a: Bluetooth (classic+BLE) | 4 | New (2 existing moved) |
| 14b: RFID / NFC | 5 | All new — new domain |
| 14c: SDR / RF | 6 | All new — new domain |
| 14d: IoT radio (Zigbee/LoRa) | 4 | All new — new domain |
| **Total new** | **30** | |

Combined with the 7 existing tools that move to the new files, the wireless/RF/NFC tool set grows from 7 to 37.

---

### Implementation Plan

#### Step 1: Fix `PentestContainerManager` (prerequisite)

Before adding any tools, fix the container manager so it returns consistent dict shapes and has timeout support:

1. Add `"error": ""` to `execute()` return dict
2. Add `timeout_seconds` parameter to `execute()`, shell-wrap with `timeout --kill-after=2 {timeout} {command}`
3. Add `_get_client()` with helpful ImportError message (pattern from `SandboxContainer`)
4. Add `cleanup_all()` classmethod for CLI cleanup command

Files: `nightwing/agent/tools/ops/pentest_container.py`

#### Step 2: Split `network_wireless_mobile_tools.py`

Split the 687-line file into phase-specific modules:

```
agent/tools/scan/
├── network_discovery_tools.py    # Phase 11 (netdiscover, masscan, arp-scan, traceroute)
├── wireless_tools.py             # Phase 12 (existing 5 + new 12a/12b/12c tools)
├── mobile_tools.py               # Phase 13 (frida, objection, mobsf, apktool, jadx, drozer)
├── bluetooth_rf_tools.py          # Phase 14 (existing bettercap/ubertooth + new 14a)
├── rfid_nfc_tools.py             # Phase 14b — NEW (proxmark3, mfoc, nfc-list, etc.)
├── sdr_tools.py                  # Phase 14c — NEW (hackrf, rtl-sdr, gqrx, inspectogram)
├── iot_radio_tools.py            # Phase 14d — NEW (killerbee, zbstumbler, lorawan)
├── iot_hardware_tools.py          # Phase 15 (firmwalker, binwalk)
```

Update `agent/tools/__init__.py` imports to reference the new files.
Delete `network_wireless_mobile_tools.py` after verifying no external imports break.

#### Step 3: Add Wi-Fi monitor mode tools (Phase 12a)

Create in `wireless_tools.py`:

```python
@tool(requires_approval=True)
def run_airmon_ng(
    interface: str,
    action: str = "start",  # "start" | "stop" | "check"
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Enable/disable monitor mode on a wireless interface.

    airmon-ng manages wireless interface modes and kills processes
    that interfere with monitor mode (NetworkManager, wpa_supplicant).

    Args:
        interface: Wireless interface (e.g. "wlan0").
        action: "start" to enable monitor mode, "stop" to disable,
            "check" to list interfering processes.
        options: Extra airmon-ng flags (e.g. "-e").
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires a monitor-mode-capable USB Wi-Fi adapter passed
    through to the container (e.g. --device /dev/bus/usb/...).
    """
    if action == "check":
        cmd = f"airmon-ng check {options}"
    else:
        cmd = f"airmon-ng {action} {interface} {options}"
    logger.info("[%s] airmon-ng: %s", distro, cmd)
    return run_in_pentest_container(
        cmd,
        container_id=container_id,
        distro=distro,
        requires_approval=True,
    )
```

Tools: `run_airmon_ng`, `run_airbase_ng`, `run_aireplay_ng`, `run_airdecap_ng`, `run_wash`

#### Step 4: Add wireless recon tools (Phase 12b)

`run_kismet` (needs `timeout {duration}`), `run_airgraph_ng` (offline), `run_horst` (needs `timeout`)

#### Step 5: Add enterprise wireless tools (Phase 12c)

`run_eaphammer`, `run_hostapd_wpe`, `run_asleap`

These require more complex command construction (cert paths, EAP profiles). Document prerequisites in docstrings.

#### Step 6: Add Bluetooth tools (Phase 14a)

Move existing `run_bettercap_bluetooth` and `run_ubertooth` to `bluetooth_rf_tools.py`. Add:

`run_bluez_scan`, `run_bluez_info`, `run_btlejack`, `run_sniffle`

#### Step 7: Add RFID/NFC tools (Phase 14b) — NEW FILE

Create `rfid_nfc_tools.py` with:

`run_proxmark3`, `run_mfoc`, `run_mfuk`, `run_nfc_tool`, `run_rfidiot`

Proxmark3 tools have a complex CLI (`pm3` interactive shell). Use `pm3 -c '{command}'` for non-interactive mode.

Example:
```python
@tool(requires_approval=True)
def run_proxmark3(
    command: str,  # e.g. "hf search", "lf search", "hf mf dump"
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Proxmark3 RFID tool — read/write/sniff/clone LF and HF tags.

    Args:
        command: Proxmark3 command (e.g. "hf search", "lf search",
            "hf mf dump", "lf hid clone").
        options: Extra pm3 flags.
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires Proxmark3 device passed through to the container.
    """
    cmd = f"pm3 -c '{command}' {options}"
    return run_in_pentest_container(cmd, distro=distro, requires_approval=True)
```

#### Step 8: Add SDR / RF tools (Phase 14c) — NEW FILE

Create `sdr_tools.py` with:

`run_hackrf_info`, `run_hackrf_sweep`, `run_rtl_433`, `run_rtl_power`, `run_gqrx`, `run_inspectrum`

```python
@tool(requires_approval=True)
def run_hackrf_sweep(
    freq_min: int = 1,  # MHz
    freq_max: int = 6000,  # MHz
    duration: int = 30,
    options: str = "",
    container_id: str | None = None,
    distro: str = "kali",
) -> dict[str, Any]:
    """Wideband spectrum sweep with HackRF.

    Scans a frequency range to find active signals. Outputs
    a waterfall plot of signal power vs frequency.

    Args:
        freq_min: Start frequency in MHz (default: 1).
        freq_max: End frequency in MHz (default: 6000).
        duration: Seconds to run the sweep.
        options: Extra hackrf_sweep flags (e.g. "-w 1000000" for 1MHz bins).
        container_id: Docker container ID; auto-discovers if None.
        distro: "kali" or "parrot".

    Returns:
        Dict with exit_code, output, and error.

    Hardware: Requires HackRF One passed through to the container.
    """
    cmd = f"timeout {duration} hackrf_sweep -f {freq_min}:{freq_max} {options}"
    return run_in_pentest_container(cmd, distro=distro, requires_approval=True)
```

#### Step 9: Add IoT radio tools (Phase 14d) — NEW FILE

Create `iot_radio_tools.py` with:

`run_killerbee`, `run_zbstumbler`, `run_lorawan_scanner`, `run_subghz_scan`

#### Step 10: Register all new tools

In `agent/tools/__init__.py:get_all_tools()`:

1. Add imports from the new split files (`wireless_tools`, `bluetooth_rf_tools`, `rfid_nfc_tools`, `sdr_tools`, `iot_radio_tools`)
2. Add each tool to the `tools` list
3. Remove old `network_wireless_mobile_tools` import block
4. Update tool count constant if applicable

#### Step 11: Add tests

Create test files following the `test_enumeration_tools.py` pattern:

- `tests/test_wireless_tools.py` — Phase 12a/12b/12c (8 new tools)
- `tests/test_bluetooth_tools.py` — Phase 14a (4 new + 2 moved)
- `tests/test_rfid_nfc_tools.py` — Phase 14b (5 new tools)
- `tests/test_sdr_tools.py` — Phase 14c (6 new tools)
- `tests/test_iot_radio_tools.py` — Phase 14d (4 new tools)

Each test file follows the mock-container pattern:

```python
@pytest.fixture
def mock_container():
    with (
        patch("nightwing.agent.tools.scan.wireless_tools.KALI") as mock_kali,
        patch("nightwing.agent.tools.scan.wireless_tools.PARROT") as mock_parrot,
    ):
        mock_kali.setup.return_value = {"container_id": "test-cid"}
        mock_kali.execute.return_value = {"exit_code": 0, "output": "", "error": ""}
        mock_parrot.setup.return_value = {"container_id": "test-cid"}
        mock_parrot.execute.return_value = {"exit_code": 0, "output": "", "error": ""}
        yield mock_kali, mock_parrot
```

Tests per tool:
1. Command construction — assert correct binary + args in `execute.call_args`
2. Distro switching — `distro="parrot"` routes to `PARROT`
3. Options passthrough — custom flags appear in command string

Plus a registration test verifying all new tools appear in `get_all_tools()`.

#### Step 12: Update README and docs

- `README.md` — expand Phase 12 section, add Phase 14 (Bluetooth/RF), Phase 14b (RFID/NFC), Phase 14c (SDR), Phase 14d (IoT Radio) sections with tool tables and examples
- `docs/architecture.md` — add wireless/RF/NFC scanning section
- `TODO.md` — track the expansion work items

#### Step 13: CI gate

Run `make lint type test` to verify:
- ruff check passes
- mypy scoped gate passes
- All tests pass including new tool tests
- Tool count updated if applicable

---

### Hardware Passthrough Reference

Docker containers need USB device passthrough for hardware-dependent tools. Document this in each tool's docstring and in the README:

| Hardware | Docker flag | Tools that need it |
|----------|-------------|-------------------|
| Wi-Fi adapter (monitor mode) | `--privileged` or `--device /dev/bus/usb/XXX/YYY` | airmon, airodump, aireplay, airbase, kismet, horst, wifite, reaver, bully, eaphammer, hostapd-wpe |
| HackRF One | `--device /dev/bus/usb/XXX/YYY` | hackrf_info, hackrf_sweep |
| RTL-SDR | `--device /dev/bus/usb/XXX/YYY` | rtl_433, rtl_power, gqrx, subghz_scan |
| Proxmark3 | `--device /dev/ttyACM0` (serial) | proxmark3, rfidiot |
| NFC reader (ACR122U) | `--device /dev/bus/usb/XXX/YYY` | mfoc, mfuk, nfc_tool |
| Ubertooth One | `--device /dev/bus/usb/XXX/YYY` | ubertooth |
| Zigbee adapter (ApiSpec) | `--device /dev/ttyUSB0` (serial) or USB | killerbee, zbstumbler |
| LoRa adapter | `--device /dev/ttyUSB0` | lorawan_scanner |
| TI CC1352/CC26x2 | `--device /dev/ttyACM0` | sniffle |
| No hardware (offline) | None | aircrack_ng, airdecap_ng, airgraph_ng, asleap, inspectrum |

Add a `hardware_required` note to each tool docstring. Consider a runtime check in the container that warns when expected devices aren't present.

---

### Estimated Effort

| Step | Time | Files touched |
|------|------|---------------|
| 1. Fix PentestContainerManager | 30 min | `pentest_container.py` |
| 2. Split megafile | 45 min | 8 new files, `__init__.py` |
| 3-5. Wi-Fi tools (11 new) | 60 min | `wireless_tools.py` |
| 6. Bluetooth tools (4 new) | 30 min | `bluetooth_rf_tools.py` |
| 7. RFID/NFC tools (5 new) | 40 min | `rfid_nfc_tools.py` |
| 8. SDR tools (6 new) | 40 min | `sdr_tools.py` |
| 9. IoT radio tools (4 new) | 30 min | `iot_radio_tools.py` |
| 10. Registration | 20 min | `__init__.py` |
| 11. Tests (5 test files) | 120 min | `tests/test_*.py` |
| 12. Docs | 45 min | `README.md`, `docs/architecture.md` |
| 13. CI gate + fixes | 30 min | various |
| **Total** | **~7.5 hours** | |

---

## 5. Priority-Ordered Improvement List

### Immediate (blocking correctness)

1. **Fix `execute()` return dict** — add `"error"` key (ISSUE 2)
2. **Move `nightwing/tests/test_enumeration_tools.py`** to `tests/` (ISSUE 1)
3. **Add timeout to `execute()`** (ISSUE 3)

### Short-term (quality of life)

4. **Split `network_wireless_mobile_tools.py`** (ISSUE 5)
5. **Add tests for wireless/mobile/ICS tools** (ISSUE 6)
6. **Fix `requires_approval` decorator vs parameter confusion** (ISSUE 9)
7. **Add `AGENTS.md`** with tool-adding workflow (ISSUE 10)

### Medium-term (robustness)

8. **Add Docker client error handling** to `PentestContainerManager` (ISSUE 7)
9. **Add container cleanup CLI command** (ISSUE 4)
10. **Document macOS network limitations** (ISSUE 8)

### Feature (wireless + RF + NFC expansion)

11. **Fix `PentestContainerManager`** (prerequisite for all tool additions)
12. **Split `network_wireless_mobile_tools.py`** into 8 phase-specific files
13. **Add 11 Wi-Fi tools** (Phase 12a/12b/12c: airmon/airbase/aireplay/airdecap/wash/kismet/airgraph/horst/eaphammer/hostapd-wpe/asleap)
14. **Add 4 Bluetooth tools** (Phase 14a: bluez_scan/bluez_info/btlejack/sniffle)
15. **Add 5 RFID/NFC tools** (Phase 14b: proxmark3/mfoc/mfuk/nfc_tool/rfidiot)
16. **Add 6 SDR/RF tools** (Phase 14c: hackrf_info/hackrf_sweep/rtl_433/rtl_power/gqrx/inspectrum)
17. **Add 4 IoT radio tools** (Phase 14d: killerbee/zbstumbler/lorawan_scanner/subghz_scan)
18. **Add hardware passthrough documentation** (Docker --device flags per hardware type)
19. **Add 5 test files** (one per new module, ~27 new test classes)