# Release notes

Release notes live at
<https://github.com/Lazarus-AI/nightwing/releases>. Notes are
auto-generated from merged-PR titles + labels via
[`.github/release.yml`](.github/release.yml) when each release is
cut.

The hand-curated pre-1.0 history has been archived to
[`docs/CHANGELOG-v1.0.md`](docs/CHANGELOG-v1.0.md). Per-PR
`CHANGELOG.md` bullets are no longer required — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the current PR checklist.

---

## Session: 2026-07-07 — Project Rename (Clearwing → Nightwing) + Wireless/RF/NFC Expansion

### Project Rename: Clearwing → Nightwing

The project has been forked from the original Clearwing and renamed to
**Nightwing** — continuing the butterfly-wing naming theme while nodding
to the caped crusader's breakaway identity. All references updated:

- Package directory `clearwing/` → `nightwing/`
- Entry point `clearwing.py` → `nightwing.py`
- CLI command `clearwing` → `nightwing`
- Environment variables `CLEARWING_*` → `NIGHTWING_*`
- Config directory `~/.clearwing/` → `~/.nightwing/`
- Container names `clearwing-kali` → `nightwing-kali`, `clearwing-parrot` → `nightwing-parrot`
- All internal imports, test paths, CI workflows, docs, Makefile targets updated
- 298 Python files + 70 config/doc files updated (368 total)

### Added: Wireless, RF & NFC Scanning Tools (30 new tools, 8 new modules)

Split the 687-line `network_wireless_mobile_tools.py` megafile into
8 phase-specific modules and added 30 new tools across 7 sub-phases:

**Phase 12a — Wi-Fi Monitor Mode (5 new):**
`run_airmon_ng`, `run_airbase_ng`, `run_aireplay_ng`, `run_airdecap_ng`, `run_wash`

**Phase 12b — Wireless Recon (3 new):**
`run_kismet`, `run_airgraph_ng`, `run_horst`

**Phase 12c — Enterprise 802.1X (3 new):**
`run_eaphammer`, `run_hostapd_wpe`, `run_asleap`

**Phase 14a — Bluetooth Classic + BLE (4 new):**
`run_bluez_scan`, `run_bluez_info`, `run_btlejack`, `run_sniffle`

**Phase 14b — RFID / NFC (5 new, new domain):**
`run_proxmark3`, `run_mfoc`, `run_mfuk`, `run_nfc_tool`, `run_rfidiot`

**Phase 14c — SDR / RF (6 new, new domain):**
`run_hackrf_info`, `run_hackrf_sweep`, `run_rtl_433`, `run_rtl_power`, `run_gqrx`, `run_inspectrum`

**Phase 14d — IoT Radio Protocols (4 new, new domain):**
`run_killerbee`, `run_zbstumbler`, `run_lorawan_scanner`, `run_subghz_scan`

New files: `wireless_tools.py`, `network_discovery_tools.py`, `mobile_tools.py`,
`bluetooth_rf_tools.py`, `rfid_nfc_tools.py`, `sdr_tools.py`, `iot_radio_tools.py`,
`iot_hardware_tools.py`. The old `network_wireless_mobile_tools.py` is kept as a
backward-compat re-export shim.

### Fixed: PentestContainerManager

- Added `"error": ""` key to all `execute()`/`install()`/`cleanup()` return dicts
  (was missing — tools checking `result["error"]` would KeyError at runtime)
- Added `timeout_seconds` parameter (default 600s) with `timeout --kill-after=2`
  shell wrapping to prevent indefinite hangs on non-self-wrapping tools
- Added `_get_client()` with cached Docker client and helpful ImportError message
- Added `cleanup_all()` function for CLI container cleanup
- Added try/except around `exec_run()` for graceful error handling

### Fixed: Test Infrastructure

- Moved `clearwing/tests/test_enumeration_tools.py` to `tests/` (was in-package,
  shipping in the wheel via `package-data`)
- Fixed mock fixture pattern: was patching `KALI`/`PARROT` directly (broken since
  enumeration_tools uses `run_in_pentest_container`), now patches the correct symbol
- Updated `EXPECTED_TOOL_COUNT` 255 → 285 in `test_tool_registry.py`

### Added: Tests

- `tests/test_wireless_tools.py` (27 tests)
- `tests/test_bluetooth_tools.py` (7 tests)
- `tests/test_rfid_nfc_tools.py` (9 tests)
- `tests/test_sdr_tools.py` (9 tests)
- `tests/test_iot_radio_tools.py` (7 tests)
- `tests/test_enumeration_tools.py` (53 tests, moved + fixed)
- Total: 112 new tests, all passing

### Added: Scripts

- `scripts/wireless_scan.py` — native macOS Wi-Fi + Bluetooth scanner using
  CoreWLAN + IOBluetooth frameworks for SOC 2 wireless assessment without
  requiring USB hardware

### Statistics

- Tool count: 255 → 285 (+30)
- Test count: 2535 → 2647 (+112)
- Source modules: 287 → 295 (+8)
- Pre-existing test failures: 11 (unchanged — CVE DB, webcrypto, auth_recorder, band_promotion, reveng)
- Lint: clean (ruff check + format)
- Zero regressions introduced

---

## Session: 2026-05-26 — Test Infrastructure Upgrades

### Summary
Added coverage measurement, parallel test execution, HTTP mocking, property-based
testing support, and updated CI/Makefile to use them.

### Added
- **Test tooling** (`pyproject.toml`)
  - `pytest-cov>=4.0.0` — coverage plugin
  - `pytest-xdist>=3.0.0` — parallel test execution (`-n auto`)
  - `pytest-httpx>=0.28.0` — HTTP mocking for API tool tests
  - `pytest-randomly>=3.12.0` — test order shuffling to catch order dependencies
  - `coverage>=7.0.0` — coverage measurement
  - `hypothesis>=6.0.0` — property-based testing
  - `dirty-equals>=0.7.0` — type-safe fixture comparisons
- **Coverage config** (`pyproject.toml` `[tool.coverage]`)
  - Branch coverage enabled, source=nightwing, omit test/venv paths
  - `fail_under = 50` threshold
  - HTML report to `htmlcov/`
- **Fixture imports** (`conftest.py`)
  - Imports all `tests.fixtures` for shared fixture availability
  - Added `pytest_collection_modifyitems` and `pytest_terminal_summary` hooks

### Changed
- **CI pipeline** (`.github/workflows/ci.yml`)
  - Added `coverage run` step after pytest
  - Added `coverage report --fail-under=50` step
- **Makefile**
  - Added `test-parallel` (`-n auto`)
  - Added `test-coverage` (`--cov=nightwing --cov-report=term-missing --cov-report=html`)
  - Added `coverage` (report + fail-under)
  - Added `coverage-html` (html generation)
  - Updated `clean` to remove `htmlcov/`
- **`tests/README.md`** — full rewrite with tooling docs, coverage/hypothesis instructions

---

## Session: 2026-05-18 — Repository Cleanup & OSINT Integration

### Summary
Codebase hygiene pass: removed stale artifacts, synced versions, wired
orphaned modules into the package, and registered 14 new tools in the
agent registry. Total bind-tools now **255** (up from 238).

### Added
- **CT Log Reconnaissance** (`agent/tools/scan/ct_log_tools.py`)
  - `query_crt_sh` — Query crt.sh for subdomains and certificate history
  - `query_certspotter` — Query CertSpotter for certificate transparency logs
- **GitHub Leak Reconnaissance** (`agent/tools/scan/github_leak_tools.py`)
  - `search_github_code` — Search GitHub code for leaked secrets/credentials
  - `search_github_commits` — Search GitHub commits for sensitive data
- **OSINT Domain Enumeration** (`agent/tools/scan/osint_recon_tools.py`)
  - `run_amass` — Active/passive subdomain enumeration
  - `run_subfinder` — Passive subdomain discovery
  - `run_recon_ng` — Multi-source OSINT framework
  - `run_assetfinder` — Asset discovery from multiple sources
  - `run_findomain` — Certificate transparency subdomain enumeration
  - `run_dnsx` — DNS toolkit for resolution and verification
  - `run_gau` — Gather URLs from Wayback/Common Crawl/URLScan
  - `run_waybackurls` — Fetch URLs from Wayback Machine
  - `run_gowitness` — Website screenshot and tech fingerprinting
- **Intelligence correlation** (`intel/correlation.py`)
  - `IntelCorrelator` class for cross-source OSINT correlation
  - Subdomain/IP, domain/URL, and infrastructure pattern correlation
- **Shodan native tools** (`native/shodan_tools.py`)
  - `query_shodan`, `get_host_info`, `get_shodan_facets`
- **OSINT workflow orchestration** (`workflows/osint_workflow.py`)
  - `run_complete_domain_recon`, `run_passive_subdomain_recon`, `aggregate_and_correlate_findings`
- **Output parsers** (`utils/output_parsers.py`)
  - Parsers for nmap XML, theHarvester XML, amass JSON, subfinder JSON,
    GitHub JSON, Wayback JSON, assetfinder output, findomain output,
    and HTML tech detection
- **Recon data store** (`data/database/recon_store.py`)
  - SQLite + JSONL persistence for reconnaissance results
  - `ReconResult` dataclass, aggregation, and reporting

### Changed
- `nightwing/__init__.py`: Version synced from `"0.1.0"` to `"1.0.0"` (matching `pyproject.toml`)
- `nightwing/agent/tools/__init__.py`: Registered all 14 new scan tools in `get_all_tools()`
- `.gitignore`: Added `results/figma/`, `scripts/figma/`, `figma_repos/` patterns
- Figma engagement scripts moved to `scripts/figma/`
- Figma scan results/databases moved to `results/figma/`
- ROE documents moved to `docs/`
- `figma_repos/` moved to `.reference/figma_repos/` (gitignored, 30MB)

### Removed
- `nightwing/venv/` — nested venv (top-level `venv/` is canonical)
- `nightwing/nightwing.egg-info/` — stale build artifact
- `nightwing/pyproject.toml` — duplicate of root-level file
- `nightwing/ruff.toml` — duplicate of root-level config

---

## Session: 2026-04-27 — Ollama Cloud + Dual Container Support

### Added
- **Ollama Cloud preset** (`nightwing/providers/catalog.py`)
  - New preset `ollama-cloud` for hosted models at `https://ollama.com`
  - Defaults: `deepseek-v4-flash`, requires `OLLAMA_API_KEY`
  - Alternative models: `qwen3-coder:480b`, `minimax-m2.7`, `kimi-k2.6`
- **Dual PentestContainer support** (`nightwing/agent/tools/ops/`)
  - New shared `PentestContainerManager` base class
  - Refactored Kali container (`kalilinux/kali-rolling`)
  - New ParrotOS container (`parrotsec/core:latest`, slim)
  - Both container types registered in tool graph, specialists, and state tracking
- **Parameterized integration tests** (`tests/test_pentest_container.py`)
  - Lifecycle tests for both Kali and ParrotOS (reused from alpine for speed)

### Changed
- `providers/manager.py`: Adapter resolution for ollama.com — now respects explicit `adapter: openai` or falls back to native `ollama`
- `providers/env.py`: Remove unused `pathlib.Path` import (F401 fix)
- `agent/state.py`: Added `parrot_container_id` alongside `kali_container_id`
- `agent/graph.py`: State updater and guardrails now track `parrot_setup` events
- `agent/prompts.py`: Context now surfaces both Kali and Parrot container IDs
- `agent/specialists/recon_agent.py` + `exploit_agent.py`: Import both Kali and Parrot tool sets
- `agent/tools/__init__.py`: `get_all_tools()` exports both Kali and Parrot operations

### Fixed
- Ollama Cloud 401 errors: `/v1` path was missing when using `adapter: openai`; config now uses `https://ollama.com/v1` + `adapter: openai` for OpenAI-compatible streaming
- `provider_name` resolution for `ollama-cloud` preset now routes correctly through `_adapter_for_provider_config`

### Known Issues
- ParrotOS `parrotsec/security:latest` (5.1 GB) is very large; using `parrotsec/core:latest` (~265 MB) may lack some pentest tools
- Windows-only tools (`mimikatz`, `PowerUp`, `WinPEAS`) still require Metasploit bridge or Windows host; no container solution yet on macOS/Linux
- `hashcat` GPU passthrough does not work on Docker Desktop for macOS

---

## Session: 2026-05-02 — Comprehensive Tool Expansion & Lazarus AI Re-Pentest

### Summary
This session implemented **87 new tools** across 6 major phases, bringing the total
from 101 to **188 bind-tools**. A full re-pentest of Lazarus AI infrastructure was
conducted as the validation exercise.

---

## Session: 2026-05-02b — Phase 11+ Network, Wireless, Mobile & IoT Tools

### Summary
Added **19 new tools** across 5 additional phases (11–15), bringing total to **207 bind-tools**.

### New Tool Suites

#### Phase 11: Network Discovery (4 tools)
- `run_netdiscover` — ARP-based host discovery
- `run_masscan` — Ultra-fast async TCP port scanning
- `run_arp_scan` — ARP scanning with vendor fingerprinting
- `run_traceroute` — Network path tracing (ICMP/UDP/TCP)

#### Phase 12: Wireless Pentesting (5 tools)
- `run_aircrack_ng` — WPA/WPA2-PSK handshake cracking
- `run_airodump_ng` — AP and client discovery (monitor mode)
- `run_wifite` — Automated WEP/WPA/WPS attacks
- `run_reaver` — WPS PIN brute-force
- `run_bully` — Modern WPS brute-force (faster alternative)

#### Phase 13: Mobile Pentesting (6 tools)
- `run_frida` — Dynamic instrumentation of Android/iOS apps
- `run_objection` — Runtime mobile exploration (SSL pinning bypass)
- `run_mobsf` — Mobile Security Framework static analysis
- `run_apktool` — APK decompilation to smali + resources
- `run_jadx` — APK decompilation to Java source
- `run_drozer` — Android security assessment framework

#### Phase 14: Bluetooth & RF (2 tools)
- `run_bettercap_bluetooth` — BLE reconnaissance
- `run_ubertooth` — Bluetooth sniffing (hardware required)

#### Phase 15: IoT & Hardware (2 tools)
- `run_firmwalker` — Firmware static analysis (secrets, backdoors)
- `run_binwalk` — Firmware extraction and binary analysis

### Key Changes
- `agent/tools/scan/network_wireless_mobile_tools.py`: New module with 19 tools
- `agent/tools/__init__.py`: Registered all 19 new tools in `get_all_tools()`
- `tests/test_enumeration_tools.py`: Added registration tests for Phases 11–15
- `README.md`: Updated tool count to 207, added usage examples for all 5 new phases

### Pentest Findings (Preview Environment)
- **CRITICAL:** `dashboard-preview.lazarusforms.com` has **empty CSP** (`content=""`) vs production CSP
- **CRITICAL:** Preview leaks `lazarus-forms-dashboard-prod-7owznqu3wq-uc.a.run.app` (prod Cloud Run) and `lazarus-apis-testing-default-rtdb.firebaseio.com` (testing RTDB)
- **CRITICAL:** Preview uses different Firebase project `lazarus-apis-testing` with unique API key `AIzaSyAnPYVXvxJ38szeKbws9pq1PppgIeT4cEo` — potential sandbox escape
- **INFO:** Preview `robots.txt` allows all crawlers (`Disallow:` empty)
- **INFO:** `vpn.ops.lzrops.com` (18.208.179.1) — all 100 top TCP ports filtered, host unresponsive to SYN

### Validation
- All new tools pass syntax check (`py_compile`)
- All 19 tools registered and importable
- 4 new test classes added (47 + 4 = 51 tests)

---

## Session: 2026-05-02c — Phase 16-18: ICS/SCADA, OSINT, and Hardware Pentesting

### Summary
Added **13 new tools** across Phase 16 (ICS/SCADA), Phase 17 (OSINT/Social Engineering), and Phase 18 (Hardware/Side-Channel), bringing total to **220 bind-tools**.

### New Tool Suites

#### Phase 16: ICS / SCADA Security (6 tools)
- `run_modbus_scan` — Modbus TCP/RTU device scanning and register reading
- `run_s7_scan` — Siemens S7 PLC scanning and enumeration
- `run_dnp3_scan` — DNP3 utility network scanning
- `run_ethernet_ip_scan` — EtherNet/IP (CIP) device discovery
- `run_bacnet_scan` — BACnet building automation scanning
- `run_ics_fuzzer` — ICS/SCADA protocol fuzzer (Modbus/S7/DNP3/ENIP/BACnet)

#### Phase 17: OSINT & Social Engineering (5 tools)
- `run_theharvester` — Email/subdomain OSINT enumeration via search engines
- `run_maltego` — Graph-based OSINT and link analysis
- `run_social_engineer_toolkit` — SET phishing and credential harvesting (approval required)
- `run_gophish` — Phishing campaign management (approval required)
- `run_osint_framework` — Multi-module OSINT aggregation (recon-ng)

#### Phase 18: Hardware / Side-Channel (2 tools)
- `run_chipwhisperer` — Power analysis side-channel attack (hardware required)
- `run_jtag_enum` — JTAG/SWD debugging interface enumeration

### Key Changes
- `agent/tools/scan/ics_osint_hw_tools.py`: New module with 13 tools
- `agent/tools/__init__.py`: Registered all 13 new tools in `get_all_tools()`
- `tests/test_enumeration_tools.py`: Added 3 new test classes (ICS, OSINT, HW)
- `README.md`: Updated tool count to 220, added usage examples for Phases 16-18

### Validation
- All 13 tools pass syntax check (`py_compile`)
- All 13 tools registered and importable
- 3 new test classes added (51 + 3 = 54 tests)

### New Tool Suites

#### Phase 4: API & Database Pentesting (10 tools)
- `run_ffuf`, `run_httpx`, `run_arjun`, `run_dalfox` — API discovery and parameter mining
- `run_jwt_tool` — JWT security testing and cracking
- `run_nosqlmap`, `run_oscanner`, `run_sqlninja`, `run_sqlsus`, `run_sqlmate` — Database pentesting

#### Phase 5: Red Team / Active Directory (3 tools)
- `run_chisel` — TCP/UDP tunnel for pivoting
- `run_crackmapexec` — Multi-protocol enumeration (SMB/WinRM/SSH/LDAP/MSSQL)
- `run_bloodhound` — AD attack path enumeration

#### Phase 6: Cloud Pentesting (11 tools)
**GCP Suite:** `run_gcp_bucket_enum`, `run_gcp_metadata_exploit`, `run_gcp_iam_audit`, `run_gcp_secrets_enum`, `run_gcp_cloudfunction_enum`
**AWS Suite:** `run_aws_s3_enum`, `run_aws_ec2_enum`, `run_aws_metadata_exploit`, `run_aws_secrets_enum`, `run_aws_lambda_enum`, `run_aws_iam_escalation`

#### Phase 7: LLM Security Testing (14 tools)
- Prompt injection, jailbreak, indirect injection, system prompt extraction
- Training data extraction, PII extraction, model consistency testing
- Toxicity regression, bias detection, agent escape, tool poisoning
- Multi-turn poisoning, token smuggling, adversarial vision

#### Phase 8: API Security Testing (8 tools)
- `run_graphqlmap`, `run_grpcurl`, `run_wsprobe` — GraphQL/gRPC/WebSocket testing
- `run_idor_scanner`, `run_race_condition_tester`, `run_swagger_abuse` — Business logic testing
- `run_2fa_bypass_tester`, `run_cors_misconfig_tester` — Authentication/CORS testing

#### Phase 9: CI/CD & Supply Chain Security (7 tools)
- `run_gitleaks`, `run_trufflehog` — Secret scanning
- `run_checkov`, `run_trivy`, `run_semgrep` — IaC/container/code scanning
- `run_dependency_audit` — Dependency confusion audit
- `run_kube_hunter` — Kubernetes cluster scanning

### Key Changes
- `agent/tools/__init__.py`: Registered all 87 new tools in `get_all_tools()`
- `agent/tools/scan/`: 5 new modules (`cloud_tools.py`, `llm_security_tools.py`, `api_testing_tools.py`, `cicd_tools.py`, `redteam_tools.py`)
- `tests/test_enumeration_tools.py`: Added registration tests for all new suites
- `README.md`: Updated tool count, added all 9 phases with descriptions
- `CHANGELOG.md`: Added session entry with full tool inventory

### Pentest Findings (Lazarus AI Re-Pentest)
- **CRITICAL-001:** Firebase API key leak (`AIzaSyBgs-...`) in production JS bundle
- **CRITICAL-002:** Backend infrastructure URLs leaked in client JS (Cloud Run, RTDB, chat subdomain)
- **CRITICAL-003:** `api.lazarusai.com/status` auth bypass — accepts ALL tokens/methods
- **CRITICAL-004:** Account enumeration via Firebase `createAuthUri`, `signInWithPassword`, `sendOobCode`
- **CRITICAL-005:** Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) + open CORS `*`
- **HIGH:** Self-service account deletion without re-auth; password change without current password; unlimited concurrent sessions
- **MEDIUM:** SPA fallback masking API paths; robots.txt allows all crawlers

### Validation
- All 47 unit tests pass
- All 188 tools registered and importable
- Report generated: `/tmp/lazarusai_repentest_report.html`
- Report stored only in `/tmp/` (never committed) per security policy

---

## Session: 2026-05-02 — Phase 11-18: Network, Wireless, Mobile, IoT, ICS, OSINT, Hardware

### Summary
Added **32 new tools** across Phases 11-18, expanding from 188 to 220 bind-tools.

### New Tool Suites

#### Phase 11: Network Discovery (4 tools)
- `run_netdiscover`, `run_masscan`, `run_arp_scan`, `run_traceroute`

#### Phase 12: Wireless Pentesting (5 tools)
- `run_aircrack_ng`, `run_airodump_ng`, `run_wifite`, `run_reaver`, `run_bully`

#### Phase 13: Mobile Pentesting (6 tools)
- `run_frida`, `run_objection`, `run_mobsf`, `run_apktool`, `run_jadx`, `run_drozer`

#### Phase 14: Bluetooth / RF (2 tools)
- `run_bettercap_bluetooth`, `run_ubertooth`

#### Phase 15: IoT / Hardware (2 tools)
- `run_firmwalker`, `run_binwalk`

#### Phase 16: ICS / SCADA (6 tools)
- `run_modbus_scan`, `run_s7_scan`, `run_dnp3_scan`, `run_ethernet_ip_scan`, `run_bacnet_scan`, `run_ics_fuzzer`

#### Phase 17: OSINT / Social Engineering (5 tools)
- `run_theharvester`, `run_maltego`, `run_social_engineer_toolkit`, `run_gophish`, `run_osint_framework`

#### Phase 18: Hardware / Side-Channel (2 tools)
- `run_chipwhisperer`, `run_jtag_enum`

### Key Changes
- `agent/tools/scan/network_wireless_mobile_tools.py`: NEW (19 tools)
- `agent/tools/scan/ics_osint_hw_tools.py`: NEW (13 tools)
- `agent/tools/__init__.py`: Registered all 32 tools
- `tests/test_enumeration_tools.py`: Added 7 new test classes
- `README.md`: Updated to 220 tools, added Phases 11-18 examples

---

## Session: 2026-05-03 — Phase 19: Android Mobile Pentesting + Master LOA

### Summary
Added **18 new Android-specific tools**, expanding from 220 to **238 bind-tools**. Created Master Letter of Authorization consolidating ROE Amendments 01-05.

### New Tool Suite: Android Pentesting (18 tools)

**Static Analysis:**
- `run_apk_info`, `run_apk_permissions`, `run_apk_components`, `run_apk_strings`, `run_apk_patch`, `run_apk_repack`

**Dynamic Analysis:**
- `run_frida_hook`, `run_objection_explore`, `run_frida_traffic_capture`

**Network Interception:**
- `run_burp_mobile_proxy`, `run_mitmproxy_android`

**Security Bypass:**
- `run_ssl_pinning_bypass` (Frida/objection/patch/Magisk), `run_root_detection_bypass` (4 methods)

**ADB / Emulator:**
- `run_adb_shell`, `run_android_emulator`

**Forensics:**
- `run_android_backup_extract`, `run_android_screenshot`, `run_safetynet_check`

### Key Changes
- `agent/tools/scan/android_tools.py`: NEW (722 lines, 18 tools)
- `agent/tools/__init__.py`: Registered all 18 Android tools
- `tests/test_enumeration_tools.py`: Added 4 Android test classes
- `README.md`: Updated to 238 tools, added Phase 19 with full usage examples
- `LETTER_OF_AUTHORIZATION_LAZARUS_AI_MASTER.md`: NEW — Master LOA consolidating Amendments 01-05

### Pentest Findings (Authorized Under Master LOA)
- **OPS-001 (CRITICAL):** Shared EC2 instance — `litellm.ml.ops.lzrops.com` and `riky-vibe.ops.lzrops.com` both resolve to `3.21.238.165`
- **RDE-004 (MEDIUM):** Rundeck API error messages leak first 5 characters of submitted tokens
- **POS-008:** Cross-project JWT isolation confirmed — prod JWT rejected by preview RTDB (401)
- **POS-009:** `secops@lazarus.enterprises` has separate localIds across prod/preview Firebase (confirmed separate DBs)
- **ML-001:** All `*.ml.lzrops.com` hosts NXDOMAIN externally; `litellm.ml.ops.lzrops.com` found via DNS only, returns 403 to all external IPs

### Reports
- All reports stored exclusively in `/tmp/` per security policy:
  - `/tmp/roe_v3_final_consolidated_report_2026-05-02.html`
  - `/tmp/ops_infrastructure_map.md`
  - `/tmp/nightwing_tool_matrix.md`
  - `/tmp/detailed_findings.html`
  - `/tmp/executive_summary.html`
- **NOT committed to repository**
