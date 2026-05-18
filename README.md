# Clearwing

<img width="400" alt="image" src="https://github.com/user-attachments/assets/c0444f24-32d8-4d62-af66-f1b7d8a123ba" />

By Eric Hartford, Lazarus AI

Inspired by Anthropic's Glasswing.  

The challenge:  Produce similar results as Glasswing - using models everyone has access to.

**Autonomous vulnerability scanner and source-code hunter.** Built on
`genai-pyo3`, a native Rust-backed LLM runtime speaking every major
provider (Anthropic, OpenAI, OpenRouter, Ollama, LM Studio, Together,
Groq, DeepSeek, MiniMax, Gemini, any OpenAI-compatible endpoint).

Clearwing is a dual-mode offensive-security tool:

- **Network-pentest agent** — a ReAct-loop agent with 255 bind-tools
  that scans live targets, detects services and vulnerabilities,
  runs sandboxed Kali/Parrot PentestContainer tools, attempts exploits
  (gated through a human-approval guardrail), and writes reports to
  a persistent knowledge graph.
- **Source-code hunter** — a file-parallel agent-driven
  pipeline that ranks source files, fans out per-file hunter agents
  (full-shell or constrained), uses ASan/UBSan crashes as ground
  truth, verifies findings with a 4-axis validator (REAL /
  TRIGGERABLE / IMPACTFUL / GENERAL), runs PoC stability checks
  across fresh containers, optionally generates validated patches,
  and emits SARIF/markdown/JSON reports with explicit evidence levels
  (`suspicion → static_corroboration → crash_reproduced →
  root_cause_explained → exploit_demonstrated → patch_validated`).
  Features three-band budget promotion, entry-point sharding for
  large files, cross-subsystem hunting, a shared findings pool with
  root-cause deduplication, multi-turn agentic exploit development,
  and human-in-the-loop exploit elaboration.
- **N-day exploit pipeline** — given CVE IDs, builds the
  vulnerable version, develops working exploits, and validates
  against the patched version to confirm the fix.
- **Reverse engineering pipeline** — decompiles closed-source
  ELF binaries via Ghidra, reconstructs plausible source with an
  LLM, then hunts vulnerabilities using a hybrid source + binary
  validation approach.
- **Campaign orchestration** — runs sourcehunt across dozens or
  hundreds of repositories from a single YAML config with shared
  budget, checkpoint/resume, and aggregate reporting.
- **Responsible disclosure** — human-in-the-loop validation
  workflow with MITRE/HackerOne template generation, SHA-3
  cryptographic commitments for provable priority, timeline
  tracking, and batched disclosure.
- **Benchmarking & evaluation** — OSS-Fuzz crash severity
  ladder for model comparison, and an A/B testing framework for
  measuring whether preprocessing helps or hurts finding quality.

**Authorized use only.** Clearwing is a dual-use offensive-security
tool. Run it only against targets you own or have explicit written
authorization to test. Operators are responsible for scope, legal
authorization, and disclosure. See `SECURITY.md`.

## Install

**End users** — install the tagged release straight from GitHub:

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing

# uv sync is recommended because Clearwing pins genai-pyo3 through
# tool.uv.sources in pyproject.toml.
uv sync --all-extras
source .venv/bin/activate  # fish: source .venv/bin/activate.fish

# Interactive setup wizard — menu-driven provider selection,
# credential entry, optional live test, persists to ~/.clearwing/config.yaml
clearwing setup

# Environment check — verifies Python, credentials, Docker daemon,
# external tools, optional extras, and network reachability
clearwing doctor

clearwing --version   # 1.0.0
clearwing --help
```

Or skip the wizard and configure directly:

```bash
# Anthropic direct
export ANTHROPIC_API_KEY=sk-ant-...

# Or any OpenAI-compatible endpoint — OpenRouter, Ollama, LM Studio,
# vLLM, Together, Groq, DeepSeek, OpenAI:
export CLEARWING_BASE_URL=https://openrouter.ai/api/v1
export CLEARWING_API_KEY=sk-or-...
export CLEARWING_MODEL=anthropic/claude-opus-4
```

See [`docs/providers.md`](docs/providers.md) for provider-specific
recipes and per-task routing.

**Developers** — clone and install the locked development environment:

```bash
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing
uv sync --all-extras
source .venv/bin/activate  # fish: source .venv/bin/activate.fish
clearwing --help
```

Requirements: Python 3.10+ and optionally Docker for the Kali container
and sanitizer-image sandbox features. `genai-pyo3` ships as prebuilt
wheels on PyPI (linux x86_64/aarch64, macOS universal2, windows x86_64,
Python 3.9–3.13), so no Rust toolchain is needed for installation.

## PentestContainer Architecture

Clearwing now ships with **dual-distro container support** for standardized penetration testing workflows. A shared `PentestContainerManager` orchestrates both Kali Linux (full-featured) and ParrotOS (slim) containers, executing external CLI tools without polluting the host operating system.

### Supported Containers

| Distro | Image | Size | Status |
|--------|-------|------|--------|
| Kali Linux | `kalilinux/kali-rolling` | ~2.5 GB | Production-ready |
| ParrotOS (slim) | `parrotsec/core:latest` | ~265 MB | Development/testing |

### Tool Categories

**Phase 2: Linux/POSIX Enumeration** (`agent/tools/scan/enumeration_tools.py`)
- `run_nmap_scan` — TCP/UDP port scanning (SYN, connect, NSE scripts)
- `run_gobuster` — Directory/file brute-forcing
- `run_sqlmap` — Automated SQL injection detection
- `run_enum4linux` — SMB enumeration
- `run_nikto` — Web vulnerability scanning
- `run_hydra` — Multi-protocol brute-force
- `run_snmpwalk` — SNMP enumeration
- `run_whatweb` — Web technology fingerprinting

**Phase 3: Windows Exploitation** (`agent/tools/ops/windows_tools.py`)
- `run_mimikatz` — LSASS credential dumping via impacket-psexec
- `run_powerup` — Privilege escalation enumeration with PowerUp.ps1
- `run_winpeas` — Comprehensive Windows security audit with WinPEAS
- `run_secretsdump` — SAM/NTDS hash extraction via impacket-secretsdump
- `run_psexec` — Remote command execution via impacket-psexec
- `run_smbexec` — Remote command execution via impacket-smbexec

**Phase 4: API & Database Pentesting** (`agent/tools/scan/enumeration_tools.py`)
- `run_ffuf` — Fast web fuzzer for directories, parameters, and virtual hosts
- `run_httpx` — Fast multi-purpose HTTP toolkit for probing and fingerprinting
- `run_arjun` — HTTP parameter discovery suite
- `run_dalfox` — Reflected and DOM XSS scanning and parameter mining
- `run_jwt_tool` — JSON Web Token (JWT) security testing and cracking
- `run_nosqlmap` — NoSQL injection and MongoDB enumeration
- `run_oscanner` — Oracle database SID and password brute-forcing
- `run_sqlninja` — Microsoft SQL Server injection and privilege escalation
- `run_sqlsus` — MySQL injection with stacked queries
- `run_sqlmate` — Automated SQL injection detection with batch and blind support

**Phase 5: Red Team / Active Directory** (`agent/tools/scan/redteam_tools.py`)
- `run_chisel` — TCP/UDP tunnel over HTTP for pivoting
- `run_crackmapexec` — SMB/WinRM/SSH/LDAP/MSSQL enumeration and credential testing
- `run_bloodhound` — Active Directory attack path enumeration and graph analysis

**Phase 6: Cloud Pentesting** (`agent/tools/scan/cloud_tools.py`)

*GCP Suite:*
- `run_gcp_bucket_enum` — GCS bucket discovery and misconfiguration scanning
- `run_gcp_metadata_exploit` — Service account token theft from metadata endpoint
- `run_gcp_iam_audit` — IAM policy and service account enumeration
- `run_gcp_secrets_enum` — Secret Manager / Cloud KMS secret discovery
- `run_gcp_cloudfunction_enum` — Cloud Functions, triggers, and env var enumeration

*AWS Suite:*
- `run_aws_s3_enum` — S3 bucket discovery and ACL testing
- `run_aws_ec2_enum` — EC2 instances, security groups, and IAM role enumeration
- `run_aws_metadata_exploit` — IMDSv1/v2 token and credential theft
- `run_aws_secrets_enum` — Secrets Manager / Parameter Store enumeration
- `run_aws_lambda_enum` — Lambda functions, layers, and IAM execution roles
- `run_aws_iam_escalation` — IAM privilege escalation path analysis

All tools support dual-distro execution (`distro="kali"` or `distro="parrot"`) and share the same container lifecycle (setup → execute → cleanup).

---

**Phase 7: LLM Security Testing** (`agent/tools/scan/llm_security_tools.py`)
- `run_prompt_injection_scanner` — Automated prompt-injection payload scanner
- `run_jailbreak_tester` — Multi-turn jailbreak orchestration (Crescendo, DAN, many-shot)
- `run_indirect_prompt_injection` — RAG / document-processing indirect prompt injection
- `run_system_prompt_extraction` — Hidden system prompt extraction via encoding tricks
- `run_training_data_extraction` — Membership-inference / training-data extraction
- `run_pii_extraction_tester` — PII extraction via persona-based prompting
- `run_model_consistency_tester` — Non-determinism and hallucination detection
- `run_toxicity_regression_tester` — Automated red-teaming for harmful outputs
- `run_bias_detector` — Demographic stereotype and bias testing
- `run_agent_escape_tester` — LLM agent sandbox escape testing
- `run_tool_poisoning_tester` — Malicious tool-description injection
- `run_multi_turn_poisoning` — Gradual context-window poisoning
- `run_token_smuggling_tester` — Content-filter bypass via encoding obfuscation
- `run_adversarial_vision_tester` — Adversarial image perturbation for vision-language models

**Phase 8: API Security Testing** (`agent/tools/scan/api_testing_tools.py`)
- `run_graphqlmap` — GraphQL introspection abuse and field suggestion
- `run_grpcurl` — gRPC / Protobuf service enumeration and method fuzzing
- `run_wsprobe` — WebSocket message injection and frame manipulation
- `run_idor_scanner` — Automated IDOR and privilege escalation detection
- `run_race_condition_tester` — Turbo Intruder-style race condition exploitation
- `run_swagger_abuse` — OpenAPI mass assignment and parameter pollution
- `run_2fa_bypass_tester` — OTP brute-force and TOTP reuse testing
- `run_cors_misconfig_tester` — Automated CORS bypass exploitation

**Phase 9: CI/CD & Supply Chain Security** (`agent/tools/scan/cicd_tools.py`)
- `run_gitleaks` — Git repository secret scanning
- `run_trufflehog` — High-entropy secret scanning with live validation
- `run_checkov` — Infrastructure-as-Code misconfiguration scanning
- `run_trivy` — Container image and filesystem vulnerability scanning
- `run_semgrep` — Static analysis rule-based security scanning
- `run_dependency_audit` — Dependency confusion and known-CVE audit
- `run_kube_hunter` — Kubernetes cluster security scanning

**Phase 10: Proxy-Based Web/API Scanning** (`agent/tools/scan/proxy_tools.py`)
- `run_burp` — Burp Suite spider, crawl, and active scan
- `run_burp_intruder` — Automated payload fuzzing with sniper/battering ram/pitchfork/cluster bomb
- `run_owaspzap` — OWASP ZAP spider, active scan, and AJAX spidering
- `run_zap_api_scan` — OpenAPI/Swagger and GraphQL schema security scanning

---

## Tool Usage Examples

### Phase 2–3: Network & Web Enumeration
```python
# Fast multi-purpose HTTP probe
run_httpx("https://api.example.com", options="-status-code -title -tech-detect")

# Directory brute-forcing
run_ffuf("https://api.example.com/FUZZ", extensions="json,php,bak")

# Parameter discovery
run_arjun("https://api.example.com/search", method="GET")

# XSS scanning
run_dalfox("https://example.com?q=test", options="--mining-dom")

# JWT cracking
run_jwt_tool("eyJhbGciOiJIUzI1NiIs...", options="-C /usr/share/wordlists/rockyou.txt")
```

### Phase 4: Database Pentesting
```python
# Automated SQL injection
run_sqlmap("http://target.com/page?id=1", options="--batch --level=3")

# NoSQL injection
run_nosqlmap("http://target.com/api/user", options="--attack")

# Oracle SID brute-force
run_oscanner("10.0.0.1", options="-P 1521")
```

### Phase 5: Red Team / Active Directory
```python
# Pivot through compromised host
run_chisel("client", "10.0.0.5:8080", options="--reverse --socks5")

# Enumerate AD shares and sessions
run_crackmapexec("192.168.1.0/24", protocol="smb", options="-u admin -p Password123 --shares")

# AD attack path graph
run_bloodhound("corp.local", options="-c All")
```

### Phase 6: Cloud Pentesting
```python
# GCP metadata token theft (from compromised VM)
run_gcp_metadata_exploit()

# Enumerate S3 buckets
run_aws_s3_enum("lazarus-forms", wordlist="/usr/share/wordlists/dirb/common.txt")

# IAM privilege escalation analysis
run_aws_iam_escalation("arn:aws:iam::123456789012:user/admin")

# Cloud Functions enumeration
run_gcp_cloudfunction_enum("lazarus-forms-api", region="us-central1")
```

### Phase 7: LLM Security Testing
```python
# Prompt injection scan
run_prompt_injection_scanner("https://api.openai.com/v1/chat/completions", model_name="gpt-4", iterations=100)

# Multi-turn jailbreak
run_jailbreak_tester("https://api.anthropic.com/v1/messages", technique="crescendo", depth=10)

# System prompt extraction
run_system_prompt_extraction("https://api.openai.com/v1/chat/completions", encoding_tricks="base64,rot13")

# Consistency / hallucination detection
run_model_consistency_tester("https://api.openai.com/v1/chat/completions", prompt="What is the capital of France?", repetitions=20)

# Bias testing
run_bias_detector("https://api.openai.com/v1/chat/completions", dimensions="gender,race,age")
```

### Phase 8: API Security Testing
```python
# GraphQL introspection abuse
run_graphqlmap("https://api.example.com/graphql", options="--dump")

# gRPC service enumeration
run_grpcurl("api.example.com:443", options="list")

# IDOR detection
run_idor_scanner("https://api.example.com/users/FUZZ", object_range="1-1000", header="Authorization: Bearer xxx")

# Race condition testing
run_race_condition_tester("https://api.example.com/redeem", request_file="/tmp/redeem.req", threads=50)

# CORS bypass
run_cors_misconfig_tester("https://api.example.com/data", origins="https://evil.com,null")
```

### Phase 9: CI/CD & Supply Chain
```python
run_gitleaks("/workspace/repo", options="--verbose")
run_trufflehog("https://github.com/example/project")
run_checkov("/workspace/terraform")
run_trivy("my-image:latest", scan_type="image")
run_semgrep("/workspace/src", config="p/owasp-top-ten")
run_kube_hunter("https://k8s-api.example.com:443")
```

### Phase 10: Proxy-Based Web/API Scanning
```python
# Burp Suite spider + active scan
run_burp("https://api.example.com", action="scan", report_format="xml")

# Burp Intruder — fuzz API parameters
run_burp_intruder(
    "https://api.example.com",
    request_template="GET /api/FUZZ HTTP/1.1\nHost: api.example.com\n\n",
    payload_file="/usr/share/wordlists/dirb/common.txt",
    attack_type="sniper",
    threads=20
)

# OWASP ZAP spider + active scan
run_owaspzap("https://api.example.com", action="ascan", report_format="json")

# ZAP OpenAPI/GraphQL API scan
run_zap_api_scan("https://api.example.com/openapi.json", options="-a")
```

### Phase 11: Network Discovery
```python
# ARP-based host discovery on internal subnet
run_netdiscover("10.0.0.0/24", interface="eth0")

# Ultra-fast async port scan (entire Internet in ~6 min at 10 Mpps)
run_masscan("10.0.0.0/8", ports="1-65535", rate=10000)

# ARP scanning with vendor fingerprinting
run_arp_scan("192.168.1.0/24", options="-I eth0 -g")

# Network path tracing (TCP, UDP, or ICMP)
run_traceroute("api.example.com", protocol="tcp")
```

### Phase 12: Wireless Pentesting
```python
# WPA/WPA2-PSK handshake cracking
run_aircrack_ng("/tmp/capture.cap", wordlist="/usr/share/wordlists/rockyou.txt")

# AP and client discovery (monitor mode required)
run_airodump_ng("wlan0mon", duration=60)

# Automated WEP/WPA/WPS attacks
run_wifite(options="--wps-only --pixie", duration=300)

# WPS PIN brute-force (Pixie Dust)
run_reaver("AA:BB:CC:DD:EE:FF", interface="wlan0mon", options="-K 1")
```

### Phase 13: Mobile Pentesting
```python
# Dynamic instrumentation with Frida
run_frida("com.example.app", script="/tmp/bypass-ssl.js")

# Runtime mobile exploration (SSL pinning bypass, root detection bypass)
run_objection("com.example.app", command="explore")

# Static analysis of APK/IPA with MobSF
run_mobsf("/tmp/target.apk")

# APK decompilation (smali + resources)
run_apktool("/tmp/target.apk", output_dir="/tmp/target-out")

# APK decompilation to Java source
run_jadx("/tmp/target.apk", output_dir="/tmp/target-java")

# Android security assessment framework
run_drozer("com.example.app", command="app.package.info")
```

### Phase 14: Bluetooth & RF
```python
# BLE reconnaissance with bettercap
run_bettercap_bluetooth(duration=60)

# Bluetooth sniffing with Ubertooth (hardware required)
run_ubertooth("scan", duration=60)
```

### Phase 15: IoT & Hardware
```python
# Firmware static analysis (hardcoded secrets, backdoors)
run_firmwalker("/tmp/extracted-firmware/")

# Firmware extraction and binary analysis
run_binwalk("/tmp/firmware.bin", options="-e")
```

### Phase 16: ICS / SCADA Security
```python
# Modbus TCP device discovery and register reading
run_modbus_scan("192.168.1.100", port=502, options="--function-code 3")

# Siemens S7 PLC scanning
run_s7_scan("192.168.1.101", port=102)

# BACnet building automation scanning
run_bacnet_scan("192.168.1.0/24", options="--enumerate-objects")

# ICS protocol fuzzer (use with extreme care)
run_ics_fuzzer("modbus", "192.168.1.100", port=502, options="--mutations 100")
```

### Phase 17: OSINT & Social Engineering
```python
# Email and subdomain enumeration via OSINT
run_theharvester("lazarusai.com", sources="baidu,bing,google", options="--limit 500")

# Social Engineer Toolkit (requires approval)
run_social_engineer_toolkit("spear-phishing", "admin@lazarusai.com")

# Phishing campaign management
run_gophish("launch", campaign="security_awareness_q2")

# OSINT framework aggregation
run_osint_framework("john.doe@lazarusai.com", category="email")
```

### Phase 18: Hardware / Side-Channel
```python
# Power analysis side-channel attack (requires ChipWhisperer hardware)
run_chipwhisperer("target_firmware.bin", attack_type="cpa")

# JTAG/SWD interface enumeration
run_jtag_enum("/dev/ttyUSB0", options="--interface jtag --speed 1000")
```

### Phase 19: Android Mobile Pentesting
```python
# APK static analysis — metadata, permissions, components
run_apk_info("/tmp/target.apk")
run_apk_permissions("/tmp/target.apk")
run_apk_components("/tmp/target.apk")
run_apk_strings("/tmp/target.apk", min_length=8)

# Dynamic instrumentation with Frida
run_frida_hook("com.example.app", hook_script="/tmp/ssl-bypass.js", spawn=True)
run_objection_explore("com.example.app", command="explore")
run_frida_traffic_capture("com.example.app", output_pcap="/tmp/capture.pcap", duration=60)

# Network interception
run_burp_mobile_proxy("com.example.app", proxy_host="127.0.0.1", proxy_port=8080)
run_mitmproxy_android("com.example.app", port=8080)

# Security bypass testing
run_ssl_pinning_bypass("com.example.app", method="frida")
run_root_detection_bypass("com.example.app", method="objection")

# ADB and emulator management
run_adb_shell(command="shell pm list packages")
run_android_emulator(avd_name="Pixel_4_API_30", options="-no-window -gpu off")

# Forensics and data extraction
run_android_backup_extract("com.example.app", output_dir="/tmp/backup")
run_android_screenshot(output_file="/tmp/screenshot.png")

# APK modification
run_apk_patch("/tmp/target.apk", patch_type="debuggable")
run_apk_repack("/tmp/target-out", output_apk="/tmp/target-patched.apk", sign=True)

# SafetyNet / Play Integrity validation
run_safetynet_check("com.example.app")
```

**Phase 20: CT Log & OSINT Reconnaissance** (`agent/tools/scan/ct_log_tools.py`, `agent/tools/scan/osint_recon_tools.py`, `agent/tools/scan/github_leak_tools.py`)
- `query_crt_sh` — Certificate Transparency log subdomain and certificate history discovery via crt.sh
- `query_certspotter` — Certificate Transparency log enumeration via CertSpotter
- `search_github_code` — GitHub code search for leaked secrets and credentials
- `search_github_commits` — GitHub commit search for sensitive data exposure
- `run_amass` — Active/passive subdomain enumeration (Kali/Parrot)
- `run_subfinder` — Passive subdomain discovery (Kali/Parrot)
- `run_recon_ng` — Multi-source OSINT framework (Kali/Parrot)
- `run_assetfinder` — Asset discovery from multiple sources (Kali/Parrot)
- `run_findomain` — Certificate transparency subdomain enumeration (Kali/Parrot)
- `run_dnsx` — DNS resolution and verification toolkit (Kali/Parrot)
- `run_gau` — Gather URLs from Wayback, Common Crawl, and URLScan (Kali/Parrot)
- `run_waybackurls` — Fetch historical URLs from the Wayback Machine (Kali/Parrot)
- `run_gowitness` — Website screenshot and technology fingerprinting (Kali/Parrot)

### Phase 20: CT Log & OSINT Reconnaissance
```python
# Certificate Transparency subdomain discovery
query_crt_sh("example.com")
query_certspotter("example.com")

# GitHub leak reconnaissance
search_github_code("example.com password", language="yaml")
search_github_commits("example.com secret", author="admin")

# Containerized OSINT (Kali/Parrot)
run_amass("example.com", options="--passive")
run_subfinder("example.com", options="-all")
run_recon_ng("example.com", workspace="recon")
run_assetfinder("example.com")
run_findomain("example.com", output_format="json")
run_dnsx("example.com", options="-a -aaaa -cname -txt")
run_gau("example.com", providers="wayback,commoncrawl,urlscan")
run_waybackurls("example.com")
run_gowitness("https://example.com", options="--screenshot")
```

All tools support dual-distro execution (`distro="kali"` or `distro="parrot"`) and share the same container lifecycle (setup → execute → cleanup).

---

## Quickstart

```bash
# Network scan a single target
clearwing scan 192.168.1.10 -p 22,80,443 --detect-services

# Source-code hunt a repo (standard depth — sandboxed LLM hunters,
# adversarial verifier, mechanism memory, variant loop)
clearwing sourcehunt https://github.com/example/project \
    --depth standard

# N-day exploit pipeline — build and exploit known CVEs
clearwing sourcehunt https://github.com/example/project \
    --nday --cve-list CVE-2024-1234,CVE-2024-5678

# Reverse engineering — hunt vulnerabilities in closed-source binaries
clearwing sourcehunt /path/to/binary --reveng --arch x86_64

# Campaign-scale orchestration across multiple projects
clearwing campaign run campaign.yaml

# Responsible disclosure workflow
clearwing disclose queue ./results/sourcehunt/sh-*/
clearwing disclose review

# OSS-Fuzz crash severity benchmark
clearwing bench ossfuzz --corpus-dir ./oss-fuzz-projects --mode standard

# A/B test whether preprocessing helps or hurts
clearwing eval preprocessing --project https://github.com/example/project \
    --configs glasswing_minimal,sourcehunt_full --runs 3

# Interactive ReAct chat with the full tool set
clearwing interactive

# Non-interactive CI mode with SARIF output for GitHub Code Scanning
clearwing ci --config .clearwing.ci.yaml --sarif results.sarif
```

See [`docs/quickstart.md`](docs/quickstart.md) for a fuller walkthrough
including credentials, session resume, and mission-mode operation.

## Running sourcehunt on a local repo (FFmpeg example)

The `clearwing sourcehunt <url>` CLI clones a remote URL. To hunt an
already-cloned tree (e.g. FFmpeg) with the native-async pipeline and a
self-hosted OpenAI-compatible backend, drive `SourceHuntRunner` directly:

```bash
# 1. Clone the target once
git clone https://github.com/FFmpeg/FFmpeg.git

# 2. Run sourcehunt against the local checkout
uv run python -u - <<'PY'
import logging
from clearwing.llm.native import AsyncLLMClient
from clearwing.sourcehunt.runner import SourceHuntRunner

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')

REPO = './FFmpeg'
RUN_DIR = './results/sourcehunt'
COMMON = dict(
    provider_name='openai_resp',            # or 'openai' for /v1/chat/completions
    api_key='YOUR_KEY',
    base_url='http://localhost:8183/v1',    # any OpenAI-compatible endpoint
    max_concurrency=15,
)

# One client per stage — routes each stage to a different model
ranker_llm    = AsyncLLMClient(model_name='gpt-5.4-mini',  **COMMON)
hunter_llm    = AsyncLLMClient(model_name='gpt-5.4',       **COMMON)
verifier_llm  = AsyncLLMClient(model_name='gpt-5.4-mini',  **COMMON)
exploiter_llm = AsyncLLMClient(model_name='gpt-5.3-codex', **COMMON)

runner = SourceHuntRunner(
    repo_url=REPO, local_path=REPO,
    depth='standard',
    budget_usd=1000.0,
    max_parallel=15,
    output_dir=RUN_DIR,
    output_formats=['json', 'markdown'],
    ranker_llm=ranker_llm,
    hunter_llm=hunter_llm,
    verifier_llm=verifier_llm,
    exploiter_llm=exploiter_llm,
    enable_patch_oracle=True,
)

print(runner.run())   # sync wrapper; internally drives SourceHuntRunner.arun()
PY
```

Findings land in `./results/sourcehunt/sh-<session-id>/` as JSON +
markdown once the run completes. FFmpeg is ~10k source files, so expect the
large-repo ranker to preselect candidates and the tier-A hunter pool to run for hours.
Redirect stdout/stderr to a file if you plan to detach the process — the
runner's own artifacts are only written at the end.

`AsyncLLMClient` accepts `provider_name` values `openai_resp` (the streaming
`/v1/responses` shape) or `openai` (standard `/v1/chat/completions`); point
`base_url` at any OpenAI-compatible server. See
[`docs/providers.md`](docs/providers.md) for the managed-provider paths.

## Architecture at a glance

```
┌──────────────────────┐      ┌────────────────────────────────┐
│ Network-pentest agent│      │ Source-code hunter             │
│ clearwing.agent.graph│      │ clearwing.sourcehunt.runner    │
│  (255 tools, ReAct)  │      │                                │
│                      │      │ preprocess → rank → pool →     │
│                      │      │   hunter → verify → exploit →  │
│                      │      │   variant loop → auto-patch →  │
│                      │      │   report                       │
└─────────┬────────────┘      └────────┬───────────────────────┘
          │                             │
          └───────────┬─────────────────┘
                      ▼
┌───────────────────────────────────────────────────────────────┐
│ N-day pipeline │ Reveng pipeline │ Campaign orchestrator      │
│ Disclosure workflow + SHA-3 commitments                       │
├───────────────────────────────────────────────────────────────┤
│                    Shared substrate                          │
│  Finding dataclass  │  capabilities probe  │  sandbox layer  │
│  knowledge graph    │  episodic memory     │  event bus      │
│  telemetry          │  guardrails + audit  │  CVSS scoring   │
│  artifact store     │  behavior monitor    │  seccomp        │
├───────────────────────────────────────────────────────────────┤
│  Bench: OSS-Fuzz severity ladder  │  Eval: preprocessing A/B │
└───────────────────────────────────────────────────────────────┘
```

Deep dives live in [`docs/`](docs/):

| Doc | What it covers |
|---|---|
| [`docs/index.md`](docs/index.md) | Landing page + table of contents |
| [`docs/quickstart.md`](docs/quickstart.md) | Full install + first run walkthrough |
| [`docs/providers.md`](docs/providers.md) | OpenRouter / Ollama / LM Studio / vLLM / Together / Groq recipes, per-task routing, env-var precedence |
| [`docs/architecture.md`](docs/architecture.md) | Both pipelines, substrate, capability gating, tool layout |
| [`docs/cli.md`](docs/cli.md) | Every subcommand flag, grouped by workflow |
| [`docs/api.md`](docs/api.md) | API reference (mkdocstrings autogen) |

Once the GitHub Pages workflow ships, docs will be hosted at
<https://lazarus-ai.github.io/clearwing/>.

## Development

```bash
uv sync --all-extras
source .venv/bin/activate  # fish: source .venv/bin/activate.fish
pytest -q
ruff check clearwing/ tests/
ruff format --check clearwing/ tests/
mypy --follow-imports=silent \
  clearwing/findings \
  clearwing/sourcehunt \
  clearwing/capabilities.py \
  clearwing/agent/tools \
  clearwing/core
python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full dev-setup guide and PR
checklist.

## Reporting vulnerabilities

There are two lanes, and they go to different places:

- **Vulnerabilities *in* Clearwing** → GitHub Security Advisories
  (<https://github.com/Lazarus-AI/clearwing/security/advisories/new>).
  See [`SECURITY.md`](SECURITY.md) for scope, SLA, and safe-harbor.
- **Vulnerabilities Clearwing *finds* in someone else's software** →
  that vendor's disclosure channel. `clearwing sourcehunt
  --export-disclosures` generates pre-filled MITRE CVE-request and
  HackerOne templates for every finding at
  `evidence_level >= root_cause_explained`.

## License

MIT. See [`LICENSE`](LICENSE).
