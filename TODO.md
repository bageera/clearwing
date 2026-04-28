# Clearwing Development TODO

## Current Session: Ollama Cloud + Dual Container Support

### Completed
- [x] Fix Ollama Cloud adapter routing (`manager.py`)
- [x] Add `ollama-cloud` preset to `catalog.py`
- [x] Update docs (`providers.md`) with Ollama Cloud section
- [x] Extract shared `PentestContainerManager` base class
- [x] Refactor Kali tools to use shared base
- [x] Add ParrotOS container support (slim image)
- [x] Register dual-container tools in agent graph + specialists
- [x] Update state tracking for both container types
- [x] Add parameterized tests for Kali + Parrot lifecycle
- [x] Run lint + tests (65 passed, 2 skipped)
- [x] Commit all changes

### Deferred: Phase 1 Tools (posix native)
- [ ] `scan_ports` enhancement — add nmap binary wrapper (SYN/UDP/NSE)
- [ ] `enumerate_directories` — gobuster wrapper or Python brute
- [ ] `run_snmpwalk` — snmpwalk/onesixtyone subprocess tool
- [ ] `john_crack` — execute john subprocess (currently generates commands only)
- [ ] `hydra_brute` — system hydra wrapper (expand existing `crack_password`)
- [ ] `gtfobins_lookup` — static JSON cache or live fetch

### Deferred: Phase 2 Tools (Kali/Parrot containers)
- [ ] `enum4linux_scan` — SMB enumeration
- [ ] `sqlmap_scan` — SQL injection automated testing
- [ ] `nikto_scan` — web vulnerability scanner
- [ ] `whatweb_scan` — web technology fingerprinting
- [ ] `wpscan_enum` — WordPress enumeration
- [ ] `impacket_psexec` — remote Windows execution from Linux
- [ ] `impacket_secretsdump` — credential extraction
- [ ] `linpeas_run` / `linenum_run` — Linux privilege escalation enumeration
- [ ] `hashcat_crack` — GPU/CPU hash cracking (Kali container)
- [ ] `responder_capture` — Net-NTLMv2 hash capture (raw sockets)

### Deferred: Phase 3 Tools (Windows emulation)
- [ ] `mimikatz` — credential dumping (Windows-only, needs Metasploit bridge or Windows container)
- [ ] `powerup` / `winpeas` — Windows privilege escalation
- [ ] `seatbelt` — Windows security assessment
- [ ] UAC bypass / potato family exploits

### Documentation
- [ ] Update README.md: mention ParrotOS alongside Kali
- [ ] Add container architecture diagram (Kali vs Parrot vs Sandbox)
- [ ] Document OSCP cheatsheet integration plan and coverage map

---

## Backlog (from upstream merge)

### Merged from upstream (2026-04-27)
- [x] Phase 6 tooling expansion findings
- [x] 15 new pentesting tools (mycelium, recovery, session, bundle, cc_tools)
- [x] Phase 4 extended pre-auth exploration findings
- [ ] Verify upstream tool compatibility with dual-container changes

### Tool Quality
- [ ] Refactor `_adapter_for_base_url` to use configurable mapping rather than hardcoded host checks
- [ ] Unify LLM endpoint creation logic (some duplication between `_create_llm` and `_create_native`)
- [ ] Consider adding `PentestContainerManager` abstraction for sandbox containers too (unify container management)
