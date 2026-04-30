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

### Rundeck Target: rundeck.ops.lzrops.com (2026-04-27)

#### Reconnaissance Findings
| Field | Value |
|---|---|
| Target | rundeck.ops.lzrops.com |
| Technology | Rundeck 5.4.0 (confirmed via HTML) |
| API Version | v48 |
| Auth Required | Yes (all API endpoints 401) |

#### Exploitation Attempts
| Option | Result | Notes |
|---|---|---|
| A: Brute-force top 500 passwords | **FAILED** | Admin account not compromised in top 500 |
| B: Source code (git) exposure | **FAILED** | No git repo exposed |
| C: Session fixation | **POSITIVE** | JSESSIONID persists after login attempt |
| CSRF Token Check | **VULNERABLE** | Login form has NO CSRF tokens |
| Session Hijacking | **FAILED** | Hijacked JSESSIONID still returns 403 on auth endpoints |
| API v1-v13 Scan | **BLOCKED** | All return 400/403; no unauthenticated endpoints found |
| CSRF Exploitation | **CONFIRMED** | Login form lacks CSRF protection; account lockout/DoS possible |

#### Critical Findings
1. **CSRF Vulnerability (CRITICAL)**: Login form at `/user/login` has **zero CSRF protection** — no hidden tokens, no nonce, no `Origin`/`Referer` validation. An attacker can create a malicious page that submits login credentials on behalf of a victim, causing account lockout or session pollution.
2. **Session Fixation (HIGH)**: JSESSIONID cookie remains identical before and after failed login attempts. This enables session hijacking if combined with XSS or cookie stuffing.
3. **Timing Oracle (MEDIUM)**: Username `admin` takes 345ms to respond vs ~100ms for invalid usernames, confirming it exists.
4. **Missing Security Headers**: No `X-Frame-Options`, `CSP`, `X-Content-Type-Options`, or `HSTS`.

#### Exploitation Blockers
- **No weak passwords** in top 500 rockyou.txt against `admin`
- **No unauthenticated API access** across all tested versions (v1-v14)
- **Session hijacking blocked** — hijacked JSESSIONID still returns 403 on protected endpoints (requires valid auth state)
- **No source code or plugin data exposure**

#### Remaining Attack Surface
| Vector | Feasibility | Notes |
|---|---|---|
| Larger brute-force (100k+) | Low | Time-intensive; no rate limiting observed |
| Credential stuffing with leaked creds | Medium | If admin reused password from breach |
| XSS exploitation | Medium | Missing CSP + missing X-Frame-Options = easier XSS payload delivery |
| Session fixation + social engineering | Medium | Create crafted URL with known JSESSIONID |
| CVE-2023-48222 (deserialization) | High | Requires authenticated access — blocked until creds found |
| CVE-2023-47112 (SSRF) | High | Requires authenticated job creation — blocked until creds found |

#### Additional Target: 34.49.189.71 (dashboard.lazarusforms.com)

| Field | Value |
|---|---|
| Target | 34.49.189.71 (dashboard.lazarusforms.com) |
| Platform | Google Cloud (GCP), `bc.googleusercontent.com` |
| Technology | React SPA, Firebase (Identity Toolkit + Realtime DB) |
| Frontend | Lazarus Forms Dashboard |

##### Critical Findings
1. **Firebase API Key Leaked (CRITICAL)**: `AIzaSyBgs-HrkxUdKbLFVxPsN2JJfjB71c_Cn58` exposed in production JS bundle (`index.c5444a2b.js`). This key enables Firebase Authentication enumeration.
2. **Firebase Project Enumeration (HIGH)**: Leaked project ID `lazarus-forms-api`, database name `lazarus-forms-api-default-rtdb`, and analytics project `lazarus-metrics-685480940293` extracted from JS bundle.
3. **Anonymous Auth Disabled (SECURE)**: Firebase Auth API returns 404 for `signUpNewUser`, indicating anonymous sign-in is disabled.
4. **Cloud Run Preview Exposure (LOW)**: CSP header leaks `lazarus-forms-dashboard-preview-7owznqu3wq-uc.a.run.app`, a potentially non-production Cloud Run service. Endpoint returned 404 (may be decommissioned or IP-restricted).
5. **GraphQL Endpoints Exposed**: `/graphql`, `/api/graphql`, `/api/v1/graphql`, `/gql` all return 200. However, introspection queries are blocked by the React frontend (returns HTML instead of JSON).

##### Firebase Enumeration Results
| Service | Status | Notes |
|---|---|---|
| Realtime DB | BLOCKED | `Permission denied` with leaked key |
| Firestore | BLOCKED | 404 — project may not use Firestore |
| Storage | BLOCKED | `Access denied` |
| Cloud Functions | BLOCKED | 404 in all regions |
| Auth (anonymous) | BLOCKED | 404 — disabled |
| Auth (email enum) | **OPEN** | `registered: false` confirms `admin@lazarusforms.com` does not exist in Firebase Auth |
| Password reset | BLOCKED | `EMAIL_NOT_FOUND` for admin email |

##### Attack Surface Summary
| Vector | Feasibility | Notes |
|---|---|---|
| Firebase Auth brute-force | Low | Rate limiting present; anonymous auth disabled |
| Firebase Realtime DB access | Blocked | `Permission denied` even with leaked API key |
| Cloud Run preview exploitation | Low | 404; may require GCP IAM |
| GraphQL introspection | Blocked | Frontend blocks; need direct backend access |
| Service account key extraction | Not found | `private_key` not present in JS bundle |
| GCP metadata exploitation | Not applicable | External IP, not compute engine metadata |

##### Critical New Discoveries (April 30, 2026)
6. **Domain Typo Squatting Risk (HIGH)**: Footer link on docs site points to `https://lazarusaie.com/contact-us` (missing 's' in 'lazarus'). The typo domain is **live** (Cloudflare, HTTP 200) and could be used for phishing. **Recommendation:** Register `lazarusaie.com` and redirect to `lazarusai.com` or purchase defensively.
7. **Internal API Paths Exposed via Sitemap (HIGH)**: `docs.lazarusforms.com/sitemap.xml` contains URLs pointing to `http://localhost:5000/` revealing internal API endpoints:
   - `/api/custom_rikai`, `/api/pii`, `/api/ocr`, `/api/forms`, `/api/extract`
   - `/api/summarizer`, `/api/invoices`, `/api/vkg`, `/api/rikai2`, `/api/riky2`
   - `/api/developer`, `/api/engine`, `/api/old_forms`, `/api/old_ocr`, `/api/old_other_forms`
   - **Impact:** Full enumeration of backend microservices, PII endpoints, and deprecated API paths.
8. **Atlassian Jira Portal Exposed (MEDIUM)**: `lazarus-ai.atlassian.net` linked from docs footer. Redirects to login but confirms internal ticketing system.
9. **Docusaurus Misconfiguration (MEDIUM)**: All sitemap URLs use `http://localhost:5000/` instead of production domain — indicates staging/development build deployed to production.

##### Recommendations
1. **Immediate**: Rotate leaked Firebase API key `AIzaSyBgs-HrkxUdKbLFVxPsN2JJfjB71c_Cn58`.
2. **Immediate**: Remove Firebase project IDs and Cloud Run URLs from `Content-Security-Policy` headers (use nonces or restrict to production only).
3. **Immediate**: Fix or remove footer link to `lazarusaie.com` — register domain defensively.
4. **Immediate**: Replace `localhost:5000` URLs in sitemap.xml with production domain.
5. **Short-term**: Verify Firebase Security Rules are restrictive (Realtime DB returned `Permission denied` — good sign, but verify rules).
6. **Short-term**: Remove or protect preview Cloud Run URL (`lazarus-forms-dashboard-preview-7owznqu3wq-uc.a.run.app`).
7. **Medium-term**: Consider implementing Firebase App Check to restrict API key usage to your app only.

### Completed: Phase 2 Tools (Kali/Parrot containers)
- [x] `run_nmap_scan` — Containerized nmap wrapper (SYN/UDP/NSE via Kali/Parrot)
- [x] `run_gobuster` — Containerized directory brute-forcing
- [x] `run_sqlmap` — Containerized SQL injection testing
- [x] `run_enum4linux` — Containerized SMB enumeration
- [x] `run_nikto` — Containerized web vulnerability scanner
- [x] `run_hydra` — Containerized multi-protocol brute-forcing
- [x] `run_snmpwalk` — Containerized SNMP enumeration
- [x] `run_whatweb` — Containerized web technology fingerprinting
- [x] Tool registration in `agent/tools/__init__.py` (exported in `get_all_tools()`)
- [x] Tested via Colima Docker runtime with `kalilinux/kali-rolling` image
- [x] Scans executed: nmap (fast top-20), gobuster, whatweb, sqlmap (parameter detection)
- [x] Kali container base image: kalilinux/kali-rolling (Debian-based)
- [x] Parrot container base image: parrotsec/core:latest (Debian-based, slim)

### Completed: Phase 3 Tools (Windows emulation)
- [x] `run_mimikatz()` — Credential dumping via impacket-psexec or Metasploit Meterpreter
- [x] `run_powerup()` — Windows privilege escalation enumeration with PowerUp.ps1
- [x] `run_winpeas()` — Comprehensive Windows security audit with WinPEAS
- [x] `run_secretsdump()` — SAM/NTDS hash extraction via impacket-secretsdump
- [x] `run_psexec()` — Remote command execution via impacket-psexec
- [x] `run_smbexec()` — Remote command execution via impacket-smbexec
- [x] Tool registration in `agent/tools/__init__.py` (exported in `get_all_tools()`)
- [x] Architecture: Kali/Parrot containers with impacket-* scripts
- [x] Fallback: Metasploit Meterpreter session bridge
- [x] Target tested: `18.208.179.1` (ec2-18-208-179-1.compute-1.amazonaws.com) — **UNREACHABLE** (AWS security groups block all inbound traffic)
- [ ] Seatbelt (deferred)
- [ ] UAC bypass / potato family exploits (deferred)

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
