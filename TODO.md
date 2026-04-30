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

##### Recommendations
1. **Immediate**: Rotate leaked Firebase API key `AIzaSyBgs-HrkxUdKbLFVxPsN2JJfjB71c_Cn58`.
2. **Immediate**: Remove Firebase project IDs and Cloud Run URLs from `Content-Security-Policy` headers (use nonces or restrict to production only).
3. **Short-term**: Verify Firebase Security Rules are restrictive (Realtime DB returned `Permission denied` — good sign, but verify rules).
4. **Short-term**: Remove or protect preview Cloud Run URL (`lazarus-forms-dashboard-preview-7owznqu3wq-uc.a.run.app`).
5. **Medium-term**: Consider implementing Firebase App Check to restrict API key usage to your app only.

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
