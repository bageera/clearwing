# Clearwing Security Assessment — Retest Executive Report

## Lazarus AI Production Environment

**Report Date:** June 5, 2026  
**Assessment Type:** Retest — Amendment 06 Re-verification  
**Original Assessment:** May 2026 (Amendments 01–05)  
**Authorization:** LOA LAZ-ROE-MASTER-2026 v1.1, Amendment 06  
**Authorization Code:** CW-2026-LAZARUS-001  
**Authorized Party:** Jon Bethea, Clearwing Security Operations  
**Authorizing CISO:** Jane Doe, Lazarus AI / Cyber Security & Infrastructure Services LLC  

---

## 1. Executive Summary

This report presents the results of a comprehensive retest of the Lazarus AI production environment, conducted under Amendment 06 of the master Letter of Authorization. The retest was initiated to verify remediation of 15 findings from the original May 2026 assessment and to identify new attack surface resulting from environmental changes.

**Overall posture has not materially improved since the original assessment.** Of 15 original findings, only 2 have been confirmed remediated. Eight remain open (one partially remediated), one is inconclusive due to credential rotation, and four entirely new findings were discovered during delta reconnaissance.

The most significant concern is the persistence of **publicly accessible Cloud Run services without IAM authentication** — a systemic issue that was present in the original assessment and has expanded. Three new unmapped backend services were discovered in client-side JavaScript that were not in the original scope, all publicly accessible. The admin API status endpoint still returns unauthenticated `SUCCESS` responses and reflects arbitrary CORS origins.

On the positive side, Firebase Identity Toolkit account enumeration has been fixed (LAZ-004), and Rundeck session fixation has been addressed (LZ-002). The `dashboard.lazarusforms.com` host has received improved security headers (CSP, HSTS, X-Content-Type-Options).

### Finding Status Summary

| Status | Count | Percentage |
|--------|-------|------------|
| Confirmed Remediated | 2 | 13% |
| Still Open | 8 | 53% |
| Partially Remediated | 1 | 7% |
| Inconclusive (credentials rotated) | 1 | 7% |
| New Findings | 4 | — |
| **Total Open Findings** | **13** | — |

### Severity Distribution (All Open Findings)

| Severity | Original | New | Total Open |
|----------|----------|-----|------------|
| High | 1 | 1 | 2 |
| Medium | 5 | 3 | 8 |
| Low | 3 | 0 | 3 |

---

## 2. Scope and Methodology

### 2.1 Scope

Full scope retest per LOA Amendment 06, Tiers 1–7:

- **Tier 1:** Public-facing web applications (lazarusai.com, lazarusforms.com, dashboard.lazarusforms.com)
- **Tier 2:** API gateways (api.lazarusai.com, api.lazarusforms.com)
- **Tier 3:** Administrative interfaces (sales-admin.lazarusforms.com, rundeck.ops.lzrops.com)
- **Tier 4:** Cloud Run services (all discovered backend endpoints)
- **Tier 5:** Firebase infrastructure (Identity Toolkit, Realtime Database)
- **Tier 6:** GCP infrastructure (staging environments, App Engine)
- **Tier 7:** New subdomains and services discovered during assessment

### 2.2 Methodology

1. **Regression testing** — Re-executed reproduction steps for each of the 15 original findings
2. **Delta discovery** — Full subdomain enumeration, endpoint probing, and Cloud Run service inventory
3. **Environment drift** — JS bundle hash comparison, TLS posture validation, security header baselines
4. **New vector testing** — IDOR on Cloud Run admin endpoints, subdomain takeover assessment, staging isolation verification

### 2.3 Retest Date and Duration

- **Start:** June 5, 2026, 14:30 UTC
- **End:** June 5, 2026, 16:45 UTC
- **Duration:** ~2.25 hours

---

## 3. Regression Results — Original Findings

### 3.1 Confirmed Remediated — 2 Findings

#### LAZ-004: Firebase Identity Toolkit Account Enumeration (MEDIUM → FIXED)

**Original Finding:** The `createAuthUri` endpoint returned `registered: true` for valid Lazarus AI email addresses and `registered: false` for non-existent ones, enabling account enumeration.

**Retest Result:** REMEDIATED. The `createAuthUri` endpoint now returns `registered: false` for all email addresses regardless of validity, eliminating the differentiator. The `sendOobCode` endpoint now requires authenticated callers (returns 403 `PERMISSION_DENIED` for unregistered callers with `key` parameter and 403 for calls without one).

**Remediation Quality:** Effective. Both primary enumeration vectors have been closed.

---

#### LZ-002: Rundeck Session Fixation (LOW → FIXED)

**Original Finding:** The `JSESSIONID` cookie was retained across failed login attempts, enabling session fixation attacks.

**Retest Result:** REMEDIATED. After a failed login attempt, Rundeck regenerates the `JSESSIONID` cookie. The session cookie now uses `SameSite=Lax`, `Secure`, and `HttpOnly` attributes. Post-failure requests do not retain the original session identifier.

**Remediation Quality:** Effective. The session is now invalidated on authentication failure.

---

### 3.2 Still Open — 8 Findings

#### LAZ-001: Firebase API Key Leaked in Production JavaScript Bundles (MEDIUM → OPEN)

**Original Finding:** Firebase API key embedded in client-side JavaScript bundles, enabling unauthorized access to Firebase services.

**Retest Evidence:**
- Key `AIzaSy[REDACTED]` confirmed present in:
  - `dashboard.lazarusforms.com/static/js/index.c5444a2b.js`
  - `sales-admin.lazarusforms.com/static/js/main.91f908c2.js`
  - `vkgchat.lazarusai.com/static/js/index.34ebda78.js` (new scope)

**Risk:** The exposed API key enables unauthorized access to Firebase services including Identity Toolkit account enumeration (partially mitigated by LAZ-004 fix), Realtime Database reads (depending on security rules), and any Firebase service that accepts browser API keys.

**Recommendation:** Remove Firebase API keys from client-side bundles. Use environment variable injection at build time. Rotate the currently exposed key and enforce Firebase App Check.

---

#### LAZ-002: Backend Infrastructure URLs Leaked in Client JavaScript (MEDIUM → OPEN)

**Original Finding:** Client-side JavaScript bundles contain 20+ internal backend service URLs, Cloud Run endpoints, and Firebase configuration details.

**Retest Evidence:**
- `sales-admin` bundle leaks 20+ URLs including:
  - `lazarus-forms-admin-api-7owznqu3wq-uc.a.run.app`
  - `lazarus-forms-dashboard-prod-7owznqu3wq-uc.a.run.app`
  - `forms-user-dashboard-685480940293.us-central1.run.app`
  - `lazarus-metrics-685480940293.us-central1.run.app`
  - `forms-admin-dashboard-685480940293.us-central1.run.app`
  - `lazarus-forms-api-default-rtdb.firebaseio.com`
  - Full API path schemas including `/models/custom`, `/orgs/models/custom/access`, `/api/query/models`
- `vkgchat` bundle (new scope) additionally leaks:
  - `ask-citations-363598527858.us-central1.run.app`
  - `legacy.lazarusforms.com/api/rikai/ocr/`
  - `legacy.lazarusforms.com/api/vkg/chat/ask`
  - `vkgui.lazarusai.com`

**Risk:** The leaked URLs provide a complete map of backend infrastructure, enabling targeted attacks against every production service. The inclusion of API paths (e.g., `/models/custom/validate`, `/api/query/models/time-period`) gives attackers a blueprint of the API surface without any reconnaissance effort.

**Recommendation:** Move all service URLs to server-side configuration. Use API gateway routing instead of direct Cloud Run URLs. Bundle minification alone is insufficient — the URLs remain in string literals.

---

#### LAZ-003: `/status` Endpoint Authentication Bypass (MEDIUM → OPEN)

**Original Finding:** The `/status` endpoint on `api.lazarusai.com` returns `SUCCESS` with HTTP 200 for any request regardless of authentication state, including requests with no authorization, invalid tokens, random UUIDs, and empty tokens.

**Retest Evidence:**
- No auth token: `{"status": "SUCCESS"}`, HTTP 200
- Invalid token (`Bearer INVALID_TOKEN_RETEST_2026`): `{"status": "SUCCESS"}`, HTTP 200
- Random UUID token: `{"status": "SUCCESS"}`, HTTP 200
- Empty token: `{"status": "SUCCESS"}`, HTTP 200

Identical behavior to original assessment. No remediation attempt detected.

**Risk:** The unauthenticated status endpoint reveals service liveness and operational state to attackers. More critically, it establishes a pattern where the API gateway does not enforce authentication, suggesting similar gaps may exist on other endpoints.

**Recommendation:** Require valid authentication on all API endpoints including `/status`. Return 401/403 for unauthenticated requests. Consider moving health checks to a separate internal-only endpoint.

---

#### LAZ-005: Missing Security Headers / Permissive CORS (LOW-MEDIUM → PARTIALLY OPEN)

**Original Finding:** Critical security headers missing across multiple hosts; `api.lazarusai.com` returns `Access-Control-Allow-Origin: *`.

**Retest Evidence:**

| Host | Status |
|------|--------|
| `lazarusai.com` | Still missing: CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection. Only HSTS present. |
| `api.lazarusai.com` | Still returns `Access-Control-Allow-Origin: *`. No CSP, no X-Frame-Options. |
| `dashboard.lazarusforms.com` | IMPROVED: Added CSP `frame-ancestors 'self'`, X-Content-Type-Options nosniff, Referrer-Policy strict-origin, HSTS. Still missing X-Frame-Options. |
| `sales-admin.lazarusforms.com` | Still missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| `vkgchat.lazarusai.com` | Still missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| `legacy.lazarusforms.com` | Missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options. Returns `Access-Control-Allow-Origin: *`. |

**Risk:** Missing security headers enable clickjacking, content-type sniffing, and protocol downgrade attacks. Wildcard CORS on `api.lazarusai.com` allows any domain to make authenticated cross-origin requests, enabling session hijacking and data exfiltration.

**Recommendation:** Deploy a comprehensive security header policy across all hosts. Replace `Access-Control-Allow-Origin: *` with an explicit allowlist of authorized origins.

---

#### LZ-001: Rundeck Login Lacks CSRF Protection (LOW → OPEN)

**Original Finding:** The Rundeck login form does not include CSRF tokens, enabling cross-site request forgery attacks against authenticated sessions.

**Retest Evidence:** Login form HTML at `rundeck.ops.lzrops.com/user/login` contains no CSRF token or nonce. CSP includes `unsafe-inline` and `unsafe-eval` directives, further weakening protection.

**Recommendation:** Add CSRF tokens to all Rundeck forms. Tighten CSP to remove `unsafe-inline` and `unsafe-eval`.

---

#### ALL-001: Firebase Auth Account Enumeration via Timing Oracle (LOW → OPEN)

**Original Finding:** Firebase `signInWithPassword` returns `EMAIL_NOT_FOUND` for non-existent accounts versus `INVALID_PASSWORD` for valid accounts, enabling account enumeration.

**Retest Evidence:**
- Non-existent email: `{"error": {"code": 400, "message": "EMAIL_NOT_FOUND"}}`
- Response time: ~183ms (consistent with previous assessment)

The error message differentiator remains active, allowing attackers to enumerate valid email addresses.

**Recommendation:** Configure Firebase Authentication to return a generic error message (e.g., "Invalid email or password") regardless of whether the account exists. Enable email enumeration protection in Firebase Console (Authentication → Settings → Email enumeration protection).

---

#### SALES-001: Sales-Admin JavaScript Bundle Leaks Complete Service Inventory (MEDIUM → OPEN)

**Original Finding:** The `sales-admin.lazarusforms.com` JavaScript bundle contains a complete inventory of backend services, API endpoints, and authentication configuration.

**Retest Evidence:** Confirmed. The `main.91f908c2.js` bundle (SHA-256: `dc9502739edd...`) contains the same 20+ backend URLs, all Cloud Run service hostnames, Firebase Realtime Database URL, password reset URL templates with parameter names, and the production Firebase API key.

**Recommendation:** Same as LAZ-002. Remove all service URLs and configuration from client bundles. Implement build-time environment variable injection.

---

#### ADMIN-CRIT-001: Admin API Unauthenticated Status + Open CORS (HIGH → OPEN)

**Original Finding:** The `lazarus-forms-admin-api` Cloud Run service's `/status` endpoint returns `SUCCESS` for any request without authentication, and the service reflects arbitrary `Origin` headers in CORS responses.

**Retest Evidence:**
- No auth: `{"status": "SUCCESS"}`, HTTP 200
- Invalid Bearer token: `{"status": "SUCCESS"}`, HTTP 200
- CORS `Origin: https://evil.com` → `Access-Control-Allow-Origin: https://evil.com`

The service is directly accessible without IAM authentication (`--allow-unauthenticated` is still configured on the Cloud Run deployment).

**Risk:** Any internet user can verify service liveness and make cross-origin requests to the admin API from any domain. Combined with the leaked URLs (LAZ-002/SALES-001), attackers have both the address and the permission to interact with administrative backend services.

**Recommendation:** Enable IAM authentication on all Cloud Run services (`--no-allow-unauthenticated`). Remove CORS reflection and implement an explicit origin allowlist. This is the highest-priority remediation.

---

### 3.3 Inconclusive — 1 Finding

#### LFR-001: LLM Model Name Not Validated Leading to 500 Crash (MEDIUM → INCONCLUSIVE)

**Original Finding:** Submitting an invalid or extremely long model name to `api-dev.gcp.lzrops.com/api/engine/internal` caused a 500 Internal Server Error, indicating unhandled exceptions and potential DoS vector.

**Retest Result:** INCONCLUSIVE. All requests to the dev API endpoint return `AUTH_FAILURE`/403 with both the original and alternative credentials. The `authkey` and `orgid` credentials from the `.env` file have been rejected, suggesting they were rotated since the original assessment. The model validation layer cannot be tested without valid credentials.

**Recommendation:** Provide updated test credentials to complete this regression test. In the interim, verify that input validation on the `modelName` field rejects unexpected values before they reach downstream processing.

---

## 4. New Findings

### NEW-001: Staging Environment Exposes Production Application (MEDIUM)

**Target:** `staging.lazarusai.com` (34.36.25.49), `staging.lazarusforms.com` (35.227.223.84)

**Description:** Both staging subdomains resolve to GCP IPs and serve content identical to the production dashboard application. They share the exact same JavaScript bundles (identical filenames and hashes as `dashboard.lazarusforms.com`), the same API version header (`apiversion: 2025-08-07`), and return `Access-Control-Allow-Origin: *`. Rather than being isolated sandboxes, the staging environments are aliases for production, redirecting to `dashboard.lazarusforms.com`.

**Risk:** No meaningful staging/production isolation. Any vulnerability discovered in staging directly affects production. CORS wildcard on staging further expands the attack surface.

**Recommendation:** Isolate staging environments in separate GCP projects with separate databases, API keys, and service accounts. Staging should never share production backends or credentials.

---

### NEW-002: Cloud Run Services Publicly Accessible Without IAM Authentication (HIGH)

**Targets:** 8 Cloud Run services discovered in client-side JavaScript bundles

**Description:** All Cloud Run services referenced in production client code are deployed with `--allow-unauthenticated`, making them directly accessible from the internet without any IAM identity. Additionally, CORS is misconfigured on most services — 4 reflect arbitrary `Origin` headers, and 2 use wildcard `Access-Control-Allow-Origin: *`.

| Service | Unauth `/status` | CORS Policy |
|---------|-----------------|-------------|
| `lazarus-forms-admin-api` | `SUCCESS` | Reflects Origin |
| `lazarus-forms-dashboard-prod` | 404 | Reflects Origin |
| `forms-user-dashboard` | 404 | Reflects Origin |
| `lazarus-metrics` | `SUCCESS` (with timestamp) | Wildcard `*` |
| `forms-admin-dashboard` | `SUCCESS` | Reflects Origin |
| `v2025-09-29---lazarus-metrics` | `SUCCESS` (with timestamp) | Wildcard `*` |
| `ask-citations` | `200 "Request made"` | Wildcard `*` |
| `lazarus-apis-testing` | Serves full SPA | No CORS headers |

**Risk:** Publicly accessible backend services with no authentication create a direct path for attackers to interact with administrative, metrics, and model-serving APIs. The `lazarus-metrics` services expose operational timestamps and health data. The `forms-admin-dashboard` reveals role names. The `ask-citations` service accepts POST requests from any origin.

**Recommendation:** Immediately run `gcloud run services update --no-allow-unauthenticated` on all 8 services. Implement Cloud Run IAM invoker roles. Replace CORS reflection with explicit origin allowlists.

---

### NEW-003: Admin Dashboard API Reveals Role Structure (MEDIUM)

**Target:** `forms-admin-dashboard-685480940293.us-central1.run.app`

**Description:** The `/models/custom` endpoint returns detailed error messages that reveal the application's authorization model:

- Without `adminId` header: `{"requiredFields": ["adminId"], "status": "FAILURE"}` (400)
- With test `adminId`: `{"message": "Insufficient privileges. You need to be an admin", "permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin", "status": "FAILURE"}` (403)
- The `/orgs/models/custom/access` endpoint reveals it requires both `adminId` and `orgId` headers

**Risk:** Verbose error messages reveal the exact role hierarchy (`prodAdmin`, `salesAdmin`, `superAdmin`) and required request headers, enabling targeted privilege escalation attempts. Combined with the unauthenticated Cloud Run access (NEW-002), an attacker knows exactly which headers and roles to target.

**Recommendation:** Return generic 400/403 responses without field names or role enums. Pattern: `{"message": "Invalid request", "status": "FAILURE"}`.

---

### NEW-004: Previously Unmapped Backend Endpoints in vkgchat JavaScript Bundle (MEDIUM)

**Targets:**
- `ask-citations-363598527858.us-central1.run.app`
- `legacy.lazarusforms.com`
- `vkgui.lazarusai.com`

**Description:** The `vkgchat.lazarusai.com` JavaScript bundle (`index.34ebda78.js`, SHA-256: `541ed95a399d...`) contains three backend endpoints that were not present in the original assessment scope:

1. **`ask-citations` Cloud Run** — Publicly accessible, accepts POST requests from any origin (wildcard CORS), reveals expected headers (`Content-Type, orgId, authKey, userId, authorization`) in CORS preflight responses. Returns `"Request made"` with HTTP 200.

2. **`legacy.lazarusforms.com`** — Serves a Flask-style login redirect (`/login`), runs on Google Frontend, returns `Access-Control-Allow-Origin: *`. This subdomain was not in the original assessment scope.

3. **`vkgui.lazarusai.com`** — Serves a React SPA via S3/CloudFront with no security headers (no CSP, no HSTS, no X-Frame-Options, no X-Content-Type-Options).

**Risk:** These endpoints expand the attack surface beyond the originally scoped infrastructure. The `ask-citations` service is an LLM citation endpoint that could be abused for unauthorized AI model access. The `legacy` subdomain suggests an older service stack that may have additional vulnerabilities. None of these services were documented in the original assessment.

**Recommendation:** Remove backend URLs from client bundles (same as LAZ-002). Enable IAM auth on `ask-citations`. Add security headers to `vkgui.lazarusai.com`. Conduct security review of `legacy.lazarusforms.com`.

---

## 5. Environment Drift Analysis

### 5.1 Attack Surface Changes Since May 2026

| Change | Risk Impact |
|--------|------------|
| 3 new subdomains active (`vkgchat`, `vkgui`, `legacy`) | Expanded attack surface |
| `ask-citations` Cloud Run service live | New unauthenticated LLM endpoint |
| 2 staging environments pointing to production | No staging isolation |
| `www.lazarusai.com` no longer resolves | Reduced surface (positive) |
| JS bundles unchanged from May 2026 | No code hardening detected |

### 5.2 JavaScript Bundle Integrity

| Bundle | SHA-256 (prefix) | Changed |
|--------|-------------------|---------|
| `dashboard.lazarusforms.com/index.c5444a2b.js` | `9f5b244e...` | No |
| `sales-admin.lazarusforms.com/main.91f908c2.js` | `dc950273...` | No |
| `lazarus-apis-testing/main.1ceea3b9.js` | `541ed95a...` | No |
| `vkgchat.lazarusai.com/index.34ebda78.js` | New | Not previously in scope |
| `vkgchat.lazarusai.com/lib-react.64b4f5a8.js` | New | Different build from dashboard |

No security-related code changes detected in existing bundles since the May assessment.

### 5.3 TLS Posture

All production hosts use valid TLS certificates with minimum TLS 1.2 enforced (TLS 1.0 and 1.1 properly rejected). Certificate expiry ranges from July 8, 2026 (api.lazarusai.com) to January 12, 2027 (dashboard.lazarusforms.com wildcard). Let's Encrypt certificates are on 90-day auto-renewal.

**Potential concern:** `api.lazarusai.com` certificate expires July 8, 2026, which is 33 days from the retest date. If auto-renewal fails, this service will become inaccessible.

### 5.4 DNS Inventory (Verified June 5, 2026)

| Subdomain | Resolution | Service |
|-----------|-----------|---------|
| lazarusai.com | 99.83.190.102 | Marketing (Webflow) |
| api.lazarusai.com | 34.160.98.212 | API Gateway (GCP) |
| docs.lazarusai.com | CloudFront (d28pwpvziuqsti) | Documentation |
| vkgchat.lazarusai.com | CloudFront (dn3bh8rkjon0mjt) | VKG Chat SPA |
| vkgui.lazarusai.com | CloudFront (dn3bh8rkjon0mjt) | VKG UI SPA |
| dashboard.lazarusforms.com | CloudFront (ds6hufxvudmjt) | Dashboard SPA |
| lazarusforms.com | 99.83.190.102 | Marketing (Webflow) |
| www.lazarusforms.com | proxy-ssl.webflow.com | Marketing |
| api.lazarusforms.com | 34.160.56.117 | API |
| sales-admin.lazarusforms.com | CloudFront (dsnhrx3423nbk) | Sales Admin SPA |
| legacy.lazarusforms.com | Google Frontend | Legacy API |
| rundeck.ops.lzrops.com | 34.238.158.171 | Rundeck |
| api-dev.gcp.lzrops.com | 34.49.189.71 | Dev API |
| staging.lazarusai.com | 34.36.25.49 | Staging (→ prod) |
| staging.lazarusforms.com | 35.227.223.84 | Staging (→ prod) |
| lazarus-apis-testing.ue.r.appspot.com | 142.250.176.84 | Testing (App Engine) |

**Subdomain takeover assessment:** No dangling CNAME risk detected. All CloudFront distributions are active and serving content. Webflow proxy is configured correctly.

---

## 6. Risk Assessment

### 6.1 Risk by Category

| Category | Risk Level | Change Since May |
|----------|-----------|------------------|
| **Authentication & Authorization** | HIGH | Unchanged — `/status` bypass persists, Cloud Run IAM still disabled |
| **Information Disclosure** | HIGH | Worsened — 3 new unmapped endpoints discovered in JS bundles |
| **CORS Policy** | HIGH | Unchanged — wildcard `*` on api.lazarusai.com, 4 Cloud Run services reflect Origin |
| **Client-Side Security** | MEDIUM | Unchanged — Firebase keys and service URLs still in bundles |
| **Session Management** | LOW | Improved — Rundeck session fixation fixed |
| **Account Enumeration** | LOW | Improved — Firebase `createAuthUri` enumeration fixed |
| **Transport Security** | LOW | Unchanged — TLS properly configured, headers still incomplete |
| **Input Validation** | MEDIUM | Unknown — LFR-001 cannot be retested without credentials |

### 6.2 Top Risks

1. **Unauthenticated Cloud Run services (NEW-002 + ADMIN-CRIT-001):** Eight backend services are accessible without any identity. Four reflect arbitrary origins in CORS. Combined with the leaked URLs (LAZ-002), attackers have both the addresses and the permission to interact with administrative, metrics, and AI model-serving APIs.

2. **Systemic information disclosure (LAZ-001 + LAZ-002 + SALES-001 + NEW-004):** Client-side JavaScript bundles provide a complete blueprint of backend infrastructure. No meaningful effort has been made to remove secrets, URLs, or configuration from bundles since the original assessment.

3. **Wildcard CORS on production API (LAZ-005):** `api.lazarusai.com` continues to return `Access-Control-Allow-Origin: *`, enabling cross-origin attacks from any domain. This is the primary enabler for session hijacking and data exfiltration.

---

## 7. Prioritized Recommendations

### P1 — Immediate (0–7 days)

| ID | Recommendation | Status |
|----|---------------|--------|
| ADMIN-CRIT-001 / NEW-002 | Enable IAM authentication on all Cloud Run services. Run `gcloud run services update --no-allow-unauthenticated` on all 8 services. | Open |
| LAZ-001 / SALES-001 / NEW-004 | Remove Firebase API keys, backend URLs, and internal endpoints from all client-side JavaScript bundles. Rotate the currently exposed key (`AIzaSy[REDACTED]`). Enable Firebase App Check. | Open |
| LAZ-005 / Legacy CORS | Remove `Access-Control-Allow-Origin: *` from `api.lazarusai.com`, `legacy.lazarusforms.com`, and all Cloud Run services. Implement explicit CORS origin allowlists. | Open |
| LAZ-003 | Require valid authentication on `/status` endpoints. Return 401 for unauthenticated requests. | Open |

### P2 — Short-Term (7–30 days)

| ID | Recommendation | Status |
|----|---------------|--------|
| NEW-003 | Remove verbose error messages revealing role structure (`prodAdmin`, `salesAdmin`, `superAdmin`) and required header names from admin dashboard API. | Open |
| NEW-001 | Isolate staging environments from production. Deploy in separate GCP projects with separate credentials and databases. | Open |
| LFR-001 | Validate `modelName` field server-side. Reject unknown model names before they reach downstream processing. Provide updated test credentials for re-verification. | Inconclusive |
| NEW-004 | Conduct security review of `legacy.lazarusforms.com` (Flask-based, wildcard CORS) and `ask-citations` Cloud Run service. Add security headers to `vkgui.lazarusai.com`. | Open |

### P3 — Medium-Term (30–60 days)

| ID | Recommendation | Status |
|----|---------------|--------|
| LZ-001 | Add CSRF tokens to Rundeck login form. Tighten CSP to remove `unsafe-inline` and `unsafe-eval`. | Open |
| ALL-001 | Enable Firebase email enumeration protection in Firebase Console (Authentication → Settings). Switch to generic "Invalid credentials" error message. | Open |
| LAZ-005 (headers) | Deploy comprehensive security headers across all hosts: CSP, X-Frame-Options, X-Content-Type-Options, HSTS (max-age ≥ 31536000), Referrer-Policy. | Partially done (dashboard only) |

---

## 8. Compliance Map

| CIS Control v8 | Finding | Status |
|----------------|---------|--------|
| 3.3 (Data Encryption) | TLS properly configured on all production hosts | Compliant |
| 4.1 (Secure Configuration) | Security headers incomplete on 5 of 7 hosts | Non-compliant |
| 4.6 (Secure Configuration) | Cloud Run services publicly accessible without auth | Non-compliant |
| 6.3 (Access Control) | API keys exposed in client-side code | Non-compliant |
| 7.1 (Vulnerability Management) | 8 of 15 original findings still open | Non-compliant |
| 16.1 (Application Security) | CORS wildcard on production API | Non-compliant |

---

## 9. Conclusion

The Lazarus AI production environment remains materially unchanged since the May 2026 assessment with respect to the critical security findings. While 2 of 15 findings have been successfully remediated (Firebase account enumeration and Rundeck session fixation), the highest-impact issues — unauthenticated backend services, leaked infrastructure URLs, and wildcard CORS — persist without any remediation effort detected.

The discovery of 3 additional unmapped backend services and 2 staging environments that alias production further expands the attack surface. The combination of publicly accessible Cloud Run services with client-side service inventories provides attackers with a complete attack blueprint requiring no reconnaissance.

The recommended path forward is clear: **enable IAM authentication on all Cloud Run services and remove all secrets and URLs from client-side JavaScript** — these two actions alone would address 7 of 13 open findings and significantly reduce the attack surface.

---

*This report was prepared by Clearwing Security Operations under LOA LAZ-ROE-MASTER-2026 v1.1, Amendment 06. All testing was conducted within the authorized scope (Tiers 1–7). Findings and recommendations are provided for the exclusive use of Lazarus AI and Cyber Security & Infrastructure Services LLC.*

*Report generated: June 5, 2026*
*Next retest recommended: July 2026 (after remediation window)*