# Nightwing Security Assessment — Retest Executive Report

## Lazarus AI Production Environment — Expanded Scope

**Report Date:** June 5, 2026  
**Assessment Type:** Retest — Amendment 06 Re-verification (Expanded Scope)  
**Original Assessment:** May 2026 (Amendments 01–05)  
**Authorization:** LOA LAZ-ROE-MASTER-2026 v1.1, Amendment 06  
**Authorization Code:** CW-2026-LAZARUS-001  
**Authorized Party:** Jon Bethea, Nightwing Security Operations  
**Authorizing CISO:** Jane Doe, Lazarus AI / Cyber Security & Infrastructure Services LLC  

---

## 1. Executive Summary

This report presents the results of a comprehensive retest of the Lazarus AI production environment, conducted under Amendment 06 of the master Letter of Authorization. The retest was initiated to verify remediation of 15 findings from the original May 2026 assessment and to identify new attack surface resulting from environmental changes. After initial regression testing, the scope was expanded to conduct deep-dive enumeration of all newly discovered infrastructure.

**Overall posture has deteriorated since the original assessment.** While 2 of 15 original findings have been confirmed remediated, the attack surface has grown by 143% in hostnames and 420% in publicly accessible endpoints. The most significant discovery is a **publicly exposed 226KB OpenAPI specification** on the lazarus-metrics Cloud Run service that documents 60+ API endpoints including authentication key management, organization CRUD operations, and permission systems — providing attackers with a complete API blueprint requiring zero reconnaissance.

### Finding Status Summary

| Status | Count | Percentage |
|--------|-------|------------|
| Confirmed Remediated | 2 | 13% |
| Still Open (expanded) | 8 | 53% |
| Partially Remediated | 1 | 7% |
| Inconclusive (credentials rotated) | 1 | 7% |
| New Findings (original) | 4 | — |
| **Expanded Scope Findings** | **5** | — |
| **Total Open Findings** | **18** | — |

### Severity Distribution (All Open Findings)

| Severity | Original | New | Expanded Scope | Total Open |
|----------|----------|-----|----------------|------------|
| Critical | 0 | 0 | 1 | 1 |
| High | 1 | 1 | 1 | 3 |
| Medium | 5 | 3 | 2 | 10 |
| Low | 3 | 0 | 1 | 4 |

### Attack Surface Growth Since May 2026

| Category | May 2026 | June 2026 | Delta |
|----------|----------|-----------|-------|
| Unique hostnames | 7 | 17 | +143% |
| Cloud Run services | 6 | 9 | +50% |
| Cloud Functions | 0 | 1 | +1 |
| Publicly accessible endpoints | ~5 | 26+ | +420% |
| OpenAPI specs exposed | 0 | 2 | +2 |
| JS bundles analyzed | 3 | 7 | +133% |
| Hosts with wildcard CORS | 4 | 7 | +75% |

---

## 2. Scope and Methodology

### 2.1 Scope

Full scope retest per LOA Amendment 06, Tiers 1–7:

- **Tier 1:** Public-facing web applications (lazarusai.com, lazarusforms.com, dashboard.lazarusforms.com, dashboard.lazarusai.com, vkgchat.lazarusai.com, vkgui.lazarusai.com, app.lazarusforms.com, status.lazarusforms.com)
- **Tier 2:** API gateways (api.lazarusai.com, api.lazarusforms.com)
- **Tier 3:** Administrative interfaces (sales-admin.lazarusforms.com, rundeck.ops.lzrops.com, forms-admin-dashboard)
- **Tier 4:** Cloud Run services (all 9 discovered backend endpoints + 1 Cloud Function)
- **Tier 5:** Firebase infrastructure (Identity Toolkit, Realtime Database, Firebase Storage)
- **Tier 6:** GCP infrastructure (staging environments, App Engine, legacy.lazarusforms.com)
- **Tier 7:** New subdomains and services discovered during assessment

### 2.2 Methodology

1. **Regression testing** — Re-executed reproduction steps for each of the 15 original findings
2. **Delta discovery** — Full subdomain enumeration, endpoint probing, and Cloud Run service inventory
3. **Environment drift** — JS bundle hash comparison, TLS posture validation, security header baselines
4. **New vector testing** — IDOR on Cloud Run admin endpoints, subdomain takeover assessment, staging isolation verification
5. **Expanded scope enumeration** — Deep-dive on all newly discovered Cloud Run services, OpenAPI specification extraction, CORS policy testing across all endpoints, Firebase configuration audit across all SPAs

### 2.3 Retest Date and Duration

- **Start:** June 5, 2026, 14:30 UTC
- **End:** June 5, 2026, 19:00 UTC
- **Duration:** ~4.5 hours (including expanded scope)

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

**Retest Result:** REMEDIATED. After a failed login attempt, Rundeck regenerates the `JSESSIONID` cookie. The session cookie now uses `SameSite=Lax`, `Secure`, and `HttpOnly` attributes.

**Remediation Quality:** Effective. The session is now invalidated on authentication failure.

---

### 3.2 Still Open — 8 Findings (Expanded Regression)

#### LAZ-001: Firebase API Key Leaked in Production JavaScript Bundles (MEDIUM → OPEN, EXPANDED)

**Original Finding:** Firebase API key embedded in 3 client-side JavaScript bundles.

**Expanded Retest Evidence:** Key `AIzaSy[REDACTED]` is now present in **6 JS bundles** across **6 SPAs**:

| SPA | Bundle | Key Present |
|-----|--------|-------------|
| dashboard.lazarusforms.com | index.c5444a2b.js | ✅ |
| sales-admin.lazarusforms.com | main.91f908c2.js | ✅ |
| vkgchat.lazarusai.com | index.34ebda78.js | ✅ (new scope) |
| vkgui.lazarusai.com | index.357f5560.js | ✅ (new scope) |
| dashboard.lazarusai.com | index.c5444a2b.js | ✅ (new scope) |
| lazarus-apis-testing.ue.r.appspot.com | main.1ceea3b9.js | ✅ (new scope) |

All 6 SPAs share the same Firebase project ID (`lazarus-forms-api`) and Realtime Database URL (`lazarus-forms-api-default-rtdb.firebaseio.com`). The Firebase RTDB security rules correctly deny unauthenticated reads (tested: all paths return `Permission denied`).

**Risk:** The exposed API key enables unauthorized access to Firebase services including Identity Toolkit (account enumeration via `signInWithPassword` — ALL-001), any Firebase service accepting browser API keys, and client-side project configuration. The scope of exposure has doubled from 3 to 6 bundles.

**Recommendation:** Remove Firebase API keys from all client-side bundles. Use environment variable injection at build time. Rotate the currently exposed key and enforce Firebase App Check.

---

#### LAZ-002: Backend Infrastructure URLs Leaked in Client JavaScript (MEDIUM → OPEN, EXPANDED)

**Original Finding:** Client-side JavaScript bundles contain internal backend service URLs and Cloud Run endpoints.

**Expanded Retest Evidence:** **48+ unique backend URLs** across **7 JS bundles**:

| Bundle | Unique Backend URLs | Key Exposure |
|--------|-------------------|--------------|
| dashboard.lazarusforms.com (index) | 13 | Metrics API, user dashboard, Firebase RTDB, Firebase Storage postman-collection |
| dashboard.lazarusforms.com (chunk 830) | 6 | report-demo-bug Cloud Run, demo-output-live Cloud Function |
| sales-admin.lazarusforms.com (main) | 18 | Admin API, admin dashboard, dashboard-prod, usercheck, reset password URLs, remove-MFA Cloud Function |
| vkgchat.lazarusai.com (index) | 4 | ask-citations Cloud Run, legacy.lazarusforms.com, vkgui |
| vkgui.lazarusai.com (index) | 4 | Firebase RTDB, dashboard-prod (update/user), vkgchat |
| dashboard.lazarusai.com (index) | 13 | Same as dashboard.lazarusforms.com |
| dashboard.lazarusai.com (chunk 830) | 6 | Same as dashboard.lazarusforms.com chunk |

Critical new exposures include:
- `https://dashboard.lazarusforms.com/account/resetPassword?accessCode=${accessCode}&user=${email}` — password reset URL template with parameter names
- `https://us-central1-lazarus-forms-api.cloudfunctions.net/remove-mfa` — MFA removal endpoint
- `https://forms-admin-dashboard-685480940293.us-central1.run.app/orgs/models/custom/access` — admin model access endpoint
- `https://v2025-09-29---lazarus-metrics-7owznqu3wq-uc.a.run.app//api/orgs?retrieve_org_id=${t}` — organization retrieval URL template

**Recommendation:** Move all service URLs to server-side configuration. Use API gateway routing instead of direct Cloud Run URLs. Bundle minification alone is insufficient — the URLs remain in string literals.

---

#### LAZ-003: `/status` Endpoint Authentication Bypass (MEDIUM → OPEN, EXPANDED)

**Original Finding:** The `/status` endpoint on `api.lazarusai.com` returns `SUCCESS` with HTTP 200 for any request regardless of authentication state.

**Expanded Retest Evidence:** **9 out of 9 Cloud Run services** return `SUCCESS`/200 on `/status` (or `/`) without any authentication. All accept invalid tokens, random UUIDs, and empty Authorization headers without challenge:

| Service | Unauth `/status` | Invalid Token | Empty Token |
|---------|-------------------|---------------|-------------|
| lazarus-forms-admin-api | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| lazarus-metrics (prod) | 200 SUCCESS+timestamp | 200 SUCCESS+timestamp | 200 SUCCESS+timestamp |
| lazarus-metrics (v2025) | 200 SUCCESS+timestamp | 200 SUCCESS+timestamp | 200 SUCCESS+timestamp |
| forms-admin-dashboard | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| ask-citations | 200 "Request made" | 200 "Request made" | 200 "Request made" |
| report-demo-bug | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| lazarus-apis-testing | 200 (full SPA) | 200 (full SPA) | 200 (full SPA) |
| lazarus-forms-dashboard-prod | 404 (accessible) | 404 | 404 |
| forms-user-dashboard | 404 (accessible) | 404 | 404 |

Additionally, `lazarus-metrics` exposes a `/status` endpoint that returns precise server timestamps (`2026-06-05T03:04:48.230554Z`), enabling time-based attacks.

**Recommendation:** Require valid authentication on all API endpoints including `/status`. Return 401 for unauthenticated requests. Move health checks to separate internal-only endpoints.

---

#### LAZ-005: Missing Security Headers / Permissive CORS (LOW-MEDIUM → PARTIALLY REMEDIATED, EXPANDED)

**Original Finding:** Critical security headers missing across multiple hosts; `api.lazarusai.com` returns `Access-Control-Allow-Origin: *`.

**Expanded Retest Evidence:** Only 3 of 12 hosts have adequate security headers. 6 hosts have wildcard `Access-Control-Allow-Origin: *`:

| Host | CSP | HSTS | X-Frame | X-Content-Type | CORS Policy |
|------|-----|------|---------|---------------|-------------|
| lazarusai.com | ❌ | ✅ | ❌ | ❌ | — |
| api.lazarusai.com | ❌ | ❌ | ❌ | ❌ | **`*`** |
| dashboard.lazarusforms.com | ✅ `frame-ancestors 'self'` | ✅ | ❌ | ✅ nosniff | — |
| dashboard.lazarusai.com | ✅ `frame-ancestors 'self'` | ✅ | ❌ | ✅ nosniff | — |
| sales-admin.lazarusforms.com | ❌ | ❌ | ❌ | ❌ | — |
| vkgchat.lazarusai.com | ❌ | ❌ | ❌ | ❌ | — |
| vkgui.lazarusai.com | ❌ | ❌ | ❌ | ❌ | — |
| legacy.lazarusforms.com | ❌ | ❌ | ❌ | ❌ | **`*`** |
| app.lazarusforms.com | ❌ | ❌ | ❌ | ❌ | **`*`** |
| status.lazarusforms.com | ❌ | ✅ | ❌ | ❌ | **`*`** |
| ask-citations | ❌ | ❌ | ❌ | ❌ | **`*`** |
| report-demo-bug | ❌ | ❌ | ❌ | ❌ | **`*`** |

**Progress since May:** `dashboard.lazarusforms.com` has received CSP, HSTS, X-Content-Type-Options, and Referrer-Policy headers. `dashboard.lazarusai.com` has similar improvements.

**Remaining gaps:** 9 of 12 hosts still lack CSP. 7 hosts use wildcard or reflected CORS. `status.lazarusforms.com` returns HTTP 500 with wildcard CORS.

**Recommendation:** Deploy comprehensive security headers across all hosts. Replace all `Access-Control-Allow-Origin: *` with explicit origin allowlists.

---

#### LZ-001: Rundeck Login Lacks CSRF Protection (LOW → STILL OPEN)

Unchanged from original finding. Login form HTML contains no CSRF token/nonce. CSP allows `unsafe-inline` and `unsafe-eval`.

---

#### ALL-001: Firebase Auth EMAIL_NOT_FOUND Enumeration (LOW → INCONCLUSIVE)

**Original Finding:** `signInWithPassword` returns `EMAIL_NOT_FOUND` for nonexistent accounts vs `INVALID_PASSWORD` for valid ones.

**Retest Result:** INCONCLUSIVE. Firebase Identity Toolkit API calls returned empty responses during expanded retest — likely rate-limited or blocked. The `createAuthUri` vector has been remediated (LAZ-004), but `signInWithPassword` enumeration could not be confirmed or denied in this retest window.

**Recommendation:** Enable Firebase email enumeration protection in Firebase Console (Authentication → Settings). Re-test in next assessment window.

---

#### SALES-001: Sales-Admin JavaScript Bundle Leaks Complete Service Inventory (MEDIUM → OPEN, EXPANDED)

See LAZ-002 — the sales-admin bundle now contains 18 unique backend URLs (up from 5+), including password reset URL templates and a `remove-mfa` Cloud Function endpoint.

---

#### ADMIN-CRIT-001: Admin API Unauthenticated Status + Open CORS (HIGH → OPEN, EXPANDED)

**Original Finding:** The admin-api `/status` endpoint returns `SUCCESS` without auth and reflects arbitrary CORS origins.

**Expanded Retest Evidence:**

- `/status` on `lazarus-forms-admin-api` returns `SUCCESS` with no auth, invalid token, random UUID, or empty token
- `/models/custom` with `adminId: test-admin-id` reveals: `"permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin"` (HTTP 403)
- `/orgs/models/custom/access` reveals required headers: `["adminId", "orgId"]` (HTTP 400)
- CORs: `Origin: https://evil.com` → `Access-Control-Allow-Origin: https://evil.com`

**New Critical Addition:** The `lazarus-metrics` service exposes:
- `GET /api/auth/keys` — Retrieve authentication keys (returns 400: `orgId` required)
- `GET /api/auth/keys/reset` — Reset authentication keys (returns 400: `orgId` required)
- Both endpoints are fully documented in the public OpenAPI specification (EXP-001)

**Recommendation:** Enable IAM authentication on all Cloud Run services. Remove verbose error messages. Remove CORS reflection.

---

### 3.3 Inconclusive — 1 Finding

#### LFR-001: LLM Model Name Not Validated Leading to 500 Crash (MEDIUM → INCONCLUSIVE)

Auth credentials (`authkey`/`orgid`) from `.env` rejected with 403 `AUTH_FAILURE`. Credentials likely rotated since original assessment. Cannot reach model validation layer without updated credentials.

---

## 4. New Findings (Original Delta Discovery)

### NEW-001: Staging Environment Exposes Production Application (MEDIUM)

**Targets:** `staging.lazarusai.com` (34.36.25.49), `staging.lazarusforms.com` (35.227.223.84)

Both staging subdomains resolve to GCP IPs and serve identical content to the production dashboard, with identical JS bundles. They share the same API (`apiversion: 2025-08-07`) and return `Access-Control-Allow-Origin: *`. Staging redirects to `dashboard.lazarusforms.com` — no isolation.

**Recommendation:** Isolate staging in separate GCP projects with separate databases, API keys, and service accounts.

---

### NEW-002: Cloud Run Services Publicly Accessible Without IAM Authentication (HIGH)

All 9 Cloud Run services + 1 Cloud Function are deployed with `--allow-unauthenticated`. See LAZ-003 for detailed `/status` testing. Four services reflect arbitrary CORS origins; 3 use wildcard `*`. Two services expose complete OpenAPI specifications (see EXP-001).

**Recommendation:** Run `gcloud run services update --no-allow-unauthenticated` on all 9 services. Implement Cloud Run IAM invoker roles.

---

### NEW-003: Admin Dashboard API Reveals Role Structure (MEDIUM)

**Target:** `forms-admin-dashboard-685480940293.us-central1.run.app`

- Without `adminId`: `{"requiredFields": ["adminId"], "status": "FAILURE"}` (HTTP 400)
- With test `adminId`: `"permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin"` (HTTP 403)
- `/orgs/models/custom/access`: reveals `["adminId", "orgId"]` requirement

**Recommendation:** Return generic 400/403 responses without field names or role enums.

---

### NEW-004: Previously Unmapped Backend Endpoints (MEDIUM)

**Targets:**
1. `ask-citations-363598527858.us-central1.run.app` — returns 200 for all paths; CORS reveals expected headers (`orgId, authKey, userId, authorization`)
2. `legacy.lazarusforms.com` — Flask app with `/api/rikai/ocr` and `/api/vkg/chat/ask` (405 POST-only); wildcard CORS
3. `vkgui.lazarusai.com` — React SPA on S3/CloudFront with no security headers

**Recommendation:** See expanded findings EXP-002 and EXP-004.

---

## 5. Expanded Scope Findings

### EXP-001: Publicly Exposed OpenAPI Specification (CRITICAL)

**Targets:**
- `lazarus-metrics-685480940293.us-central1.run.app`
- `v2025-09-29---lazarus-metrics-7owznqu3wq-uc.a.run.app`

Both services expose `/docs` (interactive Swagger UI) and `/openapi.json` (226KB OpenAPI 3.1.0 specification) **without any authentication**.

The specification documents **60+ API endpoints** including:

**Authentication & Key Management:**
- `GET /api/auth` — Authenticate organization
- `GET /api/auth/org` — Authenticate and get usage info
- `GET /api/auth/keys` — **Retrieve authentication keys**
- `GET /api/auth/keys/reset` — **Reset authentication keys**
- `GET /api/auth/keys/reset/dual-write` — Reset keys (dual-write compatible)

**Organization Management (CRUD):**
- `GET /api/orgs` — Get organization
- `POST /api/orgs` — **Create organization**
- `PUT /api/orgs` — **Update organization**
- `GET /api/orgs/all` — **List all organizations**
- `DELETE /api/orgs/{delete_org_id}` — **Delete organization**

**Model Management (CRUD):**
- `GET /api/models` — Get model
- `POST /api/models` — **Create model**
- `PUT /api/models` — **Update model**
- `DELETE /api/models/{delete_model_id}` — **Delete model**

**Permissions & Access Control:**
- `GET /api/org-perms/all` — List all org permissions
- `POST /api/org-perms/grant` — **Grant org permissions**
- `POST /api/org-perms/revoke` — Revoke org permissions
- `GET /api/model-access` — Check model access
- `POST /api/model-access/grant` — **Grant model access**

**Usage & Limits:**
- `GET /api/limits/hard-limit-orgs` — **List orgs with active hard limits**
- `POST /api/limits/{type}` — Add usage limit
- `POST /api/usage/send-notification` — Send notification
- `GET /api/queues/all` — List all queues

**Logs & Requests:**
- `POST /api/logs` — Get logs
- `GET /api/logs/{request_id}` — Get specific log
- `POST /api/requests/bulk` — Bulk async requests

The specification also contains **50+ data model schemas** including `OrganizationRequest`, `OrganizationUpdateRequest`, `BulkAsyncRequestInsert`, `LimitPostRequest`, `RequestInsert`, and more — providing a complete data layer blueprint.

**Impact Assessment:** The data endpoints require `orgId` and `authKey` headers (403 with test credentials), but the full API specification is publicly accessible. This represents the most significant information disclosure in this assessment. An attacker now has:
1. A complete map of every API endpoint and its parameters
2. Data schema definitions for precise request crafting
3. Knowledge of auth key retrieval and reset endpoints
4. Understanding of the org/model/permissions hierarchy
5. Attack surface enumeration requiring zero reconnaissance effort

**Recommendation:** Immediately restrict access to `/docs` and `/openapi.json` on both lazarus-metrics services. Implement IAM authentication. Remove Swagger UI from production deployments.

---

### EXP-002: Ask-Citations Service Catch-All 200 Response (HIGH)

**Target:** `ask-citations-363598527858.us-central1.run.app`

This Cloud Run service returns HTTP 200 `"Request made"` for **every path** including `/.env`, `/admin/shutdown`, `/swagger/.env`, and `/this/does/not/exist`. The catch-all response makes it impossible to enumerate valid endpoints or detect unauthorized access via log analysis.

- POST with JSON body returns: `{"error": "'vkg'","message": "Invalid JSON"}` (HTTP 503) — reveals internal field name `vkg`
- Accepts GET, PUT, PATCH, DELETE (all return 200 `"Request made"`)
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- CORS preflight reveals expected headers: `Content-Type, orgId, authKey, userId, authorization`

**Risk:** The service accepts LLM/AI citation requests from any origin without authentication. The catch-all 200 response defeats endpoint monitoring and incident detection. The error message leaks the internal schema field name (`vkg`).

**Recommendation:** Remove catch-all routing. Implement proper 404 responses for invalid routes. Require authentication for POST requests. Remove wildcard CORS.

---

### EXP-003: Report-Demo-Bug PII Collection Without Authentication (MEDIUM)

**Target:** `report-demo-bug-685480940293.us-central1.run.app`

Returns `{"status":"Success"}` for `/`, `/status`, and `/health` without authentication. Wildcard CORS (`Access-Control-Allow-Origin: *`). CORS headers reveal that the service expects: `userid, email, orgid, description, url` — personally identifiable information that can be submitted from any origin without authentication.

**Risk:** Spammers or attackers could inject fabricated bug reports containing PII, potentially poisoning the bug tracking pipeline or conducting phishing through the system.

**Recommendation:** Require authentication for bug report submission. Add rate limiting. Restrict CORS to authorized origins only.

---

### EXP-004: App.lazarusforms.com Flask Session Leak (LOW-MEDIUM)

**Target:** `app.lazarusforms.com`

- Sets session cookie with `{"identifier": null}` on every request (including unauthenticated)
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- No security headers (no CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Confirmed endpoints: `/api/rikai/ocr` and `/api/vkg/chat/ask` (403 with test auth headers)
- Redirects to `/login` → `dashboard.lazarusforms.com`

**Risk:** The leaked session structure reveals the Flask session format, enabling session forgery attempts. The wildcard CORS allows cross-origin API interaction from any domain.

**Recommendation:** Remove wildcard CORS. Set session cookies only on authenticated sessions. Add security headers.

---

### EXP-005: Status.lazarusforms.com Broken Status Page (LOW)

**Target:** `status.lazarusforms.com` (Hyperping/Vercel)

- Returns HTTP 500 with a Next.js client-side exception error page
- Leaks Next.js build ID: `RO0rtrAECgsc0V9exOOuo`
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- Cache tags reveal host: `sp:host:status.lazarusforms.com`
- Aggressive caching: `age: 210263` (2.4 days), `s-maxage: 31536000` (1 year)

**Risk:** Framework and build ID disclosure assists targeted attacks. The persistent 500 error suggests the status page is non-functional. The 1-year cache directive means the error page is served from CDN cache indefinitely.

**Recommendation:** Fix the 500 error. Remove build ID from error pages. Reduce cache durations for error responses.

---

## 6. Environment Drift Analysis

### 6.1 Attack Surface Changes Since May 2026

| Change | Risk Impact |
|--------|------------|
| 9 new hostnames not in original scope | +143% attack surface |
| 3 new Cloud Run services (ask-citations, report-demo-bug, metrics v2025) | +50% backend services |
| 1 Cloud Function (demo-output-live) | New serverless attack surface |
| 2 publicly exposed OpenAPI specifications (226KB) | CRITICAL — complete API blueprint |
| 7 hosts with wildcard CORS (was 4) | +75% CORS misconfiguration |
| 6 bundles with Firebase API key (was 3) | +100% key exposure |
| staging environments alias production | No staging isolation |
| JS bundles unchanged from May 2026 | No code hardening detected |

### 6.2 JavaScript Bundle Integrity

| Bundle | Changed? | Firebase Key | Backend URLs |
|--------|----------|-------------|-------------|
| dashboard.lazarusforms.com/index.c5444a2b.js | No | ✅ | 13 |
| dashboard.lazarusforms.com/830.a5cac9f9.js | No | — | 6 |
| sales-admin.lazarusforms.com/main.91f908c2.js | No | ✅ | 18 |
| vkgchat.lazarusai.com/index.34ebda78.js | New | ✅ | 4 |
| vkgui.lazarusai.com/index.357f5560.js | New | ✅ | 4 |
| dashboard.lazarusai.com/index.c5444a2b.js | New | ✅ | 13 |
| dashboard.lazarusai.com/830.a5cac9f9.js | New | — | 6 |

### 6.3 Complete DNS Inventory (Verified June 5, 2026)

| Subdomain | Resolution | Service |
|-----------|-----------|----------|
| lazarusai.com | 99.83.190.102 | Marketing (Webflow) |
| www.lazarusai.com | proxy-ssl.webflow.com | Marketing |
| api.lazarusai.com | 34.160.98.212 | API Gateway (GCP) |
| docs.lazarusai.com | CloudFront (d28pwpvziuqsti) | Documentation |
| dashboard.lazarusai.com | CloudFront (d2r0ddpke5vjsc) | Dashboard SPA |
| vkgchat.lazarusai.com | CloudFront (dn3bh8rkjon0mjt) | VKG Chat SPA |
| vkgui.lazarusai.com | CloudFront (dn3bh8rkjon0mjt) | VKG UI SPA |
| lazarusforms.com | 99.83.190.102 | Marketing (Webflow) |
| www.lazarusforms.com | proxy-ssl.webflow.com | Marketing |
| api.lazarusforms.com | 34.160.56.117 | API |
| dashboard.lazarusforms.com | CloudFront (ds6hufxvudmjt) | Dashboard SPA |
| sales-admin.lazarusforms.com | CloudFront (dsnhrx3423nbk) | Sales Admin SPA |
| app.lazarusforms.com | ghs.googlehosted.com | App server (Flask) |
| legacy.lazarusforms.com | Google Frontend | Legacy API (Flask) |
| vkg.lazarusforms.com | CloudFront (d1un8pqhr88jxl) | VKG frontend |
| status.lazarusforms.com | cname.hyperping.io | Status page (broken) |
| rundeck.ops.lzrops.com | 34.238.158.171 | Rundeck |
| api-dev.gcp.lzrops.com | 34.49.189.71 | Dev API |
| staging.lazarusai.com | 34.36.25.49 | Staging (→ prod) |
| staging.lazarusforms.com | 35.227.223.84 | Staging (→ prod) |
| lazarus-apis-testing.ue.r.appspot.com | 142.250.176.84 | Testing (App Engine) |

**Cloud Run services (all publicly accessible):**

| Service | Unauth `/status` | CORS | OpenAPI |
|---------|-------------------|------|---------|
| lazarus-forms-admin-api | 200 SUCCESS | Reflects Origin | No |
| lazarus-forms-dashboard-prod | 404 | Reflects Origin | No |
| forms-user-dashboard | 404 | Reflects Origin | No |
| lazarus-metrics (prod) | 200 SUCCESS+timestamp | Wildcard `*` | **Yes** |
| forms-admin-dashboard | 200 SUCCESS | Reflects Origin | No |
| lazarus-metrics (v2025) | 200 SUCCESS+timestamp | Wildcard `*` | **Yes** |
| ask-citations | 200 "Request made" | Wildcard `*` | No |
| report-demo-bug | 200 SUCCESS | Wildcard `*` | No |
| lazarus-apis-testing | 200 (full SPA) | No CORS | No |

**Cloud Functions:** `us-central1-lazarus-forms-api.cloudfunctions.net/demo-output-live` — returns `"Request made"` without auth.

---

## 7. Risk Assessment

### 7.1 Risk by Category

| Category | Risk Level | Change Since May |
|----------|-----------|------------------|
| **Information Disclosure** | **CRITICAL** | Worsened — public OpenAPI spec, expanded JS bundle leakage |
| **Authentication & Authorization** | HIGH | Unchanged — `/status` bypass persists, IAM still disabled |
| **CORS Policy** | HIGH | Worsened — 7 hosts with wildcard/reflected CORS (was 4) |
| **Client-Side Security** | MEDIUM | Worsened — key now in 6 bundles (was 3), 48+ URLs leaked |
| **Session Management** | LOW | Improved — Rundeck session fixation fixed |
| **Account Enumeration** | LOW | Improved — `createAuthUri` fixed; `signInWithPassword` inconclusive |
| **Transport Security** | LOW | Unchanged — TLS properly configured, headers still incomplete |
| **Input Validation** | MEDIUM | Unknown — LFR-001 cannot be retested without credentials |

### 7.2 Top Risks

1. **Publicly exposed OpenAPI specification (EXP-001):** The lazarus-metrics services expose a 226KB specification documenting 60+ endpoints including auth key management, organization CRUD, and permissions. This provides attackers with a complete API blueprint requiring zero reconnaissance. Combined with unauthenticated Cloud Run access (NEW-002), an attacker who obtains valid credentials has full knowledge of every operation they can perform.

2. **Unauthenticated Cloud Run services (NEW-002 + ADMIN-CRIT-001):** Nine backend services are accessible without IAM authentication. Four reflect arbitrary CORS origins. Combined with the leaked URLs (LAZ-002), attackers have both the addresses and the permission to interact with administrative, metrics, and AI model-serving APIs.

3. **Systemic information disclosure (LAZ-001 + LAZ-002 + SALES-001 + NEW-004):** Client-side JavaScript bundles provide a complete blueprint of backend infrastructure across 7 bundles. The scope of exposure has expanded from 3 to 6 bundles and from 5+ to 48+ leaked URLs. No meaningful effort has been made to remove secrets, URLs, or configuration from bundles since the original assessment.

4. **Wildcard CORS on production APIs (LAZ-005):** Seven hosts return `Access-Control-Allow-Origin: *`, enabling cross-origin attacks from any domain. This is the primary enabler for session hijacking and data exfiltration from authenticated users.

---

## 8. Prioritized Recommendations

### P1 — Immediate (0–7 days)

| ID | Recommendation | Impact |
|----|---------------|--------|
| EXP-001 | Restrict access to `/docs` and `/openapi.json` on lazarus-metrics services. Remove Swagger UI from production. | Eliminates complete API blueprint exposure |
| ADMIN-CRIT-001 / NEW-002 | Enable IAM authentication on all 9 Cloud Run services. Run `gcloud run services update --no-allow-unauthenticated`. | Eliminates unauthenticated access to 9 backend services |
| LAZ-001 / SALES-001 / NEW-004 | Remove Firebase API keys, backend URLs, and internal endpoints from all 7 client-side JavaScript bundles. Rotate the exposed key. Enable Firebase App Check. | Eliminates infrastructure blueprint from client code |
| LAZ-005 / EXP-004 | Remove `Access-Control-Allow-Origin: *` from all 7 hosts (api.lazarusai.com, legacy.lazarusforms.com, app.lazarusforms.com, status.lazarusforms.com, ask-citations, report-demo-bug, lazarus-metrics). Implement explicit CORS origin allowlists. | Closes cross-origin attack vector |
| LAZ-003 | Require valid authentication on all `/status` endpoints. Return 401 for unauthenticated requests. | Eliminates health-check reconnaissance |

### P2 — Short-Term (7–30 days)

| ID | Recommendation | Impact |
|----|---------------|--------|
| NEW-003 | Remove verbose error messages revealing role structure and header names. Return generic 400/403 responses. | Eliminates privilege escalation reconnaissance |
| NEW-001 | Isolate staging environments from production in separate GCP projects with separate credentials. | Prevents staging → production lateral movement |
| EXP-002 | Remove catch-all 200 routing from ask-citations. Implement 404 for invalid routes. Require authentication for POST. | Eliminates endpoint obfuscation and unauthorized AI access |
| EXP-003 | Require authentication for bug report submission on report-demo-bug. Restrict CORS. Add rate limiting. | Prevents PII injection into bug tracking |
| LFR-001 | Validate `modelName` server-side. Provide updated test credentials for re-verification. | Closes potential DoS vector |

### P3 — Medium-Term (30–60 days)

| ID | Recommendation | Impact |
|----|---------------|--------|
| LZ-001 | Add CSRF tokens to Rundeck login forms. Remove `unsafe-inline` and `unsafe-eval` from CSP. | Closes CSRF vulnerability |
| ALL-001 | Enable Firebase email enumeration protection. Switch to generic "Invalid credentials" error. | Closes remaining enumeration vector |
| LAZ-005 (headers) | Deploy comprehensive security headers across all 12 hosts: CSP, X-Frame-Options, X-Content-Type-Options, HSTS (≥31536000), Referrer-Policy. | Hardens browser security posture |
| EXP-005 | Fix status.lazarusforms.com 500 error. Remove build ID from error pages. Reduce error cache duration. | Eliminates framework disclosure |

---

## 9. Compliance Map

| CIS Control v8 | Finding | Status |
|----------------|---------|--------|
| 3.3 (Data Encryption) | TLS properly configured on all production hosts | Compliant |
| 4.1 (Secure Configuration) | Security headers incomplete on 9 of 12 hosts | Non-compliant |
| 4.6 (Secure Configuration) | Cloud Run services publicly accessible without auth | Non-compliant |
| 6.3 (Access Control) | API keys exposed in client-side code | Non-compliant |
| 6.5 (Access Control) | Publicly exposed OpenAPI specification (226KB) | Non-compliant |
| 7.1 (Vulnerability Management) | 8 of 15 original findings still open | Non-compliant |
| 16.1 (Application Security) | Wildcard CORS on 7 production hosts | Non-compliant |
| 16.5 (Application Security) | 48+ backend URLs leaked in client JS | Non-compliant |

---

## 10. Conclusion

The Lazarus AI production environment has **deteriorated** since the May 2026 assessment. While 2 of 15 original findings have been remediated (Firebase account enumeration and Rundeck session fixation), the attack surface has expanded by 143% in hostnames and 420% in publicly accessible endpoints. The most significant new discovery is the **publicly exposed OpenAPI specification** on the lazaurus-metrics service, which provides attackers with a complete 60+ endpoint API blueprint including authentication key management, organization CRUD, and permission systems — requiring zero reconnaissance effort.

The systemic issues identified in the original assessment remain unaddressed:
- Cloud Run services continue to run without IAM authentication
- Firebase API keys and backend URLs remain in client-side JavaScript bundles
- Wildcard CORS policies persist across production APIs

The recommended path forward is clear: **enable IAM authentication on all Cloud Run services, remove the OpenAPI specification from public access, and eliminate all secrets and URLs from client-side JavaScript** — these three actions address 10 of 18 open findings and dramatically reduce the attack surface.

---

*This report was prepared by Nightwing Security Operations under LOA LAZ-ROE-MASTER-2026 v1.1, Amendment 06. All testing was conducted within the authorized scope (Tiers 1–7). Findings and recommendations are provided for the exclusive use of Lazarus AI and Cyber Security & Infrastructure Services LLC.*

*Report generated: June 5, 2026*  
*Next retest recommended: July 2026 (after remediation window)*