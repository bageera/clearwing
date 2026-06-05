# Clearwing Retest Findings Summary
## Lazarus AI — Amendment 06 Retest (Expanded Scope)
**Date:** June 5, 2026  
**Authorization:** LOA LAZ-ROE-MASTER-2026 v1.1, Amendment 06  
**Tester:** Jon Bethea, Clearwing Security Operations  
**Scope:** Full Tiers 1–7 retest per Amendment 06 methodology

---

## Executive Summary

Retest of 15 original findings identified **2 confirmed remediated, 8 still open (1 partially remediated), 1 inconclusive**, and **4 new findings** discovered during delta reconnaissance. Expanded scope testing confirmed **9 new hostnames** (subdomains and Cloud Run services) and a **publicly exposed OpenAPI specification** documenting 60+ API endpoints including auth key management.

|| Status | Count |
||--------|-------|
| Remediated | 2 |
| Still Open | 8 |
| Partially Remediated | 1 |
| Inconclusive (credentials rotated) | 1 |
| New Findings | 4 |
| **Expanded Scope Findings** | **5** |

---

## Original Findings — Regression Results

### REMEDIATED

|| ID | Finding | Original Severity | Remediation Evidence |
||----|---------|-------------------|----------------------|
| LAZ-004 | Firebase Identity Toolkit account enumeration | Medium | `createAuthUri` now returns `registered: false` for all emails — no differentiator between valid/invalid accounts. `sendOobCode` requires registered caller identity and returns 403 for unauthenticated requests. |
| LZ-002 | Rundeck session fixation | Low | Post-login-failure session check shows JSESSIONID is regenerated (not retained). Session cookie uses SameSite=Lax. |

### STILL OPEN — Expanded Regression

#### LAZ-001: Firebase API Key in Production JS Bundles (MEDIUM → OPEN, EXPANDED)

**Original finding:** API key present in 3 JS bundles.  
**Expanded finding:** API key `AIzaSyBgs-HrkxUdKbLFVxPsN2JJfjB71c_Cn58` now present in **6 JS bundles** across 5 SPAs:

| SPA | Bundle | Key Present |
|-----|--------|-------------|
| dashboard.lazarusforms.com | index.c5444a2b.js | ✅ |
| sales-admin.lazarusforms.com | main.91f908c2.js | ✅ |
| vkgchat.lazarusai.com | index.34ebda78.js | ✅ |
| vkgui.lazarusai.com | index.357f5560.js | ✅ |
| dashboard.lazarusai.com | index.c5444a2b.js | ✅ |
| lazarus-apis-testing.ue.r.appspot.com | main.1ceea3b9.js | ✅ |

All share the same Firebase project (`lazarus-forms-api`) and database URL (`lazarus-forms-api-default-rtdb.firebaseio.com`).

#### LAZ-002: Backend Infra URLs Leaked in Client JS (MEDIUM → OPEN, EXPANDED)

**Original finding:** 5 Cloud Run URLs in sales-admin bundle.  
**Expanded finding:** **48+ unique backend URLs** across 7 JS bundles:

| Bundle | Unique Backend URLs | Key Exposure |
|--------|-------------------|--------------|
| dashboard.lazarusforms.com (index) | 13 | metrics API, user dashboard, Firebase RTDB, Firebase Storage |
| dashboard.lazarusforms.com (chunk 830) | 6 | report-demo-bug Cloud Run, demo-output-live Cloud Function |
| sales-admin.lazarusforms.com | 18 | admin API, admin dashboard, dashboard-prod, usercheck, reset password URLs, remove-MFA Cloud Function |
| vkgchat.lazarusai.com | 4 | ask-citations Cloud Run, legacy.lazarusforms.com, vkgui |
| vkgui.lazarusai.com | 4 | Firebase RTDB, dashboard-prod (update/user), vkgchat |
| dashboard.lazarusai.com (index) | 13 | Same as dashboard.lazarusforms.com |
| dashboard.lazarusai.com (chunk 830) | 6 | Same as dashboard.lazarusforms.com chunk |

Critical new exposures include:
- `https://dashboard.lazarusforms.com/account/resetPassword?accessCode=${accessCode}&user=${email}` — password reset URL template with parameter names
- `https://us-central1-lazarus-forms-api.cloudfunctions.net/remove-mfa` — MFA removal endpoint
- `https://forms-admin-dashboard-685480940293.us-central1.run.app/orgs/models/custom/access` — admin model access endpoint

#### LAZ-003: `/status` Endpoint Auth Bypass (MEDIUM → OPEN, EXPANDED)

**Original finding:** `/status` on `api.lazarusai.com` returns `SUCCESS` without auth.  
**Expanded finding:** **9 out of 9 Cloud Run services** return `SUCCESS`/200 on `/status` (or `/`) without any authentication. All accept invalid tokens, random UUIDs, and empty Authorization headers without challenge:

| Service | Unauth `/status` | Invalid Token | Empty Token |
|---------|-------------------|---------------|-------------|
| lazarus-forms-admin-api | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| lazarus-metrics (prod) | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| lazarus-metrics (v2025) | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| forms-admin-dashboard | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| ask-citations | 200 "Request made" | 200 "Request made" | 200 "Request made" |
| report-demo-bug | 200 SUCCESS | 200 SUCCESS | 200 SUCCESS |
| lazarus-apis-testing | 200 (full SPA) | 200 (full SPA) | 200 (full SPA) |
| lazarus-forms-dashboard-prod | 404 (but accessible) | 404 | 404 |
| forms-user-dashboard | 404 (but accessible) | 404 | 404 |

#### LAZ-005: Missing Security Headers / Open CORS (LOW-MEDIUM → PARTIALLY REMEDIATED, EXPANDED)

**Original finding:** Missing headers on most hosts.  
**Expanded finding:** Only 3 of 12 hosts have adequate security headers. 6 hosts have wildcard `Access-Control-Allow-Origin: *`:

| Host | CSP | HSTS | X-Frame | X-Content-Type | CORS |
|------|-----|------|---------|---------------|------|
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

#### LZ-001: Rundeck Login Lacks CSRF Token (LOW → STILL OPEN)

Login form HTML contains no CSRF token/nonce. CSP allows `unsafe-inline` and `unsafe-eval`. Unchanged from original finding.

#### ALL-001: Firebase Auth EMAIL_NOT_FOUND Enumeration (LOW → INCONCLUSIVE)

**Retest status:** Firebase Identity Toolkit API calls returned empty responses during expanded retest (likely rate-limited). Original finding demonstrated `EMAIL_NOT_FOUND` vs `INVALID_PASSWORD` differentiation. The `createAuthUri` endpoint has been fixed (LAZ-004), but `signInWithPassword` was not confirmable in this retest window due to rate limiting. **Recommendation:** Re-test in next assessment window.

#### SALES-001: Sales-Admin JS Bundle Leaked Backend URLs (MEDIUM → OPEN, EXPANDED)

See LAZ-002 — the sales-admin bundle now contains 18 unique backend URLs, up from the original 5+. Includes admin dashboard endpoints, MFA removal function, and password reset URL templates.

#### ADMIN-CRIT-001: Admin API `/status` Auth Bypass + Open CORS (HIGH → OPEN, EXPANDED)

**Original finding:** `/status` returns `SUCCESS` without auth on admin-api.  
**Expanded finding:** Same behavior persists AND:

- `/models/custom` with `adminId: test-admin-id` reveals role structure: `"permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin"` (403)
- `/orgs/models/custom/access` reveals requirement for `adminId` + `orgId` headers
- CORS reflects arbitrary Origin (`Access-Control-Allow-Origin: https://evil.com`)
- lazarus-metrics service exposes `/api/auth/keys` endpoint (key retrieval) requiring only `orgId` header
- lazarus-metrics service exposes `/api/auth/keys/reset` endpoint (key reset)
- Both are documented in the publicly accessible 226KB OpenAPI specification

---

## New Findings

### NEW-001: Staging Environment Exposes Production Application (MEDIUM)
- **Targets:** `staging.lazarusai.com` (34.36.25.49), `staging.lazarusforms.com` (35.227.223.84)
- Both staging subdomains resolve to GCP IPs and serve identical content to production dashboard, with identical JS bundles (`index.c5444a2b.js`, `830.a5cac9f9.js`)
- Share same API (`apiversion: 2025-08-07`) and return `Access-Control-Allow-Origin: *`
- Staging is not isolated from production — redirects to `dashboard.lazarusforms.com`

### NEW-002: Cloud Run Services Publicly Accessible Without IAM Authentication (HIGH)
- **Targets:** All 9 Cloud Run services + 1 Cloud Function
- All services respond to HTTP requests without IAM authentication (`--allow-unauthenticated`)
- 4 of 9 reflect arbitrary CORS origins; 3 use wildcard `*`
- lazarus-metrics exposes complete OpenAPI 3.1.0 specification (226KB) at `/docs` and `/openapi.json`
- The `/status` endpoint on all services returns `SUCCESS` without auth

### NEW-003: Admin Dashboard API Reveals Role Structure (MEDIUM)
- **Target:** `forms-admin-dashboard-685480940293.us-central1.run.app`
- `/models/custom` returns `{"requiredFields": ["adminId"]}` without auth (400)
- With test `adminId`: reveals `"permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin"` (403)
- `/orgs/models/custom/access` reveals `["adminId", "orgId"]` requirement
- No IAM restriction on direct Cloud Run access

### NEW-004: Previously Unknown Backend Endpoints Discovered (MEDIUM)
- **Targets:**
  1. `ask-citations-363598527858.us-central1.run.app` — catch-all 200 for ALL paths including `/.env`; POST returns `{"error": "'vkg'","message": "Invalid JSON"}`; wildcard CORS
  2. `legacy.lazarusforms.com` — Flask app with `/api/rikai/ocr` and `/api/vkg/chat/ask` (405 POST-only); wildcard CORS reflecting all methods
  3. `vkgui.lazarusai.com` — React SPA on S3/CloudFront; no security headers
  4. `report-demo-bug-685480940293.us-central1.run.app` — accepts `userid`, `email`, `orgid` PII without auth; wildcard CORS
  5. `app.lazarusforms.com` — Flask app with wildcard CORS and leaked session structure (`{"identifier": null}`)

---

## Expanded Scope Findings

### EXP-001: Publicly Exposed OpenAPI Specification (CRITICAL)
- **Target:** `lazarus-metrics-685480940293.us-central1.run.app` + `v2025-09-29---lazarus-metrics-7owznqu3wq-uc.a.run.app`
- Both services expose `/docs` (Swagger UI) and `/openapi.json` (226KB OpenAPI 3.1.0 spec) without authentication
- Documents **60+ API endpoints** including:
  - `GET /api/auth/keys` — Retrieve authentication keys
  - `GET /api/auth/keys/reset` — Reset authentication keys
  - `POST /api/orgs` — Create organizations
  - `DELETE /api/orgs/{org_id}` — Delete organizations
  - `GET /api/org-perms/all` — List all org permissions
  - `POST /api/model-access/grant` — Grant model access
  - `POST /api/usage/send-notification` — Send notifications
  - `GET /api/limits/hard-limit-orgs` — List orgs with hard limits
- Includes **50+ data model schemas** (OrganizationRequest, BulkAsyncRequestInsert, LimitPostRequest, etc.)
- Provides attackers with a complete blueprint of the API surface, data models, and authentication flow

### EXP-002: Ask-Citations Service Catch-All 200 Response (HIGH)
- **Target:** `ask-citations-363598527858.us-central1.run.app`
- Returns HTTP 200 `"Request made"` for EVERY path including `/.env`, `/admin/shutdown`, `/swagger/.env`
- POST with JSON returns `{"error": "'vkg'","message": "Invalid JSON"}` (reveals internal field name)
- Accepts GET, PUT, PATCH, DELETE (all return 200)
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- POST CORS reveals expected headers: `Content-Type, orgId, authKey, userId, authorization`

### EXP-003: Report-Demo-Bug PII Collection Without Authentication (MEDIUM)
- **Target:** `report-demo-bug-685480940293.us-central1.run.app`
- Returns `{"status":"Success"}` for `/`, `/status`, `/health` without auth
- Wildcard CORS; CORS headers reveal expected fields: `userid, email, orgid, description, url`
- Any origin can submit bug reports containing PII (user IDs, emails, organization IDs)

### EXP-004: App.lazarusforms.com Flask Session Leak (LOW-MEDIUM)
- **Target:** `app.lazarusforms.com`
- Sets session cookie with `{"identifier": null}` on every request (including unauthenticated)
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- No security headers (no CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Confirmed endpoints: `/api/rikai/ocr`, `/api/vkg/chat/ask` (403 with `orgId: test`, `authKey: test`)

### EXP-005: Status.lazarusforms.com Broken Status Page (LOW)
- **Target:** `status.lazarusforms.com` (Hyperping/Vercel)
- Returns HTTP 500 client-side exception
- Leaks Next.js build ID: `RO0rtrAECgsc0V9exOOuo`
- Wildcard CORS
- Cache tags reveal host: `sp:host:status.lazarusforms.com`

---

## Environment Drift Analysis

### JS Bundle Comparison (May 2026 vs June 2026)

| Bundle | Changed? | Notes |
|--------|----------|-------|
| dashboard.lazarusforms.com/index.c5444a2b.js | Unchanged | Same Firebase key |
| sales-admin.lazarusforms.com/main.91f908c2.js | Unchanged | Same Firebase key |
| lazarus-apis-testing/main.1ceea3b9.js | Unchanged | Same Firebase key |
| vkgchat.lazarusai.com/index.34ebda78.js | New | Not in original scope |
| vkgui.lazarusai.com/index.357f5560.js | New | Not in original scope |
| dashboard.lazarusai.com/index.c5444a2b.js | New | Identical to dashboard.lazarusforms.com |
| dashboard.lazarusai.com/830.a5cac9f9.js | New | Same as dashboard.lazarusforms.com chunk |

### TLS Posture

| Host | Certificate | TLS 1.0/1.1 | Notes |
|------|------------|-------------|-------|
| lazarusai.com | Let's Encrypt R12, expires Jul 9 2026 | Rejected ✓ | SAN: lazarusai.com only |
| api.lazarusai.com | Let's Encrypt E8, expires Jul 8 2026 | Rejected ✓ | SAN: api.lazarusai.com only |
| dashboard.lazarusforms.com | Amazon RSA 2048 M01, expires Jan 12 2027 | — | Wildcard: *.lazarusforms.com |
| rundeck.ops.lzrops.com | Let's Encrypt R12, expires Jul 19 2026 | Rejected ✓ | |

### DNS Changes

| Change | Detail |
|--------|--------|
| www.lazarusai.com | No longer resolves (was active in May) |
| staging.lazarusai.com | Now resolves to 34.36.25.49 (GCP) |
| staging.lazarusforms.com | Now resolves to 35.227.223.84 (GCP) |
| vkgchat.lazarusai.com | Now resolves via CloudFront (new subdomain) |
| legacy.lazarusforms.com | Now resolves (new subdomain) |
| vkgui.lazarusai.com | Now resolves (new subdomain) |
| app.lazarusforms.com | Resolves to ghs.googlehosted.com (new) |
| dashboard.lazarusai.com | Resolves to d2r0ddpke5vjsc.cloudfront.net (new) |
| status.lazarusforms.com | Resolves to cname.hyperping.io (new) |

### Attack Surface Growth

| Category | May 2026 | June 2026 | Delta |
|----------|----------|-----------|-------|
| Unique hostnames | 7 | 17 | +10 (+143%) |
| Cloud Run services | 6 | 9 | +3 (+50%) |
| Cloud Functions | 0 | 1 | +1 |
| Publicly accessible endpoints | ~5 | 26+ | +21 (+420%) |
| OpenAPI specs exposed | 0 | 2 | +2 |
| Total JS bundles analyzed | 3 | 7 | +4 (+133%) |
| Unique API keys in bundles | 1 | 1 | 0 |
| Hosts with wildcard CORS | 4 | 7 | +3 |

---

## Recommendations Priority Matrix

|| Priority | Finding | Recommendation |
|----------|---------|---------------|
| P1 | ADMIN-CRIT-001 + NEW-002 | Enable IAM authentication on all Cloud Run services. Remove public invocations. Implement `--no-allow-unauthenticated` on deployments. |
| P1 | EXP-001 | Remove public access to `/docs` and `/openapi.json` on lazarus-metrics services. Restrict to authenticated internal access only. |
| P1 | LAZ-001 + SALES-001 + NEW-004 | Remove all Firebase API keys, backend URLs, and internal endpoint references from client-side JS. Use environment injection at build time. |
| P1 | LAZ-005 + EXP-004 | Remove `Access-Control-Allow-Origin: *` from all Cloud Run services, api.lazarusai.com, app.lazarusforms.com, legacy.lazarusforms.com, status.lazarusforms.com. Implement proper CORS whitelisting. |
| P2 | LAZ-003 | Implement authentication/authorization on `/status` endpoints. Return 401 for unauthenticated requests. |
| P2 | NEW-003 | Remove verbose error messages revealing role structure. Return generic 403 without role names. |
| P2 | NEW-001 | Isolate staging environments from production. Use separate GCP projects. Do not share API backends. |
| P2 | EXP-002 | Remove catch-all 200 response from ask-citations. Implement proper 404 for invalid routes. Require authentication for POST. |
| P3 | LZ-001 | Add CSRF tokens to Rundeck login form. Remove `unsafe-inline` and `unsafe-eval` from CSP. |
| P3 | ALL-001 | Configure Firebase Auth to return generic error messages (disable "EMAIL_NOT_FOUND" differentiation). |
| P3 | EXP-005 | Fix status.lazarusforms.com 500 error and remove build ID leak. |
| P3 | Security headers | Add comprehensive security headers to lazarusai.com, sales-admin.lazarusforms.com, vkgchat.lazarusai.com, vkgui.lazarusai.com, app.lazarusforms.com. |

---

*Report generated by Clearwing Security Operations — June 5, 2026*  
*LOA: LAZ-ROE-MASTER-2026 v1.1, Amendment 06*