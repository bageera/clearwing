# Clearwing Retest Findings Summary
## Lazarus AI — Amendment 06 Retest
**Date:** June 5, 2026  
**Authorization:** LOA LAZ-ROE-MASTER-2026 v1.1, Amendment 06  
**Tester:** Jon Bethea, Clearwing Security Operations  
**Scope:** Full Tiers 1–7 retest per Amendment 06 methodology

---

## Executive Summary

Retest of 15 original findings identified **2 confirmed remediated, 8 still open (1 partially remediated), 1 inconclusive**, and **4 new findings** discovered during delta reconnaissance.

| Status | Count |
|--------|-------|
| Remeditated | 2 |
| Still Open | 8 |
| Partially Remediated | 1 |
| Inconclusive (credentials rotated) | 1 |
| New Findings | 4 |
| False Positive (closed) | 0 |

---

## Original Findings — Regression Results

### REMEDIATED

| ID | Finding | Original Severity | Remediation Evidence |
|----|---------|-------------------|---------------------|
| LAZ-004 | Firebase Identity Toolkit account enumeration | Medium | `createAuthUri` now returns `registered: false` for all emails — no differentiator between valid/invalid accounts. `sendOobCode` requires registered caller identity and returns 403 for unauthenticated requests. |
| LZ-002 | Rundeck session fixation | Low | Post-login-failure session check shows JSESSIONID is regenerated (not retained). Session cookie uses SameSite=Lax. |

### STILL OPEN

| ID | Finding | Severity | Retest Evidence |
|----|---------|----------|-----------------|
| LAZ-001 | Firebase API key in production JS bundle | Medium | Key `AIzaSyBgs-HrkxUdKbLFVxPsN2JJfjB71c_Cn58` still present in `dashboard.lazarusforms.com/static/js/index.c5444a2b.js` and `sales-admin.lazarusforms.com/static/js/main.91f908c2.js` and `vkgchat.lazarusai.com/static/js/index.34ebda78.js` |
| LAZ-002 | Backend infra URLs leaked in client JS | Medium | 5 Cloud Run URLs, Firebase RTDB URL, and 20+ internal endpoints still in `sales-admin` JS bundle; vkgchat bundle additionally leaks `ask-citations` Cloud Run, `legacy.lazarusforms.com`, and `vkgui.lazarusai.com` |
| LAZ-003 | `/status` endpoint auth bypass on api.lazarusai.com | Medium | Returns `SUCCESS`/HTTP 200 with no auth, invalid token, random UUID, and empty token — identical to original finding |
| LAZ-005 | Missing security headers / open CORS | Low-Medium | **Partially remediated**: `dashboard.lazarusforms.com` now has CSP `frame-ancestors 'self'`, `X-Content-Type-Options` nosniff, HSTS. **Still open**: `lazarusai.com` missing CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection. `api.lazarusai.com` still returns `Access-Control-Allow-Origin: *`. |
| LZ-001 | Rundeck login lacks CSRF token | Low | Login form HTML contains no CSRF token/nonce. CSP allows `unsafe-inline` and `unsafe-eval`. |
| ALL-001 | Firebase Auth eventual consistency enumeration | Low | `signInWithPassword` still returns `EMAIL_NOT_FOUND` for nonexistent accounts vs `INVALID_PASSWORD` for valid ones — differentiator enables account enumeration |
| SALES-001 | Sales-admin JS bundle leaked backend URLs | Medium | Confirmed with 20+ backend URLs including `forms-admin-dashboard`, `lazarus-forms-admin-api`, `lazarus-forms-dashboard-prod`, `lazarus-metrics`, and Cloud Functions endpoint. Firebase key still present. |
| ADMIN-CRIT-001 | Admin API `/status` auth bypass + open CORS | High | `/status` returns `SUCCESS`/200 without auth and with invalid token. CORS reflects arbitrary Origin (`Access-Control-Allow-Origin: https://evil.com`). No IAM restriction on direct Cloud Run access. |

### INCONCLUSIVE

| ID | Finding | Severity | Notes |
|----|---------|----------|-------|
| LFR-001 | LLM model name not validated → 500 crash | Medium | Auth credentials (`authkey`/`orgid`) rejected with 403 AUTH_FAILURE. Cannot reach model validation layer to test. Credentials likely rotated since original assessment. Requires updated credentials to retest. |

---

## New Findings

### NEW-001: Staging Environment Exposes Production Application
- **Severity:** Medium
- **Target:** `staging.lazarusai.com`, `staging.lazarusforms.com`
- **Description:** Both staging subdomains resolve to GCP IPs and serve identical content to the production dashboard, with identical JS bundles (`index.c5444a2b.js`, `830.a5cac9f9.js`). They share the same API (`apiversion: 2025-08-07`) and return `Access-Control-Allow-Origin: *`. The staging environment is not isolated from production — it redirects to `dashboard.lazarusforms.com` but also leaks the `access-control-allow-origin: *` header.
- **Evidence:** Both return HTTP 302 → `dashboard.lazarusforms.com`; response includes `apiversion: 2025-08-07` and wildcard CORS.

### NEW-002: Cloud Run Services Publicly Accessible Without IAM Authentication
- **Severity:** High
- **Targets:**
  - `lazarus-forms-admin-api-7owznqu3wq-uc.a.run.app`
  - `lazarus-forms-dashboard-prod-7owznqu3wq-uc.a.run.app`
  - `forms-user-dashboard-685480940293.us-central1.run.app`
  - `lazarus-metrics-685480940293.us-central1.run.app`
  - `forms-admin-dashboard-685480940293.us-central1.run.app`
  - `v2025-09-29---lazarus-metrics-7owznqu3wq-uc.a.run.app`
- **Description:** All 6 Cloud Run services discovered in client JS bundles are publicly accessible without IAM authentication. Four of six reflect arbitrary origins in CORS headers. The `lazarus-metrics` services use wildcard `Access-Control-Allow-Origin: *`.
- **Evidence:** All services respond to HTTP requests; admin-api and admin-dashboard return `{"status": "SUCCESS"}` on `/status` without auth; metrics service returns `AUTH_FAILURE` only on data endpoints, but `/status` and `/health` are unauthenticated.

### NEW-003: Admin Dashboard API Reveals Role Structure and Accepts Unauthenticated Requests
- **Severity:** Medium
- **Target:** `forms-admin-dashboard-685480940293.us-central1.run.app`
- **Description:** The `/models/custom` endpoint returns a detailed error message revealing the required header (`adminId`) when called without it. When called with a test `adminId` header, it reveals the admin role structure: `"permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin"`. The `/orgs/models/custom/access` endpoint similarly reveals it requires both `adminId` and `orgId` headers.
- **Evidence:** 
  - `POST /models/custom` → 400 `{"requiredFields": ["adminId"]}`
  - `POST /models/custom` with `adminId: test` → 403 `{"permission": "At least one of the following: prodAdmin, salesAdmin, superAdmin"}`
  - `POST /orgs/models/custom/access` → 400 `{"requiredFields": ["adminId", "orgId"]}`

### NEW-004: Previously Unknown Backend Endpoints Discovered in vkgchat JS Bundle
- **Severity:** Medium
- **Target:** `ask-citations-363598527858.us-central1.run.app`, `legacy.lazarusforms.com`, `vkgui.lazarusai.com`
- **Description:** The vkgchat.lazarusai.com JavaScript bundle (`index.34ebda78.js`) contains three previously unmapped backend endpoints:
  1. `ask-citations-363598527858.us-central1.run.app` — publicly accessible, returns `"Request made"` with HTTP 200 and wildcard CORS (`Access-Control-Allow-Origin: *`)
  2. `legacy.lazarusforms.com` — redirects to `/login`, runs Google Frontend, returns wildcard CORS
  3. `vkgui.lazarusai.com` — serves a React SPA via S3/CloudFront, no security headers

  The `ask-citations` service also reveals expected headers (`Content-Type, orgId, authKey, userId, authorization`) in CORS preflight responses.

---

## Environment Drift Analysis

### JS Bundle Comparison (May 2026 vs June 2026)

| Bundle | Hash (SHA-256) | Changed? |
|--------|---------------|----------|
| dashboard.lazarusforms.com/index.c5444a2b.js | `9f5b244ea07a...` | Unchanged from May |
| sales-admin.lazarusforms.com/main.91f908c2.js | `dc9502739edd...` | Unchanged from May |
| lazarus-apis-testing/main.1ceea3b9.js | `541ed95a399d...` | Unchanged from May |
| vkgchat.lazarusai.com/index.34ebda78.js | New | Not in original scope |
| vkgchat.lazarusai.com/lib-react.64b4f5a8.js | New | Different build from dashboard |

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
| All ops.lzrops.com infra (grafana, etc.) | Still NXDOMAIN |

### Security Headers Delta

| Host | Missing Headers | New Headers |
|------|----------------|------------|
| lazarusai.com | CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection | — |
| api.lazarusai.com | CORS still `*` | — |
| dashboard.lazarusforms.com | X-Frame-Options | Added: CSP `frame-ancestors 'self'`, X-Content-Type-Options nosniff, Referrer-Policy strict-origin, HSTS |
| sales-admin.lazarusforms.com | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | — |
| vkgchat.lazarusai.com | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | — |
| legacy.lazarusforms.com | CSP, HSTS, X-Frame-Options, X-Content-Type-Options | CORS: `*` |

---

## Subdomain Inventory

| Subdomain | IP / CNAME | Service | Status |
|-----------|-----------|---------|--------|
| lazarusai.com | 99.83.190.102 | Marketing (Webflow) | Active |
| api.lazarusai.com | 34.160.98.212 | API Gateway (GCP) | Active |
| docs.lazarusai.com | CloudFront | Documentation | Active |
| dashboard.lazarusforms.com | CloudFront | Main Dashboard SPA | Active |
| lazarusforms.com | 99.83.190.102 | Marketing (Webflow) | Active |
| www.lazarusforms.com | proxy-ssl.webflow.com | Marketing | Active |
| api.lazarusforms.com | 34.160.56.117 | API | Active |
| sales-admin.lazarusforms.com | CloudFront | Sales Admin SPA | Active |
| vkgchat.lazarusai.com | CloudFront | VKG Chat SPA | Active |
| vkgui.lazarusai.com | CloudFront | VKG UI SPA | Active |
| legacy.lazarusforms.com | Google Frontend | Legacy API | Active |
| rundeck.ops.lzrops.com | 34.238.158.171 | Rundeck | Active |
| api-dev.gcp.lzrops.com | 34.49.189.71 | Dev API | Active |
| staging.lazarusai.com | 34.36.25.49 | Staging (→ prod) | Active |
| staging.lazarusforms.com | 35.227.223.84 | Staging (→ prod) | Active |

**Cloud Run services (discovered from JS bundles):**

| Service | Publicly Accessible | Unauth Status | CORS |
|---------|---------------------|---------------|------|
| lazarus-forms-admin-api | Yes | `/status` → SUCCESS | Reflects Origin |
| lazarus-forms-dashboard-prod | Yes | `/` → 404 | Reflects Origin |
| forms-user-dashboard | Yes | `/` → 404 | Reflects Origin |
| lazarus-metrics | Yes | `/status` → SUCCESS, `/health` → SUCCESS | Wildcard `*` |
| forms-admin-dashboard | Yes | `/status` → SUCCESS | Reflects Origin |
| v2025-09-29---lazarus-metrics | Yes | `/status` → SUCCESS | Wildcard `*` |
| ask-citations | Yes | `/` → 200 | Wildcard `*` |
| lazarus-apis-testing | Yes | Serves full SPA | No CORS headers |

---

## Recommendations Priority Matrix

| Priority | Finding | Recommendation |
|----------|---------|---------------|
| P1 | ADMIN-CRIT-001 + NEW-002 | Enable IAM authentication on all Cloud Run services. Remove public invocations. Implement `--no-allow-unauthenticated` on deployments. |
| P1 | LAZ-001 + SALES-001 + NEW-004 | Remove all Firebase API keys, backend URLs, and internal endpoint references from client-side JS. Use environment injection at build time. |
| P1 | LAZ-005 + LEGACY CORS | Remove `Access-Control-Allow-Origin: *` from api.lazarusai.com, all Cloud Run services, and legacy.lazarusforms.com. Implement proper CORS whitelisting. |
| P2 | LAZ-003 | Implement authentication/authorization on `/status` endpoints. Return 401 for unauthenticated requests. |
| P2 | NEW-003 | Remove verbose error messages revealing role structure. Return generic 403 without role names. |
| P2 | NEW-001 | Isolate staging environments from production. Use separate GCP projects. Do not share API backends. |
| P3 | LZ-001 | Add CSRF tokens to Rundeck login form. Remove `unsafe-inline` and `unsafe-eval` from CSP. |
| P3 | ALL-001 | Configure Firebase Auth to return generic error messages (disable "EMAIL_NOT_FOUND" differentiation). |
| P3 | Security headers | Add comprehensive security headers to lazarusai.com, sales-admin.lazarusforms.com, vkgchat.lazarusai.com, and legacy.lazarusforms.com. |

---

*Report generated by Clearwing Security Operations — June 5, 2026*
*LOA: LAZ-ROE-MASTER-2026 v1.1, Amendment 06*