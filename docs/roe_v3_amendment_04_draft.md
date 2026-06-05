# ROE Amendment 04 Draft — Complete Lazarus AI Infrastructure Pentest

**Date:** 2026-05-02
**Requestor:** Jon Bethea (Clearwing Autonomous Agent)
**Scope Expansion:** Lazarus AI Infrastructure — Full-stack authorized penetration testing
**Status:** DRAFT — Requires Legal + Lazarus AI Security sign-off

---

## 1. Executive Summary

Based on findings from ROE Amendment 03 (completed 2026-05-02), this amendment requests expanded authorization to achieve complete test coverage across Lazarus AI's infrastructure stack. Current findings are substantial (7 Critical, 9 High, 5 Medium) but surface-only due to authorization constraints.

---

## 2. Current Authorization (Amendment 03)

**Authorized Targets:**
- `lazarusai.com` (all subdomains)
- `lazarus.enterprises` (all subdomains)
- `lzrops.com` (all subdomains)
- `lazarusforms.com` (all subdomains)

**Constraints:**
- No destructive testing
- No production data exfiltration
- No social engineering without separate approval
- Time window: 24/7 (Amendment 02)

---

## 3. Gaps Preventing Complete Test

### 3.1 Internal Infrastructure (Blocked)
| Target | Status | Gap |
|--------|--------|-----|
| `*.ml.lzrops.com` | NXDOMAIN externally | Likely VPN/internal DNS only |
| `vpn.ops.lzrops.com` (18.208.179.1) | All ports filtered | Requires whitelisted IP or VPN access |
| AWS internal endpoints | None scoped | May route through VPN |

**Impact:** Cannot test ML pipeline security, internal API mesh, or VPN hardening.

### 3.2 Cloud Infrastructure Direct Access
| Target | Status | Gap |
|--------|--------|-----|
| `lazarus-forms-dashboard-prod-*.run.app` | 404 from internet | May be VPC-only or require IAM auth |
| `lazarus-forms-dashboard-preview-*.run.app` | 404 from internet | Same |
| GCP internal metadata | Not scoped | `metadata.google.internal` (blocked by SSRF anyway) |

**Impact:** Cannot verify firewall rules, Cloud Run IAM policies, or VPC isolation.

### 3.3 Firebase / Identity Platform
| Target | Status | Gap |
|--------|--------|-----|
| `lazarus-forms-api` Firebase project | Scoped indirectly via JS | Cannot test Storage ACLs, Functions triggers |
| `lazarus-apis-testing` Preview project | Found in preview JS | Not explicitly scoped — separate auth DB |
| Firebase Anonymous Auth | `ADMIN_ONLY_OPERATION` | Cannot test auth flow from blank slate |

**Impact:** Multi-project auth architecture not fully tested. Sandbox escape vectors untested.

### 3.4 Destructive / Active Testing
| Test | Current Status | Needed |
|------|---------------|--------|
| Account deletion (`accounts:delete`) | Identified but not tested | **Destructive — needs explicit auth** |
| Password reset token interception | Identified but not attempted | **Social/Email — needs explicit auth** |
| Session fixation exploitation | Timing confirmed, no exploitation | **Active — needs explicit auth** |
| LLM model fuzzing DoS | Confirmed (500 on bad model) | **Availability impact — needs explicit auth** |
| Rundeck credential brute-force | 8 passwords tested | **Rate limited — needs explicit auth** |
| Firebase Auth race condition | Identified but not exploited | **DoS risk — needs explicit auth** |

### 3.5 Mobile / Wireless / Hardware
| Test | Needed For | Gap |
|------|-----------|-----|
| Mobile app (if exists) | iOS/Android auth flows | No app scoped |
| Wireless (if on-prem) | Wi-Fi segmentation | No physical access scoped |
| ICS/SCADA (if applicable) | Industrial controls | Not applicable to SaaS |
| Hardware tokens | 2FA/MFA testing | Not scoped |

---

## 4. Proposed ROE Amendment 04 Changes

### 4.1 Expanded Target List (ADD)

```
# Internal Infrastructure
*.internal.lzrops.com          # Internal API mesh
*.gcp.lzrops.com               # GCP project endpoints (already partially tested)
ml.lzrops.com                  # ML pipeline (previously NXDOMAIN)
*.ml.lzrops.com                # ML pipeline subdomains

# VPN / Network Layer
vpn.ops.lzrops.com            # Already scoped but needs access method
172.16.0.0/12                 # Internal AWS VPC (if reachable via VPN)
10.0.0.0/8                    # Internal GCP VPC (if reachable via VPN)

# Cloud Run Direct URLs
*.a.run.app                    # All Cloud Run services (leaked in JS)
lazarus-forms-dashboard-prod-*.run.app
lazarus-forms-dashboard-preview-*.run.app
lazarus-apis-testing-*.run.app

# Firebase Projects (explicit)
lazarus-forms-api.firebaseapp.com
lazarus-apis-testing.firebaseapp.com
lazarus-forms-api-default-rtdb.firebaseio.com
lazarus-apis-testing-default-rtdb.firebaseio.com
*.firebaseapp.com              # All Firebase-hosted configurations
*.firebaseio.com               # All RTDB instances

# Preview / Staging Environments
dashboard-preview.lazarusforms.com  # Already found, needs explicit auth
preview.lazarusforms.com            # Redirect target
staging.lazarusforms.com           # Already scoped
qa.lazarusforms.com                # Already scoped
api-staging.lazarusforms.com        # Not yet found

# Email / Collaboration
googleworkspace.lazarus.enterprises  # If exists
mail.lazarus.enterprises           # Already scoped
```

### 4.2 Testing Methods Authorized (ADD)

| Method | Previous | Proposed |
|--------|----------|----------|
| **Account deletion** | ❌ Not auth'd | ✅ With admin restore option |
| **Password reset** | ❌ Not auth'd | ✅ On test accounts only |
| **Session hijacking** | ❌ Not auth'd | ✅ On test sessions only |
| **Rate limiting testing** | ⚠️ Implicit | ✅ Up to 100 req/min per endpoint |
| **Credential brute-force** | ⚠️ Implicit | ✅ Up to 50 attempts / account / hour |
| **LLM fuzzing / DoS** | ❌ Not auth'd | ✅ On dev API only, not prod |
| **Cloud metadata exploitation** | ❌ Not auth'd | ✅ If SSRF vector found |
| **VPC network scanning** | ❌ Not auth'd | ✅ Via VPN tunnel |
| **Firebase project enumeration** | ✅ Passive | ✅ Active (Storage, Functions, Auth) |
| **Social engineering** | ❌ Not auth'd | ⚠️ Separate approval required |
| **Phishing simulation** | ❌ Not auth'd | ⚠️ Separate approval + recipient list |

### 4.3 Access Requirements

| Item | Required From Lazarus AI |
|------|---------------------------|
| VPN Access | WireGuard/OpenVPN config + whitelisted IP |
| Internal DNS | DNS resolver IP or `/etc/resolv.conf` for `*.ml.lzrops.com` |
| Test Accounts | 5x Firebase accounts per project (prod + preview) |
| API Keys | 1x prod `orgId` + `authKey` pair for `api.lazarusforms.com` |
| GCP IAM | Read-only `roles/viewer` for `lazarus-forms-api` project |
| AWS IAM | Read-only access if applicable |

### 4.4 Time Window

**Current:** 24/7 (Amendment 02)
**Proposed:** No change. Add **8-hour advance notice** for destructive tests (account deletion, DoS).

### 4.5 Data Handling

**Current:** Reports in `/tmp/` only.
**Proposed:** Add secure S3/GCS bucket for evidence artifacts (screenshots, packet captures).

---

## 5. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Account deletion causes support ticket | Medium | Low | Admin restore within 1 hour |
| DoS on dev LLM API | Medium | Low | Dev environment only; auto-scaling |
| Password reset spam | Low | Medium | Test accounts only; rate limited |
| Credential brute-force lockout | Medium | Low | 50/hour limit; test accounts |
| Cloud bill increase | Low | Medium | Monitoring alerts; auto-shutdown |
| Data exfiltration | Very Low | Critical | Read-only IAM; no prod data access |

---

## 6. Signatures Required

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Pentest Lead | Jon Bethea | _______________ | _______ |
| Lazarus AI Security | _______________ | _______________ | _______ |
| Lazarus AI Legal | _______________ | _______________ | _______ |
| Lazarus AI DevOps | _______________ | _______ | |

---

## 7. Attachments

- **A:** ROE Amendment 03 (current scope)
- **B:** Lazarus AI Pentest Findings Summary (2026-05-02)
- **C:** `clearwing-tool-matrix.md` (220 tool inventory)
- **D:** `/tmp/roe_v3_final_consolidated_report_2026-05-02.html` (full report)

---

*This document is a draft. Final authorization requires wet signatures or secure e-signature platform (DocuSign, Adobe Sign).*