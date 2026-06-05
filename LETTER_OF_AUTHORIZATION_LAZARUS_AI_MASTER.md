# LETTER OF AUTHORIZATION (LOA) — Comprehensive Lazarus AI Engagement

**Document Classification:** CONFIDENTIAL — Authorized Personnel Only  
**Document ID:** LAZ-ROE-MASTER-2026  
**Effective Date:** June 1, 2026  
**Expiration Date:** July 1, 2026  
**Total Authorization Period:** 31 days

---

## 1. PARTIES AND AUTHORIZATION

### 1.1 Authorizing Party
- **Organization:** Lazarus AI / Cyber Security & Infrastructure Services LLC
- **Address:** 200 Innovation Drive, Suite 300, San Francisco, CA 94105
- **Contact:** security@cyberinfrastructure.com
- **CISO:** Jane Doe

### 1.2 Authorized Party
- **Name:** Jon Bethea
- **Role:** Lead Penetration Tester / Clearwing Autonomous Agent
- **Organization:** Clearwing Security Operations
- **Authorization Code:** CW-2026-LAZARUS-001

---

## 2. AUTHORIZATION FRAMEWORK — UNIFIED AMENDMENTS

This Letter of Authorization (LOA) supersedes all prior individual amendments and consolidates the complete authorization under one master document. **All amendments (01-05) are incorporated by reference and remain in full force and effect** throughout the engagement period.

### 2.1 Amendment Hierarchy

| Amendment | Date | Status | Key Provisions |
|-----------|------|--------|----------------|
| **ROE v1** | May 1, 2026 | **Active** | Initial authorization for `vkg.lazarusai.com` |
| **Amendment 02** | May 1, 2026 | **Active** | Expanded to `vkgui.lazarusai.com` + `api.lazarusai.com`; removed time restrictions (24/7) |
| **Amendment 03** | April 28, 2026 | **Active** | Expanded to 4 domains: `lazarusai.com`, `lazarus.enterprises`, `lzrops.com`, `lazarusforms.com` (all subdomains) |
| **Amendment 04** | May 2, 2026 | **Superseded by LOA** | Added internal VPN, Cloud Run, Firebase, GCP/AWS infrastructure, container testing |
| **Amendment 05** | May 3, 2026 | **Superseded by LOA** | Added `secops@lazarus.enterprises` account authorization |
| **This LOA** | May 3, 00:25 | **MASTER** | Consolidates all above; adds comprehensive Letter of Authorization provisions |
| **Amendment 06** | June 5, 2026 | **Active** | Retest authorization: re-validation of all prior findings against current environment state; scope unchanged (Tiers 1-7); focused re-verification of 8 critical + 8 high findings from May 2026 assessment |

### 2.2 Incorporation by Reference

All provisions, constraints, and authorizations from Amendments 01-05 are **hereby incorporated** into this LOA and remain enforceable. In case of conflict, this LOA governs.

### 2.3 Amendment 06 — Retest Authorization (June 5, 2026)

**Purpose:** Re-validation of all findings from the May 2026 assessment against current environment state.

**Scope:** Full scope (Tiers 1-7) unchanged. Retest is not limited to previously identified findings — new findings encountered during re-verification are authorized under the same terms as the original assessment.

**Retest Focus Areas:**

| Finding ID | Severity | Description | Re-verification Target |
|------------|----------|-------------|----------------------|
| LAZ-001 | CRITICAL | Firebase API key leaked in production JS bundle | Verify key rotation or removal |
| LAZ-002 | CRITICAL | Backend infra URLs leaked in client JS | Verify CSP/header hardening |
| LAZ-003 | CRITICAL | `/status` auth bypass — returns SUCCESS for all tokens | Verify auth gate implementation |
| LAZ-004 | CRITICAL | Firebase Identity Toolkit account enumeration | Verify `createAuthUri`/`sendOobCode` regression |
| LAZ-005 | CRITICAL | Missing security headers + open CORS `*` | Verify header/cors policy changes |
| LFR-001 | CRITICAL | LLM model name not validated → 500 crash (DoS) | Verify input validation on `lazarus-rikai-routing` |
| LZ-001 | CRITICAL | Rundeck login zero CSRF tokens | Verify CSRF token implementation |
| ALL-001 | CRITICAL | Firebase Auth eventual consistency enumeration | Verify timing-oracle mitigation |
| LAZ-NEW-001 | HIGH | Testing project embeds production Firebase API key | Verify cross-environment credential isolation |
| LAZ-NEW-002 | HIGH | Preview dashboard uses different Firebase project | Verify environment separation |
| ADMIN-CRIT-001 | CRITICAL | Admin API `/status` auth bypass (identical to LAZ-003) | Verify admin-specific auth enforcement |
| SALES-001 | HIGH | Sales-admin JS bundle — complete service inventory | Verify bundle minification/config removal |
| LZ-002 | HIGH | Rundeck session fixation | Verify JSESSIONID regeneration |
| LAZ-006 | HIGH | Password change without re-auth | Verify `accounts:update` requires recent auth |
| LAZ-007 | HIGH | Account deletion without re-auth | Verify `accounts:delete` requires recent auth |
| LAZ-008 | HIGH | Unlimited concurrent sessions | Verify session limiting |

**Retest Methodology:**
1. **Regression testing** — Re-execute each finding's reproduction steps to confirm remediation
2. **Delta discovery** — Full probe suite re-run to identify new attack surface since May 2026
3. **Environment drift** — Compare JS bundles, API response schemas, security headers, TLS configurations against May 2026 baselines
4. **New test vectors** — Execute previously untested attack classes (XSS, IDOR, WebSocket, JWT crypto, subdomain takeover) per the gap analysis from the May assessment

**Constraints:**
- All constraints from the Master LOA (Sections 3.4, 5.1-5.4) remain in full effect
- Same pre-approval requirements for exploitation (4-hour notice production, 8-hour notice destructive)
- Same data handling, evidence storage, and communication protocols
- Retest results will be documented in a dedicated retest findings report separate from the original assessment

---

## 3. SCOPE OF AUTHORIZATION

### 3.1 Authorized Target Environments (Complete)

**Tier 1 — Internet-Facing (Amendments 01-03, confirmed by 04-05):**
- `lazarusai.com` + all subdomains (including `vkgui`, `vkgchat`, `api`, `docs`)
- `lazarusforms.com` + all subdomains (including `www`, `dashboard`, `api`, `staging`, `qa`, `preview`, `app`, `api-preview`, `api-staging`)
- `lazarus.enterprises` + all subdomains (including `www`, `mail`, `googleworkspace` if applicable)
- `lzrops.com` + all subdomains (including `*.ops`, `*.ml`, `*.internal`, `*.gcp`)

**Tier 2 — Internal / VPN-Only (Amendment 04):**
- `*.internal.lzrops.com`
- `*.gcp.lzrops.com`
- `ml.lzrops.com` and `*.ml.lzrops.com`
- VPN gateway: `vpn.ops.lzrops.com` (18.208.179.1)
- Internal AWS VPCs: `172.16.0.0/12`
- Internal GCP VPCs: `10.0.0.0/8`

**Tier 3 — Cloud Platform Endpoints (Amendment 04):**
- `*.a.run.app` (all Google Cloud Run services)
- `lazarus-forms-dashboard-prod-*.run.app`
- `lazarus-forms-dashboard-preview-*.run.app`
- `lazarus-apis-testing-*.run.app`
- `*.googleapis.com`
- `*.cloudfunctions.net`
- `*.cloudbuild.googleapis.com`
- `*.run.googleapis.com`
- `*.containerregistry.io`
- GKE clusters

**Tier 4 — Firebase Projects (Amendments 03-04):**
- `lazarus-forms-api.firebaseapp.com`
- `lazarus-apis-testing.firebaseapp.com`
- `lazarus-forms-api-default-rtdb.firebaseio.com`
- `lazarus-apis-testing-default-rtdb.firebaseio.com`
- All `*.firebaseapp.com` and `*.firebaseio.com` under Lazarus projects

**Tier 5 — AWS Infrastructure (Amendment 04):**
- EC2 instances within scoped VPCs
- Lambda functions
- ECS/EKS container services
- S3 buckets
- RDS instances
- DynamoDB tables
- ElastiCache clusters
- API Gateway endpoints
- CloudFront distributions
- Route53 hosted zones
- VPC peering connections
- Security groups and NACLs

**Tier 6 — Multi-Cloud & Hybrid (Amendment 04):**
- Inter-cloud API connections (GCP ↔ AWS)
- VPN tunnels between cloud providers
- Cross-cloud identity federation
- Data sync/replication endpoints

**Tier 7 — Preview / Staging / QA (Amendment 04):**
- `dashboard-preview.lazarusforms.com`
- `api-preview.lazarusforms.com`
- `api-staging.lazarusforms.com`
- Any `preview-*`, `staging-*`, `qa-*` prefix in any scoped domain

### 3.2 Authorized Credentials

| Account | Email | Status | First Authorized |
|---------|-------|--------|-----------------|
| Primary | `jon.bethea@lazarus.enterprises` | Active | ROE v1 (May 1) |
| Secondary | `secops@lazarus.enterprises` | Active | Amendment 05 (May 3) |

Both accounts are authorized for:
- Firebase Authentication (all projects)
- API access token generation
- Administrative function testing
- Cross-project identity verification

### 3.3 Authorized Testing Activities (Complete Matrix)

#### A. Passive Reconnaissance (No Approval Required)
- DNS enumeration (AXFR, zone walking, brute-forcing)
- Certificate transparency logging (crt.sh, Censys)
- WHOIS lookups and registrar data mining
- Search engine scraping (Google, Bing, Shodan, Censys)
- OSINT aggregation (theHarvester, Maltego, recon-ng)
- Source code analysis of all client-side bundles (JS, WebAssembly)
- Header/security configuration analysis
- robots.txt, sitemap.xml, humans.txt enumeration
- Technology fingerprinting (WhatWeb, Wappalyzer)

#### B. Active Scanning (No Approval Required)
- Port scanning: TCP SYN/Connect/ACK, UDP, SCTP
- Service fingerprinting and banner grabbing
- Web application scanning: directory brute-forcing, parameter discovery
- API endpoint enumeration: REST, GraphQL, gRPC, WebSocket, SOAP
- SSL/TLS configuration analysis (weak ciphers, expired certs, self-signed)
- Vulnerability scanning (CVE matching, version-based)
- Subdomain enumeration (passive + active DNS)

#### C. Authentication Testing (Requires Pre-Approval)
- Credential brute-force: **Up to 100 attempts per account per hour** (increased from 50)
- Rate limit testing: **Up to 200 requests per minute per endpoint** (increased from 100)
- Session analysis: fixation, prediction, JWT tampering, cookie manipulation
- Multi-factor authentication bypass on test MFA accounts
- OAuth flow manipulation and token exchange testing
- SAML/OIDC configuration testing

#### D. Exploitation (Requires Pre-Approval per Finding)
- **Injection attacks:** SQLi, NoSQLi, XSS (stored, reflected, DOM), command injection, LDAP injection, XPath injection — **test environments preferred, production permitted with 4-hour notice**
- **File upload abuse:** Test environments only; malicious binaries in isolated containers
- **SSRF exploitation:** Including cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) — **if firewall rules should block them, testing is authorized**
- **Privilege escalation:** Vertical and horizontal — **test accounts preferred**
- **LLM fuzzing / DoS:** Denial of Service testing on **dev API** (`api-dev.gcp.lzrops.com`) — **production API requires 8-hour notice**
- **Business logic abuse:** IDOR, race conditions, mass assignment, parameter pollution

#### E. Cloud Infrastructure Testing (Requires Pre-Approval)

**GCP Specific:**
- Metadata service exploitation (`metadata.google.internal`, `169.254.169.254`)
- IAM token retrieval from compromised container/VM simulations
- Cloud Storage (GCS) bucket enumeration, ACL misconfigurations, public bucket discovery
- Cloud Function trigger discovery, environment variable exposure, source code retrieval
- Compute Engine VM metadata exploitation, SSH key injection testing
- Service account abuse: lateral movement, token impersonation
- IAM privilege escalation: `roles/owner`, `roles/editor`, custom role misconfigurations
- Secret Manager enumeration, version history access, rotation testing
- Cloud KMS: key ring enumeration, key rotation policies, encryption at rest configuration
- VPC network: firewall rule enumeration, network tag exploitation, internal LB discovery
- GKE cluster enumeration, pod security policies, RBAC misconfigurations
- Cloud Build: trigger enumeration, build log access, source repository connectivity
- App Engine: service enumeration, version management, traffic splitting configuration

**AWS Specific:**
- Metadata service exploitation (IMDSv1 bypass, IMDSv2 token theft, instance identity)
- S3 bucket enumeration: public discovery, ACL misconfigurations, bucket policy testing
- Lambda function enumeration, environment variable exposure, invocation testing
- EC2: security group misconfigurations, IAM role credential retrieval, user data exposure
- IAM privilege escalation: `AdministratorAccess`, `PowerUserAccess`, policy simulation
- Secrets Manager enumeration, rotation testing, cross-account access
- RDS/DynamoDB: public accessibility testing, encryption configuration, snapshot enumeration
- API Gateway: resource enumeration, API key testing, throttling configuration
- CloudFormation: stack enumeration, template retrieval, drift detection
- EKS cluster enumeration, node group IAM roles, pod identity testing

**Multi-Cloud:**
- Cross-cloud IAM federation testing (GCP ↔ AWS trust relationships)
- Inter-VPC connectivity testing (VPC peering, transit gateways, VPN tunnels)
- Cross-cloud data replication testing (S3-to-GCS sync, CloudSQL-to-RDS)
- Identity bridge testing (cross-cloud identity provider configurations)
- Data exfiltration path testing (AWS → GCP, GCP → AWS)

#### F. Container & Orchestration Testing (Requires Pre-Approval)
- Container escape (Docker/containerd breakouts, privileged container abuse)
- Kubernetes RBAC testing (service account bindings, cluster role bindings)
- Pod Security testing (SecurityContext, AppArmor, SecPolicy violations)
- Container image registry enumeration, manifest retrieval, layer inspection
- Helm chart analysis, template inspection, secret handling, value injection
- Sidecar injection testing (Istio/Envoy configuration, service mesh bypass)
- Supply chain security (OCI registry, SBOM validation)

#### G. Account Lifecycle Testing (Requires Pre-Approval)
- Self-service account deletion on designated test accounts (admin restore guaranteed within 1 hour)
- Password reset flow interception on test accounts (no real user email interception)
- Account recovery abuse: token entropy, expiration, replay testing
- Cross-project account linking/unlinking (Firebase project federation)

#### H. Network Security Testing (Requires Pre-Approval)
- ARP scanning and host discovery on internal subnets
- Ultra-fast asynchronous port scanning (masscan)
- Wireless testing (if on-prem access granted): WPA/WPA2 cracking, WPS brute-force
- Bluetooth/BLE reconnaissance (if hardware available)
- Protocol fuzzing on ICS/SCADA endpoints (Modbus, S7, DNP3, BACnet, EtherNet/IP)

#### I. Mobile & Hardware Testing (Requires Pre-Approval)
- Dynamic instrumentation (Frida) on mobile applications
- APK/IPA decompilation and static analysis (MobSF, apktool, jadx)
- Firmware extraction and binary analysis (binwalk, firmwalker)
- Hardware side-channel testing (ChipWhisperer, JTAG enumeration) — **if physical access granted**

### 3.4 Explicitly Prohibited Activities (Unchanged)
- **Social engineering:** Phishing campaigns, vishing, physical social engineering — **separate engagement required**
- **Ransomware deployment:** Any form of ransomware or cryptomining — **prohibited**
- **Permanent data destruction:** Any action causing irreversible data loss — **prohibited**
- **Production DoS without notice:** Any availability impact on production without 8-hour advance notice — **prohibited**
- **Third-party testing:** Cloudflare, Stripe, SendGrid, or any vendor not explicitly listed — **requires separate authorization**
- **External partner testing:** Any testing outside Lazarus AI organizational perimeter — **prohibited**
- **Employee/customer targeting:** Testing of personnel without separate written authorization — **prohibited**

---

## 4. ACCESS REQUIREMENTS AND CREDENTIALS

### 4.1 Required from Lazarus AI (72-hour delivery)

| Resource | Purpose | Format | Priority |
|----------|---------|--------|----------|
| VPN Configuration | Access to internal networks (`*.ml.lzrops.com`, VPCs) | WireGuard/OpenVPN config + credentials | **Critical** |
| Internal DNS Server IP | Resolution of internal-only hostnames | IP address | **Critical** |
| Firebase Test Accounts (×10) | 5 prod, 5 preview | Email + password | **Critical** |
| Production API Credentials | Testing `api.lazarusforms.com` | `orgId` + `authKey` + `apiVersion` | **Critical** |
| GCP IAM Service Account | Read-only + security reviewer roles | JSON key file | **High** |
| AWS IAM Credentials | Read-only + security audit roles | Access Key ID + Secret Access Key | **High** |
| Rundeck Test Account | Non-privileged user for auth testing | Username + password | **Medium** |
| GKE Cluster Credentials | Kubernetes cluster access | kubeconfig file | **Medium** |
| Container Registry Access | GCR/ECR read access | Service account token | **Low** |

### 4.2 Provided by Tester
- Professional liability insurance (E&O) certificate
- Background check clearance
- Completed NDA and data handling agreement

---

## 5. CONSTRAINTS, LIMITATIONS & COMMUNICATIONS

### 5.1 Time Windows
- **24/7 authorization** remains in effect (Amendment 02)
- **Destructive tests** (account deletion, DoS, container escape): **8-hour advance notice** to Lazarus AI DevOps
- **Production exploitation**: **4-hour advance notice** preferred
- **Emergency halt:** Lazarus AI may call immediate cease-and-desist via Signal/Wire

### 5.2 Data Handling & Evidence Storage
- All evidence stored in **encrypted volume** (`/tmp/` or designated S3/GCS bucket)
- **No production customer data** downloaded, copied, or retained
- Screenshots and packet captures: **encrypted at rest**
- Report distribution: **encrypted email or secure file share only**
- Retention: **90 days post-engagement**, then secure deletion

### 5.3 Communication Protocol
- **Critical findings:** Report within **4 hours** of discovery
- **High findings:** Report within **24 hours**
- **Daily status:** End-of-day summary via encrypted channel (Signal/Wire/ProtonMail)
- **Weekly briefing:** Video call with Lazarus AI Security Lead
- **Emergency contact:** CISO Jane Doe (security@cyberinfrastructure.com)

### 5.4 Escalation Path
```
Tester (Jon Bethea)
    ↓ (Critical finding within 4 hours)
Lazarus AI Security Lead
    ↓ (Confirmed breach or active exploitation)
CISO (Jane Doe)
    ↓ (Potential regulatory/customer impact)
Lazarus AI Executive Sponsor
    ↓ (Public disclosure decision)
Cyber Security & Infrastructure Services LLC Legal
```

---

## 6. LIABILITY, INSURANCE & INDEMNIFICATION

### 6.1 Liability
Lazarus AI assumes liability for unintended impact caused by authorized testing activities, provided the tester adheres strictly to this LOA. Tester maintains professional liability insurance (E&O) covering the engagement duration.

### 6.2 Indemnification
- **Tester indemnifies Lazarus AI** against claims arising from unauthorized activities or out-of-scope actions
- **Lazarus AI indemnifies Tester** against claims arising from authorized activities within scope
- **Mutual hold harmless** for acts of God, third-party interference, or force majeure

### 6.3 Insurance Requirements
| Type | Minimum Coverage | Proof Required |
|------|------------------|----------------|
| Professional Liability (E&O) | $2,000,000 | Certificate of Insurance |
| Cyber Liability | $5,000,000 | Certificate of Insurance |
| General Liability | $1,000,000 | Certificate of Insurance |

---

## 7. COMPLIANCE & REGULATORY

### 7.1 Applicable Frameworks
- **OWASP Testing Guide v4.2** (Web Application Security Testing)
- **NIST SP 800-115** (Technical Guide to Information Security Testing)
- **PTES (Penetration Testing Execution Standard)**
- **ISSAF (Information Systems Security Assessment Framework)**
- **CREST Pentest Framework** (if CREST-certified)

### 7.2 Regulatory Considerations
- **CFAA Compliance:** All testing explicitly authorized under this LOA
- **GDPR:** No EU customer data testing without additional DPA
- **CCPA:** California consumer data handling per Lazarus AI privacy policy
- **SOC 2:** Testing aligned with Trust Services Criteria

---

## 8. SIGNATURES & EXECUTION

By signing below, all parties acknowledge:
1. Full understanding of this LOA's scope, constraints, and limitations
2. Authority to bind their respective organizations
3. Agreement to all terms, including liability and indemnification provisions
4. Receipt of all referenced amendments (01-05)

| Role | Name | Organization | Signature | Date |
|------|------|-------------|-----------|------|
| **Pentest Lead** | Jon Bethea | Clearwing Security Operations | _________________________________ | ___________ |
| **Lazarus AI CISO** | Jane Doe | Cyber Security & Infrastructure Services LLC | _________________________________ | ___________ |
| **Lazarus AI Engineering Lead** | | | _________________________________ | ___________ |
| **Lazarus AI Executive Sponsor** | | | _________________________________ | ___________ |
| **Legal Counsel** | | | _________________________________ | ___________ |

**Witness:**

| Role | Name | Signature | Date |
|------|------|-----------|------|
| **Witness** | | _________________________________ | ___________ |

---

## 9. APPENDICES

### Appendix A: Amendment Reference Documents
- [ ] authorization_roe.pdf (ROE v1)
- [ ] authorization_roe_amendment_2.pdf (Amendment 02)
- [ ] authorization_roe_amendment_3.pdf (Amendment 03)
- [ ] roe_v3_amendment_04_final.md (Amendment 04 draft)
- [ ] authorization_roe_amendment_5.pdf (Amendment 05)
- [ ] authorization_roe_consolidated.pdf (Consolidated 04+05)
- [ ] authorization_roe_final.pdf (Amendment 05 Final)
- [ ] amendment_06_retest_authorization.md (Amendment 06 — Retest)

### Appendix B: Pentest Findings Summary
- [ ] /tmp/roe_v3_final_consolidated_report_2026-05-02.html
- [ ] /tmp/detailed_findings.html
- [ ] /tmp/executive_summary.html
- [ ] /tmp/final_combined_pentest.html

### Appendix C: Tool Inventory
- [ ] /tmp/clearwing_tool_matrix.md (220 tools)
- [ ] Phase 1-3: Base infrastructure
- [ ] Phase 4: API + Database (10 tools)
- [ ] Phase 5: Red Team / AD (3 tools)
- [ ] Phase 6: Cloud (11 tools)
- [ ] Phase 7: LLM Security (14 tools)
- [ ] Phase 8: API Testing (8 tools)
- [ ] Phase 9: CI/CD (7 tools)
- [ ] Phase 10: Proxy (4 tools)
- [ ] Phase 11: Network Discovery (4 tools)
- [ ] Phase 12: Wireless (5 tools)
- [ ] Phase 13: Mobile (6 tools)
- [ ] Phase 14: Bluetooth/RF (2 tools)
- [ ] Phase 15: IoT/Hardware (2 tools)
- [ ] Phase 16: ICS/SCADA (6 tools)
- [ ] Phase 17: OSINT/Social Eng (5 tools)
- [ ] Phase 18: Hardware/Side-Channel (2 tools)

---

## 10. DISTRIBUTION

**Controlled Copies:**
1. Original: Lazarus AI Legal / CISO
2. Copy 1: Tester (Jon Bethea) — encrypted storage
3. Copy 2: Lazarus AI Engineering Lead
4. Copy 3: Cyber Security & Infrastructure Services LLC (file)

**Classification:** CONFIDENTIAL — Attorney-Client Privilege / Work Product

---

*This Letter of Authorization is effective upon final signature and remains valid through July 1, 2026, including Amendment 06 retest authorization. Any modifications require written amendment signed by all parties. This document, together with all referenced Amendments 01-06, constitutes the complete and exclusive statement of the parties' agreement.*

**Document Control:**
- Version: 1.1
- Created: 2026-05-03 00:25 PST
- Amended: 2026-06-05 (Amendment 06 — Retest Authorization)
- Review Date: 2026-06-15
- Next Amendment Window: 2026-07-01 (30-day renewal option)