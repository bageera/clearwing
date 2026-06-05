# Authorization for the Conduct of Penetration Testing

**Document:** Rules of Engagement (ROE) Amendment 04
**Effective Date:** 2026-05-02
**Expiration Date:** 2026-06-01 (Same as original)

---

## 1. Authorization and Scope Expansion

This Amendment 04 supplements and supersedes specific provisions of ROE Amendment 03, dated 2026-04-28. It expands the authorized scope of engagement to enable a **complete, non-destructive, and technically thorough** penetration test of the Lazarus AI infrastructure, covering all attack vectors observed during Amendment 03.

**Authorized Organization:** Lazarus AI / Clearwing Security Operations
**Primary Tester:** Jon Bethea (Clearwing Autonomous Agent)

---

## 2. Authorized Target Environments

### 2.1 Internet-Facing (Previously Authorized)
- `lazarusai.com` (and all subdomains)
- `lazarusforms.com` (and all subdomains)
- `lazarus.enterprises` (and all subdomains)
- `lzrops.com` (and all subdomains)

### 2.2 Internal / VPN-Only (New)
- `*.internal.lzrops.com`
- `*.gcp.lzrops.com`
- `ml.lzrops.com` and `*.ml.lzrops.com`
- Internal AWS VPC CIDRs: `172.16.0.0/12`, `10.0.0.0/8` *(accessible via provided VPN)*
- `vpn.ops.lzrops.com` (18.208.179.1) *(via whitelisted IP or VPN tunnel)*

### 2.3 Cloud Platform Endpoints (New)
- `*.a.run.app` *(All Google Cloud Run services)*
- `lazarus-forms-dashboard-prod-*.run.app`
- `lazarus-forms-dashboard-preview-*.run.app`
- `lazarus-apis-testing-*.run.app`

### 2.4 Firebase Projects (New)
- `lazarus-forms-api.firebaseapp.com`
- `lazarus-apis-testing.firebaseapp.com`
- `lazarus-forms-api-default-rtdb.firebaseio.com`
- `lazarus-apis-testing-default-rtdb.firebaseio.com`

### 2.5 Google Cloud Platform (GCP) Infrastructure (New)
#### 2.5.1 Compute & Serverless
- `*.googleapis.com` *(All GCP API endpoints used by Lazarus)*
- `*.cloudfunctions.net`
- `*.cloudbuild.googleapis.com`
- `*.run.googleapis.com`
- `*.containerregistry.io`
- Google Kubernetes Engine (GKE) clusters

#### 2.5.2 Storage & Data
- `storage.cloud.google.com`
- `*.storage.googleapis.com` *(Cloud Storage buckets)*
- `bigquery.googleapis.com`

#### 2.5.3 Identity & Access Management
- `cloudresourcemanager.googleapis.com`
- `iam.googleapis.com`
- `iamcredentials.googleapis.com`
- Service account keys and tokens

#### 2.5.4 Secrets & Key Management
- `secretmanager.googleapis.com`
- `cloudkms.googleapis.com`

### 2.6 Amazon Web Services (AWS) Infrastructure (New)
#### 2.6.1 Compute & Serverless
- EC2 instances within scoped VPCs
- Lambda functions
- ECS/EKS container services
- Elastic Beanstalk environments

#### 2.6.2 Storage & Databases
- S3 buckets (scoped to Lazarus AI accounts)
- RDS instances
- DynamoDB tables
- ElastiCache clusters

#### 2.6.3 Identity & Access Management
- IAM roles, policies, and users
- AWS STS temporary credentials
- Cognito identity pools

#### 2.6.4 Networking
- API Gateway endpoints
- CloudFront distributions
- Route53 hosted zones
- VPC peering connections
- Security groups and NACLs

### 2.7 Multi-Cloud & Hybrid Infrastructure (New)
- Inter-cloud API connections (GCP ↔ AWS)
- VPN tunnels between cloud providers
- Cross-cloud identity federation
- Data sync/replication endpoints

### 2.8 Staging / Preview Environments (New)
- `dashboard-preview.lazarusforms.com`
- `api-preview.lazarusforms.com`
- `api-staging.lazarusforms.com`
- Any environment prefixed with `preview-`, `staging-`, or `qa-`

---

## 3. Authorized Testing Activities

### 3.1 Passive Reconnaissance (No Approval Required)
- DNS enumeration, certificate transparency logging, WHOIS lookups
- Search engine scraping, OSINT aggregation
- Source code analysis of client-side bundles
- Header analysis, robots.txt, sitemap.xml

### 3.2 Active Scanning (No Approval Required)
- Port scanning (SYN, Connect, UDP) on all scoped targets
- Service fingerprinting and banner grabbing
- Web application scanning (directory brute-forcing, parameter discovery)
- API endpoint enumeration (GraphQL, gRPC, REST, WebSocket)
- SSL/TLS configuration analysis

### 3.3 Authentication Testing (Requires Pre-Approval)
- **Credential brute-force:** Up to 50 attempts per account per hour against test accounts only
- **Rate limit testing:** Up to 100 requests per minute per endpoint
- **Session analysis:** Session fixation, token prediction, JWT tampering
- **Multi-factor authentication bypass:** Testing on test MFA accounts only

### 3.4 Exploitation (Requires Pre-Approval per Finding)
- **Injection attacks:** SQLi, NoSQLi, XSS, command injection against test environments
- **File upload abuse:** Test environments only; no malicious binaries in production
- **SSRF exploitation:** Including cloud metadata endpoints (`169.254.169.254`) if firewall rules should block them
- **Privilege escalation:** Vertical and horizontal, test accounts only
- **LLM fuzzing:** Denial of Service testing on **dev API only** (`api-dev.gcp.lzrops.com`)

### 3.5 Cloud Infrastructure Testing (Requires Pre-Approval)

#### 3.5.1 Google Cloud Platform (GCP) Testing
- **GCP Metadata Service Exploitation:** Testing IAM token retrieval from compromised container/VM simulations via `metadata.google.internal` (169.254.169.254)
- **Cloud Storage Enumeration:** GCS bucket access control testing, ACL misconfigurations, public bucket discovery
- **Cloud Function Enumeration:** Trigger discovery, environment variable exposure, source code retrieval
- **Compute Engine Testing:** VM metadata exploitation, SSH key injection testing, instance metadata access
- **Service Account Abuse:** Testing lateral movement via service account keys, token impersonation
- **IAM Privilege Escalation:** Testing `roles/owner`, `roles/editor`, custom role misconfigurations
- **Secret Manager Testing:** Secret enumeration, version history access, rotation testing
- **Cloud KMS Testing:** Key ring enumeration, key rotation policies, encryption at rest configuration
- **VPC Network Testing:** Firewall rule enumeration, network tag exploitation, internal load balancer discovery
- **GKE (Kubernetes) Testing:** Cluster enumeration, pod security policies, RBAC misconfigurations
- **Cloud Build Testing:** Build trigger enumeration, build log access, source repository connectivity
- **App Engine Testing:** Service enumeration, version management, traffic splitting configuration

#### 3.5.2 Amazon Web Services (AWS) Testing
- **AWS Metadata Service Exploitation:** IMDSv1 bypass, IMDSv2 token theft, instance identity document retrieval
- **S3 Bucket Enumeration:** Public bucket discovery, ACL misconfigurations, bucket policy testing
- **Lambda Function Testing:** Function enumeration, environment variable exposure, invocation testing
- **EC2 Instance Testing:** Security group misconfigurations, IAM role credential retrieval, user data exposure
- **IAM Privilege Escalation:** Testing `AdministratorAccess`, `PowerUserAccess`, policy simulation
- **Secrets Manager Testing:** Secret enumeration, rotation testing, cross-account access
- **KMS Testing:** Key enumeration, key policies, grant management
- **VPC Network Testing:** Security group enumeration, network ACL testing, VPC endpoint discovery
- **RDS/DynamoDB Testing:** Public accessibility testing, encryption configuration, snapshot enumeration
- **API Gateway Testing:** Resource enumeration, API key testing, throttling configuration
- **CloudFormation Testing:** Stack enumeration, template retrieval, drift detection
- **EKS (Kubernetes) Testing:** Cluster enumeration, node group IAM roles, pod identity testing

#### 3.5.3 Multi-Cloud & Hybrid Testing
- **Cross-Cloud IAM Federation:** Testing trust relationships between GCP and AWS
- **Inter-VPC Connectivity:** Testing VPC peering, VPN tunnels, transit gateways
- **Cross-Cloud Data Replication:** Testing S3-to-GCS sync, CloudSQL-to-RDS replication
- **Identity Bridge Testing:** Testing cross-cloud identity provider configurations
- **Data Exfiltration Paths:** Testing egress from AWS → GCP, GCP → AWS

### 3.6 Container & Orchestration Testing (Requires Pre-Approval)
- **Container Escape:** Testing Docker/containerd breakouts, privileged container abuse
- **Kubernetes RBAC:** Testing service account bindings, cluster role bindings
- **Pod Security:** Testing SecurityContext, AppArmor, SecPolicy violations
- **Image Registry Testing:** Container image enumeration, manifest retrieval, layer inspection
- **Helm Chart Analysis:** Template inspection, secret handling, value injection
- **Sidecar Injection:** Testing Istio/Envoy configuration, service mesh bypass

### 3.7 Account Lifecycle Testing (Requires Pre-Approval)
- **Self-service account deletion:** On designated test accounts with guaranteed admin restore capability
- **Password reset flow interception:** On test accounts; no interception of real user emails
- **Account recovery abuse:** Testing recovery token entropy, expiration
- **Cross-project account linking:** Testing Firebase project linking and unlinking

### 3.8 Social Engineering (Explicitly Prohibited)
- Phishing campaigns, vishing, or physical social engineering are **NOT AUTHORIZED** under this amendment.
- A separate engagement and approval process is required for any social engineering testing.

---

## 4. Access Requirements and Credentials

To enable complete testing, Lazarus AI agrees to provide the following within 72 hours of this amendment's execution:

| Resource | Purpose | Format |
|----------|---------|--------|
| VPN Configuration (WireGuard or OpenVPN) | Access to internal networks (`*.ml.lzrops.com`, internal VPCs) | Config file + credentials |
| Internal DNS Server IP | Resolution of internal-only hostnames | IP address |
| Firebase Test Accounts (×10) | 5 for prod project, 5 for preview project | Email + password |
| Production API Credentials | Testing `api.lazarusforms.com` with valid auth | `orgId` + `authKey` + `apiVersion` |
| GCP IAM Service Account | Read-only viewer role for `lazarus-forms-api` project | JSON key file |
| Rundeck Test Account | Non-privileged user for auth testing | Username + password |

---

## 5. Constraints and Limitations

### 5.1 Time Windows
- **24/7 authorization** remains in effect per Amendment 02.
- **Destructive tests** (account deletion, rate limiting DoS) require **8-hour advance notice** to Lazarus AI DevOps.

### 5.2 Data Handling
- All evidence, screenshots, and packet captures must be stored in the designated secure location only.
- No production customer data may be downloaded, copied, or retained by the tester.
- All findings remain confidential and are the property of Lazarus AI.

### 5.3 Out-of-Scope Activities
The following activities remain **STRICTLY PROHIBITED**:
- Any action that causes permanent data loss or corruption
- Any action that degrades production service availability
- Any testing of Lazarus AI employees, contractors, or customers without separate written authorization
- Any testing of third-party services not explicitly listed in Section 2 (e.g., Cloudflare, Stripe, SendGrid)
- Any testing outside the Lazarus AI organization perimeter (e.g., partner APIs, vendor integrations)

### 5.4 Communication Protocol
- All Critical and High findings must be reported to Lazarus AI Security within **4 hours** of discovery.
- Daily status updates via encrypted channel (Signal / Wire / ProtonMail) to the designated Lazarus AI liaison.

---

## 6. Liability and Insurance

Lazarus AI assumes liability for any unintended impact caused by authorized testing activities, provided the tester strictly adheres to the scope and constraints defined in this document. The tester agrees to maintain professional liability insurance (E&O) covering the duration of the engagement.

---

## 7. Signatures

By signing below, all parties acknowledge and agree to the terms of ROE Amendment 04.

| Role | Name | Signature | Date |
|------|------|-----------|------|
| **Pentest Lead** | Jon Bethea | _________________________________ | ___________ |
| **Lazarus AI Security Lead** | | _________________________________ | ___________ |
| **Lazarus AI Engineering Lead** | | _________________________________ | ___________ |
| **Lazarus AI Executive Sponsor** | | _________________________________ | ___________ |

---

*ROE Amendment 04 is effective upon receipt of all signatures. This document, in conjunction with ROE Amendments 01-03, constitutes the complete authorization for this engagement. Any deviation from this scope requires a written amendment prior to execution.*