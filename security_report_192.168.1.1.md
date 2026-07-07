# Security Assessment Report: 192.168.1.1

**Asset:** Spectrum ASKEY Router (SBE1V1K)  
**Scan Date:** 2026-05-20T19:22:33Z  
**Firmware:** 1.4.1-13-888155-g202602200357-SBE1V1K-prod  
**Web Server:** lighttpd/1.4.59  

---

## Executive Summary

The router at 192.168.1.1 (Spectrum ASKEY SBE1V1K) has **19 security findings**: 2 high, 7 medium, 5 low, 5 informational. The most critical issues are sensitive device information exposed without authentication and missing security headers that leave the management interface vulnerable to clickjacking and XSS. The path traversal probe was verified as a false positive.

---

## Asset Profile

| Field | Value |
|-------|-------|
| Model | SBE1V1K |
| Vendor | ASKEY (askey.com) |
| Firmware | 1.4.1-13-888155-g202602200357-SBE1V1K-prod |
| Serial | 70KW2509673433D |
| MAC | 90:D3:CF:C8:D3:42 |
| WAN IP | 173.169.227.220 |
| WAN IPv6 | 2603:9000:ff00:a6:55fb:4e29:fb3c:b31b/128 |
| Web Server | lighttpd/1.4.59 |
| SSL Cert | Self-signed, CN=askey.com, RSA 2048-bit |
| Open Ports | 53/tcp (DNS), 80/tcp (HTTP→redirect), 443/tcp (HTTPS) |
| TLS Versions | 1.0, 1.1, 1.2, 1.3 |
| HTTP/2 | Yes (h2 ALPN) |

---

## Findings

### HIGH Severity

#### H-01: Sensitive Device Information Exposed Without Authentication
- **Category:** Information Disclosure
- **Detail:** The router's unauthenticated `/cgi-bin/index.cgi` page exposes the WAN IPv4 address, IPv6 address, MAC address, serial number, model, and firmware version. The `/cgi-bin/connectivity_api` and `/cgi-bin/pods_api` endpoints also respond without authentication.
- **Evidence:** WAN IP (173.x.x.x), IPv6, MAC (90:D3:CF:C8:D3:42), Serial Number (70KW2509673433D), Model (SBE1V1K), FW Version all visible without login
- **Recommendation:** Require authentication to view device information. At minimum, redact WAN IP, MAC, and serial number from unauthenticated pages.

#### H-02: Multiple Security Headers Missing
- **Category:** HTTP Headers
- **Detail:** The router management interface is missing: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security, and X-XSS-Protection headers. This enables clickjacking, MIME-type confusion, and XSS attacks.
- **Evidence:** No security headers present in any HTTPS response
- **Recommendation:** Configure lighttpd to send: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'self'`, `Strict-Transport-Security: max-age=63072000`, `X-XSS-Protection: 1; mode=block`.

---

### MEDIUM Severity

#### M-01: Insecure TLS Version Enabled (TLS 1.0 and 1.1)
- **Category:** TLS
- **Detail:** The router accepts TLSv1.0 and TLSv1.1 connections, which are deprecated and vulnerable to downgrade attacks (BEAST, POODLE variants).
- **Evidence:** `openssl s_client -tls1` and `-tls1_1` both connect successfully
- **Recommendation:** Disable TLS 1.0 and 1.1. Only TLS 1.2+ should be accepted.

#### M-02: Vendor Default Self-Signed SSL Certificate
- **Category:** SSL/TLS
- **Detail:** The router uses a default ASKEY self-signed certificate (CN=askey.com, O=ASKEY, C=CN, OU=ROUTER). This enables MITM attacks as the cert cannot be verified against a trusted CA.
- **Evidence:** Issuer: C=CN, ST=TW, L=TB, O=ASKEY, OU=ROUTER, CN=askey.com/emailAddress=askey@askey.com
- **Recommendation:** Replace the default certificate with a unique cert. For home routers, consider DNS-based ACME or manually generated certs with unique key material.

#### M-03: Server Version Disclosed in HTTP Headers
- **Category:** Information Disclosure
- **Detail:** lighttpd/1.4.59 version is disclosed via the Server header. Attackers can target known vulnerabilities specific to this version.
- **Evidence:** `Server: lighttpd/1.4.59`
- **Recommendation:** Set `server.tag = ""` in lighttpd.conf or use a generic string like `server.tag = "WebServer"`.

#### M-04: connectivity_api Accessible Without Authentication
- **Category:** Auth Bypass
- **Detail:** `GET /cgi-bin/connectivity_api` returns "Connected" without authentication. Attackers can determine internet connectivity status and potentially use this for reconnaissance.
- **Evidence:** `GET /cgi-bin/connectivity_api -> 'Connected'`
- **Recommendation:** Require authentication for all CGI API endpoints.

#### M-05: pods_api Accessible Without Authentication
- **Category:** Auth Bypass
- **Detail:** `GET /cgi-bin/pods_api` returns pod data without authentication. Pod serial numbers can be enumerated.
- **Evidence:** `GET /cgi-bin/pods_api -> 'N/A'`
- **Recommendation:** Require authentication for all CGI API endpoints.

#### M-06: lighttpd 1.4.59 — Potential CVEs Applicable
- **Category:** Known Vulnerability
- **Detail:** lighttpd 1.4.59 may be affected by CVE-2022-37796 (HTTP request smuggling via chunked TE+CL) and other vulnerabilities patched in later versions. While the firmware build is from 2026, the lighttpd binary version suggests it may not include upstream patches.
- **Evidence:** Server: lighttpd/1.4.59
- **Recommendation:** Verify if lighttpd security patches are included in the firmware build. If not, update to lighttpd 1.4.68+. Suppress version disclosure.

#### M-07: Default/Weak Credential Risk
- **Category:** Authentication
- **Detail:** Spectrum routers commonly ship with default admin credentials (printed on label, or common patterns like admin/admin). The management interface uses a CGI-based login.
- **Recommendation:** Change default admin password to a strong, unique password. Disable remote admin access if not needed. Verify no backdoor accounts exist.

---

### LOW Severity

#### L-01: 2048-bit RSA Key (Minimum Acceptable)
- **Category:** SSL/TLS
- **Detail:** Certificate uses 2048-bit RSA, which is the minimum acceptable key size. 4096-bit or ECDSA P-384 keys are preferred for long-term security.
- **Recommendation:** Consider upgrading to stronger key material on next certificate renewal.

#### L-02: No Subject Alternative Name (SAN) in Certificate
- **Category:** SSL/TLS
- **Detail:** Certificate lacks SAN extensions, which will cause browser warnings in modern Chrome/Firefox versions.
- **Recommendation:** Regenerate certificate with SAN including the router hostname/IP.

#### L-03: POST connectivity_api Accepts JSON Without Auth
- **Category:** API
- **Detail:** POST to `/cgi-bin/connectivity_api` with JSON body returns HTTP 200 without authentication.
- **Recommendation:** Validate that POST endpoints require authentication and reject unexpected content types.

#### L-04: POST pods_api Accepts JSON Without Auth
- **Category:** API
- **Detail:** POST to `/cgi-bin/pods_api` with JSON body returns HTTP 200 without authentication.
- **Recommendation:** Validate that POST endpoints require authentication and reject unexpected content types.

#### L-05: Non-Standard HTTP Methods Accepted
- **Category:** HTTP Methods
- **Detail:** OPTIONS returns 200 (expected for CORS), CONNECT returns 400 (not 405/501).
- **Recommendation:** Restrict HTTP methods to GET, POST, HEAD only. Return 405 for all others.

---

### INFORMATIONAL

#### I-01: TLS 1.3 Supported
- **Category:** TLS
- **Detail:** The router supports TLS 1.3, which is good.
- **Recommendation:** Keep TLS 1.3 enabled.

#### I-02: DNS Resolver Responds to Queries
- **Category:** DNS
- **Detail:** Port 53 accepts DNS queries and resolves external domains (confirmed: google.com -> 142.250.176.78). Expected for a home router serving LAN clients.
- **Recommendation:** Ensure DNS is not accessible from WAN side. Restrict to internal interfaces only.

#### I-03: HTTP/2 Enabled
- **Category:** HTTP/2
- **Detail:** The router supports HTTP/2 via ALPN h2.
- **Recommendation:** Monitor for HTTP/2-specific CVEs in lighttpd.

#### I-04: No Permissive CORS Headers
- **Category:** CORS
- **Detail:** No Access-Control-Allow-Origin headers are sent, preventing cross-origin JavaScript interaction.
- **Recommendation:** Current configuration is acceptable. Maintain absence of permissive CORS headers.

#### I-05: Path Traversal — Not Exploitable (Verified)
- **Category:** Path Traversal
- **Detail:** Initial scan flagged `/cgi-bin/..;/etc/passwd` as returning HTTP 200. Verification shows the response is the router's default info page (index.cgi) or lighttpd 411 error page, not /etc/passwd content. The `/cgi-bin/..;/` path resolves to index.cgi due to lighttpd path normalization. Non-existent CGI paths correctly return 404.
- **Recommendation:** No action required. Path traversal is not exploitable on this firmware.

---

## Prioritized Remediation

| Priority | Finding | Action |
|----------|---------|--------|
| **P0** | H-01: Info disclosure | Restrict `/cgi-bin/index.cgi` and API endpoints behind authentication |
| **P0** | H-02: Missing headers | Configure lighttpd security headers (X-Frame-Options, CSP, HSTS, etc.) |
| **P1** | M-01: TLS 1.0/1.1 | Disable deprecated TLS versions |
| **P1** | M-03: Server version | Suppress lighttpd version in Server header |
| **P1** | M-07: Default creds | Change default admin password immediately |
| **P1** | M-06: lighttpd CVEs | Verify firmware patches, plan lighttpd update |
| **P2** | M-02: Self-signed cert | Generate unique certificate |
| **P2** | M-04/M-05: Unauth APIs | Require auth on all CGI endpoints |
| **P3** | L-01/L-02: Cert quality | Upgrade cert key size and add SAN |

---

## Scan Files

- **Script:** `/Users/jonbethea/projects/blacktech/nightwing/scan_router.py`
- **JSON Results:** `/Users/jonbethea/projects/blacktech/nightwing/scan_results_192.168.1.1.json`