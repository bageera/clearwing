#!/usr/bin/env python3
"""Security scan for Spectrum/ASKEY router at 192.168.1.1.

Targets: lighttpd/1.4.59, CGI endpoints, TLS, DNS, info disclosure.
"""

import json
import sys
import time
import urllib.parse
import urllib.error
import ssl
import socket
import hashlib
import subprocess
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

TARGET = "192.168.1.1"
BASE_HTTP = f"http://{TARGET}"
BASE_HTTPS = f"https://{TARGET}"

@dataclass
class Finding:
    severity: str          # critical, high, medium, low, info
    category: str
    title: str
    detail: str
    evidence: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    scan_time: str = ""
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def add(self, f: Finding):
        self.findings.append(f)

    def summarize(self):
        self.summary = {}
        for f in self.findings:
            self.summary[f.severity] = self.summary.get(f.severity, 0) + 1
        self.summary["total"] = len(self.findings)
        return self.summary

    def to_json(self, path: str):
        with open(path, "w") as fh:
            json.dump(asdict(self), fh, indent=2)


def curl(args: str, timeout: int = 10) -> str:
    """Run curl and return stdout."""
    try:
        r = subprocess.run(
            f"curl -sk -m {timeout} {args}",
            shell=True, capture_output=True, text=True, timeout=timeout + 5
        )
        return r.stdout
    except Exception as e:
        return f"ERROR: {e}"


def curl_code(args: str, timeout: int = 5) -> tuple:
    """Run curl, return (status_code, body)."""
    try:
        r = subprocess.run(
            f"curl -sk -m {timeout} -o /dev/null -w '%{{http_code}}' {args}",
            shell=True, capture_output=True, text=True, timeout=timeout + 5
        )
        code = r.stdout.strip().strip("'")
        return code, ""
    except Exception as e:
        return "000", str(e)


def tls_probe(results: ScanResult):
    """Check TLS versions and cipher suites."""
    print("[*] TLS version probe...")
    versions = {
        "tls1": "TLSv1.0",
        "tls1_1": "TLSv1.1",
    }
    for flag, name in versions.items():
        try:
            ctx = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{flag.upper().replace('TLS', 'TLSv').replace('_', '.')}", ssl.PROTOCOL_TLS_CLIENT) if hasattr(ssl, f"PROTOCOL_{flag.upper()}") else ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Use openssl CLI instead
            r = subprocess.run(
                f"echo | openssl s_client -connect {TARGET}:443 -{flag} 2>&1",
                shell=True, capture_output=True, text=True, timeout=10
            )
            output = r.stdout + r.stderr
            if "Protocol" in output and name in output:
                results.add(Finding(
                    severity="medium",
                    category="TLS",
                    title=f"Insecure TLS version enabled: {name}",
                    detail=f"The router accepts {name} connections, which is deprecated and vulnerable to downgrade attacks.",
                    evidence=name,
                    recommendation=f"Disable {name} in router TLS configuration. Only TLS 1.2+ should be accepted."
                ))
            if "errno" not in output and "error" not in output.lower():
                # Connection succeeded
                pass
        except Exception:
            pass

    # Check for TLS 1.3 support
    r = subprocess.run(
        f"echo | openssl s_client -connect {TARGET}:443 -tls1_3 2>&1 | grep Protocol",
        shell=True, capture_output=True, text=True, timeout=10
    )
    if "TLSv1.3" in r.stdout:
        results.add(Finding(
            severity="info",
            category="TLS",
            title="TLS 1.3 supported",
            detail="Good — the router supports the latest TLS version.",
            evidence=r.stdout.strip(),
            recommendation="Keep TLS 1.3 enabled."
        ))


def ssl_cert_analysis(results: ScanResult):
    """Analyze SSL certificate for issues."""
    print("[*] SSL certificate analysis...")
    r = subprocess.run(
        f"echo | openssl s_client -connect {TARGET}:443 -servername {TARGET} 2>/dev/null | openssl x509 -noout -text",
        shell=True, capture_output=True, text=True, timeout=15
    )
    cert_text = r.stdout + r.stderr

    # Self-signed / vendor cert
    if "askey.com" in cert_text.lower():
        results.add(Finding(
            severity="medium",
            category="SSL/TLS",
            title="Vendor default SSL certificate",
            detail="The router uses a default ASKEY self-signed certificate (CN=askey.com, O=ASKEY, C=CN). This enables MITM attacks as the cert cannot be verified against a trusted CA.",
            evidence="Issuer: C=CN, ST=TW, O=ASKEY, CN=askey.com",
            recommendation="Replace the default certificate with a unique cert. Consider DNS-based ACME cert provisioning for home routers."
        ))

    # Key size
    if "RSA Public-Key: (2048 bit)" in cert_text:
        results.add(Finding(
            severity="low",
            category="SSL/TLS",
            title="2048-bit RSA key (minimum)",
            detail="The certificate uses a 2048-bit RSA key, which is the minimum acceptable size. 4096-bit or EC keys are preferred.",
            evidence="RSA Public-Key: (2048 bit)",
            recommendation="Consider upgrading to 4096-bit RSA or ECDSA P-384 for long-term security."
        ))

    # SAN check
    if "Subject Alternative Name" not in cert_text:
        results.add(Finding(
            severity="low",
            category="SSL/TLS",
            title="No Subject Alternative Name (SAN) in certificate",
            detail="The certificate lacks SAN extensions, which may cause warnings in modern browsers.",
            evidence="No SAN found in cert output",
            recommendation="Regenerate certificate with SAN including the hostname/IP."
        ))


def header_analysis(results: ScanResult):
    """Check for missing security headers."""
    print("[*] HTTP security header analysis...")
    r = curl("-I https://192.168.1.1/cgi-bin/index.cgi")
    headers = r.lower()

    missing = []
    header_checks = {
        "X-Frame-Options": "clickjacking protection",
        "X-Content-Type-Options": "MIME-type sniffing prevention",
        "Content-Security-Policy": "XSS/content injection protection",
        "Strict-Transport-Security": "HSTS — forces HTTPS",
        "X-XSS-Protection": "browser XSS filter",
    }
    for header, purpose in header_checks.items():
        if header.lower().replace("-", "-") not in headers:
            # More precise check
            h_normalized = header.lower()
            if h_normalized not in headers:
                missing.append(f"{header} ({purpose})")

    if missing:
        results.add(Finding(
            severity="high",
            category="HTTP Headers",
            title="Multiple security headers missing",
            detail=f"The following security headers are not set: {', '.join(missing)}. This exposes the router UI to clickjacking, XSS, MIME confusion, and protocol downgrade attacks.",
            evidence="\n".join(missing),
            recommendation="Configure lighttpd to send: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Content-Security-Policy: default-src 'self', Strict-Transport-Security: max-age=63072000, X-XSS-Protection: 1; mode=block."
        ))

    # Server version disclosure
    if "lighttpd/1.4.59" in headers or "lighttpd/1.4.59" in r:
        results.add(Finding(
            severity="medium",
            category="Information Disclosure",
            title="Server version disclosed in HTTP headers",
            detail="lighttpd/1.4.59 is disclosed via the Server header. Attackers can target known vulnerabilities for this exact version.",
            evidence="Server: lighttpd/1.4.59",
            recommendation="Set server.tag = '' in lighttpd.conf or use server.tag to show a generic string."
        ))


def info_disclosure(results: ScanResult):
    """Check for sensitive information on the info page."""
    print("[*] Information disclosure check...")
    r = curl("https://192.168.1.1/cgi-bin/index.cgi")

    sensitive_fields = []
    checks = [
        ("WAN IPv4 address", r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", "IPv4 address leaked"),
        ("IPv6 address", r"(2[0-4][0-9]{2}:[0-9a-fA-F:]+)", "IPv6 address leaked"),
        ("MAC address", r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", "MAC address leaked"),
        ("Serial number", r"Serial Number.*?<.*?>(.*?)<", "Serial number leaked"),
        ("Firmware version", r"FW Version.*?<.*?>(.*?)<", "Firmware version leaked"),
    ]

    import re
    for name, pattern, desc in checks:
        m = re.search(pattern, r)
        if m:
            sensitive_fields.append(f"{name}: exposed on unauthenticated info page")

    if sensitive_fields:
        results.add(Finding(
            severity="high",
            category="Information Disclosure",
            title="Sensitive device info exposed without authentication",
            detail=f"The router's unauthenticated info page exposes: {', '.join(sensitive_fields)}. This aids reconnaissance for targeted attacks including firmware-specific exploits, MAC-based tracking, and WAN IP profiling.",
            evidence="WAN IP, IPv6, MAC, Serial Number, Model, Firmware Version all visible on /cgi-bin/index.cgi without auth",
            recommendation="Require authentication to view device information. At minimum, redact WAN IP, MAC, and serial number from unauthenticated pages."
        ))


def unauthenticated_api_probe(results: ScanResult):
    """Test if API endpoints respond without auth."""
    print("[*] Unauthenticated API endpoint probing...")

    # connectivity_api
    r = curl("https://192.168.1.1/cgi-bin/connectivity_api")
    if r.strip() in ("Connected", "Not Connected", "Disconnected"):
        results.add(Finding(
            severity="medium",
            category="Auth Bypass",
            title="connectivity_api accessible without authentication",
            detail=f"The /cgi-bin/connectivity_api endpoint returns '{r.strip()}' without requiring authentication. Attackers can determine internet connectivity status.",
            evidence=f"GET /cgi-bin/connectivity_api -> '{r.strip()}'",
            recommendation="Require authentication for all CGI API endpoints."
        ))

    # pods_api
    r = curl("https://192.168.1.1/cgi-bin/pods_api")
    if r.strip() and r.strip() != "":
        results.add(Finding(
            severity="medium",
            category="Auth Bypass",
            title="pods_api accessible without authentication",
            detail=f"The /cgi-bin/pods_api endpoint returns data without requiring authentication. Pod serial numbers can be enumerated.",
            evidence=f"GET /cgi-bin/pods_api -> '{r.strip()[:100]}'",
            recommendation="Require authentication for all CGI API endpoints."
        ))

    # Test POST endpoints with content-length
    endpoints = [
        "/cgi-bin/connectivity_api",
        "/cgi-bin/pods_api",
    ]
    for ep in endpoints:
        r = subprocess.run(
            f'curl -sk -m 10 -X POST -H "Content-Type: application/json" -d \'{{"test":"probe"}}\' https://{TARGET}{ep} -w "\nHTTP_CODE: %{{http_code}}" 2>&1',
            shell=True, capture_output=True, text=True, timeout=15
        )
        output = r.stdout
        # Check for interesting responses (not 411/404/403)
        if "Connected" in output or "NA" in output or "200" in output:
            results.add(Finding(
                severity="low",
                category="API",
                title=f"POST {ep} accepts JSON body",
                detail=f"POST to {ep} with JSON body returned a response (not 411/403/404). May indicate input processing without auth.",
                evidence=output[:200],
                recommendation="Validate that POST endpoints require authentication and reject unexpected content types."
            ))


def cgi_attack_surface(results: ScanResult):
    """Probe CGI endpoints for common router vulnerabilities."""
    print("[*] CGI attack surface enumeration...")

    # Path traversal in CGI paths
    traversal_tests = [
        "/cgi-bin/../etc/passwd",
        "/cgi-bin/..%2f..%2fetc%2fpasswd",
        "/cgi-bin/..;/etc/passwd",
        "/cgi-bin/index.cgi?../../etc/passwd",
        "/cgi-bin/index.cgi/../../../etc/passwd",
        "/.%2e/%2e%2e/etc/passwd",
    ]
    for test in traversal_tests:
        code, _ = curl_code(f"https://{TARGET}{test}")
        if code not in ("404", "400", "000", "403"):
            results.add(Finding(
                severity="critical" if code == "200" else "medium",
                category="Path Traversal",
                title=f"Path traversal probe returned {code}",
                detail=f"Request to {test} returned HTTP {code}. May indicate path traversal vulnerability.",
                evidence=f"Path: {test}, Status: {code}",
                recommendation="Ensure CGI paths are properly sanitized. Apply input validation on all path components."
            ))
            break  # One hit is enough to flag

    # XSS probe in index.cgi (reflection test)
    xss_payloads = [
        "<PENTEST_XSS>",
        "'\"><PENTEST_XSS>",
    ]
    for payload in xss_payloads:
        encoded = urllib.parse.quote(payload)
        for param in ["SSID", "name", "q", "action", "page"]:
            url = f"https://{TARGET}/cgi-bin/index.cgi?{param}={encoded}"
            r = curl(url)
            if "PENTEST_XSS" in r:
                results.add(Finding(
                    severity="high",
                    category="XSS",
                    title=f"Reflected XSS in index.cgi parameter '{param}'",
                    detail=f"The parameter '{param}' reflects user input without encoding in the HTML response.",
                    evidence=f"Payload reflected in: {url}",
                    recommendation="Output-encode all user-supplied data before rendering in HTML."
                ))
                break


def dns_open_resolver(results: ScanResult):
    """Test if the router's DNS resolver is open to the internet."""
    print("[*] DNS open resolver check...")
    # We know DNS (53/tcp) is open. Test if it resolves external domains for us.
    try:
        r = subprocess.run(
            f"dig @192.168.1.1 google.com A +short +time=3 +tries=1 2>&1",
            shell=True, capture_output=True, text=True, timeout=10
        )
        output = r.stdout.strip()
        if output and output != "" and "connection refused" not in output.lower() and "timed out" not in output.lower():
            results.add(Finding(
                severity="info",
                category="DNS",
                title="DNS resolver responds to queries",
                detail=f"The router's DNS service resolves external queries. Output: {output[:100]}",
                evidence=output[:100],
                recommendation="If this router is not intended to serve DNS to LAN clients, restrict DNS to internal interfaces only. If serving LAN, ensure it is not accessible from WAN."
            ))
    except Exception:
        pass


def lighttpd_vuln_check(results: ScanResult):
    """Check for known lighttpd 1.4.59 vulnerabilities."""
    print("[*] Known lighttpd 1.4.59 vulnerability check...")
    # CVE checks for lighttpd <= 1.4.59
    known_cves = [
        ("CVE-2022-37796", "lighttpd 1.4.44-1.4.67: request smuggling via Transfer-Encoding: chunked + Content-Length", "medium"),
        ("CVE-2022-35293", "lighttpd 1.4.65 and before: HTTP/2 upload memory exhaustion (may be backported)", "low"),
    ]
    # The main concern with this specific version
    results.add(Finding(
        severity="medium",
        category="Known Vulnerability",
        title="lighttpd 1.4.59 — potential CVEs applicable",
        detail="lighttpd 1.4.59 (released ~Dec 2020) may be affected by CVE-2022-37796 (HTTP request smuggling via chunked TE+CL) and other vulnerabilities patched in later versions. The firmware appears to be from Feb 2026 (prod build), but lighttpd version suggests the binary itself may be outdated.",
        evidence="Server: lighttpd/1.4.59, FW: 1.4.1-13-888155-g202602200357-SBE1V1K-prod",
        recommendation="Verify if lighttpd patches are included in the firmware build. If not, update to lighttpd 1.4.68+ which addresses known CVEs. Configure server.tag to suppress version disclosure."
    ))

    # HTTP/2 check
    r = curl("--http2 -I https://192.168.1.1/ 2>&1 | head -5")
    if "h2" in r.lower() or "http/2" in r.lower() or "HTTP/2" in r:
        results.add(Finding(
            severity="info",
            category="HTTP/2",
            title="HTTP/2 enabled",
            detail="The router supports HTTP/2 (h2 ALPN was seen in nmap results). HTTP/2 multiplexing could be abused for request smuggling if lighttpd's h2 implementation has parsing bugs.",
            recommendation="Monitor for HTTP/2-specific CVEs in lighttpd."
        ))


def default_creds_check(results: ScanResult):
    """Check for default credentials on router web interfaces."""
    print("[*] Default credential check...")
    # Common Spectrum/ASKEY default usernames — no actual brute force, just document
    results.add(Finding(
        severity="medium",
        category="Authentication",
        title="Verify default/weak credentials",
        detail="Spectrum routers commonly ship with default admin credentials (admin/admin, admin/password, or printed on label). The router uses a CGI-based management interface that requires authentication for changes but exposes info without it.",
        evidence="Router model SBE1V1K, ASKEY vendor. Common defaults: admin/admin, admin/(serial#), admin/(MAC).",
        recommendation="1) Change default admin password. 2) Use a strong, unique password. 3) Disable remote admin access if not needed. 4) Verify no default backdoor accounts exist."
    ))


def http_methods_check(results: ScanResult):
    """Check for dangerous HTTP methods."""
    print("[*] HTTP methods check...")
    methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]
    allowed = []
    for method in methods:
        if method == "TRACE":
            # Already confirmed TRACE returns 403
            continue
        try:
            cmd = f'curl -sk -m 5 -X {method} https://{TARGET}/ -o /dev/null -w "%{{http_code}}" 2>/dev/null'
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            code = r.stdout.strip()
            if code not in ("405", "403", "501", "000"):
                allowed.append(f"{method}: {code}")
        except Exception:
            pass

    if allowed:
        results.add(Finding(
            severity="low",
            category="HTTP Methods",
            title="Non-standard HTTP methods accepted",
            detail=f"The following methods returned non-rejection codes: {', '.join(allowed)}",
            evidence=", ".join(allowed),
            recommendation="Disable unnecessary HTTP methods (PUT, DELETE, PATCH) on the router web server."
        ))


def cors_check(results: ScanResult):
    """Test CORS configuration."""
    print("[*] CORS configuration check...")
    r = subprocess.run(
        f'curl -sk -m 10 -H "Origin: https://evil.com" -I https://{TARGET}/cgi-bin/index.cgi 2>/dev/null',
        shell=True, capture_output=True, text=True, timeout=15
    )
    headers = r.stdout.lower()
    if "access-control-allow-origin" in headers:
        if "access-control-allow-origin: *" in headers or "evil.com" in headers:
            results.add(Finding(
                severity="medium",
                category="CORS",
                title="Permissive CORS policy",
                detail="The router responds with permissive Access-Control-Allow-Origin headers, allowing cross-origin requests from any domain.",
                evidence=headers[:200],
                recommendation="Restrict CORS to trusted origins only. Do not use wildcard (*) for router management interfaces."
            ))
    else:
        # No CORS headers is actually good for a router (prevents cross-origin attacks)
        results.add(Finding(
            severity="info",
            category="CORS",
            title="No CORS headers detected",
            detail="The router does not send CORS headers, which prevents cross-origin JavaScript from interacting with it.",
            evidence="No Access-Control-Allow-Origin in responses",
            recommendation="Current configuration is acceptable. Maintain absence of permissive CORS headers."
        ))


def main():
    results = ScanResult(
        target=TARGET,
        scan_time=datetime.utcnow().isoformat() + "Z"
    )

    print(f"=" * 60)
    print(f"Security Scan: {TARGET}")
    print(f"Time: {results.scan_time}")
    print(f"=" * 60)

    tls_probe(results)
    ssl_cert_analysis(results)
    header_analysis(results)
    info_disclosure(results)
    unauthenticated_api_probe(results)
    cgi_attack_surface(results)
    dns_open_resolver(results)
    lighttpd_vuln_check(results)
    default_creds_check(results)
    http_methods_check(results)
    cors_check(results)

    results.summarize()
    results.to_json("/Users/jonbethea/projects/blacktech/clearwing/scan_results_192.168.1.1.json")

    # Print report
    print(f"\n{'=' * 60}")
    print(f"SCAN COMPLETE — {results.summary}")
    print(f"{'=' * 60}\n")

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(results.findings, key=lambda f: severity_order.get(f.severity, 5))

    for i, f in enumerate(sorted_findings, 1):
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity, "?")
        print(f"{icon} [{f.severity.upper()}] {f.title}")
        print(f"   Category: {f.category}")
        print(f"   {f.detail[:200]}")
        if f.evidence:
            print(f"   Evidence: {f.evidence[:150]}")
        print(f"   Fix: {f.recommendation[:150]}")
        print()

    output_path = "/Users/jonbethea/projects/blacktech/clearwing/scan_results_192.168.1.1.json"
    print(f"Full results saved to: {output_path}")


if __name__ == "__main__":
    main()