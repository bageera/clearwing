Figma Audit — Task Plan
Generated from HackerOne scope export dated 2026-05-14

1  RECONNAISSANCE (Passive, no interaction with targets)
   1.1  Run passive subdomain enumeration against figma.com
        Tools: query_crt_sh, query_certspotter, run_subfinder, run_assetfinder
        Store results in ReconStore under target="figma.com", scan_id="figma-audit-2026"
   1.2  Run complete domain recon workflow for figma.com
        Tool: run_complete_domain_recon
        Outputs: subdomains, IPs, URLs, certificates, GitHub leak indicators
   1.3  Query Shodan for api.figma.com and www.figma.com
        Tool: query_shodan (from clearwing/native/shodan_tools.py)
        Requires: SHODAN_API_KEY env var
   1.4  Enumerate web archives for historical endpoints
        Tools: run_gau, run_waybackurls
        Target: figma.com, api.figma.com
   1.5  Technology fingerprinting on public pages
        Tool: extract_technologies_from_html (output_parsers.py)
        Confirm Rails/React/AWS stack from scope data
   1.6  Aggregate and correlate all recon findings
        Tool: aggregate_and_correlate_findings (osint_workflow.py)
        Generate recon summary via ReconStore

2  EXTERNAL INFRASTRUCTURE MAPPING
   2.1  DNS enumeration and probing
        Tools: run_dnsx, run_amass (enum mode)
        Map A, AAAA, CNAME, NS, MX, TXT, SOA records for figma.com
   2.2  HTTP probing of discovered subdomains
        Tool: run_httpx
        Input: subdomain list from phase 1
        Flags: -sc -cl -ct -rt (status code, content length, content type, response time)
   2.3  Screenshot and visual reconnaissance
        Tool: run_gowitness
        Input: live subdomain list from httpx
   2.4  Port scan of api.figma.com and www.figma.com
        Tool: run_nmap_scan (enumeration_tools.py)
        Options: -sT -Pn --top-ports 1000 -oX -

3  API TESTING (api.figma.com primary target)
   3.1  Figma REST API endpoint discovery
        Tool: run_ffuf (enumeration_tools.py)
        Wordlist: common API paths
        Target: api.figma.com
   3.2  Parameter fuzzing on known Figma API endpoints
        Tool: run_arjun (enumeration_tools.py)
        Discover hidden GET/POST/JSON parameters
   3.3  LLM-guided API fuzzing for auth bypass
        Tool: run_lazarus_fuzzer or equivalent LLM fuzzer
        Focus: OAuth token exchange, session management
   3.4  JWT analysis if tokens are present
        Tool: run_jwt_tool (enumeration_tools.py)
   3.5  SQL injection testing on API parameters
        Tool: run_sqlmap (enumeration_tools.py)
        Target: api.figma.com with discovered params
   3.6  NoSQL injection testing
        Tool: run_nosqlmap (enumeration_tools.py)

4  WEB APPLICATION TESTING (www.figma.com)
   4.1  Directory and file enumeration
        Tool: run_gobuster (enumeration_tools.py)
        Wordlist: dirb/common.txt
   4.2  Technology-specific vulnerability scans
        Tool: run_nikto (enumeration_tools.py)
        Rails-specific checks
   4.3  XSS testing on reflected/input surfaces
        Tool: run_dalfox (enumeration_tools.py)
   4.4  CORS and auth configuration review
        Manual + automated header analysis from httpx output
   4.5  TLS/SSL analysis
        Tool: tls_tools.py functions

5  GITHUB / SOURCE CODE LEAKAGE
   5.1  Search GitHub for Figma org code leaks
        Tool: search_github_code
        Queries: org:Figma filename:.env, org:Figma AKIA, org:Figma private_key
   5.2  Search commit history for removed secrets
        Tool: search_github_commits
        Queries: org:Figma "remove password", org:Figma "api_key"
   5.3  Clone and scan public repositories for secrets
        Tools: run_gitleaks, run_trufflehog (container-based)
        Target: Figma public repos if any

6  THIRD-PARTY INTEGRATION TESTING
   6.1  Figma Slack App surface analysis
        Target: https://figma.slack.com/apps/A01N2QYSA81
        Focus: OAuth scopes, callback URL manipulation
   6.2  Figma for Microsoft Teams surface analysis
        Target: https://appsource.microsoft.com/en-us/product/office/wa200004521
        Focus: Teams app permission model
   6.3  Figma Atlassian App (Jira) surface analysis
        Target: https://marketplace.atlassian.com/apps/1217865/figma-for-jira
        Focus: connect/app authorization flows
   6.4  Desktop app update mechanism (if reachable)
        Note: binary analysis deferred unless update endpoint is web-accessible

7  DESKTOP / MOBILE (Deferred unless web surface found)
   7.1  Check if desktop app uses web-based update/telemetry
        Target: any api.figma.com or figma.com endpoint serving desktop binaries
   7.2  If web surface exists, proxy through MITM for analysis
        Tool: run_maltego or mitm_proxy.py
   7.3  Otherwise mark as requiring binary RE and defer

8  DATA CORRELATION AND REPORTING
   8.1  Pull all recon results from ReconStore for figma.com
        Tool: get_combined_recon_results
   8.2  Generate recon summary with recommendations
        Tool: generate_recon_summary
   8.3  Run intelligence correlation across all findings
        Tool: IntelCorrelator (correlation.py)
        Identify infrastructure patterns (AWS, cloud services)
   8.4  Export findings to JSONL for further processing
        Tool: export_to_jsonl

9  HackerOne REPORTING
   9.1  For validated findings, generate HackerOne template
        Tool: DisclosureTemplate generator (sourcehunt/disclosure.py)
        Format: hackerone
   9.2  Draft submission via HackerOne API
        Tool: to be built — requires HackerOne GraphQL API client
        API key: loaded from .env (SPCKdnriMHZWMpy0SQk7I2WozzNUMNFunnIu9RyNDxI=)
        Note: test API calls against HackerOne sandbox first
   9.3  Track submission status in ReconStore

RULES OF ENGAGEMENT
-------------------
- No automated exploitation beyond what is explicitly in scope
- Rate limit all requests to avoid impacting production
- Stop immediately if any out-of-scope asset is touched
- HackerOne API key: never log, never commit, use env var only
- Report severity must not exceed CRITICAL per scope definition
- Availability testing on www.figma.com is LOW requirement — light load only
