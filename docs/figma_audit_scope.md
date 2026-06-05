Figma Bug Bounty Audit Plan
Scope as of 2026-05-14

IN-SCOPE ASSETS
---------------

1. www.figma.com (URL)
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL
   Availability: LOW | Confidentiality: HIGH | Integrity: HIGH
   Stack: Rails, React, Ruby, JavaScript, AWS, AmazonRDS
   Note: "We are primarily looking for high/critical vulnerabilities"

2. api.figma.com (URL)
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL
   Availability: HIGH | Confidentiality: HIGH | Integrity: HIGH
   Stack: not specified (treat as same backend stack)

3. Figma Atlassian App (Jira Marketplace)
   URL: https://marketplace.atlassian.com/apps/1217865/figma-for-jira
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL
   Note: Unauthorized access via this app or its APIs is in scope

4. Figma Desktop App
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL

5. Figma iOS and Android apps
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL

6. Figma Slack App
   URL: https://figma.slack.com/apps/A01N2QYSA81-figma-and-figjam
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL
   Availability: HIGH | Confidentiality: HIGH | Integrity: HIGH

7. Figma for Microsoft Teams
   URL: https://appsource.microsoft.com/en-us/product/office/wa200004521
   Bounty eligible: yes | Submission eligible: yes
   Severity: up to CRITICAL
   Availability: HIGH | Confidentiality: HIGH | Integrity: HIGH

OUT OF SCOPE
------------
- www.designsystems.com (explicitly excluded from bounty and submission)
- Any asset not listed above
- Social engineering on Figma employees
- Physical attacks
- Third-party services not operated by Figma (AWS infrastructure itself is not in scope)

TECH STACK TARGETS
------------------
Rails + Ruby backend
React + JavaScript frontend
AWS (AmazonRDS, general AWS services)
API-first architecture (api.figma.com is a first-class target)

PRIORITIZATION
--------------
Phase 1: api.figma.com (highest integrity/confidentiality/availability reqs)
Phase 2: www.figma.com (Rails/React, primary user surface)
Phase 3: Third-party integrations (Slack, Teams, Atlassian)
Phase 4: Desktop and mobile apps (require binary analysis)

HACKERONE API KEY
-----------------
Stored in .env at project root
Do not commit, do not log, do not paste into terminal commands
