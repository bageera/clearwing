#!/usr/bin/env bash
# HackerOne API submission template
# Replace [REDACTED] with your actual API key before running.
# Do NOT commit this file with a real key.

H1_API_KEY="[REDACTED]"
PROGRAM_HANDLE="figma"

curl -s -X POST "https://api.hackerone.com/v1/reports" \
  -u "${H1_API_KEY}:" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "type": "report",
      "attributes": {
        "title": "CORS Misconfiguration on api.figma.com",
        "vulnerability_types": ["cors-misconfiguration"],
        "severity_rating": 3,
        "summary": "The api.figma.com endpoint reflects arbitrary Origin headers in Access-Control-Allow-Origin.",
        "reproduction_instructions": "1. curl -I -H \"Origin: https://evil.com\" https://api.figma.com/
2. Observe ACO reflects the arbitrary origin.",
        "impact": "Cross-origin data theft if credentials are enabled. Broadens attack surface for XS-Leaks.",
        "mitigation": "Explicitly whitelist trusted origins. Avoid wildcard + credentials combination."
      },
      "relationships": {
        "program": {
          "data": {
            "type": "program",
            "attributes": {
              "handle": "'"${PROGRAM_HANDLE}"'"
            }
          }
        }
      }
    }
  }' | jq .
