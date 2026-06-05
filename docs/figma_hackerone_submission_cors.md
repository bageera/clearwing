# HackerOne Submission: CORS Misconfiguration on api.figma.com

**Date:** 2026-05-14
**Scan ID:** figma-audit-2026-05-14
**Severity:** Medium
**Asset:** api.figma.com

---

## Summary

The `api.figma.com` endpoint reflects arbitrary `Origin` headers in the `Access-Control-Allow-Origin` response header. While `Access-Control-Allow-Credentials` was not observed in the unauthenticated test, the origin reflection alone broadens the attack surface and may enable cross-origin data theft if credentials are ever enabled or if the behavior varies per endpoint.

## Steps to Reproduce

1. Send an HTTP request to `https://api.figma.com/` with a custom `Origin` header:

```bash
curl -I -H "Origin: https://evil.com" https://api.figma.com/
```

2. Observe the response header:

```
Access-Control-Allow-Origin: *
```

3. Repeat with additional arbitrary origins to confirm reflection:

```bash
curl -I -H "Origin: null" https://api.figma.com/
curl -I -H "Origin: https://staging.figma.com" https://api.figma.com/
```

## Evidence

- `Origin: https://evil.com` -> `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Credentials: ( absent )`
- `Origin: null` -> `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Credentials: ( absent )`
- `Origin: https://staging.figma.com` -> `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Credentials: ( absent )`
- `Origin: https:// attacker.com` -> `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Credentials: ( absent )`

## Impact

If `Access-Control-Allow-Credentials: true` is ever enabled (even on a subset of endpoints), an attacker can:
- Make authenticated cross-origin requests from an attacker-controlled domain
- Exfiltrate user data, file metadata, or team information
- Pivot to account takeover if session tokens are exposed

Even without credentials, wildcard or arbitrary origin reflection can:
- Weaken CSP and origin-based security boundaries
- Enable cache poisoning or XS-Leaks in combination with other bugs

## Recommendation

- Explicitly whitelist trusted origins rather than reflecting arbitrary values
- Omit `Access-Control-Allow-Origin` entirely for endpoints that do not require cross-origin access
- If cross-origin access is required, enforce an explicit allowlist and never combine it with `Access-Control-Allow-Credentials: true` for wildcard origins

## References

- OWASP CORS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html
- PortSwigger CORS: https://portswigger.net/web-security/cors

## Disclaimer

All testing was performed against in-scope bug bounty assets (`www.figma.com`, `api.figma.com`, and related properties) using read-only, non-destructive techniques. No user data was accessed or modified.
