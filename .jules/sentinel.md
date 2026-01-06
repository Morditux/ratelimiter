## 2024-03-24 - Trusted Proxies for Rate Limiting
**Vulnerability:** IP Spoofing via X-Forwarded-For
**Learning:** `DefaultKeyFunc` blindly trusted the first IP in `X-Forwarded-For`, allowing attackers to spoof their IP by injecting a fake header. Standard `strings.Split(xff, ",")[0]` is vulnerable if the proxy appends to the list.
**Prevention:** Use `TrustedIPKeyFunc` which iterates backwards through the IP chain, trusting only configured proxies (CIDRs) and stopping at the first untrusted IP. This ensures the rate limit key is the true client IP or the last untrusted hop.
