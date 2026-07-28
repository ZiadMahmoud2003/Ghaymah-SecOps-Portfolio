# Detection Testing & Validation Evidence

This document outlines the synthetic log testing framework used to validate the custom SIEM engine's parsing and detection logic.

## Sample Logs
The SIEM engine is fed a synthetic log file (`test_logs/sample_attack.log`) containing a mix of legitimate traffic and known attack patterns.

```http
192.168.1.100 - - [27/Jul/2026:10:15:32 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
10.0.5.55 - - [27/Jul/2026:10:15:33 +0000] "GET /login?user=admin' OR '1'='1 HTTP/1.1" 403 512 "-" "sqlmap/1.5.8"
10.0.5.55 - - [27/Jul/2026:10:15:34 +0000] "GET /api/v1/auth?user=admin&pass=123456 HTTP/1.1" 401 256 "-" "Hydra"
10.0.5.55 - - [27/Jul/2026:10:15:35 +0000] "GET /api/v1/auth?user=admin&pass=password HTTP/1.1" 401 256 "-" "Hydra"
172.16.0.10 - - [27/Jul/2026:10:15:38 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 128 "-" "curl/7.68.0"
```

## Expected Alerts
Based on the SIEM's RegEx signatures, feeding the above file must generate the following discrete alerts:

| Source IP | Target | Rule Triggered | Severity |
|-----------|--------|----------------|----------|
| `10.0.5.55` | `/login` | SQL Injection (`OR '1'='1`) | CRITICAL |
| `10.0.5.55` | `/api/v1/auth` | Brute Force (Multiple 401s from same IP) | HIGH |
| `172.16.0.10` | `/etc/passwd` | Path Traversal (`../../../`) | CRITICAL |

## Validation Evidence
*Refer to [Evidence EV-007 (Real-Time Alerts)](../siem_deployment_architecture.md#evidence-ev-007--real-time-alert-generation) for the screenshot proving the SIEM successfully generated these exact alerts in the UI dashboard.*
