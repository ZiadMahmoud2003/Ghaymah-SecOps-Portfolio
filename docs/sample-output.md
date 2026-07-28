# Sample Outputs: Security Audit

The following sample outputs demonstrate the functionality and reporting format of the `ghaymah_audit.sh` tool when executed against production targets.

## Port Audit Execution

```text
==================================================
GHAYMAH SECURITY AUDIT
==================================================

Target:
ghaymah.systems

-----------------------------------
PORT AUDIT
-----------------------------------
[PASS] HTTPS (443) reachable
[PASS] HTTP (80) reachable
[WARNING] SSH (22) exposed — ensure strong auth
[PASS] MySQL (3306) closed
[PASS] PostgreSQL (5432) closed
[PASS] Redis (6379) closed
[PASS] MongoDB (27017) closed
```

> [!TIP]
> **Reader Note:** Notice the script explicitly flags SSH (22) as a `[WARNING]` rather than a `[PASS]`, recognizing that while SSH may be necessary, it poses an inherent risk if exposed to the public internet without proper hardening.

---

## SSL/TLS Audit Execution

```text
-----------------------------------
SSL AUDIT
-----------------------------------
[PASS] HTTPS response code: 200
[PASS] TLS 1.3 Enabled
[PASS] Certificate Valid (312 days remaining)
[PASS] HSTS Enabled
[PASS] X-Frame-Options Enabled
[PASS] X-Content-Type-Options Enabled
[WARNING] Content-Security-Policy Missing
[WARNING] Permissions-Policy Missing
```

> [!NOTE]
> **Reader Note:** The SSL audit goes beyond basic certificate validation and deeply inspects the HTTP response headers to ensure full alignment with OWASP secure configurations.

---

## Permission Audit Execution

```text
-----------------------------------
PERMISSION AUDIT
-----------------------------------
[WARNING] World writable file: ./app/config/settings.env (777)
[WARNING] World writable file: ./app/logs/debug.log (666)
[PASS] No world writable directories
```

---

## Final Executive Summary

```text
-----------------------------------
SUMMARY
-----------------------------------
Critical : 0
Warnings : 3
Passed   : 12

Overall  : WARNING
```
