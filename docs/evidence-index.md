# Evidence Index

This document maps all screenshots, reports, and logs generated during the Ghaymah SecOps Architecture to their corresponding tasks and findings. Readers can use this index to verify the authenticity of all claims made in the documentation.

| Evidence ID | File | Used In | Purpose |
|------------|------|---------|---------|
| **EV-001** | `security-audit/ghaymah_audit.png` | Module 1 | Demonstrates successful execution of the Bash audit script and highlights missing security headers and exposed ports. |
| **EV-002** | `privacy-architecture/certificate.png` | Module 3 | Proves manual verification of the TLS certificate issuer and validity dates using browser DevTools. |
| **EV-003** | `privacy-architecture/cookies.png` | Module 3 | Identifies client-side storage mechanisms and tracking cookies set by the application. |
| **EV-004** | `privacy-architecture/network_headers.png` | Module 3 | Validates HTTP response headers, proving the absence of HSTS and CSP policies. |
| **EV-005** | `privacy-architecture/network-overview.png` | Module 3 | Shows a waterfall of network requests, highlighting third-party analytics scripts loading on the client. |
| **EV-006** | `privacy-architecture/security.png` | Module 3 | Highlights browser-level security warnings regarding mixed content or deprecated cipher suites. |
| **EV-007** | `siem-engine/alerts.png` | Module 4 | Demonstrates the SIEM engine successfully parsing logs and generating actionable alerts. |
| **EV-008** | `siem-engine/ips.png` | Module 4 | Shows the IP Reputation tracking mechanism identifying hostile actors across multiple requests. |
| **EV-009** | `siem-engine/SIEM_UI.png` | Module 4 | Provides a full overview of the custom real-time SIEM dashboard interface. |
| **EV-010** | `siem-engine/test_logs/sample_attack.log` | Module 4 | Contains the synthetic attack data used to test the SIEM parsing rules. |

> [!TIP]
> All screenshots are embedded with technical commentary in their respective task markdown files. Follow the links in the **Used In** column to view the contextual analysis.
