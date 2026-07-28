# Architectural Prevention Strategies on Ghaymah
## Preventing API Brute Force & Lateral Movement

> **Document ID:** GH-ARCH-2026-003  
> **Applies To:** Ghaymah Managed Kubernetes & Block Storage

---

## 1. Network Policy Architecture (Zero-Trust Microsegmentation)

### 1.1 Default-Deny Foundation

Every namespace on Ghaymah Kubernetes must start with a default-deny policy. This ensures no pod can communicate unless explicitly allowed.

```yaml
# default-deny-all.yaml — Apply to EVERY namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <target-namespace>
spec:
  podSelector: {}          # Applies to ALL pods in namespace
  policyTypes:
  - Ingress
  - Egress
```

### 1.2 Explicit Allow Policies (Least-Privilege)

```yaml
# allow-api-to-db.yaml — Only API pods can reach the database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-postgres
  namespace: data-pipeline
spec:
  podSelector:
    matchLabels:
      app: postgres
      tier: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
---
# allow-egress-dns-only.yaml — Pods can only resolve DNS, nothing else
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-dns-only
  namespace: data-pipeline
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Egress
  egress:
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### 1.3 Network Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GHAYMAH CLOUD PERIMETER                         │
│  ┌──────────────┐                                                   │
│  │  DDoS Shield  │ ← L3/L4 Volumetric Protection                   │
│  └──────┬───────┘                                                   │
│         ▼                                                           │
│  ┌──────────────┐                                                   │
│  │  WAF (CRS 4) │ ← L7 Application Firewall (OWASP rules)         │
│  └──────┬───────┘                                                   │
│         ▼                                                           │
│  ┌──────────────┐     ┌─────────────────────┐                       │
│  │ API Gateway  │────▶│ Rate Limiter         │                      │
│  │ (Ingress)    │     │ • Per-IP: 100/min    │                      │
│  │              │     │ • Per-User: 20/min   │                      │
│  │              │     │ • Global: 10K/min    │                      │
│  └──────┬───────┘     └─────────────────────┘                       │
│         │                                                           │
│  ╔══════╧══════════════════════════════════════════════════════╗     │
│  ║              KUBERNETES CLUSTER (Managed)                   ║     │
│  ║                                                             ║     │
│  ║  ┌─────────── Namespace: api-gateway ──────────────┐        ║     │
│  ║  │  [API Pods] ← mTLS (Istio) → [Auth Service]    │        ║     │
│  ║  │  NetworkPolicy: allow ingress from WAF only     │        ║     │
│  ║  └─────────────────────┬───────────────────────────┘        ║     │
│  ║                        │ mTLS                               ║     │
│  ║  ┌─────────── Namespace: data-pipeline ────────────┐        ║     │
│  ║  │  [Worker Pods] → [PostgreSQL] → [Redis Cache]   │        ║     │
│  ║  │  NetworkPolicy: allow from api-gateway only     │        ║     │
│  ║  │  Egress: DNS only (no internet)                 │        ║     │
│  ║  └─────────────────────┬───────────────────────────┘        ║     │
│  ║                        │                                    ║     │
│  ║  ┌─────────── Namespace: security-tools ───────────┐        ║     │
│  ║  │  [Wazuh DaemonSet] [n8n SOAR] [Falco]          │        ║     │
│  ║  │  [Elastic Stack]                                 │        ║     │
│  ║  │  NetworkPolicy: monitoring access to all NS     │        ║     │
│  ║  └──────────────────────────────────────────────────┘        ║     │
│  ╚══════════════════════════════════════════════════════════════╝     │
│                        │                                             │
│  ┌─────────────────────┴────────────────────────────┐               │
│  │           GHAYMAH BLOCK STORAGE                   │               │
│  │  • AES-256 encryption at rest (CMEK)             │               │
│  │  • Immutable snapshots with retention lock       │               │
│  │  • Cross-region replication (DR)                 │               │
│  └───────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Container Security Hardening

### 2.1 Pod Security Standards (Restricted Profile)

```yaml
# namespace-security-labels.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: data-pipeline
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 2.2 Hardened Pod Template

```yaml
# hardened-pod-template.yaml
apiVersion: v1
kind: Pod
metadata:
  name: api-server
  namespace: api-gateway
spec:
  automountServiceAccountToken: false   # No default SA token
  securityContext:
    runAsNonRoot: true                  # Never run as root
    runAsUser: 10001                    # Explicit non-root UID
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault             # Restrict syscalls
  containers:
  - name: api
    image: registry.ghaymah.systems/api-server:v2.3.1@sha256:abc123...  # Pinned digest
    securityContext:
      allowPrivilegeEscalation: false   # Cannot gain more privileges
      readOnlyRootFilesystem: true      # Immutable filesystem
      capabilities:
        drop:
          - ALL                         # Drop ALL Linux capabilities
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
        ephemeral-storage: "100Mi"
      requests:
        cpu: "100m"
        memory: "128Mi"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 50Mi
  - name: cache
    emptyDir:
      sizeLimit: 100Mi
```

### 2.3 Image Policy (OPA Gatekeeper Constraint)

```yaml
# require-signed-images.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: require-ghaymah-registry
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  parameters:
    repos:
    - "registry.ghaymah.systems/"    # Only allow images from trusted registry
```

---

## 3. API-Level Protection

### 3.1 Multi-Layer Rate Limiting Architecture

```
Request Flow:
  Client → [Global Rate Limit: 10K/min]
         → [Per-IP Rate Limit: 100/min]  
         → [Per-Account Rate Limit: 20/min]
         → [Per-Endpoint Rate Limit: varies]
         → API Handler

Rate Limit Response (429 Too Many Requests):
{
  "error": "rate_limit_exceeded",
  "retry_after": 60,
  "limit": 100,
  "remaining": 0,
  "reset": 1721890800
}
```

### 3.2 Authentication Hardening

| Control | Implementation |
|---------|---------------|
| MFA Enforcement | TOTP/WebAuthn mandatory for ALL accounts (including service accounts) |
| Password Policy | Min 14 chars, complexity required, breach database check (HaveIBeenPwned API) |
| Token Expiry | Access tokens: 15 min, Refresh tokens: 24 hrs, API keys: 90 days max |
| Account Lockout | Lock after 5 failed attempts, progressive delay (1min, 5min, 15min, 1hr) |
| Session Management | Single active session per account (configurable), IP binding optional |

---

## 4. Monitoring & Detection Architecture

### 4.1 Security Monitoring Stack

```
Data Sources:
  ├── K8s API Audit Logs ──────────────────┐
  ├── Container Runtime (Falco) ───────────┤
  ├── Wazuh Agent Logs ────────────────────┤──→ [Elastic/OpenSearch]
  ├── Application Logs (structured JSON) ──┤       │
  ├── Network Flow Logs ───────────────────┤       ├──→ [Kibana Dashboards]
  └── Ghaymah Platform Audit Logs ─────────┘       │
                                                    └──→ [Wazuh Manager]
                                                           │
                                                    ┌──────┴──────┐
                                                    │  n8n SOAR   │
                                                    │  Playbooks  │
                                                    └─────────────┘
                                                           │
                                               ┌───────────┼───────────┐
                                               ▼           ▼           ▼
                                          [Firewall]  [IAM API]   [Slack/PD]
                                          Auto-block  Lock acct   Alert team
```


