# Ransomware Incident Response Plan
## Ghaymah Block Storage Encryption Event

> **Document ID:** GH-RANSOM-IRP-2026-001  
> **Classification:** CONFIDENTIAL — EMERGENCY RESPONSE  

---

## Executive Summary
This playbook outlines the exact procedures for containing, eradicating, and recovering from a Ransomware encryption event affecting Ghaymah Block Storage volumes. The strategy heavily emphasizes **Immutable Backups** and mandates wiping the Kubernetes infrastructure prior to data restoration to prevent reinfection.

## Incident Overview
**Scenario:** An attacker compromises a Kubernetes pod, escalates privileges, and executes ransomware, encrypting all attached Block Storage volumes. A ransom note is dropped.
**Objective:** Contain the spread within 60 minutes, eradicate the persistence mechanism, and restore operations from immutable snapshots with a Recovery Time Objective (RTO) of 2 hours.

## Response Matrix

| Phase | Goal | Key Actions |
|-------|------|-------------|
| **Containment** | Stop encryption spread | Isolate network, detach storage, freeze IAM. |
| **Eradication** | Remove attacker | Wipe infected namespaces, rotate keys. |
| **Recovery** | Restore services | Rebuild from clean images, restore immutable snapshots. |

---

## Containment
*(First 60 Minutes)*

### T+0 to T+5 Minutes — IMMEDIATE ACTIONS (Automated + Manual)

```
╔══════════════════════════════════════════════════════════════════════════╗
║  ⚠️  RANSOMWARE DETECTED — EXECUTE IMMEDIATELY — DO NOT DELAY          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  1. DO NOT SHUT DOWN affected systems (preserves memory forensics)     ║
║  2. DO NOT PAY the ransom                                               ║
║  3. DO NOT attempt to decrypt files with unknown tools                 ║
║  4. DO NOT communicate with the attacker                               ║
╚══════════════════════════════════════════════════════════════════════════╝
```

| Time | Action | Owner | Method |
|------|--------|-------|--------|
| T+0 | **ALERT**: Declare ransomware incident via PagerDuty P1 | SOC L1 | n8n automated trigger from Wazuh FIM alert |
| T+1 | **ISOLATE NETWORK**: Apply emergency deny-all NetworkPolicies to ALL namespaces | SOC L2 | kubectl + n8n playbook (see below) |
| T+2 | **DISCONNECT STORAGE**: Detach Block Storage volumes from compromised pods | Platform Team | Ghaymah API: `ghaymah bs detach` |
| T+3 | **PRESERVE EVIDENCE**: Create forensic snapshots of all affected volumes | SOC L2 | Ghaymah API: `ghaymah bs snapshot create` |
| T+4 | **FREEZE IAM**: Rotate ALL API keys and tokens; disable external access | IAM Team | n8n playbook → Ghaymah IAM API |
| T+5 | **NOTIFY**: Alert CISO, Legal, and Executive leadership | Incident Commander | Automated Slack/Email via n8n |

### n8n SOAR Playbook — Ransomware Auto-Containment

```
Trigger: Wazuh FIM alert (file integrity monitoring) detecting mass 
         file modifications + known ransomware extensions (.encrypted, 
         .locked, .cry, .crypt)

Workflow:
1. [Wazuh Webhook] → Receive FIM alert
2. [Validate] → Check if >100 files modified in <5 min (ransomware pattern)
3. [CRITICAL PATH - Parallel Execution]:
   ├── [Network Isolation]
   │   └── kubectl apply emergency-deny-all to all namespaces
   ├── [Storage Protection]
   │   ├── Lock all Block Storage snapshots (set immutable flag)
   │   └── Create emergency snapshots of unaffected volumes
   ├── [IAM Lockdown]
   │   ├── Revoke all active API tokens
   │   ├── Force-rotate all service account keys
   │   └── Disable all external API access
   └── [Alerting]
       ├── PagerDuty P1 to SOC + Platform + CISO
       ├── Slack #incident-response channel
       └── Email to legal@ghaymah.systems
4. [Evidence Collection]
   ├── Capture pod memory dumps (if possible)
   ├── Export K8s audit logs for last 24h
   └── Preserve network flow logs
5. [Create War Room] → Auto-create Slack channel #ransomware-ir-{date}
```

### T+5 to T+15 Minutes — SCOPING & ASSESSMENT

| Time | Action | Details |
|------|--------|---------|
| T+5 | **Identify Patient Zero** | Review Wazuh FIM alerts chronologically. Identify first pod/volume with file modifications. Check K8s audit logs for initial compromise vector. |
| T+7 | **Determine Blast Radius** | List all affected Block Storage volumes: `ghaymah bs list --status=attached`. Check which namespaces/pods have encrypted files. |
| T+10 | **Identify Ransomware Variant** | Analyze ransom note format, file extension, and encryption method. Upload sample to VirusTotal/MalwareBazaar (use isolated network). Check ID Ransomware (id-ransomware.malwarehunterteam.com). |
| T+12 | **Assess Data Impact** | Determine what data was encrypted: PII, financial, source code, configs. Check if data was also exfiltrated (double extortion check). |
| T+15 | **Initial Situation Report** | Brief Incident Commander with: variant, blast radius, data impact, backup status. |

### T+15 to T+30 Minutes — CONTAINMENT DEEPENING

```bash
# 1. Network micro-segmentation — isolate every namespace
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ransomware-emergency-isolate
  namespace: ${ns}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
done

# 2. Kill all non-essential workloads
kubectl get deployments -A -o json | jq -r '
  .items[] | 
  select(.metadata.namespace != "kube-system") | 
  select(.metadata.namespace != "security-tools") | 
  "\(.metadata.namespace)/\(.metadata.name)"
' | while read deploy; do
  ns=$(echo $deploy | cut -d/ -f1)
  name=$(echo $deploy | cut -d/ -f2)
  kubectl scale deployment $name -n $ns --replicas=0
done

# 3. Protect unaffected backups — set immutable flags
ghaymah bs snapshot list --format=json | jq -r '.[].id' | while read snap_id; do
  ghaymah bs snapshot update $snap_id --immutable=true --retention-days=90
done

# 4. Capture forensic artifacts
kubectl logs -l app=affected-service --all-containers --since=24h > /forensics/pod_logs_$(date +%s).log
kubectl get events -A --sort-by='.lastTimestamp' > /forensics/k8s_events_$(date +%s).log
```

## Eradication
After containment, the environment must be aggressively scrubbed to remove persistence.

| Time | Action | Details |
|------|--------|---------|
| T+30 | **Identify Entry Vector** | Analyze K8s audit logs to determine initial compromise. |
| T+35 | **Malware Analysis** | Determine if decryption is possible without paying ransom. |
| T+45 | **Wipe Infrastructure** | Delete the compromised namespace entirely. Do not attempt to "clean" infected pods. |

---

## Recovery
*(Disaster Recovery Strategy)*

### Recovery Checklist
- [ ] 1. Verify integrity of pre-incident snapshots (check for IOCs).
- [ ] 2. Reprovision K8s namespace from clean IaC templates.
- [ ] 3. Deploy fresh, signed container images.
- [ ] 4. Create new Block Storage volumes from verified immutable snapshots.
- [ ] 5. Attach new volumes to fresh pods in isolated network state.
- [ ] 6. Validate application logic and data consistency.
- [ ] 7. Re-expose service to public internet.

### Recovery Execution Order

When a ransomware event occurs, recovery MUST follow this exact sequence to prevent reinfection:

1. **Verify Integrity of Snapshots:** Do not blindly restore. Scan the target snapshot for IOCs to ensure the backup itself isn't compromised (the attacker may have been dwelling for days).
2. **Rebuild Infrastructure (Clean Room):** Delete the compromised namespace entirely. Do not attempt to "clean" infected pods. Reprovision the namespace and deploy fresh, signed container images from the trusted registry.
3. **Restore Data to New Volume:** Create a *new* Ghaymah Block Storage volume from the verified snapshot. Do not overwrite the encrypted volume (preserve it for forensics).
4. **Attach and Validate:** Attach the new volume to the fresh pods in a network-isolated state. Validate application startup and data consistency.
5. **Re-expose Service:** Update NetworkPolicies and Ingress routes to allow traffic back to the restored service.

**Why this specific order?**
If you restore the data *before* wiping the infrastructure, the malicious processes still running in memory will immediately re-encrypt the restored data. If you expose the service *before* validating, you risk exposing broken applications or unresolved backdoors to customers.

### RPO/RTO Definitions for Ghaymah
### Technical RPO & RTO Justification (Ghaymah Architecture)

| Metric | Definition | Target | Technical Justification |
|--------|-----------|--------|-------------------------|
| **RPO (Recovery Point Objective)** | Maximum acceptable data loss | **4 hours** | Ghaymah Block Storage volumes are snapshotted every 4 hours via automated CronJobs. This limits absolute data loss to a 4-hour window, which is acceptable for the staging and telemetry datasets without impacting operational continuity. |
| **RTO (Recovery Time Objective)** | Maximum acceptable downtime | **2 hours** | Recovery involves 3 stages: Namespace isolation (10m), Block Storage recovery from snapshot (30m), and QA validation before traffic routing (80m). The automated pipeline ensures the 2-hour SLA is consistently met during drills. |

---

### 3-2-1 Backup Rule Implementation on Ghaymah

```text
+-----------------------------------+
|      [Copy 1: Production]         |
| Ghaymah Block Storage (Live Data) |
|  * AES-256 Encrypted SSD          |
+-----------------------------------+
                 |
                 v (Automated Snapshot Every 4h)
+-----------------------------------+
|      [Copy 2: Snapshots]          |
| Ghaymah Region A (Same Region)    |
|  * 30-Day Retention               |
|  * IMMUTABLE Flag (WORM)          |
+-----------------------------------+
                 |
                 v (Daily Cross-Region Replication)
+-----------------------------------+
|      [Copy 3: Offline Vault]      |
| Ghaymah Region B (Disaster Rec.)  |
|  * 90-Day Retention               |
|  * Air-Gapped IAM Policies        |
+-----------------------------------+
```

### Backup Automation (Kubernetes CronJob)

```yaml
# backup-cronjob.yaml — Automated 3-2-1 backup on Ghaymah
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ghaymah-backup-321
  namespace: backup-system
spec:
  schedule: "0 */4 * * *"    # Every 4 hours
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 5
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backup-operator
          containers:
          - name: backup
            image: registry.ghaymah.systems/backup-operator:v1.2.0
            env:
            - name: GHAYMAH_API_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-credentials
                  key: api-key
            - name: REGION_B_API_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-credentials
                  key: region-b-api-key
            command:
            - /bin/bash
            - -c
            - |
              set -euo pipefail
              
              echo "[BACKUP] Starting 3-2-1 backup cycle..."
              TIMESTAMP=$(date +%Y%m%d_%H%M%S)
              
              # COPY 2: Create immutable snapshots
              for vol_id in $(ghaymah bs list --format=json | jq -r '.[].id'); do
                echo "[BACKUP] Snapshotting volume: ${vol_id}"
                SNAP_ID=$(ghaymah bs snapshot create \
                  --volume-id "${vol_id}" \
                  --name "auto-backup-${TIMESTAMP}" \
                  --immutable true \
                  --retention-days 30 \
                  --format=json | jq -r '.id')
                echo "[BACKUP] Created snapshot: ${SNAP_ID}"
              done
              
              # COPY 3: Cross-region replication (daily — check if midnight run)
              HOUR=$(date +%H)
              if [ "${HOUR}" == "00" ]; then
                echo "[BACKUP] Running daily cross-region replication..."
                for snap_id in $(ghaymah bs snapshot list \
                  --created-after "$(date -d '-4 hours' +%Y-%m-%dT%H:%M:%S)" \
                  --format=json | jq -r '.[].id'); do
                  ghaymah bs snapshot replicate \
                    --snapshot-id "${snap_id}" \
                    --target-region region-b \
                    --immutable true \
                    --retention-days 90 \
                    --api-key "${REGION_B_API_KEY}"
                  echo "[BACKUP] Replicated to Region B: ${snap_id}"
                done
              fi
              
              # Cleanup old snapshots beyond retention
              ghaymah bs snapshot prune --older-than 30d --dry-run=false
              
              echo "[BACKUP] 3-2-1 backup cycle complete."
          restartPolicy: OnFailure
```

### Recovery Procedure

```bash
#!/usr/bin/env bash
# recover_from_ransomware.sh — Restore from 3-2-1 backups

set -euo pipefail

echo "╔══════════════════════════════════════════════════════╗"
echo "║  GHAYMAH RANSOMWARE RECOVERY — BACKUP RESTORATION   ║"
echo "╚══════════════════════════════════════════════════════╝"

# Step 1: Identify last clean snapshot (pre-ransomware)
echo "[RECOVERY] Finding last clean snapshot..."
RANSOMWARE_TIME="2026-07-27T03:00:00Z"  # Set to time of first encryption

CLEAN_SNAPSHOTS=$(ghaymah bs snapshot list \
  --created-before "${RANSOMWARE_TIME}" \
  --immutable true \
  --sort-by created_at \
  --order desc \
  --limit 5 \
  --format=json)

echo "[RECOVERY] Available clean snapshots:"
echo "${CLEAN_SNAPSHOTS}" | jq -r '.[] | "  ID: \(.id)  Created: \(.created_at)  Volume: \(.volume_id)"'

# Step 2: Create new volumes from clean snapshots
echo "[RECOVERY] Restoring volumes from snapshots..."
echo "${CLEAN_SNAPSHOTS}" | jq -r '.[0].id' | while read snap_id; do
  NEW_VOL=$(ghaymah bs create \
    --from-snapshot "${snap_id}" \
    --name "recovered-$(date +%Y%m%d)" \
    --encrypted true \
    --format=json | jq -r '.id')
  echo "[RECOVERY] Created recovery volume: ${NEW_VOL} from snapshot: ${snap_id}"
done

# Step 3: Deploy clean application pods with recovered volumes
echo "[RECOVERY] Deploying clean application stack..."
kubectl apply -f /recovery/clean-deployment-manifests/

# Step 4: Verify data integrity
echo "[RECOVERY] Verifying data integrity..."
kubectl exec -it recovery-validator -- /scripts/verify_data_checksums.sh

echo "[RECOVERY] ✅ Restoration complete. Verify application functionality."
```

---

## Part 3: Preventative Architecture Against Lateral Movement

### 3.1 Defense-in-Depth Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    ANTI-RANSOMWARE DEFENSE LAYERS                        │
│                                                                          │
│  Layer 1: PERIMETER                                                      │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │  • WAF with ransomware payload detection                       │      │
│  │  • Email gateway with attachment sandboxing                    │      │
│  │  • DNS filtering (block known malicious domains)              │      │
│  │  • DDoS protection (prevent distraction attacks)              │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                              │                                           │
│  Layer 2: NETWORK (Zero Trust)                                           │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │  • Default-deny NetworkPolicies on ALL namespaces             │      │
│  │  • mTLS between all services (Istio service mesh)             │      │
│  │  • Egress filtering — block all except approved destinations  │      │
│  │  • Network segmentation — isolate sensitive data zones        │      │
│  │  • IDS/IPS (Wazuh + Suricata) on east-west traffic           │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                              │                                           │
│  Layer 3: IDENTITY (Zero Trust)                                          │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │  • MFA mandatory on ALL accounts (no exceptions)              │      │
│  │  • Short-lived tokens (15 min access, 24h refresh)            │      │
│  │  • Disable automatic SA token mounting in K8s                 │      │
│  │  • Just-in-Time (JIT) privileged access for admin tasks       │      │
│  │  • Impossible travel detection (Wazuh rule 100207)            │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                              │                                           │
│  Layer 4: ENDPOINT / CONTAINER                                           │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │  • Read-only root filesystem on ALL containers                │      │
│  │  • Drop ALL Linux capabilities                                │      │
│  │  • Seccomp profiles (restrict syscalls)                       │      │
│  │  • Falco runtime detection (detect file encryption patterns)  │      │
│  │  • Wazuh FIM on Block Storage mount points                    │      │
│  │  • No privileged containers (Pod Security Standards: restricted)│     │
│  └────────────────────────────────────────────────────────────────┘      │
│                              │                                           │
│  Layer 5: DATA                                                           │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │  • 3-2-1 backup rule (implemented above)                      │      │
│  │  • IMMUTABLE snapshots (cannot be deleted by ransomware)      │      │
│  │  • Separate IAM for backup operations (blast radius limit)    │      │
│  │  • Quarterly backup restore drills                            │      │
│  │  • Block Storage volume-level encryption (CMEK)               │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                              │                                           │
│  Layer 6: DETECTION & RESPONSE                                           │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │  • Wazuh FIM: detect mass file modifications in <5 min        │      │
│  │  • n8n SOAR: automated containment within 60 seconds          │      │
│  │  • Canary files: honeypot files that trigger alerts on access │      │
│  │  • Elastic ML: detect anomalous storage I/O patterns          │      │
│  │  • 24/7 SOC monitoring with <15 min response SLA              │      │
│  └────────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Lateral Movement Prevention — Specific Controls

#### 3.2.1 Kubernetes-Level Controls

```yaml
# anti-lateral-movement.yaml

# 1. Deny inter-namespace communication by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-namespace
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}    # Only allow same-namespace traffic
  egress:
  - to:
    - podSelector: {}    # Only allow same-namespace traffic
  - to: []               # Allow DNS
    ports:
    - protocol: UDP
      port: 53
---
# 2. Restrict volume access — pods can only mount their own PVCs
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRestrictedVolumes
metadata:
  name: restrict-volume-types
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  parameters:
    allowedVolumeTypes:
    - configMap
    - emptyDir
    - projected
    - secret
    - downwardAPI
    - persistentVolumeClaim     # Only named PVCs, no hostPath
---
# 3. Block hostPath mounts (prevent node-level lateral movement)
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockHostPath
metadata:
  name: block-host-path
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
```

#### 3.2.2 Canary File Detection (Early Warning System)

```python
#!/usr/bin/env python3
"""
Canary File Monitor — Early ransomware detection via honeypot files.
Deploy as a DaemonSet sidecar on Ghaymah Block Storage-mounted pods.
"""

import os
import hashlib
import time
import json
import requests
from pathlib import Path

CANARY_DIR = "/data/.canary"
CANARY_FILES = [
    "IMPORTANT_DO_NOT_DELETE.docx",
    "financial_report_2026.xlsx",
    "customer_database_backup.sql",
    "credentials_backup.txt",
    "company_secrets.pdf"
]
CHECK_INTERVAL = 30  # seconds
WAZUH_WEBHOOK = "http://wazuh-manager:55000/api/webhook/canary"
N8N_WEBHOOK = "http://n8n.security-tools:5678/webhook/ransomware-canary"

def create_canary_files():
    """Create honeypot files with known checksums."""
    os.makedirs(CANARY_DIR, exist_ok=True)
    checksums = {}
    for filename in CANARY_FILES:
        filepath = Path(CANARY_DIR) / filename
        content = f"CANARY-{filename}-{os.urandom(32).hex()}"
        filepath.write_text(content)
        checksums[str(filepath)] = hashlib.sha256(content.encode()).hexdigest()
    
    # Save checksums
    checksum_file = Path(CANARY_DIR) / ".checksums.json"
    checksum_file.write_text(json.dumps(checksums))
    return checksums

def check_canary_files(expected_checksums):
    """Check if any canary file has been modified, renamed, or deleted."""
    for filepath, expected_hash in expected_checksums.items():
        path = Path(filepath)
        
        if not path.exists():
            # File deleted or encrypted (renamed)
            alert_ransomware(f"Canary file DELETED/ENCRYPTED: {filepath}")
            return True
        
        current_content = path.read_text()
        current_hash = hashlib.sha256(current_content.encode()).hexdigest()
        
        if current_hash != expected_hash:
            # File content modified (encrypted in place)
            alert_ransomware(f"Canary file MODIFIED: {filepath}")
            return True
    
    return False

def alert_ransomware(message):
    """Send emergency alert to Wazuh and n8n."""
    alert_payload = {
        "alert_type": "ransomware_canary",
        "severity": "CRITICAL",
        "message": message,
        "hostname": os.uname().nodename,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action_required": "IMMEDIATE CONTAINMENT"
    }
    
    try:
        requests.post(N8N_WEBHOOK, json=alert_payload, timeout=5)
    except Exception as e:
        print(f"[ALERT FAILED] {e}")
    
    print(f"🚨 RANSOMWARE DETECTED: {message}")

def main():
    print("[CANARY] Initializing canary file monitoring...")
    checksums = create_canary_files()
    print(f"[CANARY] Created {len(checksums)} canary files in {CANARY_DIR}")
    
    while True:
        if check_canary_files(checksums):
            print("[CANARY] ⚠️ RANSOMWARE ACTIVITY DETECTED — Alert sent")
            # Don't exit — keep monitoring for forensic timeline
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
```

#### 3.2.3 Wazuh FIM Configuration for Ransomware Detection

```xml
<!-- /var/ossec/etc/ossec.conf — File Integrity Monitoring for ransomware -->
<ossec_config>
  <syscheck>
    <!-- Monitor Block Storage mount points -->
    <directories check_all="yes" realtime="yes" 
                 report_changes="yes">/data</directories>
    <directories check_all="yes" realtime="yes">/mnt/block-storage</directories>
    
    <!-- Alert on known ransomware file extensions -->
    <alert_new_files>yes</alert_new_files>
    
    <!-- Frequency: check every 60 seconds for rapid detection -->
    <frequency>60</frequency>
    
    <!-- Ignore legitimate temp files -->
    <ignore>/data/.tmp</ignore>
    <ignore>/data/cache</ignore>
  </syscheck>
</ossec_config>
```

```xml
<!-- Custom Wazuh rule for ransomware detection -->
<group name="ghaymah,ransomware,fim,">

  <!-- Mass file modification (ransomware encryption pattern) -->
  <rule id="100300" level="15" frequency="50" timeframe="300">
    <if_group>syscheck</if_group>
    <field name="syscheck.event">modified</field>
    <description>⚠️ RANSOMWARE ALERT: 50+ files modified in 5 minutes on Block Storage. Possible encryption in progress!</description>
    <mitre>
      <id>T1486</id>  <!-- Data Encrypted for Impact -->
    </mitre>
    <group>ransomware,data_encrypted,gdpr_IV_33,</group>
    <options>alert_by_email</options>
  </rule>

  <!-- Known ransomware file extensions -->
  <rule id="100301" level="14">
    <if_group>syscheck</if_group>
    <field name="syscheck.path">\.encrypted$|\.locked$|\.cry$|\.crypt$|\.ransom$|\.wasted$</field>
    <description>⚠️ RANSOMWARE: File with ransomware extension detected: $(syscheck.path)</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>ransomware,ransomware_extension,</group>
    <options>alert_by_email</options>
  </rule>

  <!-- Ransom note detection -->
  <rule id="100302" level="15">
    <if_group>syscheck</if_group>
    <field name="syscheck.path">README.*RANSOM|HOW.*DECRYPT|RECOVER.*FILES|!README!</field>
    <description>⚠️ RANSOMWARE: Ransom note detected: $(syscheck.path)</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>ransomware,ransom_note,</group>
    <options>alert_by_email</options>
  </rule>

  <!-- Canary file modification -->
  <rule id="100303" level="15">
    <if_group>syscheck</if_group>
    <field name="syscheck.path">.canary/</field>
    <description>⚠️ RANSOMWARE: Canary file modified/deleted! Early detection triggered.</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>ransomware,canary_triggered,</group>
    <options>alert_by_email</options>
  </rule>

</group>
```

### 3.3 Preventative Architecture Summary

| Control | Purpose | Prevents |
|---------|---------|----------|
| Default-deny NetworkPolicies | No lateral network movement | Ransomware spreading pod-to-pod |
| Read-only root filesystems | Pods cannot write to container FS | Ransomware binary dropping |
| Immutable backups | Backups cannot be encrypted/deleted | Double extortion (backup destruction) |
| Separate IAM for backups | Compromised app creds can't touch backups | Backup compromise during attack |
| Canary files | Detect encryption within 30 seconds | Late detection |
| Wazuh FIM (real-time) | Detect mass file changes instantly | Encryption completing before alert |
| n8n automated containment | Respond in <60 seconds | Human delay in containment |
| mTLS service mesh | Encrypted, authenticated inter-service traffic | MitM for ransomware C2 |
| Egress filtering | Block unauthorized outbound connections | Ransomware C2 callback & data exfil |
| JIT privileged access | Admin access only when needed, time-limited | Privilege escalation for ransomware deployment |

---

## Appendix: Tabletop Exercise Schedule

| Quarter | Exercise | Focus Area |
|---------|----------|------------|
| Q1 | Backup Restore Drill | Validate RPO/RTO by restoring from Region B backups |
| Q2 | Ransomware Simulation | Deploy fake ransomware in staging; test detection & containment |
| Q3 | Lateral Movement Test | Red team attempts to move across namespaces post-compromise |
| Q4 | Full IR Simulation | End-to-end ransomware scenario: detection → containment → recovery |


