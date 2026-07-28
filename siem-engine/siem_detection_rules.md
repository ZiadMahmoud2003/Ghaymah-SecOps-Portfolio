# SIEM Detection Rules — Engineering Notes

Reference for each detection rule in `siem_engine.py`. Structured for technical review and interview defensibility.

---

## 1. Structural Overview & Storage Strategy

**Why these parsers exist:**
The SIEM implements parsers for three critical log sources (Firewall/iptables, WebServer/Nginx, Auth/sshd) because they represent the three primary external attack surfaces: network edge, application layer, and access management. Without parsing all three, cross-layer correlation (e.g., matching a web brute force IP to a firewall port scan) is impossible.

**Storage Strategy:**
Ghaymah Block Storage volumes are mounted as Kubernetes PersistentVolumeClaims (PVCs) for long-term log retention. Block Storage provides built-in replication, durability, and snapshots, making it ideal for append-heavy SIEM workloads.

**Scalability Limitations:**
The current `siem_engine.py` uses in-memory Python dictionaries with threading locks for state management. This limits it to a single-node deployment (vertical scaling only). For a production SIEM, the state must be moved to an external fast-datastore (like Redis) and the processing decoupled via a message queue (like Kafka) to allow horizontal scaling of parser nodes.

**False Positive Handling:**
Rule thresholds are intentionally set slightly above standard background noise levels. We use IP Reputation scoring to catch "low and slow" attacks without triggering immediate false alerts.

**False Negative Risks:**
The system struggles to detect distributed, low-volume attacks (e.g., botnets using thousands of IPs to try one password per day) because the time-window logic (`cleanup_old_events`) expires state before the threshold is met.

---

## 2. Firewall Rules

### FW-001: Port Scan Detection
- **Why this approach was selected:** Triggering on 10+ unique blocked destination ports from the same source IP within 60 seconds reliably catches active scanning tools like Nmap or masscan.
- **Alternative approaches:** Monitoring SYN flags directly (TCP SYN scan). We chose log-based counting for simplicity since the firewall already logs dropped packets.
- **Advantages:** Low overhead; relies on existing firewall drop logs.
- **Disadvantages:** Cannot detect slow scans (1 port per minute).
- **Trade-offs:** We trade the ability to catch stealthy scans for the guarantee of near-zero false positives.
- **Performance impact:** Low. Dictionary lookup and length check per blocked log line.
- **Security impact:** High. Early warning of reconnaissance.
- **Expected behavior:** Alert fires immediately when the 10th unique port is logged.
- **Failure scenarios:** A NAT gateway used by multiple legitimate users misconfigured to hit blocked internal ports might trigger this.
- **Interview explanation:** "We chose 10 unique ports in 60 seconds because legitimate traffic rarely touches more than 1-3 ports (HTTP, HTTPS, SSH). 10 ports indicate enumeration."

### FW-002: Volumetric DDoS Attack
- **Why this approach was selected:** 100+ blocked connections from a single IP within 60 seconds indicates a DoS tool.
- **Alternative approaches:** Analyzing bandwidth/bytes over time rather than packet counts. We chose packet counts as it's easier to parse from iptables logs.
- **Advantages:** Extremely fast detection of simple floods.
- **Disadvantages:** Useless against distributed DDoS (botnets) since no single IP will hit the 100 threshold.
- **Trade-offs:** We prioritize detecting single-source aggressive actors over complex distributed attacks (which should be handled by Ghaymah's L3/L4 DDoS protection).
- **Failure scenarios:** An aggressively refreshing single-page application client might trigger a false positive if a backend API route suddenly goes down and drops traffic.

---

## 3. Web Server Rules

### WEB-001: Suspicious Path Access
- **Why this approach was selected:** RegEx matching against paths like `/.env`, `/.git`, or `/.aws` provides instant detection of vulnerability scanners.
- **Alternative approaches:** Using a dedicated WAF (like ModSecurity). We implemented it in the SIEM as a secondary defense-in-depth layer.
- **Advantages:** Zero tuning required. These paths should never be accessed legitimately.
- **Disadvantages:** Signature-based; an attacker probing an unknown path (`/secret_new_api`) will not be caught.
- **Trade-offs:** Highly specific signatures mean high fidelity, but low coverage of zero-days.
- **Expected behavior:** Immediate alert on first request.
- **Interview explanation:** "We alert instantly on `/.env` or `/.aws/credentials` because there is absolutely zero legitimate business case for an external IP to request Ghaymah Cloud keys or environment variables."

### WEB-004: Web Login Brute Force
- **Why this approach was selected:** 10 HTTP 401/403 responses in 120 seconds.
- **Alternative approaches:** Tracking by username instead of IP. We chose IP to catch password spraying (trying one password across many accounts).
- **Advantages:** Catches credential stuffing tools (like Hydra).
- **Disadvantages:** Susceptible to false positives from corporate NATs where many users share an IP.
- **Trade-offs:** We chose a 120-second window to accommodate slow brute-forcing, trading memory usage (storing IP states longer) for better detection.

---

## 4. Authentication Rules

### AUTH-001: SSH Brute Force
- **Why this approach was selected:** 5 failed SSH logins in 120 seconds. SSH is not a web form; legitimate users rarely fail more than twice.
- **Alternative approaches:** Disabling SSH entirely in favor of SSM (Session Manager). We assume SSH is required for this environment.
- **Advantages:** Immediate detection of internet background noise targeting port 22.
- **Disadvantages:** Can lock out legitimate admins if Active Response is tied to it.
- **Security impact:** High. Prevents complete server compromise.
- **Failure scenarios:** A developer with 6 old SSH keys in their `ssh-agent` might trigger this automatically when connecting, as the agent tries all keys sequentially.

### AUTH-003: Privilege Escalation Attempts
- **Why this approach was selected:** 3 failed `sudo` or `su` attempts from the same user in 5 minutes.
- **Alternative approaches:** Alerting on any successful `sudo`. We chose to alert on failures to detect the *attempt* before it succeeds.
- **Advantages:** Catches attackers who have gained a low-privileged shell and are trying to guess the root password.
- **Disadvantages:** Relies on the attacker using standard tools (`sudo`). Kernel exploits (like DirtyPipe) bypass this entirely.
- **Interview explanation:** "We alert on 3 failed sudo attempts because it indicates someone with shell access who does not actually know the password, which is a classic indicator of a compromised service account trying to escalate."
