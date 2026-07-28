# Wazuh Detection Rules — Engineering Notes

Reference for each custom Wazuh rule defined in `wazuh_brute_force_rules.xml`. Designed to strictly align with interview defensibility requirements.

---

## Architecture Overview

**Why Wazuh?** 
Wazuh natively integrates with Kubernetes (via DaemonSets) and provides out-of-the-box File Integrity Monitoring (FIM), rootkit detection, and log correlation. It's lighter and more cost-effective than deploying a full Splunk forwarder on every node in Ghaymah Containers.

**Rule ID Strategy:** 
Standard Wazuh rules use IDs < 100,000. Custom user rules must be >= 100,000. We reserved `100200-100219` for Ghaymah Authentication Rules to maintain organized namespaces and prevent conflicts with future official updates.

---

## Rule Definitions

### Rule 100200: Base API Auth Failure
- **Purpose:** Acts as the foundational baseline rule, triggering on every single failed API login.
- **Parent Rule:** N/A (Standalone base rule)
- **Decoder:** `json` (Our API logs natively in structured JSON)
- **Rule ID selection:** 100200 (Start of our reserved auth block)
- **Alert Level:** 3 (Low) - High enough to index in Elastic, low enough to avoid spam.
- **MITRE ATT&CK Mapping:** T1110 (Brute Force)
- **Conditions:** `field name="event.action"` matches `login_failed`
- **False Positives:** Legitimate users mistyping passwords.
- **False Negatives:** Attackers exploiting token bypasses instead of password auth.
- **Projectple triggering log:** `{"timestamp":"2026-07-27T10:00:00Z", "event":{"action":"login_failed"}, "source":{"ip":"192.168.1.5"}}`
- **Expected alert:** Silent indexing. No active response.
- **Testing method:** `curl -X POST /api/login -d '{"user":"test", "pass":"wrong"}'`
- **Possible improvements:** Enrich with GeoIP data at the decoder level.

### Rule 100202: Confirmed Brute Force
- **Purpose:** Detects sustained, aggressive credential guessing from a single IP.
- **Parent Rule:** 100200
- **Decoder:** `json`
- **Rule ID selection:** 100202
- **Alert Level:** 10 (High)
- **MITRE ATT&CK Mapping:** T1110.001 (Password Guessing)
- **Frequency:** 20 occurrences
- **Timeframe:** 120 seconds
- **Conditions:** `<same_source_ip />`
- **False Positives:** Corporate NAT gateways where 20 different users are legitimately failing logins concurrently.
- **False Negatives:** "Low and slow" brute force (e.g., 1 attempt per hour).
- **Projectple triggering log:** (20x of Rule 100200 from the same IP)
- **Expected alert:** "Confirmed Brute Force Attack from IP X". Triggers Soft Block via n8n.
- **Testing method:** `hydra -l admin -P rockyou.txt https-post-form "/api/login"`
- **Possible improvements:** Dynamically adjust the timeframe based on the IP's previous reputation score.

### Rule 100204: Distributed Brute Force (Credential Stuffing)
- **Purpose:** Detects botnets using rotating proxies to attack a single account, bypassing per-IP rate limits.
- **Parent Rule:** 100200
- **Decoder:** `json`
- **Rule ID selection:** 100204
- **Alert Level:** 12 (High)
- **MITRE ATT&CK Mapping:** T1110.003 (Password Spraying)
- **Frequency:** 10 occurrences
- **Timeframe:** 300 seconds
- **Conditions:** `<same_field>data.target_user</same_field>` AND `<different_source_ip />`
- **False Positives:** Distributed team attempting to log into a shared service account concurrently (bad practice, but happens).
- **False Negatives:** Botnets targeting multiple accounts simultaneously (avoids `same_field` correlation).
- **Projectple triggering log:** 10 failures for `admin` from 10 different AWS/Ghaymah Cloud IPs.
- **Expected alert:** "Distributed Brute Force against Account X".
- **Testing method:** Custom Python script rotating proxies while attacking one account.
- **Possible improvements:** Integrate with Threat Intelligence feeds to identify known Tor exit nodes automatically.

### Rule 100206: Successful Login AFTER Brute Force (Compromise)
- **Purpose:** Identifies the moment a brute force attack transitions into a successful breach.
- **Parent Rule:** N/A (Correlates across auth success rule)
- **Decoder:** `json`
- **Rule ID selection:** 100206
- **Alert Level:** 14 (Critical)
- **MITRE ATT&CK Mapping:** T1078 (Valid Accounts)
- **Conditions:** `<if_matched_sid>100202</if_matched_sid>` AND `authentication_success` from the same IP.
- **False Positives:** A legitimate user legitimately forgets their password, fails 20 times, resets it, and logs in successfully.
- **False Negatives:** The attacker brute-forces the password from IP A, but uses it to log in via VPN from IP B.
- **Projectple triggering log:** Rule 100202 fires, followed immediately by `{"event":{"action":"login_success"}}`.
- **Expected alert:** "CRITICAL: Account Compromised following Brute Force".
- **Testing method:** Run hydra to trigger 100202, then immediately log in with correct credentials via curl.
- **Possible improvements:** Change correlation to track the target account rather than just the source IP to prevent the IP A/B bypass.

### Rule 100208: Service Account Brute Force
- **Purpose:** Protects non-MFA enabled machine accounts.
- **Parent Rule:** 100200
- **Decoder:** `json`
- **Rule ID selection:** 100208
- **Alert Level:** 14 (Critical)
- **MITRE ATT&CK Mapping:** T1078.003 (Local Accounts)
- **Frequency:** 5 occurrences
- **Timeframe:** 60 seconds
- **Conditions:** Regex match on `^svc-|^service-|^system-`
- **False Positives:** A misconfigured internal cronjob failing to authenticate.
- **False Negatives:** Service accounts that don't follow the naming convention.
- **Expected alert:** "CRITICAL: Service Account Brute Force Attempt".
- **Testing method:** `hydra -l svc-db-backup -P rockyou.txt https-post-form "/api/login"`
- **Possible improvements:** Query Active Directory/LDAP directly rather than relying on regex string matching for the username.
