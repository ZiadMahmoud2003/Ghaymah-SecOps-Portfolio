#!/usr/bin/env python3
"""
=============================================================================
Ghaymah Simple SIEM Engine
=============================================================================
Purpose : Aggregate and parse logs from 3 distinct sources (firewall, web
          server, system auth) to detect suspicious patterns.
Deploy  : Ghaymah Kubernetes + Block Storage
Date    : 2026-07-27
Usage   : python siem_engine.py [--demo] [--port 8000]
=============================================================================
"""

import re
import json
import time
import hashlib
import argparse
import threading
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
import os

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class Alert:
    """Represents a security alert triggered by the SIEM engine."""
    id: str
    timestamp: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source: str            # firewall, webserver, auth
    rule_id: str
    rule_name: str
    description: str
    source_ip: str
    destination_ip: str = ""
    port: int = 0
    count: int = 1
    raw_log: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    status: str = "open"   # open, investigating, resolved, false_positive

    def to_dict(self):
        return asdict(self)


@dataclass
class IPReputation:
    """Tracks reputation score for an IP address."""
    ip: str
    score: int = 0             # Higher = more suspicious (0-100)
    total_events: int = 0
    failed_logins: int = 0
    port_scans: int = 0
    blocked_requests: int = 0
    first_seen: str = ""
    last_seen: str = ""
    alerts: list = field(default_factory=list)


# =============================================================================
# LOG PARSERS
# =============================================================================

class FirewallLogParser:
    """
    Parses iptables/nftables/pf style firewall logs.
    Format: timestamp hostname kernel: [IPTABLES-*] ... SRC=x DST=y PROTO=z DPT=p
    """
    
    PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+kernel:\s*'
        r'\[?(?P<action>IPTABLES-\w+|UFW\s+\w+|DROP|ACCEPT|REJECT)\]?\s+'
        r'.*?SRC=(?P<src_ip>[\d.]+)\s+'
        r'.*?DST=(?P<dst_ip>[\d.]+)\s+'
        r'.*?PROTO=(?P<proto>\w+)\s*'
        r'(?:.*?DPT=(?P<dpt>\d+))?'
    )

    @staticmethod
    def parse(line: str) -> Optional[dict]:
        match = FirewallLogParser.PATTERN.search(line)
        if match:
            return {
                "source": "firewall",
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "action": match.group("action"),
                "src_ip": match.group("src_ip"),
                "dst_ip": match.group("dst_ip"),
                "proto": match.group("proto"),
                "dst_port": int(match.group("dpt")) if match.group("dpt") else 0,
                "raw": line.strip()
            }
        return None


class WebServerLogParser:
    """
    Parses Apache/Nginx combined log format.
    Format: IP - - [timestamp] "METHOD /path HTTP/x.x" status size "referer" "user-agent"
    """
    
    PATTERN = re.compile(
        r'(?P<src_ip>[\d.]+)\s+-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )

    SUSPICIOUS_PATHS = [
        r'/\.env', r'/wp-admin', r'/wp-login', r'/phpmyadmin',
        r'/admin', r'/\.git', r'/etc/passwd', r'/shell',
        r'/cmd', r'/eval', r'/exec', r'\.\./', r'/actuator',
        r'/api/v\d+/auth/login',   # Track login attempts
        r'/\.aws', r'/\.ssh', r'/config', r'/debug',
    ]

    SQL_INJECTION_PATTERNS = [
        r"(\bunion\b.*\bselect\b)", r"(\bor\b\s+\d+\s*=\s*\d+)",
        r"(;\s*drop\s+table)", r"(--\s*$)", r"('\s*or\s*')",
        r"(\bexec\b.*\bxp_)", r"(\binsert\b.*\binto\b)",
    ]

    XSS_PATTERNS = [
        r"(<script)", r"(javascript:)", r"(onerror\s*=)",
        r"(onload\s*=)", r"(document\.cookie)", r"(alert\s*\()",
    ]

    @staticmethod
    def parse(line: str) -> Optional[dict]:
        match = WebServerLogParser.PATTERN.search(line)
        if match:
            return {
                "source": "webserver",
                "timestamp": match.group("timestamp"),
                "src_ip": match.group("src_ip"),
                "method": match.group("method"),
                "path": match.group("path"),
                "status": int(match.group("status")),
                "size": int(match.group("size")),
                "referer": match.group("referer"),
                "user_agent": match.group("user_agent"),
                "raw": line.strip()
            }
        return None


class AuthLogParser:
    """
    Parses Linux auth/syslog authentication logs.
    Handles: sshd, sudo, su, pam, login failures
    """
    
    PATTERNS = {
        "ssh_failed": re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
            r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
            r'Failed\s+(?:password|publickey)\s+for\s+'
            r'(?:invalid\s+user\s+)?(?P<user>\S+)\s+'
            r'from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<port>\d+)'
        ),
        "ssh_success": re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
            r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
            r'Accepted\s+(?:password|publickey)\s+for\s+'
            r'(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)'
        ),
        "sudo_failure": re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
            r'(?P<hostname>\S+)\s+sudo:\s+'
            r'(?P<user>\S+)\s*:.*authentication\s+failure'
        ),
        "su_failure": re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
            r'(?P<hostname>\S+)\s+su\[\d+\]:\s+'
            r'(?:FAILED|pam_unix.*authentication failure).*'
            r'(?:ruser=(?P<user>\S+))?'
        ),
    }

    @staticmethod
    def parse(line: str) -> Optional[dict]:
        for event_type, pattern in AuthLogParser.PATTERNS.items():
            match = pattern.search(line)
            if match:
                groups = match.groupdict()
                return {
                    "source": "auth",
                    "event_type": event_type,
                    "timestamp": groups.get("timestamp", ""),
                    "hostname": groups.get("hostname", ""),
                    "user": groups.get("user", "unknown"),
                    "src_ip": groups.get("src_ip", "0.0.0.0"),
                    "port": int(groups.get("port", 0)),
                    "raw": line.strip()
                }
        return None


# =============================================================================
# DETECTION ENGINE
# =============================================================================

class DetectionEngine:
    """
    Correlation engine that analyzes parsed log events and generates
    alerts based on defined detection rules.
    """

    def __init__(self):
        self.alerts: list[Alert] = []
        self.ip_tracker: dict[str, IPReputation] = defaultdict(
            lambda: IPReputation(ip="")
        )
        self.event_windows: dict[str, list] = defaultdict(list)
        self.alert_counter = 0
        self._lock = threading.Lock()

    def _generate_alert_id(self) -> str:
        self.alert_counter += 1
        return f"GH-SIEM-{datetime.now().strftime('%Y%m%d')}-{self.alert_counter:04d}"

    def _cleanup_old_events(self, key: str, window_seconds: int = 300):
        """Remove events older than the time window."""
        cutoff = time.time() - window_seconds
        self.event_windows[key] = [
            e for e in self.event_windows[key] if e.get("_time", 0) > cutoff
        ]

    def analyze_firewall_event(self, event: dict):
        """
        Detect port scanning, suspicious blocked traffic, and DDoS patterns.
        
        [INTERVIEW NOTE - THRESHOLDS]:
        - FW-001 (Port Scan): 10 ports / 60s. Normal clients use 1-3 ports. 10 unique ports means a scanner (nmap/masscan).
        - FW-002 (Volumetric): 100 blocks / 60s. Normal users don't generate 100 blocked packets/min unless it's a DoS tool.
        - FW-003 (Bad Ports): Immediate alert on 4444, 5555, 6667, etc. These are default Metasploit/Botnet ports.
        """
        src_ip = event.get("src_ip", "")
        action = event.get("action", "").upper()
        dst_port = event.get("dst_port", 0)
        now = time.time()

        # Update IP reputation
        rep = self.ip_tracker[src_ip]
        rep.ip = src_ip
        rep.total_events += 1
        rep.last_seen = event.get("timestamp", "")
        if not rep.first_seen:
            rep.first_seen = rep.last_seen

        if "DROP" in action or "REJECT" in action or "BLOCK" in action:
            rep.blocked_requests += 1

            # --- Rule FW-001: Port Scan Detection ---
            scan_key = f"portscan:{src_ip}"
            event["_time"] = now
            event["_port"] = dst_port
            self.event_windows[scan_key].append(event)
            self._cleanup_old_events(scan_key, 60)

            unique_ports = set(
                e.get("_port", 0) for e in self.event_windows[scan_key]
            )
            if len(unique_ports) >= 10:
                rep.port_scans += 1
                rep.score = min(100, rep.score + 30)
                self._create_alert(
                    severity="HIGH",
                    source="firewall",
                    rule_id="FW-001",
                    rule_name="Port Scan Detected",
                    description=f"IP {src_ip} scanned {len(unique_ports)} ports in 60 seconds: {sorted(unique_ports)[:10]}",
                    source_ip=src_ip,
                    destination_ip=event.get("dst_ip", ""),
                    port=dst_port,
                    count=len(self.event_windows[scan_key]),
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 — Network Service Discovery"
                )
                self.event_windows[scan_key].clear()

            # --- Rule FW-002: High Volume Blocked Traffic (DDoS Indicator) ---
            vol_key = f"volume:{src_ip}"
            self.event_windows[vol_key].append({"_time": now})
            self._cleanup_old_events(vol_key, 60)

            if len(self.event_windows[vol_key]) >= 100:
                rep.score = min(100, rep.score + 40)
                self._create_alert(
                    severity="CRITICAL",
                    source="firewall",
                    rule_id="FW-002",
                    rule_name="Potential DDoS / Volumetric Attack",
                    description=f"IP {src_ip} generated {len(self.event_windows[vol_key])} blocked connections in 60 seconds.",
                    source_ip=src_ip,
                    destination_ip=event.get("dst_ip", ""),
                    count=len(self.event_windows[vol_key]),
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Impact",
                    mitre_technique="T1498 — Network Denial of Service"
                )
                self.event_windows[vol_key].clear()

            # --- Rule FW-003: Connection to Known Dangerous Ports ---
            dangerous_ports = {4444: "Metasploit", 5555: "ADB", 6667: "IRC/Botnet",
                               1337: "Backdoor", 31337: "Elite Backdoor", 12345: "NetBus"}
            if dst_port in dangerous_ports:
                rep.score = min(100, rep.score + 25)
                self._create_alert(
                    severity="HIGH",
                    source="firewall",
                    rule_id="FW-003",
                    rule_name="Connection to Suspicious Port",
                    description=f"IP {src_ip} attempted connection to port {dst_port} ({dangerous_ports[dst_port]}).",
                    source_ip=src_ip,
                    destination_ip=event.get("dst_ip", ""),
                    port=dst_port,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Command and Control",
                    mitre_technique="T1571 — Non-Standard Port"
                )

    def analyze_webserver_event(self, event: dict):
        """
        Detect web attacks: SQLi, XSS, path traversal, brute force.
        
        [INTERVIEW NOTE - THRESHOLDS]:
        - WEB-001 (Paths): Instant alert on /.env, /.git, etc. These paths should NEVER be accessed legitimately.
        - WEB-002/003 (SQLi/XSS): Instant alert on signature match. High fidelity indicators.
        - WEB-004 (Web Brute Force): 10 fails / 120s. 1-3 fails is a typo. 10 fails means automated credential stuffing.
        - WEB-005 (Scanner UA): Instant alert on sqlmap, nikto, etc. Legitimate users do not use these browsers.
        """
        src_ip = event.get("src_ip", "")
        path = event.get("path", "")
        status = event.get("status", 0)
        method = event.get("method", "")
        user_agent = event.get("user_agent", "")
        now = time.time()

        rep = self.ip_tracker[src_ip]
        rep.ip = src_ip
        rep.total_events += 1
        rep.last_seen = event.get("timestamp", "")
        if not rep.first_seen:
            rep.first_seen = rep.last_seen

        # --- Rule WEB-001: Suspicious Path Access ---
        for pattern in WebServerLogParser.SUSPICIOUS_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                rep.score = min(100, rep.score + 10)
                self._create_alert(
                    severity="MEDIUM",
                    source="webserver",
                    rule_id="WEB-001",
                    rule_name="Suspicious Path Access",
                    description=f"IP {src_ip} accessed suspicious path: {path} (status: {status})",
                    source_ip=src_ip,
                    port=443,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1595 — Active Scanning"
                )
                break

        # --- Rule WEB-002: SQL Injection Attempt ---
        for pattern in WebServerLogParser.SQL_INJECTION_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                rep.score = min(100, rep.score + 35)
                self._create_alert(
                    severity="CRITICAL",
                    source="webserver",
                    rule_id="WEB-002",
                    rule_name="SQL Injection Attempt",
                    description=f"IP {src_ip} sent SQLi payload in request: {method} {path[:100]}",
                    source_ip=src_ip,
                    port=443,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190 — Exploit Public-Facing Application"
                )
                break

        # --- Rule WEB-003: XSS Attempt ---
        for pattern in WebServerLogParser.XSS_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                rep.score = min(100, rep.score + 25)
                self._create_alert(
                    severity="HIGH",
                    source="webserver",
                    rule_id="WEB-003",
                    rule_name="Cross-Site Scripting (XSS) Attempt",
                    description=f"IP {src_ip} sent XSS payload: {method} {path[:100]}",
                    source_ip=src_ip,
                    port=443,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Initial Access",
                    mitre_technique="T1189 — Drive-by Compromise"
                )
                break

        # --- Rule WEB-004: Web Login Brute Force ---
        if status == 401 or (status == 403 and "/login" in path.lower()) or (status == 401 and "/auth" in path.lower()):
            login_key = f"web_login:{src_ip}"
            self.event_windows[login_key].append({"_time": now})
            self._cleanup_old_events(login_key, 120)

            if len(self.event_windows[login_key]) >= 10:
                rep.score = min(100, rep.score + 30)
                rep.failed_logins += len(self.event_windows[login_key])
                self._create_alert(
                    severity="HIGH",
                    source="webserver",
                    rule_id="WEB-004",
                    rule_name="Web Login Brute Force",
                    description=f"IP {src_ip} had {len(self.event_windows[login_key])} failed login attempts in 2 minutes.",
                    source_ip=src_ip,
                    port=443,
                    count=len(self.event_windows[login_key]),
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 — Brute Force"
                )
                self.event_windows[login_key].clear()

        # --- Rule WEB-005: Malicious User-Agent ---
        malicious_agents = ["sqlmap", "nikto", "nmap", "masscan", "dirbuster",
                            "gobuster", "wfuzz", "hydra", "metasploit"]
        for agent in malicious_agents:
            if agent in user_agent.lower():
                rep.score = min(100, rep.score + 40)
                self._create_alert(
                    severity="HIGH",
                    source="webserver",
                    rule_id="WEB-005",
                    rule_name="Malicious Scanner/Tool Detected",
                    description=f"IP {src_ip} using known attack tool: {user_agent[:80]}",
                    source_ip=src_ip,
                    port=443,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1595.002 — Vulnerability Scanning"
                )
                break

    def analyze_auth_event(self, event: dict):
        """
        Detect SSH brute force, privilege escalation attempts.
        
        [INTERVIEW NOTE - THRESHOLDS]:
        - AUTH-001 (SSH Brute Force): 5 fails / 120s. SSH is not a web form; >5 fails is an automated script.
        - AUTH-002 (Sensitive Login): Any success to root/admin. These should use SSH keys + Sudo, not direct logins.
        - AUTH-003 (Privesc): 3 sudo fails / 5m. Trying to guess the sudo password to escalate privileges.
        """
        src_ip = event.get("src_ip", "0.0.0.0")
        event_type = event.get("event_type", "")
        user = event.get("user", "unknown")
        now = time.time()

        rep = self.ip_tracker[src_ip]
        rep.ip = src_ip
        rep.total_events += 1
        rep.last_seen = event.get("timestamp", "")
        if not rep.first_seen:
            rep.first_seen = rep.last_seen

        # --- Rule AUTH-001: SSH Brute Force ---
        if event_type == "ssh_failed":
            rep.failed_logins += 1
            ssh_key = f"ssh_brute:{src_ip}"
            self.event_windows[ssh_key].append({"_time": now, "user": user})
            self._cleanup_old_events(ssh_key, 120)

            if len(self.event_windows[ssh_key]) >= 5:
                rep.score = min(100, rep.score + 30)
                targeted_users = set(e.get("user", "") for e in self.event_windows[ssh_key])
                self._create_alert(
                    severity="HIGH",
                    source="auth",
                    rule_id="AUTH-001",
                    rule_name="SSH Brute Force Attack",
                    description=f"IP {src_ip}: {len(self.event_windows[ssh_key])} failed SSH logins in 2 min. Targets: {', '.join(targeted_users)}",
                    source_ip=src_ip,
                    port=22,
                    count=len(self.event_windows[ssh_key]),
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.001 — Password Guessing"
                )
                self.event_windows[ssh_key].clear()

        # --- Rule AUTH-002: Login to Sensitive Account ---
        if event_type == "ssh_success":
            sensitive_users = ["root", "admin", "administrator", "postgres", "mysql", "oracle"]
            if user.lower() in sensitive_users:
                rep.score = min(100, rep.score + 20)
                self._create_alert(
                    severity="HIGH",
                    source="auth",
                    rule_id="AUTH-002",
                    rule_name="Sensitive Account Login",
                    description=f"Successful SSH login to sensitive account '{user}' from {src_ip}.",
                    source_ip=src_ip,
                    port=22,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Persistence",
                    mitre_technique="T1078 — Valid Accounts"
                )

        # --- Rule AUTH-003: Sudo/Su Privilege Escalation Failure ---
        if event_type in ("sudo_failure", "su_failure"):
            priv_key = f"privesc:{src_ip}:{user}"
            self.event_windows[priv_key].append({"_time": now})
            self._cleanup_old_events(priv_key, 300)

            if len(self.event_windows[priv_key]) >= 3:
                rep.score = min(100, rep.score + 25)
                self._create_alert(
                    severity="HIGH",
                    source="auth",
                    rule_id="AUTH-003",
                    rule_name="Privilege Escalation Attempts",
                    description=f"User '{user}' had {len(self.event_windows[priv_key])} failed sudo/su attempts in 5 minutes.",
                    source_ip=src_ip,
                    raw_log=event.get("raw", ""),
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1548 — Abuse Elevation Control Mechanism"
                )
                self.event_windows[priv_key].clear()

    def _create_alert(self, **kwargs):
        with self._lock:
            alert = Alert(
                id=self._generate_alert_id(),
                timestamp=datetime.now().isoformat(),
                **kwargs
            )
            self.alerts.append(alert)
            # Keep only last 1000 alerts in memory
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]
            return alert

    def get_alerts_json(self) -> str:
        with self._lock:
            return json.dumps(
                [a.to_dict() for a in reversed(self.alerts)],
                indent=2
            )

    def get_malicious_ips_json(self) -> str:
        with self._lock:
            suspicious = {
                ip: {
                    "ip": rep.ip,
                    "score": rep.score,
                    "total_events": rep.total_events,
                    "failed_logins": rep.failed_logins,
                    "port_scans": rep.port_scans,
                    "blocked_requests": rep.blocked_requests,
                    "first_seen": rep.first_seen,
                    "last_seen": rep.last_seen,
                }
                for ip, rep in self.ip_tracker.items()
                if rep.score >= 20
            }
            sorted_ips = dict(
                sorted(suspicious.items(), key=lambda x: x[1]["score"], reverse=True)
            )
            return json.dumps(list(sorted_ips.values()), indent=2)

    def get_stats_json(self) -> str:
        with self._lock:
            severity_counts = defaultdict(int)
            source_counts = defaultdict(int)
            for alert in self.alerts:
                severity_counts[alert.severity] += 1
                source_counts[alert.source] += 1

            return json.dumps({
                "total_alerts": len(self.alerts),
                "total_ips_tracked": len(self.ip_tracker),
                "malicious_ips": sum(1 for r in self.ip_tracker.values() if r.score >= 50),
                "suspicious_ips": sum(1 for r in self.ip_tracker.values() if 20 <= r.score < 50),
                "by_severity": dict(severity_counts),
                "by_source": dict(source_counts),
                "last_updated": datetime.now().isoformat()
            }, indent=2)


# =============================================================================
# LOG PROCESSOR
# =============================================================================

class LogProcessor:
    """Reads log files and routes events to the detection engine."""

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.parsers = {
            "firewall": FirewallLogParser(),
            "webserver": WebServerLogParser(),
            "auth": AuthLogParser(),
        }

    def process_file(self, filepath: str, log_type: str):
        """Process a log file line by line."""
        parser = self.parsers.get(log_type)
        if not parser:
            print(f"[ERROR] Unknown log type: {log_type}")
            return

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    event = parser.parse(line)
                    if event:
                        self._route_event(event, log_type)
        except FileNotFoundError:
            print(f"[WARN] Log file not found: {filepath}")
        except Exception as e:
            print(f"[ERROR] Processing {filepath}: {e}")

    def process_line(self, line: str, log_type: str):
        """Process a single log line (for real-time / demo mode)."""
        parser = self.parsers.get(log_type)
        if parser:
            event = parser.parse(line)
            if event:
                self._route_event(event, log_type)

    def _route_event(self, event: dict, log_type: str):
        """Route parsed event to the appropriate analyzer."""
        if log_type == "firewall":
            self.engine.analyze_firewall_event(event)
        elif log_type == "webserver":
            self.engine.analyze_webserver_event(event)
        elif log_type == "auth":
            self.engine.analyze_auth_event(event)


# =============================================================================
# DEMO DATA GENERATOR
# =============================================================================

def generate_demo_data(processor: LogProcessor):
    """Generate realistic sample log data to demonstrate SIEM capabilities."""
    
    print("[DEMO] Generating synthetic security events...")

    # --- Firewall logs: Port scan from attacker ---
    attacker_ip = "45.142.182.97"
    for port in [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443, 9200]:
        fw_line = f"Jul 27 03:14:22 ghaymah-node1 kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC={attacker_ip} DST=10.0.1.50 PROTO=TCP DPT={port}"
        processor.process_line(fw_line, "firewall")

    # Additional port scan from second attacker
    for port in [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 2379, 10250]:
        fw_line = f"Jul 27 03:15:01 ghaymah-node1 kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=185.220.101.44 DST=10.0.1.50 PROTO=TCP DPT={port}"
        processor.process_line(fw_line, "firewall")

    # Dangerous port connection attempt
    fw_line = f"Jul 27 03:16:00 ghaymah-node1 kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=91.240.118.172 DST=10.0.1.50 PROTO=TCP DPT=4444"
    processor.process_line(fw_line, "firewall")
    fw_line = f"Jul 27 03:16:01 ghaymah-node1 kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=91.240.118.172 DST=10.0.1.50 PROTO=TCP DPT=31337"
    processor.process_line(fw_line, "firewall")

    # DDoS simulation (100+ connections from single IP)
    ddos_ip = "23.129.64.100"
    for i in range(120):
        fw_line = f"Jul 27 03:20:{i%60:02d} ghaymah-node1 kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC={ddos_ip} DST=10.0.1.50 PROTO=TCP DPT=443"
        processor.process_line(fw_line, "firewall")

    # --- Web server logs: Various attacks ---
    # SQLi attempts
    sqli_lines = [
        f'45.142.182.97 - - [27/Jul/2026:03:14:30 +0000] "GET /api/users?id=1%20UNION%20SELECT%20*%20FROM%20passwords HTTP/1.1" 403 0 "-" "sqlmap/1.7"',
        f'45.142.182.97 - - [27/Jul/2026:03:14:31 +0000] "GET /api/users?id=1%20OR%201=1-- HTTP/1.1" 403 0 "-" "sqlmap/1.7"',
        f'45.142.182.97 - - [27/Jul/2026:03:14:32 +0000] "POST /api/login?user=admin%27;DROP%20TABLE%20users;-- HTTP/1.1" 403 0 "-" "sqlmap/1.7"',
    ]
    for line in sqli_lines:
        processor.process_line(line, "webserver")

    # XSS attempts
    xss_lines = [
        f'185.220.101.44 - - [27/Jul/2026:03:15:10 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 400 0 "-" "Mozilla/5.0"',
        f'185.220.101.44 - - [27/Jul/2026:03:15:11 +0000] "GET /profile?name=<img%20onerror=alert(1)%20src=x> HTTP/1.1" 400 0 "-" "Mozilla/5.0"',
    ]
    for line in xss_lines:
        processor.process_line(line, "webserver")

    # Suspicious path probing
    probe_lines = [
        f'103.41.167.55 - - [27/Jul/2026:03:16:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.88.1"',
        f'103.41.167.55 - - [27/Jul/2026:03:16:01 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "curl/7.88.1"',
        f'103.41.167.55 - - [27/Jul/2026:03:16:02 +0000] "GET /wp-admin/ HTTP/1.1" 404 0 "-" "curl/7.88.1"',
        f'103.41.167.55 - - [27/Jul/2026:03:16:03 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0 "-" "dirbuster/1.0"',
        f'103.41.167.55 - - [27/Jul/2026:03:16:04 +0000] "GET /admin HTTP/1.1" 404 0 "-" "gobuster/3.6"',
        f'103.41.167.55 - - [27/Jul/2026:03:16:05 +0000] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
        f'103.41.167.55 - - [27/Jul/2026:03:16:06 +0000] "GET /actuator/env HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
    ]
    for line in probe_lines:
        processor.process_line(line, "webserver")

    # Web login brute force
    for i in range(15):
        bf_line = f'192.168.1.{100+i%5} - - [27/Jul/2026:03:17:{i:02d} +0000] "POST /api/v1/auth/login HTTP/1.1" 401 42 "-" "python-requests/2.31.0"'
        processor.process_line(bf_line, "webserver")

    # Nikto scanner
    nikto_line = f'198.51.100.23 - - [27/Jul/2026:03:18:00 +0000] "GET /cgi-bin/test-cgi HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nikto/2.5)"'
    processor.process_line(nikto_line, "webserver")

    # --- Auth logs: SSH brute force ---
    ssh_attacker = "45.142.182.97"
    for i in range(8):
        users = ["root", "admin", "ubuntu", "deploy", "postgres", "test", "user", "operator"]
        auth_line = f"Jul 27 03:14:{22+i:02d} ghaymah-node1 sshd[{12340+i}]: Failed password for invalid user {users[i]} from {ssh_attacker} port {50000+i}"
        processor.process_line(auth_line, "auth")

    # SSH brute force from second attacker
    for i in range(6):
        users = ["root", "admin", "root", "root", "administrator", "root"]
        auth_line = f"Jul 27 03:20:{10+i:02d} ghaymah-node1 sshd[{12360+i}]: Failed password for {users[i]} from 185.220.101.44 port {51000+i}"
        processor.process_line(auth_line, "auth")

    # Successful login to root (suspicious after brute force)
    auth_line = f"Jul 27 03:25:00 ghaymah-node1 sshd[12380]: Accepted password for root from {ssh_attacker} port 52000"
    processor.process_line(auth_line, "auth")

    # Sudo failures (privilege escalation attempt)
    for i in range(4):
        auth_line = f"Jul 27 03:26:{i:02d} ghaymah-node1 sudo: deploy : authentication failure ; TTY=pts/0 ; PWD=/home/deploy"
        processor.process_line(auth_line, "auth")

    print(f"[DEMO] Generated events. Total alerts: {len(processor.engine.alerts)}")


# =============================================================================
# HTTP API SERVER (serves data to frontend dashboard)
# =============================================================================

class SIEMAPIHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves the dashboard and API endpoints."""
    
    engine: DetectionEngine = None
    dashboard_dir: str = "."

    def do_GET(self):
        if self.path == "/api/alerts":
            self._send_json(self.engine.get_alerts_json())
        elif self.path == "/api/ips":
            self._send_json(self.engine.get_malicious_ips_json())
        elif self.path == "/api/stats":
            self._send_json(self.engine.get_stats_json())
        elif self.path == "/" or self.path == "/index.html":
            self._serve_file("index.html", "text/html")
        elif self.path == "/style.css":
            self._serve_file("style.css", "text/css")
        elif self.path == "/app.js":
            self._serve_file("app.js", "application/javascript")
        else:
            self.send_error(404)

    def _send_json(self, data: str):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data.encode())

    def _serve_file(self, filename: str, content_type: str):
        filepath = Path(self.dashboard_dir) / filename
        if filepath.exists():
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(filepath.read_bytes())
        else:
            self.send_error(404, f"File not found: {filename}")

    def log_message(self, format, *args):
        """Suppress default HTTP log messages."""
        pass


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ghaymah Simple SIEM Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python siem_engine.py --demo                    # Run with demo data
  python siem_engine.py --demo --port 8080        # Custom port
  python siem_engine.py \\
    --firewall /var/log/iptables.log \\
    --webserver /var/log/nginx/access.log \\
    --auth /var/log/auth.log                      # Real log files
        """
    )
    parser.add_argument("--demo", action="store_true", help="Generate demo data for testing")
    parser.add_argument("--port", type=int, default=8000, help="HTTP server port (default: 8000)")
    parser.add_argument("--firewall", type=str, help="Path to firewall log file")
    parser.add_argument("--webserver", type=str, help="Path to web server log file")
    parser.add_argument("--auth", type=str, help="Path to auth log file")
    parser.add_argument("--dashboard-dir", type=str, default="dashboard",
                        help="Path to dashboard static files directory")

    args = parser.parse_args()

    # Initialize engine and processor
    engine = DetectionEngine()
    processor = LogProcessor(engine)

    # Process log files if specified
    if args.firewall:
        print(f"[*] Processing firewall logs: {args.firewall}")
        processor.process_file(args.firewall, "firewall")
    if args.webserver:
        print(f"[*] Processing web server logs: {args.webserver}")
        processor.process_file(args.webserver, "webserver")
    if args.auth:
        print(f"[*] Processing auth logs: {args.auth}")
        processor.process_file(args.auth, "auth")

    # Generate demo data if requested
    if args.demo:
        generate_demo_data(processor)

    # Resolve dashboard directory
    script_dir = Path(__file__).parent
    dashboard_dir = script_dir / args.dashboard_dir
    if not dashboard_dir.exists():
        dashboard_dir = script_dir
        print(f"[WARN] Dashboard directory '{args.dashboard_dir}' not found, serving from script directory.")

    # Start HTTP server
    SIEMAPIHandler.engine = engine
    SIEMAPIHandler.dashboard_dir = str(dashboard_dir)

    server = HTTPServer(("0.0.0.0", args.port), SIEMAPIHandler)
    print(f"\n{'='*60}")
    print(f"  GHAYMAH SIEM ENGINE - RUNNING")
    print(f"  Dashboard:  http://localhost:{args.port}")
    print(f"  API:        http://localhost:{args.port}/api/alerts")
    print(f"  Stats:      http://localhost:{args.port}/api/stats")
    print(f"  Malicious:  http://localhost:{args.port}/api/ips")
    print(f"{'='*60}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] SIEM Engine shutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
