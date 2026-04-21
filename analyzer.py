import re
import json
import os
from collections import defaultdict

BRUTE_FORCE_THRESHOLD = 3

# Patterns suspects dans les logs apache
SUSPICIOUS_PATHS = ["/admin", "/phpmyadmin", "/wp-login.php", "/etc/passwd", "/etc/shadow", "/../"]

# Commandes sudo suspectes
SUSPICIOUS_COMMANDS = ["/bin/bash", "/bin/cat /etc/shadow", "/bin/su"]


def parse_auth_log(filepath):
    failed_attempts = defaultdict(list)
    successful_logins = []
    all_events = []

    with open(filepath, "r") as f:
        for line in f:
            failed = re.search(r"(\w+\s+\d+\s+\S+).*Failed password for (\S+) from (\S+)", line)
            if failed:
                timestamp, user, ip = failed.group(1), failed.group(2), failed.group(3)
                failed_attempts[ip].append({"user": user, "timestamp": timestamp})
                all_events.append({"type": "FAILED", "ip": ip, "user": user, "timestamp": timestamp, "source": "auth.log"})

            success = re.search(r"(\w+\s+\d+\s+\S+).*Accepted password for (\S+) from (\S+)", line)
            if success:
                timestamp, user, ip = success.group(1), success.group(2), success.group(3)
                successful_logins.append({"user": user, "ip": ip, "timestamp": timestamp})
                all_events.append({"type": "SUCCESS", "ip": ip, "user": user, "timestamp": timestamp, "source": "auth.log"})

    return failed_attempts, successful_logins, all_events


def parse_apache_log(filepath):
    suspicious_events = []

    with open(filepath, "r") as f:
        for line in f:
            match = re.search(r'(\S+) - - \[(.+?)\] "(\S+) (\S+) HTTP', line)
            if match:
                ip = match.group(1)
                timestamp = match.group(2)
                path = match.group(4)
                for pattern in SUSPICIOUS_PATHS:
                    if pattern in path:
                        suspicious_events.append({
                            "type": "SUSPICIOUS_REQUEST",
                            "ip": ip,
                            "path": path,
                            "timestamp": timestamp,
                            "source": "apache.log"
                        })
                        break

    return suspicious_events


def parse_system_log(filepath):
    suspicious_events = []

    with open(filepath, "r") as f:
        for line in f:
            # Détection de commandes sudo suspectes
            sudo_match = re.search(r"(\w+\s+\d+\s+\S+).*sudo:\s+(\S+).*COMMAND=(.+)", line)
            if sudo_match:
                timestamp = sudo_match.group(1)
                user = sudo_match.group(2)
                command = sudo_match.group(3).strip()
                for suspicious in SUSPICIOUS_COMMANDS:
                    if suspicious in command:
                        suspicious_events.append({
                            "type": "SUSPICIOUS_SUDO",
                            "user": user,
                            "command": command,
                            "timestamp": timestamp,
                            "source": "system.log"
                        })
                        break

            # Détection de drops firewall
            drop_match = re.search(r"(\w+\s+\d+\s+\S+).*iptables: DROP.*SRC=(\S+).*DPT=(\d+)", line)
            if drop_match:
                timestamp = drop_match.group(1)
                ip = drop_match.group(2)
                port = drop_match.group(3)
                suspicious_events.append({
                    "type": "FIREWALL_DROP",
                    "ip": ip,
                    "port": port,
                    "timestamp": timestamp,
                    "source": "system.log"
                })

    return suspicious_events


def detect_brute_force(failed_attempts):
    alerts = []
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "ip": ip,
                "count": len(attempts),
                "severity": "HIGH" if len(attempts) >= 5 else "MEDIUM",
                "users_targeted": list(set(a["user"] for a in attempts))
            })
    return alerts


def generate_report(alerts, successful_logins, all_events, apache_events, system_events):
    print("\n===== SOC LOG ANALYZER REPORT =====\n")
    print(f"Total events analyzed  : {len(all_events)}")
    print(f"Failed attempts        : {sum(1 for e in all_events if e['type'] == 'FAILED')}")
    print(f"Successful logins      : {len(successful_logins)}")
    print(f"Suspicious IPs         : {len(alerts)}")
    print(f"Suspicious web requests: {len(apache_events)}")
    print(f"System alerts          : {len(system_events)}\n")

    if alerts:
        print("BRUTE FORCE ALERTS :")
        for alert in alerts:
            print(f"  [{alert['severity']}] IP {alert['ip']} => {alert['count']} attempts on: {alert['users_targeted']}")

    if apache_events:
        print("\nSUSPICIOUS WEB REQUESTS :")
        for e in apache_events:
            print(f"  {e['timestamp']} | {e['ip']} => {e['path']}")

    if system_events:
        print("\nSYSTEM ALERTS :")
        for e in system_events:
            if e["type"] == "SUSPICIOUS_SUDO":
                print(f"  [SUDO] {e['timestamp']} | user {e['user']} ran: {e['command']}")
            elif e["type"] == "FIREWALL_DROP":
                print(f"  [FW DROP] {e['timestamp']} | IP {e['ip']} on port {e['port']}")

    report = {
        "total_events": len(all_events),
        "failed_attempts": sum(1 for e in all_events if e["type"] == "FAILED"),
        "successful_logins": len(successful_logins),
        "alerts": alerts,
        "events": all_events,
        "apache_events": apache_events,
        "system_events": system_events
    }

    with open("report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\nReport saved to report.json")


if __name__ == "__main__":
    failed_attempts, successful_logins, all_events = parse_auth_log("sample_logs/auth.log")
    apache_events = parse_apache_log("sample_logs/apache.log")
    system_events = parse_system_log("sample_logs/system.log")
    alerts = detect_brute_force(failed_attempts)
    generate_report(alerts, successful_logins, all_events, apache_events, system_events)
    