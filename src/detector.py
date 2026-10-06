from collections import defaultdict
from datetime import timedelta

def detect(events: list[dict]) -> list[dict]:
    alerts = []
    failed_by_ip = defaultdict(list)
    ports_by_ip = defaultdict(set)

    for event in events:
        if event["result"] == "failed":
            failed_by_ip[event["src_ip"]].append(event)

        if event["action"] == "connection":
            ports_by_ip[event["src_ip"]].add(event["dst_port"])

    # SSH brute force
    for ip, items in failed_by_ip.items():
        ssh_failures = [e for e in items if e["service"] == "ssh"]
        if len(ssh_failures) >= 5:
            alerts.append({
                "alert_type": "SSH Brute Force",
                "severity": "High",
                "src_ip": ip,
                "evidence": f"{len(ssh_failures)} failed SSH authentication attempts",
            })

    # Port scan
    for ip, ports in ports_by_ip.items():
        if len(ports) >= 8:
            alerts.append({
                "alert_type": "Port Scan",
                "severity": "Medium",
                "src_ip": ip,
                "evidence": f"{len(ports)} distinct destination ports contacted",
            })

    # Repeated authentication failures
    for ip, items in failed_by_ip.items():
        items = sorted(items, key=lambda e: e["timestamp"])

        for i in range(len(items) - 2):
            window = items[i + 2]["timestamp"] - items[i]["timestamp"]
            if window <= timedelta(minutes=2):
                alerts.append({
                    "alert_type": "Repeated Authentication Failures",
                    "severity": "Medium",
                    "src_ip": ip,
                    "evidence": "At least 3 failed authentication events within 2 minutes",
                })
                break

    return alerts
