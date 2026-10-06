import json
import sqlite3
from pathlib import Path

from src.generate_sample_logs import OUTPUT
from src.parser import parse_file
from src.detector import detect

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
DATABASE = PROCESSED_DIR / "soc_alerts.db"

def save_results(events, alerts):
    normalized = []
    for event in events:
        item = dict(event)
        item["timestamp"] = item["timestamp"].isoformat()
        normalized.append(item)

    (PROCESSED_DIR / "normalized_events.json").write_text(
        json.dumps(normalized, indent=2), encoding="utf-8"
    )
    (PROCESSED_DIR / "alerts.json").write_text(
        json.dumps(alerts, indent=2), encoding="utf-8"
    )

    if DATABASE.exists():
        DATABASE.unlink()

    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                evidence TEXT NOT NULL
            )
        """)
        connection.executemany(
            "INSERT INTO alerts(alert_type,severity,src_ip,evidence) VALUES (?,?,?,?)",
            [
                (a["alert_type"], a["severity"], a["src_ip"], a["evidence"])
                for a in alerts
            ],
        )

def main():
    # Generate fresh synthetic events.
    import src.generate_sample_logs  # noqa: F401

    events = parse_file(str(OUTPUT))
    alerts = detect(events)
    save_results(events, alerts)

    print(f"Normalized events: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['alert_type']} - {alert['src_ip']}")

if __name__ == "__main__":
    main()
