from pathlib import Path
from datetime import datetime, timedelta, timezone

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

BASE = datetime(2026, 10, 6, 18, 0, 0, tzinfo=timezone.utc)
EVENTS = []

# Synthetic SSH brute-force activity.
for i in range(7):
    timestamp = BASE + timedelta(seconds=i * 20)
    EVENTS.append(
        f"{timestamp.isoformat()} src=192.0.2.10 service=ssh "
        f"action=login result=failed dst_port=22 user=admin"
    )

# Synthetic port-scan activity.
for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 443, 8080, 8443]):
    timestamp = BASE + timedelta(minutes=3, seconds=i * 5)
    EVENTS.append(
        f"{timestamp.isoformat()} src=198.51.100.23 service=tcp "
        f"action=connection result=blocked dst_port={port} user=-"
    )

# Synthetic repeated authentication failures.
for i in range(4):
    timestamp = BASE + timedelta(minutes=5, seconds=i * 25)
    EVENTS.append(
        f"{timestamp.isoformat()} src=203.0.113.5 service=ssh "
        f"action=login result=failed dst_port=22 user=guest"
    )

# Benign event for comparison.
timestamp = BASE + timedelta(minutes=8)
EVENTS.append(
    f"{timestamp.isoformat()} src=198.51.100.44 service=ssh "
    f"action=login result=success dst_port=22 user=developer"
)

OUTPUT = RAW_DIR / "sample_security.log"
OUTPUT.write_text("\n".join(EVENTS) + "\n", encoding="utf-8")
print(f"Generated {len(EVENTS)} synthetic events: {OUTPUT}")
