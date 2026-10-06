import re
from datetime import datetime

PATTERN = re.compile(
    r"^(?P<timestamp>\S+) "
    r"src=(?P<src>\S+) "
    r"service=(?P<service>\S+) "
    r"action=(?P<action>\S+) "
    r"result=(?P<result>\S+) "
    r"dst_port=(?P<dst_port>\d+) "
    r"user=(?P<user>\S+)$"
)

def parse_line(line: str) -> dict:
    match = PATTERN.match(line.strip())
    if not match:
        raise ValueError(f"Invalid security log line: {line}")

    data = match.groupdict()
    return {
        "timestamp": datetime.fromisoformat(data["timestamp"]),
        "src_ip": data["src"],
        "service": data["service"],
        "action": data["action"],
        "result": data["result"],
        "dst_port": int(data["dst_port"]),
        "user": data["user"],
    }

def parse_file(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as file:
        return [parse_line(line) for line in file if line.strip()]
