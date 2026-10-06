import unittest
from datetime import datetime, timezone

from src.parser import parse_line
from src.detector import detect

class TestPipeline(unittest.TestCase):

    def test_parser(self):
        line = (
            "2026-10-06T18:00:00+00:00 "
            "src=192.0.2.10 service=ssh action=login "
            "result=failed dst_port=22 user=admin"
        )
        event = parse_line(line)
        self.assertEqual(event["src_ip"], "192.0.2.10")
        self.assertEqual(event["dst_port"], 22)
        self.assertEqual(event["result"], "failed")

    def test_bruteforce_detection(self):
        timestamp = datetime(2026, 10, 6, 18, 0, tzinfo=timezone.utc)
        events = [{
            "timestamp": timestamp,
            "src_ip": "192.0.2.10",
            "service": "ssh",
            "action": "login",
            "result": "failed",
            "dst_port": 22,
            "user": "admin",
        } for _ in range(5)]

        alerts = detect(events)
        self.assertTrue(
            any(a["alert_type"] == "SSH Brute Force" for a in alerts)
        )

if __name__ == "__main__":
    unittest.main()
