import unittest
from datetime import datetime, timedelta

from detector import detect, parse_line

YEAR = 2026
FAILED = "Nov  5 02:14:00 web-01 sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 40000 ssh2"
ACCEPTED = "Nov  5 11:41:03 web-01 sshd[1234]: Accepted password for bob from 198.51.100.23 port 40001 ssh2"


def ev(kind, seconds, ip="198.51.100.7", user="root"):
    return {"kind": kind, "time": datetime(2026, 11, 5, 2, 0, 0) + timedelta(seconds=seconds), "user": user, "ip": ip}


class ParseTests(unittest.TestCase):
    def test_failed_line(self):
        e = parse_line(FAILED, YEAR)
        self.assertEqual((e["kind"], e["user"], e["ip"]), ("failed", "admin", "198.51.100.7"))
        self.assertEqual(e["time"], datetime(2026, 11, 5, 2, 14, 0))

    def test_accepted_line(self):
        e = parse_line(ACCEPTED, YEAR)
        self.assertEqual((e["kind"], e["user"]), ("accepted", "bob"))

    def test_unrelated_line_ignored(self):
        self.assertIsNone(parse_line("Nov  5 02:14:00 web-01 sshd[1]: session opened for user bob", YEAR))


class DetectTests(unittest.TestCase):
    def test_flags_burst_at_threshold(self):
        events = [ev("failed", i) for i in range(5)]
        self.assertEqual(len(detect(events, 5, 60)), 1)

    def test_below_threshold_not_flagged(self):
        events = [ev("failed", i) for i in range(4)]
        self.assertEqual(detect(events, 5, 60), [])

    def test_attempts_spread_outside_window_not_flagged(self):
        events = [ev("failed", i * 100) for i in range(8)]
        self.assertEqual(detect(events, 5, 60), [])

    def test_success_after_burst_is_critical(self):
        events = [ev("failed", i) for i in range(6)] + [ev("accepted", 20, user="bob")]
        alert = detect(events, 5, 60)[0]
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["successful_login_user"], "bob")

    def test_many_usernames_is_high(self):
        events = [ev("failed", i, user=f"user{i}") for i in range(6)]
        self.assertEqual(detect(events, 5, 60)[0]["severity"], "high")

    def test_ips_are_counted_separately(self):
        events = [ev("failed", i, ip="198.51.100.7") for i in range(3)] + \
                 [ev("failed", i, ip="198.51.100.8") for i in range(3)]
        self.assertEqual(detect(events, 5, 60), [])


if __name__ == "__main__":
    unittest.main()
