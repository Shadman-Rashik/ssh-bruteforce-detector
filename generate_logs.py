"""Generate a synthetic SSH auth log (sshd lines) plus a ground-truth file.

All IP addresses come from the documentation ranges (RFC 5737), so no real
data is involved. The attack patterns below are made up for testing only.
"""
import json
import random
from datetime import datetime, timedelta

random.seed(42)
START = datetime(2026, 11, 5, 0, 0, 0)
HOST = "web-server-01"
events = []  # (datetime, log line)


def stamp(t):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def add(t, text):
    pid = random.randint(1000, 9999)
    events.append((t, f"{stamp(t)} {HOST} sshd[{pid}]: {text}"))


def fail(t, user, ip, valid=True):
    who = user if valid else f"invalid user {user}"
    add(t, f"Failed password for {who} from {ip} port {random.randint(20000, 65000)} ssh2")


def ok(t, user, ip):
    add(t, f"Accepted password for {user} from {ip} port {random.randint(20000, 65000)} ssh2")


def at(h, m=0, s=0):
    return START + timedelta(hours=h, minutes=m, seconds=s)


# ---- normal office traffic -------------------------------------------------
office = {"192.0.2.11": "alice", "192.0.2.12": "dave", "192.0.2.13": "erin",
          "192.0.2.14": "bob", "192.0.2.15": "carol"}
for _ in range(150):
    ip = random.choice(list(office))
    t = at(0) + timedelta(seconds=random.randint(0, 86399))
    ok(t, office[ip], ip)
for _ in range(15):  # occasional single typo
    ip = random.choice(list(office))
    t = at(0) + timedelta(seconds=random.randint(0, 86399))
    fail(t, office[ip], ip)
    ok(t + timedelta(seconds=8), office[ip], ip)

# ---- legitimate users who mistype a few times in a row ---------------------
for i in range(3):
    fail(at(9, 30, i * 9), "carol", "192.0.2.10")
ok(at(9, 30, 40), "carol", "192.0.2.10")
for i in range(2):
    fail(at(14, 5, i * 10), "dave", "192.0.2.12")
ok(at(14, 5, 35), "dave", "192.0.2.12")

# ---- simulated attackers ---------------------------------------------------
truth = {}

ip = "198.51.100.7"  # fast brute force against common usernames
truth[ip] = "fast brute force"
names = ["root", "admin", "test", "ubuntu", "oracle"]
for i in range(40):
    fail(at(2, 14, 0) + timedelta(seconds=i * 1.5), names[i % 5], ip, valid=False)

ip = "198.51.100.23"  # brute force that ends in a successful login
truth[ip] = "brute force then successful login"
for i in range(30):
    fail(at(11, 40, 0) + timedelta(seconds=i * 2), "bob", ip)
ok(at(11, 40, 0) + timedelta(seconds=63), "bob", ip)

ip = "203.0.113.50"  # one password tried against many usernames
truth[ip] = "username spraying"
spray = ["root", "admin", "guest", "deploy", "git", "postgres", "jenkins", "user"]
for i in range(25):
    fail(at(16, 5, 0) + timedelta(seconds=i * 3), spray[i % 8], ip, valid=False)

ip = "203.0.113.99"  # low-and-slow, one attempt every 4 minutes
truth[ip] = "low-and-slow brute force"
for i in range(12):
    fail(at(20, 0, 0) + timedelta(seconds=i * 240), "root", ip, valid=False)

# ---- unrelated log noise the parser must ignore ----------------------------
for i in range(20):
    t = at(0) + timedelta(seconds=random.randint(0, 86399))
    add(t, f"pam_unix(sshd:session): session opened for user {random.choice(list(office.values()))}")
    add(t + timedelta(seconds=2), "Received disconnect from 192.0.2.11 port 50000:11: disconnected by user")

events.sort(key=lambda e: e[0])
with open("sample_auth.log", "w") as f:
    f.write("\n".join(line for _, line in events) + "\n")
with open("ground_truth.json", "w") as f:
    json.dump({"attackers": truth}, f, indent=2)
print(f"Wrote sample_auth.log ({len(events)} lines) and ground_truth.json")
