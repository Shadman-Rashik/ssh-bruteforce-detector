"""Brute-force login detector for SSH auth logs.

Rule: flag a source IP when it produces at least THRESHOLD failed logins
inside a sliding window of WINDOW seconds. Severity is then raised if the
burst targets many usernames or ends in a successful login.
"""
import argparse
import csv
import html
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

TS = r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
FAILED_RE = re.compile(TS + r".*sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) from " + IP + r" port \d+")
ACCEPTED_RE = re.compile(TS + r".*sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from " + IP + r" port \d+")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2}


def parse_line(line, year):
    """Return a dict for a failed/accepted login line, otherwise None."""
    for kind, rx in (("failed", FAILED_RE), ("accepted", ACCEPTED_RE)):
        m = rx.match(line)
        if m:
            t = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
            return {"kind": kind, "time": t, "user": m["user"], "ip": m["ip"]}
    return None


def load_events(path, year):
    events, total = [], 0
    with open(path, errors="replace") as f:
        for line in f:
            total += 1
            e = parse_line(line, year)
            if e:
                events.append(e)
    return events, total


def detect(events, threshold=5, window_seconds=60):
    window = timedelta(seconds=window_seconds)
    failures, successes = defaultdict(list), defaultdict(list)
    for e in events:
        (failures if e["kind"] == "failed" else successes)[e["ip"]].append(e)

    alerts = []
    for ip, fails in failures.items():
        fails.sort(key=lambda e: e["time"])
        start, trigger = 0, None
        for end in range(len(fails)):
            while fails[end]["time"] - fails[start]["time"] > window:
                start += 1
            if end - start + 1 >= threshold:
                trigger = start
                break
        if trigger is None:
            continue

        # extend the burst while consecutive failures stay inside the window
        last_i = trigger
        while last_i + 1 < len(fails) and fails[last_i + 1]["time"] - fails[last_i]["time"] <= window:
            last_i += 1
        burst = fails[trigger:last_i + 1]
        first_seen, last_seen = burst[0]["time"], burst[-1]["time"]
        users = sorted({e["user"] for e in burst})

        compromised = ""
        for s in sorted(successes.get(ip, []), key=lambda e: e["time"]):
            if first_seen <= s["time"] <= last_seen + window:
                compromised = s["user"]
                break

        if compromised:
            severity = "critical"
            reason = f"Successful login for '{compromised}' right after repeated failures"
        elif len(burst) >= 3 * threshold or len(users) >= 5:
            severity = "high"
            reason = "Large burst or many usernames targeted"
        else:
            severity = "medium"
            reason = "Failed-login threshold exceeded"

        alerts.append({
            "ip": ip, "severity": severity,
            "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "failed_attempts": len(burst), "usernames_targeted": len(users),
            "usernames": ", ".join(users[:8]), "successful_login_user": compromised,
            "reason": reason,
        })
    alerts.sort(key=lambda a: (SEV_ORDER[a["severity"]], a["first_seen"]))
    return alerts


def write_csv(alerts, path):
    cols = ["severity", "ip", "first_seen", "last_seen", "failed_attempts",
            "usernames_targeted", "usernames", "successful_login_user", "reason"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(alerts)


def write_html(alerts, path, threshold, window_seconds, source):
    colors = {"critical": "#c0392b", "high": "#e67e22", "medium": "#d4ac0d"}
    rows = "".join(
        "<tr><td style='color:{c};font-weight:bold'>{s}</td><td>{ip}</td><td>{f}</td><td>{l}</td>"
        "<td>{n}</td><td>{u}</td><td>{r}</td></tr>".format(
            c=colors[a["severity"]], s=a["severity"].upper(), ip=html.escape(a["ip"]),
            f=a["first_seen"], l=a["last_seen"], n=a["failed_attempts"],
            u=html.escape(a["usernames"]), r=html.escape(a["reason"]))
        for a in alerts)
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>Brute-force report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#222}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px;text-align:left;font-size:14px}}
th{{background:#f2f2f2}}</style></head><body>
<h1>Brute-force login report</h1>
<p>Source: {html.escape(source)}<br>Rule: {threshold} failed logins within {window_seconds} seconds per IP<br>
Alerts: {len(alerts)}</p>
<table><tr><th>Severity</th><th>IP</th><th>First seen</th><th>Last seen</th><th>Failed attempts</th><th>Usernames</th><th>Reason</th></tr>
{rows}</table></body></html>"""
    with open(path, "w") as f:
        f.write(page)


def evaluate(alerts, truth):
    flagged = {a["ip"] for a in alerts}
    attackers = set(truth["attackers"])
    return len(flagged & attackers), len(attackers), sorted(flagged - attackers)


def sensitivity(events, truth):
    print("\nSensitivity check (threshold x window) against ground truth")
    print(f"{'threshold':>9} {'window_s':>9} {'alerts':>7} {'attackers_caught':>17} {'false_alarms':>13}")
    for window in (60, 300, 900):
        for threshold in (3, 5, 8):
            alerts = detect(events, threshold, window)
            caught, total, fp = evaluate(alerts, truth)
            print(f"{threshold:>9} {window:>9} {len(alerts):>7} {f'{caught}/{total}':>17} {len(fp):>13}")


def main():
    p = argparse.ArgumentParser(description="Detect brute-force attempts in an SSH auth log.")
    p.add_argument("logfile")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps")
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--window", type=int, default=60, help="window in seconds")
    p.add_argument("--out-dir", default="output")
    p.add_argument("--truth", help="ground_truth.json to score the detector")
    p.add_argument("--sensitivity", action="store_true", help="try several thresholds/windows (needs --truth)")
    a = p.parse_args()

    events, total = load_events(a.logfile, a.year)
    failed = sum(e["kind"] == "failed" for e in events)
    alerts = detect(events, a.threshold, a.window)

    os.makedirs(a.out_dir, exist_ok=True)
    write_csv(alerts, os.path.join(a.out_dir, "alerts.csv"))
    write_html(alerts, os.path.join(a.out_dir, "report.html"), a.threshold, a.window, os.path.basename(a.logfile))

    print(f"Read {total} lines: {failed} failed logins, {len(events) - failed} successful logins")
    print(f"Rule: {a.threshold} failures within {a.window}s -> {len(alerts)} alert(s)\n")
    for x in alerts:
        print(f"[{x['severity'].upper():8}] {x['ip']:15} {x['failed_attempts']:3} failures, "
              f"{x['usernames_targeted']} usernames, {x['first_seen']}  {x['reason']}")

    if a.truth:
        with open(a.truth) as f:
            truth = json.load(f)
        caught, n, fp = evaluate(alerts, truth)
        print(f"\nGround truth: caught {caught} of {n} simulated attackers, "
              f"{len(fp)} false alarm(s){': ' + ', '.join(fp) if fp else ''}")
        if a.sensitivity:
            sensitivity(events, truth)
    print(f"\nWrote {a.out_dir}/alerts.csv and {a.out_dir}/report.html")


if __name__ == "__main__":
    main()
