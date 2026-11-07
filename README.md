# SSH Brute-Force Login Detector

A small Python tool that reads SSH authentication logs and flags source IP addresses showing brute-force behaviour. It was built as a learning project for security monitoring: detect, rank by severity, and report.

![Sample report](docs/report.png)

## What it does
- Parses `sshd` "Failed password" and "Accepted password" lines from a Linux auth log
- Flags an IP when it produces **N failed logins within a sliding time window** (default: 5 within 60 seconds)
- Ranks each alert by severity:
  - **Critical**: a successful login from the same IP right after the burst (possible compromise)
  - **High**: a large burst, or many different usernames targeted (password spraying)
  - **Medium**: threshold exceeded
- Writes `alerts.csv` and a readable `report.html`
- Can score itself against a ground-truth file and test several threshold/window settings

Related technique: MITRE ATT&CK T1110 (Brute Force).

## Data
All logs are **synthetic**, created by `generate_logs.py`. IP addresses come from the reserved documentation ranges, so no real data is involved. The sample log contains normal office logins, two legitimate users who mistype a few times, unrelated log noise, and four simulated attackers (fast brute force, brute force followed by a successful login, username spraying, and a low-and-slow attacker).

## Results on the sample log
Default rule (5 failures in 60 s):

| Result | Value |
|---|---|
| Lines read | 335 |
| Failed / successful logins | 127 / 168 |
| Alerts | 3 (1 critical, 2 high) |
| Simulated attackers caught | 3 of 4 |
| False alarms | 0 |

Sensitivity check:
- Lowering the threshold to 3 flagged a legitimate user who mistyped their password three times (1 false alarm).
- Widening the window to 900 s with threshold 3 caught the slow attacker (4 of 4) but still produced that false alarm.
- Thresholds of 5 and 8 produced no false alarms at any tested window.

## Limitations
- The sliding-window rule misses low-and-slow attacks (one attempt every few minutes). Catching them needs a wider window, which raises false alarms.
- Only handles Linux `sshd` password lines; it does not parse public-key failures, other services or Windows event logs.
- Offline analysis on synthetic data. It does not read live logs, block IPs or send alerts.

## How to run
Requires Python 3.8+ and nothing else (standard library only).

```
python generate_logs.py
python detector.py sample_auth.log --year 2026 --truth ground_truth.json --sensitivity
```
Open `output/report.html` in a browser. Options: `--threshold`, `--window`, `--out-dir`.

## Tests
```
python -m unittest -v
```

## Files
- `generate_logs.py`: builds the synthetic log and ground truth
- `detector.py`: parser, detection rule, severity, CSV/HTML report, evaluation
- `test_detector.py`: unit tests for parsing, thresholds, windows and severity
- `sample_auth.log`, `ground_truth.json`: sample input and answer key
