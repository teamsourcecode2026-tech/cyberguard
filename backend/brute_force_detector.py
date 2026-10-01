import json
import random
from datetime import datetime, timedelta

import pandas as pd

# ---- Settings (change these to tune sensitivity) ----
WINDOW = "5min"           # look at failures within this time window
BREACH_WINDOW = "10min"   # a success this soon after the burst = likely breach
MEDIUM_THRESHOLD = 5      # 5+ failures in the window = Medium
HIGH_THRESHOLD = 10       # 10+ failures in the window = High

RESPONSES = {
    "Critical": "Revoke session, force password reset, require MFA, notify SOC",
    "High": "Temporarily lock account, block source IP",
    "Medium": "Require CAPTCHA/MFA, warn user",
}
SCORES = {"Critical": 90, "High": 70, "Medium": 45}


def make_logs():
    """Fake login logs: normal users plus one attacker hitting user3."""
    random.seed(42)
    t = datetime(2026, 10, 1, 9, 0)
    rows = []
    # Normal traffic: 200 logins, occasional typo (5% fail)
    for i in range(200):
        rows.append([t + timedelta(minutes=i), f"user{random.randint(1, 20)}",
                     "10.0.0.5", random.random() > 0.05, "laptop", "IN"])
    # Attack: 15 failed logins in about 1 minute, then a success
    for i in range(15):
        rows.append([t + timedelta(minutes=50, seconds=i * 4), "user3",
                     "185.22.1.9", False, "unknown", "RU"])
    rows.append([t + timedelta(minutes=51), "user3",
                 "185.22.1.9", True, "unknown", "RU"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def detect_brute_force(df):
    """Input: DataFrame with columns timestamp, username, ip, success.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    for user, g in df.groupby("username"):
        g = g.set_index("timestamp")
        fails = g[~g["success"]]
        if fails.empty:
            continue

        # For each failed login, count failures in the last WINDOW
        counts = fails["success"].astype(int).rolling(WINDOW).count()
        peak = int(counts.max())
        if peak < MEDIUM_THRESHOLD:
            continue  # not enough failures, ignore

        peak_time = counts.idxmax()
        recent = fails[(fails.index > peak_time - pd.Timedelta(WINDOW))
                       & (fails.index <= peak_time)]
        src_ip = recent["ip"].mode().iloc[0]

        # Did the attacker get in right after the failures?
        later_success = g[g["success"] & (g.index > peak_time)
                          & (g.index <= peak_time + pd.Timedelta(BREACH_WINDOW))]
        breached = not later_success.empty

        if breached:
            level = "Critical"
        elif peak >= HIGH_THRESHOLD:
            level = "High"
        else:
            level = "Medium"

        explanation = f"{level} Risk: {peak} failed logins within {WINDOW} from {src_ip}"
        explanation += (", followed by a successful login (possible account takeover)."
                        if breached else ".")

        events.append({
            "source": "credential_attacks",
            "category": "Credential Theft / Account Takeover",
            "threat_type": "Brute Force",
            "timestamp": str(peak_time),
            "user": user,
            "source_ip": src_ip,
            "risk_level": level,
            "risk_score": SCORES[level],
            "explanation": explanation,
            "evidence": {"failed_attempts_in_window": peak,
                         "success_after_burst": breached},
            "response": RESPONSES[level],
            "mitre": "T1110 - Brute Force",
        })
    return events


if __name__ == "__main__":
    alerts = detect_brute_force(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")