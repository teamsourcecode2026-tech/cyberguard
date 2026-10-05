import json
import random
from datetime import datetime, timedelta

import pandas as pd
import os
import sys
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
)
from risk_scoring import score_and_explain
WINDOW = "5min"
BREACH_WINDOW = "10min"
MEDIUM_THRESHOLD = 5
HIGH_THRESHOLD = 10

RESPONSES = {
    "Critical": "Revoke session, force password reset, require MFA, notify SOC",
    "High": "Temporarily lock account, block source IP",
    "Medium": "Require CAPTCHA/MFA, warn user",
}


def make_logs():
    random.seed(42)
    t = datetime(2026, 10, 1, 9, 0)
    rows = []
    for i in range(200):
        rows.append([t + timedelta(minutes=i), f"user{random.randint(1, 20)}",
                     "10.0.0.5", random.random() > 0.05, "laptop", "IN"])
    for i in range(15):
        rows.append([t + timedelta(minutes=50, seconds=i * 4), "user3",
                     "185.22.1.9", False, "unknown", "RU"])
    rows.append([t + timedelta(minutes=51), "user3",
                 "185.22.1.9", True, "unknown", "RU"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def detect_brute_force(df):
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

        counts = fails["success"].astype(int).rolling(WINDOW).count()
        peak = int(counts.max())
        if peak < MEDIUM_THRESHOLD:
            continue

        peak_time = counts.idxmax()
        recent = fails[(fails.index > peak_time - pd.Timedelta(WINDOW))
                       & (fails.index <= peak_time)]
        src_ip = recent["ip"].mode().iloc[0]

        later_success = g[g["success"] & (g.index > peak_time)
                          & (g.index <= peak_time + pd.Timedelta(BREACH_WINDOW))]
        breached = not later_success.empty

        if breached:
            score = 90
        elif peak >= HIGH_THRESHOLD:
            score = 70
        else:
            score = 45

        indicators = [f"{peak} failed logins within {WINDOW} from {src_ip}"]
        if breached:
            indicators.append("followed by a successful login (possible account takeover)")

        scored = score_and_explain(
            {"score": score, "indicators": indicators},
            category="Brute Force"
        )
        level = scored["risk_level"]

        events.append({
            "source": "credential_attacks",
            "category": "Credential Theft / Account Takeover",
            "threat_type": "Brute Force",
            "timestamp": str(peak_time),
            "user": user,
            "source_ip": src_ip,
            "risk_level": level,
            "risk_score": scored["score"],
            "explanation": scored["explanation"],
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