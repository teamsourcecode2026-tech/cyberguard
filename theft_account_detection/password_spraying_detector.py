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

WINDOW = "10min"
BREACH_WINDOW = "10min"
MEDIUM_THRESHOLD = 5
HIGH_THRESHOLD = 10
MAX_AVG_ATTEMPTS = 3

RESPONSES = {
    "Critical": "Block source IP, force password reset for compromised accounts, revoke sessions, require MFA, notify SOC",
    "High": "Block source IP, require MFA for targeted accounts, notify SOC",
    "Medium": "Rate-limit source IP, warn targeted users, monitor",
}


def make_logs():
    random.seed(42)
    t = datetime(2026, 10, 1, 9, 0)
    rows = []
    for i in range(200):
        rows.append([t + timedelta(minutes=i), f"user{random.randint(1, 20)}",
                     "10.0.0.5", random.random() > 0.05, "laptop", "IN"])
    start = t + timedelta(minutes=120)
    for i in range(12):
        rows.append([start + timedelta(seconds=i * 10), f"user{i + 1}",
                     "45.33.12.7", False, "unknown", "RU"])
    rows.append([start + timedelta(seconds=130), "user13",
                 "45.33.12.7", True, "unknown", "RU"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def detect_password_spraying(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    for ip, g in df.groupby("ip"):
        g = g.set_index("timestamp")
        fails = g[~g["success"]]
        if fails.empty:
            continue

        codes = pd.Series(pd.factorize(fails["username"])[0],
                          index=fails.index, dtype=float)
        distinct = codes.rolling(WINDOW).apply(lambda x: len(set(x)), raw=True)
        peak_users = int(distinct.max())
        if peak_users < MEDIUM_THRESHOLD:
            continue

        peak_time = distinct.idxmax()
        window_start = peak_time - pd.Timedelta(WINDOW)
        recent = fails[(fails.index > window_start) & (fails.index <= peak_time)]

        avg_attempts = len(recent) / recent["username"].nunique()
        if avg_attempts > MAX_AVG_ATTEMPTS:
            continue

        targeted = sorted(recent["username"].unique())

        hits = g[g["success"] & (g.index > window_start)
                 & (g.index <= peak_time + pd.Timedelta(BREACH_WINDOW))]
        compromised = sorted(hits["username"].unique())

        if compromised:
            score = 90
        elif peak_users >= HIGH_THRESHOLD:
            score = 70
        else:
            score = 45

        indicators = [f"{peak_users} different accounts failed to log in from {ip} within {WINDOW} "
                      f"(about {avg_attempts:.1f} attempt(s) per account)"]
        if compromised:
            indicators.append(f"successful login to {', '.join(compromised)} (possible account takeover)")
        else:
            indicators.append("typical password-spraying pattern")

        scored = score_and_explain(
            {"score": score, "indicators": indicators},
            category="Password Spraying"
        )
        level = scored["risk_level"]

        events.append({
            "source": "credential_attacks",
            "category": "Credential Theft / Account Takeover",
            "threat_type": "Password Spraying",
            "timestamp": str(peak_time),
            "user": ", ".join(compromised) if compromised else "multiple accounts",
            "source_ip": ip,
            "risk_level": level,
            "risk_score": scored["score"],
            "explanation": scored["explanation"],
            "evidence": {"distinct_accounts_targeted": peak_users,
                         "avg_attempts_per_account": round(avg_attempts, 1),
                         "targeted_users": targeted,
                         "compromised_users": compromised},
            "response": RESPONSES[level],
            "mitre": "T1110.003 - Password Spraying",
        })
    return events


if __name__ == "__main__":
    alerts = detect_password_spraying(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")