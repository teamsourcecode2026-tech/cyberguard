import json
import random
from datetime import datetime, timedelta

import pandas as pd

# ---- Settings (change these to tune sensitivity) ----
WINDOW = "10min"          # look at failures within this time window
BREACH_WINDOW = "10min"   # a success this soon after the spray = likely breach
MEDIUM_THRESHOLD = 5      # 5+ different accounts failed from one IP = Medium
HIGH_THRESHOLD = 10       # 10+ different accounts = High
MAX_AVG_ATTEMPTS = 3      # more than 3 tries per account looks like brute force, not spraying

RESPONSES = {
    "Critical": "Block source IP, force password reset for compromised accounts, revoke sessions, require MFA, notify SOC",
    "High": "Block source IP, require MFA for targeted accounts, notify SOC",
    "Medium": "Rate-limit source IP, warn targeted users, monitor",
}
SCORES = {"Critical": 90, "High": 70, "Medium": 45}


def make_logs():
    """Fake login logs: normal users plus one attacker spraying many accounts."""
    random.seed(42)
    t = datetime(2026, 10, 1, 9, 0)
    rows = []
    # Normal traffic: 200 logins, occasional typo (5% fail)
    for i in range(200):
        rows.append([t + timedelta(minutes=i), f"user{random.randint(1, 20)}",
                     "10.0.0.5", random.random() > 0.05, "laptop", "IN"])
    # Attack: one failed attempt on each of user1..user12, 10 seconds apart
    start = t + timedelta(minutes=120)
    for i in range(12):
        rows.append([start + timedelta(seconds=i * 10), f"user{i + 1}",
                     "45.33.12.7", False, "unknown", "RU"])
    # The 13th account had a weak password, so the attacker gets in
    rows.append([start + timedelta(seconds=130), "user13",
                 "45.33.12.7", True, "unknown", "RU"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def detect_password_spraying(df):
    """Input: DataFrame with columns timestamp, username, ip, success.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    # Group by IP address (brute force grouped by username)
    for ip, g in df.groupby("ip"):
        g = g.set_index("timestamp")
        fails = g[~g["success"]]
        if fails.empty:
            continue

        # Turn usernames into numbers, then count how many DIFFERENT
        # users this IP failed against in the last WINDOW
        codes = pd.Series(pd.factorize(fails["username"])[0],
                          index=fails.index, dtype=float)
        distinct = codes.rolling(WINDOW).apply(lambda x: len(set(x)), raw=True)
        peak_users = int(distinct.max())
        if peak_users < MEDIUM_THRESHOLD:
            continue  # not enough different accounts, ignore

        peak_time = distinct.idxmax()
        window_start = peak_time - pd.Timedelta(WINDOW)
        recent = fails[(fails.index > window_start) & (fails.index <= peak_time)]

        # Spraying = few tries per account. Many tries per account is brute force.
        avg_attempts = len(recent) / recent["username"].nunique()
        if avg_attempts > MAX_AVG_ATTEMPTS:
            continue

        targeted = sorted(recent["username"].unique())

        # Did this same IP get into any account during/after the spray?
        hits = g[g["success"] & (g.index > window_start)
                 & (g.index <= peak_time + pd.Timedelta(BREACH_WINDOW))]
        compromised = sorted(hits["username"].unique())

        if compromised:
            level = "Critical"
        elif peak_users >= HIGH_THRESHOLD:
            level = "High"
        else:
            level = "Medium"

        explanation = (f"{level} Risk: {peak_users} different accounts failed to log in "
                       f"from {ip} within {WINDOW} (about {avg_attempts:.1f} attempt(s) per account)")
        if compromised:
            explanation += (f", followed by a successful login to {', '.join(compromised)} "
                            f"(possible account takeover).")
        else:
            explanation += " - typical password-spraying pattern."

        events.append({
            "source": "credential_attacks",
            "category": "Credential Theft / Account Takeover",
            "threat_type": "Password Spraying",
            "timestamp": str(peak_time),
            "user": ", ".join(compromised) if compromised else "multiple accounts",
            "source_ip": ip,
            "risk_level": level,
            "risk_score": SCORES[level],
            "explanation": explanation,
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