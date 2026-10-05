import json
from datetime import datetime, timedelta

import pandas as pd
import os
import sys
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
)
from risk_scoring import score_and_explain

MIN_HISTORY = 20
TOLERANCE_HOURS = 1
RARE_SHARE = 0.05
NIGHT_START, NIGHT_END = 0, 6

RESPONSES = {
    "High": "Require MFA, verify login with the user, revoke session if not confirmed, notify SOC",
    "Medium": "Require MFA, warn user about off-hours login",
    "Low": "Log and monitor",
}


def make_logs():
    base = datetime(2026, 9, 1)
    rows = []
    for n in range(1, 21):
        for j in range(30):
            hour = 9 + (j + n) % 9
            minute = (j * 7) % 60
            rows.append([base + timedelta(days=j, hours=hour, minutes=minute),
                         f"user{n}", f"10.0.0.{n}", True, "laptop", "IN"])
    rows.append([base + timedelta(days=31, hours=3, minutes=12),
                 "user5", "185.22.1.9", True, "unknown", "RU"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def circular_diff(a, b):
    d = abs(a - b) % 24
    return min(d, 24 - d)


def detect_unusual_login_time(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    ok = df[df["success"]]
    for user, g in ok.groupby("username"):
        g = g.reset_index(drop=True)
        g["hour"] = g["timestamp"].dt.hour + g["timestamp"].dt.minute / 60

        for i in range(MIN_HISTORY, len(g)):
            row = g.iloc[i]
            past = g.iloc[:i]

            near = sum(circular_diff(h, row["hour"]) <= TOLERANCE_HOURS for h in past["hour"])
            if near / len(past) >= RARE_SHARE:
                continue

            new_ip = row["ip"] not in set(past["ip"])
            is_night = NIGHT_START <= row["timestamp"].hour < NIGHT_END
            if new_ip:
                score = 70
            elif is_night:
                score = 45
            else:
                score = 25

            usual_hour = int(past["hour"].astype(int).mode().iloc[0])
            login_time = row["timestamp"].strftime("%H:%M")

            indicators = [f"logged in at {login_time}, but only {near} of {len(past)} past logins were within {TOLERANCE_HOURS} hour of that time (usually around {usual_hour:02d}:00)"]
            if new_ip:
                indicators.append(f"source IP {row['ip']} was never used by this user before")

            scored = score_and_explain({"score": score, "indicators": indicators}, category="Unusual Login Time")
            level = scored["risk_level"]

            events.append({
                "source": "credential_attacks",
                "category": "Credential Theft / Account Takeover",
                "threat_type": "Unusual Login Time",
                "timestamp": str(row["timestamp"]),
                "user": user,
                "source_ip": str(row["ip"]),
                "risk_level": level,
                "risk_score": scored["score"],
                "explanation": scored["explanation"],
                "evidence": {"login_time": login_time, "usual_hour": int(usual_hour), "past_logins": int(len(past)), "past_logins_near_this_time": int(near), "new_ip": bool(new_ip), "night_login": bool(is_night)},
                "response": RESPONSES[level],
                "mitre": "T1078 - Valid Accounts",
            })
    return events


if __name__ == "__main__":
    alerts = detect_unusual_login_time(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")