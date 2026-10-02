import json
from datetime import datetime, timedelta

import pandas as pd

# ---- Settings (change these to tune sensitivity) ----
MIN_HISTORY = 20          # need at least 20 past logins before judging a user
TOLERANCE_HOURS = 1       # "same time" means within +/- 1 hour
RARE_SHARE = 0.05         # fewer than 5% of past logins near this hour = unusual
NIGHT_START, NIGHT_END = 0, 6   # 00:00 to 05:59 counts as night

RESPONSES = {
    "High": "Require MFA, verify login with the user, revoke session if not confirmed, notify SOC",
    "Medium": "Require MFA, warn user about off-hours login",
    "Low": "Log and monitor",
}
SCORES = {"High": 70, "Medium": 45, "Low": 25}


def make_logs():
    """Fake logs: 20 users who log in during office hours for 30 days,
    then user5 logs in at 3 AM from a new IP."""
    base = datetime(2026, 9, 1)
    rows = []
    for n in range(1, 21):
        for j in range(30):
            hour = 9 + (j + n) % 9          # always between 09:00 and 17:59
            minute = (j * 7) % 60
            rows.append([base + timedelta(days=j, hours=hour, minutes=minute),
                         f"user{n}", f"10.0.0.{n}", True, "laptop", "IN"])
    # Attack: user5 logs in at 03:12 from an IP never seen before
    rows.append([base + timedelta(days=31, hours=3, minutes=12),
                 "user5", "185.22.1.9", True, "unknown", "RU"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def circular_diff(a, b):
    """Distance between two clock hours (23:30 and 00:30 are 1 hour apart)."""
    d = abs(a - b) % 24
    return min(d, 24 - d)


def detect_unusual_login_time(df):
    """Input: DataFrame with columns timestamp, username, ip, success.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    # Only successful logins describe a user's normal behaviour
    ok = df[df["success"]]
    for user, g in ok.groupby("username"):
        g = g.reset_index(drop=True)
        g["hour"] = g["timestamp"].dt.hour + g["timestamp"].dt.minute / 60

        for i in range(MIN_HISTORY, len(g)):
            row = g.iloc[i]
            past = g.iloc[:i]       # the user's history BEFORE this login

            near = sum(circular_diff(h, row["hour"]) <= TOLERANCE_HOURS
                       for h in past["hour"])
            if near / len(past) >= RARE_SHARE:
                continue            # normal time for this user

            new_ip = row["ip"] not in set(past["ip"])
            is_night = NIGHT_START <= row["timestamp"].hour < NIGHT_END
            if new_ip:
                level = "High"
            elif is_night:
                level = "Medium"
            else:
                level = "Low"

            usual_hour = int(past["hour"].astype(int).mode().iloc[0])
            login_time = row["timestamp"].strftime("%H:%M")
            explanation = (f"{level} Risk: {user} logged in at {login_time}, but only "
                           f"{near} of {len(past)} past logins were within "
                           f"{TOLERANCE_HOURS} hour of that time "
                           f"(usually around {usual_hour:02d}:00)")
            if new_ip:
                explanation += f"; the source IP {row['ip']} was never used by this user before"
            explanation += "."

            events.append({
                "source": "credential_attacks",
                "category": "Credential Theft / Account Takeover",
                "threat_type": "Unusual Login Time",
                "timestamp": str(row["timestamp"]),
                "user": user,
                "source_ip": str(row["ip"]),
                "risk_level": level,
                "risk_score": SCORES[level],
                "explanation": explanation,
                "evidence": {"login_time": login_time,
                             "usual_hour": int(usual_hour),
                             "past_logins": int(len(past)),
                             "past_logins_near_this_time": int(near),
                             "new_ip": bool(new_ip),
                             "night_login": bool(is_night)},
                "response": RESPONSES[level],
                "mitre": "T1078 - Valid Accounts",
            })
    return events


if __name__ == "__main__":
    alerts = detect_unusual_login_time(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")