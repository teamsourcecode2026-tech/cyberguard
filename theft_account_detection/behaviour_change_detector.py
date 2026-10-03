import json
from datetime import datetime, timedelta

import pandas as pd

# ---- Settings (change these to tune sensitivity) ----
MIN_DAYS = 7              # need 7 days of download history before judging a user
SPIKE_Z = 3               # z-score of 3+ = unusual spike (Medium)
HIGH_Z = 6                # z-score of 6+ = extreme spike (High)
MIN_STD = 2               # minimum spread, so constant users don't over-alert
MIN_ABS = 20              # a spike must be at least 20 files
PAIR_WINDOW = "30min"     # password + recovery email changed within this time

RESPONSES = {
    "Critical": "Suspend account, revoke all sessions, restore recovery email, force password reset, notify SOC",
    "High": "Require MFA, verify with the user, review recent changes and downloads, notify SOC",
    "Medium": "Warn user, require re-authentication, monitor activity",
}
SCORES = {"Critical": 90, "High": 70, "Medium": 45}


def make_logs():
    """Fake activity: 20 users download 8-12 files a day for 30 days.
    Then on day 31:
      user3  : downloads 13 files (a bit more than usual, harmless)
      user6  : downloads 150 files (spike)
      user11 : changes password and recovery email 10 minutes apart (lockout pattern)
      user15 : downloads 150 files AND changes password + recovery email (both)"""
    base = datetime(2026, 9, 1)
    rows = []
    for n in range(1, 21):
        for j in range(30):
            rows.append([base + timedelta(days=j, hours=10, minutes=n),
                         f"user{n}", "download", 8 + (j + n) % 5, f"10.0.0.{n}"])
    day31 = base + timedelta(days=30)
    rows.append([day31 + timedelta(hours=11), "user3", "download", 13, "10.0.0.3"])
    rows.append([day31 + timedelta(hours=15), "user6", "download", 150, "185.22.1.9"])
    rows.append([day31 + timedelta(hours=14), "user11", "password_change", 0, "185.22.1.9"])
    rows.append([day31 + timedelta(hours=14, minutes=10), "user11", "recovery_email_change", 0, "185.22.1.9"])
    rows.append([day31 + timedelta(hours=3), "user15", "download", 150, "94.200.1.5"])
    rows.append([day31 + timedelta(hours=3, minutes=20), "user15", "password_change", 0, "94.200.1.5"])
    rows.append([day31 + timedelta(hours=3, minutes=25), "user15", "recovery_email_change", 0, "94.200.1.5"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "action", "amount", "ip"])


def detect_behaviour_change(df):
    """Input: DataFrame with columns timestamp, username, action, amount, ip.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["day"] = df["timestamp"].dt.normalize()
    df = df.sort_values("timestamp")
    window = pd.Timedelta(PAIR_WINDOW)
    events = []

    for user, g in df.groupby("username"):
        # Files downloaded per day by this user
        downloads = g[g["action"] == "download"].groupby("day")["amount"].sum().sort_index()
        pw_times = g[g["action"] == "password_change"]["timestamp"]
        em_times = g[g["action"] == "recovery_email_change"]["timestamp"]

        for day in sorted(g["day"].drop_duplicates()):
            # Signal 1: download spike compared with this user's own past days
            spike, z, today, mean = False, 0.0, 0.0, 0.0
            if day in downloads.index:
                past = downloads[downloads.index < day]
                if len(past) >= MIN_DAYS:
                    today = float(downloads[day])
                    mean = float(past.mean())
                    std = max(float(past.std()), MIN_STD)
                    z = (today - mean) / std
                    spike = z >= SPIKE_Z and today >= MIN_ABS

            # Signal 2: password and recovery email both changed within 30 minutes
            pw_today = pw_times[pw_times.dt.normalize() == day]
            em_today = em_times[em_times.dt.normalize() == day]
            paired = any(abs(a - b) <= window for a in pw_today for b in em_today)

            if not spike and not paired:
                continue

            if spike and paired:
                level = "Critical"
            elif paired:
                level = "High"
            else:
                level = "High" if z >= HIGH_Z else "Medium"

            parts = []
            if spike:
                parts.append(f"downloaded {int(today)} files on {day:%Y-%m-%d}, but normally "
                             f"downloads about {mean:.0f} per day (z-score {z:.1f})")
            if paired:
                parts.append(f"changed both the password and the recovery email "
                             f"within {PAIR_WINDOW}")
            explanation = f"{level} Risk: {user} " + " and ".join(parts) + "."

            if spike and paired:
                mitre = "T1098 - Account Manipulation; T1567 - Exfiltration Over Web Service"
            elif paired:
                mitre = "T1098 - Account Manipulation"
            else:
                mitre = "T1567 - Exfiltration Over Web Service"

            day_rows = g[g["day"] == day]
            events.append({
                "source": "credential_attacks",
                "category": "Credential Theft / Account Takeover",
                "threat_type": "Sudden Behaviour Change",
                "timestamp": str(day_rows.iloc[-1]["timestamp"]),
                "user": str(user),
                "source_ip": str(day_rows.iloc[-1]["ip"]),
                "risk_level": level,
                "risk_score": SCORES[level],
                "explanation": explanation,
                "evidence": {"download_spike": bool(spike),
                             "files_downloaded_today": int(round(today)),
                             "normal_daily_downloads": round(mean, 1),
                             "z_score": round(z, 1),
                             "password_and_email_changed": bool(paired)},
                "response": RESPONSES[level],
                "mitre": mitre,
            })
    return events


if __name__ == "__main__":
    alerts = detect_behaviour_change(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")