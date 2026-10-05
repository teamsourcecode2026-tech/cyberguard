import json
import os
import sys
from datetime import datetime, timedelta

import pandas as pd

# Tell Python where to find risk_scoring.py (in the sibling "ml_anomaly" folder)
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
)

from risk_scoring import score_and_explain

# ---- Settings (change these to tune sensitivity) ----
MIN_EVENTS = 3

RESPONSES = {
    "Critical": "Revoke the session immediately, force password reset, require MFA, notify SOC",
    "High": "Revoke the session, require re-login with MFA, notify SOC",
    "Medium": "Require re-authentication, warn user",
    "Low": "Log and monitor (likely a Wi-Fi to mobile data switch)",
}


def make_logs():
    """Fake session activity: 20 users, each with one session of 8 requests
    from their own laptop and IP. Then three special cases:
      user6  : session suddenly used from a new IP, new device, new country (hijack)
      user10 : session moves to a new IP only (Wi-Fi -> mobile data, harmless)
      user14 : session moves to a new IP and a new device, same country"""
    base = datetime(2026, 10, 1, 9, 0)
    rows = []
    for n in range(1, 21):
        for k in range(8):
            rows.append([base + timedelta(minutes=n * 3 + k * 5), f"user{n}",
                         f"sess-{n}", f"10.0.0.{n}", f"laptop-{n}", "IN"])
    rows.append([base + timedelta(minutes=60), "user6", "sess-6",
                 "185.22.1.9", "unknown-android", "RU"])
    rows.append([base + timedelta(minutes=70), "user10", "sess-10",
                 "100.64.0.10", "laptop-10", "IN"])
    rows.append([base + timedelta(minutes=80), "user14", "sess-14",
                 "103.21.4.9", "chrome-windows-new", "IN"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "session_id",
                                       "ip", "device", "country"])


def detect_session_anomalies(df):
    """Input: DataFrame with columns timestamp, username, session_id, ip, device, country.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    events = []

    # Look at each session on its own
    for session, g in df.groupby("session_id"):
        first = g.iloc[0]
        known_ips, known_devices, known_countries = set(), set(), set()

        for count, row in enumerate(g.itertuples(index=False)):
            ip, device, country = str(row.ip), str(row.device), str(row.country)

            # "count" = how many requests this session made before this one
            if count >= MIN_EVENTS:
                new_ip = ip not in known_ips
                new_device = device not in known_devices
                new_country = country not in known_countries

                if new_ip or new_device or new_country:
                    if new_device and new_country:
                        score = 90
                    elif new_device and new_ip:
                        score = 70
                    elif new_device or new_country:
                        score = 45
                    else:
                        score = 25

                    novel = []
                    if new_device:
                        novel.append(f"new device '{device}'")
                    if new_ip:
                        novel.append(f"new IP {ip}")
                    if new_country:
                        novel.append(f"new country {country}")

                    scored = score_and_explain(
                        {"score": score, "indicators": novel},
                        category="Session Anomaly"
                    )
                    level = scored["risk_level"]

                    events.append({
                        "source": "credential_attacks",
                        "category": "Credential Theft / Account Takeover",
                        "threat_type": "Session Anomaly",
                        "timestamp": str(row.timestamp),
                        "user": str(row.username),
                        "source_ip": ip,
                        "risk_level": level,
                        "risk_score": score,
                        "explanation": scored["explanation"],
                        "evidence": {"session_id": str(session),
                                     "new_ip": bool(new_ip),
                                     "new_device": bool(new_device),
                                     "new_country": bool(new_country),
                                     "original_ip": str(first["ip"]),
                                     "original_device": str(first["device"]),
                                     "requests_before_change": int(count)},
                        "response": RESPONSES[level],
                        "mitre": "T1550.004 - Web Session Cookie",
                    })

            # Remember this request so it counts as "known" for this session
            known_ips.add(ip)
            known_devices.add(device)
            known_countries.add(country)
    return events


if __name__ == "__main__":
    alerts = detect_session_anomalies(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")