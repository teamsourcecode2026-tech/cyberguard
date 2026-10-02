import json
from datetime import datetime, timedelta

import pandas as pd

# ---- Settings (change these to tune sensitivity) ----
MIN_HISTORY = 10          # need at least 10 past logins before judging a user

RESPONSES = {
    "High": "Require MFA, revoke active sessions, verify with the user, notify SOC",
    "Medium": "Require MFA, warn user about the new device or location",
    "Low": "Log and notify user of new network",
}
SCORES = {"High": 70, "Medium": 45, "Low": 25}


def make_logs():
    """Fake logs: 20 users log in for 30 days from their own laptop and IP.
    Then user7 logs in from a completely new device, IP and country,
    and user9 logs in from just a new IP (e.g. different Wi-Fi)."""
    base = datetime(2026, 9, 1)
    rows = []
    for n in range(1, 21):
        for j in range(30):
            rows.append([base + timedelta(days=j, hours=10, minutes=n),
                         f"user{n}", f"10.0.0.{n}", True, f"laptop-{n}", "IN"])
    # Attack: user7 from a new IP, new device and new country
    rows.append([base + timedelta(days=31, hours=14),
                 "user7", "185.22.1.9", True, "unknown-android", "RU"])
    # Harmless change: user9 on a new IP, same laptop, same country
    rows.append([base + timedelta(days=31, hours=15),
                 "user9", "192.168.1.50", True, "laptop-9", "IN"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country"])


def detect_new_device_or_ip(df):
    """Input: DataFrame with columns timestamp, username, ip, success, device, country.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    # Only successful logins describe what is normal for a user
    ok = df[df["success"]]
    for user, g in ok.groupby("username"):
        known_ips, known_devices, known_countries = set(), set(), set()

        for count, row in enumerate(g.itertuples(index=False)):
            ip, device, country = str(row.ip), str(row.device), str(row.country)

            # "count" = how many logins this user had before this one
            if count >= MIN_HISTORY:
                new_ip = ip not in known_ips
                new_device = device not in known_devices
                new_country = country not in known_countries

                if new_ip or new_device or new_country:
                    if new_device and new_country:
                        level = "High"
                    elif new_device or (new_ip and new_country):
                        level = "Medium"
                    else:
                        level = "Low"

                    novel = []
                    if new_device:
                        novel.append(f"device '{device}'")
                    if new_ip:
                        novel.append(f"IP {ip}")
                    if new_country:
                        novel.append(f"country {country}")

                    explanation = (f"{level} Risk: {user} logged in using a never-seen-before "
                                   f"{', '.join(novel)} (based on {count} past logins).")

                    events.append({
                        "source": "credential_attacks",
                        "category": "Credential Theft / Account Takeover",
                        "threat_type": "New Device or IP",
                        "timestamp": str(row.timestamp),
                        "user": user,
                        "source_ip": ip,
                        "risk_level": level,
                        "risk_score": SCORES[level],
                        "explanation": explanation,
                        "evidence": {"new_ip": bool(new_ip),
                                     "new_device": bool(new_device),
                                     "new_country": bool(new_country),
                                     "device": device,
                                     "country": country,
                                     "past_logins": int(count)},
                        "response": RESPONSES[level],
                        "mitre": "T1078 - Valid Accounts",
                    })

            # Remember this login so it is "known" from now on
            known_ips.add(ip)
            known_devices.add(device)
            known_countries.add(country)
    return events


if __name__ == "__main__":
    alerts = detect_new_device_or_ip(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")