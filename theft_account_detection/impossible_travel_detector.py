import json
import math
from datetime import datetime, timedelta

import pandas as pd

# ---- Settings (change these to tune sensitivity) ----
MAX_SPEED_KMH = 900         # faster than a passenger plane = impossible
CRITICAL_SPEED_KMH = 2000   # faster than this = Critical
MIN_DISTANCE_KM = 100       # ignore short hops (GPS/IP location is not exact)
MIN_HOURS = 1 / 60          # treat gaps shorter than 1 minute as 1 minute

# City -> (latitude, longitude). Add more cities your logs contain.
CITY_COORDS = {
    "Bhubaneswar": (20.2961, 85.8245),
    "Kolkata": (22.5726, 88.3639),
    "Delhi": (28.6139, 77.2090),
    "Mumbai": (19.0760, 72.8777),
    "Dubai": (25.2048, 55.2708),
    "Moscow": (55.7558, 37.6173),
    "London": (51.5074, -0.1278),
}

RESPONSES = {
    "Critical": "Revoke all sessions, force password reset, require MFA, notify SOC",
    "High": "Require MFA, verify with the user, revoke the newer session if not confirmed",
}
SCORES = {"Critical": 90, "High": 70}


def haversine_km(lat1, lon1, lat2, lon2):
    """Distance in km between two points on Earth."""
    r = 6371
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def make_logs():
    """Fake logs: 20 users log in daily at 10:00 from their home city for 30 days.
    Then three special cases on day 31:
      user4  : Bhubaneswar 10:04 -> Moscow 10:34   (impossible)
      user12 : Mumbai 10:12      -> Dubai 12:12    (too fast for a plane)
      user8  : Delhi 10:08       -> Mumbai 18:08   (normal flight, harmless)"""
    base = datetime(2026, 9, 1)
    special_home = {4: "Bhubaneswar", 8: "Delhi", 12: "Mumbai"}
    rows = []
    for n in range(1, 21):
        home = special_home.get(n, "Kolkata")
        for j in range(30):
            rows.append([base + timedelta(days=j, hours=10, minutes=n),
                         f"user{n}", f"10.0.0.{n}", True, f"laptop-{n}", "IN", home])
    day31 = base + timedelta(days=30)
    # Normal logins at home on day 31
    rows.append([day31 + timedelta(hours=10, minutes=4), "user4", "10.0.0.4", True, "laptop-4", "IN", "Bhubaneswar"])
    rows.append([day31 + timedelta(hours=10, minutes=8), "user8", "10.0.0.8", True, "laptop-8", "IN", "Delhi"])
    rows.append([day31 + timedelta(hours=10, minutes=12), "user12", "10.0.0.12", True, "laptop-12", "IN", "Mumbai"])
    # Second logins from far away
    rows.append([day31 + timedelta(hours=10, minutes=34), "user4", "185.22.1.9", True, "unknown", "RU", "Moscow"])
    rows.append([day31 + timedelta(hours=12, minutes=12), "user12", "94.200.1.5", True, "unknown", "AE", "Dubai"])
    rows.append([day31 + timedelta(hours=18, minutes=8), "user8", "10.1.1.8", True, "laptop-8", "IN", "Mumbai"])
    return pd.DataFrame(rows, columns=["timestamp", "username", "ip",
                                       "success", "device", "country", "city"])


def detect_impossible_travel(df):
    """Input: DataFrame with columns timestamp, username, ip, success, city.
    Output: list of alert dictionaries."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["success"] = df["success"].astype(bool)
    df = df.sort_values("timestamp")
    events = []

    # Only successful logins prove where a person really was
    ok = df[df["success"]]
    for user, g in ok.groupby("username"):
        g = g.reset_index(drop=True)

        for i in range(1, len(g)):
            prev, cur = g.iloc[i - 1], g.iloc[i]
            city1, city2 = str(prev["city"]), str(cur["city"])
            if city1 not in CITY_COORDS or city2 not in CITY_COORDS:
                continue                      # unknown city, cannot judge

            km = haversine_km(*CITY_COORDS[city1], *CITY_COORDS[city2])
            if km < MIN_DISTANCE_KM:
                continue                      # same city or very close

            hours = (cur["timestamp"] - prev["timestamp"]).total_seconds() / 3600
            hours = max(hours, MIN_HOURS)
            speed = km / hours
            if speed <= MAX_SPEED_KMH:
                continue                      # a plane could do this trip

            level = "Critical" if speed > CRITICAL_SPEED_KMH else "High"
            minutes = round(hours * 60)

            explanation = (f"{level} Risk: {user} logged in from {city1} at "
                           f"{prev['timestamp']:%H:%M} and then from {city2} at "
                           f"{cur['timestamp']:%H:%M} ({minutes} minutes later). "
                           f"That is {km:.0f} km, needing about {speed:.0f} km/h, "
                           f"faster than a passenger plane (about {MAX_SPEED_KMH} km/h).")

            events.append({
                "source": "credential_attacks",
                "category": "Credential Theft / Account Takeover",
                "threat_type": "Impossible Travel",
                "timestamp": str(cur["timestamp"]),
                "user": str(user),
                "source_ip": str(cur["ip"]),
                "risk_level": level,
                "risk_score": SCORES[level],
                "explanation": explanation,
                "evidence": {"from_city": city1,
                             "to_city": city2,
                             "distance_km": int(round(km)),
                             "time_gap_minutes": int(minutes),
                             "required_speed_kmh": int(round(speed))},
                "response": RESPONSES[level],
                "mitre": "T1078 - Valid Accounts",
            })
    return events


if __name__ == "__main__":
    alerts = detect_impossible_travel(make_logs())
    print(json.dumps(alerts, indent=2))
    print(f"\nTotal alerts: {len(alerts)}")