import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)  # same data on every run

OUT = Path(__file__).parent / "data" / "login_logs.json"
BASE_TIME = datetime(2026, 9, 1, 0, 0, 0)

CITIES = [("Mumbai", "IN"), ("Delhi", "IN"), ("Bengaluru", "IN"),
          ("Pune", "IN"), ("Chennai", "IN")]

# 10 synthetic users, each with a fixed "normal" profile
users = {}
for i in range(1, 11):
    city, country = CITIES[i % len(CITIES)]
    users[f"user_{i:03d}"] = {
        "city": city, "country": country,
        "device": f"device-{i:03d}", "ip": f"192.0.2.{i}",
    }

events = []

def add(user_id, ts, ip, city, country, device, success, is_anomaly, attack_type):
    events.append({
        "user_id": user_id,
        "timestamp": ts.isoformat() + "Z",
        "ip": ip, "city": city, "country": country,
        "device_id": device, "success": success,
        "is_anomaly": is_anomaly,      # ground truth (never sent to the API)
        "attack_type": attack_type,
    })

# 1) NORMAL: 5 days of office-hours logins, ~5% typo failures
for uid, u in users.items():
    for day in range(5):
        ts = BASE_TIME + timedelta(days=day, hours=random.randint(9, 18),
                                   minutes=random.randint(0, 59))
        add(uid, ts, u["ip"], u["city"], u["country"], u["device"],
            random.random() > 0.05, False, "none")

# 2) BRUTE FORCE: 12 rapid failures on one account, then a success
t = BASE_TIME + timedelta(days=6, hours=14)
for k in range(12):
    add("user_001", t + timedelta(seconds=10 * k), "198.51.100.7",
        "Frankfurt", "DE", "unknown-dev-1", False, True, "brute_force")
add("user_001", t + timedelta(seconds=130), "198.51.100.7",
    "Frankfurt", "DE", "unknown-dev-1", True, True, "brute_force")

# 3) PASSWORD SPRAYING: one IP, one failed attempt on every account
t = BASE_TIME + timedelta(days=6, hours=16)
for n, uid in enumerate(users):
    add(uid, t + timedelta(seconds=5 * n), "198.51.100.9",
        "Singapore", "SG", "unknown-dev-2", False, True, "password_spraying")

# 4) IMPOSSIBLE TRAVEL: Delhi, then Brazil 20 minutes later
t = BASE_TIME + timedelta(days=6, hours=10)
add("user_002", t, "192.0.2.2", "Delhi", "IN", "device-002", True, False, "none")
add("user_002", t + timedelta(minutes=20), "198.51.100.21",
    "Sao Paulo", "BR", "device-002", True, True, "impossible_travel")

# 5) NEW DEVICE + NEW COUNTRY + 3 AM
t = BASE_TIME + timedelta(days=6, hours=3, minutes=10)
add("user_003", t, "198.51.100.33", "Singapore", "SG",
    "unknown-dev-3", True, True, "new_device_odd_hour")

events.sort(key=lambda e: e["timestamp"])  # detectors often need time order
OUT.write_text(json.dumps(events, indent=2), encoding="utf-8")

n_bad = sum(e["is_anomaly"] for e in events)
print(f"Wrote {len(events)} events ({n_bad} anomalous) to {OUT}")