from model import analyze_anomaly

tests = [
    {"user_id": "u1", "ip": "10.0.0.1", "device": "known_device", "timestamp": "2026-09-26T14:30:00", "failed_attempts": 0},
    {"user_id": "u2", "ip": "10.0.0.2", "device": "known_device", "timestamp": "2026-09-26T10:00:00", "failed_attempts": 1},
    {"user_id": "u3", "ip": "45.12.9.8", "device": "unknown_device", "timestamp": "2026-09-26T03:15:00", "failed_attempts": 6},
    {"user_id": "u4", "ip": "91.2.3.4", "device": "unknown_device", "timestamp": "2026-09-26T13:00:00", "failed_attempts": 4},
    {"user_id": "u5", "ip": "10.0.0.5", "device": "known_device", "timestamp": "2026-09-26T02:00:00", "failed_attempts": 0},
    {"user_id": "u6", "ip": "10.0.0.6", "device": "unknown_device", "timestamp": "2026-09-26T11:00:00", "failed_attempts": 0},
]

for t in tests:
    print(t["user_id"], "->", analyze_anomaly(t))