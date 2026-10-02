import pandas as pd
from new_device_ip_detector import detect_new_device_or_ip, make_logs

COLS = ["timestamp", "username", "ip", "success", "device", "country"]


def user_logins(user, n):
    """n daily logins for one user from the same IP, device and country."""
    base = pd.Timestamp("2026-09-01 10:00")
    return [[base + pd.Timedelta(days=i), user, "10.0.0.1", True, "laptop", "IN"]
            for i in range(n)]


def test_risk_levels_in_simulated_data():
    events = detect_new_device_or_ip(make_logs())
    levels = {e["user"]: e["risk_level"] for e in events}
    assert levels == {"user7": "High", "user9": "Low"}


def test_known_device_and_ip_is_not_flagged():
    rows = user_logins("amy", 15)
    rows.append([pd.Timestamp("2026-10-01 10:00"), "amy", "10.0.0.1", True, "laptop", "IN"])
    assert detect_new_device_or_ip(pd.DataFrame(rows, columns=COLS)) == []


def test_new_device_only_is_medium():
    rows = user_logins("amy", 15)
    rows.append([pd.Timestamp("2026-10-01 10:00"), "amy", "10.0.0.1", True, "phone", "IN"])
    events = detect_new_device_or_ip(pd.DataFrame(rows, columns=COLS))
    assert len(events) == 1
    assert events[0]["risk_level"] == "Medium"


def test_same_new_device_is_flagged_only_once():
    rows = user_logins("amy", 15)
    rows.append([pd.Timestamp("2026-10-01 10:00"), "amy", "10.0.0.1", True, "phone", "IN"])
    rows.append([pd.Timestamp("2026-10-02 10:00"), "amy", "10.0.0.1", True, "phone", "IN"])
    assert len(detect_new_device_or_ip(pd.DataFrame(rows, columns=COLS))) == 1


def test_too_little_history_is_not_flagged():
    rows = user_logins("amy", 3)
    rows.append([pd.Timestamp("2026-10-01 10:00"), "amy", "9.9.9.9", True, "phone", "RU"])
    assert detect_new_device_or_ip(pd.DataFrame(rows, columns=COLS)) == []