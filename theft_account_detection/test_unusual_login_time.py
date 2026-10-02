import pandas as pd
from unusual_login_time_detector import detect_unusual_login_time, make_logs

COLS = ["timestamp", "username", "ip", "success", "device", "country"]


def user_logins(user, n, hour, ip="10.0.0.1"):
    """n daily logins for one user, always at the same hour."""
    base = pd.Timestamp("2026-09-01")
    return [[base + pd.Timedelta(days=i, hours=hour), user, ip, True, "laptop", "IN"]
            for i in range(n)]


def test_3am_login_from_new_ip_is_high():
    events = detect_unusual_login_time(make_logs())
    assert len(events) == 1
    assert events[0]["user"] == "user5"
    assert events[0]["risk_level"] == "High"


def test_normal_time_login_is_not_flagged():
    rows = user_logins("amy", 25, 10)
    rows.append([pd.Timestamp("2026-10-10 10:30"), "amy", "10.0.0.1", True, "laptop", "IN"])
    assert detect_unusual_login_time(pd.DataFrame(rows, columns=COLS)) == []


def test_night_login_from_known_ip_is_medium():
    rows = user_logins("amy", 25, 10)
    rows.append([pd.Timestamp("2026-10-10 03:00"), "amy", "10.0.0.1", True, "laptop", "IN"])
    events = detect_unusual_login_time(pd.DataFrame(rows, columns=COLS))
    assert len(events) == 1
    assert events[0]["risk_level"] == "Medium"


def test_too_little_history_is_not_flagged():
    rows = user_logins("amy", 5, 10)
    rows.append([pd.Timestamp("2026-10-10 03:00"), "amy", "10.0.0.1", True, "laptop", "IN"])
    assert detect_unusual_login_time(pd.DataFrame(rows, columns=COLS)) == []