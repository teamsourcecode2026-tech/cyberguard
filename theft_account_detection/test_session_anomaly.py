import pandas as pd
from session_anomaly_detector import detect_session_anomalies, make_logs

COLS = ["timestamp", "username", "session_id", "ip", "device", "country"]


def session_rows(n):
    """n requests of one session, all from the same IP, device and country."""
    base = pd.Timestamp("2026-10-01 10:00")
    return [[base + pd.Timedelta(minutes=i), "amy", "s1", "10.0.0.1", "laptop", "IN"]
            for i in range(n)]


def test_levels_in_simulated_data():
    events = detect_session_anomalies(make_logs())
    levels = {e["user"]: e["risk_level"] for e in events}
    assert levels == {"user6": "Critical", "user14": "High", "user10": "Low"}


def test_consistent_session_is_not_flagged():
    rows = session_rows(8)
    assert detect_session_anomalies(pd.DataFrame(rows, columns=COLS)) == []


def test_new_device_on_same_ip_is_medium():
    rows = session_rows(6)
    rows.append([pd.Timestamp("2026-10-01 11:00"), "amy", "s1", "10.0.0.1", "phone", "IN"])
    events = detect_session_anomalies(pd.DataFrame(rows, columns=COLS))
    assert len(events) == 1
    assert events[0]["risk_level"] == "Medium"


def test_same_new_ip_is_flagged_only_once():
    rows = session_rows(6)
    rows.append([pd.Timestamp("2026-10-01 11:00"), "amy", "s1", "9.9.9.9", "laptop", "IN"])
    rows.append([pd.Timestamp("2026-10-01 11:05"), "amy", "s1", "9.9.9.9", "laptop", "IN"])
    assert len(detect_session_anomalies(pd.DataFrame(rows, columns=COLS))) == 1


def test_too_few_requests_is_not_flagged():
    rows = session_rows(2)
    rows.append([pd.Timestamp("2026-10-01 11:00"), "amy", "s1", "9.9.9.9", "phone", "RU"])
    assert detect_session_anomalies(pd.DataFrame(rows, columns=COLS)) == []