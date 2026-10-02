import pandas as pd
from impossible_travel_detector import detect_impossible_travel, make_logs

COLS = ["timestamp", "username", "ip", "success", "device", "country", "city"]


def two_logins(city1, time1, city2, time2):
    return pd.DataFrame([
        [pd.Timestamp(time1), "amy", "1.1.1.1", True, "laptop", "IN", city1],
        [pd.Timestamp(time2), "amy", "2.2.2.2", True, "laptop", "IN", city2],
    ], columns=COLS)


def test_simulated_data_levels():
    events = detect_impossible_travel(make_logs())
    levels = {e["user"]: e["risk_level"] for e in events}
    assert levels == {"user4": "Critical", "user12": "High"}


def test_realistic_flight_is_not_flagged():
    df = two_logins("Delhi", "2026-10-01 10:00", "Mumbai", "2026-10-01 18:00")
    assert detect_impossible_travel(df) == []


def test_same_city_is_not_flagged():
    df = two_logins("Delhi", "2026-10-01 10:00", "Delhi", "2026-10-01 10:05")
    assert detect_impossible_travel(df) == []


def test_unknown_city_is_ignored():
    df = two_logins("Delhi", "2026-10-01 10:00", "Atlantis", "2026-10-01 10:05")
    assert detect_impossible_travel(df) == []


def test_simultaneous_logins_far_apart_are_critical():
    df = two_logins("Delhi", "2026-10-01 10:00", "London", "2026-10-01 10:00")
    events = detect_impossible_travel(df)
    assert len(events) == 1
    assert events[0]["risk_level"] == "Critical"