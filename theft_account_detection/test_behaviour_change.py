import pandas as pd
from behaviour_change_detector import detect_behaviour_change, make_logs

COLS = ["timestamp", "username", "action", "amount", "ip"]


def daily_downloads(n, amount):
    """n days of one download per day with the same amount."""
    base = pd.Timestamp("2026-09-01 10:00")
    return [[base + pd.Timedelta(days=i), "amy", "download", amount, "10.0.0.1"]
            for i in range(n)]


def test_levels_in_simulated_data():
    events = detect_behaviour_change(make_logs())
    levels = {e["user"]: e["risk_level"] for e in events}
    assert levels == {"user6": "High", "user11": "High", "user15": "Critical"}


def test_slightly_higher_day_is_not_flagged():
    rows = daily_downloads(15, 10)
    rows.append([pd.Timestamp("2026-09-20 10:00"), "amy", "download", 13, "10.0.0.1"])
    assert detect_behaviour_change(pd.DataFrame(rows, columns=COLS)) == []


def test_big_spike_is_high():
    rows = daily_downloads(15, 10)
    rows.append([pd.Timestamp("2026-09-20 10:00"), "amy", "download", 40, "10.0.0.1"])
    events = detect_behaviour_change(pd.DataFrame(rows, columns=COLS))
    assert len(events) == 1
    assert events[0]["risk_level"] == "High"


def test_moderate_spike_is_medium():
    rows = daily_downloads(15, 10)
    rows.append([pd.Timestamp("2026-09-20 10:00"), "amy", "download", 20, "10.0.0.1"])
    events = detect_behaviour_change(pd.DataFrame(rows, columns=COLS))
    assert len(events) == 1
    assert events[0]["risk_level"] == "Medium"


def test_small_numbers_are_not_flagged():
    rows = daily_downloads(15, 1)
    rows.append([pd.Timestamp("2026-09-20 10:00"), "amy", "download", 15, "10.0.0.1"])
    assert detect_behaviour_change(pd.DataFrame(rows, columns=COLS)) == []


def test_too_little_history_is_not_flagged():
    rows = daily_downloads(3, 10)
    rows.append([pd.Timestamp("2026-09-10 10:00"), "amy", "download", 500, "10.0.0.1"])
    assert detect_behaviour_change(pd.DataFrame(rows, columns=COLS)) == []


def test_password_and_email_changed_close_together_is_high():
    rows = [[pd.Timestamp("2026-10-01 10:00"), "amy", "password_change", 0, "1.1.1.1"],
            [pd.Timestamp("2026-10-01 10:10"), "amy", "recovery_email_change", 0, "1.1.1.1"]]
    events = detect_behaviour_change(pd.DataFrame(rows, columns=COLS))
    assert len(events) == 1
    assert events[0]["risk_level"] == "High"


def test_changes_far_apart_are_not_flagged():
    rows = [[pd.Timestamp("2026-10-01 10:00"), "amy", "password_change", 0, "1.1.1.1"],
            [pd.Timestamp("2026-10-01 14:00"), "amy", "recovery_email_change", 0, "1.1.1.1"]]
    assert detect_behaviour_change(pd.DataFrame(rows, columns=COLS)) == []