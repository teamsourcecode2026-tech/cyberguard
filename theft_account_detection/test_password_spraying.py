import pandas as pd
from password_spraying_detector import detect_password_spraying, make_logs

COLS = ["timestamp", "username", "ip", "success", "device", "country"]


def test_spray_is_critical():
    events = detect_password_spraying(make_logs())
    assert len(events) == 1
    assert events[0]["source_ip"] == "45.33.12.7"
    assert events[0]["risk_level"] == "Critical"
    assert events[0]["evidence"]["compromised_users"] == ["user13"]


def test_three_accounts_failing_is_not_flagged():
    t = pd.Timestamp("2026-10-01 10:00")
    rows = [[t + pd.Timedelta(seconds=i * 20), f"user{i}", "1.1.1.1", False, "laptop", "IN"]
            for i in range(3)]
    assert detect_password_spraying(pd.DataFrame(rows, columns=COLS)) == []


def test_one_account_many_failures_is_brute_force_not_spraying():
    t = pd.Timestamp("2026-10-01 10:00")
    rows = [[t + pd.Timedelta(seconds=i * 4), "bob", "2.2.2.2", False, "laptop", "IN"]
            for i in range(15)]
    assert detect_password_spraying(pd.DataFrame(rows, columns=COLS)) == []