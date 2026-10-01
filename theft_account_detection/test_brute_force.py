import pandas as pd
from brute_force_detection import detect_brute_force, make_logs

COLS = ["timestamp", "username", "ip", "success", "device", "country"]


def test_attack_is_critical():
    events = detect_brute_force(make_logs())
    assert len(events) == 1
    assert events[0]["user"] == "user3"
    assert events[0]["risk_level"] == "Critical"


def test_three_failures_then_success_is_not_flagged():
    t = pd.Timestamp("2026-10-01 10:00")
    rows = [[t + pd.Timedelta(seconds=i * 10), "alice", "1.1.1.1", False, "laptop", "IN"]
            for i in range(3)]
    rows.append([t + pd.Timedelta(minutes=1), "alice", "1.1.1.1", True, "laptop", "IN"])
    assert detect_brute_force(pd.DataFrame(rows, columns=COLS)) == []