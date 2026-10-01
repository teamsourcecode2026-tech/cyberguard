import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from model import analyze_anomaly


def test_normal_event_scores_low():
    result = analyze_anomaly({
        "failed_attempts": 0,
        "device": "known_device",
        "timestamp": "2026-09-29T14:00:00",
    })
    assert result["score"] <= 15
    assert result["verdict"] == "Normal"
    assert result["indicators"] == []


def test_attack_event_scores_high():
    result = analyze_anomaly({
        "failed_attempts": 5,
        "device": "new_phone",
        "timestamp": "2026-09-29T02:30:00",
    })
    assert result["score"] >= 70
    assert result["verdict"] == "High-Risk"
    assert len(result["indicators"]) == 3


def test_missing_fields_default_safely():
    result = analyze_anomaly({})
    assert 0 <= result["score"] <= 100
    assert result["verdict"] in ("Normal", "Unusual", "High-Risk")


def test_malformed_timestamp_does_not_crash():
    result = analyze_anomaly({
        "failed_attempts": 1,
        "device": "known_device",
        "timestamp": "not-a-date",
    })
    assert 0 <= result["score"] <= 100


def test_score_always_within_bounds():
    result = analyze_anomaly({
        "failed_attempts": 999,
        "device": "new_phone",
        "timestamp": "2026-09-29T03:00:00",
    })
    assert 0 <= result["score"] <= 100


def test_new_device_alone_is_flagged():
    result = analyze_anomaly({
        "failed_attempts": 0,
        "device": "new_phone",
        "timestamp": "2026-09-29T14:00:00",
    })
    assert "new or unknown device" in result["indicators"]