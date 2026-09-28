import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
import pytest
from anomaly_detection import CyberGuardAnomalyDetector


@pytest.fixture
def sample_data():
    return pd.DataFrame({
        "failed_logins": [0, 1, 0, 2, 1, 0, 3, 2, 25, 30],
        "login_attempts": [2, 3, 1, 4, 2, 3, 5, 4, 40, 50],
        "connection_count": [10, 12, 8, 15, 11, 13, 20, 18, 150, 200],
        "data_transferred_mb": [20, 25, 15, 30, 22, 28, 35, 40, 900, 1200],
    })


def test_train_sets_features_mean_std(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    assert detector.features == list(sample_data.columns)
    assert detector.mean is not None
    assert detector.std is not None


def test_train_raises_on_no_numeric_columns():
    detector = CyberGuardAnomalyDetector()
    with pytest.raises(ValueError):
        detector.train(pd.DataFrame({"name": ["a", "b"]}))


def test_predict_adds_expected_columns(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    result = detector.predict(sample_data)
    for col in ["anomaly", "risk_score", "risk_level", "recommended_action"]:
        assert col in result.columns


def test_risk_score_bounds(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    result = detector.predict(sample_data)
    assert result["risk_score"].between(0, 100).all()


def test_known_outliers_flagged_as_anomaly(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    result = detector.predict(sample_data)
    assert result.loc[8, "anomaly"] == "Anomaly"
    assert result.loc[9, "anomaly"] == "Anomaly"


def test_missing_feature_raises_keyerror(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    bad_data = sample_data.drop(columns=["failed_logins"])
    with pytest.raises(KeyError):
        detector.predict(bad_data)


def test_single_normal_event_is_not_critical(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    normal_event = pd.DataFrame({
        "failed_logins": [0], "login_attempts": [2],
        "connection_count": [10], "data_transferred_mb": [20],
    })
    result = detector.predict(normal_event)
    assert result.loc[0, "risk_score"] < 60
    assert result.loc[0, "anomaly"] == "Normal"


def test_single_attack_event_is_critical(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    attack_event = pd.DataFrame({
        "failed_logins": [30], "login_attempts": [50],
        "connection_count": [200], "data_transferred_mb": [1200],
    })
    result = detector.predict(attack_event)
    assert result.loc[0, "risk_level"] == "Critical"


def test_save_and_load_model_gives_same_scores(sample_data):
    detector = CyberGuardAnomalyDetector()
    detector.train(sample_data)
    detector.save_model()
    loaded = CyberGuardAnomalyDetector.load_model()
    original = detector.predict(sample_data)["risk_score"].tolist()
    reloaded = loaded.predict(sample_data)["risk_score"].tolist()
    assert original == reloaded