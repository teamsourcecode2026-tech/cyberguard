import joblib
import pandas as pd
from datetime import datetime

model = joblib.load("anomaly_model.pkl")
FEATURES = ["failed_attempts", "new_device", "unusual_time"]

def analyze_anomaly(log: dict) -> dict:
    failed = int(log.get("failed_attempts", 0))
    new_device = 0 if log.get("device") == "known_device" else 1

    # Unusual time = login between 11 PM and 6 AM
    unusual_time = 0
    try:
        hour = datetime.fromisoformat(str(log.get("timestamp"))).hour
        if hour >= 23 or hour < 6:
            unusual_time = 1
    except Exception:
        pass

    # Isolation Forest score (lower raw value = more unusual)
    row = pd.DataFrame([[failed, new_device, unusual_time]], columns=FEATURES)
    raw = model.decision_function(row)[0]
    model_score = max(0, min(100, round((0.2 - raw) / 0.5 * 100)))

    # Rule-based score (so obvious attacks are always caught)
    rule_score = min(100, failed * 12 + new_device * 25 + unusual_time * 15)

    score = max(model_score, rule_score)

    # Human-readable reasons
    indicators = []
    if failed >= 3:
        indicators.append(f"{failed} failed login attempts")
    if new_device:
        indicators.append("new or unknown device")
    if unusual_time:
        indicators.append("login at unusual hour")
    if not indicators:
        score: int = min(score, 15)
    if score >= 70:
        verdict = "High-Risk"
    elif score >= 40:
        verdict = "Unusual"
    else:
        verdict = "Normal"

    return {"score": score, "verdict": verdict, "indicators": indicators}