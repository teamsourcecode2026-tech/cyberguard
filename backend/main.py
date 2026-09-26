from database import events, phishing_results, alerts
from risk_scoring import score_and_explain
from datetime import datetime
from phishing_model import analyze_phishing
from fastapi import FastAPI
from datetime import datetime

app = FastAPI()

# ---- Mock data (fake, hardcoded for now) ----

fake_alerts = [
    {
        "event_id": "evt_001",
        "category": "phishing",
        "overall_risk_level": "High",
        "explanation": "High Risk: This phishing message shows urgent language, suspicious link.",
        "recommended_action": "Quarantine email",
        "status": "new",
        "created_at": str(datetime.now())
    }
]

# ---- Endpoints ----

@app.post("/api/ingest/phishing")
def ingest_phishing(text: str):
    result = analyze_phishing(text)

    event = events.insert_one({"type": "phishing", "raw_payload": text, "timestamp": str(datetime.now())})
    event_id = str(event.inserted_id)

    phishing_results.insert_one({"event_id": event_id, **result})

    final = score_and_explain(result, "phishing")

    alerts.insert_one({
        "event_id": event_id,
        "category": "phishing",
        "overall_risk_level": final["risk_level"],
        "explanation": final["explanation"],
        "recommended_action": "Quarantine email" if final["risk_level"] in ["High", "Critical"] else "Monitor",
        "status": "new",
        "created_at": str(datetime.now())
    })

    return {"event_id": event_id, **result, **final}

@app.post("/api/ingest/deepfake")
def ingest_deepfake():
    return {"event_id": "evt_002"}  # fake response for now

@app.post("/api/ingest/log")
def ingest_log():
    return {"event_id": "evt_003"}  # fake response for now

@app.get("/api/alerts")
def get_alerts():
    results = list(alerts.find({}, {"_id": 0}))
    return results

@app.get("/api/alerts/{event_id}")
def get_alert_detail(event_id: str):
    alert = alerts.find_one({"event_id": event_id}, {"_id": 0})
    if alert:
        return alert
    return {"error": "not found"}
@app.get("/api/stats")
def get_stats():
    return {
        "total_events": 3,
        "threats_detected": 1,
        "by_category": {"phishing": 1, "deepfake": 0, "anomaly": 0},
        "by_risk_level": {"Safe": 0, "Low": 0, "Medium": 0, "High": 1, "Critical": 0}
    }