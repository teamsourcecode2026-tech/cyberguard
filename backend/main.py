import os
import tempfile
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import bcrypt
from impersonation_detector import analyze_impersonation

from database import events, phishing_results, anomaly_results, deepfake_results, impersonation_results, alerts, users
from risk_scoring import score_and_explain
from phishing_model import analyze_phishing
from anomaly_model import analyze_anomaly
from deepfake_model import analyze_deepfake
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Endpoints ----

class TextInput(BaseModel):
    text: str

@app.post("/api/ingest/phishing")
def ingest_phishing(body: TextInput):
    text = body.text
    result = analyze_phishing(text)

    event = events.insert_one({"type": "phishing", "raw_payload": text, "timestamp": str(datetime.now())})
    event_id = str(event.inserted_id)

    phishing_results.insert_one({"event_id": event_id, **result})

    final = score_and_explain(result, "phishing")

    alerts.insert_one({
        "event_id": event_id,
        "category": "phishing",
         "score": result["score"],
        "verdict": result["verdict"],
        "indicators": result["indicators"],
        "overall_risk_level": final["risk_level"],
        "explanation": final["explanation"],
        "recommended_action": "Quarantine email" if final["risk_level"] in ["High", "Critical"] else "Monitor",
        "status": "new",
        "created_at": str(datetime.now())
    })

    return {"event_id": event_id, **result, **final}

@app.post("/api/ingest/impersonation")
def ingest_impersonation(body: TextInput):
    text = body.text
    result = analyze_impersonation(text)

    event = events.insert_one({"type": "impersonation", "raw_payload": text, "timestamp": str(datetime.now())})
    event_id = str(event.inserted_id)

    impersonation_results.insert_one({"event_id": event_id, **result})

    final = score_and_explain(result, "impersonation")

    alerts.insert_one({
        "event_id": event_id,
        "category": "impersonation",
        "score": result["score"],
        "verdict": result["verdict"],
        "indicators": result["indicators"],
        "overall_risk_level": final["risk_level"],
        "explanation": final["explanation"],
        "recommended_action": "Block sender and warn user" if final["risk_level"] in ["High", "Critical"] else "Monitor",
        "status": "new",
        "created_at": str(datetime.now())
    })

    return {"event_id": event_id, **result, **final}

@app.post("/api/ingest/deepfake")
def ingest_deepfake(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename)[1] or ".jpg"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    try:
        result = analyze_deepfake(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    event = events.insert_one({"type": "deepfake", "raw_payload": file.filename, "timestamp": str(datetime.now())})
    event_id = str(event.inserted_id)

    deepfake_results.insert_one({"event_id": event_id, **result})

    final = score_and_explain(result, "deepfake")

    alerts.insert_one({
        "event_id": event_id,
        "category": "deepfake",
        "score": result["score"],
        "verdict": result["verdict"],
        "indicators": result["indicators"],
        "overall_risk_level": final["risk_level"],
        "explanation": final["explanation"],
        "recommended_action": "Flag for manual verification" if final["risk_level"] in ["High", "Critical"] else "Monitor",
        "status": "new",
        "created_at": str(datetime.now())
    })

    return {"event_id": event_id, **result, **final}
class LogEntry(BaseModel):
    user_id: str
    ip: str
    device: str
    timestamp: str
    failed_attempts: int = 0
@app.post("/api/ingest/log")

def ingest_log(log: LogEntry):
    data = log.model_dump()
    result = analyze_anomaly(data)

    event = events.insert_one({"type": "anomaly", "raw_payload": data, "timestamp": str(datetime.now())})
    event_id = str(event.inserted_id)

    anomaly_results.insert_one({"event_id": event_id, **result})

    final = score_and_explain(result, "anomaly")

    alerts.insert_one({
        "event_id": event_id,
        "category": "anomaly",
         "score": result["score"],
        "verdict": result["verdict"],
        "indicators": result["indicators"],
        "overall_risk_level": final["risk_level"],
        "explanation": final["explanation"],
        "recommended_action": "Revoke session and require re-authentication" if final["risk_level"] in ["High", "Critical"] else "Monitor",
        "status": "new",
        "created_at": str(datetime.now())
    })

    return {"event_id": event_id, **result, **final}
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
    categories = ["phishing", "deepfake", "anomaly", "impersonation"]
    levels = ["Safe", "Low", "Medium", "High", "Critical"]
    return {
        "total_events": events.count_documents({}),
        "threats_detected": alerts.count_documents({"overall_risk_level": {"$in": ["Medium", "High", "Critical"]}}),
        "by_category": {c: alerts.count_documents({"category": c}) for c in categories},
        "by_risk_level": {l: alerts.count_documents({"overall_risk_level": l}) for l in levels}
}

# ---- Auth Endpoints (merged from auth_server.py) ----

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/register")
def register(data: RegisterRequest):
    existing = users.find_one({"username": data.username})
    if existing:
        return {"success": False, "message": "Username already exists"}

    hashed = bcrypt.hashpw(data.password.encode("utf-8"), bcrypt.gensalt())

    users.insert_one({
        "username": data.username,
        "password": hashed.decode("utf-8"),
        "created_at": str(datetime.now())
    })

    return {"success": True, "message": "Registered successfully"}

@app.post("/api/login")
def login(data: LoginRequest):
    user = users.find_one({"username": data.username})

    if not user:
        return {"success": False, "message": "User not found"}

    stored_hash = user["password"].encode("utf-8")
    entered_password = data.password.encode("utf-8")

    if not bcrypt.checkpw(entered_password, stored_hash):
        return {"success": False, "message": "Incorrect password"}

    return {"success": True, "message": "Login successful", "username": data.username}

