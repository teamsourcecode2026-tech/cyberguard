import os
import sys
import tempfile
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import bcrypt
import pandas as pd
from impersonation_detector import analyze_impersonation

from database import events, phishing_results, anomaly_results, deepfake_results, impersonation_results, alerts, users
from risk_scoring import score_and_explain
from phishing_model import analyze_phishing
from anomaly_model import analyze_anomaly
from deepfake_model import analyze_deepfake

# Import all orphaned detectors
from detectors import (
    # ml_phishing sub-detectors
    analyze_sms_phishing,
    analyze_url_phishing,
    analyze_qr_phishing,
    analyze_social_media_phishing,
    analyze_website_phishing,
    # malicious_url_website detectors
    analyze_domain_spoofing,
    analyze_lookalike_domain,
    analyze_ssl_domain,
    analyze_url_manipulation,
    analyze_malicious_redirect,
    analyze_fake_login,
    # theft_account_detection detectors
    detect_brute_force,
    detect_impossible_travel,
    detect_new_device_or_ip,
    detect_password_spraying,
    detect_unusual_login_time,
    detect_session_anomalies,
    detect_behaviour_change,
)
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

# ---- Helper to save result + create alert ----

def _save_and_alert(result: dict, category: str, raw_payload, recommended_action_high: str):
    """Shared logic: save event, save result, create alert, return response."""
    event = events.insert_one({"type": category, "raw_payload": raw_payload, "timestamp": str(datetime.now())})
    event_id = str(event.inserted_id)

    final = score_and_explain(result, category)

    action = recommended_action_high if final["risk_level"] in ["High", "Critical"] else "Monitor"
    alerts.insert_one({
        "event_id": event_id,
        "category": category,
        "score": result["score"],
        "verdict": result["verdict"],
        "indicators": result["indicators"],
        "overall_risk_level": final["risk_level"],
        "explanation": final["explanation"],
        "recommended_action": action,
        "status": "new",
        "created_at": str(datetime.now())
    })

    return {"event_id": event_id, **result, **final}

# ---- Phishing Sub-Detector Endpoints ----

class UrlInput(BaseModel):
    url: str

@app.post("/api/ingest/sms")
def ingest_sms(body: TextInput):
    result = analyze_sms_phishing(body.text)
    return _save_and_alert(result, "sms_phishing", body.text, "Block sender number")

@app.post("/api/ingest/url")
def ingest_url(body: UrlInput):
    result = analyze_url_phishing(body.url)
    return _save_and_alert(result, "url_phishing", body.url, "Block URL and warn user")

@app.post("/api/ingest/social")
def ingest_social(body: TextInput):
    result = analyze_social_media_phishing(body.text)
    return _save_and_alert(result, "social_phishing", body.text, "Report and block account")

@app.post("/api/ingest/qr")
def ingest_qr(file: UploadFile = File(...)):
    suffix = os.path.splitext(file.filename)[1] or ".png"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    try:
        result = analyze_qr_phishing(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    return _save_and_alert(result, "qr_phishing", file.filename, "Block decoded URL")

# ---- Malicious URL / Website Endpoints ----

@app.post("/api/ingest/website")
def ingest_website(body: UrlInput):
    result = analyze_website_phishing(body.url)
    return _save_and_alert(result, "website_phishing", body.url, "Block website and warn user")

@app.post("/api/ingest/domain-spoof")
def ingest_domain_spoof(body: UrlInput):
    result = analyze_domain_spoofing(body.url)
    return _save_and_alert(result, "domain_spoofing", body.url, "Block domain")

@app.post("/api/ingest/lookalike")
def ingest_lookalike(body: UrlInput):
    result = analyze_lookalike_domain(body.url)
    return _save_and_alert(result, "lookalike_domain", body.url, "Block domain")

@app.post("/api/ingest/ssl-check")
def ingest_ssl_check(body: UrlInput):
    result = analyze_ssl_domain(body.url)
    return _save_and_alert(result, "ssl_domain", body.url, "Warn user about untrusted certificate")

@app.post("/api/ingest/url-manipulation")
def ingest_url_manipulation(body: UrlInput):
    result = analyze_url_manipulation(body.url)
    return _save_and_alert(result, "url_manipulation", body.url, "Block URL")

@app.post("/api/ingest/redirect-check")
def ingest_redirect_check(body: UrlInput):
    result = analyze_malicious_redirect(body.url)
    return _save_and_alert(result, "malicious_redirect", body.url, "Block redirect chain")

@app.post("/api/ingest/fake-login")
def ingest_fake_login(body: UrlInput):
    result = analyze_fake_login(body.url)
    return _save_and_alert(result, "fake_login", body.url, "Block website and warn user")

# ---- Account Theft / Batch Log Analysis Endpoint ----

class LoginLogEntry(BaseModel):
    timestamp: str
    username: str
    ip: str
    success: bool
    device: str = "unknown"
    country: str = "unknown"
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    session_id: Optional[str] = None
    bytes_downloaded: Optional[float] = None
    password_changed: Optional[bool] = None
    recovery_email_changed: Optional[bool] = None

class BatchLoginLogs(BaseModel):
    logs: List[LoginLogEntry]

@app.post("/api/ingest/account-theft")
def ingest_account_theft(body: BatchLoginLogs):
    """Run all 7 theft/account-takeover detectors on a batch of login logs."""
    df = pd.DataFrame([log.model_dump() for log in body.logs])
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    all_alerts = []
    detectors = [
        ("brute_force", detect_brute_force),
        ("impossible_travel", detect_impossible_travel),
        ("new_device_ip", detect_new_device_or_ip),
        ("password_spraying", detect_password_spraying),
        ("unusual_login_time", detect_unusual_login_time),
        ("session_anomaly", detect_session_anomalies),
        ("behaviour_change", detect_behaviour_change),
    ]

    for name, detector_fn in detectors:
        try:
            results = detector_fn(df)
            for r in results:
                # Convert theft detector output → standard API contract
                normalized = {
                    "score": r.get("risk_score", 50),
                    "verdict": r.get("risk_level", "Medium"),
                    "indicators": [r.get("explanation", ""), r.get("mitre", "")],
                }
                saved = _save_and_alert(
                    normalized,
                    f"account_theft_{name}",
                    {"user": r.get("user", "unknown"), "threat_type": r.get("threat_type", name)},
                    r.get("response", "Investigate immediately")
                )
                all_alerts.append(saved)
        except Exception as e:
            all_alerts.append({"detector": name, "error": str(e)})

    return {"total_alerts": len(all_alerts), "alerts": all_alerts}

# ---- Query Endpoints ----

# ---- Query Endpoints ----

class StatusUpdate(BaseModel):
    status: str

VALID_STATUSES = ["new", "investigating", "resolved"]

@app.patch("/api/alerts/{event_id}/status")
def update_alert_status(event_id: str, update: StatusUpdate):
    if update.status not in VALID_STATUSES:
        return {"error": f"Invalid status. Must be one of {VALID_STATUSES}"}

    result = alerts.update_one(
        {"event_id": event_id},
        {"$set": {"status": update.status}}
    )

    if result.matched_count == 0:
        return {"error": "Alert not found"}

    return {"event_id": event_id, "status": update.status, "message": "Status updated"}

@app.get("/api/alerts")
def get_alerts(risk_level: Optional[str] = None, category: Optional[str] = None, status: Optional[str] = None):
    query = {}
    if risk_level:
        query["overall_risk_level"] = risk_level
    if category:
        query["category"] = category
    if status:
        query["status"] = status

    results = list(alerts.find(query, {"_id": 0}))
    return results

@app.get("/api/alerts/{event_id}")
def get_alert_detail(event_id: str):
    alert = alerts.find_one({"event_id": event_id}, {"_id": 0})
    if alert:
        return alert
    return {"error": "not found"}

@app.get("/api/stats")
def get_stats():
    all_categories = [
        "phishing", "deepfake", "anomaly", "impersonation",
        "sms_phishing", "url_phishing", "social_phishing", "qr_phishing",
        "website_phishing", "domain_spoofing", "lookalike_domain",
        "ssl_domain", "url_manipulation", "malicious_redirect", "fake_login",
        "account_theft_brute_force", "account_theft_impossible_travel",
        "account_theft_new_device_ip", "account_theft_password_spraying",
        "account_theft_unusual_login_time", "account_theft_session_anomaly",
        "account_theft_behaviour_change",
    ]
    levels = ["Safe", "Low", "Medium", "High", "Critical"]
    return {
        "total_events": events.count_documents({}),
        "threats_detected": alerts.count_documents({"overall_risk_level": {"$in": ["Medium", "High", "Critical"]}}),
        "by_category": {c: alerts.count_documents({"category": c}) for c in all_categories},
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

