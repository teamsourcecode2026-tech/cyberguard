import joblib

model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

URGENT_WORDS = ["urgent", "verify", "suspended", "click here", "immediately", "account will be"]
SUSPICIOUS_LINK_HINTS = ["bit.ly", "tinyurl", "http://", "-secure", "login"]

def analyze_phishing(text: str) -> dict:
    text_lower = text.lower()
    vec = vectorizer.transform([text])
    prob = model.predict_proba(vec)[0][1]
    score = round(prob * 100)

    indicators = []
    if any(word in text_lower for word in URGENT_WORDS):
        indicators.append("urgent language")
    if any(hint in text_lower for hint in SUSPICIOUS_LINK_HINTS):
        indicators.append("suspicious link")

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"score": score, "verdict": verdict, "indicators": indicators}