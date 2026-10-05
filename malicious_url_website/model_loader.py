import os
import joblib

_dir = os.path.dirname(__file__)
model = joblib.load(os.path.join(_dir, "phishing_model.pkl"))
vectorizer = joblib.load(os.path.join(_dir, "vectorizer.pkl"))


def score_text(text: str) -> float:
    vec = vectorizer.transform([text])
    return model.predict_proba(vec)[0][1]