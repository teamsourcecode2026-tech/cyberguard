import joblib

model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


def score_text(text: str) -> float:
    vec = vectorizer.transform([text])
    return model.predict_proba(vec)[0][1]