from risk_scoring import score_and_explain

tests = [
    ({"score": 90, "verdict": "Phishing", "indicators": ["urgent language", "suspicious link"]}, "phishing"),
    ({"score": 15, "verdict": "Normal", "indicators": []}, "anomaly"),
    ({"score": 97, "verdict": "Likely Manipulated", "indicators": ["image model rates this 97% likely manipulated"]}, "deepfake"),
]

for result, category in tests:
    print(category, "->", score_and_explain(result, category))