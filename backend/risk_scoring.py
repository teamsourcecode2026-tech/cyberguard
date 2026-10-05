RISK_THRESHOLDS = [
    (20, "Safe"),
    (40, "Low"),
    (60, "Medium"),
    (85, "High"),
]  # anything above 85 is "Critical"


def get_risk_level(score: float) -> str:
    score = max(0, min(100, score))
    for limit, label in RISK_THRESHOLDS:
        if score <= limit:
            return label
    return "Critical"


def score_and_explain(module_output: dict, category: str) -> dict:
    score = max(0, min(100, module_output["score"]))
    indicators = module_output["indicators"]
    risk_level = get_risk_level(score)

    if indicators:
        explanation = f"{risk_level} Risk ({category}): {', '.join(indicators)}."
    else:
        explanation = f"{risk_level} Risk ({category}): no warning signs detected."

    return {"score": score, "indicators": indicators,
            "risk_level": risk_level, "explanation": explanation}