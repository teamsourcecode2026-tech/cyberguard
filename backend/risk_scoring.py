def score_and_explain(module_output: dict, category: str) -> dict:
    score = module_output["score"]
    indicators = module_output["indicators"]

    if score <= 20:
        risk_level = "Safe"
    elif score <= 40:
        risk_level = "Low"
    elif score <= 60:
        risk_level = "Medium"
    elif score <= 85:
        risk_level = "High"
    else:
        risk_level = "Critical"

    if indicators:
        explanation = f"{risk_level} Risk: This {category} message shows {', '.join(indicators)}."
    else:
        explanation = f"{risk_level} Risk: This {category} message shows no strong indicators, but the model still assigned this score."

    return {"risk_level": risk_level, "explanation": explanation}