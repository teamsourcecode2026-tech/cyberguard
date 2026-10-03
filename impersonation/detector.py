# impersonation/detector.py
import re
import difflib

from known_officials import (
    KNOWN_OFFICIALS,
    OFFICIAL_TITLE_KEYWORDS,
    SCAM_PHRASES,
    OFFICIAL_EMAIL_DOMAINS,
    SENIOR_MANAGEMENT,
    MANAGEMENT_TITLE_KEYWORDS,
    CEO_FRAUD_PHRASES,
)


def _name_similarity(name_a, name_b):
    """0.0-1.0 similarity score between two names."""
    return difflib.SequenceMatcher(None, name_a.lower(), name_b.lower()).ratio()


def _closest_known_identity(name):
    """Find the closest matching known government official or senior
    manager, whichever is closer, and which category it belongs to."""
    best_match, best_score, best_category = None, 0.0, None
    for official in KNOWN_OFFICIALS:
        score = _name_similarity(name, official["name"])
        if score > best_score:
            best_match, best_score, best_category = official, score, "government official"
    for manager in SENIOR_MANAGEMENT:
        score = _name_similarity(name, manager["name"])
        if score > best_score:
            best_match, best_score, best_category = manager, score, "senior manager"
    return best_match, best_score, best_category


def _claims_authority_title(text):
    text_lower = text.lower()
    claims_govt = any(keyword in text_lower for keyword in OFFICIAL_TITLE_KEYWORDS)
    claims_mgmt = any(keyword in text_lower for keyword in MANAGEMENT_TITLE_KEYWORDS)
    return claims_govt or claims_mgmt


def _analyze_profile(profile):
    """
    profile: {
        "name": str,
        "bio": str (optional),
        "claimed_title": str (optional),
        "verified": bool (optional, default False),
        "account_age_days": int (optional),
        "follower_count": int (optional),
    }
    """
    name = profile.get("name", "")
    bio = profile.get("bio", "")
    claimed_title = profile.get("claimed_title", "")
    verified = profile.get("verified", False)
    account_age_days = profile.get("account_age_days")
    follower_count = profile.get("follower_count")

    fake_points = 0.0
    indicators = []

    combined_text = f"{claimed_title} {bio}"
    claims_official = _claims_authority_title(combined_text)
    if claims_official and not verified:
        fake_points += 40
        indicators.append("Claims an official government title but account is not verified")

    match, similarity, category = _closest_known_identity(name)
    if match and 0.75 <= similarity < 1.0:
        fake_points += 35
        indicators.append(
            f"Name '{name}' is suspiciously similar to known {category} '{match['name']}' "
            f"({similarity*100:.0f}% match) - possible name-spoofing"
        )

    if account_age_days is not None and account_age_days < 30 and claims_official:
        fake_points += 15
        indicators.append(f"Account is only {account_age_days} days old but claims an official role")

    if follower_count is not None and follower_count < 100 and claims_official:
        fake_points += 10
        indicators.append(f"Very low follower count ({follower_count}) for a claimed official role")

    if not indicators:
        indicators.append("No impersonation red flags found in profile")

    score = min(100, round(fake_points, 1))
    return score, indicators


def _analyze_message(message):
    """
    message: {
        "text": str,
        "sender_name": str (optional),
        "sender_email": str (optional),
    }
    """
    text = message.get("text", "")
    sender_name = message.get("sender_name", "")
    sender_email = message.get("sender_email", "")

    fake_points = 0.0
    indicators = []

    text_lower = text.lower()

    matched_phrases = [p for p in SCAM_PHRASES if p in text_lower]
    if matched_phrases:
        fake_points += min(50, 15 * len(matched_phrases))
        indicators.append(f"Message contains scam-style phrases: {', '.join(matched_phrases)}")

    matched_fraud_phrases = [p for p in CEO_FRAUD_PHRASES if p in text_lower]
    if matched_fraud_phrases:
        fake_points += min(40, 15 * len(matched_fraud_phrases))
        indicators.append(f"Message contains CEO-fraud style language: {', '.join(matched_fraud_phrases)}")

    claims_official = _claims_authority_title(text)
    if claims_official:
        if sender_email:
            domain = sender_email.split("@")[-1].lower()
            if not any(domain.endswith(d) for d in OFFICIAL_EMAIL_DOMAINS):
                fake_points += 35
                indicators.append(
                    f"Claims to be from a government office but sender domain '{domain}' "
                    f"doesn't match known official domains ({', '.join(OFFICIAL_EMAIL_DOMAINS)})"
                )
        else:
            fake_points += 20
            indicators.append("Claims an official role but no sender email was provided to verify")

    if sender_name:
        match, similarity, category = _closest_known_identity(sender_name)
        if match and 0.75 <= similarity < 1.0:
            fake_points += 25
            indicators.append(
                f"Sender name '{sender_name}' closely resembles known {category} "
                f"'{match['name']}' ({similarity*100:.0f}% match)"
            )

    if not indicators:
        indicators.append("No impersonation red flags found in message")

    score = min(100, round(fake_points, 1))
    return score, indicators


def _verdict_from_score(score):
    if score >= 60:
        return "Likely Impersonation"
    elif score >= 30:
        return "Suspicious"
    else:
        return "Authentic"


def analyze_impersonation(profile=None, message=None):
    """
    Check a profile and/or message for signs of government-official
    or senior-management impersonation.

    Args:
        profile: dict (see _analyze_profile docstring) or None
        message: dict (see _analyze_message docstring) or None

    Returns:
        dict: {"score": 0-100 (higher = more likely impersonation),
               "verdict": str, "indicators": list[str]}
    """
    if profile is None and message is None:
        return {"score": 0.0, "verdict": "Authentic", "indicators": ["No data provided"]}

    all_indicators = []
    scores = []

    if profile is not None:
        profile_score, profile_indicators = _analyze_profile(profile)
        scores.append(profile_score)
        all_indicators.extend([f"[Profile] {i}" for i in profile_indicators])

    if message is not None:
        message_score, message_indicators = _analyze_message(message)
        scores.append(message_score)
        all_indicators.extend([f"[Message] {i}" for i in message_indicators])

    final_score = max(scores)
    return {
        "score": final_score,
        "verdict": _verdict_from_score(final_score),
        "indicators": all_indicators,
    }