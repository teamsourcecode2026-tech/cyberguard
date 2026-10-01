from model import analyze_phishing

OTP_WORDS = ["otp", "verification code", "one time password", "do not share this code"]
DELIVERY_SCAM_WORDS = ["package", "delivery failed", "redeliver", "customs fee", "shipment on hold"]
SHORTENER_DOMAINS = ["bit.ly", "tinyurl", "t.co", "is.gd", "cutt.ly", "shorturl"]


def analyze_sms_phishing(text: str) -> dict:
    result = analyze_phishing(text)
    lowered = text.lower()

    has_link = "http" in lowered or any(domain in lowered for domain in SHORTENER_DOMAINS)

    if any(word in lowered for word in OTP_WORDS) and has_link:
        result["indicators"].append("Impersonates OTP/verification code message")

    if any(word in lowered for word in DELIVERY_SCAM_WORDS):
        result["indicators"].append("Impersonates delivery/shipping notification")

    if any(domain in lowered for domain in SHORTENER_DOMAINS):
        result["indicators"].append("Uses a link-shortening service (common in smishing)")

    return result