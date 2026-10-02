import ssl
import socket
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
from model_loader import score_text


def get_registrable_domain(domain: str) -> str:
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def check_ssl_certificate(domain: str, timeout: int = 5) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        return {"valid": True, "expired": days_remaining < 0, "days_remaining": days_remaining}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "reason": "certificate verification failed (self-signed or untrusted)"}
    except Exception:
        return {"valid": None, "reason": "could not connect or retrieve certificate"}


def check_domain_age(domain: str):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        return age_days
    except Exception:
        return None


def analyze_ssl_domain(url: str) -> dict:
    full_url = url if "://" in url else f"https://{url}"
    domain = urlparse(full_url).netloc.split(":")[0]
    whois_domain = get_registrable_domain(domain)

    indicators = []

    ssl_result = check_ssl_certificate(domain)
    if ssl_result["valid"] is False:
        indicators.append(f"SSL certificate is invalid: {ssl_result['reason']}")
    elif ssl_result["valid"] is None:
        indicators.append("Could not verify SSL certificate (site may not support HTTPS)")
    elif ssl_result.get("expired"):
        indicators.append("SSL certificate has expired")
    elif ssl_result.get("days_remaining", 999) < 7:
        indicators.append("SSL certificate is expiring very soon")

    domain_age_days = check_domain_age(whois_domain)
    if domain_age_days is not None:
        if domain_age_days < 30:
            indicators.append(f"Domain was registered very recently ({domain_age_days} days ago) \u2014 common with phishing sites")
        elif domain_age_days < 180:
            indicators.append(f"Domain is relatively new ({domain_age_days} days old)")

    base_score = round(score_text(full_url) * 100)
    score = min(100, base_score + 25 * len(indicators))

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    if not indicators:
        indicators.append("No SSL or domain age concerns detected")

    return {"score": score, "verdict": verdict, "indicators": indicators}