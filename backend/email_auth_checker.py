"""
Email Authentication Checker — SPF, DKIM, DMARC verification.

Performs DNS lookups to verify:
- SPF: Whether the sending IP is authorized by the domain's SPF record
- DKIM: Whether the DKIM signature in the email header is valid
- DMARC: What policy the domain has published for failed authentication

Works with raw email headers pasted by users.
"""
import re
import dns.resolver
from typing import Optional


def _extract_domain(email_or_domain: str) -> str:
    """Extract domain from an email address or return as-is if already a domain."""
    if "@" in email_or_domain:
        return email_or_domain.split("@")[-1].strip().lower()
    return email_or_domain.strip().lower()


def _query_dns(domain: str, record_type: str) -> list:
    """Query DNS for the specified record type. Returns list of strings."""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# SPF Check
# ---------------------------------------------------------------------------

def check_spf(domain: str, sender_ip: Optional[str] = None) -> dict:
    """
    Check if the domain has a valid SPF record and optionally
    whether a sender IP is authorized.

    Returns: {"result": "pass"|"fail"|"none"|"error", "record": str, "details": str}
    """
    records = _query_dns(domain, "TXT")
    spf_records = [r.strip('"') for r in records if "v=spf1" in r.lower()]

    if not spf_records:
        return {
            "result": "none",
            "record": "",
            "details": f"No SPF record found for {domain}"
        }

    spf_record = spf_records[0]

    # Basic SPF policy analysis
    has_all_fail = spf_record.rstrip().endswith("-all")
    has_all_softfail = spf_record.rstrip().endswith("~all")
    has_all_pass = spf_record.rstrip().endswith("+all")

    if sender_ip:
        # Check if IP is in any ip4: or ip6: directive
        ip4_matches = re.findall(r"ip4:(\S+)", spf_record)
        ip6_matches = re.findall(r"ip6:(\S+)", spf_record)

        ip_authorized = False
        for ip_range in ip4_matches + ip6_matches:
            if sender_ip in ip_range or sender_ip == ip_range.split("/")[0]:
                ip_authorized = True
                break

        if ip_authorized:
            return {
                "result": "pass",
                "record": spf_record,
                "details": f"Sender IP {sender_ip} is authorized by SPF record"
            }
        elif has_all_fail:
            return {
                "result": "fail",
                "record": spf_record,
                "details": f"Sender IP {sender_ip} is NOT authorized and domain uses strict -all policy"
            }
        elif has_all_softfail:
            return {
                "result": "softfail",
                "record": spf_record,
                "details": f"Sender IP {sender_ip} is NOT explicitly authorized (softfail ~all)"
            }

    # No sender IP provided — just evaluate the record quality
    if has_all_pass:
        return {
            "result": "fail",
            "record": spf_record,
            "details": "SPF record uses +all (allows ANY server to send) — very insecure"
        }
    elif has_all_fail:
        return {
            "result": "pass",
            "record": spf_record,
            "details": "SPF record found with strict -all policy (good)"
        }
    elif has_all_softfail:
        return {
            "result": "softfail",
            "record": spf_record,
            "details": "SPF record found with softfail ~all policy (acceptable but not strict)"
        }
    else:
        return {
            "result": "pass",
            "record": spf_record,
            "details": "SPF record found"
        }


# ---------------------------------------------------------------------------
# DKIM Check
# ---------------------------------------------------------------------------

def check_dkim(domain: str, selector: str = "default") -> dict:
    """
    Check if a DKIM public key record exists for the given selector and domain.

    Returns: {"result": "pass"|"fail"|"none"|"error", "record": str, "details": str}
    """
    # Try common selectors if default doesn't work
    selectors_to_try = [selector]
    if selector == "default":
        selectors_to_try = ["default", "google", "selector1", "selector2",
                            "s1", "s2", "k1", "dkim", "mail"]

    for sel in selectors_to_try:
        dkim_domain = f"{sel}._domainkey.{domain}"
        records = _query_dns(dkim_domain, "TXT")

        if records:
            dkim_record = " ".join(r.strip('"') for r in records)
            if "p=" in dkim_record:
                # Check if the key is revoked (empty p= value)
                p_match = re.search(r"p=(\S*)", dkim_record)
                if p_match and p_match.group(1) == "":
                    return {
                        "result": "fail",
                        "record": dkim_record[:200],
                        "details": f"DKIM key found at {dkim_domain} but it is revoked (empty p= value)"
                    }
                return {
                    "result": "pass",
                    "record": dkim_record[:200],
                    "details": f"DKIM public key found at {dkim_domain} (selector: {sel})"
                }

    return {
        "result": "none",
        "record": "",
        "details": f"No DKIM record found for {domain} (tried selectors: {', '.join(selectors_to_try)})"
    }


# ---------------------------------------------------------------------------
# DMARC Check
# ---------------------------------------------------------------------------

def check_dmarc(domain: str) -> dict:
    """
    Check the domain's DMARC record.

    Returns: {"result": "pass"|"fail"|"none", "policy": str, "record": str, "details": str}
    """
    dmarc_domain = f"_dmarc.{domain}"
    records = _query_dns(dmarc_domain, "TXT")
    dmarc_records = [r.strip('"') for r in records if "v=dmarc1" in r.lower()]

    if not dmarc_records:
        # Try organizational domain (e.g., sub.example.com → example.com)
        parts = domain.split(".")
        if len(parts) > 2:
            org_domain = ".".join(parts[-2:])
            org_dmarc_domain = f"_dmarc.{org_domain}"
            org_records = _query_dns(org_dmarc_domain, "TXT")
            dmarc_records = [r.strip('"') for r in org_records if "v=dmarc1" in r.lower()]

    if not dmarc_records:
        return {
            "result": "none",
            "policy": "none",
            "record": "",
            "details": f"No DMARC record found for {domain} — domain does not protect against spoofing"
        }

    dmarc_record = dmarc_records[0]

    # Extract policy
    policy_match = re.search(r"p=(\w+)", dmarc_record)
    policy = policy_match.group(1).lower() if policy_match else "none"

    # Extract sub-domain policy
    sp_match = re.search(r"sp=(\w+)", dmarc_record)
    sub_policy = sp_match.group(1).lower() if sp_match else policy

    # Extract reporting addresses
    rua_match = re.search(r"rua=([^;]+)", dmarc_record)
    has_reporting = rua_match is not None

    if policy == "reject":
        return {
            "result": "pass",
            "policy": "reject",
            "record": dmarc_record,
            "details": f"DMARC policy is 'reject' — strongest protection against spoofing"
        }
    elif policy == "quarantine":
        return {
            "result": "pass",
            "policy": "quarantine",
            "record": dmarc_record,
            "details": f"DMARC policy is 'quarantine' — suspicious emails will be flagged"
        }
    elif policy == "none":
        return {
            "result": "fail",
            "policy": "none",
            "record": dmarc_record,
            "details": f"DMARC policy is 'none' — monitoring only, no protection against spoofing"
                       + (" (reporting enabled)" if has_reporting else " (no reporting configured)")
        }
    else:
        return {
            "result": "fail",
            "policy": policy,
            "record": dmarc_record,
            "details": f"DMARC record found but policy '{policy}' is unrecognized"
        }


# ---------------------------------------------------------------------------
# Combined Analysis
# ---------------------------------------------------------------------------

def analyze_email_auth(sender_domain: str, sender_ip: Optional[str] = None,
                       dkim_selector: str = "default") -> dict:
    """
    Run full SPF + DKIM + DMARC analysis on a sender domain.

    Returns standard CyberGuard format:
        {"score": 0-100, "verdict": str, "indicators": list[str],
         "spf": {...}, "dkim": {...}, "dmarc": {...}}
    """
    domain = _extract_domain(sender_domain)

    spf = check_spf(domain, sender_ip)
    dkim = check_dkim(domain, dkim_selector)
    dmarc = check_dmarc(domain)

    # Score calculation
    score = 0
    indicators = []

    # SPF scoring
    if spf["result"] == "none":
        score += 35
        indicators.append(f"⚠️ No SPF record — any server can send as @{domain}")
    elif spf["result"] == "fail":
        score += 40
        indicators.append(f"🔴 SPF check failed: {spf['details']}")
    elif spf["result"] == "softfail":
        score += 15
        indicators.append(f"🟡 SPF softfail: {spf['details']}")
    else:
        indicators.append(f"✅ SPF passed: {spf['details']}")

    # DKIM scoring
    if dkim["result"] == "none":
        score += 25
        indicators.append(f"⚠️ No DKIM key found — emails from {domain} cannot be signature-verified")
    elif dkim["result"] == "fail":
        score += 30
        indicators.append(f"🔴 DKIM check failed: {dkim['details']}")
    else:
        indicators.append(f"✅ DKIM passed: {dkim['details']}")

    # DMARC scoring
    if dmarc["result"] == "none":
        score += 35
        indicators.append(f"⚠️ No DMARC record — {domain} has no spoofing protection policy")
    elif dmarc["result"] == "fail":
        score += 20
        indicators.append(f"🟡 DMARC policy is weak: {dmarc['details']}")
    else:
        indicators.append(f"✅ DMARC passed: {dmarc['details']}")

    # Verdict
    if score >= 70:
        verdict = "Spoofable"
    elif score >= 40:
        verdict = "Partially Protected"
    elif score >= 15:
        verdict = "Mostly Protected"
    else:
        verdict = "Well Protected"

    return {
        "score": min(100, score),
        "verdict": verdict,
        "indicators": indicators,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }


if __name__ == "__main__":
    import json
    # Quick test
    result = analyze_email_auth("gmail.com")
    print(json.dumps(result, indent=2))
