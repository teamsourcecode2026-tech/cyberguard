from domain_spoofing_detector import analyze_domain_spoofing

test_domains = [
    "https://www.google.com",
    "https://www.gooogle.com",
    "http://paypal-secure-login-verify.com",
    "http://paypal.account-verify-secure.com",
    "http://xn--ggle-0nda.com",
    "https://www.microsoft.com"
]

for domain in test_domains:
    result = analyze_domain_spoofing(domain)
    print(f"\n{domain} -> {result}")