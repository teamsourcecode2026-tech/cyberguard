from ssl_domain_detector import analyze_ssl_domain

test_domains = [
    "https://www.google.com",
    "https://expired.badssl.com",
    "https://self-signed.badssl.com",
    "https://www.wikipedia.org"
]

for domain in test_domains:
    print(f"\nChecking {domain} ...")
    result = analyze_ssl_domain(domain)
    print(f"{domain} -> {result}")