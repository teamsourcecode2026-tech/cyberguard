from lookalike_domain_detector import analyze_lookalike_domain

test_domains = [
    "https://www.google.com",
    "http://g00gle.com",
    "http://paypa1.com",
    "http://arnazon.com",
    "http://micr0s0ft.com",
    "https://www.apple.com"
]

for domain in test_domains:
    result = analyze_lookalike_domain(domain)
    print(f"\n{domain} -> {result}")