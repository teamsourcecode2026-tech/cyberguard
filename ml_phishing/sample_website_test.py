from website_detector import analyze_website_phishing

test_sites = [
    "https://www.wikipedia.org",
    "https://www.python.org",
    "http://example.com"
]

for site in test_sites:
    print(f"\nChecking {site} ...")
    result = analyze_website_phishing(site)
    print(f"{site} -> {result}")