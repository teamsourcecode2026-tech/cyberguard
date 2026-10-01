from malicious_redirect_detector import analyze_malicious_redirect

test_urls = [
    "https://www.wikipedia.org",
    "https://httpbin.org/redirect-to?url=https://www.python.org",
    "https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to%3Furl%3Dhttps://example.com",
]

for url in test_urls:
    print(f"\nChecking {url} ...")
    result = analyze_malicious_redirect(url)
    print(f"{url} -> {result}")