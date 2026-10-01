from url_manipulation_detector import analyze_url_manipulation

test_urls = [
    "https://www.google.com/search?q=test",
    "http://trusted-looking-site.com@malicious-actual-site.com/login",
    "http://safe-site.com/redirect?url=http://evil-phishing-site.com",
    "http://%70%61%79%70%61%6c%2d%73%65%63%75%72%65.com/%6c%6f%67%69%6e",
    "http://totally-fake-domain.com/paypal/account/login",
    "https://www.amazon.com/orders/12345"
]

for url in test_urls:
    result = analyze_url_manipulation(url)
    print(f"\n{url[:60]} -> {result}")