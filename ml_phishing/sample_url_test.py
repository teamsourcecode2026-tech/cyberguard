from url_detector import analyze_url_phishing

test_urls = [
    "https://www.google.com",
    "http://192.168.1.1/login",
    "http://paypa1-secure.xyz/verify-account",
    "https://www.amazon.com/orders",
    "http://login.secure.verify.account.bank-alert.top",
    "http://arnazon.com/deals",
    "http://realsite.com@fake-login.com/steal"
]

for url in test_urls:
    result = analyze_url_phishing(url)
    print(f"\n{url} -> {result}")