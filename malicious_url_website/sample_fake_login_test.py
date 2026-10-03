from fake_login_detector import analyze_fake_login

# NOTE: to test the local fake_login.html case, first run in a separate terminal:
#   python -m http.server 8000
# Then run this script from a second terminal with the venv active.

test_urls = [
    "https://github.com/login",
    "https://www.wikipedia.org",
    "http://localhost:8000/fake_login.html"
]

for url in test_urls:
    print(f"\nChecking {url} ...")
    result = analyze_fake_login(url)
    print(f"{url} -> {result}")