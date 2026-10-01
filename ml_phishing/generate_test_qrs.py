import qrcode
import os

os.makedirs("qr_samples", exist_ok=True)

test_links = {
    "safe_qr.png": "https://www.wikipedia.org",
    "phishing_qr.png": "http://secure-bank-login-verify.com/account/suspended",
    "urgent_qr.png": "http://bit.ly/claim-your-prize-now"
}

for filename, link in test_links.items():
    img = qrcode.make(link)
    path = os.path.join("qr_samples", filename)
    img.save(path)
    print(f"Saved {path} -> {link}")