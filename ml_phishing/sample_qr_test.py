from qr_detector import analyze_qr_phishing

test_images = [
    "qr_samples/safe_qr.png",
    "qr_samples/phishing_qr.png",
    "qr_samples/urgent_qr.png"
]

for img_path in test_images:
    result = analyze_qr_phishing(img_path)
    print(f"\n{img_path} -> {result}")