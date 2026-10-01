import cv2
from model import analyze_phishing

def decode_qr(image_path: str) -> str | None:
    img = cv2.imread(image_path)
    if img is None:
        return None

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)

    return data if data else None


def analyze_qr_phishing(image_path: str) -> dict:
    decoded_text = decode_qr(image_path)

    if decoded_text is None:
        return {
            "score": 0,
            "verdict": "Safe",
            "indicators": ["No QR code detected in image"]
        }

    result = analyze_phishing(decoded_text)
    result["indicators"].append(f"Decoded from QR code: {decoded_text[:60]}")

    return result