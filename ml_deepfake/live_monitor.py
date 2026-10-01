import time
import cv2
from PIL import Image
from models import get_image_pipeline
from detector import _fake_prob_from_result

CHECK_INTERVAL_SECONDS = 3
FAKE_THRESHOLD = 0.5
ALERT_AFTER_CONSECUTIVE = 3


def monitor_webcam():
    pipe = get_image_pipeline()
    cap = cv2.VideoCapture(0)  # 0 = default webcam

    if not cap.isOpened():
        print("Could not open webcam.")
        return

    consecutive_fake = 0
    print("Monitoring started. Press Ctrl+C to stop.")

    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                print("Could not read frame from webcam.")
                break

            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(rgb)
            result = pipe(image)
            fake_prob = _fake_prob_from_result(result)

            if fake_prob >= FAKE_THRESHOLD:
                consecutive_fake += 1
                print(f"[WARNING] Frame looks manipulated ({fake_prob*100:.1f}%) - {consecutive_fake} in a row")
            else:
                consecutive_fake = 0
                print(f"[OK] Frame looks authentic ({(1-fake_prob)*100:.1f}%)")

            if consecutive_fake >= ALERT_AFTER_CONSECUTIVE:
                print("ALERT: Possible deepfake detected on this call.")

            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("Monitoring stopped.")
    finally:
        cap.release()


if __name__ == "__main__":
    monitor_webcam()