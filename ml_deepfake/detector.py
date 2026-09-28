import os
from PIL import Image
import cv2

try:
    from .models import get_image_pipeline, get_audio_pipeline  # when imported from repo root
except ImportError:
    from models import get_image_pipeline, get_audio_pipeline   # when run inside ml_deepfake/

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".webm"}
AUDIO_EXTS = {".wav", ".mp3", ".flac", ".m4a", ".ogg", ".opus"}


def extract_frames(video_path, num_frames=5):
    """Grab evenly spaced frames from a video as PIL images."""
    cap = cv2.VideoCapture(video_path)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    if total <= 0:
        cap.release()
        return []
    step = max(total // num_frames, 1)
    frames = []
    for i in range(0, total, step):
        cap.set(cv2.CAP_PROP_POS_FRAMES, i)
        ok, frame = cap.read()
        if ok:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frames.append(Image.fromarray(rgb))
        if len(frames) >= num_frames:
            break
    cap.release()
    return frames


def _fake_prob_from_result(result, fake_label_keywords=("fake", "deepfake")):
    for item in result:
        if any(kw in item["label"].lower() for kw in fake_label_keywords):
            return item["score"]
    return 0.0


def _verdict_from_score(score):
    if score >= 70:
        return "Authentic"
    elif score >= 40:
        return "Suspicious"
    else:
        return "Likely Manipulated"


def _analyze_image(path):
    pipe = get_image_pipeline()
    image = Image.open(path).convert("RGB")
    fake_prob = _fake_prob_from_result(pipe(image))
    score = round(100 * (1 - fake_prob), 1)
    return score, [f"Image classifier: {fake_prob*100:.1f}% likelihood of AI manipulation"]


def _analyze_video(path, num_frames=5):
    pipe = get_image_pipeline()
    frames = extract_frames(path, num_frames=num_frames)
    if not frames:
        return 50.0, ["Could not read frames from video file"]

    fake_probs = [_fake_prob_from_result(pipe(f)) for f in frames]
    avg_fake = sum(fake_probs) / len(fake_probs)
    max_fake = max(fake_probs)
    score = round(100 * (1 - avg_fake), 1)

    indicators = [f"Analyzed {len(frames)} sampled frames, avg manipulation likelihood {avg_fake*100:.1f}%"]
    if max_fake - avg_fake > 0.25:
        indicators.append(f"One frame scored much higher ({max_fake*100:.1f}%) than the average - possible localized manipulation")
    return score, indicators


def _analyze_audio(path):
    pipe = get_audio_pipeline()
    fake_prob = _fake_prob_from_result(pipe(path))
    score = round(100 * (1 - fake_prob), 1)
    return score, [f"Voice classifier: {fake_prob*100:.1f}% likelihood of synthetic/cloned speech"]


def analyze_deepfake(file_path):
    """
    Analyze an image, video, or audio file for deepfake manipulation.
    Returns: {"score": 0-100 (authenticity), "verdict": str, "indicators": [str]}
    """
    if not os.path.isfile(file_path):
        return {"score": 0.0, "verdict": "Likely Manipulated", "indicators": ["File not found"]}

    ext = os.path.splitext(file_path)[1].lower()

    try:
        if ext in IMAGE_EXTS:
            score, indicators = _analyze_image(file_path)
        elif ext in VIDEO_EXTS:
            score, indicators = _analyze_video(file_path)
        elif ext in AUDIO_EXTS:
            score, indicators = _analyze_audio(file_path)
        else:
            return {"score": 50.0, "verdict": "Suspicious",
                    "indicators": [f"Unsupported file type '{ext}'"]}
    except Exception as e:
        return {"score": 0.0, "verdict": "Likely Manipulated",
                "indicators": [f"Analysis failed: {e}"]}

    return {"score": score, "verdict": _verdict_from_score(score), "indicators": indicators}