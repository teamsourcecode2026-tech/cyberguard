# intelligent_detection/detector.py
import os
import math
import hashlib
from collections import Counter

from known_bad_hashes import (
    KNOWN_BAD_HASHES,
    SUSPICIOUS_EXTENSIONS,
    DOCUMENT_LIKE_EXTENSIONS,
    SUSPICIOUS_STRINGS,
)

ENTROPY_THRESHOLD = 7.2
READ_LIMIT_BYTES = 5 * 1024 * 1024


def _sha256_of_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _file_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _check_double_extension(filename):
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        first_ext = f".{parts[-2]}"
        second_ext = f".{parts[-1]}"
        if first_ext in DOCUMENT_LIKE_EXTENSIONS and second_ext in SUSPICIOUS_EXTENSIONS:
            return True, first_ext, second_ext
    return False, None, None


def _scan_suspicious_strings(data):
    text = data.decode("latin-1", errors="ignore").lower()
    return [s for s in SUSPICIOUS_STRINGS if s in text]


def analyze_malware_indicators(file_path):
    """
    Static (non-executing) scan of a file for common malware indicators.
    Returns: {"score": 0-100 (higher = more suspicious),
              "verdict": "Clean" | "Suspicious" | "Likely Malicious",
              "indicators": list[str]}
    """
    if not os.path.isfile(file_path):
        return {"score": 0.0, "verdict": "Clean", "indicators": ["File not found"]}

    filename = os.path.basename(file_path)
    ext = os.path.splitext(filename)[1].lower()

    risk_points = 0.0
    indicators = []

    try:
        file_hash = _sha256_of_file(file_path)
        if file_hash in KNOWN_BAD_HASHES:
            risk_points += 100
            indicators.append(f"File hash matches known-malicious file: {KNOWN_BAD_HASHES[file_hash]}")

        is_double_ext, doc_ext, bad_ext = _check_double_extension(filename)
        if is_double_ext:
            risk_points += 40
            indicators.append(f"Suspicious double extension: looks like '{doc_ext}' but is actually '{bad_ext}'")
        elif ext in SUSPICIOUS_EXTENSIONS:
            risk_points += 15
            indicators.append(f"File type '{ext}' is commonly used to deliver malware")

        with open(file_path, "rb") as f:
            data = f.read(READ_LIMIT_BYTES)

        entropy = _file_entropy(data)
        if entropy >= ENTROPY_THRESHOLD:
            risk_points += 25
            indicators.append(f"High file entropy ({entropy:.2f}/8.0) - possible packed/encrypted payload")

        matched_strings = _scan_suspicious_strings(data)
        if matched_strings:
            risk_points += min(30, 10 * len(matched_strings))
            indicators.append(f"Contains suspicious code patterns: {', '.join(matched_strings)}")

    except Exception as e:
        return {"score": 50.0, "verdict": "Suspicious", "indicators": [f"Scan failed: {e}"]}

    if not indicators:
        indicators.append("No malware indicators found")

    score = min(100, round(risk_points, 1))
    verdict = "Likely Malicious" if score >= 60 else "Suspicious" if score >= 25 else "Clean"

    return {"score": score, "verdict": verdict, "indicators": indicators}