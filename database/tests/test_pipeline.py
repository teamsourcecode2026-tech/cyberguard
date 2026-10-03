import json
import os
import sys
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()  # yeh aapki .env file padhta hai

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")
DATA_DIR = Path(__file__).parent / "data"

results = []


def check(name, is_correct, detail=""):
    results.append(is_correct)
    if is_correct:
        print(f"PASS: {name}")
    else:
        print(f"FAIL: {name} -- {detail}")


def test_server_is_up():
    print("\nChecking if server is running...")
    try:
        response = requests.get(BASE_URL + "/docs")
        check("Server responded", response.status_code == 200)
    except:
        print("Server is NOT running. Start it first, then try again.")
        sys.exit(1)


def test_phishing():
    print("\nTesting phishing endpoint...")

    with open(DATA_DIR / "phishing_samples.json") as f:
        samples = json.load(f)

    correct_count = 0

    for sample in samples:
        response = requests.post(
            BASE_URL + "/api/phishing/analyze",
            json={"text": sample["text"]}
        )

        if response.status_code != 200:
            check(f"{sample['id']} responded OK", False, f"status={response.status_code}")
            continue

        result = response.json()

        if "label" not in result:
            check(f"{sample['id']} has a label", False, f"got: {result}")
            continue

        got = result["label"]
        expected = sample["expected_label"]
        is_right = (got == expected)
        check(f"{sample['id']} correct label", is_right, f"expected {expected}, got {got}")

        if is_right:
            correct_count += 1

    accuracy = correct_count / len(samples)
    print(f"Phishing accuracy: {correct_count}/{len(samples)} = {accuracy:.0%}")


def test_deepfake():
    print("\nTesting deepfake endpoint...")

    deepfake_folder = DATA_DIR / "deepfake"
    correct_count = 0
    total = 0

    for image_path in deepfake_folder.iterdir():
        if image_path.name.startswith("real_"):
            expected = "real"
        elif image_path.name.startswith("fake_"):
            expected = "fake"
        else:
            continue

        total += 1

        with open(image_path, "rb") as f:
            response = requests.post(
                BASE_URL + "/api/deepfake/analyze",
                files={"file": f}
            )

        if response.status_code != 200:
            check(f"{image_path.name} responded OK", False, f"status={response.status_code}")
            continue

        result = response.json()
        got = result.get("label")
        is_right = (got == expected)
        check(f"{image_path.name} correct label", is_right, f"expected {expected}, got {got}")

        if is_right:
            correct_count += 1

    print(f"Deepfake accuracy: {correct_count}/{total}")


if __name__ == "__main__":
    test_server_is_up()
    test_phishing()
    test_deepfake()

    passed = sum(results)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")