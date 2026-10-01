import os
from detector import analyze_deepfake

folder = "samples"
skip = ["aston-martin", "audi-r26", "gargantua", "monkey-d-luffy", "oppenheimer"]

for name in sorted(os.listdir(folder)):
    if any(s in name for s in skip):
        continue
    if name.lower().endswith((".jpg", ".jpeg", ".png")):
        result = analyze_deepfake(os.path.join(folder, name))
        print(name, "->", result)