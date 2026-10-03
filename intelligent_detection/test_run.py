from detector import analyze_malware_indicators
import shutil

# Test 1: a normal file
result1 = analyze_malware_indicators("detector.py")
print("Normal file test:", result1)

# Test 2: simulated double-extension trick
shutil.copy("detector.py", "invoice.pdf.exe")
result2 = analyze_malware_indicators("invoice.pdf.exe")
print("Double-extension test:", result2)