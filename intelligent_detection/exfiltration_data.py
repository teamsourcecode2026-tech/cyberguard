# intelligent_detection/exfiltration_data.py

BULK_ACCESS_FILE_COUNT_THRESHOLD = 30
BULK_ACCESS_WINDOW_MINUTES = 15

SENSITIVE_KEYWORDS = [
    "confidential", "financial", "customer_data", "salary", "payroll",
    "contract", "private", "secret", "classified", "ssn", "passport",
]
SENSITIVE_ACCESS_THRESHOLD = 10

LARGE_EXPORT_THRESHOLD_MB = 1000

OFF_HOURS_START = 20   # 8 PM
OFF_HOURS_END = 6      # 6 AM

HIGH_RISK_EXTENSIONS = {".sql", ".bak", ".pem", ".key", ".pfx", ".env", ".db"}