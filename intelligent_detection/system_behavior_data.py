# intelligent_detection/system_behavior_data.py

# Parent -> child process combos considered suspicious
SUSPICIOUS_PROCESS_CHAINS = {
    ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"), ("outlook.exe", "powershell.exe"),
    ("acrobat.exe", "cmd.exe"), ("chrome.exe", "powershell.exe"),
    ("powershell.exe", "mshta.exe"), ("cmd.exe", "certutil.exe"),
}

SENSITIVE_CONFIG_KEYS = [
    "firewall", "startup", "scheduled_task", "registry_run_key",
    "windows_defender", "antivirus_exclusion", "logging_policy",
]

MAINTENANCE_WINDOW_START = 2   # 2 AM
MAINTENANCE_WINDOW_END = 4     # 4 AM

CRASH_COUNT_ALERT_THRESHOLD = 5
CRASH_WINDOW_MINUTES = 30

UNUSUAL_EXECUTION_PATHS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "/tmp/"]