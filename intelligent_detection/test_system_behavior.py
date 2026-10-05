from datetime import datetime, timedelta
from detector import analyze_system_behavior

base_time = datetime(2026, 10, 4, 14, 0)

# Test 1: normal activity
normal = [
    {"event_type": "process_execution", "binary_path": "C:\\Program Files\\App\\app.exe",
     "is_signed": True, "timestamp": base_time},
]
print("Normal system activity test:", analyze_system_behavior(normal))

# Test 2: suspicious macro-spawned shell + unsigned temp exe + new startup entry
suspicious = [
    {"event_type": "process_spawn", "parent_process": "winword.exe", "child_process": "powershell.exe",
     "timestamp": base_time},
    {"event_type": "process_execution", "binary_path": "C:\\Users\\user\\AppData\\Local\\Temp\\update.exe",
     "is_signed": False, "timestamp": base_time + timedelta(minutes=1)},
    {"event_type": "new_startup_entry", "entry_name": "SystemUpdater", "timestamp": base_time + timedelta(minutes=2)},
    {"event_type": "config_change", "config_key": "windows_defender_exclusion", "timestamp": base_time + timedelta(minutes=3)},
]
print("Suspicious system behavior test:", analyze_system_behavior(suspicious))