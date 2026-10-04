from datetime import datetime, timedelta
from detector import analyze_insider_threat

base_time = datetime(2026, 10, 4, 10, 0)

# Test 1: normal employee, within their role, no red flags
normal_profile = {"user_id": "emp_1", "department": "engineering", "today": base_time}
normal_events = [
    {"data_category": "source_code", "timestamp": base_time},
    {"data_category": "technical_docs", "timestamp": base_time + timedelta(hours=1)},
]
print("Normal employee test:", analyze_insider_threat(normal_profile, normal_events))

# Test 2: resigning employee, out-of-scope access, direct export
risky_profile = {
    "user_id": "emp_2", "department": "marketing",
    "is_resigning": True, "resignation_date": base_time + timedelta(days=10),
    "recent_hr_incident": True, "today": base_time,
}
risky_events = [
    {"data_category": "financial_records", "access_method": "usb_copy", "timestamp": base_time},
    {"data_category": "payroll", "access_method": "usb_copy", "timestamp": base_time + timedelta(minutes=5)},
]
print("Departing employee risk test:", analyze_insider_threat(risky_profile, risky_events))