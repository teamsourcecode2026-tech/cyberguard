from datetime import datetime, timedelta
from detector import analyze_data_exfiltration

base_time = datetime(2026, 10, 4, 22, 0)  # 10 PM, off-hours

# Test 1: normal daytime work
normal = [
    {"user_id": "employee_1", "file_name": "report.docx", "action": "read",
     "timestamp": datetime(2026, 10, 4, 14, 0)},
    {"user_id": "employee_1", "file_name": "notes.txt", "action": "read",
     "timestamp": datetime(2026, 10, 4, 14, 5)},
]
print("Normal access test:", analyze_data_exfiltration(normal))

# Test 2: bulk access + off-hours + high-risk files
suspicious = [
    {"user_id": "insider_1", "file_name": f"customer_data_{i}.csv", "action": "download",
     "size_mb": 50, "timestamp": base_time + timedelta(seconds=i * 10)}
    for i in range(35)
]
suspicious.append({"user_id": "insider_1", "file_name": "backup.sql", "action": "download",
                    "size_mb": 200, "timestamp": base_time})
print("Suspicious bulk export test:", analyze_data_exfiltration(suspicious))