from datetime import datetime, timedelta
from detector import analyze_user_activity

base_time = datetime(2026, 10, 4, 10, 0)

# Test 1: normal login
normal_logins = [
    {"user_id": "user_1", "success": True, "location": "Delhi, IN", "timestamp": base_time},
]
print("Normal login test:", analyze_user_activity(normal_logins))

# Test 2: brute force then success + impossible travel
suspicious_logins = [
    {"user_id": "user_2", "success": False, "location": "Delhi, IN", "timestamp": base_time},
    {"user_id": "user_2", "success": False, "location": "Delhi, IN", "timestamp": base_time + timedelta(minutes=1)},
    {"user_id": "user_2", "success": False, "location": "Delhi, IN", "timestamp": base_time + timedelta(minutes=2)},
    {"user_id": "user_2", "success": False, "location": "Delhi, IN", "timestamp": base_time + timedelta(minutes=3)},
    {"user_id": "user_2", "success": True, "location": "Moscow, RU", "timestamp": base_time + timedelta(minutes=4)},
]
print("Brute force + impossible travel test:", analyze_user_activity(suspicious_logins))

# Test 3: privilege escalation attempt
actions = [
    {"user_id": "user_3", "action": "delete_user", "timestamp": base_time},
    {"user_id": "user_3", "action": "modify_permissions", "timestamp": base_time + timedelta(minutes=1)},
]
print("Privilege escalation test:", analyze_user_activity([], actions))