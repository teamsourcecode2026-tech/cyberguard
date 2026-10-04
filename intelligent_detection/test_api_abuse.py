from datetime import datetime, timedelta
from detector import analyze_api_abuse

# Test 1: normal usage
normal = [
    {"client_id": "user123", "endpoint": "/api/profile", "status_code": 200,
     "timestamp": datetime(2026, 10, 4, 10, 0)},
    {"client_id": "user123", "endpoint": "/api/orders", "status_code": 200,
     "timestamp": datetime(2026, 10, 4, 10, 1)},
]
print("Normal API usage test:", analyze_api_abuse(normal))

# Test 2: rate limit violation (60 requests in under a minute)
base_time = datetime(2026, 10, 4, 10, 0)
rate_abuse = [
    {"client_id": "bot_client", "endpoint": "/api/search", "status_code": 200,
     "timestamp": base_time + timedelta(seconds=i)}
    for i in range(60)
]
print("Rate limit test:", analyze_api_abuse(rate_abuse))

# Test 3: credential stuffing (many failed logins)
cred_stuffing = [
    {"client_id": "attacker_1", "endpoint": "/api/login", "status_code": 401,
     "timestamp": base_time + timedelta(seconds=i * 2)}
    for i in range(10)
]
print("Credential stuffing test:", analyze_api_abuse(cred_stuffing))

# Test 4: injection attempt
injection = [
    {"client_id": "scanner_1", "endpoint": "/api/users", "status_code": 200,
     "query_params": "id=1' OR '1'='1", "timestamp": base_time},
]
print("Injection attempt test:", analyze_api_abuse(injection))