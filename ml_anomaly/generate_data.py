import pandas as pd
import random

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

data = []

# Normal logins
for i in range(300):
    data.append({
        "user_id": f"user_{random.randint(1,50)}",
        "ip": random_ip(),
        "device": "known_device",
        "failed_attempts": random.randint(0, 1),
        "new_device": 0,
        "unusual_time": 0,
        "label": 0  # normal
    })

# Suspicious logins
for i in range(100):
    data.append({
        "user_id": f"user_{random.randint(1,50)}",
        "ip": random_ip(),
        "device": "unknown_device",
        "failed_attempts": random.randint(3, 8),
        "new_device": 1,
        "unusual_time": random.randint(0, 1),
        "label": 1  # suspicious
    })

df = pd.DataFrame(data)
df = df.sample(frac=1).reset_index(drop=True)  # shuffle
df.to_csv("login_logs.csv", index=False)
print("Generated", len(df), "login records.")