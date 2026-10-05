from datetime import datetime, timedelta
from detector import analyze_network_traffic

# Test 1: normal browsing traffic
normal_traffic = [
    {"source_ip": "10.0.0.5", "dest_ip": "142.250.80.46", "dest_port": 443,
     "data_transferred_mb": 2.3, "timestamp": datetime(2026, 10, 3, 14, 30)},
    {"source_ip": "10.0.0.5", "dest_ip": "151.101.1.69", "dest_port": 443,
     "data_transferred_mb": 1.1, "timestamp": datetime(2026, 10, 3, 14, 32)},
]
print("Normal traffic test:", analyze_network_traffic(normal_traffic))

# Test 2: known-bad IP + suspicious port
malicious_single = [
    {"source_ip": "10.0.0.5", "dest_ip": "192.0.2.55", "dest_port": 4444,
     "data_transferred_mb": 650, "timestamp": datetime(2026, 10, 3, 3, 15)},
]
print("Malicious single connection test:", analyze_network_traffic(malicious_single))

# Test 3: beaconing pattern (regular intervals to same destination)
base_time = datetime(2026, 10, 3, 2, 0)
beaconing_traffic = [
    {"source_ip": "10.0.0.5", "dest_ip": "203.0.113.9", "dest_port": 8080,
     "data_transferred_mb": 0.1, "timestamp": base_time + timedelta(seconds=60 * i)}
    for i in range(8)
]
print("Beaconing test:", analyze_network_traffic(beaconing_traffic))