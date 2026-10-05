# intelligent_detection/network_threat_data.py
# Small demo reference data. In production this would come from a
# live threat-intel feed (e.g. AbuseIPDB, AlienVault OTX) rather
# than a hardcoded list.

KNOWN_BAD_IPS = {
    "192.0.2.55": "Known C2 server (demo entry)",
    "198.51.100.23": "Known botnet node (demo entry)",
}

SUSPICIOUS_PORTS = {
    23: "Telnet (unencrypted remote access)",
    4444: "Common Metasploit/reverse-shell default port",
    31337: "Classic backdoor port (Back Orifice)",
    6667: "IRC (common botnet C2 channel)",
    1337: "Common malware callback port",
}

LARGE_TRANSFER_THRESHOLD_MB = 500
BEACON_MIN_CONNECTIONS = 5
BEACON_MAX_INTERVAL_VARIANCE_SECONDS = 2
OFF_HOURS_START = 1   # 1 AM
OFF_HOURS_END = 5      # 5 AM