# intelligent_detection/detector.py
import os
import math
import hashlib
from collections import Counter, defaultdict
from datetime import datetime,timedelta
from collections import Counter

from api_abuse_data import (
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    AUTH_FAILURE_CODES,
    AUTH_FAILURE_RATE_THRESHOLD,
    ERROR_CODES,
    ERROR_RATE_THRESHOLD,
    ENDPOINT_ENUMERATION_THRESHOLD,
    INJECTION_PATTERNS,
)

from known_bad_hashes import (
    KNOWN_BAD_HASHES,
    SUSPICIOUS_EXTENSIONS,
    DOCUMENT_LIKE_EXTENSIONS,
    SUSPICIOUS_STRINGS,
)
from network_threat_data import (
    KNOWN_BAD_IPS,
    SUSPICIOUS_PORTS,
    LARGE_TRANSFER_THRESHOLD_MB,
    BEACON_MIN_CONNECTIONS,
    BEACON_MAX_INTERVAL_VARIANCE_SECONDS,
    OFF_HOURS_START,
    OFF_HOURS_END,
)
from exfiltration_data import (
    BULK_ACCESS_FILE_COUNT_THRESHOLD,
    BULK_ACCESS_WINDOW_MINUTES,
    SENSITIVE_KEYWORDS,
    SENSITIVE_ACCESS_THRESHOLD,
    LARGE_EXPORT_THRESHOLD_MB,
    OFF_HOURS_START as EXFIL_OFF_HOURS_START,
    OFF_HOURS_END as EXFIL_OFF_HOURS_END,
    HIGH_RISK_EXTENSIONS,
)
from user_activity_data import (
    TYPICAL_LOGIN_HOUR_START,
    TYPICAL_LOGIN_HOUR_END,
    FAILED_LOGIN_THRESHOLD,
    IMPOSSIBLE_TRAVEL_MAX_MINUTES,
    ADMIN_ACTIONS,
    SESSION_DURATION_ALERT_HOURS,
    ACTION_COUNT_ALERT_THRESHOLD,
)
from insider_threat_data import (
    DEPARTMENT_DATA_SCOPE,
    RESIGNATION_RISK_WINDOW_DAYS,
    BASELINE_MULTIPLIER_ALERT,
    RECENT_HR_INCIDENT_WEIGHT,
    DIRECT_ACCESS_METHODS,
)
ENTROPY_THRESHOLD = 7.2
READ_LIMIT_BYTES = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# Feature 1: Malware indicators
# ---------------------------------------------------------------------------

def _sha256_of_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _file_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _check_double_extension(filename):
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        first_ext = f".{parts[-2]}"
        second_ext = f".{parts[-1]}"
        if first_ext in DOCUMENT_LIKE_EXTENSIONS and second_ext in SUSPICIOUS_EXTENSIONS:
            return True, first_ext, second_ext
    return False, None, None


def _scan_suspicious_strings(data):
    text = data.decode("latin-1", errors="ignore").lower()
    return [s for s in SUSPICIOUS_STRINGS if s in text]


def analyze_malware_indicators(file_path):
    """
    Static (non-executing) scan of a file for common malware indicators.
    Returns: {"score": 0-100 (higher = more suspicious),
              "verdict": "Clean" | "Suspicious" | "Likely Malicious",
              "indicators": list[str]}
    """
    if not os.path.isfile(file_path):
        return {"score": 0.0, "verdict": "Clean", "indicators": ["File not found"]}

    filename = os.path.basename(file_path)
    ext = os.path.splitext(filename)[1].lower()

    risk_points = 0.0
    indicators = []

    try:
        file_hash = _sha256_of_file(file_path)
        if file_hash in KNOWN_BAD_HASHES:
            risk_points += 100
            indicators.append(f"File hash matches known-malicious file: {KNOWN_BAD_HASHES[file_hash]}")

        is_double_ext, doc_ext, bad_ext = _check_double_extension(filename)
        if is_double_ext:
            risk_points += 40
            indicators.append(f"Suspicious double extension: looks like '{doc_ext}' but is actually '{bad_ext}'")
        elif ext in SUSPICIOUS_EXTENSIONS:
            risk_points += 15
            indicators.append(f"File type '{ext}' is commonly used to deliver malware")

        with open(file_path, "rb") as f:
            data = f.read(READ_LIMIT_BYTES)

        entropy = _file_entropy(data)
        if entropy >= ENTROPY_THRESHOLD:
            risk_points += 25
            indicators.append(f"High file entropy ({entropy:.2f}/8.0) - possible packed/encrypted payload")

        matched_strings = _scan_suspicious_strings(data)
        if matched_strings:
            risk_points += min(30, 10 * len(matched_strings))
            indicators.append(f"Contains suspicious code patterns: {', '.join(matched_strings)}")

    except Exception as e:
        return {"score": 50.0, "verdict": "Suspicious", "indicators": [f"Scan failed: {e}"]}

    if not indicators:
        indicators.append("No malware indicators found")

    score = min(100, round(risk_points, 1))
    verdict = "Likely Malicious" if score >= 60 else "Suspicious" if score >= 25 else "Clean"

    return {"score": score, "verdict": verdict, "indicators": indicators}


# ---------------------------------------------------------------------------
# Feature 2: Suspicious network traffic
# ---------------------------------------------------------------------------

def _check_beaconing(connections):
    """Group connections by destination IP and flag regular, repeated
    intervals between them - a classic sign of malware 'calling home'."""
    by_destination = defaultdict(list)
    for conn in connections:
        by_destination[conn["dest_ip"]].append(conn["timestamp"])

    beaconing_destinations = []
    for dest_ip, timestamps in by_destination.items():
        if len(timestamps) < BEACON_MIN_CONNECTIONS:
            continue
        sorted_times = sorted(timestamps)
        intervals = [
            (sorted_times[i + 1] - sorted_times[i]).total_seconds()
            for i in range(len(sorted_times) - 1)
        ]
        if not intervals:
            continue
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        if std_dev <= BEACON_MAX_INTERVAL_VARIANCE_SECONDS:
            beaconing_destinations.append((dest_ip, len(timestamps), avg_interval))

    return beaconing_destinations


def analyze_network_traffic(connections):
    """
    Analyze a list of network connection records for suspicious patterns.

    Args:
        connections: list of dicts, each:
            {
                "source_ip": str,
                "dest_ip": str,
                "dest_port": int,
                "data_transferred_mb": float,
                "timestamp": datetime,
                "protocol": str (optional, e.g. "TCP"),
            }

    Returns:
        dict: {"score": 0-100 (higher = more suspicious),
               "verdict": "Normal" | "Suspicious" | "Likely Malicious",
               "indicators": list[str]}
    """
    if not connections:
        return {"score": 0.0, "verdict": "Normal", "indicators": ["No connection data provided"]}

    risk_points = 0.0
    indicators = []

    bad_ip_hits = set()
    suspicious_port_hits = set()
    large_transfers = []
    off_hours_count = 0

    for conn in connections:
        dest_ip = conn.get("dest_ip", "")
        dest_port = conn.get("dest_port")
        data_mb = conn.get("data_transferred_mb", 0)
        timestamp = conn.get("timestamp")

        if dest_ip in KNOWN_BAD_IPS:
            bad_ip_hits.add((dest_ip, KNOWN_BAD_IPS[dest_ip]))

        if dest_port in SUSPICIOUS_PORTS:
            suspicious_port_hits.add((dest_port, SUSPICIOUS_PORTS[dest_port]))

        if data_mb >= LARGE_TRANSFER_THRESHOLD_MB:
            large_transfers.append((dest_ip, data_mb))

        if timestamp is not None and isinstance(timestamp, datetime):
            if OFF_HOURS_START <= timestamp.hour < OFF_HOURS_END:
                off_hours_count += 1

    if bad_ip_hits:
        risk_points += 50
        for ip, reason in bad_ip_hits:
            indicators.append(f"Connection to known-malicious IP {ip}: {reason}")

    if suspicious_port_hits:
        risk_points += min(30, 15 * len(suspicious_port_hits))
        for port, reason in suspicious_port_hits:
            indicators.append(f"Traffic on suspicious port {port}: {reason}")

    if large_transfers:
        risk_points += 25
        for ip, mb in large_transfers:
            indicators.append(f"Unusually large data transfer to {ip}: {mb:.0f} MB - possible exfiltration")

    beaconing = _check_beaconing(connections)
    if beaconing:
        risk_points += 30
        for dest_ip, count, avg_interval in beaconing:
            indicators.append(
                f"Beaconing pattern detected to {dest_ip}: {count} connections, "
                f"avg {avg_interval:.0f}s apart - possible malware C2 communication"
            )

    if off_hours_count > 0:
        risk_points += 10
        indicators.append(f"{off_hours_count} connection(s) occurred during off-hours ({OFF_HOURS_START}:00-{OFF_HOURS_END}:00)")

    if not indicators:
        indicators.append("No suspicious network patterns found")

    score = min(100, round(risk_points, 1))
    verdict = "Likely Malicious" if score >= 60 else "Suspicious" if score >= 25 else "Normal"

    return {"score": score, "verdict": verdict, "indicators": indicators}
# ---------------------------------------------------------------------------
# Feature 3: API abuse
# ---------------------------------------------------------------------------

def _check_rate_limit_violations(requests):
    """Group by client, check if any client exceeded the allowed
    request count within the configured time window."""
    by_client = defaultdict(list)
    for req in requests:
        by_client[req.get("client_id", "unknown")].append(req["timestamp"])

    violators = []
    for client_id, timestamps in by_client.items():
        sorted_times = sorted(timestamps)
        for i in range(len(sorted_times)):
            window_end = sorted_times[i] + timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
            count_in_window = sum(1 for t in sorted_times[i:] if t <= window_end)
            if count_in_window > RATE_LIMIT_MAX_REQUESTS:
                violators.append((client_id, count_in_window))
                break
    return violators


def _check_injection_attempts(requests):
    hits = []
    for req in requests:
        params = str(req.get("query_params", "")).lower()
        endpoint = str(req.get("endpoint", "")).lower()
        combined = f"{endpoint} {params}"
        for pattern in INJECTION_PATTERNS:
            if pattern in combined:
                hits.append((req.get("client_id", "unknown"), pattern))
    return hits


def analyze_api_abuse(requests):
    """
    Analyze a list of API request records for abuse patterns.

    Args:
        requests: list of dicts, each:
            {
                "client_id": str,
                "endpoint": str,
                "method": str (optional),
                "status_code": int,
                "timestamp": datetime,
                "query_params": str (optional),
            }

    Returns:
        dict: {"score": 0-100 (higher = more suspicious),
               "verdict": "Normal" | "Suspicious" | "Likely Abuse",
               "indicators": list[str]}
    """
    if not requests:
        return {"score": 0.0, "verdict": "Normal", "indicators": ["No request data provided"]}

    risk_points = 0.0
    indicators = []

    rate_violators = _check_rate_limit_violations(requests)
    if rate_violators:
        risk_points += 35
        for client_id, count in rate_violators:
            indicators.append(
                f"Client '{client_id}' exceeded rate limit: {count} requests within "
                f"{RATE_LIMIT_WINDOW_SECONDS}s (limit: {RATE_LIMIT_MAX_REQUESTS})"
            )

    by_client_requests = defaultdict(list)
    for req in requests:
        by_client_requests[req.get("client_id", "unknown")].append(req)

    for client_id, client_reqs in by_client_requests.items():
        total = len(client_reqs)
        auth_failures = sum(1 for r in client_reqs if r.get("status_code") in AUTH_FAILURE_CODES)
        if total >= 5 and (auth_failures / total) >= AUTH_FAILURE_RATE_THRESHOLD:
            risk_points += 40
            indicators.append(
                f"Client '{client_id}' has a high auth-failure rate: "
                f"{auth_failures}/{total} requests ({auth_failures/total*100:.0f}%) - possible credential stuffing"
            )

        distinct_endpoints = len(set(r.get("endpoint") for r in client_reqs))
        if distinct_endpoints >= ENDPOINT_ENUMERATION_THRESHOLD:
            risk_points += 25
            indicators.append(
                f"Client '{client_id}' hit {distinct_endpoints} distinct endpoints - possible scanning/enumeration"
            )

        errors = sum(1 for r in client_reqs if r.get("status_code") in ERROR_CODES)
        if total >= 5 and (errors / total) >= ERROR_RATE_THRESHOLD:
            risk_points += 15
            indicators.append(
                f"Client '{client_id}' has a high error rate: {errors}/{total} requests ({errors/total*100:.0f}%)"
            )

    injection_hits = _check_injection_attempts(requests)
    if injection_hits:
        risk_points += min(40, 15 * len(set(injection_hits)))
        for client_id, pattern in set(injection_hits):
            indicators.append(f"Client '{client_id}' sent a request containing injection pattern: '{pattern}'")

    if not indicators:
        indicators.append("No API abuse patterns found")

    score = min(100, round(risk_points, 1))
    verdict = "Likely Abuse" if score >= 60 else "Suspicious" if score >= 25 else "Normal"

    return {"score": score, "verdict": verdict, "indicators": indicators}
# ---------------------------------------------------------------------------
# Feature 4: Data exfiltration behavior
# ---------------------------------------------------------------------------

def _check_bulk_access(events):
    """Group by user, check if any user accessed too many files within
    the configured time window."""
    by_user = defaultdict(list)
    for event in events:
        by_user[event.get("user_id", "unknown")].append(event["timestamp"])

    bulk_users = []
    for user_id, timestamps in by_user.items():
        sorted_times = sorted(timestamps)
        for i in range(len(sorted_times)):
            window_end = sorted_times[i] + timedelta(minutes=BULK_ACCESS_WINDOW_MINUTES)
            count_in_window = sum(1 for t in sorted_times[i:] if t <= window_end)
            if count_in_window >= BULK_ACCESS_FILE_COUNT_THRESHOLD:
                bulk_users.append((user_id, count_in_window))
                break
    return bulk_users


def analyze_data_exfiltration(events):
    """
    Analyze a list of file-access/export events for exfiltration behavior.

    Args:
        events: list of dicts, each:
            {
                "user_id": str,
                "file_name": str,
                "action": str ("read" | "download" | "export"),
                "size_mb": float (optional),
                "timestamp": datetime,
            }

    Returns:
        dict: {"score": 0-100 (higher = more suspicious),
               "verdict": "Normal" | "Suspicious" | "Likely Exfiltration",
               "indicators": list[str]}
    """
    if not events:
        return {"score": 0.0, "verdict": "Normal", "indicators": ["No access data provided"]}

    risk_points = 0.0
    indicators = []

    bulk_users = _check_bulk_access(events)
    if bulk_users:
        risk_points += 35
        for user_id, count in bulk_users:
            indicators.append(
                f"User '{user_id}' accessed {count} files within {BULK_ACCESS_WINDOW_MINUTES} minutes - possible bulk collection"
            )

    by_user_events = defaultdict(list)
    for event in events:
        by_user_events[event.get("user_id", "unknown")].append(event)

    for user_id, user_events in by_user_events.items():
        sensitive_hits = sum(
            1 for e in user_events
            if any(kw in str(e.get("file_name", "")).lower() for kw in SENSITIVE_KEYWORDS)
        )
        if sensitive_hits >= SENSITIVE_ACCESS_THRESHOLD:
            risk_points += 30
            indicators.append(
                f"User '{user_id}' accessed {sensitive_hits} sensitive-labeled files - unusual volume"
            )

        total_export_mb = sum(
            e.get("size_mb", 0) for e in user_events
            if e.get("action") in ("download", "export")
        )
        if total_export_mb >= LARGE_EXPORT_THRESHOLD_MB:
            risk_points += 30
            indicators.append(
                f"User '{user_id}' exported {total_export_mb:.0f} MB total - exceeds normal threshold"
            )

        off_hours_bulk = [
            e for e in user_events
            if isinstance(e.get("timestamp"), datetime) and
            (e["timestamp"].hour >= EXFIL_OFF_HOURS_START or e["timestamp"].hour < EXFIL_OFF_HOURS_END)
        ]
        if len(off_hours_bulk) >= BULK_ACCESS_FILE_COUNT_THRESHOLD // 2:
            risk_points += 20
            indicators.append(
                f"User '{user_id}' had {len(off_hours_bulk)} file access events during off-hours"
            )

        high_risk_hits = [
            e.get("file_name", "") for e in user_events
            if os.path.splitext(str(e.get("file_name", "")))[1].lower() in HIGH_RISK_EXTENSIONS
        ]
        if high_risk_hits:
            risk_points += 25
            indicators.append(
                f"User '{user_id}' accessed high-risk file types: {', '.join(set(high_risk_hits))}"
            )

    if not indicators:
        indicators.append("No data exfiltration patterns found")

    score = min(100, round(risk_points, 1))
    verdict = "Likely Exfiltration" if score >= 60 else "Suspicious" if score >= 25 else "Normal"

    return {"score": score, "verdict": verdict, "indicators": indicators}
# ---------------------------------------------------------------------------
# Feature 5: Abnormal user activity
# ---------------------------------------------------------------------------

def _check_impossible_travel(login_events):
    """Flag logins from different locations too close together in time
    to be physically possible."""
    by_user = defaultdict(list)
    for event in login_events:
        by_user[event.get("user_id", "unknown")].append(event)

    flagged = []
    for user_id, events in by_user.items():
        sorted_events = sorted(events, key=lambda e: e["timestamp"])
        for i in range(len(sorted_events) - 1):
            loc_a = sorted_events[i].get("location")
            loc_b = sorted_events[i + 1].get("location")
            if loc_a and loc_b and loc_a != loc_b:
                minutes_apart = (sorted_events[i + 1]["timestamp"] - sorted_events[i]["timestamp"]).total_seconds() / 60
                if minutes_apart <= IMPOSSIBLE_TRAVEL_MAX_MINUTES:
                    flagged.append((user_id, loc_a, loc_b, minutes_apart))
    return flagged


def analyze_user_activity(login_events, action_events=None):
    """
    Analyze login and action events for abnormal user behavior.

    Args:
        login_events: list of dicts, each:
            {
                "user_id": str,
                "success": bool,
                "location": str (optional, e.g. "Mumbai, IN"),
                "timestamp": datetime,
            }
        action_events: list of dicts (optional), each:
            {
                "user_id": str,
                "action": str,
                "timestamp": datetime,
            }

    Returns:
        dict: {"score": 0-100 (higher = more suspicious),
               "verdict": "Normal" | "Suspicious" | "Likely Compromised",
               "indicators": list[str]}
    """
    if not login_events and not action_events:
        return {"score": 0.0, "verdict": "Normal", "indicators": ["No activity data provided"]}

    risk_points = 0.0
    indicators = []
    login_events = login_events or []
    action_events = action_events or []

    by_user_logins = defaultdict(list)
    for event in login_events:
        by_user_logins[event.get("user_id", "unknown")].append(event)

    for user_id, events in by_user_logins.items():
        sorted_events = sorted(events, key=lambda e: e["timestamp"])

        failed_streak = 0
        for i, event in enumerate(sorted_events):
            if not event.get("success", True):
                failed_streak += 1
            else:
                if failed_streak >= FAILED_LOGIN_THRESHOLD:
                    risk_points += 40
                    indicators.append(
                        f"User '{user_id}' had {failed_streak} failed logins immediately before a successful one - possible brute force"
                    )
                failed_streak = 0

        unusual_hour_logins = [
            e for e in sorted_events
            if e.get("success") and isinstance(e.get("timestamp"), datetime) and
            not (TYPICAL_LOGIN_HOUR_START <= e["timestamp"].hour < TYPICAL_LOGIN_HOUR_END)
        ]
        if unusual_hour_logins:
            risk_points += 15
            indicators.append(
                f"User '{user_id}' logged in {len(unusual_hour_logins)} time(s) outside typical hours "
                f"({TYPICAL_LOGIN_HOUR_START}:00-{TYPICAL_LOGIN_HOUR_END}:00)"
            )

    travel_flags = _check_impossible_travel(login_events)
    if travel_flags:
        risk_points += 50
        for user_id, loc_a, loc_b, minutes in travel_flags:
            indicators.append(
                f"User '{user_id}' logged in from '{loc_a}' then '{loc_b}' only {minutes:.0f} minutes apart - impossible travel"
            )

    by_user_actions = defaultdict(list)
    for event in action_events:
        by_user_actions[event.get("user_id", "unknown")].append(event)

    for user_id, events in by_user_actions.items():
        admin_attempts = [e for e in events if e.get("action") in ADMIN_ACTIONS]
        if admin_attempts:
            risk_points += 35
            actions_list = ", ".join(sorted(set(e["action"] for e in admin_attempts)))
            indicators.append(f"User '{user_id}' attempted admin-level actions: {actions_list}")

        if len(events) >= ACTION_COUNT_ALERT_THRESHOLD:
            risk_points += 20
            indicators.append(f"User '{user_id}' performed {len(events)} actions - unusually high volume")

        timestamps = [e["timestamp"] for e in events if isinstance(e.get("timestamp"), datetime)]
        if len(timestamps) >= 2:
            duration_hours = (max(timestamps) - min(timestamps)).total_seconds() / 3600
            if duration_hours >= SESSION_DURATION_ALERT_HOURS:
                risk_points += 15
                indicators.append(f"User '{user_id}' had an unusually long session: {duration_hours:.1f} hours")

    if not indicators:
        indicators.append("No abnormal user activity patterns found")

    score = min(100, round(risk_points, 1))
    verdict = "Likely Compromised" if score >= 60 else "Suspicious" if score >= 25 else "Normal"

    return {"score": score, "verdict": verdict, "indicators": indicators}
# ---------------------------------------------------------------------------
# Feature 6: Insider threats
# ---------------------------------------------------------------------------

def analyze_insider_threat(employee_profile, activity_events, baseline_daily_actions=None):
    """
    Analyze an employee's profile and recent activity for insider-threat
    risk signals. Designed to be reviewed periodically (e.g. weekly),
    not necessarily in real time.

    Args:
        employee_profile: dict:
            {
                "user_id": str,
                "department": str (lowercase, e.g. "finance"),
                "is_resigning": bool (optional),
                "resignation_date": datetime (optional),
                "recent_hr_incident": bool (optional),
                "today": datetime (optional, defaults to datetime.now()),
            }
        activity_events: list of dicts, each:
            {
                "data_category": str (e.g. "financial_records"),
                "access_method": str (optional, e.g. "usb_copy"),
                "timestamp": datetime,
            }
        baseline_daily_actions: float (optional) - this employee's
            typical number of actions per day, for comparison.

    Returns:
        dict: {"score": 0-100 (higher = more suspicious),
               "verdict": "Normal" | "Elevated Risk" | "High Risk",
               "indicators": list[str]}
    """
    if not activity_events:
        return {"score": 0.0, "verdict": "Normal", "indicators": ["No activity data provided"]}

    risk_points = 0.0
    indicators = []

    user_id = employee_profile.get("user_id", "unknown")
    department = employee_profile.get("department", "").lower()
    is_resigning = employee_profile.get("is_resigning", False)
    resignation_date = employee_profile.get("resignation_date")
    recent_hr_incident = employee_profile.get("recent_hr_incident", False)
    today = employee_profile.get("today", datetime.now())

    near_resignation = False
    if is_resigning and resignation_date:
        days_to_resignation = abs((resignation_date - today).days)
        if days_to_resignation <= RESIGNATION_RISK_WINDOW_DAYS:
            near_resignation = True

    allowed_scope = DEPARTMENT_DATA_SCOPE.get(department, set())
    out_of_scope_hits = [
        e for e in activity_events
        if e.get("data_category") and e["data_category"] not in allowed_scope
    ]

    if out_of_scope_hits:
        multiplier = 2 if near_resignation else 1
        risk_points += 30 * multiplier
        categories = ", ".join(sorted(set(e["data_category"] for e in out_of_scope_hits)))
        note = " (heightened: employee is near resignation)" if near_resignation else ""
        indicators.append(
            f"User '{user_id}' (dept: {department or 'unknown'}) accessed out-of-scope data: {categories}{note}"
        )

    if baseline_daily_actions and baseline_daily_actions > 0:
        timestamps = [e["timestamp"] for e in activity_events if isinstance(e.get("timestamp"), datetime)]
        if timestamps:
            days_span = max((max(timestamps) - min(timestamps)).days, 1)
            daily_rate = len(activity_events) / days_span
            if daily_rate >= baseline_daily_actions * BASELINE_MULTIPLIER_ALERT:
                risk_points += 35
                indicators.append(
                    f"User '{user_id}' activity rate ({daily_rate:.1f}/day) is "
                    f"{daily_rate/baseline_daily_actions:.1f}x their normal baseline ({baseline_daily_actions}/day)"
                )

    direct_access_hits = [e for e in activity_events if e.get("access_method") in DIRECT_ACCESS_METHODS]
    if direct_access_hits:
        risk_points += 25
        methods = ", ".join(set(e["access_method"] for e in direct_access_hits))
        indicators.append(f"User '{user_id}' used direct/unaudited access methods: {methods}")

    if recent_hr_incident and (out_of_scope_hits or direct_access_hits):
        risk_points += RECENT_HR_INCIDENT_WEIGHT
        indicators.append(
            f"User '{user_id}' has a recent HR incident on file, combined with the above activity - elevated concern"
        )

    if near_resignation and len(activity_events) > 0 and not out_of_scope_hits and not direct_access_hits:
        risk_points += 10
        indicators.append(
            f"User '{user_id}' is within {RESIGNATION_RISK_WINDOW_DAYS} days of resignation - routine heightened monitoring"
        )

    if not indicators:
        indicators.append("No insider-threat risk signals found")

    score = min(100, round(risk_points, 1))
    verdict = "High Risk" if score >= 60 else "Elevated Risk" if score >= 25 else "Normal"

    return {"score": score, "verdict": verdict, "indicators": indicators}