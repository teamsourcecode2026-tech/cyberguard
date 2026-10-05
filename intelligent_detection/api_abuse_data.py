# intelligent_detection/api_abuse_data.py

RATE_LIMIT_MAX_REQUESTS = 50
RATE_LIMIT_WINDOW_SECONDS = 60

AUTH_FAILURE_CODES = {401, 403}
AUTH_FAILURE_RATE_THRESHOLD = 0.5  # 50%+ of requests failing auth

ERROR_CODES = {400, 401, 403, 404, 429, 500, 502, 503}
ERROR_RATE_THRESHOLD = 0.6  # 60%+ of requests erroring

ENDPOINT_ENUMERATION_THRESHOLD = 15  # distinct endpoints hit by one client

INJECTION_PATTERNS = [
    "' or '1'='1", "' or 1=1", "union select", "drop table", "--",
    "<script>", "javascript:", "onerror=", "../../../", "etc/passwd",
    "exec(", "eval(", "; cat ", "| whoami",
]