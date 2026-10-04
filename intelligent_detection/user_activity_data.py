# intelligent_detection/user_activity_data.py

TYPICAL_LOGIN_HOUR_START = 7
TYPICAL_LOGIN_HOUR_END = 22

FAILED_LOGIN_THRESHOLD = 4
IMPOSSIBLE_TRAVEL_MAX_MINUTES = 60   # can't log in from 2 far locations within this window

ADMIN_ACTIONS = {
    "delete_user", "modify_permissions", "access_admin_panel",
    "export_all_data", "change_billing", "create_admin_account",
    "disable_logging", "modify_firewall_rules",
}

SESSION_DURATION_ALERT_HOURS = 10
ACTION_COUNT_ALERT_THRESHOLD = 200