# intelligent_detection/insider_threat_data.py

# Departments and the data categories considered "within role" for each.
# Anything a department accesses outside its own list is flagged.
DEPARTMENT_DATA_SCOPE = {
    "engineering": {"source_code", "infrastructure", "technical_docs"},
    "finance": {"financial_records", "payroll", "budgets", "invoices"},
    "hr": {"employee_records", "payroll", "performance_reviews"},
    "marketing": {"campaign_data", "customer_data", "analytics"},
    "sales": {"customer_data", "contracts", "pipeline_data"},
}

RESIGNATION_RISK_WINDOW_DAYS = 30  # heightened scrutiny this close to departure

BASELINE_MULTIPLIER_ALERT = 3  # 3x a person's own normal activity level = flag

RECENT_HR_INCIDENT_WEIGHT = 25  # extra risk points if there's a recent HR flag on file

DIRECT_ACCESS_METHODS = {"usb_copy", "local_export", "screenshot_bulk", "print_bulk"}