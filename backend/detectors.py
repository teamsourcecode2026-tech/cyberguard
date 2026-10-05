"""
Unified import layer for all detection modules.
Adds the correct sys.path entries so backend can import from
ml_phishing/, malicious_url_website/, and theft_account_detection/.
"""
import os
import sys

_project_root = os.path.dirname(os.path.dirname(__file__))

# Add module directories to sys.path so their internal imports (e.g. 'from model import ...') work
_ml_phishing_dir = os.path.join(_project_root, "ml_phishing")
_malicious_url_dir = os.path.join(_project_root, "malicious_url_website")
_theft_dir = os.path.join(_project_root, "theft_account_detection")
_intelligent_dir = os.path.join(_project_root, "intelligent_detection")

for _dir in [_ml_phishing_dir, _malicious_url_dir, _theft_dir, _intelligent_dir]:
    if _dir not in sys.path:
        sys.path.insert(0, _dir)

# ---- ml_phishing detectors ----
from sms_detector import analyze_sms_phishing
from url_detector import analyze_url_phishing
from qr_detector import analyze_qr_phishing
from social_media_detector import analyze_social_media_phishing
from website_detector import analyze_website_phishing

# ---- malicious_url_website detectors ----
from domain_spoofing_detector import analyze_domain_spoofing
from lookalike_domain_detector import analyze_lookalike_domain
from ssl_domain_detector import analyze_ssl_domain
from url_manipulation_detector import analyze_url_manipulation
from malicious_redirect_detector import analyze_malicious_redirect
from fake_login_detector import analyze_fake_login

# ---- theft_account_detection detectors ----
from brute_force_detection import detect_brute_force
from impossible_travel_detector import detect_impossible_travel
from new_device_ip_detector import detect_new_device_or_ip
from password_spraying_detector import detect_password_spraying
from unusual_login_time_detector import detect_unusual_login_time
from session_anomaly_detector import detect_session_anomalies
from behaviour_change_detector import detect_behaviour_change

# ---- intelligent_detection detectors ----
from detector import analyze_malware_indicators
from detector import analyze_network_traffic
from detector import analyze_api_abuse
from detector import analyze_data_exfiltration
from detector import analyze_user_activity
from detector import analyze_insider_threat
from detector import analyze_system_behavior
