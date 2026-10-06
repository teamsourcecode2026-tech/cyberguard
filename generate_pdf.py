import os
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return  # Skip cover page
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header
        self.drawString(54, 11 * inch - 36, "CyberGuard — AI-Powered Multi-Vector Threat Detection Platform")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)
        
        # Footer
        self.line(54, 45, 8.5 * inch - 54, 45)
        self.drawString(54, 32, "Confidential — CyberGuard Project Engineering Team (2026)")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 32, page_str)
        self.restoreState()


def build_pdf(filename):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=colors.HexColor("#0F172A"),
        alignment=1, # Center
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=colors.HexColor("#3B82F6"),
        alignment=1,
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True,
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E40AF"),
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True,
    )

    h3_style = ParagraphStyle(
        'Heading3_Custom',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceAfter=5,
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=15,
        bulletIndent=5,
        spaceAfter=3,
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
    )

    table_cell_code = ParagraphStyle(
        'TableCellCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0284C7"),
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1E293B"),
    )

    story = []

    # =========================================================================
    # COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 40))
    story.append(Paragraph("🛡️", ParagraphStyle('Icon', parent=title_style, fontSize=48, leading=56)))
    story.append(Spacer(1, 10))
    story.append(Paragraph("CYBERGUARD", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Next-Generation AI-Powered Threat Detection & Incident Response Platform", subtitle_style))
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="60%", thickness=2, color=colors.HexColor("#2563EB"), spaceBefore=5, spaceAfter=20))
    
    story.append(Spacer(1, 30))
    cover_meta = [
        [Paragraph("<b>Document Version:</b>", body_style), Paragraph("2.0 (Production Release)", body_style)],
        [Paragraph("<b>Classification:</b>", body_style), Paragraph("Technical Architecture & Operational Specification", body_style)],
        [Paragraph("<b>Primary Author / Lead:</b>", body_style), Paragraph("Manish (Backend Architect & Lead)", body_style)],
        [Paragraph("<b>Engineering Team:</b>", body_style), Paragraph("Bibek, Niti, Chandan, Anisha Sahu, Chinmay, Manish", body_style)],
        [Paragraph("<b>Repository:</b>", body_style), Paragraph("teamsourcecode2026-tech/cyberguard", body_style)],
        [Paragraph("<b>Date:</b>", body_style), Paragraph("October 2026", body_style)],
    ]
    meta_table = Table(cover_meta, colWidths=[150, 320])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 60))
    abstract_box = [
        [Paragraph("<b>EXECUTIVE STATEMENT:</b> CyberGuard delivers a unified defensive perimeter covering Email Phishing, Synthetic Media (Deepfakes), Executive Impersonation, Web & Typosquatting Exploits, Account Takeover, and Network Telemetry. Powered by 24 specialized detection engines, real-time FastAPI ingestion, and a modern React 19 SOC dashboard.", callout_style)]
    ]
    abs_table = Table(abstract_box, colWidths=[470])
    abs_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EFF6FF")),
        ('BOX', (0,0), (-1,-1), 1.5, colors.HexColor("#3B82F6")),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(abs_table)
    story.append(PageBreak())

    # =========================================================================
    # SECTION 1: ARCHITECTURAL OVERVIEW
    # =========================================================================
    story.append(Paragraph("1. System Architecture & High-Level Design", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=10))
    
    story.append(Paragraph(
        "CyberGuard operates as a cohesive, distributed threat detection mesh comprised of three decoupled layers: "
        "the <b>Presentation Layer</b> (React 19 single-page application), the <b>Gateway & Analysis Layer</b> (FastAPI asynchronous microservices), "
        "and the <b>Persistence Layer</b> (MongoDB Atlas document database). Communication is governed strictly through JSON REST interfaces "
        "secured via HMAC-SHA256 JSON Web Tokens (JWT).", body_style
    ))
    story.append(Spacer(1, 6))

    arch_points = [
        "<b>Single Gateway Port (8000):</b> Consolidated authentication, telemetry ingestion, status management, and statistics into a single FastAPI engine.",
        "<b>Dynamic Modular Hub (detectors.py):</b> Central import abstraction that injects PYTHONPATH paths at runtime, eliminating dependency conflicts among standalone ML directories.",
        "<b>Normalized Risk Scoring (0–100):</b> Every detector outputs a structured tuple {score, verdict, indicators}. The central risk engine classifies threats into 5 standardized tiers: Safe (0-30), Low (31-50), Medium (51-69), High (70-84), and Critical (85-100).",
        "<b>Real-Time Forensic Enrichment:</b> Ingested events automatically undergo IP geo-registry resolution, domain extraction, infrastructure reputation assessment, and DNS cryptographic validation.",
    ]
    for pt in arch_points:
        story.append(Paragraph(f"• {pt}", bullet_style))
    story.append(Spacer(1, 10))

    # Architecture Table
    arch_summary_data = [
        [Paragraph("Layer", table_header), Paragraph("Technology", table_header), Paragraph("Core Responsibilities", table_header)],
        [Paragraph("Frontend UI", table_cell), Paragraph("React 19, Vite, Tailwind CSS", table_cell), Paragraph("SOC Overview, 6-tab Scan Center, Live Threat Feed, Forensic Alert Detail, DNS Intelligence.", table_cell)],
        [Paragraph("API Gateway", table_cell), Paragraph("FastAPI, Uvicorn, Python 3.11", table_cell), Paragraph("Authentication (JWT), CORS, 26+ REST ingestion routes, payload validation, alert persistence.", table_cell)],
        [Paragraph("Analysis Engines", table_cell), Paragraph("PyTorch, Scikit-Learn, dnspython", table_cell), Paragraph("24 specialized detectors across NLP, Computer Vision, behavioral heuristics, and DNS lookups.", table_cell)],
        [Paragraph("Database", table_cell), Paragraph("MongoDB Atlas, PyMongo", table_cell), Paragraph("Document storage across events, alerts, users, and specialized ML result collections.", table_cell)],
    ]
    arch_table = Table(arch_summary_data, colWidths=[90, 140, 240])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0F172A")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(arch_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 2: THE 24 SECURITY FEATURES IN DETAIL
    # =========================================================================
    story.append(Paragraph("2. Deep-Dive Feature Specification (All 24 Detection Engines)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=10))
    story.append(Paragraph(
        "Each security module has been engineered to counter specific cyber threat vectors. Below is the exhaustive technical specification for every feature:", body_style
    ))
    story.append(Spacer(1, 6))

    # Group 1: Phishing & Social Engineering
    story.append(Paragraph("2.1. Social Engineering & Phishing Vector (5 Engines)", h2_style))
    
    phishing_features = [
        ("Feature 1: Email Phishing Detection (/api/ingest/phishing)",
         "Leverages TF-IDF n-gram vectorization and a trained Logistic Regression classifier. Evaluates semantic urgency markers ('Account suspended within 24h'), coercive call-to-action triggers, and mismatched hyperlink anchors. Outputs confidence score and forensic keyword flags."),
        ("Feature 2: SMS Smishing Detection (/api/ingest/sms)",
         "Tokenizes short-form mobile communications. Inspects SMS strings for parcel delivery fee scams, fake banking OTP authentication requests, urgent debt warnings, and suspicious shortened domains (bit.ly, t.co)."),
        ("Feature 3: Social Media Scam Analyzer (/api/ingest/social)",
         "Analyzes direct messages, social media posts, and comments. Flags fraudulent cryptocurrency giveaways, spoofed social verification badges, Ponzi recruitment pretexts, and fake customer support handles."),
        ("Feature 4: QR Code Phishing / Quishing Scanner (/api/ingest/qr)",
         "Accepts image files (PNG, JPG). Employs OpenCV and pyzbar to isolate and decode 2D barcodes into target URL payloads. Evaluates the extracted link through the lexical and web threat pipelines to prevent physical-to-digital credential harvesting."),
        ("Feature 5: Executive & Brand Impersonation (/api/ingest/impersonation)",
         "Analyzes email display headers against corporate executive profiles (CEO, CFO, HR Director). Detects display name spoofing where an external freemail account (e.g., attacker@gmail.com) assumes an executive name to request wire transfers or gift cards.")
    ]
    for title, desc in phishing_features:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", body_style))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 6))

    # Group 2: Web, Domain & URL Vector
    story.append(Paragraph("2.2. Web, Domain & URL Threat Vector (8 Engines)", h2_style))
    web_features = [
        ("Feature 6: Lexical URL Phishing (/api/ingest/url)",
         "Calculates character entropy, sub-domain depth, suspicious high-risk TLD frequency (.top, .xyz, .cf), raw IP hostnames, and keyword stuffing in paths."),
        ("Feature 7: Website Scraping & DOM Inspection (/api/ingest/website)",
         "Utilizes BeautifulSoup4 to inspect HTML DOM structure. Flags hidden iframe overlays, login form inputs targeting unverified third-party endpoints, and missing favicon assets."),
        ("Feature 8: Domain Spoofing & IDN Homographs (/api/ingest/domain-spoof)",
         "Unmasks internationalized domain name (IDN) attacks where Cyrillic, Greek, or Latin lookalike characters deceive users (e.g., pаypal.com using Cyrillic 'а'). Converts Unicode to Punycode and performs authoritative DNS comparisons."),
        ("Feature 9: Lookalike Domain & Typosquatting (/api/ingest/lookalike)",
         "Computes Levenshtein edit distance and bit-flip distance between target domains and the Alexa Top 10,000 corporate domains to detect squatting (e.g., g00gle.com, netfllix.com)."),
        ("Feature 10: SSL/TLS Certificate Audit (/api/ingest/ssl-check)",
         "Initiates direct cryptographic TLS handshake on port 443. Audits certificate expiration, validity period, self-signed origins, Let's Encrypt mismatch, and Subject Alternative Name (SAN) coverage."),
        ("Feature 11: URL Manipulation & Evasion (/api/ingest/url-manipulation)",
         "Detects evasion patterns: double-percent hex encoding (%2520), directory traversal sequences (../), null-byte delimiters (%00), and username prefix delimiters (http://google.com@malicious.com)."),
        ("Feature 12: Malicious Redirect Chain Tracer (/api/ingest/redirect-check)",
         "Executes headless HTTP requests following 301/302/307 redirects to unmask multi-hop redirection chains designed to bypass static URL filters."),
        ("Feature 13: Fake Login Interface Detector (/api/ingest/fake-login)",
         "Inspects page titles, form POST targets, and input field patterns to flag cloned authentication portals replicating Microsoft 365, Google Workspace, and Okta SSO.")
    ]
    for title, desc in web_features:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", body_style))
        story.append(Spacer(1, 3))
    story.append(PageBreak())

    # Group 3: Email Authentication
    story.append(Paragraph("2.3. Cryptographic Email Authentication Vector (3 Protocols)", h2_style))
    story.append(Paragraph(
        "Built in <code>backend/email_auth_checker.py</code> using <code>dnspython</code>, this subsystem validates domain authenticity at the DNS level:", body_style
    ))
    story.append(Spacer(1, 4))
    
    email_auth_points = [
        ("Feature 14: SPF (Sender Policy Framework) Verification",
         "Performs DNS TXT lookups for 'v=spf1'. Evaluates IPv4/IPv6 mechanisms, 'include' directives, and qualifier strength (-all hardfail, ~all softfail, +all dangerous pass). Cross-references sender MTA IP to verify transmission authorization."),
        ("Feature 15: DKIM (DomainKeys Identified Mail) Verification",
         "Queries public cryptographic keys at <selector>._domainkey.<domain> across common selectors (default, google, s1, mail, selector1). Validates RSA key presence, format, and flags revoked public keys (p=)."),
        ("Feature 16: DMARC (Domain Message Authentication) Policy Engine (/api/ingest/email-auth)",
         "Resolves _dmarc.<domain> and organizational parent domains. Audits policy strength (p=reject strict, p=quarantine, p=none weak). Inspects sub-domain policies (sp=) and forensic reporting endpoints (rua=). Includes interactive live verification on the dashboard.")
    ]
    for title, desc in email_auth_points:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", body_style))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 6))

    # Group 4: Intelligent System & Network Telemetry
    story.append(Paragraph("2.4. Intelligent System & Network Telemetry Vector (7 Engines)", h2_style))
    story.append(Paragraph(
        "An 843-line telemetry evaluation suite (<code>intelligent_detection/detector.py</code>) designed for SOC enterprise environments:", body_style
    ))
    story.append(Spacer(1, 4))

    intel_features = [
        ("Feature 17: Malware Static Indicator Analysis (/api/ingest/malware)",
         "Performs static PE/ELF inspection: calculates section entropy to detect packers (UPX), inspects suspicious Win32 API imports (VirtualAllocEx, WriteProcessMemory), matches MD5/SHA256 hashes against known threat databases, and flags double extensions."),
        ("Feature 18: Network Traffic & C2 Telemetry (/api/ingest/network)",
         "Analyzes arrays of network connections: detects horizontal/vertical port scans, Command & Control (C2) beaconing (uniform periodic intervals), abnormal data egress volume spikes, and connections to known malicious IP subnets."),
        ("Feature 19: API Abuse & Credential Stuffing (/api/ingest/api-abuse)",
         "Evaluates API request telemetry: detects rapid volumetric bursts, credential stuffing targeting /api/login, query parameter tampering, and high concentrations of HTTP 401, 403, and 429 status codes."),
        ("Feature 20: Data Exfiltration Monitoring (/api/ingest/exfiltration)",
         "Monitors file access event logs: identifies bulk downloads of sensitive file patterns (passwords.csv, credentials.json, *.pem), off-hours data transfers, and aggregate byte transfers exceeding historical baselines."),
        ("Feature 21: User Activity Anomaly Analysis (/api/ingest/user-activity)",
         "Correlates login event arrays with subsequent action events. Flags rapid location switching, failed-then-immediate-success sequences, and anomalous administrative permission modifications."),
        ("Feature 22: Insider Threat Risk Profiling (/api/ingest/insider-threat)",
         "Correlates employee profile metadata (is_resigning: true, upcoming departure dates, recent HR incident records) with repository access and document downloads to identify intellectual property theft risks before employee exit."),
        ("Feature 23: Host Process & System Behavior (/api/ingest/system-behavior)",
         "Audits host OS events: detects anomalous parent-child process relationships (winword.exe spawning powershell.exe or cmd.exe), unsigned binaries executing from %TEMP%, and persistence registry startup additions.")
    ]
    for title, desc in intel_features:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", body_style))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 6))

    # Group 5: Identity & Account Takeover
    story.append(Paragraph("2.5. Identity & Account Takeover (ATO) Vector (Feature 24)", h2_style))
    story.append(Paragraph(
        "Feature 24 is an integrated identity defense suite (<code>POST /api/ingest/account-theft</code> & <code>/api/ingest/log</code>) featuring 7 specialized statistical algorithms:", body_style
    ))
    story.append(Spacer(1, 4))

    theft_sub = [
        "<b>Brute Force Detection:</b> Rolling-window temporal analysis flagging threshold breaches of consecutive failed authentications per user or source IP.",
        "<b>Impossible Travel:</b> Computes great-circle geodetic distance between successive login coordinates and flags geo-velocities exceeding commercial aviation thresholds (>900 km/h).",
        "<b>New Device & IP Tracking:</b> Maintains user device fingerprint baselines; flags novel JA3 TLS browser fingerprints and unrecognized Autonomous System Numbers (ASNs).",
        "<b>Password Spraying:</b> Identifies horizontal attacks where a single password is systematically attempted across hundreds of corporate usernames to evade account lockout thresholds.",
        "<b>Unusual Login Time:</b> Employs Gaussian distribution modeling to detect logins deviating significantly from the employee's historical operational hours.",
        "<b>Session Anomaly Detection:</b> Flags concurrent active sessions originating from divergent geographical regions or incompatible browser agents.",
        "<b>Behavioral Shift Analysis:</b> Detects anomalous statistical spikes in administrative write/delete operations against historic read baselines.",
    ]
    for pt in theft_sub:
        story.append(Paragraph(f"• {pt}", bullet_style))
    story.append(PageBreak())

    # =========================================================================
    # SECTION 3: AUTHENTICATION & SECURITY
    # =========================================================================
    story.append(Paragraph("3. Authentication, Identity & Security Infrastructure", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=10))

    story.append(Paragraph(
        "CyberGuard enforces a multi-tiered security model covering token authentication, cryptographic password hashing, "
        "and secure credential lifecycle management:", body_style
    ))
    story.append(Spacer(1, 6))

    auth_details = [
        ("JWT Authentication Engine (backend/auth.py)",
         "Implements RFC 7519 compliant JSON Web Tokens using python-jose. Tokens are signed via HMAC-SHA256 with 24-hour expiration. FastAPI dependencies (Depends(get_current_user) and Depends(require_auth)) guard endpoints, verifying token signature and expiration on every request."),
        ("Password Hashing & Salt Management",
         "Passwords submitted via registration or reset are automatically hashed using bcrypt with cryptographically secure random salts. Plaintext passwords are never persisted to disk or logged."),
        ("Self-Service Password Reset Subsystem (/api/reset-password)",
         "Provides an end-to-end credential update workflow. The endpoint requires the username, the current active password, and the new password. The backend verifies the current bcrypt hash before allowing any modification, enforcing an entropy threshold of minimum 6 characters on the new credential."),
        ("Frontend Token Interceptor (frontend/src/api.js)",
         "The client automatically stores issued tokens in localStorage and attaches an Authorization: Bearer <token> header to all subsequent HTTP requests. Upon logout, tokens are securely cleared from browser memory.")
    ]
    for title, desc in auth_details:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", body_style))
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 4: FRONTEND USER EXPERIENCE
    # =========================================================================
    story.append(Paragraph("4. Frontend User Experience Architecture (5 Pages + 6 Tabs)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=10))

    ui_sections = [
        ("Login & Registration Page (Login.jsx)",
         "Features a dark gradient theme with floating shield logo. Provides seamless Sign In and Sign Up tabs, animated rotating security taglines, a real-time password strength meter (Red/Yellow/Green), show/hide password toggles, and an integrated Forgot/Reset Password flow."),
        ("Security Overview Command Dashboard (Overview.jsx)",
         "The primary SOC executive screen. Features 4 KPI cards (Total Events, Threats Detected, Critical Threats, New Incidents), 7 threat category groups with real-time incident counters, a risk distribution bar chart, a recent alerts stream, and a header Refresh button."),
        ("Unified Threat Scan Center (ScanCenter.jsx — 6 Tabs)",
         "Tab 1: Email & Text (Phishing, Impersonation, SMS, Social Media)\n"
         "Tab 2: URL & Website (Multi-select: URL, Website, Domain Spoof, Lookalike, SSL, Manipulation, Redirect, Fake Login)\n"
         "Tab 3: Media & Files (Deepfake detection, QR barcode scanning, PE malware indicators)\n"
         "Tab 4: Network & System (JSON telemetry for Network Traffic, API Abuse, System Behavior)\n"
         "Tab 5: User & Insider (JSON telemetry for Data Exfiltration, User Activity, Insider Threat Profiling)\n"
         "Tab 6: Email Authentication (SPF, DKIM, DMARC domain verification with raw DNS record display)"),
        ("Live Threat Feed (ThreatFeed.jsx)",
         "Real-time event log with instant keyword search, multi-filter dropdowns for Risk Level (Critical to Safe) and Threat Category, status badges (new, investigating, resolved), header Refresh button, and single-click row navigation to deep inspection."),
        ("Alert Forensic Detail & Threat Intelligence (AlertDetail.jsx & ThreatIntelligence.jsx)",
         "AlertDetail provides comprehensive forensic inspection: MITRE ATT&CK alignment, score gauge, timeline, AI explanation, recommended response actions, and interactive lifecycle status toggles.\n"
         "ThreatIntelligence enriches indicators with Source IP, Targeted Domain, Geolocation registry, Infrastructure Reputation, an indicator checklist, and live DNS SPF/DKIM/DMARC status with an interactive test bar.")
    ]
    for title, desc in ui_sections:
        story.append(Paragraph(f"<b>{title}:</b>", h3_style))
        for line in desc.split("\n"):
            story.append(Paragraph(line, body_style))
        story.append(Spacer(1, 4))
    story.append(PageBreak())

    # =========================================================================
    # SECTION 5: API SPECIFICATION TABLE
    # =========================================================================
    story.append(Paragraph("5. Complete REST API Specification (26 Routes)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=10))

    api_routes = [
        ["GET", "/api/health", "System health & version", "None", "{status, version}"],
        ["POST", "/api/register", "User registration", "{username, password}", "{success, message}"],
        ["POST", "/api/login", "Authentication & JWT issue", "{username, password}", "{success, token}"],
        ["POST", "/api/reset-password", "Self-service password reset", "{user, old_pass, new_pass}", "{success, message}"],
        ["GET", "/api/me", "Current user profile", "Bearer Token", "{username, auth}"],
        ["GET", "/api/alerts", "Retrieve alert feed", "None", "[AlertObject, ...]"],
        ["GET", "/api/alerts/{id}", "Retrieve alert details", "None", "AlertObject"],
        ["PATCH", "/api/alerts/{id}/status", "Update alert triage status", "{status: new|inv|res}", "{modified_count}"],
        ["GET", "/api/stats", "Dashboard statistics", "None", "{total, categories, risks}"],
        ["POST", "/api/ingest/phishing", "Email phishing NLP analysis", "{text: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/sms", "SMS smishing detection", "{text: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/social", "Social media scam detection", "{text: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/impersonation", "Executive impersonation check", "{text: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/url", "Lexical URL analysis", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/website", "Website DOM scraping", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/domain-spoof", "Punycode & homograph check", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/lookalike", "Typosquatting Levenshtein scan", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/ssl-check", "SSL/TLS socket audit", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/url-manipulation", "Encoding & path evasion check", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/redirect-check", "HTTP redirect chain trace", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/fake-login", "Cloned login portal check", "{url: str}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/deepfake", "Synthetic media detection", "Multipart (file)", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/qr", "QR code extraction & scan", "Multipart (file)", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/malware", "PE/binary malware indicator scan", "Multipart (file)", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/network", "Network telemetry analysis", "{connections: [...] }", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/api-abuse", "API client request analysis", "{requests: [...] }", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/exfiltration", "File exfiltration monitoring", "{events: [...] }", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/user-activity", "User activity timeline audit", "{login_events, actions}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/insider-threat", "Insider departure threat check", "{employee, activity}", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/system-behavior", "OS process execution audit", "{events: [...] }", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/account-theft", "Batch login CSV/table audit", "{logs: [...] }", "{score, verdict, indicators}"],
        ["POST", "/api/ingest/email-auth", "SPF/DKIM/DMARC DNS audit", "{domain, ip, selector}", "{score, spf, dkim, dmarc}"],
    ]

    api_table_data = [
        [Paragraph("Method", table_header), Paragraph("Route", table_header), Paragraph("Description", table_header), Paragraph("Payload", table_header)]
    ]
    for row in api_routes:
        api_table_data.append([
            Paragraph(f"<b>{row[0]}</b>", table_cell),
            Paragraph(row[1], table_cell_code),
            Paragraph(row[2], table_cell),
            Paragraph(row[3], table_cell_code),
        ])

    api_table = Table(api_table_data, colWidths=[42, 140, 165, 123])
    api_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0F172A")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(api_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 6: TEAM CONTRIBUTIONS & VERIFICATION
    # =========================================================================
    story.append(Paragraph("6. Engineering Team Contributions & Deliverables", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=10))

    team_data = [
        [Paragraph("Team Member", table_header), Paragraph("Core Responsibility", table_header), Paragraph("Key Module Deliverables", table_header)],
        [
            Paragraph("<b>Manish</b><br/>(Backend Lead & Architect)", table_cell),
            Paragraph("System Architecture, Gateway & Security", table_cell),
            Paragraph("FastAPI gateway (main.py), JWT authentication engine (auth.py), detector routing hub (detectors.py), password reset flow, ScanCenter API wiring, MongoDB Atlas integration.", table_cell)
        ],
        [
            Paragraph("<b>Bibek</b>", table_cell),
            Paragraph("Deepfake & Intelligent Telemetry", table_cell),
            Paragraph("843-line behavioral analyzer (detector.py): malware, network traffic, API abuse, exfiltration, user activity, insider threat, and system behavior. Deepfake computer vision & audio analysis.", table_cell)
        ],
        [
            Paragraph("<b>Niti</b>", table_cell),
            Paragraph("Identity Defense & Anomaly Models", table_cell),
            Paragraph("Account takeover suite: impossible travel geodetic distance algorithms, brute force detection, password spraying, unusual login time, session anomalies, behavior shift models.", table_cell)
        ],
        [
            Paragraph("<b>Chandan</b>", table_cell),
            Paragraph("Phishing & Web Threat Intelligence", table_cell),
            Paragraph("Phishing sub-detectors (SMS, QR, URL, Social, Website) and domain inspection suite (domain spoofing, lookalike Levenshtein matching, SSL checks, redirect unmasking, fake logins).", table_cell)
        ],
        [
            Paragraph("<b>Anisha Sahu</b>", table_cell),
            Paragraph("Frontend Engineering & UI/UX", table_cell),
            Paragraph("React 19 single-page app architecture: Overview SOC dashboard, 6-tab Scan Center, Threat Feed, Alert Detail, Threat Intelligence view, dark Tailwind design, responsive layouts.", table_cell)
        ],
        [
            Paragraph("<b>Chinmay</b>", table_cell),
            Paragraph("Database & Data Persistence", table_cell),
            Paragraph("MongoDB Atlas collection modeling, connection resilience, database schemas for events, alerts, and specialized detection result tables.", table_cell)
        ],
    ]
    team_table = Table(team_data, colWidths=[110, 130, 230])
    team_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0F172A")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.append(team_table)
    story.append(Spacer(1, 16))

    # Concluding sign-off
    signoff = [
        [Paragraph("<b>FINAL VERIFICATION STATUS:</b> All 24 security detection features are fully wired, tested, and operational. The frontend Vite production build has succeeded with 0 errors. The backend FastAPI gateway is fully documented via OpenAPI (Swagger). CyberGuard stands ready for deployment and live demonstration.", callout_style)]
    ]
    signoff_table = Table(signoff, colWidths=[470])
    signoff_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ECFDF5")),
        ('BOX', (0,0), (-1,-1), 1.5, colors.HexColor("#10B981")),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(signoff_table)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully generated: {filename}")

if __name__ == "__main__":
    out_path = os.path.join(r"c:\Git\Documents\Projects\cyberguard", "CyberGuard_Complete_Project_Specification.pdf")
    build_pdf(out_path)
