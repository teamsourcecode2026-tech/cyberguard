const mockData = [
  {
    event_id: "EVT-001",
    category: "phishing",
    overall_risk_level: "High",
    score: 84,
    verdict: "Phishing Attempt",
    source_ip: "185.220.101.5",
    domain: "security-verify-portal.net",
    geolocation: "Frankfurt, Germany",
    reputation: "Malicious (Known Phishing Host)",
    indicators: [
      "🔴 SPF check failed: Sender IP 185.220.101.5 is NOT authorized by domain SPF record",
      "⚠️ No DKIM signature found in email headers (cannot verify origin authenticity)",
      "🟡 DMARC policy is 'none' — domain does not protect against address spoofing",
      "🚨 High urgency keywords: 'Immediate action required', 'Account suspended in 2 hours'",
      "🔗 Suspicious redirect link leading to unverified external domain"
    ],
    spf: {
      result: "fail",
      record: "v=spf1 include:_spf.security-verify-portal.net -all",
      details: "Sender IP 185.220.101.5 is NOT authorized and domain uses strict -all policy"
    },
    dkim: {
      result: "none",
      record: "",
      details: "No DKIM record found for security-verify-portal.net (tried selectors: default, s1, mail)"
    },
    dmarc: {
      result: "fail",
      policy: "none",
      record: "v=DMARC1; p=none; rua=mailto:dmarc-reports@security-verify-portal.net",
      details: "DMARC policy is 'none' — monitoring only, no protection against spoofing"
    },
    explanation: "Email contained urgent language, forged sender headers, and a mismatched domain with failing SPF verification.",
    recommended_action: "Block sender domain and alert affected user.",
    status: "new",
    created_at: "2026-09-26T09:15:00Z",
  },
  {
    event_id: "EVT-002",
    category: "deepfake",
    overall_risk_level: "Critical",
    score: 94,
    verdict: "Synthesized Media Detected",
    source_ip: "45.154.255.89",
    domain: "cdn-media-upload.org",
    geolocation: "Bucharest, Romania",
    reputation: "High Risk (Unverified Proxy)",
    indicators: [
      "🎭 Facial landmark temporal inconsistency score: 94/100",
      "👁️ Unnatural blink rate and erratic eye reflection patterns detected",
      "🔊 Audio-visual phoneme desynchronization in video track (offset: 140ms)",
      "⚠️ Synthetic frequency artifacts present in high-frequency spectral bands"
    ],
    explanation: "Video media showed unnatural facial micro-expressions, artificial edge blurring, and audio-lip synchronization mismatch.",
    recommended_action: "Escalate to security team immediately and quarantine media asset.",
    status: "new",
    created_at: "2026-09-26T09:40:00Z",
  },
  {
    event_id: "EVT-003",
    category: "anomaly",
    overall_risk_level: "Medium",
    score: 62,
    verdict: "Suspicious Account Access",
    source_ip: "103.251.167.22",
    domain: "auth.corp-internal.net",
    geolocation: "Singapore (APNIC)",
    reputation: "Suspicious (Multiple Failed Logins)",
    indicators: [
      "📍 Geo-velocity anomaly: Previous login from New York, US 42 minutes ago",
      "🔑 3 consecutive failed authentication attempts preceding successful token issue",
      "💻 Unrecognized User-Agent and TLS fingerprint (JA3 hash mismatch)"
    ],
    explanation: "Login attempt from a geographically distant device with 3 prior failed attempts within an impossible travel window.",
    recommended_action: "Prompt user for two-factor verification and revoke existing session tokens.",
    status: "investigating",
    created_at: "2026-09-26T10:02:00Z",
  },
  {
    event_id: "EVT-004",
    category: "phishing",
    overall_risk_level: "Low",
    score: 18,
    verdict: "Legitimate Communication",
    source_ip: "209.85.220.41",
    domain: "updates.google.com",
    geolocation: "Mountain View, CA, United States",
    reputation: "Clean (Verified Organization)",
    indicators: [
      "✅ SPF check passed: IP 209.85.220.41 is authorized by google.com SPF record",
      "✅ DKIM signature valid and cryptographically verified (selector: 20230601)",
      "✅ DMARC policy is 'reject' and alignment passed",
      "ℹ️ Generic promotional newsletter layout detected"
    ],
    spf: {
      result: "pass",
      record: "v=spf1 include:_netblocks.google.com -all",
      details: "Sender IP 209.85.220.41 is authorized by SPF record"
    },
    dkim: {
      result: "pass",
      record: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",
      details: "DKIM public key found and verified"
    },
    dmarc: {
      result: "pass",
      policy: "reject",
      record: "v=DMARC1; p=reject; sp=reject; rua=mailto:mailauth-reports@google.com",
      details: "DMARC policy is 'reject' — strongest protection against spoofing"
    },
    explanation: "Message flagged for promotional keywords but all cryptographic email authentication checks passed.",
    recommended_action: "No action needed, monitor only.",
    status: "resolved",
    created_at: "2026-09-26T10:20:00Z",
  },
  {
    event_id: "EVT-005",
    category: "anomaly",
    overall_risk_level: "Safe",
    score: 5,
    verdict: "Normal Activity",
    source_ip: "192.168.1.102",
    domain: "gateway.internal",
    geolocation: "Internal Network (LAN)",
    reputation: "Clean / Trusted Corporate Asset",
    indicators: [
      "✅ Known enterprise device certificate present",
      "✅ Standard login hour within defined employee profile baseline",
      "✅ Location matches registered corporate headquarters subnet"
    ],
    explanation: "User login event strictly matched normal behavioral baseline and known device fingerprint.",
    recommended_action: "No action needed.",
    status: "resolved",
    created_at: "2026-09-26T10:45:00Z",
  },
];

export default mockData;