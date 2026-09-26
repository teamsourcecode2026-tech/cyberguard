const mockData = [
  {
    event_id: "EVT-001",
    category: "phishing",
    overall_risk_level: "High",
    explanation: "Email contained urgent language and a mismatched sender domain.",
    recommended_action: "Block sender and alert affected user.",
    created_at: "2026-09-26T09:15:00Z",
  },
  {
    event_id: "EVT-002",
    category: "deepfake",
    overall_risk_level: "Critical",
    explanation: "Video showed unnatural blinking and audio-lip mismatch.",
    recommended_action: "Escalate to security team immediately.",
    created_at: "2026-09-26T09:40:00Z",
  },
  {
    event_id: "EVT-003",
    category: "anomaly",
    overall_risk_level: "Medium",
    explanation: "Login attempt from a new device with 3 failed attempts.",
    recommended_action: "Prompt user for two-factor verification.",
    created_at: "2026-09-26T10:02:00Z",
  },
  {
    event_id: "EVT-004",
    category: "phishing",
    overall_risk_level: "Low",
    explanation: "Message flagged for generic marketing language, likely safe.",
    recommended_action: "No action needed, monitor only.",
    created_at: "2026-09-26T10:20:00Z",
  },
  {
    event_id: "EVT-005",
    category: "anomaly",
    overall_risk_level: "Safe",
    explanation: "Login matched normal user behavior pattern.",
    recommended_action: "No action needed.",
    created_at: "2026-09-26T10:45:00Z",
  },
];

export default mockData;