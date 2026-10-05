const GROUPS = [
  {
    label: "Phishing & Social Engineering",
    color: "yellow",
    icon: "🎣",
    categories: [
      "phishing", "sms_phishing", "url_phishing",
      "social_phishing", "qr_phishing", "website_phishing",
      "lookalike_domain", "ssl_domain", "url_manipulation",
      "malicious_redirect", "fake_login",
    ],
  },
  {
    label: "Deepfake",
    color: "red",
    icon: "🎭",
    categories: ["deepfake"],
  },
  {
    label: "Impersonation",
    color: "purple",
    icon: "🕵️",
    categories: ["impersonation"],
  },
  {
    label: "Malicious URL & Website",
    color: "orange",
    icon: "🔗",
    categories: ["domain_spoofing"],
  },
  {
    label: "Account Takeover & Anomaly",
    color: "blue",
    icon: "🔑",
    categories: [
      "anomaly", "account_theft_brute_force", "account_theft_impossible_travel",
      "account_theft_new_device_ip", "account_theft_password_spraying",
      "account_theft_unusual_login_time", "account_theft_session_anomaly",
      "account_theft_behaviour_change",
    ],
  },
];

const colorClasses = {
  yellow: { text: "text-yellow-400", bar: "bg-yellow-400" },
  red: { text: "text-red-400", bar: "bg-red-400" },
  purple: { text: "text-purple-400", bar: "bg-purple-400" },
  orange: { text: "text-orange-400", bar: "bg-orange-400" },
  blue: { text: "text-blue-400", bar: "bg-blue-400" },
};

function Overview({ alerts }) {
  const total = alerts.length;

  const groupCounts = GROUPS.map((g) => ({
    ...g,
    count: alerts.filter((a) => g.categories.includes(a.category)).length,
  }));

  const threatsDetected = alerts.filter((a) =>
    ["Medium", "High", "Critical"].includes(a.overall_risk_level)
  ).length;

  const newIncidents = alerts.filter((a) => a.status === "new").length;

  return (
    <div className="min-h-screen bg-gray-900 p-8">

      <h1 className="text-white text-3xl font-bold mb-8">Overview</h1>

      {/* Main KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700 hover:border-blue-400 transition-all duration-300">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">Total Events</p>
              <p className="text-white text-3xl font-bold mt-2">{total}</p>
              <p className="text-gray-500 text-xs mt-2">Events analyzed by CyberGuard</p>
            </div>
            <div className="bg-blue-500/20 p-3 rounded-xl text-2xl">🛡️</div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700 hover:border-red-400 transition-all duration-300">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">Threats Detected</p>
              <p className="text-red-400 text-3xl font-bold mt-2">{threatsDetected}</p>
              <p className="text-gray-500 text-xs mt-2">Medium to critical risk events</p>
            </div>
            <div className="bg-red-500/20 p-3 rounded-xl text-2xl">🚨</div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700 hover:border-orange-400 transition-all duration-300">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">New Incidents</p>
              <p className="text-orange-400 text-3xl font-bold mt-2">{newIncidents}</p>
              <p className="text-gray-500 text-xs mt-2">Requires security review</p>
            </div>
            <div className="bg-orange-500/20 p-3 rounded-xl text-2xl">⚠️</div>
          </div>
        </div>
      </div>

      {/* Threat Category Summary (grouped) */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {groupCounts.map((g) => (
          <div key={g.label} className="bg-gray-800 rounded-xl p-5 shadow-lg">
            <p className="text-2xl mb-1">{g.icon}</p>
            <p className="text-gray-400 text-xs">{g.label}</p>
            <p className={`${colorClasses[g.color].text} text-2xl font-bold mt-1`}>
              {g.count}
            </p>
          </div>
        ))}
      </div>

      {/* Security Risk Overview */}
      <div className="mt-8">
        <h2 className="text-white text-xl font-semibold mb-4">Security Risk Overview</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-800 rounded-xl p-5 border border-red-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Critical Risk</p>
                <p className="text-red-400 text-2xl font-bold mt-2">
                  {alerts.filter((a) => a.overall_risk_level === "Critical").length}
                </p>
              </div>
              <span className="text-2xl">🔴</span>
            </div>
          </div>

          <div className="bg-gray-800 rounded-xl p-5 border border-orange-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">High Risk</p>
                <p className="text-orange-400 text-2xl font-bold mt-2">
                  {alerts.filter((a) => a.overall_risk_level === "High").length}
                </p>
              </div>
              <span className="text-2xl">🟠</span>
            </div>
          </div>

          <div className="bg-gray-800 rounded-xl p-5 border border-yellow-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Medium Risk</p>
                <p className="text-yellow-400 text-2xl font-bold mt-2">
                  {alerts.filter((a) => a.overall_risk_level === "Medium").length}
                </p>
              </div>
              <span className="text-2xl">🟡</span>
            </div>
          </div>

          <div className="bg-gray-800 rounded-xl p-5 border border-green-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Low Risk</p>
                <p className="text-green-400 text-2xl font-bold mt-2">
                  {alerts.filter((a) => a.overall_risk_level === "Low").length}
                </p>
              </div>
              <span className="text-2xl">🟢</span>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Activity (grouped bars) */}
      <div className="mt-8">
        <h2 className="text-white text-xl font-semibold mb-4">Threat Activity</h2>
        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700">
          {groupCounts.map((g, i) => (
            <div key={g.label} className={i !== groupCounts.length - 1 ? "mb-6" : ""}>
              <div className="flex justify-between mb-2">
                <span className="text-gray-300">{g.icon} {g.label}</span>
                <span className={`${colorClasses[g.color].text} font-semibold`}>
                  {g.count}
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3">
                <div
                  className={`${colorClasses[g.color].bar} h-3 rounded-full`}
                  style={{ width: `${Math.min(g.count * 10, 100)}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Security Alerts */}
      <div className="mt-8">
        <h2 className="text-white text-xl font-semibold mb-4">Recent Security Alerts</h2>
        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700">

          <div className="grid grid-cols-6 gap-4 text-gray-400 text-sm font-semibold border-b border-gray-700 pb-3">
            <span>Event ID</span>
            <span>Category</span>
            <span>Risk</span>
            <span>Verdict</span>
            <span>Score</span>
            <span>Action</span>
          </div>

          {[...alerts]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 5)
            .map((alert, index) => (
              <div
                key={alert.event_id || index}
                className="grid grid-cols-6 gap-4 text-gray-300 text-sm py-4 border-b border-gray-700 last:border-b-0"
              >
                <span className="text-blue-400 font-medium">{alert.event_id}</span>
                <span className="capitalize">{alert.category}</span>
                <span
                  className={
                    alert.overall_risk_level === "Critical" ? "text-red-400 font-semibold"
                    : alert.overall_risk_level === "High" ? "text-orange-400 font-semibold"
                    : alert.overall_risk_level === "Medium" ? "text-yellow-400 font-semibold"
                    : alert.overall_risk_level === "Low" ? "text-green-400"
                    : "text-gray-400"
                  }
                >
                  {alert.overall_risk_level}
                </span>
                <span className="text-cyan-400 font-medium">
                  {alert.verdict || "-"}
                </span>
                <span className="text-white font-semibold">
                  {alert.score ?? "-"}
                </span>
                <span className="text-gray-300">
                  {alert.recommended_action}
                </span>
              </div>
            ))}

          {alerts.length === 0 && (
            <p className="text-gray-500 text-sm py-4">No security alerts available.</p>
          )}
        </div>
      </div>

    </div>
  );
}

export default Overview;