
import React from "react";

const GROUPS = [
  {
    label: "Phishing & Social Engineering",
    color: "yellow",
    icon: "🎣",
    categories: [
      "phishing",
      "sms_phishing",
      "url_phishing",
      "social_phishing",
      "qr_phishing",
      "website_phishing",
      "lookalike_domain",
      "ssl_domain",
      "url_manipulation",
      "malicious_redirect",
      "fake_login",
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
      "anomaly",
      "account_theft_brute_force",
      "account_theft_impossible_travel",
      "account_theft_new_device_ip",
      "account_theft_password_spraying",
      "account_theft_unusual_login_time",
      "account_theft_session_anomaly",
      "account_theft_behaviour_change",
    ],
  },
  {
    label: "Intelligent Detection",
    color: "cyan",
    icon: "🧠",
    categories: [
      "malware",
      "network_traffic",
      "api_abuse",
      "data_exfiltration",
      "user_activity",
      "insider_threat",
      "system_behavior",
    ],
  },
  {
    label: "Email Authentication",
    color: "green",
    icon: "📧",
    categories: ["email_auth"],
  },
];

const colorClasses = {
  yellow: {
    text: "text-yellow-400",
    bar: "bg-yellow-400",
    border: "border-yellow-500/30",
  },
  red: {
    text: "text-red-400",
    bar: "bg-red-400",
    border: "border-red-500/30",
  },
  purple: {
    text: "text-purple-400",
    bar: "bg-purple-400",
    border: "border-purple-500/30",
  },
  orange: {
    text: "text-orange-400",
    bar: "bg-orange-400",
    border: "border-orange-500/30",
  },
  blue: {
    text: "text-blue-400",
    bar: "bg-blue-400",
    border: "border-blue-500/30",
  },
  cyan: {
    text: "text-cyan-400",
    bar: "bg-cyan-400",
    border: "border-cyan-500/30",
  },
  green: {
    text: "text-green-400",
    bar: "bg-green-400",
    border: "border-green-500/30",
  },
};

function Overview({ alerts = [] }) {
  const total = alerts.length;

  const threatsDetected = alerts.filter((alert) =>
    ["Medium", "High", "Critical"].includes(alert.overall_risk_level)
  ).length;

  const criticalThreats = alerts.filter(
    (alert) => alert.overall_risk_level === "Critical"
  ).length;

  const newIncidents = alerts.filter(
    (alert) => alert.status === "new"
  ).length;

  const groupCounts = GROUPS.map((group) => ({
    ...group,
    count: alerts.filter((alert) =>
      group.categories.includes(alert.category)
    ).length,
  }));

  const riskCounts = {
    Critical: alerts.filter(
      (alert) => alert.overall_risk_level === "Critical"
    ).length,

    High: alerts.filter(
      (alert) => alert.overall_risk_level === "High"
    ).length,

    Medium: alerts.filter(
      (alert) => alert.overall_risk_level === "Medium"
    ).length,

    Low: alerts.filter(
      (alert) => alert.overall_risk_level === "Low"
    ).length,
  };

  const recentAlerts = [...alerts]
    .sort(
      (a, b) =>
        new Date(b.created_at) - new Date(a.created_at)
    )
    .slice(0, 5);

  return (
    <div className="min-h-screen bg-gray-950 p-6 md:p-8">

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <span className="text-3xl">🛡️</span>

          <div>
            <h1 className="text-white text-3xl font-bold">
              Security Overview
            </h1>

            <p className="text-gray-400 mt-1">
              CyberGuard Security Operations Dashboard
            </p>
          </div>
        </div>
      </div>

      {/* KPI CARDS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">

        {/* Total Events */}
        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800 hover:border-blue-500/40 transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Total Events
              </p>

              <p className="text-white text-3xl font-bold mt-2">
                {total}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Events analyzed
              </p>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-3 text-2xl">
              📊
            </div>
          </div>
        </div>

        {/* Threats Detected */}
        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800 hover:border-red-500/40 transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Threats Detected
              </p>

              <p className="text-red-400 text-3xl font-bold mt-2">
                {threatsDetected}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Medium to critical
              </p>
            </div>

            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-3 text-2xl">
              🚨
            </div>
          </div>
        </div>

        {/* Critical Threats */}
        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800 hover:border-orange-500/40 transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Critical Threats
              </p>

              <p className="text-orange-400 text-3xl font-bold mt-2">
                {criticalThreats}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Immediate attention
              </p>
            </div>

            <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-3 text-2xl">
              🔥
            </div>
          </div>
        </div>

        {/* New Incidents */}
        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800 hover:border-yellow-500/40 transition">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                New Incidents
              </p>

              <p className="text-yellow-400 text-3xl font-bold mt-2">
                {newIncidents}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Requires review
              </p>
            </div>

            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3 text-2xl">
              ⚠️
            </div>
          </div>
        </div>

      </div>

      {/* THREAT CATEGORY */}
      <div className="mb-8">

        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-white text-xl font-semibold">
              Threat Distribution
            </h2>

            <p className="text-gray-500 text-sm mt-1">
              Detected threats grouped by security category
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-4">

          {groupCounts.map((group) => (
            <div
              key={group.label}
              className={`bg-gray-900 rounded-2xl p-5 border ${
                colorClasses[group.color].border
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-2xl">
                  {group.icon}
                </span>

                <span
                  className={`text-2xl font-bold ${
                    colorClasses[group.color].text
                  }`}
                >
                  {group.count}
                </span>
              </div>

              <p className="text-gray-400 text-sm mt-4">
                {group.label}
              </p>

              <div className="w-full bg-gray-800 rounded-full h-2 mt-4">
                <div
                  className={`${
                    colorClasses[group.color].bar
                  } h-2 rounded-full`}
                  style={{
                    width: `${
                      total > 0
                        ? Math.min(
                            (group.count / total) * 100,
                            100
                          )
                        : 0
                    }%`,
                  }}
                />
              </div>
            </div>
          ))}

        </div>
      </div>

      {/* RISK OVERVIEW */}
      <div className="mb-8">

        <div className="mb-4">
          <h2 className="text-white text-xl font-semibold">
            Security Risk Overview
          </h2>

          <p className="text-gray-500 text-sm mt-1">
            Current distribution of detected risk levels
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

          {/* Critical */}
          <div className="bg-gray-900 rounded-2xl p-5 border border-red-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm">
                  Critical Risk
                </p>

                <p className="text-red-400 text-3xl font-bold mt-2">
                  {riskCounts.Critical}
                </p>
              </div>

              <span className="text-2xl">🔴</span>
            </div>
          </div>

          {/* High */}
          <div className="bg-gray-900 rounded-2xl p-5 border border-orange-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm">
                  High Risk
                </p>

                <p className="text-orange-400 text-3xl font-bold mt-2">
                  {riskCounts.High}
                </p>
              </div>

              <span className="text-2xl">🟠</span>
            </div>
          </div>

          {/* Medium */}
          <div className="bg-gray-900 rounded-2xl p-5 border border-yellow-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm">
                  Medium Risk
                </p>

                <p className="text-yellow-400 text-3xl font-bold mt-2">
                  {riskCounts.Medium}
                </p>
              </div>

              <span className="text-2xl">🟡</span>
            </div>
          </div>

          {/* Low */}
          <div className="bg-gray-900 rounded-2xl p-5 border border-green-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-500 text-sm">
                  Low Risk
                </p>

                <p className="text-green-400 text-3xl font-bold mt-2">
                  {riskCounts.Low}
                </p>
              </div>

              <span className="text-2xl">🟢</span>
            </div>
          </div>

        </div>
      </div>

      {/* THREAT ACTIVITY */}
      <div className="mb-8">

        <div className="mb-4">
          <h2 className="text-white text-xl font-semibold">
            Threat Activity
          </h2>

          <p className="text-gray-500 text-sm mt-1">
            Activity across CyberGuard detection modules
          </p>
        </div>

        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">

          <div className="space-y-6">

            {groupCounts.map((group) => (
              <div key={group.label}>

                <div className="flex items-center justify-between mb-2">
                  <span className="text-gray-300 text-sm">
                    {group.icon} {group.label}
                  </span>

                  <span
                    className={`font-semibold ${
                      colorClasses[group.color].text
                    }`}
                  >
                    {group.count}
                  </span>
                </div>

                <div className="w-full bg-gray-800 rounded-full h-3">

                  <div
                    className={`${
                      colorClasses[group.color].bar
                    } h-3 rounded-full transition-all duration-500`}
                    style={{
                      width: `${
                        total > 0
                          ? Math.min(
                              (group.count / total) * 100,
                              100
                            )
                          : 0
                      }%`,
                    }}
                  />

                </div>

              </div>
            ))}

          </div>

        </div>
      </div>

      {/* RECENT SECURITY ALERTS */}
      <div className="mb-8">

        <div className="mb-4">
          <h2 className="text-white text-xl font-semibold">
            Recent Security Alerts
          </h2>

          <p className="text-gray-500 text-sm mt-1">
            Latest events detected by CyberGuard
          </p>
        </div>

        <div className="bg-gray-900 rounded-2xl border border-gray-800 overflow-hidden">

          {/* Desktop Header */}
          <div className="hidden md:grid grid-cols-6 gap-4 px-6 py-4 bg-gray-950 border-b border-gray-800 text-gray-500 text-xs uppercase tracking-wider">

            <span>Event ID</span>
            <span>Category</span>
            <span>Risk</span>
            <span>Verdict</span>
            <span>Score</span>
            <span>Action</span>

          </div>

          {/* Alerts */}
          {recentAlerts.map((alert, index) => {

            const riskClass =
              alert.overall_risk_level === "Critical"
                ? "text-red-400"
                : alert.overall_risk_level === "High"
                ? "text-orange-400"
                : alert.overall_risk_level === "Medium"
                ? "text-yellow-400"
                : alert.overall_risk_level === "Low"
                ? "text-green-400"
                : "text-gray-400";

            return (
              <div
                key={alert.event_id || index}
                className="px-6 py-5 border-b border-gray-800 last:border-b-0"
              >

                {/* Mobile */}
                <div className="md:hidden space-y-3">

                  <div className="flex items-center justify-between">
                    <span className="text-blue-400 font-medium text-sm">
                      {alert.event_id || "-"}
                    </span>

                    <span className={`${riskClass} font-semibold`}>
                      {alert.overall_risk_level || "-"}
                    </span>
                  </div>

                  <div>
                    <p className="text-gray-500 text-xs">
                      Category
                    </p>

                    <p className="text-gray-300 capitalize">
                      {alert.category || "-"}
                    </p>
                  </div>

                  <div>
                    <p className="text-gray-500 text-xs">
                      Verdict
                    </p>

                    <p className="text-cyan-400">
                      {alert.verdict || "-"}
                    </p>
                  </div>

                  <div>
                    <p className="text-gray-500 text-xs">
                      Score
                    </p>

                    <p className="text-white font-semibold">
                      {alert.score ?? "-"}
                    </p>
                  </div>

                  <div>
                    <p className="text-gray-500 text-xs">
                      Recommended Action
                    </p>

                    <p className="text-gray-300">
                      {alert.recommended_action || "-"}
                    </p>
                  </div>

                </div>

                {/* Desktop */}
                <div className="hidden md:grid grid-cols-6 gap-4 items-center text-sm">

                  <span className="text-blue-400 font-medium break-all">
                    {alert.event_id || "-"}
                  </span>

                  <span className="text-gray-300 capitalize">
                    {alert.category || "-"}
                  </span>

                  <span className={`${riskClass} font-semibold`}>
                    {alert.overall_risk_level || "-"}
                  </span>

                  <span className="text-cyan-400">
                    {alert.verdict || "-"}
                  </span>

                  <span className="text-white font-semibold">
                    {alert.score ?? "-"}
                  </span>

                  <span className="text-gray-300">
                    {alert.recommended_action || "-"}
                  </span>

                </div>

              </div>
            );
          })}

          {/* Empty State */}
          {recentAlerts.length === 0 && (
            <div className="p-10 text-center">

              <div className="text-4xl mb-3">
                🛡️
              </div>

              <p className="text-gray-400">
                No security alerts available.
              </p>

              <p className="text-gray-600 text-sm mt-1">
                CyberGuard will display detected events here.
              </p>

            </div>
          )}

        </div>
      </div>

      {/* SYSTEM STATUS */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

        <div className="flex items-center gap-3 mb-5">
          <span className="text-xl">⚙️</span>

          <div>
            <h2 className="text-white text-lg font-semibold">
              CyberGuard Detection Status
            </h2>

            <p className="text-gray-500 text-sm">
              Security detection modules currently represented in the dashboard
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-4">

          {GROUPS.map((group) => (
            <div
              key={group.label}
              className="bg-gray-950 rounded-xl border border-gray-800 p-4"
            >
              <div className="flex items-center gap-3">

                <span className="text-xl">
                  {group.icon}
                </span>

                <div>
                  <p className="text-gray-300 text-sm font-medium">
                    {group.label}
                  </p>

                  <p
                    className={`text-xs mt-1 ${
                      colorClasses[group.color].text
                    }`}
                  >
                    {groupCounts.find(
                      (item) => item.label === group.label
                    )?.count || 0}{" "}
                    detected
                  </p>
                </div>

              </div>
            </div>
          ))}

        </div>

      </div>

    </div>
  );
}

export default Overview;

