import React from "react";

function ThreatIntelligence({ alert }) {
  const riskLevel = alert?.overall_risk_level || "Unknown";

  const riskStyles = {
    Critical: {
      badge: "bg-red-500/10 text-red-400 border-red-500/30",
      dot: "bg-red-400",
      bar: "bg-red-500",
      width: "100%",
    },
    High: {
      badge: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      dot: "bg-orange-400",
      bar: "bg-orange-500",
      width: "80%",
    },
    Medium: {
      badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
      dot: "bg-yellow-400",
      bar: "bg-yellow-500",
      width: "60%",
    },
    Low: {
      badge: "bg-blue-500/10 text-blue-400 border-blue-500/30",
      dot: "bg-blue-400",
      bar: "bg-blue-500",
      width: "35%",
    },
    Safe: {
      badge: "bg-green-500/10 text-green-400 border-green-500/30",
      dot: "bg-green-400",
      bar: "bg-green-500",
      width: "15%",
    },
    Unknown: {
      badge: "bg-gray-500/10 text-gray-400 border-gray-500/30",
      dot: "bg-gray-400",
      bar: "bg-gray-500",
      width: "10%",
    },
  };

  const risk = riskStyles[riskLevel] || riskStyles.Unknown;

  const score =
    alert?.score !== undefined && alert?.score !== null
      ? Number(alert.score)
      : null;

  const detectedAt = alert?.created_at
    ? new Date(alert.created_at).toLocaleString()
    : "Unknown";

  return (
    <div className="min-h-screen bg-gray-950 p-6 md:p-8">
      <div className="max-w-7xl mx-auto">

        {/* PAGE HEADER */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-3xl">🌐</span>

            <div>
              <h1 className="text-white text-3xl font-bold">
                Threat Intelligence
              </h1>

              <p className="text-gray-400 mt-1">
                Security investigation and threat intelligence workspace
              </p>
            </div>
          </div>
        </div>

        {/* ACTIVE INVESTIGATION */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">

            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Active Investigation
              </p>

              <h2 className="text-white text-2xl font-bold">
                {alert?.event_id || "No alert selected"}
              </h2>

              <p className="text-gray-400 text-sm mt-2">
                Investigating the selected security event and available
                threat intelligence indicators.
              </p>
            </div>

            <div
              className={`border rounded-xl px-5 py-4 ${risk.badge}`}
            >
              <p className="text-xs uppercase tracking-wider opacity-70">
                Risk Level
              </p>

              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`w-2.5 h-2.5 rounded-full ${risk.dot}`}
                />

                <p className="text-xl font-bold">
                  {riskLevel}
                </p>
              </div>
            </div>

          </div>

          {/* Risk bar */}
          <div className="mt-6">
            <div className="flex justify-between mb-2">
              <span className="text-gray-500 text-xs">
                Risk assessment
              </span>

              <span className="text-gray-400 text-xs">
                {score !== null ? `${score}/100` : "Score unavailable"}
              </span>
            </div>

            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full ${risk.bar} transition-all`}
                style={{ width: risk.width }}
              />
            </div>
          </div>
        </div>

        {/* SELECTED ALERT */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

          <div className="flex items-center gap-3 mb-6">
            <span className="text-2xl">🎯</span>

            <div>
              <h3 className="text-white text-xl font-semibold">
                Selected Alert
              </h3>

              <p className="text-gray-500 text-sm">
                Security event information returned by the backend
              </p>
            </div>
          </div>

          {/* Event ID */}
          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5 mb-4">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Event ID
            </p>

            <p className="text-blue-400 font-mono text-sm break-all">
              {alert?.event_id || "No alert selected"}
            </p>
          </div>

          {/* Alert details */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Category
              </p>

              <p className="text-white font-semibold capitalize">
                {alert?.category || "Unknown"}
              </p>
            </div>

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Verdict
              </p>

              <p className="text-cyan-400 font-semibold">
                {alert?.verdict || "—"}
              </p>
            </div>

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Risk Score
              </p>

              <p className="text-white font-semibold">
                {score !== null ? score : "—"}
              </p>
            </div>

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Status
              </p>

              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-400" />

                <p className="text-blue-400 font-semibold capitalize">
                  {alert?.status || "Unknown"}
                </p>
              </div>
            </div>

          </div>
        </div>

        {/* AI ANALYSIS + ACTION */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">

          {/* AI ANALYSIS */}
          <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

            <div className="flex items-center gap-3 mb-5">
              <span className="text-2xl">🧠</span>

              <div>
                <h3 className="text-white text-xl font-semibold">
                  AI Threat Analysis
                </h3>

                <p className="text-gray-500 text-sm">
                  Detection explanation from CyberGuard
                </p>
              </div>
            </div>

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-300 leading-relaxed">
                {alert?.explanation ||
                  "No analysis available for this event."}
              </p>
            </div>
          </div>

          {/* ACTION */}
          <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

            <div className="flex items-center gap-3 mb-5">
              <span className="text-2xl">⚡</span>

              <div>
                <h3 className="text-white text-xl font-semibold">
                  Recommended Action
                </h3>

                <p className="text-gray-500 text-sm">
                  Suggested response from the detection system
                </p>
              </div>
            </div>

            <div className="bg-orange-500/5 rounded-xl border border-orange-500/20 p-5">
              <p className="text-orange-200 leading-relaxed">
                {alert?.recommended_action ||
                  "No recommendation available."}
              </p>
            </div>
          </div>

        </div>

        {/* DETECTION INFORMATION */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

          <div className="flex items-center gap-3 mb-6">
            <span className="text-2xl">🕐</span>

            <div>
              <h3 className="text-white text-xl font-semibold">
                Detection Information
              </h3>

              <p className="text-gray-500 text-sm">
                Event timing and investigation state
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Detected At
              </p>

              <p className="text-gray-300 text-sm">
                {detectedAt}
              </p>
            </div>

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Investigation Status
              </p>

              <p className="text-blue-400 font-semibold capitalize">
                {alert?.status || "Unknown"}
              </p>
            </div>

            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Risk Score
              </p>

              <p className="text-white font-semibold">
                {score !== null ? `${score}/100` : "Unavailable"}
              </p>
            </div>

          </div>
        </div>

        {/* THREAT INTELLIGENCE */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

          <div className="flex items-center gap-3 mb-2">
            <span className="text-2xl">🔬</span>

            <div>
              <h3 className="text-white text-xl font-semibold">
                Threat Intelligence Sources
              </h3>

              <p className="text-gray-500 text-sm">
                External intelligence fields prepared for backend integration
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">

            {/* IP */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <div className="flex items-center gap-2 mb-3">
                <span>🌐</span>

                <p className="text-gray-400 text-sm font-semibold">
                  Source IP
                </p>
              </div>

              <p className="text-gray-600 text-sm">
                Awaiting backend data
              </p>
            </div>

            {/* Domain */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <div className="flex items-center gap-2 mb-3">
                <span>🔗</span>

                <p className="text-gray-400 text-sm font-semibold">
                  Domain
                </p>
              </div>

              <p className="text-gray-600 text-sm">
                Awaiting backend data
              </p>
            </div>

            {/* Geolocation */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <div className="flex items-center gap-2 mb-3">
                <span>📍</span>

                <p className="text-gray-400 text-sm font-semibold">
                  Geolocation
                </p>
              </div>

              <p className="text-gray-600 text-sm">
                Awaiting backend data
              </p>
            </div>

            {/* Reputation */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <div className="flex items-center gap-2 mb-3">
                <span>⭐</span>

                <p className="text-gray-400 text-sm font-semibold">
                  Reputation
                </p>
              </div>

              <p className="text-gray-600 text-sm">
                Awaiting backend data
              </p>
            </div>

          </div>
        </div>

        {/* AUTHENTICATION CHECKS */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

          <div className="flex items-center gap-3 mb-2">
            <span className="text-2xl">🔐</span>

            <div>
              <h3 className="text-white text-xl font-semibold">
                Email Authentication
              </h3>

              <p className="text-gray-500 text-sm">
                SPF, DKIM and DMARC verification
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">

            {/* SPF */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
                SPF
              </p>

              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-gray-500" />

                <p className="text-gray-500 text-sm">
                  Awaiting backend data
                </p>
              </div>
            </div>

            {/* DKIM */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
                DKIM
              </p>

              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-gray-500" />

                <p className="text-gray-500 text-sm">
                  Awaiting backend data
                </p>
              </div>
            </div>

            {/* DMARC */}
            <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
                DMARC
              </p>

              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-gray-500" />

                <p className="text-gray-500 text-sm">
                  Awaiting backend data
                </p>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}

export default ThreatIntelligence;