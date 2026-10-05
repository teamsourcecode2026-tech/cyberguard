
import React from "react";

function ThreatIntelligence({ alert }) {
  const riskLevel = alert?.overall_risk_level || "Unknown";

  const riskStyles = {
    Critical: "bg-red-500/10 text-red-400 border-red-500/30",
    High: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    Medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    Low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    Safe: "bg-green-500/10 text-green-400 border-green-500/30",
    Unknown: "bg-gray-500/10 text-gray-400 border-gray-500/30",
  };

  return (
    <div className="min-h-screen bg-gray-950 p-6 md:p-8">

      {/* Page Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <span className="text-3xl">🛡️</span>

          <h1 className="text-white text-3xl font-bold">
            Threat Intelligence
          </h1>
        </div>

        <p className="text-gray-400">
          Security investigation and threat analysis workspace
        </p>
      </div>

      {/* Investigation Header */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">

          <div>
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Active Investigation
            </p>

            <h2 className="text-white text-xl font-semibold">
              Threat Investigation
            </h2>

            <p className="text-gray-400 text-sm mt-1">
              Analyze the selected security event and its risk indicators.
            </p>
          </div>

          <div
            className={`border rounded-xl px-5 py-3 ${
              riskStyles[riskLevel] || riskStyles.Unknown
            }`}
          >
            <p className="text-xs uppercase tracking-wider opacity-70">
              Risk Level
            </p>

            <p className="text-lg font-bold mt-1">
              {riskLevel}
            </p>
          </div>

        </div>
      </div>

      {/* Selected Alert */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

        <div className="flex items-center gap-3 mb-6">
          <span className="text-xl">🎯</span>

          <div>
            <h3 className="text-white text-lg font-semibold">
              Selected Alert
            </h3>

            <p className="text-gray-500 text-sm">
              Backend event information
            </p>
          </div>
        </div>

        {/* Event ID */}
        <div className="bg-gray-950 rounded-xl border border-gray-800 p-5 mb-4">

          <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
            Event ID
          </p>

          <p className="text-white font-mono text-sm break-all">
            {alert?.event_id || "No alert selected"}
          </p>

        </div>

        {/* Alert Information */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Threat Category
            </p>

            <p className="text-white font-semibold capitalize">
              {alert?.category || "Unknown"}
            </p>
          </div>

          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Risk Level
            </p>

            <p className="font-semibold">
              <span
                className={
                  riskStyles[riskLevel]?.split(" ")[1] ||
                  "text-gray-400"
                }
              >
                {riskLevel}
              </span>
            </p>
          </div>

          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Status
            </p>

            <p className="text-blue-400 font-semibold capitalize">
              {alert?.status || "Unknown"}
            </p>
          </div>

        </div>
      </div>

      {/* AI Analysis + Recommended Action */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">

        {/* AI Analysis */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

          <div className="flex items-center gap-3 mb-5">
            <span className="text-xl">🧠</span>

            <h3 className="text-white text-lg font-semibold">
              AI Threat Analysis
            </h3>
          </div>

          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">

            <p className="text-gray-300 leading-relaxed">
              {alert?.explanation || "No analysis available."}
            </p>

          </div>
        </div>

        {/* Recommended Action */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

          <div className="flex items-center gap-3 mb-5">
            <span className="text-xl">⚡</span>

            <h3 className="text-white text-lg font-semibold">
              Recommended Action
            </h3>
          </div>

          <div className="bg-orange-500/5 rounded-xl border border-orange-500/20 p-5">

            <p className="text-gray-300 leading-relaxed">
              {alert?.recommended_action ||
                "No recommendation available."}
            </p>

          </div>
        </div>

      </div>

      {/* Detection Information */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">

        <div className="flex items-center gap-3 mb-5">
          <span className="text-xl">🕐</span>

          <h3 className="text-white text-lg font-semibold">
            Detection Information
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">

            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Detected At
            </p>

            <p className="text-white">
              {alert?.created_at || "Unknown"}
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

        </div>
      </div>

      {/* Threat Intelligence Sources */}
      <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">

        <div className="flex items-center gap-3 mb-2">
          <span className="text-xl">🌐</span>

          <h3 className="text-white text-lg font-semibold">
            Threat Intelligence Sources
          </h3>
        </div>

        <p className="text-gray-500 text-sm mb-6">
          Additional intelligence will appear here when provided by the backend.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">

          {/* IP */}
          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">

            <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
              Source IP
            </p>

            <p className="text-gray-400 text-sm">
              Awaiting backend data
            </p>

          </div>

          {/* Domain */}
          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">

            <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
              Domain
            </p>

            <p className="text-gray-400 text-sm">
              Awaiting backend data
            </p>

          </div>

          {/* Location */}
          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">

            <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
              Geolocation
            </p>

            <p className="text-gray-400 text-sm">
              Awaiting backend data
            </p>

          </div>

          {/* Reputation */}
          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">

            <p className="text-gray-500 text-xs uppercase tracking-wider mb-3">
              Reputation
            </p>

            <p className="text-gray-400 text-sm">
              Awaiting backend data
            </p>

          </div>

        </div>

      </div>

    </div>
  );
}

export default ThreatIntelligence;