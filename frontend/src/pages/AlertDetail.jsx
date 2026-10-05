import mockData from "../mockData";

const riskStyles = {
  Safe: {
    badge: "bg-green-500/10 text-green-400 border-green-500/30",
    bar: "bg-green-500",
    label: "Safe",
  },
  Low: {
    badge: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    bar: "bg-blue-500",
    label: "Low",
  },
  Medium: {
    badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    bar: "bg-yellow-500",
    label: "Medium",
  },
  High: {
    badge: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    bar: "bg-orange-500",
    label: "High",
  },
  Critical: {
    badge: "bg-red-500/10 text-red-400 border-red-500/30",
    bar: "bg-red-500",
    label: "Critical",
  },
};

function AlertDetail({ alert }) {
  const data = alert || mockData[0];

  const risk =
    riskStyles[data.overall_risk_level] || {
      badge: "bg-gray-500/10 text-gray-400 border-gray-500/30",
      bar: "bg-gray-500",
      label: data.overall_risk_level || "Unknown",
    };

  const score =
    data.score !== undefined && data.score !== null
      ? Number(data.score)
      : null;

  const formattedDate = data.created_at
    ? new Date(data.created_at).toLocaleString()
    : "Unknown";

  return (
    <div className="min-h-screen bg-gray-950 p-6 md:p-8">
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-3xl">🔎</span>

            <div>
              <h1 className="text-white text-3xl font-bold">
                Alert Detail
              </h1>

              <p className="text-gray-400 mt-1">
                Detailed investigation of a CyberGuard security event
              </p>
            </div>
          </div>
        </div>

        {/* Main Alert Header */}
        <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6 md:p-8 mb-6">

          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">

            <div>
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
                Event ID
              </p>

              <h2 className="text-blue-400 text-xl md:text-2xl font-mono font-bold break-all">
                {data.event_id || "Unknown Event"}
              </h2>

              <p className="text-gray-400 text-sm mt-3">
                Detected: {formattedDate}
              </p>
            </div>

            <div
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border ${risk.badge}`}
            >
              <span className="w-2.5 h-2.5 rounded-full bg-current" />

              <span className="font-bold text-sm">
                {risk.label} Risk
              </span>
            </div>
          </div>

          {/* Category */}
          <div className="border-t border-gray-800 mt-6 pt-6">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-2">
              Threat Category
            </p>

            <p className="text-white text-xl font-semibold capitalize">
              {data.category || "Unknown"}
            </p>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">

          {/* Risk Level */}
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider">
              Risk Level
            </p>

            <p className="text-white text-xl font-bold mt-2">
              {data.overall_risk_level || "Unknown"}
            </p>

            <div className="mt-3 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full ${risk.bar}`}
                style={{
                  width:
                    data.overall_risk_level === "Critical"
                      ? "100%"
                      : data.overall_risk_level === "High"
                      ? "80%"
                      : data.overall_risk_level === "Medium"
                      ? "60%"
                      : data.overall_risk_level === "Low"
                      ? "35%"
                      : "15%",
                }}
              />
            </div>
          </div>

          {/* Verdict */}
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider">
              Verdict
            </p>

            <p className="text-cyan-400 text-xl font-bold mt-2 break-words">
              {data.verdict || "—"}
            </p>
          </div>

          {/* Score */}
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider">
              Risk Score
            </p>

            <p className="text-white text-xl font-bold mt-2">
              {score !== null ? score : "—"}
            </p>

            {score !== null && (
              <p className="text-gray-500 text-xs mt-1">
                AI detection score
              </p>
            )}
          </div>

          {/* Status */}
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
            <p className="text-gray-500 text-xs uppercase tracking-wider">
              Detection Status
            </p>

            <div className="flex items-center gap-2 mt-3">
              <span className="w-2.5 h-2.5 rounded-full bg-green-400" />

              <p className="text-green-400 font-semibold capitalize">
                {data.status || "Detected"}
              </p>
            </div>
          </div>
        </div>

        {/* AI Analysis */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">

          <div className="flex items-center gap-3 mb-4">
            <span className="text-2xl">🤖</span>

            <div>
              <h2 className="text-white text-xl font-semibold">
                AI Threat Analysis
              </h2>

              <p className="text-gray-500 text-sm">
                Analysis generated by CyberGuard
              </p>
            </div>
          </div>

          <div className="bg-gray-950 rounded-xl border border-gray-800 p-5">
            <p className="text-gray-300 leading-relaxed">
              {data.explanation || "No analysis available for this event."}
            </p>
          </div>
        </div>

        {/* Indicators */}
        {data.indicators &&
          data.indicators.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">

              <div className="flex items-center gap-3 mb-4">
                <span className="text-2xl">⚠️</span>

                <div>
                  <h2 className="text-white text-xl font-semibold">
                    Indicators Found
                  </h2>

                  <p className="text-gray-500 text-sm">
                    Suspicious indicators associated with this event
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap gap-3">
                {data.indicators.map((indicator, index) => (
                  <span
                    key={index}
                    className="bg-red-500/10 text-red-300 border border-red-500/30 px-4 py-2 rounded-lg text-sm"
                  >
                    {indicator}
                  </span>
                ))}
              </div>
            </div>
          )}

        {/* Recommended Action */}
        <div className="bg-gray-900 border border-orange-500/20 rounded-2xl p-6 mb-6">

          <div className="flex items-center gap-3 mb-4">
            <span className="text-2xl">🛡️</span>

            <div>
              <h2 className="text-white text-xl font-semibold">
                Recommended Action
              </h2>

              <p className="text-gray-500 text-sm">
                Suggested response based on the detected threat
              </p>
            </div>
          </div>

          <div className="bg-orange-500/5 border border-orange-500/20 rounded-xl p-5">
            <p className="text-orange-200 leading-relaxed">
              {data.recommended_action ||
                "No recommended action available."}
            </p>
          </div>
        </div>

        {/* Investigation Summary */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">

          <div className="flex items-center gap-3 mb-6">
            <span className="text-2xl">📋</span>

            <div>
              <h2 className="text-white text-xl font-semibold">
                Investigation Summary
              </h2>

              <p className="text-gray-500 text-sm">
                Current information available for this security event
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Event ID
              </p>

              <p className="text-blue-400 font-mono text-sm mt-2 break-all">
                {data.event_id || "—"}
              </p>
            </div>

            <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Threat Type
              </p>

              <p className="text-white font-semibold capitalize mt-2">
                {data.category || "—"}
              </p>
            </div>

            <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Verdict
              </p>

              <p className="text-cyan-400 font-semibold mt-2">
                {data.verdict || "—"}
              </p>
            </div>

            <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Detection Score
              </p>

              <p className="text-white font-semibold mt-2">
                {score !== null ? score : "—"}
              </p>
            </div>

            <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Risk Level
              </p>

              <p className="text-white font-semibold mt-2">
                {data.overall_risk_level || "—"}
              </p>
            </div>

            <div className="bg-gray-950 border border-gray-800 rounded-xl p-5">
              <p className="text-gray-500 text-xs uppercase tracking-wider">
                Detected At
              </p>

              <p className="text-gray-300 text-sm mt-2">
                {formattedDate}
              </p>
            </div>
          </div>

          {/* Investigation Note */}
          <div className="mt-6 bg-blue-500/5 border border-blue-500/20 rounded-xl p-5">
            <p className="text-blue-400 text-xs uppercase tracking-wider mb-2">
              Investigation Note
            </p>

            <p className="text-gray-300 leading-relaxed text-sm">
              CyberGuard detected this security event and classified
              it according to the available threat analysis. The
              displayed risk level, verdict, score, and recommended
              action are based on the data currently returned by the
              backend.
            </p>
          </div>

        </div>

      </div>
    </div>
  );
}

export default AlertDetail;