
import mockData from "../mockData";

const riskColors = {
  Safe: "bg-green-500",
  Low: "bg-blue-500",
  Medium: "bg-yellow-500",
  High: "bg-orange-500",
  Critical: "bg-red-600",
};

function AlertDetail({ alert }) {
  const data = alert || mockData[0];

  return (
    <div className="min-h-screen bg-gray-900 p-8">

      {/* Page Title */}
      <h1 className="text-white text-3xl font-bold mb-8">
        Alert Detail
      </h1>

      {/* Main Alert Card */}
      <div className="bg-gray-800 rounded-2xl p-8 shadow-lg border border-gray-700 max-w-4xl mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <p className="text-gray-400 text-sm mb-2">
              Event ID
            </p>

            <h2 className="text-white text-2xl font-bold">
              {data.event_id}
            </h2>
          </div>

          {/* Risk Badge */}
          <span
            className={`${
              riskColors[data.overall_risk_level] || "bg-gray-600"
            } text-white text-sm font-bold px-4 py-2 rounded-full`}
          >
            {data.overall_risk_level}
          </span>
        </div>

        {/* Category */}
        <div className="border-t border-gray-700 pt-6 mb-6">
          <p className="text-gray-400 text-sm mb-2">
            Threat Category
          </p>

          <p className="text-white text-lg font-semibold capitalize">
            {data.category}
          </p>
        </div>

        {/* Explanation */}
        <div className="mb-6">
          <p className="text-gray-400 text-sm mb-2">
            AI Analysis / Explanation
          </p>

          <div className="bg-gray-900 rounded-xl p-4">
            <p className="text-gray-200 leading-relaxed">
              {data.explanation}
            </p>
          </div>
        </div>

        {/* Recommended Action */}
        <div className="mb-6">
          <p className="text-gray-400 text-sm mb-2">
            Recommended Action
          </p>

          <div className="bg-gray-900 rounded-xl p-4 border border-orange-500/20">
            <p className="text-gray-200 leading-relaxed">
              {data.recommended_action}
            </p>
          </div>
        </div>

        {/* Detection Time */}
        <div className="border-t border-gray-700 pt-6 mb-8">
          <p className="text-gray-400 text-sm mb-2">
            Detected At
          </p>

          <p className="text-white">
            {new Date(data.created_at).toLocaleString()}
          </p>
        </div>

        {/* Investigation Summary */}
        <div className="border-t border-gray-700 pt-6">

          <h2 className="text-white text-xl font-semibold mb-6">
            Investigation Summary
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

            {/* Threat Type */}
            <div className="bg-gray-900 rounded-xl p-5">
              <p className="text-gray-400 text-sm mb-2">
                Threat Type
              </p>

              <p className="text-white font-semibold capitalize">
                {data.category}
              </p>
            </div>

            {/* Risk Level */}
            <div className="bg-gray-900 rounded-xl p-5">
              <p className="text-gray-400 text-sm mb-2">
                Risk Level
              </p>

              <p className="text-white font-semibold">
                {data.overall_risk_level}
              </p>
            </div>

            {/* Detection Status */}
            <div className="bg-gray-900 rounded-xl p-5">
              <p className="text-gray-400 text-sm mb-2">
                Detection Status
              </p>

              <p className="text-green-400 font-semibold">
                Detected
              </p>
            </div>

          </div>

          {/* Investigation Note */}
          <div className="bg-gray-900 rounded-xl p-5 mt-4">
            <p className="text-gray-400 text-sm mb-2">
              Investigation Note
            </p>

            <p className="text-gray-300 leading-relaxed">
              CyberGuard analyzed this event and identified the
              threat category and associated risk level. The
              recommended action should be reviewed by the security
              team before taking further action.
            </p>
          </div>

        </div>

      </div>
    </div>
  );
}

export default AlertDetail;
