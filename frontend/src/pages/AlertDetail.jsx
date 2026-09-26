import mockData from "../mockData";

const riskColors = {
  Safe: "bg-green-500",
  Low: "bg-blue-500",
  Medium: "bg-yellow-500",
  High: "bg-orange-500",
  Critical: "bg-red-600",
};

function AlertDetail({ alert }) {
  // Fallback to the first mock alert if none is passed in yet
  const data = alert || mockData[0];

  return (
    <div className="min-h-screen bg-gray-900 p-8 flex justify-center">
      <div className="bg-gray-800 rounded-xl p-8 shadow-lg max-w-lg w-full">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-white text-2xl font-bold">{data.event_id}</h1>
          <span
            className={`${
              riskColors[data.overall_risk_level]
            } text-white text-xs font-bold px-3 py-1 rounded-full`}
          >
            {data.overall_risk_level}
          </span>
        </div>

        <p className="text-gray-400 text-sm mb-1">Category</p>
        <p className="text-white mb-4 capitalize">{data.category}</p>

        <p className="text-gray-400 text-sm mb-1">Explanation</p>
        <p className="text-white mb-4">{data.explanation}</p>

        <p className="text-gray-400 text-sm mb-1">Recommended Action</p>
        <p className="text-white mb-4">{data.recommended_action}</p>

        <p className="text-gray-400 text-sm mb-1">Detected At</p>
        <p className="text-white">{new Date(data.created_at).toLocaleString()}</p>
      </div>
    </div>
  );
}

export default AlertDetail;