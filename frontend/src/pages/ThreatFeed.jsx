const riskColors = {
  Safe: "bg-green-500",
  Low: "bg-blue-500",
  Medium: "bg-yellow-500",
  High: "bg-orange-500",
  Critical: "bg-red-600",
};

function ThreatFeed({ alerts, onSelect }) {
  const sorted = [...alerts].sort(
    (a, b) => new Date(b.created_at) - new Date(a.created_at)
  );

  return (
    <div className="min-h-screen bg-gray-900 p-8">
      <h1 className="text-white text-3xl font-bold mb-8">Threat Feed</h1>

      <div className="space-y-4">
        {sorted.map((alert) => (
          <div
            key={alert.event_id}
            onClick={() => onSelect(alert)}
            className="bg-gray-800 hover:bg-gray-700 cursor-pointer rounded-xl p-5 shadow-lg flex items-center justify-between"
          >
            <div>
              <p className="text-white font-semibold capitalize">
                {alert.category} alert
              </p>
              <p className="text-gray-400 text-sm mt-1">{alert.explanation}</p>
              <p className="text-gray-500 text-xs mt-1">
                {new Date(alert.created_at).toLocaleString()}
              </p>
            </div>
            <span
              className={`${
                riskColors[alert.overall_risk_level]
              } text-white text-xs font-bold px-3 py-1 rounded-full`}
            >
              {alert.overall_risk_level}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default ThreatFeed;