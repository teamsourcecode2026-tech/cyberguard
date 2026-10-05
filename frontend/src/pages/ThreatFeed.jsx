
import React from "react";

const riskColors = {
  Safe: "bg-green-500",
  Low: "bg-blue-500",
  Medium: "bg-yellow-500",
  High: "bg-orange-500",
  Critical: "bg-red-600",
};

function ThreatFeed({ alerts, onSelect }) {
  const [search, setSearch] = React.useState("");
  const [riskFilter, setRiskFilter] = React.useState("All");
  const [statusFilter, setStatusFilter] = React.useState("All");

  const sorted = [...alerts].sort(
    (a, b) => new Date(b.created_at) - new Date(a.created_at)
  );

  const filteredAlerts = sorted.filter((alert) => {
    const searchText = search.toLowerCase();

    const matchesSearch =
      (alert.event_id || "").toLowerCase().includes(searchText) ||
      (alert.category || "").toLowerCase().includes(searchText) ||
      (alert.explanation || "").toLowerCase().includes(searchText) ||
      (alert.overall_risk_level || "").toLowerCase().includes(searchText);
    const matchesRisk =
  riskFilter === "All" ||
  alert.overall_risk_level === riskFilter;

const matchesStatus =
  statusFilter === "All" ||
  alert.status === statusFilter;

return matchesSearch && matchesRisk && matchesStatus;
  });

  return (
    <div className="min-h-screen bg-gray-900 p-8">
      <h1 className="text-white text-3xl font-bold mb-8">
        Threat Feed
      </h1>

      {/* Search and Filter */}
      <div className="flex flex-col md:flex-row gap-4 mb-6">

        {/* Search */}
        <input
          type="text"
          placeholder="Search threats..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 bg-gray-800 text-white border border-gray-700 rounded-xl px-4 py-3 outline-none focus:border-blue-500"
        />

        {/* Risk Filter */}
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="bg-gray-800 text-white border border-gray-700 rounded-xl px-4 py-3 outline-none focus:border-blue-500"
        >
          <option value="All">All Risk Levels</option>
          <option value="Safe">Safe</option>
          <option value="Low">Low</option>
          <option value="Medium">Medium</option>
          <option value="High">High</option>
          <option value="Critical">Critical</option>
        </select>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-gray-800 text-white border border-gray-700 rounded-xl px-4 py-3 outline-none focus:border-blue-500"
        >
          <option value="All">All Statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>

      </div>

      {/* Threat List */}
      <div className="space-y-4">
        {filteredAlerts.map((alert) => (
          <div
            key={alert.event_id}
            onClick={() => onSelect(alert)}
            className="bg-gray-800 hover:bg-gray-700 cursor-pointer rounded-xl p-5 shadow-lg flex items-center justify-between"
          >
            <div>
              <p className="text-white font-semibold capitalize">
                {alert.category} alert
              </p>

              <p className="text-gray-400 text-sm mt-1">
                {alert.explanation}
              </p>

              <p className="text-gray-500 text-xs mt-1">
                alert.created_at
                  ? new Date(alert.created_at).toLocaleString()
                  : "Unknown"
              </p>
            </div>

            <div className="flex items-center gap-3">
   
              <div className="text-right">
                <p className="text-xs text-gray-400">Status</p>
                <p
                  className={`font-semibold ${
                    alert.status === "resolved"
                      ? "text-green-400"
                      : alert.status === "investigating"
                      ? "text-yellow-400"
                      : "text-red-400"
                   }`}
                 >
                   {alert.status}
                 </p>
               </div>

               <span
                 className={`${riskColors[alert.overall_risk_level] || "bg-gray-600"} text-white text-xs font-bold px-3 py-1 rounded-full`}
              >
                 {alert.overall_risk_level}
              </span>

            </div>
          </div>
        ))}

        {/* No Results */}
        {filteredAlerts.length === 0 && (
          <div className="bg-gray-800 rounded-xl p-8 text-center">
            <p className="text-gray-400">
              No threats found.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatFeed;

