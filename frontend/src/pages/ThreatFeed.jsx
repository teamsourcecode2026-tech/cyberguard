
import React from "react";

const riskStyles = {
  Safe: {
    badge: "bg-green-500/10 text-green-400 border-green-500/30",
    dot: "bg-green-400",
  },
  Low: {
    badge: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    dot: "bg-blue-400",
  },
  Medium: {
    badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    dot: "bg-yellow-400",
  },
  High: {
    badge: "bg-orange-500/10 text-orange-400 border-orange-500/30",
    dot: "bg-orange-400",
  },
  Critical: {
    badge: "bg-red-500/10 text-red-400 border-red-500/30",
    dot: "bg-red-400",
  },
};

function ThreatFeed({ alerts = [], onSelect }) {
  const [search, setSearch] = React.useState("");
  const [riskFilter, setRiskFilter] = React.useState("All");
  const [categoryFilter, setCategoryFilter] = React.useState("All");

  /* -----------------------------------------
     SORT ALERTS
  ----------------------------------------- */

  const sortedAlerts = [...alerts].sort(
    (a, b) =>
      new Date(b.created_at) -
      new Date(a.created_at)
  );

  /* -----------------------------------------
     CATEGORY LIST
  ----------------------------------------- */

  const categories = [
    ...new Set(
      alerts
        .map((alert) => alert.category)
        .filter(Boolean)
    ),
  ];

  /* -----------------------------------------
     FILTER ALERTS
  ----------------------------------------- */

  const filteredAlerts = sortedAlerts.filter((alert) => {
    const searchText = search.toLowerCase().trim();

    const searchableText = [
      alert.event_id,
      alert.category,
      alert.explanation,
      alert.overall_risk_level,
      alert.verdict,
      alert.recommended_action,
      alert.status,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    const matchesSearch =
      searchText === "" ||
      searchableText.includes(searchText);

    const matchesRisk =
      riskFilter === "All" ||
      alert.overall_risk_level === riskFilter;

    const matchesCategory =
      categoryFilter === "All" ||
      alert.category === categoryFilter;

    return (
      matchesSearch &&
      matchesRisk &&
      matchesCategory
    );
  });

  /* -----------------------------------------
     COUNTS
  ----------------------------------------- */

  const criticalCount = alerts.filter(
    (alert) =>
      alert.overall_risk_level === "Critical"
  ).length;

  const highCount = alerts.filter(
    (alert) =>
      alert.overall_risk_level === "High"
  ).length;

  const mediumCount = alerts.filter(
    (alert) =>
      alert.overall_risk_level === "Medium"
  ).length;

  const newCount = alerts.filter(
    (alert) => alert.status === "new"
  ).length;

  return (
    <div className="min-h-screen bg-gray-950 p-6 md:p-8">

      {/* -----------------------------------------
          HEADER
      ----------------------------------------- */}

      <div className="mb-8">

        <div className="flex items-center gap-3 mb-2">

          <span className="text-3xl">
            🚨
          </span>

          <div>
            <h1 className="text-white text-3xl font-bold">
              Threat Feed
            </h1>

            <p className="text-gray-400 mt-1">
              Real-time security events detected by CyberGuard
            </p>
          </div>

        </div>

      </div>

      {/* -----------------------------------------
          THREAT SUMMARY
      ----------------------------------------- */}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">

        {/* Critical */}
        <div className="bg-gray-900 rounded-2xl border border-red-500/20 p-5">

          <p className="text-gray-500 text-xs uppercase tracking-wider">
            Critical
          </p>

          <p className="text-red-400 text-2xl font-bold mt-2">
            {criticalCount}
          </p>

          <p className="text-gray-600 text-xs mt-1">
            Immediate attention
          </p>

        </div>

        {/* High */}
        <div className="bg-gray-900 rounded-2xl border border-orange-500/20 p-5">

          <p className="text-gray-500 text-xs uppercase tracking-wider">
            High
          </p>

          <p className="text-orange-400 text-2xl font-bold mt-2">
            {highCount}
          </p>

          <p className="text-gray-600 text-xs mt-1">
            High priority
          </p>

        </div>

        {/* Medium */}
        <div className="bg-gray-900 rounded-2xl border border-yellow-500/20 p-5">

          <p className="text-gray-500 text-xs uppercase tracking-wider">
            Medium
          </p>

          <p className="text-yellow-400 text-2xl font-bold mt-2">
            {mediumCount}
          </p>

          <p className="text-gray-600 text-xs mt-1">
            Monitor closely
          </p>

        </div>

        {/* New */}
        <div className="bg-gray-900 rounded-2xl border border-blue-500/20 p-5">

          <p className="text-gray-500 text-xs uppercase tracking-wider">
            New Incidents
          </p>

          <p className="text-blue-400 text-2xl font-bold mt-2">
            {newCount}
          </p>

          <p className="text-gray-600 text-xs mt-1">
            Awaiting review
          </p>

        </div>

      </div>

      {/* -----------------------------------------
          SEARCH + FILTERS
      ----------------------------------------- */}

      <div className="bg-gray-900 rounded-2xl border border-gray-800 p-5 mb-6">

        <div className="flex flex-col lg:flex-row gap-4">

          {/* Search */}

          <div className="flex-1 relative">

            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500">
              🔍
            </span>

            <input
              type="text"
              placeholder="Search event ID, category, verdict, risk..."
              value={search}
              onChange={(e) =>
                setSearch(e.target.value)
              }
              className="w-full bg-gray-950 text-white border border-gray-800 rounded-xl pl-11 pr-4 py-3 outline-none focus:border-blue-500 transition"
            />

          </div>

          {/* Risk */}

          <select
            value={riskFilter}
            onChange={(e) =>
              setRiskFilter(e.target.value)
            }
            className="bg-gray-950 text-white border border-gray-800 rounded-xl px-4 py-3 outline-none focus:border-blue-500"
          >
            <option value="All">
              All Risk Levels
            </option>

            <option value="Critical">
              Critical
            </option>

            <option value="High">
              High
            </option>

            <option value="Medium">
              Medium
            </option>

            <option value="Low">
              Low
            </option>

            <option value="Safe">
              Safe
            </option>
          </select>

          {/* Category */}

          <select
            value={categoryFilter}
            onChange={(e) =>
              setCategoryFilter(e.target.value)
            }
            className="bg-gray-950 text-white border border-gray-800 rounded-xl px-4 py-3 outline-none focus:border-blue-500"
          >

            <option value="All">
              All Categories
            </option>

            {categories.map((category) => (
              <option
                key={category}
                value={category}
              >
                {category}
              </option>
            ))}

          </select>

        </div>

        {/* Result count */}

        <div className="mt-4 flex items-center justify-between">

          <p className="text-gray-500 text-sm">
            Showing{" "}
            <span className="text-gray-300 font-medium">
              {filteredAlerts.length}
            </span>{" "}
            of{" "}
            <span className="text-gray-300 font-medium">
              {alerts.length}
            </span>{" "}
            security events
          </p>

          {(search ||
            riskFilter !== "All" ||
            categoryFilter !== "All") && (
            <button
              type="button"
              onClick={() => {
                setSearch("");
                setRiskFilter("All");
                setCategoryFilter("All");
              }}
              className="text-blue-400 text-sm hover:text-blue-300"
            >
              Clear filters
            </button>
          )}

        </div>

      </div>

      {/* -----------------------------------------
          THREAT LIST
      ----------------------------------------- */}

      <div className="space-y-4">

        {filteredAlerts.map((alert, index) => {

          const risk =
            riskStyles[
              alert.overall_risk_level
            ] || {
              badge:
                "bg-gray-500/10 text-gray-400 border-gray-500/30",
              dot: "bg-gray-400",
            };

          return (
            <div
              key={
                alert.event_id ||
                index
              }
              onClick={() =>
                onSelect(alert)
              }
              className="group bg-gray-900 border border-gray-800 hover:border-gray-600 rounded-2xl p-5 cursor-pointer transition-all duration-200 hover:bg-gray-900/80"
            >

              {/* Top row */}

              <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">

                <div className="flex-1 min-w-0">

                  <div className="flex flex-wrap items-center gap-3 mb-3">

                    {/* Risk */}

                    <span
                      className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-semibold ${risk.badge}`}
                    >

                      <span
                        className={`w-2 h-2 rounded-full ${risk.dot}`}
                      />

                      {alert.overall_risk_level ||
                        "Unknown"}

                    </span>

                    {/* Category */}

                    <span className="text-gray-300 text-sm font-semibold capitalize">
                      {alert.category ||
                        "Unknown"}{" "}
                      Alert
                    </span>

                    {/* Status */}

                    {alert.status && (
                      <span className="px-2.5 py-1 rounded-md bg-gray-800 text-gray-400 text-xs capitalize">
                        {alert.status}
                      </span>
                    )}

                  </div>

                  {/* Event ID */}

                  <p className="text-blue-400 font-mono text-sm break-all">
                    {alert.event_id ||
                      "Unknown Event"}
                  </p>

                  {/* Explanation */}

                  <p className="text-gray-400 text-sm leading-relaxed mt-3">
                    {alert.explanation ||
                      "No explanation available."}
                  </p>

                </div>

                {/* Arrow */}

                <div className="text-gray-600 group-hover:text-blue-400 transition text-xl">
                  →
                </div>

              </div>

              {/* Bottom information */}

              <div className="mt-5 pt-4 border-t border-gray-800 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

                {/* Time */}

                <div>

                  <p className="text-gray-600 text-xs uppercase tracking-wider">
                    Detected
                  </p>

                  <p className="text-gray-300 text-sm mt-1">
                    {alert.created_at
                      ? new Date(
                          alert.created_at
                        ).toLocaleString()
                      : "Unknown"}
                  </p>

                </div>

                {/* Verdict */}

                <div>

                  <p className="text-gray-600 text-xs uppercase tracking-wider">
                    Verdict
                  </p>

                  <p className="text-cyan-400 text-sm font-medium mt-1">
                    {alert.verdict ||
                      "—"}
                  </p>

                </div>

                {/* Score */}

                <div>

                  <p className="text-gray-600 text-xs uppercase tracking-wider">
                    Risk Score
                  </p>

                  <p className="text-white text-sm font-semibold mt-1">
                    {alert.score !==
                    undefined &&
                    alert.score !==
                    null
                      ? alert.score
                      : "—"}
                  </p>

                </div>

                {/* Action */}

                <div>

                  <p className="text-gray-600 text-xs uppercase tracking-wider">
                    Recommended Action
                  </p>

                  <p className="text-gray-300 text-sm mt-1">
                    {alert.recommended_action ||
                      "—"}
                  </p>

                </div>

              </div>

            </div>
          );
        })}

        {/* -----------------------------------------
            NO RESULTS
        ----------------------------------------- */}

        {filteredAlerts.length === 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-12 text-center">

            <div className="text-5xl mb-4">
              🔍
            </div>

            <h3 className="text-white text-lg font-semibold">
              No threats found
            </h3>

            <p className="text-gray-500 text-sm mt-2">
              Try changing your search or filters.
            </p>

          </div>
        )}

      </div>

    </div>
  );
}

export default ThreatFeed;

