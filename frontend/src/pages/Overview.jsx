
function Overview({ alerts }) {
  const total = alerts.length;

  const phishing = alerts.filter(
    (a) => a.category === "phishing"
  ).length;

  const deepfake = alerts.filter(
    (a) => a.category === "deepfake"
  ).length;

  const anomaly = alerts.filter(
    (a) => a.category === "anomaly"
  ).length;

  const threatsDetected = alerts.filter((a) =>
    ["Medium", "High", "Critical"].includes(
      a.overall_risk_level
    )
  ).length;

  const newIncidents = alerts.filter(
    (a) => a.status === "new"
  ).length;

  return (
    <div className="min-h-screen bg-gray-900 p-8">

      {/* Page Title */}
      <h1 className="text-white text-3xl font-bold mb-8">
        Overview
      </h1>


      {/* Main KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">

        {/* Total Events */}
        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700 hover:border-blue-400 transition-all duration-300">
          <div className="flex items-center justify-between">

            <div>
              <p className="text-gray-400 text-sm font-medium">
                Total Events
              </p>

              <p className="text-white text-3xl font-bold mt-2">
                {total}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Events analyzed by CyberGuard
              </p>
            </div>

            <div className="bg-blue-500/20 p-3 rounded-xl text-2xl">
              🛡️
            </div>

          </div>
        </div>


        {/* Threats Detected */}
        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700 hover:border-red-400 transition-all duration-300">
          <div className="flex items-center justify-between">

            <div>
              <p className="text-gray-400 text-sm font-medium">
                Threats Detected
              </p>

              <p className="text-red-400 text-3xl font-bold mt-2">
                {threatsDetected}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Medium to critical risk events
              </p>
            </div>

            <div className="bg-red-500/20 p-3 rounded-xl text-2xl">
              🚨
            </div>

          </div>
        </div>


        {/* New Incidents */}
        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700 hover:border-orange-400 transition-all duration-300">
          <div className="flex items-center justify-between">

            <div>
              <p className="text-gray-400 text-sm font-medium">
                New Incidents
              </p>

              <p className="text-orange-400 text-3xl font-bold mt-2">
                {newIncidents}
              </p>

              <p className="text-gray-500 text-xs mt-2">
                Requires security review
              </p>
            </div>

            <div className="bg-orange-500/20 p-3 rounded-xl text-2xl">
              ⚠️
            </div>

          </div>
        </div>

      </div>


      {/* Threat Category Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* Phishing */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">
            Phishing
          </p>

          <p className="text-yellow-400 text-3xl font-bold mt-2">
            {phishing}
          </p>
        </div>


        {/* Deepfake */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">
            Deepfake
          </p>

          <p className="text-red-400 text-3xl font-bold mt-2">
            {deepfake}
          </p>
        </div>


        {/* Anomaly */}
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">
            Anomaly
          </p>

          <p className="text-blue-400 text-3xl font-bold mt-2">
            {anomaly}
          </p>
        </div>

      </div>


      {/* Security Risk Overview */}
      <div className="mt-8">

        <h2 className="text-white text-xl font-semibold mb-4">
          Security Risk Overview
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">

          {/* Critical */}
          <div className="bg-gray-800 rounded-xl p-5 border border-red-500/30">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-gray-400 text-sm">
                  Critical Risk
                </p>

                <p className="text-red-400 text-2xl font-bold mt-2">
                  {alerts.filter(
                    (a) =>
                      a.overall_risk_level === "Critical"
                  ).length}
                </p>
              </div>

              <span className="text-2xl">
                🔴
              </span>

            </div>
          </div>


          {/* High */}
          <div className="bg-gray-800 rounded-xl p-5 border border-orange-500/30">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-gray-400 text-sm">
                  High Risk
                </p>

                <p className="text-orange-400 text-2xl font-bold mt-2">
                  {alerts.filter(
                    (a) =>
                      a.overall_risk_level === "High"
                  ).length}
                </p>
              </div>

              <span className="text-2xl">
                🟠
              </span>

            </div>
          </div>


          {/* Medium */}
          <div className="bg-gray-800 rounded-xl p-5 border border-yellow-500/30">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-gray-400 text-sm">
                  Medium Risk
                </p>

                <p className="text-yellow-400 text-2xl font-bold mt-2">
                  {alerts.filter(
                    (a) =>
                      a.overall_risk_level === "Medium"
                  ).length}
                </p>
              </div>

              <span className="text-2xl">
                🟡
              </span>

            </div>
          </div>


          {/* Low */}
          <div className="bg-gray-800 rounded-xl p-5 border border-green-500/30">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-gray-400 text-sm">
                  Low Risk
                </p>

                <p className="text-green-400 text-2xl font-bold mt-2">
                  {alerts.filter(
                    (a) =>
                      a.overall_risk_level === "Low"
                  ).length}
                </p>
              </div>

              <span className="text-2xl">
                🟢
              </span>

            </div>
          </div>

        </div>

      </div>


      {/* Threat Activity */}
      <div className="mt-8">

        <h2 className="text-white text-xl font-semibold mb-4">
          Threat Activity
        </h2>

        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700">


          {/* Phishing */}
          <div className="mb-6">

            <div className="flex justify-between mb-2">

              <span className="text-gray-300">
                Phishing
              </span>

              <span className="text-yellow-400 font-semibold">
                {phishing}
              </span>

            </div>

            <div className="w-full bg-gray-700 rounded-full h-3">

              <div
                className="bg-yellow-400 h-3 rounded-full"
                style={{
                  width: `${phishing * 20}%`
                }}
              ></div>

            </div>

          </div>


          {/* Deepfake */}
          <div className="mb-6">

            <div className="flex justify-between mb-2">

              <span className="text-gray-300">
                Deepfake
              </span>

              <span className="text-red-400 font-semibold">
                {deepfake}
              </span>

            </div>

            <div className="w-full bg-gray-700 rounded-full h-3">

              <div
                className="bg-red-400 h-3 rounded-full"
                style={{
                  width: `${deepfake * 20}%`
                }}
              ></div>

            </div>

          </div>


          {/* Anomaly */}
          <div>

            <div className="flex justify-between mb-2">

              <span className="text-gray-300">
                Anomaly
              </span>

              <span className="text-blue-400 font-semibold">
                {anomaly}
              </span>

            </div>

            <div className="w-full bg-gray-700 rounded-full h-3">

              <div
                className="bg-blue-400 h-3 rounded-full"
                style={{
                  width: `${anomaly * 20}%`
                }}
              ></div>

            </div>

          </div>

        </div>

      </div>


      {/* Recent Security Alerts */}
      <div className="mt-8">

        <h2 className="text-white text-xl font-semibold mb-4">
          Recent Security Alerts
        </h2>

        <div className="bg-gray-800 rounded-2xl p-6 shadow-lg border border-gray-700">

          {/* Table Header */}
          <div className="grid grid-cols-4 gap-4 text-gray-400 text-sm font-semibold border-b border-gray-700 pb-3">

            <span>Event ID</span>
            <span>Category</span>
            <span>Risk</span>
            <span>Recommended Action</span>

          </div>


          {/* Real Alerts */}
          {alerts.slice(0, 5).map((alert, index) => (
            <div
              key={alert.event_id || index}
              className="grid grid-cols-4 gap-4 text-gray-300 text-sm py-4 border-b border-gray-700 last:border-b-0"
            >

              {/* Event ID */}
              <span className="text-blue-400 font-medium">
                {alert.event_id}
              </span>


              {/* Category */}
              <span className="capitalize">
                {alert.category}
              </span>


              {/* Risk */}
              <span
                className={
                  alert.overall_risk_level === "Critical"
                    ? "text-red-400 font-semibold"
                    : alert.overall_risk_level === "High"
                    ? "text-orange-400 font-semibold"
                    : alert.overall_risk_level === "Medium"
                    ? "text-yellow-400 font-semibold"
                    : alert.overall_risk_level === "Low"
                    ? "text-green-400"
                    : "text-gray-400"
                }
              >
                {alert.overall_risk_level}
              </span>


              {/* Recommended Action */}
              <span className="text-gray-300">
                {alert.recommended_action}
              </span>

            </div>
          ))}


          {/* No Alerts */}
          {alerts.length === 0 && (
            <p className="text-gray-500 text-sm py-4">
              No security alerts available.
            </p>
          )}

        </div>

      </div>

    </div>
  );
}

export default Overview;

