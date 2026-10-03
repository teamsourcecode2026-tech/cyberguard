
import React from "react";

function ThreatIntelligence() {
  return (
    <div className="min-h-screen bg-gray-900 p-8">

      {/* Page Title */}
      <h1 className="text-white text-3xl font-bold mb-8">
        Threat Intelligence
      </h1>

      {/* Main Card */}
      <div className="bg-gray-800 rounded-2xl p-8 shadow-lg border border-gray-700">

        <h2 className="text-white text-xl font-semibold mb-6">
          Threat Investigation
        </h2>

        <p className="text-gray-400">
          Analyze IP addresses, domains, locations and threat indicators.
        </p>
        
<div className="mt-8">

  <h3 className="text-white text-lg font-semibold mb-4">
    IP Analysis
  </h3>

  <div className="bg-gray-900 rounded-xl p-5 border border-gray-700">

    <p className="text-gray-400 text-sm mb-2">
      Source IP Address
    </p>

    <p className="text-white text-lg font-semibold">
      185.220.101.45
    </p>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">

      <div>
        <p className="text-gray-400 text-sm mb-1">
          Reputation
        </p>
        <p className="text-red-400 font-semibold">
          Suspicious
        </p>
      </div>

      <div>
        <p className="text-gray-400 text-sm mb-1">
          Threat Status
        </p>
        <p className="text-orange-400 font-semibold">
          Under Investigation
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

