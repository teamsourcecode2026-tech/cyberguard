function Overview({ alerts }) {
  const total = alerts.length;
  const phishing = alerts.filter((a) => a.category === "phishing").length;
  const deepfake = alerts.filter((a) => a.category === "deepfake").length;
  const anomaly = alerts.filter((a) => a.category === "anomaly").length;

  return (
    <div className="min-h-screen bg-gray-900 p-8">
      <h1 className="text-white text-3xl font-bold mb-8">Overview</h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">Total Events</p>
          <p className="text-white text-3xl font-bold mt-2">{total}</p>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">Phishing</p>
          <p className="text-yellow-400 text-3xl font-bold mt-2">{phishing}</p>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">Deepfake</p>
          <p className="text-red-400 text-3xl font-bold mt-2">{deepfake}</p>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
          <p className="text-gray-400 text-sm">Anomaly</p>
          <p className="text-blue-400 text-3xl font-bold mt-2">{anomaly}</p>
        </div>
      </div>
    </div>
  );
}

export default Overview;