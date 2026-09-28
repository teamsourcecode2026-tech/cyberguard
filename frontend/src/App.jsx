import { useState, useEffect } from "react";
import Overview from "./pages/Overview";
import ThreatFeed from "./pages/ThreatFeed";
import AlertDetail from "./pages/AlertDetail";
import { getAlerts } from "./api";

function App() {
  const [page, setPage] = useState("overview");
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    getAlerts().then((data) => {
      setAlerts(data);
      setSelectedAlert(data[0] || null);
    });
  }, []);

  return (
    <div>
      <nav className="bg-gray-950 px-8 py-4 flex gap-6 border-b border-gray-800">
        <button onClick={() => setPage("overview")} className="text-gray-300 hover:text-white font-medium">Overview</button>
        <button onClick={() => setPage("feed")} className="text-gray-300 hover:text-white font-medium">Threat Feed</button>
        <button onClick={() => setPage("detail")} className="text-gray-300 hover:text-white font-medium">Alert Detail</button>
      </nav>

      {page === "overview" && <Overview alerts={alerts} />}
      {page === "feed" && (
        <ThreatFeed
          alerts={alerts}
          onSelect={(a) => {
            setSelectedAlert(a);
            setPage("detail");
          }}
        />
      )}
      {page === "detail" && selectedAlert && <AlertDetail alert={selectedAlert} />}
    </div>
  );
}

export default App;