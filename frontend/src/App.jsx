import { useState } from "react";
import Overview from "./pages/Overview";
import ThreatFeed from "./pages/ThreatFeed";
import AlertDetail from "./pages/AlertDetail";
import mockData from "./mockData";

function App() {
  const [page, setPage] = useState("overview");
  const [selectedAlert, setSelectedAlert] = useState(mockData[0]);

  return (
    <div>
      <nav className="bg-gray-950 px-8 py-4 flex gap-6 border-b border-gray-800">
        <button
          onClick={() => setPage("overview")}
          className="text-gray-300 hover:text-white font-medium"
        >
          Overview
        </button>
        <button
          onClick={() => setPage("feed")}
          className="text-gray-300 hover:text-white font-medium"
        >
          Threat Feed
        </button>
        <button
          onClick={() => setPage("detail")}
          className="text-gray-300 hover:text-white font-medium"
        >
          Alert Detail
        </button>
      </nav>

      {page === "overview" && <Overview />}
      {page === "feed" && <ThreatFeed />}
      {page === "detail" && <AlertDetail alert={selectedAlert} />}
    </div>
  );
}

export default App;