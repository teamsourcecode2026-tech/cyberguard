import { useState, useEffect } from "react";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import ThreatFeed from "./pages/ThreatFeed";
import AlertDetail from "./pages/AlertDetail";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import ScanCenter from "./pages/ScanCenter";
import { getAlerts, clearToken } from "./api";

function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState("");
  const [page, setPage] = useState("overview");
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(false);
  const [usingMockData, setUsingMockData] = useState(false);

  useEffect(() => {
    if (loggedIn) {
      setLoading(true);

      getAlerts().then(({ data, isMock }) => {
        const sorted = [...data].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        setAlerts(sorted);
        setSelectedAlert(sorted[0] || null);
        setUsingMockData(isMock);
        setLoading(false);
      });
    }
  }, [loggedIn]);

  if (!loggedIn) {
    return (
      <Login
        onLogin={(name) => {
          setUsername(name);
          setLoggedIn(true);
        }}
      />
    );
  }

  return (
    <div>
      <nav className="bg-gray-950 px-8 py-4 flex items-center justify-between border-b border-gray-800">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>

            <span className="text-white font-bold text-lg tracking-wide">
              CyberGuard
            </span>
          </div>

          <div className="flex gap-1">
            {[
              { id: "overview", label: "Overview" },
              { id: "scan", label: "Scan Center" },
              { id: "feed", label: "Threat Feed" },
              { id: "detail", label: "Alert Detail" },
              { id: "intelligence", label: "Intelligence" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setPage(tab.id)}
                className={`px-4 py-2 rounded-md font-medium transition-colors ${
                  page === tab.id
                    ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                    : "text-gray-400 hover:text-white hover:bg-gray-800"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <span className="text-gray-400 text-sm">
            Hi, {username}
          </span>

          <button
            onClick={() => {
              clearToken();
              setLoggedIn(false);
              setUsername("");
              setAlerts([]);
              setSelectedAlert(null);
              setPage("overview");
            }}
            className="text-gray-400 hover:text-white text-sm"
          >
            Log Out
          </button>
        </div>
      </nav>

      {loading ? (
        <div className="min-h-screen bg-gray-900 flex items-center justify-center">
          <div className="text-center">
            <div className="w-10 h-10 border-4 border-gray-600 border-t-blue-500 rounded-full animate-spin mx-auto mb-4"></div>

            <p className="text-gray-400">
              Loading alerts...
            </p>
          </div>
        </div>
      ) : (
        <>
          {page === "overview" && (
            <Overview alerts={alerts} />
          )}

          {page === "scan" && (
            <ScanCenter />
          )}

          {page === "feed" && (
            <ThreatFeed
              alerts={alerts}
              onSelect={(a) => {
                setSelectedAlert(a);
                setPage("detail");
              }}
            />
          )}

          {page === "detail" && selectedAlert && (
            <AlertDetail alert={selectedAlert} />
          )}

          {page === "intelligence" && (
            <ThreatIntelligence alert={selectedAlert} />
          )}
        </>
      )}
    </div>
  );
}

export default App;