import { useState, useEffect } from "react";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import ThreatFeed from "./pages/ThreatFeed";
import AlertDetail from "./pages/AlertDetail";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import { getAlerts } from "./api";

function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState("");
  const [page, setPage] = useState("overview");
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (loggedIn) {
      setLoading(true);
      getAlerts().then((data) => {
        setAlerts(data);
        setSelectedAlert(data[0] || null);
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
          <div className="flex gap-6">
            <button onClick={() => setPage("overview")} className="text-gray-300 hover:text-white font-medium">Overview</button>
            <button onClick={() => setPage("feed")} className="text-gray-300 hover:text-white font-medium">Threat Feed</button>
            <button onClick={() => setPage("detail")} className="text-gray-300 hover:text-white font-medium">Alert Detail</button>
            <button
              onClick={() => setPage("intelligence")}
              className="text-gray-300 hover:text-white font-medium"
            >
              Threat Intelligence
            </button>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-gray-400 text-sm">Hi, {username}</span>
          <button
            onClick={() => {
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
            <p className="text-gray-400">Loading alerts...</p>
          </div>
        </div>
      ) : (
        <>
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
          {page === "intelligence" && <ThreatIntelligence />}
        </>
      )}
    </div>
  );
}

export default App;