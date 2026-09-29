import { useState, useEffect } from "react";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import ThreatFeed from "./pages/ThreatFeed";
import AlertDetail from "./pages/AlertDetail";
import { getAlerts } from "./api";

function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [username, setUsername] = useState("");
  const [page, setPage] = useState("overview");
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    if (loggedIn) {
      getAlerts().then((data) => {
        setAlerts(data);
        setSelectedAlert(data[0] || null);
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
        <div className="flex gap-6">
          <button onClick={() => setPage("overview")} className="text-gray-300 hover:text-white font-medium">Overview</button>
          <button onClick={() => setPage("feed")} className="text-gray-300 hover:text-white font-medium">Threat Feed</button>
          <button onClick={() => setPage("detail")} className="text-gray-300 hover:text-white font-medium">Alert Detail</button>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-gray-400 text-sm">Hi, {username}</span>
          <button
            onClick={() => setLoggedIn(false)}
            className="text-gray-400 hover:text-white text-sm"
          >
            Log Out
          </button>
        </div>
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