import { useState } from "react";
import { loginUser, registerUser } from "../api";

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [mode, setMode] = useState("login");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (username.trim() === "" || password.trim() === "") {
      setError("Please enter both username and password.");
      return;
    }

    setLoading(true);

    const result =
      mode === "login"
        ? await loginUser(username, password)
        : await registerUser(username, password);

    setLoading(false);

    if (result.success) {
      if (mode === "register") {
        setError("Registered! Now log in.");
        setMode("login");
      } else {
        onLogin(username);
      }
    } else {
      setError(result.message || "Something went wrong.");
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 to-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-6">
          <div className="text-5xl mb-2">🛡️</div>
          <h1 className="text-white text-2xl font-bold tracking-wide">
            CyberGuard
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            Threat Detection Dashboard
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-gray-800 rounded-2xl p-8 shadow-2xl border border-gray-700"
        >
          <h2 className="text-white text-lg font-semibold mb-6 text-center">
            {mode === "login" ? "Welcome back" : "Create an account"}
          </h2>

          {error && (
            <p className="text-yellow-400 text-sm mb-4 text-center bg-yellow-400/10 rounded-lg py-2 px-3">
              {error}
            </p>
          )}

          <label className="text-gray-400 text-sm">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full bg-gray-900 text-white rounded-lg px-3 py-2 mt-1 mb-4 outline-none border border-gray-700 focus:border-blue-500 transition"
            placeholder="Enter username"
          />

          <label className="text-gray-400 text-sm">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-gray-900 text-white rounded-lg px-3 py-2 mt-1 mb-6 outline-none border border-gray-700 focus:border-blue-500 transition"
            placeholder="Enter password"
          />

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white font-semibold py-2.5 rounded-lg mb-4 transition"
          >
            {loading ? "Please wait..." : mode === "login" ? "Log In" : "Register"}
          </button>

          <p className="text-gray-500 text-sm text-center">
            {mode === "login" ? "No account?" : "Already have an account?"}{" "}
            <button
              type="button"
              onClick={() => {
                setMode(mode === "login" ? "register" : "login");
                setError("");
              }}
              className="text-blue-400 hover:underline"
            >
              {mode === "login" ? "Register" : "Log In"}
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}

export default Login;