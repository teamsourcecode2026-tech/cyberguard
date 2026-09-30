import { useState } from "react";

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function handleSubmit(e) {
  e.preventDefault();

  if (username.trim() === "" || password.trim() === "") {
    setError("Please enter both username and password.");
    return;
  }

  try {
    const response = await fetch("http://127.0.0.1:8000/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });

    const data = await response.json();

    if (data.success) {
      onLogin(data.username);
    } else {
      setError("Login failed.");
    }
  } catch (error) {
    console.error(error);
    setError("Cannot connect to the backend.");
  }
}

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <form
        onSubmit={handleSubmit}
        className="bg-gray-800 rounded-xl p-8 shadow-lg w-full max-w-sm"
      >
        <h1 className="text-white text-2xl font-bold mb-6 text-center">
          CyberGuard Login
        </h1>

        {error && (
          <p className="text-red-400 text-sm mb-4 text-center">{error}</p>
        )}

        <label className="text-gray-400 text-sm">Username</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full bg-gray-700 text-white rounded-lg px-3 py-2 mt-1 mb-4 outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Enter username"
        />

        <label className="text-gray-400 text-sm">Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full bg-gray-700 text-white rounded-lg px-3 py-2 mt-1 mb-6 outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Enter password"
        />

        <button
          type="submit"
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded-lg"
        >
          Log In
        </button>
      </form>
    </div>
  );
}

export default Login;