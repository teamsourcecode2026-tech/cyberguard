import mockData from "./mockData";

const BASE_URL = "http://10.138.39.97:8000";
const AUTH_URL = "http://127.0.0.1:8001";

export async function getAlerts() {
  try {
    const res = await fetch(`${BASE_URL}/api/alerts`);
    if (!res.ok) throw new Error("Backend error");
    return await res.json();
  } catch (err) {
    console.warn("Backend not reachable, using mock data");
    return mockData;
  }
}

export async function loginUser(username, password) {
  try {
    const res = await fetch(`${AUTH_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    return await res.json();
  } catch (err) {
    return { success: false, message: "Cannot reach login server" };
  }
}

export async function registerUser(username, password) {
  try {
    const res = await fetch(`${AUTH_URL}/api/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    return await res.json();
  } catch (err) {
    return { success: false, message: "Cannot reach login server" };
  }
}