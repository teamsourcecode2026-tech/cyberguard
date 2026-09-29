import mockData from "./mockData";

const BASE_URL = "http://10.138.39.97:8000";

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