import mockData from "./mockData";

const BASE_URL = "http://localhost:8000";
const AUTH_URL = "http://localhost:8000";

export async function getAlerts() {
  try {
    const res = await fetch(`${BASE_URL}/api/alerts`);
    if (!res.ok) throw new Error("Backend error");
    return { data: await res.json(), isMock: false };
  } catch (err) {
    console.warn("Backend not reachable, using mock data");
    return { data: mockData, isMock: true };
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

// --- Generic Submissions ---
async function submitText(endpoint, text) {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    return await res.json();
  } catch (err) {
    return { error: "Failed to connect to backend" };
  }
}

async function submitUrl(endpoint, url) {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    return await res.json();
  } catch (err) {
    return { error: "Failed to connect to backend" };
  }
}

async function submitFile(endpoint, file) {
  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: "POST",
      body: formData,
    });
    return await res.json();
  } catch (err) {
    return { error: "Failed to connect to backend" };
  }
}

// --- Text Endpoints ---
export const analyzePhishing = (text) => submitText("/api/ingest/phishing", text);
export const analyzeImpersonation = (text) => submitText("/api/ingest/impersonation", text);
export const analyzeSms = (text) => submitText("/api/ingest/sms", text);
export const analyzeSocial = (text) => submitText("/api/ingest/social", text);

// --- URL Endpoints ---
export const analyzeUrl = (url) => submitUrl("/api/ingest/url", url);
export const analyzeWebsite = (url) => submitUrl("/api/ingest/website", url);
export const analyzeDomainSpoof = (url) => submitUrl("/api/ingest/domain-spoof", url);
export const analyzeLookalike = (url) => submitUrl("/api/ingest/lookalike", url);
export const analyzeSsl = (url) => submitUrl("/api/ingest/ssl-check", url);
export const analyzeUrlManipulation = (url) => submitUrl("/api/ingest/url-manipulation", url);
export const analyzeRedirect = (url) => submitUrl("/api/ingest/redirect-check", url);
export const analyzeFakeLogin = (url) => submitUrl("/api/ingest/fake-login", url);

// --- File Endpoints ---
export const analyzeDeepfake = (file) => submitFile("/api/ingest/deepfake", file);
export const analyzeQr = (file) => submitFile("/api/ingest/qr", file);