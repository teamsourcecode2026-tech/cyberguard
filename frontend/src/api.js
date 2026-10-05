import mockData from "./mockData";

const BASE_URL = "http://localhost:8000";
const AUTH_URL = "http://localhost:8000";

// --- JWT Token Management ---
export function getToken() { return localStorage.getItem("cyberguard_token"); }
export function setToken(token) { localStorage.setItem("cyberguard_token", token); }
export function clearToken() { localStorage.removeItem("cyberguard_token"); }

function authHeaders() {
  const token = getToken();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

function authHeadersNoContent() {
  const token = getToken();
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

export async function getAlerts() {
  try {
    const res = await fetch(`${BASE_URL}/api/alerts`, { headers: authHeadersNoContent() });
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
    const data = await res.json();
    if (data.success && data.token) {
      setToken(data.token);
    }
    return data;
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

export async function resetPassword(username, old_password, new_password) {
  try {
    const res = await fetch(`${AUTH_URL}/api/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, old_password, new_password }),
    });
    return await res.json();
  } catch (err) {
    return { success: false, message: "Cannot reach server" };
  }
}

// --- Generic Submissions (with auth) ---
async function submitText(endpoint, text) {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: "POST",
      headers: authHeaders(),
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
      headers: authHeaders(),
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
    const headers = authHeadersNoContent();
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: "POST",
      headers,
      body: formData,
    });
    return await res.json();
  } catch (err) {
    return { error: "Failed to connect to backend" };
  }
}

async function submitJson(endpoint, payload) {
  try {
    const res = await fetch(`${BASE_URL}${endpoint}`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(payload),
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
export const analyzeMalware = (file) => submitFile("/api/ingest/malware", file);

// --- Anomaly & Account Theft ---
export const analyzeAnomalyLog = (logData) => submitText("/api/ingest/log", JSON.stringify(logData));

// --- Intelligent Detection Endpoints ---
export const analyzeNetworkTraffic = (connections) => submitJson("/api/ingest/network", { connections });
export const analyzeApiAbuse = (requests) => submitJson("/api/ingest/api-abuse", { requests });
export const analyzeExfiltration = (events) => submitJson("/api/ingest/exfiltration", { events });
export const analyzeUserActivity = (login_events, action_events = []) => submitJson("/api/ingest/user-activity", { login_events, action_events });
export const analyzeInsiderThreat = (employee, activity_events, baseline_daily_actions = null) => submitJson("/api/ingest/insider-threat", { employee, activity_events, baseline_daily_actions });
export const analyzeSystemBehavior = (events) => submitJson("/api/ingest/system-behavior", { events });

// --- Email Authentication (SPF/DKIM/DMARC) ---
export const analyzeEmailAuth = (sender_domain, sender_ip = null, dkim_selector = "default") => submitJson("/api/ingest/email-auth", { sender_domain, sender_ip, dkim_selector });