const API_BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const AUTH_TOKEN_KEY = "zeroguard_token";

function getAuthToken() {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

export function getStoredToken() {
  return getAuthToken();
}

export function isAuthenticated() {
  return Boolean(getAuthToken());
}

async function apiRequest(endpoint, options = {}) {
  const token = getAuthToken();

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `API Error: ${response.status}`;

    try {
      const data = await response.json();

      if (data.detail) {
        message =
          typeof data.detail === "string"
            ? data.detail
            : JSON.stringify(data.detail);
      }
    } catch (error) {
      console.error("Could not parse API error:", error);
    }

    throw new Error(message);
  }

  return await response.json();
}

// ============================================================
// AUTHENTICATION
// ============================================================

export function signup({
  username,
  email,
  password,
  name = "",
}) {
  return apiRequest("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({
      username,
      email,
      password,
      name,
    }),
  });
}

export async function login(username, password) {
  const response = await apiRequest("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({
      username,
      password,
    }),
  });

  if (response.token) {
    localStorage.setItem(AUTH_TOKEN_KEY, response.token);
  }

  return response;
}

export function getCurrentUser() {
  return apiRequest("/api/auth/me");
}

export async function logout() {
  const token = getAuthToken();

  try {
    if (token) {
      await apiRequest("/api/auth/logout", {
        method: "POST",
      });
    }
  } finally {
    localStorage.removeItem(AUTH_TOKEN_KEY);
  }
}

// ============================================================
// SYSTEM
// ============================================================

export function getStatus() {
  return apiRequest("/api/status");
}

export function getApiStatus() {
  return apiRequest("/api/status");
}

export function getHealth() {
  return apiRequest("/api/health");
}

export function getDatabaseSummary() {
  return apiRequest("/api/database/summary");
}

// ============================================================
// DEVICES
// ============================================================

export function getDevices() {
  return apiRequest("/api/devices");
}
export function createDevicePairing() {
  return apiRequest("/api/device-pairings", {
    method: "POST",
  });
}

export function registerDeviceWithPairing(data) {
  return apiRequest("/api/device-pairings/register", {
    method: "POST",
    body: JSON.stringify(data),
  });
}
// ============================================================
// NETWORK EVENTS
// ============================================================

export function getNetworkEvents() {
  return apiRequest("/api/network-events");
}

export function getNetworkEventsWithLimit(limit = 100) {
  return apiRequest(`/api/network-events?limit=${limit}`);
}

export function getNetworkEventsPaginated(limit = 100, offset = 0) {
  return apiRequest(
    `/api/network-events?limit=${limit}&offset=${offset}`
  );
}

// ============================================================
// THREATS
// ============================================================

export function getThreats() {
  return apiRequest("/api/threats");
}

export function getThreatsWithLimit(limit = 100) {
  return apiRequest(`/api/threats?limit=${limit}`);
}

export function getThreatNetworkEvents(threatId) {
  return apiRequest(
    `/api/threats/${threatId}/network-events`
  );
}

export function analyzeNetwork() {
  return apiRequest("/api/detection/analyze", {
    method: "POST",
  });
}

export function linkThreatEvents(threatId, eventIds) {
  return apiRequest(`/api/threats/${threatId}/events`, {
    method: "POST",
    body: JSON.stringify({
      event_ids: eventIds,
    }),
  });
}

// ============================================================
// INCIDENTS
// ============================================================

export function getIncidents() {
  return apiRequest("/api/incidents");
}

export function updateIncidentStatus(incidentId, status) {
  return apiRequest(
    `/api/incidents/${incidentId}/status?status=${encodeURIComponent(
      status
    )}`,
    {
      method: "PATCH",
    }
  );
}

// ============================================================
// RESPONSE ACTIONS
// ============================================================

export function getResponseActions() {
  return apiRequest("/api/response-actions");
}

export function createResponseAction(data) {
  return apiRequest("/api/response-actions", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function executeResponseAction(actionId) {
  return apiRequest(
    `/api/response-actions/${actionId}/execute`,
    {
      method: "POST",
    }
  );
}

// ============================================================
// ADMIN USER MANAGEMENT
// ============================================================

export function getAdminUsers() {
  return apiRequest("/api/admin/users");
}

export function updateUserRole(userId, role) {
  return apiRequest(`/api/admin/users/${userId}/role`, {
    method: "PATCH",
    body: JSON.stringify({
      role,
    }),
  });
}

export function updateUserStatus(userId, status) {
  return apiRequest(`/api/admin/users/${userId}/status`, {
    method: "PATCH",
    body: JSON.stringify({
      status,
    }),
  });
}

export function deleteAdminUser(userId) {
  return apiRequest(`/api/admin/users/${userId}`, {
    method: "DELETE",
  });
}

export {
  API_BASE_URL,
};