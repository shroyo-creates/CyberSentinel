// Small fetch wrapper for the dashboard's JSON API. Every call sends the
// admin session cookie (credentials: "same-origin") so Flask's
// @api_admin_required decorator can recognize the logged-in admin.

const UNAUTHORIZED_REDIRECT = "/admin/login";

async function request(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (res.status === 401) {
    // Session expired or never existed - bounce to the real login page.
    window.location.href = UNAUTHORIZED_REDIRECT;
    throw new Error("unauthorized");
  }

  if (!res.ok) {
    throw new Error(`Request to ${path} failed: ${res.status}`);
  }

  return res.json();
}

export function fetchDashboard() {
  return request("/api/dashboard");
}

export function postSetting(action) {
  return request("/api/admin/settings", {
    method: "POST",
    body: JSON.stringify({ action }),
  });
}
