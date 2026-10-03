// OpenSign-Quantum SSO helpers. All protocol work happens on the server;
// the browser only reads the public config, redirects, and exchanges a one-time code.
import { serverUrl_fn } from "../constant/appinfo";

// ".../api/app" -> ".../api/auth/"
export const ssoBaseUrl = () =>
  new URL("../auth/", serverUrl_fn().replace(/\/?$/, "/")).href;

export async function fetchSsoConfig() {
  try {
    const res = await fetch(`${ssoBaseUrl()}sso/config`, {
      credentials: "omit"
    });
    if (!res.ok) return { enabled: false };
    return await res.json();
  } catch {
    return { enabled: false };
  }
}

export function startSsoLogin() {
  window.location.assign(`${ssoBaseUrl()}sso/login`);
}

export async function exchangeSsoCode(code) {
  const res = await fetch(`${ssoBaseUrl()}sso/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "omit",
    body: JSON.stringify({ code })
  });
  if (!res.ok) throw new Error("INVALID_CODE");
  const { sessionToken } = await res.json();
  return sessionToken;
}

// Read and strip sso_code / sso_error from the URL so they are never reused or bookmarked.
export function takeSsoParams() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("sso_code");
  const error = url.searchParams.get("sso_error");
  if (code || error) {
    url.searchParams.delete("sso_code");
    url.searchParams.delete("sso_error");
    window.history.replaceState(null, "", url.pathname + url.search + url.hash);
  }
  return { code, error };
}

// Ends the OpenSign session server-side. Returns the IdP logout URL for SSO users, else null.
export async function ssoLogout(sessionToken) {
  if (!sessionToken) return null;
  try {
    const res = await fetch(`${ssoBaseUrl()}sso/logout`, {
      method: "POST",
      headers: { "X-Parse-Session-Token": sessionToken },
      credentials: "omit"
    });
    if (!res.ok) return null;
    const { logoutUrl } = await res.json();
    return logoutUrl || null;
  } catch {
    return null;
  }
}
