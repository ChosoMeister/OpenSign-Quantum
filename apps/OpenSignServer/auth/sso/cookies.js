// Short-lived, signed, HttpOnly cookie carrying per-login CSRF material (OIDC state/nonce/PKCE,
// SAML correlation). Signed with SSO_COOKIE_SECRET via cookie-parser.
export const FLOW_COOKIE = 'os_sso_flow';
const FLOW_TTL_MS = 10 * 60 * 1000;

function cookieOptions() {
  return {
    httpOnly: true,
    // Secure unless explicitly running a plain-http local test setup.
    secure: process.env.SSO_INSECURE_COOKIES !== 'true',
    sameSite: 'lax', // must survive the top-level redirect back from the IdP
    signed: true,
    path: '/',
  };
}

export function setFlowCookie(res, value) {
  res.cookie(FLOW_COOKIE, JSON.stringify(value), { ...cookieOptions(), maxAge: FLOW_TTL_MS });
}

export function readFlowCookie(req) {
  const raw = req.signedCookies?.[FLOW_COOKIE];
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function clearFlowCookie(res) {
  const { maxAge, signed, ...opts } = { ...cookieOptions() };
  res.clearCookie(FLOW_COOKIE, opts);
}
