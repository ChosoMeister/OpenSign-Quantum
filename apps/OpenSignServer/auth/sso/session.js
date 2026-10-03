import crypto from 'node:crypto';
import { resolveUser } from './userProvisioning.js';
import { ssoLog } from './log.js';

export const HANDOFF_TTL_MS = 60 * 1000;
// How long the OIDC id_token is kept as a logout hint (server-side only, master-key class).
const ID_TOKEN_HINT_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const hintKey = sessionToken =>
  `oidc-idt:${crypto.createHash('sha256').update(sessionToken).digest('hex')}`;

export async function takeIdTokenHint(store, sessionToken) {
  const key = hintKey(sessionToken);
  const hint = await store.cache.get(key);
  if (hint) await store.cache.remove(key);
  return hint;
}

/**
 * Common post-validation step for both protocols:
 * identity -> OpenSign user -> Parse session -> single-use handoff code.
 * The Parse session token never appears in a URL; the frontend exchanges the code via POST.
 */
export async function completeSsoLogin(identity, { store, config, correlationId, idToken }) {
  const { userId } = await resolveUser(identity, { store, config, correlationId });
  const sessionToken = await store.createSession(userId);
  if (idToken) await store.cache.put(hintKey(sessionToken), idToken, ID_TOKEN_HINT_TTL_MS);
  const code = crypto.randomBytes(32).toString('base64url');
  await store.saveHandoff(code, sessionToken, HANDOFF_TTL_MS);
  ssoLog('sso.login.success', { correlationId, provider: identity.provider, userId });
  return `${config.frontendUrl}/?sso_code=${encodeURIComponent(code)}`;
}

export function errorRedirect(config, code) {
  return `${config.frontendUrl}/?sso_error=${encodeURIComponent(code)}`;
}
